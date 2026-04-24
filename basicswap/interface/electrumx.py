#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import json
import queue
import socket
import ssl
import threading
import time

from basicswap.util import TemporaryError


def _close_socket_safe(sock):
    if sock:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass


DEFAULT_ELECTRUM_SERVERS = {
    "bitcoin": [
        {"host": "bitcoin.stackwallet.com", "port": 50002, "ssl": True},
        {"host": "electrum.blockstream.info", "port": 50002, "ssl": True},
        {"host": "electrum.emzy.de", "port": 50002, "ssl": True},
        {"host": "electrum.bitaroo.net", "port": 50002, "ssl": True},
        {"host": "electrum.acinq.co", "port": 50002, "ssl": True},
        {"host": "btc.lastingcoin.net", "port": 50002, "ssl": True},
    ],
    "litecoin": [
        {"host": "litecoin.stackwallet.com", "port": 20063, "ssl": True},
        {"host": "electrum-ltc.bysh.me", "port": 50002, "ssl": True},
        {"host": "electrum.ltc.xurious.com", "port": 50002, "ssl": True},
        {"host": "backup.electrum-ltc.org", "port": 443, "ssl": True},
        {"host": "ltc.rentonisk.com", "port": 50002, "ssl": True},
        {"host": "electrum-ltc.petrkr.net", "port": 60002, "ssl": True},
        {"host": "electrum.jochen-hoenicke.de", "port": 50004, "ssl": True},
    ],
}

DEFAULT_ONION_SERVERS = {
    "bitcoin": [],
    "litecoin": [],
}


class ElectrumConnection:
    def __init__(
        self,
        host,
        port,
        use_ssl=True,
        timeout=10,
        log=None,
        proxy_host=None,
        proxy_port=None,
    ):
        self._host = host
        self._port = port
        self._use_ssl = use_ssl
        self._timeout = timeout
        self._socket = None
        self._request_id = 0
        self._lock = threading.Lock()
        self._connected = False
        self._response_queues = {}
        self._notification_callbacks = {}
        self._header_callback = None
        self._listener_thread = None
        self._listener_running = False
        self._log = log
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port

    @staticmethod
    def _is_private_address(host: str) -> bool:
        try:
            import ipaddress

            addr = ipaddress.ip_address(host)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError:
            return host == "localhost"

    def connect(self):
        try:
            use_proxy = (
                self._proxy_host
                and self._proxy_port
                and not self._is_private_address(self._host)
            )
            if use_proxy:
                import socks

                sock = socks.socksocket()
                sock.set_proxy(
                    socks.SOCKS5, self._proxy_host, self._proxy_port, rdns=True
                )
                sock.settimeout(self._timeout)
                sock.connect((self._host, self._port))
                if self._log:
                    self._log.debug(
                        f"Electrum connecting via proxy {self._proxy_host}:{self._proxy_port} to {self._host}:{self._port}"
                    )
            else:
                sock = socket.create_connection(
                    (self._host, self._port), timeout=self._timeout
                )
                if self._log and self._proxy_host and self._proxy_port:
                    self._log.debug(
                        f"Electrum connecting directly to LAN server {self._host}:{self._port} (bypassing proxy)"
                    )
            if self._use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                self._socket = context.wrap_socket(sock, server_hostname=self._host)
            else:
                self._socket = sock
            self._connected = True
        except Exception as e:
            self._connected = False
            raise TemporaryError(f"Failed to connect to {self._host}:{self._port}: {e}")

    def disconnect(self):
        self._stop_listener()
        sock = self._socket
        self._socket = None
        self._connected = False
        _close_socket_safe(sock)
        queues = list(self._response_queues.values())
        for q in queues:
            try:
                q.put({"error": "Connection closed"})
            except Exception:
                pass
        self._response_queues.clear()

    def is_connected(self):
        return self._connected and self._socket is not None

    def _start_listener(self):
        if self._listener_thread is not None and self._listener_thread.is_alive():
            return
        self._listener_running = True
        self._listener_thread = threading.Thread(
            target=self._listener_loop, daemon=True
        )
        self._listener_thread.start()

    def _stop_listener(self):
        self._listener_running = False
        if self._listener_thread is not None:
            self._listener_thread.join(timeout=2)
            self._listener_thread = None

    def _listener_loop(self):
        buffer = b""
        while self._listener_running and self._connected and self._socket:
            try:
                self._socket.settimeout(1.0)
                try:
                    data = self._socket.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    self._connected = False
                    break
                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    try:
                        message = json.loads(line.decode())
                        self._handle_message(message)
                    except json.JSONDecodeError:
                        if self._log:
                            self._log.debug(f"Invalid JSON from electrum: {line[:100]}")
            except Exception as e:
                if self._listener_running and self._log:
                    self._log.debug(f"Electrum listener error: {e}")
                self._connected = False
                break

    def _handle_message(self, message):
        if "id" in message and message["id"] is not None:
            request_id = message["id"]
            if request_id in self._response_queues:
                self._response_queues[request_id].put(message)
        elif "method" in message:
            self._handle_notification(message)

    def _handle_notification(self, message):
        method = message.get("method", "")
        params = message.get("params", [])

        if method == "blockchain.scripthash.subscribe" and len(params) >= 2:
            scripthash = params[0]
            new_status = params[1]
            if scripthash in self._notification_callbacks:
                try:
                    callback = self._notification_callbacks[scripthash]
                    callback(scripthash, new_status)
                except Exception as e:
                    if self._log:
                        self._log.debug(f"Notification callback error: {e}")
        elif method == "blockchain.headers.subscribe" and len(params) >= 1:
            header = params[0]
            height = header.get("height", 0)
            if self._log:
                self._log.debug(f"New block header notification: height={height}")
            if self._header_callback and height > 0:
                try:
                    self._header_callback(height)
                except Exception as e:
                    if self._log:
                        self._log.debug(f"Header callback error: {e}")

    def register_notification_callback(self, scripthash, callback):
        self._notification_callbacks[scripthash] = callback

    def register_header_callback(self, callback):
        """Register callback for header height updates. Callback receives height as argument."""
        self._header_callback = callback

    def _send_request(self, method, params=None):
        if params is None:
            params = []
        with self._lock:
            self._request_id += 1
            request_id = self._request_id

        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }
        request_data = json.dumps(request) + "\n"
        self._socket.sendall(request_data.encode())
        return request_id

    def _receive_response_sync(self, expected_id, timeout=30):
        buffer = b""
        self._socket.settimeout(timeout)
        while True:
            try:
                data = self._socket.recv(4096)
                if not data:
                    raise TemporaryError("Connection closed")
                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    response = json.loads(line.decode())
                    if response.get("id") == expected_id:
                        if "error" in response and response["error"]:
                            raise Exception(f"Electrum error: {response['error']}")
                        return response.get("result")
                    elif "method" in response:
                        self._handle_notification(response)
            except socket.timeout:
                raise TemporaryError("Request timed out")

    def _receive_response_async(self, expected_id, timeout=30):
        try:
            response = self._response_queues[expected_id].get(timeout=timeout)
            if "error" in response and response["error"]:
                raise Exception(f"Electrum error: {response['error']}")
            return response.get("result")
        except queue.Empty:
            raise TemporaryError("Request timed out")
        finally:
            self._response_queues.pop(expected_id, None)

    def _receive_response(self, expected_id, timeout=30):
        if self._listener_running:
            return self._receive_response_async(expected_id, timeout)
        return self._receive_response_sync(expected_id, timeout)

    def _receive_batch_responses(self, expected_ids, timeout=30):
        if self._listener_running:
            return self._receive_batch_responses_async(expected_ids, timeout)
        return self._receive_batch_responses_sync(expected_ids, timeout)

    def _receive_batch_responses_sync(self, expected_ids, timeout=30):
        buffer = b""
        self._socket.settimeout(timeout)
        results = {}
        pending_ids = set(expected_ids)

        while pending_ids:
            try:
                data = self._socket.recv(4096)
                if not data:
                    raise TemporaryError("Connection closed")
                buffer += data
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    response = json.loads(line.decode())
                    resp_id = response.get("id")
                    if resp_id in pending_ids:
                        if "error" in response and response["error"]:
                            results[resp_id] = {"error": response["error"]}
                        else:
                            results[resp_id] = {"result": response.get("result")}
                        pending_ids.discard(resp_id)
                    elif "method" in response:
                        self._handle_notification(response)
            except socket.timeout:
                raise TemporaryError(
                    f"Batch request timed out, {len(pending_ids)} responses pending"
                )
        return results

    def _receive_batch_responses_async(self, expected_ids, timeout=30):
        results = {}
        deadline = time.time() + timeout
        for req_id in expected_ids:
            response = None
            while response is None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TemporaryError("Batch request timed out")
                if not self._connected:
                    raise TemporaryError("Connection closed during batch request")
                poll_time = min(remaining, 2.0)
                try:
                    response = self._response_queues[req_id].get(timeout=poll_time)
                except queue.Empty:
                    continue
            try:
                if "error" in response and response["error"]:
                    error_msg = str(response["error"])
                    if "Connection closed" in error_msg:
                        raise TemporaryError("Connection closed during batch request")
                    results[req_id] = {"error": response["error"]}
                else:
                    results[req_id] = {"result": response.get("result")}
            finally:
                self._response_queues.pop(req_id, None)
        return results

    def call(self, method, params=None, timeout=10):
        if not self.is_connected():
            self.connect()
        try:
            if self._listener_running:
                with self._lock:
                    self._request_id += 1
                    request_id = self._request_id
                    self._response_queues[request_id] = queue.Queue()
                    request = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": method,
                        "params": params if params else [],
                    }
                    self._socket.sendall((json.dumps(request) + "\n").encode())
                result = self._receive_response_async(request_id, timeout=timeout)
                return result
            else:
                request_id = self._send_request(method, params)
                result = self._receive_response_sync(request_id, timeout=timeout)
                return result
        except (ssl.SSLError, OSError, ConnectionError) as e:
            _close_socket_safe(self._socket)
            self._connected = False
            self._socket = None
            raise TemporaryError(f"Connection error: {e}")

    def call_batch(self, requests):
        if not self.is_connected():
            self.connect()
        try:
            request_ids = []
            if self._listener_running:
                with self._lock:
                    for method, params in requests:
                        self._request_id += 1
                        request_id = self._request_id
                        self._response_queues[request_id] = queue.Queue()
                        request_ids.append(request_id)
                        req = {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": method,
                            "params": params if params else [],
                        }
                        self._socket.sendall((json.dumps(req) + "\n").encode())
            else:
                for method, params in requests:
                    request_id = self._send_request(method, params if params else [])
                    request_ids.append(request_id)

            responses = self._receive_batch_responses(request_ids)

            results = []
            for req_id in request_ids:
                resp = responses.get(req_id, {})
                if "error" in resp:
                    results.append(None)
                else:
                    results.append(resp.get("result"))
            return results
        except (ssl.SSLError, OSError, ConnectionError) as e:
            _close_socket_safe(self._socket)
            self._connected = False
            self._socket = None
            raise TemporaryError(f"Connection error: {e}")

    def ping(self):
        try:
            start = time.time()
            self.call("server.ping")
            return (time.time() - start) * 1000
        except Exception:
            return None

    def get_server_version(self):
        return self.call("server.version", ["BasicSwap", "1.4"])


def scripthash_from_script(script_bytes):
    sha = hashlib.sha256(script_bytes).digest()
    return sha[::-1].hex()


def scripthash_from_address(address, network_params):
    from basicswap.util.address import decodeAddress
    from basicswap.contrib.test_framework.script import (
        CScript,
        OP_DUP,
        OP_HASH160,
        OP_EQUALVERIFY,
        OP_CHECKSIG,
        OP_0,
        OP_EQUAL,
    )

    try:
        addr_data = decodeAddress(address)
        addr_type = addr_data[0]
        addr_hash = addr_data[1:]

        if addr_type == network_params.get("pubkey_address"):
            script = CScript(
                [OP_DUP, OP_HASH160, addr_hash, OP_EQUALVERIFY, OP_CHECKSIG]
            )
        elif addr_type == network_params.get("script_address"):
            script = CScript([OP_HASH160, addr_hash, OP_EQUAL])
        else:
            script = CScript([OP_0, addr_hash])

        return scripthash_from_script(bytes(script))
    except Exception:
        from basicswap.contrib.test_framework.segwit_addr import decode as bech32_decode

        hrp = network_params.get("hrp", "bc")
        witver, witprog = bech32_decode(hrp, address)
        if witver is not None:
            script = CScript([OP_0, bytes(witprog)])
            return scripthash_from_script(bytes(script))
    raise ValueError(f"Unable to decode address: {address}")


def _parse_server_string(server_str):
    parts = server_str.strip().split(":")
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 50002
    if len(parts) > 2:
        ssl_str = parts[2].lower()
        use_ssl = ssl_str in ("true", "1", "yes", "ssl")
    else:
        use_ssl = port != 50001
    return {"host": host, "port": port, "ssl": use_ssl}


class ElectrumServer:
    def __init__(
        self,
        coin_name,
        clearnet_servers=None,
        onion_servers=None,
        log=None,
        proxy_host=None,
        proxy_port=None,
    ):
        self._coin_name = coin_name
        self._log = log
        self._connection = None
        self._current_server_idx = 0
        self._lock = threading.Lock()
        self._stopping = False

        self._server_version = None
        self._current_server_host = None
        self._current_server_port = None

        self._proxy_host = proxy_host
        self._proxy_port = proxy_port

        self._notification_callbacks = {}
        self._subscribed_scripthashes = set()
        self._realtime_enabled = False

        self._connection_failures = 0
        self._last_connection_error = None
        self._using_default_servers = False
        self._all_servers_failed = False

        self._server_scores = {}

        self._server_blacklist = {}
        self._rate_limit_backoff = 300

        self._consecutive_timeouts = 0
        self._max_consecutive_timeouts = 5
        self._last_timeout_time = 0
        self._timeout_decay_seconds = 90

        self._keepalive_thread = None
        self._keepalive_running = False
        self._keepalive_interval = 15
        self._last_activity = 0
        self._last_reconnect_time = 0

        self._min_request_interval = 0.02
        self._last_request_time = 0

        self._user_connection = None
        self._user_lock = threading.Lock()
        self._user_last_activity = 0
        self._user_connection_logged = False

        self._subscribed_height = 0
        self._subscribed_height_time = 0
        self._height_callback = None

        self._initial_connection_logged = False

        use_tor = proxy_host is not None and proxy_port is not None

        user_clearnet = []
        if clearnet_servers:
            for srv in clearnet_servers:
                if isinstance(srv, str):
                    user_clearnet.append(_parse_server_string(srv))
                elif isinstance(srv, dict):
                    user_clearnet.append(srv)

        user_onion = []
        if onion_servers:
            for srv in onion_servers:
                if isinstance(srv, str):
                    user_onion.append(_parse_server_string(srv))
                elif isinstance(srv, dict):
                    user_onion.append(srv)

        final_onion = (
            user_onion if user_onion else DEFAULT_ONION_SERVERS.get(coin_name, [])
        )

        self._using_default_servers = not user_clearnet and not user_onion

        if use_tor:
            if user_onion and not user_clearnet:
                final_clearnet = []
            else:
                final_clearnet = (
                    user_clearnet
                    if user_clearnet
                    else DEFAULT_ELECTRUM_SERVERS.get(coin_name, [])
                )
            self._servers = list(final_onion) + list(final_clearnet)
            if self._log:
                self._log.info(
                    f"ElectrumServer {coin_name}: TOR enabled - "
                    f"{len(final_onion)} .onion + {len(final_clearnet)} clearnet servers"
                )
        else:
            final_clearnet = (
                user_clearnet
                if user_clearnet
                else DEFAULT_ELECTRUM_SERVERS.get(coin_name, [])
            )
            self._servers = list(final_clearnet)
            if self._log:
                self._log.info(
                    f"ElectrumServer {coin_name}: {len(final_clearnet)} clearnet servers"
                )

    def _get_server(self, index):
        if not self._servers:
            raise ValueError(f"No Electrum servers configured for {self._coin_name}")
        return self._servers[index % len(self._servers)]

    def connect(self):
        if self._stopping:
            return
        sorted_servers = self.get_sorted_servers()
        for server in sorted_servers:
            try:
                start_time = time.time()
                conn = ElectrumConnection(
                    server["host"],
                    server["port"],
                    server.get("ssl", True),
                    log=self._log,
                    proxy_host=self._proxy_host,
                    proxy_port=self._proxy_port,
                )
                conn.connect()
                connect_time = (time.time() - start_time) * 1000
                version_info = conn.get_server_version()
                if version_info and len(version_info) > 0:
                    self._server_version = version_info[0]
                prev_host = self._current_server_host
                prev_port = self._current_server_port
                self._current_server_host = server["host"]
                self._current_server_port = server["port"]
                self._connection = conn
                self._current_server_idx = self._servers.index(server)
                self._connection_failures = 0
                self._last_connection_error = None
                self._all_servers_failed = False
                self._update_server_score(server, success=True, latency_ms=connect_time)
                self._last_activity = time.time()
                self._last_reconnect_time = time.time()
                if self._log:
                    if not self._initial_connection_logged:
                        self._log.info(
                            f"Connected to Electrum server: {server['host']}:{server['port']} "
                            f"({self._server_version}, {connect_time:.0f}ms)"
                        )
                        self._initial_connection_logged = True
                    elif server["host"] != prev_host or server["port"] != prev_port:
                        self._log.info(
                            f"Switched to Electrum server: {server['host']}:{server['port']} "
                            f"({connect_time:.0f}ms)"
                        )
                if self._stopping:
                    conn.disconnect()
                    self._connection = None
                    return
                if self._realtime_enabled:
                    self._start_realtime_listener()
                self._start_keepalive()
                self._connection.register_header_callback(self._on_header_update)
                self._subscribe_headers()
                return True
            except Exception as e:
                self._connection_failures += 1
                self._last_connection_error = str(e)
                self._update_server_score(server, success=False)
                if self._is_rate_limit_error(str(e)):
                    self._blacklist_server(server, str(e))
                continue
        self._all_servers_failed = True
        raise TemporaryError(
            f"Failed to connect to any Electrum server for {self._coin_name}"
        )

    def getConnectionStatus(self):
        return {
            "connected": self._connection is not None
            and self._connection.is_connected(),
            "failures": self._connection_failures,
            "last_error": self._last_connection_error,
            "all_failed": self._all_servers_failed,
            "using_defaults": self._using_default_servers,
            "server_count": len(self._servers) if self._servers else 0,
        }

    def get_server_version(self):
        return self._server_version

    def get_current_server(self):
        return self._current_server_host, self._current_server_port

    def _get_server_key(self, server):
        return f"{server['host']}:{server['port']}"

    def _update_server_score(self, server, success: bool, latency_ms: float = None):
        key = self._get_server_key(server)
        if key not in self._server_scores:
            self._server_scores[key] = {"latency": 0, "failures": 0, "successes": 0}

        score = self._server_scores[key]
        if success:
            score["successes"] += 1
            if latency_ms is not None:
                if score["latency"] == 0:
                    score["latency"] = latency_ms
                else:
                    score["latency"] = score["latency"] * 0.7 + latency_ms * 0.3
        else:
            score["failures"] += 1

    def _get_server_score(self, server) -> float:
        key = self._get_server_key(server)
        if key not in self._server_scores:
            return 1000

        score = self._server_scores[key]
        total = score["successes"] + score["failures"]
        if total == 0:
            return 1000

        failure_rate = score["failures"] / total
        return score["latency"] + (failure_rate * 5000)

    def get_sorted_servers(self) -> list:
        now = time.time()
        available_servers = []
        for s in self._servers:
            key = self._get_server_key(s)
            if key in self._server_blacklist:
                if now < self._server_blacklist[key]:
                    continue
                else:
                    del self._server_blacklist[key]
            available_servers.append(s)

        if not available_servers and self._servers:
            if self._log:
                self._log.warning("All servers blacklisted, clearing blacklist")
            self._server_blacklist.clear()
            available_servers = list(self._servers)

        return sorted(available_servers, key=lambda s: self._get_server_score(s))

    def _blacklist_server(self, server, reason: str = ""):
        key = self._get_server_key(server)
        self._server_blacklist[key] = time.time() + self._rate_limit_backoff
        if self._log:
            self._log.warning(
                f"Blacklisted server {key} for {self._rate_limit_backoff}s: {reason}"
            )

    def _is_rate_limit_error(self, error_msg: str) -> bool:
        rate_limit_patterns = [
            "excessive resource usage",
            "rate limit",
            "too many requests",
            "throttled",
            "banned",
        ]
        error_lower = error_msg.lower()
        return any(pattern in error_lower for pattern in rate_limit_patterns)

    def _on_header_update(self, height: int):
        if height > self._subscribed_height:
            self._subscribed_height = height
            self._subscribed_height_time = time.time()
            if self._log:
                self._log.debug(f"Header subscription updated height to {height}")
            if self._height_callback:
                try:
                    self._height_callback(height)
                except Exception as e:
                    if self._log:
                        self._log.debug(f"Height callback error: {e}")

    def _subscribe_headers(self):
        try:
            if self._connection:
                self._connection._start_listener()
                result = self._connection.call(
                    "blockchain.headers.subscribe", [], timeout=20
                )
                if result and isinstance(result, dict):
                    height = result.get("height", 0)
                    if height > 0:
                        self._on_header_update(height)
        except Exception:
            pass

    def register_height_callback(self, callback):
        self._height_callback = callback

    def get_subscribed_height(self) -> int:
        return self._subscribed_height

    def recently_reconnected(self, grace_seconds: int = 30) -> bool:
        if self._last_reconnect_time == 0:
            return False
        return (time.time() - self._last_reconnect_time) < grace_seconds

    def get_server_scores(self) -> dict:
        return {
            self._get_server_key(s): {
                **self._server_scores.get(self._get_server_key(s), {}),
                "score": self._get_server_score(s),
            }
            for s in self._servers
        }

    def _start_keepalive(self):
        if self._keepalive_running:
            return
        self._keepalive_running = True
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop, daemon=True
        )
        self._keepalive_thread.start()
        if self._log:
            self._log.debug(
                f"Electrum keepalive started for {self._coin_name} "
                f"(interval={self._keepalive_interval}s)"
            )

    def _stop_keepalive(self):
        self._keepalive_running = False
        if self._keepalive_thread:
            self._keepalive_thread.join(timeout=2)
            self._keepalive_thread = None

    def _keepalive_loop(self):
        while self._keepalive_running:
            try:
                for _ in range(self._keepalive_interval):
                    if not self._keepalive_running:
                        return
                    time.sleep(1)

                now = time.time()
                if now - self._last_activity >= self._keepalive_interval:
                    if self._connection and self._connection.is_connected():
                        if self._lock.acquire(blocking=False):
                            try:
                                self._connection.call("server.ping")
                                self._last_activity = time.time()
                            except Exception:
                                pass
                            finally:
                                self._lock.release()
            except Exception:
                pass

    def _throttle_request(self):
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._min_request_interval:
            time.sleep(self._min_request_interval - elapsed)
        self._last_request_time = time.time()

    def _retry_on_failure(self):
        if self._stopping:
            return
        self._current_server_idx = (self._current_server_idx + 1) % len(self._servers)
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
        self._connection = None
        time.sleep(0.3)
        self.connect()

    def _check_connection_health(self, timeout=5) -> bool:
        if self._connection is None or not self._connection.is_connected():
            return False
        try:
            self._connection.call("server.ping", [], timeout=timeout)
            return True
        except Exception as e:
            if self._log:
                self._log.debug(f"Connection health check failed: {e}")
            return False

    def call(self, method, params=None, timeout=10):
        if self._stopping:
            raise TemporaryError("Electrum server is shutting down")
        self._throttle_request()
        lock_acquired = self._lock.acquire(timeout=timeout + 5)
        if not lock_acquired:
            raise TemporaryError(f"Electrum call timed out waiting for lock: {method}")
        try:
            for attempt in range(2):
                if self._stopping:
                    raise TemporaryError("Electrum server is shutting down")
                if self._connection is None or not self._connection.is_connected():
                    self.connect()
                    if self._connection is None:
                        raise TemporaryError("Failed to establish Electrum connection")
                elif (time.time() - self._last_activity) > 60:
                    if not self._check_connection_health():
                        self._retry_on_failure()
                        if self._connection is None:
                            raise TemporaryError(
                                "Failed to re-establish Electrum connection"
                            )
                try:
                    result = self._connection.call(method, params, timeout=timeout)
                    self._last_activity = time.time()
                    return result
                except Exception as e:
                    if self._is_rate_limit_error(str(e)):
                        server = self._get_server(self._current_server_idx)
                        self._blacklist_server(server, str(e))
                    if attempt == 0:
                        self._retry_on_failure()
                    else:
                        raise
        finally:
            self._lock.release()

    def call_batch(self, requests, timeout=15):
        if self._stopping:
            raise TemporaryError("Electrum server is shutting down")
        self._throttle_request()
        lock_acquired = self._lock.acquire(timeout=timeout + 5)
        if not lock_acquired:
            raise TemporaryError("Electrum batch call timed out waiting for lock")
        try:
            for attempt in range(2):
                if self._stopping:
                    raise TemporaryError("Electrum server is shutting down")
                if self._connection is None or not self._connection.is_connected():
                    self.connect()
                    if self._connection is None:
                        raise TemporaryError("Failed to establish Electrum connection")
                elif (time.time() - self._last_activity) > 60:
                    if not self._check_connection_health():
                        self._retry_on_failure()
                        if self._connection is None:
                            raise TemporaryError(
                                "Failed to re-establish Electrum connection"
                            )
                try:
                    result = self._connection.call_batch(requests)
                    self._last_activity = time.time()
                    return result
                except Exception as e:
                    if self._is_rate_limit_error(str(e)):
                        server = self._get_server(self._current_server_idx)
                        self._blacklist_server(server, str(e))
                    if attempt == 0:
                        self._retry_on_failure()
                    else:
                        raise
        finally:
            self._lock.release()

    def _connect_user(self):
        if self._stopping:
            return False
        sorted_servers = self.get_sorted_servers()
        for server in sorted_servers:
            try:
                conn = ElectrumConnection(
                    server["host"],
                    server["port"],
                    server.get("ssl", True),
                    log=self._log,
                    proxy_host=self._proxy_host,
                    proxy_port=self._proxy_port,
                )
                conn.connect()
                conn.get_server_version()
                self._user_connection = conn
                self._user_last_activity = time.time()
                if self._log:
                    if not self._user_connection_logged:
                        self._log.debug(
                            f"User connection established to {server['host']}"
                        )
                        self._user_connection_logged = True
                    else:
                        self._log.debug(
                            f"User connection reconnected to {server['host']}"
                        )
                return True
            except Exception as e:
                if self._log:
                    self._log.debug(f"User connection failed to {server['host']}: {e}")
                continue
        return False

    def _record_timeout(self):
        if self._stopping:
            return
        now = time.time()
        if (
            now - self._last_timeout_time
        ) > self._timeout_decay_seconds and self._last_timeout_time > 0:
            self._consecutive_timeouts = 0
        self._consecutive_timeouts += 1
        self._last_timeout_time = now
        if self._consecutive_timeouts >= self._max_consecutive_timeouts:
            server = self._get_server(self._current_server_idx)
            reason = f"{self._consecutive_timeouts} consecutive timeouts"
            self._blacklist_server(server, reason)
            self._consecutive_timeouts = 0
            self._last_timeout_time = 0
            try:
                self._retry_on_failure()
            except Exception:
                pass

    def call_background(self, method, params=None, timeout=20):
        if self._stopping:
            raise TemporaryError("Electrum server is shutting down")
        lock_acquired = self._lock.acquire(timeout=timeout + 5)
        if not lock_acquired:
            raise TemporaryError(
                f"Electrum background call timed out waiting for lock: {method}"
            )
        try:
            for attempt in range(2):
                if self._stopping:
                    raise TemporaryError("Electrum server is shutting down")
                if self._connection is None or not self._connection.is_connected():
                    self.connect()
                    if self._connection is None:
                        raise TemporaryError("Electrum call failed: no connection")
                try:
                    result = self._connection.call(method, params, timeout=timeout)
                    self._last_activity = time.time()
                    return result
                except TemporaryError as e:
                    if self._stopping:
                        raise TemporaryError("Electrum server is shutting down")
                    if "timed out" in str(e).lower():
                        self._record_timeout()
                    if attempt == 0:
                        self._retry_on_failure()
                    else:
                        raise
                except Exception as e:
                    if self._is_rate_limit_error(str(e)):
                        server = self._get_server(self._current_server_idx)
                        self._blacklist_server(server, str(e))
                    if attempt == 0:
                        self._retry_on_failure()
                    else:
                        raise
        finally:
            self._lock.release()

    def call_batch_background(self, requests, timeout=30):
        if self._stopping:
            raise TemporaryError("Electrum server is shutting down")
        lock_acquired = self._lock.acquire(timeout=timeout + 5)
        if not lock_acquired:
            raise TemporaryError(
                "Electrum background batch call timed out waiting for lock"
            )
        try:
            for attempt in range(2):
                if self._stopping:
                    raise TemporaryError("Electrum server is shutting down")
                if self._connection is None or not self._connection.is_connected():
                    self.connect()
                    if self._connection is None:
                        raise TemporaryError(
                            "Electrum batch call failed: no connection"
                        )
                try:
                    result = self._connection.call_batch(requests)
                    self._last_activity = time.time()
                    return result
                except TemporaryError as e:
                    if self._stopping:
                        raise TemporaryError("Electrum server is shutting down")
                    if "timed out" in str(e).lower():
                        self._record_timeout()
                    if attempt == 0:
                        self._retry_on_failure()
                    else:
                        raise
                except Exception as e:
                    if self._is_rate_limit_error(str(e)):
                        server = self._get_server(self._current_server_idx)
                        self._blacklist_server(server, str(e))
                    if attempt == 0:
                        self._retry_on_failure()
                    else:
                        raise
        finally:
            self._lock.release()

    def call_user(self, method, params=None, timeout=10):
        if self._stopping:
            raise TemporaryError("Electrum server is shutting down")
        lock_acquired = self._user_lock.acquire(timeout=timeout + 2)
        if not lock_acquired:
            raise TemporaryError(f"User connection busy: {method}")

        try:
            if (
                self._user_connection is None
                or not self._user_connection.is_connected()
            ):
                if not self._connect_user():
                    raise TemporaryError("User connection unavailable")

            try:
                result = self._user_connection.call(method, params, timeout=timeout)
                self._user_last_activity = time.time()
                return result
            except Exception as e:
                if self._log:
                    self._log.debug(f"User call failed ({method}): {e}")
                if self._user_connection:
                    try:
                        self._user_connection.disconnect()
                    except Exception:
                        pass
                    self._user_connection = None

                if self._connect_user():
                    try:
                        result = self._user_connection.call(
                            method, params, timeout=timeout
                        )
                        self._user_last_activity = time.time()
                        return result
                    except Exception as e2:
                        raise TemporaryError(f"User call failed: {e2}")

                raise TemporaryError(f"User call failed: {e}")
        finally:
            self._user_lock.release()

    def call_batch_user(self, requests, timeout=15):
        if self._stopping:
            raise TemporaryError("Electrum server is shutting down")
        lock_acquired = self._user_lock.acquire(timeout=timeout + 2)
        if not lock_acquired:
            raise TemporaryError("User connection busy")

        try:
            if (
                self._user_connection is None
                or not self._user_connection.is_connected()
            ):
                if not self._connect_user():
                    raise TemporaryError("User connection unavailable")

            try:
                result = self._user_connection.call_batch(requests)
                self._user_last_activity = time.time()
                return result
            except Exception as e:
                if self._log:
                    self._log.debug(f"User batch call failed: {e}")
                if self._user_connection:
                    try:
                        self._user_connection.disconnect()
                    except Exception:
                        pass
                    self._user_connection = None

                if self._connect_user():
                    try:
                        result = self._user_connection.call_batch(requests)
                        self._user_last_activity = time.time()
                        return result
                    except Exception as e2:
                        raise TemporaryError(f"User batch call failed: {e2}")

                raise TemporaryError(f"User batch call failed: {e}")
        finally:
            self._user_lock.release()

    def disconnect(self):
        self._stop_keepalive()
        lock_acquired = self._lock.acquire(timeout=5)
        if lock_acquired:
            try:
                if self._connection:
                    self._connection.disconnect()
                    self._connection = None
            finally:
                self._lock.release()
        else:
            conn = self._connection
            if conn:
                try:
                    conn.disconnect()
                except Exception:
                    pass
        with self._user_lock:
            if self._user_connection:
                try:
                    self._user_connection.disconnect()
                except Exception:
                    pass
                self._user_connection = None
                self._user_connection_logged = False

    def shutdown(self):
        self._stopping = True
        self.disconnect()

    def get_balance(self, scripthash):
        result = self.call("blockchain.scripthash.get_balance", [scripthash])
        return result

    def get_balance_batch(self, scripthashes):
        requests = [("blockchain.scripthash.get_balance", [sh]) for sh in scripthashes]
        return self.call_batch(requests)

    def get_history(self, scripthash):
        return self.call("blockchain.scripthash.get_history", [scripthash])

    def get_transaction(self, txid, verbose=False):
        return self.call("blockchain.transaction.get", [txid, verbose])

    def estimate_fee(self, num_blocks):
        result = self.call("blockchain.estimatefee", [num_blocks])
        return result

    def get_merkle(self, txid, height):
        return self.call("blockchain.transaction.get_merkle", [txid, height])

    def enable_realtime_notifications(self):
        self._realtime_enabled = True
        if self._connection and self._connection.is_connected():
            self._start_realtime_listener()
        if self._log:
            self._log.info(
                f"Electrum real-time notifications enabled for {self._coin_name}"
            )

    def _start_realtime_listener(self):
        if self._connection:
            for sh, callback in self._notification_callbacks.items():
                self._connection.register_notification_callback(sh, callback)
            self._connection._start_listener()
            self._resubscribe_all()

    def _resubscribe_all(self):
        for scripthash in list(self._subscribed_scripthashes):
            try:
                self.call("blockchain.scripthash.subscribe", [scripthash])
            except Exception as e:
                if self._log:
                    self._log.debug(
                        f"Failed to resubscribe to {scripthash[:16]}...: {e}"
                    )

    def subscribe_with_callback(self, scripthash, callback):
        self._notification_callbacks[scripthash] = callback
        self._subscribed_scripthashes.add(scripthash)

        if self._connection:
            self._connection.register_notification_callback(scripthash, callback)

        status = self.call("blockchain.scripthash.subscribe", [scripthash])
        return status

    def discover_peers(self):
        try:
            peers = self.call("server.peers.subscribe")
            if not peers:
                return []

            discovered = []
            for peer in peers:
                if not isinstance(peer, list) or len(peer) < 3:
                    continue

                ip_addr = peer[0]
                hostname = peer[1]
                features = peer[2] if len(peer) > 2 else []

                host = hostname if hostname else ip_addr
                is_onion = host.endswith(".onion")

                ssl_port = None
                tcp_port = None

                for feature in features:
                    if isinstance(feature, str):
                        if feature.startswith("s"):
                            port_str = feature[1:]
                            ssl_port = int(port_str) if port_str else 50002
                        elif feature.startswith("t"):
                            port_str = feature[1:]
                            tcp_port = int(port_str) if port_str else 50001

                if is_onion:
                    if tcp_port:
                        discovered.append(
                            {
                                "host": host,
                                "port": tcp_port,
                                "ssl": False,
                                "is_onion": True,
                            }
                        )
                    elif ssl_port:
                        discovered.append(
                            {
                                "host": host,
                                "port": ssl_port,
                                "ssl": True,
                                "is_onion": True,
                            }
                        )
                else:
                    if ssl_port:
                        discovered.append(
                            {
                                "host": host,
                                "port": ssl_port,
                                "ssl": True,
                                "is_onion": False,
                            }
                        )
                    elif tcp_port:
                        discovered.append(
                            {
                                "host": host,
                                "port": tcp_port,
                                "ssl": False,
                                "is_onion": False,
                            }
                        )

            return discovered

        except Exception as e:
            if self._log:
                self._log.debug(f"discover_peers failed: {e}")
            return []

    def ping_server(self, host, port, ssl=True, timeout=5):
        try:
            test_conn = ElectrumConnection(
                host,
                port,
                ssl,
                log=self._log,
                proxy_host=self._proxy_host,
                proxy_port=self._proxy_port,
            )
            test_conn.connect()
            latency = test_conn.ping()
            test_conn.disconnect()
            return latency
        except Exception:
            return None

    def get_current_server_info(self):
        return {
            "host": self._current_server_host,
            "port": self._current_server_port,
            "version": self._server_version,
        }
