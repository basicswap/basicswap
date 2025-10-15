# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import traceback
import urllib
import http.client
from xmlrpc.client import (
    Fault,
    Transport,
    SafeTransport,
)
from .util import jsonDecimal

_use_rpc_pooling = False
_rpc_pool_settings = {}


def enable_rpc_pooling(settings):
    global _use_rpc_pooling, _rpc_pool_settings
    _use_rpc_pooling = settings.get("enabled", False)
    _rpc_pool_settings = settings


class TimeoutTransport(Transport):
    def __init__(self, timeout=10, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def make_connection(self, host):
        conn = http.client.HTTPConnection(host, timeout=self.timeout)
        return conn


class TimeoutSafeTransport(SafeTransport):
    def __init__(self, timeout=10, *args, **kwargs):
        self.timeout = timeout
        super().__init__(*args, **kwargs)

    def make_connection(self, host):
        conn = http.client.HTTPSConnection(host, timeout=self.timeout)
        return conn


class Jsonrpc:
    # __getattr__ complicates extending ServerProxy
    def __init__(
        self,
        uri,
        transport=None,
        encoding=None,
        verbose=False,
        allow_none=False,
        use_datetime=False,
        use_builtin_types=False,
        *,
        context=None,
        timeout=10,
    ):
        # establish a "logical" server connection

        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme not in ("http", "https"):
            raise OSError("unsupported XML-RPC protocol")

        self.__auth = None
        if "@" in parsed.netloc:
            auth_part, host_port = parsed.netloc.rsplit("@", 1)
            self.__host = host_port
            if ":" in auth_part:
                import base64

                auth_bytes = auth_part.encode("utf-8")
                auth_b64 = base64.b64encode(auth_bytes).decode("ascii")
                self.__auth = f"Basic {auth_b64}"
        else:
            self.__host = parsed.netloc

        if not self.__host:
            raise ValueError(f"Invalid or empty hostname in URI: {uri}")
        self.__handler = parsed.path
        if not self.__handler:
            self.__handler = "/RPC2"

        if transport is None:
            handler = (
                TimeoutSafeTransport if parsed.scheme == "https" else TimeoutTransport
            )
            extra_kwargs = {}
            transport = handler(
                timeout=timeout,
                use_datetime=use_datetime,
                use_builtin_types=use_builtin_types,
                **extra_kwargs,
            )
        self.__transport = transport

        self.__encoding = encoding or "utf-8"
        self.__verbose = verbose
        self.__allow_none = allow_none

        self.__request_id = 1

    def close(self):
        if self.__transport is not None:
            self.__transport.close()

    def json_request(self, method, params):
        connection = None
        try:
            connection = self.__transport.make_connection(self.__host)
            headers = self.__transport._extra_headers[:]

            request_body = {"method": method, "params": params, "id": self.__request_id}

            connection.putrequest("POST", self.__handler)
            headers.append(("Content-Type", "application/json"))
            headers.append(("User-Agent", "jsonrpc"))

            if self.__auth:
                headers.append(("Authorization", self.__auth))

            self.__transport.send_headers(connection, headers)
            self.__transport.send_content(
                connection,
                json.dumps(request_body, default=jsonDecimal).encode("utf-8"),
            )
            self.__request_id += 1

            resp = connection.getresponse()
            result = resp.read()

            connection.close()

            return result

        except Fault:
            raise
        except Exception:
            self.__transport.close()
            raise
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def callrpc(rpc_port, auth, method, params=[], wallet=None, host="127.0.0.1"):
    if _use_rpc_pooling:
        return callrpc_pooled(rpc_port, auth, method, params, wallet, host)

    try:
        url = "http://{}@{}:{}/".format(auth, host, rpc_port)
        if wallet is not None:
            url += "wallet/" + urllib.parse.quote(wallet)
        x = Jsonrpc(url)

        v = x.json_request(method, params)
        x.close()
        r = json.loads(v.decode("utf-8"))
    except Exception as ex:
        raise ValueError(f"RPC server error: {ex}, method: {method}")

    if "error" in r and r["error"] is not None:
        raise ValueError("RPC error " + str(r["error"]))

    return r["result"]


def callrpc_pooled(rpc_port, auth, method, params=[], wallet=None, host="127.0.0.1"):
    from .rpc_pool import get_rpc_pool
    import http.client
    import socket

    url = "http://{}@{}:{}/".format(auth, host, rpc_port)
    if wallet is not None:
        url += "wallet/" + urllib.parse.quote(wallet)

    max_connections = _rpc_pool_settings.get("max_connections_per_daemon", 5)
    pool = get_rpc_pool(url, max_connections)

    max_retries = 2

    for attempt in range(max_retries):
        conn = pool.get_connection()

        try:
            v = conn.json_request(method, params)
            r = json.loads(v.decode("utf-8"))

            if "error" in r and r["error"] is not None:
                pool.discard_connection(conn)
                raise ValueError("RPC error " + str(r["error"]))

            pool.return_connection(conn)
            return r["result"]

        except (
            http.client.RemoteDisconnected,
            http.client.IncompleteRead,
            http.client.BadStatusLine,
            ConnectionError,
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
            TimeoutError,
            socket.timeout,
            socket.error,
            OSError,
        ) as ex:
            pool.discard_connection(conn)
            if attempt < max_retries - 1:
                continue
            logging.warning(
                f"RPC server error after {max_retries} attempts: {ex}, method: {method}"
            )
            raise ValueError(f"RPC server error: {ex}, method: {method}")
        except ValueError:
            raise
        except Exception as ex:
            pool.discard_connection(conn)
            logging.error(f"Unexpected RPC error: {ex}, method: {method}")
            raise ValueError(f"RPC server error: {ex}, method: {method}")


def openrpc(rpc_port, auth, wallet=None, host="127.0.0.1"):
    try:
        url = "http://{}@{}:{}/".format(auth, host, rpc_port)
        if wallet is not None:
            url += "wallet/" + urllib.parse.quote(wallet)
        return Jsonrpc(url)
    except Exception as ex:
        traceback.print_exc()
        raise ValueError(f"RPC error: {ex}")


def make_rpc_func(port, auth, wallet=None, host="127.0.0.1"):
    port = port
    auth = auth
    wallet = wallet
    host = host

    def rpc_func(method, params=None, wallet_override=None):
        return callrpc(
            port,
            auth,
            method,
            params,
            wallet if wallet_override is None else wallet_override,
            host,
        )

    return rpc_func


def escape_rpcauth(auth_str: str) -> str:
    username, password = auth_str.split(":", 1)
    username = urllib.parse.quote(username, safe="")
    password = urllib.parse.quote(password, safe="")
    return f"{username}:{password}"
