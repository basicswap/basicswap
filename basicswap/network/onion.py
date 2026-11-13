# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import socket
import time

from Crypto.PublicKey import ECC  # pycryptodome

from basicswap.util import ensure


class Onion:
    def waitForTor(self) -> None:
        time_limit: int = self.get_clamped_int_from(
            self.settings, "startup_timeout", 600, 1
        )
        started_at: float = time.time()
        last_logged_at: float = 0.0
        while True:
            rv = self.torControl("GETINFO status/circuit-established", log_errors=False)
            if rv is not None and b"circuit-established=1" in rv:
                self.log.info("Tor is up.")
                return
            ensure(
                rv is None or not rv.startswith(b"515"),
                "Tor control password rejected",
            )
            now: float = time.time()
            waited: int = int(now - started_at)
            ensure(waited < time_limit, "Can't reach Tor")
            if now - last_logged_at >= 30:
                last_logged_at = now
                state = "no circuit yet" if rv else "control port unreachable"
                self.log.info(f"Waiting for Tor: {state}, {waited}/{time_limit}s.")
            time.sleep(1)

    def _torCommand(self, query: str) -> list:
        """The reply lines to query, without AUTHENTICATE's and QUIT's."""
        rv = self.torControl(query)
        ensure(rv is not None, "Tor control port unreachable")
        auth, *lines = rv.decode("utf-8").split("\r\n")
        ensure(auth.startswith("250"), f"Tor: {auth}")
        return lines[:-2]

    def _onionTarget(self, host: str) -> str:
        if host not in ("0.0.0.0", "::"):
            return host
        # This host's address on the route to Tor, which is where Tor connects.
        family, kind, _, _, addr = socket.getaddrinfo(
            self.tor_proxy_host, self.tor_control_port, type=socket.SOCK_DGRAM
        )[0]
        with socket.socket(family, kind) as s:
            s.connect(addr)
            return s.getsockname()[0]

    def _addOnionService(self, key: str, client_keys: list) -> dict:
        # Detached services last until Tor restarts.
        ports = [(self.settings["htmlhost"], self.settings["htmlport"])]
        if "wshost" in self.settings:
            ports.append((self.settings["wshost"], self.settings["wsport"]))
        mappings = " ".join(f"Port={p},{self._onionTarget(h)}:{p}" for h, p in ports)
        auth = "".join(f" ClientAuthV3={k}" for k in client_keys)
        flags = "Detach,V3Auth" if client_keys else "Detach"
        fields = {}
        for line in self._torCommand(f"ADD_ONION {key} Flags={flags} {mappings}{auth}"):
            ensure(not line.startswith("5"), f"Tor: {line}")
            name, sep, value = line[4:].partition("=")
            if line.startswith("250-") and sep:
                fields[name] = value
        return fields

    def _delOnionService(self, host: str) -> None:
        reply = self._torCommand(f"DEL_ONION {host.removesuffix('.onion')}")[-1]
        # 552: Tor doesn't have it.
        ensure(reply.startswith(("250", "552")), f"Tor: {reply}")

    def _onionServiceUp(self, host: str) -> bool:
        service_id = host.removesuffix(".onion")
        lines = self._torCommand("GETINFO onions/detached")
        return service_id in lines or f"250-onions/detached={service_id}" in lines

    def onionRequiresAuth(self) -> bool:
        return self.settings.get("onion_require_auth", True)

    def _onionClientKeys(self) -> list:
        if not self.onionRequiresAuth():
            return []
        return [c["key"] for c in self.settings.get("onion_clients", [])]

    @staticmethod
    def _newOnionClient(name: str) -> tuple:
        name = name.strip()
        ensure(name, "Name the client")
        key = ECC.generate(curve="curve25519")
        public = key.public_key().export_key(format="raw")

        def b32(data: bytes) -> str:
            return base64.b32encode(data).decode().rstrip("=")

        return {"name": name, "key": b32(public)}, b32(key.seed)

    def addOnion(self, client_name: str = "") -> str | None:
        """Returns the first client's private key, which is not kept."""
        ensure(self.use_tor_proxy, "Tor mode is off")
        # Onion requests come from loopback, which the seed export trusts.
        ensure(self.settings.get("client_auth_hash"), "Set a client password first")
        if self.settings.get("onion_host"):
            return None
        clients, private = [], None
        if self.onionRequiresAuth():
            # Tor refuses V3Auth without a key.
            client, private = self._newOnionClient(client_name)
            clients = [client]
        with self.mxDB:
            fields = self._addOnionService(
                "NEW:ED25519-V3", [c["key"] for c in clients]
            )
            host = fields["ServiceID"] + ".onion"
            self.settings["onion_clients"] = clients
            self.settings["onion_published"] = self._onionPublication()
            self.settings["onion_key"] = fields["PrivateKey"]
            self.settings["onion_host"] = host
            # The Host check would otherwise turn away every request to it.
            allowed = self.settings.get("allowed_hosts", [])
            self.settings["allowed_hosts"] = allowed + [host]
            self._save_settings()
        self.log.info("Added the onion address")
        return private

    def addOnionClient(self, name: str) -> str:
        """Returns the client's private key, which is not kept."""
        ensure(self.settings.get("onion_host"), "No onion address")
        client, private = self._newOnionClient(name)
        with self.mxDB:
            clients = self.settings.get("onion_clients", [])
            self.settings["onion_clients"] = clients + [client]
            self._save_settings()
        self._ensureOnion()
        self.log.info("Added an onion client")
        return private

    def removeOnionClient(self, key: str) -> None:
        with self.mxDB:
            self.settings["onion_clients"] = [
                c for c in self.settings.get("onion_clients", []) if c["key"] != key
            ]
            self._save_settings()
        self._ensureOnion(raise_errors=True)
        self.log.info("Removed an onion client")

    def setOnionRequiresAuth(self, required: bool) -> None:
        with self.mxDB:
            self.settings["onion_require_auth"] = required
            self._save_settings()
        self._ensureOnion(raise_errors=True)

    def setClientAuthHash(self, new_hash: str) -> None:
        with self._onion_lock:
            published = "onion_published" in self.settings
            if not new_hash and self.use_tor_proxy and published:
                # Keeps the password if the open onion can't be taken down.
                self._delOnionService(self.settings["onion_host"])
            self.editGeneralSettings({"client_auth_hash": new_hash})
            self._ensureOnionLocked()

    def removeOnion(self) -> None:
        with self._onion_lock:
            host = self.settings.get("onion_host")
            if host is None:
                return
            self._delOnionService(host)
            with self.mxDB:
                for name in (
                    "onion_host",
                    "onion_key",
                    "onion_clients",
                    "onion_published",
                ):
                    self.settings.pop(name, None)
                self.settings["allowed_hosts"] = [
                    h for h in self.settings.get("allowed_hosts", []) if h != host
                ]
                self._save_settings()
        self.log.info("Removed the onion address")

    def _onionPublication(self) -> list | None:
        """The client keys Tor should require, [] for none, or None to not publish."""
        if not self.settings.get("client_auth_hash"):
            return None
        if not self.onionRequiresAuth():
            return []
        return self._onionClientKeys() or None

    def _ensureOnion(self, raise_errors: bool = False) -> None:
        with self._onion_lock:
            self._ensureOnionLocked(raise_errors)

    def _ensureOnionLocked(self, raise_errors: bool = False) -> None:
        self._last_checked_onion = self.getTime()
        key = self.settings.get("onion_key")
        if not key or not self.use_tor_proxy:
            return
        host = self.settings["onion_host"]
        wanted = self._onionPublication()
        try:
            if self.settings.get("onion_published") == wanted and (
                wanted is None or self._onionServiceUp(host)
            ):
                return
            # Tor can't change a service's clients, and re-adding moves its
            # intro points.
            self._delOnionService(host)
            if wanted is None:
                with self.mxDB:
                    self.settings.pop("onion_published", None)
                    self._save_settings()
            else:
                self._addOnionService(key, wanted)
                with self.mxDB:
                    self.settings["onion_published"] = wanted
                    self._save_settings()
        except Exception as e:
            if raise_errors:
                raise
            self.log.warning(f"Onion address not published: {e}")
