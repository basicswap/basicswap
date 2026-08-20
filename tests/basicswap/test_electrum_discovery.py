# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from unittest.mock import MagicMock, patch

from basicswap.interface.electrumx import (
    ElectrumConnection,
    ElectrumServer,
    _is_private_address,
    _resolves_to_private_address,
)

PEERS = [
    ["1.2.3.4", "electrum.example.com", ["v1.4", "s50002"]],
    ["127.0.0.1", "127.0.0.1", ["v1.4", "t50001"]],
    ["10.0.0.5", "", ["v1.4", "s50002"]],
    ["169.254.169.254", "169.254.169.254", ["v1.4", "t80"]],
    ["192.168.1.5", "public-name.example.com", ["v1.4", "s50002"]],
    ["5.6.7.8", "localhost", ["v1.4", "t50001"]],
    ["", "abcdefghij.onion", ["v1.4", "t50001"]],
]


def make_server(proxy_host=None, proxy_port=None):
    server = ElectrumServer.__new__(ElectrumServer)
    server._log = None
    server._proxy_host = proxy_host
    server._proxy_port = proxy_port
    server._cert_pins = MagicMock()
    server._coin_name = "bitcoin"
    return server


class DiscoverPeersTest(unittest.TestCase):
    def test_private_peers_filtered(self):
        server = make_server()
        server.call = lambda method: PEERS
        discovered = server.discover_peers()
        hosts = [p["host"] for p in discovered]
        self.assertEqual(hosts, ["electrum.example.com", "abcdefghij.onion"])

    def test_private_real_ip_filtered_despite_public_hostname(self):
        server = make_server()
        server.call = lambda method: [PEERS[4]]
        self.assertEqual(server.discover_peers(), [])


class PingServerTest(unittest.TestCase):
    def test_refuses_private_ip(self):
        server = make_server()
        with patch("basicswap.interface.electrumx.ElectrumConnection") as mock_conn:
            self.assertIsNone(server.ping_server("127.0.0.1", 50001))
            self.assertIsNone(server.ping_server("192.168.1.5", 50002))
            self.assertIsNone(server.ping_server("localhost", 50001))
            mock_conn.assert_not_called()

    def test_refuses_hostname_resolving_private_without_proxy(self):
        server = make_server()
        with patch(
            "basicswap.interface.electrumx._resolves_to_private_address",
            return_value=True,
        ):
            with patch("basicswap.interface.electrumx.ElectrumConnection") as mock_conn:
                self.assertIsNone(server.ping_server("evil.example.com", 50002))
                mock_conn.assert_not_called()

    def test_discovered_peer_never_bypasses_proxy(self):
        server = make_server(proxy_host="127.0.0.1", proxy_port=9050)
        with patch("basicswap.interface.electrumx.ElectrumConnection") as mock_conn:
            mock_conn.return_value.ping.return_value = 42
            latency = server.ping_server("electrum.example.com", 50002)
            self.assertEqual(latency, 42)
            self.assertFalse(mock_conn.call_args.kwargs["allow_lan_bypass"])


class OpenSocketProxyTest(unittest.TestCase):
    def _make_conn(self, allow_lan_bypass):
        return ElectrumConnection(
            "192.168.1.10",
            50002,
            proxy_host="127.0.0.1",
            proxy_port=9050,
            allow_lan_bypass=allow_lan_bypass,
        )

    def test_operator_lan_server_bypasses_proxy(self):
        conn = self._make_conn(allow_lan_bypass=True)
        with patch("socket.create_connection") as mock_direct:
            mock_direct.return_value = MagicMock()
            conn._open_socket()
            mock_direct.assert_called_once()

    def test_discovered_private_host_uses_proxy(self):
        conn = self._make_conn(allow_lan_bypass=False)
        fake_socks = MagicMock()
        with patch.dict("sys.modules", {"socks": fake_socks}):
            with patch("socket.create_connection") as mock_direct:
                conn._open_socket()
                mock_direct.assert_not_called()
                fake_socks.socksocket.assert_called_once()


class HelperTest(unittest.TestCase):
    def test_is_private_address(self):
        for host in (
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "localhost",
        ):
            self.assertTrue(_is_private_address(host), host)
        for host in ("1.2.3.4", "8.8.8.8", "example.com", "abc.onion", "None"):
            self.assertFalse(_is_private_address(host), host)

    def test_resolves_to_private_address(self):
        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 50001))],
        ):
            self.assertTrue(_resolves_to_private_address("h.example.com", 50001))
        with patch(
            "socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("1.2.3.4", 50001))],
        ):
            self.assertFalse(_resolves_to_private_address("h.example.com", 50001))
        with patch("socket.getaddrinfo", side_effect=OSError("no dns")):
            self.assertTrue(_resolves_to_private_address("h.example.com", 50001))


if __name__ == "__main__":
    unittest.main()
