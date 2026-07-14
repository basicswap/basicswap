# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.interface.electrumx import ElectrumServer

ONION = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab.onion:50001:false"
CLEARNET = "electrum.example.com:50002:true"


class TestElectrumServerSelection(unittest.TestCase):
    def test_tor_with_onion_only_uses_onion(self):
        server = ElectrumServer(
            "bitcoin",
            onion_servers=[ONION],
            proxy_host="127.0.0.1",
            proxy_port=9050,
        )
        hosts = [s["host"] for s in server._servers]
        self.assertEqual(len(hosts), 1)
        self.assertTrue(hosts[0].endswith(".onion"))

    def test_tor_with_onion_and_clearnet_uses_onion_only(self):
        server = ElectrumServer(
            "bitcoin",
            clearnet_servers=[CLEARNET],
            onion_servers=[ONION],
            proxy_host="127.0.0.1",
            proxy_port=9050,
        )
        hosts = [s["host"] for s in server._servers]
        self.assertEqual(len(hosts), 1)
        self.assertTrue(hosts[0].endswith(".onion"))

    def test_tor_without_onion_falls_back_to_clearnet(self):
        server = ElectrumServer(
            "bitcoin",
            clearnet_servers=[CLEARNET],
            proxy_host="127.0.0.1",
            proxy_port=9050,
        )
        hosts = [s["host"] for s in server._servers]
        self.assertIn("electrum.example.com", hosts)

    def test_tor_without_any_config_uses_default_clearnet(self):
        server = ElectrumServer(
            "bitcoin",
            proxy_host="127.0.0.1",
            proxy_port=9050,
        )
        self.assertGreater(len(server._servers), 0)

    def test_no_tor_uses_clearnet_only(self):
        server = ElectrumServer(
            "bitcoin",
            clearnet_servers=[CLEARNET],
            onion_servers=[ONION],
        )
        hosts = [s["host"] for s in server._servers]
        self.assertNotIn(ONION.split(":")[0], hosts)
        self.assertIn("electrum.example.com", hosts)


if __name__ == "__main__":
    unittest.main()
