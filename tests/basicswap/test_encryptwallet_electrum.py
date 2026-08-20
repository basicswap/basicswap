# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.interface.btc.btc import BTCInterface
from tests.basicswap.util.common import REQUIRED_SETTINGS


def make_interface(connection_type):
    settings = dict(REQUIRED_SETTINGS)
    settings.update(
        {
            "rpcport": 0,
            "rpcauth": "none",
            "connection_type": connection_type,
        }
    )
    return BTCInterface(settings, "regtest")


class ElectrumEncryptWalletTest(unittest.TestCase):
    def test_encrypt_wallet_warns_in_electrum_mode(self):
        ci = make_interface("electrum")
        calls = []
        ci.rpc_wallet = lambda *args, **kwargs: calls.append(args)
        with self.assertLogs(level="WARNING") as cm:
            rv = ci.encryptWallet("newpass")
        self.assertIsNone(rv)
        self.assertTrue(any("encryptWallet skipped" in m for m in cm.output))
        self.assertEqual(calls, [])

    def test_change_password_warns_in_electrum_mode(self):
        ci = make_interface("electrum")
        calls = []
        ci.rpc_wallet = lambda *args, **kwargs: calls.append(args)
        with self.assertLogs(level="WARNING") as cm:
            rv = ci.changeWalletPassword("old", "new")
        self.assertIsNone(rv)
        self.assertTrue(any("changeWalletPassword skipped" in m for m in cm.output))
        self.assertEqual(calls, [])

    def test_change_password_calls_rpc_in_rpc_mode(self):
        ci = make_interface("rpc")
        calls = []
        ci.rpc_wallet = lambda method, params=None, **kwargs: calls.append(
            (method, params)
        )
        ci.changeWalletPassword("old", "new")
        self.assertEqual(calls, [("walletpassphrasechange", ["old", "new"])])


if __name__ == "__main__":
    unittest.main()
