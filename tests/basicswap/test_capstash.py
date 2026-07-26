#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import tempfile
import unittest

from basicswap.chainparams import (
    Coins,
    chainparams,
    getCoinIdFromName,
    getCoinIdFromTicker,
)
from basicswap.interface.capstash.capstash import CapStashInterface
from basicswap.interface.capstash.core import prepare_module
from basicswap.interface.prepare_util import PrepareContext


class TestCapStash(unittest.TestCase):
    def make_interface(self, network):
        return CapStashInterface(
            {
                "rpcport": 1,
                "rpcauth": "none",
                "blocks_confirmed": 1,
                "conf_target": 2,
                "use_segwit": True,
                "use_csv": True,
                "use_descriptors": True,
                "connection_type": "rpc",
            },
            network,
        )

    def test_identity_and_chainparams(self):
        self.assertEqual(int(Coins.CAPS), 19)
        self.assertEqual(getCoinIdFromName("capstash"), Coins.CAPS)
        self.assertEqual(getCoinIdFromTicker("CAPS"), Coins.CAPS)

        params = chainparams[Coins.CAPS]
        self.assertEqual(params["display_name"], "CapStash")
        self.assertEqual(params["message_magic"], "CapStash Signed Message:\n")
        self.assertEqual(params["core_binname"], "CapStashd")
        self.assertEqual(params["cli_binname"], "CapStash-cli")
        self.assertEqual(params["mainnet"]["rpcport"], 8332)
        self.assertEqual(params["mainnet"]["pubkey_address"], 28)
        self.assertEqual(params["mainnet"]["script_address"], 18)
        self.assertEqual(params["mainnet"]["key_prefix"], 156)
        self.assertEqual(params["mainnet"]["hrp"], "cap")
        self.assertEqual(params["testnet"]["name"], "test")
        self.assertEqual(params["testnet"]["hrp"], "tcap")
        self.assertEqual(params["regtest"]["hrp"], "rcap")

    def test_interface_and_coin_type_policy(self):
        ci = self.make_interface("regtest")
        self.assertEqual(ci.coin_type(), Coins.CAPS)
        self.assertEqual(ci.getWalletAccountPath(), "84h/1h/0h")

        ci_main = self.make_interface("regtest")
        ci_main._network = "mainnet"
        with self.assertRaisesRegex(ValueError, "SLIP-0044"):
            ci_main.getWalletAccountPath()

    def test_local_only_prepare_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ctx = PrepareContext(
                data_dir=temp_dir,
                bin_dir=temp_dir,
                port_offset=0,
                should_manage_daemon=lambda ticker: True,
            )
            config = prepare_module.getConfigSegment(ctx)
            self.assertEqual(config["config_filename"], "CapStash.conf")
            self.assertEqual(config["core_version_group"], 27)
            self.assertTrue(config["use_segwit"])
            self.assertTrue(config["use_csv"])

            with self.assertRaisesRegex(RuntimeError, "Automatic CapStash"):
                prepare_module.downloadCore(ctx, temp_dir, "local-only", {})


if __name__ == "__main__":
    unittest.main()
