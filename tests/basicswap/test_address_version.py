# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.contrib import segwit_addr
from basicswap.contrib.test_framework.script import OP_0, OP_DUP, OP_EQUAL, OP_HASH160
from basicswap.interface.btc.btc import BTCInterface
from basicswap.util.address import encodeAddress
from tests.basicswap.util.common import REQUIRED_SETTINGS

HASH20 = bytes(range(20))

REGTEST_PUBKEY_PREFIX = 111
REGTEST_SCRIPT_PREFIX = 196
REGTEST_HRP = "bcrt"
BTC_MAINNET_PUBKEY_PREFIX = 0
LTC_PUBKEY_PREFIX = 48


def make_interface():
    settings = dict(REQUIRED_SETTINGS)
    settings.update(
        {
            "rpcport": 0,
            "rpcauth": "none",
            "connection_type": "none",
        }
    )
    return BTCInterface(settings, "regtest")


def make_base58_address(prefix):
    return encodeAddress(bytes((prefix,)) + HASH20)


class GetDestForAddressTest(unittest.TestCase):
    def setUp(self):
        self.ci = make_interface()

    def test_p2pkh_accepted(self):
        script = self.ci.getDestForAddress(make_base58_address(REGTEST_PUBKEY_PREFIX))
        self.assertEqual(script[0], OP_DUP)
        self.assertEqual(script[1], OP_HASH160)
        self.assertIn(HASH20, bytes(script))

    def test_p2sh_accepted(self):
        script = self.ci.getDestForAddress(make_base58_address(REGTEST_SCRIPT_PREFIX))
        self.assertEqual(script[0], OP_HASH160)
        self.assertEqual(script[-1], OP_EQUAL)
        self.assertIn(HASH20, bytes(script))

    def test_litecoin_address_rejected(self):
        with self.assertRaisesRegex(ValueError, "version byte"):
            self.ci.getDestForAddress(make_base58_address(LTC_PUBKEY_PREFIX))

    def test_wrong_network_address_rejected(self):
        with self.assertRaisesRegex(ValueError, "version byte"):
            self.ci.getDestForAddress(make_base58_address(BTC_MAINNET_PUBKEY_PREFIX))

    def test_short_hash_rejected(self):
        address = encodeAddress(bytes((REGTEST_PUBKEY_PREFIX,)) + HASH20[:19])
        with self.assertRaisesRegex(ValueError, "Invalid address"):
            self.ci.getDestForAddress(address)

    def test_segwit_v0_accepted(self):
        address = segwit_addr.encode(REGTEST_HRP, 0, HASH20)
        script = self.ci.getDestForAddress(address)
        self.assertEqual(script[0], OP_0)
        self.assertIn(HASH20, bytes(script))

    def test_taproot_rejected(self):
        address = segwit_addr.encode(REGTEST_HRP, 1, bytes(range(32)))
        with self.assertRaisesRegex(ValueError, "witness version"):
            self.ci.getDestForAddress(address)

    def test_invalid_segwit_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid segwit address"):
            self.ci.getDestForAddress("bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")

    def test_garbage_address_rejected(self):
        with self.assertRaises(ValueError):
            self.ci.getDestForAddress("notanaddress0OIl")


if __name__ == "__main__":
    unittest.main()
