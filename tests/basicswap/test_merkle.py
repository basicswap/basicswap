# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import struct
import unittest

from hashlib import sha256

from basicswap.util.merkle import (
    check_header_pow,
    electrum_merkle_root,
    header_bits,
    parse_header_merkle_root,
    target_from_bits,
    verify_tx_merkle_proof,
)


def dsha256(data: bytes) -> bytes:
    return sha256(sha256(data).digest()).digest()


GENESIS_HEADER_HEX = (
    "0100000000000000000000000000000000000000000000000000000000000000000000003b"
    "a3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff"
    "001d1dac2b7c"
)
GENESIS_COINBASE_TXID = (
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
)


def build_regtest_header(merkle_root_le: bytes) -> bytes:
    version = struct.pack("<I", 1)
    prev = bytes(32)
    time_field = struct.pack("<I", 1000)
    bits = struct.pack("<I", 0x207FFFFF)
    nonce = struct.pack("<I", 0)
    return version + prev + merkle_root_le + time_field + bits + nonce


class TestMerkle(unittest.TestCase):
    def test_single_tx_root_equals_txid(self):
        header_bytes = bytes.fromhex(GENESIS_HEADER_HEX)
        self.assertEqual(len(header_bytes), 80)
        root = electrum_merkle_root(GENESIS_COINBASE_TXID, [], 0)
        self.assertEqual(root, parse_header_merkle_root(header_bytes))

    def test_genesis_pow_valid(self):
        header_bytes = bytes.fromhex(GENESIS_HEADER_HEX)
        self.assertTrue(check_header_pow(header_bytes))

    def test_verify_full_genesis(self):
        header_bytes = bytes.fromhex(GENESIS_HEADER_HEX)
        self.assertTrue(
            verify_tx_merkle_proof(GENESIS_COINBASE_TXID, header_bytes, [], 0)
        )

    def test_two_tx_branch(self):
        txa = "aa" * 32
        txb = "bb" * 32
        txa_le = bytes.fromhex(txa)[::-1]
        txb_le = bytes.fromhex(txb)[::-1]
        root_le = dsha256(txa_le + txb_le)
        header_bytes = build_regtest_header(root_le)

        self.assertTrue(
            verify_tx_merkle_proof(txa, header_bytes, [txb], 0, require_pow=False)
        )
        self.assertTrue(
            verify_tx_merkle_proof(txb, header_bytes, [txa], 1, require_pow=False)
        )

    def test_bad_branch_fails(self):
        txa = "aa" * 32
        txb = "bb" * 32
        txc = "cc" * 32
        txa_le = bytes.fromhex(txa)[::-1]
        txb_le = bytes.fromhex(txb)[::-1]
        root_le = dsha256(txa_le + txb_le)
        header_bytes = build_regtest_header(root_le)

        self.assertFalse(
            verify_tx_merkle_proof(txa, header_bytes, [txc], 0, require_pow=False)
        )

    def test_bits_and_target(self):
        header_bytes = bytes.fromhex(GENESIS_HEADER_HEX)
        self.assertEqual(header_bits(header_bytes), 0x1D00FFFF)
        self.assertEqual(
            target_from_bits(0x1D00FFFF),
            0x00000000FFFF0000000000000000000000000000000000000000000000000000,
        )

    def test_pow_fails_on_tampered_header(self):
        header_bytes = bytearray(bytes.fromhex(GENESIS_HEADER_HEX))
        header_bytes[36] ^= 0xFF
        self.assertFalse(check_header_pow(bytes(header_bytes)))

    def test_short_header_raises(self):
        with self.assertRaises(ValueError):
            parse_header_merkle_root(b"\x00" * 40)


if __name__ == "__main__":
    unittest.main()
