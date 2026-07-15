# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.interface.btc.btc import BTCInterface

GENESIS_HEADER_HEX = (
    "0100000000000000000000000000000000000000000000000000000000000000000000003b"
    "a3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff"
    "001d1dac2b7c"
)
GENESIS_COINBASE_TXID = (
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
)


class StubLog:
    def id(self, v):
        return str(v)

    def error(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class StubServer:
    def __init__(self, merkle_result, header_hex, raise_on_merkle=False):
        self._merkle_result = merkle_result
        self._header_hex = header_hex
        self._raise_on_merkle = raise_on_merkle

    def get_merkle(self, txid, height):
        if self._raise_on_merkle:
            raise RuntimeError("no merkle support")
        return self._merkle_result

    def call(self, method, params):
        if method == "blockchain.block.header":
            return self._header_hex
        raise RuntimeError(f"unexpected call {method}")


class StubBackend:
    def __init__(self, server):
        self._server = server


def make_interface():
    ci = BTCInterface.__new__(BTCInterface)
    ci._log = StubLog()
    ci._merkle_verified = {}
    return ci


class TestElectrumMerkleAdversarial(unittest.TestCase):
    def test_honest_server_verifies(self):
        ci = make_interface()
        server = StubServer({"merkle": [], "pos": 0}, GENESIS_HEADER_HEX)
        backend = StubBackend(server)
        self.assertTrue(ci._verifyTxMerkleElectrum(backend, GENESIS_COINBASE_TXID, 1))

    def test_phantom_height_bad_merkle_fails_closed(self):
        ci = make_interface()
        server = StubServer({"merkle": ["cc" * 32], "pos": 0}, GENESIS_HEADER_HEX)
        backend = StubBackend(server)
        self.assertFalse(
            ci._verifyTxMerkleElectrum(backend, GENESIS_COINBASE_TXID, 100000)
        )

    def test_missing_merkle_support_fails_closed(self):
        ci = make_interface()
        server = StubServer(None, GENESIS_HEADER_HEX, raise_on_merkle=True)
        backend = StubBackend(server)
        self.assertFalse(
            ci._verifyTxMerkleElectrum(backend, GENESIS_COINBASE_TXID, 100000)
        )

    def test_tampered_header_fails_closed(self):
        ci = make_interface()
        tampered = bytearray(bytes.fromhex(GENESIS_HEADER_HEX))
        tampered[76] ^= 0x01
        server = StubServer({"merkle": [], "pos": 0}, bytes(tampered).hex())
        backend = StubBackend(server)
        self.assertFalse(ci._verifyTxMerkleElectrum(backend, GENESIS_COINBASE_TXID, 1))

    def test_zero_height_fails_closed(self):
        ci = make_interface()
        server = StubServer({"merkle": [], "pos": 0}, GENESIS_HEADER_HEX)
        backend = StubBackend(server)
        self.assertFalse(ci._verifyTxMerkleElectrum(backend, GENESIS_COINBASE_TXID, 0))

    def test_verified_result_is_cached(self):
        ci = make_interface()
        server = StubServer({"merkle": [], "pos": 0}, GENESIS_HEADER_HEX)
        backend = StubBackend(server)
        self.assertTrue(ci._verifyTxMerkleElectrum(backend, GENESIS_COINBASE_TXID, 1))
        self.assertEqual(ci._merkle_verified.get(GENESIS_COINBASE_TXID), 1)


if __name__ == "__main__":
    unittest.main()
