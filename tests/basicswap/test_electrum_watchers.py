# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from types import SimpleNamespace

from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from basicswap.interface.btc.btc import BTCInterface
from tests.basicswap.util.common import REQUIRED_SETTINGS

WATCHED_SCRIPT = bytes([0x00, 0x14]) + b"\x11" * 20
SPEND_HEIGHT = 100


class FakeServer:
    def __init__(self, txs, history):
        self.txs = txs
        self.history = history

    def call_background(self, method, params):
        if method == "blockchain.transaction.get":
            return self.txs.get(params[0])
        if method == "blockchain.scripthash.get_history":
            return self.history
        raise ValueError(f"Unexpected method {method}")


def make_txs():
    watched_tx = CTransaction()
    watched_tx.vin.append(CTxIn(COutPoint(1, 0)))
    watched_tx.vout.append(CTxOut(10000, WATCHED_SCRIPT))
    watched_tx.rehash()

    spend_tx = CTransaction()
    spend_tx.vin.append(CTxIn(COutPoint(int(watched_tx.hash, 16), 0)))
    spend_tx.vout.append(CTxOut(9000, bytes([0x00, 0x14]) + b"\x22" * 20))
    spend_tx.rehash()
    return watched_tx, spend_tx


def make_interface(txs, history):
    settings = dict(REQUIRED_SETTINGS)
    settings.update(
        {
            "rpcport": 0,
            "rpcauth": "none",
            "connection_type": "electrum",
        }
    )
    ci = BTCInterface(settings, "regtest")
    ci._backend = SimpleNamespace(_server=FakeServer(txs, history))
    return ci


def set_verifier(ci, result, calls):
    def fake_verify(backend, txid_hex, block_height):
        calls.append((txid_hex, block_height))
        return result

    ci._verifyTxMerkleElectrum = fake_verify


class ElectrumWatcherMerkleTest(unittest.TestCase):
    def setUp(self):
        self.watched_tx, self.spend_tx = make_txs()
        self.txs = {
            self.watched_tx.hash: self.watched_tx.serialize().hex(),
            self.spend_tx.hash: self.spend_tx.serialize().hex(),
        }
        self.history = [
            {"tx_hash": self.watched_tx.hash, "height": SPEND_HEIGHT},
            {"tx_hash": self.spend_tx.hash, "height": SPEND_HEIGHT},
        ]

    def test_output_verified_height_kept(self):
        ci = make_interface(self.txs, self.history)
        calls = []
        set_verifier(ci, True, calls)
        rv = ci.checkWatchedOutput(self.watched_tx.hash, 0)
        self.assertEqual(rv["txid"], self.spend_tx.hash)
        self.assertEqual(rv["height"], SPEND_HEIGHT)
        self.assertEqual(calls, [(self.spend_tx.hash, SPEND_HEIGHT)])

    def test_output_unverified_treated_unconfirmed(self):
        ci = make_interface(self.txs, self.history)
        calls = []
        set_verifier(ci, None, calls)
        rv = ci.checkWatchedOutput(self.watched_tx.hash, 0)
        self.assertEqual(rv["txid"], self.spend_tx.hash)
        self.assertEqual(rv["height"], 0)

    def test_output_failed_proof_rejected(self):
        ci = make_interface(self.txs, self.history)
        calls = []
        set_verifier(ci, False, calls)
        rv = ci.checkWatchedOutput(self.watched_tx.hash, 0)
        self.assertIsNone(rv)

    def test_script_verified_height_kept(self):
        ci = make_interface(self.txs, self.history[:1])
        calls = []
        set_verifier(ci, True, calls)
        rv = ci.checkWatchedScript(WATCHED_SCRIPT)
        self.assertEqual(rv["txid"], self.watched_tx.hash)
        self.assertEqual(rv["height"], SPEND_HEIGHT)
        self.assertEqual(calls, [(self.watched_tx.hash, SPEND_HEIGHT)])

    def test_script_unverified_treated_unconfirmed(self):
        ci = make_interface(self.txs, self.history[:1])
        calls = []
        set_verifier(ci, None, calls)
        rv = ci.checkWatchedScript(WATCHED_SCRIPT)
        self.assertEqual(rv["txid"], self.watched_tx.hash)
        self.assertEqual(rv["height"], 0)

    def test_script_failed_proof_rejected(self):
        ci = make_interface(self.txs, self.history[:1])
        calls = []
        set_verifier(ci, False, calls)
        rv = ci.checkWatchedScript(WATCHED_SCRIPT)
        self.assertIsNone(rv)

    def test_mempool_height_not_verified(self):
        history = [
            {"tx_hash": self.watched_tx.hash, "height": 0},
            {"tx_hash": self.spend_tx.hash, "height": 0},
        ]
        ci = make_interface(self.txs, history)
        calls = []
        set_verifier(ci, True, calls)
        rv = ci.checkWatchedOutput(self.watched_tx.hash, 0)
        self.assertEqual(rv["height"], 0)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
