# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from unittest.mock import MagicMock

from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from basicswap.interface.btc.btc import BTCInterface
from basicswap.wallet_backend import ElectrumBackend
from tests.basicswap.util.common import REQUIRED_SETTINGS

UTXOS = [
    {"tx_hash": "aa" * 32, "tx_pos": 0, "value": 5000, "height": 101},
    {"tx_hash": "bb" * 32, "tx_pos": 1, "value": 6000, "height": 0},
    {"tx_hash": "cc" * 32, "tx_pos": 0, "value": 7000, "height": 110},
]


def make_backend():
    backend = ElectrumBackend.__new__(ElectrumBackend)
    backend._log = MagicMock()
    backend.getBlockHeight = lambda: 110
    backend._call_batch = lambda calls: [UTXOS]
    return backend


class GetBatchUnspentTest(unittest.TestCase):
    def test_default_includes_unconfirmed(self):
        backend = make_backend()
        rv = backend.getBatchUnspent(["sh1"])
        self.assertEqual(len(rv["sh1"]), 3)

    def test_min_confirmations_filters_unconfirmed(self):
        backend = make_backend()
        rv = backend.getBatchUnspent(["sh1"], min_confirmations=1)
        txids = [utxo["txid"] for utxo in rv["sh1"]]
        self.assertEqual(txids, ["aa" * 32, "cc" * 32])

    def test_min_confirmations_two_excludes_tip(self):
        backend = make_backend()
        rv = backend.getBatchUnspent(["sh1"], min_confirmations=2)
        txids = [utxo["txid"] for utxo in rv["sh1"]]
        self.assertEqual(txids, ["aa" * 32])


class SentinelError(Exception):
    pass


class FundTxElectrumTest(unittest.TestCase):
    def test_funding_requires_confirmed_utxos(self):
        settings = dict(REQUIRED_SETTINGS)
        settings.update(
            {
                "rpcport": 0,
                "rpcauth": "none",
                "connection_type": "electrum",
            }
        )
        ci = BTCInterface(settings, "regtest")

        calls = []

        class RecordingBackend:
            def getBatchUnspent(self, scripthashes, min_confirmations=0):
                calls.append(min_confirmations)
                raise SentinelError()

        wm = MagicMock()
        wm.getFundedAddresses.return_value = {"addr1": "sh1"}
        ci._backend = RecordingBackend()
        ci.getWalletManager = lambda: wm

        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(1, 0)))
        tx.vout.append(CTxOut(10000, bytes([0x00, 0x14]) + b"\x11" * 20))

        with self.assertRaises(SentinelError):
            ci._fundTxElectrum(tx.serialize_without_witness(), 10000)
        self.assertEqual(calls, [1])


if __name__ == "__main__":
    unittest.main()
