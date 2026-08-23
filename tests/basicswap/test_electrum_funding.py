# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from unittest.mock import MagicMock

from basicswap.contrib.test_framework.messages import CTransaction, CTxOut
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
        rv = make_backend().getBatchUnspent(["sh1"])
        self.assertEqual(len(rv["sh1"]), 3)

    def test_min_confirmations_filters_unconfirmed(self):
        rv = make_backend().getBatchUnspent(["sh1"], min_confirmations=1)
        self.assertEqual([u["txid"] for u in rv["sh1"]], ["aa" * 32, "cc" * 32])


class FundTxElectrumTest(unittest.TestCase):
    def setUp(self):
        settings = dict(REQUIRED_SETTINGS)
        settings.update(
            {"rpcport": 0, "rpcauth": "none", "connection_type": "electrum"}
        )
        self.ci = BTCInterface(settings, "regtest")
        self.ci._log = MagicMock()
        self.addr = self.ci.encodeSegwitAddress(b"\x11" * 20)

    def _fund(self, utxos):
        sh = self.ci.addressToScripthash(self.addr)

        class FakeBackend:
            def getBatchUnspent(self, scripthashes, min_confirmations=0):
                return {
                    sh: [u for u in utxos if u["confirmations"] >= min_confirmations]
                }

        wm = MagicMock()
        wm.getFundedAddresses.return_value = {self.addr: sh}
        wm.isUTXOLocked.return_value = False
        self.ci._backend = FakeBackend()
        self.ci.getWalletManager = lambda: wm

        tx = CTransaction()
        tx.vout.append(CTxOut(10000, bytes([0x00, 0x14]) + b"\x11" * 20))
        funded = self.ci.loadTx(
            self.ci._fundTxElectrum(tx.serialize_without_witness(), 1000)
        )
        return {
            txin.prevout.hash.to_bytes(32, "little")[::-1].hex() for txin in funded.vin
        }

    def test_unconfirmed_utxos_are_not_spent(self):
        confirmed = {"txid": "aa" * 32, "vout": 0, "value": 10750, "confirmations": 3}
        unconfirmed = {"txid": "bb" * 32, "vout": 0, "value": 99000, "confirmations": 0}
        self.assertEqual(self._fund([unconfirmed, confirmed]), {"aa" * 32})

    def test_only_unconfirmed_reports_why(self):
        unconfirmed = {"txid": "bb" * 32, "vout": 0, "value": 99000, "confirmations": 0}
        with self.assertRaises(ValueError) as e:
            self._fund([unconfirmed])
        self.assertIn("awaiting confirmation", str(e.exception))


if __name__ == "__main__":
    unittest.main()
