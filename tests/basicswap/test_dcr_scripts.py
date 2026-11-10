# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
The outputs the Decred adaptor-sig verifiers check must carry script version 0.
"""

import secrets
import unittest

from basicswap.interface.dcr.dcr import DCRInterface
from basicswap.protocols.xmr_swap_1 import XmrSwapInterface
from basicswap.util.logging import BSXLogger
from tests.basicswap.util.common import REQUIRED_SETTINGS

SWAP_VALUE = 500000000
FEE_RATE = 10000
LOCK_1 = 30
LOCK_2 = 40


class TestDcrOutputScriptVersion(unittest.TestCase):
    def setUp(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = DCRInterface(coin_settings, "regtest")
        ci._log = BSXLogger("test")
        self.ci = ci
        self.Kal = ci.getPubkey(ci.getNewRandomKey())
        self.Kaf = ci.getPubkey(ci.getNewRandomKey())
        self.pkh_dest = secrets.token_bytes(20)
        self.lock_script = XmrSwapInterface().genScriptLockTxScript(
            ci, self.Kal, self.Kaf
        )
        self.lock_tx = ci.createSCLockTx(SWAP_VALUE, self.lock_script)
        self.lock_txid = ci.getTxid(ci.loadTx(self.lock_tx))

    def with_output_version(self, tx_bytes: bytes, version: int) -> bytes:
        tx = self.ci.loadTx(tx_bytes)
        tx.vout[0].version = version
        return tx.serialize()

    def verify_lock(self, tx_bytes: bytes):
        return self.ci.verifySCLockTx(
            tx_bytes, self.lock_script, SWAP_VALUE, self.Kal, self.Kaf, FEE_RATE, False
        )

    def test_lock_tx_output(self):
        self.verify_lock(self.lock_tx)
        self.assertRaises(
            ValueError, self.verify_lock, self.with_output_version(self.lock_tx, 1)
        )

    def test_lock_refund_tx_output(self):
        ci = self.ci
        refund_tx, refund_script, _ = ci.createSCLockRefundTx(
            self.lock_tx, self.lock_script, self.Kal, self.Kaf, LOCK_1, LOCK_2, FEE_RATE
        )

        def verify(tx_bytes: bytes):
            return ci.verifySCLockRefundTx(
                tx_bytes,
                self.lock_tx,
                refund_script,
                self.lock_txid,
                0,
                LOCK_1,
                self.lock_script,
                self.Kal,
                self.Kaf,
                LOCK_2,
                SWAP_VALUE,
                FEE_RATE,
            )

        verify(refund_tx)
        self.assertRaises(ValueError, verify, self.with_output_version(refund_tx, 1))
        self.assertRaises(
            ValueError, verify, self.with_output_version(refund_tx, 65535)
        )

    def test_lock_spend_tx_output(self):
        ci = self.ci
        spend_tx = ci.createSCLockSpendTx(
            self.lock_tx, self.lock_script, self.pkh_dest, FEE_RATE
        )

        def verify(tx_bytes: bytes):
            return ci.verifySCLockSpendTx(
                tx_bytes, self.lock_tx, self.lock_script, self.pkh_dest, FEE_RATE
            )

        verify(spend_tx)
        self.assertRaises(ValueError, verify, self.with_output_version(spend_tx, 1))


if __name__ == "__main__":
    unittest.main()
