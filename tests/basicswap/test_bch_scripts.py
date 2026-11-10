# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
The lock and lock refund scripts of a Bitcoin Cash adaptor-sig swap must be
the exact bytes this node builds from the agreed values.
"""

import secrets
import unittest

from basicswap.contrib.test_framework.messages import COutPoint, CTransaction, CTxIn
from basicswap.contrib.test_framework.script import CScript, OP_CHECKSEQUENCEVERIFY
from basicswap.interface.bch.bch import BCHInterface
from basicswap.util import b2i
from basicswap.util.logging import BSXLogger
from tests.basicswap.util.common import REQUIRED_SETTINGS

SWAP_VALUE = 5000000
MINING_FEE = 1000
LOCK_1 = 30
LOCK_2 = 40
OP_PUSHDATA1 = 0x4C


def pad_number(script: bytes, value: int) -> bytes:
    minimal = bytes(CScript([value]))
    padded = bytes([minimal[0] + 1]) + minimal[1:] + b"\x00"
    op_csv = bytes([OP_CHECKSEQUENCEVERIFY])
    assert script.count(minimal + op_csv) == 1
    return script.replace(minimal + op_csv, padded + op_csv)


def pad_push(script: bytes, data: bytes) -> bytes:
    direct = bytes([len(data)]) + data
    assert script.count(direct) == 1
    return script.replace(direct, bytes([OP_PUSHDATA1, len(data)]) + data)


class TestBchScriptEncoding(unittest.TestCase):
    def setUp(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = BCHInterface(coin_settings, "regtest")
        ci._log = BSXLogger("test")
        self.ci = ci
        self.Kal = ci.getPubkey(ci.getNewRandomKey())
        self.Kaf = ci.getPubkey(ci.getNewRandomKey())
        self.dest_af = bytes(ci.getScriptForPubkeyHash(secrets.token_bytes(20)))
        self.refund_args = {
            "mining_fee": MINING_FEE,
            "out_1": bytes(ci.getScriptForPubkeyHash(secrets.token_bytes(20))),
            "out_2": self.dest_af,
            "public_key": self.Kaf,
            "timelock": LOCK_2,
        }
        self.refund_script = bytes(
            ci.genScriptLockTxScript(ci, self.Kal, self.Kaf, **self.refund_args)
        )
        self.lock_args = self.lock_args_for(self.refund_script)
        self.lock_script = bytes(
            ci.genScriptLockTxScript(ci, self.Kal, self.Kaf, **self.lock_args)
        )

    def lock_args_for(self, refund_script: bytes) -> dict:
        return {
            "mining_fee": MINING_FEE,
            "out_1": self.dest_af,
            "out_2": bytes(self.ci.scriptToP2SH32LockingBytecode(refund_script)),
            "public_key": self.Kal,
            "timelock": LOCK_1,
        }

    def lock_tx(self, lock_script: bytes) -> bytes:
        ci = self.ci
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vin.append(CTxIn(COutPoint(1, 0)))
        tx.vout.append(ci.txoType()(SWAP_VALUE, ci.getScriptDest(lock_script)))
        return tx.serialize()

    def verify_lock(self, lock_script: bytes, lock_args: dict):
        return self.ci.verifySCLockTx(
            self.lock_tx(lock_script),
            lock_script,
            SWAP_VALUE,
            self.Kal,
            self.Kaf,
            MINING_FEE,
            False,
            **lock_args,
        )

    def verify_refund(self, refund_script: bytes):
        ci = self.ci
        lock_tx_bytes = self.lock_tx(self.lock_script)
        lock_txid: bytes = ci.getTxid(ci.loadTx(lock_tx_bytes))
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vin.append(
            CTxIn(
                COutPoint(b2i(lock_txid), 0),
                nSequence=LOCK_1,
                scriptSig=ci.getScriptScriptSig(self.lock_script, None),
            )
        )
        tx.vout.append(
            ci.txoType()(SWAP_VALUE - MINING_FEE, ci.getScriptDest(refund_script))
        )
        return ci.verifySCLockRefundTx(
            tx.serialize(),
            lock_tx_bytes,
            refund_script,
            lock_txid,
            0,
            LOCK_1,
            self.lock_script,
            self.Kal,
            self.Kaf,
            LOCK_2,
            SWAP_VALUE,
            MINING_FEE,
            **self.refund_args,
        )

    def assert_same_values(self, script: bytes, honest: bytes) -> None:
        ci = self.ci
        self.assertNotEqual(script, honest)
        self.assertEqual(
            ci.extractScriptLockScriptValues(script),
            ci.extractScriptLockScriptValues(honest),
        )

    def test_lock_script_must_be_the_built_bytes(self):
        self.verify_lock(self.lock_script, self.lock_args)

        for padded in (
            pad_number(self.lock_script, LOCK_1),
            pad_push(self.lock_script, self.dest_af),
        ):
            self.assert_same_values(padded, self.lock_script)
            self.assertRaises(ValueError, self.verify_lock, padded, self.lock_args)

    def test_lock_refund_script_must_be_the_built_bytes(self):
        self.verify_refund(self.refund_script)

        for padded in (
            pad_number(self.refund_script, LOCK_2),
            pad_push(self.refund_script, self.dest_af),
        ):
            self.assert_same_values(padded, self.refund_script)
            self.assertRaises(ValueError, self.verify_refund, padded)


if __name__ == "__main__":
    unittest.main()
