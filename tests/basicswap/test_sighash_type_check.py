# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for the hashtype byte on signatures received from a peer.

The protocol only ever signs SIGHASH_ALL. verifyTxSig used to strip the trailing
hashtype byte without reading it, so a counterparty could relabel an otherwise
valid signature and have it accepted locally while the node, which digests by
the declared hashtype, rejects the transaction with NULLFAIL. For a coin A lock
refund tx that means the leader funds a bare 2-of-2 it cannot refund.
"""

import unittest

from coincurve.keys import PrivateKey

from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_0,
    OP_CHECKMULTISIG,
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
    SegwitV0SignatureHash,
)
from basicswap.interface.btc.btc import BTCInterface
from basicswap.util.crypto import sha256

PREVOUT_VALUE = 2500000


def make_swap():
    """A coin A lock output and the refund tx spending it, as the leader builds them."""
    kal = PrivateKey(b"\x11" * 32)
    kaf = PrivateKey(b"\x22" * 32)
    lock_script = CScript(
        [2, kal.public_key.format(), kaf.public_key.format(), 2, OP_CHECKMULTISIG]
    )

    lock_tx = CTransaction()
    lock_tx.nVersion = 2
    lock_tx.vin.append(CTxIn(COutPoint(0xAB * 2**248, 0), nSequence=0xFFFFFFFE))
    lock_tx.vout.append(CTxOut(PREVOUT_VALUE, CScript([OP_0, sha256(lock_script)])))
    lock_tx.rehash()

    refund_tx = CTransaction()
    refund_tx.nVersion = 2
    refund_tx.vin.append(CTxIn(COutPoint(lock_tx.sha256, 0), nSequence=1000))
    refund_tx.vout.append(CTxOut(PREVOUT_VALUE - 338, CScript([OP_0, b"\x44" * 32])))

    return kaf, lock_script, refund_tx.serialize_without_witness()


def sign_with_hashtype(key, lock_script, refund_tx_bytes, hashtype_byte):
    """Sign the SIGHASH_ALL digest but label the sig with hashtype_byte."""
    ci = BTCInterface.__new__(BTCInterface)
    tx = ci.loadTx(refund_tx_bytes)
    sig_hash = SegwitV0SignatureHash(lock_script, tx, 0, SIGHASH_ALL, PREVOUT_VALUE)
    return key.sign(sig_hash, hasher=None) + bytes((hashtype_byte,))


class TestSighashTypeCheck(unittest.TestCase):
    def setUp(self):
        self.ci = BTCInterface.__new__(BTCInterface)
        self.kaf, self.lock_script, self.refund_tx = make_swap()

    def verify(self, sig):
        return self.ci.verifyTxSig(
            self.refund_tx,
            sig,
            self.kaf.public_key.format(),
            0,
            self.lock_script,
            PREVOUT_VALUE,
        )

    def test_accepts_sighash_all(self):
        sig = sign_with_hashtype(
            self.kaf, self.lock_script, self.refund_tx, SIGHASH_ALL
        )
        self.assertTrue(self.verify(sig))

    def test_rejects_relabelled_hashtypes(self):
        for hashtype in (
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
            0x00,
            0xFF,
        ):
            with self.subTest(hashtype=hashtype):
                sig = sign_with_hashtype(
                    self.kaf, self.lock_script, self.refund_tx, hashtype
                )
                self.assertFalse(self.verify(sig))

    def test_rejects_empty_sig(self):
        self.assertFalse(self.verify(b""))


if __name__ == "__main__":
    unittest.main()
