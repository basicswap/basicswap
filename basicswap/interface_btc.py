#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time
import hashlib
import logging
from io import BytesIO
from basicswap.contrib.test_framework import segwit_addr


from .util import (
    decodeScriptNum,
    getCompactSizeLen,
    dumpj,
    format_amount,
    make_int,
    decodeAddress)
from coincurve.keys import (
    PublicKey)
from coincurve.dleag import (
    verify_secp256k1_point)
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key)

from .ecc_util import (
    G, ep,
    pointToCPK, CPKToPoint,
    getSecretInt,
    b2h, i2b, b2i, i2h)

from .contrib.test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    FromHex,
    ToHex)

from .contrib.test_framework.script import (
    CScript,
    CScriptOp,
    CScriptNum,
    OP_IF, OP_ELSE, OP_ENDIF,
    OP_0,
    OP_2,
    OP_16,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
    OP_SIZE,
    OP_SHA256,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
    hash160)

from .contrib.test_framework.key import ECKey, ECPubKey

from .chainparams import CoinInterface, Coins, chainparams
from .rpc import make_rpc_func
from .util import assert_cond


def findOutput(tx, script_pk):
    for i in range(len(tx.vout)):
        if tx.vout[i].scriptPubKey == script_pk:
            return i
    return None


class BTCInterface(CoinInterface):
    @staticmethod
    def coin_type():
        return Coins.BTC

    @staticmethod
    def exp():
        return 8

    @staticmethod
    def nbk():
        return 32

    @staticmethod
    def nbK():  # No. of bytes requires to encode a public key
        return 33

    @staticmethod
    def witnessScaleFactor():
        return 4

    @staticmethod
    def txVersion():
        return 2

    @staticmethod
    def getTxOutputValue(tx):
        rv = 0
        for output in tx.vout:
            rv += output.nValue
        return rv

    def compareFeeRates(self, a, b):
        return abs(a - b) < 20

    def __init__(self, coin_settings, network):
        self.rpc_callback = make_rpc_func(coin_settings['rpcport'], coin_settings['rpcauth'])
        self.txoType = CTxOut
        self._network = network
        self.blocks_confirmed = coin_settings['blocks_confirmed']

    def testDaemonRPC(self):
        self.rpc_callback('getwalletinfo', [])

    def getDaemonVersion(self):
        return self.rpc_callback('getnetworkinfo')['version']

    def getBlockchainInfo(self):
        return self.rpc_callback('getblockchaininfo')

    def getWalletInfo(self):
        return self.rpc_callback('getwalletinfo')

    def getNewAddress(self, use_segwit):
        args = ['swap_receive']
        if use_segwit:
            args.append('bech32')
        return self.rpc_callback('getnewaddress', args)

    def decodeAddress(self, address):
        bech32_prefix = chainparams[self.coin_type()][self._network]['hrp']
        if address.startswith(bech32_prefix):
            ignr, pkhash = segwit_addr.decode(bech32_prefix, address)
            return pkhash
        return decodeAddress(address)[1:]

    def getNewSecretKey(self):
        return getSecretInt()

    def pubkey(self, key):
        return G * key

    def getPubkey(self, privkey):
        return PublicKey.from_secret(privkey).format()

    def verifyKey(self, k):
        i = b2i(k)
        return(i < ep.o and i > 0)

    def verifyPubkey(self, pubkey_bytes):
        return verify_secp256k1_point(pubkey_bytes)

    def encodePubkey(self, pk):
        return pointToCPK(pk)

    def decodePubkey(self, pke):
        return CPKToPoint(pke)

    def decodeKey(self, k):
        i = b2i(k)
        assert(i < ep.o)
        return i

    def sumKeys(self, ka, kb):
        return (ka + kb) % ep.o

    def sumPubkeys(self, Ka, Kb):
        return Ka + Kb

    def extractScriptLockScriptValues(self, script_bytes):
        script_len = len(script_bytes)
        assert_cond(script_len > 112, 'Bad script length')
        assert_cond(script_bytes[0] == OP_IF)
        assert_cond(script_bytes[1] == OP_SIZE)
        assert_cond(script_bytes[2:4] == bytes((1, 32)))  # 0120, CScriptNum length, then data
        assert_cond(script_bytes[4] == OP_EQUALVERIFY)
        assert_cond(script_bytes[5] == OP_SHA256)
        assert_cond(script_bytes[6] == 32)
        secret_hash = script_bytes[7: 7 + 32]
        assert_cond(script_bytes[39] == OP_EQUALVERIFY)
        assert_cond(script_bytes[40] == OP_2)
        assert_cond(script_bytes[41] == 33)
        pk1 = script_bytes[42: 42 + 33]
        assert_cond(script_bytes[75] == 33)
        pk2 = script_bytes[76: 76 + 33]
        assert_cond(script_bytes[109] == OP_2)
        assert_cond(script_bytes[110] == OP_CHECKMULTISIG)
        assert_cond(script_bytes[111] == OP_ELSE)
        o = 112

        #  Decode script num
        csv_val, nb = decodeScriptNum(script_bytes, o)
        o += nb

        assert_cond(script_len == o + 8 + 66, 'Bad script length')  # Fails if script too long
        assert_cond(script_bytes[o] == OP_CHECKSEQUENCEVERIFY)
        o += 1
        assert_cond(script_bytes[o] == OP_DROP)
        o += 1
        assert_cond(script_bytes[o] == OP_2)
        o += 1
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk3 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk4 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == OP_2)
        o += 1
        assert_cond(script_bytes[o] == OP_CHECKMULTISIG)
        o += 1
        assert_cond(script_bytes[o] == OP_ENDIF)

        return secret_hash, pk1, pk2, csv_val, pk3, pk4

    def genScriptLockTxScript(self, sh, Kal, Kaf, lock_blocks, Karl, Karf):

        Kal_enc = Kal if len(Kal) == 33 else self.encodePubkey(Kal)
        Kaf_enc = Kaf if len(Kaf) == 33 else self.encodePubkey(Kaf)
        Karl_enc = Karl if len(Karl) == 33 else self.encodePubkey(Karl)
        Karf_enc = Karf if len(Karf) == 33 else self.encodePubkey(Karf)

        return CScript([
            CScriptOp(OP_IF),
            CScriptOp(OP_SIZE), 32, CScriptOp(OP_EQUALVERIFY),
            CScriptOp(OP_SHA256), sh, CScriptOp(OP_EQUALVERIFY),
            2, Kal_enc, Kaf_enc, 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ELSE),
            lock_blocks, CScriptOp(OP_CHECKSEQUENCEVERIFY), CScriptOp(OP_DROP),
            2, Karl_enc, Karf_enc, 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ENDIF)])

    def createScriptLockTx(self, value, sh, Kal, Kaf, lock_blocks, Karl, Karf):

        script = self.genScriptLockTxScript(sh, Kal, Kaf, lock_blocks, Karl, Karf)
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType(value, CScript([OP_0, hashlib.sha256(script).digest()])))

        return tx.serialize(), script

    def extractScriptLockRefundScriptValues(self, script_bytes):
        script_len = len(script_bytes)
        assert_cond(script_len > 73, 'Bad script length')
        assert_cond(script_bytes[0] == OP_IF)
        assert_cond(script_bytes[1] == OP_2)
        assert_cond(script_bytes[2] == 33)
        pk1 = script_bytes[3: 3 + 33]
        assert_cond(script_bytes[36] == 33)
        pk2 = script_bytes[37: 37 + 33]
        assert_cond(script_bytes[70] == OP_2)
        assert_cond(script_bytes[71] == OP_CHECKMULTISIG)
        assert_cond(script_bytes[72] == OP_ELSE)
        o = 73
        csv_val, nb = decodeScriptNum(script_bytes, o)
        o += nb

        assert_cond(script_len == o + 5 + 33, 'Bad script length')  # Fails if script too long
        assert_cond(script_bytes[o] == OP_CHECKSEQUENCEVERIFY)
        o += 1
        assert_cond(script_bytes[o] == OP_DROP)
        o += 1
        assert_cond(script_bytes[o] == 33)
        o += 1
        pk3 = script_bytes[o: o + 33]
        o += 33
        assert_cond(script_bytes[o] == OP_CHECKSIG)
        o += 1
        assert_cond(script_bytes[o] == OP_ENDIF)

        return pk1, pk2, csv_val, pk3

    def genScriptLockRefundTxScript(self, Karl, Karf, csv_val, Kaf):

        Kaf_enc = Kaf if len(Kaf) == 33 else self.encodePubkey(Kaf)
        Karl_enc = Karl if len(Karl) == 33 else self.encodePubkey(Karl)
        Karf_enc = Karf if len(Karf) == 33 else self.encodePubkey(Karf)

        return CScript([
            CScriptOp(OP_IF),
            2, Karl_enc, Karf_enc, 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ELSE),
            csv_val, CScriptOp(OP_CHECKSEQUENCEVERIFY), CScriptOp(OP_DROP),
            Kaf_enc, CScriptOp(OP_CHECKSIG),
            CScriptOp(OP_ENDIF)])

    def createScriptLockRefundTx(self, tx_lock_bytes, script_lock, Karl, Karf, csv_val, Kaf, tx_fee_rate):
        tx_lock = CTransaction()
        tx_lock = FromHex(tx_lock, tx_lock_bytes.hex())

        output_script = CScript([OP_0, hashlib.sha256(script_lock).digest()])
        locked_n = findOutput(tx_lock, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_hash_int = tx_lock.sha256

        sh, A, B, lock1_value, C, D = self.extractScriptLockScriptValues(script_lock)

        refund_script = self.genScriptLockRefundTxScript(Karl, Karf, csv_val, Kaf)
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_hash_int, locked_n), nSequence=lock1_value))
        tx.vout.append(self.txoType(locked_coin, CScript([OP_0, hashlib.sha256(refund_script).digest()])))

        witness_bytes = len(script_lock)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 2  # 2 empty witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockRefundTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize(), refund_script, tx.vout[0].nValue

    def createScriptLockRefundSpendTx(self, tx_lock_refund_bytes, script_lock_refund, Kal, tx_fee_rate):
        # Returns the coinA locked coin to the leader
        # The follower will sign the multisig path with a signature encumbered by the leader's coinB spend pubkey
        # When the leader publishes the decrypted signature the leader's coinB spend privatekey will be revealed to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = CScript([OP_0, hashlib.sha256(script_lock_refund).digest()])
        locked_n = findOutput(tx_lock_refund, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n), nSequence=0))

        #pubkeyhash = hash160(self.encodePubkey(Kal))
        pubkeyhash = hash160(Kal)
        tx.vout.append(self.txoType(locked_coin, CScript([OP_0, pubkeyhash])))

        witness_bytes = len(script_lock_refund)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byte size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockRefundSpendTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize()

    def createScriptLockRefundSpendToFTx(self, tx_lock_refund, script_lock_refund, pkh_dest, tx_fee_rate):
        # Sends the coinA locked coin to the follower
        output_script = CScript([OP_0, hashlib.sha256(script_lock_refund).digest()])
        locked_n = findOutput(tx_lock_refund, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        A, B, lock2_value, C = self.extractScriptLockRefundScriptValues(script_lock_refund)

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n), nSequence=lock2_value))

        tx.vout.append(self.txoType(locked_coin, CScript([OP_0, pkh_dest])))

        witness_bytes = len(script_lock_refund)
        witness_bytes += 73  # signature (72 + 1 byte size)
        witness_bytes += 1  # 1 empty stack value
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockRefundSpendToFTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize()

    def createScriptLockSpendTx(self, tx_lock_bytes, script_lock, pkh_dest, tx_fee_rate):
        tx_lock = self.loadTx(tx_lock_bytes)
        output_script = CScript([OP_0, hashlib.sha256(script_lock).digest()])
        locked_n = findOutput(tx_lock, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_hash_int = tx_lock.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_hash_int, locked_n)))

        p2wpkh = CScript([OP_0, pkh_dest])
        tx.vout.append(self.txoType(locked_coin, p2wpkh))

        witness_bytes = len(script_lock)
        witness_bytes += 33  # sv, size
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = int(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        logging.info('createScriptLockSpendTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                     i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize()

    def verifyLockTx(self, tx_bytes, script_out,
                     swap_value,
                     sh,
                     Kal, Kaf,
                     lock_value, feerate,
                     Karl, Karf,
                     check_lock_tx_inputs):
        # Verify:
        #

        # Not necessary to check the lock txn is mineable, as protocol will wait for it to confirm
        # However by checking early we can avoid wasting time processing unmineable txns
        # Check fee is reasonable

        tx = self.loadTx(tx_bytes)
        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'Bad nLockTime')

        script_pk = CScript([OP_0, hashlib.sha256(script_out).digest()])
        locked_n = findOutput(tx, script_pk)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx.vout[locked_n].nValue

        assert_cond(locked_coin == swap_value, 'Bad locked value')

        # Check script and values
        shv, A, B, csv_val, C, D = self.extractScriptLockScriptValues(script_out)
        assert_cond(shv == sh, 'Bad hash lock')
        assert_cond(A == Kal, 'Bad script pubkey')
        assert_cond(B == Kaf, 'Bad script pubkey')
        assert_cond(csv_val == lock_value, 'Bad script csv value')
        assert_cond(C == Karl, 'Bad script pubkey')
        assert_cond(D == Karf, 'Bad script pubkey')

        if check_lock_tx_inputs:
            # Check that inputs are unspent and verify fee rate
            inputs_value = 0
            add_bytes = 0
            add_witness_bytes = getCompactSizeLen(len(tx.vin))
            for pi in tx.vin:
                ptx = self.rpc_callback('getrawtransaction', [i2h(pi.prevout.hash), True])
                prevout = ptx['vout'][pi.prevout.n]
                inputs_value += make_int(prevout['value'])

                prevout_type = prevout['scriptPubKey']['type']
                if prevout_type == 'witness_v0_keyhash':
                    add_witness_bytes += 107  # sig 72, pk 33 and 2 size bytes
                    add_witness_bytes += getCompactSizeLen(107)
                else:
                    # Assume P2PKH, TODO more types
                    add_bytes += 107  # OP_PUSH72 <ecdsa_signature> OP_PUSH33 <public_key>

            outputs_value = 0
            for txo in tx.vout:
                outputs_value += txo.nValue
            fee_paid = inputs_value - outputs_value
            assert(fee_paid > 0)

            vsize = self.getTxVSize(tx, add_bytes, add_witness_bytes)
            fee_rate_paid = fee_paid * 1000 / vsize

            logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', locked_coin, vsize, fee_rate_paid)

            if not self.compareFeeRates(fee_rate_paid, feerate):
                logging.warning('feerate paid doesn\'t match expected: %ld, %ld', fee_rate_paid, feerate)
                # TODO: Display warning to user

        return tx_hash, locked_n

    def verifyLockRefundTx(self, tx_bytes, script_out,
                           prevout_id, prevout_n, prevout_seq, prevout_script,
                           Karl, Karf, csv_val_expect, Kaf, swap_value, feerate):
        # Verify:
        #   Must have only one input with correct prevout and sequence
        #   Must have only one output to the p2wsh of the lock refund script
        #   Output value must be locked_coin - lock tx fee

        tx = self.loadTx(tx_bytes)
        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock refund tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'nLockTime not 0')
        assert_cond(len(tx.vin) == 1, 'tx doesn\'t have one input')

        assert_cond(tx.vin[0].nSequence == prevout_seq, 'Bad input nSequence')
        assert_cond(len(tx.vin[0].scriptSig) == 0, 'Input scriptsig not empty')
        assert_cond(tx.vin[0].prevout.hash == b2i(prevout_id) and tx.vin[0].prevout.n == prevout_n, 'Input prevout mismatch')

        assert_cond(len(tx.vout) == 1, 'tx doesn\'t have one output')

        script_pk = CScript([OP_0, hashlib.sha256(script_out).digest()])
        locked_n = findOutput(tx, script_pk)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = tx.vout[locked_n].nValue

        # Check script and values
        A, B, csv_val, C = self.extractScriptLockRefundScriptValues(script_out)
        assert_cond(A == Karl, 'Bad script pubkey')
        assert_cond(B == Karf, 'Bad script pubkey')
        assert_cond(csv_val == csv_val_expect, 'Bad script csv value')
        assert_cond(C == Kaf, 'Bad script pubkey')

        fee_paid = swap_value - locked_coin
        assert(fee_paid > 0)

        witness_bytes = len(prevout_script)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 2  # 2 empty witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 / vsize

        logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', locked_coin, vsize, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate')

        return tx_hash, locked_coin

    def verifyLockRefundSpendTx(self, tx_bytes,
                                lock_refund_tx_id, prevout_script,
                                Kal,
                                prevout_value, feerate):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output sending lock refund tx value - fee to leader's address, TODO: follower shouldn't need to verify destination addr
        tx = self.loadTx(tx_bytes)
        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock refund spend tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'nLockTime not 0')
        assert_cond(len(tx.vin) == 1, 'tx doesn\'t have one input')

        assert_cond(tx.vin[0].nSequence == 0, 'Bad input nSequence')
        assert_cond(len(tx.vin[0].scriptSig) == 0, 'Input scriptsig not empty')
        assert_cond(tx.vin[0].prevout.hash == b2i(lock_refund_tx_id) and tx.vin[0].prevout.n == 0, 'Input prevout mismatch')

        assert_cond(len(tx.vout) == 1, 'tx doesn\'t have one output')

        p2wpkh = CScript([OP_0, hash160(Kal)])
        locked_n = findOutput(tx, p2wpkh)
        assert_cond(locked_n is not None, 'Output not found in lock refund spend tx')
        tx_value = tx.vout[locked_n].nValue

        fee_paid = prevout_value - tx_value
        assert(fee_paid > 0)

        witness_bytes = len(prevout_script)
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 / vsize

        logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', tx_value, vsize, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate')

        return True

    def verifyLockSpendTx(self, tx_bytes,
                          lock_tx_bytes, lock_tx_script,
                          a_pkhash_f, feerate):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output with destination and amount

        tx = self.loadTx(tx_bytes)
        tx_hash = self.getTxHash(tx)
        logging.info('Verifying lock spend tx: {}.'.format(b2h(tx_hash)))

        assert_cond(tx.nVersion == self.txVersion(), 'Bad version')
        assert_cond(tx.nLockTime == 0, 'nLockTime not 0')
        assert_cond(len(tx.vin) == 1, 'tx doesn\'t have one input')

        lock_tx = self.loadTx(lock_tx_bytes)
        lock_tx_id = self.getTxHash(lock_tx)

        output_script = CScript([OP_0, hashlib.sha256(lock_tx_script).digest()])
        locked_n = findOutput(lock_tx, output_script)
        assert_cond(locked_n is not None, 'Output not found in tx')
        locked_coin = lock_tx.vout[locked_n].nValue

        assert_cond(tx.vin[0].nSequence == 0, 'Bad input nSequence')
        assert_cond(len(tx.vin[0].scriptSig) == 0, 'Input scriptsig not empty')
        assert_cond(tx.vin[0].prevout.hash == b2i(lock_tx_id) and tx.vin[0].prevout.n == locked_n, 'Input prevout mismatch')

        assert_cond(len(tx.vout) == 1, 'tx doesn\'t have one output')
        p2wpkh = CScript([OP_0, a_pkhash_f])
        assert_cond(tx.vout[0].scriptPubKey == p2wpkh, 'Bad output destination')

        fee_paid = locked_coin - tx.vout[0].nValue
        assert(fee_paid > 0)

        witness_bytes = len(lock_tx_script)
        witness_bytes += 33  # sv, size
        witness_bytes += 73 * 2  # 2 signatures (72 + 1 byts size)
        witness_bytes += 4  # 1 empty, 1 true witness stack values
        witness_bytes += getCompactSizeLen(witness_bytes)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 / vsize

        logging.info('tx amount, vsize, feerate: %ld, %ld, %ld', tx.vout[0].nValue, vsize, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate')

        return True

    def signTx(self, key_bytes, tx_bytes, prevout_n, prevout_script, prevout_value):
        # TODO: use libsecp356k1
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)

        eck = ECKey()
        eck.set(key_bytes, compressed=True)

        return eck.sign_ecdsa(sig_hash) + b'\x01'  # 0x1 is SIGHASH_ALL

    def signTxOtVES(self, key_sign, pubkey_encrypt, tx_bytes, prevout_n, prevout_script, prevout_value):
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)

        return ecdsaotves_enc_sign(key_sign, pubkey_encrypt, sig_hash)
        #return otves.EncSign(key_sign, key_encrypt, sig_hash)

    def verifyTxOtVES(self, tx_bytes, sig, Ks, Ke, prevout_n, prevout_script, prevout_value):
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)
        return ecdsaotves_enc_verify(Ks, Ke, sig_hash, sig)
        #return otves.EncVrfy(Ks, Ke, sig_hash, sig)

    def decryptOtVES(self, k, esig):
        return ecdsaotves_dec_sig(k, esig) + b'\x01'  # 0x1 is SIGHASH_ALL
        #return otves.DecSig(k, esig) + b'\x01'  # 0x1 is SIGHASH_ALL

    def verifyTxSig(self, tx_bytes, sig, K, prevout_n, prevout_script, prevout_value):
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(prevout_script, tx, prevout_n, SIGHASH_ALL, prevout_value)

        ecK = ECPubKey()
        #ecK.set_int(K.x(), K.y())
        ecK.set(K)
        return ecK.verify_ecdsa(sig[: -1], sig_hash)  # Pop the hashtype byte

    def fundTx(self, tx, feerate):
        feerate_str = format_amount(feerate, self.exp())
        # TODO: unlock unspents if bid cancelled
        options = {
            'lockUnspents': True,
            'feeRate': feerate_str,
        }
        rv = self.rpc_callback('fundrawtransaction', [tx.hex(), options])
        return bytes.fromhex(rv['hex'])

    def signTxWithWallet(self, tx):
        rv = self.rpc_callback('signrawtransactionwithwallet', [tx.hex()])

        #return FromHex(tx, rv['hex'])
        return bytes.fromhex(rv['hex'])

    def publishTx(self, tx):
        return self.rpc_callback('sendrawtransaction', [tx.hex()])

    def encodeTx(self, tx):
        return tx.serialize()

    def loadTx(self, tx_bytes):
        # Load tx from bytes to internal representation
        tx = CTransaction()
        tx.deserialize(BytesIO(tx_bytes))
        return tx

    def getTxHash(self, tx):
        if isinstance(tx, bytes):
            tx = self.loadTx(tx)
        tx.rehash()
        return i2b(tx.sha256)

    def getPubkeyHash(self, K):
        return hash160(self.encodePubkey(K))

    def getScriptDest(self, script):
        return CScript([OP_0, hashlib.sha256(script).digest()])

    def getPkDest(self, K):
        return CScript([OP_0, self.getPubkeyHash(K)])

    def scanTxOutset(self, dest):
        return self.rpc_callback('scantxoutset', ['start', ['raw({})'.format(dest.hex())]])

    def getTransaction(self, txid):
        try:
            return bytes.fromhex(self.rpc_callback('getrawtransaction', [txid.hex()]))
        except Exception as ex:
            # TODO: filter errors
            return None

    def setTxSignature(self, tx_bytes, stack):
        tx = self.loadTx(tx_bytes)
        tx.wit.vtxinwit.clear()
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        return tx.serialize()

    def extractLeaderSig(self, tx_bytes):
        tx = self.loadTx(tx_bytes)
        return tx.wit.vtxinwit[0].scriptWitness.stack[1]

    def extractFollowerSig(self, tx_bytes):
        tx = self.loadTx(tx_bytes)
        return tx.wit.vtxinwit[0].scriptWitness.stack[2]

    def createBLockTx(self, Kbs, output_amount):
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        p2wpkh = self.getPkDest(Kbs)
        tx.vout.append(self.txoType(output_amount, p2wpkh))
        return tx.serialize()

    def publishBLockTx(self, Kbv, Kbs, output_amount, feerate):
        b_lock_tx = self.createBLockTx(Kbs, output_amount)

        b_lock_tx = self.fundTx(b_lock_tx, feerate)
        b_lock_tx_id = self.getTxHash(b_lock_tx)
        b_lock_tx = self.signTxWithWallet(b_lock_tx)

        return self.publishTx(b_lock_tx)

    def recoverEncKey(self, esig, sig, K):
        return ecdsaotves_rec_enc_key(K, esig, sig[:-1])  # Strip sighash type
        #return otves.RecoverEncKey(esig, sig[:-1], K)  # Strip sighash type

    def getTxVSize(self, tx, add_bytes=0, add_witness_bytes=0):
        wsf = self.witnessScaleFactor()
        len_full = len(tx.serialize_with_witness()) + add_bytes + add_witness_bytes
        len_nwit = len(tx.serialize_without_witness()) + add_bytes
        weight = len_nwit * (wsf - 1) + len_full
        return (weight + wsf - 1) // wsf

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):
        raw_dest = self.getPkDest(Kbs)

        rv = self.scanTxOutset(raw_dest)
        print('scanTxOutset', dumpj(rv))

        for utxo in rv['unspents']:
            if 'height' in utxo and utxo['height'] > 0 and rv['height'] - utxo['height'] > cb_block_confirmed:
                if utxo['amount'] * COIN != cb_swap_value:
                    logging.warning('Found output to lock tx pubkey of incorrect value: %s', str(utxo['amount']))
                else:
                    return {'txid': utxo['txid'], 'vout': utxo['vout'], 'amount': utxo['amount'], 'height': utxo['height']}
        return None

    def waitForLockTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed):

        raw_dest = self.getPkDest(Kbs)

        for i in range(20):
            time.sleep(1)
            rv = self.scanTxOutset(raw_dest)
            print('scanTxOutset', dumpj(rv))

            for utxo in rv['unspents']:
                if 'height' in utxo and utxo['height'] > 0 and rv['height'] - utxo['height'] > cb_block_confirmed:

                    if utxo['amount'] * COIN != cb_swap_value:
                        logging.warning('Found output to lock tx pubkey of incorrect value: %s', str(utxo['amount']))
                    else:
                        return True
        return False

    def spendBLockTx(self, address_to, kbv, kbs, cb_swap_value, b_fee, restore_height):
        print('TODO: spendBLockTx')

    def getOutput(self, txid, dest_script, expect_value):
        # TODO: Use getrawtransaction if txindex is active
        utxos = self.rpc_callback('scantxoutset', ['start', ['raw({})'.format(dest_script.hex())]])
        print('utxos', utxos)

        chain_height = utxos['height']
        rv = []
        for utxo in utxos['unspents']:
            print('utxo', utxo)
            depth = 0 if 'height' not in utxo else utxos['height'] - utxo['height']

            if txid and txid.hex() != utxo['txid']:
                continue

            if expect_value != utxo['amount'] * COIN:
                continue

            rv.append({
                'depth': depth,
                'amount': utxo['amount'] * COIN,
                'txid': utxo['txid'],
                'vout': utxo['vout']})
        return rv



def testBTCInterface():
    print('testBTCInterface')
    script_bytes = bytes.fromhex('6382012088a820aaf125ff9a34a74c7a17f5e7ee9d07d17cc5e53a539f345d5f73baa7e79b65e28852210224019219ad43c47288c937ae508f26998dd81ec066827773db128fd5e262c04f21039a0fd752bd1a2234820707852e7a30253620052ecd162948a06532a817710b5952ae670114b2755221038689deba25c5578e5457ddadbaf8aeb8badf438dc22f540503dbd4ae10e14f512103c9c5d5acc996216d10852a72cd67c701bfd4b9137a4076350fd32f08db39575552ae68')
    i = BTCInterface(None)
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes)
    assert(csv_val == 20)

    script_bytes_t = script_bytes + bytes((0x00,))
    try:
        sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad script length')

    script_bytes_t = script_bytes[:-1]
    try:
        sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad script length')

    script_bytes_t = bytes((0x00,)) + script_bytes[1:]
    try:
        sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad opcode')

    # Remove the csv value
    script_part_a = script_bytes[:112]
    script_part_b = script_bytes[114:]

    script_bytes_t = script_part_a + bytes((0x00,)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 0)

    script_bytes_t = script_part_a + bytes((OP_16,)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 16)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(17)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 17)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(-15)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == -15)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(4000)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == 4000)

    max_pos = 0x7FFFFFFF
    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(max_pos)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == max_pos)
    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(max_pos - 1)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == max_pos - 1)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(max_pos + 1)) + script_part_b
    try:
        sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad scriptnum length')

    min_neg = -2147483647
    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(min_neg)) + script_part_b
    sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
    assert(csv_val == min_neg)

    script_bytes_t = script_part_a + CScriptNum.encode(CScriptNum(min_neg - 1)) + script_part_b
    try:
        sh, a, b, csv_val, c, d = i.extractScriptLockScriptValues(script_bytes_t)
        assert(False), 'Should fail'
    except Exception as e:
        assert(str(e) == 'Bad scriptnum length')

    print('Passed.')


if __name__ == "__main__":
    testBTCInterface()
