#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
from enum import IntEnum

from basicswap.contrib.test_framework.messages import (
    CTxOutPart,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_0,
    OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
)
from basicswap.util import (
    i2b,
    ensure,
    make_int,
    TemporaryError,
)
from basicswap.util.script import (
    getP2WSH,
    getCompactSizeLen,
    getWitnessElementLen,
)
from basicswap.util.address import (
    toWIF,
    encodeStealthAddress)
from basicswap.chainparams import Coins, chainparams
from .btc import BTCInterface


class BalanceTypes(IntEnum):
    PLAIN = 1
    BLIND = 2
    ANON = 3


class PARTInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.PART

    @staticmethod
    def balance_type():
        return BalanceTypes.PLAIN

    @staticmethod
    def witnessScaleFactor() -> int:
        return 2

    @staticmethod
    def txVersion() -> int:
        return 0xa0

    @staticmethod
    def xmr_swap_alock_spend_tx_vsize() -> int:
        return 213

    @staticmethod
    def txoType():
        return CTxOutPart

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__(coin_settings, network, swap_client)
        self.setAnonTxRingSize(int(coin_settings.get('anon_tx_ring_size', 12)))

    def setAnonTxRingSize(self, value):
        ensure(value >= 3 and value < 33, 'Invalid anon_tx_ring_size value')
        self._anon_tx_ring_size = value

    def knownWalletSeed(self):
        # TODO: Double check
        return True

    def getNewAddress(self, use_segwit, label='swap_receive'):
        return self.rpc_callback('getnewaddress', [label])

    def getNewStealthAddress(self, label='swap_stealth'):
        return self.rpc_callback('getnewstealthaddress', [label])

    def haveSpentIndex(self):
        version = self.getDaemonVersion()
        index_info = self.rpc_callback('getinsightinfo' if int(str(version)[:2]) > 19 else 'getindexinfo')
        return index_info['spentindex']

    def initialiseWallet(self, key):
        raise ValueError('TODO')

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee, '', True, self._conf_target]
        return self.rpc_callback('sendtoaddress', params)

    def sendTypeTo(self, type_from, type_to, value, addr_to, subfee):
        params = [type_from, type_to,
                  [{'address': addr_to, 'amount': value, 'subfee': subfee}, ],
                  '', '', self._anon_tx_ring_size, 1, False,
                  {'conf_target': self._conf_target}]
        return self.rpc_callback('sendtypeto', params)

    def getScriptForPubkeyHash(self, pkh):
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def formatStealthAddress(self, scan_pubkey, spend_pubkey):
        prefix_byte = chainparams[self.coin_type()][self._network]['stealth_key_prefix']

        return encodeStealthAddress(prefix_byte, scan_pubkey, spend_pubkey)

    def getWitnessStackSerialisedLength(self, witness_stack):
        length = getCompactSizeLen(len(witness_stack))
        for e in witness_stack:
            length += getWitnessElementLen(len(e) // 2)  # hex -> bytes
        return length

    def getWalletRestoreHeight(self):
        start_time = self.rpc_callback('getwalletinfo')['keypoololdest']

        blockchaininfo = self.rpc_callback('getblockchaininfo')
        best_block = blockchaininfo['bestblockhash']

        chain_synced = round(blockchaininfo['verificationprogress'], 3)
        if chain_synced < 1.0:
            raise ValueError('{} chain isn\'t synced.'.format(self.coin_name()))

        self._log.debug('Finding block at time: {}'.format(start_time))
        block_hash = self.rpc_callback('getblockhashafter', [start_time])
        block_header = self.rpc_callback('getblockheader', [block_hash])
        return block_header['height']


class PARTInterfaceBlind(PARTInterface):
    @staticmethod
    def balance_type():
        return BalanceTypes.BLIND

    def coin_name(self):
        return super().coin_name() + ' Blind'

    def getScriptLockTxNonce(self, data):
        return hashlib.sha256(data + bytes('locktx', 'utf-8')).digest()

    def getScriptLockRefundTxNonce(self, data):
        return hashlib.sha256(data + bytes('lockrefundtx', 'utf-8')).digest()

    def findOutputByNonce(self, tx_obj, nonce):
        blinded_info = None
        output_n = None
        for txo in tx_obj['vout']:
            if txo['type'] != 'blind':
                continue
            try:
                blinded_info = self.rpc_callback('rewindrangeproof', [txo['rangeproof'], txo['valueCommitment'], nonce.hex()])
                output_n = txo['n']

                self.rpc_callback('rewindrangeproof', [txo['rangeproof'], txo['valueCommitment'], nonce.hex()])
                break
            except Exception as e:
                self._log.debug('Searching for locked output: {}'.format(str(e)))
                continue
            # Should not be possible for commitment not to match
            v = self.rpc_callback('verifycommitment', [txo['valueCommitment'], blinded_info['blind'], blinded_info['amount']])
            ensure(v['result'] is True, 'verifycommitment failed')
        return output_n, blinded_info

    def createSCLockTx(self, value: int, script: bytearray, vkbv) -> bytes:

        # Nonce is derived from vkbv, ephemeral_key isn't used
        ephemeral_key = i2b(self.getNewSecretKey())
        ephemeral_pubkey = self.getPubkey(ephemeral_key)
        assert (len(ephemeral_pubkey) == 33)
        nonce = self.getScriptLockTxNonce(vkbv)
        p2wsh_addr = self.encode_p2wsh(getP2WSH(script))
        inputs = []
        outputs = [{'type': 'blind', 'amount': self.format_amount(value), 'address': p2wsh_addr, 'nonce': nonce.hex(), 'data': ephemeral_pubkey.hex()}]
        params = [inputs, outputs]
        rv = self.rpc_callback('createrawparttransaction', params)

        tx_bytes = bytes.fromhex(rv['hex'])
        return tx_bytes

    def fundSCLockTx(self, tx_bytes, feerate, vkbv):
        feerate_str = self.format_amount(feerate)
        # TODO: unlock unspents if bid cancelled

        tx_hex = tx_bytes.hex()
        nonce = self.getScriptLockTxNonce(vkbv)

        tx_obj = self.rpc_callback('decoderawtransaction', [tx_hex])

        assert (len(tx_obj['vout']) == 1)
        txo = tx_obj['vout'][0]
        blinded_info = self.rpc_callback('rewindrangeproof', [txo['rangeproof'], txo['valueCommitment'], nonce.hex()])

        outputs_info = {0: {'value': blinded_info['amount'], 'blind': blinded_info['blind'], 'nonce': nonce.hex()}}

        options = {
            'lockUnspents': True,
            'feeRate': feerate_str,
        }
        rv = self.rpc_callback('fundrawtransactionfrom', ['blind', tx_hex, {}, outputs_info, options])
        return bytes.fromhex(rv['hex'])

    def createSCLockRefundTx(self, tx_lock_bytes, script_lock, Kal, Kaf, lock1_value, csv_val, tx_fee_rate, vkbv):
        lock_tx_obj = self.rpc_callback('decoderawtransaction', [tx_lock_bytes.hex()])
        assert (self.getTxid(tx_lock_bytes).hex() == lock_tx_obj['txid'])
        # Nonce is derived from vkbv, ephemeral_key isn't used
        ephemeral_key = i2b(self.getNewSecretKey())
        ephemeral_pubkey = self.getPubkey(ephemeral_key)
        assert (len(ephemeral_pubkey) == 33)
        nonce = self.getScriptLockTxNonce(vkbv)
        output_nonce = self.getScriptLockRefundTxNonce(vkbv)

        # Find the output of the lock tx to spend
        spend_n, input_blinded_info = self.findOutputByNonce(lock_tx_obj, nonce)
        ensure(spend_n is not None, 'Output not found in tx')

        locked_coin = input_blinded_info['amount']
        tx_lock_id = lock_tx_obj['txid']
        refund_script = self.genScriptLockRefundTxScript(Kal, Kaf, csv_val)
        p2wsh_addr = self.encode_p2wsh(getP2WSH(refund_script))

        inputs = [{'txid': tx_lock_id, 'vout': spend_n, 'sequence': lock1_value, 'blindingfactor': input_blinded_info['blind']}]
        outputs = [{'type': 'blind', 'amount': locked_coin, 'address': p2wsh_addr, 'nonce': output_nonce.hex(), 'data': ephemeral_pubkey.hex()}]
        params = [inputs, outputs]
        rv = self.rpc_callback('createrawparttransaction', params)
        lock_refund_tx_hex = rv['hex']

        # Set dummy witness data for fee estimation
        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)

        # Use a junk change pubkey to avoid adding unused keys to the wallet
        zero_change_key = i2b(self.getNewSecretKey())
        zero_change_pubkey = self.getPubkey(zero_change_key)
        inputs_info = {'0': {'value': input_blinded_info['amount'], 'blind': input_blinded_info['blind'], 'witnessstack': dummy_witness_stack}}
        outputs_info = rv['amounts']
        options = {
            'changepubkey': zero_change_pubkey.hex(),
            'feeRate': self.format_amount(tx_fee_rate),
            'subtractFeeFromOutputs': [0, ]
        }
        rv = self.rpc_callback('fundrawtransactionfrom', ['blind', lock_refund_tx_hex, inputs_info, outputs_info, options])
        lock_refund_tx_hex = rv['hex']

        for vout, txo in rv['output_amounts'].items():
            if txo['value'] > 0:
                refunded_value = txo['value']

        return bytes.fromhex(lock_refund_tx_hex), refund_script, refunded_value

    def createSCLockRefundSpendTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_refund_to, tx_fee_rate, vkbv):
        # Returns the coinA locked coin to the leader
        # The follower will sign the multisig path with a signature encumbered by the leader's coinB spend pubkey
        # If the leader publishes the decrypted signature the leader's coinB spend privatekey will be revealed to the follower

        lock_refund_tx_obj = self.rpc_callback('decoderawtransaction', [tx_lock_refund_bytes.hex()])
        # Nonce is derived from vkbv
        nonce = self.getScriptLockRefundTxNonce(vkbv)

        # Find the output of the lock refund tx to spend
        spend_n, input_blinded_info = self.findOutputByNonce(lock_refund_tx_obj, nonce)
        ensure(spend_n is not None, 'Output not found in tx')

        tx_lock_refund_id = lock_refund_tx_obj['txid']
        addr_out = self.pkh_to_address(pkh_refund_to)
        addr_info = self.rpc_callback('getaddressinfo', [addr_out])
        output_pubkey_hex = addr_info['pubkey']

        # Follower won't be able to decode output to check amount, shouldn't matter as fee is public and output is to leader, sum has to balance

        inputs = [{'txid': tx_lock_refund_id, 'vout': spend_n, 'sequence': 0, 'blindingfactor': input_blinded_info['blind']}]
        outputs = [{'type': 'blind', 'amount': input_blinded_info['amount'], 'address': addr_out, 'pubkey': output_pubkey_hex}]
        params = [inputs, outputs]
        rv = self.rpc_callback('createrawparttransaction', params)
        lock_refund_spend_tx_hex = rv['hex']

        # Set dummy witness data for fee estimation
        dummy_witness_stack = self.getScriptLockRefundSpendTxDummyWitness(script_lock_refund)

        # Use a junk change pubkey to avoid adding unused keys to the wallet
        zero_change_key = i2b(self.getNewSecretKey())
        zero_change_pubkey = self.getPubkey(zero_change_key)
        inputs_info = {'0': {'value': input_blinded_info['amount'], 'blind': input_blinded_info['blind'], 'witnessstack': dummy_witness_stack}}
        outputs_info = rv['amounts']
        options = {
            'changepubkey': zero_change_pubkey.hex(),
            'feeRate': self.format_amount(tx_fee_rate),
            'subtractFeeFromOutputs': [0, ]
        }

        rv = self.rpc_callback('fundrawtransactionfrom', ['blind', lock_refund_spend_tx_hex, inputs_info, outputs_info, options])
        lock_refund_spend_tx_hex = rv['hex']

        return bytes.fromhex(lock_refund_spend_tx_hex)

    def verifySCLockTx(self, tx_bytes, script_out,
                       swap_value,
                       Kal, Kaf,
                       feerate,
                       check_lock_tx_inputs, vkbv):
        lock_tx_obj = self.rpc_callback('decoderawtransaction', [tx_bytes.hex()])
        lock_txid_hex = lock_tx_obj['txid']
        self._log.info('Verifying lock tx: {}.'.format(lock_txid_hex))

        ensure(lock_tx_obj['version'] == self.txVersion(), 'Bad version')
        ensure(lock_tx_obj['locktime'] == 0, 'Bad nLockTime')

        # Find the output of the lock tx to verify
        nonce = self.getScriptLockTxNonce(vkbv)
        lock_output_n, blinded_info = self.findOutputByNonce(lock_tx_obj, nonce)
        ensure(lock_output_n is not None, 'Output not found in tx')

        # Check value
        locked_txo_value = make_int(blinded_info['amount'])
        ensure(locked_txo_value == swap_value, 'Bad locked value')

        # Check script
        lock_txo_scriptpk = bytes.fromhex(lock_tx_obj['vout'][lock_output_n]['scriptPubKey']['hex'])
        script_pk = CScript([OP_0, hashlib.sha256(script_out).digest()])
        ensure(lock_txo_scriptpk == script_pk, 'Bad output script')
        A, B = self.extractScriptLockScriptValues(script_out)
        ensure(A == Kal, 'Bad script leader pubkey')
        ensure(B == Kaf, 'Bad script follower pubkey')

        # TODO: Check that inputs are unspent, rangeproofs and commitments sum
        # Verify fee rate
        vsize = lock_tx_obj['vsize']
        fee_paid = make_int(lock_tx_obj['vout'][0]['ct_fee'])

        fee_rate_paid = fee_paid * 1000 // vsize

        self._log.info('tx amount, vsize, feerate: %ld, %ld, %ld', locked_txo_value, vsize, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            self._log.warning('feerate paid doesn\'t match expected: %ld, %ld', fee_rate_paid, feerate)
            # TODO: Display warning to user

        return bytes.fromhex(lock_txid_hex), lock_output_n

    def verifySCLockRefundTx(self, tx_bytes, lock_tx_bytes, script_out,
                             prevout_id, prevout_n, prevout_seq, prevout_script,
                             Kal, Kaf, csv_val_expect, swap_value, feerate, vkbv):
        lock_refund_tx_obj = self.rpc_callback('decoderawtransaction', [tx_bytes.hex()])
        lock_refund_txid_hex = lock_refund_tx_obj['txid']
        self._log.info('Verifying lock refund tx: {}.'.format(lock_refund_txid_hex))

        ensure(lock_refund_tx_obj['version'] == self.txVersion(), 'Bad version')
        ensure(lock_refund_tx_obj['locktime'] == 0, 'Bad nLockTime')
        ensure(len(lock_refund_tx_obj['vin']) == 1, 'tx doesn\'t have one input')

        txin = lock_refund_tx_obj['vin'][0]
        ensure(txin['sequence'] == prevout_seq, 'Bad input nSequence')
        ensure(txin['scriptSig']['hex'] == '', 'Input scriptsig not empty')
        ensure(txin['txid'] == prevout_id.hex() and txin['vout'] == prevout_n, 'Input prevout mismatch')

        ensure(len(lock_refund_tx_obj['vout']) == 3, 'tx doesn\'t have three outputs')

        # Find the output of the lock refund tx to verify
        nonce = self.getScriptLockRefundTxNonce(vkbv)
        lock_refund_output_n, blinded_info = self.findOutputByNonce(lock_refund_tx_obj, nonce)
        ensure(lock_refund_output_n is not None, 'Output not found in tx')

        lock_refund_txo_value = make_int(blinded_info['amount'])

        # Check script
        lock_refund_txo_scriptpk = bytes.fromhex(lock_refund_tx_obj['vout'][lock_refund_output_n]['scriptPubKey']['hex'])
        script_pk = CScript([OP_0, hashlib.sha256(script_out).digest()])
        ensure(lock_refund_txo_scriptpk == script_pk, 'Bad output script')
        A, B, csv_val, C = self.extractScriptLockRefundScriptValues(script_out)
        ensure(A == Kal, 'Bad script pubkey')
        ensure(B == Kaf, 'Bad script pubkey')
        ensure(csv_val == csv_val_expect, 'Bad script csv value')
        ensure(C == Kaf, 'Bad script pubkey')

        # Check rangeproofs and commitments sum
        lock_tx_obj = self.rpc_callback('decoderawtransaction', [lock_tx_bytes.hex()])
        prevout = lock_tx_obj['vout'][prevout_n]
        prevtxns = [{'txid': prevout_id.hex(), 'vout': prevout_n, 'scriptPubKey': prevout['scriptPubKey']['hex'], 'amount_commitment': prevout['valueCommitment']}]
        rv = self.rpc_callback('verifyrawtransaction', [tx_bytes.hex(), prevtxns])
        ensure(rv['outputs_valid'] is True, 'Invalid outputs')
        ensure(rv['inputs_valid'] is True, 'Invalid inputs')

        # Check value
        fee_paid = make_int(lock_refund_tx_obj['vout'][0]['ct_fee'])
        ensure(swap_value - lock_refund_txo_value == fee_paid, 'Bad output value')

        # Check fee rate
        dummy_witness_stack = self.getScriptLockTxDummyWitness(prevout_script)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(self.loadTx(tx_bytes), add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 // vsize
        self._log.info('vsize, feerate: %ld, %ld', vsize, fee_rate_paid)

        ensure(self.compareFeeRates(fee_rate_paid, feerate), 'Bad fee rate, expected: {}'.format(feerate))

        return bytes.fromhex(lock_refund_txid_hex), lock_refund_txo_value, lock_refund_output_n

    def verifySCLockRefundSpendTx(self, tx_bytes, lock_refund_tx_bytes,
                                  lock_refund_tx_id, prevout_script,
                                  Kal,
                                  prevout_n, prevout_value, feerate, vkbv):
        lock_refund_spend_tx_obj = self.rpc_callback('decoderawtransaction', [tx_bytes.hex()])
        lock_refund_spend_txid_hex = lock_refund_spend_tx_obj['txid']
        self._log.info('Verifying lock refund spend tx: {}.'.format(lock_refund_spend_txid_hex))

        ensure(lock_refund_spend_tx_obj['version'] == self.txVersion(), 'Bad version')
        ensure(lock_refund_spend_tx_obj['locktime'] == 0, 'Bad nLockTime')
        ensure(len(lock_refund_spend_tx_obj['vin']) == 1, 'tx doesn\'t have one input')

        txin = lock_refund_spend_tx_obj['vin'][0]
        ensure(txin['sequence'] == 0, 'Bad input nSequence')
        ensure(txin['scriptSig']['hex'] == '', 'Input scriptsig not empty')
        ensure(txin['txid'] == lock_refund_tx_id.hex() and txin['vout'] == prevout_n, 'Input prevout mismatch')

        ensure(len(lock_refund_spend_tx_obj['vout']) == 3, 'tx doesn\'t have three outputs')

        # Leader picks output destinations
        # Follower is not concerned with them as they pay to leader

        # Check rangeproofs and commitments sum
        lock_refund_tx_obj = self.rpc_callback('decoderawtransaction', [lock_refund_tx_bytes.hex()])
        prevout = lock_refund_tx_obj['vout'][prevout_n]
        prevtxns = [{'txid': lock_refund_tx_id.hex(), 'vout': prevout_n, 'scriptPubKey': prevout['scriptPubKey']['hex'], 'amount_commitment': prevout['valueCommitment']}]
        rv = self.rpc_callback('verifyrawtransaction', [tx_bytes.hex(), prevtxns])
        ensure(rv['outputs_valid'] is True, 'Invalid outputs')
        ensure(rv['inputs_valid'] is True, 'Invalid inputs')

        # Check fee rate
        dummy_witness_stack = self.getScriptLockRefundSpendTxDummyWitness(prevout_script)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(self.loadTx(tx_bytes), add_witness_bytes=witness_bytes)
        fee_paid = make_int(lock_refund_spend_tx_obj['vout'][0]['ct_fee'])
        fee_rate_paid = fee_paid * 1000 // vsize
        ensure(self.compareFeeRates(fee_rate_paid, feerate), 'Bad fee rate, expected: {}'.format(feerate))

        return True

    def getLockTxSwapOutputValue(self, bid, xmr_swap):
        lock_tx_obj = self.rpc_callback('decoderawtransaction', [xmr_swap.a_lock_tx.hex()])
        nonce = self.getScriptLockTxNonce(xmr_swap.vkbv)
        output_n, _ = self.findOutputByNonce(lock_tx_obj, nonce)
        ensure(output_n is not None, 'Output not found in tx')
        return bytes.fromhex(lock_tx_obj['vout'][output_n]['valueCommitment'])

    def getLockRefundTxSwapOutputValue(self, bid, xmr_swap):
        lock_refund_tx_obj = self.rpc_callback('decoderawtransaction', [xmr_swap.a_lock_refund_tx.hex()])
        nonce = self.getScriptLockRefundTxNonce(xmr_swap.vkbv)
        output_n, _ = self.findOutputByNonce(lock_refund_tx_obj, nonce)
        ensure(output_n is not None, 'Output not found in tx')
        return bytes.fromhex(lock_refund_tx_obj['vout'][output_n]['valueCommitment'])

    def getLockRefundTxSwapOutput(self, xmr_swap):
        lock_refund_tx_obj = self.rpc_callback('decoderawtransaction', [xmr_swap.a_lock_refund_tx.hex()])
        nonce = self.getScriptLockRefundTxNonce(xmr_swap.vkbv)
        output_n, _ = self.findOutputByNonce(lock_refund_tx_obj, nonce)
        ensure(output_n is not None, 'Output not found in tx')
        return output_n

    def createSCLockSpendTx(self, tx_lock_bytes, script_lock, pk_dest, tx_fee_rate, vkbv):
        lock_tx_obj = self.rpc_callback('decoderawtransaction', [tx_lock_bytes.hex()])
        lock_txid_hex = lock_tx_obj['txid']

        ensure(lock_tx_obj['version'] == self.txVersion(), 'Bad version')
        ensure(lock_tx_obj['locktime'] == 0, 'Bad nLockTime')

        # Find the output of the lock tx to verify
        nonce = self.getScriptLockTxNonce(vkbv)
        spend_n, blinded_info = self.findOutputByNonce(lock_tx_obj, nonce)
        ensure(spend_n is not None, 'Output not found in tx')

        addr_out = self.pubkey_to_address(pk_dest)

        inputs = [{'txid': lock_txid_hex, 'vout': spend_n, 'sequence': 0, 'blindingfactor': blinded_info['blind']}]
        outputs = [{'type': 'blind', 'amount': blinded_info['amount'], 'address': addr_out, 'pubkey': pk_dest.hex()}]
        params = [inputs, outputs]
        rv = self.rpc_callback('createrawparttransaction', params)
        lock_spend_tx_hex = rv['hex']

        # Set dummy witness data for fee estimation
        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)

        # Use a junk change pubkey to avoid adding unused keys to the wallet
        zero_change_key = i2b(self.getNewSecretKey())
        zero_change_pubkey = self.getPubkey(zero_change_key)
        inputs_info = {'0': {'value': blinded_info['amount'], 'blind': blinded_info['blind'], 'witnessstack': dummy_witness_stack}}
        outputs_info = rv['amounts']
        options = {
            'changepubkey': zero_change_pubkey.hex(),
            'feeRate': self.format_amount(tx_fee_rate),
            'subtractFeeFromOutputs': [0, ]
        }

        rv = self.rpc_callback('fundrawtransactionfrom', ['blind', lock_spend_tx_hex, inputs_info, outputs_info, options])
        lock_spend_tx_hex = rv['hex']
        lock_spend_tx_obj = self.rpc_callback('decoderawtransaction', [lock_spend_tx_hex])

        vsize = lock_spend_tx_obj['vsize']
        pay_fee = make_int(lock_spend_tx_obj['vout'][0]['ct_fee'])
        actual_tx_fee_rate = pay_fee * 1000 // vsize
        self._log.info('createSCLockSpendTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                       lock_spend_tx_obj['txid'], actual_tx_fee_rate, vsize, pay_fee)

        return bytes.fromhex(lock_spend_tx_hex)

    def verifySCLockSpendTx(self, tx_bytes,
                            lock_tx_bytes, lock_tx_script,
                            a_pk_f, feerate, vkbv):
        lock_spend_tx_obj = self.rpc_callback('decoderawtransaction', [tx_bytes.hex()])
        lock_spend_txid_hex = lock_spend_tx_obj['txid']
        self._log.info('Verifying lock spend tx: {}.'.format(lock_spend_txid_hex))

        ensure(lock_spend_tx_obj['version'] == self.txVersion(), 'Bad version')
        ensure(lock_spend_tx_obj['locktime'] == 0, 'Bad nLockTime')
        ensure(len(lock_spend_tx_obj['vin']) == 1, 'tx doesn\'t have one input')

        lock_tx_obj = self.rpc_callback('decoderawtransaction', [lock_tx_bytes.hex()])
        lock_txid_hex = lock_tx_obj['txid']

        # Find the output of the lock tx to verify
        nonce = self.getScriptLockTxNonce(vkbv)
        spend_n, input_blinded_info = self.findOutputByNonce(lock_tx_obj, nonce)
        ensure(spend_n is not None, 'Output not found in tx')

        txin = lock_spend_tx_obj['vin'][0]
        ensure(txin['sequence'] == 0, 'Bad input nSequence')
        ensure(txin['scriptSig']['hex'] == '', 'Input scriptsig not empty')
        ensure(txin['txid'] == lock_txid_hex and txin['vout'] == spend_n, 'Input prevout mismatch')

        ensure(len(lock_spend_tx_obj['vout']) == 3, 'tx doesn\'t have three outputs')

        addr_out = self.pubkey_to_address(a_pk_f)
        privkey = self.rpc_callback('dumpprivkey', [addr_out])

        # Find output:
        output_blinded_info = None
        output_n = None
        for txo in lock_spend_tx_obj['vout']:
            if txo['type'] != 'blind':
                continue
            try:
                output_blinded_info = self.rpc_callback('rewindrangeproof', [txo['rangeproof'], txo['valueCommitment'], privkey, txo['data_hex']])
                output_n = txo['n']
                break
            except Exception as e:
                self._log.debug('Searching for locked output: {}'.format(str(e)))
                pass
        ensure(output_n is not None, 'Output not found in tx')

        # Commitment
        v = self.rpc_callback('verifycommitment', [lock_spend_tx_obj['vout'][output_n]['valueCommitment'], output_blinded_info['blind'], output_blinded_info['amount']])
        ensure(v['result'] is True, 'verifycommitment failed')

        # Check rangeproofs and commitments sum
        prevout = lock_tx_obj['vout'][spend_n]
        prevtxns = [{'txid': lock_txid_hex, 'vout': spend_n, 'scriptPubKey': prevout['scriptPubKey']['hex'], 'amount_commitment': prevout['valueCommitment']}]
        rv = self.rpc_callback('verifyrawtransaction', [tx_bytes.hex(), prevtxns])
        ensure(rv['outputs_valid'] is True, 'Invalid outputs')
        ensure(rv['inputs_valid'] is True, 'Invalid inputs')

        # Check amount
        fee_paid = make_int(lock_spend_tx_obj['vout'][0]['ct_fee'])
        amount_difference = make_int(input_blinded_info['amount']) - make_int(output_blinded_info['amount'])
        ensure(fee_paid == amount_difference, 'Invalid output amount')

        # Check fee
        dummy_witness_stack = self.getScriptLockTxDummyWitness(lock_tx_script)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)

        vsize = self.getTxVSize(self.loadTx(tx_bytes), add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 // vsize
        self._log.info('vsize, feerate: %ld, %ld', vsize, fee_rate_paid)
        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate, expected: {}'.format(feerate))

        return True

    def createSCLockRefundSpendToFTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_dest, tx_fee_rate, vkbv):
        # lock refund swipe tx
        # Sends the coinA locked coin to the follower
        lock_refund_tx_obj = self.rpc_callback('decoderawtransaction', [tx_lock_refund_bytes.hex()])
        nonce = self.getScriptLockRefundTxNonce(vkbv)

        # Find the output of the lock refund tx to spend
        spend_n, input_blinded_info = self.findOutputByNonce(lock_refund_tx_obj, nonce)
        ensure(spend_n is not None, 'Output not found in tx')

        tx_lock_refund_id = lock_refund_tx_obj['txid']
        addr_out = self.pkh_to_address(pkh_dest)
        addr_info = self.rpc_callback('getaddressinfo', [addr_out])
        output_pubkey_hex = addr_info['pubkey']

        A, B, lock2_value, C = self.extractScriptLockRefundScriptValues(script_lock_refund)

        # Follower won't be able to decode output to check amount, shouldn't matter as fee is public and output is to leader, sum has to balance

        inputs = [{'txid': tx_lock_refund_id, 'vout': spend_n, 'sequence': lock2_value, 'blindingfactor': input_blinded_info['blind']}]
        outputs = [{'type': 'blind', 'amount': input_blinded_info['amount'], 'address': addr_out, 'pubkey': output_pubkey_hex}]
        params = [inputs, outputs]
        rv = self.rpc_callback('createrawparttransaction', params)

        lock_refund_swipe_tx_hex = rv['hex']

        # Set dummy witness data for fee estimation
        dummy_witness_stack = self.getScriptLockRefundSwipeTxDummyWitness(script_lock_refund)

        # Use a junk change pubkey to avoid adding unused keys to the wallet
        zero_change_key = i2b(self.getNewSecretKey())
        zero_change_pubkey = self.getPubkey(zero_change_key)
        inputs_info = {'0': {'value': input_blinded_info['amount'], 'blind': input_blinded_info['blind'], 'witnessstack': dummy_witness_stack}}
        outputs_info = rv['amounts']
        options = {
            'changepubkey': zero_change_pubkey.hex(),
            'feeRate': self.format_amount(tx_fee_rate),
            'subtractFeeFromOutputs': [0, ]
        }

        rv = self.rpc_callback('fundrawtransactionfrom', ['blind', lock_refund_swipe_tx_hex, inputs_info, outputs_info, options])
        lock_refund_swipe_tx_hex = rv['hex']

        return bytes.fromhex(lock_refund_swipe_tx_hex)

    def getSpendableBalance(self):
        return self.make_int(self.rpc_callback('getbalances')['mine']['blind_trusted'])


class PARTInterfaceAnon(PARTInterface):
    @staticmethod
    def balance_type():
        return BalanceTypes.ANON

    @staticmethod
    def depth_spendable() -> int:
        return 12

    def coin_name(self):
        return super().coin_name() + ' Anon'

    def publishBLockTx(self, Kbv, Kbs, output_amount, feerate, delay_for: int = 10, unlock_time: int = 0) -> bytes:
        sx_addr = self.formatStealthAddress(Kbv, Kbs)
        self._log.debug('sx_addr: {}'.format(sx_addr))

        # TODO: Fund from other balances
        params = ['anon', 'anon',
                  [{'address': sx_addr, 'amount': self.format_amount(output_amount)}, ],
                  '', '', self._anon_tx_ring_size, 1, False,
                  {'conf_target': self._conf_target, 'blind_watchonly_visible': True}]

        txid = self.rpc_callback('sendtypeto', params)
        return bytes.fromhex(txid)

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height, bid_sender):
        Kbv = self.getPubkey(kbv)
        sx_addr = self.formatStealthAddress(Kbv, Kbs)
        self._log.debug('sx_addr: {}'.format(sx_addr))

        # Tx recipient must import the stealth address as watch only
        if bid_sender:
            cb_swap_value *= -1
        else:
            addr_info = self.rpc_callback('getaddressinfo', [sx_addr])
            if not addr_info['iswatchonly']:
                wif_prefix = self.chainparams_network()['key_prefix']
                wif_scan_key = toWIF(wif_prefix, kbv)
                self.rpc_callback('importstealthaddress', [wif_scan_key, Kbs.hex()])
                self._log.info('Imported watch-only sx_addr: {}'.format(sx_addr))
                self._log.info('Rescanning {} chain from height: {}'.format(self.coin_name(), restore_height))
                self.rpc_callback('rescanblockchain', [restore_height])

        params = [{'include_watchonly': True, 'search': sx_addr}]
        txns = self.rpc_callback('filtertransactions', params)

        if len(txns) == 1:
            tx = txns[0]
            assert (tx['outputs'][0]['stealth_address'] == sx_addr)  # Should not be possible
            ensure(tx['outputs'][0]['type'] == 'anon', 'Output is not anon')

            if make_int(tx['outputs'][0]['amount']) == cb_swap_value:
                height = 0
                if tx['confirmations'] > 0:
                    chain_height = self.rpc_callback('getblockcount')
                    height = chain_height - (tx['confirmations'] - 1)
                return {'txid': tx['txid'], 'amount': cb_swap_value, 'height': height}
            else:
                self._log.warning('Incorrect amount detected for coin b lock txn: {}'.format(tx['txid']))
                return -1
        return None

    def spendBLockTx(self, chain_b_lock_txid, address_to, kbv, kbs, cb_swap_value, b_fee, restore_height, spend_actual_balance=False):
        Kbv = self.getPubkey(kbv)
        Kbs = self.getPubkey(kbs)
        sx_addr = self.formatStealthAddress(Kbv, Kbs)
        addr_info = self.rpc_callback('getaddressinfo', [sx_addr])
        if not addr_info['ismine']:
            wif_prefix = self.chainparams_network()['key_prefix']
            wif_scan_key = toWIF(wif_prefix, kbv)
            wif_spend_key = toWIF(wif_prefix, kbs)
            self.rpc_callback('importstealthaddress', [wif_scan_key, wif_spend_key])
            self._log.info('Imported spend key for sx_addr: {}'.format(sx_addr))
            self._log.info('Rescanning {} chain from height: {}'.format(self.coin_name(), restore_height))
            self.rpc_callback('rescanblockchain', [restore_height])

        autxos = self.rpc_callback('listunspentanon', [1, 9999999, [sx_addr]])

        if len(autxos) < 1:
            raise TemporaryError('No spendable outputs')
        elif len(autxos) > 1:
            raise ValueError('Too many spendable outputs')

        utxo = autxos[0]
        utxo_sats = make_int(utxo['amount'])

        if spend_actual_balance and utxo_sats != cb_swap_value:
            self._log.warning('Spending actual balance {}, not swap value {}.'.format(utxo_sats, cb_swap_value))
            cb_swap_value = utxo_sats

        inputs = [{'tx': utxo['txid'], 'n': utxo['vout']}, ]
        params = ['anon', 'anon',
                  [{'address': address_to, 'amount': self.format_amount(cb_swap_value), 'subfee': True}, ],
                  '', '', self._anon_tx_ring_size, 1, False,
                  {'conf_target': self._conf_target, 'inputs': inputs, 'show_fee': True}]
        rv = self.rpc_callback('sendtypeto', params)
        return bytes.fromhex(rv['txid'])

    def findTxnByHash(self, txid_hex):
        # txindex is enabled for Particl

        try:
            rv = self.rpc_callback('getrawtransaction', [txid_hex, True])
        except Exception as ex:
            self._log.debug('findTxnByHash getrawtransaction failed: {}'.format(txid_hex))
            return None

        if 'confirmations' in rv and rv['confirmations'] >= self.blocks_confirmed:
            return {'txid': txid_hex, 'amount': 0, 'height': rv['height']}

        return None

    def getSpendableBalance(self):
        return self.make_int(self.rpc_callback('getbalances')['mine']['anon_trusted'])
