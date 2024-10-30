#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from typing import Union
from basicswap.contrib.test_framework.messages import COutPoint, CTransaction, CTxIn
from basicswap.util import b2h, b2i, ensure, i2h
from basicswap.util.script import decodePushData, decodeScriptNum
from .btc import BTCInterface, ensure_op, find_vout_for_address_from_txobj, findOutput
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins
from basicswap.interface.contrib.bch_test_framework.cashaddress import Address
from basicswap.util.crypto import hash160, sha256
from basicswap.interface.contrib.bch_test_framework.script import (
    OP_TXINPUTCOUNT,
    OP_1,
    OP_NUMEQUALVERIFY,
    OP_TXOUTPUTCOUNT,
    OP_0,
    OP_UTXOVALUE,
    OP_OUTPUTVALUE,
    OP_SUB,
    OP_UTXOTOKENCATEGORY,
    OP_OUTPUTTOKENCATEGORY,
    OP_EQUALVERIFY,
    OP_UTXOTOKENCOMMITMENT,
    OP_OUTPUTTOKENCOMMITMENT,
    OP_UTXOTOKENAMOUNT,
    OP_OUTPUTTOKENAMOUNT,
    OP_INPUTSEQUENCENUMBER,
    OP_NOTIF,
    OP_OUTPUTBYTECODE,
    OP_OVER,
    OP_CHECKDATASIG,
    OP_ELSE,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_EQUAL,
    OP_ENDIF,
    OP_HASH160,
    OP_DUP,
    OP_CHECKSIG,
    OP_HASH256,
)
from basicswap.contrib.test_framework.script import CScript
from coincurve.keys import (
    PrivateKey,
    PublicKey,
)
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key,
)


class BCHInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.BCH

    @staticmethod
    def xmr_swap_a_lock_spend_tx_vsize() -> int:
        return 302

    def __init__(self, coin_settings, network, swap_client=None):
        super(BCHInterface, self).__init__(coin_settings, network, swap_client)
        # No multiwallet support
        self.swap_client = swap_client
        self.rpc_wallet = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host)

    def has_segwit(self) -> bool:
        # bch does not have segwit, but we return true here to avoid extra checks in basicswap.py
        return True

    def getExchangeName(self, exchange_name):
        return 'bch'

    def getNewAddress(self, use_segwit: bool = False, label: str = 'swap_receive') -> str:
        args = [label]
        return self.rpc_wallet('getnewaddress', args)

    def getUnspentsByAddr(self):
        unspent_addr = dict()
        unspent = self.rpc_wallet('listunspent')
        for u in unspent:
            if u.get('spendable', False) is False:
                continue
            if 'address' not in u:
                continue
            unspent_addr[u['address']] = unspent_addr.get(u['address'], 0) + self.make_int(u['amount'], r=1)
        return unspent_addr

    # returns pkh
    def decodeAddress(self, address: str) -> bytes:
        return bytes(Address.from_string(address).payload)

    def encodeSegwitAddress(self, script):
        raise ValueError('Segwit not supported')

    def decodeSegwitAddress(self, addr):
        raise ValueError('Segwit not supported')

    def getSCLockScriptAddress(self, lock_script: bytes) -> str:
        lock_tx_dest = self.getScriptDest(lock_script)
        address = self.encodeScriptDest(lock_tx_dest)

        if not self.isAddressMine(address, or_watch_only=True):
            # Expects P2WSH nested in BIP16_P2SH
            ro = self.rpc('importaddress', [lock_tx_dest.hex(), 'bid lock', False, True])
            addr_info = self.rpc('validateaddress', [address])

        return address

    def createRawFundedTransaction(self, addr_to: str, amount: int, sub_fee: bool = False, lock_unspents: bool = True) -> str:
        txn = self.rpc('createrawtransaction', [[], {addr_to: self.format_amount(amount)}])

        options = {
            'lockUnspents': lock_unspents,
            # 'conf_target': self._conf_target,
        }
        if sub_fee:
            options['subtractFeeFromOutputs'] = [0,]
        return self.rpc_wallet('fundrawtransaction', [txn, options])['hex']

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def encodeScriptDest(self, script_dest: bytes) -> str:
        # Extract hash from script
        script_hash = script_dest[2:-1]
        return self.sh_to_address(script_hash)

    def sh_to_address(self, sh: bytes) -> str:
        assert (len(sh) == 20 or len(sh) == 32)
        network = self._network.upper()
        address = None
        if len(sh) == 20:
            address = Address("P2SH20" if network == "MAINNET" else "P2SH20-" + network, sh)
        else:
            address = Address("P2SH32" if network == "MAINNET" else "P2SH32-" + network, sh)

        return address.cash_address()

    def getDestForScriptHash(self, script_hash):
        assert (len(script_hash) == 20 or len(script_hash) == 32)
        if len(script_hash) == 20:
            return CScript([OP_HASH160, script_hash, OP_EQUAL])
        else:
            return CScript([OP_HASH256, script_hash, OP_EQUAL])

    def withdrawCoin(self, value: float, addr_to: str, subfee: bool):
        params = [addr_to, value, '', '', subfee, 0, False]
        return self.rpc_wallet('sendtoaddress', params)

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        add_bytes = 107
        size = len(tx.serialize_with_witness()) + add_bytes
        pay_fee = round(fee_rate * size / 1000)
        self._log.info(f'BLockSpendTx fee_rate, size, fee: {fee_rate}, {size}, {pay_fee}.')
        return pay_fee

    def findTxnByHash(self, txid_hex: str):
        # Only works for wallet txns
        try:
            rv = self.rpc('gettransaction', [txid_hex])
        except Exception as ex:
            self._log.debug('findTxnByHash getrawtransaction failed: {}'.format(txid_hex))
            return None
        if 'confirmations' in rv and rv['confirmations'] >= self.blocks_confirmed:
            block_height = self.getBlockHeader(rv['blockhash'])['height']
            return {'txid': txid_hex, 'amount': 0, 'height': block_height}
        return None

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, find_index: bool = False, vout: int = -1):
        # Add watchonly address and rescan if required
        txid = None

        # first lookup by dest_address
        if not self.isAddressMine(dest_address, or_watch_only=False):
            self.importWatchOnlyAddress(dest_address, 'bid')
            self._log.info('Imported watch-only addr: {}'.format(dest_address))
            self._log.info('Rescanning {} chain from height: {}'.format(self.coin_name(), rescan_from))
            self.rpc_wallet('rescanblockchain', [rescan_from])

        return_txid = True

        txns = self.rpc_wallet('listunspent', [0, 9999999, [dest_address, ]])

        for tx in txns:
            if self.make_int(tx['amount']) == bid_amount:
                txid = bytes.fromhex(tx['txid'])
                break

        # try to look up in past transactions
        if not txid:
            txns = self.rpc_wallet('listtransactions', ["*", 100000, 0, True])
            for tx in txns:
                if self.make_int(tx['amount']) == bid_amount and tx['category'] == 'send' and tx['address'] == dest_address:
                    txid = bytes.fromhex(tx['txid'])
                    break

        try:
            # set `include_watchonly` explicitly to `True` to get transactions for watchonly addresses also in BCH
            tx = self.rpc_wallet('gettransaction', [txid.hex(), True])

            block_height = 0
            if 'blockhash' in tx:
                block_header = self.rpc('getblockheader', [tx['blockhash']])
                block_height = block_header['height']

            rv = {
                'depth': 0 if 'confirmations' not in tx else tx['confirmations'],
                'height': block_height}

        except Exception as e:
            # self._log.debug('getLockTxHeight gettransaction failed: %s, %s', txid.hex(), str(e))
            return None

        if find_index:
            tx_obj = self.rpc('decoderawtransaction', [tx['hex']])
            rv['index'] = find_vout_for_address_from_txobj(tx_obj, dest_address)

        if return_txid:
            rv['txid'] = txid.hex()
            rv['txhex'] = tx['hex']

        return rv

    def genScriptLockTxScript(self, ci, Kal: bytes, Kaf: bytes, **kwargs) -> CScript:
        mining_fee: int = kwargs['mining_fee'] if 'mining_fee' in kwargs else 1000
        out_1: bytes = kwargs['out_1']
        out_2: bytes = kwargs['out_2']
        public_key: bytes = kwargs['public_key'] if 'public_key' in kwargs else Kal
        timelock: int = kwargs['timelock']

        return CScript([
            # // v4.1.0-CashTokens-Optimized
            # // Based on swaplock.cash v4.1.0-CashTokens
            #
            # // Alice has XMR, wants BCH and/or CashTokens.
            # // Bob has BCH and/or CashTokens, wants XMR.
            #
            # // Verify 1-in-1-out TX form
            OP_TXINPUTCOUNT,
            OP_1, OP_NUMEQUALVERIFY,
            OP_TXOUTPUTCOUNT,
            OP_1, OP_NUMEQUALVERIFY,

            # // int miningFee
            mining_fee,
            # // Verify pre-agreed mining fee and that the rest of BCH is forwarded
            # // to the output.
            OP_0, OP_UTXOVALUE,
            OP_0, OP_OUTPUTVALUE,
            OP_SUB, OP_NUMEQUALVERIFY,

            # # // Verify that any CashTokens are forwarded to the output.
            OP_0, OP_UTXOTOKENCATEGORY,
            OP_0, OP_OUTPUTTOKENCATEGORY,
            OP_EQUALVERIFY,
            OP_0, OP_UTXOTOKENCOMMITMENT,
            OP_0, OP_OUTPUTTOKENCOMMITMENT,
            OP_EQUALVERIFY,
            OP_0, OP_UTXOTOKENAMOUNT,
            OP_0, OP_OUTPUTTOKENAMOUNT,
            OP_NUMEQUALVERIFY,

            # // If sequence is not used then it is a regular swap TX.
            OP_0, OP_INPUTSEQUENCENUMBER,
            OP_NOTIF,
                # // bytes aliceOutput
                out_1,
                # // Verify that the BCH and/or CashTokens are forwarded to Alice's
                # // output.
                OP_0, OP_OUTPUTBYTECODE,
                OP_OVER, OP_EQUALVERIFY,

                # // pubkey bobPubkeyVES
                public_key,
                # // Require Alice to decrypt and publish Bob's VES signature.
                # // The "message" signed is simply a sha256 hash of Alice's output
                # // locking bytecode.
                # // By decrypting Bob's VES and publishing it, Alice reveals her
                # // XMR key share to Bob.
                OP_CHECKDATASIG,

                # // If a TX using this path is mined then Alice gets her BCH.
                # // Bob uses the revealed XMR key share to collect his XMR.

            # // Refund will become available when timelock expires, and it would
            # // expire because Alice didn't collect on time, either of her own accord
            # // or because Bob bailed out and withheld the encrypted signature.
            OP_ELSE,
                # // int timelock_0
                timelock,
                # // Verify refund timelock.
                OP_CHECKSEQUENCEVERIFY, OP_DROP,

                # // bytes refundLockingBytecode
                out_2,

                # // Verify that the BCH and/or CashTokens are forwarded to Refund
                # // contract.
                OP_0, OP_OUTPUTBYTECODE,
                OP_EQUAL,

                # // BCH and/or CashTokens are simply forwarded to Refund contract.
            OP_ENDIF
        ])

    def pubkey_to_segwit_address(self, pk: bytes) -> str:
        raise NotImplementedError()

    def pkh_to_address(self, pkh: bytes) -> str:
        # pkh is ripemd160(sha256(pk))
        assert (len(pkh) == 20)
        network = self._network.upper()
        address = Address("P2PKH" if network == "MAINNET" else "P2PKH-" + network, pkh)

        return address.cash_address()

    def encodeSharedAddress(self, Kbv: bytes, Kbs: bytes) -> str:
        return self.pkh_to_address(hash160(Kbs))

    def addressToLockingBytecode(self, address: str) -> bytes:
        return b'\x76\xa9\x14' + bytes(Address.from_string(address).payload) + b'\x88\xac'

    def getSpendableBalance(self) -> int:
        return self.make_int(self.rpc_wallet('getbalance', ["*", 1, False]))

    def getScriptDest(self, script):
        return self.scriptToP2SH32LockingBytecode(script)

    def scriptToP2SH32LockingBytecode(self, script: Union[bytes, str]) -> bytes:
        return CScript([
            OP_HASH256,
            sha256(sha256(script)),
            OP_EQUAL,
        ])

    def createSCLockTx(self, value: int, script: bytearray, vkbv: bytes = None) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType()(value, self.getScriptDest(script)))
        return tx.serialize_without_witness()

    def getTxSize(self, tx: CTransaction) -> int:
        return len(tx.serialize_without_witness())

    def getScriptScriptSig(self, script: bytes, ves: bytes = None) -> bytes:
        if ves is not None:
            return CScript([ves, script])
        else:
            return CScript([script])

    def createSCLockSpendTx(self, tx_lock_bytes, script_lock, pkh_dest, tx_fee_rate, vkbv=None, fee_info={}, **kwargs):
        # tx_fee_rate in this context is equal to `mining_fee` contract param
        ves = kwargs['ves'] if 'ves' in kwargs else None
        tx_lock = self.loadTx(tx_lock_bytes)
        output_script = self.getScriptDest(script_lock)
        locked_n = findOutput(tx_lock, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_id_int = tx_lock.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_id_int, locked_n),
                            scriptSig=self.getScriptScriptSig(script_lock, ves),
                            nSequence=0))

        tx.vout.append(self.txoType()(locked_coin, self.getScriptForPubkeyHash(pkh_dest)))
        pay_fee = tx_fee_rate
        tx.vout[0].nValue = locked_coin - pay_fee

        size = self.getTxSize(tx)

        fee_info['fee_paid'] = pay_fee
        fee_info['rate_used'] = tx_fee_rate
        fee_info['size'] = size
        # vsize is the same as size for BCH
        fee_info['vsize'] = size

        tx.rehash()
        self._log.info('createSCLockSpendTx %s:\n    fee_rate, size, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, size, pay_fee)

        return tx.serialize_without_witness()

    def createSCLockRefundTx(self, tx_lock_bytes, script_lock, Kal, Kaf, lock1_value, csv_val, tx_fee_rate, vkbv=None, **kwargs):
        tx_lock = CTransaction()
        tx_lock = self.loadTx(tx_lock_bytes)

        output_script = self.getScriptDest(script_lock)
        locked_n = findOutput(tx_lock, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_id_int = tx_lock.sha256

        refund_script = kwargs['refund_lock_tx_script']
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_id_int, locked_n),
                            nSequence=kwargs['timelock'] if 'timelock' in kwargs else lock1_value,
                            scriptSig=self.getScriptScriptSig(script_lock, None)))
        tx.vout.append(self.txoType()(locked_coin, self.getScriptDest(refund_script)))

        pay_fee = kwargs['mining_fee'] if 'mining_fee' in kwargs else tx_fee_rate
        tx.vout[0].nValue = locked_coin - pay_fee

        size = self.getTxSize(tx)
        vsize = size

        tx.rehash()
        self._log.info('createSCLockRefundTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize_without_witness(), refund_script, tx.vout[0].nValue

    def createSCLockRefundSpendTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_refund_to, tx_fee_rate, vkbv=None, **kwargs):
        # it is not possible to create the refund spend tx without the prior knowledge of the VES which is part of transaction preimage
        # but it is better and more secure to create a lock spend transaction committing to zero VES than returning static data
        kwargs['ves'] = bytes(73)
        return self.createSCLockSpendTx(tx_lock_refund_bytes, script_lock_refund, pkh_refund_to, tx_fee_rate, vkbv, **kwargs)

    def createSCLockRefundSpendToFTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_dest, tx_fee_rate, vkbv=None):
        # lock refund swipe tx
        # Sends the coinA locked coin to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = self.getScriptDest(script_lock_refund)
        locked_n = findOutput(tx_lock_refund, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        mining_fee, out_1, out_2, public_key, timelock = self.extractScriptLockScriptValues(script_lock_refund)

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n),
                            nSequence=timelock,
                            scriptSig=self.getScriptScriptSig(script_lock_refund, None)))

        tx.vout.append(self.txoType()(locked_coin, CScript(out_2)))

        size = self.getTxSize(tx)
        vsize = size

        pay_fee = mining_fee
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        self._log.info('createSCLockRefundSpendToFTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize()

    def signTx(self, key_bytes: bytes, tx_bytes: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bytes:
        # simply sign the entire tx data, as this is not a preimage signature
        eck = PrivateKey(key_bytes)
        return eck.sign(sha256(tx_bytes), hasher=None)

    def verifyTxSig(self, tx_bytes: bytes, sig: bytes, K: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bool:
        # simple ecdsa signature verification
        return self.verifyDataSig(tx_bytes, sig, K)

    def verifyDataSig(self, data: bytes, sig: bytes, K: bytes) -> bool:
        # simple ecdsa signature verification
        pubkey = PublicKey(K)
        return pubkey.verify(sig, sha256(data), hasher=None)

    def setTxSignature(self, tx_bytes: bytes, stack) -> bytes:
        return tx_bytes

    def extractScriptLockScriptValuesFromScriptSig(self, script_bytes):
        signature, nb = decodePushData(script_bytes, 0)
        if nb == len(script_bytes):
            unlock_script = signature[:]
            signature = None
        else:
            unlock_script, _ = decodePushData(script_bytes, nb)
        mining_fee, out_1, out_2, public_key, timelock = self.extractScriptLockScriptValues(unlock_script)

        return signature, mining_fee, out_1, out_2, public_key, timelock

    def extractScriptLockScriptValues(self, script_bytes):
        # see BCHInterface.genScriptLockTxScript for reference

        o = 0

        script_len = len(script_bytes)
        # TODO: stricter script_len checks

        ensure_op(script_bytes[o] == OP_TXINPUTCOUNT); o += 1
        ensure_op(script_bytes[o] == OP_1); o += 1
        ensure_op(script_bytes[o] == OP_NUMEQUALVERIFY); o += 1
        ensure_op(script_bytes[o] == OP_TXOUTPUTCOUNT); o += 1
        ensure_op(script_bytes[o] == OP_1); o += 1
        ensure_op(script_bytes[o] == OP_NUMEQUALVERIFY); o += 1
        mining_fee, nb = decodeScriptNum(script_bytes, o); o += nb

        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_UTXOVALUE); o += 1
        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_OUTPUTVALUE); o += 1
        ensure_op(script_bytes[o] == OP_SUB); o += 1
        ensure_op(script_bytes[o] == OP_NUMEQUALVERIFY); o += 1

        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_UTXOTOKENCATEGORY); o += 1
        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_OUTPUTTOKENCATEGORY); o += 1

        ensure_op(script_bytes[o] == OP_EQUALVERIFY); o += 1
        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_UTXOTOKENCOMMITMENT); o += 1
        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_OUTPUTTOKENCOMMITMENT); o += 1
        ensure_op(script_bytes[o] == OP_EQUALVERIFY); o += 1
        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_UTXOTOKENAMOUNT); o += 1
        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_OUTPUTTOKENAMOUNT); o += 1
        ensure_op(script_bytes[o] == OP_NUMEQUALVERIFY); o += 1

        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_INPUTSEQUENCENUMBER); o += 1
        ensure_op(script_bytes[o] == OP_NOTIF); o += 1
        out_1, nb = decodePushData(script_bytes, o); o += nb

        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_OUTPUTBYTECODE); o += 1
        ensure_op(script_bytes[o] == OP_OVER); o += 1
        ensure_op(script_bytes[o] == OP_EQUALVERIFY); o += 1
        public_key, nb = decodePushData(script_bytes, o); o += nb
        ensure_op(script_bytes[o] == OP_CHECKDATASIG); o += 1

        ensure_op(script_bytes[o] == OP_ELSE); o += 1
        timelock, nb = decodeScriptNum(script_bytes, o); o += nb
        ensure_op(script_bytes[o] == OP_CHECKSEQUENCEVERIFY); o += 1
        ensure_op(script_bytes[o] == OP_DROP); o += 1

        out_2, nb = decodePushData(script_bytes, o); o += nb

        ensure_op(script_bytes[o] == OP_0); o += 1
        ensure_op(script_bytes[o] == OP_OUTPUTBYTECODE); o += 1
        ensure_op(script_bytes[o] == OP_EQUAL); o += 1

        ensure_op(script_bytes[o] == OP_ENDIF); o += 1

        ensure(o == script_len, 'Unexpected script length')

        ensure(mining_fee >= 700 and mining_fee <= 10000, 'Bad mining_fee')
        ensure(len(out_1) == 25, 'Bad out_1')
        ensure(len(out_2) == 25 or len(out_2) == 35, 'Bad out_2')
        ensure(len(public_key) == 33, 'Bad public_key')
        ensure(timelock >= 0, 'Bad timelock')

        return mining_fee, out_1, out_2, public_key, timelock

    def verifySCLockTx(self, tx_bytes, script_out,
                       swap_value,
                       Kal, Kaf,
                       feerate,
                       check_lock_tx_inputs, vkbv=None,
                       **kwargs):

        # Verify:
        #

        # Not necessary to check the lock txn is mineable, as protocol will wait for it to confirm
        # However by checking early we can avoid wasting time processing unmineable txns
        # Check fee is reasonable

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock tx: {}.'.format(b2h(txid)))

        ensure(tx.nVersion == self.txVersion(), 'Bad version')
        ensure(tx.nLockTime == 0, 'Bad nLockTime')  # TODO match txns created by cores

        script_pk = self.getScriptDest(script_out)
        locked_n = findOutput(tx, script_pk)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx.vout[locked_n].nValue

        # Check value
        ensure(locked_coin == swap_value, 'Bad locked value')

        # Check script
        mining_fee: int = kwargs['mining_fee'] if 'mining_fee' in kwargs else 1000
        out_1: bytes = kwargs['out_1']
        out_2: bytes = kwargs['out_2']
        public_key: bytes = kwargs['public_key'] if 'public_key' in kwargs else Kal
        timelock: int = kwargs['timelock']

        _mining_fee, _out_1, _out_2, _public_key, _timelock = self.extractScriptLockScriptValues(script_out)
        ensure(mining_fee == _mining_fee, 'mining mismatch fee')
        ensure(out_1 == _out_1, 'out_1 mismatch')
        ensure(out_2 == _out_2, 'out_2 mismatch')
        ensure(public_key == _public_key, 'public_key mismatch')
        ensure(timelock == _timelock, 'timelock mismatch')

        return txid, locked_n

    def verifySCLockRefundTx(self, tx_bytes, lock_tx_bytes, script_out,
                             prevout_id, prevout_n, prevout_seq, prevout_script,
                             Kal, Kaf, csv_val_expect, swap_value, feerate, vkbv=None, **kwargs):
        # Verify:
        #   Must have only one input with correct prevout and sequence
        #   Must have only one output to the p2wsh of the lock refund script
        #   Output value must be locked_coin - lock tx fee

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock refund tx: {}.'.format(b2h(txid)))

        ensure(tx.nVersion == self.txVersion(), 'Bad version')
        ensure(tx.nLockTime == 0, 'nLockTime not 0')
        ensure(len(tx.vin) == 1, 'tx doesn\'t have one input')

        ensure(tx.vin[0].nSequence == prevout_seq, 'Bad input nSequence')
        ensure(tx.vin[0].scriptSig == self.getScriptScriptSig(prevout_script, None), 'Input scriptsig mismatch')
        ensure(tx.vin[0].prevout.hash == b2i(prevout_id) and tx.vin[0].prevout.n == prevout_n, 'Input prevout mismatch')

        ensure(len(tx.vout) == 1, 'tx doesn\'t have one output')

        script_pk = self.getScriptDest(script_out)
        locked_n = findOutput(tx, script_pk)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx.vout[locked_n].nValue

        # Check script
        mining_fee: int = kwargs['mining_fee'] if 'mining_fee' in kwargs else 1000
        out_1: bytes = kwargs['out_1']
        out_2: bytes = kwargs['out_2']
        public_key: bytes = kwargs['public_key'] if 'public_key' in kwargs else Kal
        timelock: int = kwargs['timelock']

        _mining_fee, _out_1, _out_2, _public_key, _timelock = self.extractScriptLockScriptValues(script_out)
        ensure(mining_fee == _mining_fee, 'mining mismatch fee')
        ensure(out_1 == _out_1, 'out_1 mismatch')
        ensure(out_2 == _out_2, 'out_2 mismatch')
        ensure(public_key == _public_key, 'public_key mismatch')
        ensure(timelock == _timelock, 'timelock mismatch')

        fee_paid = locked_coin - mining_fee
        assert (fee_paid > 0)

        size = self.getTxSize(tx)
        vsize = size

        self._log.info('tx amount, vsize, fee: %ld, %ld, %ld', locked_coin, vsize, fee_paid)

        return txid, locked_coin, locked_n

    def verifySCLockRefundSpendTx(self, tx_bytes, lock_refund_tx_bytes,
                                  lock_refund_tx_id, prevout_script,
                                  Kal,
                                  prevout_n, prevout_value, feerate, vkbv=None, **kwargs):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output sending lock refund tx value - fee to leader's address, TODO: follower shouldn't need to verify destination addr
        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock refund spend tx: {}.'.format(b2h(txid)))

        ensure(tx.nVersion == self.txVersion(), 'Bad version')
        ensure(tx.nLockTime == 0, 'nLockTime not 0')
        ensure(len(tx.vin) == 1, 'tx doesn\'t have one input')

        ensure(tx.vin[0].nSequence == 0, 'Bad input nSequence')
        ensure(tx.vin[0].scriptSig == self.getScriptScriptSig(prevout_script, bytes(73)), 'Input scriptsig mismatch')
        ensure(tx.vin[0].prevout.hash == b2i(lock_refund_tx_id) and tx.vin[0].prevout.n == 0, 'Input prevout mismatch')

        ensure(len(tx.vout) == 1, 'tx doesn\'t have one output')

        # Check script
        mining_fee: int = kwargs['mining_fee'] if 'mining_fee' in kwargs else 1000
        out_1: bytes = kwargs['out_1']
        out_2: bytes = kwargs['out_2']
        public_key: bytes = kwargs['public_key'] if 'public_key' in kwargs else Kal
        timelock: int = kwargs['timelock']

        _mining_fee, _out_1, _out_2, _public_key, _timelock = self.extractScriptLockScriptValues(prevout_script)
        ensure(mining_fee == _mining_fee, 'mining mismatch fee')
        ensure(out_1 == _out_1, 'out_1 mismatch')
        ensure(out_2 == _out_2, 'out_2 mismatch')
        ensure(public_key == _public_key, 'public_key mismatch')
        ensure(timelock == _timelock, 'timelock mismatch')

        tx_value = tx.vout[0].nValue
        fee_paid = tx_value - mining_fee
        assert (fee_paid > 0)

        size = self.getTxSize(tx)
        vsize = size

        self._log.info('tx amount, vsize, fee: %ld, %ld, %ld', tx_value, vsize, fee_paid)

        return True

    def verifySCLockSpendTx(self, tx_bytes,
                            lock_tx_bytes, lock_tx_script,
                            a_pkhash_f, feerate, vkbv=None):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output with destination and amount

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock spend tx: {}.'.format(b2h(txid)))

        ensure(tx.nVersion == self.txVersion(), 'Bad version')
        ensure(tx.nLockTime == 0, 'nLockTime not 0')
        ensure(len(tx.vin) == 1, 'tx doesn\'t have one input')

        lock_tx = self.loadTx(lock_tx_bytes)
        lock_tx_id = self.getTxid(lock_tx)

        output_script = self.getScriptDest(lock_tx_script)
        locked_n = findOutput(lock_tx, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = lock_tx.vout[locked_n].nValue

        ensure(tx.vin[0].nSequence == 0, 'Bad input nSequence')
        ensure(tx.vin[0].scriptSig == self.getScriptScriptSig(lock_tx_script), 'Input scriptsig mismatch')

        # allow for this mismatch in BCH, since the lock txid will get changed after signing
        # ensure(tx.vin[0].prevout.hash == b2i(lock_tx_id) and tx.vin[0].prevout.n == locked_n, 'Input prevout mismatch')

        ensure(len(tx.vout) == 1, 'tx doesn\'t have one output')
        p2pkh = self.getScriptForPubkeyHash(a_pkhash_f)
        ensure(tx.vout[0].scriptPubKey == p2pkh, 'Bad output destination')

        # The value of the lock tx output should already be verified, if the fee is as expected the difference will be the correct amount
        fee_paid = locked_coin - tx.vout[0].nValue
        assert (fee_paid > 0)

        size = self.getTxSize(tx)
        vsize = size

        self._log.info('tx amount, vsize, fee: %ld, %ld, %ld', tx.vout[0].nValue, vsize, fee_paid)

        return True

    def signTxOtVES(self, key_sign: bytes, pubkey_encrypt: bytes, tx_bytes: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bytes:
        _, out_1, _, _, _ = self.extractScriptLockScriptValues(prevout_script)
        msg = sha256(out_1)

        return ecdsaotves_enc_sign(key_sign, pubkey_encrypt, msg)

    def decryptOtVES(self, k: bytes, esig: bytes) -> bytes:
        return ecdsaotves_dec_sig(k, esig)

    def recoverEncKey(self, esig, sig, K):
        return ecdsaotves_rec_enc_key(K, esig, sig)

    def verifyTxOtVES(self, tx_bytes: bytes, ct: bytes, Ks: bytes, Ke: bytes, input_n: int, prevout_script: bytes, prevout_value):
        _, out_1, _, _, _ = self.extractScriptLockScriptValues(prevout_script)
        msg = sha256(out_1)

        return ecdsaotves_enc_verify(Ks, Ke, msg, ct)

    def extractLeaderSig(self, tx_bytes: bytes) -> bytes:
        tx = self.loadTx(tx_bytes)
        signature, _, _, _, _, _ = self.extractScriptLockScriptValuesFromScriptSig(tx.vin[0].scriptSig)
        return signature

    def extractFollowerSig(self, tx_bytes: bytes) -> bytes:
        tx = self.loadTx(tx_bytes)
        signature, _, _, _, _, _ = self.extractScriptLockScriptValuesFromScriptSig(tx.vin[0].scriptSig)
        return signature

    def isSpendingLockTx(self, spend_tx: CTransaction) -> bool:
        signature, _, _, _, _, _ = self.extractScriptLockScriptValuesFromScriptSig(spend_tx.vin[0].scriptSig)
        return spend_tx.vin[0].nSequence == 0 and signature is not None

    def isSpendingLockRefundTx(self, spend_tx: CTransaction) -> bool:
        signature, _, _, _, _, _ = self.extractScriptLockScriptValuesFromScriptSig(spend_tx.vin[0].scriptSig)
        return spend_tx.vin[0].nSequence == 0 and signature is not None

    def isTxExistsError(self, err_str: str) -> bool:
        return 'transaction already in block chain' in err_str
