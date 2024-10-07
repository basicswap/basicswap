#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from typing import Union
from basicswap.contrib.test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from basicswap.util import ensure, i2h
from .btc import BTCInterface, findOutput
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins, chainparams
from basicswap.interface.contrib.bch_test_framework.cashaddress import Address
from basicswap.util.crypto import hash160, sha256
from basicswap.interface.contrib.bch_test_framework.script import OP_EQUAL, OP_EQUALVERIFY, OP_HASH256, OP_DUP, OP_HASH160, OP_CHECKSIG
from basicswap.contrib.test_framework.script import (
    CScript, CScriptOp,
)

class BCHInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.BCH

    def __init__(self, coin_settings, network, swap_client=None):
        super(BCHInterface, self).__init__(coin_settings, network, swap_client)


    def decodeAddress(self, address: str) -> bytes:
        return bytes(Address.from_string(address).payload)

    def pubkey_to_segwit_address(self, pk: bytes) -> str:
        raise NotImplementedError()

    def pkh_to_address(self, pkh: bytes) -> str:
        # pkh is ripemd160(sha256(pk))
        assert (len(pkh) == 20)
        prefix = self.chainparams_network()['hrp']
        address = Address("P2PKH", b'\x76\xa9\x14' + pkh + b'\x88\xac')
        address.prefix = prefix
        return address.cash_address()

    def getNewAddress(self, use_segwit: bool = False, label: str = 'swap_receive') -> str:
        args = [label]
        return self.rpc_wallet('getnewaddress', args)

    def addressToLockingBytecode(self, address: str) -> bytes:
        return b'\x76\xa9\x14' + bytes(Address.from_string(address).payload) + b'\x88\xac'
    
    def getScriptDest(self, script):
        return self.scriptToP2SH32LockingBytecode(script)

    def scriptToP2SH32LockingBytecode(self, script: Union[bytes, str]) -> bytes:
        if isinstance(script, str):
            script = bytes.fromhex(script)

        return CScript([
            CScriptOp(OP_HASH256),
            sha256(sha256(script)),
            CScriptOp(OP_EQUAL),
        ])
    
    def createSCLockTx(self, value: int, script: bytearray, vkbv: bytes = None) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType()(value, self.getScriptDest(script)))
        return tx.serialize_without_witness()

    def getScriptForPubkeyHash(self, pkh: bytes) -> CScript:
        return CScript([
            CScriptOp(OP_DUP),
            CScriptOp(OP_HASH160),
            pkh,
            CScriptOp(OP_EQUALVERIFY),
            CScriptOp(OP_CHECKSIG),
        ])

    def getTxSize(self, tx: CTransaction) -> int:
        return len(tx.serialize_without_witness())

    def getScriptScriptSig(self, script: bytes, ves: bytes) -> bytes:
        if ves is not None:
            return CScript([ves, script])
        else:
            return CScript([script])

    def createSCLockSpendTx(self, tx_lock_bytes, script_lock, pkh_dest, tx_fee_rate, ves=None, fee_info={}):
        # tx_fee_rate in this context is equal to `mining_fee` contract param
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

        tx.rehash()
        self._log.info('createSCLockSpendTx %s:\n    fee_rate, size, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, size, pay_fee)

        return tx.serialize_without_witness()
