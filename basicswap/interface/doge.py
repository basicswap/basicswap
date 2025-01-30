#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 The BasicSwap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins
from basicswap.util.crypto import hash160

from basicswap.contrib.test_framework.script import (
    CScript,
    OP_DUP,
    OP_CHECKSIG,
    OP_HASH160,
    OP_EQUAL,
    OP_EQUALVERIFY,
)


class DOGEInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.DOGE

    @staticmethod
    def est_lock_tx_vsize() -> int:
        return 192

    @staticmethod
    def xmr_swap_b_lock_spend_tx_vsize() -> int:
        return 192

    def __init__(self, coin_settings, network, swap_client=None):
        super(DOGEInterface, self).__init__(coin_settings, network, swap_client)

    def getScriptDest(self, script: bytearray) -> bytearray:
        # P2SH

        script_hash = hash160(script)
        assert len(script_hash) == 20

        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def encodeScriptDest(self, script_dest: bytes) -> str:
        # Extract hash from script
        script_hash = script_dest[2:-1]
        return self.sh_to_address(script_hash)

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        add_bytes = 107
        size = len(tx.serialize_with_witness()) + add_bytes
        pay_fee = round(fee_rate * size / 1000)
        self._log.info(
            f"BLockSpendTx fee_rate, size, fee: {fee_rate}, {size}, {pay_fee}."
        )
        return pay_fee
