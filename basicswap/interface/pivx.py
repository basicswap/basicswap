#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins
from basicswap.util.address import decodeAddress
from .contrib.pivx_test_framework.messages import (
    CBlock,
    ToHex,
    FromHex)


class PIVXInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.PIVX

    def createRawSignedTransaction(self, addr_to, amount):
        txn = self.rpc_callback('createrawtransaction', [[], {addr_to: self.format_amount(amount)}])

        fee_rate, fee_src = self.get_fee_rate(self._conf_target)
        self._log.debug(f'Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}')

        options = {
            'lockUnspents': True,
            'feeRate': fee_rate,
        }
        txn_funded = self.rpc_callback('fundrawtransaction', [txn, options])['hex']
        txn_signed = self.rpc_callback('signrawtransaction', [txn_funded])['hex']
        return txn_signed

    def decodeAddress(self, address):
        return decodeAddress(address)[1:]

    def getBlockWithTxns(self, block_hash):
        # TODO: Bypass decoderawtransaction and getblockheader
        block = self.rpc_callback('getblock', [block_hash, False])
        block_header = self.rpc_callback('getblockheader', [block_hash])
        decoded_block = CBlock()
        decoded_block = FromHex(decoded_block, block)

        tx_rv = []
        for tx in decoded_block.vtx:
            tx_dec = self.rpc_callback('decoderawtransaction', [ToHex(tx)])
            tx_rv.append(tx_dec)

        block_rv = {
            'hash': block_hash,
            'tx': tx_rv,
            'confirmations': block_header['confirmations'],
            'height': block_header['height'],
            'version': block_header['version'],
            'merkleroot': block_header['merkleroot'],
        }

        return block_rv

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee]
        return self.rpc_callback('sendtoaddress', params)

    def getSpendableBalance(self):
        return self.make_int(self.rpc_callback('getwalletinfo')['balance'])
