#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from io import BytesIO

from .btc import BTCInterface
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins
from basicswap.util.address import decodeAddress
from .contrib.pivx_test_framework.messages import (
    CBlock,
    ToHex,
    FromHex,
    CTransaction)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_DUP,
    OP_HASH160,
    OP_CHECKSIG,
    OP_EQUALVERIFY,
)


class PIVXInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.PIVX

    def __init__(self, coin_settings, network, swap_client=None):
        super(PIVXInterface, self).__init__(coin_settings, network, swap_client)
        # No multiwallet support
        self.rpc_wallet = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host)

    def checkWallets(self) -> int:
        return 1

    def signTxWithWallet(self, tx):
        rv = self.rpc('signrawtransaction', [tx.hex()])
        return bytes.fromhex(rv['hex'])

    def createRawFundedTransaction(self, addr_to: str, amount: int, sub_fee: bool = False, lock_unspents: bool = True) -> str:
        txn = self.rpc('createrawtransaction', [[], {addr_to: self.format_amount(amount)}])
        fee_rate, fee_src = self.get_fee_rate(self._conf_target)
        self._log.debug(f'Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}')
        options = {
            'lockUnspents': lock_unspents,
            'feeRate': fee_rate,
        }
        if sub_fee:
            options['subtractFeeFromOutputs'] = [0,]
        return self.rpc('fundrawtransaction', [txn, options])['hex']

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self.createRawFundedTransaction(addr_to, amount)
        return self.rpc('signrawtransaction', [txn_funded])['hex']

    def decodeAddress(self, address):
        return decodeAddress(address)[1:]

    def getBlockWithTxns(self, block_hash):
        # TODO: Bypass decoderawtransaction and getblockheader
        block = self.rpc('getblock', [block_hash, False])
        block_header = self.rpc('getblockheader', [block_hash])
        decoded_block = CBlock()
        decoded_block = FromHex(decoded_block, block)

        tx_rv = []
        for tx in decoded_block.vtx:
            tx_dec = self.rpc('decoderawtransaction', [ToHex(tx)])
            tx_rv.append(tx_dec)

        block_rv = {
            'hash': block_hash,
            'previousblockhash': block_header['previousblockhash'],
            'tx': tx_rv,
            'confirmations': block_header['confirmations'],
            'height': block_header['height'],
            'time': block_header['time'],
            'version': block_header['version'],
            'merkleroot': block_header['merkleroot'],
        }

        return block_rv

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee]
        return self.rpc('sendtoaddress', params)

    def getSpendableBalance(self) -> int:
        return self.make_int(self.rpc('getwalletinfo')['balance'])

    def loadTx(self, tx_bytes):
        # Load tx from bytes to internal representation
        tx = CTransaction()
        tx.deserialize(BytesIO(tx_bytes))
        return tx

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        add_bytes = 107
        size = len(tx.serialize_with_witness()) + add_bytes
        pay_fee = round(fee_rate * size / 1000)
        self._log.info(f'BLockSpendTx fee_rate, size, fee: {fee_rate}, {size}, {pay_fee}.')
        return pay_fee

    def signTxWithKey(self, tx: bytes, key: bytes) -> bytes:
        key_wif = self.encodeKey(key)
        rv = self.rpc('signrawtransaction', [tx.hex(), [], [key_wif, ]])
        return bytes.fromhex(rv['hex'])

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
