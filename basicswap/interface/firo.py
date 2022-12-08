#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
from .btc import BTCInterface, find_vout_for_address_from_txobj
from basicswap.chainparams import Coins

from basicswap.util.address import decodeAddress
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_0,
    OP_DUP,
    OP_EQUAL,
    OP_HASH160,
    OP_CHECKSIG,
    OP_EQUALVERIFY,
    hash160,
)
from basicswap.contrib.test_framework.messages import (
    CTransaction,
)


class FIROInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.FIRO

    def getExchangeName(self, exchange_name):
        return 'zcoin'

    def initialiseWallet(self, key):
        # load with -hdseed= parameter
        pass

    def getNewAddress(self, use_segwit, label='swap_receive'):
        return self.rpc_callback('getnewaddress', [label])
        # addr_plain = self.rpc_callback('getnewaddress', [label])
        # return self.rpc_callback('addwitnessaddress', [addr_plain])

    def decodeAddress(self, address):
        return decodeAddress(address)[1:]

    def encodeSegwitAddress(self, script):
        raise ValueError('TODO')

    def decodeSegwitAddress(self, addr):
        raise ValueError('TODO')

    def isWatchOnlyAddress(self, address):
        addr_info = self.rpc_callback('validateaddress', [address])
        return addr_info['iswatchonly']

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        addr_info = self.rpc_callback('validateaddress', [address])
        if not or_watch_only:
            return addr_info['ismine']
        return addr_info['ismine'] or addr_info['iswatchonly']

    def getSCLockScriptAddress(self, lock_script):
        lock_tx_dest = self.getScriptDest(lock_script)
        address = self.encodeScriptDest(lock_tx_dest)

        if not self.isAddressMine(address, or_watch_only=True):
            # Expects P2WSH nested in BIP16_P2SH
            ro = self.rpc_callback('importaddress', [lock_tx_dest.hex(), 'bid lock', False, True])
            addr_info = self.rpc_callback('validateaddress', [address])

        return address

    def getLockTxHeightFiro(self, txid, lock_script, bid_amount, rescan_from, find_index=False):
        # Add watchonly address and rescan if required
        lock_tx_dest = self.getScriptDest(lock_script)
        dest_address = self.encodeScriptDest(lock_tx_dest)
        if not self.isAddressMine(dest_address, or_watch_only=True):
            self.rpc_callback('importaddress', [lock_tx_dest.hex(), 'bid lock', False, True])
            self._log.info('Imported watch-only addr: {}'.format(dest_address))
            self._log.info('Rescanning {} chain from height: {}'.format(self.coin_name(), rescan_from))
            self.rpc_callback('rescanblockchain', [rescan_from])

        return_txid = True if txid is None else False
        if txid is None:
            txns = self.rpc_callback('listunspent', [0, 9999999, [dest_address, ]])

            for tx in txns:
                if self.make_int(tx['amount']) == bid_amount:
                    txid = bytes.fromhex(tx['txid'])
                    break

        if txid is None:
            return None

        try:
            tx = self.rpc_callback('gettransaction', [txid.hex()])

            block_height = 0
            if 'blockhash' in tx:
                block_header = self.rpc_callback('getblockheader', [tx['blockhash']])
                block_height = block_header['height']

            rv = {
                'depth': 0 if 'confirmations' not in tx else tx['confirmations'],
                'height': block_height}

        except Exception as e:
            self._log.debug('getLockTxHeight gettransaction failed: %s, %s', txid.hex(), str(e))
            return None

        if find_index:
            tx_obj = self.rpc_callback('decoderawtransaction', [tx['hex']])
            rv['index'] = find_vout_for_address_from_txobj(tx_obj, dest_address)

        if return_txid:
            rv['txid'] = txid.hex()

        return rv

    def createSCLockTx(self, value: int, script: bytearray, vkbv=None) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType()(value, self.getScriptDest(script)))

        return tx.serialize()

    def fundSCLockTx(self, tx_bytes, feerate, vkbv=None):
        return self.fundTx(tx_bytes, feerate)

    def signTxWithWallet(self, tx):
        rv = self.rpc_callback('signrawtransaction', [tx.hex()])
        return bytes.fromhex(rv['hex'])

    def createRawFundedTransaction(self, addr_to: str, amount: int, sub_fee: bool = False, lock_unspents: bool = True) -> str:
        txn = self.rpc_callback('createrawtransaction', [[], {addr_to: self.format_amount(amount)}])
        fee_rate, fee_src = self.get_fee_rate(self._conf_target)
        self._log.debug(f'Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}')
        options = {
            'lockUnspents': lock_unspents,
            'feeRate': fee_rate,
        }
        if sub_fee:
            options['subtractFeeFromOutputs'] = [0,]
        return self.rpc_callback('fundrawtransaction', [txn, options])['hex']

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self.createRawFundedTransaction(addr_to, amount)
        return self.rpc_callback('signrawtransaction', [txn_funded])['hex']

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH

        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def getScriptDest(self, script: bytearray) -> bytearray:
        # P2WSH nested in BIP16_P2SH

        script_hash = hashlib.sha256(script).digest()
        assert len(script_hash) == 32
        script_hash_hash = hash160(script_hash)
        assert len(script_hash_hash) == 20

        return CScript([OP_HASH160, script_hash_hash, OP_EQUAL])

    def getSeedHash(self, seed):
        return hash160(seed)[::-1]

    def encodeScriptDest(self, script):
        # Extract hash from script
        script_hash = script[2:-1]
        return self.sh_to_address(script_hash)

    def getScriptScriptSig(self, script):
        return CScript([OP_0, hashlib.sha256(script).digest()])

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee]
        return self.rpc_callback('sendtoaddress', params)

    def getWalletSeedID(self):
        return self.rpc_callback('getwalletinfo')['hdmasterkeyid']

    def getSpendableBalance(self):
        return self.make_int(self.rpc_callback('getwalletinfo')['balance'])
