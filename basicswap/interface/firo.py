#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import hashlib

from .btc import BTCInterface, find_vout_for_address_from_txobj
from basicswap.util import (
    i2b,
    ensure,
)
from basicswap.rpc import make_rpc_func
from basicswap.util.crypto import hash160
from basicswap.util.address import decodeAddress
from basicswap.chainparams import Coins
from basicswap.interface.contrib.firo_test_framework.script import (
    CScript,
    OP_DUP,
    OP_EQUAL,
    OP_HASH160,
    OP_CHECKSIG,
    OP_EQUALVERIFY,
)
from basicswap.interface.contrib.firo_test_framework.mininode import (
    CBlock,
    FromHex,
    CTransaction,
)


class FIROInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.FIRO

    def __init__(self, coin_settings, network, swap_client=None):
        super(FIROInterface, self).__init__(coin_settings, network, swap_client)
        # No multiwallet support
        self.rpc_wallet = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host)

    def checkWallets(self) -> int:
        return 1

    def getExchangeName(self, exchange_name):
        return 'zcoin'

    def initialiseWallet(self, key):
        # load with -hdseed= parameter
        pass

    def getNewAddress(self, use_segwit, label='swap_receive'):
        return self.rpc('getnewaddress', [label])
        # addr_plain = self.rpc('getnewaddress', [label])
        # return self.rpc('addwitnessaddress', [addr_plain])

    def decodeAddress(self, address):
        return decodeAddress(address)[1:]

    def encodeSegwitAddress(self, script):
        raise ValueError('TODO')

    def decodeSegwitAddress(self, addr):
        raise ValueError('TODO')

    def isWatchOnlyAddress(self, address):
        addr_info = self.rpc('validateaddress', [address])
        return addr_info['iswatchonly']

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        addr_info = self.rpc('validateaddress', [address])
        if not or_watch_only:
            return addr_info['ismine']
        return addr_info['ismine'] or addr_info['iswatchonly']

    def getSCLockScriptAddress(self, lock_script):
        lock_tx_dest = self.getScriptDest(lock_script)
        address = self.encodeScriptDest(lock_tx_dest)

        if not self.isAddressMine(address, or_watch_only=True):
            # Expects P2WSH nested in BIP16_P2SH
            ro = self.rpc('importaddress', [lock_tx_dest.hex(), 'bid lock', False, True])
            addr_info = self.rpc('validateaddress', [address])

        return address

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, find_index: bool = False):
        # Add watchonly address and rescan if required

        if not self.isAddressMine(dest_address, or_watch_only=True):
            self.importWatchOnlyAddress(dest_address, 'bid')
            self._log.info('Imported watch-only addr: {}'.format(dest_address))
            self._log.info('Rescanning {} chain from height: {}'.format(self.coin_name(), rescan_from))
            self.rescanBlockchainForAddress(rescan_from, dest_address)

        return_txid = True if txid is None else False
        if txid is None:
            txns = self.rpc('listunspent', [0, 9999999, [dest_address, ]])

            for tx in txns:
                if self.make_int(tx['amount']) == bid_amount:
                    txid = bytes.fromhex(tx['txid'])
                    break

        if txid is None:
            return None

        try:
            tx = self.rpc('gettransaction', [txid.hex()])

            block_height = 0
            if 'blockhash' in tx:
                block_header = self.rpc('getblockheader', [tx['blockhash']])
                block_height = block_header['height']

            rv = {
                'depth': 0 if 'confirmations' not in tx else tx['confirmations'],
                'height': block_height}

        except Exception as e:
            self._log.debug('getLockTxHeight gettransaction failed: %s, %s', txid.hex(), str(e))
            return None

        if find_index:
            tx_obj = self.rpc('decoderawtransaction', [tx['hex']])
            rv['index'] = find_vout_for_address_from_txobj(tx_obj, dest_address)

        if return_txid:
            rv['txid'] = txid.hex()

        return rv

    def createSCLockTx(self, value: int, script: bytearray, vkbv: bytes = None) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType()(value, self.getScriptDest(script)))

        return tx.serialize()

    def fundSCLockTx(self, tx_bytes, feerate, vkbv=None):
        return self.fundTx(tx_bytes, feerate)

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

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def getScriptDest(self, script: bytearray) -> bytearray:
        # P2SH

        script_hash = hash160(script)
        assert len(script_hash) == 20

        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def getSeedHash(self, seed: bytes) -> bytes:
        return hash160(seed)[::-1]

    def encodeScriptDest(self, script_dest: bytes) -> str:
        # Extract hash from script
        script_hash = script_dest[2:-1]
        return self.sh_to_address(script_hash)

    def getDestForScriptHash(self, script_hash):
        assert len(script_hash) == 20
        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee]
        return self.rpc('sendtoaddress', params)

    def getWalletSeedID(self):
        return self.rpc('getwalletinfo')['hdmasterkeyid']

    def getSpendableBalance(self) -> int:
        return self.make_int(self.rpc('getwalletinfo')['balance'])

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        add_bytes = 107
        size = len(tx.serialize_with_witness()) + add_bytes
        pay_fee = round(fee_rate * size / 1000)
        self._log.info(f'BLockSpendTx  fee_rate, size, fee: {fee_rate}, {size}, {pay_fee}.')
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

    def getProofOfFunds(self, amount_for, extra_commit_bytes):
        # TODO: Lock unspent and use same output/s to fund bid

        unspents_by_addr = dict()
        unspents = self.rpc('listunspent')
        for u in unspents:
            if u['spendable'] is not True:
                continue
            if u['address'] not in unspents_by_addr:
                unspents_by_addr[u['address']] = {'total': 0, 'utxos': []}
            utxo_amount: int = self.make_int(u['amount'], r=1)
            unspents_by_addr[u['address']]['total'] += utxo_amount
            unspents_by_addr[u['address']]['utxos'].append((utxo_amount, u['txid'], u['vout']))

        max_utxos: int = 4

        viable_addrs = []
        for addr, data in unspents_by_addr.items():
            if data['total'] >= amount_for:
                # Sort from largest to smallest amount
                sorted_utxos = sorted(data['utxos'], key=lambda x: x[0])

                # Max outputs required to reach amount_for
                utxos_req: int = 0
                sum_value: int = 0
                for utxo in sorted_utxos:
                    sum_value += utxo[0]
                    utxos_req += 1
                    if sum_value >= amount_for:
                        break

                if utxos_req <= max_utxos:
                    viable_addrs.append(addr)
                    continue

        ensure(len(viable_addrs) > 0, 'Could not find address with enough funds for proof')

        sign_for_addr: str = random.choice(viable_addrs)
        self._log.debug('sign_for_addr %s', sign_for_addr)

        prove_utxos = []
        sorted_utxos = sorted(unspents_by_addr[sign_for_addr]['utxos'], key=lambda x: x[0])

        hasher = hashlib.sha256()

        sum_value: int = 0
        for utxo in sorted_utxos:
            sum_value += utxo[0]
            outpoint = (bytes.fromhex(utxo[1]), utxo[2])
            prove_utxos.append(outpoint)
            hasher.update(outpoint[0])
            hasher.update(outpoint[1].to_bytes(2, 'big'))
            if sum_value >= amount_for:
                break
        utxos_hash = hasher.digest()

        if self.using_segwit():  # TODO: Use isSegwitAddress when scantxoutset can use combo
            # 'Address does not refer to key' for non p2pkh
            pkh = self.decodeAddress(sign_for_addr)
            sign_for_addr = self.pkh_to_address(pkh)
            self._log.debug('sign_for_addr converted %s', sign_for_addr)

        signature = self.rpc('signmessage', [sign_for_addr, sign_for_addr + '_swap_proof_' + utxos_hash.hex() + extra_commit_bytes.hex()])

        return (sign_for_addr, signature, prove_utxos)

    def verifyProofOfFunds(self, address, signature, utxos, extra_commit_bytes):
        hasher = hashlib.sha256()
        sum_value: int = 0
        for outpoint in utxos:
            hasher.update(outpoint[0])
            hasher.update(outpoint[1].to_bytes(2, 'big'))
        utxos_hash = hasher.digest()

        passed = self.verifyMessage(address, address + '_swap_proof_' + utxos_hash.hex() + extra_commit_bytes.hex(), signature)
        ensure(passed is True, 'Proof of funds signature invalid')

        if self.using_segwit():
            address = self.encodeSegwitAddress(decodeAddress(address)[1:])

        sum_value: int = 0
        for outpoint in utxos:
            txout = self.rpc('gettxout', [outpoint[0].hex(), outpoint[1]])
            sum_value += self.make_int(txout['value'])

        return sum_value

    def rescanBlockchainForAddress(self, height_start: int, addr_find: str):
        # Very ugly workaround for missing `rescanblockchain` rpc command

        chain_blocks: int = self.getChainHeight()

        current_height: int = chain_blocks
        block_hash = self.rpc('getblockhash', [current_height])

        script_hash: bytes = self.decodeAddress(addr_find)
        find_scriptPubKey = self.getDestForScriptHash(script_hash)

        while current_height > height_start:
            block_hash = self.rpc('getblockhash', [current_height])

            block = self.rpc('getblock', [block_hash, False])
            decoded_block = CBlock()
            decoded_block = FromHex(decoded_block, block)
            for tx in decoded_block.vtx:
                for txo in tx.vout:
                    if txo.scriptPubKey == find_scriptPubKey:
                        tx.rehash()
                        txid = i2b(tx.sha256)
                        self._log.info('Found output to addr: {} in tx {} in block {}'.format(addr_find, txid.hex(), block_hash))
                        self._log.info('rescanblockchain hack invalidateblock {}'.format(block_hash))
                        self.rpc('invalidateblock', [block_hash])
                        self.rpc('reconsiderblock', [block_hash])
                        return
            current_height -= 1

    def getBlockWithTxns(self, block_hash):
        # TODO: Bypass decoderawtransaction and getblockheader
        block = self.rpc('getblock', [block_hash, False])
        block_header = self.rpc('getblockheader', [block_hash])
        decoded_block = CBlock()
        decoded_block = FromHex(decoded_block, block)

        tx_rv = []
        for tx in decoded_block.vtx:
            tx_hex = tx.serialize_with_witness().hex()
            tx_dec = self.rpc('decoderawtransaction', [tx_hex])
            if 'hex' not in tx_dec:
                tx_dec['hex'] = tx_hex

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
