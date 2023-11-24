#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import hashlib

from io import BytesIO
from coincurve.keys import (
    PublicKey,
    PrivateKey,
)
from .btc import BTCInterface, find_vout_for_address_from_txobj, findOutput
from basicswap.chainparams import Coins
from basicswap.interface.contrib.nav_test_framework.mininode import (
    CTxIn,
    CTxOut,
    CBlock,
    COutPoint,
    CTransaction,
    CTxInWitness,
    FromHex,
    uint256_from_str,
)
from basicswap.util.address import (
    decodeWif,
    pubkeyToAddress,
    encodeAddress,
)
from basicswap.util import (
    i2b, i2h,
    ensure,
)
from basicswap.basicswap_util import (
    getVoutByScriptPubKey,
)

from basicswap.interface.contrib.nav_test_framework.script import (
    hash160,
    CScript,
    OP_0,
    OP_EQUAL,
    OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG,
    SIGHASH_ALL,
    SegwitVersion1SignatureHash,
)
from mnemonic import Mnemonic


class NAVInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.NAV

    @staticmethod
    def txVersion() -> int:
        return 3

    @staticmethod
    def txoType():
        return CTxOut

    def use_p2shp2wsh(self) -> bool:
        # p2sh-p2wsh
        return True

    def seedToMnemonic(self, key):
        return Mnemonic('english').to_mnemonic(key)

    def initialiseWallet(self, key):
        # load with -importmnemonic= parameter
        pass

    def getWalletSeedID(self):
        return self.rpc_callback('getwalletinfo')['hdmasterkeyid']

    def withdrawCoin(self, value, addr_to: str, subfee: bool):
        strdzeel = ''
        params = [addr_to, value, '', '', strdzeel, subfee]
        return self.rpc_callback('sendtoaddress', params)

    def getSpendableBalance(self) -> int:
        return self.make_int(self.rpc_callback('getwalletinfo')['balance'])

    def signTxWithWallet(self, tx: bytes) -> bytes:
        rv = self.rpc_callback('signrawtransaction', [tx.hex()])

        return bytes.fromhex(rv['hex'])

    def checkExpectedSeed(self, key_hash: str):
        try:
            rv = self.rpc_callback('dumpmnemonic')
            entropy = Mnemonic('english').to_entropy(rv.split(' '))

            entropy_hash = self.getAddressHashFromKey(entropy)[::-1].hex()
            self._have_checked_seed = True
            return entropy_hash == key_hash
        except Exception as e:
            self._log.warning('checkExpectedSeed failed: {}'.format(str(e)))
        return False

    def getScriptForP2PKH(self, pkh: bytes) -> bytearray:
        # Return P2PKH
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2SH-p2wpkh

        script = CScript([OP_0, pkh])
        script_hash = hash160(script)
        assert len(script_hash) == 20

        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def getInputScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        script = CScript([OP_0, pkh])
        return bytes((len(script),)) + script

    def encodeSegwitAddress(self, pkh: bytes) -> str:
        # P2SH-p2wpkh
        script = CScript([OP_0, pkh])
        script_hash = hash160(script)
        assert len(script_hash) == 20
        return encodeAddress(bytes((self.chainparams_network()['script_address'],)) + script_hash)

    def encodeSegwitAddressScript(self, script: bytes) -> str:
        if len(script) == 23 and script[0] == OP_HASH160 and script[1] == 20 and script[22] == OP_EQUAL:
            script_hash = script[2:22]
            return encodeAddress(bytes((self.chainparams_network()['script_address'],)) + script_hash)
        raise ValueError('Unknown Script')

    def loadTx(self, tx_bytes: bytes) -> CTransaction:
        # Load tx from bytes to internal representation
        tx = CTransaction()
        tx.deserialize(BytesIO(tx_bytes))
        return tx

    def signTx(self, key_bytes: bytes, tx_bytes: bytes, input_n: int, prevout_script, prevout_value: int):
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitVersion1SignatureHash(prevout_script, tx, input_n, SIGHASH_ALL, prevout_value)
        eck = PrivateKey(key_bytes)
        return eck.sign(sig_hash, hasher=None) + bytes((SIGHASH_ALL,))

    def setTxSignature(self, tx_bytes: bytes, stack) -> bytes:
        tx = self.loadTx(tx_bytes)
        tx.wit.vtxinwit.clear()
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        return tx.serialize_with_witness()

    def getProofOfFunds(self, amount_for, extra_commit_bytes):
        # TODO: Lock unspent and use same output/s to fund bid

        unspents_by_addr = dict()
        unspents = self.rpc_callback('listunspent')
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

        self._log.debug('sign_for_addr %s', sign_for_addr)

        if self.using_segwit():  # TODO: Use isSegwitAddress when scantxoutset can use combo
            # 'Address does not refer to key' for non p2pkh
            addr_info = self.rpc_callback('validateaddress', [addr, ])
            if 'isscript' in addr_info and addr_info['isscript'] and 'hex' in addr_info:
                pkh = bytes.fromhex(addr_info['hex'])[2:]
                sign_for_addr = self.pkh_to_address(pkh)
                self._log.debug('sign_for_addr converted %s', sign_for_addr)

        signature = self.rpc_callback('signmessage', [sign_for_addr, sign_for_addr + '_swap_proof_' + utxos_hash.hex() + extra_commit_bytes.hex()])

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
            address = self.encodeSegwitAddress(self.decodeAddress(address)[1:])

        sum_value: int = 0
        for outpoint in utxos:
            txout = self.rpc_callback('gettxout', [outpoint[0].hex(), outpoint[1]])
            sum_value += self.make_int(txout['value'])

        return sum_value

    def createRawFundedTransaction(self, addr_to: str, amount: int, sub_fee: bool = False, lock_unspents: bool = True) -> str:
        txn = self.rpc_callback('createrawtransaction', [[], {addr_to: self.format_amount(amount)}])
        fee_rate, fee_src = self.get_fee_rate(self._conf_target)
        self._log.debug(f'Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}')
        if sub_fee:
            raise ValueError('Navcoin fundrawtransaction is missing the subtractFeeFromOutputs parameter')
            # options['subtractFeeFromOutputs'] = [0,]

        fee_rate = self.make_int(fee_rate, r=1)
        return self.fundTx(txn, fee_rate, lock_unspents).hex()

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        addr_info = self.rpc_callback('validateaddress', [address])
        if not or_watch_only:
            return addr_info['ismine']
        return addr_info['ismine'] or addr_info['iswatchonly']

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self.createRawFundedTransaction(addr_to, amount)
        return self.rpc_callback('signrawtransaction', [txn_funded])['hex']

    def getBlockchainInfo(self):
        rv = self.rpc_callback('getblockchaininfo')
        synced = round(rv['verificationprogress'], 3)
        if synced >= 0.997:
            rv['verificationprogress'] = 1.0
        return rv

    def encodeScriptDest(self, script_dest: bytes) -> str:
        script_hash = script_dest[2:-1]  # Extract hash from script
        return self.sh_to_address(script_hash)

    def encode_p2wsh(self, script: bytes) -> str:
        return pubkeyToAddress(self.chainparams_network()['script_address'], script)

    def find_prevout_info(self, txn_hex: str, txn_script: bytes):
        txjs = self.rpc_callback('decoderawtransaction', [txn_hex])
        n = getVoutByScriptPubKey(txjs, self.getScriptDest(txn_script).hex())

        return {
            'txid': txjs['txid'],
            'vout': n,
            'scriptPubKey': txjs['vout'][n]['scriptPubKey']['hex'],
            'redeemScript': txn_script.hex(),
            'amount': txjs['vout'][n]['value']
        }

    def getNewAddress(self, use_segwit: bool, label: str = 'swap_receive') -> str:
        address: str = self.rpc_callback('getnewaddress', [label,])
        if use_segwit:
            return self.rpc_callback('addwitnessaddress', [address,])
        return address

    def createRedeemTxn(self, prevout, output_addr: str, output_value: int, txn_script: bytes) -> str:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        prev_txid = uint256_from_str(bytes.fromhex(prevout['txid'])[::-1])

        tx.vin.append(CTxIn(COutPoint(prev_txid, prevout['vout']),
                            scriptSig=self.getScriptScriptSig(txn_script)))
        pkh = self.decodeAddress(output_addr)
        script = self.getScriptForPubkeyHash(pkh)
        tx.vout.append(self.txoType()(output_value, script))
        tx.rehash()
        return tx.serialize().hex()

    def createRefundTxn(self, prevout, output_addr: str, output_value: int, locktime: int, sequence: int, txn_script: bytes) -> str:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.nLockTime = locktime
        prev_txid = uint256_from_str(bytes.fromhex(prevout['txid'])[::-1])
        tx.vin.append(CTxIn(COutPoint(prev_txid, prevout['vout']),
                            nSequence=sequence,
                            scriptSig=self.getScriptScriptSig(txn_script)))
        pkh = self.decodeAddress(output_addr)
        script = self.getScriptForPubkeyHash(pkh)
        tx.vout.append(self.txoType()(output_value, script))
        tx.rehash()
        return tx.serialize().hex()

    def getTxSignature(self, tx_hex: str, prevout_data, key_wif: str) -> str:
        key = decodeWif(key_wif)
        redeem_script = bytes.fromhex(prevout_data['redeemScript'])
        sig = self.signTx(key, bytes.fromhex(tx_hex), 0, redeem_script, self.make_int(prevout_data['amount']))

        return sig.hex()

    def verifyTxSig(self, tx_bytes: bytes, sig: bytes, K: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bool:
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitVersion1SignatureHash(prevout_script, tx, input_n, SIGHASH_ALL, prevout_value)

        pubkey = PublicKey(K)
        return pubkey.verify(sig[: -1], sig_hash, hasher=None)  # Pop the hashtype byte

    def verifyRawTransaction(self, tx_hex: str, prevouts):
        # Only checks signature
        # verifyrawtransaction
        self._log.warning('NAV verifyRawTransaction only checks signature')
        inputs_valid: bool = False
        validscripts: int = 0

        tx_bytes = bytes.fromhex(tx_hex)
        tx = self.loadTx(bytes.fromhex(tx_hex))

        signature = tx.wit.vtxinwit[0].scriptWitness.stack[0]
        pubkey = tx.wit.vtxinwit[0].scriptWitness.stack[1]

        input_n: int = 0
        prevout_data = prevouts[input_n]
        redeem_script = bytes.fromhex(prevout_data['redeemScript'])
        prevout_value = self.make_int(prevout_data['amount'])

        if self.verifyTxSig(tx_bytes, signature, pubkey, input_n, redeem_script, prevout_value):
            validscripts += 1

        # TODO: validate inputs
        inputs_valid = True

        return {
            'inputs_valid': inputs_valid,
            'validscripts': validscripts,
        }

    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        tx_vsize = 5  # Add a few bytes, sequence in script takes variable amount of bytes

        tx_vsize += 184 if redeem else 187
        return tx_vsize

    def getTxid(self, tx) -> bytes:
        if isinstance(tx, str):
            tx = bytes.fromhex(tx)
        if isinstance(tx, bytes):
            tx = self.loadTx(tx)
        tx.rehash()
        return i2b(tx.sha256)

    def rescanBlockchainForAddress(self, height_start: int, addr_find: str):
        # Very ugly workaround for missing `rescanblockchain` rpc command

        chain_blocks: int = self.getChainHeight()

        current_height: int = chain_blocks
        block_hash = self.rpc_callback('getblockhash', [current_height])

        script_hash: bytes = self.decodeAddress(addr_find)
        find_scriptPubKey = self.getDestForScriptHash(script_hash)

        while current_height > height_start:
            block_hash = self.rpc_callback('getblockhash', [current_height])

            block = self.rpc_callback('getblock', [block_hash, False])
            decoded_block = CBlock()
            decoded_block = FromHex(decoded_block, block)
            for tx in decoded_block.vtx:
                for txo in tx.vout:
                    if txo.scriptPubKey == find_scriptPubKey:
                        tx.rehash()
                        txid = i2b(tx.sha256)
                        self._log.info('Found output to addr: {} in tx {} in block {}'.format(addr_find, txid.hex(), block_hash))
                        self._log.info('rescanblockchain hack invalidateblock {}'.format(block_hash))
                        self.rpc_callback('invalidateblock', [block_hash])
                        self.rpc_callback('reconsiderblock', [block_hash])
                        return
            current_height -= 1

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, find_index: bool = False):
        # Add watchonly address and rescan if required

        if not self.isAddressMine(dest_address, or_watch_only=True):
            self.importWatchOnlyAddress(dest_address, 'bid')
            self._log.info('Imported watch-only addr: {}'.format(dest_address))
            self._log.info('Rescanning {} chain from height: {}'.format(self.coin_name(), rescan_from))
            self.rescanBlockchainForAddress(rescan_from, dest_address)

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

    def getBlockWithTxns(self, block_hash):
        # TODO: Bypass decoderawtransaction and getblockheader
        block = self.rpc_callback('getblock', [block_hash, False])
        block_header = self.rpc_callback('getblockheader', [block_hash])
        decoded_block = CBlock()
        decoded_block = FromHex(decoded_block, block)

        tx_rv = []
        for tx in decoded_block.vtx:
            tx_hex = tx.serialize_with_witness().hex()
            tx_dec = self.rpc_callback('decoderawtransaction', [tx_hex])
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

    def getScriptScriptSig(self, script: bytes) -> bytearray:
        return self.getP2SHP2WSHScriptSig(script)

    def getScriptDest(self, script):
        return self.getP2SHP2WSHDest(script)

    def getDestForScriptHash(self, script_hash):
        assert len(script_hash) == 20
        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def pubkey_to_segwit_address(self, pk: bytes) -> str:
        pkh = hash160(pk)
        script_out = self.getScriptForPubkeyHash(pkh)
        return self.encodeSegwitAddressScript(script_out)

    def createBLockTx(self, Kbs: bytes, output_amount: int, vkbv=None) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        script_pk = self.getPkDest(Kbs)
        tx.vout.append(self.txoType()(output_amount, script_pk))
        return tx.serialize()

    def spendBLockTx(self, chain_b_lock_txid: bytes, address_to: str, kbv: bytes, kbs: bytes, cb_swap_value: int, b_fee: int, restore_height: int) -> bytes:
        self._log.info('spendBLockTx %s:\n', chain_b_lock_txid.hex())
        wtx = self.rpc_callback('gettransaction', [chain_b_lock_txid.hex(), ])
        lock_tx = self.loadTx(bytes.fromhex(wtx['hex']))

        Kbs = self.getPubkey(kbs)
        script_pk = self.getPkDest(Kbs)
        locked_n = findOutput(lock_tx, script_pk)
        ensure(locked_n is not None, 'Output not found in tx')
        pkh_to = self.decodeAddress(address_to)

        tx = CTransaction()
        tx.nVersion = self.txVersion()

        chain_b_lock_txid_int = uint256_from_str(chain_b_lock_txid[::-1])

        script_sig = self.getInputScriptForPubkeyHash(self.getPubkeyHash(Kbs))

        tx.vin.append(CTxIn(COutPoint(chain_b_lock_txid_int, locked_n),
                            nSequence=0,
                            scriptSig=script_sig))
        tx.vout.append(self.txoType()(cb_swap_value, self.getScriptForPubkeyHash(pkh_to)))

        pay_fee = self.getBLockSpendTxFee(tx, b_fee)
        tx.vout[0].nValue = cb_swap_value - pay_fee

        b_lock_spend_tx = tx.serialize()
        b_lock_spend_tx = self.signTxWithKey(b_lock_spend_tx, kbs, cb_swap_value)

        return bytes.fromhex(self.publishTx(b_lock_spend_tx))

    def signTxWithKey(self, tx: bytes, key: bytes, prev_amount: int) -> bytes:
        Key = self.getPubkey(key)
        pkh = self.getPubkeyHash(Key)
        script = self.getScriptForP2PKH(pkh)

        sig = self.signTx(key, tx, 0, script, prev_amount)

        stack = [
            sig,
            Key,
        ]
        return self.setTxSignature(tx, stack)

    def findTxnByHash(self, txid_hex: str):
        # Only works for wallet txns
        try:
            rv = self.rpc_callback('gettransaction', [txid_hex])
        except Exception as ex:
            self._log.debug('findTxnByHash getrawtransaction failed: {}'.format(txid_hex))
            return None
        if 'confirmations' in rv and rv['confirmations'] >= self.blocks_confirmed:
            block_height = self.getBlockHeader(rv['blockhash'])['height']
            return {'txid': txid_hex, 'amount': 0, 'height': block_height}
        return None

    def createSCLockTx(self, value: int, script: bytearray, vkbv: bytes = None) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType()(value, self.getScriptDest(script)))

        return tx.serialize()

    def fundTx(self, tx_hex: str, feerate: int, lock_unspents: bool = True):
        feerate_str = self.format_amount(feerate)
        # TODO: unlock unspents if bid cancelled
        options = {
            'lockUnspents': lock_unspents,
            'feeRate': feerate_str,
        }
        rv = self.rpc_callback('fundrawtransaction', [tx_hex, options])

        # Sign transaction then strip witness data to fill scriptsig
        rv = self.rpc_callback('signrawtransaction', [rv['hex']])

        tx_signed = self.loadTx(bytes.fromhex(rv['hex']))
        if len(tx_signed.vin) != len(tx_signed.wit.vtxinwit):
            raise ValueError('txn has non segwit input')
        for witness_data in tx_signed.wit.vtxinwit:
            if len(witness_data.scriptWitness.stack) < 2:
                raise ValueError('txn has non segwit input')

        return tx_signed.serialize_without_witness()

    def fundSCLockTx(self, tx_bytes: bytes, feerate, vkbv=None) -> bytes:
        tx_funded = self.fundTx(tx_bytes.hex(), feerate)
        return tx_funded

    def createSCLockRefundTx(self, tx_lock_bytes, script_lock, Kal, Kaf, lock1_value, csv_val, tx_fee_rate, vkbv=None):
        tx_lock = CTransaction()
        tx_lock = self.loadTx(tx_lock_bytes)

        output_script = self.getScriptDest(script_lock)
        locked_n = findOutput(tx_lock, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_id_int = tx_lock.sha256

        refund_script = self.genScriptLockRefundTxScript(Kal, Kaf, csv_val)
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_id_int, locked_n),
                            nSequence=lock1_value,
                            scriptSig=self.getScriptScriptSig(script_lock)))
        tx.vout.append(self.txoType()(locked_coin, self.getScriptDest(refund_script)))

        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        self._log.info('createSCLockRefundTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize(), refund_script, tx.vout[0].nValue

    def createSCLockRefundSpendTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_refund_to, tx_fee_rate, vkbv=None):
        # Returns the coinA locked coin to the leader
        # The follower will sign the multisig path with a signature encumbered by the leader's coinB spend pubkey
        # If the leader publishes the decrypted signature the leader's coinB spend privatekey will be revealed to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = self.getScriptDest(script_lock_refund)
        locked_n = findOutput(tx_lock_refund, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n),
                            nSequence=0,
                            scriptSig=self.getScriptScriptSig(script_lock_refund)))

        tx.vout.append(self.txoType()(locked_coin, self.getScriptForPubkeyHash(pkh_refund_to)))

        dummy_witness_stack = self.getScriptLockRefundSpendTxDummyWitness(script_lock_refund)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        self._log.info('createSCLockRefundSpendTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize()

    def createSCLockRefundSpendToFTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_dest, tx_fee_rate, vkbv=None):
        # lock refund swipe tx
        # Sends the coinA locked coin to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = self.getScriptDest(script_lock_refund)
        locked_n = findOutput(tx_lock_refund, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        A, B, lock2_value, C = self.extractScriptLockRefundScriptValues(script_lock_refund)

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n),
                            nSequence=lock2_value,
                            scriptSig=self.getScriptScriptSig(script_lock_refund)))

        tx.vout.append(self.txoType()(locked_coin, self.getScriptForPubkeyHash(pkh_dest)))

        dummy_witness_stack = self.getScriptLockRefundSwipeTxDummyWitness(script_lock_refund)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        self._log.info('createSCLockRefundSpendToFTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize()

    def createSCLockSpendTx(self, tx_lock_bytes, script_lock, pkh_dest, tx_fee_rate, vkbv=None, fee_info={}):
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
                            scriptSig=self.getScriptScriptSig(script_lock)))

        tx.vout.append(self.txoType()(locked_coin, self.getScriptForPubkeyHash(pkh_dest)))

        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        fee_info['fee_paid'] = pay_fee
        fee_info['rate_used'] = tx_fee_rate
        fee_info['witness_bytes'] = witness_bytes
        fee_info['vsize'] = vsize

        tx.rehash()
        self._log.info('createSCLockSpendTx %s:\n    fee_rate, vsize, fee: %ld, %ld, %ld.',
                       i2h(tx.sha256), tx_fee_rate, vsize, pay_fee)

        return tx.serialize()

    def get_fee_rate(self, conf_target: int = 2):

        try:
            fee_rate = self.rpc_callback('estimatesmartfee', [conf_target])['feerate']
            assert (fee_rate > 0.0), 'Non positive feerate'
            return fee_rate, 'estimatesmartfee'
        except Exception:
            try:
                fee_rate = self.rpc_callback('getwalletinfo')['paytxfee']
                assert (fee_rate > 0.0), 'Non positive feerate'
                return fee_rate, 'paytxfee'
            except Exception:
                return self.rpc_callback('getnetworkinfo')['relayfee'], 'relayfee'
