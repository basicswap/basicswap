#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import hashlib
import logging
import random

from basicswap.basicswap_util import (
    getVoutByScriptPubKey,
    TxLockTypes
)
from basicswap.chainparams import Coins
from basicswap.interface.btc import Secp256k1Interface
from basicswap.util import (
    ensure,
)
from basicswap.util.address import (
    b58decode,
    b58encode,
)
from basicswap.util.crypto import (
    blake256,
    hash160,
    ripemd160,
)
from basicswap.util.script import (
    SerialiseNumCompact,
)
from basicswap.util.extkey import ExtKeyPair
from basicswap.util.integer import encode_varint
from basicswap.interface.dcr.rpc import make_rpc_func
from .messages import CTransaction, CTxOut, SigHashType, TxSerializeType
from .script import push_script_data, OP_HASH160, OP_EQUAL, OP_DUP, OP_EQUALVERIFY, OP_CHECKSIG

from coincurve.keys import (
    PrivateKey,
    PublicKey,
)


SEQUENCE_LOCKTIME_GRANULARITY = 9  # 512 seconds
SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)
SEQUENCE_LOCKTIME_MASK = 0x0000f

SigHashSerializePrefix: int = 1
SigHashSerializeWitness: int = 3


def DCRSignatureHash(sign_script: bytes, hash_type: SigHashType, tx: CTransaction, idx: int) -> bytes:
    masked_hash_type = hash_type & SigHashType.SigHashMask
    if masked_hash_type != SigHashType.SigHashAll:
        raise ValueError('todo')

    # Prefix hash
    sign_tx_in_idx: int = idx
    sign_vins = tx.vin
    if hash_type & SigHashType.SigHashAnyOneCanPay != 0:
        sign_vins = [tx.vin[idx],]
        sign_tx_in_idx = 0

    hash_buffer = bytearray()
    version: int = tx.version | (SigHashSerializePrefix << 16)
    hash_buffer += version.to_bytes(4, 'little')
    hash_buffer += encode_varint(len(sign_vins))

    for txi_n, txi in enumerate(sign_vins):
        hash_buffer += txi.prevout.hash.to_bytes(32, 'little')
        hash_buffer += txi.prevout.n.to_bytes(4, 'little')
        hash_buffer += txi.prevout.tree.to_bytes(1)

        # In the case of SigHashNone and SigHashSingle, commit to 0 for everything that is not the input being signed instead.
        if (masked_hash_type == SigHashType.SigHashNone
            or masked_hash_type == SigHashType.SigHashSingle) and \
           sign_tx_in_idx != txi_n:
            hash_buffer += (0).to_bytes(4, 'little')
        else:
            hash_buffer += txi.sequence.to_bytes(4, 'little')

    hash_buffer += encode_varint(len(tx.vout))

    for txo_n, txo in enumerate(tx.vout):
        if masked_hash_type == SigHashType.SigHashSingle and \
           idx != txo_n:
            hash_buffer += (-1).to_bytes(8, 'little')
            hash_buffer += txo.version.to_bytes(2, 'little')
            hash_buffer += encode_varint(0)
            continue
        hash_buffer += txo.value.to_bytes(8, 'little')
        hash_buffer += txo.version.to_bytes(2, 'little')
        hash_buffer += encode_varint(len(txo.script_pubkey))
        hash_buffer += txo.script_pubkey

    hash_buffer += tx.locktime.to_bytes(4, 'little')
    hash_buffer += tx.expiry.to_bytes(4, 'little')

    prefix_hash = blake256(hash_buffer)

    # Witness hash
    hash_buffer.clear()

    version: int = tx.version | (SigHashSerializeWitness << 16)
    hash_buffer += version.to_bytes(4, 'little')

    hash_buffer += encode_varint(len(sign_vins))
    for txi_n, txi in enumerate(sign_vins):
        if sign_tx_in_idx != txi_n:
            hash_buffer += encode_varint(0)
            continue
        hash_buffer += encode_varint(len(sign_script))
        hash_buffer += sign_script

    witness_hash = blake256(hash_buffer)

    hash_buffer.clear()
    hash_buffer += hash_type.to_bytes(4, 'little')
    hash_buffer += prefix_hash
    hash_buffer += witness_hash

    return blake256(hash_buffer)


class DCRInterface(Secp256k1Interface):

    @staticmethod
    def coin_type():
        return Coins.DCR

    @staticmethod
    def exp() -> int:
        return 8

    @staticmethod
    def COIN() -> int:
        return 100000000

    @staticmethod
    def nbk() -> int:
        return 32

    @staticmethod
    def nbK() -> int:  # No. of bytes requires to encode a public key
        return 33

    @staticmethod
    def txVersion() -> int:
        return 2

    @staticmethod
    def txoType():
        return CTxOut

    @staticmethod
    def getExpectedSequence(lockType: int, lockVal: int) -> int:
        ensure(lockVal >= 1, 'Bad lockVal')
        if lockType == TxLockTypes.SEQUENCE_LOCK_BLOCKS:
            return lockVal
        if lockType == TxLockTypes.SEQUENCE_LOCK_TIME:
            secondsLocked = lockVal
            # Ensure the locked time is never less than lockVal
            if secondsLocked % (1 << SEQUENCE_LOCKTIME_GRANULARITY) != 0:
                secondsLocked += (1 << SEQUENCE_LOCKTIME_GRANULARITY)
            secondsLocked >>= SEQUENCE_LOCKTIME_GRANULARITY
            return secondsLocked | SEQUENCE_LOCKTIME_TYPE_FLAG
        raise ValueError('Unknown lock type')

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__(network)
        self._rpc_host = coin_settings.get('rpchost', '127.0.0.1')
        self._rpcport = coin_settings['rpcport']
        self._rpcauth = coin_settings['rpcauth']
        self._sc = swap_client
        self._log = self._sc.log if self._sc and self._sc.log else logging
        self.rpc = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host)
        if 'walletrpcport' in coin_settings:
            self.rpc_wallet = make_rpc_func(coin_settings['walletrpcport'], self._rpcauth, host=self._rpc_host)
        else:
            self.rpc_wallet = None
        self.blocks_confirmed = coin_settings['blocks_confirmed']
        self.setConfTarget(coin_settings['conf_target'])

        self._use_segwit = coin_settings['use_segwit']

    def pkh(self, pubkey: bytes) -> bytes:
        return ripemd160(blake256(pubkey))

    def pkh_to_address(self, pkh: bytes) -> str:
        prefix = self.chainparams_network()['pubkey_address']

        data = prefix.to_bytes(2, 'big') + pkh
        checksum = blake256(blake256(data))
        return b58encode(data + checksum[0:4])

    def sh_to_address(self, sh: bytes) -> str:
        assert (len(sh) == 20)
        prefix = self.chainparams_network()['script_address']
        data = prefix.to_bytes(2, 'big') + sh
        checksum = blake256(blake256(data))
        return b58encode(data + checksum[0:4])

    def decode_address(self, address: str) -> bytes:
        addr_data = b58decode(address)
        if addr_data is None:
            return None
        prefixed_data = addr_data[:-4]
        checksum = addr_data[-4:]
        if blake256(blake256(prefixed_data))[:4] != checksum:
            raise ValueError('Checksum mismatch')
        return prefixed_data

    def testDaemonRPC(self, with_wallet=True) -> None:
        if with_wallet:
            self.rpc_wallet('getinfo')
        else:
            self.rpc('getblockchaininfo')

    def getChainHeight(self) -> int:
        return self.rpc('getblockcount')

    def checkWallets(self) -> int:
        # Only one wallet possible?
        return 1

    def initialiseWallet(self, key: bytes) -> None:
        # Load with --create
        pass

    def getDaemonVersion(self):
        return self.rpc('getnetworkinfo')['version']

    def getBlockchainInfo(self):
        return self.rpc('getblockchaininfo')

    def using_segwit(self) -> bool:
        return self._use_segwit

    def getWalletInfo(self):
        rv = {}
        rv = self.rpc_wallet('getinfo')
        wi = self.rpc_wallet('walletinfo')
        balances = self.rpc_wallet('getbalance')

        default_account_bal = balances['balances'][0]  # 0 always default?
        rv['balance'] = default_account_bal['spendable']
        rv['unconfirmed_balance'] = default_account_bal['unconfirmed']
        rv['immature_balance'] = default_account_bal['immaturecoinbaserewards'] + default_account_bal['immaturestakegeneration']
        rv['encrypted'] = True
        rv['locked'] = True if wi['unlocked'] is False else False

        return rv

    def getSeedHash(self, seed: bytes) -> bytes:
        # m / purpose' / coin_type' / account' / change / address_index
        # m/44'/coin_type'/0'/0/0

        ek = ExtKeyPair(self.coin_type())
        ek.set_seed(seed)

        coin_type = self.chainparams_network()['bip44']
        ek_purpose = ek.derive(44 | (1 << 31))
        ek_coin = ek_purpose.derive(coin_type | (1 << 31))
        ek_account = ek_coin.derive(0 | (1 << 31))

        return hash160(ek_account.encode_p())

    def decodeKey(self, encoded_key: str) -> (int, bytes):
        key = b58decode(encoded_key)
        checksum = key[-4:]
        key = key[:-4]

        if blake256(key)[:4] != checksum:
            raise ValueError('Checksum mismatch')
        return key[2], key[3:]

    def loadTx(self, tx_bytes: bytes) -> CTransaction:
        tx = CTransaction()
        tx.deserialize(tx_bytes)
        return tx

    def signTx(self, key_bytes: bytes, tx_bytes: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bytes:
        tx = self.loadTx(tx_bytes)
        sig_hash = DCRSignatureHash(prevout_script, SigHashType.SigHashAll, tx, input_n)

        eck = PrivateKey(key_bytes)
        return eck.sign(sig_hash, hasher=None) + bytes((SigHashType.SigHashAll,))

    def setTxSignature(self, tx_bytes: bytes, stack, txi: int = 0) -> bytes:
        tx = self.loadTx(tx_bytes)

        script_data = bytearray()
        for data in stack:
            push_script_data(script_data, data)

        tx.vin[txi].signature_script = script_data

        return tx.serialize()

    def stripTxSignature(self, tx_bytes) -> bytes:
        tx = self.loadTx(tx_bytes)
        return tx.serialize(TxSerializeType.NoWitness)

    def getTxSignature(self, tx_hex: str, prevout_data, key_wif: str) -> str:
        sig_type, key = self.decodeKey(key_wif)
        redeem_script = bytes.fromhex(prevout_data['redeemScript'])
        sig = self.signTx(key, bytes.fromhex(tx_hex), 0, redeem_script, self.make_int(prevout_data['amount']))

        return sig.hex()

    def getScriptDest(self, script: bytes) -> bytes:
        # P2SH
        script_hash = self.pkh(script)
        assert len(script_hash) == 20

        return OP_HASH160.to_bytes(1) + len(script_hash).to_bytes(1) + script_hash + OP_EQUAL.to_bytes(1)

    def encodeScriptDest(self, script_dest: bytes) -> str:
        script_hash = script_dest[2:-1]  # Extract hash from script
        return self.sh_to_address(script_hash)

    def getPubkeyHashDest(self, pkh: bytes) -> bytes:
        # P2PKH

        assert len(pkh) == 20
        return OP_DUP.to_bytes(1) + OP_HASH160.to_bytes(1) + len(pkh).to_bytes(1) + pkh + OP_EQUALVERIFY.to_bytes(1) + OP_CHECKSIG.to_bytes(1)

    def get_fee_rate(self, conf_target: int = 2) -> (float, str):
        chain_client_settings = self._sc.getChainClientSettings(self.coin_type())  # basicswap.json
        override_feerate = chain_client_settings.get('override_feerate', None)
        if override_feerate:
            self._log.debug('Fee rate override used for %s: %f', self.coin_name(), override_feerate)
            return override_feerate, 'override_feerate'

        min_relay_fee = chain_client_settings.get('min_relay_fee', None)

        def try_get_fee_rate(self, conf_target):
            # TODO: How to estimate required fee?
            try:
                fee_rate: float = self.rpc_wallet('walletinfo')['txfee']
                assert (fee_rate > 0.0), 'Non positive feerate'
                return fee_rate, 'paytxfee'
            except Exception:
                fee_rate: float = self.rpc('getnetworkinfo')['relayfee']
                return fee_rate, 'relayfee'

        fee_rate, rate_src = try_get_fee_rate(self, conf_target)
        if min_relay_fee and min_relay_fee > fee_rate:
            self._log.warning('Feerate {} ({}) is below min relay fee {} for {}'.format(self.format_amount(fee_rate, True, 1), rate_src, self.format_amount(min_relay_fee, True, 1), self.coin_name()))
            return min_relay_fee, 'min_relay_fee'
        return fee_rate, rate_src

    def getNewAddress(self, use_segwit: bool = True, label: str = 'swap_receive') -> str:
        return self.rpc_wallet('getnewaddress')

    def getProofOfFunds(self, amount_for, extra_commit_bytes):
        # TODO: Lock unspent and use same output/s to fund bid

        unspents_by_addr = dict()
        unspents = self.rpc_wallet('listunspent')
        if unspents is None:
            unspents = []
        for u in unspents:
            if u['spendable'] is not True:
                continue
            if u['address'] not in unspents_by_addr:
                unspents_by_addr[u['address']] = {'total': 0, 'utxos': []}
            utxo_amount: int = self.make_int(u['amount'], r=1)
            unspents_by_addr[u['address']]['total'] += utxo_amount
            unspents_by_addr[u['address']]['utxos'].append((utxo_amount, u['txid'], u['vout'], u['tree']))

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
            outpoint = (bytes.fromhex(utxo[1]), utxo[2], utxo[3])
            prove_utxos.append(outpoint)
            hasher.update(outpoint[0])
            hasher.update(outpoint[1].to_bytes(2, 'big'))
            hasher.update(outpoint[2].to_bytes(1))
            if sum_value >= amount_for:
                break
        utxos_hash = hasher.digest()

        signature = self.rpc_wallet('signmessage', [sign_for_addr, sign_for_addr + '_swap_proof_' + utxos_hash.hex() + extra_commit_bytes.hex()])

        return (sign_for_addr, signature, prove_utxos)

    def withdrawCoin(self, value: float, addr_to: str, subfee: bool = False) -> str:
        if subfee:
            raise ValueError('TODO')
        params = [addr_to, value]
        return self.rpc_wallet('sendtoaddress', params)

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        addr_info = self.rpc('validateaddress', [address])
        return addr_info.get('ismine', False)

    def encodeProofUtxos(self, proof_utxos):
        packed_utxos = bytes()
        for utxo in proof_utxos:
            packed_utxos += utxo[0] + utxo[1].to_bytes(2, 'big') + utxo[2].to_bytes(1)
        return packed_utxos

    def decodeProofUtxos(self, msg_utxos):
        proof_utxos = []
        if len(msg_utxos) > 0:
            num_utxos = len(msg_utxos) // 34
            p: int = 0
            for i in range(num_utxos):
                proof_utxos.append((msg_utxos[p: p + 32], int.from_bytes(msg_utxos[p + 32: p + 34], 'big'), msg_utxos[p + 34]))
                p += 35
        return proof_utxos

    def verifyProofOfFunds(self, address: str, signature: bytes, utxos, extra_commit_bytes: bytes):
        hasher = hashlib.sha256()
        sum_value: int = 0
        for outpoint in utxos:
            hasher.update(outpoint[0])
            hasher.update(outpoint[1].to_bytes(2, 'big'))
            hasher.update(outpoint[2].to_bytes(1))
        utxos_hash = hasher.digest()

        passed = self.verifyMessage(address, address + '_swap_proof_' + utxos_hash.hex() + extra_commit_bytes.hex(), signature)
        ensure(passed is True, 'Proof of funds signature invalid')

        sum_value: int = 0
        for outpoint in utxos:
            txout = self.rpc('gettxout', [outpoint[0].hex(), outpoint[1], outpoint[2]])
            sum_value += self.make_int(txout['value'])

        return sum_value

    def verifyMessage(self, address: str, message: str, signature: str, message_magic: str = None) -> bool:
        if message_magic is None:
            message_magic = self.chainparams()['message_magic']

        message_bytes = SerialiseNumCompact(len(message_magic)) + bytes(message_magic, 'utf-8') + SerialiseNumCompact(len(message)) + bytes(message, 'utf-8')
        message_hash = blake256(message_bytes)
        signature_bytes = base64.b64decode(signature)
        rec_id = (signature_bytes[0] - 27) & 3
        signature_bytes = signature_bytes[1:] + bytes((rec_id,))
        try:
            pubkey = PublicKey.from_signature_and_message(signature_bytes, message_hash, hasher=None)
        except Exception as e:
            self._log.info('verifyMessage failed: ' + str(e))
            return False

        address_hash = self.decode_address(address)[2:]
        pubkey_hash = ripemd160(blake256(pubkey.format()))

        return True if address_hash == pubkey_hash else False

    def signTxWithWallet(self, tx) -> bytes:
        return bytes.fromhex(self.rpc('signrawtransaction', [tx.hex()])['hex'])

    def createRawFundedTransaction(self, addr_to: str, amount: int, sub_fee: bool = False, lock_unspents: bool = True) -> str:

        # amount can't be a string, else: Failed to parse request: parameter #2 'amounts' must be type float64 (got string)
        float_amount = float(self.format_amount(amount))
        txn = self.rpc('createrawtransaction', [[], {addr_to: float_amount}])
        fee_rate, fee_src = self.get_fee_rate(self._conf_target)
        self._log.debug(f'Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}')
        options = {
            'lockUnspents': lock_unspents,
            'feeRate': fee_rate,
        }
        if sub_fee:
            options['subtractFeeFromOutputs'] = [0,]
        return self.rpc_wallet('fundrawtransaction', [txn, 'default', options])['hex']

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self.createRawFundedTransaction(addr_to, amount)
        return self.rpc_wallet('signrawtransaction', [txn_funded])['hex']

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, find_index: bool = False):
        self._log.debug('TODO: getLockTxHeight')
        return None

    def find_prevout_info(self, txn_hex: str, txn_script: bytes):
        txjs = self.rpc('decoderawtransaction', [txn_hex])
        n = getVoutByScriptPubKey(txjs, self.getScriptDest(txn_script).hex())

        return {
            'txid': txjs['txid'],
            'vout': n,
            'scriptPubKey': txjs['vout'][n]['scriptPubKey']['hex'],
            'redeemScript': txn_script.hex(),
            'amount': txjs['vout'][n]['value']
        }
