#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import hashlib
import json
import logging
import random
import traceback

from basicswap.basicswap_util import (
    getVoutByScriptPubKey,
    TxLockTypes
)
from basicswap.chainparams import Coins
from basicswap.contrib.test_framework.script import (
    CScriptNum,
)
from basicswap.interface.base import (
    Secp256k1Interface,
)
from basicswap.interface.btc import (
    extractScriptLockScriptValues,
    extractScriptLockRefundScriptValues,
)
from basicswap.util import (
    ensure,
    b2h, b2i, i2b, i2h,
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
from basicswap.interface.dcr.rpc import make_rpc_func, openrpc
from .messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    findOutput,
    SigHashType,
    TxSerializeType,
)
from .script import (
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    push_script_data,
)
from coincurve.keys import (
    PrivateKey,
    PublicKey,
)
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key
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
        hash_buffer += txi.prevout.tree.to_bytes(1, 'little')

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


def extract_sig_and_pk(sig_script: bytes) -> (bytes, bytes):
    sig = None
    pk = None
    o: int = 0
    num_bytes = sig_script[o]
    o += 1
    sig = sig_script[o: o + num_bytes]
    o += num_bytes
    num_bytes = sig_script[o]
    o += 1
    pk = sig_script[o: o + num_bytes]
    return sig, pk


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
    def xmr_swap_a_lock_spend_tx_vsize() -> int:
        return 327

    @staticmethod
    def xmr_swap_b_lock_spend_tx_vsize() -> int:
        return 224

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

    @staticmethod
    def decodeSequence(lock_value: int) -> int:
        # Return the raw value
        if lock_value & SEQUENCE_LOCKTIME_TYPE_FLAG:
            return (lock_value & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY
        return lock_value & SEQUENCE_LOCKTIME_MASK

    @staticmethod
    def watch_blocks_for_scripts() -> bool:
        return True

    @staticmethod
    def depth_spendable() -> int:
        return 0

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__(network)
        self._rpc_host = coin_settings.get('rpchost', '127.0.0.1')
        self._rpcport = coin_settings['rpcport']
        self._rpcauth = coin_settings['rpcauth']
        self._sc = swap_client
        self._log = self._sc.log if self._sc and self._sc.log else logging
        self.rpc = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host)
        if 'walletrpcport' in coin_settings:
            self._walletrpcport = coin_settings['walletrpcport']
            self.rpc_wallet = make_rpc_func(self._walletrpcport, self._rpcauth, host=self._rpc_host)
        else:
            self._walletrpcport = None
            self.rpc_wallet = None
        self.blocks_confirmed = coin_settings['blocks_confirmed']
        self.setConfTarget(coin_settings['conf_target'])

        self._use_segwit = True  # Decred is natively segwit
        self._connection_type = coin_settings['connection_type']

    def open_rpc(self):
        return openrpc(self._rpcport, self._rpcauth, host=self._rpc_host)

    def json_request(self, rpc_conn, method, params):
        try:
            v = rpc_conn.json_request(method, params)
            r = json.loads(v.decode('utf-8'))
        except Exception as ex:
            traceback.print_exc()
            raise ValueError('RPC Server Error ' + str(ex))
        if 'error' in r and r['error'] is not None:
            raise ValueError('RPC error ' + str(r['error']))
        return r['result']

    def close_rpc(self, rpc_conn):
        rpc_conn.close()

    def use_tx_vsize(self) -> bool:
        return False

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
        # Different from decodeAddress returns more prefix bytes
        addr_data = b58decode(address)
        if addr_data is None:
            return None
        prefixed_data = addr_data[:-4]
        checksum = addr_data[-4:]
        if blake256(blake256(prefixed_data))[:4] != checksum:
            raise ValueError('Checksum mismatch')
        return prefixed_data

    def decodeAddress(self, address: str) -> bytes:
        return self.decode_address(address)[2:]

    def testDaemonRPC(self, with_wallet=True) -> None:
        if with_wallet:
            self.rpc_wallet('getinfo')
        else:
            self.rpc('getblockchaininfo')

    def getChainHeight(self) -> int:
        return self.rpc('getblockcount')

    def initialiseWallet(self, key: bytes) -> None:
        # Load with --create
        pass

    def isWalletEncrypted(self) -> bool:
        return True

    def isWalletLocked(self) -> bool:
        walletislocked = self.rpc_wallet('walletislocked')
        return walletislocked

    def isWalletEncryptedLocked(self) -> (bool, bool):
        walletislocked = self.rpc_wallet('walletislocked')
        return True, walletislocked

    def changeWalletPassword(self, old_password: str, new_password: str):
        self._log.info('changeWalletPassword - {}'.format(self.ticker()))
        if old_password == '':
            # Read initial pwd from settings
            settings = self._sc.getChainClientSettings(self.coin_type())
            old_password = settings['wallet_pwd']
        self.rpc_wallet('walletpassphrasechange', [old_password, new_password])

        # Lock wallet to match other coins
        self.rpc_wallet('walletlock')

        # Clear initial password
        self._sc.editSettings(self.coin_name().lower(), {'wallet_pwd': ''})

    def unlockWallet(self, password: str):
        if password == '':
            return
        self._log.info('unlockWallet - {}'.format(self.ticker()))

        # Max timeout value, ~3 years
        self.rpc_wallet('walletpassphrase', [password, 100000000])
        self._sc.checkWalletSeed(self.coin_type())

    def lockWallet(self):
        self._log.info('lockWallet - {}'.format(self.ticker()))
        self.rpc_wallet('walletlock')

    def getWalletSeedID(self):
        masterpubkey = self.rpc_wallet('getmasterpubkey')
        masterpubkey_data = self.decode_address(masterpubkey)[4:]
        return hash160(masterpubkey_data).hex()

    def checkExpectedSeed(self, expect_seedid) -> bool:
        self._expect_seedid_hex = expect_seedid
        return expect_seedid == self.getWalletSeedID()

    def getDaemonVersion(self):
        return self.rpc('getnetworkinfo')['version']

    def getBlockchainInfo(self):
        bci = self.rpc('getblockchaininfo')

        # Adjust verificationprogress to consider blocks wallet has synced
        wallet_blocks = self.rpc_wallet('getinfo')['blocks']
        synced_ind = bci['verificationprogress']
        wallet_synced_ind = wallet_blocks / bci['headers']
        if wallet_synced_ind < synced_ind:
            bci['verificationprogress'] = wallet_synced_ind

        return bci

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

    def getSpendableBalance(self) -> int:
        balances = self.rpc_wallet('getbalance')
        default_account_bal = balances['balances'][0]  # 0 always default?
        return self.make_int(default_account_bal['spendable'])

    def getSeedHash(self, seed: bytes, coin_type_id=None) -> bytes:
        # m / purpose' / coin_type' / account' / change / address_index
        # m/44'/coin_type'/0'/0/0

        ek = ExtKeyPair(self.coin_type())
        ek.set_seed(seed)

        coin_type = self.chainparams_network()['bip44'] if coin_type_id is None else coin_type_id
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

    def encodeKey(self, key_bytes: bytes) -> str:
        wif_prefix = self.chainparams_network()['key_prefix']
        key_type = 0  # STEcdsaSecp256k1
        b = wif_prefix.to_bytes(2, 'big') + key_type.to_bytes(1, 'big') + key_bytes
        b += blake256(b)[:4]
        return b58encode(b)

    def loadTx(self, tx_bytes: bytes) -> CTransaction:
        tx = CTransaction()
        tx.deserialize(tx_bytes)
        return tx

    def signTx(self, key_bytes: bytes, tx_bytes: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bytes:
        tx = self.loadTx(tx_bytes)
        sig_hash = DCRSignatureHash(prevout_script, SigHashType.SigHashAll, tx, input_n)

        eck = PrivateKey(key_bytes)
        return eck.sign(sig_hash, hasher=None) + bytes((SigHashType.SigHashAll,))

    def setTxSignatureScript(self, tx_bytes: bytes, script: bytes, txi: int = 0) -> bytes:
        tx = self.loadTx(tx_bytes)

        tx.vin[txi].signature_script = script
        return tx.serialize()

    def setTxSignature(self, tx_bytes: bytes, stack, txi: int = 0) -> bytes:
        tx = self.loadTx(tx_bytes)

        script_data = bytearray()
        for data in stack:
            push_script_data(script_data, data)

        tx.vin[txi].signature_script = script_data
        test_ser = tx.serialize()
        test_tx = self.loadTx(test_ser)

        return tx.serialize()

    def stripTxSignature(self, tx_bytes) -> bytes:
        tx = self.loadTx(tx_bytes)
        return tx.serialize(TxSerializeType.NoWitness)

    def getTxSignature(self, tx_hex: str, prevout_data, key_wif: str) -> str:
        sig_type, key = self.decodeKey(key_wif)
        redeem_script = bytes.fromhex(prevout_data['redeemScript'])
        sig = self.signTx(key, bytes.fromhex(tx_hex), 0, redeem_script, self.make_int(prevout_data['amount']))

        return sig.hex()

    def verifyTxSig(self, tx_bytes: bytes, sig: bytes, K: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bool:
        tx = self.loadTx(tx_bytes)

        sig_hash = DCRSignatureHash(prevout_script, SigHashType.SigHashAll, tx, input_n)
        pubkey = PublicKey(K)
        return pubkey.verify(sig[: -1], sig_hash, hasher=None)  # Pop the hashtype byte

    def getTxid(self, tx) -> bytes:
        if isinstance(tx, str):
            tx = bytes.fromhex(tx)
        if isinstance(tx, bytes):
            tx = self.loadTx(tx)
        return tx.TxHash()

    def getScriptDest(self, script: bytes) -> bytes:
        # P2SH
        script_hash = self.pkh(script)
        assert len(script_hash) == 20

        return bytes((OP_HASH160,)) + bytes((len(script_hash),)) + script_hash + bytes((OP_EQUAL,))

    def encodeScriptDest(self, script_dest: bytes) -> str:
        script_hash = script_dest[2:-1]  # Extract hash from script
        return self.sh_to_address(script_hash)

    def getPubkeyHashDest(self, pkh: bytes) -> bytes:
        # P2PKH
        assert len(pkh) == 20
        return bytes((OP_DUP,)) + bytes((OP_HASH160,)) + bytes((len(pkh),)) + pkh + bytes((OP_EQUALVERIFY,)) + bytes((OP_CHECKSIG,))

    def getPkDest(self, K: bytes) -> bytearray:
        return self.getPubkeyHashDest(self.pkh(K))

    def getSCLockScriptAddress(self, lock_script: bytes) -> str:
        lock_tx_dest = self.getScriptDest(lock_script)
        return self.encodeScriptDest(lock_tx_dest)

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

    def getWalletTransaction(self, txid: bytes):
        try:
            return bytes.fromhex(self.rpc_wallet('gettransaction', [txid.hex()])['hex'])
        except Exception as ex:
            # TODO: filter errors
            return None

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
            hasher.update(outpoint[2].to_bytes(1, 'big'))
            if sum_value >= amount_for:
                break
        utxos_hash = hasher.digest()

        signature = self.rpc_wallet('signmessage', [sign_for_addr, sign_for_addr + '_swap_proof_' + utxos_hash.hex() + extra_commit_bytes.hex()])

        return (sign_for_addr, signature, prove_utxos)

    def withdrawCoin(self, value: float, addr_to: str, subfee: bool = False) -> str:
        if subfee:
            raise ValueError('TODO')
        params = [addr_to, float(value)]
        return self.rpc_wallet('sendtoaddress', params)

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        addr_info = self.rpc_wallet('validateaddress', [address])
        return addr_info.get('ismine', False)

    def encodeProofUtxos(self, proof_utxos):
        packed_utxos = bytes()
        for utxo in proof_utxos:
            packed_utxos += utxo[0] + utxo[1].to_bytes(2, 'big') + utxo[2].to_bytes(1, 'big')
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
            hasher.update(outpoint[2].to_bytes(1, 'big'))
        utxos_hash = hasher.digest()

        passed = self.verifyMessage(address, address + '_swap_proof_' + utxos_hash.hex() + extra_commit_bytes.hex(), signature)
        ensure(passed is True, 'Proof of funds signature invalid')

        sum_value: int = 0
        for outpoint in utxos:
            txout = self.rpc('gettxout', [outpoint[0].hex(), outpoint[1], outpoint[2]])
            sum_value += self.make_int(txout['value'])

        return sum_value

    def signCompact(self, k, message):
        message_hash = blake256(bytes(message, 'utf-8'))

        privkey = PrivateKey(k)
        return privkey.sign_recoverable(message_hash, hasher=None)[:64]

    def signRecoverable(self, k, message: str) -> bytes:
        message_hash = blake256(bytes(message, 'utf-8'))

        privkey = PrivateKey(k)
        return privkey.sign_recoverable(message_hash, hasher=None)

    def verifyCompactSig(self, K, message: str, sig) -> None:
        message_hash = blake256(bytes(message, 'utf-8'))
        pubkey = PublicKey(K)
        rv = pubkey.verify_compact(sig, message_hash, hasher=None)
        assert (rv is True)

    def verifySigAndRecover(self, sig, message: str) -> bytes:
        message_hash = blake256(bytes(message, 'utf-8'))
        pubkey = PublicKey.from_signature_and_message(sig, message_hash, hasher=None)
        return pubkey.format()

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
        return bytes.fromhex(self.rpc_wallet('signrawtransaction', [tx.hex()])['hex'])

    def signTxWithKey(self, tx: bytes, key: bytes) -> bytes:
        key_wif = self.encodeKey(key)
        rv = self.rpc_wallet('signrawtransaction', [tx.hex(), [], [key_wif, ]])
        return bytes.fromhex(rv['hex'])

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

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, find_index: bool = False, vout: int = -1):
        if txid is None:
            self._log.debug('TODO: getLockTxHeight')
            return None

        found_vout = None
        # Search for txo at vout 0 and 1 if vout is not known
        if vout is None:
            test_range = range(2)
        else:
            test_range = (vout, )
        for try_vout in test_range:
            try:
                txout = self.rpc('gettxout', [txid.hex(), try_vout, 0, True])
                addresses = txout['scriptPubKey']['addresses']
                if len(addresses) != 1 or addresses[0] != dest_address:
                    continue
                if self.make_int(txout['value']) != bid_amount:
                    self._log.warning('getLockTxHeight found txout {} with incorrect amount {}'.format(txid.hex(), txout['value']))
                    continue
                found_vout = try_vout
                break
            except Exception as e:
                # self._log.warning('gettxout {}'.format(e))
                return None

        if found_vout is None:
            return None

        block_height: int = 0
        confirmations: int = 0 if 'confirmations' not in txout else txout['confirmations']

        # TODO: Better way?
        if confirmations > 0:
            block_height = self.getChainHeight() - confirmations

        rv = {
            'txid': txid.hex(),
            'depth': confirmations,
            'index': found_vout,
            'height': block_height}

        return rv

    def find_prevout_info(self, txn_hex: str, txn_script: bytes):
        txjs = self.rpc('decoderawtransaction', [txn_hex])
        n = getVoutByScriptPubKey(txjs, self.getScriptDest(txn_script).hex())

        txo = txjs['vout'][n]
        return {
            'txid': txjs['txid'],
            'vout': n,
            'scriptPubKey': txo['scriptPubKey']['hex'],
            'redeemScript': txn_script.hex(),
            'amount': txo['value'],
        }

    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        tx_vsize = 5  # Add a few bytes, sequence in script takes variable amount of bytes
        tx_vsize += 348 if redeem else 316
        return tx_vsize

    def createRedeemTxn(self, prevout, output_addr: str, output_value: int, txn_script: bytes = None) -> str:
        tx = CTransaction()
        tx.version = self.txVersion()
        prev_txid = b2i(bytes.fromhex(prevout['txid']))
        tx.vin.append(CTxIn(COutPoint(prev_txid, prevout['vout'], 0)))
        pkh = self.decode_address(output_addr)[2:]
        script = self.getPubkeyHashDest(pkh)
        tx.vout.append(self.txoType()(output_value, script))
        return tx.serialize().hex()

    def createRefundTxn(self, prevout, output_addr: str, output_value: int, locktime: int, sequence: int, txn_script: bytes = None) -> str:
        tx = CTransaction()
        tx.version = self.txVersion()
        tx.locktime = locktime
        prev_txid = b2i(bytes.fromhex(prevout['txid']))
        tx.vin.append(CTxIn(COutPoint(prev_txid, prevout['vout'], 0), sequence=sequence,))
        pkh = self.decode_address(output_addr)[2:]
        script = self.getPubkeyHashDest(pkh)
        tx.vout.append(self.txoType()(output_value, script))
        return tx.serialize().hex()

    def verifyRawTransaction(self, tx_hex: str, prevouts):
        inputs_valid: bool = True
        validscripts: int = 0

        tx_bytes = bytes.fromhex(tx_hex)
        tx = self.loadTx(bytes.fromhex(tx_hex))

        for i, txi in enumerate(tx.vin):
            prevout_data = prevouts[i]
            redeem_script = bytes.fromhex(prevout_data['redeemScript'])
            prevout_value = self.make_int(prevout_data['amount'])
            sig, pk = extract_sig_and_pk(txi.signature_script)

            if not sig or not pk:
                self._log.warning(f'verifyRawTransaction failed to extract signature for input {i}')
                continue

            if self.verifyTxSig(tx_bytes, sig, pk, i, redeem_script, prevout_value):
                validscripts += 1

        # TODO: validate inputs
        inputs_valid = True

        return {
            'inputs_valid': inputs_valid,
            'validscripts': validscripts,
        }

    def getBlockHeaderFromHeight(self, height):
        block_hash = self.rpc('getblockhash', [height])
        return self.rpc('getblockheader', [block_hash])

    def getBlockHeaderAt(self, time: int, block_after=False):
        blockchaininfo = self.rpc('getblockchaininfo')
        last_block_header = self.rpc('getblockheader', [blockchaininfo['bestblockhash']])

        max_tries = 5000
        for i in range(max_tries):
            prev_block_header = self.rpc('getblockheader', [last_block_header['previousblockhash']])
            if prev_block_header['time'] <= time:
                return last_block_header if block_after else prev_block_header

            last_block_header = prev_block_header
        raise ValueError(f'Block header not found at time: {time}')

    def getMempoolTx(self, txid):
        raise ValueError('TODO')

    def getBlockWithTxns(self, block_hash: str):
        block = self.rpc('getblock', [block_hash, True, True])

        return {
            'hash': block['hash'],
            'previousblockhash': block['previousblockhash'],
            'tx': block['rawtx'],
            'confirmations': block['confirmations'],
            'height': block['height'],
            'time': block['time'],
            'version': block['version'],
            'merkleroot': block['merkleroot'],
        }

    def publishTx(self, tx: bytes):
        return self.rpc('sendrawtransaction', [tx.hex()])

    def describeTx(self, tx_hex: str):
        return self.rpc('decoderawtransaction', [tx_hex])

    def fundTx(self, tx: bytes, feerate) -> bytes:
        feerate_str = float(self.format_amount(feerate))
        # TODO: unlock unspents if bid cancelled
        options = {
            'feeRate': feerate_str,
        }
        rv = self.rpc_wallet('fundrawtransaction', [tx.hex(), 'default', options])
        tx_bytes = bytes.fromhex(rv['hex'])

        tx_obj = self.loadTx(tx_bytes)
        for txi in tx_obj.vin:
            utxos = [{'amount': float(self.format_amount(txi.value_in)),
                      'txid': i2h(txi.prevout.hash),
                      'vout': txi.prevout.n,
                      'tree': txi.prevout.tree}]
            rv = self.rpc_wallet('lockunspent', [False, utxos])

        return tx_bytes

    def createSCLockTx(self, value: int, script: bytearray, vkbv: bytes = None) -> bytes:
        tx = CTransaction()
        tx.version = self.txVersion()
        tx.vout.append(self.txoType()(value, self.getScriptDest(script)))
        return tx.serialize()

    def fundSCLockTx(self, tx_bytes, feerate, vkbv=None):
        return self.fundTx(tx_bytes, feerate)

    def genScriptLockRefundTxScript(self, Kal, Kaf, csv_val) -> bytes:

        Kal_enc = Kal if len(Kal) == 33 else self.encodePubkey(Kal)
        Kaf_enc = Kaf if len(Kaf) == 33 else self.encodePubkey(Kaf)

        script = bytearray()
        script += bytes((OP_IF,))
        push_script_data(script, bytes((2,)))
        push_script_data(script, Kal_enc)
        push_script_data(script, Kaf_enc)
        push_script_data(script, bytes((2,)))
        script += bytes((OP_CHECKMULTISIG,))
        script += bytes((OP_ELSE,))
        script += CScriptNum.encode(CScriptNum(csv_val))
        script += bytes((OP_CHECKSEQUENCEVERIFY,))
        script += bytes((OP_DROP,))
        push_script_data(script, Kaf_enc)
        script += bytes((OP_CHECKSIG,))
        script += bytes((OP_ENDIF,))

        return script

    def createSCLockSpendTx(self, tx_lock_bytes, script_lock, pkh_dest, tx_fee_rate, vkbv=None, fee_info={}):
        tx_lock = self.loadTx(tx_lock_bytes)
        output_script = self.getScriptDest(script_lock)
        locked_n = findOutput(tx_lock, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].value

        tx_lock_id_int = b2i(tx_lock.TxHash())

        tx = CTransaction()
        tx.version = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_id_int, locked_n, 0)))
        tx.vout.append(self.txoType()(locked_coin, self.getPubkeyHashDest(pkh_dest)))

        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)
        size = len(self.setTxSignature(tx.serialize(), dummy_witness_stack))
        pay_fee = round(tx_fee_rate * size / 1000)
        tx.vout[0].value = locked_coin - pay_fee

        fee_info['fee_paid'] = pay_fee
        fee_info['rate_used'] = tx_fee_rate
        fee_info['size'] = size

        self._log.info('createSCLockSpendTx %s:\n    fee_rate, size, fee: %ld, %ld, %ld.',
                       tx.TxHash().hex(), tx_fee_rate, size, pay_fee)

        return tx.serialize(TxSerializeType.NoWitness)

    def createSCLockRefundTx(self, tx_lock_bytes, script_lock, Kal, Kaf, lock1_value, csv_val, tx_fee_rate, vkbv=None):
        tx_lock = CTransaction()
        tx_lock = self.loadTx(tx_lock_bytes)

        output_script = self.getScriptDest(script_lock)
        locked_n = findOutput(tx_lock, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock.vout[locked_n].value

        tx_lock_id_int = b2i(tx_lock.TxHash())

        refund_script = self.genScriptLockRefundTxScript(Kal, Kaf, csv_val)
        tx = CTransaction()
        tx.version = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_id_int, locked_n, 0),
                            sequence=lock1_value))
        tx.vout.append(self.txoType()(locked_coin, self.getScriptDest(refund_script)))

        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)
        size = len(self.setTxSignature(tx.serialize(), dummy_witness_stack))
        pay_fee = round(tx_fee_rate * size / 1000)
        tx.vout[0].value = locked_coin - pay_fee

        self._log.info('createSCLockRefundTx %s:\n    fee_rate, size, fee: %ld, %ld, %ld.',
                       tx.TxHash().hex(), tx_fee_rate, size, pay_fee)

        return tx.serialize(TxSerializeType.NoWitness), refund_script, tx.vout[0].value

    def createSCLockRefundSpendTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_refund_to, tx_fee_rate, vkbv=None):
        # Returns the coinA locked coin to the leader
        # The follower will sign the multisig path with a signature encumbered by the leader's coinB spend pubkey
        # If the leader publishes the decrypted signature the leader's coinB spend privatekey will be revealed to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = self.getScriptDest(script_lock_refund)
        locked_n = findOutput(tx_lock_refund, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx_lock_refund.vout[locked_n].value

        tx_lock_refund_hash_int = b2i(tx_lock_refund.TxHash())

        tx = CTransaction()
        tx.version = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n, 0),
                            sequence=0))

        tx.vout.append(self.txoType()(locked_coin, self.getPubkeyHashDest(pkh_refund_to)))

        dummy_witness_stack = self.getScriptLockRefundSpendTxDummyWitness(script_lock_refund)
        size = len(self.setTxSignature(tx.serialize(), dummy_witness_stack))
        pay_fee = round(tx_fee_rate * size / 1000)
        tx.vout[0].value = locked_coin - pay_fee

        self._log.info('createSCLockRefundSpendTx %s:\n    fee_rate, size, fee: %ld, %ld, %ld.',
                       tx.TxHash().hex(), tx_fee_rate, size, pay_fee)

        return tx.serialize(TxSerializeType.NoWitness)

    def verifySCLockTx(self, tx_bytes, script_out,
                       swap_value,
                       Kal, Kaf,
                       feerate,
                       check_lock_tx_inputs, vkbv=None):
        # Verify:
        #

        # Not necessary to check the lock txn is mineable, as protocol will wait for it to confirm
        # However by checking early we can avoid wasting time processing unmineable txns
        # Check fee is reasonable

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock tx: {}.'.format(b2h(txid)))

        ensure(tx.version == self.txVersion(), 'Bad version')
        ensure(tx.locktime == 0, 'Bad locktime')
        ensure(tx.expiry == 0, 'Bad expiry')

        script_pk = self.getScriptDest(script_out)
        locked_n = findOutput(tx, script_pk)
        ensure(locked_n is not None, 'Lock output not found in tx')
        locked_coin = tx.vout[locked_n].value

        # Check value
        ensure(locked_coin == swap_value, 'Bad locked value')

        # Check script
        A, B = extractScriptLockScriptValues(script_out)
        ensure(A == Kal, 'Bad script pubkey')
        ensure(B == Kaf, 'Bad script pubkey')

        if check_lock_tx_inputs:
            # TODO: Check that inputs are unspent
            # Verify fee rate
            inputs_value = 0
            add_bytes = 0
            add_witness_bytes = 0
            for pi in tx.vin:
                ptx = self.rpc('getrawtransaction', [i2h(pi.prevout.hash), True])
                prevout = ptx['vout'][pi.prevout.n]
                inputs_value += self.make_int(prevout['value'])
                self._log.info('prevout: {}.'.format(prevout))
                prevout_type = prevout['scriptPubKey']['type']

                '''
                if prevout_type == 'witness_v0_keyhash':
                    #add_witness_bytes += 107  # sig 72, pk 33 and 2 size bytes
                    #add_witness_bytes += getCompactSizeLen(107)
                else:
                    # Assume P2PKH, TODO more types
                    add_bytes += 107  # OP_PUSH72 <ecdsa_signature> OP_PUSH33 <public_key>
                '''

            outputs_value = 0
            for txo in tx.vout:
                outputs_value += txo.nValue
            fee_paid = inputs_value - outputs_value
            assert (fee_paid > 0)

            size = len(tx.serialize()) + add_witness_bytes
            fee_rate_paid = fee_paid * 1000 // size

            self._log.info('tx amount, size, feerate: %ld, %ld, %ld', locked_coin, size, fee_rate_paid)

            if not self.compareFeeRates(fee_rate_paid, feerate):
                self._log.warning('feerate paid doesn\'t match expected: %ld, %ld', fee_rate_paid, feerate)
                # TODO: Display warning to user

        return txid, locked_n

    def verifySCLockSpendTx(self, tx_bytes,
                            lock_tx_bytes, lock_tx_script,
                            a_pkhash_f, feerate, vkbv=None):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output with destination and amount

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock spend tx: {}.'.format(b2h(txid)))

        ensure(tx.version == self.txVersion(), 'Bad version')
        ensure(tx.locktime == 0, 'Bad locktime')
        ensure(tx.expiry == 0, 'Bad expiry')
        ensure(len(tx.vin) == 1, 'tx doesn\'t have one input')

        lock_tx = self.loadTx(lock_tx_bytes)
        lock_tx_id = self.getTxid(lock_tx)

        output_script = self.getScriptDest(lock_tx_script)
        locked_n = findOutput(lock_tx, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = lock_tx.vout[locked_n].value

        ensure(tx.vin[0].sequence == 0, 'Bad input nSequence')
        ensure(len(tx.vin[0].signature_script) == 0, 'Input sig not empty')
        ensure(i2b(tx.vin[0].prevout.hash) == lock_tx_id and tx.vin[0].prevout.n == locked_n, 'Input prevout mismatch')

        ensure(len(tx.vout) == 1, 'tx doesn\'t have one output')
        p2wpkh = self.getPubkeyHashDest(a_pkhash_f)
        ensure(tx.vout[0].script_pubkey == p2wpkh, 'Bad output destination')

        # The value of the lock tx output should already be verified, if the fee is as expected the difference will be the correct amount
        fee_paid = locked_coin - tx.vout[0].value
        assert (fee_paid > 0)

        dummy_witness_stack = self.getScriptLockTxDummyWitness(lock_tx_script)
        size = len(self.setTxSignature(tx.serialize(), dummy_witness_stack))
        fee_rate_paid = fee_paid * 1000 // size

        self._log.info('tx amount, size, feerate: %ld, %ld, %ld', tx.vout[0].value, size, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate, expected: {}'.format(feerate))

        return True

    def verifySCLockRefundTx(self, tx_bytes, lock_tx_bytes, script_out,
                             prevout_id, prevout_n, prevout_seq, prevout_script,
                             Kal, Kaf, csv_val_expect, swap_value, feerate, vkbv=None):
        # Verify:
        #   Must have only one input with correct prevout and sequence
        #   Must have only one output to the p2wsh of the lock refund script
        #   Output value must be locked_coin - lock tx fee

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock refund tx: {}.'.format(b2h(txid)))

        ensure(tx.version == self.txVersion(), 'Bad version')
        ensure(tx.locktime == 0, 'locktime not 0')
        ensure(tx.expiry == 0, 'Bad expiry')
        ensure(len(tx.vin) == 1, 'tx doesn\'t have one input')

        ensure(tx.vin[0].sequence == prevout_seq, 'Bad input sequence')
        ensure(i2b(tx.vin[0].prevout.hash) == prevout_id and tx.vin[0].prevout.n == prevout_n and tx.vin[0].prevout.tree == 0, 'Input prevout mismatch')
        ensure(len(tx.vin[0].signature_script) == 0, 'Input sig not empty')

        ensure(len(tx.vout) == 1, 'tx doesn\'t have one output')

        script_pk = self.getScriptDest(script_out)
        locked_n = findOutput(tx, script_pk)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_coin = tx.vout[locked_n].value

        # Check script and values
        A, B, csv_val, C = extractScriptLockRefundScriptValues(script_out)
        ensure(A == Kal, 'Bad script pubkey')
        ensure(B == Kaf, 'Bad script pubkey')
        ensure(csv_val == csv_val_expect, 'Bad script csv value')
        ensure(C == Kaf, 'Bad script pubkey')

        fee_paid = swap_value - locked_coin
        assert (fee_paid > 0)

        dummy_witness_stack = self.getScriptLockTxDummyWitness(prevout_script)
        size = len(self.setTxSignature(tx.serialize(), dummy_witness_stack))
        fee_rate_paid = fee_paid * 1000 // size

        self._log.info('tx amount, size, feerate: %ld, %ld, %ld', locked_coin, size, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate, expected: {}'.format(feerate))

        return txid, locked_coin, locked_n

    def verifySCLockRefundSpendTx(self, tx_bytes, lock_refund_tx_bytes,
                                  lock_refund_tx_id, prevout_script,
                                  Kal,
                                  prevout_n, prevout_value, feerate, vkbv=None):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output sending lock refund tx value - fee to leader's address, TODO: follower shouldn't need to verify destination addr
        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info('Verifying lock refund spend tx: {}.'.format(b2h(txid)))

        ensure(tx.version == self.txVersion(), 'Bad version')
        ensure(tx.locktime == 0, 'locktime not 0')
        ensure(tx.expiry == 0, 'Bad expiry')
        ensure(len(tx.vin) == 1, 'tx doesn\'t have one input')

        ensure(tx.vin[0].sequence == 0, 'Bad input sequence')
        ensure(len(tx.vin[0].signature_script) == 0, 'Input sig not empty')
        ensure(i2b(tx.vin[0].prevout.hash) == lock_refund_tx_id and tx.vin[0].prevout.n == 0 and tx.vin[0].prevout.tree == 0, 'Input prevout mismatch')

        ensure(len(tx.vout) == 1, 'tx doesn\'t have one output')

        # Destination doesn't matter to the follower
        '''
        p2wpkh = CScript([OP_0, hash160(Kal)])
        locked_n = findOutput(tx, p2wpkh)
        ensure(locked_n is not None, 'Output not found in lock refund spend tx')
        '''
        tx_value = tx.vout[0].value

        fee_paid = prevout_value - tx_value
        assert (fee_paid > 0)

        dummy_witness_stack = self.getScriptLockRefundSpendTxDummyWitness(prevout_script)
        size = len(self.setTxSignature(tx.serialize(), dummy_witness_stack))
        fee_rate_paid = fee_paid * 1000 // size

        self._log.info('tx amount, size, feerate: %ld, %ld, %ld', tx_value, size, fee_rate_paid)

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError('Bad fee rate, expected: {}'.format(feerate))

        return True

    def createSCLockRefundSpendToFTx(self, tx_lock_refund_bytes, script_lock_refund, pkh_dest, tx_fee_rate, vkbv=None):
        # lock refund swipe tx
        # Sends the coinA locked coin to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = self.getScriptDest(script_lock_refund)
        locked_n = findOutput(tx_lock_refund, output_script)
        ensure(locked_n is not None, 'Output not found in tx')
        locked_amount = tx_lock_refund.vout[locked_n].value

        A, B, lock2_value, C = extractScriptLockRefundScriptValues(script_lock_refund)

        tx_lock_refund_hash_int = b2i(tx_lock_refund.TxHash())

        tx = CTransaction()
        tx.version = self.txVersion()
        tx.vin.append(CTxIn(COutPoint(tx_lock_refund_hash_int, locked_n, 0),
                            sequence=lock2_value,))

        tx.vout.append(self.txoType()(locked_amount, self.getPubkeyHashDest(pkh_dest)))

        dummy_witness_stack = self.getScriptLockRefundSwipeTxDummyWitness(script_lock_refund)
        size = len(self.setTxSignature(tx.serialize(), dummy_witness_stack))
        pay_fee = round(tx_fee_rate * size / 1000)
        tx.vout[0].value = locked_amount - pay_fee

        self._log.info('createSCLockRefundSpendToFTx %s:\n    fee_rate, size, fee: %ld, %ld, %ld.',
                       tx.TxHash().hex(), tx_fee_rate, size, pay_fee)

        return tx.serialize(TxSerializeType.NoWitness)

    def signTxOtVES(self, key_sign: bytes, pubkey_encrypt: bytes, tx_bytes: bytes, input_n: int, prevout_script: bytes, prevout_value: int) -> bytes:
        tx = self.loadTx(tx_bytes)
        sig_hash = DCRSignatureHash(prevout_script, SigHashType.SigHashAll, tx, input_n)

        return ecdsaotves_enc_sign(key_sign, pubkey_encrypt, sig_hash)

    def verifyTxOtVES(self, tx_bytes: bytes, ct: bytes, Ks: bytes, Ke: bytes, input_n: int, prevout_script: bytes, prevout_value):
        tx = self.loadTx(tx_bytes)
        sig_hash = DCRSignatureHash(prevout_script, SigHashType.SigHashAll, tx, input_n)
        return ecdsaotves_enc_verify(Ks, Ke, sig_hash, ct)

    def decryptOtVES(self, k: bytes, esig: bytes) -> bytes:
        return ecdsaotves_dec_sig(k, esig) + bytes((SigHashType.SigHashAll,))

    def recoverEncKey(self, esig, sig, K):
        return ecdsaotves_rec_enc_key(K, esig, sig[:-1])  # Strip sighash type

    def getTxOutputPos(self, tx, script):
        if isinstance(tx, bytes):
            tx = self.loadTx(tx)
        script_pk = self.getScriptDest(script)
        return findOutput(tx, script_pk)

    def getScriptLockTxDummyWitness(self, script: bytes):
        return [
            bytes(72),
            bytes(72),
            bytes(len(script))
        ]

    def getScriptLockRefundSpendTxDummyWitness(self, script: bytes):
        return [
            bytes(72),
            bytes(72),
            bytes((1,)),
            bytes(len(script))
        ]

    def extractLeaderSig(self, tx_bytes: bytes) -> bytes:
        tx = self.loadTx(tx_bytes)

        sig_len = tx.vin[0].signature_script[0]
        return tx.vin[0].signature_script[1: 1 + sig_len]

    def extractFollowerSig(self, tx_bytes: bytes) -> bytes:
        tx = self.loadTx(tx_bytes)

        sig_len = tx.vin[0].signature_script[0]
        ofs = 1 + sig_len
        sig_len = tx.vin[0].signature_script[ofs]
        ofs += 1
        return tx.vin[0].signature_script[ofs: ofs + sig_len]

    def listInputs(self, tx_bytes: bytes):
        tx = self.loadTx(tx_bytes)

        all_locked = self.rpc_wallet('listlockunspent')
        inputs = []
        for txi in tx.vin:
            txid_hex = i2h(txi.prevout.hash)
            islocked = any([txid_hex == a['txid'] and txi.prevout.n == a['vout'] for a in all_locked])
            inputs.append({'txid': txid_hex, 'vout': txi.prevout.n, 'islocked': islocked})
        return inputs

    def unlockInputs(self, tx_bytes):
        tx = self.loadTx(tx_bytes)

        inputs = []
        for txi in tx.vin:
            inputs.append({'amount': float(self.format_amount(txi.value_in)), 'txid': i2h(txi.prevout.hash), 'vout': txi.prevout.n, 'tree': txi.prevout.tree})
        self.rpc_wallet('lockunspent', [True, inputs])

    def getWalletRestoreHeight(self) -> int:
        start_time = self.rpc_wallet('getinfo')['keypoololdest']

        blockchaininfo = self.getBlockchainInfo()
        best_block = blockchaininfo['bestblockhash']

        chain_synced = round(blockchaininfo['verificationprogress'], 3)
        if chain_synced < 1.0:
            raise ValueError('{} chain isn\'t synced.'.format(self.coin_name()))

        if start_time == 0:
            self._log.debug('Using genesis block for restore height as keypoololdest is 0.')
            return 0

        self._log.info('Finding block at time: {} for restore height.'.format(start_time))

        blocks_searched: int = 0
        rpc_conn = self.open_rpc()
        try:
            block_hash = best_block
            while True:
                block_header = self.json_request(rpc_conn, 'getblockheader', [block_hash])
                if block_header['time'] < start_time:
                    return block_header['height']
                # genesis block
                if block_header['previousblockhash'] == '0000000000000000000000000000000000000000000000000000000000000000':
                    return block_header['height']

                block_hash = block_header['previousblockhash']
                blocks_searched += 1
                if blocks_searched % 10000 == 0:
                    self._log.debug('Still finding restore height, block at height {} has time {}.'.format(block_header['height'], block_header['time']))
        finally:
            self.close_rpc(rpc_conn)
        raise ValueError('{} wallet restore height not found.'.format(self.coin_name()))

    def createBLockTx(self, Kbs, output_amount, vkbv=None) -> bytes:
        tx = CTransaction()
        tx.version = self.txVersion()
        script_pk = self.getPkDest(Kbs)
        tx.vout.append(self.txoType()(output_amount, script_pk))
        return tx.serialize()

    def publishBLockTx(self, kbv, Kbs, output_amount, feerate, unlock_time: int = 0) -> bytes:
        b_lock_tx = self.createBLockTx(Kbs, output_amount)

        b_lock_tx = self.fundTx(b_lock_tx, feerate)
        b_lock_tx_id = self.getTxid(b_lock_tx)
        b_lock_tx = self.signTxWithWallet(b_lock_tx)

        return bytes.fromhex(self.publishTx(b_lock_tx))

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        witness_bytes = 115
        size = len(tx.serialize()) + witness_bytes
        pay_fee = round(fee_rate * size / 1000)
        self._log.info(f'BLockSpendTx fee_rate, vsize, fee: {fee_rate}, {size}, {pay_fee}.')
        return pay_fee

    def spendBLockTx(self, chain_b_lock_txid: bytes, address_to: str, kbv: bytes, kbs: bytes, cb_swap_value: int, b_fee: int, restore_height: int, lock_tx_vout=None) -> bytes:
        self._log.info('spendBLockTx %s:\n', chain_b_lock_txid.hex())
        locked_n = lock_tx_vout

        Kbs = self.getPubkey(kbs)
        script_pk = self.getPkDest(Kbs)

        if locked_n is None:
            self._log.debug(f'Unknown lock vout, searching tx: {chain_b_lock_txid.hex()}')
            # When refunding a lock tx, it should be in the wallet as a sent tx
            wtx = self.rpc_wallet('gettransaction', [chain_b_lock_txid.hex(), ])
            lock_tx = self.loadTx(bytes.fromhex(wtx['hex']))
            locked_n = findOutput(lock_tx, script_pk)

        ensure(locked_n is not None, 'Output not found in tx')
        pkh_to = self.decodeAddress(address_to)

        tx = CTransaction()
        tx.version = self.txVersion()

        chain_b_lock_txid_int = b2i(chain_b_lock_txid)

        tx.vin.append(CTxIn(COutPoint(chain_b_lock_txid_int, locked_n, 0),
                            sequence=0))
        tx.vout.append(self.txoType()(cb_swap_value, self.getPubkeyHashDest(pkh_to)))

        pay_fee = self.getBLockSpendTxFee(tx, b_fee)
        tx.vout[0].value = cb_swap_value - pay_fee

        b_lock_spend_tx = tx.serialize()
        b_lock_spend_tx = self.signTxWithKey(b_lock_spend_tx, kbs)

        return bytes.fromhex(self.publishTx(b_lock_spend_tx))

    def findTxnByHash(self, txid_hex: str):
        try:
            txout = self.rpc('gettxout', [txid_hex, 0, 0, True])
        except Exception as e:
            # self._log.warning('gettxout {}'.format(e))
            return None

        confirmations: int = 0 if 'confirmations' not in txout else txout['confirmations']
        if confirmations >= self.blocks_confirmed:
            block_height = self.getChainHeight() - confirmations  # TODO: Better way?
            return {'txid': txid_hex, 'amount': 0, 'height': block_height}
        return None

    def encodeSharedAddress(self, Kbv, Kbs):
        return self.pkh_to_address(self.pkh(Kbs))

    def isTxExistsError(self, err_str: str) -> bool:
        return 'transaction already exists' in err_str or 'already have transaction' in err_str

    def isTxNonFinalError(self, err_str: str) -> bool:
        return 'locks on inputs not met' in err_str
