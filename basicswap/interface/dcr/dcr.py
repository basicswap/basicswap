#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging

from basicswap.chainparams import Coins
from basicswap.interface.btc import Secp256k1Interface
from basicswap.util.address import (
    b58decode,
    b58encode,
)
from basicswap.util.crypto import (
    blake256,
    hash160,
    ripemd160,
)
from basicswap.util.extkey import ExtKeyPair
from basicswap.util.integer import encode_varint
from basicswap.interface.dcr.rpc import make_rpc_func
from .messages import CTransaction, CTxOut, SigHashType, TxSerializeType
from .script import push_script_data, OP_HASH160, OP_EQUAL, OP_DUP, OP_EQUALVERIFY, OP_CHECKSIG

from coincurve.keys import (
    PrivateKey
)


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

        self._use_segwit = coin_settings['use_segwit']

    def pkh(self, pubkey: bytes) -> bytes:
        return ripemd160(blake256(pubkey))

    def pkh_to_address(self, pkh: bytes) -> str:
        prefix = self.chainparams_network()['pubkey_address']

        data = prefix.to_bytes(2, 'big') + pkh
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
        rv = self.rpc_wallet('getinfo')
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

    def getScriptDest(self, script: bytes) -> bytes:
        # P2SH
        script_hash = self.pkh(script)
        assert len(script_hash) == 20

        return OP_HASH160.to_bytes(1) + len(script_hash).to_bytes(1) + script_hash + OP_EQUAL.to_bytes(1)

    def getPubkeyHashDest(self, pkh: bytes) -> bytes:
        # P2PKH

        assert len(pkh) == 20
        return OP_DUP.to_bytes(1) + OP_HASH160.to_bytes(1) + len(pkh).to_bytes(1) + pkh + OP_EQUALVERIFY.to_bytes(1) + OP_CHECKSIG.to_bytes(1)
