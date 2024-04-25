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
from basicswap.interface.dcr.rpc import make_rpc_func
from .messages import CTransaction


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

    def loadTx(self, tx_bytes: bytes) -> CTransaction:
        tx = CTransaction()
        tx.deserialize(tx_bytes)
        return tx
