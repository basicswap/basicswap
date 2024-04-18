#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.chainparams import Coins
from basicswap.interface.btc import Secp256k1Interface
from basicswap.util.address import (
    b58decode,
    b58encode,
)
from basicswap.util.crypto import (
    blake256,
    ripemd160,
)
from basicswap.interface.dcr.rpc import make_rpc_func


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
        self.rpc = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host)

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
            self.rpc_wallet('getwalletinfo')
        else:
            self.rpc('getblockchaininfo')
