#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 The BasicSwap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins
from basicswap.rpc import make_rpc_func


class DOGEInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.DOGE

    def __init__(self, coin_settings, network, swap_client=None):
        super(DOGEInterface, self).__init__(coin_settings, network, swap_client)
        # No multiwallet support
        self.rpc_wallet = make_rpc_func(
            self._rpcport, self._rpcauth, host=self._rpc_host
        )

    def initialiseWallet(self, key):
        # load with -hdseed= parameter
        pass

    def checkWallets(self) -> int:
        return 1

    def getNewAddress(self, use_segwit, label="swap_receive"):
        return self.rpc("getnewaddress", [label])

    def isWatchOnlyAddress(self, address):
        addr_info = self.rpc("validateaddress", [address])
        return addr_info["iswatchonly"]

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        addr_info = self.rpc("validateaddress", [address])
        if not or_watch_only:
            return addr_info["ismine"]
        return addr_info["ismine"] or addr_info["iswatchonly"]
