#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .contrib.test_framework.messages import (
    CTxOutPart,
)

from .interface_btc import BTCInterface
from .chainparams import Coins
from .rpc import make_rpc_func


class PARTInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.PART

    @staticmethod
    def witnessScaleFactor():
        return 2

    @staticmethod
    def txVersion():
        return 0xa0

    def __init__(self, coin_settings, network):
        self.rpc_callback = make_rpc_func(coin_settings['rpcport'], coin_settings['rpcauth'])
        self.txoType = CTxOutPart
        self._network = network
        self.blocks_confirmed = coin_settings['blocks_confirmed']

    def getNewAddress(self, use_segwit):
        return self.rpc_callback('getnewaddress', ['swap_receive'])

    def haveSpentIndex(self):
        version = self.getDaemonVersion()
        index_info = self.rpc_callback('getinsightinfo' if int(str(version)[:2]) > 19 else 'getindexinfo')
        return index_info['spentindex']

    def initialiseWallet(self, key):
        raise ValueError('TODO')
