#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .contrib.test_framework.messages import (
    CTxOutPart,
)

from .interface_btc import BTCInterface
from .chainparams import CoinInterface
from .rpc import make_rpc_func


class PARTInterface(BTCInterface):
    @staticmethod
    def witnessScaleFactor():
        return 2

    @staticmethod
    def txVersion():
        return 0xa0

    def __init__(self, coin_settings):
        self.rpc_callback = make_rpc_func(coin_settings['rpcport'], coin_settings['rpcauth'])
        self.txoType = CTxOutPart

    def getNewAddress(self, use_segwit):
        return self.rpc_callback('getnewaddress', ['swap_receive'])
