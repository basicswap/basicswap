# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Ethereum coin interface.

ETH is the first EVM-native-currency coin; all behaviour lives in the
chain-agnostic EVMInterface base.  This subclass only supplies ETH's identity.
"""

from basicswap.chainparams import Coins
from basicswap.interface.eth.chainparams import ETH_COIN
from basicswap.interface.evm.base import EVMInterface


class ETHInterface(EVMInterface):
    MAX_FEE_PER_GAS = 5 * 10**9

    @staticmethod
    def coin_type():
        return Coins.ETH

    @staticmethod
    def ticker_str() -> str:
        return Coins.ETH.name

    @staticmethod
    def COIN():
        return ETH_COIN
