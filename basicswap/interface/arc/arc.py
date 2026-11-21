# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Arc coin interface (native currency USDC). USDC can be frozen per address, so
each swap escrows at its own address (SwapFactory).
"""

from basicswap.chainparams import Coins
from basicswap.interface.arc.chainparams import ARC_COIN
from basicswap.interface.evm.base import EVMInterface
from basicswap.interface.evm.swapfactory import SwapFactory


class ARCInterface(EVMInterface):
    SWAP_CONTRACT = SwapFactory

    @staticmethod
    def coin_type():
        return Coins.ARC

    @staticmethod
    def ticker_str() -> str:
        return Coins.ARC.name

    @staticmethod
    def COIN():
        return ARC_COIN
