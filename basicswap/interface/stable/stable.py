# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Stable coin interface (native currency USDT0).

A second EVM coin proving the EVM_XMR_SWAP layer is chain-agnostic: all
behaviour lives in the shared EVMInterface base; this subclass supplies
Stable's identity and its swap design. USDT0 can be frozen per address, so
each swap escrows at its own address (SwapFactory).
"""

from basicswap.chainparams import Coins
from basicswap.interface.stable.chainparams import STABLE_COIN
from basicswap.interface.evm.base import EVMInterface
from basicswap.interface.evm.swapfactory import SwapFactory


class STABLEInterface(EVMInterface):
    SWAP_CONTRACT = SwapFactory
    # Stable charges a tip but has no use for one
    PRIORITY_FEE = 0

    @staticmethod
    def coin_type():
        return Coins.STABLE

    @staticmethod
    def ticker_str() -> str:
        return Coins.STABLE.name

    @staticmethod
    def COIN():
        return STABLE_COIN
