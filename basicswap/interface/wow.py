#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.chainparams import WOW_COIN, Coins
from .xmr import XMRInterface


class WOWInterface(XMRInterface):

    @staticmethod
    def coin_type():
        return Coins.WOW

    @staticmethod
    def ticker_str() -> int:
        return Coins.WOW.name

    @staticmethod
    def COIN():
        return WOW_COIN

    @staticmethod
    def exp() -> int:
        return 11
