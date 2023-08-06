#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins


class VEILInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.VEIL

    @staticmethod
    def txVersion() -> int:
        return 2
