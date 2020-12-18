#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .interface_btc import BTCInterface
from .chainparams import Coins


class LTCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.LTC
