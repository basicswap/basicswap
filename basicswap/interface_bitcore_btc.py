#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .interface_btc import BTCInterface
from .contrib.test_framework.messages import (
    CTxOut)


class BitcoreBTCInterface(BTCInterface):
    def __init__(self, coin_settings, network):
        super().__init__(coin_settings, network)
        self.txoType = CTxOut
        self._network = network
        self.blocks_confirmed = coin_settings['blocks_confirmed']
        self.setConfTarget(coin_settings['conf_target'])
