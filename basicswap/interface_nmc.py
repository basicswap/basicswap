#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .interface_btc import BTCInterface
from .chainparams import Coins


class NMCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.NMC

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, find_index=False):
        raise ValueError('TODO: Use scantxoutset')
