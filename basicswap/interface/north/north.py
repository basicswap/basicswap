# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.interface.btc.btc import BTCInterface
from basicswap.chainparams import Coins


class NORTHInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.NORTH

    def max_money(self) -> int:
        # MAX_MONEY in src/consensus/amount.h, there is no fixed supply cap
        return 10000000000 * self.COIN()
