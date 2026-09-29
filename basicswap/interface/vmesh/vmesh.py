# -*- coding: utf-8 -*-

# VargaMesh integration for BasicSwap

from basicswap.interface.btc.btc import BTCInterface
from basicswap.chainparams import Coins


class VMESHInterface(BTCInterface):

    @staticmethod
    def coin_type():
        return Coins.VMESH

    def max_money(self) -> int:
        # VMESH:
        # 25 VMESH initial subsidy
        # halving every 1,051,200 blocks
        # geometric upper bound = 52,560,000 VMESH
        return 52_560_000 * self.COIN()
