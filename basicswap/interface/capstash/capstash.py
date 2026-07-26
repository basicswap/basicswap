# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.chainparams import Coins
from basicswap.interface.btc.btc import BTCInterface


class CapStashInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.CAPS

    def getWalletAccountPath(self) -> str:
        if self._network == "mainnet":
            raise ValueError(
                "CapStash mainnet descriptor wallet initialisation is disabled "
                "until an authoritative SLIP-0044 coin type is published."
            )
        return super().getWalletAccountPath()
