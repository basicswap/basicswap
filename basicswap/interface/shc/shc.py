# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.chainparams import Coins
from basicswap.interface.btc.btc import BTCInterface


class SHCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.SHC

    def max_money(self) -> int:
        # From GetBlockSubsidy (validation.cpp): 100 SHC initial subsidy halving every
        # 2,500,000 blocks (consensus.nSubsidyHalvingInterval), so the total is
        # 100 * 2,500,000 * 2 = 500,000,000 SHC.
        return 500000000 * self.COIN()

    # No other overrides needed: SHC uses standard P2PKH/P2SH/native-segwit
    # scripts exactly like BTCInterface's own defaults (confirmed - unlike
    # LTC, which adds a whole separate MWEB interface class, or DOGE, which
    # overrides getScriptDest/getScriptForPubkeyHash/encodeScriptDest for a
    # legacy-only, no-segwit setup). SHC needs neither.
