# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""validateSwapType's pair restriction for EVM_XMR_SWAP; needs no anvil or node."""

import unittest

from basicswap.chainparams import Coins
from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import SwapTypes


class _StubSwapClient:
    """Minimal stand-in exposing the attributes validateSwapType touches."""

    balance_only_coins = (Coins.LTC_MWEB,)
    evm_contract_coins = (Coins.ETH,)
    scriptless_coins = (Coins.XMR, Coins.WOW)
    adaptor_swap_only_coins = (Coins.XMR, Coins.WOW, Coins.BCH)
    coins_without_segwit = (Coins.PIVX, Coins.DASH)
    settings = {}
    chain = "regtest"

    is_reverse_ads_bid = BasicSwap.is_reverse_ads_bid


class ValidateSwapTypeTest(unittest.TestCase):
    def setUp(self):
        self.c = _StubSwapClient()

    def _validate(self, coin_from, coin_to, swap_type):
        return BasicSwap.validateSwapType(self.c, coin_from, coin_to, swap_type)

    def test_accepts_evm_xmr_both_directions(self):
        # Should not raise.
        self._validate(Coins.ETH, Coins.XMR, SwapTypes.EVM_XMR_SWAP)
        self._validate(Coins.XMR, Coins.ETH, SwapTypes.EVM_XMR_SWAP)

    def test_rejects_eth_btc(self):
        with self.assertRaises(ValueError):
            self._validate(Coins.ETH, Coins.BTC, SwapTypes.EVM_XMR_SWAP)
        with self.assertRaises(ValueError):
            self._validate(Coins.BTC, Coins.ETH, SwapTypes.EVM_XMR_SWAP)

    def test_rejects_eth_under_other_swap_types(self):
        # ETH may only be swapped via EVM_XMR_SWAP.
        with self.assertRaises(ValueError):
            self._validate(Coins.ETH, Coins.XMR, SwapTypes.XMR_SWAP)
        with self.assertRaises(ValueError):
            self._validate(Coins.ETH, Coins.BTC, SwapTypes.SELLER_FIRST)


if __name__ == "__main__":
    unittest.main()
