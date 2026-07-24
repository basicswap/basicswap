#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 REU26 atomic-swap research.
# Distributed under the MIT software license.
#
# Zephyr (ZEPH) <-> Litecoin (LTC) adaptor-signature swap test, on regtest.
#
# Phase 1 of the Week-4 Bitcoin-family extension -- the floor. LTC is a near-clone of BTC, and
# test_xmr.py::BaseTest already has built-in LTC node-start (start_ltc_nodes / ltc_daemons) and
# auto-adds the "litecoin" chainclient settings (use_segwit, wallet_name="bsx_wallet"). So unlike
# the BCH case (which needed ported bring-up hooks), this just subclasses test_zeph.py::Test (the
# ZEPH scriptless machinery), flips start_ltc_nodes=True, skips the inherited ZEPH<->BTC/PART tests,
# and adds ZEPH<->LTC ADS methods. The swap construction is identical to ZEPH<->BTC -- LTC uses
# standard P2WSH segwit; the adaptor-swap lock/refund outputs do NOT use the MWEB extension-block
# path (that is the separate Coins.LTC_MWEB).
#
# NOTE (4-core box): brings up PART + BTC + ZEPH + LTC (BaseTest always starts BTC) + 3 RandomX ZEPH
# miners -> run one test at a time with zephyr-testnet/scripts/nice-miners.sh up.
#
#   ZEPH_BINDIR=/home/user/REU26/work/bin pytest -v \
#       tests/basicswap/extended/test_zeph_ltc.py::TestZEPH_LTC::test_11_ads_ltc_coin

from basicswap.basicswap import Coins
from tests.basicswap.extended.test_dcr import (
    run_test_ads_success_path,
    run_test_ads_both_refund,
)

# Import the module (not the class) so pytest does not re-collect test_zeph's Test in this file.
from tests.basicswap.extended import test_zeph as _test_zeph


class TestZEPH_LTC(_test_zeph.Test):
    __test__ = True
    # test_coin stays Coins.ZEPH (the scriptless side, inherited). Enable BaseTest's built-in LTC
    # node-start; BaseTest also auto-adds the "litecoin" chainclient settings via with_coins.
    start_ltc_nodes = True

    # ---- skip the inherited ZEPH<->BTC/PART tests (covered by test_zeph.py) ------------------

    def _skip_inherited(self):
        self.skipTest(
            "ZEPH<->BTC/PART are covered by test_zeph.py; this class tests ZEPH<->LTC"
        )

    test_01_ads_part_coin = _skip_inherited
    test_02_ads_coin_part = _skip_inherited
    test_03_ads_btc_coin = _skip_inherited
    test_04_ads_coin_btc = _skip_inherited
    test_05_ads_btc_coin_both_refund = _skip_inherited
    test_06_ads_coin_btc_both_refund = _skip_inherited
    test_07_ads_btc_coin_swipe_refund = _skip_inherited
    test_08_ads_coin_btc_swipe_refund = _skip_inherited

    # ---- ZEPH <-> LTC adaptor swaps ---------------------------------------------------------
    # LTC is the scripted side (SWAPLOCK script + CSV, like BTC); ZEPH the scriptless Monero-fork side.

    def test_11_ads_ltc_coin(self):
        """Happy path, LTC -> ZEPH (LTC scripted side, ZEPH scriptless)."""
        run_test_ads_success_path(self, Coins.LTC, self.test_coin)

    def test_12_ads_coin_ltc(self):
        """Happy path, ZEPH -> LTC (reverse bid)."""
        run_test_ads_success_path(self, self.test_coin, Coins.LTC)

    def test_13_ads_ltc_coin_both_refund(self):
        """Refund path: both lock txns refund, LTC -> ZEPH."""
        run_test_ads_both_refund(self, Coins.LTC, self.test_coin, lock_value=20)
