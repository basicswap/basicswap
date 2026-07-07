#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 REU26 atomic-swap research.
# Distributed under the MIT software license.
#
# Zephyr (ZEPH) <-> Bitcoin Cash (BCH) adaptor-signature swap test, on regtest.
#
# Phase 2b of the Week-4 Bitcoin-family extension. It *composes* two already-working halves:
#   - the ZEPH scriptless side  -> reused wholesale from extended/test_zeph.py::Test (the joint-key
#     RingCT lock, built only via the AUDIT_FORK_HEIGHT wallet patch), and
#   - the BCH scripted side     -> the node bring-up ported from test_bch_xmr.py::TestBCH (the
#     swaplock.cash CashScript covenant + P2SH32 + OP_CHECKDATASIG VES, on BCHN v29.0.0).
#
# Because BasicSwapTest (BCH's base) and this class both descend from test_xmr.py::BaseTest, the
# five extension hooks (prepareExtraDataDir / addPIDInfo / prepareExtraCoins / addCoinSettings /
# coins_loop) chain cleanly: each override calls super() to bring up ZEPH, then adds BCH.
#
# The inherited ZEPH<->BTC/PART tests are skipped here (they are covered by test_zeph.py); this
# class only exercises ZEPH<->BCH. NOTE (4-core box): this brings up PART + BTC + ZEPH + BCH
# (BaseTest always starts BTC) plus 3 RandomX ZEPH miners -> run one test at a time with
# zephyr-testnet/scripts/nice-miners.sh up.
#
#   ZEPH_BINDIR=/home/user/REU26/work/bin pytest -v \
#       tests/basicswap/extended/test_zeph_bch.py::TestZEPH_BCH::test_11_ads_bch_coin

import logging
import os

from basicswap.basicswap import Coins
import basicswap.config as cfg
from basicswap.bin.run import startDaemon
from tests.basicswap.common import (
    callrpc_cli,
    make_rpc_func,
    prepareDataDir,
    stopDaemons,
    waitForRPC,
)
from tests.basicswap.test_xmr import callnoderpc, test_delay_event
from tests.basicswap.test_bch_xmr import (
    BITCOINCASH_BINDIR,
    BITCOINCASHD,
    BCH_BASE_PORT,
    BCH_BASE_RPC_PORT,
)
from tests.basicswap.extended.test_dcr import (
    run_test_ads_success_path,
    run_test_ads_both_refund,
)

# Import the module (not the class) so pytest does not re-collect test_zeph's Test in this file.
from tests.basicswap.extended import test_zeph as _test_zeph


class TestZEPH_BCH(_test_zeph.Test):
    __test__ = True
    # test_coin stays Coins.ZEPH (the scriptless side, inherited). Add the BCH scripted leg.
    bch_daemons = []
    bch_addr = None

    # ---- bring-up hooks: super() does the ZEPH (+ base) part, then we add BCH ---------------

    @classmethod
    def prepareExtraDataDir(cls, i):
        # ZEPH node i (daemon + wallet-rpc + wallet) via test_zeph.Test
        super(TestZEPH_BCH, cls).prepareExtraDataDir(i)

        # BCH node i (ported from test_bch_xmr.py::TestBCH.prepareExtraDataDir)
        if not cls.restore_instance:
            data_dir = prepareDataDir(
                cfg.TEST_DATADIRS,
                i,
                "bitcoin.conf",
                "bch_",
                base_p2p_port=BCH_BASE_PORT,
                base_rpc_port=BCH_BASE_RPC_PORT,
            )
            config_filename = os.path.join(
                cfg.TEST_DATADIRS, "bch_" + str(i), "bitcoin.conf"
            )
            with open(config_filename, "r") as fp:
                lines = fp.readlines()
            with open(config_filename, "w") as fp:
                for line in lines:
                    if not line.startswith("findpeers"):
                        fp.write(line)

            bch_wallet_bin = "bitcoin-wallet" + (".exe" if os.name == "nt" else "")
            if os.path.exists(os.path.join(BITCOINCASH_BINDIR, bch_wallet_bin)):
                callrpc_cli(
                    BITCOINCASH_BINDIR,
                    data_dir,
                    "regtest",
                    "-wallet=bsx_wallet create",
                    bch_wallet_bin,
                )

        cls.bch_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "bch_" + str(i)),
                BITCOINCASH_BINDIR,
                BITCOINCASHD,
            )
        )
        logging.info("BCH: Started %s %d", BITCOINCASHD, cls.bch_daemons[-1].handle.pid)
        waitForRPC(make_rpc_func(i, base_rpc_port=BCH_BASE_RPC_PORT), test_delay_event)

    @classmethod
    def addPIDInfo(cls, sc, i):
        super(TestZEPH_BCH, cls).addPIDInfo(sc, i)
        sc.setDaemonPID(Coins.BCH, cls.bch_daemons[i].handle.pid)

    @classmethod
    def prepareExtraCoins(cls):
        super(TestZEPH_BCH, cls).prepareExtraCoins()
        cls.bch_addr = callnoderpc(
            0,
            "getnewaddress",
            ["mining_addr"],
            base_rpc_port=BCH_BASE_RPC_PORT,
            wallet="bsx_wallet",
        )
        if not cls.restore_instance:
            num_blocks: int = 200
            logging.info("Mining %d BitcoinCash blocks to %s", num_blocks, cls.bch_addr)
            callnoderpc(
                0,
                "generatetoaddress",
                [num_blocks, cls.bch_addr],
                base_rpc_port=BCH_BASE_RPC_PORT,
                wallet="bsx_wallet",
            )

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        super(TestZEPH_BCH, cls).addCoinSettings(settings, datadir, node_id)
        settings["chainclients"]["bitcoincash"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": BCH_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "bch_" + str(node_id)),
            "bindir": BITCOINCASH_BINDIR,
            "use_segwit": False,
            # BCHN has no auto "wallet.dat"; prepareExtraDataDir creates+funds "bsx_wallet". See the
            # Week-4 wallet-bootstrap finding (test_bch_xmr.py / engineering log [TEST/RQ2]).
            "wallet_name": "bsx_wallet",
        }

    @classmethod
    def coins_loop(cls):
        super(TestZEPH_BCH, cls).coins_loop()
        try:
            if cls.bch_addr is not None:
                callnoderpc(
                    0,
                    "generatetoaddress",
                    [1, cls.bch_addr],
                    base_rpc_port=BCH_BASE_RPC_PORT,
                    wallet="bsx_wallet",
                )
        except Exception as e:
            logging.warning("coins_loop bch generate {}".format(e))

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Zephyr-BitcoinCash Test")
        super(TestZEPH_BCH, cls).tearDownClass()
        stopDaemons(cls.bch_daemons)
        cls.bch_daemons.clear()

    # ---- skip the inherited ZEPH<->BTC/PART tests (covered by test_zeph.py) ------------------

    def _skip_inherited(self):
        self.skipTest(
            "ZEPH<->BTC/PART are covered by test_zeph.py; this class tests ZEPH<->BCH"
        )

    test_01_ads_part_coin = _skip_inherited
    test_02_ads_coin_part = _skip_inherited
    test_03_ads_btc_coin = _skip_inherited
    test_04_ads_coin_btc = _skip_inherited
    test_05_ads_btc_coin_both_refund = _skip_inherited
    test_06_ads_coin_btc_both_refund = _skip_inherited
    test_07_ads_btc_coin_swipe_refund = _skip_inherited
    test_08_ads_coin_btc_swipe_refund = _skip_inherited

    # ---- ZEPH <-> BCH adaptor swaps ---------------------------------------------------------
    # BCH is the scripted side (swaplock.cash covenant + CSV); ZEPH the scriptless Monero-fork side.

    def test_11_ads_bch_coin(self):
        """Happy path, BCH -> ZEPH (BCH scripted side, ZEPH scriptless)."""
        run_test_ads_success_path(self, Coins.BCH, self.test_coin)

    def test_12_ads_coin_bch(self):
        """Happy path, ZEPH -> BCH (reverse bid)."""
        run_test_ads_success_path(self, self.test_coin, Coins.BCH)

    def test_13_ads_bch_coin_both_refund(self):
        """Refund path: both lock txns refund, BCH -> ZEPH.

        Exercises the BCH swaplock.cash covenant refund branch. Requires the bch.py createSCLockRefundTx
        nSequence fix (input nSequence = lock_time_1, not lock_time_2). See engineering log [TEST/RQ2].
        """
        run_test_ads_both_refund(self, Coins.BCH, self.test_coin, lock_value=20)
