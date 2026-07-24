#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 REU26 atomic-swap research.
# Distributed under the MIT software license.
#
# Zephyr (ZEPH) adaptor-signature swap test, on regtest. Modeled on the Wownero test
# (extended/test_wow.py) since both are Monero forks. The wallet's daemon RPC is routed through
# rct_distribution_proxy so a STOCK zephyr-wallet-rpc can build RingCT on the short regtest chain
# (see README-ZEPH.md). Set ZEPH_BINDIR to the dir holding zephyrd + zephyr-wallet-rpc.
#
#   ZEPH_BINDIR=/path/to/zephyr/bin pytest -v -s \
#       tests/basicswap/extended/test_zeph.py::Test::test_01_ads_part_coin

import time
import logging
import os

from basicswap.basicswap import (
    Coins,
)
import basicswap.config as cfg
from basicswap.rpc_xmr import (
    callrpc_xmr,
)
from tests.basicswap.common import (
    stopDaemons,
)
from tests.basicswap.test_xmr import BaseTest
from basicswap.bin.run import startXmrDaemon, startXmrWalletDaemon
from tests.basicswap.rct_distribution_proxy import start_rct_distribution_proxy

from tests.basicswap.extended.test_dcr import (
    run_test_ads_success_path,
    run_test_ads_both_refund,
    run_test_ads_swipe_refund,
)

NUM_NODES = 3

ZEPH_BINDIR = os.path.expanduser(os.getenv("ZEPH_BINDIR", "~/.basicswap/bin/zephyr"))
ZEPHD = os.getenv("ZEPHD", "zephyrd" + cfg.bin_suffix)
ZEPH_WALLET_RPC = os.getenv("ZEPH_WALLET", "zephyr-wallet-rpc" + cfg.bin_suffix)

ZEPH_BASE_PORT = 56932
ZEPH_BASE_RPC_PORT = 57932
ZEPH_BASE_WALLET_RPC_PORT = 57952
ZEPH_BASE_ZMQ_PORT = 57972
ZEPH_PROXY_BASE_PORT = (
    57992  # rct-distribution proxy: wallet -> proxy -> zephyrd (test-only)
)


def prepareZEPHDataDir(datadir, node_id, conf_file):
    node_dir = os.path.join(datadir, "zeph_" + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, "w+") as fp:
        fp.write("regtest=1\n")
        fp.write("log-level=1\n")
        fp.write("keep-fakechain=1\n")
        fp.write("data-dir={}\n".format(node_dir))
        fp.write("fixed-difficulty=1\n")
        fp.write("p2p-bind-port={}\n".format(ZEPH_BASE_PORT + node_id))
        fp.write("rpc-bind-port={}\n".format(ZEPH_BASE_RPC_PORT + node_id))
        fp.write("p2p-bind-ip=127.0.0.1\n")
        fp.write("rpc-bind-ip=127.0.0.1\n")
        fp.write("prune-blockchain=1\n")
        fp.write("zmq-rpc-bind-port={}\n".format(ZEPH_BASE_ZMQ_PORT + node_id))
        fp.write("zmq-rpc-bind-ip=127.0.0.1\n")

        for i in range(0, NUM_NODES):
            if node_id == i:
                continue
            fp.write("add-exclusive-node=127.0.0.1:{}\n".format(ZEPH_BASE_PORT + i))


def waitForZEPHNode(rpc_offset, max_tries=15, auth=None):
    # 4-core box: 3 zephyrd + 3 bitcoind + 3 particld all start at once, so the ZEPH daemon can
    # take well over the old ~28s (7 tries) to become RPC-ready. 15 tries ≈ 120s of backoff gives
    # enough slack for setUpClass to not spuriously fail with "waitForZEPHNode failed".
    for i in range(max_tries + 1):
        try:
            if auth is None:
                callrpc_xmr(ZEPH_BASE_RPC_PORT + rpc_offset, "get_block_count")
            else:
                callrpc_xmr(
                    ZEPH_BASE_WALLET_RPC_PORT + rpc_offset, "get_languages", auth=auth
                )
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning(
                    "Can't connect to ZEPH%s RPC: %s. Retrying in %d second/s.",
                    "" if auth is None else " wallet",
                    str(ex),
                    (i + 1),
                )
                time.sleep(i + 1)
    raise ValueError("waitForZEPHNode failed")


class Test(BaseTest):
    __test__ = True
    test_coin = Coins.ZEPH
    zeph_daemons = []
    zeph_proxies = []
    zeph_wallet_auth = []
    start_ltc_nodes = False
    start_xmr_nodes = False
    zeph_addr = None
    # Extra slack (seconds) added to the refund-path wait_for_bid timeouts. The 4-core box mines
    # 3× RandomX nodes (reniced) so coordination/refund steps run slower than on a fast host.
    extra_wait_time = 60
    # Fee tolerance (atomic units) for the post-swap amount checks on the *scripted* counterparty
    # (e.g. BTC in ZEPH<->BTC). The ZEPH side is skipped by the Monero-family gate; this is only
    # compared against BTC sats. Matches the DCR test class. Without it the BTC-side verify raises
    # AttributeError after an otherwise-completed swap.
    max_fee: int = 10000

    @classmethod
    def prepareExtraCoins(cls):
        # Zephyr regtest RandomX mining is ~2s/block, so 300 blocks in one generateblocks
        # call exceeds the RPC timeout. Mine in small batches. [RQ2 adaptation finding]
        num_blocks = 150
        cls.zeph_addr = cls.callzephnodewallet(cls, 1, "get_address")["address"]
        have = callrpc_xmr(ZEPH_BASE_RPC_PORT + 1, "get_block_count")["count"]
        if have < num_blocks:
            logging.info(
                "Mining %d Zephyr blocks to %s (batched).", num_blocks, cls.zeph_addr
            )
            while have < num_blocks:
                batch = min(25, num_blocks - have)
                callrpc_xmr(
                    ZEPH_BASE_RPC_PORT + 1,
                    "generateblocks",
                    {"wallet_address": cls.zeph_addr, "amount_of_blocks": batch},
                    timeout=300,
                )
                have = callrpc_xmr(ZEPH_BASE_RPC_PORT + 1, "get_block_count")["count"]
        logging.info("ZEPH blocks: %d", have)

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Zephyr Test")
        super(Test, cls).tearDownClass()
        stopDaemons(cls.zeph_daemons)
        cls.zeph_daemons.clear()
        for proxy in cls.zeph_proxies:
            proxy.shutdown()
        cls.zeph_proxies.clear()

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()
        if cls.zeph_addr is not None:
            callrpc_xmr(
                ZEPH_BASE_RPC_PORT + 0,
                "generateblocks",
                {"wallet_address": cls.zeph_addr, "amount_of_blocks": 1},
            )

    @classmethod
    def prepareExtraDataDir(cls, i):
        if not cls.restore_instance:
            prepareZEPHDataDir(cfg.TEST_DATADIRS, i, "monerod.conf")

        node_dir = os.path.join(cfg.TEST_DATADIRS, "zeph_" + str(i))
        cls.zeph_daemons.append(startXmrDaemon(node_dir, ZEPH_BINDIR, ZEPHD))
        logging.info("Started %s %d", ZEPHD, cls.zeph_daemons[-1].handle.pid)
        waitForZEPHNode(i)

        # Route the wallet's daemon RPC through a proxy that rewrites the RingCT
        # get_output_distribution request's from_height to 0, so the STOCK zephyr-wallet-rpc can
        # build RingCT on the short regtest chain (the mainnet AUDIT_FORK_HEIGHT=481500 floor would
        # otherwise be past the chain tip). A strict mainnet no-op; test-only. See README-ZEPH.md.
        cls.zeph_proxies.append(
            start_rct_distribution_proxy(
                ZEPH_PROXY_BASE_PORT + i, ZEPH_BASE_RPC_PORT + i
            )
        )

        opts = [
            "--daemon-address=127.0.0.1:{}".format(ZEPH_PROXY_BASE_PORT + i),
            "--no-dns",
            "--rpc-bind-port={}".format(ZEPH_BASE_WALLET_RPC_PORT + i),
            "--wallet-dir={}".format(os.path.join(node_dir, "wallets")),
            "--log-file={}".format(os.path.join(node_dir, "wallet.log")),
            "--rpc-login=test{0}:test_pass{0}".format(i),
            "--shared-ringdb-dir={}".format(os.path.join(node_dir, "shared-ringdb")),
            "--allow-mismatched-daemon-version",
        ]
        cls.zeph_daemons.append(
            startXmrWalletDaemon(node_dir, ZEPH_BINDIR, ZEPH_WALLET_RPC, opts=opts)
        )

        cls.zeph_wallet_auth.append(("test{0}".format(i), "test_pass{0}".format(i)))
        waitForZEPHNode(i, auth=cls.zeph_wallet_auth[i])

        if not cls.restore_instance:
            logging.info("Creating ZEPH wallet %i", i)
            cls.callzephnodewallet(
                cls,
                i,
                "create_wallet",
                {"filename": "testwallet", "language": "English"},
            )
        else:
            cls.callzephnodewallet(cls, i, "open_wallet", {"filename": "testwallet"})

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.ZEPH, cls.zeph_daemons[i].handle.pid)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["zephyr"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": ZEPH_BASE_RPC_PORT + node_id,
            "walletrpcport": ZEPH_BASE_WALLET_RPC_PORT + node_id,
            "walletrpcuser": "test" + str(node_id),
            "walletrpcpassword": "test_pass" + str(node_id),
            "wallet_name": "testwallet",
            "datadir": os.path.join(datadir, "zeph_" + str(node_id)),
            "bindir": ZEPH_BINDIR,
        }

    def callzephnodewallet(self, node_id, method, params=None):
        return callrpc_xmr(
            ZEPH_BASE_WALLET_RPC_PORT + node_id,
            method,
            params,
            auth=self.zeph_wallet_auth[node_id],
        )

    def test_01_ads_part_coin(self):
        """Happy path, PART -> ZEPH (PART scripted side, ZEPH scriptless)."""
        run_test_ads_success_path(self, Coins.PART, self.test_coin)

    def test_02_ads_coin_part(self):
        """Happy path, ZEPH -> PART (reverse bid)."""
        run_test_ads_success_path(self, self.test_coin, Coins.PART)

    # --- ZEPH <-> BTC: the Week-3 headline deliverable -----------------------------------------
    # BTC is the scripted side (SWAPLOCK script + CSV timelock); ZEPH the scriptless Monero-fork
    # side. Structurally identical to the BTC<->XMR baseline, with ZEPH in place of XMR.

    def test_03_ads_btc_coin(self):
        """Happy path, BTC -> ZEPH (BTC scripted side, ZEPH scriptless) -- Week-3 headline."""
        run_test_ads_success_path(self, Coins.BTC, self.test_coin)

    def test_04_ads_coin_btc(self):
        """Happy path, ZEPH -> BTC (reverse bid)."""
        run_test_ads_success_path(self, self.test_coin, Coins.BTC)

    # --- ZEPH <-> BTC refund paths (counterparty drops mid-protocol) ---------------------------
    # both_refund: both lock txns refund. swipe_refund: leader swipes after the second timelock.

    def test_05_ads_btc_coin_both_refund(self):
        """Refund path: both lock txns refund, BTC -> ZEPH."""
        run_test_ads_both_refund(self, Coins.BTC, self.test_coin, lock_value=20)

    def test_06_ads_coin_btc_both_refund(self):
        """Refund path: both lock txns refund, ZEPH -> BTC (reverse bid)."""
        run_test_ads_both_refund(self, self.test_coin, Coins.BTC, lock_value=20)

    def test_07_ads_btc_coin_swipe_refund(self):
        """Refund path: leader swipes after the 2nd timelock, BTC -> ZEPH."""
        run_test_ads_swipe_refund(self, Coins.BTC, self.test_coin, lock_value=20)

    def test_08_ads_coin_btc_swipe_refund(self):
        """Refund path: leader swipes after the 2nd timelock, ZEPH -> BTC (reverse bid)."""
        run_test_ads_swipe_refund(self, self.test_coin, Coins.BTC, lock_value=20)
