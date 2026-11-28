#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/basicswap/extended/test_north.py

TrueNorth Core binaries are read from TRUENORTH_BINDIR, default
~/.basicswap/bin/truenorth.
"""

import logging
import os
import sys
import threading
import unittest

import basicswap.config as cfg
from basicswap.basicswap import (
    Coins,
)
from basicswap.bin.run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from tests.basicswap.util.common import (
    NORTH_BASE_PORT,
    NORTH_BASE_RPC_PORT,
    stopDaemons,
    waitForRPC,
    make_rpc_func,
    wait_for_no_offer,
)

from tests.basicswap.test_btc_xmr import BasicSwapTest, test_delay_event
from tests.basicswap.test_xmr import NUM_NODES
from tests.basicswap.extended.test_dcr import (
    run_test_success_path,
    run_test_bad_ptx,
    run_test_itx_refund,
)

logger = logging.getLogger("BSX Tests")

if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


TRUENORTH_BINDIR = os.path.expanduser(
    os.getenv("TRUENORTH_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "truenorth"))
)
TRUENORTHD = os.getenv("TRUENORTHD", "truenorthd" + cfg.bin_suffix)

# Blocks are RandomX hashed, one call for many of them can pass the rpc timeout
MINE_BATCH_SIZE = 20


def mineBlocks(rpc_func, num_blocks: int, addr: str) -> None:
    while num_blocks > 0:
        batch: int = min(num_blocks, MINE_BATCH_SIZE)
        rpc_func("generatetoaddress", [batch, addr])
        num_blocks -= batch


def prepareNORTHDataDir(datadir, nodeId, conf_file="truenorth.conf"):
    node_dir = os.path.join(datadir, "north_" + str(nodeId))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    filePath = os.path.join(node_dir, conf_file)

    with open(filePath, "w+") as fp:
        fp.write("regtest=1\n")
        fp.write("[regtest]\n")

        fp.write("port=" + str(NORTH_BASE_PORT + nodeId) + "\n")
        fp.write("rpcport=" + str(NORTH_BASE_RPC_PORT + nodeId) + "\n")
        salt = generate_salt(16)
        fp.write(
            "rpcauth={}:{}${}\n".format(
                "test" + str(nodeId),
                salt,
                password_to_hmac(salt, "test_pass" + str(nodeId)),
            )
        )

        fp.write("daemon=0\n")
        fp.write("printtoconsole=0\n")
        fp.write("server=1\n")
        fp.write("discover=0\n")
        fp.write("listenonion=0\n")
        fp.write("bind=127.0.0.1\n")
        fp.write("debug=1\n")
        fp.write("debugexclude=libevent\n")
        # The tests look up txns no wallet of the node holds, as on bitcoin
        fp.write("txindex=1\n")

        fp.write("fallbackfee=0.01\n")
        fp.write("acceptnonstdtxn=0\n")
        # The wallet default is P2QRH
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")

        for i in range(0, NUM_NODES):
            if nodeId == i:
                continue
            fp.write("addnode=127.0.0.1:{}\n".format(NORTH_BASE_PORT + i))


class TestNORTH(BasicSwapTest):
    __test__ = True
    test_coin = Coins.NORTH
    test_coin_from = Coins.NORTH
    north_daemons = []
    start_ltc_nodes = False
    start_xmr_nodes = True
    base_rpc_port = NORTH_BASE_RPC_PORT
    north_addr = None
    max_fee: int = 10000
    # The test thread and coins_loop both mine on node 0.  A RandomX block
    # takes long enough for their generatetoaddress calls to overlap, then
    # only one of the two blocks reaches the chain and a test can find the tx
    # it just mined unconfirmed.
    mining_lock = threading.Lock()

    def mineBlock(self, num_blocks: int = 1) -> None:
        if self.north_addr is None:
            logging.info("NORTH mining paused")
            return
        with self.mining_lock:
            mineBlocks(self.callnoderpc, num_blocks, self.north_addr)

    def getMiningAddr(self):
        return self.north_addr

    def pauseMining(self):
        logging.info(f"Pausing NORTH mining to {self.north_addr}")
        self.old_north_addr: str = self.__class__.north_addr
        self.__class__.north_addr = None

    def continueMining(self):
        logging.info(f"Resuming NORTH mining to {self.old_north_addr}")
        self.__class__.north_addr = self.old_north_addr

    def _assert_mercy_waits_for_swipe(
        self, bid_id, id_leader: int, id_follower: int, chain_a_coin
    ) -> None:
        # The inherited check pauses mining while the swipe tx is short of
        # blocks_confirmed.  A block is mined every second here, the swipe tx
        # can pass 1 before the pause, so the follower waits for 12 from here
        # to the end of the test.
        ci = self.swap_clients[id_follower].ci(chain_a_coin)
        self.addCleanup(setattr, ci, "blocks_confirmed", ci.blocks_confirmed)
        ci.blocks_confirmed = 12
        super()._assert_mercy_waits_for_swipe(
            bid_id, id_leader, id_follower, chain_a_coin
        )

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising TrueNorth Test")
        stopDaemons(cls.north_daemons)
        cls.north_daemons.clear()

        super(TestNORTH, cls).tearDownClass()

    @classmethod
    def coins_loop(cls):
        super(TestNORTH, cls).coins_loop()
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        try:
            if cls.north_addr is not None:
                with cls.mining_lock:
                    ci0.rpc_wallet("generatetoaddress", [1, cls.north_addr])
        except Exception as e:
            logging.warning(f"coins_loop generate {e}")

    @classmethod
    def prepareExtraDataDir(cls, i: int) -> None:
        if not cls.restore_instance:
            prepareNORTHDataDir(cfg.TEST_DATADIRS, i)

        cls.north_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "north_" + str(i)),
                TRUENORTH_BINDIR,
                TRUENORTHD,
            )
        )
        logging.info(
            "Started {} {}".format(TRUENORTHD, cls.north_daemons[-1].handle.pid)
        )

        north_rpc = make_rpc_func(i, base_rpc_port=NORTH_BASE_RPC_PORT)
        waitForRPC(
            north_rpc,
            test_delay_event,
            rpc_command="getnetworkinfo",
            max_tries=12,
        )
        waitForRPC(north_rpc, test_delay_event, rpc_command="getblockchaininfo")
        if len(north_rpc("listwallets")) < 1:
            # TrueNorth Core is based on Bitcoin Core v30, which has descriptor wallets only
            north_rpc(
                "createwallet",
                ["bsx_wallet", False, True, "", False, True],
            )
            north_rpc(
                "createwallet",
                ["bsx_watch", True, True, "", False, True],
            )

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemon(Coins.NORTH, cls.north_daemons[i])

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["truenorth"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": NORTH_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "north_" + str(node_id)),
            "bindir": TRUENORTH_BINDIR,
            "use_csv": True,
            "use_segwit": True,
            "blocks_confirmed": 1,
            "use_descriptors": True,
            "wallet_name": "bsx_wallet",
            "watch_wallet_name": "bsx_watch",
        }

    @classmethod
    def prepareExtraCoins(cls):
        super(TestNORTH, cls).prepareExtraCoins()
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        if not cls.restore_instance:
            for sc in cls.swap_clients:
                ci = sc.ci(cls.test_coin)
                ci.initialiseWallet(ci.getNewRandomKey())
            cls.north_addr = ci0.rpc_wallet("getnewaddress", ["mining_addr", "bech32"])
        else:
            addrs = ci0.rpc_wallet(
                "getaddressesbylabel",
                [
                    "mining_addr",
                ],
            )
            cls.north_addr = list(addrs.keys())[0]

        num_blocks: int = 500
        have_blocks: int = ci0.rpc("getblockcount")
        if have_blocks < num_blocks:
            logging.info(f"Mining {num_blocks} TrueNorth blocks to {cls.north_addr}")
            mineBlocks(ci0.rpc, num_blocks - have_blocks, cls.north_addr)
        logging.info("NORTH blocks: {}".format(ci0.rpc("getblockcount")))

    def test_002_native_segwit(self):
        # The wallet default address type is P2QRH, the node config sets bech32
        super().test_002_native_segwit()
        ci = self.swap_clients[0].ci(self.test_coin_from)
        addr = ci.rpc_wallet("getnewaddress", ["default type"])
        assert addr.startswith("rnorth1q")

    def hold_ptx_redeem(self, coin_to) -> None:
        # run_test_success_path compares the bidder's whole state history.  It
        # has "PTX Confirmed" only if the bidder sees the participate tx
        # confirmed before the offerer's redeem tx spends it, so the offerer
        # waits for more confirmations to the end of the test.
        coin_client = self.swap_clients[0].coin_clients[coin_to]
        self.addCleanup(
            coin_client.__setitem__, "blocks_confirmed", coin_client["blocks_confirmed"]
        )
        coin_client["blocks_confirmed"] += 20

    def revoke_sent_offers(self, coin_from, coin_to) -> None:
        # run_test_bad_ptx leaves an offer that accepts bids automatically, a
        # later bid plan of the same pair would take it in
        swap_clients = self.swap_clients
        filters = {
            "coin_from": int(coin_from),
            "coin_to": int(coin_to),
            "active": "active",
        }
        for offer in swap_clients[0].listOffers(sent=True, filters=filters):
            swap_clients[0].revokeOffer(offer.offer_id)
            wait_for_no_offer(test_delay_event, swap_clients[1], offer.offer_id)

    def test_02_sh_part_coin(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        self.hold_ptx_redeem(self.test_coin)
        run_test_success_path(self, Coins.PART, self.test_coin)

    def test_03_sh_coin_part(self):
        self.hold_ptx_redeem(Coins.PART)
        run_test_success_path(self, self.test_coin, Coins.PART)

    def test_04_sh_part_coin_bad_ptx(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_bad_ptx(self, Coins.PART, self.test_coin)
        self.revoke_sent_offers(Coins.PART, self.test_coin)

    def test_05_sh_coin_part_bad_ptx(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_bad_ptx(self, self.test_coin, Coins.PART)
        self.revoke_sent_offers(self.test_coin, Coins.PART)

    def test_06_sh_part_coin_itx_refund(self):
        run_test_itx_refund(self, Coins.PART, self.test_coin)

    def test_07_sh_coin_part_itx_refund(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_itx_refund(self, self.test_coin, Coins.PART)

    def test_04_a_follower_recover_b_lock_tx(self):
        # The follower must send its coin B lock tx before the coin A lock
        # refund timelock passes.  A block is mined every second here, and
        # reaching that step takes the follower about the default 32 blocks.
        self.do_test_04_follower_recover_b_lock_tx(
            self.test_coin_from, Coins.XMR, lock_value=64
        )

    def test_04_b_follower_recover_b_lock_tx_reverse(self):
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_04_follower_recover_b_lock_tx(
            Coins.XMR, self.test_coin_from, lock_value=64
        )

    def test_01_b_full_swap_reverse(self):
        self.prepare_balance(self.test_coin, 100.0, 1801, 1800)
        self.do_test_01_full_swap(Coins.XMR, self.test_coin_from)


if __name__ == "__main__":
    unittest.main()
