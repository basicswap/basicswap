#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Integration tests for Navio (BLSCT) swaps.

Run:
    python tests/basicswap/extended/test_nav.py
"""

import logging
import os
import random
import unittest

import basicswap.config as cfg
from basicswap.basicswap import (
    BidStates,
    Coins,
    DebugTypes,
    SwapTypes,
    TxStates,
)
from basicswap.basicswap_util import TxLockTypes
from tests.basicswap.util.common import (
    make_rpc_func,
    read_json_api,
    stopDaemons,
    wait_for_bid,
    wait_for_bid_tx_state,
    wait_for_offer,
    waitForRPC,
)
from tests.basicswap.test_xmr import BaseTest, test_delay_event, callnoderpc
from basicswap.bin.run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac

logger = logging.getLogger()

NAV_BINDIR = os.path.expanduser(
    os.getenv("NAV_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "navio"))
)
NAVIOD = os.getenv("NAVIOD", "naviod" + cfg.bin_suffix)
NAVIO_CLI = os.getenv("NAVIO_CLI", "navio-cli" + cfg.bin_suffix)

NAV_BASE_PORT = 44832
NAV_BASE_RPC_PORT = 45832


def prepareNavDataDir(
    datadir, node_id, conf_file, dir_prefix, base_p2p_port, base_rpc_port, num_nodes=3
):
    node_dir = os.path.join(datadir, dir_prefix + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return node_dir
    with open(cfg_file_path, "w+") as fp:
        fp.write("regtest=1\n")
        fp.write("port=" + str(base_p2p_port + node_id) + "\n")
        fp.write("rpcport=" + str(base_rpc_port + node_id) + "\n")
        salt = generate_salt(16)
        fp.write(
            "rpcauth={}:{}${}\n".format(
                "test" + str(node_id),
                salt,
                password_to_hmac(salt, "test_pass" + str(node_id)),
            )
        )
        fp.write("daemon=0\n")
        fp.write("printtoconsole=0\n")
        fp.write("server=1\n")
        fp.write("discover=0\n")
        fp.write("listenonion=0\n")
        fp.write("bind=127.0.0.1\n")
        fp.write("findpeers=0\n")
        fp.write("debug=1\n")
        fp.write("debugexclude=libevent\n")
        fp.write("fallbackfee=0.01\n")
        fp.write("acceptnonstdtxn=0\n")
        fp.write("dandelion=0\n")
        fp.write("ntpminmeasures=-1\n")
        fp.write("torserver=0\n")
        fp.write("suppressblsctwarning=1\n")
        fp.write("staking=0\n")
        for i in range(num_nodes):
            if node_id == i:
                continue
            fp.write("addnode=127.0.0.1:{}\n".format(base_p2p_port + i))
    return node_dir


def run_test_success_path_lock_type(
    self, coin_from: Coins, coin_to: Coins, lock_type: TxLockTypes, lock_value: int
):
    logging.info(
        f"---------- Test {coin_from.name} to {coin_to.name} lock_type={lock_type.name} lock_value={lock_value}"
    )

    node_from = 0
    node_to = 1
    swap_clients = self.swap_clients
    ci_from = swap_clients[node_from].ci(coin_from)
    ci_to = swap_clients[node_to].ci(coin_to)

    self.prepare_balance(coin_to, 100.0, 1801, 1800)
    self.prepare_balance(coin_from, 100.0, 1800, 1801)

    amt_swap = ci_from.make_int(random.uniform(0.1, 5.0), r=1)
    rate_swap = ci_to.make_int(random.uniform(0.2, 10.0), r=1)

    offer_id = swap_clients[node_from].postOffer(
        coin_from,
        coin_to,
        amt_swap,
        rate_swap,
        amt_swap,
        SwapTypes.SELLER_FIRST,
        lock_type,
        lock_value,
    )

    wait_for_offer(test_delay_event, swap_clients[node_to], offer_id)
    offer = swap_clients[node_to].getOffer(offer_id)
    bid_id = swap_clients[node_to].postBid(offer_id, offer.amount_from)

    wait_for_bid(test_delay_event, swap_clients[node_from], bid_id)
    swap_clients[node_from].acceptBid(bid_id)

    wait_for_bid(
        test_delay_event,
        swap_clients[node_from],
        bid_id,
        BidStates.SWAP_COMPLETED,
        wait_for=300,
    )
    wait_for_bid(
        test_delay_event,
        swap_clients[node_to],
        bid_id,
        BidStates.SWAP_COMPLETED,
        sent=True,
        wait_for=60,
    )

    js_0 = read_json_api(1800 + node_from)
    js_1 = read_json_api(1800 + node_to)
    assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
    assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0


def run_test_success_path(self, coin_from: Coins, coin_to: Coins):
    run_test_success_path_lock_type(
        self,
        coin_from,
        coin_to,
        TxLockTypes.SEQUENCE_LOCK_TIME,
        48 * 60 * 60,
    )


def run_test_bad_ptx(self, coin_from: Coins, coin_to: Coins):
    logging.info(f"---------- Test bad ptx {coin_from.name} to {coin_to.name}")

    node_from = 0
    node_to = 1
    swap_clients = self.swap_clients
    ci_from = swap_clients[node_from].ci(coin_from)
    ci_to = swap_clients[node_to].ci(coin_to)

    self.prepare_balance(coin_to, 100.0, 1801, 1800)
    self.prepare_balance(coin_from, 100.0, 1800, 1801)

    amt_swap = ci_from.make_int(random.uniform(1.1, 10.0), r=1)
    rate_swap = ci_to.make_int(random.uniform(0.1, 2.0), r=1)

    offer_id = swap_clients[node_from].postOffer(
        coin_from,
        coin_to,
        amt_swap,
        rate_swap,
        amt_swap,
        SwapTypes.SELLER_FIRST,
        TxLockTypes.SEQUENCE_LOCK_BLOCKS,
        10,
        auto_accept_bids=True,
    )

    wait_for_offer(test_delay_event, swap_clients[node_to], offer_id)
    offer = swap_clients[node_to].getOffer(offer_id)
    bid_id = swap_clients[node_to].postBid(offer_id, offer.amount_from)
    swap_clients[node_to].setBidDebugInd(bid_id, DebugTypes.MAKE_INVALID_PTX)

    wait_for_bid(
        test_delay_event,
        swap_clients[node_from],
        bid_id,
        BidStates.SWAP_COMPLETED,
        wait_for=300,
    )
    wait_for_bid(
        test_delay_event,
        swap_clients[node_to],
        bid_id,
        BidStates.SWAP_COMPLETED,
        sent=True,
        wait_for=60,
    )

    js_0_bid = read_json_api(1800 + node_from, "bids/{}".format(bid_id.hex()))
    js_1_bid = read_json_api(1800 + node_to, "bids/{}".format(bid_id.hex()))
    assert js_0_bid["itx_state"] == "Refunded"
    assert js_1_bid["ptx_state"] == "Refunded"

    js_0 = read_json_api(1800 + node_from)
    js_1 = read_json_api(1800 + node_to)
    assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
    assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0


def run_test_itx_refund(self, coin_from: Coins, coin_to: Coins):
    logging.info(f"---------- Test itx refund {coin_from.name} to {coin_to.name}")

    node_from = 0
    node_to = 1
    swap_clients = self.swap_clients

    self.prepare_balance(coin_to, 100.0, 1801, 1800)
    self.prepare_balance(coin_from, 100.0, 1800, 1801)

    ci_from = swap_clients[node_from].ci(coin_from)
    ci_to = swap_clients[node_to].ci(coin_to)

    swap_value = ci_from.make_int(random.uniform(2.0, 20.0), r=1)
    rate_swap = ci_to.make_int(0.5, r=1)

    offer_id = swap_clients[node_from].postOffer(
        coin_from,
        coin_to,
        swap_value,
        rate_swap,
        swap_value,
        SwapTypes.SELLER_FIRST,
        TxLockTypes.SEQUENCE_LOCK_BLOCKS,
        12,
    )

    wait_for_offer(test_delay_event, swap_clients[node_to], offer_id)
    offer = swap_clients[node_to].getOffer(offer_id)
    bid_id = swap_clients[node_to].postBid(offer_id, offer.amount_from)
    swap_clients[node_to].setBidDebugInd(bid_id, DebugTypes.DONT_SPEND_ITX)

    wait_for_bid(test_delay_event, swap_clients[node_from], bid_id)

    # Delay ITX refund until after PTX is redeemed to avoid timing issues
    swap_clients[node_from].setBidDebugInd(bid_id, DebugTypes.SKIP_LOCK_TX_REFUND)
    swap_clients[node_from].acceptBid(bid_id)

    wait_for_bid_tx_state(
        test_delay_event,
        swap_clients[node_from],
        bid_id,
        TxStates.TX_CONFIRMED,
        TxStates.TX_REDEEMED,
        wait_for=240,
    )
    swap_clients[node_from].setBidDebugInd(bid_id, DebugTypes.NONE)

    wait_for_bid_tx_state(
        test_delay_event,
        swap_clients[node_from],
        bid_id,
        TxStates.TX_REFUNDED,
        TxStates.TX_REDEEMED,
        wait_for=120,
    )

    wait_for_bid(
        test_delay_event,
        swap_clients[0],
        bid_id,
        BidStates.SWAP_COMPLETED,
        wait_for=60,
    )


class Test(BaseTest):
    __test__ = True
    test_coin = Coins.NAV
    nav_daemons = []
    nav_addr = None
    start_ltc_nodes = False
    start_xmr_nodes = False
    extra_wait_time = 0
    max_fee: int = 50000

    @classmethod
    def prepareExtraDataDir(cls, i):
        if not cls.restore_instance:
            prepareNavDataDir(
                cfg.TEST_DATADIRS,
                i,
                "navio.conf",
                "nav_",
                base_p2p_port=NAV_BASE_PORT,
                base_rpc_port=NAV_BASE_RPC_PORT,
            )
        cls.nav_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "nav_" + str(i)),
                NAV_BINDIR,
                NAVIOD,
            )
        )
        logging.info("Started %s %d", NAVIOD, cls.nav_daemons[-1].handle.pid)
        waitForRPC(
            make_rpc_func(i, base_rpc_port=NAV_BASE_RPC_PORT),
            test_delay_event,
            max_tries=12,
        )

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.NAV, cls.nav_daemons[i].handle.pid)

    @classmethod
    def prepareExtraCoins(cls):
        if cls.restore_instance:
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.nav_addr = (
                cls.swap_clients[0]
                .ci(Coins.NAV)
                .pubkey_to_address(void_block_rewards_pubkey)
            )
        else:
            num_blocks = 400
            cls.nav_addr = callnoderpc(
                0, "getnewaddress", ["mining_addr"], base_rpc_port=NAV_BASE_RPC_PORT
            )
            logging.info("Mining %d NAV blocks to %s", num_blocks, cls.nav_addr)
            callnoderpc(
                0,
                "generatetoaddress",
                [num_blocks, cls.nav_addr],
                base_rpc_port=NAV_BASE_RPC_PORT,
            )

            # Fund both nodes' BLSCT wallets; initialiseWallet has run at this point
            nav_blsct_addr0 = (
                cls.swap_clients[0].ci(Coins.NAV).getNewAddress(True, "initial addr")
            )
            nav_blsct_addr1 = (
                cls.swap_clients[1].ci(Coins.NAV).getNewAddress(True, "initial addr")
            )
            for _ in range(5):
                callnoderpc(
                    0,
                    "sendtoaddress",
                    [nav_blsct_addr0, 1000],
                    base_rpc_port=NAV_BASE_RPC_PORT,
                )
                callnoderpc(
                    0,
                    "sendtoaddress",
                    [nav_blsct_addr1, 1000],
                    base_rpc_port=NAV_BASE_RPC_PORT,
                )

            # Confirm the sends
            callnoderpc(
                0,
                "generatetoaddress",
                [10, cls.nav_addr],
                base_rpc_port=NAV_BASE_RPC_PORT,
            )

            # Switch mining to a void address so wallet amounts stay constant
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.nav_addr = (
                cls.swap_clients[0]
                .ci(Coins.NAV)
                .pubkey_to_address(void_block_rewards_pubkey)
            )
            num_blocks = 100
            logging.info("Mining %d NAV blocks to %s", num_blocks, cls.nav_addr)
            callnoderpc(
                0,
                "generatetoaddress",
                [num_blocks, cls.nav_addr],
                base_rpc_port=NAV_BASE_RPC_PORT,
            )

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Navio Test")
        super(Test, cls).tearDownClass()
        stopDaemons(cls.nav_daemons)
        cls.nav_daemons.clear()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["navio"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": NAV_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "nav_" + str(node_id)),
            "bindir": NAV_BINDIR,
            "use_csv": False,
            "use_segwit": False,
            "blocks_confirmed": 1,
        }

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()
        callnoderpc(
            0,
            "generatetoaddress",
            [1, cls.nav_addr],
            base_rpc_port=NAV_BASE_RPC_PORT,
        )

    def callnoderpc(self, method, params=[], wallet=None, node_id=0):
        return callnoderpc(
            node_id, method, params, wallet, base_rpc_port=NAV_BASE_RPC_PORT
        )

    def mineBlock(self, num_blocks: int = 1):
        self.callnoderpc("generatetoaddress", [num_blocks, self.nav_addr])

    def test_001_navio_wallet(self):
        logging.info("---------- Test navio wallet")
        ci0 = self.swap_clients[0].ci(Coins.NAV)
        blsct_addr = ci0.getNewAddress(True, "test_addr")
        assert len(blsct_addr) > 10
        wallet_info = ci0.getWalletInfo()
        assert "balance" in wallet_info
        assert wallet_info["balance"] >= 0.0

    def test_02_part_nav(self):
        run_test_success_path(self, Coins.PART, Coins.NAV)

    def test_03_nav_part(self):
        run_test_success_path(self, Coins.NAV, Coins.PART)

    def test_04_part_nav_bad_ptx(self):
        run_test_bad_ptx(self, Coins.PART, Coins.NAV)

    def test_05_nav_part_bad_ptx(self):
        run_test_bad_ptx(self, Coins.NAV, Coins.PART)

    def test_06_part_nav_itx_refund(self):
        run_test_itx_refund(self, Coins.PART, Coins.NAV)

    def test_07_nav_part_itx_refund(self):
        run_test_itx_refund(self, Coins.NAV, Coins.PART)

    def test_08_part_nav_sequence_lock_blocks(self):
        run_test_success_path_lock_type(
            self, Coins.PART, Coins.NAV, TxLockTypes.SEQUENCE_LOCK_BLOCKS, 10
        )

    def test_09_nav_part_sequence_lock_time(self):
        run_test_success_path_lock_type(
            self, Coins.NAV, Coins.PART, TxLockTypes.SEQUENCE_LOCK_TIME, 48 * 60 * 60
        )

    def test_10_part_nav_abs_lock_blocks(self):
        run_test_success_path_lock_type(
            self, Coins.PART, Coins.NAV, TxLockTypes.ABS_LOCK_BLOCKS, 10
        )

    def test_11_nav_part_abs_lock_time(self):
        run_test_success_path_lock_type(
            self, Coins.NAV, Coins.PART, TxLockTypes.ABS_LOCK_TIME, 48 * 60 * 60
        )


if __name__ == "__main__":
    unittest.main()
