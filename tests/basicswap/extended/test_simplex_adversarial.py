#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Adversarial and transport-loss regtest swaps over SimpleX (3 nodes, SimpleX only).

Requires SimpleX SMP server and simplex-chat binary (see test_simplex.py).

Reuses the recovery scenarios from test_btc_xmr.TestFunctions with every
node on SimpleX, then kills a node's simplex-chat client mid-swap.

export PYTHONPATH=$(pwd)
pytest -v -s tests/basicswap/extended/test_simplex_adversarial.py
"""

import logging
import os
import random
import signal
import sys

import basicswap.config as cfg

from basicswap.basicswap import (
    BidStates,
    SwapTypes,
)
from basicswap.chainparams import Coins
from basicswap.network.simplex_chat import startSimplexClient

from tests.basicswap.extended.test_simplex import (
    SIMPLEX_CLIENT_PATH,
    SIMPLEX_SERVER_ADDRESS,
    TestSimplex2,
)
from tests.basicswap.test_btc_xmr import BTC_BASE_RPC_PORT, TestFunctions
from tests.basicswap.test_xmr import test_delay_event
from tests.basicswap.util.common import (
    wait_for_bid,
    wait_for_offer,
)

TEST_DIR = cfg.TEST_DATADIRS

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class TestSimplexAdversarial(TestSimplex2, TestFunctions):
    __test__ = True
    base_rpc_port = BTC_BASE_RPC_PORT
    extra_wait_time = 60

    def simplexThread(self, node_id: int):
        for network in self.swap_clients[node_id].active_networks:
            if network["type"] == "simplex":
                return network["ws_thread"]
        raise ValueError("No active SimpleX network")

    def restartSimplexClient(self, node_id: int) -> None:
        daemon = self.daemons[node_id]
        logger.info(f"Killing simplex-chat of node {node_id}, pid {daemon.handle.pid}")
        daemon.handle.send_signal(signal.SIGKILL)
        daemon.handle.wait(timeout=20)
        for fp in daemon.files:
            fp.close()

        for _ in range(30):
            if not self.simplexThread(node_id).connected:
                break
            test_delay_event.wait(1)
        else:
            raise ValueError("SimpleX websocket did not notice the client exit")

        test_delay_event.wait(5)
        client_dir = os.path.join(TEST_DIR, f"simplex_client{node_id}")
        self.daemons[node_id] = startSimplexClient(
            SIMPLEX_CLIENT_PATH,
            client_dir,
            SIMPLEX_SERVER_ADDRESS,
            5225 + node_id,
            logger,
            test_delay_event,
        )
        for _ in range(60):
            if self.simplexThread(node_id).connected:
                break
            test_delay_event.wait(1)
        else:
            raise ValueError("SimpleX websocket did not reconnect")
        logger.info(f"simplex-chat of node {node_id} restarted and reconnected")

    def test_01_leader_recover_a_lock_tx(self):
        self.do_test_02_leader_recover_a_lock_tx(Coins.BTC, Coins.XMR)

    def test_02_leader_recover_a_lock_tx_reverse(self):
        # Reversed, so the bidder funds the bid in coin_from
        self.prepare_balance(Coins.BTC, 100.0, 1801, 1800)
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_02_leader_recover_a_lock_tx(Coins.XMR, Coins.BTC)

    def test_03_follower_recover_a_lock_tx(self):
        self.do_test_03_follower_recover_a_lock_tx(Coins.BTC, Coins.XMR)

    def test_04_follower_recover_b_lock_tx(self):
        self.do_test_04_follower_recover_b_lock_tx(Coins.BTC, Coins.XMR)

    def test_05_follower_recover_b_lock_tx_reverse(self):
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_04_follower_recover_b_lock_tx(Coins.XMR, Coins.BTC)

    def test_06_client_restart_after_accept(self):
        logger.info("---------- Test bidder simplex-chat crash after bid accept")
        swap_clients = self.swap_clients
        id_offerer: int = 0
        id_bidder: int = 1
        ci_from = swap_clients[id_offerer].ci(Coins.BTC)
        ci_to = swap_clients[id_bidder].ci(Coins.XMR)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(
            Coins.BTC, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP
        )
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].getOffer(offer_id)

        bid_id = swap_clients[id_bidder].postBid(offer_id, offer.amount_from)
        wait_for_bid(
            test_delay_event,
            swap_clients[id_offerer],
            bid_id,
            BidStates.BID_RECEIVED,
            wait_for=(self.extra_wait_time + 60),
        )
        swap_clients[id_offerer].acceptBid(bid_id)
        wait_for_bid(
            test_delay_event,
            swap_clients[id_bidder],
            bid_id,
            BidStates.BID_ACCEPTED,
            sent=True,
            wait_for=(self.extra_wait_time + 60),
        )

        self.restartSimplexClient(id_bidder)

        wait_for_bid(
            test_delay_event,
            swap_clients[id_offerer],
            bid_id,
            BidStates.SWAP_COMPLETED,
            wait_for=(self.extra_wait_time + 320),
        )
        wait_for_bid(
            test_delay_event,
            swap_clients[id_bidder],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=(self.extra_wait_time + 320),
        )
        for sc in swap_clients[:2]:
            bids = sc.listBids(offer_id=offer_id)
            assert len(bids) == 1, f"Expected one bid, found {len(bids)}"
