#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Adversarial and transport-loss regtest swaps over Nostr (3 nodes, Nostr only).

Reuses the recovery scenarios from test_btc_xmr.TestFunctions with every
node on the in-process test relay, then drops the relay mid-swap.

export PYTHONPATH=$(pwd)
pytest -v -s tests/basicswap/extended/test_nostr_adversarial.py
"""

import logging
import random
import sys

from basicswap.basicswap import (
    BidStates,
    SwapTypes,
)
from basicswap.chainparams import Coins

from tests.basicswap.test_btc_xmr import BTC_BASE_RPC_PORT, TestFunctions
from tests.basicswap.test_xmr import test_delay_event
from tests.basicswap.util.common import (
    wait_for_bid,
    wait_for_offer,
)
from tests.basicswap.util.nostr_test_helpers import (
    NostrRelayFixture,
    getNostrNetworkConfig,
)

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class TestNostrAdversarial(TestFunctions, NostrRelayFixture):
    __test__ = True
    base_rpc_port = BTC_BASE_RPC_PORT
    start_ltc_nodes = False
    start_xmr_nodes = True
    extra_wait_time = 60
    nostr_keys = []

    @classmethod
    def prepareTestDir(cls):
        cls.startRelay()

    @classmethod
    def tearDownClass(cls):
        logger.info("Finalising Test")
        super().tearDownClass()
        cls.stopRelay()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        from coincurve.keys import PrivateKey

        while len(cls.nostr_keys) <= node_id:
            cls.nostr_keys.append(PrivateKey().to_hex())
        settings["smsg_payload_version"] = 2
        settings["networks"] = [
            getNostrNetworkConfig(
                node_id,
                relay_url=cls.relay_url,
                private_key=cls.nostr_keys[node_id],
            ),
        ]

    def nostrClient(self, node_id: int):
        for network in self.swap_clients[node_id].active_networks:
            if network["type"] == "nostr":
                return network["client"]
        raise ValueError("No active Nostr network")

    def relayOutage(self, seconds: int) -> None:
        relay_port: int = self.relay.port
        logger.info(f"Stopping relay on port {relay_port} for {seconds}s")
        self.stopRelay()
        test_delay_event.wait(seconds)
        for i in range(len(self.swap_clients)):
            assert not any(r.connected for r in self.nostrClient(i).relays)
        self.startRelay(port=relay_port)
        for _ in range(60):
            if all(
                any(r.connected for r in self.nostrClient(i).relays)
                for i in range(len(self.swap_clients))
            ):
                break
            test_delay_event.wait(1)
        else:
            raise ValueError("Relays did not reconnect")
        logger.info("Relay restored, all nodes reconnected")

    def assertSingleBid(self, offer_id: bytes) -> None:
        for sc in self.swap_clients[:2]:
            bids = sc.listBids(offer_id=offer_id)
            assert len(bids) == 1, f"Expected one bid, found {len(bids)}"

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

    def runSwapWithOutage(self, outage_after_accept: bool) -> None:
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
        if not outage_after_accept:
            # Route handshake and bid delivery are in flight.
            self.relayOutage(20)

        wait_for_bid(
            test_delay_event,
            swap_clients[id_offerer],
            bid_id,
            BidStates.BID_RECEIVED,
            wait_for=(self.extra_wait_time + 60),
        )
        swap_clients[id_offerer].acceptBid(bid_id)
        if outage_after_accept:
            wait_for_bid(
                test_delay_event,
                swap_clients[id_bidder],
                bid_id,
                BidStates.BID_ACCEPTED,
                sent=True,
                wait_for=(self.extra_wait_time + 60),
            )
            # Lock tx messages are exchanged while the relay is down.
            self.relayOutage(30)

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
        self.assertSingleBid(offer_id)

    def test_06_relay_outage_during_bid(self):
        logger.info("---------- Test relay outage between bid and accept")
        self.runSwapWithOutage(outage_after_accept=False)

    def test_07_relay_outage_after_accept(self):
        logger.info("---------- Test relay outage after bid accept")
        self.runSwapWithOutage(outage_after_accept=True)
