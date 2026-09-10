#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Three-node BTC↔XMR swaps over Nostr only (regtest).

Starts an in-process mini relay; no external Nostr infrastructure required.

export PYTHONPATH=$(pwd)
pytest -v -s tests/basicswap/extended/test_nostr.py
"""

import logging
import random
import sys

from basicswap.basicswap import (
    BidStates,
    SwapTypes,
)
from basicswap.chainparams import Coins

from tests.basicswap.util.common import (
    wait_for_bid,
    wait_for_offer,
)
from tests.basicswap.util.nostr_test_helpers import (
    NostrRelayFixture,
    getNostrNetworkConfig,
)
from tests.basicswap.test_xmr import BaseTest, test_delay_event

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class TestNostr2(BaseTest, NostrRelayFixture):
    __test__ = False
    start_ltc_nodes = False
    start_xmr_nodes = True
    coin_to = Coins.XMR
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


class Test(TestNostr2):
    __test__ = True

    def test_01_swap(self):
        logger.info("---------- Test adaptor sig swap over Nostr")

        swap_clients = self.swap_clients

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "nostr"

        num_direct_nostr_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_nostr_messages_received_before[i] = swap_clients[
                i
            ].num_direct_nostr_messages_received

        coin_from = Coins.BTC
        coin_to = self.coin_to

        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP
        )

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(
            test_delay_event,
            swap_clients[0],
            bid_id,
            BidStates.SWAP_COMPLETED,
            wait_for=320,
        )
        wait_for_bid(
            test_delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=320,
        )

        for i in range(3):
            assert (
                swap_clients[i].num_direct_nostr_messages_received
                >= num_direct_nostr_messages_received_before[i]
            )

    def test_02_swap_reverse(self):
        logger.info("---------- Test adaptor sig swap reverse over Nostr")

        swap_clients = self.swap_clients

        coin_from = self.coin_to
        coin_to = Coins.BTC

        ci_from = swap_clients[1].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[1].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP
        )

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.BID_RECEIVED)
        swap_clients[1].acceptBid(bid_id)

        wait_for_bid(
            test_delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            wait_for=320,
        )
        wait_for_bid(
            test_delay_event,
            swap_clients[0],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=320,
        )
