#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Nostr ↔ SMSG bridge regtest swaps (3 nodes).

Node 0: active Nostr, bridged to SMSG
Node 1: active SMSG, bridged to Nostr
Node 2: both Nostr and SMSG, network bridging enabled

export PYTHONPATH=$(pwd)
pytest -v -s tests/basicswap/extended/test_multinet_nostr.py
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
    read_json_api,
)
from tests.basicswap.util.nostr_test_helpers import (
    getNostrNetworkConfig,
    wait_for_portal,
)
from tests.basicswap.test_xmr import test_delay_event
from tests.basicswap.extended.test_nostr import TestNostr2

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(TestNostr2):
    __test__ = True

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        from coincurve.keys import PrivateKey

        while len(cls.nostr_keys) <= node_id:
            cls.nostr_keys.append(PrivateKey().to_hex())

        settings["networks"] = []
        settings["smsg_payload_version"] = 2
        if node_id in (0, 2):
            network = getNostrNetworkConfig(
                node_id,
                relay_url=cls.relay_url,
                private_key=cls.nostr_keys[node_id],
            )
            if node_id == 0:
                network["bridged"] = [{"type": "smsg"}]
            settings["networks"].append(network)
        if node_id in (1, 2):
            smsg_network = {"type": "smsg", "enabled": True}
            if node_id == 1:
                smsg_network["bridged"] = [{"type": "nostr"}]
            settings["networks"].append(smsg_network)

        settings["enabled_log_categories"] = ["net"]

    def test_01_across_networks(self):
        logger.info("---------- Test Nostr/SMSG bridge swap")

        swap_clients = self.swap_clients
        swap_clients[2]._bridge_networks = True

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "nostr"
        assert len(swap_clients[1].active_networks) == 1
        assert swap_clients[1].active_networks[0]["type"] == "smsg"
        assert len(swap_clients[2].active_networks) == 2

        coin_from = Coins.BTC
        coin_to = self.coin_to

        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        wait_for_portal(test_delay_event, swap_clients[0])

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP
        )

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(
            test_delay_event,
            swap_clients[0],
            bid_id,
            BidStates.BID_RECEIVED,
            wait_for=60,
        )
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

    def test_02_across_networks(self):
        logger.info("---------- Test reversed Nostr/SMSG bridge swap")

        swap_clients = self.swap_clients
        swap_clients[2]._bridge_networks = True

        coin_from = Coins.XMR
        coin_to = Coins.BTC

        ci_from = swap_clients[1].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)

        wait_for_portal(test_delay_event, swap_clients[1])

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[1].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP
        )

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(
            test_delay_event,
            swap_clients[1],
            bid_id,
            BidStates.BID_RECEIVED,
            wait_for=60,
        )
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

    def test_03_multiple_active(self):
        logger.info("---------- Test bridge swap with multiple active networks")

        swap_clients = self.swap_clients
        swap_clients[2]._bridge_networks = True
        assert len(swap_clients[2].active_networks) == 2

        coin_from = Coins.BTC
        coin_to = self.coin_to

        self.prepare_balance(coin_from, 100.0, 1802, 1800)
        self.prepare_balance(coin_from, 200.0, 1802, 1800)
        self.prepare_balance(coin_to, 1000.0, 1800, 1801)

        ci_from = swap_clients[2].ci(coin_from)
        ci_to0 = swap_clients[0].ci(coin_to)

        wait_for_portal(test_delay_event, swap_clients[0])
        swap_value = ci_from.make_int(random.uniform(0.2, 10.0), r=1)
        rate_swap = ci_to0.make_int(random.uniform(0.2, 10.0), r=1)
        offer_id = swap_clients[2].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP
        )

        rv = read_json_api(1802, f"offers/{offer_id.hex()}")
        assert "smsg" in rv[0]["message_nets"] and "nostr" in rv[0]["message_nets"]

        bid_ids = []
        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_ids.append(swap_clients[0].postBid(offer_id, offer.amount_from))

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        bid_ids.append(swap_clients[1].postBid(offer_id, offer.amount_from))

        bid_0 = read_json_api(1800, f"bids/{bid_ids[0].hex()}")
        assert bid_0["message_nets"] == "nostr"

        bid_1 = read_json_api(1801, f"bids/{bid_ids[1].hex()}")
        assert bid_1["message_nets"] == "smsg"

        for bid_id in bid_ids:
            wait_for_bid(
                test_delay_event,
                swap_clients[2],
                bid_id,
                BidStates.BID_RECEIVED,
                wait_for=60,
            )
            swap_clients[2].acceptBid(bid_id)

        wait_for_bid(
            test_delay_event,
            swap_clients[0],
            bid_ids[0],
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=320,
        )
        wait_for_bid(
            test_delay_event,
            swap_clients[1],
            bid_ids[1],
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=320,
        )
        for bid_id in bid_ids:
            wait_for_bid(
                test_delay_event,
                swap_clients[2],
                bid_id,
                BidStates.SWAP_COMPLETED,
                wait_for=320,
            )
