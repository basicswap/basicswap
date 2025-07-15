#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
docker run \
    -e "ADDR=127.0.0.1" \
    -e "PASS=password" \
    -p 5223:5223 \
    -v /tmp/simplex/smp/config:/etc/opt/simplex:z \
    -v /tmp/simplex/smp/logs:/var/opt/simplex:z \
    -v /tmp/simplex/certs:/certificates \
    simplexchat/smp-server:latest

Fingerprint: Q8SNxc2SRcKyXlhJM8KFUgPNW4KXPGRm4eSLtT_oh-I=

export SIMPLEX_SERVER_ADDRESS=smp://Q8SNxc2SRcKyXlhJM8KFUgPNW4KXPGRm4eSLtT_oh-I=:password@127.0.0.1:5223

https://github.com/simplex-chat/simplex-chat/issues/4127
    json: {"corrId":"3","cmd":"/_send #1 text test123"}
    direct message: {"corrId":"1","cmd":"/_send @2 text the message"}

"""

import logging
import random
import sys

from basicswap.basicswap import (
    BidStates,
    SwapTypes,
)
from basicswap.chainparams import Coins

from tests.basicswap.common import (
    wait_for_bid,
    wait_for_offer,
)
from tests.basicswap.test_xmr import test_delay_event
from tests.basicswap.extended.test_simplex import (
    TestSimplex2,
    SIMPLEX_SERVER_ADDRESS,
    SIMPLEX_CLIENT_PATH,
)

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def wait_for_portal(delay_event, swap_client, wait_for=20):
    logging.info("wait_for_portal")

    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        delay_event.wait(1)
        if len(swap_client.known_portals) > 0:
            return
    raise ValueError("wait_for_portal timed out.")


class Test(TestSimplex2):
    __test__ = True

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["networks"] = []
        settings["smsg_plaintext_version"] = 2
        if node_id in (0, 2):
            settings["networks"].append(
                {
                    "type": "simplex",
                    "server_address": SIMPLEX_SERVER_ADDRESS,
                    "client_path": SIMPLEX_CLIENT_PATH,
                    "ws_port": 5225 + node_id,
                    "group_link": cls.group_link,
                    "enabled": True,
                },
            )
            if node_id == 0:
                settings["networks"][-1]["bridged"] = [{"type": "smsg"}]
        if node_id in (1, 2):
            settings["networks"].append(
                {
                    "type": "smsg",
                    "enabled": True,
                },
            )
            if node_id == 1:
                settings["networks"][-1]["bridged"] = [{"type": "simplex"}]

        for node_id in range(3):
            settings["enabled_log_categories"] = ["net", ]

    def test_01_across_networks(self):
        logger.info("---------- Test multinet swap across networks")

        swap_clients = self.swap_clients
        for sc in swap_clients:
            sc._use_direct_message_routes = False
        swap_clients[2]._bridge_networks = True

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"
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
        logger.info("---------- Test reversed swap across networks")

        swap_clients = self.swap_clients
        for sc in swap_clients:
            sc._use_direct_message_routes = False
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

    def test_03_across_networks(self):
        logger.info("---------- Test secret hash swap across networks")

        swap_clients = self.swap_clients
        for sc in swap_clients:
            sc._use_direct_message_routes = False
        swap_clients[2]._bridge_networks = True
        coin_from = Coins.PART
        coin_to = Coins.BTC
        self.prepare_balance(coin_to, 100.0, 1801, 1800)

        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        wait_for_portal(test_delay_event, swap_clients[0])

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.SELLER_FIRST
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

    def test_04_multiple_active(self):
        logger.info("---------- Test multinet swap with multiple active networks")

        # Messages for bids should only be sent to one network
        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = False
        swap_clients[2]._bridge_networks = True
        assert len(swap_clients[2].active_networks) == 2

        num_group_simplex_messages_received_before = [0 for _ in range(3)]
        num_group_simplex_messages_sent_before = [0 for _ in range(3)]
        num_direct_simplex_messages_received_before = [0 for _ in range(3)]
        num_direct_simplex_messages_sent_before = [0 for _ in range(3)]
        num_smsg_messages_received_before = [0 for _ in range(3)]
        num_smsg_messages_sent_before = [0 for _ in range(3)]

        for i in range(3):
            num_group_simplex_messages_received_before[i] = swap_clients[
                i
            ].num_group_simplex_messages_received
            num_group_simplex_messages_sent_before[i] = swap_clients[
                i
            ].num_group_simplex_messages_sent
            num_direct_simplex_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received
            num_direct_simplex_messages_sent_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_sent
            num_smsg_messages_received_before[i] = swap_clients[
                i
            ].num_smsg_messages_received
            num_smsg_messages_sent_before[i] = swap_clients[i].num_smsg_messages_sent

        coin_from = Coins.BTC
        coin_to = self.coin_to

        # Prepare balances
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

        bid_ids = []
        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_ids.append(swap_clients[0].postBid(offer_id, offer.amount_from))

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        bid_ids.append(swap_clients[1].postBid(offer_id, offer.amount_from))

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

        num_group_simplex_messages_received = [0 for _ in range(3)]
        num_group_simplex_messages_sent = [0 for _ in range(3)]
        num_direct_simplex_messages_received = [0 for _ in range(3)]
        num_direct_simplex_messages_sent = [0 for _ in range(3)]
        num_smsg_messages_received = [0 for _ in range(3)]
        num_smsg_messages_sent = [0 for _ in range(3)]

        for i in range(3):
            num_group_simplex_messages_received[i] = (
                swap_clients[i].num_group_simplex_messages_received
                - num_group_simplex_messages_received_before[i]
            )
            num_group_simplex_messages_sent[i] = (
                swap_clients[i].num_group_simplex_messages_sent
                - num_group_simplex_messages_sent_before[i]
            )
            num_direct_simplex_messages_received[i] = (
                swap_clients[i].num_direct_simplex_messages_received
                - num_direct_simplex_messages_received_before[i]
            )
            num_direct_simplex_messages_sent[i] = (
                swap_clients[i].num_direct_simplex_messages_sent
                - num_direct_simplex_messages_sent_before[i]
            )
            num_smsg_messages_received[i] = (
                swap_clients[i].num_smsg_messages_received
                - num_smsg_messages_received_before[i]
            )
            num_smsg_messages_sent[i] = (
                swap_clients[i].num_smsg_messages_sent
                - num_smsg_messages_sent_before[i]
            )

        assert num_group_simplex_messages_sent[2] <= 9
        assert num_smsg_messages_sent[2] <= 9
