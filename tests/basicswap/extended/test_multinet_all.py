#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
SMSG + SimpleX + Nostr bridge regtest swaps (3 nodes).

Requires SimpleX SMP server and simplex-chat binary (see test_simplex.py).

Node 0: active SimpleX, bridged to SMSG
Node 1: active Nostr, bridged to SMSG
Node 2: active SMSG, bridged to SimpleX and Nostr, network bridging enabled

export PYTHONPATH=$(pwd)
pytest -v -s tests/basicswap/extended/test_multinet_all.py
"""

import logging
import os
import random
import shutil
import sys

import basicswap.config as cfg

from basicswap.basicswap import (
    BidStates,
    SwapTypes,
)
from basicswap.chainparams import Coins
from basicswap.network.simplex import (
    getNewSimplexLink,
    getResponseData,
    waitForConnected,
    waitForResponse,
    WebSocketThread,
)
from basicswap.network.simplex_chat import startSimplexClient

from tests.basicswap.util.common import (
    stopDaemons,
    wait_for_bid,
    wait_for_offer,
    read_json_api,
)
from tests.basicswap.util.nostr_test_helpers import (
    NostrRelayFixture,
    getNostrNetworkConfig,
    wait_for_portal,
)
from tests.basicswap.test_xmr import BaseTest, test_delay_event

TEST_DIR = cfg.TEST_DATADIRS

SIMPLEX_SERVER_FINGERPRINT = os.getenv("SIMPLEX_SERVER_FINGERPRINT", "")
SIMPLEX_SERVER_ADDRESS = os.getenv(
    "SIMPLEX_SERVER_ADDRESS",
    f"smp://{SIMPLEX_SERVER_FINGERPRINT}:password@127.0.0.1:5223",
)
SIMPLEX_CLIENT_PATH = os.path.expanduser(os.getenv("SIMPLEX_CLIENT_PATH", ""))

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class TestMultinetAll(BaseTest, NostrRelayFixture):
    __test__ = False
    start_ltc_nodes = False
    start_xmr_nodes = True
    group_link = None
    daemons = []
    coin_to = Coins.XMR
    nostr_keys = []

    @classmethod
    def prepareTestDir(cls):
        cls.startRelay()

        base_ws_port: int = 5225
        for i in range(cls.num_nodes):
            client_dir = os.path.join(TEST_DIR, f"simplex_client{i}")
            if os.path.exists(client_dir):
                shutil.rmtree(client_dir)

            client_daemon = startSimplexClient(
                SIMPLEX_CLIENT_PATH,
                client_dir,
                SIMPLEX_SERVER_ADDRESS,
                base_ws_port + i,
                logger,
                test_delay_event,
            )
            cls.daemons.append(client_daemon)

        logger.info("Creating BSX group")
        ws_thread = None
        try:
            ws_thread = WebSocketThread(f"ws://127.0.0.1:{base_ws_port}", tag="C0")
            ws_thread.start()
            waitForConnected(ws_thread, test_delay_event)
            sent_id = ws_thread.send_command("/group bsx")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            if getResponseData(response, "type") != "groupCreated":
                raise ValueError(f"Expected groupCreated: {response}")

            ws_thread.send_command("/set voice #bsx off")
            ws_thread.send_command("/set files #bsx off")
            ws_thread.send_command("/set direct #bsx off")
            ws_thread.send_command("/set reactions #bsx off")
            ws_thread.send_command("/set reports #bsx off")
            ws_thread.send_command("/set disappear #bsx on week")
            sent_id = ws_thread.send_command("/create link #bsx")

            connReqMsgData = waitForResponse(ws_thread, sent_id, test_delay_event)
            connReqContact = getNewSimplexLink(connReqMsgData)
            cls.group_link = "https://simplex.chat" + connReqContact[8:]
            logger.info(f"BSX group_link: {cls.group_link}")

        finally:
            if ws_thread:
                ws_thread.stop()
                ws_thread.join()

    @classmethod
    def tearDownClass(cls):
        logger.info("Finalising Test")
        super().tearDownClass()
        stopDaemons(cls.daemons)
        cls.stopRelay()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        from coincurve.keys import PrivateKey

        while len(cls.nostr_keys) <= node_id:
            cls.nostr_keys.append(PrivateKey().to_hex())

        settings["networks"] = []
        settings["smsg_payload_version"] = 2

        if node_id == 0:
            settings["networks"].append(
                {
                    "type": "simplex",
                    "server_address": SIMPLEX_SERVER_ADDRESS,
                    "client_path": SIMPLEX_CLIENT_PATH,
                    "ws_port": 5225 + node_id,
                    "group_link": cls.group_link,
                    "enabled": True,
                    "bridged": [{"type": "smsg"}],
                },
            )
        elif node_id == 1:
            settings["networks"].append(
                getNostrNetworkConfig(
                    node_id,
                    relay_url=cls.relay_url,
                    private_key=cls.nostr_keys[node_id],
                    bridged=[{"type": "smsg"}],
                ),
            )
        elif node_id == 2:
            settings["networks"].append(
                {
                    "type": "smsg",
                    "enabled": True,
                    "bridged": [{"type": "simplex"}, {"type": "nostr"}],
                },
            )

        settings["enabled_log_categories"] = ["net"]


class Test(TestMultinetAll):
    __test__ = True

    def test_01_simplex_to_nostr(self):
        logger.info("---------- Test SimpleX offer to Nostr bidder via bridge")

        swap_clients = self.swap_clients
        swap_clients[2]._bridge_networks = True

        for sc in swap_clients:
            sc._use_direct_message_routes = False

        assert swap_clients[0].active_networks[0]["type"] == "simplex"
        assert swap_clients[1].active_networks[0]["type"] == "nostr"
        assert swap_clients[2].active_networks[0]["type"] == "smsg"

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

        wait_for_offer(test_delay_event, swap_clients[1], offer_id, wait_for=120)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(
            test_delay_event,
            swap_clients[0],
            bid_id,
            BidStates.BID_RECEIVED,
            wait_for=90,
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

    def test_02_nostr_to_simplex(self):
        logger.info("---------- Test Nostr offer to SimpleX bidder via bridge")

        swap_clients = self.swap_clients
        swap_clients[2]._bridge_networks = True

        for sc in swap_clients:
            sc._use_direct_message_routes = False

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

        wait_for_offer(test_delay_event, swap_clients[0], offer_id, wait_for=120)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(
            test_delay_event,
            swap_clients[1],
            bid_id,
            BidStates.BID_RECEIVED,
            wait_for=90,
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

    def test_03_triple_network_offer(self):
        logger.info("---------- Test offer on bridge node reaches both networks")

        swap_clients = self.swap_clients
        swap_clients[2]._bridge_networks = True

        for sc in swap_clients:
            sc._use_direct_message_routes = False

        coin_from = Coins.BTC
        coin_to = self.coin_to

        self.prepare_balance(coin_from, 100.0, 1802, 1800)
        self.prepare_balance(coin_to, 1000.0, 1800, 1801)

        ci_from = swap_clients[2].ci(coin_from)
        ci_to0 = swap_clients[0].ci(coin_to)

        wait_for_portal(test_delay_event, swap_clients[2])

        swap_value = ci_from.make_int(random.uniform(0.2, 10.0), r=1)
        rate_swap = ci_to0.make_int(random.uniform(0.2, 10.0), r=1)
        offer_id = swap_clients[2].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP
        )

        rv = read_json_api(1802, f"offers/{offer_id.hex()}")
        message_nets = rv[0]["message_nets"]
        assert "smsg" in message_nets
        assert "simplex" in message_nets or "nostr" in message_nets

        bid_ids = []
        wait_for_offer(test_delay_event, swap_clients[0], offer_id, wait_for=120)
        offer = swap_clients[0].getOffer(offer_id)
        bid_ids.append(swap_clients[0].postBid(offer_id, offer.amount_from))

        wait_for_offer(test_delay_event, swap_clients[1], offer_id, wait_for=120)
        offer = swap_clients[1].getOffer(offer_id)
        bid_ids.append(swap_clients[1].postBid(offer_id, offer.amount_from))

        for bid_id in bid_ids:
            wait_for_bid(
                test_delay_event,
                swap_clients[2],
                bid_id,
                BidStates.BID_RECEIVED,
                wait_for=90,
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
