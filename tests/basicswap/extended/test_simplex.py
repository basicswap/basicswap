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

export SIMPLEX_SERVER_ADDRESS=smp://Q8SNxc2SRcKyXlhJM8KFUgPNW4KXPGRm4eSLtT_oh-I=:password@127.0.0.1:5223,443


https://github.com/simplex-chat/simplex-chat/issues/4127
    json: {"corrId":"3","cmd":"/_send #1 text test123"}
    direct message: {"corrId":"1","cmd":"/_send @2 text the message"}

"""

import json
import logging
import os
import random
import shutil
import sys
import unittest

import basicswap.config as cfg

from basicswap.basicswap import (
    BidStates,
    SwapTypes,
)
from basicswap.chainparams import Coins

from basicswap.network.simplex import (
    WebSocketThread,
    waitForConnected,
    waitForResponse,
)
from basicswap.network.simplex_chat import startSimplexClient
from tests.basicswap.common import (
    stopDaemons,
    wait_for_bid,
    wait_for_offer,
)
from tests.basicswap.test_xmr import BaseTest, test_delay_event, RESET_TEST


SIMPLEX_SERVER_ADDRESS = os.getenv("SIMPLEX_SERVER_ADDRESS")
SIMPLEX_CLIENT_PATH = os.path.expanduser(os.getenv("SIMPLEX_CLIENT_PATH"))
TEST_DIR = cfg.TEST_DATADIRS


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class TestSimplex(unittest.TestCase):
    daemons = []
    remove_testdir: bool = False

    @classmethod
    def tearDownClass(cls):
        stopDaemons(cls.daemons)

    def test_basic(self):

        if os.path.isdir(TEST_DIR):
            if RESET_TEST:
                logging.info("Removing " + TEST_DIR)
                shutil.rmtree(TEST_DIR)
            else:
                logging.info("Restoring instance from " + TEST_DIR)
        if not os.path.exists(TEST_DIR):
            os.makedirs(TEST_DIR)

        client1_dir = os.path.join(TEST_DIR, "client1")
        if os.path.exists(client1_dir):
            shutil.rmtree(client1_dir)

        client1_daemon = startSimplexClient(
            SIMPLEX_CLIENT_PATH,
            client1_dir,
            SIMPLEX_SERVER_ADDRESS,
            5225,
            logger,
            test_delay_event,
        )
        self.daemons.append(client1_daemon)

        client2_dir = os.path.join(TEST_DIR, "client2")
        if os.path.exists(client2_dir):
            shutil.rmtree(client2_dir)
        client2_daemon = startSimplexClient(
            SIMPLEX_CLIENT_PATH,
            client2_dir,
            SIMPLEX_SERVER_ADDRESS,
            5226,
            logger,
            test_delay_event,
        )
        self.daemons.append(client2_daemon)

        threads = []
        try:
            ws_thread = WebSocketThread("ws://127.0.0.1:5225", tag="C1")
            ws_thread.start()
            threads.append(ws_thread)

            ws_thread2 = WebSocketThread("ws://127.0.0.1:5226", tag="C2")
            ws_thread2.start()
            threads.append(ws_thread2)

            waitForConnected(ws_thread, test_delay_event)
            sent_id = ws_thread.send_command("/group bsx")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            assert response["resp"]["type"] == "groupCreated"

            ws_thread.send_command("/set voice #bsx off")
            ws_thread.send_command("/set files #bsx off")
            ws_thread.send_command("/set direct #bsx off")
            ws_thread.send_command("/set reactions #bsx off")
            ws_thread.send_command("/set reports #bsx off")
            ws_thread.send_command("/set disappear #bsx on week")
            sent_id = ws_thread.send_command("/create link #bsx")

            connReqContact = None
            connReqMsgData = waitForResponse(ws_thread, sent_id, test_delay_event)
            connReqContact = connReqMsgData["resp"]["connReqContact"]

            group_link = "https://simplex.chat" + connReqContact[8:]
            logger.info(f"group_link: {group_link}")

            sent_id = ws_thread2.send_command("/c " + group_link)
            response = waitForResponse(ws_thread2, sent_id, test_delay_event)
            assert "groupLinkId" in response["resp"]["connection"]

            sent_id = ws_thread2.send_command("/groups")
            response = waitForResponse(ws_thread2, sent_id, test_delay_event)
            assert len(response["resp"]["groups"]) == 1

            ws_thread.send_command("#bsx test msg 1")

            found_1 = False
            found_2 = False
            for i in range(100):
                message = ws_thread.queue_get()
                if message is not None:
                    data = json.loads(message)
                    # print(f"message 1: {json.dumps(data, indent=4)}")
                    try:
                        if data["resp"]["type"] in (
                            "chatItemsStatusesUpdated",
                            "newChatItems",
                        ):
                            for chat_item in data["resp"]["chatItems"]:
                                # print(f"chat_item 1: {json.dumps(chat_item, indent=4)}")
                                if chat_item["chatItem"]["meta"]["itemStatus"][
                                    "type"
                                ] in ("sndRcvd", "rcvNew"):
                                    if (
                                        chat_item["chatItem"]["content"]["msgContent"][
                                            "text"
                                        ]
                                        == "test msg 1"
                                    ):
                                        found_1 = True
                    except Exception as e:
                        print(f"error 1: {e}")

                message = ws_thread2.queue_get()
                if message is not None:
                    data = json.loads(message)
                    # print(f"message 2: {json.dumps(data, indent=4)}")
                    try:
                        if data["resp"]["type"] in (
                            "chatItemsStatusesUpdated",
                            "newChatItems",
                        ):
                            for chat_item in data["resp"]["chatItems"]:
                                # print(f"chat_item 1: {json.dumps(chat_item, indent=4)}")
                                if chat_item["chatItem"]["meta"]["itemStatus"][
                                    "type"
                                ] in ("sndRcvd", "rcvNew"):
                                    if (
                                        chat_item["chatItem"]["content"]["msgContent"][
                                            "text"
                                        ]
                                        == "test msg 1"
                                    ):
                                        found_2 = True
                    except Exception as e:
                        print(f"error 2: {e}")

                if found_1 and found_2:
                    break
                test_delay_event.wait(0.5)

            assert found_1 is True
            assert found_2 is True

        finally:
            for t in threads:
                t.stop()
                t.join()


class Test(BaseTest):
    __test__ = True
    start_ltc_nodes = False
    start_xmr_nodes = True
    group_link = None
    daemons = []
    coin_to = Coins.XMR
    # coin_to = Coins.PART

    @classmethod
    def prepareTestDir(cls):
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

        # Create the group for bsx
        logger.info("Creating BSX group")
        ws_thread = None
        try:
            ws_thread = WebSocketThread(f"ws://127.0.0.1:{base_ws_port}", tag="C0")
            ws_thread.start()
            waitForConnected(ws_thread, test_delay_event)
            sent_id = ws_thread.send_command("/group bsx")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            assert response["resp"]["type"] == "groupCreated"

            ws_thread.send_command("/set voice #bsx off")
            ws_thread.send_command("/set files #bsx off")
            ws_thread.send_command("/set direct #bsx off")
            ws_thread.send_command("/set reactions #bsx off")
            ws_thread.send_command("/set reports #bsx off")
            ws_thread.send_command("/set disappear #bsx on week")
            sent_id = ws_thread.send_command("/create link #bsx")

            connReqContact = None
            connReqMsgData = waitForResponse(ws_thread, sent_id, test_delay_event)
            connReqContact = connReqMsgData["resp"]["connReqContact"]
            cls.group_link = "https://simplex.chat" + connReqContact[8:]
            logger.info(f"BSX group_link: {cls.group_link}")

        finally:
            if ws_thread:
                ws_thread.stop()
                ws_thread.join()

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Test")
        super(Test, cls).tearDownClass()
        stopDaemons(cls.daemons)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):

        settings["networks"] = [
            {
                "type": "simplex",
                "server_address": SIMPLEX_SERVER_ADDRESS,
                "client_path": SIMPLEX_CLIENT_PATH,
                "ws_port": 5225 + node_id,
                "group_link": cls.group_link,
            },
        ]

    def test_01_swap(self):
        logging.info("---------- Test xmr swap")

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc.dleag_split_size_init = 9000
            sc.dleag_split_size = 11000

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

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
