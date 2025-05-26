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
from tests.basicswap.util import read_json_api
from tests.basicswap.test_xmr import BaseTest, test_delay_event, RESET_TEST

SIMPLEX_SERVER_FINGERPRINT = os.getenv("SIMPLEX_SERVER_FINGERPRINT", "")
SIMPLEX_SERVER_ADDRESS = os.getenv(
    "SIMPLEX_SERVER_ADDRESS",
    f"smp://{SIMPLEX_SERVER_FINGERPRINT}:password@127.0.0.1:5223",
)
SIMPLEX_CLIENT_PATH = os.path.expanduser(os.getenv("SIMPLEX_CLIENT_PATH"))
TEST_DIR = cfg.TEST_DATADIRS


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def parse_message(msg_data):
    if msg_data["resp"]["type"] not in ("chatItemsStatusesUpdated", "newChatItems"):
        return None

    for chat_item in msg_data["resp"]["chatItems"]:
        chat_type: str = chat_item["chatInfo"]["type"]
        if chat_type == "group":
            chat_name = chat_item["chatInfo"]["groupInfo"]["localDisplayName"]
        elif chat_type == "direct":
            chat_name = chat_item["chatInfo"]["contact"]["localDisplayName"]
        else:
            return None

        dir_type = chat_item["chatItem"]["meta"]["itemStatus"]["type"]
        msg_dir = "recv" if dir_type == "rcvNew" else "sent"
        if dir_type in ("sndRcvd", "rcvNew"):
            msg_content = chat_item["chatItem"]["content"]["msgContent"]["text"]
            return {
                "text": msg_content,
                "chat_type": chat_type,
                "chat_name": chat_name,
                "msg_dir": msg_dir,
            }
    return None


class TestSimplex(unittest.TestCase):
    daemons = []
    remove_testdir: bool = False

    @classmethod
    def tearDownClass(cls):
        stopDaemons(cls.daemons)

    def test_basic(self):

        if os.path.isdir(TEST_DIR):
            if RESET_TEST:
                logger.info("Removing " + TEST_DIR)
                shutil.rmtree(TEST_DIR)
            else:
                logger.info("Restoring instance from " + TEST_DIR)
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

            sent_id = ws_thread2.send_command("/connect")
            response = waitForResponse(ws_thread2, sent_id, test_delay_event)
            with open(os.path.join(client2_dir, "chat_inv.txt"), "w") as fp:
                fp.write(json.dumps(response, indent=4))

            connReqInvitation = response["resp"]["connReqInvitation"]
            logger.info(f"direct_link: {connReqInvitation}")
            pccConnId_2_sent = response["resp"]["connection"]["pccConnId"]
            print(f"pccConnId_2_sent: {pccConnId_2_sent}")

            sent_id = ws_thread.send_command(f"/connect {connReqInvitation}")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            with open(os.path.join(client1_dir, "chat_inv_accept.txt"), "w") as fp:
                fp.write(json.dumps(response, indent=4))
            pccConnId_1_accepted = response["resp"]["connection"]["pccConnId"]
            print(f"pccConnId_1_accepted: {pccConnId_1_accepted}")

            sent_id = ws_thread.send_command("/chats")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            with open(os.path.join(client1_dir, "chats.txt"), "w") as fp:
                fp.write(json.dumps(response, indent=4))

            direct_local_name_1 = None
            for chat in response["resp"]["chats"]:
                print(f"chat: {chat}")
                if (
                    chat["chatInfo"]["contact"]["activeConn"]["connId"]
                    == pccConnId_1_accepted
                ):
                    direct_local_name_1 = chat["chatInfo"]["contact"][
                        "localDisplayName"
                    ]
                    break
            print(f"direct_local_name_1: {direct_local_name_1}")

            sent_id = ws_thread2.send_command("/chats")
            response = waitForResponse(ws_thread2, sent_id, test_delay_event)
            with open(os.path.join(client2_dir, "chats.txt"), "w") as fp:
                fp.write(json.dumps(response, indent=4))

            direct_local_name_2 = None
            for chat in response["resp"]["chats"]:
                print(f"chat: {chat}")
                if (
                    chat["chatInfo"]["contact"]["activeConn"]["connId"]
                    == pccConnId_2_sent
                ):
                    direct_local_name_2 = chat["chatInfo"]["contact"][
                        "localDisplayName"
                    ]
                    break
            print(f"direct_local_name_2: {direct_local_name_2}")
            # localDisplayName in chats doesn't match the contactConnected message.
            assert direct_local_name_1 == "user_1"
            assert direct_local_name_2 == "user_1"

            sent_id = ws_thread.send_command("#bsx test msg 1")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            assert response["resp"]["type"] == "newChatItems"
            sent_id = ws_thread.send_command("@user_1 test msg 2")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            assert response["resp"]["type"] == "newChatItems"

            msg_counter1: int = 0
            msg_counter2: int = 0
            found = [dict(), dict()]
            found_connected = [dict(), dict()]

            for i in range(100):
                if test_delay_event.is_set():
                    break
                for k in range(100):
                    message = ws_thread.queue_get()
                    if message is None or test_delay_event.is_set():
                        break
                    msg_counter1 += 1
                    data = json.loads(message)
                    try:
                        msg_type = data["resp"]["type"]
                    except Exception as e:
                        print(f"msg_type error: {e}")
                        msg_type = "None"
                    with open(
                        os.path.join(
                            client1_dir, f"recv_{msg_counter1}_{msg_type}.txt"
                        ),
                        "w",
                    ) as fp:
                        fp.write(json.dumps(data, indent=4))
                    if msg_type == "contactConnected":
                        found_connected[0][msg_counter1] = data
                        continue
                    try:
                        simplex_msg = parse_message(data)
                        if simplex_msg:
                            simplex_msg["msg_id"] = msg_counter1
                            found[0][msg_counter1] = simplex_msg
                    except Exception as e:
                        print(f"error 1: {e}")

                for k in range(100):
                    message = ws_thread2.queue_get()
                    if message is None or test_delay_event.is_set():
                        break
                    msg_counter2 += 1
                    data = json.loads(message)
                    try:
                        msg_type = data["resp"]["type"]
                    except Exception as e:
                        print(f"msg_type error: {e}")
                        msg_type = "None"
                    with open(
                        os.path.join(
                            client2_dir, f"recv_{msg_counter2}_{msg_type}.txt"
                        ),
                        "w",
                    ) as fp:
                        fp.write(json.dumps(data, indent=4))
                    if msg_type == "contactConnected":
                        found_connected[1][msg_counter2] = data
                        continue
                    try:
                        simplex_msg = parse_message(data)
                        if simplex_msg:
                            simplex_msg["msg_id"] = msg_counter2
                            found[1][msg_counter2] = simplex_msg
                    except Exception as e:
                        print(f"error 2: {e}")
                if (
                    len(found[0]) >= 2
                    and len(found[1]) >= 2
                    and len(found_connected[0]) >= 1
                    and len(found_connected[1]) >= 1
                ):
                    break
                test_delay_event.wait(0.5)

            assert len(found_connected[0]) == 1
            node1_connect = list(found_connected[0].values())[0]
            assert (
                node1_connect["resp"]["contact"]["activeConn"]["connId"]
                == pccConnId_1_accepted
            )
            assert node1_connect["resp"]["contact"]["localDisplayName"] == "user_2"

            assert len(found_connected[1]) == 1
            node2_connect = list(found_connected[1].values())[0]
            assert (
                node2_connect["resp"]["contact"]["activeConn"]["connId"]
                == pccConnId_2_sent
            )
            assert node2_connect["resp"]["contact"]["localDisplayName"] == "user_2"

            node1_msg1 = [m for m in found[0].values() if m["text"] == "test msg 1"]
            assert len(node1_msg1) == 1
            node1_msg1 = node1_msg1[0]
            assert node1_msg1["chat_type"] == "group"
            assert node1_msg1["chat_name"] == "bsx"
            assert node1_msg1["msg_dir"] == "sent"
            node1_msg2 = [m for m in found[0].values() if m["text"] == "test msg 2"]
            assert len(node1_msg2) == 1
            node1_msg2 = node1_msg2[0]
            assert node1_msg2["chat_type"] == "direct"
            assert node1_msg2["chat_name"] == "user_1"
            assert node1_msg2["msg_dir"] == "sent"

            node2_msg1 = [m for m in found[1].values() if m["text"] == "test msg 1"]
            assert len(node2_msg1) == 1
            node2_msg1 = node2_msg1[0]
            assert node2_msg1["chat_type"] == "group"
            assert node2_msg1["chat_name"] == "bsx"
            assert node2_msg1["msg_dir"] == "recv"
            node2_msg2 = [m for m in found[1].values() if m["text"] == "test msg 2"]
            assert len(node2_msg2) == 1
            node2_msg2 = node2_msg2[0]
            assert node2_msg2["chat_type"] == "direct"
            assert node2_msg2["chat_name"] == "user_1"
            assert node2_msg2["msg_dir"] == "recv"

            sent_id = ws_thread.send_command("/delete @user_1")
            response = waitForResponse(ws_thread, sent_id, test_delay_event)
            assert response["resp"]["type"] == "contactDeleted"

            sent_id = ws_thread2.send_command("/delete @user_1")
            response = waitForResponse(ws_thread2, sent_id, test_delay_event)
            assert response["resp"]["type"] == "contactDeleted"

            sent_id = ws_thread2.send_command("/chats")
            response = waitForResponse(ws_thread2, sent_id, test_delay_event)
            with open(os.path.join(client2_dir, "chats_after_delete.txt"), "w") as fp:
                fp.write(json.dumps(response, indent=4))

            assert len(response["resp"]["chats"]) == 4

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
        logger.info("Finalising Test")
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
        logger.info("---------- Test adaptor sig swap")

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = False

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

        num_direct_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received

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
                num_direct_messages_received_before[i]
                == swap_clients[i].num_direct_simplex_messages_received
            )

    def test_01_swap_reverse(self):
        logger.info("---------- Test adaptor sig swap reverse")

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = False

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

        num_direct_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received

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

        for i in range(3):
            assert (
                num_direct_messages_received_before[i]
                == swap_clients[i].num_direct_simplex_messages_received
            )

    def test_02_direct(self):
        logger.info("---------- Test adaptor sig swap with direct messages")

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = True

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

        num_direct_messages_received_before = [0] * 3
        num_group_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received
            num_group_messages_received_before[i] = swap_clients[
                i
            ].num_group_simplex_messages_received

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

        for i in range(3):
            swap_clients[
                i
            ].num_group_simplex_messages_received == num_group_messages_received_before[
                i
            ] + 2
        swap_clients[
            2
        ].num_direct_simplex_messages_received == num_direct_messages_received_before[2]

    def test_02_direct_reverse(self):
        logger.info(
            "---------- Test test_02_direct_reverse adaptor sig swap with direct messages"
        )

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = True

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

        num_direct_messages_received_before = [0] * 3
        num_group_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received
            num_group_messages_received_before[i] = swap_clients[
                i
            ].num_group_simplex_messages_received

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

        for i in range(3):
            swap_clients[
                i
            ].num_group_simplex_messages_received == num_group_messages_received_before[
                i
            ] + 2
        swap_clients[
            2
        ].num_direct_simplex_messages_received == num_direct_messages_received_before[2]

    def test_03_hltc(self):
        logger.info("---------- Test secret hash swap")

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = False

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

        num_direct_messages_received_before = [0] * 3
        num_group_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received
            num_group_messages_received_before[i] = swap_clients[
                i
            ].num_group_simplex_messages_received

        coin_from = Coins.PART
        coin_to = Coins.BTC

        self.prepare_balance(coin_to, 200.0, 1801, 1800)

        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from,
            coin_to,
            swap_value,
            rate_swap,
            swap_value,
            SwapTypes.SELLER_FIRST,
        )

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
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

        for i in range(3):
            assert (
                num_direct_messages_received_before[i]
                == swap_clients[i].num_direct_simplex_messages_received
            )

    def test_03_direct_hltc(self):
        logger.info("---------- Test secret hash swap with direct messages")

        for i in range(3):
            message_routes = read_json_api(
                1800 + i, "messageroutes", {"action": "clear"}
            )
            assert len(message_routes) == 0

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = True

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

        num_direct_messages_received_before = [0] * 3
        num_group_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received
            num_group_messages_received_before[i] = swap_clients[
                i
            ].num_group_simplex_messages_received

        coin_from = Coins.PART
        coin_to = Coins.BTC

        self.prepare_balance(coin_to, 200.0, 1801, 1800)

        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from,
            coin_to,
            swap_value,
            rate_swap,
            swap_value,
            SwapTypes.SELLER_FIRST,
        )

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
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

        message_routes = read_json_api(1800, "messageroutes")
        assert len(message_routes) == 1

        for i in range(3):
            swap_clients[
                i
            ].num_group_simplex_messages_received == num_group_messages_received_before[
                i
            ] + 2
        swap_clients[
            2
        ].num_direct_simplex_messages_received == num_direct_messages_received_before[2]

    def test_04_multiple(self):
        logger.info("---------- Test multiple swaps with direct messages")

        for i in range(3):
            message_routes = read_json_api(
                1800 + i, "messageroutes", {"action": "clear"}
            )
            assert len(message_routes) == 0

        swap_clients = self.swap_clients

        for sc in swap_clients:
            sc._use_direct_message_routes = True

        assert len(swap_clients[0].active_networks) == 1
        assert swap_clients[0].active_networks[0]["type"] == "simplex"

        num_direct_messages_received_before = [0] * 3
        num_group_messages_received_before = [0] * 3
        for i in range(3):
            num_direct_messages_received_before[i] = swap_clients[
                i
            ].num_direct_simplex_messages_received
            num_group_messages_received_before[i] = swap_clients[
                i
            ].num_group_simplex_messages_received

        coin_from = Coins.BTC
        coin_to = self.coin_to

        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP
        )

        swap_clients[1].active_networks[0]["ws_thread"].ignore_events = True

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        addr1_bids = swap_clients[1].getReceiveAddressForCoin(Coins.PART)

        bid_ids = []
        for i in range(2):
            bid_ids.append(
                swap_clients[1].postBid(
                    offer_id, offer.amount_from, addr_send_from=addr1_bids
                )
            )

        swap_clients[1].active_networks[0]["ws_thread"].disable_debug_mode()

        bid_ids.append(swap_clients[1].postBid(offer_id, offer.amount_from))

        for i in range(len(bid_ids)):
            wait_for_bid(
                test_delay_event,
                swap_clients[0],
                bid_ids[i],
                BidStates.BID_RECEIVED,
                wait_for=60,
            )
            swap_clients[0].acceptBid(bid_ids[i])

        logger.info("Message routes with active bids shouldn't expire")
        swap_clients[0].mock_time_offset = (
            swap_clients[0]._expire_message_routes_after + 1
        )
        swap_clients[0].expireMessageRoutes()
        swap_clients[0].mock_time_offset = 0
        message_routes_0 = read_json_api(1800, "messageroutes")
        assert len(message_routes_0) == 2

        for i in range(len(bid_ids)):
            wait_for_bid(
                test_delay_event,
                swap_clients[0],
                bid_ids[i],
                BidStates.SWAP_COMPLETED,
                wait_for=320,
            )
            wait_for_bid(
                test_delay_event,
                swap_clients[1],
                bid_ids[i],
                BidStates.SWAP_COMPLETED,
                sent=True,
                wait_for=320,
            )

        for i in range(3):
            swap_clients[
                i
            ].num_group_simplex_messages_received == num_group_messages_received_before[
                i
            ] + 2
        swap_clients[
            2
        ].num_direct_simplex_messages_received == num_direct_messages_received_before[2]

        message_routes_0 = read_json_api(1800, "messageroutes")
        assert len(message_routes_0) == 2
        message_routes_1 = read_json_api(1801, "messageroutes")
        assert len(message_routes_1) == 2

        logger.info("Test closing routes")
        read_json_api(1800, "messageroutes", {"action": "clear"})

        def waitForNumMessageRoutes(
            port: int = 1800, num_routes: int = 0, num_tries: int = 40
        ):
            logger.info(
                f"Waiting for {num_routes} message route{'s' if num_routes != 1 else ''}, port: {port}."
            )
            for i in range(num_tries):
                test_delay_event.wait(1)
                if test_delay_event.is_set():
                    raise ValueError("Test stopped.")
                message_routes = read_json_api(port, "messageroutes")
                if len(message_routes) == num_routes:
                    return True
            raise ValueError("waitForNumMessageRoutes timed out.")

        waitForNumMessageRoutes(1800, 0)
        waitForNumMessageRoutes(1801, 0)
