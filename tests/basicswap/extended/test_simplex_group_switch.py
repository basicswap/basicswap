#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
SimpleX group switching against a live simplex-chat client (3 nodes).

Requires SimpleX SMP server and simplex-chat binary (see test_simplex.py).

Two host clients each own a group with display name "bsx" (A and B).
All nodes start in group A.  Node 0 is restarted with group_link set to B
on the same SimpleX database, then again with joined_group_link removed
(upgrade from a version without it).  Node 2 is made the owner of its group
and must refuse to switch.

export PYTHONPATH=$(pwd)
pytest -v -s tests/basicswap/extended/test_simplex_group_switch.py
"""

import json
import logging
import os
import random
import shutil
import sys

import basicswap.config as cfg

from basicswap.basicswap import (
    BasicSwap,
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
)
from tests.basicswap.test_xmr import BaseTest, test_delay_event

TEST_DIR = cfg.TEST_DATADIRS

SIMPLEX_SERVER_FINGERPRINT = os.getenv("SIMPLEX_SERVER_FINGERPRINT", "")
SIMPLEX_SERVER_ADDRESS = os.getenv(
    "SIMPLEX_SERVER_ADDRESS",
    f"smp://{SIMPLEX_SERVER_FINGERPRINT}:password@127.0.0.1:5223",
)
SIMPLEX_CLIENT_PATH = os.path.expanduser(os.getenv("SIMPLEX_CLIENT_PATH", ""))

BASE_WS_PORT: int = 5225
HOST_A_WS_PORT: int = 5228
HOST_B_WS_PORT: int = 5229

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def sendCommand(ws_thread, cmd: str):
    sent_id = ws_thread.send_command(cmd)
    return waitForResponse(ws_thread, sent_id, test_delay_event)


def createBsxGroup(ws_thread) -> str:
    response = sendCommand(ws_thread, "/group bsx")
    if getResponseData(response, "type") != "groupCreated":
        raise ValueError(f"Expected groupCreated: {response}")
    for pref in ("voice", "files", "direct", "reactions", "reports"):
        ws_thread.send_command(f"/set {pref} #bsx off")
    ws_thread.send_command("/set disappear #bsx on week")
    response = sendCommand(ws_thread, "/create link #bsx")
    return "https://simplex.chat" + getNewSimplexLink(response)[8:]


def listGroups(ws_port: int) -> list:
    ws_thread = WebSocketThread(f"ws://127.0.0.1:{ws_port}", tag=f"Q{ws_port}")
    ws_thread.start()
    try:
        waitForConnected(ws_thread, test_delay_event)
        return getResponseData(sendCommand(ws_thread, "/groups"), "groups")
    finally:
        ws_thread.stop()
        ws_thread.join()


def drainGroupMessages(ws_thread) -> int:
    num_messages: int = 0
    while True:
        message = ws_thread.queue_get()
        if message is None:
            return num_messages
        num_messages += countGroupItems(message)


def countGroupItems(message: str) -> int:
    data = json.loads(message)
    if getResponseData(data, "type") != "newChatItems":
        return 0
    return sum(
        1
        for chat_item in getResponseData(data, "chatItems")
        if chat_item["chatInfo"]["type"] == "group"
    )


def waitForGroupMessages(ws_thread, wait_for: int = 30) -> int:
    for _ in range(wait_for):
        if test_delay_event.is_set():
            raise ValueError("Test stopped.")
        num_messages: int = drainGroupMessages(ws_thread)
        if num_messages > 0:
            return num_messages
        test_delay_event.wait(1)
    return 0


class StoppedNode:
    # Placeholder in swap_clients while a node is stopped, keeps indices stable.
    def update(self) -> None:
        pass

    def finalise(self) -> None:
        pass


def membershipId(group: dict) -> str:
    # groupId is reused by simplex-chat after a delete, memberId is per membership.
    member_id = group["membership"]["memberId"]
    assert member_id
    return member_id


class TestSimplexGroupSwitch(BaseTest):
    __test__ = True
    start_ltc_nodes = False
    start_xmr_nodes = False
    group_link_a = None
    group_link_b = None
    daemons = []
    host_threads = []

    @classmethod
    def prepareTestDir(cls):
        client_dirs = [
            (os.path.join(TEST_DIR, f"simplex_client{i}"), BASE_WS_PORT + i)
            for i in range(cls.num_nodes)
        ]
        client_dirs.append((os.path.join(TEST_DIR, "simplex_host_a"), HOST_A_WS_PORT))
        client_dirs.append((os.path.join(TEST_DIR, "simplex_host_b"), HOST_B_WS_PORT))
        for client_dir, ws_port in client_dirs:
            if os.path.exists(client_dir):
                shutil.rmtree(client_dir)
            cls.daemons.append(
                startSimplexClient(
                    SIMPLEX_CLIENT_PATH,
                    client_dir,
                    SIMPLEX_SERVER_ADDRESS,
                    ws_port,
                    logger,
                    test_delay_event,
                )
            )

        for tag, ws_port in (("HA", HOST_A_WS_PORT), ("HB", HOST_B_WS_PORT)):
            ws_thread = WebSocketThread(f"ws://127.0.0.1:{ws_port}", tag=tag)
            ws_thread.start()
            waitForConnected(ws_thread, test_delay_event)
            cls.host_threads.append(ws_thread)

        cls.group_link_a = createBsxGroup(cls.host_threads[0])
        cls.group_link_b = createBsxGroup(cls.host_threads[1])
        logger.info(f"Group A link: {cls.group_link_a}")
        logger.info(f"Group B link: {cls.group_link_b}")

    @classmethod
    def tearDownClass(cls):
        logger.info("Finalising Test")
        super().tearDownClass()
        for ws_thread in cls.host_threads:
            ws_thread.stop()
            ws_thread.join()
        stopDaemons(cls.daemons)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["smsg_payload_version"] = 2
        settings["networks"] = [
            {
                "type": "simplex",
                "server_address": SIMPLEX_SERVER_ADDRESS,
                "client_path": SIMPLEX_CLIENT_PATH,
                "ws_port": BASE_WS_PORT + node_id,
                "group_link": cls.group_link_a,
                "enabled": True,
            },
        ]

    # Node restart helpers.  The update thread iterates swap_clients, so remove
    # the client from the list before finalising it.

    @classmethod
    def settingsPath(cls, node_id: int) -> str:
        return os.path.join(TEST_DIR, f"basicswap_{node_id}", cfg.CONFIG_FILENAME)

    @classmethod
    def readSettings(cls, node_id: int) -> dict:
        with open(cls.settingsPath(node_id)) as fp:
            return json.load(fp)

    @classmethod
    def writeSettings(cls, node_id: int, settings: dict) -> None:
        with open(cls.settingsPath(node_id), "w") as fp:
            json.dump(settings, fp, indent=4)

    @classmethod
    def simplexSettings(cls, node_id: int) -> dict:
        for network in cls.readSettings(node_id)["networks"]:
            if network["type"] == "simplex":
                return network
        raise ValueError("No simplex network in settings")

    @classmethod
    def stopNode(cls, node_id: int) -> None:
        logger.info(f"Stopping node {node_id}")
        sc = cls.swap_clients[node_id]
        cls.swap_clients[node_id] = StoppedNode()
        test_delay_event.wait(3)
        sc.finalise()

    @classmethod
    def startNode(cls, node_id: int, insert: bool = True):
        logger.info(f"Starting node {node_id}")
        basicswap_dir = os.path.join(TEST_DIR, f"basicswap_{node_id}")
        sc = BasicSwap(
            basicswap_dir,
            cls.readSettings(node_id),
            "regtest",
            log_name=f"BasicSwap{node_id}",
        )
        sc.setDaemonPID(Coins.BTC, cls.btc_daemons[node_id].handle.pid)
        sc.setDaemonPID(Coins.PART, cls.part_daemons[node_id].handle.pid)
        try:
            sc.start()
        except Exception:
            sc.finalise()
            raise
        if insert:
            cls.swap_clients[node_id] = sc
        return sc

    def countRoutes(self, node_id: int) -> int:
        sc = self.swap_clients[node_id]
        cursor = sc.openDB()
        try:
            return cursor.execute(
                "SELECT COUNT(*) FROM direct_message_routes"
            ).fetchone()[0]
        finally:
            sc.closeDB(cursor)

    def postOffer(self, node_id: int) -> bytes:
        sc = self.swap_clients[node_id]
        ci_from = sc.ci(Coins.BTC)
        ci_to = sc.ci(Coins.PART)
        swap_value = ci_from.make_int(random.uniform(0.2, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        return sc.postOffer(
            Coins.BTC,
            Coins.PART,
            swap_value,
            rate_swap,
            swap_value,
            SwapTypes.XMR_SWAP,
        )

    def test_01_switch_group(self):
        logger.info("---------- Test switching node 0 from group A to group B")
        swap_clients = self.swap_clients

        for i in range(3):
            assert self.simplexSettings(i)["joined_group_link"] == self.group_link_a

        # Trade in group A so node 0 has a populated database.
        offer_id = self.postOffer(0)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id, wait_for=60)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)
        wait_for_bid(
            test_delay_event,
            swap_clients[0],
            bid_id,
            BidStates.BID_RECEIVED,
            wait_for=90,
        )
        routes_before: int = self.countRoutes(0)
        assert routes_before > 0
        logger.info(f"Node 0 direct message routes before switch: {routes_before}")

        self.stopNode(0)
        groups = listGroups(BASE_WS_PORT)
        assert len(groups) == 1
        assert groups[0]["localDisplayName"] == "bsx"
        assert groups[0]["membership"]["memberRole"] != "owner"
        membership_a: str = membershipId(groups[0])

        settings = self.readSettings(0)
        for network in settings["networks"]:
            if network["type"] == "simplex":
                network["group_link"] = self.group_link_b
        self.writeSettings(0, settings)
        self.startNode(0)
        swap_clients = self.swap_clients

        assert self.simplexSettings(0)["joined_group_link"] == self.group_link_b
        assert self.countRoutes(0) == routes_before

        # Offers from node 0 now reach group B only.
        for ws_thread in self.host_threads:
            drainGroupMessages(ws_thread)
        offer_id = self.postOffer(0)
        assert waitForGroupMessages(self.host_threads[1]) > 0
        assert drainGroupMessages(self.host_threads[0]) == 0
        test_delay_event.wait(10)
        assert swap_clients[1].getOffer(offer_id) is None
        assert drainGroupMessages(self.host_threads[0]) == 0

        self.stopNode(0)
        groups = listGroups(BASE_WS_PORT)
        assert len(groups) == 1
        assert groups[0]["localDisplayName"] == "bsx"
        membership_b: str = membershipId(groups[0])
        assert membership_b != membership_a

        # Upgrade case: joined_group_link missing, link unchanged, no rejoin.
        settings = self.readSettings(0)
        for network in settings["networks"]:
            if network["type"] == "simplex":
                del network["joined_group_link"]
        self.writeSettings(0, settings)
        self.startNode(0)
        assert self.simplexSettings(0)["joined_group_link"] == self.group_link_b

        self.stopNode(0)
        groups = listGroups(BASE_WS_PORT)
        assert len(groups) == 1
        assert membershipId(groups[0]) == membership_b
        self.startNode(0)

    def test_02_owner_refuses_switch(self):
        logger.info("---------- Test a node owning its group refuses to switch")

        self.stopNode(2)
        ws_thread = WebSocketThread(f"ws://127.0.0.1:{BASE_WS_PORT + 2}", tag="N2")
        ws_thread.start()
        try:
            waitForConnected(ws_thread, test_delay_event)
            sendCommand(ws_thread, "/leave #bsx")
            sendCommand(ws_thread, "/delete #bsx")
            response = sendCommand(ws_thread, "/group bsx")
            assert getResponseData(response, "type") == "groupCreated"
        finally:
            ws_thread.stop()
            ws_thread.join()

        groups = listGroups(BASE_WS_PORT + 2)
        assert len(groups) == 1
        assert groups[0]["membership"]["memberRole"] == "owner"
        owned_membership: str = membershipId(groups[0])

        settings = self.readSettings(2)
        for network in settings["networks"]:
            if network["type"] == "simplex":
                network["group_link"] = self.group_link_b
        self.writeSettings(2, settings)

        with self.assertRaises(ValueError) as cm:
            self.startNode(2, insert=False)
        assert "owns" in str(cm.exception)

        groups = listGroups(BASE_WS_PORT + 2)
        assert len(groups) == 1
        assert membershipId(groups[0]) == owned_membership
        assert groups[0]["membership"]["memberRole"] == "owner"
        assert self.simplexSettings(2)["joined_group_link"] == self.group_link_a

        # Restore the link so the node starts again for teardown.
        settings = self.readSettings(2)
        for network in settings["networks"]:
            if network["type"] == "simplex":
                network["group_link"] = self.group_link_a
        self.writeSettings(2, settings)
        self.startNode(2)
