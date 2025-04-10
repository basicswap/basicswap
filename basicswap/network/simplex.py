#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import json
import threading
import websocket


from queue import Queue, Empty

from basicswap.util.smsg import (
    smsgEncrypt,
    smsgDecrypt,
    smsgGetID,
)
from basicswap.chainparams import (
    Coins,
)
from basicswap.util.address import (
    b58decode,
    decodeWif,
)
from basicswap.basicswap_util import (
    BidStates,
)


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def decode_base64(encoded_data: str) -> bytes:
    return base64.b64decode(encoded_data)


class WebSocketThread(threading.Thread):
    def __init__(self, url: str, tag: str = None, logger=None):
        super().__init__()
        self.url: str = url
        self.tag = tag
        self.logger = logger
        self.ws = None
        self.mutex = threading.Lock()
        self.corrId: int = 0
        self.connected: bool = False
        self.delay_event = threading.Event()

        self.recv_queue = Queue()
        self.cmd_recv_queue = Queue()

    def on_message(self, ws, message):
        if self.logger:
            self.logger.debug("Simplex received msg")
        else:
            print(f"{self.tag} - Received msg")

        if message.startswith('{"corrId"'):
            self.cmd_recv_queue.put(message)
        else:
            self.recv_queue.put(message)

    def queue_get(self):
        try:
            return self.recv_queue.get(block=False)
        except Empty:
            return None

    def cmd_queue_get(self):
        try:
            return self.cmd_recv_queue.get(block=False)
        except Empty:
            return None

    def on_error(self, ws, error):
        if self.logger:
            self.logger.error(f"Simplex ws - {error}")
        else:
            print(f"{self.tag} - Error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        if self.logger:
            self.logger.info(f"Simplex ws - Closed: {close_status_code}, {close_msg}")
        else:
            print(f"{self.tag} - Closed: {close_status_code}, {close_msg}")

    def on_open(self, ws):
        if self.logger:
            self.logger.info("Simplex ws - Connection opened")
        else:
            print(f"{self.tag}: WebSocket connection opened")
        self.connected = True

    def send_command(self, cmd_str: str):
        with self.mutex:
            self.corrId += 1
            if self.logger:
                self.logger.debug(f"Simplex sent command {self.corrId}")
            else:
                print(f"{self.tag}: sent command {self.corrId}")
            cmd = json.dumps({"corrId": str(self.corrId), "cmd": cmd_str})
            self.ws.send(cmd)
            return self.corrId

    def run(self):
        self.ws = websocket.WebSocketApp(
            self.url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_open=self.on_open,
            on_close=self.on_close,
        )
        while not self.delay_event.is_set():
            self.ws.run_forever()
            self.delay_event.wait(0.5)

    def stop(self):
        self.delay_event.set()
        if self.ws:
            self.ws.close()


def waitForResponse(ws_thread, sent_id, delay_event):
    sent_id = str(sent_id)
    for i in range(100):
        message = ws_thread.cmd_queue_get()
        if message is not None:
            data = json.loads(message)
            # print(f"json: {json.dumps(data, indent=4)}")
            if "corrId" in data:
                if data["corrId"] == sent_id:
                    return data
        delay_event.wait(0.5)
    raise ValueError(f"waitForResponse timed-out waiting for id: {sent_id}")


def waitForConnected(ws_thread, delay_event):
    for i in range(100):
        if ws_thread.connected:
            return True
        delay_event.wait(0.5)
    raise ValueError("waitForConnected timed-out.")


def getPrivkeyForAddress(self, addr) -> bytes:

    ci_part = self.ci(Coins.PART)
    try:
        return ci_part.decodeKey(
            self.callrpc(
                "smsgdumpprivkey",
                [
                    addr,
                ],
            )
        )
    except Exception as e:  # noqa: F841
        pass
    try:
        return ci_part.decodeKey(
            ci_part.rpc_wallet(
                "dumpprivkey",
                [
                    addr,
                ],
            )
        )
    except Exception as e:  # noqa: F841
        pass
    raise ValueError("key not found")


def sendSimplexMsg(
    self, network, addr_from: str, addr_to: str, payload: bytes, msg_valid: int, cursor
) -> bytes:
    self.log.debug("sendSimplexMsg")

    try:
        rv = self.callrpc(
            "smsggetpubkey",
            [
                addr_to,
            ],
        )
        pubkey_to: bytes = b58decode(rv["publickey"])
    except Exception as e:  # noqa: F841
        use_cursor = self.openDB(cursor)
        try:
            query: str = "SELECT pk_from FROM offers WHERE addr_from = :addr_to LIMIT 1"
            rows = use_cursor.execute(query, {"addr_to": addr_to}).fetchall()
            if len(rows) > 0:
                pubkey_to = rows[0][0]
            else:
                query: str = (
                    "SELECT pk_bid_addr FROM bids WHERE bid_addr = :addr_to LIMIT 1"
                )
                rows = use_cursor.execute(query, {"addr_to": addr_to}).fetchall()
                if len(rows) > 0:
                    pubkey_to = rows[0][0]
                else:
                    raise ValueError(f"Could not get public key for address {addr_to}")
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    privkey_from = getPrivkeyForAddress(self, addr_from)

    payload += bytes((0,))  # Include null byte to match smsg
    smsg_msg: bytes = smsgEncrypt(privkey_from, pubkey_to, payload)

    smsg_id = smsgGetID(smsg_msg)

    ws_thread = network["ws_thread"]
    sent_id = ws_thread.send_command("#bsx " + encode_base64(smsg_msg))
    response = waitForResponse(ws_thread, sent_id, self.delay_event)
    if response["resp"]["type"] != "newChatItems":
        json_str = json.dumps(response, indent=4)
        self.log.debug(f"Response {json_str}")
        raise ValueError("Send failed")

    return smsg_id


def decryptSimplexMsg(self, msg_data):
    ci_part = self.ci(Coins.PART)

    # Try with the network key first
    network_key: bytes = decodeWif(self.network_key)
    try:
        decrypted = smsgDecrypt(network_key, msg_data, output_dict=True)
        decrypted["from"] = ci_part.pubkey_to_address(
            bytes.fromhex(decrypted["pk_from"])
        )
        decrypted["to"] = self.network_addr
        decrypted["msg_net"] = "simplex"
        return decrypted
    except Exception as e:  # noqa: F841
        pass

    # Try with all active bid/offer addresses
    query: str = """SELECT DISTINCT address FROM (
        SELECT bid_addr AS address FROM bids WHERE active_ind = 1
               AND (in_progress = 1 OR (state > :bid_received AND state < :bid_completed) OR (state IN (:bid_received, :bid_sent) AND expire_at > :now))
        UNION
        SELECT addr_from AS address FROM offers WHERE active_ind = 1 AND expire_at > :now
        )"""

    now: int = self.getTime()

    try:
        cursor = self.openDB()
        addr_rows = cursor.execute(
            query,
            {
                "bid_received": int(BidStates.BID_RECEIVED),
                "bid_completed": int(BidStates.SWAP_COMPLETED),
                "bid_sent": int(BidStates.BID_SENT),
                "now": now,
            },
        ).fetchall()
    finally:
        self.closeDB(cursor, commit=False)

    decrypted = None
    for row in addr_rows:
        addr = row[0]
        try:
            vk_addr = getPrivkeyForAddress(self, addr)
            decrypted = smsgDecrypt(vk_addr, msg_data, output_dict=True)
            decrypted["from"] = ci_part.pubkey_to_address(
                bytes.fromhex(decrypted["pk_from"])
            )
            decrypted["to"] = addr
            decrypted["msg_net"] = "simplex"
            return decrypted
        except Exception as e:  # noqa: F841
            pass

    return decrypted


def readSimplexMsgs(self, network):
    ws_thread = network["ws_thread"]

    for i in range(100):
        message = ws_thread.queue_get()
        if message is None:
            break

        data = json.loads(message)
        # self.log.debug(f"message 1: {json.dumps(data, indent=4)}")
        try:
            if data["resp"]["type"] in ("chatItemsStatusesUpdated", "newChatItems"):
                for chat_item in data["resp"]["chatItems"]:
                    item_status = chat_item["chatItem"]["meta"]["itemStatus"]
                    if item_status["type"] in ("sndRcvd", "rcvNew"):
                        snd_progress = item_status.get("sndProgress", None)
                        if snd_progress:
                            if snd_progress != "complete":
                                item_id = chat_item["chatItem"]["meta"]["itemId"]
                                self.log.debug(
                                    f"simplex chat item {item_id} {snd_progress}"
                                )
                                continue
                        try:
                            msg_data: bytes = decode_base64(
                                chat_item["chatItem"]["content"]["msgContent"]["text"]
                            )
                            decrypted_msg = decryptSimplexMsg(self, msg_data)
                            if decrypted_msg is None:
                                continue
                            self.processMsg(decrypted_msg)
                        except Exception as e:  # noqa: F841
                            # self.log.debug(f"decryptSimplexMsg error: {e}")
                            pass
        except Exception as e:
            self.log.debug(f"readSimplexMsgs error: {e}")

        self.delay_event.wait(0.05)


def initialiseSimplexNetwork(self, network_config) -> None:
    self.log.debug("initialiseSimplexNetwork")

    client_host: str = network_config.get("client_host", "127.0.0.1")
    ws_port: str = network_config.get("ws_port")

    ws_thread = WebSocketThread(f"ws://{client_host}:{ws_port}", logger=self.log)
    self.threads.append(ws_thread)
    ws_thread.start()
    waitForConnected(ws_thread, self.delay_event)

    sent_id = ws_thread.send_command("/groups")
    response = waitForResponse(ws_thread, sent_id, self.delay_event)

    if len(response["resp"]["groups"]) < 1:
        sent_id = ws_thread.send_command("/c " + network_config["group_link"])
        response = waitForResponse(ws_thread, sent_id, self.delay_event)
        assert "groupLinkId" in response["resp"]["connection"]

    network = {
        "type": "simplex",
        "ws_thread": ws_thread,
    }

    self.active_networks.append(network)
