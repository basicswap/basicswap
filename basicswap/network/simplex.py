#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import json
import logging
import threading
import traceback
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
from basicswap.util import ensure, TemporaryError
from basicswap.util.address import (
    decodeWif,
)
from basicswap.basicswap_util import AddressTypes

# The websocket library logs every connection error to its own logger,
# duplicating the on_error callbacks.
logging.getLogger("websocket").setLevel(logging.CRITICAL)


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def decode_base64(encoded_data: str) -> bytes:
    return base64.b64decode(encoded_data)


class WebSocketThread(threading.Thread):
    def __init__(self, url: str, tag: str = None, logger=None, shutdown_event=None):
        super().__init__()
        self.url: str = url
        self.tag = tag
        self.logger = logger
        self.shutdown_event = shutdown_event
        self.ws = None
        self.mutex = threading.Lock()
        self.corrId: int = 0
        self.connected: bool = False
        self.delay_event = threading.Event()

        self.recv_queue = Queue()
        self.cmd_recv_queue = Queue()
        self.delayed_events_queue = Queue()

        self.ignore_events: bool = False

        self.num_messages_received: int = 0
        self.last_error_str: str = ""
        self._stopping: bool = False

    def _should_stop(self) -> bool:
        if self._stopping or self.delay_event.is_set():
            return True
        if self.shutdown_event is not None and self.shutdown_event.is_set():
            return True
        return False

    def disable_debug_mode(self):
        self.ignore_events = False
        for i in range(100):
            try:
                message = self.delayed_events_queue.get(block=False)
            except Empty:
                break
            self.recv_queue.put(message)

    def on_message(self, ws, message):
        if self.logger:
            self.logger.debug("Simplex received msg")
        else:
            print(f"{self.tag} - Received msg")

        if message.startswith('{"corrId"'):
            self.cmd_recv_queue.put(message)
        else:
            self.num_messages_received += 1
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
        if self._should_stop():
            return
        error_str = str(error)
        repeated: bool = error_str == self.last_error_str
        self.last_error_str = error_str
        if self.logger:
            log_func = self.logger.debug if repeated else self.logger.error
            log_func(f"Simplex ws - {error}")
        else:
            print(f"{self.tag} - Error: {error}")

    def on_close(self, ws, close_status_code, close_msg):
        was_connected: bool = self.connected
        self.connected = False
        if self._should_stop():
            return
        if self.logger:
            log_func = self.logger.info if was_connected else self.logger.debug
            log_func(f"Simplex ws - Closed: {close_status_code}, {close_msg}")
        else:
            print(f"{self.tag} - Closed: {close_status_code}, {close_msg}")

    def on_open(self, ws):
        if self.logger:
            self.logger.info("Simplex ws - Connection opened")
        else:
            print(f"{self.tag}: WebSocket connection opened")
        self.connected = True
        self.last_error_str = ""

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

    def wait_for_command_response(self, cmd_id, num_tries: int = 200):
        cmd_id = str(cmd_id)
        for i in range(num_tries):
            message = self.cmd_queue_get()
            if message is not None:
                data = json.loads(message)
                if "corrId" in data:
                    if data["corrId"] == cmd_id:
                        return data
            self.delay_event.wait(0.5)
        raise ValueError(
            f"wait_for_command_response timed-out waiting for ID: {cmd_id}"
        )

    def run(self):
        self.ws = websocket.WebSocketApp(
            self.url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_open=self.on_open,
            on_close=self.on_close,
        )
        while not self._should_stop():
            self.ws.run_forever()
            if self._should_stop():
                break
            self.delay_event.wait(0.5)

    def stop(self):
        if self._stopping:
            return
        self._stopping = True
        self.delay_event.set()
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass


def waitForResponse(ws_thread, sent_id, delay_event):
    sent_id = str(sent_id)
    for i in range(200):
        message = ws_thread.cmd_queue_get()
        if message is not None:
            data = json.loads(message)
            if "corrId" in data:
                if data["corrId"] == sent_id:
                    return data
        delay_event.wait(0.5)
    raise ValueError(f"waitForResponse timed-out waiting for ID: {sent_id}")


def waitForConnected(ws_thread, delay_event):
    for i in range(100):
        if ws_thread.connected:
            return True
        delay_event.wait(0.5)
    raise ValueError("waitForConnected timed-out.")


def encryptMsg(
    self,
    addr_from: str,
    addr_to: str,
    payload: bytes,
    msg_valid: int,
    cursor,
    timestamp=None,
    deterministic=False,
    difficulty_target=0x1EFFFFFF,
    pubkey_to: bytes = None,
) -> bytes:
    self.log.debug("encryptMsg")

    if pubkey_to is None:
        pubkey_to = self.getPubkeyForAddress(cursor, addr_to)
    privkey_from = self.getPrivkeyForAddress(cursor, addr_from)

    payload_format: int = 2
    smsg_msg: bytes = smsgEncrypt(
        privkey_from,
        pubkey_to,
        payload,
        timestamp,
        deterministic,
        payload_format,
        msg_valid,
        difficulty_target=difficulty_target,
    )

    return smsg_msg


def sendSimplexMsg(
    self,
    network,
    addr_from: str,
    addr_to: str,
    payload: bytes,
    msg_valid: int,
    cursor,
    timestamp: int = None,
    deterministic: bool = False,
    to_user_name: str = None,
    return_msg: bool = False,
    difficulty_target=0x1EFFFFFF,
) -> bytes:
    self.log.debug("sendSimplexMsg")

    smsg_msg: bytes = encryptMsg(
        self,
        addr_from,
        addr_to,
        payload,
        msg_valid,
        cursor,
        timestamp,
        deterministic,
        difficulty_target,
    )
    smsg_id = smsgGetID(smsg_msg)

    ws_thread = network["ws_thread"]
    if to_user_name is not None:
        to = "@" + to_user_name + " "
    else:
        to = "#bsx "
    sent_id = ws_thread.send_command(to + encode_base64(smsg_msg))
    response = waitForResponse(ws_thread, sent_id, self.delay_event)
    if getResponseData(response, "type") != "newChatItems":
        json_str = json.dumps(response, indent=4)
        self.log.debug(f"Response {json_str}")
        raise ValueError("Send failed")
    if to_user_name is not None:
        self.num_direct_simplex_messages_sent += 1
    else:
        self.num_group_simplex_messages_sent += 1

    if return_msg:
        return smsg_id, smsg_msg
    return smsg_id


def forwardSimplexMsg(self, network, smsg_msg, to_user_name: str = None):
    smsg_id = smsgGetID(smsg_msg)
    ws_thread = network["ws_thread"]
    if to_user_name is not None:
        to = "@" + to_user_name + " "
    else:
        to = "#bsx "
    sent_id = ws_thread.send_command(to + encode_base64(smsg_msg))
    response = waitForResponse(ws_thread, sent_id, self.delay_event)
    if getResponseData(response, "type") != "newChatItems":
        json_str = json.dumps(response, indent=4)
        self.log.debug(f"Response {json_str}")
        raise ValueError("Send failed")
    if to_user_name is not None:
        self.num_direct_simplex_messages_sent += 1
    else:
        self.num_group_simplex_messages_sent += 1

    return smsg_id


def decryptSimplexMsg(self, msg_data):
    ci_part = self.ci(Coins.PART)

    # Try with the network key first
    network_key: bytes = decodeWif(self.network_key)
    try:
        decrypted = smsgDecrypt(network_key, msg_data, output_dict=True)
        decrypted["from"] = ci_part.pubkey_to_address(
            bytes.fromhex(decrypted["pubkey_from"])
        )
        decrypted["to"] = self.network_addr
        decrypted["msg_net"] = "simplex"
        return decrypted
    except Exception as e:  # noqa: F841
        pass

    # Try with all active bid/offer addresses
    query: str = """SELECT DISTINCT address FROM (
        SELECT b.bid_addr AS address FROM bids b
               JOIN bidstates s ON b.state = s.state_id
               WHERE b.active_ind = 1
                     AND (s.in_progress OR (s.swap_ended = 0 AND b.expire_at > :now))
        UNION
        SELECT addr_from AS address FROM offers WHERE active_ind = 1 AND expire_at > :now
        UNION
        SELECT addr AS address FROM smsgaddresses
               WHERE active_ind = 1 AND use_type IN (
                   :local_portal, :bid, :offer, :recv_offer, :send_offer)
        )"""

    now: int = self.getTime()

    try:
        cursor = self.openDB()
        addr_rows = cursor.execute(
            query,
            {
                "now": now,
                "local_portal": AddressTypes.PORTAL_LOCAL,
                "bid": AddressTypes.BID,
                "offer": AddressTypes.OFFER,
                "recv_offer": AddressTypes.RECV_OFFER,
                "send_offer": AddressTypes.SEND_OFFER,
            },
        ).fetchall()
        decrypted = None
        for row in addr_rows:
            addr = row[0]
            try:
                vk_addr = self.getPrivkeyForAddress(cursor, addr)
                decrypted = smsgDecrypt(vk_addr, msg_data, output_dict=True)
                decrypted["from"] = ci_part.pubkey_to_address(
                    bytes.fromhex(decrypted["pubkey_from"])
                )
                decrypted["to"] = addr
                decrypted["msg_net"] = "simplex"
                return decrypted
            except Exception as e:  # noqa: F841
                pass
    finally:
        self.closeDB(cursor, commit=False)

    return decrypted


def parseSimplexMsg(self, chat_item):
    item_status = chat_item["chatItem"]["meta"]["itemStatus"]
    dir_type = item_status["type"]
    if dir_type not in ("sndRcvd", "rcvNew"):
        return None

    snd_progress = item_status.get("sndProgress", None)
    if snd_progress and snd_progress != "complete":
        item_id = chat_item["chatItem"]["meta"]["itemId"]
        self.log.debug(f"simplex chat item {item_id} {snd_progress}")
        return None

    conn_id = None
    msg_dir: str = "recv" if dir_type == "rcvNew" else "sent"
    chat_type: str = chat_item["chatInfo"]["type"]
    if chat_type == "group":
        chat_name = chat_item["chatInfo"]["groupInfo"]["localDisplayName"]
        conn_id = chat_item["chatInfo"]["groupInfo"]["groupId"]
        self.num_group_simplex_messages_received += 1
    elif chat_type == "direct":
        chat_name = chat_item["chatInfo"]["contact"]["localDisplayName"]
        conn_id = chat_item["chatInfo"]["contact"]["activeConn"]["connId"]
        self.num_direct_simplex_messages_received += 1
    else:
        return None

    msg_content = chat_item["chatItem"]["content"]["msgContent"]["text"]
    try:
        msg_data: bytes = decode_base64(msg_content)
        decrypted_msg = decryptSimplexMsg(self, msg_data)
        if decrypted_msg is None:
            return None
        decrypted_msg["chat_type"] = chat_type
        decrypted_msg["chat_name"] = chat_name
        decrypted_msg["conn_id"] = conn_id
        decrypted_msg["msg_dir"] = msg_dir
        return decrypted_msg
    except Exception as e:  # noqa: F841
        # self.log.debug(f"decryptSimplexMsg error: {e}")
        pass
    return None


def processEvent(self, ws_thread, msg_type: str, data) -> bool:
    if ws_thread.ignore_events:
        if msg_type not in ("contactConnected", "contactDeletedByContact"):
            return False
        ws_thread.delayed_events_queue.put(json.dumps(data))
        return True

    if msg_type == "contactConnected":
        self.processContactConnected(data)
    elif msg_type == "contactDeletedByContact":
        self.processContactDisconnected(data)
    else:
        return False
    return True


def readSimplexMsgs(self, network):
    ws_thread = network["ws_thread"]
    for i in range(100):
        message = ws_thread.queue_get()
        if message is None:
            break
        if self.delay_event.is_set():
            break

        data = json.loads(message)
        # self.log.debug(f"Message: {json.dumps(data, indent=4)}")
        try:
            msg_type: str = getResponseData(data, "type")
            if msg_type in ("chatItemsStatusesUpdated", "newChatItems"):
                for chat_item in getResponseData(data, "chatItems"):
                    decrypted_msg = parseSimplexMsg(self, chat_item)
                    if decrypted_msg is None:
                        continue
                    self.processMsg(decrypted_msg)
            elif msg_type == "chatError":
                # self.log.debug(f"chatError Message: {json.dumps(data, indent=4)}")
                pass
            elif processEvent(self, ws_thread, msg_type, data):
                pass
            else:
                self.log.debug(f"simplex: Unknown msg_type: {msg_type}")
                # self.log.debug(f"Message: {json.dumps(data, indent=4)}")
        except Exception as e:
            self.log.debug(f"readSimplexMsgs error: {e}")
            if self.debug:
                self.log.error(traceback.format_exc())

        self.delay_event.wait(0.05)


def getResponseData(data, tag=None):
    for pretag in ("Right", "Left"):
        if pretag in data["resp"]:
            if tag:
                return data["resp"][pretag][tag]
            return data["resp"][pretag]
    if tag:
        return data["resp"][tag]
    return data["resp"]


def getNewSimplexLink(data):
    return getResponseData(data)["connLinkContact"]["connFullLink"]


def formatSimplexChatError(chat_error) -> str:
    if not chat_error:
        return "unknown error"
    error_type = chat_error.get("errorType")
    if isinstance(error_type, dict):
        if error_type.get("message"):
            return error_type["message"]
        if error_type.get("type"):
            return error_type["type"]
    agent_error = chat_error.get("agentError")
    if isinstance(agent_error, dict):
        broker_err = agent_error.get("brokerErr")
        if isinstance(broker_err, dict):
            network_error = broker_err.get("networkError")
            if isinstance(network_error, dict):
                if network_error.get("connectError"):
                    return network_error["connectError"]
                if network_error.get("type"):
                    return network_error["type"]
            if broker_err.get("type"):
                return broker_err["type"]
        if agent_error.get("brokerAddress"):
            return "{} ({})".format(
                agent_error.get("type", "agent error"), agent_error["brokerAddress"]
            )
        if agent_error.get("type"):
            return agent_error["type"]
    if chat_error.get("type"):
        return chat_error["type"]
    return json.dumps(chat_error)


def getJoinedSimplexLink(data):
    response_data = getResponseData(data)
    # SimpleX responds with connLinkInvitation for one-time invitations
    # and connLinkContact for contact addresses.
    for link_tag in ("connLinkInvitation", "connLinkContact"):
        if link_tag in response_data:
            return response_data[link_tag]["connFullLink"]
    resp_type = response_data.get("type", "unknown")
    if resp_type == "chatCmdError":
        detail = formatSimplexChatError(response_data.get("chatError"))
        raise TemporaryError("SimpleX /connect failed: {}".format(detail))
    raise ValueError("Unexpected SimpleX response type: {}".format(resp_type))


def createSimplexConnectInvitation(
    ws_thread, delay_event, logger=None, num_tries: int = 3
):
    last_error = None
    for attempt in range(num_tries):
        cmd_id = ws_thread.send_command("/connect")
        response = ws_thread.wait_for_command_response(cmd_id)
        try:
            conn_link = getJoinedSimplexLink(response)
            pccConnId = getResponseData(response, "connection")["pccConnId"]
            return conn_link, pccConnId
        except TemporaryError as ex:
            last_error = ex
            if logger:
                logger.warning(
                    "SimpleX /connect failed (attempt {}/{}): {}".format(
                        attempt + 1, num_tries, ex
                    )
                )
            if attempt + 1 < num_tries:
                delay_event.wait(2.0)
    raise last_error


def initialiseSimplexNetwork(self, network_config) -> None:
    self.log.debug("initialiseSimplexNetwork")

    client_host: str = network_config.get("client_host", "127.0.0.1")
    ws_port: str = network_config.get("ws_port")

    ws_thread = WebSocketThread(
        f"ws://{client_host}:{ws_port}",
        logger=self.log,
        shutdown_event=self.delay_event,
    )
    self.threads.append(ws_thread)
    ws_thread.start()
    waitForConnected(ws_thread, self.delay_event)

    sent_id = ws_thread.send_command("/groups")
    response = waitForResponse(ws_thread, sent_id, self.delay_event)

    if len(getResponseData(response, "groups")) < 1:
        sent_id = ws_thread.send_command("/c " + network_config["group_link"])
        response = waitForResponse(ws_thread, sent_id, self.delay_event)
        ensure(
            "groupLinkId" in getResponseData(response, "connection"),
            "Missing groupLinkId",
        )

    add_network = {
        "type": "simplex",
        "ws_thread": ws_thread,
    }
    if "bridged" in network_config:
        add_network["bridged"] = network_config["bridged"]

    self.active_networks.append(add_network)


def closeSimplexChat(self, net_i, connId) -> bool:
    try:
        cmd_id = net_i.send_command("/chats")
        response = net_i.wait_for_command_response(cmd_id, num_tries=500)
        remote_name = None
        for chat in getResponseData(response, "chats"):
            if (
                "chatInfo" not in chat
                or "type" not in chat["chatInfo"]
                or chat["chatInfo"]["type"] != "direct"
            ):
                continue
            try:
                if chat["chatInfo"]["contact"]["activeConn"]["connId"] == connId:
                    remote_name = chat["chatInfo"]["contact"]["localDisplayName"]
                    break
            except Exception as e:
                self.log.debug(f"Error parsing chat: {e}")

        if remote_name is None:
            self.log.warning(
                f"Unable to find remote name for simplex direct chat, ID: {connId}"
            )
            return False

        self.log.debug(f"Deleting simplex chat @{remote_name}, connID {connId}")
        cmd_id = net_i.send_command(f"/delete @{remote_name}")
        cmd_response = net_i.wait_for_command_response(cmd_id)

        if getResponseData(cmd_response, "type") != "contactDeleted":
            self.log.warning(f"Failed to delete simplex chat, ID: {connId}")
            self.log.debug(
                "cmd_response: {}".format(json.dumps(cmd_response, indent=4))
            )
            return False
    except Exception as e:
        self.log.warning(f"Error deleting simplex chat, ID: {connId} - {e}")
        return False
    return True
