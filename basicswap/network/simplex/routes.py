# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json

from basicswap.basicswap_util import (
    ConnectionRequestTypes,
    MessageNetworks,
    MessageTypes,
)
from basicswap.db import Concepts, DirectMessageRoute, DirectMessageRouteLink
from basicswap.messages_npb import ConnectReqMessage
from basicswap.network.simplex.simplex import (
    createSimplexConnectInvitation,
    getResponseData,
    sendSimplexMsg,
)
from basicswap.util import ensure


def prepareSimplexMessageRoute(
    self,
    net_i,
    req_data,
    addr_from: str,
    addr_to: str,
    cursor,
    valid_for_seconds,
    message_nets,
) -> (int, bool):
    message_route = self.getMessageRoute(
        MessageNetworks.SIMPLEX, addr_from, addr_to, cursor=cursor
    )
    if message_route:
        is_active: bool = message_route.active_ind == 1
        self.log.debug(
            f"{'Using active' if is_active else 'Waiting for'} message route: {message_route}"
        )
        return message_route.record_id, is_active

    connReqInvitation, pccConnId = createSimplexConnectInvitation(
        net_i, self.delay_event, logger=self.log
    )
    req_data["bsx_address"] = addr_from
    req_data["connection_req"] = connReqInvitation

    msg_buf = ConnectReqMessage()
    msg_buf.network_type = MessageNetworks.SIMPLEX
    msg_buf.network_data = b"bsx"
    msg_buf.request_type = ConnectionRequestTypes.BID
    msg_buf.request_data = json.dumps(req_data).encode("UTF-8")

    bid_bytes = msg_buf.to_bytes()
    payload_hex = str.format("{:02x}", MessageTypes.CONNECT_REQ) + bid_bytes.hex()

    msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
    connect_req_msgid = self.sendMessage(
        addr_from,
        addr_to,
        payload_hex,
        msg_valid,
        cursor,
        message_nets=message_nets,
    )

    now: int = self.getTime()
    message_route = DirectMessageRoute(
        active_ind=2,
        network_id=MessageNetworks.SIMPLEX,
        linked_type=Concepts.OFFER,
        smsg_addr_local=addr_from,
        smsg_addr_remote=addr_to,
        route_data=json.dumps(
            {
                "connection_req": connReqInvitation,
                "connect_req_msgid": connect_req_msgid.hex(),
                "pccConnId": pccConnId,
            }
        ).encode("UTF-8"),
        created_at=now,
    )
    message_route_id = self.add(message_route, cursor)

    self.log.info(f"Sent CONNECT_REQ {self.logIDB(connect_req_msgid)}")
    return message_route_id, False


def processSimplexConnectRequest(self, net_i, req_data, offer, cursor) -> None:
    offer_id = offer.offer_id
    bidder_addr = req_data["bsx_address"]

    self.log.debug(
        f"Opening direct message route from {offer.addr_from} to {bidder_addr}"
    )
    message_route = self.getMessageRoute(2, bidder_addr, offer.addr_from, cursor=cursor)
    if message_route:
        raise ValueError("Direct message route already exists")

    connReqInvitation = req_data["connection_req"]
    ensure(isinstance(connReqInvitation, str), "Invalid connection request type")
    ensure(0 < len(connReqInvitation) <= 4096, "Invalid connection request length")
    ensure(
        all(33 <= ord(c) <= 126 for c in connReqInvitation),
        "Invalid characters in connection request",
    )

    self.checkConnectRequestRateLimit(int(MessageNetworks.SIMPLEX))

    cmd_id = net_i.send_command(f"/connect {connReqInvitation}")
    response = net_i.wait_for_command_response(cmd_id)
    pccConnId = getResponseData(response, "connection")["pccConnId"]

    now: int = self.getTime()
    message_route = DirectMessageRoute(
        active_ind=2,
        network_id=2,
        linked_type=Concepts.OFFER,
        smsg_addr_local=offer.addr_from,
        smsg_addr_remote=bidder_addr,
        route_data=json.dumps(
            {"connection_req": connReqInvitation, "pccConnId": pccConnId}
        ).encode("UTF-8"),
        created_at=now,
    )
    message_route_id = self.add(message_route, cursor)

    message_route_link = DirectMessageRouteLink(
        active_ind=1,
        direct_message_route_id=message_route_id,
        linked_type=Concepts.OFFER,
        linked_id=offer_id,
        created_at=now,
    )
    self.add(message_route_link, cursor)


def sendSimplexRouteMsg(
    self,
    message_route,
    addr_from: str,
    addr_to: str,
    payload_hex: str,
    msg_valid: int,
    cursor,
    timestamp,
    deterministic,
) -> bytes:
    network = self.getActiveNetwork(MessageNetworks.SIMPLEX)
    net_i = network["ws_thread"]

    remote_name = None
    route_data = json.loads(message_route.route_data.decode("UTF-8"))
    if "localDisplayName" in route_data:
        remote_name = route_data["localDisplayName"]
    else:
        pccConnId = route_data["pccConnId"]
        self.log.debug(f"Finding name for Simplex chat, ID: {pccConnId}")
        cmd_id = net_i.send_command("/chats")
        response = net_i.wait_for_command_response(cmd_id)
        for chat in getResponseData(response, "chats"):
            if (
                "chatInfo" not in chat
                or "type" not in chat["chatInfo"]
                or chat["chatInfo"]["type"] != "direct"
            ):
                continue
            try:
                if chat["chatInfo"]["contact"]["activeConn"]["connId"] == pccConnId:
                    remote_name = chat["chatInfo"]["contact"]["localDisplayName"]
                    break
            except Exception as e:
                self.log.debug(f"Error parsing chat: {e}")

    if remote_name is None:
        raise RuntimeError(
            f"Unable to find remote name for simplex direct chat, pccConnId: {pccConnId}"
        )

    message_id = sendSimplexMsg(
        self,
        network,
        addr_from,
        addr_to,
        bytes.fromhex(payload_hex),
        msg_valid,
        cursor,
        timestamp,
        deterministic,
        to_user_name=remote_name,
    )
    return message_id
