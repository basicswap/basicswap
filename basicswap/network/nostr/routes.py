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
from basicswap.network.nostr.nostr import newNostrRouteKey, sendNostrMsg
from basicswap.network.util import getMsgPubkey
from basicswap.util import ensure


def prepareNostrMessageRoute(
    self,
    net_i,
    req_data,
    addr_from: str,
    addr_to: str,
    cursor,
    valid_for_seconds,
    message_nets,
) -> (int, bool):
    # Each route has its own signing key so relays can't link swaps to the node key
    message_route = self.getMessageRoute(
        int(MessageNetworks.NOSTR), addr_from, addr_to, cursor=cursor
    )
    if message_route:
        if message_route.active_ind == 1:
            self.log.debug(f"Using active message route: {message_route}")
            return message_route.record_id, True
        route_data = json.loads(message_route.route_data.decode("UTF-8"))
        if not resendNostrConnectReq(
            self,
            message_route.record_id,
            message_route.created_at,
            addr_from,
            addr_to,
            route_data,
            cursor,
        ):
            self.log.debug(f"Waiting for message route: {message_route}")
        return message_route.record_id, False

    route_privkey_hex, route_pubkey = newNostrRouteKey()

    req_data["bsx_address"] = addr_from
    req_data["nostr_pubkey"] = route_pubkey
    now: int = self.getTime()
    msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
    route_data = {
        "local_pubkey": route_pubkey,
        "local_privkey": route_privkey_hex,
        "connect_req_data": req_data,
        "connect_req_valid": msg_valid,
        "connect_req_message_nets": message_nets,
        "connect_req_sent_at": now,
        "connect_req_attempts": 1,
    }

    connect_req_msgid = sendNostrConnectReq(
        self, addr_from, addr_to, route_data, cursor
    )
    route_data["connect_req_msgid"] = connect_req_msgid.hex()

    message_route = DirectMessageRoute(
        active_ind=2,
        network_id=int(MessageNetworks.NOSTR),
        linked_type=Concepts.OFFER,
        smsg_addr_local=addr_from,
        smsg_addr_remote=addr_to,
        route_data=json.dumps(route_data).encode("UTF-8"),
        created_at=now,
    )
    message_route_id = self.add(message_route, cursor)

    self.log.info(f"Sent CONNECT_REQ {self.logIDB(connect_req_msgid)}")
    return message_route_id, False


def sendNostrConnectReq(
    self, addr_from: str, addr_to: str, route_data: dict, cursor
) -> bytes:
    msg_buf = ConnectReqMessage()
    msg_buf.network_type = int(MessageNetworks.NOSTR)
    msg_buf.network_data = b"bsx"
    msg_buf.request_type = ConnectionRequestTypes.BID
    msg_buf.request_data = json.dumps(route_data["connect_req_data"]).encode("UTF-8")
    payload_hex = (
        str.format("{:02x}", MessageTypes.CONNECT_REQ) + msg_buf.to_bytes().hex()
    )
    return self.sendMessage(
        addr_from,
        addr_to,
        payload_hex,
        int(route_data.get("connect_req_valid", self.SMSG_SECONDS_IN_HOUR)),
        cursor,
        message_nets=route_data.get("connect_req_message_nets", "nostr"),
        sign_privkey=bytes.fromhex(route_data["local_privkey"]),
    )


def resendNostrConnectReq(
    self,
    route_id: int,
    created_at: int,
    addr_from: str,
    addr_to: str,
    route_data: dict,
    cursor,
) -> bool:
    attempts: int = int(route_data.get("connect_req_attempts", 1))
    if attempts >= self._connect_req_max_attempts:
        self.log.debug(
            f"Not resending CONNECT_REQ for route {route_id}, {attempts} attempts made."
        )
        return False
    now: int = self.getTime()
    last_sent_at: int = int(route_data.get("connect_req_sent_at", created_at or 0))
    wait_seconds: int = min(
        self._connect_req_retry_seconds * (2 ** (attempts - 1)),
        self._connect_req_max_retry_seconds,
    )
    if now - last_sent_at < wait_seconds:
        return False
    if "connect_req_data" not in route_data:
        self.log.debug(
            f"Not resending CONNECT_REQ for route {route_id}, no stored request."
        )
        return False

    connect_req_msgid = sendNostrConnectReq(
        self, addr_from, addr_to, route_data, cursor
    )
    route_data["connect_req_msgid"] = connect_req_msgid.hex()
    route_data["connect_req_sent_at"] = now
    route_data["connect_req_attempts"] = attempts + 1
    cursor.execute(
        "UPDATE direct_message_routes SET route_data = :route_data "
        "WHERE record_id = :record_id",
        {
            "route_data": json.dumps(route_data).encode("UTF-8"),
            "record_id": route_id,
        },
    )
    self.log.info(
        f"Resent CONNECT_REQ {self.logIDB(connect_req_msgid)} for nostr route {route_id}, "
        f"attempt {attempts + 1} of {self._connect_req_max_attempts}."
    )
    return True


def processNostrConnectRequest(self, net_i, msg, req_data, offer, cursor) -> None:
    offer_id = offer.offer_id
    bidder_addr = req_data["bsx_address"]
    self.log.debug(
        f"Opening direct message route from {offer.addr_from} to {bidder_addr}"
    )
    remote_pubkey = req_data["nostr_pubkey"]
    ensure(isinstance(remote_pubkey, str), "Invalid nostr pubkey type")
    ensure(len(remote_pubkey) == 64, "Invalid nostr pubkey length")
    bytes.fromhex(remote_pubkey)  # Raises on invalid hex
    event_pubkey = msg.get("nostr_pubkey_from")
    if event_pubkey is not None:
        ensure(
            event_pubkey == remote_pubkey,
            "Connect request not signed by announced route key",
        )

    message_route = self.getMessageRoute(
        int(MessageNetworks.NOSTR),
        offer.addr_from,
        bidder_addr,
        cursor=cursor,
    )
    if message_route:
        route_data = json.loads(message_route.route_data.decode("UTF-8"))
        replace_key: bool = route_data.get("remote_pubkey") != remote_pubkey
        if replace_key:
            # A newer request replaces a lost route key, an older one is a replay
            ensure(
                msg["sent"] > route_data.get("req_sent", 0),
                "Direct message route already exists",
            )
        self.checkConnectRequestRateLimit(int(MessageNetworks.NOSTR))
        if replace_key:
            self.log.info(f"Replacing remote key of route {message_route.record_id}")
            route_data["remote_pubkey"] = remote_pubkey
            route_data["req_sent"] = msg["sent"]
            cursor.execute(
                "UPDATE direct_message_routes SET route_data = :route_data "
                "WHERE record_id = :record_id",
                {
                    "route_data": json.dumps(route_data).encode("UTF-8"),
                    "record_id": message_route.record_id,
                },
            )
            self.add(
                DirectMessageRouteLink(
                    active_ind=1,
                    direct_message_route_id=message_route.record_id,
                    linked_type=Concepts.OFFER,
                    linked_id=offer_id,
                    created_at=self.getTime(),
                ),
                cursor,
            )
        else:
            # The bidder resends CONNECT_REQ when the ACK did not arrive.
            self.log.info(
                f"Resending CONNECT_REQ ACK for route {message_route.record_id}"
            )
        sendConnectRequestAck(
            self,
            offer_id,
            offer.addr_from,
            bidder_addr,
            route_data["local_pubkey"],
            route_data["remote_pubkey"],
            getMsgPubkey(self, msg),
            cursor,
            sign_privkey=bytes.fromhex(route_data["local_privkey"]),
        )
        return
    route_privkey_hex, route_pubkey = newNostrRouteKey()

    self.checkConnectRequestRateLimit(int(MessageNetworks.NOSTR))

    now: int = self.getTime()
    # No connection to establish, the route is usable immediately.
    message_route = DirectMessageRoute(
        active_ind=1,
        network_id=int(MessageNetworks.NOSTR),
        linked_type=Concepts.OFFER,
        smsg_addr_local=offer.addr_from,
        smsg_addr_remote=bidder_addr,
        route_data=json.dumps(
            {
                "remote_pubkey": remote_pubkey,
                "local_pubkey": route_pubkey,
                "local_privkey": route_privkey_hex,
                "req_sent": msg["sent"],
            }
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

    sendConnectRequestAck(
        self,
        offer_id,
        offer.addr_from,
        bidder_addr,
        route_pubkey,
        remote_pubkey,
        getMsgPubkey(self, msg),
        cursor,
        sign_privkey=bytes.fromhex(route_privkey_hex),
    )


def sendConnectRequestAck(
    self,
    offer_id: bytes,
    addr_from: str,
    addr_to: str,
    local_pubkey: str,
    remote_pubkey: str,
    pubkey_to: bytes,
    cursor,
    sign_privkey: bytes = None,
) -> None:
    # req_pubkey binds the ACK to this key exchange against replayed ACKs
    ack_data = {
        "offer_id": offer_id.hex(),
        "bsx_address": addr_from,
        "nostr_pubkey": local_pubkey,
        "req_pubkey": remote_pubkey,
    }
    msg_buf = ConnectReqMessage()
    msg_buf.network_type = int(MessageNetworks.NOSTR)
    msg_buf.network_data = b"bsx"
    msg_buf.request_type = ConnectionRequestTypes.ACK
    msg_buf.request_data = json.dumps(ack_data).encode("UTF-8")

    payload_hex = (
        str.format("{:02x}", MessageTypes.CONNECT_REQ) + msg_buf.to_bytes().hex()
    )
    network = self.getActiveNetwork(MessageNetworks.NOSTR)
    ack_msgid = sendNostrMsg(
        self,
        network,
        addr_from,
        addr_to,
        bytes.fromhex(payload_hex),
        self.SMSG_SECONDS_IN_HOUR,
        cursor,
        pubkey_to=pubkey_to,
        sign_privkey=sign_privkey,
    )
    self.log.info(f"Sent CONNECT_REQ ACK {self.logIDB(ack_msgid)}")


def processConnectRequestAck(self, msg, msg_data, req_data) -> None:
    self.log.debug(
        "Processing connection request ack msg {}.".format(self.log.id(msg["msgid"]))
    )
    ensure(
        int(msg_data.network_type) == MessageNetworks.NOSTR,
        "Unsupported connect request ack network",
    )
    remote_pubkey = req_data["nostr_pubkey"]
    ensure(isinstance(remote_pubkey, str), "Invalid nostr pubkey type")
    ensure(len(remote_pubkey) == 64, "Invalid nostr pubkey length")
    bytes.fromhex(remote_pubkey)  # Raises on invalid hex

    try:
        cursor = self.openDB()
        message_route = self.getMessageRoute(
            int(MessageNetworks.NOSTR), msg["to"], msg["from"], cursor=cursor
        )
        ensure(message_route, "No matching direct message route for ack")

        route_data = json.loads(message_route.route_data.decode("UTF-8"))
        # Relays can redeliver an ACK from an earlier route between these addresses
        ensure(
            req_data.get("req_pubkey") == route_data.get("local_pubkey"),
            "Connect request ack does not match pending route",
        )
        ensure(
            req_data.get("bsx_address") == msg["from"],
            "Mismatched ack from address",
        )
        event_pubkey = msg.get("nostr_pubkey_from")
        if event_pubkey is not None:
            ensure(
                event_pubkey == remote_pubkey,
                "Connect request ack not signed by announced route key",
            )

        if message_route.active_ind == 1:
            ensure(
                route_data.get("remote_pubkey") == remote_pubkey,
                "Connect request ack does not match active route",
            )
            self.log.debug("Direct message route is already active.")
        else:
            route_data["remote_pubkey"] = remote_pubkey
            query = "UPDATE direct_message_routes SET active_ind = 1, route_data = :route_data WHERE record_id = :record_id "
            cursor.execute(
                query,
                {
                    "route_data": json.dumps(route_data).encode("UTF-8"),
                    "record_id": message_route.record_id,
                },
            )
            self.log.debug(
                f"Direct message route established local: {msg['to']}, remote: {msg['from']}."
            )

        self.dispatchPendingRouteBids(message_route.record_id, cursor)
    finally:
        self.closeDB(cursor)
