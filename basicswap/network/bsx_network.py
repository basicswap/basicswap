# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import random
import zmq

from basicswap.basicswap_util import (
    AddressTypes,
    MessageNetworkLinkTypes,
    MessageNetworks,
    MessageTypes,
)
from basicswap.chainparams import (
    Coins,
)
from basicswap.db import DirectMessageRoute
from basicswap.messages_npb import (
    MessagePortalOffer,
    MessagePortalSend,
)
from basicswap.network.simplex import (
    closeSimplexChat,
    encryptMsg,
    forwardSimplexMsg,
    getResponseData,
    initialiseSimplexNetwork,
    readSimplexMsgs,
    sendSimplexMsg,
)
from basicswap.util import ensure
from basicswap.util.address import (
    b58decode,
)
from basicswap.util.logging import LogCategories as LC
from basicswap.util.smsg import smsgGetID


class NetworkPortal:
    __slots__ = (
        "time_start",
        "time_valid",
        "network_from",
        "network_to",
        "address_from",
        "address_to",
        "smsg_difficulty",
        "num_refreshes",
        "messages_sent",
        "responses_seen",
        "time_last_used",
        "num_issues",
    )

    def __init__(
        self, time_start, time_valid, network_from, network_to, address_from, address_to
    ):
        self.time_start = time_start
        self.time_valid = time_valid
        self.network_from = network_from
        self.network_to = network_to
        self.address_from = address_from
        self.address_to = address_to

        self.smsg_difficulty = 0x1EFFFFFF

        self.num_refreshes = 0
        self.messages_sent = 0
        self.responses_seen = 0
        self.time_last_used = 0
        self.num_issues = 0


def networkTypeToID(type: str) -> int:
    # TODO: remove
    if type == "smsg":
        return MessageNetworks.SMSG
    elif type == "simplex":
        return MessageNetworks.SIMPLEX
    raise RuntimeError(f"Unknown message type: {type}")


def networkIDToType(id: int) -> str:
    if id == MessageNetworks.SMSG:
        return "smsg"
    elif id == MessageNetworks.SIMPLEX:
        return "simplex"
    raise RuntimeError(f"Unknown message network id: {id}")


class BSXNetwork:
    _read_zmq_queue: bool = True

    def __init__(self, data_dir, settings, **kwargs):
        self._bridge_networks = self.settings.get("bridge_networks", False)
        self._use_direct_message_routes = True
        self._smsg_plaintext_version = self.settings.get("smsg_plaintext_version", 1)
        self._smsg_add_to_outbox = self.settings.get("smsg_add_to_outbox", False)
        self._have_smsg_rpc = False  # Set in startNetworks

        self._expire_message_routes_after = self._expire_db_records_after = (
            self.get_int_setting(
                "expire_message_routes_after", 48 * 3600, 10 * 60, 31 * 86400
            )
        )  # Seconds
        self.check_smsg_seconds = self.get_int_setting(
            "check_smsg_seconds", 10, 1, 10 * 60
        )
        self._last_checked_smsg = 0
        self.check_bridges_seconds = self.get_int_setting(
            "check_bridges_seconds", 10, 1, 10 * 60
        )
        self._last_checked_bridges = 0

        self._zmq_queue_enabled = self.settings.get("zmq_queue_enabled", True)
        self._poll_smsg = self.settings.get("poll_smsg", False)
        self.zmqContext = None
        self.zmqSubscriber = None

        self.SMSG_SECONDS_IN_HOUR = (
            60 * 60
        )  # Note: Set smsgsregtestadjust=0 for regtest

        self.num_group_simplex_messages_received = 0
        self.num_group_simplex_messages_sent = 0
        self.num_direct_simplex_messages_received = 0
        self.num_direct_simplex_messages_sent = 0

        self.num_smsg_messages_received = 0
        self.num_smsg_messages_sent = 0

        self.known_portals = {}
        self.own_portals = {}

        super().__init__(data_dir=data_dir, settings=settings, **kwargs)

    def finalise(self):
        if self._network:
            self._network.stopNetwork()
            self._network = None

        if self.zmqContext:
            self.zmqContext.destroy()

    def startNetworks(self):
        if self._zmq_queue_enabled and self._poll_smsg:
            self.log.warning("SMSG polling and zmq listener enabled.")
        self.active_networks = []
        network_config_list = self.settings.get("networks", [])
        if len(network_config_list) < 1:
            network_config_list = [{"type": "smsg", "enabled": True}]

        have_smsg: bool = False
        for network in network_config_list:
            if network.get("enabled", True) is False:
                continue
            if network["type"] == "smsg":
                have_smsg = True
                add_network = {"type": "smsg"}
                if "bridged" in network:
                    add_network["bridged"] = network["bridged"]
                self.active_networks.append(add_network)
            elif network["type"] == "simplex":
                initialiseSimplexNetwork(self, network)

        if have_smsg:
            self._have_smsg_rpc = True
            if self._zmq_queue_enabled:
                self.zmqContext = zmq.Context()
                self.zmqSubscriber = self.zmqContext.socket(zmq.SUB)

                self.zmqSubscriber.connect(
                    self.settings["zmqhost"] + ":" + str(self.settings["zmqport"])
                )
                self.zmqSubscriber.setsockopt_string(zmq.SUBSCRIBE, "smsg")
                self.zmqSubscriber.setsockopt_string(zmq.SUBSCRIBE, "hashwtx")

            ro = self.callrpc("smsglocalkeys")
            found = False
            for k in ro["smsg_keys"]:
                if k["address"] == self.network_addr:
                    found = True
                    break
            if not found:
                self.log.info("Importing network key to SMSG")
                self.callrpc(
                    "smsgimportprivkey", [self.network_key, "basicswap offers"]
                )
                ro = self.callrpc("smsglocalkeys", ["anon", "-", self.network_addr])
                ensure(ro["result"] == "Success.", "smsglocalkeys failed")
        else:
            now = self.getTime()
            try:
                cursor = self.openDB()
                query: str = "SELECT addr_id FROM smsgaddresses WHERE addr = :addr"
                addresses = cursor.execute(
                    query, {"addr": self.network_addr}
                ).fetchall()
                if len(addresses) < 1:
                    query: str = (
                        "INSERT INTO smsgaddresses (active_ind, created_at, addr, pubkey, use_type) VALUES (:active_ind, :created_at, :addr, :pubkey, :use_type)"
                    )
                    cursor.execute(
                        query,
                        {
                            "active_ind": 1,
                            "created_at": now,
                            "addr": self.network_addr,
                            "pubkey": self.network_pubkey,
                            "use_type": AddressTypes.OFFER,
                        },
                    )
            finally:
                self.closeDB(cursor)

        # TODO: Ensure smsg is enabled for the active wallet.

        if self._smsg_plaintext_version >= 2:
            ro = self.callrpc("smsgoptions", ["set", "addReceivedPubkeys", False])
            self.log.debug("smsgoptions {ro}")

    def add_connection(self, host, port, peer_pubkey):
        self.log.info(f"add_connection {host} {port} {peer_pubkey.hex()}.")
        self._network.add_connection(host, port, peer_pubkey)

    def get_network_info(self):
        if not self._network:
            return {"Error": "Not Initialised"}
        return self._network.get_info()

    def getPrivkeyForAddress(self, cursor, addr: str) -> bytes:
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

    def getPubkeyForAddress(self, cursor, addr: str) -> bytes:
        if addr == self.network_addr:
            return bytes.fromhex(self.network_pubkey)

        use_cursor = self.openDB(cursor)
        try:
            query: str = "SELECT pk_from FROM offers WHERE addr_from = :addr_to LIMIT 1"
            rows = use_cursor.execute(query, {"addr_to": addr}).fetchall()
            if len(rows) > 0:
                return rows[0][0]
            query: str = "SELECT pk_bid_addr FROM bids WHERE bid_addr = :addr_to LIMIT 1"
            rows = use_cursor.execute(query, {"addr_to": addr}).fetchall()
            if len(rows) > 0:
                return rows[0][0]
            query: str = "SELECT pubkey FROM smsgaddresses WHERE addr = :addr LIMIT 1"
            rows = use_cursor.execute(query, {"addr": addr}).fetchall()
            if len(rows) > 0:
                return bytes.fromhex(rows[0][0])
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)
        if self._have_smsg_rpc:
            try:
                rv = self.callrpc(
                    "smsggetpubkey",
                    [
                        addr,
                    ],
                )
                return b58decode(rv["publickey"])
            except Exception as e:  # noqa: F841
                pass
        raise ValueError(f"Could not get public key for address: {addr}")

    def addMessageNetworkLink(
        self, linked_type, linked_id, link_type, network_id, cursor
    ) -> None:
        now: int = self.getTime()
        query = """INSERT INTO message_network_links
                   (active_ind, linked_type, linked_id, link_type, network_id, created_at)
                   VALUES
                   (1, :linked_type, :linked_id, :link_type, :network_id, :created_at)"""
        cursor.execute(
            query,
            {
                "linked_type": linked_type,
                "linked_id": linked_id,
                "link_type": link_type,
                "network_id": network_id,
                "created_at": now,
            },
        )

    def getActiveNetwork(self, network_id: int):
        for network in self.active_networks:
            if networkTypeToID(network["type"]) == network_id:
                return network
        raise RuntimeError("Network not found.")

    def getActiveNetworkInterface(self, network_id: int):
        network = self.getActiveNetwork(network_id)
        return network["ws_thread"]

    def getMessageNetsString(self, with_bridged: bool = False) -> str:
        if self._smsg_plaintext_version < 2:
            return ""
        active_networks_set = set()
        bridged_networks_set = set()
        for network in self.active_networks:
            network_type = network.get("type", "smsg")
            active_networks_set.add(network_type)
            if with_bridged is False:
                continue
            for bridged_network in network.get("bridged", []):
                bridged_network_type = bridged_network.get("type", "smsg")
                bridged_networks_set.add(bridged_network_type)
        all_networks = active_networks_set | bridged_networks_set
        return ",".join(all_networks)

    def selectMessageNetString(self, received_on_network_ids, remote_message_nets: str) -> str:
        if self._smsg_plaintext_version < 2:
            return ""
        active_networks_set = set()
        bridged_networks_set = set()
        for network in self.active_networks:
            network_type: str = network.get("type", "smsg")
            active_networks_set.add(networkTypeToID(network_type))
            for bridged_network in network.get("bridged", []):
                bridged_network_type = bridged_network.get("type", "smsg")
                bridged_networks_set.add(networkTypeToID(bridged_network_type))
        remote_network_ids = self.expandMessageNets(remote_message_nets)

        if len(remote_network_ids) < 1 and len(received_on_network_ids) < 1:
            return networkIDToType(random.choice(tuple(active_networks_set)))

        # Choose which network to respond on
        # Pick the received on network if it's in the local node's active networks and the list of remote node's networks
        # else prefer a network the local node has active
        for received_on_id in received_on_network_ids:
            if received_on_id in active_networks_set and received_on_id in remote_network_ids:
                return networkIDToType(received_on_id)
        for local_net_id in active_networks_set:
            if local_net_id in remote_network_ids:
                return networkIDToType(local_net_id)
        for local_net_id in bridged_networks_set:
            if local_net_id in remote_network_ids:
                return networkIDToType(local_net_id)
        raise RuntimeError("Unable to select network to respond on")

    def selectMessageNetStringForConcept(
        self, linked_type: int, linked_id: bytes, remote_message_nets: str, cursor
    ) -> str:
        received_on_network_ids = set()
        query = """SELECT network_id FROM message_network_links
                   WHERE linked_type = :linked_type AND linked_id = :linked_id AND link_type = :link_type"""
        rows = cursor.execute(
            query,
            {
                "linked_type": linked_type,
                "linked_id": linked_id,
                "link_type": MessageNetworkLinkTypes.RECEIVED_ON,
            },
        )
        for row in rows:
            # TODO: rank networks
            network_id = row
            received_on_network_ids.add(network_id)

        return self.selectMessageNetString(received_on_network_ids, remote_message_nets)

    def expandMessageNets(self, message_nets: str) -> list:
        if message_nets is None or len(message_nets) < 1:
            return []
        if len(message_nets) > 256:
            raise ValueError("message_nets string is too large")
        rv = []
        for network_string in message_nets.split(","):
            try:
                rv.append(networkTypeToID(network_string))
            except Exception as e:  # noqa: F841
                self.log.debug(f"Unknown message_net {network_string}")
        return rv

    def getMessageRoute(
        self, network_id: int, address_from: str, address_to: str, cursor=None
    ):
        try:
            use_cursor = self.openDB(cursor)
            route = self.queryOne(
                DirectMessageRoute,
                use_cursor,
                {
                    "network_id": network_id,
                    "smsg_addr_local": address_from,
                    "smsg_addr_remote": address_to,
                },
            )
            return route
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def setMsgSplitInfo(self, xmr_swap) -> None:
        for network in self.active_networks:
            if network["type"] == "simplex":
                xmr_swap.msg_split_info = "9000:11000"
                return
            for bridged_network in network.get("bridged", []):
                if bridged_network["type"] == "simplex":
                    xmr_swap.msg_split_info = "9000:11000"
                    return
        xmr_swap.msg_split_info = "16000:17000"

    def sendMessage(
        self,
        addr_from: str,
        addr_to: str,
        payload_hex: bytes,
        msg_valid: int,
        cursor,
        linked_type=None,
        linked_id=None,
        timestamp=None,
        deterministic=False,
        message_nets=None,  # None -> all, else
    ) -> bytes:
        message_id: bytes = None
        networks_list = self.expandMessageNets(
            message_nets
        )  # Empty list means send to all networks
        networks_sent_to = set()

        # Message routes work only with simplex messages for now.
        message_route = self.getMessageRoute(1, addr_from, addr_to, cursor=cursor)
        if message_route:
            raise RuntimeError("Trying to send through an unestablished direct route.")

        message_route = self.getMessageRoute(2, addr_from, addr_to, cursor=cursor)
        if message_route:
            network = self.getActiveNetwork(2)
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
                        if (
                            chat["chatInfo"]["contact"]["activeConn"]["connId"]
                            == pccConnId
                        ):
                            remote_name = chat["chatInfo"]["contact"][
                                "localDisplayName"
                            ]
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

        smsg_difficulty: int = 0x1EFFFFFF
        if self._have_smsg_rpc:
            smsg_difficulty = self.callrpc("smsggetdifficulty", [-1, True])
        else:
            self.log.debug("TODO, get difficulty from a portal")

        # First network in list will set message_id
        smsg_msg: bytes = None
        for network in self.active_networks:
            net_message_id = None
            network_type: int = networkTypeToID(network.get("type", "smsg"))
            if network_type in networks_sent_to:
                self.logD(
                    LC.NET, f"Skipping active network {network_type}, already sent to"
                )
                continue
            if len(networks_list) > 0 and network_type not in networks_list:
                self.logD(
                    LC.NET,
                    f"Skipping active network {network_type}, not in networks_list",
                )
                continue

            if network_type == MessageNetworks.SMSG:
                if smsg_msg:
                    self.forwardSmsg(smsg_msg)
                else:
                    net_message_id, smsg_msg = self.sendSmsg(
                        addr_from, addr_to, payload_hex, msg_valid, return_msg=True, cursor=cursor
                    )
            elif network_type == MessageNetworks.SIMPLEX:
                if smsg_msg:
                    forwardSimplexMsg(self, network, smsg_msg)
                else:
                    net_message_id, smsg_msg = sendSimplexMsg(
                        self,
                        network,
                        addr_from,
                        addr_to,
                        bytes.fromhex(payload_hex),
                        msg_valid,
                        cursor,
                        timestamp,
                        deterministic,
                        return_msg=True,
                        difficulty_target=smsg_difficulty,
                    )
            else:
                raise ValueError("Unknown network: {}".format(network["type"]))
            networks_sent_to.add(network_type)
            if not message_id:
                message_id = net_message_id

        for network in self.active_networks:
            net_message_id = None
            network_type_from = networkTypeToID(network.get("type", "smsg"))
            if network_type_from not in self.known_portals:
                self.known_portals[network_type_from] = {}
            portals_from = self.known_portals[network_type_from]

            for bridged_network in network.get("bridged", []):
                network_type_to = networkTypeToID(bridged_network["type"])
                if network_type_to in networks_sent_to:
                    self.logD(
                        LC.NET,
                        f"Skipping bridged network {network_type_to}, already sent to",
                    )
                    continue
                if len(networks_list) > 0 and network_type_to not in networks_list:
                    self.logD(
                        LC.NET,
                        f"Skipping bridged network {network_type_to}, not in networks_list",
                    )
                    continue

                if network_type_to not in portals_from:
                    portals_from[network_type_to] = []
                portals_from_to = portals_from[network_type_to]
                use_portal = None
                for portal in portals_from_to:
                    if use_portal is None:
                        use_portal = portal
                    else:
                        # TODO:  Pick better
                        if portal.num_issues < use_portal.num_issues:
                            use_portal = portal

                if use_portal is None:
                    self.log.warning(
                        f"Could not pick portal to network {network_type_to}, msg {self.logIDM(net_message_id)}"
                    )
                else:
                    if smsg_msg is None:
                        smsg_msg = encryptMsg(
                            self,
                            addr_from,
                            addr_to,
                            bytes.fromhex(payload_hex),
                            msg_valid,
                            cursor,
                            timestamp,
                            deterministic,
                            use_portal.smsg_difficulty,
                        )
                        if not message_id:
                            message_id = smsgGetID(smsg_msg)

                    forward_to = None  # TODO - simplex username
                    self.usePortal(use_portal, smsg_msg, addr_from, forward_to, cursor)
                    networks_sent_to.add(network_type_to)

        return message_id

    def sendSmsg(
        self,
        addr_from: str,
        addr_to: str,
        payload_hex: bytes,
        msg_valid: int,
        return_msg: bool = False,
        cursor=None,
    ) -> bytes:
        options = {"decodehex": True, "ttl_is_seconds": True}
        if self._smsg_plaintext_version >= 2:
            options["plaintext_format_version"] = 2
            options["compression"] = 0
            send_to = self.getPubkeyForAddress(cursor, addr_to).hex()
        else:
            send_to = addr_to
        if self._smsg_add_to_outbox is False:
            options["savemsg"] = False
        if return_msg:
            options["returnmsg"] = True

        try:
            ro = self.callrpc(
                "smsgsend",
                [addr_from, send_to, payload_hex, False, msg_valid, False, options],
            )
            self.num_smsg_messages_sent += 1
            if return_msg:
                return bytes.fromhex(ro["msgid"]), bytes.fromhex(ro["msg"])
            return bytes.fromhex(ro["msgid"])
        except Exception as e:
            if self.debug:
                self.log.error("smsgsend failed {}".format(json.dumps(ro, indent=4)))
            raise e

    def forwardSmsg(self, smsg_msg: bytes) -> None:
        options = {"submitmsg": True, "rehashmsg": False}
        self.callrpc("smsgimport", [smsg_msg.hex(), options])
        self.num_smsg_messages_sent += 1

    def processContactDisconnected(self, event_data) -> None:
        net_i = self.getActiveNetworkInterface(2)
        connId = getResponseData(event_data, "contact")["activeConn"]["connId"]
        self.log.info(f"Direct message route disconnected, connId: {connId}")
        closeSimplexChat(self, net_i, connId)

        query_str = "SELECT record_id, network_id, smsg_addr_local, smsg_addr_remote, route_data FROM direct_message_routes"
        try:
            cursor = self.openDB()

            rows = cursor.execute(query_str).fetchall()

            for row in rows:
                record_id, network_id, smsg_addr_local, smsg_addr_remote, route_data = (
                    row
                )
                route_data = json.loads(route_data.decode("UTF-8"))

                if connId == route_data["pccConnId"]:
                    self.log.debug(f"Removing direct message route: {record_id}.")
                    cursor.execute(
                        "DELETE FROM direct_message_routes WHERE record_id = :record_id ",
                        {"record_id": record_id},
                    )
                    break
        finally:
            self.closeDB(cursor)

    def closeMessageRoute(self, record_id, network_id, route_data, cursor):
        net_i = self.getActiveNetworkInterface(2)

        connId = route_data["pccConnId"]

        self.log.info(f"Closing Simplex chat, id: {connId}")
        closeSimplexChat(self, net_i, connId)

        self.log.debug(f"Removing direct message route: {record_id}.")
        cursor.execute(
            "DELETE FROM direct_message_routes WHERE record_id = :record_id ",
            {"record_id": record_id},
        )
        self.commitDB()

    def getSmsgMsgBytes(self, msg) -> bytes:
        if int(self._smsg_plaintext_version) < 2:
            return bytes.fromhex(msg["hex"][2:-2])
        return bytes.fromhex(msg["hex"][2:])

    def processZmqSmsg(self) -> None:
        message = self.zmqSubscriber.recv()
        # Clear
        _ = self.zmqSubscriber.recv()

        if message[0] == 3:  # Paid smsg
            return  # TODO: Switch to paid?

        msg_id = message[2:]
        options = {"encoding": "hex", "setread": True}
        if self._smsg_plaintext_version >= 2:
            options["pubkey_from"] = True
        num_tries = 5
        for i in range(num_tries + 1):
            try:
                msg = self.callrpc("smsg", [msg_id.hex(), options])
                break
            except Exception as e:
                if "Unknown message id" in str(e) and i < num_tries:
                    self.delay_event.wait(1)
                else:
                    raise RuntimeError(f"\"smsg\" failed for {msg_id.hex()}: {e}")

        self.processMsg(msg)

    def newPortal(self, network_from_id, network_to_id, now):
        addr_to: str = self.network_addr
        cursor = self.openDB()
        try:
            addr_portal: str = self.prepareSMSGAddress(
                None, AddressTypes.PORTAL_LOCAL, cursor
            )
        finally:
            self.closeDB(cursor)

        portal = NetworkPortal(
            now, 30 * 60, network_from_id, network_to_id, addr_portal, addr_to
        )

        smsg_difficulty: int = 0x1EFFFFFF
        if self._have_smsg_rpc:
            smsg_difficulty = self.callrpc("smsggetdifficulty", [-1, True])

        msg_buf = MessagePortalOffer()
        msg_buf.network_type_from = network_from_id
        msg_buf.network_type_to = network_to_id
        msg_buf.time_valid = portal.time_valid
        msg_buf.smsg_difficulty = smsg_difficulty
        payload_hex = (
            str.format("{:02x}", MessageTypes.PORTAL_OFFER) + msg_buf.to_bytes().hex()
        )

        msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, portal.time_valid)
        if network_from_id == MessageNetworks.SMSG:
            net_message_id = self.sendSmsg(addr_portal, addr_to, payload_hex, msg_valid, cursor=cursor)
        elif network_from_id == MessageNetworks.SIMPLEX:
            network = self.getActiveNetwork(MessageNetworks.SIMPLEX)

            deterministic: bool = True
            cursor = self.openDB()
            try:
                net_message_id = sendSimplexMsg(
                    self,
                    network,
                    addr_portal,
                    addr_to,
                    bytes.fromhex(payload_hex),
                    msg_valid,
                    cursor,
                    portal.time_start,
                    deterministic,
                )
            finally:
                self.closeDB(cursor)
        else:
            raise RuntimeError(f"Unknown network id {network_from_id}")
        if network_from_id not in self.own_portals:
            self.own_portals[network_from_id] = {}
        self.own_portals[network_from_id][network_to_id] = portal
        portal = self.own_portals.get(network_from_id, {}).get(network_to_id, None)
        self.logD(
            LC.NET,
            f"Opened new portal {addr_portal} {network_from_id} -> {network_to_id}, {self.logIDM(net_message_id)}",
        )

    def refreshPortal(self, portal):
        # TODO: Add random delay between refreshes

        now: int = self.getTime()
        addr_portal: str = portal.address_from
        addr_to: str = self.network_addr
        smsg_difficulty: int = 0x1EFFFFFF
        if self._have_smsg_rpc:
            smsg_difficulty = self.callrpc("smsggetdifficulty", [-1, True])

        msg_buf = MessagePortalOffer()
        msg_buf.network_type_from = portal.network_from
        msg_buf.network_type_to = portal.network_to
        msg_buf.time_valid = portal.time_valid
        msg_buf.smsg_difficulty = smsg_difficulty
        payload_hex = (
            str.format("{:02x}", MessageTypes.PORTAL_OFFER) + msg_buf.to_bytes().hex()
        )
        cursor = self.openDB()
        try:
            msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, portal.time_valid)
            if portal.network_from == MessageNetworks.SMSG:
                net_message_id = self.sendSmsg(addr_portal, addr_to, payload_hex, msg_valid, cursor=cursor)
            elif portal.network_from == MessageNetworks.SIMPLEX:
                network = self.getActiveNetwork(MessageNetworks.SIMPLEX)
                net_message_id = sendSimplexMsg(
                    self,
                    network,
                    addr_portal,
                    addr_to,
                    bytes.fromhex(payload_hex),
                    msg_valid,
                    cursor,
                    portal.time_start,
                )
            else:
                raise RuntimeError(f"Unknown network id {portal.network_from}")
        finally:
            self.closeDB(cursor)

        portal.time_start = now
        self.logD(
            LC.NET,
            f"Refreshed portal {addr_portal} {portal.network_from} -> {portal.network_to}, {self.logIDM(net_message_id)}",
        )

    def usePortal(self, portal, smsg, addr_from: str, forward_to: str, cursor):
        if forward_to is not None:
            raise ValueError("TODO")
        now: int = self.getTime()
        msg_buf = MessagePortalSend()
        msg_buf.message_bytes = smsg
        payload_hex = (
            str.format("{:02x}", MessageTypes.PORTAL_SEND) + msg_buf.to_bytes().hex()
        )
        msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, portal.time_valid)
        addr_to: str = portal.address_from

        if portal.network_from == MessageNetworks.SMSG:
            net_message_id = self.sendSmsg(addr_from, addr_to, payload_hex, msg_valid, cursor=cursor)
        elif portal.network_from == MessageNetworks.SIMPLEX:
            network = self.getActiveNetwork(MessageNetworks.SIMPLEX)

            net_message_id = sendSimplexMsg(
                self,
                network,
                addr_from,
                addr_to,
                bytes.fromhex(payload_hex),
                msg_valid,
                cursor,
                now,
            )
        else:
            raise ValueError("Unknown network from ind.")
        self.logD(
            LC.NET,
            f"Sending through portal {portal.address_from} {portal.network_from} -> {portal.network_to}, {self.logIDM(net_message_id)}",
        )

    def processPortalOffer(self, msg) -> None:
        self.log.debug(
            "Processing network portal offer {}.".format(self.log.id(msg["msgid"]))
        )
        network_received_on: int = networkTypeToID(msg.get("msg_net", "smsg"))

        time_start: int = msg["sent"]
        addr_portal: str = msg["from"]
        msg_bytes = self.getSmsgMsgBytes(msg)
        portal_data = MessagePortalOffer(init_all=False)
        portal_data.from_bytes(msg_bytes)
        if portal_data.network_type_from != network_received_on:
            raise RuntimeError("Network from must match network received on.")

        network_from = self.getActiveNetwork(portal_data.network_type_from)

        # Ignore own portals
        for network_to_id, portal in self.own_portals.get(
            portal_data.network_type_from, {}
        ).items():
            if portal.address_from == addr_portal:
                self.log.debug("Ignoring own portal.")
                return

        # Skip portals to networks this node is not using
        found_enabled_bridge: bool = False
        enabled_bridged = network_from.get("bridged", [])
        for network_to_cross in enabled_bridged:
            if network_to_cross.get("enabled", True) is False:
                continue
            if (
                networkTypeToID(network_to_cross.get("type", "smsg"))
                == portal_data.network_type_to
            ):
                found_enabled_bridge = True
                break

        if found_enabled_bridge is False:
            self.log.debug("Ignoring portal to an unbridged network.")
            return

        now: int = self.getTime()
        if time_start + portal_data.time_valid < now:
            self.log.warning("Offered portal is expired.")
            return

        received_portal = NetworkPortal(
            time_start,
            portal_data.time_valid,
            portal_data.network_type_from,
            portal_data.network_type_to,
            addr_portal,
            portal_data.portal_address_to,
        )
        received_portal.smsg_difficulty = portal_data.smsg_difficulty

        if received_portal.network_from not in self.known_portals:
            self.known_portals[received_portal.network_from] = {}
        portals_from = self.known_portals[received_portal.network_from]

        if received_portal.network_to not in portals_from:
            portals_from[received_portal.network_to] = []

        portals_from_to = portals_from[received_portal.network_to]

        for portal in portals_from_to:
            if portal.address_from == received_portal.address_from:
                portal.num_refreshes += 1
                portal.time_start = received_portal.time_start
                portal.time_valid = received_portal.time_valid
                portal.smsg_difficulty = received_portal.smsg_difficulty
                return

        portals_from_to.append(received_portal)

        try:
            cursor = self.openDB()
            query: str = "SELECT addr_id FROM smsgaddresses WHERE addr = :addr"
            addresses = cursor.execute(
                query, {"addr": received_portal.address_from}
            ).fetchall()
            if len(addresses) < 1:
                pk_address_from: str = msg["pubkey_from"]
                query: str = (
                    "INSERT INTO smsgaddresses (active_ind, created_at, addr, pubkey, use_type) VALUES (:active_ind, :created_at, :addr, :pubkey, :use_type)"
                )
                cursor.execute(
                    query,
                    {
                        "active_ind": 1,
                        "created_at": now,
                        "addr": received_portal.address_from,
                        "pubkey": pk_address_from,
                        "use_type": AddressTypes.PORTAL,
                    },
                )

        finally:
            self.closeDB(cursor)

    def processPortalMessage(self, msg):
        msg_id = msg["msgid"]
        self.log.debug(f"Processing network portal message {msg_id}.")

        addr_to: str = msg["to"]
        network_from_id: int = networkTypeToID(msg.get("msg_net", "smsg"))
        from_portals = self.own_portals.get(network_from_id, {})
        portal = None
        for network_to_id, to_portal in from_portals.items():
            if to_portal.address_from == addr_to:
                portal = to_portal
                break
        if portal is None:
            self.log.debug(f"Portal not found for portal message {msg_id}")
            return
        network_to_id = portal.network_to

        msg_bytes = self.getSmsgMsgBytes(msg)
        portal_msg = MessagePortalSend(init_all=False)
        portal_msg.from_bytes(msg_bytes)

        if network_to_id == MessageNetworks.SMSG:
            self.forwardSmsg(portal_msg.message_bytes)
        elif network_to_id == MessageNetworks.SIMPLEX:
            network = self.getActiveNetwork(MessageNetworks.SIMPLEX)
            forwardSimplexMsg(self, network, portal_msg.message_bytes)
        else:
            raise ValueError(f"Unknown network ID {network_to_id}")

    def updateNetworkBridges(self, now: int) -> None:
        for network in self.active_networks:
            network_from_id: int = networkTypeToID(network["type"])

            for other_network in self.active_networks:
                if network == other_network:
                    continue
                network_id: int = networkTypeToID(other_network["type"])
                portal = self.own_portals.get(network_from_id, {}).get(network_id, None)

                if portal is None:
                    self.newPortal(network_from_id, network_id, now)
                else:
                    if portal.time_start + portal.time_valid <= now - (5 * 60):
                        self.refreshPortal(portal)
        self._last_checked_bridges = now

    def updateNetwork(self) -> None:
        now: int = self.getTime()

        if self._poll_smsg:
            if now - self._last_checked_smsg >= self.check_smsg_seconds:
                self._last_checked_smsg = now
                options = {"encoding": "hex", "setread": True}
                if self._smsg_plaintext_version >= 2:
                    options["pubkey_from"] = True
                msgs = self.callrpc("smsginbox", ["unread", "", options])
                for msg in msgs["messages"]:
                    self.processMsg(msg)

        try:
            if self._bridge_networks:
                if len(self.active_networks) > 1:
                    if now - self._last_checked_bridges >= self.check_bridges_seconds:
                        self.updateNetworkBridges(now)
            for network in self.active_networks:
                if network["type"] == "simplex":
                    readSimplexMsgs(self, network)

        except Exception as ex:
            self.logException(f"updateNetwork {ex}")
