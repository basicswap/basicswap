# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import json
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
from basicswap.db import (
    DirectMessageRoute,
    NetworkPortal,
    SmsgAddress,
)
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


def networkTypeToID(type: str) -> int:
    # TODO: remove
    if type == "smsg":
        return MessageNetworks.SMSG
    elif type == "simplex":
        return MessageNetworks.SIMPLEX
    raise RuntimeError(f"Unknown message network type: {type}")


def networkIDToType(id: int, bridged: bool = False) -> str:
    network_name = None
    if id == MessageNetworks.SMSG:
        network_name = "smsg"
    elif id == MessageNetworks.SIMPLEX:
        network_name = "simplex"
    else:
        raise RuntimeError(f"Unknown message network id: {id}")
    return ("b." if bridged else "") + network_name


class BSXNetwork:
    _read_zmq_queue: bool = True

    def __init__(self, data_dir, settings, **kwargs):
        self._bridge_networks = self.settings.get("bridge_networks", False)
        self._use_direct_message_routes = True
        self._smsg_payload_version = 0  # Set in startNetworks (if 0)
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
        self._forget_portals_after = 86400 * 7

        self._zmq_queue_enabled = self.settings.get("zmq_queue_enabled", True)
        self._poll_smsg = self.settings.get("poll_smsg", False)
        self.zmqContext = None
        self.zmqSubscriber = None
        self.zmq_server_key = self.settings.get("zmq_server_pubkey", None)

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

        self._can_use_smsg_payload2 = False
        if (
            Coins.PART in self.coin_clients
            and self.coin_clients[Coins.PART]["core_version"] > 23020700
        ):
            self._can_use_smsg_payload2 = True

        self.log.debug(f'"can_use_smsg_payload2": {self._can_use_smsg_payload2}')
        # Set smsg_payload_version automatically if it's unset
        was_set: bool = False
        if self._smsg_payload_version == 0:
            self._smsg_payload_version = int(
                self.settings.get(
                    "smsg_payload_version", 2 if self._can_use_smsg_payload2 else 1
                )
            )
            was_set = True
        self.log.debug(
            '{}"smsg_payload_version": {}'.format(
                "Set " if was_set else "", self._smsg_payload_version
            )
        )

        have_smsg: bool = False
        for network in network_config_list:
            if network.get("enabled", True) is False:
                continue
            if network["type"] == "smsg":
                have_smsg = True
                add_network = {"type": "smsg"}
                if "bridged" in network:
                    if self._smsg_payload_version < 2:
                        raise ValueError(
                            'Bridged networks require "smsg_payload_version" >= 2'
                        )
                    add_network["bridged"] = network["bridged"]
                self.active_networks.append(add_network)
            elif network["type"] == "simplex":
                initialiseSimplexNetwork(self, network)

        if have_smsg:
            self._have_smsg_rpc = True
            if self._can_use_smsg_payload2:
                self.callrpc("smsgoptions", ["set", "addReceivedPubkeys", False])
            if self._zmq_queue_enabled:
                self.zmqContext = zmq.Context()
                self.zmqSubscriber = self.zmqContext.socket(zmq.SUB)
                if self.zmq_server_key is not None:
                    zmq_server_key = base64.b64decode(self.zmq_server_key)
                    zmq_client_key = base64.b64decode(self.settings["zmq_client_key"])
                    zmq_client_pubkey = base64.b64decode(
                        self.settings["zmq_client_pubkey"]
                    )

                    self.zmqSubscriber.setsockopt(
                        zmq.CURVE_PUBLICKEY, zmq_client_pubkey
                    )
                    self.zmqSubscriber.setsockopt(zmq.CURVE_SECRETKEY, zmq_client_key)
                    self.zmqSubscriber.setsockopt(zmq.CURVE_SERVERKEY, zmq_server_key)
                self.zmqSubscriber.setsockopt_string(zmq.SUBSCRIBE, "smsg")
                self.zmqSubscriber.setsockopt_string(zmq.SUBSCRIBE, "hashwtx")
                self.zmqSubscriber.connect(
                    self.settings["zmqhost"] + ":" + str(self.settings["zmqport"])
                )

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

        now: int = self.getTime()

        # Load portal data
        try:
            cursor = self.openDB()
            portals = self.query(
                NetworkPortal,
                cursor,
            )
            for portal_data in portals:
                if portal_data.time_start + portal_data.time_valid < now:
                    # Database records are kept longer
                    continue

                if portal_data.own_portal == 1:
                    self.own_portals.add(portal_data)
                else:
                    self.known_portals.add(portal_data)

        finally:
            self.closeDB(cursor)

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
            query: str = (
                "SELECT pk_bid_addr FROM bids WHERE bid_addr = :addr_to LIMIT 1"
            )
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
        if self._smsg_payload_version < 2:
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
        all_networks = active_networks_set
        # Join without duplicates, bridged networks are prefixed with "b."
        for bridged_network in bridged_networks_set:
            if bridged_network not in active_networks_set:
                all_networks.add("b." + bridged_network)
        return ",".join(all_networks)

    def selectMessageNetString(
        self, received_on_network_ids, remote_message_nets: str
    ) -> str:
        if self._smsg_payload_version < 2:
            return ""
        active_networks_set = set()
        bridged_networks_set = set()
        for network in self.active_networks:
            network_type: str = network.get("type", "smsg")
            active_networks_set.add(networkTypeToID(network_type))
            for bridged_network in network.get("bridged", []):
                bridged_network_type = bridged_network.get("type", "smsg")
                bridged_networks_set.add(networkTypeToID(bridged_network_type))
        remote_active_network_ids, remote_bridged_network_ids = self.expandMessageNets(
            remote_message_nets
        )
        if len(received_on_network_ids) < 1:
            self.log.debug("selectMessageNetString: received_on_network_ids is empty.")
            received_on_network_ids.append(MessageNetworks.SMSG)
        # If no data was sent it must be from an old version
        if len(remote_active_network_ids) < 1 and len(remote_bridged_network_ids) < 1:
            return networkIDToType(received_on_network_ids[0])

        # Choose which network to respond on
        # Pick the received on network if it's in the local node's active networks and the list of remote node's active networks
        # else prefer a network the local node has active
        for received_on_id in received_on_network_ids:
            if (
                received_on_id in active_networks_set
                and received_on_id in remote_active_network_ids
            ):
                return networkIDToType(received_on_id)
        # Prefer to use a network both nodes have active
        for local_net_id in active_networks_set:
            if local_net_id in remote_active_network_ids:
                return networkIDToType(local_net_id)
        # Else prefer to use a network this node has active
        for local_net_id in active_networks_set:
            if local_net_id in remote_bridged_network_ids:
                return networkIDToType(local_net_id, True)

        for local_net_id in bridged_networks_set:
            if local_net_id in remote_active_network_ids:
                return networkIDToType(local_net_id, True)
        for local_net_id in bridged_networks_set:
            if local_net_id in remote_bridged_network_ids:
                return networkIDToType(local_net_id, True)
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
            network_id = row[0]
            received_on_network_ids.add(network_id)
        return self.selectMessageNetString(
            list(received_on_network_ids), remote_message_nets
        )

    def expandMessageNets(self, message_nets: str) -> (list, list):
        if message_nets is None or len(message_nets) < 1:
            return [], []
        if len(message_nets) > 256:
            raise ValueError("message_nets string is too large")
        active_networks = []
        bridged_networks = []
        for network_string in message_nets.split(","):
            add_to_list = active_networks
            if network_string.startswith("b."):
                network_string = network_string[2:]
                add_to_list = bridged_networks
            try:
                network_id: int = networkTypeToID(network_string)
            except Exception as e:  # noqa: F841
                self.log.debug(f"Unknown message_net {network_string}")
            if network_id in active_networks or network_id in bridged_networks:
                raise ValueError("Malformed networks data.")
            add_to_list.append(network_id)
        return active_networks, bridged_networks

    def validateMessageNets(self, message_nets: str) -> None:
        # Decode to validate
        _, _ = self.expandMessageNets(message_nets)

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
        message_nets=None,  # None|empty -> all
        payload_version=None,
    ) -> bytes:
        message_id: bytes = None
        active_networks_list, bridged_networks_list = self.expandMessageNets(
            message_nets
        )
        # Empty list means send to all networks
        networks_list = active_networks_list + bridged_networks_list
        networks_sent_to = set()

        # Message routes work only with simplex messages for now.
        message_route = self.getMessageRoute(1, addr_from, addr_to, cursor=cursor)
        if message_route:
            raise RuntimeError("Trying to send through an unestablished direct route.")

        message_route = self.getMessageRoute(2, addr_from, addr_to, cursor=cursor)
        if message_route:
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
        if self._have_smsg_rpc and self._smsg_payload_version >= 2:
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
                    if self._smsg_payload_version < 2:
                        # TODO: Remove when Particl 23.2.8 is min version
                        net_message_id = self.sendSmsg(
                            addr_from,
                            addr_to,
                            payload_hex,
                            msg_valid,
                            return_msg=False,
                            cursor=cursor,
                            payload_version=payload_version,
                        )
                    else:
                        net_message_id, smsg_msg = self.sendSmsg(
                            addr_from,
                            addr_to,
                            payload_hex,
                            msg_valid,
                            return_msg=True,
                            cursor=cursor,
                            payload_version=payload_version,
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
        payload_version: int = None,
    ) -> bytes:
        options = {"decodehex": True, "ttl_is_seconds": True}
        use_payload_version = (
            self._smsg_payload_version if payload_version is None else payload_version
        )
        if use_payload_version >= 2:
            options["payload_format_version"] = 2
            options["compression"] = 0
        if self._can_use_smsg_payload2:
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
        net_i = self.getActiveNetworkInterface(MessageNetworks.SIMPLEX)
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
        net_i = self.getActiveNetworkInterface(MessageNetworks.SIMPLEX)

        connId = route_data["pccConnId"]

        self.log.info(f"Closing Simplex chat, id: {connId}")
        closeSimplexChat(self, net_i, connId)

        self.log.debug(f"Removing direct message route: {record_id}.")
        cursor.execute(
            "DELETE FROM direct_message_routes WHERE record_id = :record_id ",
            {"record_id": record_id},
        )
        self.commitDB()

    def getSmsgMsgPayloadVersion(self, msg) -> int:
        return msg.get("payloadversion", self._smsg_payload_version)

    def getSmsgMsgBytes(self, msg) -> bytes:
        payload_version = self.getSmsgMsgPayloadVersion(msg)
        if payload_version < 2:
            return bytes.fromhex(msg["hex"][2:-2])
        return bytes.fromhex(msg["hex"][2:])

    def processZmqSmsg(self, message) -> None:
        if message[0] == 3:  # Paid smsg
            return  # TODO: Switch to paid?

        msg_id = message[2:]
        options = {"encoding": "hex", "setread": True}
        if self._can_use_smsg_payload2:
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
                    raise RuntimeError(f'"smsg" failed for {msg_id.hex()}: {e}')

        self.processMsg(msg)

    def newPortal(self, network_from_id, network_to_id, now):
        addr_to: str = self.network_addr
        cursor = self.openDB()
        try:
            addr_portal: str = self.prepareSMSGAddress(
                None, AddressTypes.PORTAL_LOCAL, cursor
            )
            portal = NetworkPortal()
            portal.set(
                now, 30 * 60, network_from_id, network_to_id, addr_portal, addr_to
            )
            portal.created_at = now
            portal.own_portal = True
            portal.record_id = self.add(portal, cursor)
        finally:
            self.closeDB(cursor)

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
            net_message_id = self.sendSmsg(
                addr_portal, addr_to, payload_hex, msg_valid, cursor=cursor
            )
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
                net_message_id = self.sendSmsg(
                    addr_portal, addr_to, payload_hex, msg_valid, cursor=cursor
                )
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
            net_message_id = self.sendSmsg(
                addr_from, addr_to, payload_hex, msg_valid, cursor=cursor
            )
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

        cursor = self.openDB()
        try:
            received_portal = self.queryOne(
                NetworkPortal,
                cursor,
                {
                    "address_from": addr_portal,
                },
            )
            if received_portal is None:
                received_portal = NetworkPortal()
                received_portal.set(
                    time_start,
                    portal_data.time_valid,
                    portal_data.network_type_from,
                    portal_data.network_type_to,
                    addr_portal,
                    portal_data.portal_address_to,
                )
                received_portal.created_at = now
            else:
                received_portal.num_refreshes += 1
            received_portal.smsg_difficulty = portal_data.smsg_difficulty
            received_portal.time_start = time_start
            received_portal.time_valid = portal_data.time_valid

            self.add(received_portal, cursor, upsert=True)

            address_record = self.queryOne(
                SmsgAddress,
                cursor,
                {
                    "addr": addr_portal,
                },
            )
            if address_record is None or len(address_record.pubkey) < 33:
                if address_record is None:
                    address_record = SmsgAddress()
                    address_record.active_ind = 1
                    address_record.created_at = now
                    address_record.addr = received_portal.address_from
                    address_record.use_type = AddressTypes.PORTAL
                address_record.pubkey = msg["pubkey_from"]
                self.add(address_record, cursor, upsert=True)
        finally:
            self.closeDB(cursor)

        if received_portal.network_from not in self.known_portals:
            self.known_portals[received_portal.network_from] = {}
        portals_from = self.known_portals[received_portal.network_from]

        if received_portal.network_to not in portals_from:
            portals_from[received_portal.network_to] = []

        portals_from_to = portals_from[received_portal.network_to]

        for portal in portals_from_to:
            if portal.address_from == received_portal.address_from:
                portal.num_refreshes = received_portal.num_refreshes
                portal.time_start = received_portal.time_start
                portal.time_valid = received_portal.time_valid
                portal.smsg_difficulty = received_portal.smsg_difficulty
                return

        portals_from_to.append(received_portal)

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

        portal.messages_sent += 1
        cursor = self.openDB()
        try:
            portal_record = self.queryOne(
                NetworkPortal,
                cursor,
                {
                    "address_from": portal.address_from,
                },
            )
            portal_record.messages_sent = portal.messages_sent
            self.add(portal_record, cursor, upsert=True)
        finally:
            self.closeDB(cursor)

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

        cursor = self.openDB()
        try:
            query: str = "DELETE FROM network_portals WHERE time_start < :time_delete"
            cursor.execute(query, {"time_delete": now - self._forget_portals_after})
        finally:
            self.closeDB(cursor)
        self._last_checked_bridges = now

    def updateNetwork(self) -> None:
        now: int = self.getTime()

        if self._poll_smsg:
            if now - self._last_checked_smsg >= self.check_smsg_seconds:
                self._last_checked_smsg = now
                options = {"encoding": "hex", "setread": True}
                if self._can_use_smsg_payload2:
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
