#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import traceback

from basicswap.network.nostr_client import (
    DEFAULT_BROADCAST_TAG,
    NostrClient,
)
from basicswap.network.simplex import (
    decryptSimplexMsg,
    encryptMsg,
)
from basicswap.util.smsg import (
    smsgGetID,
    smsgGetTimestamp,
    smsgGetTTL,
)


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def decode_base64(encoded_data: str) -> bytes:
    return base64.b64decode(encoded_data)


def initialiseNostrNetwork(self, network_config) -> None:
    self.log.debug("initialiseNostrNetwork")

    relays = network_config.get("relays", [])
    if len(relays) < 1:
        raise ValueError("Nostr network requires at least one relay.")

    privkey_hex: str = network_config.get("private_key", "")
    if len(privkey_hex) != 64:
        raise ValueError('Nostr network requires a 32 byte hex "private_key".')
    privkey: bytes = bytes.fromhex(privkey_hex)

    socks_proxy = None
    if "socks_proxy_override" in network_config:
        socks_proxy = network_config["socks_proxy_override"]
    elif getattr(self, "use_tor_proxy", False):
        socks_proxy = f"{self.tor_proxy_host}:{self.tor_proxy_port}"

    client = NostrClient(
        relays,
        privkey,
        self.log,
        broadcast_tag=network_config.get("broadcast_tag", DEFAULT_BROADCAST_TAG),
        pow_target=int(network_config.get("pow_target", 0)),
        socks_proxy=socks_proxy,
        abort_event=self.delay_event,
    )
    client.start()
    self.threads.append(client)  # Stopped and joined in finalise
    client.waitForConnected(self.delay_event)

    add_network = {
        "type": "nostr",
        "client": client,
    }
    if "bridged" in network_config:
        add_network["bridged"] = network_config["bridged"]

    self.active_networks.append(add_network)


def publishNostrSmsg(self, network, smsg_msg: bytes, to_pubkey: str = None) -> None:
    client: NostrClient = network["client"]
    expiration: int = smsgGetTimestamp(smsg_msg) + smsgGetTTL(smsg_msg)
    event = client.buildEvent(
        encode_base64(smsg_msg), to_pubkey=to_pubkey, expiration=expiration
    )
    client.publishEvent(event, delay_event=self.delay_event)
    if to_pubkey is not None:
        self.num_direct_nostr_messages_sent += 1
    else:
        self.num_nostr_messages_sent += 1


def sendNostrMsg(
    self,
    network,
    addr_from: str,
    addr_to: str,
    payload: bytes,
    msg_valid: int,
    cursor,
    timestamp: int = None,
    deterministic: bool = False,
    to_pubkey: str = None,
    return_msg: bool = False,
    difficulty_target=0x1EFFFFFF,
    pubkey_to: bytes = None,
) -> bytes:
    self.log.debug("sendNostrMsg")

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
        pubkey_to=pubkey_to,
    )
    smsg_id = smsgGetID(smsg_msg)

    publishNostrSmsg(self, network, smsg_msg, to_pubkey=to_pubkey)

    if return_msg:
        return smsg_id, smsg_msg
    return smsg_id


def forwardNostrMsg(self, network, smsg_msg: bytes, to_pubkey: str = None) -> bytes:
    smsg_id = smsgGetID(smsg_msg)
    publishNostrSmsg(self, network, smsg_msg, to_pubkey=to_pubkey)
    return smsg_id


def decryptNostrMsg(self, msg_data: bytes):
    decrypted = decryptSimplexMsg(self, msg_data)
    if decrypted is not None:
        decrypted["msg_net"] = "nostr"
    return decrypted


def parseNostrEvent(self, network, event):
    client: NostrClient = network["client"]
    is_direct: bool = False
    for tag in event.get("tags", []):
        if len(tag) >= 2 and tag[0] == "p" and tag[1] == client.pubkey:
            is_direct = True
            break

    try:
        msg_data: bytes = decode_base64(event["content"])
    except Exception:
        return None

    decrypted_msg = decryptNostrMsg(self, msg_data)
    if decrypted_msg is None:
        return None
    if is_direct:
        self.num_direct_nostr_messages_received += 1
    else:
        self.num_nostr_messages_received += 1
    decrypted_msg["nostr_event_id"] = event["id"]
    decrypted_msg["nostr_pubkey_from"] = event["pubkey"]
    decrypted_msg["nostr_direct"] = is_direct
    return decrypted_msg


def readNostrMsgs(self, network) -> None:
    client: NostrClient = network["client"]
    for i in range(100):
        event = client.queue_get()
        if event is None:
            break
        if self.delay_event.is_set():
            break
        try:
            decrypted_msg = parseNostrEvent(self, network, event)
            if decrypted_msg is None:
                continue
            self.processMsg(decrypted_msg)
        except Exception as e:
            self.log.debug(f"readNostrMsgs error: {e}")
            if self.debug:
                self.log.error(traceback.format_exc())

        self.delay_event.wait(0.05)
