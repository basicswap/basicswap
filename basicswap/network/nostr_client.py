#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Minimal Nostr relay client used as a BSX message transport.

Events carry base64 encoded SMSG encrypted payloads:
 - Broadcast messages are tagged ["t", <broadcast_tag>], the shared channel
   all BSX nodes subscribe to (analogue of the Simplex #bsx group).
 - Direct messages are tagged ["p", <recipient xonly pubkey hex>] with no
   broadcast tag.  Payload confidentiality comes from the SMSG layer.
 - Events carry a NIP-40 ["expiration", ts] tag derived from the SMSG TTL.
 - Optional NIP-13 proof of work (["nonce", n, target]).
"""

import hashlib
import json
import ssl
import threading
import time

from collections import OrderedDict
from queue import Queue, Empty

from coincurve.keys import PrivateKey, PublicKeyXOnly

import websocket

from basicswap.util import TemporaryError

BSX_NOSTR_KIND: int = 4859  # Regular (stored) custom kind
DEFAULT_BROADCAST_TAG: str = "bsx"
MAX_SEEN_EVENT_IDS: int = 10000
MAX_EVENT_CONTENT_LEN: int = 65536
MAX_POW_TARGET_BITS: int = 32


def eventSerialize(
    pubkey_hex: str, created_at: int, kind: int, tags, content: str
) -> bytes:
    return json.dumps(
        [0, pubkey_hex, created_at, kind, tags, content],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def eventID(pubkey_hex: str, created_at: int, kind: int, tags, content: str) -> bytes:
    return hashlib.sha256(
        eventSerialize(pubkey_hex, created_at, kind, tags, content)
    ).digest()


def countLeadingZeroBits(data: bytes) -> int:
    bits: int = 0
    for byte in data:
        if byte == 0:
            bits += 8
            continue
        for i in range(7, -1, -1):
            if byte & (1 << i):
                return bits
            bits += 1
    return bits


def signEvent(privkey: bytes, event: dict) -> dict:
    """Fill in pubkey, id and sig fields of a partial event.
    Requires created_at, kind, tags and content to be set.
    """
    k = PrivateKey(privkey)
    pubkey_hex: str = k.public_key_xonly.format().hex()
    event["pubkey"] = pubkey_hex
    event_id: bytes = eventID(
        pubkey_hex, event["created_at"], event["kind"], event["tags"], event["content"]
    )
    event["id"] = event_id.hex()
    event["sig"] = k.sign_schnorr(event_id).hex()
    return event


def verifyEvent(event: dict) -> bool:
    try:
        event_id: bytes = eventID(
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        )
        if event_id.hex() != event["id"]:
            return False
        pk = PublicKeyXOnly(bytes.fromhex(event["pubkey"]))
        return pk.verify(bytes.fromhex(event["sig"]), event_id)
    except Exception:
        return False


def mineEventPow(
    privkey: bytes, event: dict, target_bits: int, abort_event=None
) -> dict:
    """NIP-13: append a nonce tag and grind until the id has target_bits leading zero bits."""
    k = PrivateKey(privkey)
    pubkey_hex: str = k.public_key_xonly.format().hex()
    base_tags = [t for t in event["tags"] if len(t) < 1 or t[0] != "nonce"]
    nonce: int = 0
    while True:
        if abort_event is not None and nonce % 4096 == 0 and abort_event.is_set():
            raise TemporaryError("Nostr PoW mining aborted.")
        tags = base_tags + [["nonce", str(nonce), str(target_bits)]]
        event_id: bytes = eventID(
            pubkey_hex, event["created_at"], event["kind"], tags, event["content"]
        )
        if countLeadingZeroBits(event_id) >= target_bits:
            event["tags"] = tags
            return event
        nonce += 1


def getEventPow(event: dict) -> int:
    """Committed NIP-13 difficulty, 0 if no valid nonce tag."""
    for tag in event.get("tags", []):
        if len(tag) >= 3 and tag[0] == "nonce":
            try:
                target = int(tag[2])
            except ValueError:
                return 0
            actual = countLeadingZeroBits(bytes.fromhex(event["id"]))
            return min(target, actual)
    return 0


def getTagValue(event: dict, tag_name: str):
    for tag in event.get("tags", []):
        if len(tag) >= 2 and tag[0] == tag_name:
            return tag[1]
    return None


class RelayThread(threading.Thread):
    def __init__(self, client, url: str):
        super().__init__(daemon=True)
        self.client = client
        self.url: str = url
        self.ws = None
        self.connected: bool = False
        self.delay_event = threading.Event()
        self.sub_id: str = "bsxsub"
        self.num_events_received: int = 0
        self.num_events_sent: int = 0
        self.last_error: str = ""

    def on_open(self, ws) -> None:
        self.connected = True
        self.client.log.info(f"Nostr relay connected: {self.url}")
        try:
            for i, sub_filter in enumerate(self.client.getSubscriptionFilters()):
                ws.send(json.dumps(["REQ", f"{self.sub_id}{i}", sub_filter]))
        except Exception as e:
            self.client.log.warning(f"Nostr relay {self.url} subscribe error: {e}")

    def on_message(self, ws, message) -> None:
        try:
            data = json.loads(message)
            if not isinstance(data, list) or len(data) < 2:
                return
            msg_type = data[0]
            if msg_type == "EVENT" and len(data) >= 3:
                self.num_events_received += 1
                self.client.receiveEvent(self.url, data[2])
            elif msg_type == "OK" and len(data) >= 3:
                self.client.receiveOK(
                    self.url, data[1], data[2], data[3] if len(data) > 3 else ""
                )
            elif msg_type in ("EOSE", "CLOSED", "NOTICE"):
                pass
        except Exception as e:
            self.client.log.debug(f"Nostr relay {self.url} message error: {e}")

    def on_error(self, ws, error) -> None:
        self.last_error = str(error)
        self.client.log.debug(f"Nostr relay {self.url} error: {error}")

    def on_close(self, ws, close_status_code, close_msg) -> None:
        self.connected = False
        self.client.log.info(f"Nostr relay closed: {self.url} {close_status_code}")

    def send(self, data: str) -> bool:
        if not self.connected or self.ws is None:
            return False
        try:
            self.ws.send(data)
            return True
        except Exception as e:
            self.client.log.debug(f"Nostr relay {self.url} send error: {e}")
            return False

    def run(self) -> None:
        self.ws = websocket.WebSocketApp(
            self.url,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
        )
        while not self.delay_event.is_set():
            try:
                kwargs = {}
                if self.client.socks_proxy_host:
                    kwargs["http_proxy_host"] = self.client.socks_proxy_host
                    kwargs["http_proxy_port"] = self.client.socks_proxy_port
                    kwargs["proxy_type"] = "socks5h"
                self.ws.run_forever(
                    sslopt={"cert_reqs": ssl.CERT_REQUIRED},
                    **kwargs,
                )
            except Exception as e:
                self.last_error = str(e)
            self.connected = False
            self.delay_event.wait(5.0)

    def stop(self) -> None:
        self.delay_event.set()
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass


class NostrClient:
    def __init__(
        self,
        relays,
        privkey: bytes,
        logger,
        broadcast_tag: str = DEFAULT_BROADCAST_TAG,
        pow_target: int = 0,
        socks_proxy: str = None,
        subscribe_since_seconds: int = 48 * 3600,
        abort_event=None,
    ):
        self.log = logger
        self.privkey: bytes = privkey
        self.pubkey: str = PrivateKey(privkey).public_key_xonly.format().hex()
        self.broadcast_tag: str = broadcast_tag
        self.pow_target: int = max(0, min(int(pow_target), MAX_POW_TARGET_BITS))
        self.subscribe_since_seconds: int = subscribe_since_seconds
        self.abort_event = abort_event if abort_event is not None else threading.Event()

        self.socks_proxy_host = None
        self.socks_proxy_port = None
        if socks_proxy:
            self.socks_proxy_host, port_str = socks_proxy.rsplit(":", 1)
            self.socks_proxy_port = int(port_str)

        self.mutex = threading.Lock()
        self.recv_queue = Queue()
        self.ok_queue = Queue()
        self._seen_event_ids = OrderedDict()

        self.num_messages_received: int = 0
        self.num_messages_sent: int = 0

        self.relays = []
        for url in relays:
            self.relays.append(RelayThread(self, url.strip()))

    def start(self) -> None:
        for relay in self.relays:
            relay.start()

    def stop(self) -> None:
        self.abort_event.set()
        for relay in self.relays:
            relay.stop()

    def join(self, timeout=None) -> None:
        for relay in self.relays:
            relay.join(timeout=timeout)

    def waitForConnected(self, delay_event, num_tries: int = 100) -> bool:
        for i in range(num_tries):
            if self.numConnected() > 0:
                return True
            if delay_event.is_set():
                break
            delay_event.wait(0.5)
        raise ValueError("Nostr waitForConnected timed-out.")

    def numConnected(self) -> int:
        return sum(1 for relay in self.relays if relay.connected)

    def getSubscriptionFilters(self) -> list:
        since: int = int(time.time()) - self.subscribe_since_seconds
        return [
            {
                "kinds": [BSX_NOSTR_KIND],
                "#t": [self.broadcast_tag],
                "since": since,
            },
            {
                "kinds": [BSX_NOSTR_KIND],
                "#p": [self.pubkey],
                "since": since,
            },
        ]

    def receiveEvent(self, relay_url: str, event: dict) -> None:
        try:
            event_id: str = event["id"]
            if not isinstance(event_id, str) or len(event_id) != 64:
                return
            if not isinstance(event.get("content"), str):
                return
            if len(event["content"]) > MAX_EVENT_CONTENT_LEN:
                return
            with self.mutex:
                if event_id in self._seen_event_ids:
                    return
            # Only verified events enter the seen-cache, or a relay could
            # suppress an event on all relays by sending a corrupted copy
            # of it first.
            if not verifyEvent(event):
                self.log.debug(f"Nostr event failed verification: {event_id}")
                return
            expiration = getTagValue(event, "expiration")
            if expiration is not None:
                try:
                    if int(expiration) < time.time():
                        return
                except ValueError:
                    return
            with self.mutex:
                if event_id in self._seen_event_ids:
                    return
                self._seen_event_ids[event_id] = True
                while len(self._seen_event_ids) > MAX_SEEN_EVENT_IDS:
                    self._seen_event_ids.popitem(last=False)
            self.num_messages_received += 1
            self.recv_queue.put(event)
        except Exception as e:
            self.log.debug(f"Nostr receiveEvent error: {e}")

    def receiveOK(
        self, relay_url: str, event_id: str, accepted: bool, message: str
    ) -> None:
        self.ok_queue.put((relay_url, event_id, accepted, message))
        if not accepted:
            self.log.debug(f"Nostr relay {relay_url} rejected {event_id}: {message}")

    def queue_get(self):
        try:
            return self.recv_queue.get(block=False)
        except Empty:
            return None

    def buildEvent(
        self, content: str, to_pubkey: str = None, expiration: int = None
    ) -> dict:
        tags = []
        if to_pubkey is not None:
            tags.append(["p", to_pubkey])
        else:
            tags.append(["t", self.broadcast_tag])
        if expiration is not None:
            tags.append(["expiration", str(int(expiration))])
        event = {
            "created_at": int(time.time()),
            "kind": BSX_NOSTR_KIND,
            "tags": tags,
            "content": content,
        }
        if self.pow_target > 0:
            event = mineEventPow(
                self.privkey, event, self.pow_target, abort_event=self.abort_event
            )
        return signEvent(self.privkey, event)

    def publishEvent(
        self, event: dict, delay_event=None, wait_seconds: float = 10.0
    ) -> int:
        """Send event to all connected relays, wait for at least one OK.
        Returns the number of relays that accepted the event.
        """
        # Drain stale OK responses
        while True:
            try:
                self.ok_queue.get(block=False)
            except Empty:
                break

        # Mark own event as seen before sending so the subscription echo
        # is ignored even if a relay echoes it back immediately.
        with self.mutex:
            self._seen_event_ids[event["id"]] = True

        event_json: str = json.dumps(["EVENT", event], separators=(",", ":"))
        num_sent: int = 0
        for relay in self.relays:
            if relay.send(event_json):
                relay.num_events_sent += 1
                num_sent += 1
        if num_sent < 1:
            raise TemporaryError("No connected Nostr relays.")

        num_accepted: int = 0
        deadline: float = time.time() + wait_seconds
        while time.time() < deadline:
            if delay_event is not None and delay_event.is_set():
                break
            try:
                _, event_id, accepted, _ = self.ok_queue.get(block=True, timeout=0.5)
            except Empty:
                continue
            if event_id == event["id"] and accepted:
                num_accepted += 1
                break
        if num_accepted < 1:
            raise TemporaryError("No Nostr relay accepted the event.")
        self.num_messages_sent += 1
        return num_accepted

    def get_info(self) -> dict:
        return {
            "pubkey": self.pubkey,
            "broadcast_tag": self.broadcast_tag,
            "pow_target": self.pow_target,
            "messages_received": self.num_messages_received,
            "messages_sent": self.num_messages_sent,
            "relays": [
                {
                    "url": relay.url,
                    "connected": relay.connected,
                    "events_received": relay.num_events_received,
                    "events_sent": relay.num_events_sent,
                    "last_error": relay.last_error,
                }
                for relay in self.relays
            ],
        }
