#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Nostr transport tests.  No external infrastructure required, integration
tests run against an in-process mini relay (tests/basicswap/util/nostr_relay.py).

export PYTHONPATH=$(pwd)
pytest -v tests/basicswap/test_nostr.py
"""

import json
import logging
import os
import shutil
import sys
import threading
import time
import unittest

from coincurve.keys import PrivateKey, PublicKeyXOnly

from basicswap.util import TemporaryError
from basicswap.network.nostr_client import (
    BSX_NOSTR_KIND,
    MAX_POW_TARGET_BITS,
    MAX_RECV_QUEUE_SIZE,
    MAX_RELAY_MESSAGE_LEN,
    RELAY_EVENT_BURST,
    NostrClient,
    countLeadingZeroBits,
    eventID,
    getEventPow,
    getTagValue,
    mineEventPow,
    signEvent,
    verifyEvent,
)
from tests.basicswap.util.nostr_relay import MiniNostrRelay, eventMatchesFilter
from tests.basicswap.util.socks5_proxy import MiniSocks5Proxy

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


# BIP-340 reference test vectors (index, seckey, pubkey, aux, message, signature)
BIP340_VECTORS = [
    (
        0,
        "0000000000000000000000000000000000000000000000000000000000000003",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ),
    (
        1,
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    ),
]


class TestNostrPrimitives(unittest.TestCase):
    def test_bip340_vectors(self):
        for index, seckey_hex, pubkey_hex, aux_hex, msg_hex, sig_hex in BIP340_VECTORS:
            seckey = bytes.fromhex(seckey_hex)
            msg = bytes.fromhex(msg_hex)
            k = PrivateKey(seckey)
            assert k.public_key_xonly.format().hex().upper() == pubkey_hex

            sig = k.sign_schnorr(msg, aux_randomness=bytes.fromhex(aux_hex))
            assert sig.hex().upper() == sig_hex, f"Vector {index} signature mismatch"

            pk = PublicKeyXOnly(bytes.fromhex(pubkey_hex))
            pk.verify(sig, msg)

    def test_event_id(self):
        # Canonical serialisation: no whitespace, utf-8
        event_id = eventID("a" * 64, 1700000000, 1, [["t", "bsx"]], "hello")
        assert len(event_id) == 32
        event_id2 = eventID("a" * 64, 1700000000, 1, [["t", "bsx"]], "hello")
        assert event_id == event_id2
        event_id3 = eventID("a" * 64, 1700000001, 1, [["t", "bsx"]], "hello")
        assert event_id != event_id3

    def test_sign_verify(self):
        privkey = PrivateKey().secret
        event = {
            "created_at": int(time.time()),
            "kind": BSX_NOSTR_KIND,
            "tags": [["t", "bsx"]],
            "content": "dGVzdA==",
        }
        event = signEvent(privkey, event)
        assert verifyEvent(event)

        tampered = dict(event)
        tampered["content"] = "dGVzdDI="
        assert not verifyEvent(tampered)

        tampered = dict(event)
        tampered["sig"] = "00" * 64
        assert not verifyEvent(tampered)

    def test_pow(self):
        assert countLeadingZeroBits(bytes.fromhex("00" * 32)) == 256
        assert countLeadingZeroBits(bytes.fromhex("01" + "00" * 31)) == 7
        assert countLeadingZeroBits(bytes.fromhex("80" + "00" * 31)) == 0
        assert countLeadingZeroBits(bytes.fromhex("002f" + "00" * 30)) == 10

        privkey = PrivateKey().secret
        event = {
            "created_at": int(time.time()),
            "kind": BSX_NOSTR_KIND,
            "tags": [["t", "bsx"]],
            "content": "cG93dGVzdA==",
        }
        event = mineEventPow(privkey, event, 10)
        event = signEvent(privkey, event)
        assert verifyEvent(event)
        assert countLeadingZeroBits(bytes.fromhex(event["id"])) >= 10
        assert getEventPow(event) == 10
        assert getTagValue(event, "nonce") is not None

    def test_pow_abort(self):
        privkey = PrivateKey().secret
        event = {
            "created_at": int(time.time()),
            "kind": BSX_NOSTR_KIND,
            "tags": [["t", "bsx"]],
            "content": "cG93YWJvcnQ=",
        }
        abort_event = threading.Event()
        abort_event.set()
        # Must be transient so an abort during shutdown doesn't error the bid
        with self.assertRaises(TemporaryError):
            mineEventPow(privkey, event, 32, abort_event=abort_event)

    def test_pow_target_clamped(self):
        assert MAX_POW_TARGET_BITS <= 12
        client = NostrClient(
            ["ws://127.0.0.1:1"], PrivateKey().secret, logger, pow_target=64
        )
        assert client.pow_target == MAX_POW_TARGET_BITS
        client = NostrClient(
            ["ws://127.0.0.1:1"], PrivateKey().secret, logger, pow_target=-1
        )
        assert client.pow_target == 0

    def test_direct_event_also_has_broadcast_tag(self):
        client = NostrClient(["ws://127.0.0.1:1"], PrivateKey().secret, logger)
        event = client.buildEvent("ZGlyZWN0", to_pubkey="ab" * 32)
        assert getTagValue(event, "p") == "ab" * 32
        assert getTagValue(event, "t") == "bsx"

    def test_build_event_sign_key_override(self):
        client = NostrClient(["ws://127.0.0.1:1"], PrivateKey().secret, logger)
        route_key = PrivateKey()

        event = client.buildEvent("ZGVmYXVsdA==")
        assert event["pubkey"] == client.pubkey
        assert verifyEvent(event)

        event = client.buildEvent("cm91dGU=", sign_privkey=route_key.secret)
        assert event["pubkey"] == route_key.public_key_xonly.format().hex()
        assert event["pubkey"] != client.pubkey
        assert verifyEvent(event)

        # PoW is mined against the override key too
        client_pow = NostrClient(
            ["ws://127.0.0.1:1"], PrivateKey().secret, logger, pow_target=6
        )
        event = client_pow.buildEvent("cG93", sign_privkey=route_key.secret)
        assert event["pubkey"] == route_key.public_key_xonly.format().hex()
        assert verifyEvent(event)
        assert getEventPow(event) >= 6

    def test_plaintext_relays(self):
        client = NostrClient(
            ["ws://127.0.0.1:1", "wss://relay.example.com", " ws://other:80 "],
            PrivateKey().secret,
            logger,
        )
        assert client.getPlaintextRelays() == ["ws://127.0.0.1:1", "ws://other:80"]
        client = NostrClient(["wss://relay.example.com"], PrivateKey().secret, logger)
        assert client.getPlaintextRelays() == []

    def test_oversized_relay_message_dropped(self):
        client = NostrClient(["ws://127.0.0.1:1"], PrivateKey().secret, logger)
        relay = client.relays[0]
        received = []
        client.receiveEvent = lambda url, event: received.append(event)

        privkey = PrivateKey().secret
        event = signEvent(
            privkey,
            {
                "created_at": int(time.time()),
                "kind": BSX_NOSTR_KIND,
                "tags": [["t", "bsx"]],
                "content": "b2s=",
            },
        )
        relay.on_message(None, json.dumps(["EVENT", "sub", event]))
        assert len(received) == 1
        assert relay.num_oversized_messages == 0

        event["content"] = "A" * (MAX_RELAY_MESSAGE_LEN + 1)
        relay.on_message(None, json.dumps(["EVENT", "sub", event]))
        assert len(received) == 1
        assert relay.num_oversized_messages == 1

    def test_filter_matching(self):
        event = {
            "id": "ab" * 32,
            "pubkey": "cd" * 32,
            "created_at": 1700000000,
            "kind": BSX_NOSTR_KIND,
            "tags": [["t", "bsx"]],
            "content": "x",
        }
        assert eventMatchesFilter(event, {"kinds": [BSX_NOSTR_KIND]})
        assert not eventMatchesFilter(event, {"kinds": [1]})
        assert eventMatchesFilter(event, {"#t": ["bsx"]})
        assert not eventMatchesFilter(event, {"#t": ["other"]})
        assert not eventMatchesFilter(event, {"#p": ["cd" * 32]})
        assert eventMatchesFilter(event, {"since": 1699999999})
        assert not eventMatchesFilter(event, {"since": 1700000001})


class TestNostrInboundGates(unittest.TestCase):
    """Inbound event gates: kind, PoW, and SMSG replay dedup (CR-N03)."""

    def makeClient(self, **kwargs) -> NostrClient:
        return NostrClient(["ws://127.0.0.1:1"], PrivateKey().secret, logger, **kwargs)

    def makeEvent(self, kind=BSX_NOSTR_KIND, content="dGVzdA==", pow_bits=0) -> dict:
        privkey = PrivateKey().secret
        event = {
            "created_at": int(time.time()),
            "kind": kind,
            "tags": [["t", "bsx"]],
            "content": content,
        }
        if pow_bits > 0:
            event = mineEventPow(privkey, event, pow_bits)
        return signEvent(privkey, event)

    def test_wrong_kind_dropped(self):
        # Relays are not obliged to honour REQ filters
        client = self.makeClient()
        client.receiveEvent("test", self.makeEvent(kind=1))
        assert client.queue_get() is None

        client.receiveEvent("test", self.makeEvent())
        assert client.queue_get() is not None

    def test_inbound_pow_enforced(self):
        client = self.makeClient(min_incoming_pow=8)

        # No committed PoW
        client.receiveEvent("test", self.makeEvent())
        assert client.queue_get() is None

        # Fake claimed id with leading zeros passes the gate but fails verify
        event = self.makeEvent()
        event["tags"].append(["nonce", "0", "8"])
        event["id"] = "00" * 32
        client.receiveEvent("test", event)
        assert client.queue_get() is None

        # Genuinely mined event is accepted
        client.receiveEvent("test", self.makeEvent(pow_bits=8))
        assert client.queue_get() is not None

        assert self.makeClient(min_incoming_pow=99).min_incoming_pow == (
            MAX_POW_TARGET_BITS
        )
        assert self.makeClient(min_incoming_pow=-1).min_incoming_pow == 0

    def test_outgoing_pow_does_not_filter_incoming(self):
        pow_client = self.makeClient(pow_target=8)
        default_client = self.makeClient()

        pow_client.receiveEvent("test", self.makeEvent())
        assert pow_client.queue_get() is not None
        mined = pow_client.buildEvent("cG93")
        assert getEventPow(mined) >= 8
        default_client.receiveEvent("test", mined)
        assert default_client.queue_get() is not None

        info = pow_client.get_info()
        assert info["pow_target"] == 8
        assert info["min_incoming_pow"] == 0

    def test_unsolicited_oks_dropped(self):
        client = self.makeClient()
        relay = client.relays[0]
        for i in range(1000):
            relay.on_message(
                None,
                json.dumps(["OK", os.urandom(32).hex(), True, "x" * 60000]),
            )
        assert len(client._pending_publishes) == 0
        assert client.num_unsolicited_oks == 1000
        assert client.get_info()["unsolicited_oks"] == 1000

    def test_ok_matched_to_pending_publish(self):
        from unittest import mock
        from basicswap.network.nostr_client import (
            MAX_OK_MESSAGE_LEN,
            MAX_PENDING_PUBLISHES,
            PendingPublish,
        )

        client = self.makeClient()
        relay = client.relays[0]
        event = client.buildEvent("b2s=")
        result = {}

        def publish():
            try:
                result["accepted"] = client.publishEvent(event, wait_seconds=5.0)
            except Exception as e:
                result["error"] = e

        with mock.patch.object(relay, "send", return_value=True):
            t = threading.Thread(target=publish)
            t.start()
            for i in range(50):
                if event["id"] in client._pending_publishes:
                    break
                time.sleep(0.02)
            assert event["id"] in client._pending_publishes
            client.receiveOK(relay.url, "ab" * 32, True, "")
            client.receiveOK(
                relay.url, event["id"], False, "rate-limited: " + "y" * 500
            )
            time.sleep(0.1)
            assert t.is_alive()
            pending = client._pending_publishes[event["id"]]
            assert len(pending.rejected[relay.url]) == MAX_OK_MESSAGE_LEN
            client.receiveOK(relay.url, event["id"], True, "")
            t.join(timeout=5.0)
        assert result.get("accepted") == 1
        assert event["id"] not in client._pending_publishes
        assert client.num_unsolicited_oks == 1

        event_b = client.buildEvent("cmVq")

        def publish_b():
            try:
                client.publishEvent(event_b, wait_seconds=1.0)
            except Exception as e:
                result["error_b"] = e

        with mock.patch.object(relay, "send", return_value=True):
            t = threading.Thread(target=publish_b)
            t.start()
            for i in range(50):
                if event_b["id"] in client._pending_publishes:
                    break
                time.sleep(0.02)
            client.receiveOK(relay.url, event_b["id"], False, "blocked: no")
            time.sleep(0.1)
            assert t.is_alive()
            t.join(timeout=10.0)
        assert isinstance(result.get("error_b"), TemporaryError)
        assert "blocked: no" in str(result["error_b"])

        for i in range(MAX_PENDING_PUBLISHES):
            client._pending_publishes[os.urandom(32).hex()] = PendingPublish()
        with self.assertRaisesRegex(TemporaryError, "Too many"):
            client.publishEvent(client.buildEvent("ZnVsbA=="), wait_seconds=0.0)

    def test_frame_limits_reject_before_payload(self):
        import struct
        from websocket import WebSocketPayloadException
        from websocket._abnf import ABNF
        from basicswap.network.nostr_client import (
            MAX_WS_FRAME_LEN,
            BoundedContinuousFrame,
            BoundedFrameBuffer,
        )

        claimed = 8 * 1024 * 1024
        header = bytes([0x81, 127]) + struct.pack(">Q", claimed)
        offered = bytearray(header)
        requested = []

        def recv(n):
            requested.append(n)
            if len(offered) < 1:
                raise AssertionError("Payload requested after oversized header")
            chunk = bytes(offered[:n])
            del offered[:n]
            return chunk

        fb = BoundedFrameBuffer(recv, True, MAX_WS_FRAME_LEN)
        with self.assertRaisesRegex(WebSocketPayloadException, "Frame too large"):
            fb.recv_frame()
        assert sum(requested) <= len(header)

        payload = b"a" * 200
        offered = bytearray(bytes([0x81, 126]) + struct.pack(">H", 200) + payload)
        fb = BoundedFrameBuffer(recv, True, MAX_WS_FRAME_LEN)
        frame = fb.recv_frame()
        assert frame.data == payload

        cf = BoundedContinuousFrame(False, True, 1000)
        first = ABNF(0, 0, 0, 0, ABNF.OPCODE_TEXT, 0, b"x" * 600)
        cf.validate(first)
        cf.add(first)
        second = ABNF(1, 0, 0, 0, ABNF.OPCODE_CONT, 0, b"y" * 500)
        cf.validate(second)
        with self.assertRaisesRegex(WebSocketPayloadException, "Message too large"):
            cf.add(second)
        assert cf.cont_data is None

    def test_closed_subscription_tracked(self):
        from unittest import mock

        client = self.makeClient()
        relay = client.relays[0]
        sent = []
        ws = mock.Mock()
        ws.send = lambda data: sent.append(json.loads(data))
        ws.sock = None

        relay.on_open(ws)
        assert relay.connected
        assert [m[0] for m in sent] == ["REQ", "REQ"]
        assert relay.isReceiving()
        assert client.numReceiving() == 1

        with mock.patch.object(relay, "scheduleResubscribe") as mock_sched:
            relay.on_message(ws, json.dumps(["CLOSED", "bsxsub0", "error: backend"]))
            mock_sched.assert_called_once()
        assert relay.connected
        assert not relay.isReceiving()
        assert client.numConnected() == 1
        assert client.numReceiving() == 0
        assert relay.num_subscriptions_closed == 1
        assert "error: backend" in relay.last_error
        info = client.get_info()["relays"][0]
        assert info["connected"] is True
        assert info["receiving"] is False
        assert info["subscriptions_closed"] == 1

        del sent[:]
        relay.ws = ws
        relay.resubscribe()
        assert [(m[0], m[1]) for m in sent] == [("REQ", "bsxsub0")]
        assert relay.isReceiving()

        with mock.patch.object(relay, "scheduleResubscribe") as mock_sched:
            relay.on_message(
                ws, json.dumps(["CLOSED", "bsxsub1", "auth-required: login"])
            )
            mock_sched.assert_not_called()
        assert not relay.isReceiving()
        assert "auth-required" in relay.last_error

        with mock.patch.object(relay, "scheduleResubscribe") as mock_sched:
            relay.on_message(ws, json.dumps(["CLOSED", "other", ""]))
            mock_sched.assert_not_called()
        assert relay.num_subscriptions_closed == 2

        from basicswap.network.nostr_client import (
            RESUBSCRIBE_BASE_SECONDS,
            RESUBSCRIBE_MAX_SECONDS,
        )

        waits = []
        with mock.patch(
            "basicswap.network.nostr_client.threading.Timer",
            side_effect=lambda w, fn: waits.append(w) or mock.Mock(),
        ):
            for i in range(10):
                relay.scheduleResubscribe()
                relay._resub_timer = None
        assert waits[0] == RESUBSCRIBE_BASE_SECONDS
        assert waits[1] == RESUBSCRIBE_BASE_SECONDS * 2
        assert waits[-1] == RESUBSCRIBE_MAX_SECONDS
        assert max(waits) == RESUBSCRIBE_MAX_SECONDS

    def test_recv_queue_bounded(self):
        from unittest import mock

        client = self.makeClient()
        # Skip the signature check so the test can fill the queue quickly
        with mock.patch(
            "basicswap.network.nostr_client.verifyEvent", return_value=True
        ):
            events = []
            for i in range(MAX_RECV_QUEUE_SIZE + 10):
                event = {
                    "id": "%064x" % i,
                    "pubkey": "cd" * 32,
                    "created_at": int(time.time()),
                    "kind": BSX_NOSTR_KIND,
                    "tags": [["t", "bsx"]],
                    "content": "dGVzdA==",
                    "sig": "00" * 64,
                }
                events.append(event)
                client.receiveEvent("test", event)
            assert client.recv_queue.qsize() == MAX_RECV_QUEUE_SIZE
            assert client.num_messages_dropped == 10
            assert client.num_messages_received == MAX_RECV_QUEUE_SIZE
            assert client.get_info()["messages_dropped"] == 10

            # A dropped event is not remembered as seen: once the main loop
            # drains the queue a redelivery is accepted.
            assert client.queue_get() is not None
            client.receiveEvent("test", events[-1])
            assert client.recv_queue.qsize() == MAX_RECV_QUEUE_SIZE
            assert client.num_messages_dropped == 10

    def test_relay_rate_limit(self):
        client = self.makeClient()
        relay = client.relays[0]
        received = []
        client.receiveEvent = lambda url, event: received.append(event)

        message = json.dumps(["EVENT", "sub", {"id": "ab" * 32}])
        for i in range(RELAY_EVENT_BURST + 50):
            relay.on_message(None, message)
        assert len(received) == RELAY_EVENT_BURST
        assert relay.num_events_rate_limited == 50
        assert relay.num_events_received == RELAY_EVENT_BURST + 50
        assert client.get_info()["relays"][0]["events_rate_limited"] == 50

        # Tokens refill over time
        relay._tokens_updated -= 1.0
        relay.on_message(None, message)
        assert len(received) == RELAY_EVENT_BURST + 1

        # Non-event relay messages are not counted against the limit
        relay._tokens = 0.0
        relay._tokens_updated = time.monotonic()
        relay.on_message(None, json.dumps(["EOSE", "sub"]))
        relay.on_message(None, json.dumps(["OK", "ab" * 32, True, ""]))
        assert relay.num_events_rate_limited == 50

    def test_smsg_replay_dropped(self):
        # The same SMSG blob wrapped in a fresh event must not trigger
        # another trial decryption.
        import base64
        from types import SimpleNamespace
        from unittest import mock
        from basicswap.network.nostr import parseNostrEvent

        client = self.makeClient()
        network = {"client": client}
        fake_self = SimpleNamespace(
            num_nostr_messages_received=0,
            num_direct_nostr_messages_received=0,
        )

        content = base64.b64encode(bytes(200)).decode("utf-8")
        event_a = self.makeEvent(content=content)
        event_b = self.makeEvent(content=content)
        assert event_a["id"] != event_b["id"]

        with mock.patch(
            "basicswap.network.nostr.decryptNostrMsg", return_value={"payload": b"x"}
        ) as mock_decrypt:
            assert parseNostrEvent(fake_self, network, event_a) is not None
            assert parseNostrEvent(fake_self, network, event_b) is None
        assert mock_decrypt.call_count == 1

    def test_failed_decrypt_does_not_burn_smsg_id(self):
        # A CONNECT_REQ ACK can arrive before the bid address is queryable.
        # A decrypt miss must not permanently drop that SMSG id.
        import base64
        from types import SimpleNamespace
        from unittest import mock
        from basicswap.network.nostr import parseNostrEvent

        client = self.makeClient()
        network = {"client": client}
        fake_self = SimpleNamespace(
            num_nostr_messages_received=0,
            num_direct_nostr_messages_received=0,
        )

        content = base64.b64encode(bytes(200)).decode("utf-8")
        event = self.makeEvent(content=content)

        with mock.patch(
            "basicswap.network.nostr.decryptNostrMsg",
            side_effect=[None, {"payload": b"x"}],
        ) as mock_decrypt:
            assert parseNostrEvent(fake_self, network, event) is None
            assert parseNostrEvent(fake_self, network, event) is not None
        assert mock_decrypt.call_count == 2


class TestNostrClientRelay(unittest.TestCase):
    """Integration tests against the in-process mini relay."""

    def setUp(self):
        # A fresh relay per test, stored events would leak between tests otherwise
        self.relay = MiniNostrRelay()
        self.relay.start()
        self.delay_event = threading.Event()

    def tearDown(self):
        self.relay.stop()

    def makeClient(self, **kwargs) -> NostrClient:
        client = NostrClient(
            [self.relay.url()],
            PrivateKey().secret,
            logger,
            **kwargs,
        )
        client.start()
        client.waitForConnected(self.delay_event)
        return client

    def waitForEvent(self, client, timeout: float = 10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            event = client.queue_get()
            if event is not None:
                return event
            time.sleep(0.05)
        raise TimeoutError("No event received")

    def test_send_failure_is_transient(self):
        # Send failures must raise TemporaryError so checkQueuedActions
        # retries the queued swap action instead of latching BID_ERROR.
        client = NostrClient([self.relay.url()], PrivateKey().secret, logger)
        event = client.buildEvent("dHJhbnNpZW50", expiration=int(time.time()) + 600)

        # Not started: no connected relays
        with self.assertRaises(TemporaryError):
            client.publishEvent(event, delay_event=self.delay_event)

        # Connected, but no relay OK arrives before the deadline
        client_b = self.makeClient()
        try:
            event_b = client_b.buildEvent(
                "dHJhbnNpZW50Mg==", expiration=int(time.time()) + 600
            )
            with self.assertRaises(TemporaryError):
                client_b.publishEvent(
                    event_b, delay_event=self.delay_event, wait_seconds=0.0
                )
        finally:
            client_b.stop()

    def test_broadcast(self):
        client_a = self.makeClient()
        client_b = self.makeClient()
        try:
            event = client_a.buildEvent(
                "YnJvYWRjYXN0", expiration=int(time.time()) + 600
            )
            client_a.publishEvent(event, delay_event=self.delay_event)

            received = self.waitForEvent(client_b)
            assert received["id"] == event["id"]
            assert received["content"] == "YnJvYWRjYXN0"
            assert getTagValue(received, "t") == "bsx"

            # Sender must not see its own event echoed back
            assert client_a.queue_get() is None
        finally:
            client_a.stop()
            client_b.stop()

    def test_socks_proxy(self):
        # Relay connections go through the configured SOCKS5 proxy
        proxy = MiniSocks5Proxy()
        proxy.start()
        client_a = self.makeClient(socks_proxy=proxy.address())
        client_b = self.makeClient()
        try:
            assert client_a.relays[0].connected
            assert proxy.targets == [("127.0.0.1", self.relay.port)]

            event = client_a.buildEvent(
                "cHJveGllZA==", expiration=int(time.time()) + 600
            )
            client_a.publishEvent(event, delay_event=self.delay_event)
            received = self.waitForEvent(client_b)
            assert received["id"] == event["id"]
        finally:
            client_a.stop()
            client_b.stop()
            proxy.stop()

        # An unreachable proxy must not fall back to a direct connection
        client_c = NostrClient(
            [self.relay.url()],
            PrivateKey().secret,
            logger,
            socks_proxy=proxy.address(),
        )
        client_c.start()
        try:
            time.sleep(1.0)
            assert not client_c.relays[0].connected
            assert client_c.relays[0].last_error != ""
        finally:
            client_c.stop()

    def test_direct_message(self):
        client_a = self.makeClient()
        client_b = self.makeClient()
        client_c = self.makeClient()
        try:
            event = client_a.buildEvent(
                "ZGlyZWN0",
                to_pubkey=client_b.pubkey,
                expiration=int(time.time()) + 600,
            )
            client_a.publishEvent(event, delay_event=self.delay_event)

            received = self.waitForEvent(client_b)
            assert received["id"] == event["id"]
            assert getTagValue(received, "p") == client_b.pubkey
            assert getTagValue(received, "t") == "bsx"

            # DMs also carry #t so public relays deliver them; client_c
            # is subscribed to the broadcast tag and therefore receives too.
            received_c = self.waitForEvent(client_c)
            assert received_c["id"] == event["id"]
        finally:
            client_a.stop()
            client_b.stop()
            client_c.stop()

    def test_expired_event_skipped(self):
        client_a = self.makeClient()
        client_b = self.makeClient()
        try:
            event = client_a.buildEvent(
                "ZXhwaXJlZA==", expiration=int(time.time()) - 10
            )
            client_a.publishEvent(event, delay_event=self.delay_event)
            time.sleep(0.5)
            assert client_b.queue_get() is None
        finally:
            client_a.stop()
            client_b.stop()

    def test_invalid_sig_skipped(self):
        client_a = self.makeClient()
        client_b = self.makeClient()
        try:
            event = client_a.buildEvent("YmFkc2ln")
            event["content"] = "dGFtcGVyZWQ="  # Invalidate after signing
            event_json = json.dumps(["EVENT", event], separators=(",", ":"))
            for relay in client_a.relays:
                relay.send(event_json)
            time.sleep(0.5)
            assert client_b.queue_get() is None
        finally:
            client_a.stop()
            client_b.stop()

    def test_corrupted_copy_does_not_block_event(self):
        # A corrupted copy must not block the genuine event that follows it
        client_a = self.makeClient()
        client_b = self.makeClient()
        try:
            event = client_a.buildEvent("cG9pc29u", expiration=int(time.time()) + 600)
            corrupted = dict(event)
            corrupted["sig"] = "00" * 64
            client_b.receiveEvent(self.relay.url(), corrupted)
            assert client_b.queue_get() is None

            client_b.receiveEvent(self.relay.url(), event)
            received = client_b.queue_get()
            assert received is not None
            assert received["id"] == event["id"]

            # Verified events are still deduplicated
            client_b.receiveEvent(self.relay.url(), event)
            assert client_b.queue_get() is None
        finally:
            client_a.stop()
            client_b.stop()

    def test_backlog_on_subscribe(self):
        client_a = self.makeClient()
        try:
            event = client_a.buildEvent(
                "YmFja2xvZw==", expiration=int(time.time()) + 600
            )
            client_a.publishEvent(event, delay_event=self.delay_event)

            # A client connecting later must receive the stored event
            client_b = self.makeClient()
            try:
                received = self.waitForEvent(client_b)
                assert received["id"] == event["id"]
            finally:
                client_b.stop()
        finally:
            client_a.stop()

    def test_pow_client(self):
        client_a = self.makeClient(pow_target=8)
        client_b = self.makeClient()
        try:
            event = client_a.buildEvent("cG93", expiration=int(time.time()) + 600)
            assert countLeadingZeroBits(bytes.fromhex(event["id"])) >= 8
            client_a.publishEvent(event, delay_event=self.delay_event)
            received = self.waitForEvent(client_b)
            assert getEventPow(received) == 8

            event_b = client_b.buildEvent("bm9wb3c=", expiration=int(time.time()) + 600)
            assert getEventPow(event_b) == 0
            client_b.publishEvent(event_b, delay_event=self.delay_event)
            received = self.waitForEvent(client_a)
            assert received["id"] == event_b["id"]
        finally:
            client_a.stop()
            client_b.stop()

    def test_closed_subscription_recovers(self):
        from unittest import mock

        with mock.patch("basicswap.network.nostr_client.RESUBSCRIBE_BASE_SECONDS", 0.2):
            client_a = self.makeClient()
            client_b = self.makeClient()
            try:
                for i in range(100):
                    if client_a.numReceiving() == 1 and client_b.numReceiving() == 1:
                        break
                    time.sleep(0.05)
                assert client_a.numReceiving() == 1

                assert self.relay.closeSubscriptions("error: backend restart") == 4
                for i in range(100):
                    if client_a.numReceiving() == 0 and client_b.numReceiving() == 0:
                        break
                    time.sleep(0.05)
                assert client_a.numConnected() == 1
                assert client_a.numReceiving() == 0
                relay = client_a.relays[0]
                assert "backend restart" in relay.last_error
                assert client_a.get_info()["relays"][0]["receiving"] is False

                event = client_a.buildEvent(
                    "bG9zdA==", expiration=int(time.time()) + 600
                )
                client_a.publishEvent(event, delay_event=self.delay_event)

                for i in range(100):
                    if client_a.numReceiving() == 1 and client_b.numReceiving() == 1:
                        break
                    time.sleep(0.05)
                assert client_b.numReceiving() == 1
                received = self.waitForEvent(client_b)
                assert received["id"] == event["id"]

                event = client_a.buildEvent(
                    "YWZ0ZXI=", expiration=int(time.time()) + 600
                )
                client_a.publishEvent(event, delay_event=self.delay_event)
                received = self.waitForEvent(client_b)
                assert received["id"] == event["id"]

                assert self.relay.closeSubscriptions("auth-required: nope") == 4
                time.sleep(1.0)
                assert client_a.numConnected() == 1
                assert client_a.numReceiving() == 0
                assert "auth-required" in client_a.relays[0].last_error
            finally:
                client_a.stop()
                client_b.stop()

    def test_oversized_frame_rejected_early(self):
        client = self.makeClient()
        try:
            relay = client.relays[0]
            t = threading.Thread(
                target=self.relay.sendOversizedFrames, args=(8 * 1024 * 1024,)
            )
            t.start()
            for i in range(100):
                if not relay.connected:
                    break
                time.sleep(0.05)
            t.join(timeout=5.0)
            assert not relay.connected
            assert "Frame too large" in relay.last_error
            assert relay.num_oversized_messages == 0
        finally:
            client.stop()


class BasicSwapFixture(unittest.TestCase):
    """A BasicSwap instance with smsg and nostr configured, networks not started."""

    def setUp(self):
        import basicswap.config as cfg
        from basicswap.basicswap import BasicSwap
        from basicswap.util.address import toWIF

        self.basicswap_dir = "/tmp/bsx_test_nostr_settings"
        if os.path.exists(self.basicswap_dir):
            shutil.rmtree(self.basicswap_dir)
        os.makedirs(self.basicswap_dir)

        PREFIX_SECRET_KEY_REGTEST = 0x2E
        k = PrivateKey()
        self.settings = {
            "network_key": toWIF(PREFIX_SECRET_KEY_REGTEST, k.secret),
            "network_pubkey": k.public_key.format().hex(),
            "networks": [
                {"type": "smsg", "enabled": True},
                {
                    "type": "nostr",
                    "relays": ["wss://relay.one", "wss://relay.two"],
                    "private_key": PrivateKey().to_hex(),
                    "pow_target": 0,
                    "enabled": True,
                },
            ],
        }
        settings_path = os.path.join(self.basicswap_dir, cfg.CONFIG_FILENAME)
        with open(settings_path, "w") as fp:
            json.dump(self.settings, fp, indent=4)

        self.sc = BasicSwap(
            self.basicswap_dir,
            self.settings,
            "regtest",
            log_name="bsx_test_nostr",
        )

    def tearDown(self):
        del self.sc
        shutil.rmtree(self.basicswap_dir, ignore_errors=True)


class TestTrialDecryptCandidates(BasicSwapFixture):

    def test_candidate_addresses(self):
        from unittest import mock
        from basicswap.basicswap_util import AddressTypes, BidStates
        from basicswap.db import (
            Bid,
            Concepts,
            DirectMessageRoute,
            Offer,
            SmsgAddress,
        )
        from basicswap.network.simplex import decryptSimplexMsg

        now = self.sc.getTime()

        def add_offer(offer_id, addr_from, was_sent, expire_at):
            self.sc.add(
                Offer(
                    offer_id=offer_id,
                    active_ind=1,
                    addr_from=addr_from,
                    was_sent=was_sent,
                    created_at=now,
                    expire_at=expire_at,
                ),
                cursor,
            )

        def add_bid(offer_id, bid_addr, was_sent, state, expire_at):
            bid = Bid(
                bid_id=os.urandom(28),
                offer_id=offer_id,
                active_ind=1,
                bid_addr=bid_addr,
                was_sent=was_sent,
                was_received=not was_sent,
                created_at=now,
                expire_at=expire_at,
            )
            bid.setState(state)
            self.sc.add(bid, cursor)

        def add_route(active_ind, local, remote):
            self.sc.add(
                DirectMessageRoute(
                    active_ind=active_ind,
                    network_id=3,
                    linked_type=Concepts.OFFER,
                    smsg_addr_local=local,
                    smsg_addr_remote=remote,
                    route_data=b"{}",
                    created_at=now,
                ),
                cursor,
            )

        def add_addr(addr, use_type, active_ind=1):
            self.sc.add(
                SmsgAddress(
                    active_ind=active_ind,
                    created_at=now,
                    addr=addr,
                    use_type=int(use_type),
                ),
                cursor,
            )

        try:
            cursor = self.sc.openDB()
            from basicswap.db_upgrades import addBidState

            for state in BidStates:
                addBidState(self.sc, state, now, cursor)

            add_offer(b"\x01" * 28, "own_offer_active", True, now + 3600)
            add_offer(b"\x02" * 28, "own_offer_expired_live_bid", True, now - 10)
            add_bid(
                b"\x02" * 28, "remote_bidder", False, BidStates.BID_ACCEPTED, now - 10
            )
            add_offer(b"\x03" * 28, "own_offer_expired", True, now - 10)
            add_bid(
                b"\x03" * 28,
                "remote_bidder_done",
                False,
                BidStates.SWAP_COMPLETED,
                now - 10,
            )
            add_offer(b"\x04" * 28, "remote_offer_active", False, now + 3600)
            add_offer(b"\x05" * 28, "remote_offer_bid_on", False, now + 3600)
            add_bid(
                b"\x05" * 28,
                "own_bid_waiting",
                True,
                BidStates.CONNECT_REQ_SENT,
                now + 3600,
            )
            add_bid(
                b"\x05" * 28,
                "own_bid_swapping",
                True,
                BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED,
                now - 10,
            )
            add_bid(
                b"\x05" * 28,
                "own_bid_completed",
                True,
                BidStates.SWAP_COMPLETED,
                now + 3600,
            )
            add_bid(b"\x05" * 28, "own_bid_expired", True, BidStates.BID_SENT, now - 10)
            add_route(2, "own_route_pending", "remote_a")
            add_route(1, "own_route_active_no_bid", "remote_b")
            add_addr("recv_offer_addr", AddressTypes.RECV_OFFER)
            add_addr("recv_offer_addr_disabled", AddressTypes.RECV_OFFER, 0)
            add_addr("portal_local_addr", AddressTypes.PORTAL_LOCAL)
            add_addr("send_offer_to_addr", AddressTypes.SEND_OFFER)
            for i in range(100):
                add_addr(f"old_bid_addr_{i}", AddressTypes.BID)
                add_addr(f"old_offer_addr_{i}", AddressTypes.OFFER)
        finally:
            self.sc.closeDB(cursor)

        tried = []

        def fake_privkey(cursor, addr):
            tried.append(addr)
            raise ValueError("key not found")

        with (
            mock.patch.object(self.sc, "ci", return_value=mock.Mock()),
            mock.patch.object(
                self.sc, "getPrivkeyForAddress", side_effect=fake_privkey
            ),
        ):
            assert decryptSimplexMsg(self.sc, os.urandom(300)) is None

        assert sorted(tried) == sorted(
            [
                "own_offer_active",
                "own_offer_expired_live_bid",
                "own_bid_waiting",
                "own_bid_swapping",
                "own_route_pending",
                "recv_offer_addr",
                "portal_local_addr",
            ]
        )

    def test_privkey_cache(self):
        from unittest import mock

        with mock.patch.object(
            self.sc, "_lookupPrivkeyForAddress", return_value=b"k" * 32
        ) as mock_lookup:
            assert self.sc.getPrivkeyForAddress(None, "addr_a") == b"k" * 32
            assert self.sc.getPrivkeyForAddress(None, "addr_a") == b"k" * 32
            assert mock_lookup.call_count == 1
            for i in range(self.sc._privkey_cache_size + 10):
                self.sc.getPrivkeyForAddress(None, f"addr_{i}")
            assert len(self.sc._privkey_cache) == self.sc._privkey_cache_size
            assert "addr_a" not in self.sc._privkey_cache

        with mock.patch.object(
            self.sc, "_lookupPrivkeyForAddress", side_effect=ValueError("locked")
        ) as mock_lookup:
            for i in range(2):
                with self.assertRaises(ValueError):
                    self.sc.getPrivkeyForAddress(None, "addr_locked")
            assert mock_lookup.call_count == 2


class TestNetworkSettings(BasicSwapFixture):
    """editNetworkSettings and getNetworksInfo on a BasicSwap instance."""

    def test_send_with_nostr_route_but_network_inactive(self):
        # An established nostr route must not break sendMessage when the
        # nostr network is inactive, it should fall back to broadcast.
        from unittest import mock
        from basicswap.basicswap_util import MessageNetworks

        fake_route = mock.Mock()
        fake_route.route_data = json.dumps({"remote_pubkey": "ab" * 32}).encode("UTF-8")

        def fake_get_route(network_id, addr_from, addr_to, cursor=None):
            if network_id == int(MessageNetworks.NOSTR):
                return fake_route
            return None

        self.sc.active_networks = []  # Started node with nostr disabled
        with mock.patch.object(self.sc, "getMessageRoute", side_effect=fake_get_route):
            # No active networks, must not raise "Network not found."
            message_id = self.sc.sendMessage("addr_a", "addr_b", "00", 3600, None)
        assert message_id is None

    def test_send_failure_retries_queued_action(self):
        from unittest import mock
        from basicswap.basicswap_util import ActionTypes, BidStates
        from basicswap.db import Action, Bid

        bid_id = bytes.fromhex("aa" * 28)
        now = self.sc.getTime()
        try:
            cursor = self.sc.openDB()
            bid = Bid(
                bid_id=bid_id,
                offer_id=bytes(28),
                active_ind=1,
                created_at=now,
                expire_at=now + 3600,
                was_sent=True,
            )
            bid.setState(BidStates.SWAP_DELAYING)
            self.sc.add(bid, cursor)
            self.sc.add(
                Action(
                    active_ind=1,
                    created_at=now,
                    trigger_at=now,
                    action_type=int(ActionTypes.SEND_XMR_SWAP_LOCK_TX_A),
                    linked_id=bid_id,
                ),
                cursor,
            )
        finally:
            self.sc.closeDB(cursor)

        # The real failure mode: publishing with no connected relays
        client = NostrClient(["ws://127.0.0.1:1"], PrivateKey().secret, logger)

        def fail_send(bid_id_arg, cursor_arg):
            event = client.buildEvent("dGVzdA==", expiration=int(time.time()) + 600)
            client.publishEvent(event, delay_event=threading.Event())

        def read_state():
            try:
                cursor = self.sc.openDB()
                action_row = cursor.execute(
                    "SELECT active_ind FROM actions WHERE linked_id = :bid_id",
                    {"bid_id": bid_id},
                ).fetchone()
                bid_state = cursor.execute(
                    "SELECT state FROM bids WHERE bid_id = :bid_id",
                    {"bid_id": bid_id},
                ).fetchone()[0]
            finally:
                self.sc.closeDB(cursor)
            return action_row, bid_state

        with mock.patch.object(self.sc, "isSystemUnlocked", return_value=True):
            with mock.patch.object(
                self.sc, "sendXmrBidCoinALockTx", side_effect=fail_send
            ):
                self.sc.checkQueuedActions()

            action_row, bid_state = read_state()
            assert action_row is not None and action_row[0] == 1  # Kept for retry
            assert bid_state != BidStates.BID_ERROR

            # A non-transient failure must still error the bid
            with mock.patch.object(
                self.sc,
                "sendXmrBidCoinALockTx",
                side_effect=ValueError("permanent failure"),
            ):
                self.sc.checkQueuedActions()

            action_row, bid_state = read_state()
            assert action_row is None or action_row[0] != 1
            assert bid_state == BidStates.BID_ERROR

    def test_startup_continues_without_relay(self):
        from unittest import mock
        from basicswap.network.nostr import initialiseNostrNetwork

        self.sc.active_networks = []
        nostr_config = next(
            n for n in self.sc.settings["networks"] if n["type"] == "nostr"
        )
        with mock.patch("basicswap.network.nostr.NostrClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.waitForConnected.side_effect = ValueError(
                "Nostr waitForConnected timed-out."
            )
            initialiseNostrNetwork(self.sc, nostr_config)

        assert any(n["type"] == "nostr" for n in self.sc.active_networks)
        assert mock_client in self.sc.threads
        mock_client.stop.assert_not_called()

    def test_startup_fails_if_nostr_is_only_network(self):
        from unittest import mock
        from basicswap.network.nostr import initialiseNostrNetwork

        self.sc.active_networks = []
        for network in self.sc.settings["networks"]:
            if network["type"] != "nostr":
                network["enabled"] = False
        nostr_config = next(
            n for n in self.sc.settings["networks"] if n["type"] == "nostr"
        )
        with mock.patch("basicswap.network.nostr.NostrClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.waitForConnected.side_effect = ValueError(
                "Nostr waitForConnected timed-out."
            )
            with self.assertRaises(ValueError):
                initialiseNostrNetwork(self.sc, nostr_config)

        assert not any(n["type"] == "nostr" for n in self.sc.active_networks)
        mock_client.stop.assert_called_once()

    def test_networks_info(self):
        info = self.sc.getNetworksInfo()
        assert len(info) == 2
        by_type = {n["type"]: n for n in info}
        assert by_type["smsg"]["enabled"] is True
        assert by_type["nostr"]["enabled"] is True
        assert by_type["nostr"]["relays"] == ["wss://relay.one", "wss://relay.two"]
        assert by_type["nostr"]["active"] is False  # Networks not started
        assert by_type["nostr"]["messages_received_broadcast"] == 0
        assert by_type["nostr"]["messages_received_direct"] == 0
        assert by_type["nostr"]["messages_sent_broadcast"] == 0
        assert by_type["nostr"]["messages_sent_direct"] == 0

    def test_concurrent_settings_edits_both_persist(self):
        import basicswap.config as cfg

        nostr_net = next(
            n for n in self.sc.settings["networks"] if n["type"] == "nostr"
        )
        old_key = nostr_net["private_key"]
        results = {}

        def regenerate():
            results["key"] = self.sc.editNetworkSettings(
                "nostr", {"regenerate_key": True}
            )

        def set_relays():
            results["relays"] = self.sc.editNetworkSettings(
                "nostr", {"relays": ["wss://relay.new"]}
            )

        def set_bridge():
            results["bridge"] = self.sc.editBridgeNetworksSetting(True)

        threads = [
            threading.Thread(target=fn) for fn in (regenerate, set_relays, set_bridge)
        ]
        with self.sc.mxDB:
            for t in threads:
                t.start()
            time.sleep(0.3)
        for t in threads:
            t.join(timeout=10.0)

        assert results["key"] == (True, True)
        assert results["relays"] == (True, True)
        assert results["bridge"] == (True, True)

        nostr_net = next(
            n for n in self.sc.settings["networks"] if n["type"] == "nostr"
        )
        assert nostr_net["private_key"] != old_key
        assert nostr_net["relays"] == ["wss://relay.new"]
        assert self.sc.settings["bridge_networks"] is True

        with open(os.path.join(self.basicswap_dir, cfg.CONFIG_FILENAME)) as fp:
            on_disk = json.load(fp)
        nostr_disk = next(n for n in on_disk["networks"] if n["type"] == "nostr")
        assert nostr_disk["private_key"] == nostr_net["private_key"]
        assert nostr_disk["relays"] == ["wss://relay.new"]
        assert on_disk["bridge_networks"] is True

    def test_edit_network_settings(self):
        changed, reboot = self.sc.editNetworkSettings("nostr", {"pow_target": 12})
        assert changed and reboot
        assert (
            next(n for n in self.sc.settings["networks"] if n["type"] == "nostr")[
                "pow_target"
            ]
            == 12
        )

        changed, _ = self.sc.editNetworkSettings("nostr", {"pow_target": 12})
        assert not changed  # No change

        changed, _ = self.sc.editNetworkSettings(
            "nostr", {"relays": ["wss://relay.three"]}
        )
        assert changed

        self.assertRaises(
            ValueError,
            self.sc.editNetworkSettings,
            "nostr",
            {"relays": ["http://bad.relay"]},
        )
        self.assertRaises(
            ValueError, self.sc.editNetworkSettings, "nostr", {"relays": []}
        )
        self.assertRaises(
            ValueError, self.sc.editNetworkSettings, "nostr", {"pow_target": 100}
        )
        self.assertRaises(
            ValueError,
            self.sc.editNetworkSettings,
            "nostr",
            {"pow_target": MAX_POW_TARGET_BITS + 1},
        )
        self.assertRaises(
            ValueError, self.sc.editNetworkSettings, "badnet", {"enabled": True}
        )

    def test_cannot_disable_last_network(self):
        changed, _ = self.sc.editNetworkSettings("smsg", {"enabled": False})
        assert changed
        self.assertRaises(
            ValueError, self.sc.editNetworkSettings, "nostr", {"enabled": False}
        )

    def test_settings_persisted(self):
        import basicswap.config as cfg

        self.sc.editNetworkSettings("nostr", {"pow_target": 11})
        settings_path = os.path.join(self.basicswap_dir, cfg.CONFIG_FILENAME)
        with open(settings_path) as fp:
            saved = json.load(fp)
        nostr_net = next(n for n in saved["networks"] if n["type"] == "nostr")
        assert nostr_net["pow_target"] == 11

    def test_add_network_nostr(self):
        self.sc.settings["networks"] = [
            n for n in self.sc.settings["networks"] if n["type"] != "nostr"
        ]
        changed, reboot = self.sc.editNetworkSettings("nostr", {"add": True})
        assert changed and reboot
        nostr_net = next(
            n for n in self.sc.settings["networks"] if n["type"] == "nostr"
        )
        assert nostr_net["enabled"] is True
        assert len(nostr_net["relays"]) > 0
        assert all(r.startswith("wss://") for r in nostr_net["relays"])
        assert len(nostr_net["private_key"]) == 64
        bytes.fromhex(nostr_net["private_key"])

        info = next(n for n in self.sc.getNetworksInfo() if n["type"] == "nostr")
        assert info["pubkey"]
        assert info["key_pending_restart"] is False
        assert info["restart_required"] is True  # enabled but not started

    def test_add_network_simplex_rejected(self):
        self.assertRaises(
            ValueError, self.sc.editNetworkSettings, "simplex", {"add": True}
        )

    def test_key_pending_restart(self):
        from unittest import mock

        old_pub = "ab" * 32
        mock_client = mock.Mock()
        mock_client.get_info.return_value = {"pubkey": old_pub, "relays": []}
        self.sc.active_networks = [{"type": "nostr", "client": mock_client}]

        before = next(n for n in self.sc.getNetworksInfo() if n["type"] == "nostr")
        assert before["active_pubkey"] == old_pub
        assert before["pubkey"] != old_pub
        assert before["key_pending_restart"] is True

        changed, reboot = self.sc.editNetworkSettings("nostr", {"regenerate_key": True})
        assert changed and reboot
        after = next(n for n in self.sc.getNetworksInfo() if n["type"] == "nostr")
        assert after["key_pending_restart"] is True
        assert after["active_pubkey"] == old_pub
        assert after["pubkey"] != old_pub
        assert after["restart_required"] is True

    def test_regenerate_key(self):
        import basicswap.config as cfg

        def current_key():
            return next(
                n for n in self.sc.settings["networks"] if n["type"] == "nostr"
            )["private_key"]

        old_key = current_key()
        changed, reboot = self.sc.editNetworkSettings("nostr", {"regenerate_key": True})
        assert changed and reboot
        new_key = current_key()
        assert new_key != old_key
        assert len(new_key) == 64
        bytes.fromhex(new_key)

        settings_path = os.path.join(self.basicswap_dir, cfg.CONFIG_FILENAME)
        with open(settings_path) as fp:
            saved = json.load(fp)
        nostr_net = next(n for n in saved["networks"] if n["type"] == "nostr")
        assert nostr_net["private_key"] == new_key

        # Not triggered by a falsy value
        changed, _ = self.sc.editNetworkSettings("nostr", {"regenerate_key": False})
        assert not changed
        assert current_key() == new_key

    def test_send_signs_with_route_key(self):
        # Messages over an established nostr route are signed with the
        # route key, not the node key.
        from unittest import mock
        from basicswap.basicswap_util import MessageNetworks

        route_privkey = PrivateKey()
        fake_route = mock.Mock()
        fake_route.route_data = json.dumps(
            {
                "remote_pubkey": "ab" * 32,
                "local_pubkey": route_privkey.public_key_xonly.format().hex(),
                "local_privkey": route_privkey.to_hex(),
            }
        ).encode("UTF-8")

        def fake_get_route(network_id, addr_from, addr_to, cursor=None):
            if network_id == int(MessageNetworks.NOSTR):
                return fake_route
            return None

        self.sc.active_networks = [{"type": "nostr", "client": None}]
        with (
            mock.patch.object(self.sc, "getMessageRoute", side_effect=fake_get_route),
            mock.patch(
                "basicswap.network.bsx_network.sendNostrMsg",
                return_value=os.urandom(28),
            ) as mock_send,
        ):
            self.sc.sendMessage("addr_a", "addr_b", "00", 3600, None)
        assert mock_send.call_count == 1
        assert mock_send.call_args.kwargs["sign_privkey"] == route_privkey.secret

    def test_bridge_networks_setting(self):
        import basicswap.config as cfg

        changed, reboot = self.sc.editBridgeNetworksSetting(True)
        assert changed and reboot
        assert self.sc.settings["bridge_networks"] is True

        changed, _ = self.sc.editBridgeNetworksSetting(True)
        assert not changed  # No change

        settings_path = os.path.join(self.basicswap_dir, cfg.CONFIG_FILENAME)
        with open(settings_path) as fp:
            saved = json.load(fp)
        assert saved["bridge_networks"] is True

        changed, _ = self.sc.editBridgeNetworksSetting(False)
        assert changed
        assert self.sc.settings["bridge_networks"] is False

        # Requires two enabled networks to enable
        self.sc.editNetworkSettings("nostr", {"enabled": False})
        self.assertRaises(ValueError, self.sc.editBridgeNetworksSetting, True)


class TestNostrHandshake(BasicSwapFixture):
    """CONNECT_REQ / ACK route establishment over Nostr.

    Runs both sides on one BasicSwap instance with the network layer mocked
    out, the route tables are real.
    """

    OFFER_ADDR = "offer_addr"
    BIDDER_ADDR = "bidder_addr"
    OFFERER_PUBKEY = "cd" * 32
    BIDDER_PUBKEY = "ab" * 32

    def setUp(self):
        super().setUp()
        self.offer_id = os.urandom(28)
        self.bid_id = os.urandom(28)

    def makeConnectMsg(self, request_type, req_data, addr_from, addr_to) -> dict:
        from basicswap.basicswap_util import MessageNetworks, MessageTypes
        from basicswap.messages_npb import ConnectReqMessage

        msg_buf = ConnectReqMessage()
        msg_buf.network_type = int(MessageNetworks.NOSTR)
        msg_buf.network_data = b"bsx"
        msg_buf.request_type = int(request_type)
        msg_buf.request_data = json.dumps(req_data).encode("UTF-8")
        return {
            "msgid": os.urandom(28).hex(),
            "from": addr_from,
            "to": addr_to,
            "payloadversion": 2,
            "hex": "{:02x}".format(MessageTypes.CONNECT_REQ) + msg_buf.to_bytes().hex(),
        }

    def parseSentAck(self, send_call) -> dict:
        from basicswap.basicswap_util import ConnectionRequestTypes, MessageTypes
        from basicswap.messages_npb import ConnectReqMessage

        payload: bytes = send_call.args[4]
        assert payload[0] == MessageTypes.CONNECT_REQ
        msg_data = ConnectReqMessage(init_all=False)
        msg_data.from_bytes(payload[1:])
        assert msg_data.request_type == ConnectionRequestTypes.ACK
        return json.loads(msg_data.request_data)

    def readRoutes(self):
        try:
            cursor = self.sc.openDB()
            routes = cursor.execute(
                "SELECT record_id, active_ind, network_id, smsg_addr_local, "
                "smsg_addr_remote, route_data FROM direct_message_routes"
            ).fetchall()
            links = cursor.execute(
                "SELECT active_ind, direct_message_route_id, linked_type, linked_id "
                "FROM direct_message_route_links"
            ).fetchall()
        finally:
            self.sc.closeDB(cursor)
        return routes, links

    def ageRoute(self, cursor, route_id: int, seconds: int) -> None:
        route_data = json.loads(
            cursor.execute(
                "SELECT route_data FROM direct_message_routes WHERE record_id = :record_id",
                {"record_id": route_id},
            ).fetchone()[0]
        )
        route_data["connect_req_sent_at"] -= seconds
        cursor.execute(
            "UPDATE direct_message_routes SET created_at = created_at - :seconds, "
            "route_data = :route_data WHERE record_id = :record_id",
            {
                "seconds": seconds,
                "route_data": json.dumps(route_data).encode("UTF-8"),
                "record_id": route_id,
            },
        )

    def openPendingBidderRoute(self, sent_msgids: list) -> int:
        from types import SimpleNamespace
        from unittest import mock
        from basicswap.db import Concepts, DirectMessageRouteLink

        net_i = SimpleNamespace(pubkey=self.BIDDER_PUBKEY)

        def fake_send_message(*args, **kwargs):
            msgid = os.urandom(28)
            sent_msgids.append(msgid)
            return msgid

        with (
            mock.patch.object(self.sc, "getActiveNetworkInterface", return_value=net_i),
            mock.patch.object(self.sc, "sendMessage", side_effect=fake_send_message),
        ):
            try:
                cursor = self.sc.openDB()
                route_id, established = self.sc.prepareMessageRoute(
                    "nostr",
                    {"offer_id": self.offer_id.hex()},
                    self.BIDDER_ADDR,
                    self.OFFER_ADDR,
                    cursor,
                    3600,
                )
                assert established is False
                self.sc.add(
                    DirectMessageRouteLink(
                        active_ind=1,
                        direct_message_route_id=route_id,
                        linked_type=Concepts.BID,
                        linked_id=self.bid_id,
                        created_at=self.sc.getTime(),
                    ),
                    cursor,
                )
            finally:
                self.sc.closeDB(cursor)
        return route_id

    def makeAckFor(self, route_id: int) -> dict:
        from basicswap.basicswap_util import ConnectionRequestTypes

        routes, _ = self.readRoutes()
        route_data = json.loads(
            [r for r in routes if r[0] == route_id][0][5].decode("UTF-8")
        )
        ack = self.makeConnectMsg(
            ConnectionRequestTypes.ACK,
            {
                "offer_id": self.offer_id.hex(),
                "bsx_address": self.OFFER_ADDR,
                "nostr_pubkey": self.OFFERER_PUBKEY,
                "req_pubkey": route_data["local_pubkey"],
            },
            self.OFFER_ADDR,
            self.BIDDER_ADDR,
        )
        ack["nostr_pubkey_from"] = self.OFFERER_PUBKEY
        return ack

    def test_bid_send_failure_after_ack_is_retried(self):
        from unittest import mock
        from basicswap.db import Concepts

        sent_msgids = []
        route_id = self.openPendingBidderRoute(sent_msgids)
        ack_msg = self.makeAckFor(route_id)

        with mock.patch.object(
            self.sc,
            "routeEstablishedForBid",
            side_effect=TemporaryError("No relay accepted event"),
        ) as mock_est:
            self.sc.processConnectRequest(ack_msg)
            mock_est.assert_called_once()

        routes, links = self.readRoutes()
        assert routes[0][1] == 1
        assert links == [(1, route_id, int(Concepts.BID), self.bid_id)]

        with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
            self.sc.checkPendingMessageRoutes()
            mock_est.assert_called_once()
            assert mock_est.call_args.args[0] == self.bid_id

        routes, links = self.readRoutes()
        assert links == [(2, route_id, int(Concepts.BID), self.bid_id)]

        with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
            self.sc.checkPendingMessageRoutes()
            mock_est.assert_not_called()
        assert len(sent_msgids) == 1

    def test_redelivered_ack_dispatches_pending_bid(self):
        from unittest import mock
        from basicswap.db import Concepts

        sent_msgids = []
        route_id = self.openPendingBidderRoute(sent_msgids)
        ack_msg = self.makeAckFor(route_id)

        with mock.patch.object(
            self.sc, "routeEstablishedForBid", side_effect=TemporaryError("down")
        ):
            self.sc.processConnectRequest(ack_msg)
        _, links = self.readRoutes()
        assert links[0][0] == 1

        with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
            self.sc.processConnectRequest(ack_msg)
            mock_est.assert_called_once()
        _, links = self.readRoutes()
        assert links == [(2, route_id, int(Concepts.BID), self.bid_id)]

        from basicswap.basicswap_util import ConnectionRequestTypes

        routes, _ = self.readRoutes()
        route_data = json.loads(routes[0][5].decode("UTF-8"))
        bad_ack = self.makeConnectMsg(
            ConnectionRequestTypes.ACK,
            {
                "offer_id": self.offer_id.hex(),
                "bsx_address": self.OFFER_ADDR,
                "nostr_pubkey": "ef" * 32,
                "req_pubkey": route_data["local_pubkey"],
            },
            self.OFFER_ADDR,
            self.BIDDER_ADDR,
        )
        bad_ack["nostr_pubkey_from"] = "ef" * 32
        with self.assertRaisesRegex(ValueError, "does not match active route"):
            self.sc.processConnectRequest(bad_ack)

    def test_connect_req_retransmitted_by_update_loop(self):
        from unittest import mock

        sent_msgids = []
        route_id = self.openPendingBidderRoute(sent_msgids)
        assert len(sent_msgids) == 1

        def read_route_data():
            routes, _ = self.readRoutes()
            return json.loads(routes[0][5].decode("UTF-8"))

        route_data = read_route_data()
        assert route_data["connect_req_attempts"] == 1
        assert route_data["connect_req_data"]["offer_id"] == self.offer_id.hex()
        first_pubkey = route_data["local_pubkey"]

        def fake_send_message(addr_from, addr_to, payload_hex, *args, **kwargs):
            from basicswap.messages_npb import ConnectReqMessage

            assert (addr_from, addr_to) == (self.BIDDER_ADDR, self.OFFER_ADDR)
            assert kwargs["message_nets"] == "nostr"
            msg_data = ConnectReqMessage(init_all=False)
            msg_data.from_bytes(bytes.fromhex(payload_hex[2:]))
            req = json.loads(msg_data.request_data)
            assert req["nostr_pubkey"] == first_pubkey
            assert req["offer_id"] == self.offer_id.hex()
            assert (
                PrivateKey(kwargs["sign_privkey"]).public_key_xonly.format().hex()
                == first_pubkey
            )
            msgid = os.urandom(28)
            sent_msgids.append(msgid)
            return msgid

        max_attempts = self.sc._connect_req_max_attempts
        with mock.patch.object(self.sc, "sendMessage", side_effect=fake_send_message):
            self.sc.checkPendingMessageRoutes()
            assert len(sent_msgids) == 1

            expect_wait = 30
            for attempt in range(2, max_attempts + 1):
                try:
                    cursor = self.sc.openDB()
                    self.ageRoute(cursor, route_id, expect_wait - 5)
                finally:
                    self.sc.closeDB(cursor)
                self.sc.checkPendingMessageRoutes()
                assert len(sent_msgids) == attempt - 1

                try:
                    cursor = self.sc.openDB()
                    self.ageRoute(cursor, route_id, 5)
                finally:
                    self.sc.closeDB(cursor)
                self.sc.checkPendingMessageRoutes()
                assert len(sent_msgids) == attempt
                route_data = read_route_data()
                assert route_data["connect_req_attempts"] == attempt
                assert route_data["connect_req_msgid"] == sent_msgids[-1].hex()
                expect_wait = min(expect_wait * 2, 600)

            try:
                cursor = self.sc.openDB()
                self.ageRoute(cursor, route_id, 24 * 3600)
            finally:
                self.sc.closeDB(cursor)
            self.sc.checkPendingMessageRoutes()
            assert len(sent_msgids) == max_attempts

        routes, links = self.readRoutes()
        assert routes[0][1] == 2
        assert links[0][0] == 1

        with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
            self.sc.processConnectRequest(self.makeAckFor(route_id))
            mock_est.assert_called_once()
        routes, links = self.readRoutes()
        assert routes[0][1] == 1
        assert links[0][0] == 2

    def test_route_established_for_bid_is_idempotent(self):
        from unittest import mock
        from basicswap.basicswap_util import BidStates
        from basicswap.db import Bid, Offer

        now = self.sc.getTime()
        try:
            cursor = self.sc.openDB()
            self.sc.add(
                Offer(offer_id=self.offer_id, active_ind=1, created_at=now), cursor
            )
            bid = Bid(
                bid_id=self.bid_id,
                offer_id=self.offer_id,
                active_ind=1,
                created_at=now,
                expire_at=now + 3600,
                was_sent=True,
            )
            bid.setState(BidStates.BID_SENT)
            self.sc.add(bid, cursor)
        finally:
            self.sc.closeDB(cursor)

        with mock.patch.object(self.sc, "sendBidMessage") as mock_send:
            try:
                cursor = self.sc.openDB()
                self.sc.routeEstablishedForBid(self.bid_id, cursor)
            finally:
                self.sc.closeDB(cursor)
            mock_send.assert_not_called()

        try:
            cursor = self.sc.openDB()
            cursor.execute(
                "UPDATE bids SET state = :state, expire_at = :expire_at WHERE bid_id = :bid_id",
                {
                    "state": int(BidStates.CONNECT_REQ_SENT),
                    "expire_at": now - 1,
                    "bid_id": self.bid_id,
                },
            )
        finally:
            self.sc.closeDB(cursor)
        with mock.patch.object(self.sc, "sendBidMessage") as mock_send:
            try:
                cursor = self.sc.openDB()
                self.sc.routeEstablishedForBid(self.bid_id, cursor)
            finally:
                self.sc.closeDB(cursor)
            mock_send.assert_not_called()

    def test_offerer_accepts_and_acks(self):
        from types import SimpleNamespace
        from unittest import mock
        from basicswap.basicswap_util import ConnectionRequestTypes, MessageNetworks
        from basicswap.db import Concepts

        now = self.sc.getTime()
        offer = SimpleNamespace(addr_from=self.OFFER_ADDR, expire_at=now + 3600)
        net_i = SimpleNamespace(pubkey=self.OFFERER_PUBKEY)
        req_data = {
            "offer_id": self.offer_id.hex(),
            "bsx_address": self.BIDDER_ADDR,
            "nostr_pubkey": self.BIDDER_PUBKEY,
        }
        msg = self.makeConnectMsg(
            ConnectionRequestTypes.BID, req_data, self.BIDDER_ADDR, self.OFFER_ADDR
        )

        with (
            mock.patch.object(self.sc, "getOffer", return_value=offer),
            mock.patch.object(self.sc, "getActiveNetworkInterface", return_value=net_i),
            mock.patch.object(
                self.sc, "getActiveNetwork", return_value={"type": "nostr"}
            ),
            mock.patch("basicswap.basicswap.getMsgPubkey", return_value=bytes(33)),
            mock.patch(
                "basicswap.basicswap.sendNostrMsg", return_value=os.urandom(28)
            ) as mock_send,
        ):
            self.sc.processConnectRequest(msg)

            routes, links = self.readRoutes()
            assert len(routes) == 1
            record_id, active_ind, network_id, local, remote, route_data = routes[0]
            assert active_ind == 1  # Usable immediately
            assert network_id == int(MessageNetworks.NOSTR)
            assert (local, remote) == (self.OFFER_ADDR, self.BIDDER_ADDR)
            route_data = json.loads(route_data.decode("UTF-8"))
            assert route_data["remote_pubkey"] == self.BIDDER_PUBKEY
            # The route gets its own key, not the node key
            route_pubkey = route_data["local_pubkey"]
            route_privkey = bytes.fromhex(route_data["local_privkey"])
            assert route_pubkey != self.OFFERER_PUBKEY
            assert (
                PrivateKey(route_privkey).public_key_xonly.format().hex()
                == route_pubkey
            )
            assert links == [(1, record_id, int(Concepts.OFFER), self.offer_id)]

            assert mock_send.call_count == 1
            ack = self.parseSentAck(mock_send.call_args)
            assert ack["offer_id"] == self.offer_id.hex()
            assert ack["bsx_address"] == self.OFFER_ADDR
            assert ack["nostr_pubkey"] == route_pubkey
            # Echoes the bidder's route key so the ACK is bound to the request
            assert ack["req_pubkey"] == self.BIDDER_PUBKEY
            # ACK goes offer address -> bidder address, encrypted to the
            # bidder's address key, signed with the route key, not p-tagged.
            assert mock_send.call_args.args[2:4] == (self.OFFER_ADDR, self.BIDDER_ADDR)
            assert mock_send.call_args.kwargs.get("pubkey_to") == bytes(33)
            assert mock_send.call_args.kwargs.get("sign_privkey") == route_privkey
            assert "to_pubkey" not in mock_send.call_args.kwargs

            # The bidder resends CONNECT_REQ when the ACK was lost: the
            # offerer must re-ACK with the same route key instead of
            # rejecting the duplicate.
            self.sc.processConnectRequest(msg)
            assert mock_send.call_count == 2
            resent_ack = self.parseSentAck(mock_send.call_args)
            assert resent_ack["nostr_pubkey"] == route_pubkey
            assert resent_ack["req_pubkey"] == self.BIDDER_PUBKEY
            assert mock_send.call_args.kwargs.get("sign_privkey") == route_privkey
            routes, _ = self.readRoutes()
            assert len(routes) == 1  # No duplicate route

            # A different node claiming the same addresses is rejected
            req_data["nostr_pubkey"] = "ef" * 32
            other_msg = self.makeConnectMsg(
                ConnectionRequestTypes.BID,
                req_data,
                self.BIDDER_ADDR,
                self.OFFER_ADDR,
            )
            with self.assertRaisesRegex(ValueError, "already exists"):
                self.sc.processConnectRequest(other_msg)
            assert mock_send.call_count == 2

    def test_offerer_rejects_bad_pubkey(self):
        from types import SimpleNamespace
        from unittest import mock
        from basicswap.basicswap_util import ConnectionRequestTypes

        now = self.sc.getTime()
        offer = SimpleNamespace(addr_from=self.OFFER_ADDR, expire_at=now + 3600)
        net_i = SimpleNamespace(pubkey=self.OFFERER_PUBKEY)
        for bad_pubkey in ("zz" * 32, "ab" * 31, 12):
            req_data = {
                "offer_id": self.offer_id.hex(),
                "bsx_address": self.BIDDER_ADDR,
                "nostr_pubkey": bad_pubkey,
            }
            msg = self.makeConnectMsg(
                ConnectionRequestTypes.BID,
                req_data,
                self.BIDDER_ADDR,
                self.OFFER_ADDR,
            )
            with (
                mock.patch.object(self.sc, "getOffer", return_value=offer),
                mock.patch.object(
                    self.sc, "getActiveNetworkInterface", return_value=net_i
                ),
                mock.patch("basicswap.basicswap.sendNostrMsg") as mock_send,
            ):
                with self.assertRaises(ValueError):
                    self.sc.processConnectRequest(msg)
                mock_send.assert_not_called()
        routes, _ = self.readRoutes()
        assert len(routes) == 0

    def test_bidder_sends_connect_req_and_completes_on_ack(self):
        from types import SimpleNamespace
        from unittest import mock
        from basicswap.basicswap_util import ConnectionRequestTypes, MessageNetworks
        from basicswap.db import Concepts, DirectMessageRouteLink
        from basicswap.messages_npb import ConnectReqMessage

        net_i = SimpleNamespace(pubkey=self.BIDDER_PUBKEY)
        sent_msgids = []
        sent_pubkeys = []

        def fake_send_message(
            addr_from,
            addr_to,
            payload_hex,
            msg_valid,
            cursor,
            message_nets="",
            sign_privkey=None,
        ):
            assert (addr_from, addr_to) == (self.BIDDER_ADDR, self.OFFER_ADDR)
            assert message_nets == "nostr"
            msg_data = ConnectReqMessage(init_all=False)
            msg_data.from_bytes(bytes.fromhex(payload_hex[2:]))
            assert msg_data.network_type == int(MessageNetworks.NOSTR)
            assert msg_data.request_type == ConnectionRequestTypes.BID
            req = json.loads(msg_data.request_data)
            # CONNECT_REQ carries and is signed with a per-route key
            assert req["nostr_pubkey"] != self.BIDDER_PUBKEY
            assert (
                PrivateKey(sign_privkey).public_key_xonly.format().hex()
                == req["nostr_pubkey"]
            )
            assert req["bsx_address"] == self.BIDDER_ADDR
            sent_pubkeys.append(req["nostr_pubkey"])
            msgid = os.urandom(28)
            sent_msgids.append(msgid)
            return msgid

        with (
            mock.patch.object(self.sc, "getActiveNetworkInterface", return_value=net_i),
            mock.patch.object(self.sc, "sendMessage", side_effect=fake_send_message),
        ):
            try:
                cursor = self.sc.openDB()
                # First call sends CONNECT_REQ and opens a pending route
                route_id, established = self.sc.prepareMessageRoute(
                    "nostr",
                    {"offer_id": self.offer_id.hex()},
                    self.BIDDER_ADDR,
                    self.OFFER_ADDR,
                    cursor,
                    3600,
                )
                assert established is False
                assert len(sent_msgids) == 1

                # Link the bid, as postBid does
                self.sc.add(
                    DirectMessageRouteLink(
                        active_ind=1,
                        direct_message_route_id=route_id,
                        linked_type=Concepts.BID,
                        linked_id=self.bid_id,
                        created_at=self.sc.getTime(),
                    ),
                    cursor,
                )

                # Immediately again: still waiting, nothing resent
                rv = self.sc.prepareMessageRoute(
                    "nostr", {}, self.BIDDER_ADDR, self.OFFER_ADDR, cursor, 3600
                )
                assert rv == (route_id, False)
                assert len(sent_msgids) == 1

                # After 30s without an ACK the CONNECT_REQ is resent on the
                # same route
                self.ageRoute(cursor, route_id, 60)
                rv = self.sc.prepareMessageRoute(
                    "nostr", {}, self.BIDDER_ADDR, self.OFFER_ADDR, cursor, 3600
                )
                assert rv == (route_id, False)
                assert len(sent_msgids) == 2
                # The resend reuses the route key
                assert sent_pubkeys[0] == sent_pubkeys[1]
            finally:
                self.sc.closeDB(cursor)

            routes, _ = self.readRoutes()
            assert len(routes) == 1
            record_id, active_ind, network_id, local, remote, route_data = routes[0]
            assert (record_id, active_ind) == (route_id, 2)
            route_data = json.loads(route_data.decode("UTF-8"))
            assert route_data["local_pubkey"] == sent_pubkeys[0]
            assert (
                PrivateKey(bytes.fromhex(route_data["local_privkey"]))
                .public_key_xonly.format()
                .hex()
                == sent_pubkeys[0]
            )
            assert route_data["connect_req_msgid"] == sent_msgids[-1].hex()
            assert "remote_pubkey" not in route_data

            def makeAck(req_pubkey, event_pubkey=None) -> dict:
                ack = self.makeConnectMsg(
                    ConnectionRequestTypes.ACK,
                    {
                        "offer_id": self.offer_id.hex(),
                        "bsx_address": self.OFFER_ADDR,
                        "nostr_pubkey": self.OFFERER_PUBKEY,
                        "req_pubkey": req_pubkey,
                    },
                    self.OFFER_ADDR,
                    self.BIDDER_ADDR,
                )
                if event_pubkey is not None:
                    ack["nostr_pubkey_from"] = event_pubkey
                return ack

            # A stale ACK for an earlier route between the same addresses
            # (different route key) must not activate this route.
            with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
                with self.assertRaisesRegex(ValueError, "does not match pending route"):
                    self.sc.processConnectRequest(makeAck("11" * 32))
                # Same for an ACK missing the binding altogether
                unbound = self.makeConnectMsg(
                    ConnectionRequestTypes.ACK,
                    {
                        "offer_id": self.offer_id.hex(),
                        "bsx_address": self.OFFER_ADDR,
                        "nostr_pubkey": self.OFFERER_PUBKEY,
                    },
                    self.OFFER_ADDR,
                    self.BIDDER_ADDR,
                )
                with self.assertRaisesRegex(ValueError, "does not match pending route"):
                    self.sc.processConnectRequest(unbound)
                # The event must be signed by the route key it announces
                with self.assertRaisesRegex(ValueError, "not signed by announced"):
                    self.sc.processConnectRequest(
                        makeAck(sent_pubkeys[0], event_pubkey="22" * 32)
                    )
                mock_est.assert_not_called()
            routes, _ = self.readRoutes()
            assert routes[0][1] == 2  # Still pending

            # ACK from the offerer activates the route and releases the bid
            ack_msg = makeAck(sent_pubkeys[0], event_pubkey=self.OFFERER_PUBKEY)
            with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
                self.sc.processConnectRequest(ack_msg)
                mock_est.assert_called_once()
                assert mock_est.call_args.args[0] == self.bid_id

            routes, links = self.readRoutes()
            _, active_ind, _, _, _, route_data = routes[0]
            assert active_ind == 1
            assert json.loads(route_data.decode("UTF-8"))["remote_pubkey"] == (
                self.OFFERER_PUBKEY
            )
            assert links == [(2, route_id, int(Concepts.BID), self.bid_id)]

            # Established route is used for subsequent messages
            try:
                cursor = self.sc.openDB()
                rv = self.sc.prepareMessageRoute(
                    "nostr", {}, self.BIDDER_ADDR, self.OFFER_ADDR, cursor, 3600
                )
            finally:
                self.sc.closeDB(cursor)
            assert rv == (route_id, True)
            assert len(sent_msgids) == 2

            # A duplicate ACK is ignored
            with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
                self.sc.processConnectRequest(ack_msg)
                mock_est.assert_not_called()

    def test_simplex_route_readers_skip_nostr_routes(self):
        from unittest import mock
        from basicswap.basicswap_util import MessageNetworks
        from basicswap.db import Concepts, DirectMessageRoute, DirectMessageRouteLink

        now = self.sc.getTime()
        try:
            cursor = self.sc.openDB()
            self.sc.add(
                DirectMessageRoute(
                    active_ind=1,
                    network_id=int(MessageNetworks.NOSTR),
                    linked_type=Concepts.OFFER,
                    smsg_addr_local="nostr_local",
                    smsg_addr_remote="nostr_remote",
                    route_data=json.dumps(
                        {"local_pubkey": "ab" * 32, "local_privkey": "cd" * 32}
                    ).encode("UTF-8"),
                    created_at=now,
                ),
                cursor,
            )
            simplex_route_id = self.sc.add(
                DirectMessageRoute(
                    active_ind=2,
                    network_id=int(MessageNetworks.SIMPLEX),
                    linked_type=Concepts.OFFER,
                    smsg_addr_local="sx_local",
                    smsg_addr_remote="sx_remote",
                    route_data=json.dumps({"pccConnId": "conn-77"}).encode("UTF-8"),
                    created_at=now,
                ),
                cursor,
            )
            self.sc.add(
                DirectMessageRouteLink(
                    active_ind=1,
                    direct_message_route_id=simplex_route_id,
                    linked_type=Concepts.BID,
                    linked_id=self.bid_id,
                    created_at=now,
                ),
                cursor,
            )
        finally:
            self.sc.closeDB(cursor)

        other_bid_id = os.urandom(28)
        self.sc.addRecvBidNetworkLink(
            {"chat_type": "direct", "conn_id": "conn-77"}, other_bid_id
        )
        _, links = self.readRoutes()
        assert (2, simplex_route_id, int(Concepts.BID), other_bid_id) in links

        event = {
            "resp": {
                "Right": {
                    "contact": {
                        "activeConn": {"connId": "conn-77"},
                        "localDisplayName": "peer",
                    }
                }
            }
        }
        with mock.patch.object(self.sc, "routeEstablishedForBid") as mock_est:
            self.sc.processContactConnected(event)
            mock_est.assert_called_once()
            assert mock_est.call_args.args[0] == self.bid_id
        routes, links = self.readRoutes()
        assert [r[1] for r in routes if r[0] == simplex_route_id] == [1]
        assert (2, simplex_route_id, int(Concepts.BID), self.bid_id) in links

        with (
            mock.patch.object(self.sc, "getActiveNetworkInterface"),
            mock.patch("basicswap.network.bsx_network.closeSimplexChat"),
        ):
            self.sc.processContactDisconnected(event)
        routes, _ = self.readRoutes()
        assert [r[2] for r in routes] == [int(MessageNetworks.NOSTR)]

    def test_ack_without_route_is_rejected(self):
        from basicswap.basicswap_util import ConnectionRequestTypes

        ack_msg = self.makeConnectMsg(
            ConnectionRequestTypes.ACK,
            {
                "offer_id": self.offer_id.hex(),
                "bsx_address": self.OFFER_ADDR,
                "nostr_pubkey": self.OFFERER_PUBKEY,
                "req_pubkey": self.BIDDER_PUBKEY,
            },
            self.OFFER_ADDR,
            self.BIDDER_ADDR,
        )
        with self.assertRaisesRegex(ValueError, "No matching direct message route"):
            self.sc.processConnectRequest(ack_msg)


if __name__ == "__main__":
    unittest.main()
