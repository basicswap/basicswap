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
        client = self.makeClient(pow_target=8)

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
        finally:
            client_a.stop()
            client_b.stop()


class TestNetworkSettings(unittest.TestCase):
    """editNetworkSettings and getNetworksInfo on a BasicSwap instance."""

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


if __name__ == "__main__":
    unittest.main()
