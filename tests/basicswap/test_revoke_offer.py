# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import collections
import logging
import os
import shutil
import tempfile
import threading
import unittest

from basicswap.basicswap import BasicSwap
from basicswap.db import create_db_, DBMethods, Offer
from basicswap.messages_npb import OfferRevokeMessage

logger = logging.getLogger()

NOW: int = 1785225600
NETWORK_ADDR: str = "PuwLwszCnY6ZXAsBZPvE5EieosFdsVzDWb"
OFFER_ADDR: str = "PdZ7kX1168Kw6uFsWjPMshq88VwDWRiyE6"

MAX_OFFER_TTL: int = 48 * 60 * 60
CLOCK_SLACK: int = 10 * 60

# processOfferRevoke drops any revoke whose offer id is older than this.
TTL_CUTOFF: int = MAX_OFFER_TTL + CLOCK_SLACK


class _Log:
    def __init__(self):
        self.lines = []

    def info(self, msg):
        pass

    def debug(self, msg):
        self.lines.append(msg)

    def id(self, concept_id, prefix: str = "") -> str:
        if concept_id is None:
            return prefix + "None"
        return prefix + concept_id.hex()

    def addr(self, addr: str) -> str:
        return addr


class _Signed(Exception):
    pass


class _SendingClient(DBMethods):
    def __init__(self, data_dir: str):
        self.sqlite_file = os.path.join(data_dir, "db.sqlite")
        self.mxDB = threading.RLock()
        self.log = _Log()
        cursor = self.openDB()
        create_db_(self._db_con, logger)
        self.closeDB(cursor)

    def getTime(self) -> int:
        return NOW

    def ci(self, coin_type):
        raise _Signed()


class OfferValidTimeTest(unittest.TestCase):
    """processOfferRevoke drops revokes for offer ids older than the maximum
    offer lifetime.  That shortcut is only sound while this cap holds."""

    def test_offer_ttl_cap_is_48h(self):
        BasicSwap.validateOfferValidTime(None, None, None, None, MAX_OFFER_TTL)
        with self.assertRaises(ValueError):
            BasicSwap.validateOfferValidTime(None, None, None, None, MAX_OFFER_TTL + 1)


class RevokeOfferGuardsTest(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def _client(self, expire_at=None, active_ind=1):
        client = _SendingClient(self.data_dir)
        if expire_at is None:
            return client
        offer = Offer()
        offer.offer_id = bytes.fromhex("00" * 28)
        offer.active_ind = active_ind
        offer.addr_from = OFFER_ADDR
        offer.expire_at = expire_at
        offer.time_valid = 1200
        offer.smsg_payload_version = 2
        cursor = client.openDB()
        try:
            client.add(offer, cursor)
        finally:
            client.closeDB(cursor)
        return client

    def test_unknown_offer_is_rejected(self):
        with self.assertRaises(ValueError) as e:
            BasicSwap.revokeOffer(self._client(), bytes.fromhex("11" * 28))
        self.assertIn("Offer not found", str(e.exception))

    def test_expired_offer_is_rejected(self):
        with self.assertRaises(ValueError) as e:
            BasicSwap.revokeOffer(self._client(NOW - 1), bytes.fromhex("00" * 28))
        self.assertEqual(str(e.exception), "Offer has expired")

    def test_already_revoked_offer_is_rejected(self):
        client = self._client(NOW + 1, active_ind=2)
        with self.assertRaises(ValueError) as e:
            BasicSwap.revokeOffer(client, bytes.fromhex("00" * 28))
        self.assertEqual(str(e.exception), "Offer not active")

    def test_live_offer_is_broadcast(self):
        with self.assertRaises(_Signed):
            BasicSwap.revokeOffer(self._client(NOW + 1), bytes.fromhex("00" * 28))


class _ExpiredOffer:
    expire_at = NOW - 1
    active_ind = 1


class _LiveOffer:
    def __init__(self):
        self.expire_at = NOW + 60 * 60
        self.active_ind = 1
        self.addr_from = OFFER_ADDR


class _WsServer:
    def __init__(self):
        self.messages = []

    def send_message_to_all(self, message):
        self.messages.append(message)


class _Verifier:
    def __init__(self, valid):
        self.valid = valid

    def verifyMessage(self, address, message, signature) -> bool:
        if self.valid == "raise":
            raise RuntimeError("malformed signature")
        return self.valid


class _ReceivingClient:
    def __init__(self, offer=None, signature_valid: bool = True):
        self.network_addr = NETWORK_ADDR
        self.log = _Log()
        self.ws_server = None
        self._expired_offer_revokes = collections.deque([], maxlen=1000)
        self._possibly_revoked_offers = collections.deque([], maxlen=1000)
        self.db_opens = 0
        self.db_updates = 0
        self._offer = offer
        self._signature_valid = signature_valid

    def getTime(self) -> int:
        return NOW

    def getSmsgMsgBytes(self, msg) -> bytes:
        return bytes.fromhex(msg["hex"][2:])

    def openDB(self, cursor=None):
        self.db_opens += 1
        return None

    def closeDB(self, cursor, commit=True):
        pass

    def getOffer(self, offer_id, cursor=None):
        return self._offer

    def updateDB(self, obj, cursor, constraints):
        self.db_updates += 1

    def ci(self, coin_type):
        return _Verifier(self._signature_valid)

    def storeOfferRevoke(self, offer_id: bytes, sig) -> bool:
        return BasicSwap.storeOfferRevoke(self, offer_id, sig)


def _revoke_msg(sent_at: int, tail: bytes = bytes(20), sig_len: int = 65) -> dict:
    msg_buf = OfferRevokeMessage()
    msg_buf.offer_msg_id = sent_at.to_bytes(8, byteorder="big") + tail
    msg_buf.signature = bytes(sig_len)
    return {
        "to": NETWORK_ADDR,
        "from": OFFER_ADDR,
        "hex": "0b" + msg_buf.to_bytes().hex(),
        "payloadversion": 2,
    }


class ProcessOfferRevokeTest(unittest.TestCase):
    def test_revoke_at_the_ttl_cutoff_is_dropped_outright(self):
        client = _ReceivingClient()
        BasicSwap.processOfferRevoke(client, _revoke_msg(NOW - TTL_CUTOFF))

        self.assertEqual(client.db_opens, 0)
        self.assertEqual(client.log.lines, [])

    def test_revoke_one_second_inside_the_ttl_cutoff_is_processed(self):
        client = _ReceivingClient()
        BasicSwap.processOfferRevoke(client, _revoke_msg(NOW - TTL_CUTOFF + 1))

        self.assertEqual(client.db_opens, 1)

    def test_malformed_offer_id_is_rejected(self):
        client = _ReceivingClient()
        with self.assertRaises(ValueError) as e:
            BasicSwap.processOfferRevoke(client, _revoke_msg(NOW, tail=bytes(19)))
        self.assertEqual(str(e.exception), "Invalid msg_id length")

    def test_malformed_signature_is_rejected(self):
        client = _ReceivingClient()
        with self.assertRaises(ValueError) as e:
            BasicSwap.processOfferRevoke(client, _revoke_msg(NOW, sig_len=64))
        self.assertEqual(str(e.exception), "Invalid signature length")

    def test_repeat_revokes_for_an_expired_offer_skip_the_db(self):
        client = _ReceivingClient(_ExpiredOffer())
        msg = _revoke_msg(NOW - 60 * 60)

        for _ in range(20):
            BasicSwap.processOfferRevoke(client, msg)

        self.assertEqual(client.db_opens, 1)
        self.assertEqual(len(client.log.lines), 1)

    def test_repeat_revokes_for_an_unknown_offer_are_stored_once(self):
        client = _ReceivingClient()
        msg = _revoke_msg(NOW - 60 * 60)

        for _ in range(20):
            BasicSwap.processOfferRevoke(client, msg)

        self.assertEqual(len(client._possibly_revoked_offers), 1)
        self.assertEqual(len(client.log.lines), 2)
        self.assertEqual(client.db_opens, 20)

    def test_distinct_offers_are_each_looked_up(self):
        client = _ReceivingClient(_ExpiredOffer())

        for i in range(5):
            BasicSwap.processOfferRevoke(
                client, _revoke_msg(NOW - 60 * 60, bytes([i]) + bytes(19))
            )

        self.assertEqual(client.db_opens, 5)

    def test_revoke_with_an_invalid_signature_is_not_stored(self):
        client = _ReceivingClient(signature_valid=False)
        BasicSwap.processOfferRevoke(client, _revoke_msg(NOW - 60 * 60))

        self.assertEqual(len(client._possibly_revoked_offers), 0)
        self.assertEqual(len(client.log.lines), 1)
        self.assertIn("invalid signature", client.log.lines[0])

    def test_invalid_signature_names_the_sender(self):
        client = _ReceivingClient(signature_valid=False)
        BasicSwap.processOfferRevoke(client, _revoke_msg(NOW - 60 * 60))

        self.assertIn(OFFER_ADDR, client.log.lines[0])

    def test_a_raising_verifier_is_treated_as_invalid(self):
        client = _ReceivingClient(signature_valid="raise")
        BasicSwap.processOfferRevoke(client, _revoke_msg(NOW - 60 * 60))

        self.assertEqual(len(client._possibly_revoked_offers), 0)
        self.assertIn("invalid signature", client.log.lines[0])

    def test_a_live_offer_is_revoked(self):
        offer = _LiveOffer()
        client = _ReceivingClient(offer)
        client.ws_server = _WsServer()

        BasicSwap.processOfferRevoke(client, _revoke_msg(NOW - 60 * 60))

        self.assertEqual(offer.active_ind, 2)
        self.assertEqual(client.db_updates, 1)
        self.assertIn("offer_revoked", client.ws_server.messages[0])

    def test_a_live_offer_survives_an_invalid_signature(self):
        offer = _LiveOffer()
        client = _ReceivingClient(offer, signature_valid=False)
        client.ws_server = _WsServer()

        with self.assertRaises(ValueError) as e:
            BasicSwap.processOfferRevoke(client, _revoke_msg(NOW - 60 * 60))

        self.assertEqual(str(e.exception), "Signature invalid")
        self.assertEqual(offer.active_ind, 1)
        self.assertEqual(client.db_updates, 0)
        self.assertEqual(client.ws_server.messages, [])


if __name__ == "__main__":
    unittest.main()
