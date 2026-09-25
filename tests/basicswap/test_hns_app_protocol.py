"""BasicSwap HNS bid sender stores its session before SMSG submission."""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from coincurve import PrivateKey

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import MessageNetworks, SwapTypes
from basicswap.chainparams import Coins
from basicswap.db import (
    DBMethods,
    HnsBtcOutbox,
    HnsBtcSwap,
    create_table,
    extract_schema,
)
from basicswap.interface.hns.app_protocol import (
    flush_hns_app_outbox,
    receive_hns_btc_bid,
)
from basicswap.util.smsg import smsgEncrypt, smsgGetID


class FakeBridge:
    def identity(self, network):
        assert network == "regtest"
        return bytes.fromhex("11" * 16), bytes.fromhex("22" * 32)

    def key(self, offer_id, session_nonce, refund):
        scalar = b"\x05" * 32 if refund else b"\x04" * 32
        return PrivateKey(scalar).public_key.format()


class FakeCoin:
    def __init__(self):
        self.bridge = FakeBridge()

    def walletIdentityReady(self):
        return True

    def getChainHeight(self):
        return 110


class FakeApp(DBMethods):
    SMSG_SECONDS_IN_HOUR = 3600
    chain = "regtest"
    _smsg_payload_version = 2

    def __init__(self, path):
        self.path = path
        self.now = 1_790_000_000
        self.coin = FakeCoin()
        self.sent = []
        self.fail_first_send = True
        self.logs = []
        self.log = SimpleNamespace(
            warning=lambda *args: self.logs.append(args),
            debug=lambda *args: None,
            id=lambda value: value.hex(),
        )
        self.connections = {}
        with closing(sqlite3.connect(path)) as connection, connection:
            schema = extract_schema()
            for table in ("bids", "hns_btc_swaps", "hns_btc_outbox"):
                create_table(connection.cursor(), table, schema[table])

    def openDB(self):
        connection = sqlite3.connect(self.path)
        cursor = connection.cursor()
        self.connections[id(cursor)] = connection
        return cursor

    def closeDB(self, cursor, commit=True):
        connection = self.connections.pop(id(cursor))
        if commit:
            connection.commit()
        else:
            connection.rollback()
        cursor.close()
        connection.close()

    def getTime(self):
        return self.now

    def getOffer(self, offer_id):
        assert offer_id == self.offer.offer_id
        return self.offer

    def expandMessageNets(self, networks):
        assert networks == "smsg"
        return [MessageNetworks.SMSG], []

    def validateBidValidTime(self, *args):
        assert args[-1] == 600

    def ci(self, coin):
        assert coin in (Coins.HNS, Coins.BTC)
        return self.coin

    def setBidAmounts(self, amount, offer, extra_options, ci_from):
        return amount, offer.amount_to, offer.rate

    def validateBidAmount(self, *args):
        return None

    def checkCoinsReady(self, *args):
        return None

    def getNewContractId(self, cursor):
        return 1

    def getPathKey(self, *args):
        return b"\x06" * 32

    def prepareSMSGAddress(self, *args):
        return "sender"

    def saveBidInSession(self, bid_id, bid, cursor):
        assert bid_id == bid.bid_id
        self.add(bid, cursor)

    def getSmsgMsgBytes(self, msg):
        return msg["raw"]

    def addRecvBidNetworkLink(self, msg, bid_id, cursor):
        return None

    def callrpc(self, method, params):
        assert method == "smsgimport"
        raw = bytes.fromhex(params[0])
        self.sent.append(raw)
        if self.fail_first_send:
            self.fail_first_send = False
            raise ConnectionError("SMSG offline")
        return {"msgid": smsgGetID(raw).hex()}


class HnsAppProtocolTest(unittest.TestCase):
    def test_sender_commits_bid_id_then_retries_same_encrypted_message(self):
        with tempfile.TemporaryDirectory() as directory:
            app = FakeApp(Path(directory) / "app.sqlite")
            offer = SimpleNamespace(
                offer_id=b"\x33" * 28,
                swap_type=SwapTypes.HNS_BTC_SWAP,
                coin_from=Coins.HNS,
                coin_to=Coins.BTC,
                amount_from=2_000_000,
                amount_to=100_000,
                rate=50_000,
                amount_negotiable=False,
                rate_negotiable=False,
                message_nets="smsg",
                expire_at=app.now + 3600,
                addr_from="receiver",
                protocol_version=5,
                active_ind=1,
                was_sent=False,
            )
            app.offer = offer

            def easy_encrypt(
                _app,
                _sender,
                _receiver,
                payload,
                ttl,
                _cursor,
                timestamp,
                deterministic,
            ):
                self.assertTrue(deterministic)
                return smsgEncrypt(
                    b"\x07" * 32,
                    PrivateKey(b"\x08" * 32).public_key.format(),
                    payload,
                    smsg_timestamp=timestamp,
                    deterministic=True,
                    smsg_ttl=ttl,
                    difficulty_target=0x207FFFFF,
                )

            with patch("basicswap.interface.hns.app_protocol.encryptMsg", easy_encrypt):
                bid_id = BasicSwap.postBid(
                    app, offer.offer_id, offer.amount_from, None, {}
                )
            self.assertEqual(len(app.sent), 1)
            with closing(sqlite3.connect(app.path)) as connection:
                record = app.queryOne(
                    HnsBtcSwap,
                    connection.cursor(),
                    {"bid_id": bid_id},
                )
                row = app.queryOne(
                    HnsBtcOutbox,
                    connection.cursor(),
                    {"message_id": bid_id},
                )
            self.assertEqual(record.session_id, row.session_id)
            self.assertEqual(record.bid_id, smsgGetID(row.message_bytes))
            self.assertIsNone(row.delivered_at)
            self.assertEqual(flush_hns_app_outbox(app, app.now + 1), 1)
            self.assertEqual(app.sent, [row.message_bytes, row.message_bytes])
            self.assertEqual(flush_hns_app_outbox(app, app.now + 2), 0)

            maker = FakeApp(Path(directory) / "maker.sqlite")
            maker.offer = SimpleNamespace(**vars(offer))
            maker.offer.was_sent = True
            msg = {
                "msgid": bid_id.hex(),
                "sent": app.now,
                "from": "sender",
                "to": "receiver",
                "type": "smsg",
                "raw": record.bid_message,
            }
            with patch(
                "basicswap.interface.hns.app_protocol.getMsgPubkey",
                return_value=b"\x02" + b"\x09" * 32,
            ):
                self.assertEqual(receive_hns_btc_bid(maker, msg), bid_id)
                self.assertEqual(receive_hns_btc_bid(maker, msg), bid_id)
                changed = dict(msg, **{"from": "other sender"})
                with self.assertRaisesRegex(ValueError, "replay changed"):
                    receive_hns_btc_bid(maker, changed)
            with closing(sqlite3.connect(maker.path)) as connection:
                maker_record = maker.queryOne(
                    HnsBtcSwap,
                    connection.cursor(),
                    {"bid_id": bid_id},
                )
            self.assertEqual(maker_record.session_id, record.session_id)


if __name__ == "__main__":
    unittest.main()
