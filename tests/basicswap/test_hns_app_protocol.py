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
from basicswap.basicswap_util import (
    BidStates,
    MessageNetworks,
    MessageTypes,
    SwapTypes,
    TxLockTypes,
)
from basicswap.chainparams import Coins
from basicswap.db import (
    Bid,
    DBMethods,
    HnsBtcOutbox,
    HnsBtcSwap,
    Offer,
    OfferTracking,
    SentOffer,
    create_table,
    extract_schema,
)
from basicswap.interface.hns.app_protocol import (
    flush_hns_app_outbox,
    receive_hns_btc_accept,
    receive_hns_btc_bid,
    receive_hns_btc_second_lock,
)
from basicswap.interface.hns.app_settlement import progress_hns_btc_trades
from basicswap.interface.hns.node_rpc import hns_network_binding
from basicswap.interface.hns.settlement import ObservedSwapSpend
from basicswap.interface.hns.trade_protocol import receive_accept_message
from basicswap.interface.hns.trade_record import bind_lock
from basicswap.messages_npb import OfferMessage
from basicswap.offer_tracking import OfferTrackingModes
from basicswap.util.smsg import smsgEncrypt, smsgGetID


class FakeBridge:
    def __init__(self, maker=False):
        self.maker = maker

    def identity(self, network):
        assert network == "regtest"
        return bytes.fromhex("11" * 16), bytes.fromhex("22" * 32)

    def key(self, offer_id, session_nonce, refund):
        scalar = (
            (b"\x15" if refund else b"\x14") * 32
            if self.maker
            else ((b"\x05" if refund else b"\x04") * 32)
        )
        return PrivateKey(scalar).public_key.format()

    def submitted_spend(self, *args, **kwargs):
        return None


class FakeCoin:
    def __init__(self, maker=False):
        self.bridge = FakeBridge(maker)
        self.node = object()

    def walletIdentityReady(self):
        return True

    def getChainHeight(self):
        return 110

    def get_fee_rate(self, _target):
        return 0.00002, "fake"

    def getNewAddress(self, _segwit, _label):
        return "bitcoin-receive"


class FakeApp(DBMethods):
    SMSG_SECONDS_IN_HOUR = 3600
    chain = "regtest"
    _smsg_payload_version = 2

    def __init__(self, path, maker=False, create_schema=True):
        self.path = path
        self.now = 1_790_000_000
        self.coin = FakeCoin(maker)
        self.maker = maker
        self.coin_clients = {
            Coins.HNS: {"maximum_htlc_fee": 100_000},
            Coins.BTC: {"connection_type": "rpc"},
        }
        self.sent = []
        self.fail_first_send = True
        self.logs = []
        self.log = SimpleNamespace(
            warning=lambda *args: self.logs.append(args),
            debug=lambda *args: None,
            info=lambda *args: None,
            id=lambda value: value.hex(),
        )
        self.connections = {}
        if create_schema:
            with closing(sqlite3.connect(path)) as connection, connection:
                schema = extract_schema()
                for table in ("offers", "bids", "hns_btc_swaps", "hns_btc_outbox"):
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
        return (b"\x16" if self.maker else b"\x06") * 32

    def getContractSecret(self, *args):
        return b"\x19" * 32

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
    def test_worker_resumes_maker_after_terms_commit_before_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            app = FakeApp(Path(directory) / "maker-recovery.sqlite", maker=True)
            offer_id = b"\x51" * 28
            bid_id = b"\x52" * 28
            cursor = app.openDB()
            try:
                app.add(
                    Offer(offer_id=offer_id, swap_type=SwapTypes.HNS_BTC_SWAP),
                    cursor,
                )
                app.add(
                    Bid(
                        bid_id=bid_id,
                        offer_id=offer_id,
                        state=BidStates.BID_RECEIVED,
                        created_at=app.now,
                    ),
                    cursor,
                )
                app.add(
                    HnsBtcSwap(
                        session_id=b"\x53" * 32,
                        offer_id=offer_id,
                        bid_id=bid_id,
                        role=1,
                        phase=1,
                    ),
                    cursor,
                )
            finally:
                app.closeDB(cursor)
            reopened = FakeApp(app.path, maker=True, create_schema=False)
            with (
                patch(
                    "basicswap.interface.hns.app_settlement.accept_hns_btc_bid"
                ) as resume,
                patch(
                    "basicswap.interface.hns.app_settlement.progress_hns_btc_maker",
                    return_value=False,
                ) as monitor,
            ):
                self.assertEqual(progress_hns_btc_trades(reopened), 0)
            resume.assert_called_once_with(reopened, bid_id)
            monitor.assert_called_once_with(reopened, bid_id)
            with (
                patch(
                    "basicswap.interface.hns.app_settlement.accept_hns_btc_bid",
                    side_effect=ValueError("second deadline passed"),
                ),
                patch(
                    "basicswap.interface.hns.app_settlement.progress_hns_btc_maker",
                    return_value=True,
                ) as monitor_refund,
            ):
                self.assertEqual(progress_hns_btc_trades(reopened), 1)
            monitor_refund.assert_called_once_with(reopened, bid_id)

    def test_native_offer_post_uses_smsg_v2_and_one_time_tracking(self):
        with tempfile.TemporaryDirectory() as directory:
            app = FakeApp(Path(directory) / "post-offer.sqlite", maker=True)
            app.network_addr = "public"
            app.ws_server = None
            app.coin.COIN = lambda: 1_000_000
            app.coin.getSpendableBalance = lambda: 10_000_000
            app.coin.ensureFunds = lambda _amount: None
            app.coin.make_int = lambda value, r=0: round(value * 1_000_000)
            app.validateSwapType = lambda *args: BasicSwap.validateSwapType(app, *args)
            app.validateOfferLockValue = lambda *args: BasicSwap.validateOfferLockValue(app, *args)
            app.validateOfferValidTime = lambda *args: BasicSwap.validateOfferValidTime(app, *args)
            app.validateOfferAmounts = lambda *_args: None
            app.getFeeRateForCoin = lambda *_args: (0.00002, "test")
            app.is_reverse_ads_bid = lambda *_args: False
            app.getOfferAddressTo = lambda options: BasicSwap.getOfferAddressTo(app, options)
            app.getPubkeyForAddress = lambda *_args: PrivateKey(
                b"\x14" * 32
            ).public_key.format()
            sent = []

            def send_message(*args, **kwargs):
                sent.append((args, kwargs))
                return b"\x74" * 28

            app.sendMessage = send_message
            with closing(sqlite3.connect(app.path)) as connection, connection:
                create_table(
                    connection.cursor(), "sentoffers", extract_schema()["sentoffers"]
                )
                create_table(
                    connection.cursor(),
                    "offer_tracking",
                    extract_schema()["offer_tracking"],
                )
            offer_id = BasicSwap.postOffer(
                app,
                Coins.HNS,
                Coins.BTC,
                2_000_000,
                50_000,
                2_000_000,
                SwapTypes.HNS_BTC_SWAP,
                lock_type=TxLockTypes.ABS_LOCK_TIME,
                lock_value=24 * 3600,
            )
            self.assertEqual(offer_id, b"\x74" * 28)
            self.assertEqual(sent[0][1]["message_nets"], "smsg")
            self.assertEqual(sent[0][1]["payload_version"], 2)
            self.assertEqual(bytes.fromhex(sent[0][0][2])[:1], bytes((MessageTypes.OFFER,)))
            with closing(sqlite3.connect(app.path)) as connection:
                offer = app.queryOne(
                    Offer, connection.cursor(), {"offer_id": offer_id}
                )
                posted = app.queryOne(
                    SentOffer, connection.cursor(), {"offer_id": offer_id}
                )
                tracking = app.queryOne(
                    OfferTracking, connection.cursor(), {"offer_id": offer_id}
                )
            self.assertEqual(offer.message_nets, "smsg")
            self.assertEqual(offer.min_bid_amount, offer.amount_from)
            self.assertIsNotNone(posted)
            self.assertEqual(tracking.mode, OfferTrackingModes.ONE_TIME)
            self.assertEqual(tracking.max_fills, 1)
            with self.assertRaisesRegex(ValueError, "prefunded"):
                BasicSwap.postOffer(
                    app,
                    Coins.HNS,
                    Coins.BTC,
                    2_000_000,
                    50_000,
                    2_000_000,
                    SwapTypes.HNS_BTC_SWAP,
                    lock_type=TxLockTypes.ABS_LOCK_TIME,
                    lock_value=24 * 3600,
                    extra_options={"prefunded_itx": b"unexpected"},
                )
            self.assertEqual(len(sent), 1)

    def test_native_offer_is_received_with_fixed_smsg_terms(self):
        with tempfile.TemporaryDirectory() as directory:
            app = FakeApp(Path(directory) / "offer.sqlite")
            app.network_addr = "receiver"
            app._debug_cases = []
            app.getSmsgMsgPayloadVersion = lambda _msg: 2
            app.getOffer = lambda offer_id, cursor=None: app.queryOne(
                Offer, cursor, {"offer_id": offer_id}
            )
            app.isOfferRevoked = lambda *_args: False
            app.notify = lambda *_args: None
            app.addMessageNetworkLink = lambda *_args: None
            app.is_reverse_ads_bid = lambda *_args: False
            app.validateSwapType = lambda *args: BasicSwap.validateSwapType(app, *args)
            app.validateOfferAmounts = lambda *_args: None
            app.validateOfferLockValue = lambda *args: BasicSwap.validateOfferLockValue(app, *args)
            app.validateOfferValidTime = lambda *args: BasicSwap.validateOfferValidTime(app, *args)
            app.validateMessageNets = lambda *args: BasicSwap.validateMessageNets(app, *args)
            app.coin.validateFeeRate = lambda *_args: None
            app.coin.make_int = lambda value, r=0: round(value * 1_000_000)

            for hns_first in (True, False):
                with self.subTest(hns_first=hns_first):
                    message = OfferMessage()
                    message.protocol_version = 5
                    message.coin_from = int(Coins.HNS if hns_first else Coins.BTC)
                    message.coin_to = int(Coins.BTC if hns_first else Coins.HNS)
                    message.amount_from = 2_000_000 if hns_first else 100_000
                    message.amount_to = 100_000 if hns_first else 2_000_000
                    message.min_bid_amount = message.amount_from
                    message.time_valid = 3600
                    message.lock_type = int(TxLockTypes.ABS_LOCK_TIME)
                    message.lock_value = 24 * 3600
                    message.swap_type = int(SwapTypes.HNS_BTC_SWAP)
                    message.message_nets = "smsg"
                    if hns_first:
                        message.fee_rate_to = 1000
                    else:
                        message.fee_rate_from = 1000
                    msg_id = (b"\x71" if hns_first else b"\x72") * 28
                    incoming = {
                        "msgid": msg_id.hex(),
                        "sent": app.now,
                        "from": "sender",
                        "to": "receiver",
                        "type": "smsg",
                        "raw": message.to_bytes(),
                    }
                    with patch(
                        "basicswap.basicswap.getMsgPubkey",
                        return_value=PrivateKey(b"\x04" * 32).public_key.format(),
                    ):
                        BasicSwap.processOffer(app, incoming)
                    with closing(sqlite3.connect(app.path)) as connection:
                        offer = app.queryOne(
                            Offer, connection.cursor(), {"offer_id": msg_id}
                        )
                    self.assertEqual(offer.swap_type, SwapTypes.HNS_BTC_SWAP)
                    self.assertEqual(offer.message_nets, "smsg")
                    self.assertEqual(offer.min_bid_amount, offer.amount_from)
                    self.assertEqual(offer.smsg_payload_version, 2)

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
                lock_type=TxLockTypes.ABS_LOCK_TIME,
                lock_value=24 * 3600,
            )
            app.offer = offer
            taker_cursor = app.openDB()
            try:
                app.add(Offer(**vars(offer)), taker_cursor)
            finally:
                app.closeDB(taker_cursor)

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

            maker = FakeApp(Path(directory) / "maker.sqlite", maker=True)
            maker.offer = Offer(**vars(offer))
            maker.offer.was_sent = True
            maker_cursor = maker.openDB()
            try:
                maker.add(maker.offer, maker_cursor)
            finally:
                maker.closeDB(maker_cursor)
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

            class FakeSettlement:
                MINIMUM_MAKER_REDEEM_MARGIN_SECONDS = 30 * 60
                def __init__(self, maker_record, terms, *args, btc_scan_start_height):
                    self.record = maker_record
                    self.persist = args[-1]
                    self.terms = terms
                    assert type(btc_scan_start_height) is int

                def fund_owned_lock(self, maximum_hns_fee):
                    self.assertEqual(maximum_hns_fee, 100_000)
                    bind_lock(self.record, "hns", b"\x27" * 32, 0)
                    self.persist(self.record)

            FakeSettlement.assertEqual = self.assertEqual
            maker.fail_first_send = False
            with (
                patch(
                    "basicswap.interface.hns.app_protocol.HnsBtcSettlement",
                    FakeSettlement,
                ),
                patch("basicswap.interface.hns.app_protocol.encryptMsg", easy_encrypt),
            ):
                accept_id = BasicSwap.acceptBid(maker, bid_id)
            with closing(sqlite3.connect(maker.path)) as connection:
                maker_record = maker.queryOne(
                    HnsBtcSwap, connection.cursor(), {"bid_id": bid_id}
                )
                accept_row = maker.queryOne(
                    HnsBtcOutbox, connection.cursor(), {"message_id": accept_id}
                )
            self.assertEqual(maker_record.hns_lock_txid, b"\x27" * 32)
            maker_cursor = maker.openDB()
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    maker.add(
                        HnsBtcSwap(
                            session_id=b"\x71" * 32,
                            offer_id=offer.offer_id,
                            bid_id=b"\x72" * 28,
                            role=1,
                            phase=1,
                        ),
                        maker_cursor,
                    )
            finally:
                maker.closeDB(maker_cursor, commit=False)
            self.assertEqual(smsgGetID(accept_row.message_bytes), accept_id)
            self.assertIsNotNone(accept_row.delivered_at)
            self.assertEqual(maker.sent, [accept_row.message_bytes])
            self.assertEqual(BasicSwap.acceptBid(maker, bid_id), accept_id)
            self.assertEqual(maker.sent, [accept_row.message_bytes])
            magic, genesis = hns_network_binding("regtest")
            terms = receive_accept_message(
                record,
                maker_record.accept_message,
                True,
                offer.amount_from,
                offer.amount_to,
                app.now,
                magic,
                genesis,
            )
            self.assertEqual(terms.hns_wallet_terms().session_id(), record.session_id)
            accept_msg = {
                "msgid": accept_id.hex(),
                "sent": app.now,
                "from": "receiver",
                "to": "sender",
                "type": "smsg",
                "raw": maker_record.accept_message,
            }
            self.assertEqual(receive_hns_btc_accept(app, accept_msg), bid_id)
            self.assertEqual(receive_hns_btc_accept(app, accept_msg), bid_id)
            with closing(sqlite3.connect(app.path)) as connection:
                saved = app.queryOne(
                    HnsBtcSwap, connection.cursor(), {"bid_id": bid_id}
                )
            self.assertEqual(saved.accept_message, maker_record.accept_message)
            self.assertEqual(saved.hns_lock_txid, b"\x27" * 32)
            with self.assertRaisesRegex(ValueError, "sender or bid mismatch"):
                receive_hns_btc_accept(
                    app, dict(accept_msg, **{"from": "different maker"})
                )

            confirmed = {"hns": False, "btc": False}
            funded = []

            class FakeTakerSettlement:
                MINIMUM_MAKER_REDEEM_MARGIN_SECONDS = 30 * 60
                own_coin = "btc"
                peer_coin = "hns"

                def __init__(self, taker_record, _terms, *args, btc_scan_start_height):
                    self.record = taker_record
                    self.persist = args[-1]
                    assert type(btc_scan_start_height) is int

                def verify_lock(self, coin):
                    return confirmed[coin]

                def scan_own_btc_lock_spend(self, _height):
                    return None

                def _chain_now(self):
                    return app.now

                def fund_owned_lock(self, maximum_hns_fee):
                    assert maximum_hns_fee == 100_000
                    if self.record.btc_lock_txid is None:
                        funded.append(True)
                        bind_lock(self.record, "btc", b"\x28" * 32, 1)
                        self.persist(self.record)

            with (
                patch(
                    "basicswap.interface.hns.app_settlement.HnsBtcSettlement",
                    FakeTakerSettlement,
                ),
                patch(
                    "basicswap.interface.hns.app_settlement.encryptMsg", easy_encrypt
                ),
            ):
                self.assertEqual(progress_hns_btc_trades(app), 0)
                confirmed["hns"] = True
                self.assertEqual(progress_hns_btc_trades(app), 0)
                confirmed["btc"] = True
                self.assertEqual(progress_hns_btc_trades(app), 1, app.logs)
                self.assertEqual(progress_hns_btc_trades(app), 0)
            self.assertEqual(len(funded), 1)
            with closing(sqlite3.connect(app.path)) as connection:
                taker_record = app.queryOne(
                    HnsBtcSwap, connection.cursor(), {"bid_id": bid_id}
                )
                second_row = app.queryOne(
                    HnsBtcOutbox,
                    connection.cursor(),
                    {
                        "session_id": taker_record.session_id,
                        "message_type": int(MessageTypes.HNS_BTC_SECOND_LOCK),
                    },
                )
            self.assertEqual(taker_record.btc_lock_txid, b"\x28" * 32)
            self.assertIsNotNone(taker_record.second_lock_message)
            self.assertIsNotNone(second_row)
            second_msg = {
                "msgid": second_row.message_id.hex(),
                "sent": app.now,
                "from": "sender",
                "to": "receiver",
                "type": "smsg",
                "raw": taker_record.second_lock_message,
            }
            self.assertEqual(receive_hns_btc_second_lock(maker, second_msg), bid_id)
            self.assertEqual(receive_hns_btc_second_lock(maker, second_msg), bid_id)

            maker_chain = {
                "peer_confirmed": False,
                "own_spent": False,
                "peer_spent": False,
            }
            redeemed = []

            class FakeMakerSettlement:
                own_coin = "hns"
                peer_coin = "btc"

                def __init__(self, maker_record, swap_terms, *args, btc_scan_start_height):
                    self.record = maker_record
                    self.terms = swap_terms
                    self.persist = args[-1]
                    self.hns_bridge = maker.coin.bridge
                    assert type(btc_scan_start_height) is int

                def observe_own_lock_spend(self):
                    if not maker_chain["own_spent"]:
                        return None
                    return ObservedSwapSpend(
                        "redeem", b"\x31" * 32, 2, self.record.secret_preimage
                    )

                def verify_lock(self, coin):
                    assert coin == "btc"
                    return maker_chain["peer_confirmed"]

                def redeem_peer_lock(self, maximum_hns_fee, **kwargs):
                    assert maximum_hns_fee == 100_000
                    redeemed.append(kwargs)
                    if self.record.btc_redeem_tx is None:
                        self.record.btc_redeem_tx = b"prepared"
                        self.persist(self.record)

                def scan_peer_btc_lock_spend(self, _height):
                    if not maker_chain["peer_spent"]:
                        return None
                    return ObservedSwapSpend(
                        "redeem", b"\x30" * 32, 2, self.record.secret_preimage
                    )

                def _prepared_btc(self, _field):
                    return (
                        SimpleNamespace(txid=b"\x30" * 32)
                        if self.record.btc_redeem_tx is not None
                        else None
                    )

            with patch(
                "basicswap.interface.hns.app_settlement.HnsBtcSettlement",
                FakeMakerSettlement,
            ):
                self.assertEqual(progress_hns_btc_trades(maker), 0, maker.logs)
                self.assertEqual(redeemed, [])
                maker_chain["peer_confirmed"] = True
                self.assertEqual(progress_hns_btc_trades(maker), 0, maker.logs)
                self.assertEqual(len(redeemed), 1)
                maker_chain["own_spent"] = True
                maker_chain["peer_spent"] = True
                self.assertEqual(progress_hns_btc_trades(maker), 1, maker.logs)
            with closing(sqlite3.connect(maker.path)) as connection:
                maker_bid = maker.queryOne(Bid, connection.cursor(), {"bid_id": bid_id})
            self.assertEqual(maker_bid.state, BidStates.SWAP_COMPLETED)


if __name__ == "__main__":
    unittest.main()
