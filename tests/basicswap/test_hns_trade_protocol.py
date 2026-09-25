"""Persisted bid, acceptance, and second-lock handoff in both directions."""

import unittest

from coincurve import PrivateKey

from basicswap.interface.hns.trade_protocol import (
    bind_sent_bid,
    make_accept_message,
    make_second_lock_message,
    prepare_maker_terms,
    prepare_taker_bid,
    receive_accept_message,
    receive_maker_bid,
    receive_second_lock_message,
    restore_maker_terms,
)
from basicswap.interface.hns.trade_record import bind_lock, restore_trade
from tests.basicswap.test_hns_btc_swap import GENESIS, MAGIC, NOW

OFFER_ID = bytes.fromhex("11" * 28)
BID_ID = bytes.fromhex("22" * 28)
NONCE = bytes.fromhex("33" * 32)
MAKER_BTC_KEY = bytes.fromhex("01" * 32)
TAKER_BTC_KEY = bytes.fromhex("02" * 32)
SECRET = bytes.fromhex("aa" * 32)


class FakeHnsBridge:
    def __init__(self, scalar):
        self.scalar = scalar

    def key(self, offer_id, session_nonce, refund):
        assert offer_id == OFFER_ID
        assert session_nonce == NONCE
        scalar = self.scalar + int(refund)
        return PrivateKey(bytes([scalar]) * 32).public_key.format(compressed=True)


class HnsTradeProtocolTest(unittest.TestCase):
    def test_durable_message_handoff_both_directions(self):
        for hns_first in (True, False):
            with self.subTest(hns_first=hns_first):
                taker_bridge = FakeHnsBridge(3)
                maker_bridge = FakeHnsBridge(5)
                taker, bid_raw = prepare_taker_bid(
                    OFFER_ID,
                    hns_first,
                    2_000_000,
                    100_000,
                    TAKER_BTC_KEY,
                    taker_bridge,
                    NOW,
                    session_nonce=NONCE,
                )
                self.assertIsNone(taker.bid_id)
                self.assertEqual(taker.bid_message, bid_raw)
                bind_sent_bid(taker, BID_ID)
                maker = receive_maker_bid(OFFER_ID, BID_ID, bid_raw, NOW, NOW)
                self.assertEqual(maker.session_id, taker.session_id)

                terms = prepare_maker_terms(
                    maker,
                    hns_first,
                    2_000_000,
                    100_000,
                    MAKER_BTC_KEY,
                    maker_bridge,
                    SECRET,
                    NOW + 24 * 3600,
                    NOW + 12 * 3600,
                    NOW,
                    MAGIC,
                    GENESIS,
                )
                self.assertEqual(maker.secret_preimage, SECRET)
                self.assertEqual(
                    restore_maker_terms(
                        maker, hns_first, 2_000_000, 100_000, NOW, MAGIC, GENESIS
                    ),
                    terms,
                )
                self.assertEqual(
                    prepare_maker_terms(
                        maker,
                        hns_first,
                        2_000_000,
                        100_000,
                        MAKER_BTC_KEY,
                        maker_bridge,
                        SECRET,
                        NOW + 24 * 3600,
                        NOW + 12 * 3600,
                        NOW,
                        MAGIC,
                        GENESIS,
                    ),
                    terms,
                )
                bind_lock(
                    maker,
                    "hns" if hns_first else "btc",
                    bytes.fromhex("ab" * 32),
                    0 if hns_first else 1,
                )
                accept_raw = make_accept_message(maker, terms, NOW, MAGIC, GENESIS)
                taker_terms = receive_accept_message(
                    taker,
                    accept_raw,
                    hns_first,
                    2_000_000,
                    100_000,
                    NOW,
                    MAGIC,
                    GENESIS,
                )
                self.assertEqual(taker_terms, terms)
                self.assertEqual(maker.terms_commitment, taker.terms_commitment)
                self.assertEqual(
                    receive_accept_message(
                        taker,
                        accept_raw,
                        hns_first,
                        2_000_000,
                        100_000,
                        NOW + 48 * 3600,
                        MAGIC,
                        GENESIS,
                    ),
                    terms,
                )
                bind_lock(
                    taker,
                    "btc" if hns_first else "hns",
                    bytes.fromhex("cd" * 32),
                    2 if hns_first else 0,
                )
                second_raw = make_second_lock_message(taker, terms, NOW, MAGIC, GENESIS)
                self.assertEqual(
                    receive_second_lock_message(
                        maker, terms, second_raw, NOW, MAGIC, GENESIS
                    ),
                    (bytes.fromhex("cd" * 32), 2 if hns_first else 0),
                )
                for record in (maker, taker):
                    restored, first = restore_trade(
                        record,
                        hns_first,
                        2_000_000,
                        100_000,
                        NOW + 48 * 3600,
                        MAGIC,
                        GENESIS,
                    )
                    self.assertEqual(restored, terms)
                    self.assertEqual(first[0], bytes.fromhex("ab" * 32))

    def test_recovery_rejects_changed_maker_wallet_key(self):
        maker_bridge = FakeHnsBridge(5)
        _, bid_raw = prepare_taker_bid(
            OFFER_ID,
            True,
            2_000_000,
            100_000,
            TAKER_BTC_KEY,
            FakeHnsBridge(3),
            NOW,
            session_nonce=NONCE,
        )
        maker = receive_maker_bid(OFFER_ID, BID_ID, bid_raw, NOW, NOW)
        prepare_maker_terms(
            maker,
            True,
            2_000_000,
            100_000,
            MAKER_BTC_KEY,
            maker_bridge,
            SECRET,
            NOW + 24 * 3600,
            NOW + 12 * 3600,
            NOW,
            MAGIC,
            GENESIS,
        )
        with self.assertRaisesRegex(ValueError, "wallet key changed"):
            prepare_maker_terms(
                maker,
                True,
                2_000_000,
                100_000,
                MAKER_BTC_KEY,
                FakeHnsBridge(6),
                SECRET,
                NOW + 24 * 3600,
                NOW + 12 * 3600,
                NOW,
                MAGIC,
                GENESIS,
            )

    def test_expired_inbound_bid_is_rejected(self):
        _, bid_raw = prepare_taker_bid(
            OFFER_ID,
            True,
            2_000_000,
            100_000,
            TAKER_BTC_KEY,
            FakeHnsBridge(3),
            NOW,
            session_nonce=NONCE,
        )
        with self.assertRaisesRegex(ValueError, "receive time"):
            receive_maker_bid(OFFER_ID, BID_ID, bid_raw, NOW, NOW + 601)


if __name__ == "__main__":
    unittest.main()
