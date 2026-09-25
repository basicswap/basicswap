"""Cross-check both BTC/HNS seller-first terms before any funding action."""

import unittest
from dataclasses import replace

from basicswap.interface.hns.htlc import HnsHtlc
from basicswap.interface.hns.swap_terms import (
    HNS_TIME_UNIT,
    HnsBtcSwapTerms,
    hns_time_lock_at_or_after,
    hns_time_lock_threshold,
    make_btc_contract_script,
)
from basicswap.messages_npb import (
    HnsBtcBidAcceptMessage,
    HnsBtcBidMessage,
    HnsBtcSecondLockMessage,
)
from tests.basicswap.test_hns_htlc import DESCRIPTOR

NOW = 1_760_000_000
MAGIC = 0x5B6EC393
GENESIS = bytes.fromhex("11" * 32)
BASE_DESCRIPTOR = HnsHtlc.decode(DESCRIPTOR, MAGIC, GENESIS)
HASHLOCK = BASE_DESCRIPTOR.hashlock
BTC_RECEIVER = bytes.fromhex("31" * 20)
BTC_REFUND = bytes.fromhex("42" * 20)


def terms(hns_first):
    hns_deadline = NOW + (24 if hns_first else 12) * 60 * 60
    btc_deadline = NOW + (12 if hns_first else 24) * 60 * 60
    descriptor = replace(
        BASE_DESCRIPTOR,
        value=2_000_000,
        refund_locktime=hns_time_lock_at_or_after(hns_deadline),
    )
    return HnsBtcSwapTerms(
        offer_id=bytes.fromhex("11" * 28),
        bid_id=bytes.fromhex("22" * 28),
        session_nonce=bytes.fromhex("33" * 32),
        hns_first=hns_first,
        hns_amount=2_000_000,
        btc_amount=100_000,
        hns_descriptor=descriptor,
        btc_contract_script=make_btc_contract_script(
            btc_deadline, HASHLOCK, BTC_RECEIVER, BTC_REFUND
        ),
        maker_hns_public_key=(
            descriptor.refund_public_key
            if hns_first
            else descriptor.receiver_public_key
        ),
        taker_hns_public_key=(
            descriptor.receiver_public_key
            if hns_first
            else descriptor.refund_public_key
        ),
        maker_btc_key_hash=BTC_RECEIVER if hns_first else BTC_REFUND,
        taker_btc_key_hash=BTC_REFUND if hns_first else BTC_RECEIVER,
        minimum_hns_confirmations=2,
        minimum_btc_confirmations=2,
    )


def messages(trade):
    bid = HnsBtcBidMessage(
        protocol_version=1,
        offer_msg_id=trade.offer_id,
        amount_from=trade.hns_amount if trade.hns_first else trade.btc_amount,
        amount_to=trade.btc_amount if trade.hns_first else trade.hns_amount,
        session_nonce=trade.session_nonce,
        taker_hns_public_key=trade.taker_hns_public_key,
        taker_btc_key_hash=trade.taker_btc_key_hash,
        minimum_hns_confirmations=trade.minimum_hns_confirmations,
        minimum_btc_confirmations=trade.minimum_btc_confirmations,
    )
    accept = HnsBtcBidAcceptMessage(
        bid_msg_id=trade.bid_id,
        first_txid=bytes.fromhex("ab" * 32),
        first_vout=1,
        hns_descriptor=trade.hns_descriptor.encode(),
        btc_contract_script=trade.btc_contract_script,
        maker_hns_public_key=trade.maker_hns_public_key,
        maker_btc_key_hash=trade.maker_btc_key_hash,
        terms_commitment=trade.commitment(NOW, MAGIC, GENESIS),
    )
    return bid, accept


class HnsBtcSwapTermsTest(unittest.TestCase):
    def test_negotiated_messages_rebuild_both_trade_directions(self):
        for hns_first in (True, False):
            with self.subTest(hns_first=hns_first):
                trade = terms(hns_first)
                bid, accept = messages(trade)
                decoded, first_outpoint = HnsBtcSwapTerms.from_messages(
                    bid.to_bytes(),
                    accept.to_bytes(),
                    trade.offer_id,
                    trade.bid_id,
                    hns_first,
                    trade.hns_amount,
                    trade.btc_amount,
                    NOW,
                    MAGIC,
                    GENESIS,
                )
                self.assertEqual(decoded, trade)
                self.assertEqual(
                    decoded.hns_wallet_terms().descriptor, trade.hns_descriptor
                )
                self.assertEqual(len(decoded.hns_wallet_terms().session_id()), 32)
                self.assertEqual(first_outpoint, (bytes.fromhex("ab" * 32), 1))
                second = HnsBtcSecondLockMessage(
                    bid_msg_id=trade.bid_id,
                    second_txid=bytes.fromhex("cd" * 32),
                    second_vout=0,
                    terms_commitment=trade.commitment(NOW, MAGIC, GENESIS),
                )
                self.assertEqual(
                    decoded.second_lock_outpoint(
                        second.to_bytes(), NOW, MAGIC, GENESIS
                    ),
                    (bytes.fromhex("cd" * 32), 0),
                )
                second.terms_commitment = bytes(32)
                with self.assertRaises(ValueError):
                    decoded.second_lock_outpoint(second.to_bytes(), NOW, MAGIC, GENESIS)

    def test_message_mutations_and_noncanonical_encoding_are_rejected(self):
        trade = terms(True)
        bid, accept = messages(trade)
        original = (bid.to_bytes(), accept.to_bytes())
        variations = []
        bid.session_nonce = bytes.fromhex("44" * 32)
        variations.append((bid.to_bytes(), original[1]))
        bid, accept = messages(trade)
        accept.terms_commitment = bytes.fromhex("66" * 32)
        variations.append((original[0], accept.to_bytes()))
        bid, accept = messages(trade)
        accept.first_txid = bytes(32)
        variations.append((original[0], accept.to_bytes()))
        variations.append((original[0] + original[0][:2], original[1]))
        variations.append((original[0] + b"\x98\x06\x01", original[1]))
        for bid_bytes, accept_bytes in variations:
            with (
                self.subTest(bid_bytes=bid_bytes, accept_bytes=accept_bytes),
                self.assertRaises(ValueError),
            ):
                HnsBtcSwapTerms.from_messages(
                    bid_bytes,
                    accept_bytes,
                    trade.offer_id,
                    trade.bid_id,
                    True,
                    trade.hns_amount,
                    trade.btc_amount,
                    NOW,
                    MAGIC,
                    GENESIS,
                )

    def test_both_funding_directions_have_later_first_refund(self):
        for hns_first in (True, False):
            with self.subTest(hns_first=hns_first):
                trade = terms(hns_first)
                first, second = trade.validate(NOW, MAGIC, GENESIS)
                self.assertGreater(first, second)
                self.assertEqual(len(trade.commitment(NOW, MAGIC, GENESIS)), 32)
                self.assertEqual(
                    hns_time_lock_threshold(trade.hns_descriptor.refund_locktime)
                    % HNS_TIME_UNIT,
                    0,
                )

    def test_changed_hashlock_key_amount_and_network_are_rejected(self):
        trade = terms(True)
        changed = (
            replace(trade, hns_amount=trade.hns_amount + 1),
            replace(trade, maker_btc_key_hash=BTC_REFUND),
            replace(trade, btc_contract_script=trade.btc_contract_script[:-1]),
            replace(
                trade,
                hns_descriptor=replace(
                    trade.hns_descriptor, hashlock=bytes.fromhex("55" * 32)
                ),
            ),
            replace(trade, session_nonce=bytes(32)),
        )
        for mutation in changed:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                mutation.validate(NOW, MAGIC, GENESIS)
        with self.assertRaises(ValueError):
            trade.validate(NOW, MAGIC + 1, GENESIS)

    def test_short_or_reversed_refund_window_is_rejected(self):
        trade = terms(True)
        short_btc = make_btc_contract_script(
            NOW + 60, HASHLOCK, BTC_RECEIVER, BTC_REFUND
        )
        with self.assertRaisesRegex(ValueError, "unsafe swap refund ordering"):
            replace(trade, btc_contract_script=short_btc).validate(NOW, MAGIC, GENESIS)
        reversed_hns = replace(
            trade.hns_descriptor,
            refund_locktime=hns_time_lock_at_or_after(NOW + 10 * 60 * 60),
        )
        with self.assertRaisesRegex(ValueError, "unsafe swap refund ordering"):
            replace(trade, hns_descriptor=reversed_hns).validate(NOW, MAGIC, GENESIS)


if __name__ == "__main__":
    unittest.main()
