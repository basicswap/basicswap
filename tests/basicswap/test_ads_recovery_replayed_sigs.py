# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for adaptor-sig swap message replay handling:
a replayed XMR_BID_TXN_SIGS message must not error the bid, and the
coin A lock tx must only be sent from the expected bid state.
"""

import unittest
from types import SimpleNamespace

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import (
    BidStates,
)
from basicswap.chainparams import Coins
from basicswap.messages_npb import XmrBidLockTxSigsMessage

BID_ID = b"b" * 28


class StubLog:
    def id(self, v):
        return str(v)

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


def base_swap_client():
    sc = BasicSwap.__new__(BasicSwap)
    sc.fp = None
    sc.log = StubLog()
    sc.event_log = []  # (event_type, msg)
    sc.saved = []
    sc.bid_errors = []

    sc.openDB = lambda cursor=None: object()
    sc.closeDB = lambda cursor, commit=True: None
    sc.commitDB = lambda: None
    sc.logBidEvent = lambda bid_id, event, msg, cursor: sc.event_log.append(
        (event, msg)
    )
    sc.setBidError = lambda bid, msg, save_bid=True, xmr_swap=None, cursor=None: sc.bid_errors.append(
        msg
    )
    sc.saveBidInSession = lambda bid_id, bid, cursor, xmr_swap=None, save_in_progress=None: sc.saved.append(
        bid.state
    )
    sc.is_reverse_ads_bid = lambda cf, ct: False
    sc.isBchXmrSwap = lambda offer: False
    sc.logIDM = lambda t: str(t)
    return sc


def make_offer():
    return SimpleNamespace(
        coin_from=int(Coins.BTC),
        coin_to=int(Coins.PART),
        offer_id=b"offer",
        swap_type=None,
    )


class TestAdsRecoveryReplayedSigs(unittest.TestCase):
    def make_sigs_msg_client(self, bid):
        sc = base_swap_client()
        xmr_swap = SimpleNamespace()
        offer = make_offer()
        offer.addr_from = "addr_offerer"
        offer.was_sent = False
        xmr_offer = SimpleNamespace()

        msg_buf = XmrBidLockTxSigsMessage(
            bid_msg_id=BID_ID,
            af_lock_refund_spend_tx_esig=b"\x01" * 32,
            af_lock_refund_tx_sig=b"\x02" * 32,
        )
        msg = {
            "msgid": "aa" * 28,
            "to": "addr_offerer",
            "from": "addr_bidder",
            "hex": "00" + msg_buf.to_bytes().hex() + "00",
        }
        sc.getSmsgMsgBytes = lambda m: msg_buf.to_bytes()
        sc.getXmrBid = lambda bid_id: (bid, xmr_swap)
        sc.getXmrOffer = lambda offer_id: (offer, xmr_offer)
        sc.ci = lambda coin: SimpleNamespace(curve_type=lambda: None)
        return sc, msg

    def test_replayed_message_does_not_error_bid(self):
        # Bid has already progressed past BID_ACCEPTED.
        bid = SimpleNamespace(
            bid_id=BID_ID,
            offer_id=b"offer",
            state=BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS,
            was_sent=False,
            was_received=True,
            bid_addr="addr_bidder",
        )
        sc, msg = self.make_sigs_msg_client(bid)

        with self.assertRaises(ValueError):
            sc.processXmrBidCoinALockSigs(msg)

        # The state guard must reject the replay without erroring the bid.
        self.assertEqual(len(sc.bid_errors), 0)
        self.assertEqual(bid.state, BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)


class TestAdsRecoveryCoinALockGate(unittest.TestCase):
    def test_errored_bid_does_not_publish_coin_a(self):
        sc = base_swap_client()
        bid = SimpleNamespace(
            bid_id=BID_ID,
            offer_id=b"offer",
            state=BidStates.BID_ERROR,
        )
        xmr_swap = SimpleNamespace()
        sc.getXmrBidFromSession = lambda cursor, bid_id: (bid, xmr_swap)

        def fail_offer_lookup(cursor, offer_id):
            raise AssertionError("Should have returned before the offer lookup")

        sc.getXmrOfferFromSession = fail_offer_lookup

        sc.sendXmrBidCoinALockTx(BID_ID, object())
        self.assertEqual(len(sc.bid_errors), 0)

    def test_expected_state_proceeds(self):
        sc = base_swap_client()
        bid = SimpleNamespace(
            bid_id=BID_ID,
            offer_id=b"offer",
            state=BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS,
        )
        xmr_swap = SimpleNamespace()
        sc.getXmrBidFromSession = lambda cursor, bid_id: (bid, xmr_swap)

        sentinel = RuntimeError("reached offer lookup")

        def offer_lookup(cursor, offer_id):
            raise sentinel

        sc.getXmrOfferFromSession = offer_lookup

        with self.assertRaises(RuntimeError):
            sc.sendXmrBidCoinALockTx(BID_ID, object())


if __name__ == "__main__":
    unittest.main()
