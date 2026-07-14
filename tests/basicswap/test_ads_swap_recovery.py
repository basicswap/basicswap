# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for adaptor-sig swap resilience: crash recovery, message replays,
lost queued actions, and chain reorg handling.
"""

import unittest
from types import SimpleNamespace

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import (
    ActionTypes,
    BidStates,
    DebugTypes,
    EventLogTypes,
    TxStates,
)
from basicswap.chainparams import Coins
from basicswap.messages_npb import XmrBidLockTxSigsMessage

BID_ID = b"b" * 28
REFUND_TXID = bytes.fromhex("cc" * 32)


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


class StubTx:
    def __init__(self, state=None, txid=REFUND_TXID, vout=0, block_height=10):
        self.state = state
        self.txid = txid
        self.vout = vout
        self.block_height = block_height
        self.states_set = []

    def setState(self, state):
        self.states_set.append(state)
        self.state = state


def base_swap_client():
    sc = BasicSwap.__new__(BasicSwap)
    sc.fp = None
    sc.log = StubLog()
    sc.event_log = []  # (event_type, msg)
    sc.commits = []
    sc.saved = []
    sc.bid_errors = []
    sc.created_actions = []

    sc.openDB = lambda cursor=None: object()
    sc.closeDB = lambda cursor, commit=True: None
    sc.commitDB = lambda: sc.commits.append(len(sc.event_log))
    sc.logBidEvent = lambda bid_id, event, msg, cursor: sc.event_log.append(
        (event, msg)
    )
    sc.countBidEvents = lambda bid, event, cursor: sum(
        1 for e, _ in sc.event_log if e == event
    )
    sc.setBidError = lambda bid, msg, save_bid=True, xmr_swap=None, cursor=None: sc.bid_errors.append(
        msg
    )
    sc.saveBidInSession = lambda bid_id, bid, cursor, xmr_swap=None, save_in_progress=None: sc.saved.append(
        bid.state
    )
    sc.createActionInSession = (
        lambda delay, action_type, bid_id, cursor: sc.created_actions.append(
            action_type
        )
    )
    sc.get_delay_event_seconds = lambda: 1
    sc.is_reverse_ads_bid = lambda cf, ct: False
    sc.isBchXmrSwap = lambda offer: False
    sc.logIDT = lambda t: str(t)
    sc.logIDM = lambda t: str(t)
    return sc


def make_offer():
    return SimpleNamespace(
        coin_from=int(Coins.BTC),
        coin_to=int(Coins.PART),
        offer_id=b"offer",
        swap_type=None,
    )


# ---------------------------------------------------------------------------
# Coin B lock publish recovery
# ---------------------------------------------------------------------------


class StubCIB:
    def __init__(self, calls):
        self.calls = calls

    def coin_name(self):
        return "PART"

    def publishBLockTx(self, vkbv, pkbs, amount, fee_rate, unlock_time=0):
        self.calls.append("publish")
        return bytes.fromhex("dd" * 32)


def make_b_lock_client(bid):
    sc = base_swap_client()
    calls = []
    sc.calls = calls
    sc.commitDB = lambda: calls.append("commit")

    orig_log = sc.logBidEvent
    sc.logBidEvent = lambda bid_id, event, msg, cursor: (
        sc.event_log.append((event, msg)),
        calls.append(event),
    )
    assert orig_log  # silence lint

    xmr_swap = SimpleNamespace(vkbv=b"v", pkbs=b"p", b_lock_tx_id=None)
    offer = make_offer()
    xmr_offer = SimpleNamespace(a_fee_rate=1, b_fee_rate=1)

    sc.getXmrBidFromSession = lambda cursor, bid_id: (bid, xmr_swap)
    sc.getXmrOfferFromSession = lambda cursor, offer_id: (offer, xmr_offer)
    sc.findTxB = lambda ci, xmr_swap, bid, cursor, was_sent: False
    sc.getPreFundedTx = lambda concept, bid_id, tx_type, cursor=None: None
    sc.ci = lambda coin: StubCIB(calls)
    return sc


def make_b_lock_bid():
    return SimpleNamespace(
        bid_id=BID_ID,
        offer_id=b"offer",
        was_sent=True,
        was_received=False,
        debug_ind=DebugTypes.NONE,
        xmr_b_lock_tx=None,
        amount_to=1000,
        state=BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED,
        setState=lambda s: None,
    )


class TestAdsSwapRecoveryCoinBLock(unittest.TestCase):
    def test_write_ahead_marker_committed_before_broadcast(self):
        bid = make_b_lock_bid()
        sc = make_b_lock_client(bid)

        sc.sendXmrBidCoinBLockTx(BID_ID, object())

        calls = sc.calls
        self.assertIn("publish", calls)
        started_idx = calls.index(EventLogTypes.LOCK_TX_B_PUBLISH_STARTED)
        commit_idx = calls.index("commit")
        publish_idx = calls.index("publish")
        published_idx = calls.index(EventLogTypes.LOCK_TX_B_PUBLISHED)
        self.assertLess(started_idx, commit_idx)
        self.assertLess(commit_idx, publish_idx)
        self.assertLess(publish_idx, published_idx)
        self.assertEqual(len(sc.bid_errors), 0)

    def test_unmatched_marker_blocks_rebroadcast(self):
        bid = make_b_lock_bid()
        sc = make_b_lock_client(bid)
        # Simulate a crash after the marker was committed but before the
        # publish outcome was recorded.
        sc.event_log.append((EventLogTypes.LOCK_TX_B_PUBLISH_STARTED, ""))

        sc.sendXmrBidCoinBLockTx(BID_ID, object())

        self.assertNotIn("publish", sc.calls)
        self.assertEqual(len(sc.bid_errors), 1)

    def test_failed_attempt_allows_retry(self):
        bid = make_b_lock_bid()
        sc = make_b_lock_client(bid)
        # A previous attempt that failed cleanly must not block the retry.
        sc.event_log.append((EventLogTypes.LOCK_TX_B_PUBLISH_STARTED, ""))
        sc.event_log.append((EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, "err"))

        sc.sendXmrBidCoinBLockTx(BID_ID, object())

        self.assertIn("publish", sc.calls)
        self.assertEqual(len(sc.bid_errors), 0)


# ---------------------------------------------------------------------------
# Replayed bid message and coin A lock state gate
# ---------------------------------------------------------------------------


class TestAdsSwapRecoveryReplayedSigs(unittest.TestCase):
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


class TestAdsSwapRecoveryCoinALockGate(unittest.TestCase):
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


# ---------------------------------------------------------------------------
# Bid state polling recovery
# ---------------------------------------------------------------------------


class StubCIA:
    def __init__(
        self, blocks_confirmed=2, refund_chain_info=None, have_signed_refund=False
    ):
        self.blocks_confirmed = blocks_confirmed
        self.coin_ticker = "BTC"
        self._refund_chain_info = refund_chain_info
        self._have_signed_refund = have_signed_refund

    def getSCLockScriptAddress(self, script):
        return "addr"

    def getLockRefundTxSwapOutputValue(self, bid, xmr_swap):
        return 1000

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, vout=None):
        return self._refund_chain_info

    def haveSignedLockRefundTx(self, xmr_swap):
        return self._have_signed_refund

    def isCsvLockMature(self, lock_type, lock_time, block_height, block_time):
        return False


def make_check_state_client(ci, bid, xmr_swap):
    sc = base_swap_client()
    xmr_offer = SimpleNamespace(lock_time_1=10, lock_time_2=10)
    sc.queryOne = lambda model, cursor, filters: (
        xmr_offer if model.__name__ == "XmrOffer" else xmr_swap
    )
    sc.ci = lambda coin: ci
    sc.add = lambda obj, cursor, upsert=False: sc.saved.append(obj)
    sc.setTxBlockInfoFromHeight = lambda ci_, tx, height: None
    sc.findTxB = lambda ci_, xmr_swap_, bid_, cursor, was_sent: False
    sc.countQueuedActions = lambda cursor, bid_id, action_type: 0
    sc.haveDebugInd = lambda bid_id, ind: False
    return sc


def make_refund_bid(state, refund_tx):
    from basicswap.basicswap_util import TxTypes

    return SimpleNamespace(
        bid_id=BID_ID,
        offer_id=b"offer",
        state=state,
        was_sent=False,
        was_received=False,
        chain_a_height_start=1,
        txns={TxTypes.XMR_SWAP_A_LOCK_REFUND: refund_tx},
        xmr_a_lock_tx=None,
        xmr_b_lock_tx=None,
        debug_ind=DebugTypes.NONE,
    )


class TestAdsSwapRecoveryRefundDepth(unittest.TestCase):
    def run_check(self, refund_tx, chain_info):
        xmr_swap = SimpleNamespace(a_lock_refund_tx_script=b"script")
        bid = make_refund_bid(BidStates.SWAP_COMPLETED, refund_tx)
        ci = StubCIA(blocks_confirmed=2, refund_chain_info=chain_info)
        sc = make_check_state_client(ci, bid, xmr_swap)
        offer = make_offer()
        sc.checkXmrBidState(BID_ID, bid, offer)
        return sc

    def test_reorged_refund_reverts_cached_state(self):
        refund_tx = StubTx(state=TxStates.TX_CONFIRMED)
        sc = self.run_check(refund_tx, {"height": 100, "depth": 1})

        self.assertEqual(refund_tx.state, TxStates.TX_IN_CHAIN)
        self.assertEqual(refund_tx.states_set, [TxStates.TX_IN_CHAIN])
        assert sc is not None

    def test_evicted_refund_reverts_to_mempool_state(self):
        refund_tx = StubTx(state=TxStates.TX_CONFIRMED)
        self.run_check(refund_tx, {"height": 0, "depth": 0})

        self.assertEqual(refund_tx.state, TxStates.TX_IN_MEMPOOL)

    def test_still_confirmed_no_state_change(self):
        refund_tx = StubTx(state=TxStates.TX_CONFIRMED)
        sc = self.run_check(refund_tx, {"height": 100, "depth": 5})

        self.assertEqual(refund_tx.state, TxStates.TX_CONFIRMED)
        self.assertEqual(refund_tx.states_set, [])
        # No duplicate confirmed event.
        self.assertEqual(
            sum(
                1
                for e, _ in sc.event_log
                if e == EventLogTypes.LOCK_TX_A_REFUND_TX_CONFIRMED
            ),
            0,
        )

    def test_query_failure_keeps_confirmed_state(self):
        refund_tx = StubTx(state=TxStates.TX_CONFIRMED)
        self.run_check(refund_tx, None)

        self.assertEqual(refund_tx.state, TxStates.TX_CONFIRMED)
        self.assertEqual(refund_tx.states_set, [])

    def test_fresh_confirmation_still_recorded(self):
        refund_tx = StubTx(state=TxStates.TX_IN_CHAIN)
        sc = self.run_check(refund_tx, {"height": 100, "depth": 2})

        self.assertEqual(refund_tx.state, TxStates.TX_CONFIRMED)
        self.assertEqual(
            sum(
                1
                for e, _ in sc.event_log
                if e == EventLogTypes.LOCK_TX_A_REFUND_TX_CONFIRMED
            ),
            1,
        )


class TestAdsSwapRecoveryRequeueLockTxB(unittest.TestCase):
    def run_check(self, bid, queued_count=0):
        xmr_swap = SimpleNamespace(a_lock_refund_tx_script=b"script")
        ci = StubCIA(blocks_confirmed=2)
        sc = make_check_state_client(ci, bid, xmr_swap)
        sc.countQueuedActions = lambda cursor, bid_id, action_type: queued_count
        offer = make_offer()
        sc.checkXmrBidState(BID_ID, bid, offer)
        return sc

    def make_bid(self, state):
        return SimpleNamespace(
            bid_id=BID_ID,
            offer_id=b"offer",
            state=state,
            was_sent=True,
            was_received=False,
            chain_a_height_start=1,
            txns={},
            xmr_a_lock_tx=None,
            xmr_b_lock_tx=None,
            debug_ind=DebugTypes.NONE,
        )

    def test_purged_action_is_recreated(self):
        bid = self.make_bid(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        sc = self.run_check(bid, queued_count=0)

        self.assertIn(ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, sc.created_actions)

    def test_existing_action_not_duplicated(self):
        bid = self.make_bid(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        sc = self.run_check(bid, queued_count=1)

        self.assertNotIn(ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, sc.created_actions)

    def test_not_recreated_in_prerefund_state(self):
        bid = self.make_bid(BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND)
        sc = self.run_check(bid, queued_count=0)

        self.assertNotIn(ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, sc.created_actions)


if __name__ == "__main__":
    unittest.main()
