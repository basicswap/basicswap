# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for adaptor-sig swap coin B lock publish recovery: a write-ahead
marker records that a broadcast was attempted. After a crash the shared view
wallet (findTxB) is checked before re-broadcasting, so recovery is automatic
rather than requiring manual intervention.
"""

import threading
import unittest
from types import SimpleNamespace

import basicswap.util_xmr as xmr_util
from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import (
    BidStates,
    DebugTypes,
    EventLogTypes,
)
from basicswap.chainparams import Coins
from basicswap.interface.xmr.xmr import XMRInterface
from basicswap.util import TemporaryError

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
    sc.commits = []
    sc.saved = []
    sc.bid_errors = []

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
    sc.is_reverse_ads_bid = lambda cf, ct: False
    sc.logIDT = lambda t: str(t)
    return sc


def make_offer():
    return SimpleNamespace(
        coin_from=int(Coins.BTC),
        coin_to=int(Coins.PART),
        offer_id=b"offer",
        swap_type=None,
    )


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


class TestAdsRecoveryCoinBLock(unittest.TestCase):
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

    def test_unmatched_marker_recovers_when_tx_found(self):
        bid = make_b_lock_bid()
        sc = make_b_lock_client(bid)

        # findTxB detects the lock tx already exists (shared view wallet), so it
        # must not re-broadcast and must not error the bid.
        def found_txb(ci, xmr_swap, bid_, cursor, was_sent):
            bid_.xmr_b_lock_tx = SimpleNamespace(
                txid=bytes.fromhex("dd" * 32),
                b_lock_tx_id=bytes.fromhex("dd" * 32),
            )
            return True

        sc.findTxB = found_txb
        # Simulate a crash after the marker was committed but before the
        # publish outcome was recorded.
        sc.event_log.append((EventLogTypes.LOCK_TX_B_PUBLISH_STARTED, ""))

        sc.sendXmrBidCoinBLockTx(BID_ID, object())

        self.assertNotIn("publish", sc.calls)
        self.assertEqual(len(sc.bid_errors), 0)

    def test_unmatched_marker_republishes_when_not_found(self):
        bid = make_b_lock_bid()
        sc = make_b_lock_client(bid)
        # Crash after the marker was committed; findTxB finds nothing, so it is
        # safe to re-publish (publishBLockTx dedups against the sending wallet).
        sc.event_log.append((EventLogTypes.LOCK_TX_B_PUBLISH_STARTED, ""))

        sc.sendXmrBidCoinBLockTx(BID_ID, object())

        self.assertIn("publish", sc.calls)
        self.assertEqual(len(sc.bid_errors), 0)

    def test_failed_attempt_allows_retry(self):
        bid = make_b_lock_bid()
        sc = make_b_lock_client(bid)
        # A previous attempt that failed cleanly must not block the retry.
        sc.event_log.append((EventLogTypes.LOCK_TX_B_PUBLISH_STARTED, ""))
        sc.event_log.append((EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, "err"))

        sc.sendXmrBidCoinBLockTx(BID_ID, object())

        self.assertIn("publish", sc.calls)
        self.assertEqual(len(sc.bid_errors), 0)


KBV = b"\x03" * 32
PKBS = b"\x04" * 32
SWAP_VALUE = 1000


def make_xmr_interface(
    transfers,
    daemon_height=100,
    target_height=0,
    wallet_height=100,
):
    ci = XMRInterface.__new__(XMRInterface)
    ci._log = StubLog()
    ci._mx_wallet = threading.Lock()
    ci._addr_prefix = 18
    ci._rpctimeout = 60
    ci.getPubkey = lambda k: b"\x02" * 32
    ci.openWallet = lambda name: None
    ci.createWallet = lambda params: None

    shared_addr = xmr_util.encode_address(b"\x02" * 32, PKBS, 18)

    def rpc_wallet(method, params=None):
        if method == "refresh":
            return {}
        if method == "get_address":
            return {"address": shared_addr}
        if method == "incoming_transfers":
            return {"transfers": transfers}
        if method == "get_height":
            return {"height": wallet_height}
        raise RuntimeError(f"unexpected wallet rpc {method}")

    def rpc2(method, params=None, timeout=None):
        if method == "get_info":
            return {"height": daemon_height, "target_height": target_height}
        raise RuntimeError(f"unexpected daemon rpc {method}")

    ci.rpc_wallet = rpc_wallet
    ci.rpc2 = rpc2
    return ci


class TestFindTxBSyncGate(unittest.TestCase):
    def find_tx_b(self, ci):
        return ci.findTxB(KBV, PKBS, SWAP_VALUE, 2, 1, True)

    def test_not_found_synced_returns_none(self):
        ci = make_xmr_interface([])
        self.assertIsNone(self.find_tx_b(ci))

    def test_not_found_daemon_syncing_raises(self):
        ci = make_xmr_interface([], daemon_height=90, target_height=100)
        with self.assertRaises(TemporaryError):
            self.find_tx_b(ci)

    def test_not_found_wallet_behind_raises(self):
        ci = make_xmr_interface([], daemon_height=100, wallet_height=50)
        with self.assertRaises(TemporaryError):
            self.find_tx_b(ci)

    def test_found_while_syncing_returns_tx(self):
        transfers = [
            {
                "unlocked": True,
                "amount": SWAP_VALUE,
                "tx_hash": "dd" * 32,
                "block_height": 5,
            }
        ]
        ci = make_xmr_interface(transfers, daemon_height=90, target_height=100)
        found = self.find_tx_b(ci)
        self.assertEqual(found["txid"], "dd" * 32)


if __name__ == "__main__":
    unittest.main()
