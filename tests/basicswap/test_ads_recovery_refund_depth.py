# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for adaptor-sig swap lock refund tx monitoring:
refund tx depth must be re-queried after confirmation so a chain reorg
is detected instead of trusting the cached TX_CONFIRMED state.
"""

import unittest
from types import SimpleNamespace

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import (
    BidStates,
    DebugTypes,
    EventLogTypes,
    TxStates,
    TxTypes,
)
from basicswap.chainparams import Coins

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
    return sc


def make_offer():
    return SimpleNamespace(
        coin_from=int(Coins.BTC),
        coin_to=int(Coins.PART),
        offer_id=b"offer",
        swap_type=None,
    )


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


class TestAdsRecoveryRefundDepth(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
