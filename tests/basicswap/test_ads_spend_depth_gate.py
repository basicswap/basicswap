# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from types import SimpleNamespace

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import BidStates
from basicswap.chainparams import Coins

SPEND_TXID = bytes.fromhex("aa" * 32)
LOCK_TXID = bytes.fromhex("bb" * 32)


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
    def __init__(self):
        self.spend_txid = None
        self.states = []

    def setState(self, state):
        self.states.append(state)


class StubBid:
    def __init__(self, state):
        self.state = state
        self.states_set = []
        self.was_received = False
        self.was_sent = True
        self.offer_id = b"offer"
        self.bid_id = b"bid"
        self.xmr_a_lock_tx = StubTx()

    def setState(self, state):
        self.states_set.append(state)
        self.state = state


class StubCI:
    def __init__(self, spend_depth, blocks_confirmed=2, chain_height=100):
        self._spend_depth = spend_depth
        self.blocks_confirmed = blocks_confirmed
        self._chain_height = chain_height

    def loadTx(self, tx_bytes):
        return SimpleNamespace(vin=[])

    def getChainHeight(self):
        return self._chain_height

    def getTxOutInfo(self, txid, n):
        if self._spend_depth < 1:
            return None
        return {
            "block_height": self._chain_height - (self._spend_depth - 1),
            "block_hash": b"\x00" * 32,
            "block_time": 1000,
        }


def make_swap_client(ci, bid, xmr_swap, wait_for_depth=True):
    sc = BasicSwap.__new__(BasicSwap)
    sc.fp = None
    sc._wait_for_lock_spend_depth = wait_for_depth
    sc.log = StubLog()
    sc.saved = []
    sc.events = []
    sc.notifications = []

    offer = SimpleNamespace(
        coin_from=int(Coins.BTC),
        coin_to=int(Coins.PART),
        offer_id=b"offer",
        swap_type=None,
    )
    xmr_offer = SimpleNamespace()

    sc.openDB = lambda cursor=None: object()
    sc.closeDB = lambda cursor, commit=True: None
    sc.getXmrBidFromSession = lambda cursor, bid_id: (bid, xmr_swap)
    sc.getXmrOfferFromSession = lambda cursor, offer_id: (offer, xmr_offer)
    sc.is_reverse_ads_bid = lambda cf, ct: False
    sc.isBchXmrSwap = lambda offer: False
    sc.ci = lambda coin: ci
    sc.saveBidInSession = (
        lambda bid_id, bid, cursor, xmr_swap, save_in_progress=None: sc.saved.append(
            bid.state
        )
    )
    sc.logBidEvent = lambda bid_id, event, msg, cursor: sc.events.append(event)
    sc.notify = lambda event_type, data: sc.notifications.append(event_type)
    sc.logIDT = lambda t: str(t)
    sc.logException = lambda msg: (_ for _ in ()).throw(AssertionError(msg))
    return sc


def make_xmr_swap():
    return SimpleNamespace(
        a_lock_spend_tx_id=SPEND_TXID,
        a_lock_tx_id=LOCK_TXID,
        a_lock_spend_tx=None,
        a_lock_refund_tx_id=bytes.fromhex("cc" * 32),
    )


class TestAdsSpendDepthGate(unittest.TestCase):
    def test_unconfirmed_spend_does_not_transition(self):
        bid = StubBid(BidStates.XMR_SWAP_LOCK_RELEASED)
        xmr_swap = make_xmr_swap()
        ci = StubCI(spend_depth=0, blocks_confirmed=2)
        sc = make_swap_client(ci, bid, xmr_swap)

        sc.process_XMR_SWAP_A_LOCK_tx_spend(b"bid", SPEND_TXID.hex(), "00")

        self.assertEqual(bid.states_set, [])
        self.assertEqual(bid.state, BidStates.XMR_SWAP_LOCK_RELEASED)
        self.assertEqual(len(sc.saved), 1)
        self.assertEqual(xmr_swap.a_lock_spend_tx, b"\x00")

    def test_shallow_spend_does_not_transition(self):
        bid = StubBid(BidStates.XMR_SWAP_LOCK_RELEASED)
        xmr_swap = make_xmr_swap()
        ci = StubCI(spend_depth=1, blocks_confirmed=2)
        sc = make_swap_client(ci, bid, xmr_swap)

        sc.process_XMR_SWAP_A_LOCK_tx_spend(b"bid", SPEND_TXID.hex(), "00")

        self.assertEqual(bid.states_set, [])
        self.assertEqual(bid.state, BidStates.XMR_SWAP_LOCK_RELEASED)

    def test_confirmed_spend_transitions_sender(self):
        bid = StubBid(BidStates.XMR_SWAP_LOCK_RELEASED)
        xmr_swap = make_xmr_swap()
        ci = StubCI(spend_depth=2, blocks_confirmed=2)
        sc = make_swap_client(ci, bid, xmr_swap)

        sc.process_XMR_SWAP_A_LOCK_tx_spend(b"bid", SPEND_TXID.hex(), "00")

        self.assertIn(BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED, bid.states_set)
        self.assertIn(BidStates.SWAP_COMPLETED, bid.states_set)
        self.assertEqual(len(sc.notifications), 1)

    def test_confirmed_spend_transitions_receiver(self):
        bid = StubBid(BidStates.XMR_SWAP_LOCK_RELEASED)
        bid.was_received = True
        bid.was_sent = False
        xmr_swap = make_xmr_swap()
        ci = StubCI(spend_depth=2, blocks_confirmed=2)
        sc = make_swap_client(ci, bid, xmr_swap)

        sc.process_XMR_SWAP_A_LOCK_tx_spend(b"bid", SPEND_TXID.hex(), "00")

        self.assertIn(BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED, bid.states_set)
        self.assertNotIn(BidStates.SWAP_COMPLETED, bid.states_set)
        self.assertEqual(len(sc.notifications), 0)

    def test_gate_disabled_unconfirmed_spend_transitions(self):
        # Default behavior (option off): transition without waiting for depth.
        bid = StubBid(BidStates.XMR_SWAP_LOCK_RELEASED)
        xmr_swap = make_xmr_swap()
        ci = StubCI(spend_depth=0, blocks_confirmed=2)
        sc = make_swap_client(ci, bid, xmr_swap, wait_for_depth=False)

        sc.process_XMR_SWAP_A_LOCK_tx_spend(b"bid", SPEND_TXID.hex(), "00")

        self.assertIn(BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED, bid.states_set)
        self.assertIn(BidStates.SWAP_COMPLETED, bid.states_set)


if __name__ == "__main__":
    unittest.main()
