# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for the key half recovered from a counterparty's on-chain witness.

recoverEncKey derives the other side's scriptless spend key half from a
signature extracted out of a transaction they published. Every other branch that
obtains a key half from external data checks it against the pubkey agreed during
the bid; these two did not, so a bad recovery produced a wrong summed key and an
unexplained chain B spend failure instead of an error naming the cause.
"""

import unittest
from types import SimpleNamespace

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import BidStates, TxTypes
from basicswap.chainparams import Coins

BID_ID = b"b" * 28
PKBSL = b"\x0a" * 32
PKBSF = b"\x0f" * 32
GOOD_KEY = b"\x01" * 32
WRONG_KEY = b"\x02" * 32


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
    sc.debug = False
    sc.is_reverse_ads_bid = lambda cf, ct: False
    sc.isBchXmrSwap = lambda offer: False
    sc.logIDT = lambda t: str(t)
    sc.createActionInSession = lambda *args, **kwargs: None
    sc.get_delay_retry_seconds = lambda: 1
    return sc


def make_interfaces(recovered_key):
    """ci_from recovers the key half, ci_to maps it back to a pubkey."""
    pubkeys = {GOOD_KEY: PKBSL, WRONG_KEY: b"\xff" * 32}

    ci_from = SimpleNamespace(
        extractFollowerSig=lambda tx: b"sig",
        extractLeaderSig=lambda tx: b"sig",
        recoverEncKey=lambda esig, sig, K: recovered_key,
    )
    ci_to = SimpleNamespace(
        curve_type=lambda: None,
        getPubkey=lambda k: pubkeys[k],
        getChainHeight=lambda: 1000,
        depth_spendable=lambda: 10,
        sumKeys=lambda a, b: b"\x00" * 32,
    )
    return ci_from, ci_to


def make_bid_and_swap():
    bid = SimpleNamespace(
        bid_id=BID_ID,
        offer_id=b"offer",
        state=BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED,
        created_at=0,
        was_sent=True,
        was_received=False,
        txns={},
        xmr_b_lock_tx=SimpleNamespace(chain_height=100, spend_txid=None),
    )
    xmr_swap = SimpleNamespace(
        contract_count=0,
        pkbsl=PKBSL,
        pkbsf=PKBSF,
        pkasl=b"\x03" * 33,
        pkasf=b"\x04" * 33,
        a_lock_spend_tx=b"tx",
        a_lock_refund_spend_tx=b"tx",
        al_lock_spend_tx_esig=b"esig",
        af_lock_refund_spend_tx_esig=b"esig",
    )
    return bid, xmr_swap


class TestRecoveredKeyshareCheck(unittest.TestCase):
    def make_client(self, recovered_key):
        sc = base_swap_client()
        bid, xmr_swap = make_bid_and_swap()
        offer = SimpleNamespace(
            coin_from=int(Coins.BTC),
            coin_to=int(Coins.XMR),
            offer_id=b"offer",
            bid_reversed=False,
        )
        xmr_offer = SimpleNamespace(a_fee_rate=1000, b_fee_rate=1000)
        ci_from, ci_to = make_interfaces(recovered_key)

        sc.getXmrBidFromSession = lambda cursor, bid_id: (bid, xmr_swap)
        sc.getXmrOfferFromSession = lambda cursor, offer_id: (offer, xmr_offer)
        sc.ci = lambda coin: ci_to if coin == int(Coins.XMR) else ci_from
        sc.getPathKey = lambda *args, **kwargs: GOOD_KEY
        return sc

    def test_follower_refund_rejects_wrong_key(self):
        sc = self.make_client(WRONG_KEY)
        with self.assertRaises(ValueError) as e:
            sc.recoverXmrBidCoinBLockTx(BID_ID, object())
        self.assertIn("does not match expected pubkey", str(e.exception))

    def test_follower_refund_accepts_recovered_key(self):
        sc = self.make_client(GOOD_KEY)
        sentinel = RuntimeError("reached the chain B spend")
        _, ci_to = make_interfaces(GOOD_KEY)

        def past_the_check(a, b):
            raise sentinel

        ci_to.sumKeys = past_the_check
        sc.ci = lambda coin: (
            ci_to if coin == int(Coins.XMR) else make_interfaces(GOOD_KEY)[0]
        )

        with self.assertRaises(RuntimeError):
            sc.recoverXmrBidCoinBLockTx(BID_ID, object())


class TestRecoveredKeyshareCheckLeader(unittest.TestCase):
    """The leader's redeem path catches the error and errors the bid with it."""

    def make_client(self, recovered_key):
        sc = base_swap_client()
        bid, xmr_swap = make_bid_and_swap()
        xmr_swap.pkbsf = PKBSL  # ci_to.getPubkey maps GOOD_KEY to PKBSL
        offer = SimpleNamespace(
            coin_from=int(Coins.BTC),
            coin_to=int(Coins.XMR),
            offer_id=b"offer",
            bid_reversed=False,
        )
        xmr_offer = SimpleNamespace(a_fee_rate=1000, b_fee_rate=1000)
        ci_from, ci_to = make_interfaces(recovered_key)
        ci_to.is_transient_error = lambda ex: False

        sc.getXmrBidFromSession = lambda cursor, bid_id: (bid, xmr_swap)
        sc.getXmrOfferFromSession = lambda cursor, offer_id: (offer, xmr_offer)
        sc.ci = lambda coin: ci_to if coin == int(Coins.XMR) else ci_from
        sc.getPathKey = lambda *args, **kwargs: GOOD_KEY
        sc.countBidEvents = lambda bid, event, cursor: 0
        sc.is_transient_error = lambda ex: False
        sc._max_transient_errors = 3
        sc.bid_errors = []
        sc.setBidError = lambda bid, msg, save_bid=True, xmr_swap=None, cursor=None: sc.bid_errors.append(
            msg
        )
        sc.saveBidInSession = lambda *args, **kwargs: None
        sc.logBidEvent = lambda *args, **kwargs: None
        return sc, bid

    def test_redeem_errors_bid_on_wrong_key(self):
        sc, bid = self.make_client(WRONG_KEY)
        self.assertNotIn(TxTypes.MERCY, bid.txns)

        sc.redeemXmrBidCoinBLockTx(BID_ID, object())

        self.assertEqual(len(sc.bid_errors), 1)
        self.assertIn("does not match expected pubkey", sc.bid_errors[0])


if __name__ == "__main__":
    unittest.main()
