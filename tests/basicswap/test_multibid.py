#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import unittest

from types import SimpleNamespace

from basicswap.basicswap_util import SwapTypes
from basicswap.bidplanner import (
    AUTO_ACCEPT_ANY,
    AUTO_ACCEPT_NONE,
    FILL_RECEIVE,
    FILL_SPEND,
    REASON_FEE_TOO_HIGH,
    REASON_MIN_TOO_HIGH,
    REASON_NO_AUTO_ACCEPT,
    REASON_NOT_NEEDED,
    REASON_NOT_PICKED,
    REASON_OVER_LIMIT,
    REASON_OWN,
)
from basicswap.chainparams import Coins
from basicswap.js_server import js_bids_bulk
from basicswap.multibid import (
    ANCHOR_BEST,
    ANCHOR_MARKET,
    PLAN_ID_LENGTH,
    describePlan,
    placeMultiBid,
    planMultiBid,
)
from basicswap.util import format_amount, make_int

EXP = {Coins.XMR: 12, Coins.LTC: 8, Coins.BTC: 8}


def units(v: float, coin_type) -> int:
    return make_int(v, EXP[coin_type])


def xmr(v: float) -> int:
    return units(v, Coins.XMR)


def ltc(v: float) -> int:
    return units(v, Coins.LTC)


def exclusions(plan):
    return [(entry.offer_id, entry.reason) for entry in plan.excluded]


class FakeCI:
    def __init__(self, coin_type, name: str, balance: int = 0, fee_rate: float = 0.0):
        self._coin_type = coin_type
        self._exp = EXP[coin_type]
        self._name = name
        self._balance = balance
        self._fee_rate = fee_rate

    def max_batched_lock_outputs(self):
        return 15 if self._coin_type == Coins.XMR else None

    def xmr_swap_a_lock_spend_tx_vsize(self) -> int:
        # Monero is never the scripted leader, matching the real interface.
        if self._coin_type == Coins.XMR:
            raise ValueError("Not possible")
        return 100

    def xmr_swap_b_lock_spend_tx_vsize(self) -> int:
        return 100

    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        return 100

    def get_fee_rate(self, conf_target: int = 2):
        return self._fee_rate, "fake"

    def COIN(self) -> int:
        return 10**self._exp

    def exp(self) -> int:
        return self._exp

    def make_int(self, v, r: int = 0) -> int:
        return make_int(v, self._exp, r=r)

    def format_amount(self, v, conv_int: bool = False, r: int = 0) -> str:
        return format_amount(v, self._exp)

    def coin_name(self) -> str:
        return self._name

    def getSpendableBalance(self) -> int:
        return self._balance


class FakeOffer:
    """An offer amount is scaled by coin_from, but its rate is scaled by coin_to."""

    def __init__(
        self,
        offer_id: bytes,
        amount_from: float,
        rate: float,
        coin_from=Coins.XMR,
        coin_to=Coins.LTC,
        amount_negotiable: bool = True,
        min_bid_amount: float = 0.0,
        auto_accept_type: int = AUTO_ACCEPT_ANY,
        swap_type=SwapTypes.XMR_SWAP,
        a_fee_rate: int = 0,
        b_fee_rate: int = 0,
    ):
        self.offer_id = offer_id
        self.coin_from = coin_from
        self.coin_to = coin_to
        self.amount_from = units(amount_from, coin_from)
        self.rate = units(rate, coin_to)
        self.amount_negotiable = amount_negotiable
        self.min_bid_amount = units(min_bid_amount, coin_from)
        self.auto_accept_type = auto_accept_type
        self.swap_type = swap_type
        self.a_fee_rate = a_fee_rate
        self.b_fee_rate = b_fee_rate
        self.active_ind = 1
        self.was_sent = False
        self.expire_at = 2_000_000_000


class FakeSwapClient:
    def __init__(
        self, offers=(), market_rate=None, balance: int = 10**12, fee_rate=0.0
    ):
        self.offers = list(offers)
        self.market_rate = market_rate
        self.log = logging.getLogger("fake")
        self.list_filters = None
        self.posted = []
        self.bid_plans = {}
        self.kv = {}
        self.fail_offers = set()
        self._cis = {
            Coins.XMR: FakeCI(Coins.XMR, "Monero", balance=balance, fee_rate=fee_rate),
            Coins.LTC: FakeCI(
                Coins.LTC, "Litecoin", balance=balance, fee_rate=fee_rate
            ),
            Coins.BTC: FakeCI(Coins.BTC, "Bitcoin", balance=balance, fee_rate=fee_rate),
        }

    def getXmrOffer(self, offer_id: bytes, cursor=None):
        offer = self.getOffer(offer_id)
        if not offer:
            return None, None
        xmr_offer = (
            SimpleNamespace(a_fee_rate=offer.a_fee_rate, b_fee_rate=offer.b_fee_rate)
            if offer.swap_type == SwapTypes.XMR_SWAP
            else None
        )
        return offer, xmr_offer

    def is_reverse_ads_bid(self, coin_from, coin_to) -> bool:
        # Monero is the scriptless coin, so buying it is a reverse bid.
        return Coins(int(coin_from)) == Coins.XMR

    def ci(self, coin_type):
        return self._cis[Coins(int(coin_type))]

    def getTime(self) -> int:
        return 1000

    def listOffers(self, sent: bool = False, filters={}):
        self.list_filters = filters
        return [
            o
            for o in self.offers
            if int(o.coin_from) == filters["coin_from"]
            and int(o.coin_to) == filters["coin_to"]
        ]

    def lookupRates(self, coin_from, coin_to):
        if self.market_rate is None:
            raise ValueError("coingecko unavailable")
        return {
            "coingecko": {
                "rate_inferred": format_amount(self.market_rate, EXP[Coins(coin_to)])
            }
        }

    def getOffer(self, offer_id: bytes):
        for o in self.offers:
            if o.offer_id == offer_id:
                return o
        return None

    def validateBidAmount(self, offer, bid_amount: int, bid_rate: int) -> None:
        if bid_amount < offer.min_bid_amount:
            raise ValueError("Bid amount below minimum")
        if bid_amount > offer.amount_from:
            raise ValueError("Bid amount above offer amount")
        if not offer.amount_negotiable and bid_amount != offer.amount_from:
            raise ValueError("Bid amount must match offer amount.")

    def setBidPlan(self, bid_id: bytes, plan_id: bytes) -> None:
        self.bid_plans[bid_id] = plan_id

    def setStringKV(self, key: str, value: str) -> None:
        self.kv[key] = value

    def getStringKV(self, key: str):
        return self.kv.get(key)

    def postBid(self, offer_id, amount, addr_send_from=None, extra_options={}):
        return self._post("postBid", offer_id, amount)

    def postXmrBid(self, offer_id, amount, addr_send_from=None, extra_options={}):
        return self._post("postXmrBid", offer_id, amount)

    def _post(self, method: str, offer_id: bytes, amount: int) -> bytes:
        if offer_id in self.fail_offers:
            raise ValueError("Offer no longer available")
        self.posted.append((method, offer_id, amount))
        return bytes((len(self.posted),)) * 28


class TestPlanMultiBid(unittest.TestCase):

    def book(self):
        return [
            FakeOffer(b"A", 4, 0.42, min_bid_amount=0.1),
            FakeOffer(b"B", 9, 0.43, amount_negotiable=False),
            FakeOffer(b"C", 5, 0.45, min_bid_amount=0.1),
        ]

    def test_plans_against_the_requested_pair_only(self):
        swap_client = FakeSwapClient(self.book(), market_rate=ltc(0.43))
        plan, market_rate, limit_rate = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(10)
        )

        self.assertEqual(
            swap_client.list_filters,
            {
                "coin_from": int(Coins.XMR),
                "coin_to": int(Coins.LTC),
                "include_sent": False,
            },
        )
        self.assertEqual(market_rate, ltc(0.43))
        self.assertEqual(plan.total_receive, xmr(10))
        self.assertEqual(
            [(leg.offer_id, leg.amount) for leg in plan.legs],
            [(b"A", xmr(1)), (b"B", xmr(9))],
        )

    def test_skips_offers_too_small_for_the_redeem_fee(self):
        # floor = 20 * 5e8 * 100 // 1000 = 0.001 XMR; DUST is below it.
        book = [
            FakeOffer(b"BIG", 4, 0.42, min_bid_amount=0.1, b_fee_rate=500_000_000),
            FakeOffer(b"DUST", 0.0001, 0.42, b_fee_rate=500_000_000),
        ]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(4)
        )

        self.assertIn((b"DUST", REASON_FEE_TOO_HIGH), exclusions(plan))
        self.assertEqual([leg.offer_id for leg in plan.legs], [b"BIG"])

    def test_a_big_offer_is_not_bid_below_its_redeem_floor(self):
        # BIG could fill 1, but the target is under its 0.001 redeem floor, so
        # taking that sliver would be mostly fee - leave it unused, unfilled.
        book = [FakeOffer(b"BIG", 1, 0.42, b_fee_rate=500_000_000)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(0.0005)
        )

        self.assertEqual(plan.legs, [])
        self.assertEqual(plan.unfilled, xmr(0.0005))

    def test_secret_hash_offers_use_the_live_redeem_fee(self):
        # No stored rate, so the floor comes from the live fee rate: 20 * 5e4 *
        # 100 // 1000 = 0.001 BTC; the dust HTLC offer is below it.
        common = dict(
            coin_from=Coins.BTC,
            coin_to=Coins.LTC,
            swap_type=SwapTypes.SELLER_FIRST,
        )
        book = [
            FakeOffer(b"BIG", 4, 0.42, min_bid_amount=0.1, **common),
            FakeOffer(b"DUST", 0.0001, 0.42, **common),
        ]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43), fee_rate=0.0005)

        plan, _, _ = planMultiBid(
            swap_client, Coins.BTC, Coins.LTC, FILL_RECEIVE, units(4, Coins.BTC)
        )

        self.assertIn((b"DUST", REASON_FEE_TOO_HIGH), exclusions(plan))
        self.assertEqual([leg.offer_id for leg in plan.legs], [b"BIG"])

    def test_normal_bid_uses_the_stored_leader_fee(self):
        # Buying a scripted coin redeems the coin A lock at the offer's a_fee_rate
        # (b_fee_rate is left unset), so a leg too small to clear it is skipped.
        common = dict(coin_from=Coins.LTC, coin_to=Coins.XMR)
        book = [
            FakeOffer(
                b"BIG", 4, 2.0, min_bid_amount=0.1, a_fee_rate=5_000_000, **common
            ),
            FakeOffer(b"DUST", 0.0001, 2.0, a_fee_rate=5_000_000, **common),
        ]
        swap_client = FakeSwapClient(book, market_rate=xmr(2.0))

        plan, _, _ = planMultiBid(
            swap_client, Coins.LTC, Coins.XMR, FILL_RECEIVE, ltc(4)
        )

        self.assertIn((b"DUST", REASON_FEE_TOO_HIGH), exclusions(plan))
        self.assertEqual([leg.offer_id for leg in plan.legs], [b"BIG"])

    def test_does_not_split_across_equal_rate_offers(self):
        # Three offers at one rate, the first big enough for the whole buy;
        # splitting would only add redeem fees, so expect a single leg.
        book = [
            FakeOffer(o, 5, 0.42, min_bid_amount=0.1, b_fee_rate=100_000_000)
            for o in (b"A", b"B", b"C")
        ]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(3)
        )

        self.assertEqual(len(plan.legs), 1)
        self.assertEqual(plan.total_receive - plan.fees, xmr(3))

    def test_receive_mode_grosses_up_for_the_redeem_fee(self):
        # fee = 1e8 * 100 // 1000 = 1e7 per leg, deducted when the leg is
        # redeemed, so buy that much extra to net the requested target.
        book = [FakeOffer(b"A", 4, 0.42, min_bid_amount=0.1, b_fee_rate=100_000_000)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(1)
        )

        self.assertEqual(plan.fees, 10_000_000)
        self.assertEqual(plan.legs[0].amount, xmr(1) + 10_000_000)
        self.assertEqual(plan.total_receive, xmr(1) + 10_000_000)

    def test_receive_mode_grosses_up_across_every_leg(self):
        # Two legs are needed to fill, so the gross-up covers both redeem fees.
        book = [
            FakeOffer(b"A", 1, 0.42, amount_negotiable=False, b_fee_rate=100_000_000),
            FakeOffer(b"B", 4, 0.43, min_bid_amount=0.1, b_fee_rate=100_000_000),
        ]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(3)
        )

        self.assertEqual(len(plan.legs), 2)
        self.assertEqual(plan.fees, 20_000_000)
        self.assertEqual(plan.total_receive, xmr(3) + 20_000_000)

    def test_spend_mode_takes_the_redeem_fee_out_of_what_is_received(self):
        # Spending a fixed budget, the redeem fee is not added to the target but
        # still comes out of the received amount, so it is reported net.
        book = [FakeOffer(b"A", 4, 0.42, min_bid_amount=0.1, b_fee_rate=100_000_000)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_SPEND, ltc(0.42)
        )

        self.assertEqual(plan.fees, 10_000_000)
        self.assertEqual(plan.total_receive - plan.fees, xmr(1) - 10_000_000)

    def test_a_picked_dust_offer_is_still_bid_on(self):
        book = [FakeOffer(b"DUST", 0.0001, 0.42, b_fee_rate=500_000_000)]
        swap_client = FakeSwapClient(book)

        plan, _, _ = planMultiBid(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            xmr(0.0001),
            manual_offers=[b"DUST"],
        )

        self.assertEqual([leg.offer_id for leg in plan.legs], [b"DUST"])

    def test_market_anchor_excludes_offers_above_the_limit(self):
        # Limit is 0.43 * 1.05 = 0.4515, so C at 0.45 stays and a 0.46 is cut.
        book = self.book() + [FakeOffer(b"D", 20, 0.46, min_bid_amount=0.1)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, limit_rate = planMultiBid(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            xmr(30),
            anchor=ANCHOR_MARKET,
            slip_percent=5.0,
        )

        self.assertEqual(limit_rate, ltc(0.4515))
        self.assertNotIn(b"D", [leg.offer_id for leg in plan.legs])
        self.assertEqual(plan.total_receive, xmr(18))
        self.assertEqual(plan.unfilled, xmr(12))

    def test_best_anchor_slips_from_the_cheapest_offer(self):
        swap_client = FakeSwapClient(self.book(), market_rate=ltc(0.43))

        plan, _, limit_rate = planMultiBid(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            xmr(20),
            anchor=ANCHOR_BEST,
            slip_percent=5.0,
        )

        # Cheapest is A at 0.42, so the limit is 0.441 and C at 0.45 is cut.
        self.assertEqual(limit_rate, ltc(0.441))
        self.assertEqual(sorted(leg.offer_id for leg in plan.legs), [b"A", b"B"])

    def test_market_anchor_refuses_to_plan_without_a_market_rate(self):
        swap_client = FakeSwapClient(self.book(), market_rate=None)

        with self.assertRaises(ValueError) as e:
            planMultiBid(
                swap_client,
                Coins.XMR,
                Coins.LTC,
                FILL_RECEIVE,
                xmr(10),
                anchor=ANCHOR_MARKET,
            )
        self.assertIn("Market rate unavailable", str(e.exception))

    def test_best_anchor_still_works_without_a_market_rate(self):
        swap_client = FakeSwapClient(self.book(), market_rate=None)

        plan, market_rate, limit_rate = planMultiBid(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            xmr(10),
            anchor=ANCHOR_BEST,
        )

        self.assertIsNone(market_rate)
        self.assertEqual(plan.total_receive, xmr(10))

    def test_skips_offers_without_auto_accept(self):
        book = [
            FakeOffer(b"cheap", 10, 0.40, auto_accept_type=AUTO_ACCEPT_NONE),
            FakeOffer(b"auto", 10, 0.50, min_bid_amount=0.1),
        ]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.50))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(5)
        )

        self.assertEqual([leg.offer_id for leg in plan.legs], [b"auto"])

    def test_rejects_a_same_coin_pair(self):
        with self.assertRaises(ValueError):
            planMultiBid(FakeSwapClient(), Coins.XMR, Coins.XMR, FILL_RECEIVE, xmr(1))

    def own_book(self):
        mine = FakeOffer(b"mine", 10, 0.40, min_bid_amount=0.1)
        mine.was_sent = True
        return [mine] + self.book()

    def test_own_offers_are_skipped(self):
        swap_client = FakeSwapClient(self.own_book(), market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(4)
        )

        self.assertFalse(swap_client.list_filters["include_sent"])
        self.assertNotIn(b"mine", [leg.offer_id for leg in plan.legs])
        self.assertIn((b"mine", REASON_OWN), exclusions(plan))

    def test_own_offers_can_be_bid_on(self):
        swap_client = FakeSwapClient(self.own_book(), market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            xmr(4),
            allow_self_bids=True,
        )

        self.assertTrue(swap_client.list_filters["include_sent"])
        # The cheapest of the book, so the whole fill comes from it.
        self.assertEqual(
            [(leg.offer_id, leg.amount) for leg in plan.legs], [(b"mine", xmr(4))]
        )
        self.assertNotIn(b"mine", [offer_id for offer_id, _ in exclusions(plan)])

    def test_a_picked_offer_is_bid_on_whatever_its_rate(self):
        dear = FakeOffer(b"dear", 20, 0.46, min_bid_amount=0.1)
        dear.was_sent = True
        swap_client = FakeSwapClient(self.book() + [dear], market_rate=ltc(0.43))

        plan, _, limit_rate = planMultiBid(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            xmr(4),
            manual_offers=[b"dear"],
        )

        self.assertTrue(swap_client.list_filters["include_sent"])
        self.assertIsNone(limit_rate)
        self.assertEqual(
            [(leg.offer_id, leg.amount) for leg in plan.legs], [(b"dear", xmr(4))]
        )
        self.assertEqual(
            exclusions(plan),
            [
                (b"A", REASON_NOT_PICKED),
                (b"B", REASON_NOT_PICKED),
                (b"C", REASON_NOT_PICKED),
            ],
        )

    def test_reports_why_each_offer_was_passed_over(self):
        book = self.book() + [
            FakeOffer(b"dear", 20, 0.46, min_bid_amount=0.1),
            FakeOffer(b"manual", 20, 0.42, auto_accept_type=AUTO_ACCEPT_NONE),
        ]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        # A takes the whole 4, leaving C unused; B is fixed at 9, above the request.
        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(4)
        )

        self.assertEqual([leg.offer_id for leg in plan.legs], [b"A"])
        self.assertEqual(
            exclusions(plan),
            [
                (b"manual", REASON_NO_AUTO_ACCEPT),
                (b"B", REASON_MIN_TOO_HIGH),
                (b"C", REASON_NOT_NEEDED),
                (b"dear", REASON_OVER_LIMIT),
            ],
        )

    def test_reports_a_minimum_above_the_requested_amount(self):
        book = self.book() + [FakeOffer(b"chunky", 20, 0.40, min_bid_amount=10)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(4)
        )

        self.assertEqual([leg.offer_id for leg in plan.legs], [b"A"])
        self.assertIn((b"chunky", REASON_MIN_TOO_HIGH), exclusions(plan))

    def test_reports_a_minimum_above_what_the_spend_buys(self):
        book = self.book() + [FakeOffer(b"chunky", 20, 0.40, min_bid_amount=10)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.43))

        plan, _, _ = planMultiBid(swap_client, Coins.XMR, Coins.LTC, FILL_SPEND, ltc(1))

        self.assertIn((b"chunky", REASON_MIN_TOO_HIGH), exclusions(plan))


class TestRateScale(unittest.TestCase):
    """A rate is scaled by coin_to, so a pair whose coins differ in exponent
    (Monero has 12 places, Litecoin 8) catches a rate built to the wrong scale."""

    def test_plans_the_reverse_direction(self):
        # Buying Litecoin and paying Monero: coin_to now carries the larger
        # exponent. A market rate built against coin_from lands 10^4 too low
        # here, putting the limit under every offer and emptying the book.
        book = [FakeOffer(b"A", 10, 3.0, coin_from=Coins.LTC, coin_to=Coins.XMR)]
        swap_client = FakeSwapClient(book, market_rate=xmr(3.0))

        plan, market_rate, limit_rate = planMultiBid(
            swap_client, Coins.LTC, Coins.XMR, FILL_RECEIVE, ltc(2)
        )

        self.assertEqual(market_rate, xmr(3.0))
        self.assertEqual(limit_rate, xmr(3.15))
        self.assertEqual(plan.num_bids, 1)
        self.assertEqual(plan.total_receive, ltc(2))
        self.assertEqual(plan.total_spend, xmr(6))
        self.assertEqual(plan.unfilled, 0)

    def test_reports_the_rate_against_market_at_par(self):
        book = [FakeOffer(b"A", 10, 3.0, coin_from=Coins.LTC, coin_to=Coins.XMR)]
        swap_client = FakeSwapClient(book, market_rate=xmr(3.0))

        plan, market_rate, limit_rate = planMultiBid(
            swap_client, Coins.LTC, Coins.XMR, FILL_RECEIVE, ltc(2)
        )
        described = describePlan(
            swap_client,
            Coins.LTC,
            Coins.XMR,
            FILL_RECEIVE,
            plan,
            market_rate,
            limit_rate,
        )

        self.assertEqual(described["pct_vs_market"], 0.0)
        self.assertEqual(described["avg_rate"], "3.000000000000")
        self.assertEqual(described["market_rate"], "3.000000000000")
        self.assertEqual(described["total_receive"], "2.00000000")
        self.assertEqual(described["total_spend"], "6.000000000000")


class TestPlaceMultiBid(unittest.TestCase):

    def legs(self, swap_client):
        return [
            {"offer_id": b"A", "amount": xmr(1)},
            {"offer_id": b"B", "amount": xmr(9)},
        ]

    def book(self):
        return [
            FakeOffer(b"A", 4, 0.42, min_bid_amount=0.1),
            FakeOffer(b"B", 9, 0.43, amount_negotiable=False),
        ]

    def test_places_every_leg(self):
        swap_client = FakeSwapClient(self.book())

        placed, failed, _ = placeMultiBid(swap_client, self.legs(swap_client))

        self.assertEqual(len(placed), 2)
        self.assertEqual(failed, [])
        self.assertEqual(
            [(m, o) for m, o, _ in swap_client.posted],
            [("postXmrBid", b"A"), ("postXmrBid", b"B")],
        )

    def test_marks_every_placed_bid_with_the_one_plan(self):
        swap_client = FakeSwapClient(self.book())

        placed, _, plan_id = placeMultiBid(swap_client, self.legs(swap_client))

        self.assertEqual(len(plan_id), PLAN_ID_LENGTH)
        self.assertEqual(
            swap_client.bid_plans,
            {bytes.fromhex(bid["bid_id"]): plan_id for bid in placed},
        )

    def test_a_failed_leg_is_not_marked(self):
        swap_client = FakeSwapClient(self.book())
        swap_client.fail_offers.add(b"B")

        placed, failed, plan_id = placeMultiBid(swap_client, self.legs(swap_client))

        self.assertEqual(len(placed), 1)
        self.assertEqual(len(failed), 1)
        self.assertEqual(
            list(swap_client.bid_plans.values()),
            [plan_id],
        )

    def test_a_plan_is_not_shared_between_buys(self):
        swap_client = FakeSwapClient(self.book())

        _, _, first = placeMultiBid(swap_client, self.legs(swap_client))
        _, _, second = placeMultiBid(swap_client, self.legs(swap_client))

        self.assertNotEqual(first, second)

    def test_a_retry_reuses_the_given_plan(self):
        swap_client = FakeSwapClient(self.book())
        original = b"\x11" * PLAN_ID_LENGTH

        placed, _, plan_id = placeMultiBid(
            swap_client, self.legs(swap_client), plan_id=original
        )

        self.assertEqual(plan_id, original)
        self.assertEqual(
            swap_client.bid_plans,
            {bytes.fromhex(bid["bid_id"]): original for bid in placed},
        )

    def test_a_new_plan_stores_its_requested_target(self):
        swap_client = FakeSwapClient(self.book())

        _, _, plan_id = placeMultiBid(swap_client, self.legs(swap_client))

        self.assertEqual(
            swap_client.kv[f"plan_target:{plan_id.hex()}"],
            str(xmr(1) + xmr(9)),
        )

    def test_a_retry_does_not_overwrite_the_target(self):
        swap_client = FakeSwapClient(self.book())
        original = b"\x22" * PLAN_ID_LENGTH
        swap_client.kv[f"plan_target:{original.hex()}"] = str(xmr(10))

        placeMultiBid(swap_client, self.legs(swap_client), plan_id=original)

        self.assertEqual(
            swap_client.kv[f"plan_target:{original.hex()}"],
            str(xmr(10)),
        )

    def test_rejects_more_bids_than_the_spend_coin_can_batch(self):
        # Paying XMR caps a plan at 15 bids: one Monero tx holds 16 outputs.
        offers = [
            FakeOffer(bytes((i,)) * 28, 1, 0.5, coin_from=Coins.LTC, coin_to=Coins.XMR)
            for i in range(16)
        ]
        legs = [{"offer_id": o.offer_id, "amount": ltc(0.1)} for o in offers]
        swap_client = FakeSwapClient(offers)

        with self.assertRaises(ValueError) as e:
            placeMultiBid(swap_client, legs)
        self.assertIn("at most 15", str(e.exception))
        self.assertEqual(swap_client.posted, [])

    def test_allows_many_bids_when_the_spend_coin_is_unbounded(self):
        # Paying LTC has no per-tx output cap, so a large plan is fine.
        offers = [
            FakeOffer(bytes((i,)) * 28, 1, 0.5, coin_from=Coins.XMR, coin_to=Coins.LTC)
            for i in range(16)
        ]
        legs = [{"offer_id": o.offer_id, "amount": xmr(0.1)} for o in offers]
        swap_client = FakeSwapClient(offers)

        placed, failed, _ = placeMultiBid(swap_client, legs)
        self.assertEqual(len(placed), 16)
        self.assertEqual(failed, [])

    def test_routes_non_xmr_offers_to_postbid(self):
        book = [
            FakeOffer(
                b"A", 4, 0.42, min_bid_amount=0.1, swap_type=SwapTypes.SELLER_FIRST
            )
        ]
        swap_client = FakeSwapClient(book)

        placeMultiBid(swap_client, [{"offer_id": b"A", "amount": xmr(1)}])

        self.assertEqual(swap_client.posted[0][0], "postBid")

    def test_blocks_the_whole_plan_when_the_balance_is_short(self):
        # 1 @ 0.42 + 9 @ 0.43 = 4.29 LTC needed.
        swap_client = FakeSwapClient(self.book(), balance=ltc(4.28))

        with self.assertRaises(ValueError) as e:
            placeMultiBid(swap_client, self.legs(swap_client))

        self.assertIn("Insufficient Litecoin balance", str(e.exception))
        self.assertEqual(swap_client.posted, [])

    def test_rejects_a_plan_that_spends_the_whole_balance(self):
        # 4.29 LTC needed; a balance of exactly that leaves nothing for the lock fee.
        swap_client = FakeSwapClient(self.book(), balance=ltc(4.29))

        with self.assertRaises(ValueError) as e:
            placeMultiBid(swap_client, self.legs(swap_client))

        self.assertIn("fee reserve", str(e.exception))
        self.assertEqual(swap_client.posted, [])

    def test_places_when_the_balance_covers_the_spend_and_the_reserve(self):
        swap_client = FakeSwapClient(self.book(), balance=ltc(4.30))

        placed, failed, _ = placeMultiBid(swap_client, self.legs(swap_client))

        self.assertEqual(len(placed), 2)
        self.assertEqual(failed, [])

    def test_a_failed_leg_does_not_stop_the_others(self):
        swap_client = FakeSwapClient(self.book())
        swap_client.fail_offers.add(b"A")

        placed, failed, _ = placeMultiBid(swap_client, self.legs(swap_client))

        self.assertEqual([p["offer_id"] for p in placed], [b"B".hex()])
        self.assertEqual([f["offer_id"] for f in failed], [b"A".hex()])
        self.assertIn("no longer available", failed[0]["error"])

    def test_an_invalid_leg_places_nothing(self):
        swap_client = FakeSwapClient(self.book())
        # B is not negotiable, so a partial bid on it can never be accepted.
        legs = [{"offer_id": b"B", "amount": xmr(5)}]

        with self.assertRaises(ValueError):
            placeMultiBid(swap_client, legs)

        self.assertEqual(swap_client.posted, [])

    def test_rejects_duplicate_offers(self):
        swap_client = FakeSwapClient(self.book())
        legs = [
            {"offer_id": b"A", "amount": xmr(1)},
            {"offer_id": b"A", "amount": xmr(1)},
        ]

        with self.assertRaises(ValueError):
            placeMultiBid(swap_client, legs)

    def test_rejects_legs_that_do_not_share_a_coin_to(self):
        book = self.book() + [FakeOffer(b"X", 4, 0.42, coin_to=Coins.BTC)]
        swap_client = FakeSwapClient(book)
        legs = [
            {"offer_id": b"A", "amount": xmr(1)},
            {"offer_id": b"X", "amount": xmr(1)},
        ]

        with self.assertRaises(ValueError):
            placeMultiBid(swap_client, legs)

    def test_rejects_legs_that_do_not_share_a_coin_from(self):
        # Same pay coin, different coin bought: not one plan, and the leg
        # amounts would not share a precision.
        book = self.book() + [FakeOffer(b"X", 4, 0.42, coin_from=Coins.BTC)]
        swap_client = FakeSwapClient(book)
        legs = [
            {"offer_id": b"A", "amount": xmr(1)},
            {"offer_id": b"X", "amount": xmr(1)},
        ]

        with self.assertRaises(ValueError):
            placeMultiBid(swap_client, legs)

    def test_rejects_an_unknown_offer(self):
        swap_client = FakeSwapClient(self.book())

        with self.assertRaises(ValueError):
            placeMultiBid(swap_client, [{"offer_id": b"Z", "amount": xmr(1)}])


class TestJsBidsBulk(unittest.TestCase):
    """The legs arrive as decoded JSON, not as form entries."""

    def setUp(self):
        self.offer_id = bytes(range(28))
        self.swap_client = FakeSwapClient(
            [FakeOffer(self.offer_id, 4, 0.42, min_bid_amount=0.1)]
        )
        self.handler = SimpleNamespace(
            server=SimpleNamespace(swap_client=self.swap_client)
        )

    def call(self, body):
        return json.loads(js_bids_bulk(self.handler, json.dumps(body), True))

    def test_places_a_leg_posted_as_json(self):
        rv = self.call({"legs": [{"offer_id": self.offer_id.hex(), "amount": "1.0"}]})

        self.assertEqual(rv["failed"], [])
        self.assertEqual(
            [(method, offer_id) for method, offer_id, _ in self.swap_client.posted],
            [("postXmrBid", self.offer_id)],
        )
        self.assertEqual(rv["placed"][0]["offer_id"], self.offer_id.hex())
        self.assertEqual(rv["placed"][0]["amount"], "1.000000000000")

        bid_id = bytes.fromhex(rv["placed"][0]["bid_id"])
        self.assertEqual(
            self.swap_client.bid_plans[bid_id], bytes.fromhex(rv["plan_id"])
        )

    def test_rejects_a_leg_missing_its_amount(self):
        with self.assertRaises(ValueError):
            self.call({"legs": [{"offer_id": self.offer_id.hex()}]})


class TestDescribePlan(unittest.TestCase):

    def test_reports_the_discount_against_market(self):
        book = [FakeOffer(b"A", 10, 0.40, min_bid_amount=0.1)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.50))

        plan, market_rate, limit_rate = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(10)
        )
        described = describePlan(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            plan,
            market_rate,
            limit_rate,
        )

        self.assertEqual(described["coin_from"], "Monero")
        self.assertEqual(described["coin_to"], "Litecoin")
        self.assertEqual(described["total_receive"], "10.000000000000")
        self.assertEqual(described["total_spend"], "4.00000000")
        self.assertEqual(described["avg_rate"], "0.40000000")
        self.assertEqual(described["legs"][0]["rate"], "0.40000000")
        self.assertEqual(described["pct_vs_market"], -20.0)
        self.assertEqual(described["num_bids"], 1)
        self.assertEqual(described["unfilled"], "0.000000000000")

    def test_reports_the_fees_and_the_net_received(self):
        book = [FakeOffer(b"A", 4, 0.40, min_bid_amount=0.1, b_fee_rate=100_000_000)]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.40))

        plan, market_rate, limit_rate = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(1)
        )
        described = describePlan(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            plan,
            market_rate,
            limit_rate,
        )

        self.assertEqual(described["fees"], "0.000010000000")
        self.assertEqual(described["net_receive"], "1.000000000000")
        self.assertEqual(described["total_receive"], "1.000010000000")

    def test_describes_a_skipped_offer_at_its_own_size(self):
        book = [
            FakeOffer(b"A", 10, 0.40, min_bid_amount=0.1),
            FakeOffer(b"dear", 20, 0.60, min_bid_amount=0.1),
        ]
        swap_client = FakeSwapClient(book, market_rate=ltc(0.40))

        plan, market_rate, limit_rate = planMultiBid(
            swap_client, Coins.XMR, Coins.LTC, FILL_RECEIVE, xmr(10)
        )
        described = describePlan(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            plan,
            market_rate,
            limit_rate,
        )

        # Cost is the whole offer at its rate, as none of it is being taken.
        self.assertEqual(
            described["excluded"],
            [
                {
                    "offer_id": b"dear".hex(),
                    "amount": "20.000000000000",
                    "rate": "0.60000000",
                    "cost": "12.00000000",
                    "reason": REASON_OVER_LIMIT,
                    "own": False,
                }
            ],
        )

    def test_marks_which_offers_are_your_own(self):
        mine = FakeOffer(b"mine", 10, 0.42, min_bid_amount=0.1)
        mine.was_sent = True
        swap_client = FakeSwapClient(
            [FakeOffer(b"A", 10, 0.40, min_bid_amount=0.1), mine],
            market_rate=ltc(0.43),
        )

        plan, market_rate, limit_rate = planMultiBid(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            xmr(15),
            allow_self_bids=True,
        )
        described = describePlan(
            swap_client,
            Coins.XMR,
            Coins.LTC,
            FILL_RECEIVE,
            plan,
            market_rate,
            limit_rate,
        )

        self.assertEqual(
            {leg["offer_id"]: leg["own"] for leg in described["legs"]},
            {b"A".hex(): False, b"mine".hex(): True},
        )


if __name__ == "__main__":
    unittest.main()
