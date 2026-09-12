#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import itertools
import random
import unittest

from basicswap.bidplanner import (
    _allocate,
    AUTO_ACCEPT_ANY,
    AUTO_ACCEPT_KNOWN_ONLY,
    AUTO_ACCEPT_NONE,
    Candidate,
    FILL_RECEIVE,
    FILL_SPEND,
    compute_limit_rate,
    plan_fill,
    select_candidates,
)

COIN = 10**8


def coin(v: float) -> int:
    return int(round(v * COIN))


class FakeOffer:
    def __init__(
        self,
        offer_id: bytes,
        amount_from: float,
        rate: float,
        amount_negotiable: bool = True,
        min_bid_amount: float = 0.0,
        auto_accept_type: int = AUTO_ACCEPT_ANY,
        active_ind: int = 1,
        was_sent: bool = False,
        expire_at: int = 2_000_000_000,
    ):
        self.offer_id = offer_id
        self.amount_from = coin(amount_from)
        self.rate = coin(rate)
        self.amount_negotiable = amount_negotiable
        self.min_bid_amount = coin(min_bid_amount)
        self.auto_accept_type = auto_accept_type
        self.active_ind = active_ind
        self.was_sent = was_sent
        self.expire_at = expire_at


def candidate(offer_id: bytes, amount: float, rate: float, min_amount: float = None):
    max_amount = coin(amount)
    return Candidate(
        offer_id=offer_id,
        rate=coin(rate),
        max_amount=max_amount,
        min_amount=max_amount if min_amount is None else coin(min_amount),
    )


def fixed(offer_id: bytes, amount: float, rate: float):
    return candidate(offer_id, amount, rate)


def legs_by_id(plan):
    return {leg.offer_id: leg.amount for leg in plan.legs}


class TestPlanFill(unittest.TestCase):

    def book(self):
        # A cheap flexible offer, a chunky cheap fixed offer, then pricier depth.
        return [
            candidate(b"A", 4, 0.42, min_amount=0.1),
            fixed(b"B", 9, 0.43),
            candidate(b"C", 5, 0.45, min_amount=0.1),
            fixed(b"D", 3, 0.46),
            candidate(b"E", 2, 0.48, min_amount=2),
        ]

    def test_holds_back_cheapest_offer_to_fit_fixed_offer(self):
        # Greedy would take all 4 of A, which makes B overshoot, and settle for
        # 9 XMR via C. Taking only 1 of A fits B exactly: more filled, cheaper.
        plan = plan_fill(self.book(), coin(10), FILL_RECEIVE, scale=COIN)

        self.assertEqual(plan.total_receive, coin(10))
        self.assertEqual(plan.unfilled, 0)
        self.assertEqual(plan.num_bids, 2)
        self.assertEqual(legs_by_id(plan), {b"A": coin(1), b"B": coin(9)})
        self.assertEqual(plan.total_spend, coin(4.29))
        self.assertEqual(plan.avg_rate, coin(0.429))

    def test_beats_the_greedy_fill_on_both_axes(self):
        plan = plan_fill(self.book(), coin(10), FILL_RECEIVE, scale=COIN)

        greedy_receive, greedy_spend = coin(9), coin(3.93)
        self.assertGreater(plan.total_receive, greedy_receive)
        self.assertLess(plan.avg_rate, (greedy_spend * COIN) // greedy_receive)

    def test_never_exceeds_the_target(self):
        plan = plan_fill([fixed(b"X", 9, 0.40)], coin(5), FILL_RECEIVE, scale=COIN)

        self.assertEqual(plan.legs, [])
        self.assertEqual(plan.total_receive, 0)
        self.assertEqual(plan.unfilled, coin(5))

    def test_holds_back_cheapest_offer_to_clear_a_minimum(self):
        book = [
            candidate(b"A", 4, 0.42, min_amount=0.1),
            candidate(b"E", 2, 0.48, min_amount=2),
        ]
        plan = plan_fill(book, coin(5), FILL_RECEIVE, scale=COIN)

        # Taking all 4 of A leaves 1, below E's minimum of 2. Taking 3 fills.
        self.assertEqual(legs_by_id(plan), {b"A": coin(3), b"E": coin(2)})
        self.assertEqual(plan.unfilled, 0)

    def test_never_bids_below_an_offer_minimum(self):
        book = [candidate(b"E", 2, 0.48, min_amount=2)]
        plan = plan_fill(book, coin(1), FILL_RECEIVE, scale=COIN)

        self.assertEqual(plan.legs, [])
        self.assertEqual(plan.unfilled, coin(1))

    def test_reports_the_shortfall_when_the_book_is_thin(self):
        book = [candidate(b"A", 2, 0.42, min_amount=0.1)]
        plan = plan_fill(book, coin(10), FILL_RECEIVE, scale=COIN)

        self.assertEqual(plan.total_receive, coin(2))
        self.assertEqual(plan.unfilled, coin(8))

    def test_max_bids_forces_a_shorter_pricier_plan(self):
        book = [
            candidate(b"A", 3, 0.40, min_amount=0.1),
            candidate(b"B", 3, 0.41, min_amount=0.1),
            candidate(b"C", 3, 0.42, min_amount=0.1),
            candidate(b"D", 10, 0.50, min_amount=0.1),
        ]
        unbounded = plan_fill(book, coin(9), FILL_RECEIVE, scale=COIN)
        self.assertEqual(unbounded.num_bids, 3)
        self.assertEqual(unbounded.total_spend, coin(3.69))

        capped = plan_fill(book, coin(9), FILL_RECEIVE, max_bids=1, scale=COIN)
        self.assertEqual(capped.num_bids, 1)
        self.assertEqual(legs_by_id(capped), {b"D": coin(9)})
        self.assertGreater(capped.total_spend, unbounded.total_spend)

    def test_empty_book(self):
        plan = plan_fill([], coin(10), FILL_RECEIVE, scale=COIN)

        self.assertEqual(plan.legs, [])
        self.assertEqual(plan.unfilled, coin(10))
        self.assertEqual(plan.avg_rate, 0)

    def test_all_fixed_book_subset_sums_to_the_target(self):
        book = [
            fixed(b"A", 7, 0.40),
            fixed(b"B", 6, 0.41),
            fixed(b"C", 4, 0.42),
        ]
        plan = plan_fill(book, coin(10), FILL_RECEIVE, scale=COIN)

        self.assertEqual(legs_by_id(plan), {b"B": coin(6), b"C": coin(4)})
        self.assertEqual(plan.unfilled, 0)

    def test_all_negotiable_book_is_a_plain_cheapest_first_fill(self):
        book = [
            candidate(b"A", 4, 0.40, min_amount=0.1),
            candidate(b"B", 4, 0.41, min_amount=0.1),
            candidate(b"C", 4, 0.42, min_amount=0.1),
        ]
        plan = plan_fill(book, coin(6), FILL_RECEIVE, scale=COIN)

        self.assertEqual(legs_by_id(plan), {b"A": coin(4), b"B": coin(2)})
        self.assertEqual(plan.total_spend, coin(2.42))


class TestPlanSpend(unittest.TestCase):

    def test_spends_the_budget_cheapest_first(self):
        book = [
            candidate(b"A", 4, 0.40, min_amount=0.1),
            candidate(b"B", 10, 0.50, min_amount=0.1),
        ]
        # 4 @ 0.40 = 1.6, leaving 0.4 of budget -> 0.8 of B at 0.50.
        plan = plan_fill(book, coin(2), FILL_SPEND, scale=COIN)

        self.assertEqual(legs_by_id(plan), {b"A": coin(4), b"B": coin(0.8)})
        self.assertEqual(plan.total_receive, coin(4.8))
        self.assertLessEqual(plan.total_spend, coin(2))
        self.assertEqual(plan.unfilled, 0)

    def test_reports_unspent_budget_when_the_book_runs_out(self):
        book = [candidate(b"A", 2, 0.50, min_amount=0.1)]
        plan = plan_fill(book, coin(10), FILL_SPEND, scale=COIN)

        self.assertEqual(plan.total_receive, coin(2))
        self.assertEqual(plan.total_spend, coin(1))
        self.assertEqual(plan.unfilled, coin(9))

    def test_never_exceeds_the_budget(self):
        plan = plan_fill([fixed(b"X", 10, 0.50)], coin(2), FILL_SPEND, scale=COIN)

        self.assertEqual(plan.legs, [])
        self.assertEqual(plan.unfilled, coin(2))


class TestSelectCandidates(unittest.TestCase):

    def test_excludes_offers_without_auto_accept(self):
        offers = [
            FakeOffer(b"cheap", 10, 0.40, auto_accept_type=AUTO_ACCEPT_NONE),
            FakeOffer(b"auto", 10, 0.50, auto_accept_type=AUTO_ACCEPT_ANY),
        ]
        candidates = select_candidates(offers)

        self.assertEqual([c.offer_id for c in candidates], [b"auto"])

    def test_excludes_known_identities_only_offers_by_default(self):
        offers = [
            FakeOffer(b"known", 10, 0.40, auto_accept_type=AUTO_ACCEPT_KNOWN_ONLY)
        ]

        self.assertEqual(select_candidates(offers), [])
        self.assertEqual(
            [c.offer_id for c in select_candidates(offers, allow_known_only=True)],
            [b"known"],
        )

    def test_a_thin_auto_accept_book_yields_a_worse_plan(self):
        offers = [
            FakeOffer(b"cheap", 10, 0.40, auto_accept_type=AUTO_ACCEPT_NONE),
            FakeOffer(b"auto", 3, 0.50, auto_accept_type=AUTO_ACCEPT_ANY),
        ]
        plan = plan_fill(select_candidates(offers), coin(10), FILL_RECEIVE, scale=COIN)

        self.assertEqual(plan.total_receive, coin(3))
        self.assertEqual(plan.unfilled, coin(7))
        self.assertEqual(plan.avg_rate, coin(0.50))

    def test_excludes_own_revoked_and_expired_offers(self):
        offers = [
            FakeOffer(b"own", 10, 0.40, was_sent=True),
            FakeOffer(b"revoked", 10, 0.40, active_ind=2),
            FakeOffer(b"expired", 10, 0.40, expire_at=1000),
            FakeOffer(b"good", 10, 0.40),
        ]
        candidates = select_candidates(offers, now=2000)

        self.assertEqual([c.offer_id for c in candidates], [b"good"])

    def test_excludes_offers_expiring_within_the_bid_window(self):
        offers = [
            FakeOffer(b"soon", 10, 0.40, expire_at=1030),
            FakeOffer(b"later", 10, 0.40, expire_at=1120),
        ]
        candidates = select_candidates(offers, now=1000)

        self.assertEqual([c.offer_id for c in candidates], [b"later"])

    def test_excludes_offers_above_the_limit_rate(self):
        offers = [
            FakeOffer(b"at", 10, 0.44),
            FakeOffer(b"over", 10, 0.45),
        ]
        limit = compute_limit_rate(coin(0.40), 10.0)
        candidates = select_candidates(offers, limit_rate=limit)

        self.assertEqual([c.offer_id for c in candidates], [b"at"])

    def test_fixed_offers_become_all_or_nothing_candidates(self):
        offers = [FakeOffer(b"fixed", 5, 0.40, amount_negotiable=False)]
        candidate_out = select_candidates(offers)[0]

        self.assertTrue(candidate_out.is_fixed)
        self.assertEqual(candidate_out.min_amount, candidate_out.max_amount)

    def test_returned_cheapest_first(self):
        offers = [
            FakeOffer(b"mid", 10, 0.45),
            FakeOffer(b"low", 10, 0.40),
            FakeOffer(b"high", 10, 0.50),
        ]
        candidates = select_candidates(offers)

        self.assertEqual([c.offer_id for c in candidates], [b"low", b"mid", b"high"])


class TestOptimality(unittest.TestCase):
    """Cross-check the search against brute force over every subset.

    Uses scale=1 so leg costs are exact, isolating the branch-and-bound pruning
    from floor-division truncation.
    """

    def brute_force(self, candidates, target, mode, fees):
        best = (0, 0)
        for size in range(len(candidates) + 1):
            for combo in itertools.combinations(range(len(candidates)), size):
                allocated = _allocate(
                    [candidates[i] for i in combo], target, mode, 1, fees
                )
                if allocated is None:
                    continue
                filled, cost, _ = allocated
                if filled > best[0] or (filled == best[0] and cost < best[1]):
                    best = (filled, cost)
        return best

    def test_matches_brute_force_on_random_books(self):
        rng = random.Random(7)

        for _ in range(400):
            candidates = []
            fees = {}
            for i in range(rng.randint(1, 9)):
                max_amount = rng.randint(1, 12)
                fixed_offer = rng.random() < 0.4
                min_amount = (
                    max_amount
                    if fixed_offer
                    else rng.choice([1, max(1, max_amount // 2)])
                )
                oid = bytes([i])
                candidates.append(
                    Candidate(
                        offer_id=oid,
                        rate=rng.randint(30, 60),
                        max_amount=max_amount,
                        min_amount=min_amount,
                    )
                )
                fees[oid] = rng.randint(0, min_amount)
            candidates.sort(key=lambda c: (c.rate, c.offer_id))

            for mode in (FILL_RECEIVE, FILL_SPEND):
                target = rng.randint(1, 40)
                plan = plan_fill(candidates, target, mode, scale=1, fees=fees)

                self.assertEqual(
                    (plan.total_receive - plan.fees, plan.total_spend),
                    self.brute_force(candidates, target, mode, fees),
                )


class TestLimitRate(unittest.TestCase):

    def test_slip_off_anchor(self):
        self.assertEqual(compute_limit_rate(coin(0.40), 0.0), coin(0.40))
        self.assertEqual(compute_limit_rate(coin(0.40), 5.0), coin(0.42))

    def test_rejects_a_negative_slip(self):
        with self.assertRaises(ValueError):
            compute_limit_rate(coin(0.40), -1.0)


if __name__ == "__main__":
    unittest.main()
