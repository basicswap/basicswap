#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""Split a requested buy across multiple offers.

Amounts are integer base units of the offer's coin_from and rates are scaled by
coin_from's COIN, so a leg's cost in coin_to units is (amount * rate) // scale,
matching basicswap.postBid.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

AUTO_ACCEPT_NONE: int = 0
AUTO_ACCEPT_ANY: int = 1
AUTO_ACCEPT_KNOWN_ONLY: int = 2

OFFER_ACTIVE: int = 1

FILL_RECEIVE: str = "receive"
FILL_SPEND: str = "spend"

REASON_OWN: str = "Your own offer"
REASON_INACTIVE: str = "Inactive"
REASON_NO_AUTO_ACCEPT: str = "No auto accept"
REASON_MIN_TOO_HIGH: str = "Minimum too high"
REASON_OVER_LIMIT: str = "Rate too high"
REASON_FEE_TOO_HIGH: str = "Fee too high"
REASON_NOT_NEEDED: str = "Not needed"
REASON_NOT_PICKED: str = "Not picked"

DEFAULT_SCALE: int = 10**8
DEFAULT_NODE_LIMIT: int = 200000
NO_SLACK_RATE: int = 2**63
MIN_SECONDS_TO_EXPIRY: int = 60


@dataclass(frozen=True)
class Candidate:
    offer_id: bytes
    rate: int
    max_amount: int
    min_amount: int

    @property
    def is_fixed(self) -> bool:
        return self.min_amount >= self.max_amount


@dataclass(frozen=True)
class Leg:
    offer_id: bytes
    rate: int
    amount: int
    cost: int


@dataclass(frozen=True)
class Excluded:
    offer_id: bytes
    rate: int
    max_amount: int
    reason: str


@dataclass
class Plan:
    legs: List[Leg] = field(default_factory=list)
    total_receive: int = 0
    total_spend: int = 0
    unfilled: int = 0
    scale: int = DEFAULT_SCALE
    exhaustive: bool = True
    fees: int = 0
    excluded: List[Excluded] = field(default_factory=list)
    own_offers: List[bytes] = field(default_factory=list)

    @property
    def num_bids(self) -> int:
        return len(self.legs)

    @property
    def avg_rate(self) -> int:
        if self.total_receive <= 0:
            return 0
        return (self.total_spend * self.scale) // self.total_receive


def compute_limit_rate(anchor_rate: int, slip_percent: float) -> int:
    if anchor_rate <= 0:
        raise ValueError("anchor_rate must be greater than zero")
    if slip_percent < 0.0:
        raise ValueError("slip_percent must not be negative")
    return int(anchor_rate * (100.0 + slip_percent) / 100.0)


def classify_offers(
    offers: Sequence,
    limit_rate: Optional[int] = None,
    require_auto_accept: bool = True,
    allow_known_only: bool = False,
    allow_own_offers: bool = False,
    now: Optional[int] = None,
    min_seconds_left: int = MIN_SECONDS_TO_EXPIRY,
):
    """Split offers into the ones the node may bid on and the ones it may not.

    Candidates come back cheapest rate first, each exclusion with its reason.
    """
    auto_accept_ok = {AUTO_ACCEPT_ANY}
    if allow_known_only:
        auto_accept_ok.add(AUTO_ACCEPT_KNOWN_ONLY)

    rv: List[Candidate] = []
    excluded: List[Excluded] = []

    for offer in offers:
        max_amount = int(offer.amount_from)
        rate = int(offer.rate)
        # Nothing to bid on and nothing worth showing.
        if max_amount <= 0 or rate <= 0:
            continue

        def drop(reason: str) -> None:
            excluded.append(Excluded(offer.offer_id, rate, max_amount, reason))

        if getattr(offer, "active_ind", OFFER_ACTIVE) != OFFER_ACTIVE:
            drop(REASON_INACTIVE)
            continue
        if getattr(offer, "was_sent", False) and not allow_own_offers:
            drop(REASON_OWN)
            continue

        expire_at = getattr(offer, "expire_at", None)
        if (
            now is not None
            and expire_at is not None
            and expire_at <= now + min_seconds_left
        ):
            continue

        if require_auto_accept:
            if (
                getattr(offer, "auto_accept_type", AUTO_ACCEPT_NONE)
                not in auto_accept_ok
            ):
                drop(REASON_NO_AUTO_ACCEPT)
                continue

        if limit_rate is not None and rate > limit_rate:
            drop(REASON_OVER_LIMIT)
            continue

        min_bid_amount = int(getattr(offer, "min_bid_amount", 0) or 0)
        if getattr(offer, "amount_negotiable", False):
            min_amount = max(min_bid_amount, 1)
        else:
            min_amount = max_amount

        rv.append(Candidate(offer.offer_id, rate, max_amount, min_amount))

    rv.sort(key=lambda c: (c.rate, c.offer_id))
    excluded.sort(key=lambda e: (e.rate, e.offer_id))
    return rv, excluded


def select_candidates(
    offers: Sequence,
    limit_rate: Optional[int] = None,
    require_auto_accept: bool = True,
    allow_known_only: bool = False,
    allow_own_offers: bool = False,
    now: Optional[int] = None,
) -> List[Candidate]:
    """Offers the node is actually allowed to bid on, cheapest rate first."""
    candidates, _ = classify_offers(
        offers,
        limit_rate=limit_rate,
        require_auto_accept=require_auto_accept,
        allow_known_only=allow_known_only,
        allow_own_offers=allow_own_offers,
        now=now,
    )
    return candidates


def apply_limit(candidates: Sequence[Candidate], limit_rate: int) -> List[Candidate]:
    return [c for c in candidates if c.rate <= limit_rate]


def _allocate(members: Sequence[Candidate], target: int, mode: str, scale: int, fees):
    """Best split of target across a fixed set of offers, None if it cannot be used.

    Optimal for a given member set, which is what lets plan_fill branch on
    membership alone. `filled` is net of each leg's redeem fee.
    """
    amounts = [c.min_amount for c in members]
    fee_total = sum(fees.get(c.offer_id, 0) for c in members)

    if mode == FILL_RECEIVE:
        gross_target = target + fee_total
        seeded = sum(amounts)
        if seeded > gross_target:
            return None
        remaining = gross_target - seeded
        for i, c in enumerate(members):
            if remaining <= 0:
                break
            take = min(remaining, c.max_amount - c.min_amount)
            amounts[i] += take
            remaining -= take
    else:
        seeded_cost = sum((a * c.rate) // scale for a, c in zip(amounts, members))
        if seeded_cost > target:
            return None
        budget = target - seeded_cost
        for i, c in enumerate(members):
            if budget <= 0:
                break
            slack = c.max_amount - c.min_amount
            if slack <= 0:
                continue
            take = min(slack, (budget * scale) // c.rate)
            if take <= 0:
                continue
            amounts[i] += take
            budget -= (take * c.rate) // scale

    filled = sum(amounts) - fee_total
    cost = sum((a * c.rate) // scale for a, c in zip(amounts, members))
    return filled, cost, amounts


def fits_alone(
    candidate: Candidate,
    target: int,
    mode: str = FILL_RECEIVE,
    scale: int = DEFAULT_SCALE,
    fees: Optional[dict] = None,
) -> bool:
    """Whether a single offer's minimum leaves room within the target."""
    return _allocate([candidate], target, mode, scale, fees or {}) is not None


def plan_fill(
    candidates: Sequence[Candidate],
    target: int,
    mode: str = FILL_RECEIVE,
    max_bids: Optional[int] = None,
    scale: int = DEFAULT_SCALE,
    fees: Optional[dict] = None,
    node_limit: int = DEFAULT_NODE_LIMIT,
) -> Plan:
    """Cheapest way to buy `target` (FILL_RECEIVE) or to spend `target` (FILL_SPEND).

    Taking the cheapest offers greedily is not optimal: a fixed-amount offer only
    fits if the flexible offers around it are held back to leave room for it, so
    the search is over which offers to touch.

    `fees` maps an offer to its leg's redeem fee, which the fill is net of.
    """
    if mode not in (FILL_RECEIVE, FILL_SPEND):
        raise ValueError("Unknown fill mode: " + str(mode))

    fees = fees or {}

    candidates = list(candidates)
    num_candidates = len(candidates)

    if num_candidates < 1 or target <= 0:
        return Plan(unfilled=max(target, 0), scale=scale)

    if max_bids is None or max_bids > num_candidates:
        max_bids = num_candidates
    if max_bids < 1:
        return Plan(unfilled=target, scale=scale)

    suffix_max = [0] * (num_candidates + 1)
    for i in range(num_candidates - 1, -1, -1):
        suffix_max[i] = suffix_max[i + 1] + candidates[i].max_amount

    best = {"filled": -1, "cost": 0, "members": [], "amounts": []}
    state = {"nodes": 0, "exhaustive": True}

    def consider(chosen: List[int]) -> None:
        members = [candidates[i] for i in chosen]
        allocated = _allocate(members, target, mode, scale, fees)
        if allocated is None:
            return
        filled, cost, amounts = allocated
        if filled > best["filled"] or (
            filled == best["filled"] and cost < best["cost"]
        ):
            best.update(filled=filled, cost=cost, members=members, amounts=amounts)

    # Incumbent, so the bounds in search() have something to prune against.
    greedy: List[int] = []
    seeded, seeded_fee, seeded_cost = 0, 0, 0
    for i, c in enumerate(candidates):
        if len(greedy) >= max_bids:
            break
        fee_i = fees.get(c.offer_id, 0)
        c_cost = (c.min_amount * c.rate) // scale
        if mode == FILL_RECEIVE and seeded + c.min_amount > target + seeded_fee + fee_i:
            continue
        if mode == FILL_SPEND and seeded_cost + c_cost > target:
            continue
        greedy.append(i)
        seeded += c.min_amount
        seeded_fee += fee_i
        seeded_cost += c_cost
    consider(greedy)

    def search(
        i: int,
        chosen: List[int],
        min_amount: int,
        min_cost: int,
        max_amount: int,
        cheap_rate: int,
        min_fee: int,
    ) -> None:
        state["nodes"] += 1
        if state["nodes"] > node_limit:
            state["exhaustive"] = False
            return

        if i >= num_candidates:
            consider(chosen)
            return

        next_cheap = min(cheap_rate, candidates[i].rate)
        if mode == FILL_RECEIVE:
            reachable = min(target, max_amount + suffix_max[i])
            if reachable < best["filled"]:
                return
            if reachable == best["filled"]:
                bound = min_cost + ((reachable - min_amount) * next_cheap) // scale
                if bound >= best["cost"]:
                    return
        else:
            affordable = min_amount + ((target - min_cost) * scale) // next_cheap
            reachable = min(max_amount + suffix_max[i], affordable)
            if reachable < best["filled"]:
                return
            if reachable == best["filled"] and min_cost >= best["cost"]:
                return

        c = candidates[i]
        if len(chosen) < max_bids:
            c_cost = (c.min_amount * c.rate) // scale
            fee_i = fees.get(c.offer_id, 0)
            fits = (
                min_amount + c.min_amount <= target + min_fee + fee_i
                if mode == FILL_RECEIVE
                else min_cost + c_cost <= target
            )
            if fits:
                chosen.append(i)
                search(
                    i + 1,
                    chosen,
                    min_amount + c.min_amount,
                    min_cost + c_cost,
                    max_amount + c.max_amount,
                    (
                        min(cheap_rate, c.rate)
                        if c.max_amount > c.min_amount
                        else cheap_rate
                    ),
                    min_fee + fee_i,
                )
                chosen.pop()

        search(i + 1, chosen, min_amount, min_cost, max_amount, cheap_rate, min_fee)

    search(0, [], 0, 0, 0, NO_SLACK_RATE, 0)

    if best["filled"] < 0:
        return Plan(unfilled=target, scale=scale, exhaustive=state["exhaustive"])

    legs = [
        Leg(c.offer_id, c.rate, amount, (amount * c.rate) // scale)
        for c, amount in zip(best["members"], best["amounts"])
        if amount > 0
    ]
    total_receive = sum(leg.amount for leg in legs)
    total_spend = sum(leg.cost for leg in legs)
    fees_total = sum(fees.get(leg.offer_id, 0) for leg in legs)
    net_receive = total_receive - fees_total

    return Plan(
        legs=legs,
        total_receive=total_receive,
        total_spend=total_spend,
        unfilled=max(
            0, target - (net_receive if mode == FILL_RECEIVE else total_spend)
        ),
        scale=scale,
        exhaustive=state["exhaustive"],
        fees=fees_total,
    )
