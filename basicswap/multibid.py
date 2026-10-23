#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""Plan and place a buy that is split across several offers."""

import json
import os

from dataclasses import dataclass, replace
from math import ceil
from typing import Callable, List, Optional

from .basicswap_util import BidStates, SwapTypes
from .bidplanner import (
    apply_limit,
    classify_offers,
    compute_limit_rate,
    Excluded,
    FILL_RECEIVE,
    FILL_SPEND,
    fits_alone,
    Plan,
    plan_fill,
    REASON_FEE_TOO_HIGH,
    REASON_MIN_TOO_HIGH,
    REASON_NOT_NEEDED,
    REASON_NOT_PICKED,
    REASON_OVER_LIMIT,
)
from .util import ensure

ANCHOR_MARKET: str = "market"
ANCHOR_BEST: str = "best"

DEFAULT_SLIP_PERCENT: float = 5.0
DEFAULT_MAX_BIDS: int = 15
DEFAULT_BID_VALID_SECONDS: int = 10 * 60
PLAN_ID_LENGTH: int = 16
# Block intervals allowed for a straggler's coin A lock, to cover the tail.
CONFIRM_INTERVAL_MULTIPLE: int = 3
MAX_CONFIRM_WAIT_SECONDS: int = 60 * 60
MIN_LEG_TIMEOUT_SECONDS: int = 5 * 60
# Slowest coin B: one confirmation at 10 minute blocks, x3 for variance.
PEER_CONFIRM_ALLOWANCE_SECONDS: int = 30 * 60
# Skip an offer worth less than this many times its own redeem fee.
DUST_FEE_MULTIPLE: int = 20

# A leg is ready to send its coin B lock once its coin A lock has confirmed.
READY_STATE = BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED
# States before the leader's coin A confirms: nothing is locked yet, so a leg
# here is cheap to abandon. BID_ACCEPTED is shared with secret-hash swaps, so
# the batch decision is scoped to adaptor-sig legs.
WAITING_STATES = (
    BidStates.CONNECT_REQ_SENT,
    BidStates.BID_SENT,
    BidStates.BID_REQUEST_SENT,
    BidStates.BID_RECEIVING_ACC,
    BidStates.BID_ACCEPTED,
    BidStates.BID_REQUEST_ACCEPTED,
    BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS,
    BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX,
)


def _leg_ready(leg) -> bool:
    return leg.state == READY_STATE and leg.xmr_b_lock_tx is None


def _can_hold(ready, lock_margin: int) -> bool:
    """Whether the batch can be held without stranding a ready leg past its coin
    A refund timelock. A leg with no measurable window does not block a hold."""
    required: int = lock_margin + PEER_CONFIRM_ALLOWANCE_SECONDS
    return all(
        leg.lock_remaining_seconds is None or leg.lock_remaining_seconds > required
        for leg in ready
    )


@dataclass(frozen=True)
class BatchPlan:
    # Reschedule instead of locking now: a cohort sibling is still on its way.
    wait: bool
    # Ready sibling legs to lock together with the deciding leg (never itself).
    batch: List
    # Cohort legs to abandon: coin A still unseen while a ready leg was held.
    drop: List


def plan_batch_decision(
    legs,
    bid_id: bytes,
    *,
    cap=None,
    now: int = 0,
    ready_timeout: int = 0,
    confirm_timeout: Optional[int] = None,
    lock_margin: int = 0,
) -> BatchPlan:
    """Decide how bid_id's coin B lock batches with its cohort, and which
    stragglers to drop. Only adaptor-sig legs sharing bid_id's cohort are
    weighed, so a retry never waits with, or locks into the same tx as, an
    earlier placement.

    A straggler's coin A lock has ready_timeout to be seen and, once seen,
    confirm_timeout to confirm (None means the same for both), measured from the
    longest-held ready leg. An unseen leg past its deadline is dropped, a seen
    one is left to lock on its own. Waiting stops early once a held ready leg has
    less than lock_margin plus PEER_CONFIRM_ALLOWANCE_SECONDS left on its coin A
    refund window.

    batch is the ready siblings to lock alongside bid_id, sliced to keep the tx
    within cap lock outputs (None means unbounded)."""
    me = next((leg for leg in legs if leg.bid_id == bid_id), None)
    if me is None:
        # Absent from its own plan: lock alone rather than batch on a partial view.
        return BatchPlan(wait=False, batch=[], drop=[])
    siblings = [
        leg
        for leg in legs
        if leg.bid_id != bid_id
        and leg.cohort == me.cohort
        and leg.is_adaptor
        and leg.locks_coin_b
    ]

    ready = [me] + [leg for leg in siblings if _leg_ready(leg)]
    held_for = max(now - leg.state_time for leg in ready)

    if confirm_timeout is None:
        confirm_timeout = ready_timeout
    can_hold: bool = _can_hold(ready, lock_margin)

    batch, drop, waiting = [], [], False
    for leg in siblings:
        if _leg_ready(leg):
            batch.append(leg)
        elif leg.state in WAITING_STATES:
            if held_for >= (confirm_timeout if leg.coin_a_seen else ready_timeout):
                if not leg.coin_a_seen:
                    drop.append(leg)
                # Past the timeout but funded: leave it to lock on its own.
            elif can_hold:
                waiting = True
        # Any other state (B lock already sent, failed, done) is not our concern.

    if waiting:
        return BatchPlan(wait=True, batch=[], drop=drop)
    if cap is not None:
        batch = batch[: max(cap - 1, 0)]
    return BatchPlan(wait=False, batch=batch, drop=drop)


# Before a leg's initiate txn confirms it owes nothing, so it is still coming.
HTLC_WAITING_STATES = (
    BidStates.BID_SENT,
    BidStates.BID_RECEIVING,
    BidStates.BID_RECEIVED,
    BidStates.BID_RECEIVING_ACC,
    BidStates.BID_ACCEPTED,
    BidStates.SWAP_DELAYING,
)


def _htlc_leg_ready(leg) -> bool:
    return leg.state == BidStates.SWAP_INITIATED and not leg.ptx_sent


def _htlc_can_hold(ready) -> bool:
    """Whether the batch can be held without spending a leg's redeem window. The
    seller may sit on a participate txn until its own refund unlocks, so half the
    contract belongs to the buyer's redeem and must outlast the hold. A leg with
    no measurable window does not block a hold."""
    return all(
        leg.lock_remaining_seconds is None
        or leg.lock_remaining_seconds
        > leg.lock_value // 2 + PEER_CONFIRM_ALLOWANCE_SECONDS
        for leg in ready
    )


def plan_htlc_batch(
    legs,
    bid_id,
    *,
    cap=None,
    now: int = 0,
    ready_timeout: int = 0,
    confirm_timeout: Optional[int] = None,
):
    """Decide whether bid_id sends its participate txn now and which sibling legs
    share it.

    A leg still working toward its own initiate confirmation holds the batch,
    measured from the longest-held ready leg. Its initiate txn has ready_timeout
    to be seen and, once seen, confirm_timeout to confirm (None means the same
    for both), because arrival is a peer's responsiveness while confirmation is a
    chain's block time. Waiting stops early once holding would eat into a ready
    leg's own redeem window."""
    me = next((leg for leg in legs if leg.bid_id == bid_id), None)
    if me is None:
        return BatchPlan(wait=False, batch=[], drop=[])

    siblings = [
        leg
        for leg in legs
        if leg.bid_id != bid_id and leg.cohort == me.cohort and leg.sends_ptx
    ]
    ready = [me] + [leg for leg in siblings if _htlc_leg_ready(leg)]
    held_for = max(now - leg.state_time for leg in ready)
    if confirm_timeout is None:
        confirm_timeout = ready_timeout
    can_hold: bool = _htlc_can_hold(ready)

    batch, waiting = [], False
    for leg in siblings:
        if _htlc_leg_ready(leg):
            batch.append(leg)
        elif leg.state in HTLC_WAITING_STATES:
            deadline = confirm_timeout if leg.itx_seen else ready_timeout
            if held_for < deadline and can_hold:
                waiting = True

    if waiting:
        return BatchPlan(wait=True, batch=[], drop=[])
    if cap is not None:
        batch = batch[: max(cap - 1, 0)]
    return BatchPlan(wait=False, batch=batch, drop=[])


def redeem_fee(fee_rate: int, redeem_vsize: int) -> int:
    """Fee to redeem one received swap output."""
    return fee_rate * redeem_vsize // 1000


@dataclass(frozen=True)
class FeeReserve:
    """Fees a plan holds back from the coin it pays with: each offer's lock,
    the tx splitting the wallet when the legs fund from their own outputs, and
    the inputs past the first that covering the spend takes, counting the
    wallet's outputs largest first. Monero-based coins have their wallet size
    the locks instead (locks_fee(amount, num_locks)) and say how much they can
    spend (max_locks(num_locks))."""

    lock: dict
    split_fixed: int = 0
    split_per_output: int = 0
    outputs: tuple = ()
    input_fee: int = 0
    locks_fee: Optional[Callable[[int, int], int]] = None
    max_locks: Optional[Callable[[int], int]] = None

    def split(self, num_legs: int) -> int:
        # A lone leg can combine outputs, so it never needs a split.
        if num_legs < 2:
            return 0
        return self.split_fixed + num_legs * self.split_per_output

    def extra_inputs(self, amount: int, fees: int) -> int:
        covered, extra = 0, 0
        for n, value in enumerate(self.outputs):
            if covered >= amount + fees + extra:
                break
            covered += value
            extra = n * self.input_fee
        return extra

    def spendable(self, num_legs: int, balance: int) -> int:
        """Spend left from balance after the worst-case fees of num_legs legs."""
        if self.max_locks:
            return self.max_locks(num_legs)
        max_lock_fee: int = max(self.lock.values(), default=0)
        fees: int = self.split(num_legs) + num_legs * max_lock_fee
        return balance - fees - self.extra_inputs(balance, fees)

    def for_offers(self, offer_ids, amount: int) -> int:
        if self.locks_fee:
            return self.locks_fee(amount, len(offer_ids))
        fees: int = self.split(len(offer_ids)) + sum(self.lock[o] for o in offer_ids)
        return fees + self.extra_inputs(amount, fees)

    def fits(self, offer_ids, spend: int, balance: int) -> bool:
        if self.max_locks:
            return spend <= self.max_locks(len(offer_ids))
        return spend + self.for_offers(offer_ids, spend) <= balance


def plan_fee_reserve(swap_client, ci, offer_ids, splits: bool) -> FeeReserve:
    """Adaptor-sig locks pay the offer's to-rate and secret-hash locks the live
    rate. Only legs given their own inputs (splits) can need a split. Extra
    inputs are priced at the highest of those rates."""
    if ci.coin_type() in swap_client.xmr_based_coins:
        return FeeReserve({}, locks_fee=ci.estLockTxsFee, max_locks=ci.estMaxLockAmount)
    input_vsize: int = ci.est_tx_input_vsize()
    lock_vsize: int = ci.est_lock_tx_vsize() + input_vsize
    live_rate = None
    rates = {}
    lock = {}
    for offer_id in offer_ids:
        _, xmr_offer = swap_client.getXmrOffer(offer_id)
        if xmr_offer:
            rate = xmr_offer.b_fee_rate
        else:
            if live_rate is None:
                live_rate = ci.make_int(ci.get_fee_rate()[0])
            rate = live_rate
        rates[offer_id] = rate
        lock[offer_id] = ceil(rate * lock_vsize / 1000)
    outputs = tuple(
        sorted((o["value"] for o in ci.getSpendableOutputs() or ()), reverse=True)
    )
    input_fee: int = ceil(max(rates.values(), default=0) * input_vsize / 1000)
    if not splits:
        return FeeReserve(lock, outputs=outputs, input_fee=input_fee)
    split_fixed, split_per_output, split_per_input = ci.getSplitTxFees()
    return FeeReserve(
        lock,
        split_fixed,
        split_per_output,
        outputs,
        max(input_fee, split_per_input),
    )


def plan_spend_max(fill, balance: int, reserve: FeeReserve, max_bids: int):
    """Largest spend plan whose spend, plus the fee reserve for the legs it
    uses, fits the balance. Returns (plan, target), or (None, None) when the
    balance can't cover the fees of a single leg.

    fill(target) plans one spend. Reserving the worst-case fees of k legs leaves
    the rest to spend. Fewer reserved legs means a larger spend, so search for
    the smallest k whose plan fits with its own legs' fees."""
    best = (None, None)
    lo, hi = 1, max_bids
    while lo <= hi:
        k: int = (lo + hi) // 2
        target: int = reserve.spendable(k, balance)
        if target <= 0:
            hi = k - 1
            continue
        trial = fill(target)
        legs = [leg.offer_id for leg in trial.legs]
        if reserve.fits(legs, trial.total_spend, balance):
            best = (trial, target)
            hi = k - 1
        else:
            lo = k + 1
    return best


def live_redeem_fee(ci) -> int:
    """Redeem fee for a swap that redeems at the live fee rate (secret-hash).

    Raises rather than returning 0, which would silently disable the dust floor."""
    try:
        fee_rate = ci.make_int(ci.get_fee_rate()[0])
    except Exception as e:
        raise ValueError(
            f"Could not get the {ci.coin_name()} fee rate to size the redeem fee: {e}"
        )
    return redeem_fee(fee_rate, ci.getHTLCSpendTxVSize())


def redeem_fees_by_offer(swap_client, coin_from, coin_to, ci_from, candidates) -> dict:
    """Per-offer fee to redeem the received coin_from. Adaptor-sig swaps spend
    the lock at the offer's committed rate; secret-hash swaps spend the HTLC at
    the live rate. When coin_from is the follower (a reverse bid) it is the coin
    B lock that is spent, otherwise the coin A lock. Either way the fee is paid
    in coin_from, so it is a_fee_rate that sizes it: the offer stores
    a_fee_rate/b_fee_rate as the from/to rates, not as the chain A/B rates.

    A coin that sets its own redeem fee overrides that with the rate it will
    actually pay."""
    reverse_bid = swap_client.is_reverse_ads_bid(coin_from, coin_to)
    redeem_vsize = (
        ci_from.xmr_swap_b_lock_spend_tx_vsize()
        if reverse_bid
        else ci_from.xmr_swap_a_lock_spend_tx_vsize()
    )
    wallet_rate = ci_from.getRedeemFeeRate() if candidates else None
    live_fee = None
    fees = {}
    for c in candidates:
        _, xmr_offer = swap_client.getXmrOffer(c.offer_id)
        if xmr_offer:
            rate = wallet_rate if wallet_rate is not None else xmr_offer.a_fee_rate
            fees[c.offer_id] = redeem_fee(rate or 0, redeem_vsize)
        else:
            if live_fee is None:
                live_fee = live_redeem_fee(ci_from)
            fees[c.offer_id] = live_fee
    return fees


def assign_prevouts(outputs, needs, extra_input_costs=None):
    """Give every leg its own inputs, largest need first and best fit, so no two
    legs fund from the same output. Combining outputs for one leg costs its
    entry in extra_input_costs per input past the first. None when the outputs
    cannot cover every leg."""
    extras = extra_input_costs or [0] * len(needs)
    pool = sorted(outputs, key=lambda o: o["value"])
    assigned = [None] * len(needs)
    for i in sorted(range(len(needs)), key=lambda i: needs[i], reverse=True):
        single = next((o for o in pool if o["value"] >= needs[i]), None)
        if single is not None:
            pool.remove(single)
            assigned[i] = [single]
            continue
        taken, total = [], 0
        while pool and total < needs[i] + max(len(taken) - 1, 0) * extras[i]:
            taken.append(pool.pop())
            total += taken[-1]["value"]
        if not taken or total < needs[i] + (len(taken) - 1) * extras[i]:
            return None
        assigned[i] = taken
    return [[{"txid": o["txid"], "vout": o["vout"]} for o in leg] for leg in assigned]


def leg_prevouts(swap_client, ci_from, ci_to, offers, legs):
    """Inputs for each leg's coin A lock, or None when the coin cannot preselect
    them. Raises when the wallet's outputs cannot fund every leg separately."""
    outputs = ci_to.getSpendableOutputs()
    if outputs is None:
        return None

    needs, extras = [], []
    for leg in legs:
        offer = offers[leg["offer_id"]]
        _, xmr_offer = swap_client.getXmrOffer(leg["offer_id"])
        # Chain A is coin_to on a reverse bid, so it is the offer's to-rate.
        fee_rate: int = xmr_offer.b_fee_rate if xmr_offer else 0
        cost: int = (int(leg["amount"]) * offer.rate) // ci_from.COIN()
        extra: int = fee_rate * ci_to.est_tx_input_vsize() // 1000
        # est_lock_tx_vsize is rough and leaves out change, a spare input's
        # worth covers both.
        needs.append(cost + fee_rate * ci_to.est_lock_tx_vsize() // 1000 + extra)
        extras.append(extra)

    assigned = assign_prevouts(outputs, needs, extras)
    if assigned is None:
        try:
            split = ci_to.splitOutputs(needs)
        except Exception as e:
            raise ValueError(
                "The {} wallet cannot fund {} locks at once and splitting it failed: {}".format(
                    ci_to.coin_name(), len(legs), e
                )
            )
        assigned = assign_prevouts(split, needs, extras)
    ensure(
        assigned is not None,
        "The {} wallet cannot fund {} locks at once".format(
            ci_to.coin_name(), len(legs)
        ),
    )
    return assigned


def getMarketRate(swap_client, coin_from, coin_to) -> Optional[int]:
    ci_to = swap_client.ci(coin_to)
    try:
        rates = swap_client.lookupRates(coin_from, coin_to)
        return ci_to.make_int(rates["oracle"]["rate_inferred"], r=1)
    except Exception as e:  # noqa: F841
        swap_client.log.debug(f"Market rate unavailable: {e}")
        return None


def planMultiBid(
    swap_client,
    coin_from,
    coin_to,
    mode: str,
    target: Optional[int],
    anchor: str = ANCHOR_MARKET,
    slip_percent: float = DEFAULT_SLIP_PERCENT,
    max_bids: int = DEFAULT_MAX_BIDS,
    allow_known_only: bool = False,
    allow_self_bids: bool = False,
    manual_offers: Optional[List[bytes]] = None,
    spend_max: bool = False,
):
    """Split `target` across the offers to buy coin_from paying coin_to.

    manual_offers overrides the rate limit: the picked offers are the only ones
    bid on, whatever they cost. The rest are still listed, so a caller showing
    the plan can offer them to be picked instead.

    spend_max replaces `target` with the whole coin_to balance, less the fee
    reserve for the legs the plan actually uses.
    """

    ensure(mode in (FILL_RECEIVE, FILL_SPEND), "Unknown fill mode")
    ensure(anchor in (ANCHOR_MARKET, ANCHOR_BEST), "Unknown anchor")
    if spend_max:
        ensure(mode == FILL_SPEND, "spend_max requires spend mode")
    else:
        ensure(target > 0, "Amount must be greater than zero")
    ensure(int(coin_from) != int(coin_to), "coin_from and coin_to must differ")

    ci_from = swap_client.ci(coin_from)
    picked = set(manual_offers or [])
    include_own: bool = allow_self_bids or len(picked) > 0

    offers = swap_client.listOffers(
        sent=False,
        filters={
            "coin_from": int(coin_from),
            "coin_to": int(coin_to),
            "include_sent": include_own,
        },
    )
    candidates, excluded = classify_offers(
        offers,
        require_auto_accept=True,
        allow_known_only=allow_known_only,
        allow_own_offers=include_own,
        now=swap_client.getTime(),
    )

    market_rate = getMarketRate(swap_client, coin_from, coin_to)

    limit_rate = None
    if picked:
        excluded += [
            Excluded(c.offer_id, c.rate, c.max_amount, REASON_NOT_PICKED)
            for c in candidates
            if c.offer_id not in picked
        ]
        candidates = [c for c in candidates if c.offer_id in picked]
    else:
        if anchor == ANCHOR_MARKET:
            # No market rate means no ceiling to slip from.
            ensure(market_rate, "Market rate unavailable, cannot anchor to market")
            anchor_rate = market_rate
        else:
            anchor_rate = candidates[0].rate if candidates else None

        if anchor_rate:
            limit_rate = compute_limit_rate(anchor_rate, slip_percent)
            excluded += [
                Excluded(c.offer_id, c.rate, c.max_amount, REASON_OVER_LIMIT)
                for c in candidates
                if c.rate > limit_rate
            ]
            candidates = apply_limit(candidates, limit_rate)

    fee_by_offer = redeem_fees_by_offer(
        swap_client, coin_from, coin_to, ci_from, candidates
    )

    if not picked:
        # A leg is only worth taking if it clears its own redeem fee, so raise each
        # offer's minimum to that floor and drop offers too small to reach it.
        floored = []
        for c in candidates:
            floor = DUST_FEE_MULTIPLE * fee_by_offer[c.offer_id]
            if floor > c.max_amount:
                excluded.append(
                    Excluded(c.offer_id, c.rate, c.max_amount, REASON_FEE_TOO_HIGH)
                )
            elif floor > c.min_amount:
                floored.append(replace(c, min_amount=floor))
            else:
                floored.append(c)
        candidates = floored

    def fill(fill_target: int) -> Plan:
        return plan_fill(
            candidates,
            fill_target,
            mode,
            max_bids=max_bids,
            scale=ci_from.COIN(),
            fees=fee_by_offer,
        )

    if spend_max:
        ci_to = swap_client.ci(coin_to)
        plan, target = plan_spend_max(
            fill,
            ci_to.getSpendableBalance(),
            plan_fee_reserve(
                swap_client,
                ci_to,
                [c.offer_id for c in candidates],
                swap_client.is_reverse_ads_bid(coin_from, coin_to),
            ),
            max_bids,
        )
        ensure(
            plan is not None,
            f"{ci_to.coin_name()} balance is too low to cover the fees of a bid",
        )
    else:
        plan = fill(target)

    bid_on = {leg.offer_id for leg in plan.legs}
    excluded += [
        Excluded(
            c.offer_id,
            c.rate,
            c.max_amount,
            (
                REASON_NOT_NEEDED
                if fits_alone(c, target, mode, ci_from.COIN(), fee_by_offer)
                else REASON_MIN_TOO_HIGH
            ),
        )
        for c in candidates
        if c.offer_id not in bid_on
    ]
    plan.excluded = sorted(excluded, key=lambda e: (e.rate, e.offer_id))
    plan.own_offers = [o.offer_id for o in offers if getattr(o, "was_sent", False)]

    return plan, market_rate, limit_rate


def placeMultiBid(
    swap_client,
    legs,
    valid_for_seconds: int = DEFAULT_BID_VALID_SECONDS,
    addr_from: Optional[str] = None,
    plan_id: Optional[bytes] = None,
    leg_timeout_seconds: Optional[int] = None,
):
    """Bid each leg of an approved plan. Returns (placed, failed, plan_id).

    A leg that fails does not stop the rest, so a caller that wanted the whole
    amount must re-plan the shortfall. Every bid placed carries the same plan_id,
    which is what groups them as one buy. Pass plan_id to retry a shortfall under
    the original buy, leave it unset to start a new one.
    """
    ensure(len(legs) > 0, "No legs to bid on")

    offers = {}
    coin_from = None
    coin_to = None
    total_spend: int = 0

    for leg in legs:
        offer_id = leg["offer_id"]
        offer = swap_client.getOffer(offer_id)
        ensure(offer, "Offer not found")
        ensure(offer_id not in offers, "Duplicate offer in legs")

        if coin_from is None:
            coin_from, coin_to = offer.coin_from, offer.coin_to
        ensure(
            offer.coin_from == coin_from and offer.coin_to == coin_to,
            "Legs must share one trading pair",
        )

        amount = int(leg["amount"])
        swap_client.validateBidAmount(offer, amount, offer.rate)

        ci_from = swap_client.ci(coin_from)
        total_spend += (amount * offer.rate) // ci_from.COIN()
        offers[offer_id] = offer

    ci_to = swap_client.ci(coin_to)
    batch_cap = ci_to.max_batched_lock_outputs()
    ensure(
        batch_cap is None or len(legs) <= batch_cap,
        "{} can lock at most {} bids in one transaction".format(
            ci_to.coin_name(), batch_cap
        ),
    )
    # Every leg can be accepted, so the whole spend and its fees must be covered
    # up front. The bidder funds coin_to in both directions.
    balance = ci_to.getSpendableBalance()
    reverse_bid: bool = swap_client.is_reverse_ads_bid(coin_from, coin_to)
    reserve = plan_fee_reserve(swap_client, ci_to, offers, reverse_bid)
    total_need = total_spend + reserve.for_offers(offers, total_spend)
    ensure(
        balance >= total_need,
        "Insufficient {} balance for the full plan: have {}, need {} including fees".format(
            ci_to.coin_name(),
            ci_to.format_amount(balance),
            ci_to.format_amount(total_need),
        ),
    )

    # Every leg is funded before any is broadcast, so an unbroadcast leg's
    # change cannot fund the next. Each leg gets its own inputs instead.
    assigned = (
        leg_prevouts(swap_client, ci_from, ci_to, offers, legs) if reverse_bid else None
    )

    placed: List[dict] = []
    failed: List[dict] = []
    cohort_id: Optional[bytes] = None
    if plan_id is None:
        plan_id = os.urandom(PLAN_ID_LENGTH)
        # Remember what the buy set out to fill, so a retry measures the shortfall
        # against a fixed target rather than a growing leg total.
        target_receive = sum(int(leg["amount"]) for leg in legs)
        swap_client.setStringKV(f"plan_target:{plan_id.hex()}", str(target_receive))
        # Stored per plan so a retry, which reuses plan_id, inherits it.
        if leg_timeout_seconds is not None:
            swap_client.setStringKV(
                f"plan_leg_timeout:{plan_id.hex()}", str(leg_timeout_seconds)
            )
    else:
        # A retry keeps the plan but is its own cohort, so it locks in a fresh tx.
        cohort_id = os.urandom(PLAN_ID_LENGTH)

    for leg_n, leg in enumerate(legs):
        offer_id = leg["offer_id"]
        offer = offers[offer_id]
        amount = int(leg["amount"])
        try:
            post_bid = (
                swap_client.postXmrBid
                if offer.swap_type == SwapTypes.XMR_SWAP
                else swap_client.postBid
            )
            extra_options = {"valid_for_seconds": valid_for_seconds}
            if assigned is not None:
                extra_options["reserved_prevouts"] = assigned[leg_n]
            bid_id = post_bid(
                offer_id,
                amount,
                addr_send_from=addr_from,
                extra_options=extra_options,
            )
            # The bid is already placed, so failing to mark it is not worth losing it over.
            try:
                swap_client.setBidPlan(bid_id, plan_id)
                if cohort_id is not None:
                    swap_client.setStringKV(
                        f"bid_cohort:{bid_id.hex()}", cohort_id.hex()
                    )
                if assigned is not None:
                    swap_client.setStringKV(
                        f"bid_prevouts:{bid_id.hex()}", json.dumps(assigned[leg_n])
                    )
                    for prevout in assigned[leg_n]:
                        ci_to.lockOutput(
                            prevout["txid"], prevout["vout"], bid_id=bid_id
                        )
            except Exception as e:  # noqa: F841
                swap_client.log.warning(
                    f"Could not mark bid {bid_id.hex()} as part of the plan: {e}"
                )
            placed.append(
                {
                    "offer_id": offer_id.hex(),
                    "bid_id": bid_id.hex(),
                    "amount": amount,
                    "rate": offer.rate,
                }
            )
        except Exception as e:
            swap_client.log.error(f"Bid failed on offer {offer_id.hex()}: {e}")
            failed.append(
                {"offer_id": offer_id.hex(), "amount": amount, "error": str(e)}
            )

    return placed, failed, plan_id


def describePlan(
    swap_client, coin_from, coin_to, mode: str, plan: Plan, market_rate, limit_rate
):
    ci_from = swap_client.ci(coin_from)
    ci_to = swap_client.ci(coin_to)

    pct_vs_market = None
    if market_rate and plan.avg_rate > 0:
        pct_vs_market = round((plan.avg_rate / market_rate - 1.0) * 100.0, 2)

    own = set(plan.own_offers)

    return {
        "coin_from": ci_from.coin_name(),
        "coin_to": ci_to.coin_name(),
        "legs": [
            {
                "offer_id": leg.offer_id.hex(),
                "amount": ci_from.format_amount(leg.amount),
                "rate": ci_to.format_amount(leg.rate),
                "cost": ci_to.format_amount(leg.cost),
                "own": leg.offer_id in own,
            }
            for leg in plan.legs
        ],
        "excluded": [
            {
                "offer_id": entry.offer_id.hex(),
                "amount": ci_from.format_amount(entry.max_amount),
                "rate": ci_to.format_amount(entry.rate),
                "cost": ci_to.format_amount(
                    (entry.max_amount * entry.rate) // ci_from.COIN()
                ),
                "reason": entry.reason,
                "own": entry.offer_id in own,
            }
            for entry in plan.excluded
        ],
        "num_bids": plan.num_bids,
        "total_receive": ci_from.format_amount(plan.total_receive),
        "fees": ci_from.format_amount(plan.fees),
        "net_receive": ci_from.format_amount(plan.total_receive - plan.fees),
        "total_spend": ci_to.format_amount(plan.total_spend),
        "avg_rate": ci_to.format_amount(plan.avg_rate),
        "market_rate": ci_to.format_amount(market_rate) if market_rate else None,
        "limit_rate": ci_to.format_amount(limit_rate) if limit_rate else None,
        "pct_vs_market": pct_vs_market,
        "mode": mode,
        "unfilled": (
            ci_from.format_amount(plan.unfilled)
            if mode == FILL_RECEIVE
            else ci_to.format_amount(plan.unfilled)
        ),
        "exhaustive": plan.exhaustive,
    }
