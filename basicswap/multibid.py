#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""Plan and place a buy that is split across several offers."""

import os

from dataclasses import dataclass, replace
from typing import List, Optional

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
# Leave this fraction of the balance unspent to cover the coin B lock fee.
# Mirrors FEE_RESERVE_FRACTION in the Smart Buy page's Max button.
FEE_RESERVE_FRACTION: float = 0.001


# A leg is ready to send its coin B lock once its coin A lock has confirmed.
READY_STATE = BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED
# States before the leader's coin A confirms: nothing is locked yet, so a leg
# here is cheap to abandon. BID_ACCEPTED is shared with secret-hash swaps, so
# the batch decision is scoped to adaptor-sig legs.
WAITING_STATES = (
    BidStates.CONNECT_REQ_SENT,
    BidStates.BID_SENT,
    BidStates.BID_REQUEST_SENT,
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


def redeem_fee(fee_rate: int, redeem_vsize: int) -> int:
    """Fee to redeem one received swap output."""
    return fee_rate * redeem_vsize // 1000


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
    """Per-offer fee to redeem the received coin_from, mirroring the lock-spend
    fee the offer page shows. Adaptor-sig swaps spend the lock at the offer's
    committed rate; secret-hash swaps spend the HTLC at the live rate. When
    coin_from is the follower (a reverse bid) the coin B lock-spend and the
    matching committed rate apply, otherwise the coin A lock-spend."""
    reverse_bid = swap_client.is_reverse_ads_bid(coin_from, coin_to)
    redeem_vsize = (
        ci_from.xmr_swap_b_lock_spend_tx_vsize()
        if reverse_bid
        else ci_from.xmr_swap_a_lock_spend_tx_vsize()
    )
    live_fee = None
    fees = {}
    for c in candidates:
        _, xmr_offer = swap_client.getXmrOffer(c.offer_id)
        if xmr_offer:
            rate = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate
            fees[c.offer_id] = redeem_fee(rate or 0, redeem_vsize)
        else:
            if live_fee is None:
                live_fee = live_redeem_fee(ci_from)
            fees[c.offer_id] = live_fee
    return fees


def getMarketRate(swap_client, coin_from, coin_to) -> Optional[int]:
    ci_to = swap_client.ci(coin_to)
    try:
        rates = swap_client.lookupRates(coin_from, coin_to)
        return ci_to.make_int(rates["coingecko"]["rate_inferred"], r=1)
    except Exception as e:  # noqa: F841
        swap_client.log.debug(f"Market rate unavailable: {e}")
        return None


def planMultiBid(
    swap_client,
    coin_from,
    coin_to,
    mode: str,
    target: int,
    anchor: str = ANCHOR_MARKET,
    slip_percent: float = DEFAULT_SLIP_PERCENT,
    max_bids: int = DEFAULT_MAX_BIDS,
    allow_known_only: bool = False,
    allow_self_bids: bool = False,
    manual_offers: Optional[List[bytes]] = None,
):
    """Split `target` across the offers to buy coin_from paying coin_to.

    manual_offers overrides the rate limit: the picked offers are the only ones
    bid on, whatever they cost. The rest are still listed, so a caller showing
    the plan can offer them to be picked instead.
    """

    ensure(mode in (FILL_RECEIVE, FILL_SPEND), "Unknown fill mode")
    ensure(anchor in (ANCHOR_MARKET, ANCHOR_BEST), "Unknown anchor")
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

    plan = plan_fill(
        candidates,
        target,
        mode,
        max_bids=max_bids,
        scale=ci_from.COIN(),
        fees=fee_by_offer,
    )

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
    # Every leg can be accepted, so the whole spend must be covered up front.
    # The bidder funds coin_to in both directions, so hold back a fraction of it
    # for the lock fee rather than letting a plan spend 100%.
    balance = ci_to.getSpendableBalance()
    spendable = int(balance * (1 - FEE_RESERVE_FRACTION))
    ensure(
        spendable >= total_spend,
        "Insufficient {} balance for the full plan: have {}, need {} plus fee reserve".format(
            ci_to.coin_name(),
            ci_to.format_amount(balance),
            ci_to.format_amount(total_spend),
        ),
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

    for leg in legs:
        offer_id = leg["offer_id"]
        offer = offers[offer_id]
        amount = int(leg["amount"])
        try:
            post_bid = (
                swap_client.postXmrBid
                if offer.swap_type == SwapTypes.XMR_SWAP
                else swap_client.postBid
            )
            bid_id = post_bid(
                offer_id,
                amount,
                addr_send_from=addr_from,
                extra_options={"valid_for_seconds": valid_for_seconds},
            )
            # The bid is already placed, so failing to mark it is not worth losing it over.
            try:
                swap_client.setBidPlan(bid_id, plan_id)
                if cohort_id is not None:
                    swap_client.setStringKV(
                        f"bid_cohort:{bid_id.hex()}", cohort_id.hex()
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
