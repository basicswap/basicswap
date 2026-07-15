# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time

from enum import IntEnum

from .db import OfferTracking


class OfferTrackingModes(IntEnum):
    LEGACY = 0
    ONE_TIME = 1
    FIXED_TOTAL = 2
    STANDING = 3


def strOfferTrackingMode(mode: int) -> str:
    try:
        mode = OfferTrackingModes(int(mode))
    except Exception:
        return "Unknown"
    return {
        OfferTrackingModes.LEGACY: "Legacy",
        OfferTrackingModes.ONE_TIME: "One-time",
        OfferTrackingModes.FIXED_TOTAL: "Fixed total",
        OfferTrackingModes.STANDING: "Standing",
    }[mode]


def offerTrackingModeFromString(s):
    if s is None:
        return OfferTrackingModes.LEGACY
    if isinstance(s, int):
        try:
            return OfferTrackingModes(int(s))
        except ValueError:
            raise ValueError(f"Unknown offer tracking mode: {s}")
    key = str(s).strip().lower().replace("-", "_").replace(" ", "_")
    mapping = {
        "legacy": OfferTrackingModes.LEGACY,
        "none": OfferTrackingModes.LEGACY,
        "one_time": OfferTrackingModes.ONE_TIME,
        "onetime": OfferTrackingModes.ONE_TIME,
        "fixed_total": OfferTrackingModes.FIXED_TOTAL,
        "fixedtotal": OfferTrackingModes.FIXED_TOTAL,
        "standing": OfferTrackingModes.STANDING,
    }
    if key not in mapping:
        raise ValueError(f"Unknown offer tracking mode: {s}")
    return mapping[key]


def offerTrackingModeToString(mode) -> str:
    try:
        mode = OfferTrackingModes(int(mode))
    except Exception:
        return "legacy"
    return {
        OfferTrackingModes.LEGACY: "legacy",
        OfferTrackingModes.ONE_TIME: "one_time",
        OfferTrackingModes.FIXED_TOTAL: "fixed_total",
        OfferTrackingModes.STANDING: "standing",
    }[mode]


def offer_tracking_remaining(row, in_flight: int = 0) -> "int | None":
    if row is None:
        return None
    if int(row.mode) == OfferTrackingModes.STANDING:
        return None
    total = row.total_budget or 0
    if total <= 0:
        return None
    used = (row.filled_amount or 0) + int(in_flight)
    remaining = total - used
    return remaining if remaining > 0 else 0


def offer_tracking_is_exhausted(row, in_flight: int = 0) -> bool:
    if row is None:
        return False
    if int(row.mode) == OfferTrackingModes.STANDING:
        return False
    max_fills = row.max_fills or 0
    if max_fills > 0 and (row.fills_completed or 0) >= max_fills:
        return True
    remaining = offer_tracking_remaining(row, in_flight)
    if remaining is not None and remaining <= 0:
        return True
    return False


def init_offer_tracking(
    self,
    offer_id: bytes,
    mode,
    per_swap_amount: int,
    cursor,
    total_budget: int = 0,
    max_fills: int = 0,
    min_wallet_reserve: int = 0,
    now: int = None,
):

    mode = OfferTrackingModes(int(mode))
    if mode == OfferTrackingModes.LEGACY:
        return None

    if now is None:
        now = int(time.time())

    per_swap_amount = int(per_swap_amount)

    if mode == OfferTrackingModes.ONE_TIME:
        total_budget = per_swap_amount
        max_fills = 1
    elif mode == OfferTrackingModes.FIXED_TOTAL:
        total_budget = int(total_budget)
        if total_budget < per_swap_amount:
            raise ValueError("total_budget must be >= per_swap_amount")
        max_fills = 0  # Unlimited fills, bounded by budget
    elif mode == OfferTrackingModes.STANDING:
        total_budget = 0  # Unlimited
        max_fills = 0

    row = OfferTracking(
        offer_id=offer_id,
        active_ind=1,
        mode=int(mode),
        per_swap_amount=per_swap_amount,
        total_budget=int(total_budget),
        filled_amount=0,
        reserved_amount=0,
        max_fills=int(max_fills),
        fills_completed=0,
        min_wallet_reserve=int(min_wallet_reserve),
        created_at=now,
        updated_at=now,
    )
    self.add(row, cursor)
    return row


def get_offer_tracking(self, offer_id: bytes, cursor):
    return self.queryOne(OfferTracking, cursor, {"offer_id": offer_id})


def offer_in_flight_amount(
    cursor, offer_id: bytes, accept_action_types, exclude_bid_id=None, reverse_bid=False
) -> int:
    action_type_params = {}
    action_placeholders = []
    for i, at in enumerate(accept_action_types):
        key = f"acc_action_{i}"
        action_type_params[key] = int(at)
        action_placeholders.append(f":{key}")
    action_in = ", ".join(action_placeholders) if action_placeholders else "NULL"

    amount_col = "bids.amount_to" if reverse_bid else "bids.amount"
    query = f"""SELECT bids.bid_id, {amount_col} FROM bids
           JOIN bidstates ON bidstates.state_id = bids.state AND bidstates.in_progress > 0
           WHERE bids.active_ind = 1 AND bids.offer_id = :offer_id
           UNION
           SELECT bids.bid_id, {amount_col} FROM bids
           JOIN actions ON actions.linked_id = bids.bid_id AND actions.active_ind = 1 AND actions.action_type IN ({action_in})
           WHERE bids.active_ind = 1 AND bids.offer_id = :offer_id
        """
    params = {"offer_id": offer_id}
    params.update(action_type_params)
    total: int = 0
    for row in cursor.execute(query, params):
        bid_id, amount = row
        if exclude_bid_id is not None and bid_id == exclude_bid_id:
            continue
        total += amount if amount else 0
    return total


def complete_offer_fill(self, offer_id: bytes, amount: int, cursor) -> bool:
    row = get_offer_tracking(self, offer_id, cursor)
    if row is None:
        return False

    amount = int(amount)
    row.filled_amount = (row.filled_amount or 0) + amount
    row.fills_completed = (row.fills_completed or 0) + 1
    row.updated_at = int(time.time())
    self.updateDB(row, cursor, ["offer_id"])

    # A completed bid is no longer in-flight, so evaluate exhaustion with 0.
    return offer_tracking_is_exhausted(row, in_flight=0)


def validate_offer_budget(
    self, offer, bid_amount: int, cursor, in_flight: int = 0
) -> None:
    row = get_offer_tracking(self, offer.offer_id, cursor)
    if row is None:
        return
    if offer_tracking_is_exhausted(row, in_flight):
        raise ValueError("Offer budget exhausted")
    remaining = offer_tracking_remaining(row, in_flight)
    if remaining is not None and int(bid_amount) > remaining:
        raise ValueError("Bid amount exceeds remaining offer budget")


def offer_budget_allows(
    self, offer_id: bytes, bid_amount: int, cursor, in_flight: int = 0
) -> bool:
    row = get_offer_tracking(self, offer_id, cursor)
    if row is None:
        return True
    if offer_tracking_is_exhausted(row, in_flight):
        return False
    remaining = offer_tracking_remaining(row, in_flight)
    if remaining is not None and int(bid_amount) > remaining:
        return False
    return True
