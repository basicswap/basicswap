# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import threading
import time
import unittest

from basicswap.db import (
    Bid,
    BidState,
    create_db_,
    DBMethods,
    Offer,
)
from basicswap.offer_tracking import (
    OfferTrackingModes,
    complete_offer_fill,
    init_offer_tracking,
    offer_budget_allows,
    offer_in_flight_amount,
    validate_offer_budget,
)

logger = logging.getLogger()

STATE_IN_PROGRESS = 100
STATE_COMPLETED = 101
STATE_FAILED = 102

ACCEPT_ACTION_TYPES = (3, 4)


class OfferTrackingIntegrationTest(unittest.TestCase):
    def _new_db(self):
        db = DBMethods()
        db.sqlite_file = ":memory:"
        db.mxDB = threading.RLock()
        cursor = db.openDB()
        create_db_(db._db_con, logger)
        now = int(time.time())
        for state_id, in_progress in (
            (STATE_IN_PROGRESS, 1),
            (STATE_COMPLETED, 0),
            (STATE_FAILED, 0),
        ):
            db.add(
                BidState(
                    active_ind=1,
                    state_id=state_id,
                    in_progress=in_progress,
                    label=f"state_{state_id}",
                    created_at=now,
                ),
                cursor,
            )
        return db, cursor

    def _add_offer(self, db, cursor, offer_id):
        db.add(
            Offer(
                offer_id=offer_id,
                active_ind=1,
                coin_from=1,
                coin_to=2,
                amount_from=1_00000000,
                was_sent=True,
                created_at=int(time.time()),
                expire_at=int(time.time()) + 3600,
            ),
            cursor,
        )

    def _add_bid(self, db, cursor, bid_id, offer_id, amount, state):
        db.add(
            Bid(
                bid_id=bid_id,
                offer_id=offer_id,
                active_ind=1,
                amount=amount,
                state=state,
                created_at=int(time.time()),
                expire_at=int(time.time()) + 3600,
            ),
            cursor,
        )

    def _in_flight(self, cursor, offer_id, exclude_bid_id=None):
        return offer_in_flight_amount(
            cursor, offer_id, ACCEPT_ACTION_TYPES, exclude_bid_id
        )

    def test_in_flight_counts_only_active_uncompleted(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x11" * 28
            self._add_offer(db, cursor, oid)
            self._add_bid(db, cursor, b"\xa1" * 28, oid, 1_00000000, STATE_IN_PROGRESS)
            self._add_bid(db, cursor, b"\xa2" * 28, oid, 2_00000000, STATE_COMPLETED)
            self._add_bid(db, cursor, b"\xa3" * 28, oid, 3_00000000, STATE_FAILED)

            # Only the in-progress bid contributes.
            self.assertEqual(self._in_flight(cursor, oid), 1_00000000)
            # Excluding it yields zero.
            self.assertEqual(
                self._in_flight(cursor, oid, exclude_bid_id=b"\xa1" * 28), 0
            )
        finally:
            db.closeDB(cursor)

    def test_one_time_blocks_second_concurrent_accept(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x12" * 28
            per_swap = 1_00000000
            self._add_offer(db, cursor, oid)
            init_offer_tracking(db, oid, OfferTrackingModes.ONE_TIME, per_swap, cursor)

            # First bid accepted and in-progress.
            self._add_bid(db, cursor, b"\xb1" * 28, oid, per_swap, STATE_IN_PROGRESS)

            offer = db.queryOne(Offer, cursor, {"offer_id": oid})
            in_flight = self._in_flight(cursor, oid, exclude_bid_id=b"\xb2" * 28)
            self.assertEqual(in_flight, per_swap)

            # A second concurrent bid must be rejected (budget already reserved).
            self.assertFalse(
                offer_budget_allows(db, oid, per_swap, cursor, in_flight=in_flight)
            )
            with self.assertRaises(ValueError):
                validate_offer_budget(db, offer, per_swap, cursor, in_flight=in_flight)
        finally:
            db.closeDB(cursor)

    def test_one_time_fill_then_exhausted(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x13" * 28
            per_swap = 1_00000000
            self._add_offer(db, cursor, oid)
            init_offer_tracking(db, oid, OfferTrackingModes.ONE_TIME, per_swap, cursor)
            exhausted = complete_offer_fill(db, oid, per_swap, cursor)
            self.assertTrue(exhausted)
            self.assertFalse(offer_budget_allows(db, oid, per_swap, cursor))
        finally:
            db.closeDB(cursor)

    def test_fixed_total_ten_one_unit_fills(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x14" * 28
            per_swap = 1_00000000
            total = 10_00000000
            self._add_offer(db, cursor, oid)
            init_offer_tracking(
                db,
                oid,
                OfferTrackingModes.FIXED_TOTAL,
                per_swap,
                cursor,
                total_budget=total,
            )
            fills = 0
            while offer_budget_allows(
                db, oid, per_swap, cursor, in_flight=self._in_flight(cursor, oid)
            ):
                complete_offer_fill(db, oid, per_swap, cursor)
                fills += 1
                if fills > 50:
                    self.fail("did not terminate")
            self.assertEqual(fills, 10)
        finally:
            db.closeDB(cursor)

    def test_failed_swap_frees_budget(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x15" * 28
            per_swap = 1_00000000
            self._add_offer(db, cursor, oid)
            init_offer_tracking(db, oid, OfferTrackingModes.ONE_TIME, per_swap, cursor)

            bid_id = b"\xc1" * 28
            self._add_bid(db, cursor, bid_id, oid, per_swap, STATE_IN_PROGRESS)
            self.assertEqual(self._in_flight(cursor, oid), per_swap)

            bid = db.queryOne(Bid, cursor, {"bid_id": bid_id})
            bid.state = STATE_FAILED
            db.updateDB(bid, cursor, ["bid_id"])

            self.assertEqual(self._in_flight(cursor, oid), 0)
            self.assertTrue(offer_budget_allows(db, oid, per_swap, cursor, in_flight=0))
        finally:
            db.closeDB(cursor)


if __name__ == "__main__":
    unittest.main()
