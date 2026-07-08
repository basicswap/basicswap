# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import threading
import unittest

from basicswap.db import create_db_, DBMethods
from basicswap.offer_tracking import (
    OfferTrackingModes,
    complete_offer_fill,
    get_offer_tracking,
    init_offer_tracking,
    offer_budget_allows,
    offer_tracking_is_exhausted,
    offer_tracking_remaining,
    offerTrackingModeFromString,
    offerTrackingModeToString,
    strOfferTrackingMode,
    validate_offer_budget,
)

logger = logging.getLogger()


class _Offer:
    def __init__(self, offer_id):
        self.offer_id = offer_id


class OfferTrackingTest(unittest.TestCase):
    def _new_db(self):
        db = DBMethods()
        db.sqlite_file = ":memory:"
        db.mxDB = threading.RLock()
        cursor = db.openDB()
        create_db_(db._db_con, logger)
        return db, cursor

    def test_mode_helpers(self):
        self.assertEqual(
            offerTrackingModeFromString("one-time"), OfferTrackingModes.ONE_TIME
        )
        self.assertEqual(
            offerTrackingModeFromString("FIXED_TOTAL"),
            OfferTrackingModes.FIXED_TOTAL,
        )
        self.assertEqual(offerTrackingModeFromString(None), OfferTrackingModes.LEGACY)
        self.assertEqual(strOfferTrackingMode(OfferTrackingModes.STANDING), "Standing")
        with self.assertRaises(ValueError):
            offerTrackingModeFromString("bogus")

    def test_mode_to_string_round_trip(self):
        for mode in (
            OfferTrackingModes.LEGACY,
            OfferTrackingModes.ONE_TIME,
            OfferTrackingModes.FIXED_TOTAL,
            OfferTrackingModes.STANDING,
        ):
            key = offerTrackingModeToString(mode)
            self.assertEqual(offerTrackingModeFromString(key), mode)

    def test_mode_from_int_round_trip(self):
        for mode in (
            OfferTrackingModes.LEGACY,
            OfferTrackingModes.ONE_TIME,
            OfferTrackingModes.FIXED_TOTAL,
            OfferTrackingModes.STANDING,
        ):
            self.assertEqual(offerTrackingModeFromString(int(mode)), mode)
            self.assertEqual(offerTrackingModeFromString(mode), mode)
        with self.assertRaises(ValueError):
            offerTrackingModeFromString(99)

    def test_legacy_creates_no_row(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x01" * 28
            row = init_offer_tracking(db, oid, OfferTrackingModes.LEGACY, 100, cursor)
            self.assertIsNone(row)
            self.assertIsNone(get_offer_tracking(db, oid, cursor))
            # Legacy offers are always allowed and never exhausted.
            self.assertTrue(offer_budget_allows(db, oid, 10**18, cursor))
            validate_offer_budget(db, _Offer(oid), 10**18, cursor)
        finally:
            db.closeDB(cursor)

    def test_one_time_single_fill_then_exhausted(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x02" * 28
            per_swap = 1_00000000  # 1 XMR
            row = init_offer_tracking(
                db, oid, OfferTrackingModes.ONE_TIME, per_swap, cursor
            )
            self.assertEqual(row.total_budget, per_swap)
            self.assertEqual(row.max_fills, 1)
            self.assertEqual(offer_tracking_remaining(row), per_swap)
            self.assertFalse(offer_tracking_is_exhausted(row))

            self.assertFalse(
                offer_budget_allows(db, oid, per_swap, cursor, in_flight=per_swap)
            )

            exhausted = complete_offer_fill(db, oid, per_swap, cursor)
            self.assertTrue(exhausted)
            row = get_offer_tracking(db, oid, cursor)
            self.assertEqual(row.filled_amount, per_swap)
            self.assertEqual(row.fills_completed, 1)
            self.assertTrue(offer_tracking_is_exhausted(row))
            self.assertFalse(offer_budget_allows(db, oid, per_swap, cursor))
        finally:
            db.closeDB(cursor)

    def test_one_time_failed_swap_allows_retry(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x03" * 28
            per_swap = 5_00000000
            init_offer_tracking(db, oid, OfferTrackingModes.ONE_TIME, per_swap, cursor)
            row = get_offer_tracking(db, oid, cursor)
            self.assertEqual(row.fills_completed, 0)
            self.assertFalse(offer_tracking_is_exhausted(row, in_flight=0))
            self.assertTrue(offer_budget_allows(db, oid, per_swap, cursor, in_flight=0))
        finally:
            db.closeDB(cursor)

    def test_fixed_total_stops_at_budget(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x04" * 28
            per_swap = 1_00000000
            total = 10_00000000  # 10 total, 1 per swap
            row = init_offer_tracking(
                db,
                oid,
                OfferTrackingModes.FIXED_TOTAL,
                per_swap,
                cursor,
                total_budget=total,
            )
            self.assertEqual(row.max_fills, 0)
            self.assertEqual(row.total_budget, total)

            exhausted = False
            fills = 0
            while offer_budget_allows(db, oid, per_swap, cursor):
                exhausted = complete_offer_fill(db, oid, per_swap, cursor)
                fills += 1
                if fills > 100:
                    self.fail("Fixed total did not terminate")

            self.assertEqual(fills, 10)
            self.assertTrue(exhausted)
            row = get_offer_tracking(db, oid, cursor)
            self.assertEqual(row.filled_amount, total)
            self.assertEqual(offer_tracking_remaining(row), 0)
        finally:
            db.closeDB(cursor)

    def test_fixed_total_rejects_bid_over_remaining(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x05" * 28
            per_swap = 1_00000000
            total = 3_00000000
            init_offer_tracking(
                db,
                oid,
                OfferTrackingModes.FIXED_TOTAL,
                per_swap,
                cursor,
                total_budget=total,
            )
            complete_offer_fill(db, oid, 2_00000000, cursor)
            self.assertFalse(offer_budget_allows(db, oid, 2_00000000, cursor))
            with self.assertRaises(ValueError):
                validate_offer_budget(db, _Offer(oid), 2_00000000, cursor)
            self.assertTrue(offer_budget_allows(db, oid, 1_00000000, cursor))
        finally:
            db.closeDB(cursor)

    def test_fixed_total_in_flight_reduces_remaining(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x08" * 28
            per_swap = 1_00000000
            total = 5_00000000
            init_offer_tracking(
                db,
                oid,
                OfferTrackingModes.FIXED_TOTAL,
                per_swap,
                cursor,
                total_budget=total,
            )
            complete_offer_fill(db, oid, 2_00000000, cursor)
            # 2 filled, 2 in-flight -> 1 remaining.
            self.assertTrue(
                offer_budget_allows(db, oid, 1_00000000, cursor, in_flight=2_00000000)
            )
            self.assertFalse(
                offer_budget_allows(db, oid, 2_00000000, cursor, in_flight=2_00000000)
            )
        finally:
            db.closeDB(cursor)

    def test_fixed_total_requires_valid_budget(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x06" * 28
            with self.assertRaises(ValueError):
                init_offer_tracking(
                    db,
                    oid,
                    OfferTrackingModes.FIXED_TOTAL,
                    1_00000000,
                    cursor,
                    total_budget=1000,  # < per_swap
                )
        finally:
            db.closeDB(cursor)

    def test_standing_unlimited_and_tracked(self):
        db, cursor = self._new_db()
        try:
            oid = b"\x07" * 28
            per_swap = 1_00000000
            floor = 2_00000000
            row = init_offer_tracking(
                db,
                oid,
                OfferTrackingModes.STANDING,
                per_swap,
                cursor,
                min_wallet_reserve=floor,
            )
            self.assertEqual(row.total_budget, 0)
            self.assertEqual(row.min_wallet_reserve, floor)
            self.assertIsNone(offer_tracking_remaining(row))

            for _ in range(20):
                exhausted = complete_offer_fill(db, oid, per_swap, cursor)
                self.assertFalse(exhausted)

            row = get_offer_tracking(db, oid, cursor)
            self.assertEqual(row.fills_completed, 20)
            self.assertFalse(offer_tracking_is_exhausted(row))
            self.assertTrue(
                offer_budget_allows(
                    db, oid, per_swap * 100, cursor, in_flight=per_swap * 50
                )
            )
        finally:
            db.closeDB(cursor)


if __name__ == "__main__":
    unittest.main()
