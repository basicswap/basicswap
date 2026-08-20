# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import importlib.util
import os
import unittest

_SCRIPT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "scripts", "createoffers.py"
)
_spec = importlib.util.spec_from_file_location("createoffers", _SCRIPT_PATH)
createoffers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(createoffers)

apply_market_rate_floor = createoffers.apply_market_rate_floor


class ApplyMarketRateFloorTest(unittest.TestCase):
    def test_poisoned_rate_clamped_to_coingecko_floor(self):
        template = {"name": "t", "minrate": 0}
        rv = apply_market_rate_floor(0.0001, 100.0, template)
        self.assertEqual(rv, 80.0)

    def test_market_rate_within_deviation_unchanged(self):
        template = {"name": "t", "minrate": 0}
        rv = apply_market_rate_floor(95.0, 100.0, template)
        self.assertEqual(rv, 95.0)

    def test_minrate_floor_without_coingecko(self):
        template = {"name": "t", "minrate": 90.0}
        rv = apply_market_rate_floor(0.0001, None, template)
        self.assertEqual(rv, 90.0)

    def test_no_reference_returns_none(self):
        template = {"name": "t", "minrate": 0}
        self.assertIsNone(apply_market_rate_floor(0.0001, None, template))
        self.assertIsNone(apply_market_rate_floor(100.0, None, template))

    def test_minrate_above_coingecko_floor_wins(self):
        template = {"name": "t", "minrate": 95.0}
        rv = apply_market_rate_floor(50.0, 100.0, template)
        self.assertEqual(rv, 95.0)

    def test_custom_deviation_percent(self):
        template = {"name": "t", "minrate": 0, "market_rate_deviation_percent": 5.0}
        rv = apply_market_rate_floor(90.0, 100.0, template)
        self.assertEqual(rv, 95.0)
        rv = apply_market_rate_floor(96.0, 100.0, template)
        self.assertEqual(rv, 96.0)

    def test_missing_minrate_key(self):
        template = {"name": "t"}
        rv = apply_market_rate_floor(0.5, 1.0, template)
        self.assertEqual(rv, 0.8)


if __name__ == "__main__":
    unittest.main()
