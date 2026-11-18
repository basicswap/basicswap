# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import importlib.util
import json
import os
import tempfile
import unittest
from types import SimpleNamespace

_SCRIPT_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "scripts", "createoffers.py"
)
_spec = importlib.util.spec_from_file_location("createoffers", _SCRIPT_PATH)
createoffers = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(createoffers)

check_market_oracle_divergence = createoffers.check_market_oracle_divergence
readConfig = createoffers.readConfig


class CheckMarketOracleDivergenceTest(unittest.TestCase):
    def test_disabled_when_unset(self):
        self.assertIsNone(check_market_oracle_divergence(1.0, 2.0, None))

    def test_disabled_when_not_positive(self):
        self.assertIsNone(check_market_oracle_divergence(1.0, 2.0, 0))
        self.assertIsNone(check_market_oracle_divergence(1.0, 2.0, -5))

    def test_no_oracle_rate(self):
        self.assertIsNone(check_market_oracle_divergence(1.0, None, 5))
        self.assertIsNone(check_market_oracle_divergence(1.0, 0, 5))

    def test_no_market_rate(self):
        self.assertIsNone(check_market_oracle_divergence(None, 1.0, 5))

    def test_divergence_below_threshold(self):
        self.assertIsNone(check_market_oracle_divergence(1.04, 1.0, 5))

    def test_divergence_above_threshold(self):
        divergence = check_market_oracle_divergence(1.10, 1.0, 5)
        self.assertAlmostEqual(divergence, 10.0)

    def test_divergence_exactly_at_threshold_not_exceeded(self):
        # 1.0625 / 1.0 diverges by exactly 6.25% (exact in binary floating point)
        self.assertIsNone(check_market_oracle_divergence(1.0625, 1.0, 6.25))

    def test_divergence_is_symmetric(self):
        divergence = check_market_oracle_divergence(0.90, 1.0, 5)
        self.assertAlmostEqual(divergence, 10.0)


def _read_config(config_data):
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.json")
        with open(config_path, "w") as fp:
            json.dump(config_data, fp)
        args = SimpleNamespace(configfile=config_path)
        return readConfig(args, [])


class ReadConfigMaxOracleDivergenceTest(unittest.TestCase):
    def _base_template(self):
        return {
            "name": "Offer 0",
            "coin_from": "particl",
            "coin_to": "monero",
            "amount": 1.0,
        }

    def test_key_absent_by_default(self):
        config = _read_config({"offers": [self._base_template()]})
        self.assertNotIn("max_oracle_divergence_percent", config["offers"][0])

    def test_valid_key_kept_as_float(self):
        template = self._base_template()
        template["max_oracle_divergence_percent"] = 5
        config = _read_config({"offers": [template]})
        self.assertEqual(config["offers"][0]["max_oracle_divergence_percent"], 5.0)

    def test_invalid_key_removed(self):
        for bad_value in (0, -1, "abc", None):
            template = self._base_template()
            template["max_oracle_divergence_percent"] = bad_value
            config = _read_config({"offers": [template]})
            self.assertNotIn(
                "max_oracle_divergence_percent",
                config["offers"][0],
                msg=f"value {bad_value!r} should be rejected",
            )


if __name__ == "__main__":
    unittest.main()
