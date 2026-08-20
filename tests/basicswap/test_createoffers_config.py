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

get_bid_template_max_rate = createoffers.get_bid_template_max_rate
readConfig = createoffers.readConfig


class BidTemplateMaxRateTest(unittest.TestCase):
    def test_reads_ui_key(self):
        self.assertEqual(get_bid_template_max_rate({"max_rate": 10000.0}), 10000.0)

    def test_reads_script_key(self):
        self.assertEqual(get_bid_template_max_rate({"maxrate": 5000.0}), 5000.0)

    def test_script_key_takes_precedence(self):
        template = {"maxrate": 5000.0, "max_rate": 10000.0}
        self.assertEqual(get_bid_template_max_rate(template), 5000.0)

    def test_missing_returns_none(self):
        self.assertIsNone(get_bid_template_max_rate({}))
        self.assertIsNone(get_bid_template_max_rate({"maxrate": None}))


class ReadConfigMaxRateTest(unittest.TestCase):
    def _run_read_config(self, bid_template):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "createoffers.json")
            with open(config_path, "w") as fp:
                json.dump({"offers": [], "bids": [bid_template]}, fp)
            args = SimpleNamespace(configfile=config_path)
            config = readConfig(args, [])
            with open(config_path) as fp:
                written_config = json.load(fp)
        return config, written_config

    def test_normalizes_ui_authored_template(self):
        config, written_config = self._run_read_config(
            {
                "name": "UI Bid",
                "coin_from": "Particl",
                "coin_to": "Bitcoin",
                "amount": 0.01,
                "max_rate": 10000.0,
                "min_coin_to_balance": 1.0,
            }
        )
        self.assertEqual(config["bids"][0]["maxrate"], 10000.0)
        self.assertEqual(written_config["bids"][0]["maxrate"], 10000.0)
        self.assertEqual(
            get_bid_template_max_rate(config["bids"][0]),
            10000.0,
        )

    def test_keeps_existing_maxrate(self):
        config, _ = self._run_read_config(
            {
                "name": "Script Bid",
                "coin_from": "Particl",
                "coin_to": "Bitcoin",
                "amount": 0.01,
                "maxrate": 5000.0,
            }
        )
        self.assertEqual(config["bids"][0]["maxrate"], 5000.0)

    def test_template_without_max_rate_does_not_crash(self):
        config, _ = self._run_read_config(
            {
                "name": "No Rate Bid",
                "coin_from": "Particl",
                "coin_to": "Bitcoin",
                "amount": 0.01,
            }
        )
        self.assertNotIn("maxrate", config["bids"][0])
        self.assertIsNone(get_bid_template_max_rate(config["bids"][0]))


if __name__ == "__main__":
    unittest.main()
