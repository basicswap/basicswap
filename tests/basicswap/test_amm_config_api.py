# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.ui.page_amm import (
    validate_amm_config,
    get_amm_template_runtime,
    get_amm_bid_runtime,
    classify_offer_ids,
)


class AmmConfigValidationTest(unittest.TestCase):
    def _valid_standing_offer(self):
        return {
            "name": "offer_a",
            "coin_from": "Particl",
            "coin_to": "Bitcoin",
            "amount": 10,
            "amount_step": 1,
            "offer_valid_seconds": 3600,
            "offer_mode": "standing",
            "min_coin_from_amt": 5,
        }

    def test_valid_config_has_no_errors(self):
        config = {"offers": [self._valid_standing_offer()], "bids": []}
        self.assertEqual(validate_amm_config(config), [])

    def test_missing_name_reported(self):
        offer = self._valid_standing_offer()
        offer["name"] = ""
        errors = validate_amm_config({"offers": [offer]})
        self.assertTrue(any("name is required" in e for e in errors))

    def test_duplicate_names_allowed(self):
        # createoffers.py de-duplicates template names on load (name -> name_2),
        # so the config layer must not reject duplicates.
        offer = self._valid_standing_offer()
        config = {"offers": [dict(offer), dict(offer)]}
        errors = validate_amm_config(config)
        self.assertFalse(any("duplicate template name" in e for e in errors))

    def test_same_coin_reported(self):
        offer = self._valid_standing_offer()
        offer["coin_to"] = offer["coin_from"]
        errors = validate_amm_config({"offers": [offer]})
        self.assertTrue(any("must be different" in e for e in errors))

    def test_amount_step_exceeds_amount(self):
        offer = self._valid_standing_offer()
        offer["amount_step"] = 100
        errors = validate_amm_config({"offers": [offer]})
        self.assertTrue(any("amount_step cannot exceed amount" in e for e in errors))

    def test_offer_valid_seconds_too_low(self):
        offer = self._valid_standing_offer()
        offer["offer_valid_seconds"] = 60
        errors = validate_amm_config({"offers": [offer]})
        self.assertTrue(any("offer_valid_seconds" in e for e in errors))

    def test_standing_allows_zero_min_coin_from_amt(self):
        offer = self._valid_standing_offer()
        offer["min_coin_from_amt"] = 0
        self.assertEqual(validate_amm_config({"offers": [offer]}), [])

    def test_standing_allows_missing_min_coin_from_amt(self):
        offer = self._valid_standing_offer()
        del offer["min_coin_from_amt"]
        self.assertEqual(validate_amm_config({"offers": [offer]}), [])

    def test_standing_rejects_negative_min_coin_from_amt(self):
        offer = self._valid_standing_offer()
        offer["min_coin_from_amt"] = -1
        errors = validate_amm_config({"offers": [offer]})
        self.assertTrue(any("min_coin_from_amt" in e for e in errors))

    def test_fixed_total_allows_zero_min_coin_from_amt(self):
        offer = self._valid_standing_offer()
        offer["offer_mode"] = "fixed_total"
        offer["total_to_sell"] = 100
        offer["min_coin_from_amt"] = 0
        self.assertEqual(validate_amm_config({"offers": [offer]}), [])

    def test_legacy_zero_floor_config_saves(self):
        offer = {
            "name": "my_offer",
            "coin_from": "Monero",
            "coin_to": "Bitcoin",
            "amount": 0.1,
            "amount_step": 0.001,
            "offer_valid_seconds": 3600,
            "offer_mode": "standing",
            "min_coin_from_amt": 0,
            "enabled": False,
        }
        self.assertEqual(validate_amm_config({"offers": [offer]}), [])

    def test_fixed_total_requires_total(self):
        offer = self._valid_standing_offer()
        offer["offer_mode"] = "fixed_total"
        offer["total_to_sell"] = 1
        errors = validate_amm_config({"offers": [offer]})
        self.assertTrue(any("total_to_sell" in e for e in errors))

    def test_fixed_total_valid(self):
        offer = self._valid_standing_offer()
        offer["offer_mode"] = "fixed_total"
        offer["total_to_sell"] = 100
        self.assertEqual(validate_amm_config({"offers": [offer]}), [])

    def test_invalid_offer_mode(self):
        offer = self._valid_standing_offer()
        offer["offer_mode"] = "bogus"
        errors = validate_amm_config({"offers": [offer]})
        self.assertTrue(any("offer_mode must be one of" in e for e in errors))

    def test_non_dict_config(self):
        self.assertEqual(validate_amm_config([]), ["Config must be a JSON object"])


class AmmTemplateRuntimeTest(unittest.TestCase):
    def test_runtime_counts_and_fixed_total(self):
        config_data = {
            "offers": [
                {
                    "name": "ft",
                    "offer_mode": "fixed_total",
                    "amount": 10,
                    "total_to_sell": 100,
                },
                {
                    "name": "std",
                    "offer_mode": "standing",
                    "amount": 5,
                },
            ]
        }
        state_data = {
            "offers": {
                "ft": [{"offer_id": "aaa"}, {"offer_id": "bbb"}],
                "std": [{"offer_id": "ccc"}],
            },
            "template_tracking": {
                "ft": {
                    "exhausted": False,
                    "sold_by_offer": {"aaa": 20, "bbb": 10},
                },
            },
        }

        runtime = get_amm_template_runtime(
            None, config_data=config_data, state_data=state_data
        )

        self.assertEqual(runtime["ft"]["active_offer_count"], 2)
        self.assertEqual(runtime["ft"]["fixed_total_budget"], 100)
        self.assertEqual(runtime["ft"]["fixed_total_sold"], 30)
        self.assertEqual(runtime["std"]["active_offer_count"], 1)
        self.assertNotIn("fixed_total_budget", runtime["std"])

    def test_runtime_exhausted_flag(self):
        config_data = {
            "offers": [{"name": "once", "offer_mode": "one_time", "amount": 5}]
        }
        state_data = {
            "offers": {},
            "template_tracking": {"once": {"exhausted": True}},
        }
        runtime = get_amm_template_runtime(
            None, config_data=config_data, state_data=state_data
        )
        self.assertTrue(runtime["once"]["exhausted"])
        self.assertEqual(runtime["once"]["active_offer_count"], 0)


class AmmBidRuntimeTest(unittest.TestCase):
    def test_bid_runtime_counts_only_active(self):
        config_data = {
            "bids": [
                {"name": "bid_a"},
                {"name": "bid_b"},
            ]
        }
        state_data = {
            "bids": {
                "bid_a": [
                    {"bid_id": "0a", "active": True},
                    {"bid_id": "0b", "active": False},
                ],
                "bid_b": [],
            }
        }

        runtime = get_amm_bid_runtime(
            None, config_data=config_data, state_data=state_data
        )

        self.assertEqual(runtime["bid_a"]["active_bid_count"], 1)
        self.assertEqual(runtime["bid_a"]["bid_ids"], ["0a"])
        self.assertEqual(runtime["bid_b"]["active_bid_count"], 0)
        self.assertEqual(runtime["bid_b"]["bid_ids"], [])


class _FakeCi:
    @staticmethod
    def format_amount(sats):
        return sats / 1e8


class _FakeOffer:
    def __init__(self, coin_from):
        self.coin_from = coin_from


class _FakeSwapClient:
    def __init__(self, filled_sats_by_offer):
        self._filled = filled_sats_by_offer

    def getOffer(self, offer_id_bytes):
        return _FakeOffer(1)

    def getOfferTrackingSummary(self, offer):
        return None

    def ci(self, coin_from):
        return _FakeCi()


class _LiveSwapClient(_FakeSwapClient):
    def getOfferTrackingSummary(self, offer):
        return {"filled_amount": self._current}

    def getOffer(self, offer_id_bytes):
        self._current = self._filled.get(offer_id_bytes.hex(), 0)
        return _FakeOffer(1)


class AmmLiveFillsTest(unittest.TestCase):
    def test_live_fills_merge_with_persisted(self):
        config_data = {
            "offers": [
                {
                    "name": "ft",
                    "offer_mode": "fixed_total",
                    "amount": 10,
                    "total_to_sell": 100,
                }
            ]
        }
        state_data = {
            "offers": {"ft": [{"offer_id": "bb"}, {"offer_id": "cc"}]},
            "template_tracking": {
                "ft": {
                    "exhausted": False,
                    "sold_by_offer": {"aa": 5.0, "bb": 2.0},
                }
            },
        }
        client = _LiveSwapClient({"bb": 300000000, "cc": 400000000})
        runtime = get_amm_template_runtime(
            client, config_data=config_data, state_data=state_data
        )
        self.assertEqual(runtime["ft"]["fixed_total_sold"], 12.0)
        self.assertFalse(runtime["ft"]["exhausted"])

    def test_live_fills_include_revoked_offer_after_repost(self):
        config_data = {
            "offers": [
                {
                    "name": "ft",
                    "offer_mode": "fixed_total",
                    "amount": 10,
                    "total_to_sell": 30,
                }
            ]
        }
        state_data = {
            "offers": {"ft": [{"offer_id": "0b"}]},
            "template_tracking": {
                "ft": {
                    "exhausted": False,
                    "sold_by_offer": {"0a": 1.0},
                }
            },
        }
        client = _LiveSwapClient({"0a": 100000000, "0b": 200000000})
        runtime = get_amm_template_runtime(
            client, config_data=config_data, state_data=state_data
        )
        self.assertEqual(runtime["ft"]["fixed_total_sold"], 3.0)

    def test_live_fills_mark_exhausted(self):
        config_data = {
            "offers": [
                {
                    "name": "ft",
                    "offer_mode": "fixed_total",
                    "amount": 10,
                    "total_to_sell": 10,
                }
            ]
        }
        state_data = {
            "offers": {"ft": [{"offer_id": "bb"}]},
            "template_tracking": {"ft": {"sold_by_offer": {}}},
        }
        client = _LiveSwapClient({"bb": 1000000000})
        runtime = get_amm_template_runtime(
            client, config_data=config_data, state_data=state_data
        )
        self.assertEqual(runtime["ft"]["fixed_total_sold"], 10.0)
        self.assertTrue(runtime["ft"]["exhausted"])


class _StatefulOffer:
    def __init__(self, active_ind, expire_at, state):
        self.coin_from = 1
        self.active_ind = active_ind
        self.expire_at = expire_at
        self.state = state


class _StateClient:
    def __init__(self, offers_by_id, now=1000):
        self._offers = offers_by_id
        self._now = now

    def getTime(self):
        return self._now

    def getOffer(self, offer_id_bytes):
        return self._offers.get(offer_id_bytes.hex())


class ClassifyOfferIdsTest(unittest.TestCase):
    def test_none_client_treats_all_active(self):
        active, stale, details = classify_offer_ids(None, ["0a", "0b"])
        self.assertEqual(active, ["0a", "0b"])
        self.assertEqual(stale, [])
        self.assertEqual(details, {})

    def test_active_revoked_expired_gone(self):
        offers = {
            "0a": _StatefulOffer(active_ind=1, expire_at=2000, state=1),
            "0b": _StatefulOffer(active_ind=2, expire_at=2000, state=1),
            "0c": _StatefulOffer(active_ind=1, expire_at=500, state=1),
            "0d": None,
        }
        client = _StateClient(offers, now=1000)
        active, stale, details = classify_offer_ids(client, ["0a", "0b", "0c", "0d"])
        self.assertEqual(active, ["0a"])
        self.assertEqual(set(stale), {"0b", "0c", "0d"})
        self.assertTrue(details["0b"]["is_revoked"])
        self.assertTrue(details["0c"]["is_expired"])
        self.assertEqual(details["0d"]["state"], "Gone")

    def test_runtime_uses_active_count(self):
        config_data = {
            "offers": [{"name": "std", "offer_mode": "standing", "amount": 5}]
        }
        state_data = {
            "offers": {"std": [{"offer_id": "0a"}, {"offer_id": "0b"}]},
            "template_tracking": {},
        }
        offers = {
            "0a": _StatefulOffer(active_ind=1, expire_at=2000, state=1),
            "0b": _StatefulOffer(active_ind=2, expire_at=2000, state=1),
        }
        client = _StateClient(offers, now=1000)
        runtime = get_amm_template_runtime(
            client, config_data=config_data, state_data=state_data
        )
        self.assertEqual(runtime["std"]["active_offer_count"], 1)
        self.assertEqual(runtime["std"]["offer_ids"], ["0a"])
        self.assertEqual(runtime["std"]["stale_offer_ids"], ["0b"])


if __name__ == "__main__":
    unittest.main()
