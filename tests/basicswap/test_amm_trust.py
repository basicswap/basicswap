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


def make_offer(strat_id=1, addr_from="addr_peer"):
    return {
        "offer_id": "abcd",
        "addr_from": addr_from,
        "rate": 1.0,
        "automation_strat_id": strat_id,
    }


class FakeIdentityApi:
    def __init__(self, identities):
        self._identities = identities

    def __call__(self, path, json_data=None):
        addr = path.split("/")[-1]
        if addr in self._identities:
            return dict(self._identities[addr], address=addr)
        return {}


def set_identities(identities):
    createoffers.read_json_api = FakeIdentityApi(identities)


class IsLocallyTrustedOfferTest(unittest.TestCase):
    def test_unknown_identity_not_trusted(self):
        set_identities({})
        self.assertFalse(createoffers.is_locally_trusted_offer(make_offer()))

    def test_automation_override_always_trusted(self):
        set_identities({"addr_peer": {"automation_override": 1}})
        self.assertTrue(createoffers.is_locally_trusted_offer(make_offer()))

    def test_automation_override_never_not_trusted(self):
        set_identities(
            {
                "addr_peer": {
                    "automation_override": 2,
                    "num_sent_bids_successful": 10,
                    "num_sent_bids_failed": 0,
                }
            }
        )
        self.assertFalse(createoffers.is_locally_trusted_offer(make_offer()))

    def test_successful_history_trusted(self):
        set_identities(
            {
                "addr_peer": {
                    "automation_override": 0,
                    "num_sent_bids_successful": 2,
                    "num_sent_bids_failed": 1,
                }
            }
        )
        self.assertTrue(createoffers.is_locally_trusted_offer(make_offer()))

    def test_no_successful_history_not_trusted(self):
        set_identities(
            {
                "addr_peer": {
                    "automation_override": 0,
                    "num_sent_bids_successful": 0,
                    "num_sent_bids_failed": 0,
                }
            }
        )
        self.assertFalse(createoffers.is_locally_trusted_offer(make_offer()))

    def test_too_many_failed_bids_not_trusted(self):
        set_identities(
            {
                "addr_peer": {
                    "automation_override": 0,
                    "num_sent_bids_successful": 1,
                    "num_sent_bids_failed": 5,
                }
            }
        )
        self.assertFalse(createoffers.is_locally_trusted_offer(make_offer()))

    def test_missing_addr_from_not_trusted(self):
        set_identities({"addr_peer": {"automation_override": 1}})
        offer = make_offer()
        del offer["addr_from"]
        self.assertFalse(createoffers.is_locally_trusted_offer(offer))


class ShouldBidOnOfferTest(unittest.TestCase):
    def test_claimed_auto_accept_alone_is_not_enough(self):
        set_identities({})
        offer = make_offer(strat_id=1)
        self.assertFalse(createoffers.should_bid_on_offer(offer, "conservative"))
        self.assertFalse(createoffers.should_bid_on_offer(offer, "auto_accept_only"))

    def test_claimed_and_locally_trusted(self):
        set_identities({"addr_peer": {"automation_override": 1}})
        offer = make_offer(strat_id=1)
        self.assertTrue(createoffers.should_bid_on_offer(offer, "conservative"))
        self.assertTrue(createoffers.should_bid_on_offer(offer, "auto_accept_only"))

    def test_trusted_without_auto_accept_claim(self):
        set_identities({"addr_peer": {"automation_override": 1}})
        offer = make_offer(strat_id=0)
        self.assertFalse(createoffers.should_bid_on_offer(offer, "conservative"))

    def test_aggressive_unchanged(self):
        set_identities({})
        self.assertTrue(createoffers.should_bid_on_offer(make_offer(), "aggressive"))


class FilterBiddableOffersTest(unittest.TestCase):
    def test_untrusted_claimed_offer_filtered_out(self):
        set_identities({"addr_known": {"automation_override": 1}})
        offers = [
            make_offer(strat_id=1, addr_from="addr_unknown"),
            make_offer(strat_id=1, addr_from="addr_known"),
        ]
        template = {"bid_strategy": "conservative", "bid_rate_tolerance": 2.0}
        filtered = createoffers.filter_biddable_offers(offers, template, 1.0)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["addr_from"], "addr_known")


if __name__ == "__main__":
    unittest.main()
