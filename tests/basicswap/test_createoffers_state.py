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

reconcile_state_keys = createoffers.reconcile_state_keys


class ReconcileStateKeysTest(unittest.TestCase):
    def test_migrates_legacy_name_keys_to_id(self):
        config = {"offers": [{"id": "offer_1", "name": "Foo"}]}
        state = {
            "offers": {"Foo": [{"offer_id": "aa"}]},
            "template_tracking": {"Foo": {"sold_by_offer": {"aa": 5}}},
        }
        changed = reconcile_state_keys(config, state)
        self.assertTrue(changed)
        self.assertEqual(state["offers"], {"offer_1": [{"offer_id": "aa"}]})
        self.assertEqual(
            state["template_tracking"], {"offer_1": {"sold_by_offer": {"aa": 5}}}
        )

    def test_keeps_valid_id_keys_untouched(self):
        config = {"offers": [{"id": "offer_1", "name": "Foo"}]}
        state = {"offers": {"offer_1": [{"offer_id": "aa"}]}}
        changed = reconcile_state_keys(config, state)
        self.assertFalse(changed)
        self.assertEqual(state["offers"], {"offer_1": [{"offer_id": "aa"}]})

    def test_drops_state_for_reset_or_deleted_template(self):
        # A regenerated id (reset) or removed template leaves state matching neither
        # a current id nor a current name -> dropped.
        config = {"offers": [{"id": "offer_new", "name": "Foo"}]}
        state = {"template_tracking": {"offer_old": {"sold_by_offer": {"aa": 5}}}}
        changed = reconcile_state_keys(config, state)
        self.assertTrue(changed)
        self.assertEqual(state["template_tracking"], {})

    def test_migration_does_not_clobber_existing_id_entry(self):
        config = {"offers": [{"id": "offer_1", "name": "Foo"}]}
        state = {
            "offers": {
                "offer_1": [{"offer_id": "new"}],
                "Foo": [{"offer_id": "stale"}],
            }
        }
        reconcile_state_keys(config, state)
        self.assertEqual(state["offers"], {"offer_1": [{"offer_id": "new"}]})

    def test_reconciles_bids(self):
        config = {"bids": [{"id": "bid_1", "name": "B"}]}
        state = {"bids": {"B": [{"bid_id": "aa", "active": True}]}}
        changed = reconcile_state_keys(config, state)
        self.assertTrue(changed)
        self.assertEqual(state["bids"], {"bid_1": [{"bid_id": "aa", "active": True}]})


if __name__ == "__main__":
    unittest.main()
