# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import importlib
import os
import unittest

MODULE_NAME = "basicswap.interface.dcr.core"
ENV_VARS = ("DCR_WALLET_PWD", "DCR_RPC_PWD")


def reload_with_env(env_values):
    old_values = {}
    for var in ENV_VARS:
        old_values[var] = os.environ.pop(var, None)
    try:
        for var, value in env_values.items():
            os.environ[var] = value
        module = importlib.import_module(MODULE_NAME)
        return importlib.reload(module)
    finally:
        for var, old_value in old_values.items():
            if old_value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = old_value


class DCRPasswordTest(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        importlib.reload(importlib.import_module(MODULE_NAME))

    def test_unset_env_generates_random_password(self):
        module = reload_with_env({})
        for attr in ("DCR_WALLET_PWD", "DCR_RPC_PWD"):
            pwd = getattr(module, attr)
            self.assertNotEqual(pwd, "")
            self.assertGreaterEqual(len(pwd), 32)

    def test_generated_passwords_differ_between_runs(self):
        first = reload_with_env({})
        first_values = (first.DCR_WALLET_PWD, first.DCR_RPC_PWD)
        second = reload_with_env({})
        self.assertNotEqual(first_values[0], second.DCR_WALLET_PWD)
        self.assertNotEqual(first_values[1], second.DCR_RPC_PWD)
        self.assertNotEqual(second.DCR_WALLET_PWD, second.DCR_RPC_PWD)

    def test_env_value_is_respected(self):
        module = reload_with_env(
            {"DCR_WALLET_PWD": "custom_wallet_pwd", "DCR_RPC_PWD": "custom_rpc_pwd"}
        )
        self.assertEqual(module.DCR_WALLET_PWD, "custom_wallet_pwd")
        self.assertEqual(module.DCR_RPC_PWD, "custom_rpc_pwd")

    def test_empty_env_generates_random_password(self):
        module = reload_with_env({"DCR_WALLET_PWD": "", "DCR_RPC_PWD": ""})
        for attr in ("DCR_WALLET_PWD", "DCR_RPC_PWD"):
            pwd = getattr(module, attr)
            self.assertNotEqual(pwd, "")
            self.assertGreaterEqual(len(pwd), 32)


if __name__ == "__main__":
    unittest.main()
