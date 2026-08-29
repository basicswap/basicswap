# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import importlib
import os
import unittest

MODULES = (
    ("basicswap.interface.xmr.core", "XMR_WALLET_RPC_PWD", "xmr_wallet_pwd"),
    ("basicswap.interface.wow.core", "WOW_WALLET_RPC_PWD", "wow_wallet_pwd"),
)


def reload_with_env(module_name, env_var, env_value):
    old_value = os.environ.pop(env_var, None)
    try:
        if env_value is not None:
            os.environ[env_var] = env_value
        module = importlib.import_module(module_name)
        return importlib.reload(module)
    finally:
        if old_value is None:
            os.environ.pop(env_var, None)
        else:
            os.environ[env_var] = old_value


class WalletRPCPasswordTest(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        for module_name, _, _ in MODULES:
            importlib.reload(importlib.import_module(module_name))

    def test_unset_env_generates_random_password(self):
        for module_name, attr, old_default in MODULES:
            module = reload_with_env(module_name, attr, None)
            pwd = getattr(module, attr)
            self.assertNotEqual(pwd, "")
            self.assertNotEqual(pwd, old_default)
            self.assertGreaterEqual(len(pwd), 32)

    def test_generated_passwords_differ_between_runs(self):
        for module_name, attr, _ in MODULES:
            first = getattr(reload_with_env(module_name, attr, None), attr)
            second = getattr(reload_with_env(module_name, attr, None), attr)
            self.assertNotEqual(first, second)

    def test_env_value_is_respected(self):
        for module_name, attr, _ in MODULES:
            module = reload_with_env(module_name, attr, "custom_pwd_123")
            self.assertEqual(getattr(module, attr), "custom_pwd_123")

    def test_empty_env_generates_random_password(self):
        for module_name, attr, old_default in MODULES:
            module = reload_with_env(module_name, attr, "")
            pwd = getattr(module, attr)
            self.assertNotEqual(pwd, "")
            self.assertNotEqual(pwd, old_default)
            self.assertGreaterEqual(len(pwd), 32)


if __name__ == "__main__":
    unittest.main()
