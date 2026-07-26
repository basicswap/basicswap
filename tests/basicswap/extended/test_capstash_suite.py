#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Explicit reviewer-facing CapStash integration suite.

This loader intentionally names every swap method. Loading
TestCapStashSwaps as a TestCase would also include unrelated inherited tests.
"""

import os
import unittest

from tests.basicswap.extended.test_capstash import TestCapStashLocalBinary
from tests.basicswap.extended.test_capstash_multinode import TestCapStashMultiNode
from tests.basicswap.extended.test_capstash_policy import TestCapStashPolicy
from tests.basicswap.extended.test_capstash_swaps import TestCapStashSwaps
from tests.basicswap.test_capstash import TestCapStash


SWAP_TESTS = (
    "test_02_sh_part_coin",
    "test_03_sh_coin_part",
    "test_06_sh_part_coin_itx_refund",
    "test_07_sh_coin_part_itx_refund",
    "test_10_sh_part_caps_daemon_restart",
    "test_11_sh_caps_part_daemon_restart",
    "test_12_sh_part_caps_basicswap_restart",
    "test_13_sh_caps_part_basicswap_restart",
    "test_14_sh_caps_part_refund_daemon_restart",
)


def load_tests(loader, tests, pattern):
    required_env = (
        "CAPS_BINDIR",
        "CAPS_DAEMON_SHA256",
        "CAPS_CLI_SHA256",
    )
    missing_env = [name for name in required_env if not os.getenv(name)]
    if missing_env:
        raise RuntimeError(
            "set required CapStash test environment: "
            + ", ".join(missing_env)
        )

    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestCapStash))
    suite.addTest(
        TestCapStashLocalBinary("test_daemon_wallet_address_and_mining")
    )
    suite.addTest(TestCapStashMultiNode("test_two_node_regtest"))
    suite.addTest(TestCapStashPolicy("test_fee_dust_and_funding_policy"))
    suite.addTests(TestCapStashSwaps(name) for name in SWAP_TESTS)
    return suite


if __name__ == "__main__":
    unittest.main()
