# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from unittest.mock import MagicMock

from basicswap.network.bsx_network import (
    BSXNetwork,
    PORTAL_DIFFICULTY_DEFAULT,
    PORTAL_MAX_TIME_VALID_HOURS,
)

SECONDS_IN_HOUR = 60 * 60


def make_network():
    net = BSXNetwork.__new__(BSXNetwork)
    net.log = MagicMock()
    net.SMSG_SECONDS_IN_HOUR = SECONDS_IN_HOUR
    return net


class ClampPortalDifficultyTest(unittest.TestCase):
    def test_default_difficulty_unchanged(self):
        net = make_network()
        rv = net.clampPortalDifficulty(PORTAL_DIFFICULTY_DEFAULT)
        self.assertEqual(rv, PORTAL_DIFFICULTY_DEFAULT)

    def test_slightly_harder_target_unchanged(self):
        net = make_network()
        rv = net.clampPortalDifficulty(0x1E7FFFFF)
        self.assertEqual(rv, 0x1E7FFFFF)

    def test_absurdly_hard_target_clamped(self):
        net = make_network()
        rv = net.clampPortalDifficulty(0x03FFFFFF)
        self.assertEqual(rv, PORTAL_DIFFICULTY_DEFAULT)
        net.log.warning.assert_called_once()

    def test_zero_difficulty_clamped(self):
        net = make_network()
        rv = net.clampPortalDifficulty(0)
        self.assertEqual(rv, PORTAL_DIFFICULTY_DEFAULT)

    def test_easier_than_default_clamped(self):
        net = make_network()
        rv = net.clampPortalDifficulty(0x1FFFFFFF)
        self.assertEqual(rv, PORTAL_DIFFICULTY_DEFAULT)

    def test_huge_exponent_clamped(self):
        net = make_network()
        rv = net.clampPortalDifficulty(0xFFFFFFFF)
        self.assertEqual(rv, PORTAL_DIFFICULTY_DEFAULT)


class ClampPortalTimeValidTest(unittest.TestCase):
    def test_normal_value_unchanged(self):
        net = make_network()
        self.assertEqual(
            net.clampPortalTimeValid(4 * SECONDS_IN_HOUR), 4 * SECONDS_IN_HOUR
        )

    def test_below_floor_raised(self):
        net = make_network()
        self.assertEqual(net.clampPortalTimeValid(60), SECONDS_IN_HOUR)
        self.assertEqual(net.clampPortalTimeValid(-1), SECONDS_IN_HOUR)

    def test_above_ceiling_clamped(self):
        net = make_network()
        max_valid = PORTAL_MAX_TIME_VALID_HOURS * SECONDS_IN_HOUR
        self.assertEqual(net.clampPortalTimeValid(max_valid + 1), max_valid)
        net.log.warning.assert_called_once()

    def test_four_byte_overflow_clamped(self):
        net = make_network()
        max_valid = PORTAL_MAX_TIME_VALID_HOURS * SECONDS_IN_HOUR
        rv = net.clampPortalTimeValid(2**32)
        self.assertEqual(rv, max_valid)
        rv.to_bytes(4, byteorder="little")


if __name__ == "__main__":
    unittest.main()
