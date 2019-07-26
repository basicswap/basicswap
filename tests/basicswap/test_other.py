#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import unittest
from basicswap.util import (
    SerialiseNum,
    DeserialiseNum,
)
from basicswap.basicswap import (
    Coins,
    getExpectedSequence,
    decodeSequence,
    SEQUENCE_LOCK_BLOCKS,
    SEQUENCE_LOCK_TIME,
)


def test_case(v, nb=None):
    b = SerialiseNum(v)
    if nb is not None:
        assert(len(b) == nb)
    assert(v == DeserialiseNum(b))


class Test(unittest.TestCase):
    def test_serialise_num(self):
        test_case(0, 1)
        test_case(1, 1)
        test_case(16, 1)

        test_case(-1, 2)
        test_case(17, 2)

        test_case(500)
        test_case(-500)
        test_case(4194642)

    def test_sequence(self):
        time_val = 48 * 60 * 60
        encoded = getExpectedSequence(SEQUENCE_LOCK_TIME, time_val, Coins.PART)
        decoded = decodeSequence(encoded)
        assert(decoded >= time_val)
        assert(decoded <= time_val + 512)

        time_val = 24 * 60
        encoded = getExpectedSequence(SEQUENCE_LOCK_TIME, time_val, Coins.PART)
        decoded = decodeSequence(encoded)
        assert(decoded >= time_val)
        assert(decoded <= time_val + 512)

        blocks_val = 123
        encoded = getExpectedSequence(SEQUENCE_LOCK_BLOCKS, blocks_val, Coins.PART)
        decoded = decodeSequence(encoded)
        assert(decoded == blocks_val)


if __name__ == '__main__':
    unittest.main()
