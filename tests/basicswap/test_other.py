#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import unittest
from basicswap.util import (
    SerialiseNum,
    DeserialiseNum,
    makeInt,
    format8,
)
from basicswap.basicswap import (
    Coins,
    getExpectedSequence,
    decodeSequence,
    SEQUENCE_LOCK_BLOCKS,
    SEQUENCE_LOCK_TIME,
)


class Test(unittest.TestCase):
    def test_serialise_num(self):
        def test_case(v, nb=None):
            b = SerialiseNum(v)
            if nb is not None:
                assert(len(b) == nb)
            assert(v == DeserialiseNum(b))
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

    def test_makeInt(self):
        def test_case(v):
            sv = format8(makeInt(v))
            # Strip
            for i in range(7):
                if sv[-1] == '0':
                    sv = sv[:-1]
            assert(sv == v)
        test_case('0.00899999')
        test_case('899999.0')
        test_case('899999.00899999')
        test_case('1.0')
        test_case('1.1')
        test_case('1.2')
        test_case('0.00899991')
        test_case('0.0089999')
        test_case('0.0089991')
        test_case('0.123')
        test_case('123000.000123')


if __name__ == '__main__':
    unittest.main()
