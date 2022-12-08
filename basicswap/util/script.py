# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import struct
import hashlib
from basicswap.script import OpCodes


def decodeScriptNum(script_bytes, o):
    v = 0
    num_len = script_bytes[o]
    if num_len >= OpCodes.OP_1 and num_len <= OpCodes.OP_16:
        return ((num_len - OpCodes.OP_1) + 1, 1)

    if num_len > 4:
        raise ValueError('Bad scriptnum length')  # Max 4 bytes
    if num_len + o >= len(script_bytes):
        raise ValueError('Bad script length')
    o += 1
    for i in range(num_len):
        b = script_bytes[o + i]
        # Negative flag set in last byte, if num is positive and > 0x80 an extra 0x00 byte will be appended
        if i == num_len - 1 and b & 0x80:
            b &= (~(0x80) & 0xFF)
            v += int(b) << 8 * i
            v *= -1
        else:
            v += int(b) << 8 * i
    return (v, 1 + num_len)


def getP2SHScriptForHash(p2sh):
    return bytes((OpCodes.OP_HASH160, 0x14)) \
        + p2sh \
        + bytes((OpCodes.OP_EQUAL,))


def getP2WSH(script):
    return bytes((OpCodes.OP_0, 0x20)) + hashlib.sha256(script).digest()


def SerialiseNumCompact(v):
    if v < 253:
        return bytes((v,))
    if v <= 0xffff:  # USHRT_MAX
        return struct.pack("<BH", 253, v)
    if v <= 0xffffffff:  # UINT_MAX
        return struct.pack("<BI", 254, v)
    if v <= 0xffffffffffffffff:  # UINT_MAX
        return struct.pack("<BQ", 255, v)
    raise ValueError('Value too large')


def getCompactSizeLen(v):
    # Compact Size
    if v < 253:
        return 1
    if v <= 0xffff:  # USHRT_MAX
        return 3
    if v <= 0xffffffff:  # UINT_MAX
        return 5
    if v <= 0xffffffffffffffff:  # UINT_MAX
        return 9
    raise ValueError('Value too large')


def getWitnessElementLen(v):
    return getCompactSizeLen(v) + v
