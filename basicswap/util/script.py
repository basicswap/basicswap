# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import struct
from basicswap.contrib.test_framework.script import (
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_PUSHDATA4,
    CScriptInvalidError,
    CScriptTruncatedPushDataError,
)
from basicswap.script import OpCodes


def decodeScriptNum(script_bytes, o):
    v = 0
    num_len = script_bytes[o]
    if num_len >= OpCodes.OP_1 and num_len <= OpCodes.OP_16:
        return ((num_len - OpCodes.OP_1) + 1, 1)

    if num_len > 4:
        raise ValueError("Bad scriptnum length")  # Max 4 bytes
    if num_len + o >= len(script_bytes):
        raise ValueError("Bad script length")
    o += 1
    for i in range(num_len):
        b = script_bytes[o + i]
        # Negative flag set in last byte, if num is positive and > 0x80 an extra 0x00 byte will be appended
        if i == num_len - 1 and b & 0x80:
            b &= ~(0x80) & 0xFF
            v += int(b) << 8 * i
            v *= -1
        else:
            v += int(b) << 8 * i
    return (v, 1 + num_len)


def decodePushData(script_bytes, o):
    datasize = None
    pushdata_type = None
    i = o
    opcode = script_bytes[i]
    i += 1

    if opcode < OP_PUSHDATA1:
        pushdata_type = "PUSHDATA(%d)" % opcode
        datasize = opcode

    elif opcode == OP_PUSHDATA1:
        pushdata_type = "PUSHDATA1"
        if i >= len(script_bytes):
            raise CScriptInvalidError("PUSHDATA1: missing data length")
        datasize = script_bytes[i]
        i += 1

    elif opcode == OP_PUSHDATA2:
        pushdata_type = "PUSHDATA2"
        if i + 1 >= len(script_bytes):
            raise CScriptInvalidError("PUSHDATA2: missing data length")
        datasize = script_bytes[i] + (script_bytes[i + 1] << 8)
        i += 2

    elif opcode == OP_PUSHDATA4:
        pushdata_type = "PUSHDATA4"
        if i + 3 >= len(script_bytes):
            raise CScriptInvalidError("PUSHDATA4: missing data length")
        datasize = (
            script_bytes[i]
            + (script_bytes[i + 1] << 8)
            + (script_bytes[i + 2] << 16)
            + (script_bytes[i + 3] << 24)
        )
        i += 4

    else:
        assert False  # shouldn't happen

    data = bytes(script_bytes[i : i + datasize])

    # Check for truncation
    if len(data) < datasize:
        raise CScriptTruncatedPushDataError("%s: truncated data" % pushdata_type, data)

    # return data and the number of bytes to skip forward
    return (data, i + datasize - o)


def SerialiseNumCompact(v):
    if v < 253:
        return bytes((v,))
    if v <= 0xFFFF:  # USHRT_MAX
        return struct.pack("<BH", 253, v)
    if v <= 0xFFFFFFFF:  # UINT_MAX
        return struct.pack("<BI", 254, v)
    if v <= 0xFFFFFFFFFFFFFFFF:  # UINT_MAX
        return struct.pack("<BQ", 255, v)
    raise ValueError("Value too large")


def getCompactSizeLen(v):
    # Compact Size
    if v < 253:
        return 1
    if v <= 0xFFFF:  # USHRT_MAX
        return 3
    if v <= 0xFFFFFFFF:  # UINT_MAX
        return 5
    if v <= 0xFFFFFFFFFFFFFFFF:  # UINT_MAX
        return 9
    raise ValueError("Value too large")


def getWitnessElementLen(v):
    return getCompactSizeLen(v) + v
