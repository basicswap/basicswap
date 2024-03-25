# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


def decode_varint(b: bytes) -> int:
    i = 0
    shift = 0
    for c in b:
        i += (c & 0x7F) << shift
        shift += 7
    return i


def encode_varint(i: int) -> bytes:
    b = bytearray()
    while i > 0x7F:
        b += bytes(((i & 0x7F) | 0x80,))
        i = (i >> 7)
    b += bytes((i,))
    return b
