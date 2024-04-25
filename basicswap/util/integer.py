# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


def decode_varint(b: bytes, offset: int = 0) -> (int, int):
    i: int = 0
    num_bytes: int = 0
    while True:
        c = b[offset + num_bytes]
        i += (c & 0x7F) << (num_bytes * 7)
        num_bytes += 1
        if not c & 0x80:
            break
        if num_bytes > 8:
            raise ValueError('Too many bytes')
    return i, num_bytes


def encode_varint(i: int) -> bytes:
    b = bytearray()
    while i > 0x7F:
        b += bytes(((i & 0x7F) | 0x80,))
        i = (i >> 7)
    b += bytes((i,))
    return b
