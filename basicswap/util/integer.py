# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


def decode_compactsize(b: bytes, offset: int = 0) -> (int, int):
    i = b[offset]
    if i < 0xFD:
        return i, 1
    offset += 1
    if i == 0xFD:
        return int.from_bytes(b[offset : offset + 2], "little"), 3
    if i == 0xFE:
        return int.from_bytes(b[offset : offset + 4], "little"), 5
    # 0xff
    return int.from_bytes(b[offset : offset + 8], "little"), 9


def encode_compactsize(i: int) -> bytes:
    if i < 0xFD:
        return bytes((i,))
    if i <= 0xFFFF:
        return bytes((0xFD,)) + i.to_bytes(2, "little")
    if i <= 0xFFFFFFFF:
        return bytes((0xFE,)) + i.to_bytes(4, "little")
    return bytes((0xFF,)) + i.to_bytes(8, "little")


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
            raise ValueError("Too many bytes")
    return i, num_bytes


def encode_varint(i: int) -> bytes:
    b = bytearray()
    while i > 0x7F:
        b += bytes(((i & 0x7F) | 0x80,))
        i = i >> 7
    b += bytes((i,))
    return b
