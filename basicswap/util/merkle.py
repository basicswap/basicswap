# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import struct

from hashlib import sha256 as _hashlib_sha256


def _double_sha256(data: bytes) -> bytes:
    return _hashlib_sha256(_hashlib_sha256(data).digest()).digest()


def electrum_merkle_root(txid_hex: str, branch: list, tx_pos: int) -> bytes:
    current = bytes.fromhex(txid_hex)[::-1]
    pos = tx_pos
    for sibling_hex in branch:
        sibling = bytes.fromhex(sibling_hex)[::-1]
        if pos & 1:
            current = _double_sha256(sibling + current)
        else:
            current = _double_sha256(current + sibling)
        pos >>= 1
    return current


def parse_header_merkle_root(header_bytes: bytes) -> bytes:
    if len(header_bytes) < 80:
        raise ValueError("Block header too short")
    return header_bytes[36:68]


def header_bits(header_bytes: bytes) -> int:
    if len(header_bytes) < 80:
        raise ValueError("Block header too short")
    return struct.unpack("<I", header_bytes[72:76])[0]


def target_from_bits(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def check_header_pow(header_bytes: bytes) -> bool:
    target = target_from_bits(header_bits(header_bytes))
    if target <= 0:
        return False
    block_hash = int.from_bytes(_double_sha256(header_bytes), "little")
    return block_hash <= target


def verify_tx_merkle_proof(
    txid_hex: str,
    header_bytes: bytes,
    branch: list,
    tx_pos: int,
    require_pow: bool = True,
) -> bool:
    if require_pow and not check_header_pow(header_bytes):
        return False
    computed_root = electrum_merkle_root(txid_hex, branch, tx_pos)
    return computed_root == parse_header_merkle_root(header_bytes)
