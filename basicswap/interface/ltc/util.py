# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from hashlib import scrypt as hashlib_scrypt
from basicswap.util.merkle import header_bits, target_from_bits


def scrypt_hash(data: bytes) -> bytes:
    return hashlib_scrypt(data, salt=data, n=1024, r=1, p=1, dklen=32)


def check_header_pow_scrypt(header_bytes: bytes) -> bool:
    target = target_from_bits(header_bits(header_bytes))
    if target <= 0:
        return False
    pow_hash = int.from_bytes(scrypt_hash(header_bytes), "little")
    return pow_hash <= target
