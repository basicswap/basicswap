# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from hashlib import scrypt as hashlib_scrypt


def scrypt_hash(data: bytes) -> bytes:
    return hashlib_scrypt(data, salt=data, n=1024, r=1, p=1, dklen=32)
