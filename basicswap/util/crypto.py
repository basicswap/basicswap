# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from Crypto.Hash import RIPEMD160, SHA256  # pycryptodome
from basicswap.contrib.blake256.blake256 import blake_hash


def sha256(data: bytes) -> bytes:
    h = SHA256.new()
    h.update(data)
    return h.digest()


def ripemd160(data: bytes) -> bytes:
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()


def blake256(data: bytes) -> bytes:
    return blake_hash(data)


def hash160(s: bytes) -> bytes:
    return ripemd160(sha256(s))
