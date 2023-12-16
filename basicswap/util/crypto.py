# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from Crypto.Hash import RIPEMD160, SHA256  # pycryptodome


def sha256(data):
    h = SHA256.new()
    h.update(data)
    return h.digest()


def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()


def hash160(s):
    return ripemd160(sha256(s))
