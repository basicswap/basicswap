# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from Crypto.Hash import RIPEMD160  # pycryptodome


def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()
