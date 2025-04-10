#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util.address import b58decode


def getMsgPubkey(self, msg) -> bytes:
    if "pk_from" in msg:
        return bytes.fromhex(msg["pk_from"])
    rv = self.callrpc(
        "smsggetpubkey",
        [
            msg["from"],
        ],
    )
    return b58decode(rv["publickey"])
