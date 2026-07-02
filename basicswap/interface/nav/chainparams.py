# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "navcoin",
    "ticker": "NAV",
    "message_magic": "Navcoin Signed Message:\n",
    "blocks_target": 30,
    "decimal_places": 8,
    "has_csv": True,
    "has_segwit": True,
    "has_multiwallet": False,
    "mainnet": {
        "rpcport": 44444,
        "pubkey_address": 53,
        "script_address": 85,
        "key_prefix": 150,
        "hrp": "",
        "bip44": 130,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 44445,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "regtest": {
        "rpcport": 44446,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
