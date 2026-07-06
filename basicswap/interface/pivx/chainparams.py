# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "pivx",
    "ticker": "PIVX",
    "display_name": "PIVX",
    "message_magic": "DarkNet Signed Message:\n",
    "blocks_target": 60 * 1,
    "decimal_places": 8,
    "has_cltv": True,
    "has_csv": False,
    "has_segwit": False,
    "mainnet": {
        "rpcport": 51473,
        "pubkey_address": 30,
        "script_address": 13,
        "key_prefix": 212,
        "bip44": 119,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 51475,
        "pubkey_address": 139,
        "script_address": 19,
        "key_prefix": 239,
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet4",
    },
    "regtest": {
        "rpcport": 51477,
        "pubkey_address": 139,
        "script_address": 19,
        "key_prefix": 239,
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
