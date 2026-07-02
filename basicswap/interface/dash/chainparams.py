# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "dash",
    "ticker": "DASH",
    "message_magic": "DarkCoin Signed Message:\n",
    "blocks_target": 60 * 2.5,
    "decimal_places": 8,
    "has_csv": True,
    "has_segwit": False,
    "mainnet": {
        "rpcport": 9998,
        "pubkey_address": 76,
        "script_address": 16,
        "key_prefix": 204,
        "hrp": "",
        "bip44": 5,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 19998,
        "pubkey_address": 140,
        "script_address": 19,
        "key_prefix": 239,
        "hrp": "",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "regtest": {
        "rpcport": 18332,
        "pubkey_address": 140,
        "script_address": 19,
        "key_prefix": 239,
        "hrp": "",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
