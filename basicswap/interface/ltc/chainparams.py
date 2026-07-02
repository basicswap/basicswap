# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "litecoin",
    "ticker": "LTC",
    "message_magic": "Litecoin Signed Message:\n",
    "blocks_target": 60 * 1,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 9332,
        "pubkey_address": 48,
        "script_address": 5,
        "script_address2": 50,
        "key_prefix": 176,
        "hrp": "ltc",
        "bip44": 2,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 19332,
        "pubkey_address": 111,
        "script_address": 196,
        "script_address2": 58,
        "key_prefix": 239,
        "hrp": "tltc",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet4",
    },
    "regtest": {
        "rpcport": 19443,
        "pubkey_address": 111,
        "script_address": 196,
        "script_address2": 58,
        "key_prefix": 239,
        "hrp": "rltc",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
