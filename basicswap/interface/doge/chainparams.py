# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "dogecoin",
    "ticker": "DOGE",
    "message_magic": "Dogecoin Signed Message:\n",
    "blocks_target": 60 * 1,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 22555,
        "pubkey_address": 30,
        "script_address": 22,
        "key_prefix": 158,
        "hrp": "doge",
        "bip44": 3,
        "min_amount": 100000,  # TODO increase above fee
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 44555,
        "pubkey_address": 113,
        "script_address": 196,
        "key_prefix": 241,
        "hrp": "tdge",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet4",
    },
    "regtest": {
        "rpcport": 18332,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "rdge",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
