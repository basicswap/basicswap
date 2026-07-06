# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "firo",
    "ticker": "FIRO",
    "message_magic": "Zcoin Signed Message:\n",
    "blocks_target": 60 * 10,
    "decimal_places": 8,
    "has_cltv": False,
    "has_csv": False,
    "has_segwit": False,
    "has_multiwallet": False,
    "mainnet": {
        "rpcport": 8888,
        "pubkey_address": 82,
        "script_address": 7,
        "key_prefix": 210,
        "hrp": "",
        "bip44": 136,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 18888,
        "pubkey_address": 65,
        "script_address": 178,
        "key_prefix": 185,
        "hrp": "",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "regtest": {
        "rpcport": 28888,
        "pubkey_address": 65,
        "script_address": 178,
        "key_prefix": 239,
        "hrp": "",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
