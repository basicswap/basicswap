# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "bitcoin",
    "ticker": "BTC",
    "message_magic": "Bitcoin Signed Message:\n",
    "blocks_target": 60 * 10,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 8332,
        "pubkey_address": 0,
        "script_address": 5,
        "key_prefix": 128,
        "hrp": "bc",
        "bip44": 0,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x0488B21E,
        "ext_secret_key_prefix": 0x0488ADE4,
    },
    "testnet": {
        "rpcport": 18332,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "tb",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet3",
        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
    },
    "regtest": {
        "rpcport": 18443,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "bcrt",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
    },
}
