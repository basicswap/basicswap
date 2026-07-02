# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "namecoin",
    "ticker": "NMC",
    "message_magic": "Namecoin Signed Message:\n",
    "blocks_target": 60 * 10,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 8336,
        "pubkey_address": 52,
        "script_address": 13,
        "key_prefix": 180,
        "hrp": "nc",
        "bip44": 7,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x0488B21E,  # base58Prefixes[EXT_PUBLIC_KEY]
        "ext_secret_key_prefix": 0x0488ADE4,
    },
    "testnet": {
        "rpcport": 18336,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "tn",
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
        "hrp": "ncrt",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
    },
}
