# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "particl",
    "ticker": "PART",
    "message_magic": "Bitcoin Signed Message:\n",
    "blocks_target": 60 * 2,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 51735,
        "pubkey_address": 0x38,
        "script_address": 0x3C,
        "key_prefix": 0x6C,
        "stealth_key_prefix": 0x14,
        "hrp": "pw",
        "bip44": 44,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x696E82D1,
        "ext_secret_key_prefix": 0x8F1DAEB8,
    },
    "testnet": {
        "rpcport": 51935,
        "pubkey_address": 0x76,
        "script_address": 0x7A,
        "key_prefix": 0x2E,
        "stealth_key_prefix": 0x15,
        "hrp": "tpw",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0xE1427800,
        "ext_secret_key_prefix": 0x04889478,
    },
    "regtest": {
        "rpcport": 51936,
        "pubkey_address": 0x76,
        "script_address": 0x7A,
        "key_prefix": 0x2E,
        "stealth_key_prefix": 0x15,
        "hrp": "rtpw",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0xE1427800,
        "ext_secret_key_prefix": 0x04889478,
    },
}
