# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "decred",
    "ticker": "DCR",
    "message_magic": "Decred Signed Message:\n",
    "blocks_target": 60 * 5,
    "decimal_places": 8,
    "has_multiwallet": False,
    "mainnet": {
        "rpcport": 9109,
        "pubkey_address": 0x073F,
        "script_address": 0x071A,
        "key_prefix": 0x22DE,
        "bip44": 42,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 19109,
        "pubkey_address": 0x0F21,
        "script_address": 0x0EFC,
        "key_prefix": 0x230E,
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet3",
    },
    "regtest": {  # simnet
        "rpcport": 18656,
        "pubkey_address": 0x0E91,
        "script_address": 0x0E6C,
        "key_prefix": 0x2307,
        "bip44": 115,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
