# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

# Values from src/kernel/chainparams.cpp and src/chainparamsbase.cpp of
# TrueNorth Core, https://github.com/truenorth-project/truenorth
params = {
    "name": "truenorth",
    "display_name": "TrueNorth",
    "ticker": "NORTH",
    "rate_ids": {},  # Not listed on any of the rate sources
    "message_magic": "TrueNorth Signed Message:\n",
    "blocks_target": 60 * 2,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 9554,
        "pubkey_address": 53,
        "script_address": 65,
        "key_prefix": 180,
        "hrp": "north",
        "bip44": 1867,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x7E5D5A83,
        "ext_secret_key_prefix": 0x7E5C6544,
    },
    "testnet": {
        # The public TrueNorth test network is testnet4
        "rpcport": 49554,
        "pubkey_address": 126,
        "script_address": 17,
        "key_prefix": 254,
        "hrp": "tnorth4",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet4",
        "cli_chain_arg": "-testnet4",
        "ext_public_key_prefix": 0x043587CD,
        "ext_secret_key_prefix": 0x04358392,
    },
    "regtest": {
        "rpcport": 18443,
        "pubkey_address": 122,
        "script_address": 123,
        "key_prefix": 252,
        "hrp": "rnorth",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x043587CB,
        "ext_secret_key_prefix": 0x04358390,
    },
}
