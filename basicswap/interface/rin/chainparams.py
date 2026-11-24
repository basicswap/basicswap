# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

# Values from Rincoin Core v1.1.0: src/chainparams.cpp, src/chainparamsbase.cpp
# and src/util/message.cpp.
params = {
    "name": "rincoin",
    "ticker": "RIN",
    "rate_ids": {},
    "message_magic": "rincoin Signed Message:\n",
    "blocks_target": 60,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 9556,
        "pubkey_address": 60,
        "script_address": 122,
        "script_address2": 50,
        "key_prefix": 188,
        "hrp": "rin",
        "bip44": 9555,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x0488B21E,
        "ext_secret_key_prefix": 0x0488ADE4,
        "genesis_hash": "000096bdd6e4613ca89b074ebd6f609aba6fe3f868b34ee79380aa3bc7a8c9db",
    },
    "testnet": {
        "rpcport": 19556,
        "pubkey_address": 65,
        "script_address": 127,
        "script_address2": 50,
        "key_prefix": 209,
        "hrp": "trin",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet4",
        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
        "genesis_hash": "00009d5fbc8579e8b4292f1bab22437d9468c0cc615cb5b0242d8159b31760ad",
    },
    "regtest": {
        "rpcport": 29556,
        "pubkey_address": 111,
        "script_address": 196,
        "script_address2": 58,
        "key_prefix": 239,
        "hrp": "rrin",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
        "genesis_hash": "7d2c8c57ce2597f86c9fe41f9865ad664b04d2aad4321fdaab48ed3da1805fe7",
    },
}
