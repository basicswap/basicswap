# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "bitcoincash",
    "ticker": "BCH",
    "display_name": "Bitcoin Cash",
    "message_magic": "Bitcoin Signed Message:\n",
    "blocks_target": 60 * 2,
    "decimal_places": 8,
    "has_cltv": True,
    "has_csv": True,
    "has_segwit": False,
    "cli_binname": "bitcoin-cli",
    "core_binname": "bitcoind",
    "mainnet": {
        "rpcport": 8332,
        "pubkey_address": 0,
        "script_address": 5,
        "key_prefix": 128,
        "hrp": "bitcoincash",
        "bip44": 0,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 18332,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "bchtest",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet3",
    },
    "regtest": {
        "rpcport": 18443,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "bchreg",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
