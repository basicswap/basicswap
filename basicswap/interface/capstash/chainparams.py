# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN


params = {
    "name": "capstash",
    "display_name": "CapStash",
    # Provisional: CapStash Core does not declare an authoritative exchange ticker.
    "ticker": "CAPS",
    "message_magic": "CapStash Signed Message:\n",
    "blocks_target": 60,
    "decimal_places": 8,
    "core_binname": "CapStashd",
    "cli_binname": "CapStash-cli",
    "mainnet": {
        "rpcport": 8332,
        "pubkey_address": 28,
        "script_address": 18,
        "key_prefix": 156,
        "hrp": "cap",
        # No authoritative SLIP-0044 assignment is known. Mainnet descriptor
        # wallet initialisation is deliberately blocked by CapStashInterface.
        "bip44": None,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x03464B57,
        "ext_secret_key_prefix": 0x03464B50,
    },
    "testnet": {
        "rpcport": 18332,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "tcap",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "test",
        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
    },
    "regtest": {
        "rpcport": 18443,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "rcap",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
    },
}
