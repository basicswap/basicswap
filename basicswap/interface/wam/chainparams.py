# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "wam",
    "ticker": "WAM",
    "message_magic": "WAM Coin Signed Message:\n",
    "blocks_target": 60 * 2,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 9554,
        "pubkey_address": 73,
        "script_address": 135,
        "key_prefix": 190,
        "hrp": "wam",
        # 0x57414D, which is "WAM" in ASCII. Not invented: wamd already derives
        # here -- listdescriptors returns 44h/5718349h -- so this describes the
        # wallet rather than asking for something.
        #
        # Registered, not merely claimed: satoshilabs/slips PR #2051 was merged
        # into master on 2026-08-26, so 5718349 is reserved to this chain in
        # SLIP-0044 and the prefixes wam / twam / wamrt in SLIP-0173.
        #
        # It is still decided in exactly one place -- WAM_BIP44_COIN_TYPE in
        # src/wam/wam-params.h -- and scripts/audit_repo.sh rejects any file
        # here that disagrees with it.
        "bip44": 5718349,
        "min_amount": 100000,
        "max_amount": 1000000 * COIN,
    },
    "testnet": {
        "rpcport": 19554,
        "pubkey_address": 65,
        "script_address": 128,
        "key_prefix": 239,
        "hrp": "twam",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 1000000 * COIN,
        "name": "testnet3",
    },
    "regtest": {
        "rpcport": 29554,
        "pubkey_address": 65,
        "script_address": 128,
        "key_prefix": 239,
        "hrp": "wamrt",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 1000000 * COIN,
    },
}
