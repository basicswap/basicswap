# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

# Divi is a PIVX fork and shares its script capabilities:
#   CLTV yes, CSV no, segwit no, watch-only yes.
# Verified against divid v3.0.0: decodescript on 0xb1 returns
# OP_CHECKLOCKTIMEVERIFY, on 0xb2 returns OP_NOP3 (so no CSV), and v0 witness
# programs decode as "nonstandard" (so no segwit).  Coins.DIVI is therefore
# listed in coins_without_segwit, as PIVX and Dash are.
#
# The rpcports below are deliberately NOT divid's defaults.  Divi forked PIVX
# without changing them, so divid defaults to 51473/51475 - exactly the ports
# the PIVX entry already uses.  Basicswap writes rpcport into each managed
# coin's config file, so picking free numbers here avoids the clash.

params = {
    "name": "divi",
    "ticker": "DIVI",
    "rate_ids": {
        "coingecko.com": "divi",
        # "kraken.com": N/A  # not listed on Kraken
        # "kucoin.com": N/A  # not listed on KuCoin
        # "mexc.com": N/A  # DIVIUSDT returns "invalid symbol"
        # "coinlore.com": N/A  # not listed
        # "neroswap.com": N/A  # not listed on neroswap
    },
    "display_name": "Divi",
    # Inherited from the PIVX/Dash lineage, identical string by descent.
    "message_magic": "DarkNet Signed Message:\n",
    "blocks_target": 60 * 1,
    "decimal_places": 8,
    "has_cltv": True,
    "has_csv": False,
    "has_segwit": False,
    "mainnet": {
        "rpcport": 51873,  # divid default is 51473, taken by PIVX
        "pubkey_address": 30,
        "script_address": 13,
        "key_prefix": 212,
        "bip44": 119,  # Divi ships PIVX's coin type, not SLIP-44's 301
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x022D2533,
        "ext_secret_key_prefix": 0x0221312B,
    },
    "testnet": {
        "rpcport": 51875,  # divid default is 51475, taken by PIVX
        "pubkey_address": 139,
        "script_address": 19,
        "key_prefix": 239,
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet3",
        "ext_public_key_prefix": 0x3A8061A0,
        "ext_secret_key_prefix": 0x3A805837,
    },
    "regtest": {
        "rpcport": 51877,
        "pubkey_address": 139,
        "script_address": 19,
        "key_prefix": 239,
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "ext_public_key_prefix": 0x3A8061A0,
        "ext_secret_key_prefix": 0x3A805837,
    },
}
