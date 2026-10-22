# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

params = {
    "name": "litecoin",
    "ticker": "LTC",
    "rate_ids": {
        "coingecko.com": "litecoin",
        "kraken.com": "XLTCZUSD",
        "kucoin.com": "LTC-USDT",
        "mexc.com": "LTCUSDT",
        # "coinlore.com": "1",  # no per-coin timestamp, used only where CoinPaprika is unreliable
        "coinpaprika.com": "ltc-litecoin",
        "neroswap.com": "LTC",
    },
    "message_magic": "Litecoin Signed Message:\n",
    "blocks_target": 150,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 9332,
        "pubkey_address": 48,
        "script_address": 5,
        "script_address2": 50,
        "key_prefix": 176,
        "hrp": "ltc",
        "bip44": 2,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "genesis_hash": "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2",
    },
    "testnet": {
        "rpcport": 19332,
        "pubkey_address": 111,
        "script_address": 196,
        "script_address2": 58,
        "key_prefix": 239,
        "hrp": "tltc",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet4",
        "genesis_hash": "4966625a4b2851d9fdee139e56211a0d88575f59ed816ff5e6a63deb4e3e29a0",
    },
    "regtest": {
        "rpcport": 19443,
        "pubkey_address": 111,
        "script_address": 196,
        "script_address2": 58,
        "key_prefix": 239,
        "hrp": "rltc",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "genesis_hash": "530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9",
    },
}
