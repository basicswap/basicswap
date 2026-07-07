# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


WOW_COIN = 10**11


params = {
    "name": "wownero",
    "ticker": "WOW",
    "client": "wow",
    "decimal_places": 11,
    "mainnet": {
        "rpcport": 34568,
        "walletrpcport": 34572,  # todo
        "min_amount": 100000000,
        "max_amount": 10000000 * WOW_COIN,
        "address_prefix": 4146,
        "subaddress_prefix": 12208,
    },
    "testnet": {
        "rpcport": 44568,
        "walletrpcport": 44572,
        "min_amount": 100000000,
        "max_amount": 10000000 * WOW_COIN,
        "address_prefix": 4146,
        "subaddress_prefix": 12208,
    },
    "regtest": {
        "rpcport": 54568,
        "walletrpcport": 54572,
        "min_amount": 100000000,
        "max_amount": 10000000 * WOW_COIN,
        "address_prefix": 4146,
        "subaddress_prefix": 12208,
    },
}
