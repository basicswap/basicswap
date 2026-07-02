# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


XMR_COIN = 10**12


params = {
    "name": "monero",
    "ticker": "XMR",
    "client": "xmr",
    "decimal_places": 12,
    "mainnet": {
        "rpcport": 18081,
        "walletrpcport": 18082,
        "min_amount": 1000000000,
        "max_amount": 10000000 * XMR_COIN,
        "address_prefix": 18,
        "subaddress_prefix": 42,
    },
    "testnet": {
        "rpcport": 28081,
        "walletrpcport": 28082,
        "min_amount": 1000000000,
        "max_amount": 10000000 * XMR_COIN,
        "address_prefix": 18,
        "subaddress_prefix": 42,
    },
    "regtest": {
        "rpcport": 18081,
        "walletrpcport": 18082,
        "min_amount": 1000000000,
        "max_amount": 10000000 * XMR_COIN,
        "address_prefix": 18,
        "subaddress_prefix": 42,
    },
}
