# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


WOW_COIN = 10**11


params = {
    "name": "wownero",
    "ticker": "WOW",
    "rate_ids": {
        # "coingecko.com": "wownero",  # last updated 2025-09-08, 4x the market price
        # "kraken.com": N/A  # not listed on Kraken
        # "kucoin.com": N/A  # not listed on KuCoin
        # "mexc.com": N/A  # not listed on MEXC
        # "coinlore.com": "36551",  # zero volume market that only tracks BTC
        # "coinpaprika.com": "wow-wownero",  # inactive on CoinPaprika, no ticker
        "neroswap.com": "WOW",
    },
    "client": "wow",
    "blocks_target": 60 * 5,
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
