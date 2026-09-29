# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json

from .basicswap_util import fiatTicker
from .chainparams import Coins, chainparams

rate_sources_ordered = ("coingecko.com",)


def getExchangeName(coin_id: int, exchange_name: str):
    # Handle coin variants that use base coin chainparams
    use_coinid = coin_id
    if coin_id == Coins.PART_ANON or coin_id == Coins.PART_BLIND:
        use_coinid = Coins.PART
    elif coin_id == Coins.LTC_MWEB:
        use_coinid = Coins.LTC

    return chainparams[use_coinid]["rate_ids"].get(exchange_name)


def fetchCoinGeckoRates(
    swap_client, coins_list, currency_to, oldest_valid_update: int
) -> dict:
    exchange_name_map = {
        exchange_name: coin_id
        for coin_id in coins_list
        if (exchange_name := getExchangeName(coin_id, "coingecko.com"))
    }
    coin_ids = ",".join(exchange_name_map)
    ticker_to = fiatTicker(currency_to).lower()
    root, headers = swap_client._coingeckoAuth()
    url = f"{root}/simple/price?ids={coin_ids}&vs_currencies={ticker_to}&include_24hr_vol=true&include_24hr_change=true&include_last_updated_at=true"

    js = json.loads(swap_client.readURL(url, timeout=5, headers=headers))

    rates = {}
    stale = []
    for k, v in js.items():
        if v.get("last_updated_at", 0) < oldest_valid_update:
            stale.append(k)
            continue
        if ticker_to not in v:
            continue
        rates[exchange_name_map[k]] = (
            v[ticker_to],
            v.get(f"{ticker_to}_24h_vol"),
            v.get(f"{ticker_to}_24h_change"),
        )
    if stale:
        swap_client.log.debug(f"Ignoring stale coingecko.com rates: {stale}")
    return rates


oracle_fetchers = {
    "coingecko.com": fetchCoinGeckoRates,
}
