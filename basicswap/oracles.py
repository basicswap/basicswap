# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import datetime as dt
import json
import urllib.error

from .basicswap_util import fiatTicker
from .chainparams import Coins, Fiat, chainparams
from .util import ensure

rate_sources_ordered = (
    "coingecko.com",
    "kraken.com",
    "kucoin.com",
    "mexc.com",
    "coinlore.com",
    "coinpaprika.com",
    "neroswap.com",
)


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


def fetchKrakenRates(
    swap_client, coins_list, currency_to, oldest_valid_update: int
) -> dict:
    ensure(currency_to == Fiat.USD, "Kraken rates are USD only")
    headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}
    pair_map = {
        pair: c for c in coins_list if (pair := getExchangeName(c, "kraken.com"))
    }
    if not pair_map:
        return {}

    url = f"https://api.kraken.com/0/public/Ticker?pair={','.join(pair_map)}"
    js = json.loads(swap_client.readURL(url, timeout=5, headers=headers))
    ensure(not js.get("error"), f"Kraken error: {js.get('error')}")

    rates = {}
    for pair, v in js["result"].items():
        if pair not in pair_map:
            continue
        price = float(v["c"][0])
        rates[pair_map[pair]] = (price, float(v["v"][1]) * price, None)
    return rates


def fetchKuCoinRates(
    swap_client, coins_list, currency_to, oldest_valid_update: int
) -> dict:
    ensure(currency_to == Fiat.USD, "KuCoin rates are USDT only")
    headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}

    rates = {}
    for coin_id in coins_list:
        symbol = getExchangeName(coin_id, "kucoin.com")
        if symbol is None:
            continue
        url = f"https://api.kucoin.com/api/v1/market/stats?symbol={symbol}"
        try:
            js = json.loads(swap_client.readURL(url, timeout=5, headers=headers))
        except urllib.error.HTTPError as e:
            if swap_client.isRateLimitError(e):
                raise
            swap_client.log.debug(f"kucoin.com rate for {symbol} failed: {e}")
            continue
        data = js.get("data") or {}
        if data.get("last") is None:
            continue
        rates[coin_id] = (
            float(data["last"]),
            data.get("volValue"),
            (
                float(data["changeRate"]) * 100
                if data.get("changeRate") is not None
                else None
            ),
        )
    return rates


def fetchMexcRates(
    swap_client, coins_list, currency_to, oldest_valid_update: int
) -> dict:
    ensure(currency_to == Fiat.USD, "MEXC rates are USDT only")
    headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}

    rates = {}
    for coin_id in coins_list:
        symbol = getExchangeName(coin_id, "mexc.com")
        if symbol is None:
            continue
        url = f"https://api.mexc.com/api/v3/ticker/24hr?symbol={symbol}"
        try:
            js = json.loads(swap_client.readURL(url, timeout=5, headers=headers))
        except urllib.error.HTTPError as e:
            if swap_client.isRateLimitError(e):
                raise
            swap_client.log.debug(f"mexc.com rate for {symbol} failed: {e}")
            continue
        if js.get("lastPrice") is None:
            continue
        rates[coin_id] = (
            float(js["lastPrice"]),
            js.get("quoteVolume"),
            (
                float(js["priceChangePercent"]) * 100
                if js.get("priceChangePercent") is not None
                else None
            ),
        )
    return rates


def fetchCoinLoreRates(
    swap_client, coins_list, currency_to, oldest_valid_update: int
) -> dict:
    ensure(currency_to == Fiat.USD, "CoinLore rates are USD only")
    headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}
    id_map = {
        coinlore_id: c
        for c in coins_list
        if (coinlore_id := getExchangeName(c, "coinlore.com"))
    }
    if not id_map:
        return {}

    url = f"https://api.coinlore.net/api/ticker/?id={','.join(id_map)}"
    js = json.loads(swap_client.readURL(url, timeout=5, headers=headers))

    rates = {}
    for v in js:
        if v.get("id") not in id_map or v.get("price_usd") is None:
            continue
        rates[id_map[v["id"]]] = (
            float(v["price_usd"]),
            v.get("volume24"),
            v.get("percent_change_24h"),
        )
    return rates


def fetchCoinPaprikaRates(
    swap_client, coins_list, currency_to, oldest_valid_update: int
) -> dict:
    headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}
    ticker_to = fiatTicker(currency_to)

    rates = {}
    stale = []
    for coin_id in coins_list:
        paprika_id = getExchangeName(coin_id, "coinpaprika.com")
        if paprika_id is None:
            continue
        url = f"https://api.coinpaprika.com/v1/tickers/{paprika_id}?quotes={ticker_to}"
        try:
            js = json.loads(swap_client.readURL(url, timeout=5, headers=headers))
        except urllib.error.HTTPError as e:
            if swap_client.isRateLimitError(e):
                raise
            swap_client.log.debug(f"coinpaprika.com rate for {paprika_id} failed: {e}")
            continue
        if (
            dt.datetime.fromisoformat(js["last_updated"]).timestamp()
            < oldest_valid_update
        ):
            stale.append(paprika_id)
            continue
        quote = js["quotes"][ticker_to]
        rates[coin_id] = (
            quote["price"],
            quote["volume_24h"],
            quote["percent_change_24h"],
        )
    if stale:
        swap_client.log.debug(f"Ignoring stale coinpaprika.com rates: {stale}")
    return rates


def fetchNeroswapRates(
    swap_client, coins_list, currency_to, oldest_valid_update: int
) -> dict:
    ensure(currency_to == Fiat.USD, "neroswap rates are USD only")
    headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}
    js = json.loads(
        swap_client.readURL(
            "https://prices.neroswap.com/v1/prices", timeout=5, headers=headers
        )
    )
    if dt.datetime.fromisoformat(js["fetched_at"]).timestamp() < oldest_valid_update:
        swap_client.log.debug(f"Ignoring stale neroswap.com rates: {js['fetched_at']}")
        return {}

    rates = {}
    for coin_id in coins_list:
        symbol = getExchangeName(coin_id, "neroswap.com")
        if symbol in js["rates"]:
            rates[coin_id] = (float(js["rates"][symbol]), None, None)
    return rates


oracle_fetchers = {
    "coingecko.com": fetchCoinGeckoRates,
    "kraken.com": fetchKrakenRates,
    "kucoin.com": fetchKuCoinRates,
    "mexc.com": fetchMexcRates,
    "coinlore.com": fetchCoinLoreRates,
    "coinpaprika.com": fetchCoinPaprikaRates,
    "neroswap.com": fetchNeroswapRates,
}
