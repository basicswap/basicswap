# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from enum import IntEnum

from basicswap.interface.part.chainparams import params as part_params
from basicswap.interface.btc.chainparams import params as btc_params
from basicswap.interface.ltc.chainparams import params as ltc_params
from basicswap.interface.doge.chainparams import params as doge_params
from basicswap.interface.dcr.chainparams import params as dcr_params
from basicswap.interface.nmc.chainparams import params as nmc_params
from basicswap.interface.xmr.chainparams import params as xmr_params
from basicswap.interface.wow.chainparams import params as wow_params
from basicswap.interface.pivx.chainparams import params as pivx_params
from basicswap.interface.dash.chainparams import params as dash_params
from basicswap.interface.firo.chainparams import params as firo_params
from basicswap.interface.nav.chainparams import params as nav_params
from basicswap.interface.bch.chainparams import params as bch_params


class Coins(IntEnum):
    PART = 1
    BTC = 2
    LTC = 3
    DCR = 4
    NMC = 5
    XMR = 6
    PART_BLIND = 7
    PART_ANON = 8
    WOW = 9
    # NDAU = 10
    PIVX = 11
    DASH = 12
    FIRO = 13
    NAV = 14
    LTC_MWEB = 15
    # ZANO = 16
    BCH = 17
    DOGE = 18


class Fiat(IntEnum):
    USD = -1
    GBP = -2
    EUR = -3


coins_without_segwit = (Coins.PIVX, Coins.DASH)
scriptless_coins = (
    Coins.XMR,
    Coins.WOW,
    Coins.PART_ANON,
    Coins.FIRO,
    Coins.DOGE,
)
xmr_based_coins = (Coins.XMR, Coins.WOW)

chainparams = {
    Coins.PART: part_params,
    Coins.BTC: btc_params,
    Coins.LTC: ltc_params,
    Coins.DCR: dcr_params,
    Coins.NMC: nmc_params,
    Coins.XMR: xmr_params,
    Coins.WOW: wow_params,
    Coins.PIVX: pivx_params,
    Coins.DASH: dash_params,
    Coins.FIRO: firo_params,
    Coins.NAV: nav_params,
    Coins.BCH: bch_params,
    Coins.DOGE: doge_params,
}

name_map = {}
ticker_map = {}
variant_ticker_map = {}


for c, params in chainparams.items():
    name_map[params["name"].lower()] = c
    ticker_map[params["ticker"].lower()] = c

# Add coin variants, eg: LTC_MWEB, PART_ANON
for c in Coins:
    if c.name.lower() in ticker_map:
        continue
    variant_ticker_map[c.name.lower()] = c


def getCoinIdFromTicker(ticker: str, inc_variant: bool = False) -> str:
    lc_ticker: str = ticker.lower()
    try:
        if inc_variant and lc_ticker in variant_ticker_map:
            return variant_ticker_map[lc_ticker]
        return ticker_map[lc_ticker]
    except Exception:
        raise ValueError(f"Unknown coin {ticker}")


def getCoinIdFromName(name: str) -> Coins:
    try:
        return name_map[name.lower()]
    except Exception:
        raise ValueError(f"Unknown coin {name}")


def isKnownCoinName(name: str) -> bool:
    return name.lower() in name_map
