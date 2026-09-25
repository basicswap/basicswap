"""Handshake network and monetary parameters for the native HSRD backend."""

from . import HNS_COIN, HNS_MAX_MONEY

params = {
    "name": "handshake",
    "ticker": "HNS",
    "blocks_target": 10 * 60,
    "decimal_places": 6,
    "has_segwit": True,
    "has_csv": True,
    "mainnet": {
        "rpcport": 12037,
        "hrp": "hs",
        "bip44": 5353,
        "min_amount": HNS_COIN,
        "max_amount": HNS_MAX_MONEY,
    },
    "testnet": {
        "rpcport": 13037,
        "hrp": "ts",
        "bip44": 5353,
        "min_amount": HNS_COIN,
        "max_amount": HNS_MAX_MONEY,
    },
    "regtest": {
        "rpcport": 14037,
        "hrp": "rs",
        "bip44": 5353,
        "min_amount": HNS_COIN,
        "max_amount": HNS_MAX_MONEY,
    },
}
