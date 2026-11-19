# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Stable (https://stable.xyz) chain parameters.

Stable is an EVM chain whose native gas currency is USDT0.  Like every EVM
chain the native currency is 18-decimal at the protocol level, so the
settlement math is identical to ETH.
"""

STABLE_COIN = 10**8

params = {
    "name": "stable",
    "display_name": "USDT0 (Stable)",
    "display_ticker": "USDT0",
    "ticker": "USDT0_STABLE",
    "rate_ids": {
        "coingecko.com": "tether",
        "kraken.com": "USDTZUSD",
        # "kucoin.com": "USDT-USDC",  # quoted in USDC; rates here are taken as USDT
        # "mexc.com": N/A  # only USDCUSDT, the inverse
        # "coinlore.com": "518",  # no per-coin timestamp, used only where CoinPaprika is unreliable
        "coinpaprika.com": "usdt-tether",
        "neroswap.com": "USDT",
    },
    "client": "stable",
    "decimal_places": 8,
    # SwapCreator per chain id; code_hashes keeps every past keccak256 so in-flight swaps can settle
    "deployments": {},
    # USDT0 per chain id; its blocklist can freeze native balances
    "blocklist": {
        988: "0x779Ded0c9e1022225f8E0630b35a9b54bE713736",
        2201: "0x78Cf24370174180738C5B8E352B6D14c83a6c9A9",
    },
    "blocklist_function": "isBlocked(address)",
    "mainnet": {
        "rpcport": 0,  # external JSON-RPC node, no managed port
        "chain_id": 988,
        "rpc_nodes_default": [
            "https://rpc.stable.xyz",
            "https://stable-evm-rpc.publicnode.com",
        ],
        "min_amount": STABLE_COIN // 1000,
        "max_amount": 100000 * STABLE_COIN,
        "blocks_confirmed": 2,
    },
    "testnet": {
        "rpcport": 0,
        "chain_id": 2201,
        "rpc_nodes_default": [
            "https://rpc.testnet.stable.xyz",
            "https://stable-testnet-evm-rpc.publicnode.com",
        ],
        "min_amount": STABLE_COIN // 1000,
        "max_amount": 100000 * STABLE_COIN,
        "blocks_confirmed": 2,
    },
    "regtest": {
        "rpcport": 0,
        "chain_id": 31337,  # anvil default
        "min_amount": STABLE_COIN // 1000,
        "max_amount": 100000 * STABLE_COIN,
        "blocks_confirmed": 1,
    },
}
