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
    # Swap contract per chain id; code_hashes maps every past keccak256 to its
    # design so in-flight swaps can settle
    "deployments": {
        988: {  # mainnet
            "address": "0x7df19AD2321ad2dA0F20e9c1d51378D9eb100eA6",
            "code_hashes": {
                "5860dfbd5ce5b422d1aa1e5491be4feedeabc21bb9ead50a11359c144ed1dac7": "swapfactory",
            },
        },
        2201: {  # testnet
            "address": "0x910a3801EEf5D50103396E9739d9FD0b7Cb3683D",
            "code_hashes": {
                "5860dfbd5ce5b422d1aa1e5491be4feedeabc21bb9ead50a11359c144ed1dac7": "swapfactory",
            },
        },
    },
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
            "https://stable.gateway.tenderly.co",
            "https://stable.drpc.org",
        ],
        "min_amount": STABLE_COIN,
        "max_amount": 15000 * STABLE_COIN,
        "blocks_confirmed": 2,
    },
    "testnet": {
        "rpcport": 0,
        "chain_id": 2201,
        "rpc_nodes_default": [
            "https://rpc.testnet.stable.xyz",
            "https://stable-testnet-evm-rpc.publicnode.com",
        ],
        "min_amount": STABLE_COIN,
        "max_amount": 100000 * STABLE_COIN,
        "blocks_confirmed": 2,
    },
    "regtest": {
        "rpcport": 0,
        "chain_id": 31337,  # anvil default
        "min_amount": STABLE_COIN,
        "max_amount": 100000 * STABLE_COIN,
        "blocks_confirmed": 1,
    },
}
