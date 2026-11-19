# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


ETH_COIN = 10**8

params = {
    "name": "ethereum",
    "ticker": "ETH",
    "rate_ids": {
        "coingecko.com": "ethereum",
        "kraken.com": "XETHZUSD",
        "kucoin.com": "ETH-USDT",
        "mexc.com": "ETHUSDT",
        # "coinlore.com": "80",  # no per-coin timestamp, used only where CoinPaprika is unreliable
        "coinpaprika.com": "eth-ethereum",
        "neroswap.com": "ETH",
    },
    "client": "eth",
    "decimal_places": 8,
    "deployments": {},
    "mainnet": {
        "rpcport": 8545,
        "rpc_nodes_default": [
            "https://ethereum-rpc.publicnode.com",
            "https://eth2.stackwallet.com",
        ],
        "chain_id": 1,
        "min_amount": ETH_COIN // 1000,
        "max_amount": 1000 * ETH_COIN,
        "blocks_confirmed": 4,
    },
    "testnet": {
        "rpcport": 8545,
        "rpc_nodes_default": ["https://ethereum-sepolia-rpc.publicnode.com"],
        "chain_id": 11155111,  # Sepolia
        "min_amount": ETH_COIN // 1000,
        "max_amount": 1000 * ETH_COIN,
        "blocks_confirmed": 4,
    },
    "regtest": {
        "rpcport": 8545,
        "chain_id": 31337,  # anvil default
        "min_amount": ETH_COIN // 1000,
        "max_amount": 1000 * ETH_COIN,
        "blocks_confirmed": 1,
    },
}
