# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Arc (https://arc.io) chain parameters.

Arc is an EVM chain whose native gas currency is USDC, 18-decimal at the
protocol level like every EVM native currency.
"""

ARC_COIN = 10**8

params = {
    "name": "arc",
    "display_name": "USDC (Arc)",
    "display_ticker": "USDC",
    "ticker": "USDC_ARC",
    "rate_ids": {
        "coingecko.com": "usd-coin",
        "kraken.com": "USDCUSD",
        "coinpaprika.com": "usdc-usd-coin",
        "neroswap.com": "USDC",
    },
    "client": "arc",
    "decimal_places": 8,
    "deployments": {
        5042002: {  # testnet
            "address": "0x6c17467e7bD1FEc57ccBFcBB0E937bc82f1a75db",
            "code_hashes": {
                "66d8c64b3304957d6195a5dba374a36d7f876bda8039bb73f6997a278c6551cb": "swapfactory",
            },
        },
    },
    # USDC's ERC-20 interface; its blocklist also blocks native transfers
    "blocklist": {
        5042: "0x3600000000000000000000000000000000000000",
        5042002: "0x3600000000000000000000000000000000000000",
    },
    "blocklist_function": "isBlacklisted(address)",
    "mainnet": {
        "rpcport": 0,
        "chain_id": 5042,
        "rpc_nodes_default": [
            "https://rpc.mainnet.arc.io",
            "https://rpc.blockdaemon.mainnet.arc.io",
            "https://rpc.drpc.mainnet.arc.io",
            "https://rpc.quicknode.mainnet.arc.io",
        ],
        "min_amount": ARC_COIN // 1000,
        "max_amount": 100000 * ARC_COIN,
        "blocks_confirmed": 1,
    },
    "testnet": {
        "rpcport": 0,
        "chain_id": 5042002,
        "rpc_nodes_default": [
            "https://rpc.testnet.arc.io",
            "https://rpc.blockdaemon.testnet.arc.io",
            "https://rpc.drpc.testnet.arc.io",
            "https://rpc.quicknode.testnet.arc.io",
        ],
        "min_amount": ARC_COIN // 1000,
        "max_amount": 100000 * ARC_COIN,
        "blocks_confirmed": 1,
    },
    "regtest": {
        "rpcport": 0,
        "chain_id": 31337,
        "min_amount": ARC_COIN // 1000,
        "max_amount": 100000 * ARC_COIN,
        "blocks_confirmed": 1,
    },
}
