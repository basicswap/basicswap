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
        5042: {  # mainnet
            "address": "0x7df19AD2321ad2dA0F20e9c1d51378D9eb100eA6",
            "code_hashes": {
                "5860dfbd5ce5b422d1aa1e5491be4feedeabc21bb9ead50a11359c144ed1dac7": "swapfactory",
            },
        },
        5042002: {  # testnet
            "address": "0xC7CA49c43A74670115AAD78fb8423fa39E89d8Bb",
            "code_hashes": {
                "5860dfbd5ce5b422d1aa1e5491be4feedeabc21bb9ead50a11359c144ed1dac7": "swapfactory",
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
            "https://arc.drpc.org",
            "https://arc.gateway.tenderly.co",
        ],
        "min_amount": ARC_COIN,
        "max_amount": 15000 * ARC_COIN,
        "blocks_confirmed": 1,
    },
    "testnet": {
        "rpcport": 0,
        "chain_id": 5042002,
        "rpc_nodes_default": [
            "https://rpc.testnet.arc.io",
            "https://rpc.blockdaemon.testnet.arc.io",
            "https://arc-testnet.drpc.org",
            "https://arc-testnet.gateway.tenderly.co",
        ],
        "min_amount": ARC_COIN,
        "max_amount": 100000 * ARC_COIN,
        "blocks_confirmed": 1,
    },
    "regtest": {
        "rpcport": 0,
        "chain_id": 31337,
        "min_amount": ARC_COIN,
        "max_amount": 100000 * ARC_COIN,
        "blocks_confirmed": 1,
    },
}
