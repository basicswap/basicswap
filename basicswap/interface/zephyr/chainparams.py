# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


ZEPH_COIN = 10**12  # Zephyr: 12 decimal places, same as Monero


# Address prefixes are the CryptoNote base58 tags from Zephyr's cryptonote_config.h.
params = {
    "name": "zephyr",
    "ticker": "ZEPH",
    "client": "zephyr",
    "decimal_places": 12,
    "mainnet": {
        "rpcport": 17767,
        "walletrpcport": 17768,
        "min_amount": 1000000000,
        "max_amount": 10000000 * ZEPH_COIN,
        "address_prefix": 0x6241D18C0,  # ZEPHYR
        "subaddress_prefix": 0x8DD58C0,  # ZEPHs
    },
    "testnet": {
        "rpcport": 27767,
        "walletrpcport": 27768,
        "min_amount": 1000000000,
        "max_amount": 10000000 * ZEPH_COIN,
        "address_prefix": 0x334E41,  # ZPHT
        "subaddress_prefix": 0xF1FCE41,  # ZPHts
    },
    "regtest": {
        "rpcport": 18081,
        "walletrpcport": 18083,
        "min_amount": 1000000000,
        "max_amount": 10000000 * ZEPH_COIN,
        "address_prefix": 0x6241D18C0,  # fakechain uses the mainnet prefix
        "subaddress_prefix": 0x8DD58C0,  # ZEPHs
    },
}
