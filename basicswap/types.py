# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


class WatchedOutput:  # Watch for spends
    __slots__ = ("bid_id", "txid_hex", "vout", "tx_type", "swap_type")

    def __init__(self, bid_id: bytes, txid_hex: str, vout, tx_type, swap_type):
        self.bid_id = bid_id
        self.txid_hex = txid_hex
        self.vout = vout
        self.tx_type = tx_type
        self.swap_type = swap_type


class WatchedScript:  # Watch for txns containing outputs
    __slots__ = ("bid_id", "script", "tx_type", "swap_type", "ignored_outputs")

    def __init__(self, bid_id: bytes, script: bytes, tx_type, swap_type):
        self.bid_id = bid_id
        self.script = script
        self.tx_type = tx_type
        self.swap_type = swap_type
        self.ignored_outputs = set()


class WatchedTransaction:
    __slots__ = (
        "bid_id",
        "coin_type",
        "txid_hex",
        "tx_type",
        "swap_type",
        "block_hash",
        "depth",
    )

    # TODO
    # Watch for presence in mempool (getrawtransaction)
    def __init__(
        self, bid_id: bytes, coin_type: int, txid_hex: str, tx_type, swap_type
    ):
        self.bid_id = bid_id
        self.coin_type = coin_type
        self.txid_hex = txid_hex
        self.tx_type = tx_type
        self.swap_type = swap_type
        self.block_hash = None
        self.depth = -1
