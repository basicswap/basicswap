#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import os
import sqlite3
import tempfile
import unittest

from basicswap.chainparams import Coins
from basicswap.wallet_manager import WalletManager


class FakeSwapClient:
    def __init__(self, sqlite_file: str):
        self.sqlite_file = sqlite_file


def _make_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE wallet_addresses (
            coin_type INTEGER,
            address TEXT,
            is_internal INTEGER DEFAULT 0,
            is_funded INTEGER DEFAULT 0,
            cached_balance INTEGER DEFAULT 0,
            derivation_index INTEGER DEFAULT 0
        )""")
    cursor.execute("""CREATE TABLE wallet_watch_only (
            coin_type INTEGER,
            address TEXT,
            is_funded INTEGER DEFAULT 0,
            cached_balance INTEGER DEFAULT 0,
            private_key_encrypted BLOB
        )""")
    conn.commit()
    conn.close()
    return path


class TestWalletManagerBalance(unittest.TestCase):
    """A watch-only address only counts toward spendable balance when we hold
    its private key. Swap multisig lock outputs are watched but keyless, so they
    must not inflate the wallet balance while funds are locked."""

    def setUp(self):
        self.db_path = _make_db()
        coin = int(Coins.BTC)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        # Our own derived address, spendable.
        cursor.execute(
            "INSERT INTO wallet_addresses (coin_type, address, is_internal, is_funded, cached_balance, derivation_index) VALUES (?, ?, 0, 1, ?, 0)",
            (coin, "own_addr", 100_000_000),
        )
        # A watch-only address we swept/imported with its key: spendable.
        cursor.execute(
            "INSERT INTO wallet_watch_only (coin_type, address, is_funded, cached_balance, private_key_encrypted) VALUES (?, ?, 1, ?, ?)",
            (coin, "imported_with_key", 30_000_000, b"encrypted-key"),
        )
        # A swap multisig lock output: watched for detection, no private key.
        cursor.execute(
            "INSERT INTO wallet_watch_only (coin_type, address, is_funded, cached_balance, private_key_encrypted) VALUES (?, ?, 1, ?, NULL)",
            (coin, "swap_lock_addr", 500_000_000),
        )
        conn.commit()
        conn.close()

        self.wm = WalletManager(FakeSwapClient(self.db_path), logging.getLogger())

    def tearDown(self):
        os.remove(self.db_path)

    def test_cached_total_excludes_keyless_watch_only(self):
        total = self.wm.getCachedTotalBalance(Coins.BTC)
        # own (1 BTC) + imported-with-key (0.3 BTC); the 5 BTC swap lock is excluded.
        self.assertEqual(total, 130_000_000)

    def test_get_all_addresses_require_key_excludes_swap_lock(self):
        spendable = self.wm.getAllAddresses(Coins.BTC, watch_only_require_key=True)
        self.assertIn("own_addr", spendable)
        self.assertIn("imported_with_key", spendable)
        self.assertNotIn("swap_lock_addr", spendable)

    def test_get_all_addresses_default_still_watches_swap_lock(self):
        # Without the flag every watched address is returned, so lock detection
        # and address subscription are unaffected.
        watched = self.wm.getAllAddresses(Coins.BTC)
        self.assertIn("swap_lock_addr", watched)


if __name__ == "__main__":
    unittest.main()
