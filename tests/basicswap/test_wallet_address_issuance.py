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


def _make_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE wallet_addresses (
            coin_type INTEGER,
            address TEXT,
            is_internal INTEGER DEFAULT 0,
            is_funded INTEGER DEFAULT 0,
            cached_balance INTEGER DEFAULT 0,
            derivation_index INTEGER DEFAULT 0,
            ever_used INTEGER DEFAULT 0
        )""")
    conn.commit()
    conn.close()
    return path


class FakeWalletAddress:
    def __init__(self, address: str):
        self.address = address


class FakeWalletState:
    def __init__(self, last_external_index: int, last_internal_index: int):
        self.last_external_index = last_external_index
        self.last_internal_index = last_internal_index
        self.updated_at = 0


class IssuanceSwapClient:
    def __init__(self, conn, state):
        self.conn = conn
        self.state = state

    def openDB(self, cursor=None):
        return cursor if cursor is not None else self.conn.cursor()

    def queryOne(self, table, cursor, constraints):
        if getattr(table, "__name__", "") == "WalletState":
            return self.state
        cursor.execute(
            "SELECT address FROM wallet_addresses WHERE coin_type = ?"
            " AND derivation_index = ? AND is_internal = ?",
            (
                constraints["coin_type"],
                constraints["derivation_index"],
                int(constraints["is_internal"]),
            ),
        )
        row = cursor.fetchone()
        return FakeWalletAddress(row[0]) if row else None

    def add(self, obj, cursor):
        cursor.execute(
            "INSERT INTO wallet_addresses (coin_type, address,"
            " is_internal, is_funded, cached_balance, derivation_index, ever_used)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                obj.coin_type,
                obj.address,
                int(obj.is_internal),
                int(obj.is_funded),
                obj.cached_balance,
                obj.derivation_index,
                int(obj.ever_used),
            ),
        )

    def updateDB(self, obj, cursor, constraints=None):
        pass

    def commitDB(self):
        self.conn.commit()

    def rollbackDB(self):
        self.conn.rollback()

    def closeDB(self, cursor, commit=False):
        pass


class TestAddressIssuanceDensity(unittest.TestCase):
    """A field report traced a lost balance to a permanent hole in the change
    chain: initialize pre-created indexes 0-19, the old threshold guard consumed
    0 and 1, then went inert and appended from 20 onward. Indexes 2-19 were
    never handed out, and a restoring wallet stopped scanning at the hole with
    every later change output behind it."""

    POOL_SIZE = 20

    def setUp(self):
        self.db_path = _make_db()
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()
        for index in range(self.POOL_SIZE):
            for internal in (0, 1):
                cursor.execute(
                    "INSERT INTO wallet_addresses (coin_type, address,"
                    " is_internal, is_funded, cached_balance, derivation_index, ever_used)"
                    " VALUES (?, ?, ?, 0, 0, ?, 0)",
                    (
                        int(Coins.BTC),
                        f"addr_{internal}_{index}",
                        internal,
                        index,
                    ),
                )
        self.conn.commit()

        # initialize leaves the cursor at the top of the pre-created pool.
        self.state = FakeWalletState(self.POOL_SIZE - 1, self.POOL_SIZE - 1)
        self.wm = WalletManager.__new__(WalletManager)
        self.wm._swap_client = IssuanceSwapClient(self.conn, self.state)
        self.wm._log = logging.getLogger("issuance")
        self.wm.isInitialized = lambda coin_type: True
        self.wm._deriveAddress = lambda coin_type, index, internal: (
            f"addr_{int(internal)}_{index}",
            f"sh_{int(internal)}_{index}",
            b"pubkey",
        )

    def tearDown(self):
        self.conn.close()
        os.remove(self.db_path)

    def _handed_out(self, internal: bool):
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT derivation_index FROM wallet_addresses"
            " WHERE coin_type = ? AND is_internal = ? AND ever_used = 1"
            " ORDER BY derivation_index ASC",
            (int(Coins.BTC), int(internal)),
        )
        return [row[0] for row in cursor.fetchall()]

    def test_change_chain_has_no_hole(self):
        issued = [
            self.wm.getNewAddress(Coins.BTC, internal=True)
            for _ in range(self.POOL_SIZE + 2)
        ]
        self.assertEqual(len(set(issued)), len(issued))
        self.assertEqual(self._handed_out(True), list(range(self.POOL_SIZE + 2)))

    def test_pool_is_consumed_before_deriving_past_it(self):
        for _ in range(self.POOL_SIZE):
            self.wm.getNewAddress(Coins.BTC, internal=True)
        self.assertEqual(self._handed_out(True), list(range(self.POOL_SIZE)))

        self.wm.getNewAddress(Coins.BTC, internal=True)
        self.assertEqual(self._handed_out(True)[-1], self.POOL_SIZE)

    def test_receive_chain_has_no_hole(self):
        for _ in range(self.POOL_SIZE + 1):
            self.wm.getNewAddress(Coins.BTC, internal=False)
        self.assertEqual(self._handed_out(False), list(range(self.POOL_SIZE + 1)))

    def test_funded_index_is_skipped_but_leaves_no_gap(self):
        # An address that already holds coins has on-chain history, so passing
        # over it does not create a gap a restoring wallet would stop at.
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE wallet_addresses SET cached_balance = 1000"
            " WHERE coin_type = ? AND is_internal = 1 AND derivation_index = 0",
            (int(Coins.BTC),),
        )
        self.conn.commit()

        first = self.wm.getNewAddress(Coins.BTC, internal=True)
        self.assertEqual(first, "addr_1_1")
        self.assertEqual(self._handed_out(True), [1])

    def test_high_water_index_only_advances(self):
        self.wm.getNewAddress(Coins.BTC, internal=True)
        self.assertEqual(self.state.last_internal_index, self.POOL_SIZE - 1)

        for _ in range(self.POOL_SIZE):
            self.wm.getNewAddress(Coins.BTC, internal=True)
        self.assertEqual(self.state.last_internal_index, self.POOL_SIZE)


if __name__ == "__main__":
    unittest.main()
