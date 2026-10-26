# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import os
import sqlite3
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from basicswap.interface.btc.btc import BTCInterface
from basicswap.wallet_manager import WalletManager
from tests.basicswap.util.common import REQUIRED_SETTINGS


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

    def test_pool_extends_past_addresses_with_history(self):
        self.assertEqual(self.wm.extendAddressPool(Coins.BTC, []), [])

        self.wm.markAddressesUsed(Coins.BTC, ["addr_1_15"])
        added = self.wm.extendAddressPool(Coins.BTC, ["addr_1_15"])
        self.assertEqual(
            [address for address, _ in added],
            [f"addr_1_{i}" for i in range(self.POOL_SIZE, 15 + self.POOL_SIZE + 1)],
        )
        self.assertEqual(self.state.last_internal_index, 15 + self.POOL_SIZE)
        self.assertEqual(self.wm.extendAddressPool(Coins.BTC, ["addr_1_15"]), [])

    def test_used_addresses_at_pool_head(self):
        self.wm.markAddressesUsed(Coins.BTC, ["addr_1_2", "addr_0_3", "addr_1_7"])
        self.assertEqual(
            self.wm.usedAddressesAtPoolHead(Coins.BTC),
            [["addr_0_3"], ["addr_1_7", "addr_1_2"]],
        )

        self.wm.extendAddressPool(Coins.BTC, ["addr_1_7"])
        self.assertEqual(self.wm.usedAddressesAtPoolHead(Coins.BTC), [["addr_0_3"], []])

    def test_pool_grows_only_past_history_proven_on_chain(self):
        self.wm.getAddressesForSubscription = lambda coin_type: [
            (f"addr_{internal}_{i}", f"sh_{internal}_{i}")
            for internal in (0, 1)
            for i in range(self.POOL_SIZE)
        ]
        subscribed = []

        class LyingBackend:
            def isSubscribed(self, scripthash):
                return False

            def subscribeAddresses(self, addresses):
                subscribed.append(list(addresses))
                if len(subscribed) > 5:
                    raise RuntimeError("the pool kept growing")
                return {address: "status" for address in addresses}

        ci = SimpleNamespace(
            hasBuriedHistoryElectrum=lambda address: address == "addr_1_15"
        )
        swap_client = SimpleNamespace(
            _wallet_manager=self.wm,
            log=logging.getLogger("issuance"),
            ci=lambda coin_type: ci,
        )
        BasicSwap._subscribeElectrumAddresses(swap_client, Coins.BTC, LyingBackend())

        self.assertEqual(len(subscribed), 2)
        self.assertEqual(
            subscribed[1],
            [f"addr_1_{i}" for i in range(self.POOL_SIZE, 15 + self.POOL_SIZE + 1)],
        )

    def test_an_unproven_extension_is_retried_on_reconcile(self):
        initial = [
            (f"addr_{internal}_{i}", f"sh_{internal}_{i}")
            for internal in (0, 1)
            for i in range(self.POOL_SIZE)
        ]
        self.wm.getAddressesForSubscription = lambda coin_type: initial
        subscribed_scripthashes = set()
        subscribed = []

        class Backend:
            def isSubscribed(self, scripthash):
                return scripthash in subscribed_scripthashes

            def subscribeAddresses(self, addresses):
                subscribed.append(list(addresses))
                subscribed_scripthashes.update(
                    address.replace("addr_", "sh_") for address in addresses
                )
                return {
                    address: "status" if address == "addr_1_15" else None
                    for address in addresses
                }

        proven = set()
        ci = SimpleNamespace(hasBuriedHistoryElectrum=lambda address: address in proven)
        swap_client = SimpleNamespace(
            _wallet_manager=self.wm,
            log=logging.getLogger("issuance"),
            ci=lambda coin_type: ci,
        )
        backend = Backend()
        BasicSwap._subscribeElectrumAddresses(swap_client, Coins.BTC, backend)
        self.assertEqual(len(subscribed), 1)

        proven.add("addr_1_15")
        BasicSwap._subscribeElectrumAddresses(swap_client, Coins.BTC, backend)
        self.assertEqual(len(subscribed), 2)
        self.assertEqual(
            subscribed[1],
            [f"addr_1_{i}" for i in range(self.POOL_SIZE, 15 + self.POOL_SIZE + 1)],
        )

    def test_used_history_is_not_handed_out(self):
        self.wm.markAddressesUsed(Coins.BTC, ["addr_0_0", "addr_0_1"])
        self.assertEqual(self.wm.getNewAddress(Coins.BTC), "addr_0_2")


class TestBuriedHistory(unittest.TestCase):
    TIP = 110

    def setUp(self):
        settings = dict(REQUIRED_SETTINGS)
        settings.update(
            {"rpcport": 0, "rpcauth": "none", "connection_type": "electrum"}
        )
        self.ci = BTCInterface(settings, "regtest")
        self.ci._log = MagicMock()
        self.address = self.ci.encodeSegwitAddress(b"\x11" * 20)
        self.history = []
        self.txs = {}
        self.proof = True
        self.proofs_checked = []

        test = self

        class Backend:
            def hasHistory(self, address):
                return bool(test.history)

            def getAddressHistory(self, address):
                return test.history

            def getTransactionRaw(self, txid):
                return test.txs.get(txid)

        def verify(backend, txid, height):
            self.proofs_checked.append((txid, height))
            return self.proof

        self.ci._backend = Backend()
        self.ci.getChainHeight = lambda: self.TIP
        self.ci._verifyTxMerkleElectrum = verify

    def addTx(self, pkh: bytes, height: int) -> str:
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(1, 0)))
        tx.vout.append(CTxOut(10000, bytes([0x00, 0x14]) + pkh))
        txid = self.ci.getTxid(tx).hex()
        self.txs[txid] = tx.serialize().hex()
        self.history.append({"txid": txid, "height": height})
        return txid

    def test_a_buried_proven_payment_counts(self):
        txid = self.addTx(b"\x11" * 20, self.TIP - 2)
        self.assertTrue(self.ci.hasBuriedHistoryElectrum(self.address))
        self.assertEqual(self.proofs_checked, [(txid, self.TIP - 2)])

    def test_a_later_spend_does_not_hide_the_payment(self):
        receive = self.addTx(b"\x11" * 20, self.TIP - 5)
        self.addTx(b"\x22" * 20, self.TIP - 3)
        self.assertTrue(self.ci.hasBuriedHistoryElectrum(self.address))
        self.assertEqual(self.proofs_checked, [(receive, self.TIP - 5)])

    def test_a_shallow_or_unmined_payment_does_not_count(self):
        self.addTx(b"\x11" * 20, self.TIP - 1)
        self.addTx(b"\x11" * 20, 0)
        self.assertFalse(self.ci.hasBuriedHistoryElectrum(self.address))
        self.assertEqual(self.proofs_checked, [])

    def test_a_mined_tx_not_paying_the_address_does_not_count(self):
        self.addTx(b"\x22" * 20, self.TIP - 10)
        self.assertFalse(self.ci.hasBuriedHistoryElectrum(self.address))

    def test_an_unproven_payment_does_not_count(self):
        self.addTx(b"\x11" * 20, self.TIP - 10)
        for proof in (None, False):
            self.proof = proof
            self.assertFalse(self.ci.hasBuriedHistoryElectrum(self.address))

    def test_a_tx_the_server_does_not_return_does_not_count(self):
        txid = self.addTx(b"\x11" * 20, self.TIP - 10)
        del self.txs[txid]
        self.assertFalse(self.ci.hasBuriedHistoryElectrum(self.address))


if __name__ == "__main__":
    unittest.main()
