# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock

from basicswap.chainparams import Coins
from basicswap.wallet_manager import WalletManager
from basicswap.contrib.test_framework import segwit_addr
from basicswap.util.crypto import hash160
from coincurve import PublicKey

SEED = bytes(range(32))
PRIVATE_KEY = bytes(range(1, 33))


class ImportKeyMigrationTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        sqlite_file = os.path.join(self.tmpdir.name, "db.sqlite")
        conn = sqlite3.connect(sqlite_file)
        conn.execute(
            "CREATE TABLE wallet_addresses (coin_type INT, address TEXT, derivation_index INT, is_internal INT)"
        )
        conn.execute(
            "CREATE TABLE wallet_watch_only (coin_type INT, address TEXT, private_key_encrypted BLOB)"
        )
        conn.commit()
        conn.close()

        swap_client = MagicMock()
        swap_client.sqlite_file = sqlite_file
        swap_client.chain = "regtest"
        self.log = MagicMock()
        self.wm = WalletManager(swap_client, self.log)
        self.wm.needsMigration = lambda coin_type: False
        self.wm.initialize(Coins.BTC, SEED)

        pubkey = PublicKey.from_secret(PRIVATE_KEY).format()
        self.address = segwit_addr.encode(
            self.wm._getHRP(Coins.BTC), 0, hash160(pubkey)
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def _insert_watch_only(self, address, encrypted_key):
        conn = sqlite3.connect(self.wm._swap_client.sqlite_file)
        conn.execute(
            "INSERT INTO wallet_watch_only (coin_type, address, private_key_encrypted) VALUES (?, ?, ?)",
            (int(Coins.BTC), address, encrypted_key),
        )
        conn.commit()
        conn.close()

    def _fetch_encrypted(self, address):
        conn = sqlite3.connect(self.wm._swap_client.sqlite_file)
        row = conn.execute(
            "SELECT private_key_encrypted FROM wallet_watch_only WHERE address = ?",
            (address,),
        ).fetchone()
        conn.close()
        return row[0]

    def _legacy_encrypt(self, private_key):
        keystream = self.wm._getXorKey(Coins.BTC)
        return bytes(a ^ b for a, b in zip(private_key, keystream))

    def test_valid_legacy_record_migrates(self):
        self._insert_watch_only(self.address, self._legacy_encrypt(PRIVATE_KEY))
        rv = self.wm.getPrivateKey(Coins.BTC, self.address)
        self.assertEqual(rv, PRIVATE_KEY)
        migrated = self._fetch_encrypted(self.address)
        self.assertTrue(WalletManager._isAEADImportKey(migrated))

    def test_mismatched_legacy_record_not_migrated(self):
        other_address = segwit_addr.encode(
            self.wm._getHRP(Coins.BTC), 0, hash160(b"\x03" * 33)
        )
        legacy = self._legacy_encrypt(PRIVATE_KEY)
        self._insert_watch_only(other_address, legacy)
        rv = self.wm.getPrivateKey(Coins.BTC, other_address)
        self.assertIsNone(rv)
        self.assertEqual(self._fetch_encrypted(other_address), legacy)
        self.log.error.assert_called_once()
        self.assertIn("does not match", self.log.error.call_args[0][0])

    def test_tampered_aead_record_reports_error(self):
        encrypted = self.wm._encryptPrivateKey(PRIVATE_KEY, Coins.BTC)
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 0x01])
        self._insert_watch_only(self.address, tampered)
        rv = self.wm.getPrivateKey(Coins.BTC, self.address)
        self.assertIsNone(rv)
        self.log.error.assert_called_once()
        self.assertIn("Failed to decrypt", self.log.error.call_args[0][0])

    def test_valid_aead_record_returned(self):
        encrypted = self.wm._encryptPrivateKey(PRIVATE_KEY, Coins.BTC)
        self._insert_watch_only(self.address, encrypted)
        rv = self.wm.getPrivateKey(Coins.BTC, self.address)
        self.assertEqual(rv, PRIVATE_KEY)
        self.assertEqual(self._fetch_encrypted(self.address), encrypted)


if __name__ == "__main__":
    unittest.main()
