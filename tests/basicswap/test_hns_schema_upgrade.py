"""An existing HNS/BTC database gains the replay and offer safety indexes."""

import sqlite3
import unittest
from types import SimpleNamespace

from basicswap.db import extract_schema
from basicswap.db_upgrades import upgradeDatabaseFromSchema


class HnsSchemaUpgradeTest(unittest.TestCase):
    def test_v41_rows_gain_v42_cursors_and_unique_indexes(self):
        with sqlite3.connect(":memory:") as connection:
            cursor = connection.cursor()
            cursor.execute(
                "CREATE TABLE hns_btc_swaps (session_id BLOB PRIMARY KEY, "
                "offer_id BLOB, bid_id BLOB, role INTEGER, phase INTEGER)"
            )
            cursor.execute(
                "CREATE TABLE hns_btc_outbox (message_id BLOB PRIMARY KEY, "
                "session_id BLOB, message_type INTEGER)"
            )
            schema = extract_schema()
            tables = {
                name: schema[name] for name in ("hns_btc_swaps", "hns_btc_outbox")
            }
            app = SimpleNamespace(log=SimpleNamespace(info=lambda *_args: None))
            upgradeDatabaseFromSchema(app, cursor, tables)

            columns = {
                row[1] for row in cursor.execute("PRAGMA table_info(hns_btc_swaps)")
            }
            self.assertIn("btc_peer_scan_height", columns)
            self.assertIn("btc_peer_scan_anchor", columns)
            cursor.execute(
                "INSERT INTO hns_btc_swaps "
                "(session_id, offer_id, bid_id, role, phase) VALUES (?, ?, ?, 1, 1)",
                (b"a", b"offer", b"bid-a"),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute(
                    "INSERT INTO hns_btc_swaps "
                    "(session_id, offer_id, bid_id, role, phase) VALUES (?, ?, ?, 1, 1)",
                    (b"b", b"offer", b"bid-b"),
                )
            cursor.execute(
                "INSERT INTO hns_btc_swaps "
                "(session_id, offer_id, bid_id, role) VALUES (?, ?, ?, 1)",
                (b"c", b"offer", b"bid-c"),
            )
            cursor.execute(
                "INSERT INTO hns_btc_outbox "
                "(message_id, session_id, message_type) VALUES (?, ?, 1)",
                (b"one", b"session"),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                cursor.execute(
                    "INSERT INTO hns_btc_outbox "
                    "(message_id, session_id, message_type) VALUES (?, ?, 1)",
                    (b"two", b"session"),
                )


if __name__ == "__main__":
    unittest.main()
