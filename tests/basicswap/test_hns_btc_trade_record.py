"""Persist terms and Bitcoin broadcast intent before value actions."""

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from basicswap.db import DBMethods, HnsBtcSwap, create_table, extract_schema
from basicswap.interface.hns.trade_record import (
    TAKER,
    bind_bid_id,
    bind_lock,
    bind_message,
    bind_preimage,
    bind_terms,
    new_trade_record,
    restore_trade,
)
from tests.basicswap.test_hns_btc_swap import GENESIS, MAGIC, NOW, messages, terms


class HnsBtcTradeRecordTest(unittest.TestCase):
    def test_identity_and_contract_survive_sqlite_restart(self):
        trade = terms(False)
        bid, accept = messages(trade)
        record = new_trade_record(
            trade.offer_id, trade.session_nonce, TAKER, bid.to_bytes(), NOW
        )
        with self.assertRaisesRegex(ValueError, "terms do not match"):
            bind_terms(record, trade, NOW, MAGIC, GENESIS)
        bind_bid_id(record, trade.bid_id)
        bind_terms(record, trade, NOW, MAGIC, GENESIS)
        bind_terms(record, trade, NOW + 48 * 60 * 60, MAGIC, GENESIS)
        bind_message(record, "accept_message", accept.to_bytes())
        bind_lock(record, "btc", bytes.fromhex("ab" * 32), 1)
        with self.assertRaisesRegex(ValueError, "already bound"):
            bind_lock(record, "btc", bytes.fromhex("bb" * 32), 3)
        with self.assertRaisesRegex(ValueError, "does not match"):
            bind_preimage(record, bytes.fromhex("66" * 32))
        bind_preimage(record, bytes.fromhex("55" * 32))

        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "trade.sqlite"
            with sqlite3.connect(db_path) as connection:
                cursor = connection.cursor()
                create_table(cursor, "hns_btc_swaps", extract_schema()["hns_btc_swaps"])
                DBMethods().add(record, cursor)
            with sqlite3.connect(db_path) as connection:
                restored = DBMethods().queryOne(
                    HnsBtcSwap,
                    connection.cursor(),
                    {"session_id": record.session_id},
                )
                self.assertEqual(restored.bid_id, trade.bid_id)
                self.assertEqual(restored.hns_descriptor, trade.hns_descriptor.encode())
                self.assertEqual(
                    restored.btc_contract_script, trade.btc_contract_script
                )
                self.assertEqual(restored.terms_commitment, accept.terms_commitment)
                self.assertEqual(restored.btc_lock_vout, 1)
                self.assertEqual(restored.btc_lock_txid, bytes.fromhex("ab" * 32))
                self.assertEqual(restored.secret_preimage, bytes.fromhex("55" * 32))
                recovered, outpoint = restore_trade(
                    restored,
                    False,
                    trade.hns_amount,
                    trade.btc_amount,
                    NOW + 48 * 60 * 60,
                    MAGIC,
                    GENESIS,
                )
                self.assertEqual(recovered, trade)
                self.assertEqual(outpoint, (bytes.fromhex("ab" * 32), 1))

    def test_changed_negotiation_cannot_replace_bound_contract(self):
        trade = terms(True)
        bid, _ = messages(trade)
        record = new_trade_record(
            trade.offer_id, trade.session_nonce, TAKER, bid.to_bytes(), NOW
        )
        bind_bid_id(record, trade.bid_id)
        bind_terms(record, trade, NOW, MAGIC, GENESIS)
        changed = replace(trade, minimum_hns_confirmations=3)
        with self.assertRaisesRegex(ValueError, "already bound"):
            bind_terms(record, changed, NOW, MAGIC, GENESIS)
        self.assertEqual(record.terms_commitment, trade.commitment(NOW, MAGIC, GENESIS))


if __name__ == "__main__":
    unittest.main()
