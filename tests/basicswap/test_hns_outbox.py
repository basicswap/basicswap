"""The negotiated HNS session and exact bid ID survive a failed send."""

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from coincurve import PrivateKey

from basicswap.basicswap_util import MessageTypes
from basicswap.db import (
    DBMethods,
    HnsBtcOutbox,
    HnsBtcSwap,
    create_table,
    extract_schema,
)
from basicswap.interface.hns.outbox import (
    deliver_hns_outbox_message,
    prepare_hns_outbox_message,
)
from basicswap.interface.hns.trade_record import (
    bind_bid_id,
    new_trade_record,
)
from basicswap.util.smsg import smsgEncrypt


class HnsOutboxTest(unittest.TestCase):
    def test_bid_id_is_committed_before_first_submit_and_retried_exactly(self):
        created_at = 1_790_000_000
        sender = bytes.fromhex("11" * 32)
        receiver = PrivateKey(bytes.fromhex("22" * 32)).public_key.format()
        encrypted = smsgEncrypt(
            sender,
            receiver,
            bytes((MessageTypes.HNS_BTC_BID,)) + b"bid wire bytes",
            smsg_timestamp=created_at,
            deterministic=True,
            smsg_ttl=3600,
            difficulty_target=0x207FFFFF,
        )
        record = new_trade_record(
            bytes.fromhex("33" * 28),
            bytes.fromhex("44" * 32),
            2,
            b"bid wire bytes",
            created_at,
        )
        row = prepare_hns_outbox_message(
            record.session_id,
            MessageTypes.HNS_BTC_BID,
            encrypted,
            created_at,
            created_at + 600,
        )
        bind_bid_id(record, row.message_id)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "outbox.sqlite"
            methods = DBMethods()
            schema = extract_schema()
            with closing(sqlite3.connect(database)) as connection, connection:
                for table in ("hns_btc_swaps", "hns_btc_outbox"):
                    create_table(connection.cursor(), table, schema[table])
                methods.add(record, connection.cursor())
                methods.add(row, connection.cursor())

            with closing(sqlite3.connect(database)) as connection:
                restored_record = methods.queryOne(
                    HnsBtcSwap,
                    connection.cursor(),
                    {"session_id": record.session_id},
                )
                restored = methods.queryOne(
                    HnsBtcOutbox,
                    connection.cursor(),
                    {"message_id": row.message_id},
                )
            self.assertEqual(restored_record.bid_id, restored.message_id)
            self.assertEqual(restored.message_bytes, encrypted)
            self.assertIsNone(restored.delivered_at)

            submitted = []

            def submit(message):
                submitted.append(message)
                if len(submitted) == 1:
                    raise ConnectionError("network submission failed")

            def persist(changed):
                with closing(sqlite3.connect(database)) as connection, connection:
                    methods.updateDB(changed, connection.cursor(), ["message_id"])

            with self.assertRaises(ConnectionError):
                deliver_hns_outbox_message(restored, created_at + 1, submit, persist)
            self.assertIsNone(restored.delivered_at)
            self.assertEqual(
                deliver_hns_outbox_message(restored, created_at + 2, submit, persist),
                row.message_id,
            )
            self.assertEqual(submitted, [encrypted, encrypted])
            with closing(sqlite3.connect(database)) as connection:
                delivered = methods.queryOne(
                    HnsBtcOutbox,
                    connection.cursor(),
                    {"message_id": row.message_id},
                )
            self.assertEqual(delivered.delivered_at, created_at + 2)
            deliver_hns_outbox_message(delivered, created_at + 3, submit, persist)
            self.assertEqual(len(submitted), 2)

    def test_outbox_rejects_changed_bytes_and_expired_retry(self):
        created_at = 1_790_000_000
        encrypted = smsgEncrypt(
            bytes.fromhex("11" * 32),
            PrivateKey(bytes.fromhex("22" * 32)).public_key.format(),
            b"test",
            smsg_timestamp=created_at,
            deterministic=True,
            smsg_ttl=3600,
            difficulty_target=0x207FFFFF,
        )
        row = prepare_hns_outbox_message(
            bytes.fromhex("44" * 32),
            MessageTypes.HNS_BTC_BID,
            encrypted,
            created_at,
            created_at + 600,
        )
        with self.assertRaisesRegex(ValueError, "expired"):
            deliver_hns_outbox_message(
                row, created_at + 600, lambda _: None, lambda _: None
            )
        row.message_bytes = encrypted[:-1] + bytes((encrypted[-1] ^ 1,))
        with self.assertRaisesRegex(ValueError, "changed"):
            deliver_hns_outbox_message(
                row, created_at + 1, lambda _: None, lambda _: None
            )


if __name__ == "__main__":
    unittest.main()
