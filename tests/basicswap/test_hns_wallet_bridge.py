"""Exercise the private bridge pipe and BasicSwap session binding."""

import os
import tempfile
import unittest
from pathlib import Path

from basicswap.interface.hns.htlc import HnsHtlc
from basicswap.interface.hns.wallet_bridge import (
    HnsBridgeTerms,
    HnsWalletBridge,
    HnsWalletBridgeError,
    initialize_hns_wallet,
)
from tests.basicswap.test_hns_htlc import DESCRIPTOR

FAKE_BRIDGE = """#!/usr/bin/env python3
import json
import struct
import sys

reader = sys.stdin.buffer
writer = sys.stdout.buffer
while True:
    prefix = reader.read(4)
    if not prefix:
        break
    length = struct.unpack('<I', prefix)[0]
    request = json.loads(reader.read(length))
    operation = request['request']['operation']
    sequence = request['sequence']
    if operation == 'key':
        result = {'public_key': '02' + '11' * 32}
    elif operation == 'identity':
        result = {'wallet_id': '44' * 16, 'seed_fingerprint': '55' * 32,
                  'network': 'regtest'}
    elif operation == 'receive':
        result = {'address': 'rs1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpprmh8u',
                  'derivation_index': 0}
    elif operation == 'snapshot':
        result = {'balance': '1000000',
                  'receive_address': 'rs1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpprmh8u'}
    elif operation == 'verify_lock':
        result = {'verified': False}
    elif operation == 'fund':
        result = {'transaction_id': '44' * 32, 'output_index': 0,
                  'recovered': False}
    elif operation == 'submitted_funding':
        result = {'transaction_id': '44' * 32}
    elif operation == 'submitted_spend':
        result = {'transaction_id': None}
    elif operation == 'observe_spend':
        result = {'observed': False}
    elif operation == 'lock':
        result = {'unlocked': False}
    elif operation == 'change_passphrase':
        result = {'changed': True, 'unlocked': False}
    else:
        result = {'unlocked': True}
    if operation == 'sync':
        sequence += 1
    if operation == 'rebroadcast':
        result = {'count': 0}
    response = {'version': 2, 'sequence': sequence, 'ok': True,
                'result': result, 'error': None}
    if operation == 'rebroadcast':
        response['version'] = True
    payload = json.dumps(response).encode()
    writer.write(struct.pack('<I', len(payload)) + payload)
    writer.flush()
"""


class HnsWalletBridgeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.executable = root / "fake-bridge"
        self.executable.write_text(FAKE_BRIDGE)
        self.executable.chmod(0o700)
        self.database = root / "wallet.db"
        self.database.touch()
        self.authorization = root / "node.auth"
        self.authorization.write_text("Basic secret")
        self.authorization.chmod(0o600)
        self.terms = HnsBridgeTerms(
            bytes.fromhex("11" * 28),
            bytes.fromhex("22" * 28),
            bytes.fromhex("23" * 32),
            HnsHtlc.decode(DESCRIPTOR, 0x5B6EC393, bytes.fromhex("11" * 32)),
        )

    def tearDown(self):
        self.temp.cleanup()

    def bridge(self):
        return HnsWalletBridge(
            self.executable, self.database, "127.0.0.1:24192", self.authorization
        )

    def test_session_and_framed_operations(self):
        self.assertEqual(
            self.terms.session_id().hex(),
            "b21dc4109bd11c635b5f092849de8121700c137209834cca621f3974ae501b38",
        )
        with self.bridge() as bridge:
            self.assertTrue(bridge.is_running())
            bridge.unlock("test passphrase")
            self.assertEqual(
                bridge.identity("regtest"),
                (bytes.fromhex("44" * 16), bytes.fromhex("55" * 32)),
            )
            with self.assertRaisesRegex(HnsWalletBridgeError, "network mismatch"):
                bridge.identity("mainnet")
            self.assertEqual(bridge.receive("regtest")[1], 0)
            self.assertEqual(bridge.snapshot("regtest")[0], 1_000_000)
            self.assertEqual(
                bridge.key(self.terms.offer_id, self.terms.session_nonce, False),
                bytes.fromhex("02" + "11" * 32),
            )
            self.assertFalse(bridge.verify_lock(self.terms, bytes(32), 2))
            self.assertEqual(
                bridge.fund(self.terms, 1_000), (bytes.fromhex("44" * 32), 0)
            )
            self.assertEqual(
                bridge.submitted_funding(self.terms), bytes.fromhex("44" * 32)
            )
            self.assertIsNone(bridge.submitted_spend(self.terms, bytes(32), False))
            self.assertIsNone(bridge.observe_spend(self.terms, bytes(32), 2))
            with self.assertRaisesRegex(ValueError, "old HNS wallet passphrase"):
                bridge.change_passphrase("", "next passphrase")
            bridge.change_passphrase("test passphrase", "next passphrase")
            bridge.lock()
        self.assertFalse(bridge.is_running())

    def test_response_sequence_and_auth_file_fail_closed(self):
        with (
            self.bridge() as bridge,
            self.assertRaisesRegex(HnsWalletBridgeError, "response mismatch"),
        ):
            bridge.sync()
        with (
            self.bridge() as bridge,
            self.assertRaisesRegex(HnsWalletBridgeError, "response mismatch"),
        ):
            bridge.rebroadcast()
        if os.name == "posix":
            self.authorization.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "must be private"):
                self.bridge()

    @unittest.skipUnless(os.getenv("HNS_BRIDGE_BIN"), "set HNS_BRIDGE_BIN")
    def test_initializer_create_and_restore_over_private_pipe(self):
        executable = os.environ["HNS_BRIDGE_BIN"]
        created_db = Path(self.temp.name) / "created.db"
        restored_db = Path(self.temp.name) / "restored.db"
        wallet_id, fingerprint, phrase = initialize_hns_wallet(
            executable, created_db, "regtest", 0, "test passphrase"
        )
        self.assertEqual(len(wallet_id), 16)
        self.assertEqual(len(fingerprint), 32)
        self.assertEqual(len(phrase.split()), 24)
        restored_id, restored_fingerprint, restored_phrase = initialize_hns_wallet(
            executable,
            restored_db,
            "regtest",
            0,
            "test passphrase",
            recovery_phrase=phrase,
        )
        self.assertEqual(len(restored_id), 16)
        self.assertEqual(restored_fingerprint, fingerprint)
        self.assertIsNone(restored_phrase)
        with HnsWalletBridge(
            executable, created_db, "127.0.0.1:24192", self.authorization
        ) as bridge:
            bridge.unlock("test passphrase")
            self.assertEqual(bridge.identity("regtest"), (wallet_id, fingerprint))
        with self.assertRaisesRegex(ValueError, "already exists"):
            initialize_hns_wallet(
                executable, created_db, "regtest", 0, "test passphrase"
            )


if __name__ == "__main__":
    unittest.main()
