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
    elif operation == 'verify_lock':
        result = {'verified': False}
    elif operation == 'fund':
        result = {'transaction_id': '44' * 32, 'output_index': 0,
                  'recovered': False}
    elif operation == 'observe_spend':
        result = {'observed': False}
    else:
        result = {'unlocked': True}
    if operation == 'sync':
        sequence += 1
    if operation == 'rebroadcast':
        result = {'count': 0}
    response = {'version': 1, 'sequence': sequence, 'ok': True,
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
            "25993e216776141c0e1e4f68712c48b71b954fabbc98cb47c1c960f5a3196777",
        )
        with self.bridge() as bridge:
            bridge.unlock("test passphrase")
            self.assertEqual(
                bridge.key(self.terms.offer_id, self.terms.bid_id, False),
                bytes.fromhex("02" + "11" * 32),
            )
            self.assertFalse(bridge.verify_lock(self.terms, bytes(32), 2))
            self.assertEqual(
                bridge.fund(self.terms, 1_000), (bytes.fromhex("44" * 32), 0)
            )
            self.assertIsNone(bridge.observe_spend(self.terms, bytes(32), 2))

    def test_response_sequence_and_auth_file_fail_closed(self):
        with self.bridge() as bridge:
            with self.assertRaisesRegex(HnsWalletBridgeError, "response mismatch"):
                bridge.sync()
        with self.bridge() as bridge:
            with self.assertRaisesRegex(HnsWalletBridgeError, "response mismatch"):
                bridge.rebroadcast()
        if os.name == "posix":
            self.authorization.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "must be private"):
                self.bridge()


if __name__ == "__main__":
    unittest.main()
