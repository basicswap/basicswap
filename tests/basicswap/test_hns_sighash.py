"""Compare native HNS signing digests with the pinned HSD oracle vectors."""

import json
import unittest
from pathlib import Path

from basicswap.interface.hns.sighash import signature_hash, valid_sighash_type
from basicswap.interface.hns.transaction import HnsTransaction, HnsTransactionError

FIXTURE = Path(__file__).with_name("hns_sighash_hsd_v1.json")


class HnsSighashTest(unittest.TestCase):
    def test_hsd_oracle_vectors(self):
        fixture = json.loads(FIXTURE.read_text())
        self.assertEqual(fixture["oracle"]["repository"], "handshake-org/hsd")
        transaction = HnsTransaction.decode(bytes.fromhex(fixture["transactionRaw"]))
        script = bytes.fromhex(fixture["previousScriptRaw"])
        for vector in fixture["vectors"]:
            with self.subTest(index=vector["inputIndex"], hash_type=vector["type"]):
                self.assertEqual(
                    signature_hash(
                        transaction,
                        vector["inputIndex"],
                        script,
                        fixture["previousValue"],
                        vector["type"],
                    ).hex(),
                    vector["hash"],
                )
        for item in fixture["signatureTypes"]:
            self.assertEqual(valid_sighash_type(item["type"]), item["valid"])

    def test_invalid_signing_inputs_fail_closed(self):
        fixture = json.loads(FIXTURE.read_text())
        transaction = HnsTransaction.decode(bytes.fromhex(fixture["transactionRaw"]))
        with self.assertRaises(HnsTransactionError):
            signature_hash(transaction, 2, b"", 1, 1)
        with self.assertRaises(HnsTransactionError):
            signature_hash(transaction, 0, b"", -1, 1)
        with self.assertRaises(HnsTransactionError):
            signature_hash(transaction, 0, b"", 1, 5)


if __name__ == "__main__":
    unittest.main()
