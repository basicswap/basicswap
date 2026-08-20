# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.interface.btc.btc import BTCInterface
from tests.basicswap.util.common import REQUIRED_SETTINGS

ADDRESS = "mnnneadnnywzceaadkfnzknnnnnnnnnnnn"
SIGNATURE = b"sig"
COMMIT_BYTES = b"\x01\x02"


def make_interface(connection_type="none"):
    settings = dict(REQUIRED_SETTINGS)
    settings.update(
        {
            "rpcport": 0,
            "rpcauth": "none",
            "connection_type": connection_type,
            "use_segwit": False,
        }
    )
    ci = BTCInterface(settings, "regtest")
    ci.verifyMessage = lambda address, message, signature: True
    return ci


class ElectrumBalanceBackend:
    def __init__(self, unspents=None, error=None):
        self._unspents = unspents
        self._error = error

    def getUnspentOutputs(self, addresses):
        if self._error is not None:
            raise self._error
        return self._unspents


class VerifyProofOfFundsTest(unittest.TestCase):
    def test_invalid_signature_raises(self):
        ci = make_interface()
        ci.verifyMessage = lambda address, message, signature: False
        with self.assertRaisesRegex(ValueError, "signature invalid"):
            ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)

    def test_electrum_returns_balance(self):
        ci = make_interface("electrum")
        ci._backend = ElectrumBalanceBackend(
            unspents=[{"value": 5000}, {"value": 6000}]
        )
        rv = ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)
        self.assertEqual(rv, 11000)

    def test_electrum_failure_raises(self):
        ci = make_interface("electrum")
        ci._backend = ElectrumBalanceBackend(error=ConnectionError("server gone"))
        with self.assertRaisesRegex(ValueError, "balance check failed"):
            ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)

    def test_rpc_returns_balance(self):
        ci = make_interface()
        ci.getUTXOBalance = lambda address: 12345
        rv = ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)
        self.assertEqual(rv, 12345)

    def test_rpc_failure_raises(self):
        ci = make_interface()

        def fail(address):
            raise ConnectionError("rpc down")

        ci.getUTXOBalance = fail
        with self.assertRaisesRegex(ValueError, "balance check failed"):
            ci.verifyProofOfFunds(ADDRESS, SIGNATURE, [], COMMIT_BYTES)


if __name__ == "__main__":
    unittest.main()
