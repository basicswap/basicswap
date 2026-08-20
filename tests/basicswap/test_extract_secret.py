# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from basicswap.protocols.atomic_swap_1 import buildContractScript
from basicswap.util.crypto import sha256

SECRET = bytes(range(32))
OTHER_SECRET = bytes(range(1, 33))


def make_stub(use_segwit=True):
    stub = SimpleNamespace()
    stub.coin_clients = {Coins.BTC: {"use_segwit": use_segwit}}
    stub.log = MagicMock()
    return stub


def make_bid(script):
    return SimpleNamespace(
        bid_id=b"\xab" * 28,
        initiate_tx=SimpleNamespace(script=script) if script is not None else None,
        participate_tx=None,
    )


def make_script(secret):
    return buildContractScript(10, sha256(secret), b"\x11" * 20, b"\x22" * 20)


def witness_spend(secret):
    return {
        "txinwitness": [
            "30" * 71,
            "02" + "33" * 32,
            secret.hex(),
            "01",
            make_script(secret).hex(),
        ]
    }


class ExtractSecretTest(unittest.TestCase):
    def test_valid_secret_returned(self):
        stub = make_stub()
        bid = make_bid(make_script(SECRET))
        rv = BasicSwap.extractSecret(stub, Coins.BTC, bid, witness_spend(SECRET))
        self.assertEqual(rv, SECRET)
        stub.log.warning.assert_not_called()

    def test_wrong_secret_rejected(self):
        stub = make_stub()
        bid = make_bid(make_script(SECRET))
        rv = BasicSwap.extractSecret(stub, Coins.BTC, bid, witness_spend(OTHER_SECRET))
        self.assertIsNone(rv)
        stub.log.warning.assert_called_once()

    def test_refund_witness_returns_none(self):
        stub = make_stub()
        bid = make_bid(make_script(SECRET))
        spend_in = {"txinwitness": ["30" * 71, "02" + "33" * 32, "", "00"]}
        rv = BasicSwap.extractSecret(stub, Coins.BTC, bid, spend_in)
        self.assertIsNone(rv)

    def test_no_script_available_returns_secret(self):
        stub = make_stub()
        bid = make_bid(None)
        rv = BasicSwap.extractSecret(stub, Coins.BTC, bid, witness_spend(SECRET))
        self.assertEqual(rv, SECRET)

    def test_scriptsig_path_validates(self):
        stub = make_stub(use_segwit=False)
        bid = make_bid(make_script(SECRET))
        spend_in = {
            "scriptSig": {
                "asm": " ".join(
                    [
                        "30" * 71,
                        "02" + "33" * 32,
                        OTHER_SECRET.hex(),
                        "01",
                        make_script(SECRET).hex(),
                    ]
                )
            }
        }
        rv = BasicSwap.extractSecret(stub, Coins.BTC, bid, spend_in)
        self.assertIsNone(rv)
        stub.log.warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
