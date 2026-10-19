# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for adaptor-sig swap coin B lock lookups: findTxB must not report
the coin B lock tx as missing while the daemon or wallet is still syncing.
"""

import threading
import unittest

import basicswap.util_xmr as xmr_util
from basicswap.interface.xmr.xmr import XMRInterface
from basicswap.util import TemporaryError


class StubLog:
    def id(self, v):
        return str(v)

    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


KBV = b"\x03" * 32
PKBS = b"\x04" * 32
SWAP_VALUE = 1000


def make_xmr_interface(
    transfers,
    daemon_height=100,
    target_height=0,
    wallet_height=100,
):
    ci = XMRInterface.__new__(XMRInterface)
    ci._log = StubLog()
    ci._mx_wallet = threading.Lock()
    ci._addr_prefix = 18
    ci._rpctimeout = 60
    ci.getPubkey = lambda k: b"\x02" * 32
    ci.openWallet = lambda name: None
    ci.createWallet = lambda params: None

    shared_addr = xmr_util.encode_address(b"\x02" * 32, PKBS, 18)

    def rpc_wallet(method, params=None):
        if method == "refresh":
            return {}
        if method == "get_address":
            return {"address": shared_addr}
        if method == "incoming_transfers":
            return {"transfers": transfers}
        if method == "get_height":
            return {"height": wallet_height}
        raise RuntimeError(f"unexpected wallet rpc {method}")

    def rpc2(method, params=None, timeout=None):
        if method == "get_info":
            return {"height": daemon_height, "target_height": target_height}
        raise RuntimeError(f"unexpected daemon rpc {method}")

    ci.rpc_wallet = rpc_wallet
    ci.rpc2 = rpc2
    return ci


class TestFindTxBSyncGate(unittest.TestCase):
    def find_tx_b(self, ci):
        return ci.findTxB(KBV, PKBS, SWAP_VALUE, 2, 1, True)

    def test_not_found_synced_returns_none(self):
        ci = make_xmr_interface([])
        self.assertIsNone(self.find_tx_b(ci))

    def test_not_found_daemon_syncing_raises(self):
        ci = make_xmr_interface([], daemon_height=90, target_height=100)
        with self.assertRaises(TemporaryError):
            self.find_tx_b(ci)

    def test_not_found_wallet_behind_raises(self):
        ci = make_xmr_interface([], daemon_height=100, wallet_height=50)
        with self.assertRaises(TemporaryError):
            self.find_tx_b(ci)

    def test_found_while_syncing_returns_tx(self):
        transfers = [
            {
                "unlocked": True,
                "amount": SWAP_VALUE,
                "tx_hash": "dd" * 32,
                "block_height": 5,
            }
        ]
        ci = make_xmr_interface(transfers, daemon_height=90, target_height=100)
        found = self.find_tx_b(ci)
        self.assertEqual(found["txid"], "dd" * 32)


if __name__ == "__main__":
    unittest.main()
