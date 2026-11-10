# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Unit tests for queued action retries: transient daemon/RPC/Electrum failures
must retry the action instead of erroring the bid and deleting the action row.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import ActionTypes, BidStates
from basicswap.chainparams import Coins

BID_ID = b"b" * 28
ACTION_ID = 7


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


class StubCI:
    def is_transient_error(self, ex) -> bool:
        return "daemon is busy" in str(ex).lower()


class FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class FakeCursor:
    def __init__(self, action_rows):
        self.action_rows = action_rows
        self.executed = []

    def execute(self, query, params=None):
        self.executed.append((query, params))
        if query.startswith("SELECT action_id"):
            return FakeResult(self.action_rows)
        if query.startswith("SELECT COUNT(*) FROM actions"):
            return FakeResult([(0,)])
        return FakeResult([])


def make_swap_client(action_rows):
    sc = BasicSwap.__new__(BasicSwap)
    sc.fp = None
    sc.log = StubLog()
    sc.debug = False
    sc.debug_logs = False
    sc.delay_event = SimpleNamespace(is_set=lambda: False)
    sc.errored_bids = []
    sc.events = []

    cursor = FakeCursor(action_rows)
    sc._test_cursor = cursor

    offer = SimpleNamespace(
        offer_id=b"offer",
        coin_from=int(Coins.BTC),
        coin_to=int(Coins.PART),
        bid_reversed=False,
    )
    bid = SimpleNamespace(
        bid_id=BID_ID,
        offer_id=b"offer",
        state=BidStates.SWAP_INITIATED,
        states=b"",
        setState=lambda s: sc.errored_bids.append(s),
    )

    sc.isSystemUnlocked = lambda: True
    sc.getTime = lambda: 1000
    sc.openDB = lambda cursor=None: cursor or sc._test_cursor
    sc.closeDB = lambda cursor, commit=True: None
    sc.logException = lambda msg: None
    sc.logEvent = lambda concept, linked_id, event, msg, cursor: sc.events.append(event)
    sc.getBidAndOffer = lambda bid_id, cursor=None: (bid, offer)
    sc.getBid = lambda bid_id, cursor=None: bid
    sc.saveBidInSession = lambda bid_id, bid, cursor, xmr_swap=None: None
    sc.ci = lambda coin: StubCI()
    sc.handleSessionErrors = lambda ex, cursor, tag: (_ for _ in ()).throw(
        AssertionError(f"handleSessionErrors reached: {ex}")
    )
    return sc


def run_actions_with_error(error):
    action_rows = [(ACTION_ID, int(ActionTypes.REDEEM_ITX), BID_ID)]
    sc = make_swap_client(action_rows)

    def failing_redeem(swap_client, bid_id, cursor):
        raise error

    with patch(
        "basicswap.basicswap.atomic_swap_1.redeemITx", side_effect=failing_redeem
    ):
        sc.checkQueuedActions()
    return sc


def retried_action_ids(sc):
    for query, params in sc._test_cursor.executed:
        if "NOT IN" in query and params:
            return [v for k, v in params.items() if k.startswith("retry_")]
    return []


class TestTransientErrorMatching(unittest.TestCase):
    def make_client(self):
        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        return sc

    def test_connection_class_errors_are_transient(self):
        sc = self.make_client()
        for msg in (
            "RPC server error: [Errno 111] Connection refused, method: getblockcount",
            "RPC server error: [Errno 104] Connection reset by peer",
            "RPC server error: [Errno 32] Broken pipe",
            "RPC server error: Remote end closed connection without response",
            "Read timed out",
        ):
            self.assertTrue(sc.is_transient_error(ValueError(msg)), msg)

    def test_core_warmup_errors_are_transient(self):
        sc = self.make_client()
        for msg in (
            "RPC error {'code': -28, 'message': 'Loading block index…'}",
            "RPC error {'code': -28, 'message': 'Verifying blocks…'}",
            "RPC error {'code': -28, 'message': 'Rewinding blocks…'}",
            "RPC error {'code': -28, 'message': 'Activating best chain…'}",
            "RPC error {'code': -28, 'message': 'Loading wallet…'}",
        ):
            self.assertTrue(sc.is_transient_error(ValueError(msg)), msg)

    def test_electrum_rate_limit_is_transient(self):
        sc = self.make_client()
        self.assertTrue(
            sc.is_transient_error(Exception("Electrum error: excessive resource usage"))
        )

    def test_genuine_errors_are_not_transient(self):
        sc = self.make_client()
        for msg in (
            "bad-txns-inputs-missingorspent",
            "Invalid signature",
            "mandatory-script-verify-flag-failed",
            "Swap output index not found in txn",
        ):
            self.assertFalse(sc.is_transient_error(ValueError(msg)), msg)


class TestQueuedActionRetry(unittest.TestCase):
    def test_transient_error_retries_action(self):
        sc = run_actions_with_error(
            ValueError("RPC server error: [Errno 111] Connection refused")
        )

        self.assertEqual(retried_action_ids(sc), [ACTION_ID])
        self.assertEqual(sc.errored_bids, [])

    def test_coin_interface_transient_error_retries_action(self):
        # Matched only by the coin interface matcher, not the base one.
        sc = run_actions_with_error(ValueError("daemon is busy"))

        self.assertEqual(retried_action_ids(sc), [ACTION_ID])
        self.assertEqual(sc.errored_bids, [])

    def test_permanent_error_still_errors_bid(self):
        sc = run_actions_with_error(ValueError("bad-txns-inputs-missingorspent"))

        self.assertEqual(retried_action_ids(sc), [])
        self.assertEqual(sc.errored_bids, [BidStates.BID_ERROR])


if __name__ == "__main__":
    unittest.main()


def make_activation_client():
    from basicswap.basicswap_util import SwapTypes
    from basicswap.db import Bid, Offer, XmrSwap
    from basicswap.interface.btc.btc import BTCInterface
    from basicswap.util.logging import BSXLogger
    from tests.basicswap.util.common import REQUIRED_SETTINGS

    coin_settings = {"rpcport": 0, "rpcauth": "none"}
    coin_settings.update(REQUIRED_SETTINGS)
    ci = BTCInterface(coin_settings, "regtest")
    ci._log = BSXLogger("test")
    ci._connection_type = "electrum"
    backend = SimpleNamespace(_server=SimpleNamespace(primary_key=lambda: "a"))
    ci._backend = backend
    ci.getBackend = lambda: backend
    ci._header_syncs = {"a": object()}
    header = {
        "version": 1,
        "prev_block_hash": "00" * 32,
        "merkle_root": "00" * 32,
        "timestamp": 1700000000,
        "bits": 0x207FFFFF,
        "nonce": 0,
        "block_height": 100,
    }
    ci._readHeaderElectrum = lambda sync, height: header

    offer = Offer(
        offer_id=b"offer",
        coin_from=int(Coins.BTC),
        coin_to=int(Coins.BTC),
        swap_type=int(SwapTypes.XMR_SWAP),
    )
    bid = Bid(
        bid_id=BID_ID,
        offer_id=b"offer",
        state=int(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED),
        in_progress=1,
        chain_a_height_start=100,
        was_sent=False,
        was_received=True,
    )
    bid.txns = {}
    bid.xmr_a_lock_tx = None
    bid.xmr_b_lock_tx = None
    xmr_swap = XmrSwap()

    sc = BasicSwap.__new__(BasicSwap)
    sc.fp = None
    sc.log = BSXLogger("test")
    sc.swaps_in_progress = {}
    sc._activate_retry = set()
    sc.coin_clients = {
        Coins.BTC: {
            "watched_outputs": [],
            "watched_transactions": [],
            "watched_scripts": [],
            "last_height_checked": 0,
        }
    }
    sc.ci = lambda coin_type: ci
    sc.is_reverse_ads_bid = lambda coin_from, coin_to: False
    sc.isSystemUnlocked = lambda: True
    sc.openDB = lambda cursor=None: "cursor"
    sc.getNewDBCursor = lambda: "bid_cursor"
    sc.closeDB = lambda cursor, commit=True: None
    sc.closeDBCursor = lambda cursor: None
    sc.query = lambda cls, cursor, *args, **kwargs: [bid]
    sc.queryOne = lambda cls, cursor, filters: {
        Bid: bid,
        XmrSwap: xmr_swap,
        Offer: offer,
    }[cls]
    sc.getOffer = lambda offer_id, cursor=None: offer
    sc.loadBidTxns = lambda bid, cursor: None
    sc.buildNotificationsCache = lambda cursor: None
    sc.setIntKV = lambda *args, **kwargs: None
    sc.kv = {}
    sc.getStringKV = lambda key, cursor=None: sc.kv.get(key)
    sc.events = []
    sc.logEvent = lambda concept, linked_id, event, msg, cursor: sc.events.append(event)
    sc.logException = lambda msg: None
    sc.deactivated = []
    sc.deactivateBid = lambda cursor, offer, bid: sc.deactivated.append(bid.bid_id)
    return sc, ci


class TestBidActivationRetry(unittest.TestCase):
    def test_unsynced_headers_retry_activation(self):
        from basicswap.basicswap_util import EventLogTypes

        sc, ci = make_activation_client()

        sc.loadFromDB()
        self.assertEqual(sc._activate_retry, {BID_ID})
        self.assertNotIn(BID_ID, sc.swaps_in_progress)

        ci._headers_synced = True
        sc.retryBidActivation()
        self.assertEqual(sc._activate_retry, set())
        self.assertIn(BID_ID, sc.swaps_in_progress)
        self.assertEqual(sc.deactivated, [])
        self.assertNotIn(EventLogTypes.ERROR, sc.events)

    def test_recorded_lock_tx_inputs_locked_again(self):
        import json

        from basicswap.contrib.test_framework.messages import (
            COutPoint,
            CTransaction,
            CTxIn,
            CTxOut,
        )

        sc, ci = make_activation_client()
        ci._headers_synced = True
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(5, 1)))
        tx.vin.append(CTxIn(COutPoint(6, 2)))
        tx.vout.append(CTxOut(1000, b"\x51"))
        sc.kv[f"b_lock_tx:{BID_ID.hex()}"] = json.dumps(
            {"tx": tx.serialize().hex(), "vout": 0, "bids": [BID_ID.hex()]}
        )
        locked = []

        def lock_utxo(coin_type, txid, vout, bid_id=None, expires_in=0, cursor=None):
            locked.append((txid, vout, bid_id, expires_in))

        ci.getWalletManager = lambda: SimpleNamespace(lockUTXO=lock_utxo)

        sc.loadFromDB()
        self.assertIn(BID_ID, sc.swaps_in_progress)
        self.assertEqual(
            locked,
            [
                (f"{5:064x}", 1, BID_ID, 86400),
                (f"{6:064x}", 2, BID_ID, 86400),
            ],
        )
