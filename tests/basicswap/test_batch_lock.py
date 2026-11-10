#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import threading
import unittest

import basicswap.util_xmr as xmr_util

from basicswap.basicswap_util import BidStates
from basicswap.interface.part.part import (
    PARTInterfaceAnon,
    PARTInterfaceBlind,
)
from basicswap.interface.xmr.xmr import XMRInterface
from basicswap.multibid import (
    plan_batch_decision,
    plan_htlc_batch,
    HTLC_WAITING_STATES,
)
from basicswap.util import format_amount, make_int


def key(seed: int) -> bytes:
    return bytes([seed]) * 32


class FakeXmr:
    """Just enough of XMRInterface to exercise publishBLockTxs."""

    publishBLockTx = XMRInterface.publishBLockTx
    publishBLockTxs = XMRInterface.publishBLockTxs
    findPendingLockTx = XMRInterface.findPendingLockTx

    def __init__(self):
        self._mx_wallet = threading.Lock()
        self._wallet_filename = "wallet"
        self._addr_prefix = 18
        self._fee_priority = 0
        self._log = logging.getLogger("test")
        self._log.id = lambda v: v
        self._log.addr = lambda v: v
        self.calls = []
        self.pending_destinations = []
        self.pending_tag = "pending"

    def coin_name(self) -> str:
        return "Monero"

    def openWallet(self, filename):
        self.calls.append(("openWallet", filename))

    def getPubkey(self, k: bytes) -> bytes:
        return k

    def rpc_wallet(self, method, params=None):
        self.calls.append((method, params))
        if method == "transfer":
            return {"tx_hash": "ab" * 32}
        if method == "get_transfers":
            if not self.pending_destinations:
                return {}
            return {
                self.pending_tag: [
                    {"txid": "cd" * 32, "destinations": self.pending_destinations}
                ]
            }
        return {}

    def lock_address(self, kbv: bytes, Kbs: bytes) -> str:
        return xmr_util.encode_address(self.getPubkey(kbv), Kbs, self._addr_prefix)


def paid_addresses(ci, txid: bytes) -> set:
    """The addresses the tx returned by a publish actually pays."""
    if txid == bytes.fromhex("ab" * 32):
        params = [p for method, p in ci.calls if method == "transfer"][-1]
        return {d["address"] for d in params["destinations"]}
    return {d["address"] for d in ci.pending_destinations}


class TestXmrPublishBLockTxs(unittest.TestCase):

    def test_locks_every_swap_in_one_transfer(self):
        ci = FakeXmr()

        txid, covered = ci.publishBLockTxs(
            [
                (key(1), key(2), 100),
                (key(3), key(4), 250),
                (key(5), key(6), 375),
            ]
        )

        self.assertEqual(txid, bytes.fromhex("ab" * 32))
        self.assertEqual(covered, [0, 1, 2])

        transfers = [params for method, params in ci.calls if method == "transfer"]
        self.assertEqual(len(transfers), 1)

        destinations = transfers[0]["destinations"]
        self.assertEqual([d["amount"] for d in destinations], [100, 250, 375])
        # One output per swap, each to that swap's own shared address.
        self.assertEqual(len({d["address"] for d in destinations}), 3)
        self.assertEqual(transfers[0]["unlock_time"], 0)

    def test_returns_the_in_flight_tx_instead_of_locking_twice(self):
        ci = FakeXmr()
        locks = [(key(1), key(2), 100), (key(3), key(4), 250)]
        ci.pending_destinations = [
            {"address": ci.lock_address(key(1), key(2))},
            {"address": ci.lock_address(key(3), key(4))},
        ]

        txid, covered = ci.publishBLockTxs(locks, 0)

        self.assertEqual(txid, bytes.fromhex("cd" * 32))
        self.assertEqual(covered, [0, 1])
        self.assertEqual([m for m, _ in ci.calls if m == "transfer"], [])

    def test_reports_only_the_locks_the_in_flight_tx_pays(self):
        # A retry can plan a batch the in-flight tx was never built for.
        ci = FakeXmr()
        locks = [(key(1), key(2), 100), (key(3), key(4), 250)]
        # Only the second leg's address is in flight.
        ci.pending_destinations = [{"address": ci.lock_address(key(3), key(4))}]

        txid, covered = ci.publishBLockTxs(locks, 0)

        self.assertEqual(txid, bytes.fromhex("cd" * 32))
        self.assertEqual(covered, [1])
        self.assertEqual([m for m, _ in ci.calls if m == "transfer"], [])

    def test_an_unrelated_pending_send_does_not_block_the_batch(self):
        ci = FakeXmr()
        ci.pending_destinations = [{"address": ci.lock_address(key(9), key(9))}]

        txid, covered = ci.publishBLockTxs([(key(1), key(2), 100)], 0)

        self.assertEqual(txid, bytes.fromhex("ab" * 32))
        self.assertEqual(covered, [0])
        self.assertEqual(len([m for m, _ in ci.calls if m == "transfer"]), 1)

    def test_single_lock_keeps_its_in_flight_guard(self):
        ci = FakeXmr()
        ci.pending_destinations = [{"address": ci.lock_address(key(1), key(2))}]

        txid = ci.publishBLockTx(key(1), key(2), 100, 0)

        self.assertEqual(txid, bytes.fromhex("cd" * 32))
        self.assertEqual([m for m, _ in ci.calls if m == "transfer"], [])

    def test_does_not_reuse_a_tx_that_misses_a_lock_address(self):
        # A retry re-plans the cohort, so a straggler that turned ready in the
        # meantime joins a batch the in-flight tx never paid.
        ci = FakeXmr()
        locks = [(key(1), key(2), 100), (key(3), key(4), 250), (key(5), key(6), 375)]
        wanted_paid = {
            ci.lock_address(key(1), key(2)),
            ci.lock_address(key(3), key(4)),
        }
        ci.pending_destinations = [
            {"address": ci.lock_address(key(1), key(2))},
            {"address": ci.lock_address(key(3), key(4))},
        ]

        txid, covered = ci.publishBLockTxs(locks, 0)

        self.assertEqual(paid_addresses(ci, txid), wanted_paid)
        self.assertEqual(covered, [0, 1])
        self.assertEqual([m for m, _ in ci.calls if m == "transfer"], [])

    def test_does_not_reuse_a_confirmed_tx_that_misses_a_lock_address(self):
        # get_transfers reports a mined lock under "out", so the stale match
        # outlives the mempool.
        ci = FakeXmr()
        ci.pending_tag = "out"
        locks = [(key(1), key(2), 100), (key(5), key(6), 375)]
        wanted_paid = {ci.lock_address(key(1), key(2))}
        ci.pending_destinations = [{"address": ci.lock_address(key(1), key(2))}]

        txid, covered = ci.publishBLockTxs(locks, 0)

        self.assertEqual(paid_addresses(ci, txid), wanted_paid)
        self.assertEqual(covered, [0])

    def test_priority_is_passed_when_set(self):
        ci = FakeXmr()
        ci._fee_priority = 2

        ci.publishBLockTxs([(key(1), key(2), 100)], unlock_time=7)

        params = [p for method, p in ci.calls if method == "transfer"][0]
        self.assertEqual(params["priority"], 2)
        self.assertEqual(params["unlock_time"], 7)


def sx_addr(seed: int) -> str:
    return "SX" + key(seed).hex()


class FakePart:
    """Just enough of the CT interfaces to exercise the lock tx methods."""

    def __init__(self, txns=None):
        self._anon_tx_ring_size = 12
        self._conf_target = 2
        self._log = logging.getLogger("test")
        self._log.id = lambda v: v
        self._txns = txns if txns else []
        self.calls = []

    def formatStealthAddress(self, Kbv, Kbs) -> str:
        return "SX" + Kbs.hex()

    def getPubkey(self, k: bytes) -> bytes:
        return k

    def format_amount(self, v: int) -> str:
        return format_amount(v, 8)

    def make_int(self, v) -> int:
        return make_int(v, 8)

    def rpc(self, method, params=None):
        self.calls.append((method, params))
        if method == "getblockcount":
            return 5000
        return {}

    def rpc_wallet(self, method, params=None):
        self.calls.append((method, params))
        if method == "sendtypeto":
            return "ab" * 32
        if method == "filtertransactions":
            return self._txns
        if method == "getaddressinfo":
            return {"iswatchonly": True}
        return {}


class FakeAnon(FakePart):
    publishBLockTx = PARTInterfaceAnon.publishBLockTx
    publishBLockTxs = PARTInterfaceAnon.publishBLockTxs
    findTxB = PARTInterfaceAnon.findTxB


class FakeBlind(FakePart):
    publishBLockTx = PARTInterfaceBlind.publishBLockTx
    publishBLockTxs = PARTInterfaceBlind.publishBLockTxs
    findTxB = PARTInterfaceBlind.findTxB
    lockWatchOnlyOutput = PARTInterfaceBlind.lockWatchOnlyOutput


def anon_output(seed: int, amount: str, vout: int, out_type: str = "anon") -> dict:
    return {
        "stealth_address": sx_addr(seed),
        "amount": amount,
        "vout": vout,
        "type": out_type,
    }


class TestPartPublishBLockTxs(unittest.TestCase):

    def test_anon_locks_every_swap_in_one_send(self):
        ci = FakeAnon()

        txid, covered = ci.publishBLockTxs(
            [
                (key(1), key(2), make_int(1)),
                (key(3), key(4), make_int(2)),
                (key(5), key(6), make_int(3)),
            ],
            1000,
        )

        self.assertEqual(txid, bytes.fromhex("ab" * 32))
        self.assertEqual(covered, [0, 1, 2])

        sends = [params for method, params in ci.calls if method == "sendtypeto"]
        self.assertEqual(len(sends), 1)

        type_in, type_out, outputs = sends[0][0], sends[0][1], sends[0][2]
        self.assertEqual((type_in, type_out), ("anon", "anon"))
        self.assertEqual(
            [o["amount"] for o in outputs],
            ["1.00000000", "2.00000000", "3.00000000"],
        )
        # One output per swap, each to that swap's own stealth address.
        self.assertEqual(len({o["address"] for o in outputs}), 3)

    def test_blind_locks_every_swap_in_one_send(self):
        ci = FakeBlind()

        ci.publishBLockTxs([(key(1), key(2), make_int(1))], 1000)

        params = [p for method, p in ci.calls if method == "sendtypeto"][0]
        self.assertEqual((params[0], params[1]), ("blind", "blind"))
        self.assertEqual(len(params[2]), 1)

    def test_batched_send_matches_the_single_send_shape(self):
        # The batch must not drift from the per-swap send it replaces.
        one = FakeAnon()
        one.publishBLockTx(key(1), key(2), make_int(1), 1000)
        batched = FakeAnon()
        batched.publishBLockTxs([(key(1), key(2), make_int(1))], 1000)

        single_params = [p for m, p in one.calls if m == "sendtypeto"][0]
        batch_params = [p for m, p in batched.calls if m == "sendtypeto"][0]
        self.assertEqual(single_params, batch_params)


class TestPartFindTxB(unittest.TestCase):

    def test_finds_a_lock_that_is_not_the_first_output(self):
        tx = {
            "txid": "cd" * 32,
            "confirmations": 3,
            "outputs": [
                anon_output(9, "4.00000000", 0),
                anon_output(2, "2.00000000", 2),
            ],
        }
        ci = FakeAnon([tx])

        found = ci.findTxB(key(1), key(2), make_int(2), 1, 0, False)

        self.assertEqual(found["txid"], "cd" * 32)
        self.assertEqual(found["amount"], make_int(2))
        self.assertEqual(found["index"], 2)
        self.assertEqual(found["height"], 4998)

    def test_finds_the_senders_own_lock_among_the_other_outputs(self):
        # The sending wallet sees every lock in the batch, reported negative.
        tx = {
            "txid": "cd" * 32,
            "confirmations": 0,
            "outputs": [
                anon_output(9, "-4.00000000", 0),
                anon_output(2, "-2.00000000", 2),
            ],
        }
        ci = FakeAnon([tx])

        found = ci.findTxB(key(1), key(2), make_int(2), 1, 0, True)

        self.assertEqual(found["amount"], make_int(2))
        self.assertEqual(found["index"], 2)
        self.assertEqual(found["height"], 0)

    def test_skips_a_tx_without_the_wanted_stealth_address(self):
        tx = {
            "txid": "cd" * 32,
            "confirmations": 1,
            "outputs": [anon_output(9, "4.00000000", 0)],
        }
        ci = FakeAnon([tx])

        self.assertIsNone(ci.findTxB(key(1), key(2), make_int(2), 1, 0, False))

    def test_reports_a_batched_lock_of_the_wrong_amount(self):
        tx = {
            "txid": "cd" * 32,
            "confirmations": 1,
            "outputs": [
                anon_output(9, "4.00000000", 0),
                anon_output(2, "1.50000000", 2),
            ],
        }
        ci = FakeAnon([tx])

        self.assertEqual(ci.findTxB(key(1), key(2), make_int(2), 1, 0, False), -1)

    def test_blind_lock_output_must_be_blind(self):
        tx = {
            "txid": "cd" * 32,
            "confirmations": 1,
            "outputs": [
                anon_output(9, "4.00000000", 0),
                anon_output(2, "2.00000000", 2, out_type="anon"),
            ],
        }
        ci = FakeBlind([tx])

        with self.assertRaises(ValueError):
            ci.findTxB(key(1), key(2), make_int(2), 1, 0, False)


class Leg:
    def __init__(
        self,
        bid_id: bytes,
        state,
        xmr_b_lock_tx=None,
        cohort=b"cohort",
        coin_a_seen=False,
        state_time=0,
        is_adaptor=True,
        locks_coin_b=True,
        lock_remaining_seconds=None,
    ):
        self.bid_id = bid_id
        self.state = state
        self.xmr_b_lock_tx = xmr_b_lock_tx
        self.cohort = cohort
        self.coin_a_seen = coin_a_seen
        self.state_time = state_time
        self.is_adaptor = is_adaptor
        self.locks_coin_b = locks_coin_b
        self.lock_remaining_seconds = lock_remaining_seconds


READY = BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED
WAITING = BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX


def decide(legs, bid_id=b"self", **kwargs):
    return plan_batch_decision(legs, bid_id, **kwargs)


class TestPlanBatchDecision(unittest.TestCase):

    def test_batches_ready_siblings_and_excludes_self(self):
        legs = [
            Leg(b"self", READY),
            Leg(b"sib1", READY),
            Leg(b"sib2", READY),
        ]
        plan = decide(legs)
        self.assertFalse(plan.wait)
        self.assertEqual([leg.bid_id for leg in plan.batch], [b"sib1", b"sib2"])
        self.assertEqual(plan.drop, [])

    def test_lone_leg_batches_nothing(self):
        plan = decide([Leg(b"self", READY)])
        self.assertFalse(plan.wait)
        self.assertEqual(plan.batch, [])

    def test_missing_deciding_leg_locks_alone(self):
        plan = decide([Leg(b"sib1", READY), Leg(b"sib2", WAITING)])
        self.assertFalse(plan.wait)
        self.assertEqual(plan.batch, [])
        self.assertEqual(plan.drop, [])

    def test_skips_a_sibling_that_already_locked_its_coin_b(self):
        legs = [
            Leg(b"self", READY),
            Leg(b"sib_done", READY, xmr_b_lock_tx=object()),
        ]
        self.assertEqual(decide(legs).batch, [])

    def test_waits_for_a_seen_but_unconfirmed_sibling(self):
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_wait", WAITING, coin_a_seen=True),
        ]
        plan = decide(legs, now=100, ready_timeout=300)
        self.assertTrue(plan.wait)
        self.assertEqual(plan.drop, [])

    def test_leaves_a_seen_sibling_behind_once_the_timeout_passes(self):
        # Its coin A is funded, so it is never dropped, but a ready cohort is
        # not held for it either: it locks on its own in a later tx.
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_ready", READY),
            Leg(b"sib_wait", WAITING, coin_a_seen=True),
        ]
        plan = decide(legs, now=9999, ready_timeout=300)
        self.assertFalse(plan.wait)
        self.assertEqual([leg.bid_id for leg in plan.batch], [b"sib_ready"])
        self.assertEqual(plan.drop, [])

    def test_waits_for_a_sibling_still_receiving_its_accept(self):
        # An accept split into several messages can take a while to arrive.
        legs = [
            Leg(b"self", READY, state_time=900),
            Leg(b"sib_accepting", BidStates.BID_RECEIVING_ACC),
        ]
        plan = decide(legs, now=1000, ready_timeout=300)
        self.assertTrue(plan.wait)
        self.assertEqual(plan.batch, [])

    def test_waits_for_an_unseen_sibling_before_the_timeout(self):
        legs = [
            Leg(b"self", READY, state_time=900),
            Leg(b"sib_wait", WAITING, coin_a_seen=False),
        ]
        plan = decide(legs, now=1000, ready_timeout=300)  # held 100s < 300s
        self.assertTrue(plan.wait)
        self.assertEqual(plan.drop, [])

    def test_drops_an_unseen_straggler_once_a_ready_leg_waited(self):
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_ready", READY),
            Leg(b"sib_stalled", WAITING, coin_a_seen=False),
        ]
        plan = decide(legs, now=1000, ready_timeout=300)  # held 1000s >= 300s
        self.assertFalse(plan.wait)  # nothing seen-but-pending left to wait for
        self.assertEqual([leg.bid_id for leg in plan.drop], [b"sib_stalled"])
        self.assertEqual([leg.bid_id for leg in plan.batch], [b"sib_ready"])

    def test_drops_an_unaccepted_straggler(self):
        # A leg the maker never accepted (still BID_SENT) has locked nothing, so
        # it is dropped once a ready sibling has waited, same as a stalled one.
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_ready", READY),
            Leg(b"sib_unaccepted", BidStates.BID_SENT, coin_a_seen=False),
        ]
        plan = decide(legs, now=1000, ready_timeout=300)
        self.assertFalse(plan.wait)
        self.assertEqual([leg.bid_id for leg in plan.drop], [b"sib_unaccepted"])

    def test_drops_an_unaccepted_reverse_bid_request(self):
        # Reverse bids sit at BID_REQUEST_SENT before acceptance, the analog of
        # BID_SENT, and must drop the same way.
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_ready", READY),
            Leg(b"sib_unaccepted", BidStates.BID_REQUEST_SENT, coin_a_seen=False),
        ]
        plan = decide(legs, now=1000, ready_timeout=300)
        self.assertEqual([leg.bid_id for leg in plan.drop], [b"sib_unaccepted"])

    def test_waits_for_an_unaccepted_straggler_before_the_timeout(self):
        legs = [
            Leg(b"self", READY, state_time=900),
            Leg(b"sib_unaccepted", BidStates.BID_SENT, coin_a_seen=False),
        ]
        plan = decide(legs, now=1000, ready_timeout=300)  # held 100s < 300s
        self.assertTrue(plan.wait)
        self.assertEqual(plan.drop, [])

    def test_waits_out_a_block_interval_for_a_seen_coin_a(self):
        # A bitcoin lock seen at the 10 minute arrival deadline is not abandoned
        # for taking a normal block interval to confirm.
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_ready", READY),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        plan = decide(legs, now=1200, ready_timeout=600, confirm_timeout=1800)
        self.assertTrue(plan.wait)
        self.assertEqual(plan.drop, [])

    def test_seen_leg_is_left_behind_once_its_own_deadline_passes(self):
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_ready", READY),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        plan = decide(legs, now=1900, ready_timeout=600, confirm_timeout=1800)
        self.assertFalse(plan.wait)
        self.assertEqual(plan.drop, [])
        self.assertEqual([leg.bid_id for leg in plan.batch], [b"sib_ready"])

    def test_drops_an_unseen_leg_while_still_waiting_on_a_seen_one(self):
        # The two deadlines run at once: the no-show is cut at 600s while the
        # confirming sibling still holds the batch.
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
            Leg(b"sib_stalled", WAITING, coin_a_seen=False),
        ]
        plan = decide(legs, now=1200, ready_timeout=600, confirm_timeout=1800)
        self.assertTrue(plan.wait)
        self.assertEqual([leg.bid_id for leg in plan.drop], [b"sib_stalled"])

    def test_confirm_wait_defaults_to_the_arrival_deadline(self):
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        self.assertFalse(decide(legs, now=700, ready_timeout=600).wait)

    def test_holds_while_the_refund_window_clears_the_release_margin(self):
        legs = [
            Leg(b"self", READY, state_time=0, lock_remaining_seconds=2 * 60 * 60),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        plan = decide(
            legs, now=700, ready_timeout=600, confirm_timeout=1800, lock_margin=3600
        )
        self.assertTrue(plan.wait)

    def test_stops_holding_before_the_leader_can_no_longer_release(self):
        # 1.4x the margin left: the coin B lock would confirm too late for the
        # leader's own release check, so lock now instead of waiting.
        legs = [
            Leg(b"self", READY, state_time=0, lock_remaining_seconds=5040),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        plan = decide(
            legs, now=700, ready_timeout=600, confirm_timeout=1800, lock_margin=3600
        )
        self.assertFalse(plan.wait)
        self.assertEqual(plan.drop, [])

    def test_hold_follows_the_leg_with_the_least_window_left(self):
        legs = [
            Leg(b"self", READY, state_time=0, lock_remaining_seconds=48 * 60 * 60),
            Leg(b"sib_ready", READY, state_time=0, lock_remaining_seconds=5040),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        plan = decide(
            legs, now=700, ready_timeout=600, confirm_timeout=1800, lock_margin=3600
        )
        self.assertFalse(plan.wait)

    def test_a_lowered_margin_still_leaves_room_to_confirm(self):
        # 25 min left against a 10 min margin: too little for the coin B lock to
        # confirm before the peer checks its own clock.
        legs = [
            Leg(b"self", READY, state_time=0, lock_remaining_seconds=1500),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        plan = decide(
            legs, now=700, ready_timeout=600, confirm_timeout=1800, lock_margin=600
        )
        self.assertFalse(plan.wait)

    def test_an_unmeasurable_window_does_not_stop_the_hold(self):
        # Block height locks (regtest) carry no seconds to compare.
        legs = [
            Leg(b"self", READY, state_time=0, lock_remaining_seconds=None),
            Leg(b"sib_seen", WAITING, coin_a_seen=True),
        ]
        plan = decide(
            legs, now=700, ready_timeout=600, confirm_timeout=1800, lock_margin=3600
        )
        self.assertTrue(plan.wait)

    def test_a_closing_window_still_drops_a_no_show(self):
        # The timelock stops the waiting, but dropping stays tied to the
        # straggler's own deadline.
        legs = [
            Leg(b"self", READY, state_time=0, lock_remaining_seconds=5040),
            Leg(b"sib_stalled", WAITING, coin_a_seen=False),
        ]
        plan = decide(
            legs, now=700, ready_timeout=600, confirm_timeout=1800, lock_margin=3600
        )
        self.assertFalse(plan.wait)
        self.assertEqual([leg.bid_id for leg in plan.drop], [b"sib_stalled"])

    def test_ready_anchor_uses_the_longest_held_leg(self):
        # self only just became ready, but a sibling has been ready for ages, so
        # the unseen straggler is still cut.
        legs = [
            Leg(b"self", READY, state_time=990),
            Leg(b"sib_ready", READY, state_time=0),
            Leg(b"sib_stalled", WAITING, coin_a_seen=False),
        ]
        plan = decide(legs, now=1000, ready_timeout=300)
        self.assertEqual([leg.bid_id for leg in plan.drop], [b"sib_stalled"])

    def test_ignores_a_different_cohort(self):
        legs = [
            Leg(b"self", READY, cohort=b"A"),
            Leg(b"other", READY, cohort=b"B"),
            Leg(b"other_wait", WAITING, cohort=b"B", coin_a_seen=False),
        ]
        plan = decide(legs, now=9999, ready_timeout=1)
        self.assertFalse(plan.wait)
        self.assertEqual(plan.batch, [])  # cohort B is not ours
        self.assertEqual(plan.drop, [])

    def test_ignores_a_leg_whose_coin_b_the_counterparty_owes(self):
        # A reverse self-bid leg both sent and received, so it locks its own
        # coin B, but a sibling on someone else's offer is led by us and its
        # maker owes the coin B: batching it would fund both sides.
        legs = [
            Leg(b"self", READY, locks_coin_b=True),
            Leg(b"we_lead", READY, locks_coin_b=False),
        ]
        plan = decide(legs)
        self.assertFalse(plan.wait)
        self.assertEqual(plan.batch, [])
        self.assertEqual(plan.drop, [])

    def test_ignores_secret_hash_legs(self):
        # A secret-hash sibling shares BID_ACCEPTED but must not be waited on or
        # dropped by the adaptor-sig batch.
        legs = [
            Leg(b"self", READY, state_time=0),
            Leg(b"sh", BidStates.BID_ACCEPTED, coin_a_seen=False, is_adaptor=False),
        ]
        plan = decide(legs, now=9999, ready_timeout=1)
        self.assertFalse(plan.wait)
        self.assertEqual(plan.drop, [])
        self.assertEqual(plan.batch, [])

    def test_batch_is_capped_to_the_output_limit(self):
        legs = [Leg(b"self", READY)] + [Leg(bytes([i]), READY) for i in range(1, 6)]
        # cap 3 outputs => self + 2 siblings.
        plan = decide(legs, cap=3)
        self.assertEqual(len(plan.batch), 2)
        self.assertFalse(plan.wait)


class HTLCLeg:
    def __init__(
        self,
        bid_id,
        state=BidStates.SWAP_INITIATED,
        ptx_sent=False,
        state_time=0,
        cohort=b"plan",
        sends_ptx=True,
        itx_seen=False,
        lock_value=24 * 60 * 60,
        lock_remaining_seconds=None,
    ):
        self.bid_id = bid_id
        self.state = state
        self.ptx_sent = ptx_sent
        self.state_time = state_time
        self.cohort = cohort
        self.sends_ptx = sends_ptx
        self.itx_seen = itx_seen
        self.lock_value = lock_value
        self.lock_remaining_seconds = lock_remaining_seconds


class TestPlanHTLCBatch(unittest.TestCase):
    def decide(self, legs, **kwargs):
        kwargs.setdefault("now", 0)
        return plan_htlc_batch(legs, b"self", **kwargs)

    def test_batches_every_ready_leg(self):
        legs = [HTLCLeg(b"self"), HTLCLeg(b"a"), HTLCLeg(b"b")]
        plan = self.decide(legs)
        self.assertFalse(plan.wait)
        self.assertEqual([leg.bid_id for leg in plan.batch], [b"a", b"b"])

    def test_waits_for_a_leg_in_any_state_before_its_initiate_confirms(self):
        # The bug this guards: only BID_ACCEPTED counted, so a leg part way
        # through acceptance read as never coming and its siblings sent alone.
        for state in HTLC_WAITING_STATES:
            legs = [HTLCLeg(b"self"), HTLCLeg(b"a", state=state)]
            plan = self.decide(legs, ready_timeout=60)
            self.assertTrue(plan.wait, state.name)
            self.assertEqual(plan.batch, [], state.name)

    def test_does_not_wait_on_a_leg_that_has_finished_or_failed(self):
        for state in (BidStates.SWAP_COMPLETED, BidStates.BID_ERROR):
            legs = [HTLCLeg(b"self"), HTLCLeg(b"a", state=state)]
            self.assertFalse(self.decide(legs, ready_timeout=60).wait, state.name)

    def test_gives_a_seen_initiate_tx_the_longer_deadline(self):
        # Arrival is a peer's responsiveness, confirmation is a chain's block
        # time, so a leg already seen is not dropped from the batch for being a
        # block behind.
        legs = [
            HTLCLeg(b"self", state_time=-100),
            HTLCLeg(b"a", state=BidStates.BID_ACCEPTED, itx_seen=True),
        ]
        self.assertTrue(self.decide(legs, ready_timeout=60, confirm_timeout=600).wait)
        legs[1].itx_seen = False
        self.assertFalse(self.decide(legs, ready_timeout=60, confirm_timeout=600).wait)

    def test_will_not_hold_past_a_legs_redeem_window(self):
        # The seller may sit on the participate txn until half the contract has
        # run, so that half has to outlast the hold.
        waiting = HTLCLeg(b"a", state=BidStates.BID_ACCEPTED)
        roomy = HTLCLeg(b"self", lock_value=7200, lock_remaining_seconds=7000)
        self.assertTrue(self.decide([roomy, waiting], ready_timeout=600).wait)

        tight = HTLCLeg(b"self", lock_value=7200, lock_remaining_seconds=3800)
        self.assertFalse(self.decide([tight, waiting], ready_timeout=600).wait)

    def test_still_batches_ready_legs_when_it_cannot_hold(self):
        # Refusing to wait must not cost the legs that are already ready.
        tight = HTLCLeg(b"self", lock_value=7200, lock_remaining_seconds=3800)
        legs = [tight, HTLCLeg(b"a"), HTLCLeg(b"b", state=BidStates.BID_ACCEPTED)]
        plan = self.decide(legs, ready_timeout=600)
        self.assertFalse(plan.wait)
        self.assertEqual([leg.bid_id for leg in plan.batch], [b"a"])

    def test_an_unmeasurable_window_does_not_block_a_hold(self):
        legs = [
            HTLCLeg(b"self", lock_remaining_seconds=None),
            HTLCLeg(b"a", state=BidStates.BID_ACCEPTED),
        ]
        self.assertTrue(self.decide(legs, ready_timeout=600).wait)

    def test_stops_waiting_once_the_timeout_lapses(self):
        legs = [HTLCLeg(b"self"), HTLCLeg(b"a", state=BidStates.BID_ACCEPTED)]
        plan = self.decide(legs, now=9999, ready_timeout=60)
        self.assertFalse(plan.wait)
        self.assertEqual(plan.batch, [])

    def test_skips_a_leg_that_already_sent_its_participate_tx(self):
        legs = [HTLCLeg(b"self"), HTLCLeg(b"a", ptx_sent=True)]
        plan = self.decide(legs)
        self.assertEqual(plan.batch, [])

    def test_ignores_legs_of_another_cohort(self):
        legs = [
            HTLCLeg(b"self"),
            HTLCLeg(b"a", state=BidStates.BID_ACCEPTED, cohort=b"retry"),
        ]
        self.assertFalse(self.decide(legs, ready_timeout=60).wait)

    def test_ignores_a_leg_whose_participate_tx_is_not_ours(self):
        legs = [HTLCLeg(b"self"), HTLCLeg(b"a", sends_ptx=False)]
        self.assertEqual(self.decide(legs).batch, [])

    def test_batch_is_capped_to_the_output_limit(self):
        legs = [HTLCLeg(b"self")] + [HTLCLeg(bytes((i,))) for i in range(5)]
        self.assertEqual(len(self.decide(legs, cap=3).batch), 2)

    def test_sends_alone_when_absent_from_its_own_plan(self):
        plan = self.decide([HTLCLeg(b"other")])
        self.assertFalse(plan.wait)
        self.assertEqual(plan.batch, [])


if __name__ == "__main__":
    unittest.main()


class TestBLockTxRetry(unittest.TestCase):
    def make_client(self, ci_cls=None, publish_errors=()):
        from types import SimpleNamespace

        from basicswap.basicswap import BasicSwap
        from basicswap.basicswap_util import SwapTypes, TxTypes
        from basicswap.chainparams import Coins
        from basicswap.contrib.test_framework.messages import COutPoint, CTxIn
        from basicswap.db import Bid, Offer, SwapTx, XmrOffer, XmrSwap
        from basicswap.interface.bch.bch import BCHInterface
        from basicswap.util.logging import BSXLogger
        from tests.basicswap.util.common import REQUIRED_SETTINGS

        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = (ci_cls or BCHInterface)(coin_settings, "regtest")
        ci._log = BSXLogger("test")
        funded = []

        def fund_tx(tx_bytes, feerate, bid_id=None, cursor=None):
            funded.append(bid_id)
            tx = ci.loadTx(tx_bytes, allow_witness=False)
            tx.vin.append(CTxIn(COutPoint(len(funded), 0)))
            return tx.serialize()

        published = []
        publish_errors = list(publish_errors)

        def publish_tx(tx_bytes):
            published.append(tx_bytes)
            if publish_errors:
                raise publish_errors.pop(0)
            return ci.getTxid(tx_bytes).hex()

        wallet_txids = set()
        wallet_errors = []

        def rpc_wallet(method, params=[]):
            assert method == "gettransaction"
            if wallet_errors:
                raise wallet_errors[0]
            if bytes.fromhex(params[0]) not in wallet_txids:
                raise ValueError(
                    "RPC error {'code': -5, 'message': 'Invalid or non-wallet transaction id'}"
                )
            return {}

        unlocked = []
        a_lock = {"info": {"depth": 2, "height": 100}}
        ci.blocks_confirmed = 2
        ci.getLockTxHeight = lambda *args, **kwargs: a_lock["info"]
        ci.isAddressMine = lambda address, or_watch_only=False: True
        ci.fundTx = fund_tx
        ci.signTxWithWallet = lambda tx_bytes: tx_bytes
        ci.publishTx = publish_tx
        ci.rpc_wallet = rpc_wallet
        ci.unlockInputs = lambda tx_data, cursor=None: unlocked.append(tx_data)

        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc.debug = False
        sc.debug_logs = False
        sc.log = BSXLogger("test")
        bid_id = bytes(range(28))
        bid = Bid(
            bid_id=bid_id,
            offer_id=bytes(28),
            state=int(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED),
            amount_to=make_int(1.5),
            was_sent=True,
        )
        bid.xmr_b_lock_tx = None
        bid.xmr_a_lock_tx = SwapTx(
            bid_id=bid_id, tx_type=TxTypes.XMR_SWAP_A_LOCK, txid=bytes(32), vout=0
        )
        xmr_swap = XmrSwap(
            vkbv=key(1), pkbs=ci.getPubkey(key(2)), a_lock_tx_script=bytes([0x51])
        )
        sibling_id = bytes(range(1, 29))
        sibling = Bid(
            bid_id=sibling_id,
            offer_id=bytes(28),
            state=int(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED),
            amount_to=make_int(0.5),
            was_sent=True,
        )
        sibling.xmr_b_lock_tx = None
        sibling.xmr_a_lock_tx = SwapTx(
            bid_id=sibling_id, tx_type=TxTypes.XMR_SWAP_A_LOCK, txid=bytes(32), vout=0
        )
        sibling_swap = XmrSwap(
            vkbv=key(3), pkbs=ci.getPubkey(key(4)), a_lock_tx_script=bytes([0x51])
        )
        bids = {bid_id: (bid, xmr_swap), sibling_id: (sibling, sibling_swap)}
        offer = Offer(
            offer_id=bytes(28),
            coin_from=int(Coins.BTC),
            coin_to=int(ci.coin_type()),
            swap_type=int(SwapTypes.XMR_SWAP),
        )
        xmr_offer = XmrOffer(a_fee_rate=1000, b_fee_rate=1000)
        kv = {}
        actions = []
        events = []
        bid_errors = []
        lock = {"remaining": None, "sibling_remaining": None, "margin": 0}
        sc.getXmrBidFromSession = lambda cursor, bid_id: bids[bid_id]
        sc.getXmrOfferFromSession = lambda cursor, offer_id: (offer, xmr_offer)
        sc.is_reverse_ads_bid = lambda coin_from, coin_to: False
        sc.ci = lambda coin_type: ci
        sc.getBLockMinMargin = lambda ci_to: lock["margin"]
        sc.getLegLockRemaining = lambda leg, *args: lock[
            "sibling_remaining" if leg is sibling else "remaining"
        ]
        sc.getPreFundedTx = lambda *args, **kwargs: None
        sc.getStringKV = lambda key, cursor=None: kv.get(key)
        sc.setStringKV = lambda key, value, cursor=None: kv.__setitem__(key, value)
        sc.clearStringKV = lambda key, cursor=None: kv.pop(key, None)
        sc.commitDB = lambda: None
        sc.logBidEvent = lambda bid_id, event, msg, cursor: events.append(event)
        sc.countBidEvents = lambda bid, event, cursor: events.count(event)
        sc.setBidError = lambda bid, msg, **kwargs: bid_errors.append(msg)
        sc.saveBidInSession = lambda *args, **kwargs: None
        sc.get_delay_retry_seconds = lambda: 1
        sc.createActionInSession = lambda delay, action_type, linked_id, cursor: (
            actions.append(action_type)
        )
        return SimpleNamespace(
            sc=sc,
            ci=ci,
            bid=bid,
            bid_id=bid_id,
            xmr_swap=xmr_swap,
            sibling=sibling,
            sibling_id=sibling_id,
            sibling_swap=sibling_swap,
            kv=kv,
            actions=actions,
            events=events,
            bid_errors=bid_errors,
            lock=lock,
            funded=funded,
            published=published,
            wallet_txids=wallet_txids,
            wallet_errors=wallet_errors,
            unlocked=unlocked,
            a_lock=a_lock,
        )

    def test_retry_publishes_the_recorded_tx(self):
        from basicswap.basicswap_util import ActionTypes
        from basicswap.interface.base import TemporaryError

        c = self.make_client(
            publish_errors=[
                TemporaryError("timed out"),
                TemporaryError("timed out"),
                ValueError("transaction already in block chain"),
            ]
        )

        for attempt in range(2):
            c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
            self.assertIsNone(c.bid.xmr_b_lock_tx)
        self.assertEqual(c.actions, [ActionTypes.SEND_XMR_SWAP_LOCK_TX_B] * 2)
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)

        self.assertEqual(c.funded, [c.bid_id])
        self.assertEqual(len(c.published), 3)
        self.assertEqual(c.published, [c.published[0]] * 3)
        self.assertEqual(c.bid.xmr_b_lock_tx.txid, c.ci.getTxid(c.published[0]))
        self.assertEqual(c.kv, {})

    def test_late_retry_tracks_a_tx_the_node_has(self):
        from basicswap.interface.base import TemporaryError

        c = self.make_client(publish_errors=[TemporaryError("timed out")])
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertIsNone(c.bid.xmr_b_lock_tx)

        c.lock.update(remaining=0, margin=3600)
        c.wallet_txids.add(c.ci.getTxid(c.published[0]))
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)

        self.assertEqual(len(c.published), 1)
        self.assertEqual(c.bid.xmr_b_lock_tx.txid, c.ci.getTxid(c.published[0]))
        self.assertEqual(c.kv, {})

    def test_late_retry_drops_a_tx_the_node_never_got(self):
        from basicswap.basicswap_util import EventLogTypes
        from basicswap.interface.base import TemporaryError

        c = self.make_client(publish_errors=[TemporaryError("timed out")])
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)

        c.lock.update(remaining=0, margin=3600)
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)

        self.assertEqual(len(c.published), 1)
        self.assertIsNone(c.bid.xmr_b_lock_tx)
        self.assertEqual(c.kv, {})
        self.assertEqual(c.unlocked, [c.published[0]])
        self.assertIn(EventLogTypes.LOCK_TX_B_ABANDONED_LOCK_CLOSE, c.events)

    def test_late_retry_waits_while_the_wallet_lookup_fails(self):
        from basicswap.basicswap_util import EventLogTypes
        from basicswap.interface.base import TemporaryError

        c = self.make_client(publish_errors=[TemporaryError("timed out")])
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)

        c.lock.update(remaining=0, margin=3600)
        c.wallet_errors.append(
            ValueError("RPC server error: timed out, method: gettransaction")
        )
        self.assertRaises(TemporaryError, c.sc.sendXmrBidCoinBLockTx, c.bid_id, None)

        self.assertEqual(len(c.published), 1)
        self.assertEqual(len(c.kv), 1)
        self.assertEqual(c.unlocked, [])
        self.assertNotIn(EventLogTypes.LOCK_TX_B_ABANDONED_LOCK_CLOSE, c.events)

    def record_shared_tx(self, c) -> bytes:
        locks = [
            (swap.vkbv, swap.pkbs, leg.amount_to)
            for leg, swap in ((c.bid, c.xmr_swap), (c.sibling, c.sibling_swap))
        ]
        shared_tx = c.ci.fundBLockTxs(locks, 1000, bid_id=c.bid_id, cursor=None)
        c.sc.recordSignedBLockTx(shared_tx, None, [c.bid_id, c.sibling_id], None)
        return shared_tx

    def test_shared_tx_is_not_published_past_the_margin_of_a_bid_it_pays(self):
        from basicswap.basicswap_util import EventLogTypes

        c = self.make_client()
        shared_tx = self.record_shared_tx(c)
        c.lock.update(remaining=7200, sibling_remaining=0, margin=3600)

        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(c.unlocked, [shared_tx])
        self.assertEqual(len(c.published), 1)
        self.assertNotEqual(c.published[0], shared_tx)
        self.assertEqual(len(c.ci.loadTx(c.published[0]).vout), 1)
        self.assertEqual(c.bid.xmr_b_lock_tx.txid, c.ci.getTxid(c.published[0]))
        self.assertEqual(c.kv, {})

        c.sc.sendXmrBidCoinBLockTx(c.sibling_id, None)
        self.assertEqual(len(c.published), 1)
        self.assertIsNone(c.sibling.xmr_b_lock_tx)
        self.assertIn(EventLogTypes.LOCK_TX_B_ABANDONED_LOCK_CLOSE, c.events)

    def test_dropped_shared_tx_is_dropped_for_every_bid_it_pays(self):
        c = self.make_client()
        shared_tx = self.record_shared_tx(c)
        c.lock.update(remaining=0, sibling_remaining=7200, margin=3600)

        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(c.kv, {})
        self.assertEqual(c.unlocked, [shared_tx])
        self.assertEqual(c.published, [])
        self.assertIsNone(c.bid.xmr_b_lock_tx)

        c.sc.sendXmrBidCoinBLockTx(c.sibling_id, None)
        self.assertEqual(len(c.published), 1)
        self.assertNotEqual(c.published[0], shared_tx)
        self.assertEqual(c.sibling.xmr_b_lock_tx.txid, c.ci.getTxid(c.published[0]))
        self.assertIsNone(c.bid.xmr_b_lock_tx)

    def test_shared_tx_the_node_has_is_tracked_for_every_bid_it_pays(self):
        c = self.make_client()
        shared_tx = self.record_shared_tx(c)
        c.lock.update(remaining=7200, sibling_remaining=0, margin=3600)
        c.wallet_txids.add(c.ci.getTxid(shared_tx))

        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(c.published, [])
        self.assertEqual(c.unlocked, [])
        for leg in (c.bid, c.sibling):
            self.assertEqual(leg.xmr_b_lock_tx.txid, c.ci.getTxid(shared_tx))
        self.assertEqual(c.kv, {})

    def test_shared_tx_is_dropped_for_a_bid_that_left_the_locked_state(self):
        c = self.make_client()
        shared_tx = self.record_shared_tx(c)
        c.sibling.state = int(BidStates.BID_ERROR)

        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(c.unlocked, [shared_tx])
        self.assertEqual(len(c.published), 1)
        self.assertNotEqual(c.published[0], shared_tx)
        self.assertEqual(c.bid.xmr_b_lock_tx.txid, c.ci.getTxid(c.published[0]))
        self.assertIsNone(c.sibling.xmr_b_lock_tx)
        self.assertEqual(c.kv, {})

    def test_shared_tx_the_node_has_is_tracked_for_a_bid_that_left_the_locked_state(
        self,
    ):
        c = self.make_client()
        shared_tx = self.record_shared_tx(c)
        c.sibling.state = int(BidStates.BID_ERROR)
        c.wallet_txids.add(c.ci.getTxid(shared_tx))

        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(c.published, [])
        self.assertEqual(c.unlocked, [])
        self.assertEqual(c.bid.xmr_b_lock_tx.txid, c.ci.getTxid(shared_tx))

    def test_failed_publish_drops_the_record(self):
        c = self.make_client(
            publish_errors=[ValueError("bad-txns-inputs-missingorspent")]
        )
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)

        self.assertEqual(len(c.bid_errors), 1)
        self.assertIsNone(c.bid.xmr_b_lock_tx)
        self.assertEqual(c.kv, {})
        self.assertEqual(c.unlocked, [c.published[0]])

    def test_lock_found_by_lookup_drops_the_record(self):
        from basicswap.interface.base import TemporaryError
        from basicswap.interface.btc.btc import BTCInterface

        c = self.make_client(BTCInterface, [TemporaryError("timed out")])
        found = []
        c.ci.findTxB = lambda *args, **kwargs: found[0] if found else None
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(len(c.kv), 1)

        lock_txid: bytes = c.ci.getTxid(c.published[0])
        found.append(
            {
                "txid": lock_txid.hex(),
                "height": 0,
                "index": 0,
                "value": c.bid.amount_to,
            }
        )
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)

        self.assertEqual(len(c.published), 1)
        self.assertEqual(c.bid.xmr_b_lock_tx.txid, lock_txid)
        self.assertEqual(c.kv, {})

    def test_lock_b_waits_for_a_lock_a_that_left_the_chain(self):
        from basicswap.interface.base import TemporaryError

        c = self.make_client()
        for a_lock_info in (None, {"depth": 1, "height": 101}):
            c.a_lock["info"] = a_lock_info
            self.assertRaises(
                TemporaryError, c.sc.sendXmrBidCoinBLockTx, c.bid_id, None
            )
        self.assertEqual(c.funded, [])
        self.assertEqual(c.published, [])

        c.a_lock["info"] = {"depth": 2, "height": 101}
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(len(c.published), 1)
        self.assertEqual(c.bid.xmr_b_lock_tx.txid, c.ci.getTxid(c.published[0]))

    def test_recorded_tx_is_not_published_again_without_lock_a(self):
        from basicswap.interface.base import TemporaryError

        c = self.make_client(publish_errors=[TemporaryError("timed out")])
        c.sc.sendXmrBidCoinBLockTx(c.bid_id, None)
        self.assertEqual(len(c.published), 1)

        c.a_lock["info"] = None
        self.assertRaises(TemporaryError, c.sc.sendXmrBidCoinBLockTx, c.bid_id, None)
        self.assertEqual(len(c.published), 1)
        self.assertEqual(len(c.kv), 1)

    def test_tx_exists_error_texts(self):
        from basicswap.interface.btc.btc import BTCInterface

        ci = self.make_client(BTCInterface).ci
        for text in (
            "Transaction already in block chain",
            "transaction already in block chain",
            "Transaction outputs already in utxo set",
        ):
            self.assertTrue(ci.isTxExistsError(text))
        self.assertFalse(ci.isTxExistsError("bad-txns-inputs-missingorspent"))
