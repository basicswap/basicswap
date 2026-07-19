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
from basicswap.multibid import plan_batch_decision
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
                "pending": [
                    {"txid": "cd" * 32, "destinations": self.pending_destinations}
                ]
            }
        return {}

    def lock_address(self, kbv: bytes, Kbs: bytes) -> str:
        return xmr_util.encode_address(self.getPubkey(kbv), Kbs, self._addr_prefix)


class TestXmrPublishBLockTxs(unittest.TestCase):

    def test_locks_every_swap_in_one_transfer(self):
        ci = FakeXmr()

        txid = ci.publishBLockTxs(
            [
                (key(1), key(2), 100),
                (key(3), key(4), 250),
                (key(5), key(6), 375),
            ]
        )

        self.assertEqual(txid, bytes.fromhex("ab" * 32))

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
        # Only the second leg's address is in flight; the batch is still one tx.
        ci.pending_destinations = [{"address": ci.lock_address(key(3), key(4))}]

        txid = ci.publishBLockTxs(locks, 0)

        self.assertEqual(txid, bytes.fromhex("cd" * 32))
        self.assertEqual([m for m, _ in ci.calls if m == "transfer"], [])

    def test_an_unrelated_pending_send_does_not_block_the_batch(self):
        ci = FakeXmr()
        ci.pending_destinations = [{"address": ci.lock_address(key(9), key(9))}]

        txid = ci.publishBLockTxs([(key(1), key(2), 100)], 0)

        self.assertEqual(txid, bytes.fromhex("ab" * 32))
        self.assertEqual(len([m for m, _ in ci.calls if m == "transfer"]), 1)

    def test_single_lock_keeps_its_in_flight_guard(self):
        ci = FakeXmr()
        ci.pending_destinations = [{"address": ci.lock_address(key(1), key(2))}]

        txid = ci.publishBLockTx(key(1), key(2), 100, 0)

        self.assertEqual(txid, bytes.fromhex("cd" * 32))
        self.assertEqual([m for m, _ in ci.calls if m == "transfer"], [])

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

        txid = ci.publishBLockTxs(
            [
                (key(1), key(2), make_int(1)),
                (key(3), key(4), make_int(2)),
                (key(5), key(6), make_int(3)),
            ],
            1000,
        )

        self.assertEqual(txid, bytes.fromhex("ab" * 32))

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


if __name__ == "__main__":
    unittest.main()


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


if __name__ == "__main__":
    unittest.main()
