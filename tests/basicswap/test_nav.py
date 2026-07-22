#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from coincurve.keys import PrivateKey

import types

from basicswap.basicswap_util import (
    EventLogTypes,
    SwapTypes,
    TxLockTypes,
    TxStates,
)
from basicswap.chainparams import Coins
from basicswap.interface.nav.nav import NAVInterface
from basicswap.util import TemporaryError
import basicswap.protocols.atomic_swap_1 as atomic_swap_1
import basicswap.protocols.nav_swap_1 as nav_swap_1
from tests.basicswap.util.common import REQUIRED_SETTINGS


def ci_nav():
    settings = {"rpcport": 0, "rpcauth": "none"}
    settings.update(REQUIRED_SETTINGS)
    return NAVInterface(settings, "regtest")


class TestFakeHTLCScript(unittest.TestCase):
    """Tests for createFakeNonNavHTLCScript and extractHTLCLockVal."""

    def setUp(self):
        self.ci = ci_nav()
        self.secret_hash = bytes(32)

    def test_roundtrip_block_heights(self):
        for lock_value in (1, 100, 123456, 499_999_999):
            script = self.ci.createFakeNonNavHTLCScript(self.secret_hash, lock_value)
            assert (
                self.ci.extractHTLCLockVal(bytes(script), is_nav=False) == lock_value
            ), lock_value

    def test_roundtrip_timestamps(self):
        for lock_value in (500_000_000, 1_700_000_000, 1_800_000_000):
            script = self.ci.createFakeNonNavHTLCScript(self.secret_hash, lock_value)
            assert (
                self.ci.extractHTLCLockVal(bytes(script), is_nav=False) == lock_value
            ), lock_value

    def test_secret_hash_preserved(self):
        secret_hash = bytes(range(32))
        script = self.ci.createFakeNonNavHTLCScript(secret_hash, 123456)
        extracted = atomic_swap_1.extractScriptSecretHash(bytes(script))
        assert extracted == secret_hash

    def test_short_secret_hash_padded(self):
        # extractScriptSecretHash must still recover correct hash after rjust padding
        secret_hash = b"\x01" * 20
        script = self.ci.createFakeNonNavHTLCScript(secret_hash, 100)
        extracted = atomic_swap_1.extractScriptSecretHash(bytes(script))
        assert extracted == secret_hash.rjust(32, b"\x00")


class TestIsHTLCScript(unittest.TestCase):
    """Tests for _isHTLCScript."""

    def setUp(self):
        self.ci = ci_nav()

    def test_valid_script_1_byte_locktime(self):
        # From docstring: 1-byte locktime
        hex1 = (
            "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
            "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
            "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
            "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
            "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
        )
        assert self.ci._isHTLCScript(hex1) is True

    def test_valid_script_4_byte_locktime(self):
        # From docstring: 4-byte locktime
        hex2 = (
            "6382012088a8206756e66c48945a6851790e94fed56b86ec9d1e05116d4d289bf"
            "62f858389c3998830a6c43cded614e403d715cd7f28a57736214937dd811bd7e2927eed4cd"
            "904ee8df0066923c7dc021a36e94fa6f8fa21e36703710040b17530a769dfbee940c4f72c1"
            "29b5a315822dabda7932f5f12b8d1c56d2335544995504af3e11446a3b544cb6ec51403377"
            "33468b3"
        )
        assert self.ci._isHTLCScript(hex2) is True

    def test_invalid_p2pkh(self):
        assert self.ci._isHTLCScript("76a91488ac") is False

    def test_invalid_empty(self):
        assert self.ci._isHTLCScript("") is False

    def test_invalid_zeroes(self):
        assert self.ci._isHTLCScript("00" * 100) is False

    def test_case_insensitive(self):
        hex1 = (
            "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
            "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
            "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
            "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
            "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
        )
        assert self.ci._isHTLCScript(hex1.upper()) is True


class TestDeriveBlindingKey(unittest.TestCase):
    """Tests for deriveBlindingKey."""

    def setUp(self):
        self.ci = ci_nav()
        self.privA = bytes.fromhex(
            "e6b8e7c2ca3a88fe4f28591aa0f91fec340179346559e4ec430c2531aecc19aa"
        )
        self.privB = bytes.fromhex(
            "b725b6359bd2b510d9d5a7bba7bdee17abbf113253f6338ea50a8f0cf45fd0d0"
        )
        self.pubA = PrivateKey(self.privA).public_key.format(compressed=True)
        self.pubB = PrivateKey(self.privB).public_key.format(compressed=True)

    def test_returns_nonzero_int(self):
        key = self.ci.deriveBlindingKey(self.privA, self.pubB)
        assert isinstance(key, int)
        assert key > 0

    def test_ecdh_commutative(self):
        # ECDH(privA, pubB) == ECDH(privB, pubA) — same shared secret
        key_ab = self.ci.deriveBlindingKey(self.privA, self.pubB)
        key_ba = self.ci.deriveBlindingKey(self.privB, self.pubA)
        assert key_ab == key_ba

    def test_different_keys_different_result(self):
        privC = bytes.fromhex(
            "0b4c6e34c21b910f92c7985a8093de526f5f8677a112a8c672d1098139b70e0f"
        )
        pubC = PrivateKey(privC).public_key.format(compressed=True)
        key_ab = self.ci.deriveBlindingKey(self.privA, self.pubB)
        key_ac = self.ci.deriveBlindingKey(self.privA, pubC)
        assert key_ab != key_ac

    def test_deterministic(self):
        key1 = self.ci.deriveBlindingKey(self.privA, self.pubB)
        key2 = self.ci.deriveBlindingKey(self.privA, self.pubB)
        assert key1 == key2


class TestIsTxNonFinalError(unittest.TestCase):
    """Tests for isTxNonFinalError."""

    def setUp(self):
        self.ci = ci_nav()

    def test_non_final_input(self):
        assert self.ci.isTxNonFinalError("non-final-input") is True
        assert (
            self.ci.isTxNonFinalError("sendrawtransaction: non-final-input (code 64)")
            is True
        )

    def test_bad_input_unknown(self):
        assert self.ci.isTxNonFinalError("bad-input-unknown") is True
        assert self.ci.isTxNonFinalError("bad-inputs-unknown") is True

    def test_code_25(self):
        assert (
            self.ci.isTxNonFinalError("{'code': 25, 'message': 'Missing inputs'}")
            is True
        )

    def test_unrelated_errors(self):
        assert self.ci.isTxNonFinalError("insufficient fee") is False
        assert self.ci.isTxNonFinalError("") is False
        assert self.ci.isTxNonFinalError("transaction already in mempool") is False


class TestGetHTLCSpendTxVSize(unittest.TestCase):
    def test_returns_expected_size(self):
        ci = ci_nav()
        assert ci.getHTLCSpendTxVSize(redeem=True) == 1336
        assert ci.getHTLCSpendTxVSize(redeem=False) == 1336


class TestGetSeedHash(unittest.TestCase):
    def test_returns_seed_unchanged(self):
        ci = ci_nav()
        seed = bytes(range(32))
        assert ci.getSeedHash(seed) == seed


class TestGetLockValue(unittest.TestCase):
    """getLockValue: absolute timestamp vs block-height CLTV, ITX vs PTX duration."""

    NOW = 1_700_000_000
    HEIGHT = 2_000_000

    def _ci(self):
        ci = ci_nav()
        ci.getChainHeight = lambda: self.HEIGHT
        ci._sc = types.SimpleNamespace(getTime=lambda: self.NOW)
        return ci

    def _offer(self, lock_type, lock_value):
        return types.SimpleNamespace(lock_type=lock_type, lock_value=lock_value)

    def test_abs_lock_time_initiate_uses_timestamp(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_TIME, 3600)
        assert ci.getLockValue(offer, is_initiate=True) == self.NOW + 3600

    def test_abs_lock_time_participate_is_half(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_TIME, 3600)
        assert ci.getLockValue(offer, is_initiate=False) == self.NOW + 1800

    def test_abs_lock_blocks_initiate_uses_height(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_BLOCKS, 100)
        assert ci.getLockValue(offer, is_initiate=True) == self.HEIGHT + 100

    def test_abs_lock_blocks_participate_is_half(self):
        ci = self._ci()
        offer = self._offer(TxLockTypes.ABS_LOCK_BLOCKS, 100)
        assert ci.getLockValue(offer, is_initiate=False) == self.HEIGHT + 50


class TestIsHTLCTxnSpent(unittest.TestCase):
    """Tests for isHTLCTxnSpent (RPCs stubbed)."""

    # Real HTLC spk that passes _isHTLCScript; secret_hash + lock_val (is_nav=True) below.
    HTLC_HEX = (
        "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
        "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
        "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
        "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
        "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
    )
    # A different valid HTLC spk (different secret_hash) for the no-match case.
    OTHER_HTLC_HEX = (
        "6382012088a8206756e66c48945a6851790e94fed56b86ec9d1e05116d4d289bf"
        "62f858389c3998830a6c43cded614e403d715cd7f28a57736214937dd811bd7e2927eed4cd"
        "904ee8df0066923c7dc021a36e94fa6f8fa21e36703710040b17530a769dfbee940c4f72c1"
        "29b5a315822dabda7932f5f12b8d1c56d2335544995504af3e11446a3b544cb6ec51403377"
        "33468b3"
    )

    def setUp(self):
        self.ci = ci_nav()
        spk = bytes.fromhex(self.HTLC_HEX)
        secret_hash = atomic_swap_1.extractScriptSecretHash(spk)
        lock_val = self.ci.extractHTLCLockVal(spk, is_nav=True)
        # bidder-side stored ITX script (non-NAV fake) sharing the same hash + locktime
        self.script = bytes(self.ci.createFakeNonNavHTLCScript(secret_hash, lock_val))

    def _stub(self, utxos, gettxout=None):
        self.ci._listBlsctUnspent = lambda: utxos
        self.ci.rpc = lambda method, params=None: gettxout

    def test_match_in_utxo_set_is_unspent(self):
        self._stub(
            [{"scriptPubKey": self.HTLC_HEX, "outid": "abc"}], gettxout={"value": 1}
        )
        assert self.ci.isHTLCTxnSpent(self.script) is False

    def test_match_not_in_utxo_set_is_spent(self):
        # gettxout returns empty → output confirmed-spent
        self._stub([{"scriptPubKey": self.HTLC_HEX, "outid": "abc"}], gettxout=None)
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_match_no_outid_falls_back_to_unspent(self):
        self._stub([{"scriptPubKey": self.HTLC_HEX}])
        assert self.ci.isHTLCTxnSpent(self.script) is False

    def test_no_matching_htlc_is_spent(self):
        # Different HTLC script (different secret_hash) → no match → spent
        self._stub([{"scriptPubKey": self.OTHER_HTLC_HEX, "outid": "abc"}])
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_non_htlc_utxos_skipped_is_spent(self):
        self._stub(
            [
                {"scriptPubKey": "76a91488ac", "outid": "x"},
                {"scriptPubKey": "", "outid": "y"},
            ]
        )
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_empty_utxo_list_is_spent(self):
        self._stub([])
        assert self.ci.isHTLCTxnSpent(self.script) is True

    def test_exception_returns_false(self):
        def boom():
            raise RuntimeError("rpc down")

        self.ci._listBlsctUnspent = boom
        assert self.ci.isHTLCTxnSpent(self.script) is False


class TestGetPrevOutInfoFromChain(unittest.TestCase):
    """Tests for getPrevOutInfoFromChain (listblsctunspent stubbed)."""

    HTLC_HEX = TestIsHTLCTxnSpent.HTLC_HEX
    OTHER_HTLC_HEX = TestIsHTLCTxnSpent.OTHER_HTLC_HEX

    def setUp(self):
        self.ci = ci_nav()
        spk = bytes.fromhex(self.HTLC_HEX)
        self.secret_hash = atomic_swap_1.extractScriptSecretHash(spk)

    def _stub(self, utxos):
        self.ci._listBlsctUnspent = lambda: utxos

    def test_match_returns_prevout(self):
        self._stub(
            [
                {
                    "scriptPubKey": self.HTLC_HEX,
                    "outid": "abc",
                    "amount": 1.5,
                    "gamma": "gg",
                }
            ]
        )
        prevout = self.ci.getPrevOutInfoFromChain(self.secret_hash)
        assert prevout == {"outid": "abc", "amount": 1.5, "gamma": "gg"}

    def test_outputHash_fallback_when_no_outid(self):
        self._stub(
            [
                {
                    "scriptPubKey": self.HTLC_HEX,
                    "outputHash": "deadbeef",
                    "amount": 2,
                    "gamma": "g",
                }
            ]
        )
        prevout = self.ci.getPrevOutInfoFromChain(self.secret_hash)
        assert prevout["outid"] == "deadbeef"

    def test_secret_hash_mismatch_raises(self):
        self._stub(
            [
                {
                    "scriptPubKey": self.OTHER_HTLC_HEX,
                    "outid": "abc",
                    "amount": 1,
                    "gamma": "g",
                }
            ]
        )
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash)

    def test_non_htlc_utxos_skipped_raises(self):
        self._stub(
            [{"scriptPubKey": "76a91488ac", "outid": "x", "amount": 1, "gamma": "g"}]
        )
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash)

    def test_empty_utxo_list_raises(self):
        self._stub([])
        with self.assertRaises(ValueError):
            self.ci.getPrevOutInfoFromChain(self.secret_hash)


def _mk_bid(
    *, ptx_state=None, itx_state=None, was_received=False, has_ptx=True, has_itx=True
):
    b = types.SimpleNamespace(
        was_received=was_received,
        participate_tx=types.SimpleNamespace(script=b"ptx") if has_ptx else None,
        initiate_tx=types.SimpleNamespace(script=b"itx") if has_itx else None,
    )
    b._ptx = ptx_state
    b._itx = itx_state
    b.getPTxState = lambda: b._ptx
    b.getITxState = lambda: b._itx

    def set_ptx(s):
        b._ptx = s

    def set_itx(s):
        b._itx = s

    b.setPTxState = set_ptx
    b.setITxState = set_itx
    return b


def _ev(event_type):
    return types.SimpleNamespace(event_type=int(event_type))


class TestHandleSwapParticipatingLabel(unittest.TestCase):
    """handleSwapParticipating: redeem vs refund labelling on a NAV HTLC spend.

    BLSCT hides the preimage on-chain, so the state is inferred from this node's
    own recorded action then its role. Roles are reversed between legs: the
    offerer is the redeem party of the PTX but the refund party of the ITX.
    """

    def setUp(self):
        self.ci = ci_nav()
        self.ci.isHTLCTxnSpent = lambda script: True  # spent

    def _run(self, bid, coin_from, coin_to, events):
        self.ci._sc = types.SimpleNamespace(getEvents=lambda ct, bid_id: events)
        return self.ci.handleSwapParticipating(b"bid", bid, coin_from, coin_to)

    # ---- PTX (coin_to == NAV): offerer = redeem, bidder = refund ----
    def test_ptx_own_refund_event(self):
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED)
        assert (
            self._run(
                bid, Coins.LTC, Coins.NAV, [_ev(EventLogTypes.PTX_REFUND_PUBLISHED)]
            )
            is True
        )
        assert bid.getPTxState() == TxStates.TX_REFUNDED

    def test_ptx_own_redeem_event(self):
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED)
        self._run(bid, Coins.LTC, Coins.NAV, [_ev(EventLogTypes.PTX_REDEEM_PUBLISHED)])
        assert bid.getPTxState() == TxStates.TX_REDEEMED

    def test_ptx_offerer_no_event_is_refund(self):
        # offerer (was_received) didn't redeem -> bidder refunded
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED, was_received=True)
        self._run(bid, Coins.LTC, Coins.NAV, [])
        assert bid.getPTxState() == TxStates.TX_REFUNDED

    def test_ptx_bidder_no_event_is_redeem(self):
        # bidder (was_sent) didn't refund -> offerer redeemed
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED, was_received=False)
        self._run(bid, Coins.LTC, Coins.NAV, [])
        assert bid.getPTxState() == TxStates.TX_REDEEMED

    def test_ptx_guard_skips_when_already_terminal(self):
        bid = _mk_bid(ptx_state=TxStates.TX_REFUNDED, was_received=True)
        assert self._run(bid, Coins.LTC, Coins.NAV, []) is False
        assert bid.getPTxState() == TxStates.TX_REFUNDED  # unchanged, no re-append

    def test_ptx_not_spent_no_change(self):
        self.ci.isHTLCTxnSpent = lambda script: False
        bid = _mk_bid(ptx_state=TxStates.TX_CONFIRMED, was_received=True)
        assert self._run(bid, Coins.LTC, Coins.NAV, []) is False
        assert bid.getPTxState() == TxStates.TX_CONFIRMED

    # ---- ITX (coin_from == NAV): offerer = refund, bidder = redeem ----
    def test_itx_own_refund_event(self):
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        assert (
            self._run(
                bid, Coins.NAV, Coins.LTC, [_ev(EventLogTypes.ITX_REFUND_PUBLISHED)]
            )
            is True
        )
        assert bid.getITxState() == TxStates.TX_REFUNDED

    def test_itx_own_redeem_event(self):
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        self._run(bid, Coins.NAV, Coins.LTC, [_ev(EventLogTypes.ITX_REDEEM_PUBLISHED)])
        assert bid.getITxState() == TxStates.TX_REDEEMED

    def test_itx_offerer_no_event_is_redeem(self):
        # offerer (was_received) owns the ITX; didn't refund -> bidder redeemed
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED, was_received=True)
        self._run(bid, Coins.NAV, Coins.LTC, [])
        assert bid.getITxState() == TxStates.TX_REDEEMED

    def test_itx_bidder_no_event_is_refund(self):
        # bidder (was_sent) didn't redeem -> offerer refunded
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED, was_received=False)
        self._run(bid, Coins.NAV, Coins.LTC, [])
        assert bid.getITxState() == TxStates.TX_REFUNDED

    def test_itx_guard_skips_when_already_terminal(self):
        bid = _mk_bid(itx_state=TxStates.TX_REDEEMED, was_received=True)
        assert self._run(bid, Coins.NAV, Coins.LTC, []) is False


class TestDetectNavItxRefund(unittest.TestCase):
    """detectNavItxRefund must not mislabel this node's own ITX redeem as a refund.

    The ITX HTLC output has two spenders (bidder redeem, offerer refund). This
    early detector runs before handleSwapParticipating; when our own in-flight
    redeem spends the ITX but the ITX state has not yet flipped to TX_REDEEMED,
    the spend must not be recorded as TX_REFUNDED.
    """

    def setUp(self):
        self.ci = ci_nav()
        self.ci.isHTLCTxnSpent = lambda script: True  # spent

    def _run(self, bid, events):
        self.ci._sc = types.SimpleNamespace(
            getEvents=lambda ct, bid_id: events,
            log=types.SimpleNamespace(id=lambda x: x, info=lambda *a, **k: None),
        )
        return self.ci.detectNavItxRefund(bid)

    def test_spent_with_own_redeem_event_is_not_refund(self):
        # Regression: our own redeem raced ahead of the ITX state update.
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        bid.bid_id = b"bid"
        assert self._run(bid, [_ev(EventLogTypes.ITX_REDEEM_PUBLISHED)]) is False
        assert bid.getITxState() == TxStates.TX_CONFIRMED  # unchanged

    def test_spent_without_redeem_event_is_refund(self):
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        bid.bid_id = b"bid"
        assert self._run(bid, []) is True
        assert bid.getITxState() == TxStates.TX_REFUNDED

    def test_not_spent_no_change(self):
        self.ci.isHTLCTxnSpent = lambda script: False
        bid = _mk_bid(itx_state=TxStates.TX_CONFIRMED)
        bid.bid_id = b"bid"
        assert self._run(bid, []) is False
        assert bid.getITxState() == TxStates.TX_CONFIRMED

    def test_terminal_state_skipped(self):
        bid = _mk_bid(itx_state=TxStates.TX_REDEEMED)
        bid.bid_id = b"bid"
        assert self._run(bid, []) is False


class TestProcessNavHtlcPreimageLength(unittest.TestCase):
    """processNavHtlcPreimage rejects a payload that isn't bid_id(28)+secret(32)."""

    def setUp(self):
        self.ci = ci_nav()

    def _run(self, payload):
        log = types.SimpleNamespace(
            id=lambda x: "id",
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            debug=lambda *a, **k: None,
        )
        self.ci._sc = types.SimpleNamespace(
            getSmsgMsgBytes=lambda msg: payload,
            log=log,
            swaps_in_progress={},
        )
        return self.ci.processNavHtlcPreimage({})

    def test_short_message_raises(self):
        with self.assertRaises(ValueError):
            self._run(b"\x00" * 59)

    def test_long_message_raises(self):
        with self.assertRaises(ValueError):
            self._run(b"\x00" * 61)

    def test_correct_length_passes_gate(self):
        # 60 bytes, bid not in progress -> returns gracefully (length gate passed)
        assert self._run(b"\x00" * 60) is None


class TestNavSwapRedeemITx(unittest.TestCase):
    """nav_swap_1.redeemITx: NAV wraps transient failures as TemporaryError so
    checkQueuedActions retries; non-NAV delegates unchanged."""

    def _swap(self, coin_from, coin_to):
        offer = types.SimpleNamespace(coin_from=int(coin_from), coin_to=int(coin_to))
        return types.SimpleNamespace(
            getBidAndOffer=lambda bid_id, cursor, with_txns: (None, offer)
        )

    def _patch_redeem(self, fn):
        self._orig = atomic_swap_1.redeemITx
        atomic_swap_1.redeemITx = fn

    def tearDown(self):
        if hasattr(self, "_orig"):
            atomic_swap_1.redeemITx = self._orig

    def test_non_nav_delegates(self):
        calls = []
        self._patch_redeem(lambda self, bid_id, cursor: calls.append("d") or "ok")
        r = nav_swap_1.redeemITx(self._swap(Coins.LTC, Coins.BTC), b"bid", None)
        assert calls == ["d"]
        assert r == "ok"

    def test_nav_success_returns(self):
        self._patch_redeem(lambda self, bid_id, cursor: "done")
        assert (
            nav_swap_1.redeemITx(self._swap(Coins.NAV, Coins.LTC), b"bid", None)
            == "done"
        )

    def test_nav_generic_exception_becomes_temporary(self):
        def boom(self, bid_id, cursor):
            raise RuntimeError("rpc down")

        self._patch_redeem(boom)
        with self.assertRaises(TemporaryError):
            nav_swap_1.redeemITx(self._swap(Coins.NAV, Coins.LTC), b"bid", None)

    def test_nav_temporary_error_not_double_wrapped(self):
        def boom(self, bid_id, cursor):
            raise TemporaryError("already temp")

        self._patch_redeem(boom)
        with self.assertRaises(TemporaryError) as cm:
            nav_swap_1.redeemITx(self._swap(Coins.NAV, Coins.LTC), b"bid", None)
        assert str(cm.exception) == "already temp"


class TestNavSwapInterface(unittest.TestCase):
    def test_swap_type_and_inheritance(self):
        iface = nav_swap_1.NavSwapInterface()
        assert iface.swap_type == SwapTypes.SECRET_HASH_BLSCT
        assert isinstance(iface, atomic_swap_1.AtomicSwapInterface)
        assert hasattr(iface, "getFundedInitiateTxTemplate")
        assert hasattr(iface, "promoteMockTx")


if __name__ == "__main__":
    unittest.main()
