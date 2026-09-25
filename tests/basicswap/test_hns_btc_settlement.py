"""Value ordering at the HNS/BTC chain boundary."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from basicswap.interface.hns.btc_contract import BtcSpendObservation
from basicswap.interface.hns.settlement import HnsBtcSettlement
from basicswap.interface.hns.trade_record import (
    MAKER,
    TAKER,
    bind_bid_id,
    bind_lock,
    bind_terms,
    bind_wallet_fingerprint,
    new_trade_record,
)
from tests.basicswap.test_hns_btc_swap import GENESIS, MAGIC, NOW, messages, terms


class FakeBitcoin:
    def __init__(self):
        self.tip = 11
        self.hashes = {height: f"{height:064x}" for height in range(12)}

    def rpc(self, method, params=None):
        if method == "getblockchaininfo":
            return {"mediantime": NOW}
        if method == "getblockcount":
            return self.tip
        if method == "getblockhash":
            return self.hashes[params[0]]
        raise AssertionError(f"unexpected Bitcoin RPC {method}")


class FakeHnsNode:
    ready = True

    def bound_snapshot(self, network):
        if network != "regtest":
            raise AssertionError("wrong HNS network")
        return SimpleNamespace(tip={"median_time_past": NOW})

    def sync_ready(self, network, binding):
        return self.ready


class FakeHnsBridge:
    def __init__(self):
        self.first_verified = False
        self.funded = 0
        self.submitted_funding_id = None
        self.submitted_spend_id = None

    def identity(self, expected_network):
        assert expected_network == "regtest"
        return bytes.fromhex("44" * 16), bytes.fromhex("55" * 32)

    def submitted_funding(self, terms):
        return self.submitted_funding_id

    def submitted_spend(self, terms, funding_id, refund):
        return self.submitted_spend_id

    def verify_lock(self, terms, txid, confirmations):
        return self.first_verified

    def fund(self, terms, maximum_fee):
        self.funded += 1
        return bytes.fromhex("ab" * 32), 0


class HnsBtcSettlementTest(unittest.TestCase):
    def make_settlement(self, hns_first, role):
        trade = terms(hns_first)
        bid, _ = messages(trade)
        record = new_trade_record(
            trade.offer_id, trade.session_nonce, role, bid.to_bytes(), NOW
        )
        bind_bid_id(record, trade.bid_id)
        bind_terms(record, trade, NOW, MAGIC, GENESIS)
        bind_wallet_fingerprint(record, bytes.fromhex("55" * 32))
        bridge = FakeHnsBridge()
        saved = []
        settlement = HnsBtcSettlement(
            record,
            trade,
            FakeBitcoin(),
            bridge,
            FakeHnsNode(),
            "regtest",
            lambda changed: saved.append(changed.hns_lock_txid),
        )
        return settlement, bridge, saved

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_maker_persists_hns_lock_and_taker_cannot_fund_before_confirmation(
        self, _mock_time
    ):
        maker, bridge, saved = self.make_settlement(True, MAKER)
        self.assertEqual(maker.own_coin, "hns")
        self.assertEqual(maker.fund_owned_lock(100000), (bytes.fromhex("ab" * 32), 0))
        self.assertEqual(saved, [bytes.fromhex("ab" * 32)])
        self.assertEqual(bridge.funded, 1)

        taker, taker_bridge, saved = self.make_settlement(True, TAKER)
        bind_lock(taker.record, "hns", bytes.fromhex("ab" * 32), 0)
        self.assertEqual(taker.own_coin, "btc")
        with self.assertRaisesRegex(ValueError, "not sufficiently confirmed"):
            taker.fund_owned_lock(100000)
        self.assertEqual(taker_bridge.funded, 0)
        self.assertEqual(saved, [])

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_changed_stored_commitment_cannot_start_settlement(self, _mock_time):
        settlement, bridge, saved = self.make_settlement(False, MAKER)
        settlement.record.terms_commitment = bytes(32)
        with self.assertRaisesRegex(ValueError, "differ from durable record"):
            HnsBtcSettlement(
                settlement.record,
                settlement.terms,
                FakeBitcoin(),
                bridge,
                FakeHnsNode(),
                "regtest",
                lambda changed: saved.append(changed.hns_lock_txid),
            )

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_restored_wallet_seed_must_match_persisted_trade(self, _mock_time):
        settlement, bridge, saved = self.make_settlement(False, MAKER)
        settlement.record.hns_wallet_fingerprint = bytes.fromhex("66" * 32)
        with self.assertRaisesRegex(ValueError, "recovery seed changed"):
            HnsBtcSettlement(
                settlement.record,
                settlement.terms,
                FakeBitcoin(),
                bridge,
                FakeHnsNode(),
                "regtest",
                lambda changed: saved.append(changed.hns_lock_txid),
            )

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_maker_does_not_reveal_secret_near_second_refund(self, _mock_time):
        settlement, _, _ = self.make_settlement(True, MAKER)
        bind_lock(settlement.record, "btc", bytes.fromhex("cd" * 32), 1)
        with (
            patch.object(settlement, "_chain_now", return_value=NOW + 12 * 60 * 60),
            self.assertRaisesRegex(ValueError, "too close to refund"),
        ):
            settlement.redeem_peer_lock(100000)

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_recovers_submitted_hns_funding_after_window_closes(self, _mock_time):
        settlement, bridge, saved = self.make_settlement(True, MAKER)
        bridge.submitted_funding_id = bytes.fromhex("ab" * 32)
        with patch.object(settlement, "_funding_now", side_effect=AssertionError):
            self.assertEqual(
                settlement.fund_owned_lock(100000), (bridge.submitted_funding_id, 0)
            )
        self.assertEqual(settlement.record.hns_lock_txid, bridge.submitted_funding_id)
        self.assertEqual(saved, [bridge.submitted_funding_id])
        self.assertEqual(bridge.funded, 0)

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_recovers_submitted_hns_redeem_without_revealing_again(self, _mock_time):
        settlement, bridge, _ = self.make_settlement(True, TAKER)
        bind_lock(settlement.record, "hns", bytes.fromhex("ab" * 32), 0)
        bridge.submitted_spend_id = bytes.fromhex("ef" * 32)
        with patch.object(settlement, "_chain_now", side_effect=AssertionError):
            self.assertEqual(
                settlement.redeem_peer_lock(100000), bridge.submitted_spend_id
            )

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_funding_waits_for_hsrd_sync(self, _mock_time):
        settlement, bridge, saved = self.make_settlement(True, MAKER)
        settlement.hns_node.ready = False
        with self.assertRaisesRegex(ValueError, "not synchronized"):
            settlement.fund_owned_lock(100000)
        self.assertEqual(bridge.funded, 0)
        self.assertEqual(saved, [])

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_bitcoin_spend_cursor_rewinds_after_reorg(self, _mock_time):
        settlement, _, _ = self.make_settlement(True, TAKER)
        bind_lock(settlement.record, "btc", bytes.fromhex("cd" * 32), 1)
        saved = []
        settlement.persist_record = lambda record: saved.append(
            (record.btc_scan_height, record.btc_scan_anchor)
        )
        with patch.object(settlement.btc, "scan_confirmed_spend") as scan:
            scan.return_value = None
            self.assertIsNone(settlement.scan_own_btc_lock_spend(5, max_blocks=3))
            scan.assert_called_with(settlement.record.btc_lock_txid, 1, 5, 7, 2)
            self.assertEqual(settlement.record.btc_scan_height, 7)

            settlement.btc.ci.hashes[7] = "ab" * 32
            observed = BtcSpendObservation(
                bytes.fromhex("ef" * 32),
                "refund",
                None,
                6,
                bytes.fromhex(settlement.btc.ci.hashes[6]),
            )
            scan.return_value = observed
            result = settlement.scan_own_btc_lock_spend(5, max_blocks=3)
            self.assertEqual(result.branch, "refund")
            self.assertEqual(settlement.record.btc_scan_height, 5)
            self.assertEqual(len(saved), 3)  # advance, reorg rewind, spend

            result = settlement.scan_own_btc_lock_spend(5, max_blocks=3)
            self.assertEqual(result.txid, observed.txid)
            scan.assert_called_with(settlement.record.btc_lock_txid, 1, 6, 8, 2)

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_bitcoin_cursor_does_not_advance_across_mid_scan_reorg(self, _mock_time):
        settlement, _, saved = self.make_settlement(True, TAKER)
        bind_lock(settlement.record, "btc", bytes.fromhex("cd" * 32), 1)

        def reorganize(*args):
            settlement.btc.ci.hashes[7] = "ab" * 32

        with (
            patch.object(
                settlement.btc, "scan_confirmed_spend", side_effect=reorganize
            ),
            self.assertRaisesRegex(ValueError, "chain changed"),
        ):
            settlement.scan_own_btc_lock_spend(5, max_blocks=3)
        self.assertIsNone(settlement.record.btc_scan_height)
        self.assertEqual(saved, [])

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_peer_bitcoin_cursor_is_independent_and_rewinds_after_reorg(
        self, _mock_time
    ):
        settlement, _, _ = self.make_settlement(True, MAKER)
        bind_lock(settlement.record, "btc", bytes.fromhex("cd" * 32), 1)
        with patch.object(settlement.btc, "scan_confirmed_spend", return_value=None):
            self.assertIsNone(settlement.scan_peer_btc_lock_spend(5, max_blocks=3))
            self.assertEqual(settlement.record.btc_peer_scan_height, 7)
            self.assertIsNone(settlement.record.btc_scan_height)
            settlement.btc.ci.hashes[7] = "ab" * 32
            self.assertIsNone(settlement.scan_peer_btc_lock_spend(5, max_blocks=3))
            self.assertEqual(settlement.record.btc_peer_scan_height, 7)
            self.assertEqual(
                settlement.record.btc_peer_scan_anchor, bytes.fromhex("ab" * 32)
            )


if __name__ == "__main__":
    unittest.main()
