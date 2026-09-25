"""Value ordering at the HNS/BTC chain boundary."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from basicswap.interface.hns.settlement import HnsBtcSettlement
from basicswap.interface.hns.trade_record import (
    MAKER,
    TAKER,
    bind_bid_id,
    bind_lock,
    bind_terms,
    new_trade_record,
)
from tests.basicswap.test_hns_btc_swap import GENESIS, MAGIC, NOW, messages, terms


class FakeBitcoin:
    def rpc(self, method, params=None):
        if method == "getblockchaininfo":
            return {"mediantime": NOW}
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
    def test_maker_does_not_reveal_secret_near_second_refund(self, _mock_time):
        settlement, _, _ = self.make_settlement(True, MAKER)
        with (
            patch.object(settlement, "_chain_now", return_value=NOW + 12 * 60 * 60),
            self.assertRaisesRegex(ValueError, "too close to refund"),
        ):
            settlement.redeem_peer_lock(100000)

    @patch("basicswap.interface.hns.settlement.time.time", return_value=NOW)
    def test_funding_waits_for_hsrd_sync(self, _mock_time):
        settlement, bridge, saved = self.make_settlement(True, MAKER)
        settlement.hns_node.ready = False
        with self.assertRaisesRegex(ValueError, "not synchronized"):
            settlement.fund_owned_lock(100000)
        self.assertEqual(bridge.funded, 0)
        self.assertEqual(saved, [])


if __name__ == "__main__":
    unittest.main()
