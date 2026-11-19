# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
EVM<->XMR swaps between two BasicSwap nodes over SMSG, on the regtest harness
with SwapCreator on anvil. Node 0 is always the EVM side and node 1 the XMR
side; only node 0 starts with ETH, so node 1's first claim runs on the drip.

Run:
    python -m unittest tests.basicswap.test_evm_xmr_p2p
"""

import logging
import os
import unittest

from basicswap.basicswap_util import BidStates, SwapTypes
from basicswap.bidplanner import FILL_RECEIVE
from basicswap.chainparams import Coins
from basicswap.db import EvmXmrSwap
from basicswap.multibid import placeMultiBid, planMultiBid
from basicswap.interface.eth.chainparams import ETH_COIN
from basicswap.interface.xmr.xmr import XMR_COIN
from basicswap.util import TemporaryError
from tests.basicswap.test_xmr import BaseTest, test_delay_event
from tests.basicswap.util.anvil import Anvil, KEY_0, REQUIREMENTS_MET, SKIP_REASON
from tests.basicswap.util.common import wait_for_bid, wait_for_offer

ANVIL_PORT = int(os.environ.get("TEST_ANVIL_PORT", "8658"))
LOCK_SECONDS = 24 * 60 * 60


@unittest.skipUnless(REQUIREMENTS_MET, SKIP_REASON)
class Test(BaseTest):
    __test__ = True
    anvil = None

    @classmethod
    def prepareTestDir(cls):
        cls.anvil = Anvil(ANVIL_PORT)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["ethereum"] = {
            "connection_type": "web3",
            "manage_daemon": False,
            "rpc_url": f"http://127.0.0.1:{ANVIL_PORT}",
            "chain_id": 31337,
            "contract_address": cls.anvil.contract_address,
            "blocks_confirmed": 1,
        }

    @classmethod
    def prepareExtraCoins(cls):
        to = cls.swap_clients[0].ci(Coins.ETH).account.address
        txid = cls.anvil.iface(KEY_0).withdrawCoin("100", to, False)
        cls.anvil.w3.eth.wait_for_transaction_receipt(txid)

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            if cls.anvil is not None:
                cls.anvil.stop()

    def _waitXmrWalletsSynced(self):
        for swap_client in self.swap_clients[:2]:
            ci = swap_client.ci(Coins.XMR)
            for _ in range(60):
                try:
                    ci.ensureWalletSynced()
                    break
                except TemporaryError:
                    test_delay_event.wait(1)

    def _swap(self, offerer, bidder, coin_from, coin_to, amount, rate):
        self._waitXmrWalletsSynced()
        offer_id = offerer.postOffer(
            coin_from,
            coin_to,
            amount,
            rate,
            amount,
            SwapTypes.EVM_XMR_SWAP,
            lock_value=LOCK_SECONDS,
            auto_accept_bids=True,
        )
        wait_for_offer(test_delay_event, bidder, offer_id)
        offer = bidder.listOffers(filters={"offer_id": offer_id})[0]
        bid_id = bidder.postBid(offer_id, offer.amount_from)
        wait_for_bid(
            test_delay_event, offerer, bid_id, BidStates.SWAP_COMPLETED, wait_for=300
        )
        wait_for_bid(
            test_delay_event,
            bidder,
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=120,
        )

    def _smartBuy(self, offerer, buyer, coin_from, coin_to, amount, rate, legs=2):
        self._waitXmrWalletsSynced()
        offer_ids = [
            offerer.postOffer(
                coin_from,
                coin_to,
                amount,
                rate,
                amount,
                SwapTypes.EVM_XMR_SWAP,
                lock_value=LOCK_SECONDS,
                auto_accept_bids=True,
            )
            for _ in range(legs)
        ]
        for offer_id in offer_ids:
            wait_for_offer(test_delay_event, buyer, offer_id)
        plan, _, _ = planMultiBid(
            buyer,
            coin_from,
            coin_to,
            FILL_RECEIVE,
            amount * legs,
            manual_offers=offer_ids,
        )
        placed, failed, _ = placeMultiBid(
            buyer,
            [{"offer_id": leg.offer_id, "amount": leg.amount} for leg in plan.legs],
        )
        self.assertEqual((len(placed), failed), (legs, []))
        bid_ids = [bytes.fromhex(p["bid_id"]) for p in placed]
        for bid_id in bid_ids:
            wait_for_bid(
                test_delay_event,
                offerer,
                bid_id,
                BidStates.SWAP_COMPLETED,
                wait_for=400,
            )
            wait_for_bid(
                test_delay_event,
                buyer,
                bid_id,
                BidStates.SWAP_COMPLETED,
                sent=True,
                wait_for=200,
            )
        return bid_ids

    def _xmrLockTxids(self, swap_client, bid_ids) -> set:
        cursor = swap_client.openDB()
        try:
            return {
                swap_client.queryOne(EvmXmrSwap, cursor, {"bid_id": b}).b_lock_tx_id
                for b in bid_ids
            }
        finally:
            swap_client.closeDB(cursor, commit=False)

    def test_01_eth_to_xmr(self):
        logging.info("---------- Test ETH to XMR, the XMR side claims on the drip")
        sc0, sc1 = self.swap_clients[0], self.swap_clients[1]
        assert sc1.ci(Coins.ETH).getSpendableBalance() == 0

        self._swap(sc0, sc1, Coins.ETH, Coins.XMR, 12 * ETH_COIN, XMR_COIN // 2)

        assert sc1.ci(Coins.ETH).getSpendableBalance() > ETH_COIN

    def test_02_xmr_to_eth(self):
        logging.info("---------- Test XMR to ETH, the XMR side made the offer")
        sc0, sc1 = self.swap_clients[0], self.swap_clients[1]
        eth1_start = sc1.ci(Coins.ETH).getSpendableBalance()

        self._swap(sc1, sc0, Coins.XMR, Coins.ETH, XMR_COIN // 2, 2 * ETH_COIN)

        assert sc1.ci(Coins.ETH).getSpendableBalance() > eth1_start

    def test_03_smart_buy_eth_batches_the_xmr_locks(self):
        logging.info("---------- Smart Buy ETH from two offers, one XMR lock tx")
        sc0, sc1 = self.swap_clients[0], self.swap_clients[1]
        bid_ids = self._smartBuy(
            sc0, sc1, Coins.ETH, Coins.XMR, ETH_COIN, XMR_COIN // 2
        )
        self.assertEqual(len(self._xmrLockTxids(sc1, bid_ids)), 1)

    def test_04_smart_buy_xmr_with_eth(self):
        logging.info("---------- Smart Buy XMR from two offers, paying ETH")
        sc0, sc1 = self.swap_clients[0], self.swap_clients[1]
        bid_ids = self._smartBuy(
            sc1, sc0, Coins.XMR, Coins.ETH, XMR_COIN // 4, ETH_COIN
        )
        # Each offerer locks its own XMR
        self.assertEqual(len(self._xmrLockTxids(sc1, bid_ids)), 2)


if __name__ == "__main__":
    unittest.main()
