#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import logging
import unittest

from basicswap.basicswap import (
    Coins,
    SwapTypes,
    BidStates,
    DebugTypes,
)
from basicswap.basicswap_util import (
    TxLockTypes,
)
from basicswap.util import (
    make_int,
    format_amount,
)
from tests.basicswap.common import (
    wait_for_bid,
    read_json_api,
    wait_for_offer,
    wait_for_none_active,
)

from .test_xmr import BaseTest, test_delay_event

logger = logging.getLogger()


class Test(BaseTest):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        if not hasattr(cls, 'test_coin_from'):
            cls.test_coin_from = Coins.BTC
        if not hasattr(cls, 'start_ltc_nodes'):
            cls.start_ltc_nodes = False
        super(Test, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising BTC Test')
        super(Test, cls).tearDownClass()

    def getBalance(self, js_wallets):
        return float(js_wallets[str(int(self.test_coin_from))]['balance']) + float(js_wallets[str(int(self.test_coin_from))]['unconfirmed'])

    def getXmrBalance(self, js_wallets):
        return float(js_wallets[str(int(Coins.XMR))]['unconfirmed']) + float(js_wallets[str(int(Coins.XMR))]['balance'])

    def test_01_full_swap(self):
        logging.info('---------- Test {} to XMR'.format(str(self.test_coin_from)))
        swap_clients = self.swap_clients

        js_0 = read_json_api(1800, 'wallets')
        node0_from_before = self.getBalance(js_0)

        js_1 = read_json_api(1801, 'wallets')
        node1_from_before = self.getBalance(js_1)

        js_0_xmr = read_json_api(1800, 'wallets/xmr')
        js_1_xmr = read_json_api(1801, 'wallets/xmr')

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[0].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        amount_from = float(format_amount(amt_swap, 8))
        js_1 = read_json_api(1801, 'wallets')
        node1_from_after = self.getBalance(js_1)
        assert(node1_from_after > node1_from_before + (amount_from - 0.05))

        js_0 = read_json_api(1800, 'wallets')
        node0_from_after = self.getBalance(js_0)
        # TODO: Discard block rewards
        # assert(node0_from_after < node0_from_before - amount_from)

        js_0_xmr_after = read_json_api(1800, 'wallets/xmr')
        js_1_xmr_after = read_json_api(1801, 'wallets/xmr')

        scale_from = 8
        amount_to = int((amt_swap * rate_swap) // (10 ** scale_from))
        amount_to_float = float(format_amount(amount_to, 12))
        node1_xmr_after = float(js_1_xmr_after['unconfirmed']) + float(js_1_xmr_after['balance'])
        node1_xmr_before = float(js_1_xmr['unconfirmed']) + float(js_1_xmr['balance'])
        assert(node1_xmr_after > node1_xmr_before + (amount_to_float - 0.02))

    def test_02_leader_recover_a_lock_tx(self):
        logging.info('---------- Test {} to XMR leader recovers coin a lock tx'.format(str(self.test_coin_from)))
        swap_clients = self.swap_clients

        js_w0_before = read_json_api(1800, 'wallets')
        node0_from_before = self.getBalance(js_w0_before)

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(
            self.test_coin_from, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=12)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

        js_w0_after = read_json_api(1800, 'wallets')
        node0_from_after = self.getBalance(js_w0_after)

        # TODO: Discard block rewards
        # assert(node0_from_before - node0_from_after < 0.02)

    def test_03_follower_recover_a_lock_tx(self):
        logging.info('---------- Test {} to XMR follower recovers coin a lock tx'.format(str(self.test_coin_from)))
        swap_clients = self.swap_clients

        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(
            self.test_coin_from, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=12)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[0].setBidDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_STALLED_FOR_TEST, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_SWIPED, wait_for=80, sent=True)

        js_w1_after = read_json_api(1801, 'wallets')

        node1_from_before = self.getBalance(js_w1_before)
        node1_from_after = self.getBalance(js_w1_after)
        amount_from = float(format_amount(amt_swap, 8))
        # TODO: Discard block rewards
        # assert(node1_from_after - node1_from_before > (amount_from - 0.02))

        wait_for_none_active(test_delay_event, 1800)
        wait_for_none_active(test_delay_event, 1801)

    def test_04_follower_recover_b_lock_tx(self):
        logging.info('---------- Test {} to XMR follower recovers coin b lock tx'.format(str(self.test_coin_from)))

        swap_clients = self.swap_clients

        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(
            self.test_coin_from, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=18)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

        js_w0_after = read_json_api(1800, 'wallets')
        js_w1_after = read_json_api(1801, 'wallets')

        node0_from_before = self.getBalance(js_w0_before)
        node0_from_after = self.getBalance(js_w0_after)

        # TODO: Discard block rewards
        # assert(node0_from_before - node0_from_after < 0.02)

        node1_xmr_before = self.getXmrBalance(js_w1_before)
        node1_xmr_after = self.getXmrBalance(js_w1_after)
        assert(node1_xmr_before - node1_xmr_after < 0.02)


if __name__ == '__main__':
    unittest.main()
