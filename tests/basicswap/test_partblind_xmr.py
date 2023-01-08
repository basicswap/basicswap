#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import random
import logging
import unittest
from urllib import parse
from urllib.request import urlopen

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
from tests.basicswap.util import (
    post_json_req,
    read_json_api,
)
from tests.basicswap.common import (
    wait_for_bid,
    wait_for_offer,
    wait_for_none_active,
    wait_for_balance,
    wait_for_unspent,
)

from .test_xmr import BaseTest, test_delay_event

logger = logging.getLogger()


class Test(BaseTest):
    __test__ = True
    test_coin_from = Coins.PART_BLIND
    has_segwit = True

    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        js_0 = read_json_api(1800, 'wallets/part')
        node0_blind_before = js_0['blind_balance'] + js_0['blind_unconfirmed']

        post_json = {
            'value': 100,
            'address': js_0['stealth_address'],
            'subfee': False,
            'type_to': 'blind',
        }
        json_rv = json.loads(post_json_req('http://127.0.0.1:1800/json/wallets/part/withdraw', post_json))
        assert (len(json_rv['txid']) == 64)

        logging.info('Waiting for blind balance')
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1800/json/wallets/part', 'blind_balance', 100.0 + node0_blind_before)
        js_0 = read_json_api(1800, 'wallets/part')
        node0_blind_before = js_0['blind_balance'] + js_0['blind_unconfirmed']

    def ensure_balance(self, coin_type, node_id, amount):
        tla = 'PART'
        js_w = read_json_api(1800 + node_id, 'wallets')
        print('js_w', js_w)
        if float(js_w[tla]['blind_balance']) < amount:
            post_json = {
                'value': amount,
                'type_to': 'blind',
                'address': js_w[tla]['stealth_address'],
                'subfee': False,
            }
            json_rv = read_json_api(1800, 'wallets/{}/withdraw'.format(tla.lower()), post_json)
            assert (len(json_rv['txid']) == 64)
            wait_for_balance(test_delay_event, 'http://127.0.0.1:{}/json/wallets/{}'.format(1800 + node_id, tla.lower()), 'blind_balance', amount)

    def getBalance(self, js_wallets):
        return float(js_wallets[Coins.PART.name]['blind_balance']) + float(js_wallets[Coins.PART.name]['blind_unconfirmed'])

    def getXmrBalance(self, js_wallets):
        return float(js_wallets[Coins.XMR.name]['unconfirmed']) + float(js_wallets[Coins.XMR.name]['balance'])

    def test_01_part_xmr(self):
        logging.info('---------- Test PARTct to XMR')
        swap_clients = self.swap_clients

        js_0 = read_json_api(1800, 'wallets/part')
        assert (float(js_0['blind_balance']) > 10.0)
        node0_blind_before = js_0['blind_balance'] + js_0['blind_unconfirmed']

        js_1 = read_json_api(1801, 'wallets/part')
        node1_blind_before = js_1['blind_balance'] + js_1['blind_unconfirmed']

        js_0_xmr = read_json_api(1800, 'wallets/xmr')
        js_1_xmr = read_json_api(1801, 'wallets/xmr')

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(Coins.PART_BLIND, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[0].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        amount_from = float(format_amount(amt_swap, 8))
        js_1 = read_json_api(1801, 'wallets/part')
        node1_blind_after = js_1['blind_balance'] + js_1['blind_unconfirmed']
        assert (node1_blind_after > node1_blind_before + (amount_from - 0.05))

        js_0 = read_json_api(1800, 'wallets/part')
        node0_blind_after = js_0['blind_balance'] + js_0['blind_unconfirmed']
        assert (node0_blind_after < node0_blind_before - amount_from)

        js_0_xmr_after = read_json_api(1800, 'wallets/xmr')
        js_1_xmr_after = read_json_api(1801, 'wallets/xmr')

        scale_from = 8
        amount_to = int((amt_swap * rate_swap) // (10 ** scale_from))
        amount_to_float = float(format_amount(amount_to, 12))
        node1_xmr_after = float(js_1_xmr_after['unconfirmed']) + float(js_1_xmr_after['balance'])
        node1_xmr_before = float(js_1_xmr['unconfirmed']) + float(js_1_xmr['balance'])
        assert (node1_xmr_after > node1_xmr_before + (amount_to_float - 0.02))

    def test_02_leader_recover_a_lock_tx(self):
        logging.info('---------- Test PARTct to XMR leader recovers coin a lock tx')
        swap_clients = self.swap_clients

        js_w0_before = read_json_api(1800, 'wallets')
        node0_blind_before = self.getBalance(js_w0_before)

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(
            Coins.PART_BLIND, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=12)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, [BidStates.BID_STALLED_FOR_TEST, BidStates.XMR_SWAP_FAILED], sent=True)

        js_w0_after = read_json_api(1800, 'wallets')
        node0_blind_after = self.getBalance(js_w0_after)
        assert (node0_blind_before - node0_blind_after < 0.02)

    def test_03_follower_recover_a_lock_tx(self):
        logging.info('---------- Test PARTct to XMR follower recovers coin a lock tx')
        swap_clients = self.swap_clients

        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(
            Coins.PART_BLIND, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=32)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[0].setBidDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_STALLED_FOR_TEST, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_SWIPED, wait_for=80, sent=True)

        js_w1_after = read_json_api(1801, 'wallets')

        node1_blind_before = self.getBalance(js_w1_before)
        node1_blind_after = self.getBalance(js_w1_after)
        amount_from = float(format_amount(amt_swap, 8))
        assert (node1_blind_after - node1_blind_before > (amount_from - 0.02))

        swap_clients[0].abandonBid(bid_id)
        swap_clients[1].abandonBid(bid_id)

        wait_for_none_active(test_delay_event, 1800)
        wait_for_none_active(test_delay_event, 1801)

        data = parse.urlencode({
            'chainbkeysplit': True
        }).encode()
        offerer_key = json.loads(urlopen('http://127.0.0.1:1800/json/bids/{}'.format(bid_id.hex()), data=data).read())['splitkey']

        data = parse.urlencode({
            'spendchainblocktx': True,
            'remote_key': offerer_key
        }).encode()
        redeemed_txid = json.loads(urlopen('http://127.0.0.1:1801/json/bids/{}'.format(bid_id.hex()), data=data).read())['txid']
        assert (len(redeemed_txid) == 64)

    def do_test_04_follower_recover_b_lock_tx(self, coin_from, coin_to):
        logging.info('---------- Test {} to {} follower recovers coin b lock tx'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=28)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

    def test_04_follower_recover_b_lock_tx(self):
        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_from, Coins.XMR)
        js_w0_after = read_json_api(1800, 'wallets')
        js_w1_after = read_json_api(1801, 'wallets')
        node0_blind_before = self.getBalance(js_w0_before)
        node0_blind_after = self.getBalance(js_w0_after)
        assert (node0_blind_before - node0_blind_after < 0.02)

        node1_xmr_before = self.getXmrBalance(js_w1_before)
        node1_xmr_after = self.getXmrBalance(js_w1_after)
        assert (node1_xmr_before - node1_xmr_after < 0.02)

    def test_04_follower_recover_b_lock_tx_from_part(self):
        self.ensure_balance(self.test_coin_from, 1, 50.0)
        self.do_test_04_follower_recover_b_lock_tx(Coins.PART, self.test_coin_from)

    def do_test_05_self_bid(self, coin_from, coin_to):
        logging.info('---------- Test {} to {} same client'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        ci_to = swap_clients[0].ci(coin_to)

        self.ensure_balance(coin_from, 1, 50.0)

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)

        offer_id = swap_clients[1].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        bid_id = swap_clients[1].postXmrBid(offer_id, amt_swap)

        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)

    def test_05_self_bid(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(self.test_coin_from, Coins.XMR)

    def test_05_self_bid_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(self.test_coin_from, Coins.PART)

    def test_05_self_bid_from_part(self):
        self.do_test_05_self_bid(Coins.PART, self.test_coin_from)

    def test_06_preselect_inputs(self):
        raise ValueError('TODO')
        tla_from = self.test_coin_from.name
        logging.info('---------- Test {} Preselected inputs'.format(tla_from))
        swap_clients = self.swap_clients

        # Prepare balance
        self.ensure_balance(self.test_coin_from, 2, 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        post_json = {
            'value': float(js_w2['PART']['blind_balance']),
            'type_from': 'blind',
            'type_to': 'blind',
            'address': js_w2['PART']['stealth_address'],
            'subfee': True,
        }
        json_rv = read_json_api(1802, 'wallets/{}/withdraw'.format('part'), post_json)
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1802/json/wallets/{}'.format('part'), 'blind_balance', 10.0)
        assert (len(json_rv['txid']) == 64)

        # Create prefunded ITX
        ci = swap_clients[2].ci(self.test_coin_from)
        ci_to = swap_clients[2].ci(Coins.XMR)
        pi = swap_clients[2].pi(SwapTypes.XMR_SWAP)
        js_w2 = read_json_api(1802, 'wallets')
        swap_value = ci.make_int(js_w2['PART']['blind_balance'])
        assert (swap_value > ci.make_int(95))

        itx = pi.getFundedInitiateTxTemplate(ci, swap_value, True)
        itx_decoded = ci.describeTx(itx.hex())
        n = pi.findMockVout(ci, itx_decoded)
        value_after_subfee = ci.make_int(itx_decoded['vout'][n]['value'])
        assert (value_after_subfee < swap_value)
        swap_value = value_after_subfee
        wait_for_unspent(test_delay_event, ci, swap_value)

        extra_options = {'prefunded_itx': itx}
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0))
        offer_id = swap_clients[2].postOffer(self.test_coin_from, Coins.XMR, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP, extra_options=extra_options)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.BID_RECEIVED)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

        # Verify expected inputs were used
        bid, _, _, _, _ = swap_clients[2].getXmrBidAndOffer(bid_id)
        assert (bid.xmr_a_lock_tx)
        wtx = ci.rpc_callback('gettransaction', [bid.xmr_a_lock_tx.txid.hex(),])
        itx_after = ci.describeTx(wtx['hex'])
        assert (len(itx_after['vin']) == len(itx_decoded['vin']))
        for i, txin in enumerate(itx_decoded['vin']):
            txin_after = itx_after['vin'][i]
            assert (txin['txid'] == txin_after['txid'])
            assert (txin['vout'] == txin_after['vout'])


if __name__ == '__main__':
    unittest.main()
