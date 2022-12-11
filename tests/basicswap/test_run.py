#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ pytest

Run one test:
$ pytest -v -s tests/basicswap/test_run.py::Test::test_04_ltc_btc

"""

import os
import random
import logging
import unittest

from basicswap.basicswap import (
    Coins,
    SwapTypes,
    BidStates,
    TxStates,
    DebugTypes,
)
from basicswap.basicswap_util import (
    TxLockTypes,
)
from basicswap.chainparams import (
    chainparams,
)
from basicswap.util import (
    COIN,
    make_int,
    format_amount,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    wait_for_offer,
    wait_for_bid,
    wait_for_balance,
    wait_for_unspent,
    wait_for_bid_tx_state,
    wait_for_in_progress,
    TEST_HTTP_PORT,
    LTC_BASE_RPC_PORT,
    BTC_BASE_RPC_PORT,
    compare_bid_states,
    extract_states_from_xu_file,
)
from .test_xmr import BaseTest, test_delay_event, callnoderpc


logger = logging.getLogger()


class Test(BaseTest):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.start_ltc_nodes = True
        cls.start_xmr_nodes = False
        cls.start_pivx_nodes = False
        super(Test, cls).setUpClass()

        btc_addr1 = callnoderpc(1, 'getnewaddress', ['initial funds', 'bech32'], base_rpc_port=BTC_BASE_RPC_PORT)
        ltc_addr1 = callnoderpc(1, 'getnewaddress', ['initial funds', 'bech32'], base_rpc_port=LTC_BASE_RPC_PORT)

        callnoderpc(0, 'sendtoaddress', [btc_addr1, 1000], base_rpc_port=BTC_BASE_RPC_PORT)
        callnoderpc(0, 'sendtoaddress', [ltc_addr1, 1000], base_rpc_port=LTC_BASE_RPC_PORT)

        wait_for_balance(test_delay_event, 'http://127.0.0.1:1801/json/wallets/btc', 'balance', 1000.0)
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1801/json/wallets/ltc', 'balance', 1000.0)

        diagrams_dir = 'doc/protocols/sequence_diagrams'
        cls.states_bidder = extract_states_from_xu_file(os.path.join(diagrams_dir, 'bidder.alt.xu'), 'B')
        cls.states_offerer = extract_states_from_xu_file(os.path.join(diagrams_dir, 'offerer.alt.xu'), 'O')

        # Wait for height, or sequencelock is thrown off by genesis blocktime
        cls.waitForParticlHeight(3)

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising test')
        super(Test, cls).tearDownClass()

    def getBalance(self, js_wallets, coin_type):
        ci = self.swap_clients[0].ci(coin_type)
        ticker = chainparams[coin_type]['ticker']
        return ci.make_int(float(js_wallets[ticker]['balance']) + float(js_wallets[ticker]['unconfirmed']))

    def test_001_js_coins(self):
        js_coins = read_json_api(1800, 'coins')

        for c in Coins:
            coin = next((x for x in js_coins if x['id'] == int(c)), None)
            if c in (Coins.PART, Coins.BTC, Coins.LTC, Coins.PART_ANON, Coins.PART_BLIND):
                assert (coin['active'] is True)
            else:
                assert (coin['active'] is False)
            if c in (Coins.PART_ANON, Coins.PART_BLIND):
                assert (coin['ticker'] == 'PART')

    def test_002_lookup_rates(self):
        rv = self.swap_clients[0].lookupRates(Coins.BTC, Coins.PART)
        assert ('coingecko' in rv)
        assert ('bittrex' in rv)

        rv = self.swap_clients[0].lookupRates(Coins.LTC, Coins.BTC)
        assert ('coingecko' in rv)
        assert ('bittrex' in rv)

        rv = read_json_api(1800, 'rateslist?from=PART&to=BTC')
        assert len(rv) == 2

    def test_003_api(self):
        logging.info('---------- Test API')

        help_output = read_json_api(1800, 'help')
        assert ('getcoinseed' in help_output['commands'])

        rv = read_json_api(1800, 'getcoinseed')
        assert (rv['error'] == 'No post data')

        rv = read_json_api(1800, 'getcoinseed', {'coin': 'PART'})
        assert ('seed is set from the Basicswap mnemonic' in rv['error'])

        rv = read_json_api(1800, 'getcoinseed', {'coin': 'BTC'})
        assert (rv['seed'] == '8e54a313e6df8918df6d758fafdbf127a115175fdd2238d0e908dd8093c9ac3b')

    def test_01_verifyrawtransaction(self):
        txn = '0200000001eb6e5c4ebba4efa32f40c7314cad456a64008e91ee30b2dd0235ab9bb67fbdbb01000000ee47304402200956933242dde94f6cf8f195a470f8d02aef21ec5c9b66c5d3871594bdb74c9d02201d7e1b440de8f4da672d689f9e37e98815fb63dbc1706353290887eb6e8f7235012103dc1b24feb32841bc2f4375da91fa97834e5983668c2a39a6b7eadb60e7033f9d205a803b28fe2f86c17db91fa99d7ed2598f79b5677ffe869de2e478c0d1c02cc7514c606382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914225fbfa4cb725b75e511810ac4d6f74069bdded26703520140b27576a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666888acffffffff01e0167118020000001976a9140044e188928710cecba8311f1cf412135b98145c88ac00000000'
        prevout = {
            'txid': 'bbbd7fb69bab3502ddb230ee918e00646a45ad4c31c7402fa3efa4bb4e5c6eeb',
            'vout': 1,
            'scriptPubKey': 'a9143d37191e8b864222d14952a14c85504677a0581d87',
            'redeemScript': '6382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914225fbfa4cb725b75e511810ac4d6f74069bdded26703520140b27576a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666888ac',
            'amount': 1.0}
        ro = callnoderpc(0, 'verifyrawtransaction', [txn, [prevout, ]])
        assert (ro['inputs_valid'] is False)
        assert (ro['validscripts'] == 1)

        prevout['amount'] = 100.0
        ro = callnoderpc(0, 'verifyrawtransaction', [txn, [prevout, ]])
        assert (ro['inputs_valid'] is True)
        assert (ro['validscripts'] == 1)

        txn = 'a000000000000128e8ba6a28673f2ebb5fd983b27a791fd1888447a47638b3cd8bfdd3f54a6f1e0100000000a90040000101e0c69a3b000000001976a9146c0f1ea47ca2bf84ed87bf3aa284e18748051f5788ac04473044022026b01f3a90e46883949404141467b741cd871722a4aaae8ddc8c4d6ab6fb1c77022047a2f3be2dcbe4c51837d2d5e0329aaa8a13a8186b03186b127cc51185e4f3ab012103dc1b24feb32841bc2f4375da91fa97834e5983668c2a39a6b7eadb60e7033f9d0100606382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666703a90040b27576a914225fbfa4cb725b75e511810ac4d6f74069bdded26888ac'
        prevout = {
            'txid': '1e6f4af5d3fd8bcdb33876a4478488d11f797ab283d95fbb2e3f67286abae828',
            'vout': 1,
            'scriptPubKey': 'a914129aee070317bbbd57062288849e85cf57d15c2687',
            'redeemScript': '6382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666703a90040b27576a914225fbfa4cb725b75e511810ac4d6f74069bdded26888ac',
            'amount': 1.0}
        ro = callnoderpc(0, 'verifyrawtransaction', [txn, [prevout, ]])
        assert (ro['inputs_valid'] is False)
        assert (ro['validscripts'] == 0)  # Amount covered by signature

        prevout['amount'] = 90.0
        ro = callnoderpc(0, 'verifyrawtransaction', [txn, [prevout, ]])
        assert (ro['inputs_valid'] is True)
        assert (ro['validscripts'] == 1)

    def test_02_part_ltc(self):
        logging.info('---------- Test PART to LTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.LTC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)

        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        offerer_states = read_json_api(1800, path)
        bidder_states = read_json_api(1801, path)

        assert (compare_bid_states(offerer_states, self.states_offerer[0]) is True)
        assert (compare_bid_states(bidder_states, self.states_bidder[0]) is True)

    def test_03_ltc_part(self):
        logging.info('---------- Test LTC to PART')
        swap_clients = self.swap_clients

        offer_id = swap_clients[1].postOffer(Coins.LTC, Coins.PART, 10 * COIN, 9.0 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[1], bid_id)
        swap_clients[1].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[0], bid_id, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_04_ltc_btc(self):
        logging.info('---------- Test LTC to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.LTC, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_05_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info('---------- Test refund, LTC to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.LTC, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 10)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[1].abandonBid(bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.BID_ABANDONED, sent=True, wait_for=60)

        js_0_bid = read_json_api(1800, 'bids/{}'.format(bid_id.hex()))
        js_1_bid = read_json_api(1801, 'bids/{}'.format(bid_id.hex()))
        assert (js_0_bid['itx_state'] == 'Refunded')
        assert (js_1_bid['ptx_state'] == 'Unknown')

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        offerer_states = read_json_api(1800, path)
        bidder_states = read_json_api(1801, path)

        assert (compare_bid_states(offerer_states, self.states_offerer[1]) is True)
        assert (bidder_states[-1][1] == 'Bid Abandoned')

    def test_06_self_bid(self):
        logging.info('---------- Test same client, BTC to LTC')
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.LTC, 10 * COIN, 10 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid_tx_state(test_delay_event, swap_clients[0], bid_id, TxStates.TX_REDEEMED, TxStates.TX_REDEEMED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = read_json_api(1800)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_0['num_recv_bids'] == js_0_before['num_recv_bids'] + 1 and js_0['num_sent_bids'] == js_0_before['num_sent_bids'] + 1)

    def test_07_error(self):
        logging.info('---------- Test error, BTC to LTC, set fee above bid value')
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.LTC, 0.001 * COIN, 1.0 * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate'] = 10.0
        swap_clients[0].getChainClientSettings(Coins.LTC)['override_feerate'] = 10.0

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=60)

        swap_clients[0].abandonBid(bid_id)
        del swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate']
        del swap_clients[0].getChainClientSettings(Coins.LTC)['override_feerate']

    def test_08_part_ltc_buyer_first(self):
        logging.info('---------- Test PART to LTC, buyer first')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.LTC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.BUYER_FIRST)

        logging.warning('TODO')

    def test_09_part_ltc_auto_accept(self):
        logging.info('---------- Test PART to LTC, auto accept bid')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.LTC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST, auto_accept_bids=True)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

    def test_10_bad_ptx(self):
        # Invalid PTX sent, swap should stall and ITx and PTx should be reclaimed by senders
        logging.info('---------- Test bad PTx, LTC to BTC')
        swap_clients = self.swap_clients

        swap_value = make_int(random.uniform(0.001, 10.0), scale=8, r=1)
        logging.info('swap_value {}'.format(format_amount(swap_value, 8)))
        offer_id = swap_clients[0].postOffer(Coins.LTC, Coins.BTC, swap_value, 0.1 * COIN, swap_value, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 18)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.MAKE_INVALID_PTX)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

        js_0_bid = read_json_api(1800, 'bids/{}'.format(bid_id.hex()))
        js_1_bid = read_json_api(1801, 'bids/{}'.format(bid_id.hex()))
        assert (js_0_bid['itx_state'] == 'Refunded')
        assert (js_1_bid['ptx_state'] == 'Refunded')

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        offerer_states = read_json_api(1800, path)
        bidder_states = read_json_api(1801, path)

        assert (compare_bid_states(offerer_states, self.states_offerer[1]) is True)
        assert (compare_bid_states(bidder_states, self.states_bidder[1]) is True)

    '''
    def test_11_refund(self):
        # Seller submits initiate txn, buyer doesn't respond, repeat of test 5 using debug_ind
        logging.info('---------- Test refund, LTC to BTC')
        swap_clients = self.swap_clients

        swap_value = make_int(random.uniform(0.001, 10.0), scale=8, r=1)
        logging.info('swap_value {}'.format(format_amount(swap_value, 8)))
        offer_id = swap_clients[0].postOffer(Coins.LTC, Coins.BTC, swap_value, 0.1 * COIN, swap_value, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 10)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BUYER_STOP_AFTER_ITX)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.BID_ABANDONED, sent=True, wait_for=120)

        js_0_bid = read_json_api(1800, 'bids/{}'.format(bid_id.hex()))
        js_1_bid = read_json_api(1801, 'bids/{}'.format(bid_id.hex()))
        assert (js_0_bid['itx_state'] == 'Refunded')
        assert (js_1_bid['ptx_state'] == 'Unknown')

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)
    '''

    def test_12_withdrawal(self):
        logging.info('---------- Test LTC withdrawals')

        ltc_addr = callnoderpc(0, 'getnewaddress', ['Withdrawal test', 'legacy'], base_rpc_port=LTC_BASE_RPC_PORT)
        wallets0 = read_json_api(TEST_HTTP_PORT + 0, 'wallets')
        assert (float(wallets0['LTC']['balance']) > 100)

        post_json = {
            'value': 100,
            'address': ltc_addr,
            'subfee': False,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, 'wallets/ltc/withdraw', post_json)
        assert (len(json_rv['txid']) == 64)

    def test_13_itx_refund(self):
        logging.info('---------- Test ITX refunded')
        # Initiator claims PTX and refunds ITX after lock expires
        # Participant loses PTX value without gaining ITX value
        swap_clients = self.swap_clients

        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        swap_value = make_int(random.uniform(2.0, 20.0), scale=8, r=1)
        logging.info('swap_value {}'.format(format_amount(swap_value, 8)))
        offer_id = swap_clients[0].postOffer(Coins.LTC, Coins.BTC, swap_value, 0.5 * COIN, swap_value, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 18)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.DONT_SPEND_ITX)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)

        # For testing: Block refunding the ITX until PTX has been redeemed, else ITX refund can become spendable before PTX confirms
        swap_clients[0].setBidDebugInd(bid_id, DebugTypes.SKIP_LOCK_TX_REFUND)
        swap_clients[0].acceptBid(bid_id)
        wait_for_bid_tx_state(test_delay_event, swap_clients[0], bid_id, TxStates.TX_CONFIRMED, TxStates.TX_REDEEMED, wait_for=60)
        swap_clients[0].setBidDebugInd(bid_id, DebugTypes.NONE)

        wait_for_bid_tx_state(test_delay_event, swap_clients[0], bid_id, TxStates.TX_REFUNDED, TxStates.TX_REDEEMED, wait_for=60)

        js_w0_after = read_json_api(1800, 'wallets')
        js_w1_after = read_json_api(1801, 'wallets')

        ltc_swap_value = swap_value
        btc_swap_value = swap_value // 2
        node0_btc_before = self.getBalance(js_w0_before, Coins.BTC)
        node0_btc_after = self.getBalance(js_w0_after, Coins.BTC)
        node0_ltc_before = self.getBalance(js_w0_before, Coins.LTC)
        node0_ltc_after = self.getBalance(js_w0_after, Coins.LTC)

        node1_btc_before = self.getBalance(js_w1_before, Coins.BTC)
        node1_btc_after = self.getBalance(js_w1_after, Coins.BTC)
        node1_ltc_before = self.getBalance(js_w1_before, Coins.LTC)
        node1_ltc_after = self.getBalance(js_w1_after, Coins.LTC)

        high_fee_value_btc = int(0.001 * COIN)
        high_fee_value_ltc = int(0.01 * COIN)  # TODO Set fees directly, see listtransactions

        assert (node0_btc_after > node0_btc_before + btc_swap_value - high_fee_value_btc)
        assert (node0_ltc_after > node0_ltc_before - high_fee_value_ltc)

        assert (node1_btc_after < node1_btc_before - btc_swap_value)
        assert (node1_ltc_before == node1_ltc_after)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        offerer_states = read_json_api(1800, path)
        bidder_states = read_json_api(1801, path)

        assert (compare_bid_states(offerer_states, self.states_offerer[2]) is True)
        assert (compare_bid_states(bidder_states, self.states_bidder[2], exact_match=False) is True)

    def test_14_sweep_balance(self):
        logging.info('---------- Test sweep balance offer')
        swap_clients = self.swap_clients

        # Disable staking
        walletsettings = callnoderpc(2, 'walletsettings', ['stakingoptions', ])
        walletsettings['enabled'] = False
        walletsettings = callnoderpc(2, 'walletsettings', ['stakingoptions', walletsettings])
        walletsettings = callnoderpc(2, 'walletsettings', ['stakingoptions', ])
        assert (walletsettings['stakingoptions']['enabled'] is False)

        # Prepare balance
        js_w2 = read_json_api(1802, 'wallets')
        if float(js_w2['PART']['balance']) < 100.0:
            post_json = {
                'value': 100,
                'address': js_w2['PART']['deposit_address'],
                'subfee': False,
            }
            json_rv = read_json_api(TEST_HTTP_PORT + 0, 'wallets/part/withdraw', post_json)
            assert (len(json_rv['txid']) == 64)
            wait_for_balance(test_delay_event, 'http://127.0.0.1:1802/json/wallets/part', 'balance', 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        assert (float(js_w2['PART']['balance']) >= 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        post_json = {
            'value': float(js_w2['PART']['balance']),
            'address': read_json_api(1802, 'wallets/part/nextdepositaddr'),
            'subfee': True,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 2, 'wallets/part/withdraw', post_json)
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1802/json/wallets/part', 'balance', 10.0)
        assert (len(json_rv['txid']) == 64)

        # Create prefunded ITX
        ci = swap_clients[2].ci(Coins.PART)
        pi = swap_clients[2].pi(SwapTypes.SELLER_FIRST)
        js_w2 = read_json_api(1802, 'wallets')
        swap_value = ci.make_int(js_w2['PART']['balance'])

        itx = pi.getFundedInitiateTxTemplate(ci, swap_value, True)
        itx_decoded = ci.describeTx(itx.hex())
        n = pi.findMockVout(ci, itx_decoded)
        value_after_subfee = ci.make_int(itx_decoded['vout'][n]['value'])
        assert (value_after_subfee < swap_value)
        swap_value = value_after_subfee
        wait_for_unspent(test_delay_event, ci, swap_value)

        # Create swap with prefunded ITX
        extra_options = {'prefunded_itx': itx}
        offer_id = swap_clients[2].postOffer(Coins.PART, Coins.BTC, swap_value, 2 * COIN, swap_value, SwapTypes.SELLER_FIRST, extra_options=extra_options)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        # Verify expected inputs were used
        bid, offer = swap_clients[2].getBidAndOffer(bid_id)
        assert (bid.initiate_tx)
        wtx = ci.rpc_callback('gettransaction', [bid.initiate_tx.txid.hex(),])
        itx_after = ci.describeTx(wtx['hex'])
        assert (len(itx_after['vin']) == len(itx_decoded['vin']))
        for i, txin in enumerate(itx_decoded['vin']):
            assert (txin['txid'] == itx_after['vin'][i]['txid'])
            assert (txin['vout'] == itx_after['vin'][i]['vout'])

    def pass_99_delay(self):
        logging.info('Delay')
        for i in range(60 * 10):
            if test_delay_event.is_set():
                break
            test_delay_event.wait(1)
            print('delay', i)
            if i % 2 == 0:
                offer_id = self.swap_clients[0].postOffer(Coins.BTC, Coins.LTC, 0.001 * (i + 1) * COIN, 1.0 * (i + 1) * COIN, 0.001 * (i + 1) * COIN, SwapTypes.SELLER_FIRST)
            else:
                offer_id = self.swap_clients[1].postOffer(Coins.LTC, Coins.BTC, 0.001 * (i + 1) * COIN, 1.0 * (i + 1) * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST)


if __name__ == '__main__':
    unittest.main()
