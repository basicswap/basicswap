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
)
from basicswap.util import (
    COIN,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    wait_for_bid,
    wait_for_offer,
    wait_for_in_progress,
    LTC_BASE_RPC_PORT,
)
from .test_btc_xmr import BasicSwapTest, test_delay_event

logger = logging.getLogger()


class TestLTC(BasicSwapTest):
    __test__ = True
    test_coin_from = Coins.LTC
    start_ltc_nodes = True
    base_rpc_port = LTC_BASE_RPC_PORT

    def mineBlock(self, num_blocks=1):
        self.callnoderpc('generatetoaddress', [num_blocks, self.ltc_addr])

    def test_001_nested_segwit(self):
        logging.info('---------- Test {} p2sh nested segwit'.format(self.test_coin_from.name))
        logging.info('Skipped')

    def test_002_native_segwit(self):
        logging.info('---------- Test {} p2sh native segwit'.format(self.test_coin_from.name))

        addr_segwit = self.callnoderpc('getnewaddress', ['segwit test', 'bech32'])
        addr_info = self.callnoderpc('getaddressinfo', [addr_segwit, ])
        assert addr_info['iswitness'] is True

        txid = self.callnoderpc('sendtoaddress', [addr_segwit, 1.0])
        assert len(txid) == 64
        tx_wallet = self.callnoderpc('gettransaction', [txid, ])['hex']
        tx = self.callnoderpc('decoderawtransaction', [tx_wallet, ])

        self.mineBlock()
        ro = self.callnoderpc('scantxoutset', ['start', ['addr({})'.format(addr_segwit)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

        prevout_n = -1
        for txo in tx['vout']:
            if addr_segwit in txo['scriptPubKey']['addresses']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        tx_funded = self.callnoderpc('createrawtransaction', [[{'txid': txid, 'vout': prevout_n}], {addr_segwit: 0.99}])
        tx_signed = self.callnoderpc('signrawtransactionwithwallet', [tx_funded, ])['hex']
        tx_funded_decoded = self.callnoderpc('decoderawtransaction', [tx_funded, ])
        tx_signed_decoded = self.callnoderpc('decoderawtransaction', [tx_signed, ])
        assert tx_funded_decoded['txid'] == tx_signed_decoded['txid']

    def test_007_hdwallet(self):
        logging.info('---------- Test {} hdwallet'.format(self.test_coin_from.name))

        test_seed = '8e54a313e6df8918df6d758fafdbf127a115175fdd2238d0e908dd8093c9ac3b'
        test_wif = self.swap_clients[0].ci(self.test_coin_from).encodeKey(bytes.fromhex(test_seed))
        new_wallet_name = random.randbytes(10).hex()
        self.callnoderpc('createwallet', [new_wallet_name])
        self.callnoderpc('sethdseed', [True, test_wif], wallet=new_wallet_name)
        addr = self.callnoderpc('getnewaddress', wallet=new_wallet_name)
        self.callnoderpc('unloadwallet', [new_wallet_name])
        assert (addr == 'rltc1qps7hnjd866e9ynxadgseprkc2l56m00djr82la')

    def test_20_btc_coin(self):
        logging.info('---------- Test BTC to {}'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.BTC, self.test_coin_from, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST)

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


if __name__ == '__main__':
    unittest.main()
