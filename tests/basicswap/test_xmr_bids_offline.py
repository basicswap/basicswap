#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_RELOAD_PATH=/tmp/test_basicswap
mkdir -p ${TEST_RELOAD_PATH}/bin/{particl,monero}
cp ~/tmp/particl-0.21.2.3-x86_64-linux-gnu.tar.gz ${TEST_RELOAD_PATH}/bin/particl
cp ~/tmp/monero-linux-x64-v0.17.2.3.tar.bz2 ${TEST_RELOAD_PATH}/bin/monero/monero-0.17.2.3-x86_64-linux-gnu.tar.bz2
export PYTHONPATH=$(pwd)
python tests/basicswap/test_xmr_bids_offline.py


"""

import sys
import json
import logging
import unittest
import multiprocessing
from urllib import parse
from urllib.request import urlopen

from tests.basicswap.common import (
    waitForServer,
    waitForNumOffers,
    waitForNumBids,
)
from tests.basicswap.common_xmr import (
    XmrTestBase,
    waitForBidState,
)

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(XmrTestBase):

    def test_bids_offline(self):
        # Start multiple bids while offering node is offline

        self.start_processes()

        waitForServer(self.delay_event, 12700)
        waitForServer(self.delay_event, 12701)
        wallets1 = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())
        assert(float(wallets1['6']['balance']) > 0.0)

        offer_data = {
            'addr_from': -1,
            'coin_from': 1,
            'coin_to': 6,
            'amt_from': 1,
            'amt_to': 1,
            'lockhrs': 24,
            'autoaccept': True}
        rv = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=parse.urlencode(offer_data).encode()).read())
        offer0_id = rv['offer_id']

        offer_data['amt_from'] = '2'
        rv = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=parse.urlencode(offer_data).encode()).read())
        offer1_id = rv['offer_id']

        summary = json.loads(urlopen('http://127.0.0.1:12700/json').read())
        assert(summary['num_sent_offers'] > 1)

        logger.info('Waiting for offer')
        waitForNumOffers(self.delay_event, 12701, 2)

        logger.info('Stopping node 0')
        c0 = self.processes[0]
        c0.terminate()
        c0.join()

        offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers/{}'.format(offer0_id)).read())
        assert(len(offers) == 1)
        offer0 = offers[0]

        post_data = {
            'coin_from': '1'
        }
        test_post_offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers', data=parse.urlencode(post_data).encode()).read())
        assert(len(test_post_offers) == 2)
        post_data['coin_from'] = '2'
        test_post_offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers', data=parse.urlencode(post_data).encode()).read())
        assert(len(test_post_offers) == 0)

        bid_data = {
            'offer_id': offer0_id,
            'amount_from': offer0['amount_from']}

        bid0_id = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(bid_data).encode()).read())['bid_id']

        offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers/{}'.format(offer1_id)).read())
        assert(len(offers) == 1)
        offer1 = offers[0]

        bid_data = {
            'offer_id': offer1_id,
            'amount_from': offer1['amount_from']}

        bid1_id = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(bid_data).encode()).read())['bid_id']

        logger.info('Delaying for 5 seconds.')
        self.delay_event.wait(5)

        logger.info('Starting node 0')
        self.processes[0] = multiprocessing.Process(target=self.run_thread, args=(0,))
        self.processes[0].start()

        waitForServer(self.delay_event, 12700)
        waitForNumBids(self.delay_event, 12700, 2)

        waitForBidState(self.delay_event, 12700, bid0_id, 'Received')
        waitForBidState(self.delay_event, 12700, bid1_id, 'Received')

        # Manually accept on top of auto-accept for extra chaos
        data = parse.urlencode({
            'accept': True
        }).encode()
        try:
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid0_id), data=data).read())
            assert(rv['bid_state'] == 'Accepted')
        except Exception as e:
            print('Accept bid failed', str(e), rv)
        try:
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid1_id), data=data).read())
            assert(rv['bid_state'] == 'Accepted')
        except Exception as e:
            print('Accept bid failed', str(e), rv)

        logger.info('Completing swap')
        for i in range(240):
            if self.delay_event.is_set():
                raise ValueError('Test stopped.')
            self.delay_event.wait(4)

            rv0 = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid0_id)).read())
            rv1 = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid1_id)).read())
            if rv0['bid_state'] == 'Completed' and rv1['bid_state'] == 'Completed':
                break
        assert(rv0['bid_state'] == 'Completed')
        assert(rv1['bid_state'] == 'Completed')


if __name__ == '__main__':
    unittest.main()
