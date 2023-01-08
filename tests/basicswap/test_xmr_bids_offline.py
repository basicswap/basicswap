#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
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

from tests.basicswap.util import (
    read_json_api,
    waitForServer,
)
from tests.basicswap.common import (
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
        wallets1 = read_json_api(12701, 'wallets')
        assert (float(wallets1['XMR']['balance']) > 0.0)

        offer_data = {
            'addr_from': -1,
            'coin_from': 'PART',
            'coin_to': 'XMR',
            'amt_from': 1,
            'amt_to': 1,
            'lockhrs': 24,
            'automation_strat_id': 1}
        rv = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=parse.urlencode(offer_data).encode()).read())
        offer0_id = rv['offer_id']

        offer_data['amt_from'] = '2'
        rv = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=parse.urlencode(offer_data).encode()).read())
        offer1_id = rv['offer_id']

        summary = read_json_api(12700)
        assert (summary['num_sent_offers'] > 1)

        logger.info('Waiting for offer')
        waitForNumOffers(self.delay_event, 12701, 2)

        logger.info('Stopping node 0')
        c0 = self.processes[0]
        c0.terminate()
        c0.join()

        offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers/{}'.format(offer0_id)).read())
        assert (len(offers) == 1)
        offer0 = offers[0]

        post_data = {
            'coin_from': 'PART'
        }
        test_post_offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers', data=parse.urlencode(post_data).encode()).read())
        assert (len(test_post_offers) == 2)
        post_data['coin_from'] = '2'
        test_post_offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers', data=parse.urlencode(post_data).encode()).read())
        assert (len(test_post_offers) == 0)

        bid_data = {
            'offer_id': offer0_id,
            'amount_from': offer0['amount_from']}

        bid0_id = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(bid_data).encode()).read())['bid_id']

        offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers/{}'.format(offer1_id)).read())
        assert (len(offers) == 1)
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
            assert rv['bid_state'] == 'Accepted'
        except Exception as e:
            print('Accept bid failed', str(e), rv)
        try:
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid1_id), data=data).read())
            assert (rv['bid_state'] == 'Accepted')
        except Exception as e:
            print('Accept bid failed', str(e), rv)

        logger.info('Completing swap')
        for i in range(240):
            if self.delay_event.is_set():
                raise ValueError('Test stopped.')
            self.delay_event.wait(4)

            rv0 = read_json_api(12700, 'bids/{}'.format(bid0_id))
            rv1 = read_json_api(12700, 'bids/{}'.format(bid1_id))
            if rv0['bid_state'] == 'Completed' and rv1['bid_state'] == 'Completed':
                break
        assert rv0['bid_state'] == 'Completed'
        assert rv1['bid_state'] == 'Completed'


if __name__ == '__main__':
    unittest.main()
