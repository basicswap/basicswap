#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_RELOAD_PATH=/tmp/test_basicswap
mkdir -p ${TEST_RELOAD_PATH}/bin/{particl,monero}
cp ~/tmp/particl-0.21.2.7-x86_64-linux-gnu.tar.gz ${TEST_RELOAD_PATH}/bin/particl
cp ~/tmp/monero-linux-x64-v0.17.3.0.tar.bz2 ${TEST_RELOAD_PATH}/bin/monero/monero-0.17.3.0-x86_64-linux-gnu.tar.bz2
export PYTHONPATH=$(pwd)
python tests/basicswap/test_xmr_reload.py


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
    waitForNumSwapping,
)
from tests.basicswap.common_xmr import (
    XmrTestBase,
)

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(XmrTestBase):

    def test_reload(self):
        self.start_processes()

        waitForServer(self.delay_event, 12700)
        waitForServer(self.delay_event, 12701)
        wallets1 = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())
        assert(float(wallets1['6']['balance']) > 0.0)

        data = parse.urlencode({
            'addr_from': '-1',
            'coin_from': 'part',
            'coin_to': 'xmr',
            'amt_from': '1',
            'amt_to': '1',
            'lockhrs': '24'}).encode()

        offer_id = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=data).read())['offer_id']
        summary = json.loads(urlopen('http://127.0.0.1:12700/json').read())
        assert(summary['num_sent_offers'] == 1)

        logger.info('Waiting for offer')
        waitForNumOffers(self.delay_event, 12701, 1)

        offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers').read())
        offer = offers[0]

        data = {
            'offer_id': offer['offer_id'],
            'amount_from': offer['amount_from']}

        data['valid_for_seconds'] = 24 * 60 * 60 + 1
        bid = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(data).encode()).read())
        assert(bid['error'] == 'Bid TTL too high')
        del data['valid_for_seconds']
        data['validmins'] = 24 * 60 + 1
        bid = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(data).encode()).read())
        assert(bid['error'] == 'Bid TTL too high')

        del data['validmins']
        data['valid_for_seconds'] = 10
        bid = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(data).encode()).read())
        assert(bid['error'] == 'Bid TTL too low')
        del data['valid_for_seconds']
        data['validmins'] = 1
        bid = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(data).encode()).read())
        assert(bid['error'] == 'Bid TTL too low')

        data['validmins'] = 60
        bid_id = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=parse.urlencode(data).encode()).read())

        waitForNumBids(self.delay_event, 12700, 1)

        for i in range(10):
            bids = json.loads(urlopen('http://127.0.0.1:12700/json/bids').read())
            bid = bids[0]
            if bid['bid_state'] == 'Received':
                break
            self.delay_event.wait(1)
        assert(bid['expire_at'] == bid['created_at'] + data['validmins'] * 60)

        data = parse.urlencode({
            'accept': True
        }).encode()
        rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid['bid_id']), data=data).read())
        assert(rv['bid_state'] == 'Accepted')

        waitForNumSwapping(self.delay_event, 12701, 1)

        logger.info('Restarting client')
        c1 = self.processes[1]
        c1.terminate()
        c1.join()
        self.processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
        self.processes[1].start()

        waitForServer(self.delay_event, 12701)
        rv = json.loads(urlopen('http://127.0.0.1:12701/json').read())
        assert(rv['num_swapping'] == 1)

        rv = json.loads(urlopen('http://127.0.0.1:12700/json/revokeoffer/{}'.format(offer_id)).read())
        assert(rv['revoked_offer'] == offer_id)

        logger.info('Completing swap')
        for i in range(240):
            if self.delay_event.is_set():
                raise ValueError('Test stopped.')
            self.delay_event.wait(4)

            rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid['bid_id'])).read())
            if rv['bid_state'] == 'Completed':
                break
        assert(rv['bid_state'] == 'Completed')

        # Ensure offer was revoked
        summary = json.loads(urlopen('http://127.0.0.1:12700/json').read())
        assert(summary['num_network_offers'] == 0)

        # Wait for bid to be removed from in-progress
        waitForNumBids(self.delay_event, 12700, 0)


if __name__ == '__main__':
    unittest.main()
