#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
python tests/basicswap/test_reload.py

"""

import os
import sys
import json
import logging
import unittest
import traceback
import threading
import multiprocessing
from urllib import parse
from urllib.request import urlopen
from unittest.mock import patch

from basicswap.rpc import (
    callrpc_cli,
)
from tests.basicswap.common import (
    read_json_api,
    waitForServer,
    waitForNumOffers,
    waitForNumBids,
    waitForNumSwapping,
)
from tests.basicswap.common_xmr import (
    prepare_nodes,
)
import bin.basicswap_run as runSystem

TEST_PATH = os.path.expanduser(os.getenv('TEST_PATH', '~/test_basicswap1'))
PARTICL_PORT_BASE = int(os.getenv('PARTICL_PORT_BASE', '11938'))
BITCOIN_PORT_BASE = int(os.getenv('BITCOIN_PORT_BASE', '10938'))
delay_event = threading.Event()

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def btcRpc(client_no, cmd):
    bin_path = os.path.join(TEST_PATH, 'bin', 'bitcoin')
    data_path = os.path.join(TEST_PATH, 'client{}'.format(client_no), 'bitcoin')
    return callrpc_cli(bin_path, data_path, 'regtest', cmd, 'bitcoin-cli')


def updateThread():
    btc_addr = btcRpc(0, 'getnewaddress mining_addr bech32')

    while not delay_event.is_set():
        btcRpc(0, 'generatetoaddress {} {}'.format(1, btc_addr))
        delay_event.wait(5)


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        prepare_nodes(3, 'bitcoin')

    def run_thread(self, client_id):
        client_path = os.path.join(TEST_PATH, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def test_reload(self):
        global stop_test
        processes = []

        for i in range(3):
            processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            processes[-1].start()

        try:
            waitForServer(delay_event, 12700)

            num_blocks = 500
            btc_addr = btcRpc(1, 'getnewaddress mining_addr bech32')
            logging.info('Mining %d Bitcoin blocks to %s', num_blocks, btc_addr)
            btcRpc(1, 'generatetoaddress {} {}'.format(num_blocks, btc_addr))

            for i in range(20):
                if delay_event.is_set():
                    raise ValueError('Test stopped.')
                blocks = btcRpc(0, 'getblockchaininfo')['blocks']
                if blocks >= num_blocks:
                    break
                delay_event.wait(2)
            assert(blocks >= num_blocks)

            data = parse.urlencode({
                'addr_from': '-1',
                'coin_from': '1',
                'coin_to': '2',
                'amt_from': '1',
                'amt_to': '1',
                'lockhrs': '24'}).encode()

            offer_id = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=data).read())
            summary = read_json_api(12700)
            assert(summary['num_sent_offers'] == 1)
        except Exception:
            traceback.print_exc()

        logger.info('Waiting for offer:')
        waitForNumOffers(delay_event, 12701, 1)

        offers = read_json_api(12701, 'offers')
        offer = offers[0]

        data = parse.urlencode({
            'offer_id': offer['offer_id'],
            'amount_from': offer['amount_from']}).encode()

        bid_id = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=data).read())

        waitForNumBids(delay_event, 12700, 1)

        bids = read_json_api(12700, 'bids')
        bid = bids[0]

        data = parse.urlencode({
            'accept': True
        }).encode()
        rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid['bid_id']), data=data).read())
        assert(rv['bid_state'] == 'Accepted')

        waitForNumSwapping(delay_event, 12701, 1)

        logger.info('Restarting client:')
        c1 = processes[1]
        c1.terminate()
        c1.join()
        processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
        processes[1].start()

        waitForServer(delay_event, 12701)
        rv = read_json_api(12701)
        assert(rv['num_swapping'] == 1)

        update_thread = threading.Thread(target=updateThread)
        update_thread.start()

        logger.info('Completing swap:')
        for i in range(240):
            delay_event.wait(5)

            rv = read_json_api(12700, 'bids/{}'.format(bid['bid_id']))
            print(rv)
            if rv['bid_state'] == 'Completed':
                break
        assert(rv['bid_state'] == 'Completed')

        delay_event.set()
        update_thread.join()
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()


if __name__ == '__main__':
    unittest.main()
