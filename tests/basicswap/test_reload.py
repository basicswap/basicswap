#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2023 tecnovert
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
import logging
import unittest
import traceback
import threading
import multiprocessing
from unittest.mock import patch

from basicswap.rpc import (
    callrpc_cli,
)
from tests.basicswap.util import (
    read_json_api,
    post_json_api,
    waitForServer,
)
from tests.basicswap.common import (
    waitForNumOffers,
    waitForNumBids,
    waitForNumSwapping,
)
from tests.basicswap.common_xmr import (
    prepare_nodes,
)
import basicswap.bin.run as runSystem

TEST_PATH = os.path.expanduser(os.getenv('TEST_PATH', '~/test_basicswap1'))
delay_event = threading.Event()

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def btcRpc(client_no, cmd):
    bin_path = os.path.join(TEST_PATH, 'bin', 'bitcoin')
    data_path = os.path.join(TEST_PATH, 'client{}'.format(client_no), 'bitcoin')
    return callrpc_cli(bin_path, data_path, 'regtest', cmd, 'bitcoin-cli')


def partRpc(client_no, cmd):
    bin_path = os.path.join(TEST_PATH, 'bin', 'particl')
    data_path = os.path.join(TEST_PATH, 'client{}'.format(client_no), 'particl')
    return callrpc_cli(bin_path, data_path, 'regtest', cmd, 'particl-cli')


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

    def wait_for_node_height(self, port=12701, wallet_ticker='part', wait_for_blocks=3):
        # Wait for height, or sequencelock is thrown off by genesis blocktime
        logging.info(f'Waiting for {wallet_ticker} chain height {wait_for_blocks} at port {port}', )
        for i in range(60):
            if delay_event.is_set():
                raise ValueError('Test stopped.')
            try:
                wallet = read_json_api(port, f'wallets/{wallet_ticker}')
                node_blocks = wallet['blocks']
                print(f'{wallet_ticker} node_blocks {node_blocks}')
                if node_blocks >= wait_for_blocks:
                    return
            except Exception as e:
                print('Error reading wallets', str(e))
            delay_event.wait(1)
        raise ValueError(f'wait_for_node_height timed out, {wallet_ticker}, {wait_for_blocks}, {port}')

    def test_reload(self):
        global stop_test
        processes = []

        for i in range(3):
            processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            processes[-1].start()

        try:
            waitForServer(delay_event, 12700)
            partRpc(0, 'reservebalance false')  # WakeThreadStakeMiner
            self.wait_for_node_height()

            num_blocks = 500
            btc_addr = btcRpc(1, 'getnewaddress mining_addr bech32')
            logging.info('Mining %d Bitcoin blocks to %s', num_blocks, btc_addr)
            btcRpc(1, 'generatetoaddress {} {}'.format(num_blocks, btc_addr))
            self.wait_for_node_height(12700, 'btc', num_blocks)

            data = {
                'addr_from': '-1',
                'coin_from': 'PART',
                'coin_to': '2',
                'amt_from': '1',
                'amt_to': '1',
                'lockhrs': '24'}

            offer_id = post_json_api(12700, 'offers/new', data)['offer_id']
            summary = read_json_api(12700)
            assert (summary['num_sent_offers'] == 1)
        except Exception:
            traceback.print_exc()

        sentoffers = read_json_api(12700, 'sentoffers', {'active': True})
        assert sentoffers[0]['offer_id'] == offer_id

        logger.info('Waiting for offer:')
        waitForNumOffers(delay_event, 12701, 1)

        offers = read_json_api(12701, 'offers')
        offer = offers[0]

        data = {
            'offer_id': offer['offer_id'],
            'amount_from': offer['amount_from']}

        bid_id = post_json_api(12701, 'bids/new', data)

        waitForNumBids(delay_event, 12700, 1)

        bids = read_json_api(12700, 'bids')
        bid = bids[0]

        data = {
            'accept': True
        }
        rv = post_json_api(12700, 'bids/{}'.format(bid['bid_id']), data)
        assert (rv['bid_state'] == 'Accepted')

        waitForNumSwapping(delay_event, 12701, 1)

        logger.info('Restarting client:')
        c1 = processes[1]
        c1.terminate()
        c1.join()
        processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
        processes[1].start()

        waitForServer(delay_event, 12701)
        rv = read_json_api(12701)
        assert (rv['num_swapping'] == 1)

        update_thread = threading.Thread(target=updateThread)
        update_thread.start()

        logger.info('Completing swap:')
        for i in range(240):
            delay_event.wait(5)

            rv = read_json_api(12700, 'bids/{}'.format(bid['bid_id']))
            if rv['bid_state'] == 'Completed':
                break
        assert (rv['bid_state'] == 'Completed')

        delay_event.set()
        update_thread.join()
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()


if __name__ == '__main__':
    unittest.main()
