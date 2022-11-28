#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export RESET_TEST=true
export TEST_PATH=/tmp/test_persistent
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
python tests/basicswap/extended/test_xmr_persistent.py

"""

import os
import sys
import json
import time
import random
import signal
import logging
import unittest
import threading
import multiprocessing
from unittest.mock import patch

from basicswap.rpc_xmr import (
    callrpc_xmr,
)
from basicswap.rpc import (
    callrpc,
)
from tests.basicswap.common import (
    BASE_RPC_PORT,
    BTC_BASE_RPC_PORT,
)
from tests.basicswap.util import (
    make_boolean,
    read_json_api,
    waitForServer,
)
from tests.basicswap.common_xmr import (
    prepare_nodes,
    XMR_BASE_RPC_PORT,
)
import bin.basicswap_run as runSystem


test_path = os.path.expanduser(os.getenv('TEST_PATH', '/tmp/test_persistent'))
RESET_TEST = make_boolean(os.getenv('RESET_TEST', 'false'))

PORT_OFS = int(os.getenv('PORT_OFS', 1))
UI_PORT = 12700 + PORT_OFS

PARTICL_RPC_PORT_BASE = int(os.getenv('PARTICL_RPC_PORT_BASE', BASE_RPC_PORT))
BITCOIN_RPC_PORT_BASE = int(os.getenv('BITCOIN_RPC_PORT_BASE', BTC_BASE_RPC_PORT))
XMR_BASE_RPC_PORT = int(os.getenv('XMR_BASE_RPC_PORT', XMR_BASE_RPC_PORT))


NUM_NODES = int(os.getenv('NUM_NODES', 3))
EXTRA_CONFIG_JSON = json.loads(os.getenv('EXTRA_CONFIG_JSON', '{}'))

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def callpartrpc(node_id, method, params=[], wallet=None, base_rpc_port=PARTICL_RPC_PORT_BASE + PORT_OFS):
    auth = 'test_part_{0}:test_part_pwd_{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def callbtcrpc(node_id, method, params=[], wallet=None, base_rpc_port=BITCOIN_RPC_PORT_BASE + PORT_OFS):
    auth = 'test_btc_{0}:test_btc_pwd_{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def updateThread(cls):
    while not cls.delay_event.is_set():
        try:
            if cls.btc_addr is not None:
                callbtcrpc(0, 'generatetoaddress', [1, cls.btc_addr])
        except Exception as e:
            print('updateThread error', str(e))
        cls.delay_event.wait(random.randrange(cls.update_min, cls.update_max))


def updateThreadXmr(cls):
    while not cls.delay_event.is_set():
        try:
            if cls.xmr_addr is not None:
                callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': 1})
        except Exception as e:
            print('updateThreadXmr error', str(e))
        cls.delay_event.wait(random.randrange(cls.xmr_update_min, cls.xmr_update_max))


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        cls.update_min = int(os.getenv('UPDATE_THREAD_MIN_WAIT', '1'))
        cls.update_max = cls.update_min * 4

        cls.xmr_update_min = int(os.getenv('XMR_UPDATE_THREAD_MIN_WAIT', '1'))
        cls.xmr_update_max = cls.xmr_update_min * 4

        cls.delay_event = threading.Event()
        cls.update_thread = None
        cls.update_thread_xmr = None
        cls.processes = []
        cls.btc_addr = None
        cls.xmr_addr = None

        random.seed(time.time())

        if os.path.exists(test_path) and not RESET_TEST:
            logging.info(f'Continuing with existing directory: {test_path}')
        else:
            logging.info('Preparing %d nodes.', NUM_NODES)
            prepare_nodes(NUM_NODES, 'bitcoin,monero', True, {'min_sequence_lock_seconds': 60}, PORT_OFS)

        signal.signal(signal.SIGINT, lambda signal, frame: cls.signal_handler(cls, signal, frame))

    def signal_handler(self, sig, frame):
        logging.info('signal {} detected.'.format(sig))
        self.delay_event.set()

    def run_thread(self, client_id):
        client_path = os.path.join(test_path, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def start_processes(self):
        self.delay_event.clear()

        for i in range(NUM_NODES):
            self.processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            self.processes[-1].start()

        for i in range(NUM_NODES):
            waitForServer(self.delay_event, UI_PORT + i)

        wallets = read_json_api(UI_PORT + 1, 'wallets')

        self.xmr_addr = wallets['XMR']['main_address']
        num_blocks = 100
        if callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
            logging.info('Mining {} Monero blocks to {}.'.format(num_blocks, self.xmr_addr))
            callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': self.xmr_addr, 'amount_of_blocks': num_blocks})
        logging.info('XMR blocks: %d', callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'])

        self.btc_addr = callbtcrpc(0, 'getnewaddress', ['mining_addr', 'bech32'])
        num_blocks = 500  # Mine enough to activate segwit
        if callbtcrpc(0, 'getblockchaininfo')['blocks'] < num_blocks:
            logging.info('Mining %d Bitcoin blocks to %s', num_blocks, self.btc_addr)
            callbtcrpc(0, 'generatetoaddress', [num_blocks, self.btc_addr])
        logging.info('BTC blocks: %d', callbtcrpc(0, 'getblockchaininfo')['blocks'])

        # Lower output split threshold for more stakeable outputs
        for i in range(NUM_NODES):
            callpartrpc(i, 'walletsettings', ['stakingoptions', {'stakecombinethreshold': 100, 'stakesplitthreshold': 200}])
        self.update_thread = threading.Thread(target=updateThread, args=(self,))
        self.update_thread.start()

        self.update_thread_xmr = threading.Thread(target=updateThreadXmr, args=(self,))
        self.update_thread_xmr.start()

        # Wait for height, or sequencelock is thrown off by genesis blocktime
        num_blocks = 3
        logging.info('Waiting for Particl chain height %d', num_blocks)
        for i in range(60):
            if self.delay_event.is_set():
                raise ValueError('Test stopped.')
            particl_blocks = callpartrpc(0, 'getblockcount')
            print('particl_blocks', particl_blocks)
            if particl_blocks >= num_blocks:
                break
            self.delay_event.wait(1)
        logging.info('PART blocks: %d', callpartrpc(0, 'getblockcount'))
        assert particl_blocks >= num_blocks

    @classmethod
    def tearDownClass(cls):
        logging.info('Stopping test')
        cls.delay_event.set()
        if cls.update_thread:
            cls.update_thread.join()
        if cls.update_thread_xmr:
            cls.update_thread_xmr.join()
        for p in cls.processes:
            p.terminate()
        for p in cls.processes:
            p.join()
        cls.update_thread = None
        cls.update_thread_xmr = None
        cls.processes = []

    def test_persistent(self):

        self.start_processes()

        waitForServer(self.delay_event, UI_PORT + 0)
        waitForServer(self.delay_event, UI_PORT + 1)

        while not self.delay_event.is_set():
            logging.info('Looping indefinitely, ctrl+c to exit.')
            self.delay_event.wait(10)


if __name__ == '__main__':
    unittest.main()
