#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_RELOAD_PATH=/tmp/test_basicswap
mkdir -p ${TEST_RELOAD_PATH}/bin/{particl,monero}
cp ~/tmp/particl-0.19.1.2-x86_64-linux-gnu.tar.gz ${TEST_RELOAD_PATH}/bin/particl
cp ~/tmp/monero-0.17.1.9-x86_64-linux-gnu.tar.gz ${TEST_RELOAD_PATH}/bin/monero
export PYTHONPATH=$(pwd)
python tests/basicswap/test_reload_xmr.py


"""

import os
import sys
import json
import time
import shutil
import logging
import unittest
import traceback
import threading
import multiprocessing
from urllib import parse
from urllib.request import urlopen
from unittest.mock import patch

from basicswap.rpc_xmr import (
    callrpc_xmr_na,
)
from tests.basicswap.mnemonics import mnemonics

import basicswap.config as cfg
import bin.basicswap_prepare as prepareSystem
import bin.basicswap_run as runSystem

test_path = os.path.expanduser(os.getenv('TEST_RELOAD_PATH', '~/test_basicswap1'))
PARTICL_PORT_BASE = int(os.getenv('PARTICL_PORT_BASE', '11938'))

XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 29798
XMR_BASE_WALLET_RPC_PORT = 29998

stop_test = False

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def waitForServer(port):
    for i in range(20):
        try:
            time.sleep(1)
            summary = json.loads(urlopen('http://localhost:{}/json'.format(port)).read())
            break
        except Exception:
            traceback.print_exc()


def waitForNumOffers(port, offers):
    for i in range(20):
        summary = json.loads(urlopen('http://localhost:{}/json'.format(port)).read())
        if summary['num_network_offers'] >= offers:
            return
        time.sleep(1)
    raise ValueError('waitForNumOffers failed')


def waitForNumBids(port, bids):
    for i in range(20):
        summary = json.loads(urlopen('http://localhost:{}/json'.format(port)).read())
        if summary['num_recv_bids'] >= bids:
            return
        time.sleep(1)
    raise ValueError('waitForNumBids failed')


def waitForNumSwapping(port, bids):
    for i in range(20):
        summary = json.loads(urlopen('http://localhost:{}/json'.format(port)).read())
        if summary['num_swapping'] >= bids:
            return
        time.sleep(1)
    raise ValueError('waitForNumSwapping failed')


def updateThread(xmr_addr):
    while not stop_test:
        callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr, 'amount_of_blocks': 1})
        time.sleep(5)


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        for i in range(3):
            client_path = os.path.join(test_path, 'client{}'.format(i))
            config_path = os.path.join(client_path, cfg.CONFIG_FILENAME)
            try:
                shutil.rmtree(client_path)
            except Exception as ex:
                logger.warning('setUpClass %s', str(ex))
            testargs = [
                'basicswap-prepare',
                '-datadir="{}"'.format(client_path),
                '-bindir="{}"'.format(os.path.join(test_path, 'bin')),
                '-portoffset={}'.format(i),
                '-particl_mnemonic="{}"'.format(mnemonics[i]),
                '-regtest', '-withcoin=monero']
            with patch.object(sys, 'argv', testargs):
                prepareSystem.main()

            with open(os.path.join(client_path, 'particl', 'particl.conf'), 'r') as fp:
                lines = fp.readlines()
            with open(os.path.join(client_path, 'particl', 'particl.conf'), 'w') as fp:
                for line in lines:
                    if not line.startswith('staking'):
                        fp.write(line)
                fp.write('port={}\n'.format(PARTICL_PORT_BASE + i))
                fp.write('bind=127.0.0.1\n')
                fp.write('dnsseed=0\n')
                fp.write('minstakeinterval=5\n')
                for ip in range(3):
                    if ip != i:
                        fp.write('connect=localhost:{}\n'.format(PARTICL_PORT_BASE + ip))

            with open(os.path.join(client_path, 'monero', 'monerod.conf'), 'a') as fp:
                fp.write('p2p-bind-ip=127.0.0.1\n')
                fp.write('p2p-bind-port={}\n'.format(XMR_BASE_P2P_PORT + i))
                for ip in range(3):
                    if ip != i:
                        fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(XMR_BASE_P2P_PORT + ip))

            assert(os.path.exists(config_path))

    def run_thread(self, client_id):
        client_path = os.path.join(test_path, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def test_reload(self):
        global stop_test
        update_thread = None
        processes = []

        for i in range(3):
            processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            processes[-1].start()

        try:
            waitForServer(12701)

            wallets = json.loads(urlopen('http://localhost:12701/json/wallets').read())

            xmr_addr1 = wallets['6']['deposit_address']
            num_blocks = 500

            logging.info('Mining %d Monero blocks.', num_blocks)
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr1, 'amount_of_blocks': num_blocks})
            rv = callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')
            logging.info('XMR blocks: %d', rv['count'])

            data = parse.urlencode({
                'addr_from': '-1',
                'coin_from': '1',
                'coin_to': '6',
                'amt_from': '1',
                'amt_to': '1',
                'lockhrs': '24'}).encode()

            offer_id = json.loads(urlopen('http://localhost:12700/json/offers/new', data=data).read())
            summary = json.loads(urlopen('http://localhost:12700/json').read())
            assert(summary['num_sent_offers'] == 1)

            logger.info('Waiting for offer')
            waitForNumOffers(12701, 1)

            offers = json.loads(urlopen('http://localhost:12701/json/offers').read())
            offer = offers[0]

            data = parse.urlencode({
                'offer_id': offer['offer_id'],
                'amount_from': offer['amount_from']}).encode()

            bid_id = json.loads(urlopen('http://localhost:12701/json/bids/new', data=data).read())

            waitForNumBids(12700, 1)

            for i in range(10):
                bids = json.loads(urlopen('http://localhost:12700/json/bids').read())
                bid = bids[0]
                if bid['bid_state'] == 'Received':
                    break
                time.sleep(1)

            data = parse.urlencode({
                'accept': True
            }).encode()
            rv = json.loads(urlopen('http://localhost:12700/json/bids/{}'.format(bid['bid_id']), data=data).read())
            assert(rv['bid_state'] == 'Accepted')

            waitForNumSwapping(12701, 1)

            logger.info('Restarting client')
            c1 = processes[1]
            c1.terminate()
            c1.join()
            processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
            processes[1].start()

            waitForServer(12701)
            rv = json.loads(urlopen('http://localhost:12701/json').read())
            assert(rv['num_swapping'] == 1)

            update_thread = threading.Thread(target=updateThread, args=(xmr_addr1,))
            update_thread.start()

            logger.info('Completing swap')
            for i in range(240):
                time.sleep(5)

                rv = json.loads(urlopen('http://localhost:12700/json/bids/{}'.format(bid['bid_id'])).read())
                print(rv)
                if rv['bid_state'] == 'Completed':
                    break
            assert(rv['bid_state'] == 'Completed')
        except Exception:
            traceback.print_exc()

        logger.info('Stopping test')
        stop_test = True
        if update_thread:
            update_thread.join()
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()


if __name__ == '__main__':
    unittest.main()
