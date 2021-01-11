#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_RELOAD_PATH=/tmp/test_basicswap
mkdir -p ${TEST_RELOAD_PATH}/bin/{particl,monero}
cp ~/tmp/particl-0.19.1.2-x86_64-linux-gnu.tar.gz ${TEST_RELOAD_PATH}/bin/particl
cp ~/tmp/monero-linux-x64-v0.17.1.9.tar.bz2 ${TEST_RELOAD_PATH}/bin/monero/monero-0.17.1.9-x86_64-linux-gnu.tar.bz2
export PYTHONPATH=$(pwd)
python tests/basicswap/test_reload_xmr.py


"""

import os
import sys
import json
import shutil
import signal
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

delay_event = threading.Event()

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def waitForServer(port, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        try:
            delay_event.wait(1)
            summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
            return
        except Exception as e:
            print('waitForServer, error:', str(e))
    raise ValueError('waitForServer failed')


def waitForNumOffers(port, offers, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
        if summary['num_network_offers'] >= offers:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumOffers failed')


def waitForNumBids(port, bids, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
        if summary['num_recv_bids'] >= bids:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumBids failed')


def waitForNumSwapping(port, bids, wait_for=60):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
        if summary['num_swapping'] >= bids:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumSwapping failed')


def waitForBidState(port, bid_id, state_str, wait_for=60):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        bid = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid_id)).read())
        print('[rm] bid', bid)
        if bid['bid_state'] == state_str:
            return
        delay_event.wait(1)
    raise ValueError('waitForBidState failed')


def updateThread(xmr_addr):
    while not delay_event.is_set():
        try:
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr, 'amount_of_blocks': 1})
        except Exception as e:
            print('updateThread error', str(e))
        delay_event.wait(2)


def signal_handler(sig, frame):
    logging.info('signal {} detected.'.format(sig))
    delay_event.set()


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        cls.update_thread = None
        cls.processes = []

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
                '-regtest',
                '-withcoin=monero',
                '-noextractover',
                '-xmrrestoreheight=0']
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
                        fp.write('connect=127.0.0.1:{}\n'.format(PARTICL_PORT_BASE + ip))

            with open(os.path.join(client_path, 'monero', 'monerod.conf'), 'a') as fp:
                fp.write('p2p-bind-ip=127.0.0.1\n')
                fp.write('p2p-bind-port={}\n'.format(XMR_BASE_P2P_PORT + i))
                for ip in range(3):
                    if ip != i:
                        fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(XMR_BASE_P2P_PORT + ip))

            with open(config_path) as fs:
                settings = json.load(fs)

            settings['min_delay_event'] = 1
            settings['max_delay_event'] = 4

            settings['check_progress_seconds'] = 5
            settings['check_watched_seconds'] = 5
            settings['check_expired_seconds'] = 60
            settings['check_events_seconds'] = 5
            settings['check_xmr_swaps_seconds'] = 5

            with open(config_path, 'w') as fp:
                json.dump(settings, fp, indent=4)

        signal.signal(signal.SIGINT, signal_handler)

    def run_thread(self, client_id):
        client_path = os.path.join(test_path, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def start_processes(self):
        delay_event.clear()

        for i in range(3):
            self.processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            self.processes[-1].start()

        try:
            waitForServer(12701)

            wallets = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())

            xmr_addr1 = wallets['6']['deposit_address']
            num_blocks = 100

            if callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
                logging.info('Mining {} Monero blocks to {}.'.format(num_blocks, xmr_addr1))
                callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr1, 'amount_of_blocks': num_blocks})
            logging.info('XMR blocks: %d', callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'])

            self.update_thread = threading.Thread(target=updateThread, args=(xmr_addr1,))
            self.update_thread.start()
        except Exception:
            traceback.print_exc()

    def stop_processes(self):
        logger.info('Stopping test')
        delay_event.set()
        if self.update_thread:
            self.update_thread.join()
        for p in self.processes:
            p.terminate()
        for p in self.processes:
            p.join()
        self.update_thread = None
        self.processes = []

    def test_01_reload(self):
        self.start_processes()

        try:
            waitForServer(12700)
            waitForServer(12701)
            wallets1 = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())
            assert(float(wallets1['6']['balance']) > 0.0)

            data = parse.urlencode({
                'addr_from': '-1',
                'coin_from': '1',
                'coin_to': '6',
                'amt_from': '1',
                'amt_to': '1',
                'lockhrs': '24'}).encode()

            offer_id = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=data).read())['offer_id']
            summary = json.loads(urlopen('http://127.0.0.1:12700/json').read())
            assert(summary['num_sent_offers'] == 1)

            logger.info('Waiting for offer')
            waitForNumOffers(12701, 1)

            offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers').read())
            offer = offers[0]

            data = parse.urlencode({
                'offer_id': offer['offer_id'],
                'amount_from': offer['amount_from']}).encode()

            bid_id = json.loads(urlopen('http://127.0.0.1:12701/json/bids/new', data=data).read())

            waitForNumBids(12700, 1)

            for i in range(10):
                bids = json.loads(urlopen('http://127.0.0.1:12700/json/bids').read())
                bid = bids[0]
                if bid['bid_state'] == 'Received':
                    break
                delay_event.wait(1)

            data = parse.urlencode({
                'accept': True
            }).encode()
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid['bid_id']), data=data).read())
            assert(rv['bid_state'] == 'Accepted')

            waitForNumSwapping(12701, 1)

            logger.info('Restarting client')
            c1 = self.processes[1]
            c1.terminate()
            c1.join()
            self.processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
            self.processes[1].start()

            waitForServer(12701)
            rv = json.loads(urlopen('http://127.0.0.1:12701/json').read())
            assert(rv['num_swapping'] == 1)

            rv = json.loads(urlopen('http://127.0.0.1:12700/json/revokeoffer/{}'.format(offer_id)).read())
            assert(rv['revoked_offer'] == offer_id)

            logger.info('Completing swap')
            for i in range(240):
                if delay_event.is_set():
                    raise ValueError('Test stopped.')
                delay_event.wait(4)

                rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid['bid_id'])).read())
                if rv['bid_state'] == 'Completed':
                    break
            assert(rv['bid_state'] == 'Completed')

            # Ensure offer was revoked
            summary = json.loads(urlopen('http://127.0.0.1:12700/json').read())
            assert(summary['num_network_offers'] == 0)

        except Exception as e:
            traceback.print_exc()
            raise(e)
        finally:
            self.stop_processes()

    def test_02_bids_offline(self):
        # Start multiple bids while offering node is offline
        self.start_processes()

        try:
            waitForServer(12700)
            waitForServer(12701)
            wallets1 = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())
            assert(float(wallets1['6']['balance']) > 0.0)

            offer_data = {
                'addr_from': '-1',
                'coin_from': '1',
                'coin_to': '6',
                'amt_from': '1',
                'amt_to': '1',
                'lockhrs': '24',
                'autoaccept': True}
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=parse.urlencode(offer_data).encode()).read())
            offer0_id = rv['offer_id']

            offer_data['amt_from'] = '2'
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/offers/new', data=parse.urlencode(offer_data).encode()).read())
            offer1_id = rv['offer_id']

            summary = json.loads(urlopen('http://127.0.0.1:12700/json').read())
            assert(summary['num_sent_offers'] > 1)

            logger.info('Waiting for offer')
            waitForNumOffers(12701, 2)

            logger.info('Stopping node 0')
            c0 = self.processes[0]
            c0.terminate()
            c0.join()

            offers = json.loads(urlopen('http://127.0.0.1:12701/json/offers/{}'.format(offer0_id)).read())
            assert(len(offers) == 1)
            offer0 = offers[0]

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

            delay_event.wait(5)

            logger.info('Starting node 0')
            self.processes[0] = multiprocessing.Process(target=self.run_thread, args=(0,))
            self.processes[0].start()

            waitForServer(12700)
            waitForNumBids(12700, 2)

            waitForBidState(12700, bid0_id, 'Received')
            waitForBidState(12700, bid1_id, 'Received')

            # Manually accept on top of auto-accept for extra chaos
            data = parse.urlencode({
                'accept': True
            }).encode()
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid0_id), data=data).read())
            assert(rv['bid_state'] == 'Accepted')
            rv = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid1_id), data=data).read())
            assert(rv['bid_state'] == 'Accepted')

            logger.info('Completing swap')
            for i in range(240):
                if delay_event.is_set():
                    raise ValueError('Test stopped.')
                delay_event.wait(4)

                rv0 = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid0_id)).read())
                rv1 = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid1_id)).read())
                if rv0['bid_state'] == 'Completed' and rv1['bid_state'] == 'Completed':
                    break
            assert(rv0['bid_state'] == 'Completed')
            assert(rv1['bid_state'] == 'Completed')

        except Exception as e:
            traceback.print_exc()
            raise(e)
        finally:
            self.stop_processes()


if __name__ == '__main__':
    unittest.main()
