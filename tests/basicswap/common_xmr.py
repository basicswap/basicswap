#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import json
import shutil
import signal
import logging
import unittest
import threading
import multiprocessing
from urllib.request import urlopen
from unittest.mock import patch

from basicswap.rpc_xmr import (
    callrpc_xmr_na,
)
from tests.basicswap.mnemonics import mnemonics
from tests.basicswap.common import (
    waitForServer,
)

import basicswap.config as cfg
import bin.basicswap_prepare as prepareSystem
import bin.basicswap_run as runSystem

test_path = os.path.expanduser(os.getenv('TEST_RELOAD_PATH', '~/test_basicswap1'))
PARTICL_PORT_BASE = int(os.getenv('PARTICL_PORT_BASE', '11938'))

XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 29798
XMR_BASE_WALLET_RPC_PORT = 29998


def waitForBidState(delay_event, port, bid_id, state_str, wait_for=60):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        bid = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid_id)).read())
        if bid['bid_state'] == state_str:
            return
        delay_event.wait(1)
    raise ValueError('waitForBidState failed')


def updateThread(xmr_addr, delay_event):
    while not delay_event.is_set():
        try:
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr, 'amount_of_blocks': 1})
        except Exception as e:
            print('updateThread error', str(e))
        delay_event.wait(2)


class XmrTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(XmrTestBase, cls).setUpClass()

        cls.delay_event = threading.Event()
        cls.update_thread = None
        cls.processes = []

        for i in range(3):
            client_path = os.path.join(test_path, 'client{}'.format(i))
            config_path = os.path.join(client_path, cfg.CONFIG_FILENAME)
            try:
                shutil.rmtree(client_path)
            except Exception as ex:
                logging.warning('setUpClass %s', str(ex))
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
                fp.write('discover=0\n')
                fp.write('listenonion=0\n')
                fp.write('upnp=0\n')
                fp.write('minstakeinterval=5\n')
                fp.write('smsgsregtestadjust=0\n')
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
            settings['min_delay_event_short'] = 1
            settings['max_delay_event_short'] = 4
            settings['min_delay_retry'] = 10
            settings['max_delay_retry'] = 20

            settings['check_progress_seconds'] = 5
            settings['check_watched_seconds'] = 5
            settings['check_expired_seconds'] = 60
            settings['check_events_seconds'] = 5
            settings['check_xmr_swaps_seconds'] = 5

            with open(config_path, 'w') as fp:
                json.dump(settings, fp, indent=4)

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

        for i in range(3):
            self.processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            self.processes[-1].start()

        waitForServer(self.delay_event, 12701)

        def waitForMainAddress():
            for i in range(20):
                if self.delay_event.is_set():
                    raise ValueError('Test stopped.')
                try:
                    wallets = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())
                    return wallets['6']['main_address']
                except Exception as e:
                    print('Waiting for main address {}'.format(str(e)))
                self.delay_event.wait(1)
            raise ValueError('waitForMainAddress timedout')
        xmr_addr1 = waitForMainAddress()

        num_blocks = 100

        if callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
            logging.info('Mining {} Monero blocks to {}.'.format(num_blocks, xmr_addr1))
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr1, 'amount_of_blocks': num_blocks})
        logging.info('XMR blocks: %d', callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'])

        self.update_thread = threading.Thread(target=updateThread, args=(xmr_addr1, self.delay_event))
        self.update_thread.start()

        # Wait for height, or sequencelock is thrown off by genesis blocktime
        num_blocks = 3
        logging.info('Waiting for Particl chain height %d', num_blocks)
        for i in range(60):
            if self.delay_event.is_set():
                raise ValueError('Test stopped.')
            try:
                wallets = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())
                particl_blocks = wallets['1']['blocks']
                print('particl_blocks', particl_blocks)
                if particl_blocks >= num_blocks:
                    break
            except Exception as e:
                print('Error reading wallets', str(e))

            self.delay_event.wait(1)
        assert(particl_blocks >= num_blocks)

    @classmethod
    def tearDownClass(cls):
        logging.info('Stopping test')
        cls.delay_event.set()
        if cls.update_thread:
            cls.update_thread.join()
        for p in cls.processes:
            p.terminate()
        for p in cls.processes:
            p.join()
        cls.update_thread = None
        cls.processes = []
