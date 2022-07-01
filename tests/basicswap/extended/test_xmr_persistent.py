#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export RESET_TEST=true
export TEST_PATH=/tmp/test_persistent
mkdir -p ${TEST_PATH}/bin/{particl,monero,bitcoin}
cp ~/tmp/particl-0.21.2.9-x86_64-linux-gnu_nousb.tar.gz ${TEST_PATH}/bin/particl
cp ~/tmp/bitcoin-22.0-x86_64-linux-gnu.tar.gz ${TEST_PATH}/bin/bitcoin
XMR_VERSION=0.17.3.2 cp ~/tmp/monero-linux-x64-v${XMR_VERSION}.tar.bz2 ${TEST_RELOAD_PATH}/bin/monero/monero-${XMR_VERSION}-x86_64-linux-gnu.tar.bz2
export PYTHONPATH=$(pwd)
python tests/basicswap/extended/test_xmr_persistent.py


"""

import os
import sys
import json
import time
import random
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
from basicswap.rpc import (
    callrpc,
)
from tests.basicswap.mnemonics import mnemonics as test_mnemonics
from tests.basicswap.common import (
    waitForServer,
)
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac

import basicswap.config as cfg
import bin.basicswap_prepare as prepareSystem
import bin.basicswap_run as runSystem


def make_boolean(s):
    return s.lower() in ['1', 'true']


test_path = os.path.expanduser(os.getenv('TEST_PATH', '/tmp/test_persistent'))
PARTICL_PORT_BASE = int(os.getenv('PARTICL_PORT_BASE', '11938'))
BITCOIN_PORT_BASE = int(os.getenv('BITCOIN_PORT_BASE', '10938'))
RESET_TEST = make_boolean(os.getenv('RESET_TEST', 'false'))

XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 29798
XMR_BASE_WALLET_RPC_PORT = 29998

PORT_OFS = 1
UI_PORT = 12700 + PORT_OFS

BASE_PART_RPC_PORT = 19792
BASE_BTC_RPC_PORT = 19796

NUM_NODES = int(os.getenv('NUM_NODES', 3))
EXTRA_CONFIG_JSON = json.loads(os.getenv('EXTRA_CONFIG_JSON', '{}'))


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def recursive_update_dict(base, new_vals):
    for key, value in new_vals.items():
        if key in base and isinstance(value, dict):
            recursive_update_dict(base[key], value)
        else:
            base[key] = value


def callpartrpc(node_id, method, params=[], wallet=None, base_rpc_port=BASE_PART_RPC_PORT + PORT_OFS):
    auth = 'test_part_{0}:test_part_pwd_{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def callbtcrpc(node_id, method, params=[], wallet=None, base_rpc_port=BASE_BTC_RPC_PORT + PORT_OFS):
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
                callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': 1})
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

        logging.info('Preparing %d nodes.', NUM_NODES)
        for i in range(NUM_NODES):
            logging.info('Preparing node: %d.', i)
            client_path = os.path.join(test_path, 'client{}'.format(i))
            config_path = os.path.join(client_path, cfg.CONFIG_FILENAME)
            if RESET_TEST:
                try:
                    logging.info('Removing dir %s', client_path)
                    shutil.rmtree(client_path)
                except Exception as ex:
                    logging.warning('setUpClass %s', str(ex))

            if not os.path.exists(config_path):

                os.environ['PART_RPC_PORT'] = str(BASE_PART_RPC_PORT)
                os.environ['BTC_RPC_PORT'] = str(BASE_BTC_RPC_PORT)

                testargs = [
                    'basicswap-prepare',
                    '-datadir="{}"'.format(client_path),
                    '-bindir="{}"'.format(os.path.join(test_path, 'bin')),
                    '-portoffset={}'.format(i + PORT_OFS),
                    '-regtest',
                    '-withcoins=monero,bitcoin',
                    '-noextractover',
                    '-xmrrestoreheight=0']
                if i < len(test_mnemonics):
                    testargs.append('-particl_mnemonic="{}"'.format(test_mnemonics[i]))
                with patch.object(sys, 'argv', testargs):
                    prepareSystem.main()

                with open(os.path.join(client_path, 'particl', 'particl.conf'), 'r') as fp:
                    lines = fp.readlines()
                with open(os.path.join(client_path, 'particl', 'particl.conf'), 'w') as fp:
                    for line in lines:
                        if not line.startswith('staking'):
                            fp.write(line)
                    fp.write('port={}\n'.format(PARTICL_PORT_BASE + i + PORT_OFS))
                    fp.write('bind=127.0.0.1\n')
                    fp.write('dnsseed=0\n')
                    fp.write('discover=0\n')
                    fp.write('listenonion=0\n')
                    fp.write('upnp=0\n')
                    fp.write('minstakeinterval=5\n')
                    fp.write('smsgsregtestadjust=0\n')
                    salt = generate_salt(16)
                    fp.write('rpcauth={}:{}${}\n'.format('test_part_' + str(i), salt, password_to_hmac(salt, 'test_part_pwd_' + str(i))))
                    for ip in range(NUM_NODES):
                        if ip != i:
                            fp.write('connect=127.0.0.1:{}\n'.format(PARTICL_PORT_BASE + ip + PORT_OFS))
                    for opt in EXTRA_CONFIG_JSON.get('part{}'.format(i), []):
                        fp.write(opt + '\n')

                # Pruned nodes don't provide blocks
                with open(os.path.join(client_path, 'bitcoin', 'bitcoin.conf'), 'r') as fp:
                    lines = fp.readlines()
                with open(os.path.join(client_path, 'bitcoin', 'bitcoin.conf'), 'w') as fp:
                    for line in lines:
                        if not line.startswith('prune'):
                            fp.write(line)
                    fp.write('port={}\n'.format(BITCOIN_PORT_BASE + i + PORT_OFS))
                    fp.write('bind=127.0.0.1\n')
                    fp.write('dnsseed=0\n')
                    fp.write('discover=0\n')
                    fp.write('listenonion=0\n')
                    fp.write('upnp=0\n')
                    salt = generate_salt(16)
                    fp.write('rpcauth={}:{}${}\n'.format('test_btc_' + str(i), salt, password_to_hmac(salt, 'test_btc_pwd_' + str(i))))
                    for ip in range(NUM_NODES):
                        if ip != i:
                            fp.write('connect=127.0.0.1:{}\n'.format(BITCOIN_PORT_BASE + ip + PORT_OFS))
                    for opt in EXTRA_CONFIG_JSON.get('btc{}'.format(i), []):
                        fp.write(opt + '\n')

                with open(os.path.join(client_path, 'monero', 'monerod.conf'), 'a') as fp:
                    fp.write('p2p-bind-ip=127.0.0.1\n')
                    fp.write('p2p-bind-port={}\n'.format(XMR_BASE_P2P_PORT + i + PORT_OFS))
                    for ip in range(NUM_NODES):
                        if ip != i:
                            fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(XMR_BASE_P2P_PORT + ip + PORT_OFS))

                with open(config_path) as fs:
                    settings = json.load(fs)

                settings['min_delay_event'] = 1
                settings['max_delay_event'] = 4
                settings['min_delay_event_short'] = 1
                settings['max_delay_event_short'] = 4
                settings['min_delay_retry'] = 15
                settings['max_delay_retry'] = 30
                settings['min_sequence_lock_seconds'] = 60

                settings['check_progress_seconds'] = 5
                settings['check_watched_seconds'] = 5
                settings['check_expired_seconds'] = 60
                settings['check_events_seconds'] = 5
                settings['check_xmr_swaps_seconds'] = 5

                settings['chainclients']['particl']['rpcuser'] = 'test_part_' + str(i)
                settings['chainclients']['particl']['rpcpassword'] = 'test_part_pwd_' + str(i)

                settings['chainclients']['bitcoin']['rpcuser'] = 'test_btc_' + str(i)
                settings['chainclients']['bitcoin']['rpcpassword'] = 'test_btc_pwd_' + str(i)

                extra_config = EXTRA_CONFIG_JSON.get('sc{}'.format(i), {})
                recursive_update_dict(settings, extra_config)

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

        for i in range(NUM_NODES):
            self.processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            self.processes[-1].start()

        for i in range(NUM_NODES):
            waitForServer(self.delay_event, UI_PORT + i)

        wallets = json.loads(urlopen('http://127.0.0.1:{}/json/wallets'.format(UI_PORT + 1)).read())

        self.xmr_addr = wallets['6']['main_address']
        num_blocks = 100
        if callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
            logging.info('Mining {} Monero blocks to {}.'.format(num_blocks, self.xmr_addr))
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': self.xmr_addr, 'amount_of_blocks': num_blocks})
        logging.info('XMR blocks: %d', callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'])

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
            particl_blocks = callpartrpc(0, 'getblockchaininfo')['blocks']
            print('particl_blocks', particl_blocks)
            if particl_blocks >= num_blocks:
                break
            self.delay_event.wait(1)

        logging.info('PART blocks: %d', callpartrpc(0, 'getblockchaininfo')['blocks'])
        assert(particl_blocks >= num_blocks)

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
