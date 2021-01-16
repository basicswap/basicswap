#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap_wallet_init
mkdir -p ${TEST_PATH}/bin/{particl,monero,bitcoin}
cp ~/tmp/particl-0.19.1.2-x86_64-linux-gnu.tar.gz ${TEST_PATH}/bin/particl
cp ~/tmp/monero-linux-x64-v0.17.1.9.tar.bz2 ${TEST_PATH}/bin/monero/monero-0.17.1.9-x86_64-linux-gnu.tar.bz2
cp ~/tmp/bitcoin-0.20.1-x86_64-linux-gnu.tar.gz ${TEST_PATH}/bin/bitcoin
export PYTHONPATH=$(pwd)
python tests/basicswap/extended/test_wallet_init.py


"""

import os
import sys
import json
import time
import shutil
import logging
import unittest
import traceback
import multiprocessing
from urllib.request import urlopen
from unittest.mock import patch

from tests.basicswap.mnemonics import mnemonics

import basicswap.config as cfg
import bin.basicswap_prepare as prepareSystem
import bin.basicswap_run as runSystem

test_path = os.path.expanduser(os.getenv('TEST_PATH', '~/test_basicswap1'))
PARTICL_PORT_BASE = int(os.getenv('PARTICL_PORT_BASE', '11938'))
BITCOIN_PORT_BASE = int(os.getenv('BITCOIN_PORT_BASE', '10938'))
XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 21792
XMR_BASE_ZMQ_PORT = 22792
XMR_BASE_WALLET_RPC_PORT = 23792

stop_test = False

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def waitForServer(port):
    for i in range(20):
        try:
            time.sleep(1)
            summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
            break
        except Exception as e:
            print('waitForServer, error:', str(e))


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        for i in range(2):
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
                '-particl_mnemonic="{}"'.format(mnemonics[0]),
                '-regtest',
                '-withcoin=monero,bitcoin',
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
                for ip in range(3):
                    if ip != i:
                        fp.write('connect=127.0.0.1:{}\n'.format(PARTICL_PORT_BASE + ip))

            # Pruned nodes don't provide blocks
            with open(os.path.join(client_path, 'bitcoin', 'bitcoin.conf'), 'r') as fp:
                lines = fp.readlines()
            with open(os.path.join(client_path, 'bitcoin', 'bitcoin.conf'), 'w') as fp:
                for line in lines:
                    if not line.startswith('prune'):
                        fp.write(line)
                fp.write('port={}\n'.format(BITCOIN_PORT_BASE + i))
                fp.write('bind=127.0.0.1\n')
                fp.write('dnsseed=0\n')
                fp.write('discover=0\n')
                fp.write('listenonion=0\n')
                fp.write('upnp=0\n')
                for ip in range(3):
                    if ip != i:
                        fp.write('connect=127.0.0.1:{}\n'.format(BITCOIN_PORT_BASE + ip))

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

    def test_wallet(self):
        global stop_test
        update_thread = None
        processes = []

        time.sleep(5)
        for i in range(2):
            processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            processes[-1].start()

        try:
            waitForServer(12700)

            wallets_0 = json.loads(urlopen('http://127.0.0.1:12700/json/wallets').read())
            assert(wallets_0['1']['expected_seed'] is True)
            assert(wallets_0['6']['expected_seed'] is True)

            waitForServer(12701)
            wallets_1 = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())

            assert(wallets_0['1']['expected_seed'] is True)
            assert(wallets_1['6']['expected_seed'] is True)

            # TODO: Check other coins

            assert(wallets_0['1']['deposit_address'] == wallets_1['1']['deposit_address'])
            assert(wallets_0['6']['deposit_address'] == wallets_1['6']['deposit_address'])
        except Exception:
            traceback.print_exc()

        stop_test = True
        if update_thread:
            update_thread.join()
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()


if __name__ == '__main__':
    unittest.main()
