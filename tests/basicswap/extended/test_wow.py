#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time
import logging
import os

from basicswap.basicswap import (
    Coins,
)
import basicswap.config as cfg
from basicswap.rpc_xmr import (
    callrpc_xmr,
)
from tests.basicswap.common import (
    stopDaemons,
)
from tests.basicswap.test_xmr import BaseTest
from basicswap.bin.run import startXmrDaemon, startXmrWalletDaemon

from tests.basicswap.extended.test_dcr import (
    run_test_ads_success_path,
    run_test_ads_both_refund,
    run_test_ads_swipe_refund,
)

NUM_NODES = 3

WOW_BINDIR = os.path.expanduser(os.getenv('WOW_BINDIR', os.path.join(cfg.DEFAULT_TEST_BINDIR, 'wownero')))
WOWD = os.getenv('WOWD', 'wownerod' + cfg.bin_suffix)
WOW_WALLET_RPC = os.getenv('WOW_WALLET', 'wownero-wallet-rpc' + cfg.bin_suffix)

WOW_BASE_PORT = 54932
WOW_BASE_RPC_PORT = 55932
WOW_BASE_WALLET_RPC_PORT = 55952
WOW_BASE_ZMQ_PORT = 55972


def prepareWOWDataDir(datadir, node_id, conf_file):
    node_dir = os.path.join(datadir, 'wow_' + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('log-level=4\n')
        fp.write('keep-fakechain=1\n')
        fp.write('data-dir={}\n'.format(node_dir))
        fp.write('fixed-difficulty=1\n')
        fp.write('p2p-bind-port={}\n'.format(WOW_BASE_PORT + node_id))
        fp.write('rpc-bind-port={}\n'.format(WOW_BASE_RPC_PORT + node_id))
        fp.write('p2p-bind-ip=127.0.0.1\n')
        fp.write('rpc-bind-ip=127.0.0.1\n')
        fp.write('prune-blockchain=1\n')
        fp.write('zmq-rpc-bind-port={}\n'.format(WOW_BASE_ZMQ_PORT + node_id))
        fp.write('zmq-rpc-bind-ip=127.0.0.1\n')

        for i in range(0, NUM_NODES):
            if node_id == i:
                continue
            fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(WOW_BASE_PORT + i))


def waitForWOWNode(rpc_offset, max_tries=7, auth=None):
    for i in range(max_tries + 1):
        try:
            if auth is None:
                callrpc_xmr(WOW_BASE_RPC_PORT + rpc_offset, 'get_block_count')
            else:
                callrpc_xmr(WOW_BASE_WALLET_RPC_PORT + rpc_offset, 'get_languages', auth=auth)
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning('Can\'t connect to WOW%s RPC: %s. Retrying in %d second/s.', '' if auth is None else ' wallet', str(ex), (i + 1))
                time.sleep(i + 1)
    raise ValueError('waitForWOWNode failed')


class Test(BaseTest):
    __test__ = True
    test_coin = Coins.WOW
    wow_daemons = []
    wow_wallet_auth = []
    start_ltc_nodes = False
    start_xmr_nodes = False
    wow_addr = None
    extra_wait_time = 0

    @classmethod
    def prepareExtraCoins(cls):
        pass
        num_blocks = 300
        cls.wow_addr = cls.callwownodewallet(cls, 1, 'get_address')['address']
        if callrpc_xmr(WOW_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
            logging.info('Mining %d Wownero blocks to %s.', num_blocks, cls.wow_addr)
            callrpc_xmr(WOW_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.wow_addr, 'amount_of_blocks': num_blocks})
        logging.info('WOW blocks: %d', callrpc_xmr(WOW_BASE_RPC_PORT + 1, 'get_block_count')['count'])

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising Wownero Test')
        super(Test, cls).tearDownClass()

        stopDaemons(cls.wow_daemons)
        cls.wow_daemons.clear()

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()

        if cls.wow_addr is not None:
            callrpc_xmr(WOW_BASE_RPC_PORT + 0, 'generateblocks', {'wallet_address': cls.wow_addr, 'amount_of_blocks': 1})

    @classmethod
    def prepareExtraDataDir(cls, i):
        if not cls.restore_instance:
            prepareWOWDataDir(cfg.TEST_DATADIRS, i, 'wownerod.conf')

        node_dir = os.path.join(cfg.TEST_DATADIRS, 'wow_' + str(i))
        cls.wow_daemons.append(startXmrDaemon(node_dir, WOW_BINDIR, WOWD))
        logging.info('Started %s %d', WOWD, cls.wow_daemons[-1].handle.pid)
        waitForWOWNode(i)

        opts = [
            '--daemon-address=127.0.0.1:{}'.format(WOW_BASE_RPC_PORT + i),
            '--no-dns',
            '--rpc-bind-port={}'.format(WOW_BASE_WALLET_RPC_PORT + i),
            '--wallet-dir={}'.format(os.path.join(node_dir, 'wallets')),
            '--log-file={}'.format(os.path.join(node_dir, 'wallet.log')),
            '--rpc-login=test{0}:test_pass{0}'.format(i),
            '--wow-shared-ringdb-dir={}'.format(os.path.join(node_dir, 'shared-ringdb')),
            '--allow-mismatched-daemon-version',
        ]
        cls.wow_daemons.append(startXmrWalletDaemon(node_dir, WOW_BINDIR, WOW_WALLET_RPC, opts=opts))

        cls.wow_wallet_auth.append(('test{0}'.format(i), 'test_pass{0}'.format(i)))

        waitForWOWNode(i, auth=cls.wow_wallet_auth[i])

        if not cls.restore_instance:
            logging.info('Creating WOW wallet %i', i)
            cls.callwownodewallet(cls, i, 'create_wallet', {'filename': 'testwallet', 'language': 'English'})
        cls.callwownodewallet(cls, i, 'open_wallet', {'filename': 'testwallet'})

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.WOW, cls.wow_daemons[i].handle.pid)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings['chainclients']['wownero'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': WOW_BASE_RPC_PORT + node_id,
            'walletrpcport': WOW_BASE_WALLET_RPC_PORT + node_id,
            'walletrpcuser': 'test' + str(node_id),
            'walletrpcpassword': 'test_pass' + str(node_id),
            'walletfile': 'testwallet',
            'datadir': os.path.join(datadir, 'xmr_' + str(node_id)),
            'bindir': WOW_BINDIR,
        }

    def callwownodewallet(self, node_id, method, params=None):
        return callrpc_xmr(WOW_BASE_WALLET_RPC_PORT + node_id, method, params, auth=self.wow_wallet_auth[node_id])

    def test_01_ads_part_coin(self):
        run_test_ads_success_path(self, Coins.PART, self.test_coin)

    def test_02_ads_coin_part(self):
        # Reverse bid
        run_test_ads_success_path(self, self.test_coin, Coins.PART)

    def test_03_ads_part_coin_both_refund(self):
        run_test_ads_both_refund(self, Coins.PART, self.test_coin, lock_value=20)

    def test_04_ads_coin_part_both_refund(self):
        # Reverse bid
        run_test_ads_both_refund(self, self.test_coin, Coins.PART, lock_value=20)

    def test_05_ads_part_coin_swipe_refund(self):
        run_test_ads_swipe_refund(self, Coins.PART, self.test_coin, lock_value=20)

    def test_06_ads_coin_part_swipe_refund(self):
        # Reverse bid
        run_test_ads_swipe_refund(self, self.test_coin, Coins.PART, lock_value=20)
