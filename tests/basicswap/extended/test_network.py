#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import time
import shutil
import signal
import logging
import unittest
import threading
import traceback

import basicswap.config as cfg
from basicswap.basicswap import (
    BasicSwap,
    Coins,
    SwapTypes,
)
from basicswap.util import (
    COIN,
    dumpj,
)
from basicswap.util.address import (
    toWIF,
)
from basicswap.rpc import (
    callrpc,
    callrpc_cli,
)
from basicswap.contrib.key import (
    ECKey,
)
from basicswap.http_server import (
    HttpThread,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    prepareDataDir,
    make_rpc_func,
    checkForks,
    stopDaemons,
    delay_for,
    TEST_HTTP_HOST,
    TEST_HTTP_PORT,
    BASE_P2P_PORT,
    BASE_RPC_PORT,
    BASE_ZMQ_PORT,
    BTC_BASE_PORT,
    BTC_BASE_RPC_PORT,
    PREFIX_SECRET_KEY_REGTEST,
    waitForRPC,
)

from basicswap.bin.run import startDaemon


logger = logging.getLogger()

NUM_NODES = 3
NUM_BTC_NODES = 3
TEST_DIR = cfg.TEST_DATADIRS

delay_event = threading.Event()
stop_test = False


def prepare_swapclient_dir(datadir, node_id, network_key, network_pubkey):
    basicswap_dir = os.path.join(datadir, 'basicswap_' + str(node_id))
    if not os.path.exists(basicswap_dir):
        os.makedirs(basicswap_dir)

    settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
    settings = {
        'debug': True,
        'p2p_host': '127.0.0.1',
        'p2p_port': BASE_P2P_PORT + node_id,
        'zmqhost': 'tcp://127.0.0.1',
        'zmqport': BASE_ZMQ_PORT + node_id,
        'htmlhost': '127.0.0.1',
        'htmlport': TEST_HTTP_PORT + node_id,
        'network_key': network_key,
        'network_pubkey': network_pubkey,
        'chainclients': {
            'particl': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': BASE_RPC_PORT + node_id,
                'rpcuser': 'test' + str(node_id),
                'rpcpassword': 'test_pass' + str(node_id),
                'datadir': os.path.join(datadir, 'part_' + str(node_id)),
                'bindir': cfg.PARTICL_BINDIR,
                'blocks_confirmed': 2,  # Faster testing
            },
            'bitcoin': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': BTC_BASE_RPC_PORT + node_id,
                'rpcuser': 'test' + str(node_id),
                'rpcpassword': 'test_pass' + str(node_id),
                'datadir': os.path.join(datadir, 'btc_' + str(node_id)),
                'bindir': cfg.BITCOIN_BINDIR,
                'use_segwit': True,
            }

        },
        'check_progress_seconds': 2,
        'check_watched_seconds': 4,
        'check_expired_seconds': 60,
        'check_events_seconds': 1,
        'check_xmr_swaps_seconds': 1,
        'min_delay_event': 1,
        'max_delay_event': 5,
        'min_delay_event_short': 1,
        'max_delay_event_short': 5,
        'min_delay_retry': 2,
        'max_delay_retry': 10,
        'restrict_unknown_seed_wallets': False
    }

    with open(settings_path, 'w') as fp:
        json.dump(settings, fp, indent=4)


def partRpc(cmd, node_id=0):
    return callrpc_cli(cfg.PARTICL_BINDIR, os.path.join(TEST_DIR, 'part_' + str(node_id)), 'regtest', cmd, cfg.PARTICL_CLI)


def btcRpc(cmd, node_id=0):
    return callrpc_cli(cfg.BITCOIN_BINDIR, os.path.join(TEST_DIR, 'btc_' + str(node_id)), 'regtest', cmd, cfg.BITCOIN_CLI)


def signal_handler(sig, frame):
    global stop_test
    logging.info('signal {} detected.'.format(sig))
    stop_test = True
    delay_event.set()


def callnoderpc(node_id, method, params=[], wallet=None, base_rpc_port=BASE_RPC_PORT):
    auth = 'test{0}:test_pass{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def run_coins_loop(cls):
    while not stop_test:
        try:
            if cls.btc_addr is not None:
                btcRpc('generatetoaddress 1 {}'.format(cls.btc_addr))
        except Exception as e:
            logging.warning('run_coins_loop ' + str(e))
        time.sleep(1.0)


def run_loop(cls):
    while not stop_test:
        for c in cls.swap_clients:
            c.update()
        time.sleep(1.0)


class Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        cls.update_thread = None
        cls.coins_update_thread = None
        cls.http_threads = []
        cls.swap_clients = []
        cls.part_daemons = []
        cls.btc_daemons = []

        cls.btc_addr = None

        logger.propagate = False
        logger.handlers = []
        logger.setLevel(logging.INFO)  # DEBUG shows many messages from requests.post
        formatter = logging.Formatter('%(asctime)s %(levelname)s : %(message)s')
        stream_stdout = logging.StreamHandler()
        stream_stdout.setFormatter(formatter)
        logger.addHandler(stream_stdout)

        if os.path.isdir(TEST_DIR):
            logging.info('Removing ' + TEST_DIR)
            shutil.rmtree(TEST_DIR)
        if not os.path.exists(TEST_DIR):
            os.makedirs(TEST_DIR)

        cls.stream_fp = logging.FileHandler(os.path.join(TEST_DIR, 'test.log'))
        cls.stream_fp.setFormatter(formatter)
        logger.addHandler(cls.stream_fp)

        try:
            logging.info('Preparing coin nodes.')
            for i in range(NUM_NODES):
                data_dir = prepareDataDir(TEST_DIR, i, 'particl.conf', 'part_')
                if os.path.exists(os.path.join(cfg.PARTICL_BINDIR, 'particl-wallet')):
                    callrpc_cli(cfg.PARTICL_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat -legacy create', 'particl-wallet')

                cls.part_daemons.append(startDaemon(os.path.join(TEST_DIR, 'part_' + str(i)), cfg.PARTICL_BINDIR, cfg.PARTICLD))
                logging.info('Started %s %d', cfg.PARTICLD, cls.handle.part_daemons[-1].handle.pid)

            for i in range(NUM_NODES):
                # Load mnemonics after all nodes have started to avoid staking getting stuck in TryToSync
                rpc = make_rpc_func(i)
                waitForRPC(rpc, delay_event)
                if i == 0:
                    rpc('extkeyimportmaster', ['abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb'])
                elif i == 1:
                    rpc('extkeyimportmaster', ['pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true'])
                    rpc('getnewextaddress', ['lblExtTest'])
                    rpc('rescanblockchain')
                else:
                    rpc('extkeyimportmaster', [rpc('mnemonic', ['new'])['master']])
                # Lower output split threshold for more stakeable outputs
                rpc('walletsettings', ['stakingoptions', {'stakecombinethreshold': 100, 'stakesplitthreshold': 200}])
                rpc('reservebalance', [False,])

            for i in range(NUM_BTC_NODES):
                data_dir = prepareDataDir(TEST_DIR, i, 'bitcoin.conf', 'btc_', base_p2p_port=BTC_BASE_PORT, base_rpc_port=BTC_BASE_RPC_PORT)
                if os.path.exists(os.path.join(cfg.BITCOIN_BINDIR, 'bitcoin-wallet')):
                    callrpc_cli(cfg.BITCOIN_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat -legacy create', 'bitcoin-wallet')

                cls.btc_daemons.append(startDaemon(os.path.join(TEST_DIR, 'btc_' + str(i)), cfg.BITCOIN_BINDIR, cfg.BITCOIND))
                logging.info('Started %s %d', cfg.BITCOIND, cls.handle.part_daemons[-1].handle.pid)

                waitForRPC(make_rpc_func(i, base_rpc_port=BTC_BASE_RPC_PORT), delay_event)

            logging.info('Preparing swap clients.')
            eckey = ECKey()
            eckey.generate()
            cls.network_key = toWIF(PREFIX_SECRET_KEY_REGTEST, eckey.get_bytes())
            cls.network_pubkey = eckey.get_pubkey().get_bytes().hex()

            for i in range(NUM_NODES):
                prepare_swapclient_dir(TEST_DIR, i, cls.network_key, cls.network_pubkey)
                basicswap_dir = os.path.join(os.path.join(TEST_DIR, 'basicswap_' + str(i)))
                settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
                with open(settings_path) as fs:
                    settings = json.load(fs)
                fp = open(os.path.join(basicswap_dir, 'basicswap.log'), 'w')
                sc = BasicSwap(fp, basicswap_dir, settings, 'regtest', log_name='BasicSwap{}'.format(i))
                cls.swap_clients.append(sc)
                sc.setDaemonPID(Coins.BTC, cls.btc_daemons[i].handle.pid)
                sc.setDaemonPID(Coins.PART, cls.part_daemons[i].handle.pid)
                sc.start()

                t = HttpThread(sc.fp, TEST_HTTP_HOST, TEST_HTTP_PORT + i, False, sc)
                cls.http_threads.append(t)
                t.start()

            cls.btc_addr = callnoderpc(0, 'getnewaddress', ['mining_addr', 'bech32'], base_rpc_port=BTC_BASE_RPC_PORT)

            num_blocks = 500
            logging.info('Mining %d Bitcoin blocks to %s', num_blocks, cls.btc_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.btc_addr], base_rpc_port=BTC_BASE_RPC_PORT)

            checkForks(callnoderpc(0, 'getblockchaininfo', base_rpc_port=BTC_BASE_RPC_PORT))

            logging.info('Starting update thread.')
            signal.signal(signal.SIGINT, signal_handler)
            cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
            cls.update_thread.start()

            cls.coins_update_thread = threading.Thread(target=run_coins_loop, args=(cls,))
            cls.coins_update_thread.start()
        except Exception:
            traceback.print_exc()
            cls.tearDownClass()
            raise ValueError('setUpClass() failed.')

    @classmethod
    def tearDownClass(cls):
        global stop_test
        logging.info('Finalising')
        stop_test = True
        if cls.update_thread is not None:
            try:
                cls.update_thread.join()
            except Exception:
                logging.info('Failed to join update_thread')
        if cls.coins_update_thread is not None:
            try:
                cls.coins_update_thread.join()
            except Exception:
                logging.info('Failed to join coins_update_thread')

        for t in cls.http_threads:
            t.stop()
            t.join()
        for c in cls.swap_clients:
            c.finalise()
            c.fp.close()

        stopDaemons(cls.part_daemons)
        stopDaemons(cls.btc_daemons)

        cls.part_daemons.clear()
        cls.btc_daemons.clear()
        cls.http_threads.clear()
        cls.swap_clients.clear()

        super(Test, cls).tearDownClass()

    def wait_for_num_nodes(self, port, expect_nodes, wait_for=20):
        for i in range(wait_for):
            if delay_event.is_set():
                raise ValueError('Test stopped.')
            js = read_json_api(port, 'network')
            num_nodes = 0
            for p in js['peers']:
                if p['ready'] is True:
                    num_nodes += 1
            if num_nodes >= expect_nodes:
                return True
            delay_event.wait(1)
        raise ValueError('wait_for_num_nodes timed out.')

    def test_01_network(self):

        logging.info('---------- Test Network')
        swap_clients = self.swap_clients

        js_1 = read_json_api(1801, 'wallets')

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.BTC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST)

        swap_clients[1].add_connection('127.0.0.1', BASE_P2P_PORT + 0, swap_clients[0]._network._network_pubkey)
        swap_clients[2].add_connection('127.0.0.1', BASE_P2P_PORT + 0, swap_clients[0]._network._network_pubkey)

        self.wait_for_num_nodes(1800, 2)

        js_n0 = read_json_api(1800, 'network')
        print(dumpj(js_n0))

        path = [swap_clients[0]._network._network_pubkey, swap_clients[2]._network._network_pubkey]
        swap_clients[1]._network.test_onion(path)

        delay_for(delay_event, 1000)


if __name__ == '__main__':
    unittest.main()
