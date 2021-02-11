#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import time
import random
import shutil
import signal
import logging
import unittest
import traceback
import threading
import subprocess
from urllib.request import urlopen

import basicswap.config as cfg
from basicswap.basicswap import (
    BasicSwap,
    Coins,
    SwapTypes,
    BidStates,
    DebugTypes,
    SEQUENCE_LOCK_BLOCKS,
)
from basicswap.util import (
    COIN,
    toWIF,
    make_int,
)
from basicswap.rpc import (
    callrpc,
    callrpc_cli,
    waitForRPC,
)
from basicswap.rpc_xmr import (
    callrpc_xmr_na,
    callrpc_xmr,
)
from basicswap.interface_xmr import (
    XMR_COIN,
)
from basicswap.contrib.key import (
    ECKey,
)
from basicswap.http_server import (
    HttpThread,
)
from tests.basicswap.common import (
    prepareDataDir,
    make_rpc_func,
    checkForks,
    stopDaemons,
    wait_for_bid,
    wait_for_offer,
    wait_for_no_offer,
    wait_for_none_active,
    wait_for_balance,
    post_json_req,
    TEST_HTTP_HOST,
    TEST_HTTP_PORT,
    BASE_RPC_PORT,
    BASE_ZMQ_PORT,
    BTC_BASE_PORT,
    BTC_BASE_RPC_PORT,
    PREFIX_SECRET_KEY_REGTEST,
)
from bin.basicswap_run import startDaemon, startXmrDaemon


logger = logging.getLogger()

NUM_NODES = 3
NUM_XMR_NODES = 3
NUM_BTC_NODES = 3
TEST_DIR = cfg.TEST_DATADIRS

XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 21792
XMR_BASE_ZMQ_PORT = 22792
XMR_BASE_WALLET_RPC_PORT = 23792

test_delay_event = threading.Event()


def prepareXmrDataDir(datadir, node_id, conf_file):
    node_dir = os.path.join(datadir, 'xmr_' + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('keep-fakechain=1\n')
        fp.write('data-dir={}\n'.format(node_dir))
        fp.write('fixed-difficulty=1\n')
        # fp.write('offline=1\n')
        fp.write('p2p-bind-port={}\n'.format(XMR_BASE_P2P_PORT + node_id))
        fp.write('rpc-bind-port={}\n'.format(XMR_BASE_RPC_PORT + node_id))
        fp.write('p2p-bind-ip=127.0.0.1\n')
        fp.write('rpc-bind-ip=127.0.0.1\n')
        fp.write('prune-blockchain=1\n')
        fp.write('zmq-rpc-bind-port={}\n'.format(XMR_BASE_ZMQ_PORT + node_id))
        fp.write('zmq-rpc-bind-ip=127.0.0.1\n')

        for i in range(0, NUM_XMR_NODES):
            if node_id == i:
                continue
            fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(XMR_BASE_P2P_PORT + i))


def startXmrWalletRPC(node_dir, bin_dir, wallet_bin, node_id, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, wallet_bin))

    data_dir = os.path.expanduser(node_dir)
    args = [daemon_bin]
    args += ['--non-interactive']
    args += ['--daemon-address=127.0.0.1:{}'.format(XMR_BASE_RPC_PORT + node_id)]
    args += ['--no-dns']
    args += ['--rpc-bind-port={}'.format(XMR_BASE_WALLET_RPC_PORT + node_id)]
    args += ['--wallet-dir={}'.format(os.path.join(data_dir, 'wallets'))]
    args += ['--log-file={}'.format(os.path.join(data_dir, 'wallet.log'))]
    args += ['--rpc-login=test{0}:test_pass{0}'.format(node_id)]
    args += ['--shared-ringdb-dir={}'.format(os.path.join(data_dir, 'shared-ringdb'))]

    args += opts
    logging.info('Starting daemon {} --wallet-dir={}'.format(daemon_bin, node_dir))

    wallet_stdout = open(os.path.join(data_dir, 'wallet_stdout.log'), 'w')
    wallet_stderr = open(os.path.join(data_dir, 'wallet_stderr.log'), 'w')
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=wallet_stdout, stderr=wallet_stderr, cwd=data_dir)


def prepare_swapclient_dir(datadir, node_id, network_key, network_pubkey):
    basicswap_dir = os.path.join(datadir, 'basicswap_' + str(node_id))
    if not os.path.exists(basicswap_dir):
        os.makedirs(basicswap_dir)

    settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
    settings = {
        'debug': True,
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
            'monero': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': XMR_BASE_RPC_PORT + node_id,
                'walletrpcport': XMR_BASE_WALLET_RPC_PORT + node_id,
                'walletrpcuser': 'test' + str(node_id),
                'walletrpcpassword': 'test_pass' + str(node_id),
                'walletfile': 'testwallet',
                'datadir': os.path.join(datadir, 'xmr_' + str(node_id)),
                'bindir': cfg.XMR_BINDIR,
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
        'min_delay_retry': 2,
        'max_delay_retry': 10
    }

    with open(settings_path, 'w') as fp:
        json.dump(settings, fp, indent=4)


def btcRpc(cmd, node_id=0):
    return callrpc_cli(cfg.BITCOIN_BINDIR, os.path.join(TEST_DIR, 'btc_' + str(node_id)), 'regtest', cmd, cfg.BITCOIN_CLI)


def signal_handler(sig, frame):
    logging.info('signal {} detected.'.format(sig))
    test_delay_event.set()


def waitForXMRNode(rpc_offset, max_tries=7):
    for i in range(max_tries + 1):
        try:
            callrpc_xmr_na(XMR_BASE_RPC_PORT + rpc_offset, 'get_block_count')
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning('Can\'t connect to XMR RPC: %s. Retrying in %d second/s.', str(ex), (i + 1))
                time.sleep(i + 1)
    raise ValueError('waitForXMRNode failed')


def waitForXMRWallet(rpc_offset, auth, max_tries=7):
    for i in range(max_tries + 1):
        try:
            callrpc_xmr(XMR_BASE_WALLET_RPC_PORT + rpc_offset, auth, 'get_languages')
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning('Can\'t connect to XMR wallet RPC: %s. Retrying in %d second/s.', str(ex), (i + 1))
                time.sleep(i + 1)
    raise ValueError('waitForXMRWallet failed')


def callnoderpc(node_id, method, params=[], wallet=None, base_rpc_port=BASE_RPC_PORT):
    auth = 'test{0}:test_pass{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def run_coins_loop(cls):
    while not test_delay_event.is_set():
        try:
            if cls.btc_addr is not None:
                btcRpc('generatetoaddress 1 {}'.format(cls.btc_addr))
            if cls.xmr_addr is not None:
                callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': 1})
        except Exception as e:
            logging.warning('run_coins_loop ' + str(e))
        test_delay_event.wait(1.0)


def run_loop(cls):
    while not test_delay_event.is_set():
        for c in cls.swap_clients:
            c.update()
        test_delay_event.wait(1.0)


class Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        random.seed(time.time())

        cls.update_thread = None
        cls.coins_update_thread = None
        cls.http_threads = []
        cls.swap_clients = []
        cls.part_daemons = []
        cls.btc_daemons = []
        cls.xmr_daemons = []
        cls.xmr_wallet_auth = []

        cls.part_stakelimit = 0
        cls.xmr_addr = None
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
                    callrpc_cli(cfg.PARTICL_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'particl-wallet')

                cls.part_daemons.append(startDaemon(os.path.join(TEST_DIR, 'part_' + str(i)), cfg.PARTICL_BINDIR, cfg.PARTICLD))
                logging.info('Started %s %d', cfg.PARTICLD, cls.part_daemons[-1].pid)

            for i in range(NUM_NODES):
                # Load mnemonics after all nodes have started to avoid staking getting stuck in TryToSync
                rpc = make_rpc_func(i)
                waitForRPC(rpc)
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

            for i in range(NUM_BTC_NODES):
                data_dir = prepareDataDir(TEST_DIR, i, 'bitcoin.conf', 'btc_', base_p2p_port=BTC_BASE_PORT, base_rpc_port=BTC_BASE_RPC_PORT)
                if os.path.exists(os.path.join(cfg.BITCOIN_BINDIR, 'bitcoin-wallet')):
                    callrpc_cli(cfg.BITCOIN_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'bitcoin-wallet')

                cls.btc_daemons.append(startDaemon(os.path.join(TEST_DIR, 'btc_' + str(i)), cfg.BITCOIN_BINDIR, cfg.BITCOIND))
                logging.info('Started %s %d', cfg.BITCOIND, cls.part_daemons[-1].pid)

                waitForRPC(make_rpc_func(i, base_rpc_port=BTC_BASE_RPC_PORT))

            for i in range(NUM_XMR_NODES):
                prepareXmrDataDir(TEST_DIR, i, 'monerod.conf')

                cls.xmr_daemons.append(startXmrDaemon(os.path.join(TEST_DIR, 'xmr_' + str(i)), cfg.XMR_BINDIR, cfg.XMRD))
                logging.info('Started %s %d', cfg.XMRD, cls.xmr_daemons[-1].pid)
                waitForXMRNode(i)

                cls.xmr_daemons.append(startXmrWalletRPC(os.path.join(TEST_DIR, 'xmr_' + str(i)), cfg.XMR_BINDIR, cfg.XMR_WALLET_RPC, i))

            for i in range(NUM_XMR_NODES):
                cls.xmr_wallet_auth.append(('test{0}'.format(i), 'test_pass{0}'.format(i)))
                logging.info('Creating XMR wallet %i', i)

                waitForXMRWallet(i, cls.xmr_wallet_auth[i])

                cls.callxmrnodewallet(cls, i, 'create_wallet', {'filename': 'testwallet', 'language': 'English'})
                cls.callxmrnodewallet(cls, i, 'open_wallet', {'filename': 'testwallet'})

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
                sc.setDaemonPID(Coins.BTC, cls.btc_daemons[i].pid)
                sc.setDaemonPID(Coins.PART, cls.part_daemons[i].pid)
                sc.start()
                cls.swap_clients.append(sc)

                t = HttpThread(cls.swap_clients[i].fp, TEST_HTTP_HOST, TEST_HTTP_PORT + i, False, cls.swap_clients[i])
                cls.http_threads.append(t)
                t.start()

            cls.btc_addr = callnoderpc(0, 'getnewaddress', ['mining_addr', 'bech32'], base_rpc_port=BTC_BASE_RPC_PORT)
            cls.xmr_addr = cls.callxmrnodewallet(cls, 1, 'get_address')['address']

            num_blocks = 500  # Mine enough to activate segwit
            logging.info('Mining %d Bitcoin blocks to %s', num_blocks, cls.btc_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.btc_addr], base_rpc_port=BTC_BASE_RPC_PORT)

            checkForks(callnoderpc(0, 'getblockchaininfo', base_rpc_port=BTC_BASE_RPC_PORT))

            num_blocks = 100
            if callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
                logging.info('Mining %d Monero blocks to %s.', num_blocks, cls.xmr_addr)
                callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': num_blocks})
            logging.info('XMR blocks: %d', callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'])

            logging.info('Starting update thread.')
            signal.signal(signal.SIGINT, signal_handler)
            cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
            cls.update_thread.start()

            cls.coins_update_thread = threading.Thread(target=run_coins_loop, args=(cls,))
            cls.coins_update_thread.start()
        except Exception:
            traceback.print_exc()
            Test.tearDownClass()
            raise ValueError('setUpClass() failed.')

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising')
        test_delay_event.set()
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

        stopDaemons(cls.xmr_daemons)
        stopDaemons(cls.part_daemons)
        stopDaemons(cls.btc_daemons)

        super(Test, cls).tearDownClass()

    def callxmrnodewallet(self, node_id, method, params=None):
        return callrpc_xmr(XMR_BASE_WALLET_RPC_PORT + node_id, self.xmr_wallet_auth[node_id], method, params)

    def test_01_part_xmr(self):
        logging.info('---------- Test PART to XMR')
        swap_clients = self.swap_clients

        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json/wallets').read())
        assert(make_int(js_1[str(int(Coins.XMR))]['balance'], scale=12) > 0)
        assert(make_int(js_1[str(int(Coins.XMR))]['unconfirmed'], scale=12) > 0)

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, 100 * COIN, 0.11 * XMR_COIN, 100 * COIN, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        assert(len(offers) == 1)
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        js_0_end = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())
        end_xmr = float(js_0_end['6']['balance']) + float(js_0_end['6']['unconfirmed'])
        assert(end_xmr > 10.9 and end_xmr < 11.0)

    def test_02_leader_recover_a_lock_tx(self):
        logging.info('---------- Test PART to XMR leader recovers coin a lock tx')
        swap_clients = self.swap_clients

        js_w0_before = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.12 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=SEQUENCE_LOCK_BLOCKS, lock_value=12)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

        js_w0_after = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())
        print('[rm] js_w0_before', json.dumps(js_w0_before))
        print('[rm] js_w0_after', json.dumps(js_w0_after))

    def test_03_follower_recover_a_lock_tx(self):
        logging.info('---------- Test PART to XMR follower recovers coin a lock tx')
        swap_clients = self.swap_clients

        js_w0_before = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.13 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=SEQUENCE_LOCK_BLOCKS, lock_value=12)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[0].setBidDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_STALLED_FOR_TEST, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_SWIPED, wait_for=80, sent=True)

        js_w0_after = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())

        wait_for_none_active(test_delay_event, 1800)
        wait_for_none_active(test_delay_event, 1801)

    def test_04_follower_recover_b_lock_tx(self):
        logging.info('---------- Test PART to XMR follower recovers coin b lock tx')

        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.14 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=SEQUENCE_LOCK_BLOCKS, lock_value=18)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

    def test_05_btc_xmr(self):
        logging.info('---------- Test BTC to XMR')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        swap_clients[1].ci(Coins.XMR).setFeePriority(3)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        swap_clients[1].ci(Coins.XMR).setFeePriority(0)

    def test_06_multiple_swaps(self):
        logging.info('---------- Test Multiple concurrent swaps')
        swap_clients = self.swap_clients

        js_w0_before = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())
        js_w1_before = json.loads(urlopen('http://127.0.0.1:1801/json/wallets').read())

        amt_1 = make_int(random.uniform(0.001, 49.0), scale=8, r=1)
        amt_2 = make_int(random.uniform(0.001, 49.0), scale=8, r=1)

        rate_1 = make_int(random.uniform(80.0, 110.0), scale=12, r=1)
        rate_2 = make_int(random.uniform(0.01, 0.5), scale=12, r=1)

        logging.info('amt_1 {}, rate_1 {}'.format(amt_1, rate_1))
        logging.info('amt_2 {}, rate_2 {}'.format(amt_2, rate_2))
        offer1_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, amt_1, rate_1, amt_1, SwapTypes.XMR_SWAP)
        offer2_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, amt_2, rate_2, amt_2, SwapTypes.XMR_SWAP)

        wait_for_offer(test_delay_event, swap_clients[1], offer1_id)
        offer1 = swap_clients[1].getOffer(offer1_id)
        wait_for_offer(test_delay_event, swap_clients[1], offer2_id)
        offer2 = swap_clients[1].getOffer(offer2_id)

        bid1_id = swap_clients[1].postXmrBid(offer1_id, offer1.amount_from)
        bid2_id = swap_clients[1].postXmrBid(offer2_id, offer2.amount_from)

        offer3_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, 11 * COIN, 0.15 * XMR_COIN, 11 * COIN, SwapTypes.XMR_SWAP)

        wait_for_bid(test_delay_event, swap_clients[0], bid1_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid1_id)

        wait_for_offer(test_delay_event, swap_clients[1], offer3_id)
        offer3 = swap_clients[1].getOffer(offer3_id)
        bid3_id = swap_clients[1].postXmrBid(offer3_id, offer3.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid2_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid2_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid3_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid3_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid1_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid1_id, BidStates.SWAP_COMPLETED, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid2_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid2_id, BidStates.SWAP_COMPLETED, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid3_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid3_id, BidStates.SWAP_COMPLETED, sent=True)

        wait_for_none_active(test_delay_event, 1800)
        wait_for_none_active(test_delay_event, 1801)

        js_w0_after = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())
        js_w1_after = json.loads(urlopen('http://127.0.0.1:1801/json/wallets').read())
        logging.info('[rm] js_w0_after {}'.format(json.dumps(js_w0_after, indent=4)))
        logging.info('[rm] js_w1_after {}'.format(json.dumps(js_w1_after, indent=4)))

        assert(make_int(js_w1_after['2']['balance'], scale=8, r=1) - (make_int(js_w1_before['2']['balance'], scale=8, r=1) + amt_1) < 1000)

    def test_07_revoke_offer(self):
        logging.info('---------- Test offer revocaction')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)

        swap_clients[0].revokeOffer(offer_id)

        wait_for_no_offer(test_delay_event, swap_clients[1], offer_id)

    def test_08_withdraw(self):
        logging.info('---------- Test xmr withdrawals')
        swap_clients = self.swap_clients
        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json/wallets').read())
        print('js_0 debug', js_0)
        address_to = js_0[str(int(Coins.XMR))]['deposit_address']

        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json/wallets').read())
        assert(float(js_1[str(int(Coins.XMR))]['balance']) > 0.0)

        swap_clients[1].withdrawCoin(Coins.XMR, 1.1, address_to, False)

    def test_09_auto_accept(self):
        logging.info('---------- Test BTC to XMR auto accept')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 11 * COIN, 101 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].listOffers(filters={'offer_id': offer_id})[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

    def test_10_locked_refundtx(self):
        logging.info('---------- Test Refund tx is locked')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED, wait_for=180)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        try:
            swap_clients[0].ci(Coins.BTC).publishTx(xmr_swap.a_lock_refund_tx)
            assert(False), 'Lock refund tx should be locked'
        except Exception as e:
            assert('non-BIP68-final' in str(e))

    def test_11_particl_anon(self):
        logging.info('---------- Test Particl anon transactions')
        swap_clients = self.swap_clients

        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json/wallets/part').read())
        assert(float(js_0['anon_balance']) == 0.0)

        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json/wallets/part').read())
        assert(float(js_1['balance']) > 200.0)

        post_json = {
            'value': 100,
            'address': js_0['stealth_address'],
            'subfee': False,
            'type_to': 'anon',
        }
        json_rv = json.loads(post_json_req('http://127.0.0.1:1801/json/wallets/part/withdraw', post_json))
        assert(len(json_rv['txid']) == 64)

        post_json['value'] = 0.5
        for i in range(22):
            json_rv = json.loads(post_json_req('http://127.0.0.1:1801/json/wallets/part/withdraw', post_json))
            assert(len(json_rv['txid']) == 64)

        logging.info('Waiting for anon balance')
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1800/json/wallets/part', 'anon_balance', 110.0)

        post_json = {
            'value': 10,
            'address': js_0['stealth_address'],
            'subfee': True,
            'type_from': 'anon',
            'type_to': 'blind',
        }
        json_rv = json.loads(post_json_req('http://127.0.0.1:1800/json/wallets/part/withdraw', post_json))
        assert(len(json_rv['txid']) == 64)

        logging.info('Waiting for blind balance')
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1800/json/wallets/part', 'blind_balance', 9.8)
        if float(js_0['blind_balance']) >= 10.0:
            raise ValueError('Expect blind balance < 10')

        logging.warning('TODO')
        return

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(2.0, 20.0), scale=8, r=1)
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.PART_ANON, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json/wallets/part').read())
        print('[rm] js_1', js_1)


if __name__ == '__main__':
    unittest.main()
