#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import time
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
    checkForks,
    TEST_HTTP_HOST,
    TEST_HTTP_PORT,
)
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from bin.basicswap_run import startDaemon


logger = logging.getLogger()

NUM_NODES = 3
NUM_XMR_NODES = 3
NUM_BTC_NODES = 3
TEST_DIR = cfg.TEST_DATADIRS

BASE_PORT = 14792
BASE_RPC_PORT = 19792
BASE_ZMQ_PORT = 20792

BTC_BASE_PORT = 31792
BTC_BASE_RPC_PORT = 32792
BTC_BASE_ZMQ_PORT = 33792

XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 21792
XMR_BASE_ZMQ_PORT = 22792
XMR_BASE_WALLET_RPC_PORT = 23792

PREFIX_SECRET_KEY_REGTEST = 0x2e

delay_event = threading.Event()
stop_test = False


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

        fp.write('zmq-rpc-bind-port={}\n'.format(XMR_BASE_ZMQ_PORT + node_id))
        fp.write('zmq-rpc-bind-ip=127.0.0.1\n')

        for i in range(0, NUM_XMR_NODES):
            if node_id == i:
                continue
            fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(XMR_BASE_P2P_PORT + i))


def prepareDataDir(datadir, node_id, conf_file, dir_prefix, base_p2p_port=BASE_PORT, base_rpc_port=BASE_RPC_PORT):
    node_dir = os.path.join(datadir, dir_prefix + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('[regtest]\n')
        fp.write('port=' + str(base_p2p_port + node_id) + '\n')
        fp.write('rpcport=' + str(base_rpc_port + node_id) + '\n')

        salt = generate_salt(16)
        fp.write('rpcauth={}:{}${}\n'.format('test' + str(node_id), salt, password_to_hmac(salt, 'test_pass' + str(node_id))))

        fp.write('daemon=0\n')
        fp.write('printtoconsole=0\n')
        fp.write('server=1\n')
        fp.write('discover=0\n')
        fp.write('listenonion=0\n')
        fp.write('bind=127.0.0.1\n')
        fp.write('debug=1\n')
        fp.write('debugexclude=libevent\n')

        fp.write('fallbackfee=0.01\n')
        fp.write('acceptnonstdtxn=0\n')
        fp.write('txindex=1\n')

        fp.write('findpeers=0\n')
        # minstakeinterval=5  # Using walletsettings stakelimit instead

        if base_p2p_port == BASE_PORT:  # Particl
            fp.write('zmqpubsmsg=tcp://127.0.0.1:{}\n'.format(BASE_ZMQ_PORT + node_id))

        for i in range(0, NUM_NODES):
            if node_id == i:
                continue
            fp.write('addnode=127.0.0.1:{}\n'.format(base_p2p_port + i))


def startXmrDaemon(node_dir, bin_dir, daemon_bin, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    args = [daemon_bin, '--config-file=' + os.path.join(os.path.expanduser(node_dir), 'monerod.conf')] + opts
    logging.info('Starting node {} --data-dir={}'.format(daemon_bin, node_dir))

    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def startXmrWalletRPC(node_dir, bin_dir, wallet_bin, node_id, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, wallet_bin))

    data_dir = os.path.expanduser(node_dir)
    args = [daemon_bin]
    args += ['--daemon-address=localhost:{}'.format(XMR_BASE_RPC_PORT + node_id)]
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
        'htmlhost': 'localhost',
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


def partRpc(cmd, node_id=0):
    return callrpc_cli(cfg.PARTICL_BINDIR, os.path.join(TEST_DIR, 'part_' + str(node_id)), 'regtest', cmd, cfg.PARTICL_CLI)


def btcRpc(cmd, node_id=0):
    return callrpc_cli(cfg.BITCOIN_BINDIR, os.path.join(TEST_DIR, 'btc_' + str(node_id)), 'regtest', cmd, cfg.BITCOIN_CLI)


def make_rpc_func(node_id, base_rpc_port=BASE_RPC_PORT):
    node_id = node_id
    auth = 'test{0}:test_pass{0}'.format(node_id)

    def rpc_func(method, params=None, wallet=None):
        nonlocal node_id, auth
        return callrpc(base_rpc_port + node_id, auth, method, params, wallet)
    return rpc_func


def signal_handler(sig, frame):
    global stop_test
    logging.info('signal {} detected.'.format(sig))
    stop_test = True
    delay_event.set()


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
    global stop_test
    while not stop_test:
        if cls.btc_addr is not None:
            btcRpc('generatetoaddress 1 {}'.format(cls.btc_addr))

        if cls.xmr_addr is not None:
            callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': 1})
        time.sleep(1.0)


def run_loop(cls):
    global stop_test
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
                prepareDataDir(TEST_DIR, i, 'particl.conf', 'part_')

                cls.part_daemons.append(startDaemon(os.path.join(TEST_DIR, 'part_' + str(i)), cfg.PARTICL_BINDIR, cfg.PARTICLD))
                logging.info('Started %s %d', cfg.PARTICLD, cls.part_daemons[-1].pid)

                waitForRPC(make_rpc_func(i))

            for i in range(NUM_BTC_NODES):
                prepareDataDir(TEST_DIR, i, 'bitcoin.conf', 'btc_', base_p2p_port=BTC_BASE_PORT, base_rpc_port=BTC_BASE_RPC_PORT)

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

            logging.info('Initialising coin networks.')
            cls.swap_clients[0].callrpc('extkeyimportmaster', ['abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb'])
            cls.swap_clients[1].callrpc('extkeyimportmaster', ['pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true'])
            cls.swap_clients[1].callrpc('getnewextaddress', ['lblExtTest'])
            cls.swap_clients[1].callrpc('rescanblockchain')

            for i in range(3):
                t = HttpThread(cls.swap_clients[i].fp, TEST_HTTP_HOST, TEST_HTTP_PORT + i, False, cls.swap_clients[i])
                cls.http_threads.append(t)
                t.start()

            cls.btc_addr = callnoderpc(0, 'getnewaddress', ['mining_addr', 'bech32'], base_rpc_port=BTC_BASE_RPC_PORT)
            cls.xmr_addr = cls.callxmrnodewallet(cls, 1, 'get_address')['address']

            num_blocks = 500
            logging.info('Mining %d Bitcoin blocks to %s', num_blocks, cls.btc_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.btc_addr], base_rpc_port=BTC_BASE_RPC_PORT)

            checkForks(callnoderpc(0, 'getblockchaininfo', base_rpc_port=BTC_BASE_RPC_PORT))

            if callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
                logging.info('Mining %d Monero blocks.', num_blocks)
                callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': num_blocks})
            rv = callrpc_xmr_na(XMR_BASE_RPC_PORT + 1, 'get_block_count')
            logging.info('XMR blocks: %d', rv['count'])

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
            c.fp.close()

        for d in cls.xmr_daemons:
            logging.info('Interrupting %d', d.pid)
            try:
                d.send_signal(signal.SIGINT)
            except Exception as e:
                logging.info('Interrupting %d, error %s', d.pid, str(e))
        for d in cls.xmr_daemons:
            try:
                d.wait(timeout=20)
                if d.stdout:
                    d.stdout.close()
                if d.stderr:
                    d.stderr.close()
                if d.stdin:
                    d.stdin.close()
            except Exception as e:
                logging.info('Closing %d, error %s', d.pid, str(e))

        for d in cls.part_daemons + cls.btc_daemons:
            logging.info('Interrupting %d', d.pid)
            try:
                d.send_signal(signal.SIGINT)
            except Exception as e:
                logging.info('Interrupting %d, error %s', d.pid, str(e))
        for d in cls.part_daemons + cls.btc_daemons:
            try:
                d.wait(timeout=20)
                if d.stdout:
                    d.stdout.close()
                if d.stderr:
                    d.stderr.close()
                if d.stdin:
                    d.stdin.close()
            except Exception as e:
                logging.info('Closing %d, error %s', d.pid, str(e))

        super(Test, cls).tearDownClass()

    def callxmrnodewallet(self, node_id, method, params=None):
        return callrpc_xmr(XMR_BASE_WALLET_RPC_PORT + node_id, self.xmr_wallet_auth[node_id], method, params)

    def wait_for_offer(self, swap_client, offer_id, wait_for=20):
        logging.info('wait_for_offer %s', offer_id.hex())
        for i in range(wait_for):
            if stop_test:
                raise ValueError('Test stopped.')
            time.sleep(1)
            offers = swap_client.listOffers()
            for offer in offers:
                if offer.offer_id == offer_id:
                    return
        raise ValueError('wait_for_offer timed out.')

    def wait_for_no_offer(self, swap_client, offer_id, wait_for=20):
        logging.info('wait_for_no_offer %s', offer_id.hex())
        for i in range(wait_for):
            if stop_test:
                raise ValueError('Test stopped.')
            time.sleep(1)
            offers = swap_client.listOffers()
            found_offer = False
            for offer in offers:
                if offer.offer_id == offer_id:
                    found_offer = True
                    break
            if not found_offer:
                return True
        raise ValueError('wait_for_offer timed out.')

    def wait_for_bid(self, swap_client, bid_id, state=None, sent=False, wait_for=20):
        logging.info('wait_for_bid %s', bid_id.hex())
        for i in range(wait_for):
            if stop_test:
                raise ValueError('Test stopped.')
            time.sleep(1)
            bids = swap_client.listBids(sent=sent)
            for bid in bids:
                if bid[1] == bid_id:
                    if state is not None and state != bid[4]:
                        continue
                    return
        raise ValueError('wait_for_bid timed out.')

    def delay_for(self, delay_for=60):
        logging.info('Delaying for {} seconds.'.format(delay_for))
        delay_event.clear()
        delay_event.wait(delay_for)

    def test_01_part_xmr(self):
        logging.info('---------- Test PART to XMR')
        swap_clients = self.swap_clients

        js_0 = json.loads(urlopen('http://localhost:1801/json/wallets').read())
        assert(make_int(js_0[str(int(Coins.XMR))]['balance'], scale=12) > 0)
        assert(make_int(js_0[str(int(Coins.XMR))]['unconfirmed'], scale=12) > 0)

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, 100 * COIN, 0.11 * XMR_COIN, 100 * COIN, SwapTypes.XMR_SWAP)
        self.wait_for_offer(swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        assert(len(offers) == 1)
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        self.wait_for_bid(swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        js_0_end = json.loads(urlopen('http://localhost:1800/json/wallets').read())
        end_xmr = float(js_0_end['6']['balance']) + float(js_0_end['6']['unconfirmed'])
        assert(end_xmr > 10.9 and end_xmr < 11.0)

    def test_02_leader_recover_a_lock_tx(self):
        logging.info('---------- Test PART to XMR leader recovers coin a lock tx')
        swap_clients = self.swap_clients

        js_w0_before = json.loads(urlopen('http://localhost:1800/json/wallets').read())

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.12 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=SEQUENCE_LOCK_BLOCKS, lock_value=12)
        self.wait_for_offer(swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        self.wait_for_bid(swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

        js_w0_after = json.loads(urlopen('http://localhost:1800/json/wallets').read())
        print('[rm] js_w0_before', json.dumps(js_w0_before))
        print('[rm] js_w0_after', json.dumps(js_w0_after))

    def test_03_follower_recover_a_lock_tx(self):
        logging.info('---------- Test PART to XMR follower recovers coin a lock tx')
        swap_clients = self.swap_clients

        js_w0_before = json.loads(urlopen('http://localhost:1800/json/wallets').read())

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.13 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=SEQUENCE_LOCK_BLOCKS, lock_value=12)
        self.wait_for_offer(swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[0].setBidDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND)

        swap_clients[0].acceptXmrBid(bid_id)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.BID_ABANDONED, wait_for=180)
        self.wait_for_bid(swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_SWIPED, wait_for=80, sent=True)

        js_w0_after = json.loads(urlopen('http://localhost:1800/json/wallets').read())

    def test_04_follower_recover_b_lock_tx(self):
        logging.info('---------- Test PART to XMR follower recovers coin b lock tx')

        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.14 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=SEQUENCE_LOCK_BLOCKS, lock_value=18)
        self.wait_for_offer(swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        self.wait_for_bid(swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

    def test_05_btc_xmr(self):
        logging.info('---------- Test BTC to XMR')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        self.wait_for_offer(swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert(xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        self.wait_for_bid(swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        self.wait_for_bid(swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

    def test_06_multiple_swaps(self):
        logging.info('---------- Test Multiple concurrent swaps')
        swap_clients = self.swap_clients
        offer1_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        offer2_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, 10 * COIN, 0.14 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)

        self.wait_for_offer(swap_clients[1], offer1_id)
        offer1 = swap_clients[1].getOffer(offer1_id)
        self.wait_for_offer(swap_clients[1], offer2_id)
        offer2 = swap_clients[1].getOffer(offer2_id)

        bid1_id = swap_clients[1].postXmrBid(offer1_id, offer1.amount_from)
        bid2_id = swap_clients[1].postXmrBid(offer2_id, offer2.amount_from)

        offer3_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, 11 * COIN, 0.15 * XMR_COIN, 11 * COIN, SwapTypes.XMR_SWAP)

        self.wait_for_bid(swap_clients[0], bid1_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid1_id)

        self.wait_for_offer(swap_clients[1], offer3_id)
        offer3 = swap_clients[1].getOffer(offer3_id)
        bid3_id = swap_clients[1].postXmrBid(offer3_id, offer3.amount_from)

        self.wait_for_bid(swap_clients[0], bid2_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid2_id)

        self.wait_for_bid(swap_clients[0], bid3_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid3_id)

        self.wait_for_bid(swap_clients[0], bid1_id, BidStates.SWAP_COMPLETED, wait_for=180)
        self.wait_for_bid(swap_clients[1], bid1_id, BidStates.SWAP_COMPLETED, sent=True)

        self.wait_for_bid(swap_clients[0], bid2_id, BidStates.SWAP_COMPLETED, wait_for=60)
        self.wait_for_bid(swap_clients[1], bid2_id, BidStates.SWAP_COMPLETED, sent=True)

        self.wait_for_bid(swap_clients[0], bid3_id, BidStates.SWAP_COMPLETED, wait_for=60)
        self.wait_for_bid(swap_clients[1], bid3_id, BidStates.SWAP_COMPLETED, sent=True)

    def test_07_revoke_offer(self):
        logging.info('---------- Test offer revocaction')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        self.wait_for_offer(swap_clients[1], offer_id)

        swap_clients[0].revokeOffer(offer_id)

        self.wait_for_no_offer(swap_clients[1], offer_id)

if __name__ == '__main__':
    unittest.main()
