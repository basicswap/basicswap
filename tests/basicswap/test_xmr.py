#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
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

import basicswap.config as cfg
from basicswap.db import (
    Concepts,
)
from basicswap.basicswap import (
    Coins,
    BasicSwap,
    BidStates,
    SwapTypes,
    DebugTypes,
)
from basicswap.basicswap_util import (
    TxLockTypes,
    EventLogTypes,
)
from basicswap.util import (
    COIN,
    format_amount,
    make_int,
    TemporaryError
)
from basicswap.util.address import (
    toWIF,
)
from basicswap.rpc import (
    callrpc,
    callrpc_cli,
)
from basicswap.rpc_xmr import (
    callrpc_xmr,
)
from basicswap.interface.xmr import (
    XMR_COIN,
)
from basicswap.contrib.key import (
    ECKey,
)
from basicswap.http_server import (
    HttpThread,
)
from tests.basicswap.util import (
    make_boolean,
    post_json_req,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    prepareDataDir,
    make_rpc_func,
    checkForks,
    stopDaemons,
    wait_for_bid,
    wait_for_event,
    wait_for_offer,
    wait_for_no_offer,
    wait_for_none_active,
    wait_for_balance,
    wait_for_unspent,
    waitForRPC,
    compare_bid_states,
    extract_states_from_xu_file,
    TEST_HTTP_HOST,
    TEST_HTTP_PORT,
    BASE_RPC_PORT,
    BASE_ZMQ_PORT,
    BTC_BASE_PORT,
    BTC_BASE_RPC_PORT,
    LTC_BASE_PORT,
    LTC_BASE_RPC_PORT,
    PREFIX_SECRET_KEY_REGTEST,
)
from basicswap.db_util import (
    remove_expired_data,
)
from basicswap.bin.run import startDaemon, startXmrDaemon, startXmrWalletDaemon


logger = logging.getLogger()

NUM_NODES = 3
NUM_XMR_NODES = 3
NUM_BTC_NODES = 3
NUM_LTC_NODES = 3
TEST_DIR = cfg.TEST_DATADIRS

XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 21792
XMR_BASE_ZMQ_PORT = 22792
XMR_BASE_WALLET_RPC_PORT = 23792

signal_event = threading.Event()  # Set if test was cancelled
test_delay_event = threading.Event()
RESET_TEST = make_boolean(os.getenv('RESET_TEST', 'true'))


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


def prepare_swapclient_dir(datadir, node_id, network_key, network_pubkey, with_coins=set(), cls=None):
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
                'anon_tx_ring_size': 5,  # Faster testing
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
        'max_delay_event': 4,
        'min_delay_event_short': 1,
        'max_delay_event_short': 3,
        'min_delay_retry': 2,
        'max_delay_retry': 10,
        'debug_ui': True,
        'restrict_unknown_seed_wallets': False,
    }

    if Coins.XMR in with_coins:
        settings['chainclients']['monero'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': XMR_BASE_RPC_PORT + node_id,
            'walletrpcport': XMR_BASE_WALLET_RPC_PORT + node_id,
            'walletrpcuser': 'test' + str(node_id),
            'walletrpcpassword': 'test_pass' + str(node_id),
            'walletfile': 'testwallet',
            'datadir': os.path.join(datadir, 'xmr_' + str(node_id)),
            'bindir': cfg.XMR_BINDIR,
        }

    if Coins.LTC in with_coins:
        settings['chainclients']['litecoin'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': LTC_BASE_RPC_PORT + node_id,
            'rpcuser': 'test' + str(node_id),
            'rpcpassword': 'test_pass' + str(node_id),
            'datadir': os.path.join(datadir, 'ltc_' + str(node_id)),
            'bindir': cfg.LITECOIN_BINDIR,
            'use_segwit': True,
        }

    if cls:
        cls.addCoinSettings(settings, datadir, node_id)

    with open(settings_path, 'w') as fp:
        json.dump(settings, fp, indent=4)


def btcCli(cmd, node_id=0):
    return callrpc_cli(cfg.BITCOIN_BINDIR, os.path.join(TEST_DIR, 'btc_' + str(node_id)), 'regtest', cmd, cfg.BITCOIN_CLI)


def ltcCli(cmd, node_id=0):
    return callrpc_cli(cfg.LITECOIN_BINDIR, os.path.join(TEST_DIR, 'ltc_' + str(node_id)), 'regtest', cmd, cfg.LITECOIN_CLI)


def signal_handler(sig, frame):
    logging.info('signal {} detected.'.format(sig))
    signal_event.set()
    test_delay_event.set()


def waitForXMRNode(rpc_offset, max_tries=7):
    for i in range(max_tries + 1):
        try:
            callrpc_xmr(XMR_BASE_RPC_PORT + rpc_offset, 'get_block_count')
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning('Can\'t connect to XMR RPC: %s. Retrying in %d second/s.', str(ex), (i + 1))
                time.sleep(i + 1)
    raise ValueError('waitForXMRNode failed')


def waitForXMRWallet(rpc_offset, auth, max_tries=7):
    for i in range(max_tries + 1):
        try:
            callrpc_xmr(XMR_BASE_WALLET_RPC_PORT + rpc_offset, 'get_languages', auth=auth)
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning('Can\'t connect to XMR wallet RPC: %s. Retrying in %d second/s.', str(ex), (i + 1))
                time.sleep(i + 1)
    raise ValueError('waitForXMRWallet failed')


def callnoderpc(node_id, method, params=[], wallet=None, base_rpc_port=BASE_RPC_PORT):
    auth = 'test{0}:test_pass{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


pause_event = threading.Event()


def run_coins_loop(cls):
    while not test_delay_event.is_set():
        pause_event.wait()
        try:
            cls.coins_loop()
        except Exception as e:
            logging.warning('run_coins_loop ' + str(e))
        test_delay_event.wait(1.0)


def run_loop(cls):
    while not test_delay_event.is_set():
        for c in cls.swap_clients:
            c.update()
        test_delay_event.wait(1.0)


class BaseTest(unittest.TestCase):
    __test__ = False
    update_thread = None
    coins_update_thread = None
    http_threads = []
    swap_clients = []
    part_daemons = []
    btc_daemons = []
    ltc_daemons = []
    xmr_daemons = []
    xmr_wallet_auth = []
    restore_instance = False

    start_ltc_nodes = False
    start_xmr_nodes = True
    has_segwit = True

    xmr_addr = None
    btc_addr = None
    ltc_addr = None

    @classmethod
    def getRandomPubkey(cls):
        eckey = ECKey()
        eckey.generate()
        return eckey.get_pubkey().get_bytes()

    @classmethod
    def setUpClass(cls):
        if signal_event.is_set():
            raise ValueError('Test has been cancelled.')
        test_delay_event.clear()
        random.seed(time.time())

        logger.propagate = False
        logger.handlers = []
        logger.setLevel(logging.INFO)  # DEBUG shows many messages from requests.post
        formatter = logging.Formatter('%(asctime)s %(levelname)s : %(message)s')
        stream_stdout = logging.StreamHandler()
        stream_stdout.setFormatter(formatter)
        logger.addHandler(stream_stdout)

        logging.info('Setting up tests for class: ' + cls.__name__)

        diagrams_dir = 'doc/protocols/sequence_diagrams'
        cls.states_bidder = extract_states_from_xu_file(os.path.join(diagrams_dir, 'ads.bidder.alt.xu'), 'B')
        cls.states_offerer = extract_states_from_xu_file(os.path.join(diagrams_dir, 'ads.offerer.alt.xu'), 'O')

        cls.states_bidder_sh = extract_states_from_xu_file(os.path.join(diagrams_dir, 'bidder.alt.xu'), 'B')
        cls.states_offerer_sh = extract_states_from_xu_file(os.path.join(diagrams_dir, 'offerer.alt.xu'), 'O')

        if os.path.isdir(TEST_DIR):
            if RESET_TEST:
                logging.info('Removing ' + TEST_DIR)
                for name in os.listdir(TEST_DIR):
                    if name == 'pivx-params':
                        continue
                    fullpath = os.path.join(TEST_DIR, name)
                    if os.path.isdir(fullpath):
                        shutil.rmtree(fullpath)
                    else:
                        os.remove(fullpath)
            else:
                logging.info('Restoring instance from ' + TEST_DIR)
                cls.restore_instance = True
        if not os.path.exists(TEST_DIR):
            os.makedirs(TEST_DIR)

        cls.stream_fp = logging.FileHandler(os.path.join(TEST_DIR, 'test.log'))
        cls.stream_fp.setFormatter(formatter)
        logger.addHandler(cls.stream_fp)

        try:
            logging.info('Preparing coin nodes.')
            for i in range(NUM_NODES):
                if not cls.restore_instance:
                    data_dir = prepareDataDir(TEST_DIR, i, 'particl.conf', 'part_')
                    if os.path.exists(os.path.join(cfg.PARTICL_BINDIR, 'particl-wallet')):
                        try:
                            callrpc_cli(cfg.PARTICL_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat -legacy create', 'particl-wallet')
                        except Exception as e:
                            logging.warning('particl-wallet create failed, retrying without -legacy')
                            callrpc_cli(cfg.PARTICL_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'particl-wallet')

                cls.part_daemons.append(startDaemon(os.path.join(TEST_DIR, 'part_' + str(i)), cfg.PARTICL_BINDIR, cfg.PARTICLD))
                logging.info('Started %s %d', cfg.PARTICLD, cls.part_daemons[-1].handle.pid)

            if not cls.restore_instance:
                for i in range(NUM_NODES):
                    # Load mnemonics after all nodes have started to avoid staking getting stuck in TryToSync
                    rpc = make_rpc_func(i)
                    waitForRPC(rpc, test_delay_event)
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
                    rpc('reservebalance', [False])

            for i in range(NUM_BTC_NODES):
                if not cls.restore_instance:
                    data_dir = prepareDataDir(TEST_DIR, i, 'bitcoin.conf', 'btc_', base_p2p_port=BTC_BASE_PORT, base_rpc_port=BTC_BASE_RPC_PORT)
                    if os.path.exists(os.path.join(cfg.BITCOIN_BINDIR, 'bitcoin-wallet')):
                        try:
                            callrpc_cli(cfg.BITCOIN_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat -legacy create', 'bitcoin-wallet')
                        except Exception as e:
                            logging.warning('bitcoin-wallet create failed, retrying without -legacy')
                            callrpc_cli(cfg.BITCOIN_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'bitcoin-wallet')

                cls.btc_daemons.append(startDaemon(os.path.join(TEST_DIR, 'btc_' + str(i)), cfg.BITCOIN_BINDIR, cfg.BITCOIND))
                logging.info('Started %s %d', cfg.BITCOIND, cls.part_daemons[-1].handle.pid)

                waitForRPC(make_rpc_func(i, base_rpc_port=BTC_BASE_RPC_PORT), test_delay_event)

            if cls.start_ltc_nodes:
                for i in range(NUM_LTC_NODES):
                    if not cls.restore_instance:
                        data_dir = prepareDataDir(TEST_DIR, i, 'litecoin.conf', 'ltc_', base_p2p_port=LTC_BASE_PORT, base_rpc_port=LTC_BASE_RPC_PORT)
                        if os.path.exists(os.path.join(cfg.LITECOIN_BINDIR, 'litecoin-wallet')):
                            callrpc_cli(cfg.LITECOIN_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'litecoin-wallet')

                    cls.ltc_daemons.append(startDaemon(os.path.join(TEST_DIR, 'ltc_' + str(i)), cfg.LITECOIN_BINDIR, cfg.LITECOIND))
                    logging.info('Started %s %d', cfg.LITECOIND, cls.part_daemons[-1].handle.pid)

                    waitForRPC(make_rpc_func(i, base_rpc_port=LTC_BASE_RPC_PORT), test_delay_event)

            if cls.start_xmr_nodes:
                for i in range(NUM_XMR_NODES):
                    if not cls.restore_instance:
                        prepareXmrDataDir(TEST_DIR, i, 'monerod.conf')

                    node_dir = os.path.join(TEST_DIR, 'xmr_' + str(i))
                    cls.xmr_daemons.append(startXmrDaemon(node_dir, cfg.XMR_BINDIR, cfg.XMRD))
                    logging.info('Started %s %d', cfg.XMRD, cls.xmr_daemons[-1].handle.pid)
                    waitForXMRNode(i)

                    opts = [
                        '--daemon-address=127.0.0.1:{}'.format(XMR_BASE_RPC_PORT + i),
                        '--no-dns',
                        '--rpc-bind-port={}'.format(XMR_BASE_WALLET_RPC_PORT + i),
                        '--wallet-dir={}'.format(os.path.join(node_dir, 'wallets')),
                        '--log-file={}'.format(os.path.join(node_dir, 'wallet.log')),
                        '--rpc-login=test{0}:test_pass{0}'.format(i),
                        '--shared-ringdb-dir={}'.format(os.path.join(node_dir, 'shared-ringdb')),
                        '--allow-mismatched-daemon-version',
                    ]
                    cls.xmr_daemons.append(startXmrWalletDaemon(node_dir, cfg.XMR_BINDIR, cfg.XMR_WALLET_RPC, opts=opts))

                for i in range(NUM_XMR_NODES):
                    cls.xmr_wallet_auth.append(('test{0}'.format(i), 'test_pass{0}'.format(i)))
                    logging.info('Creating XMR wallet %i', i)

                    waitForXMRWallet(i, cls.xmr_wallet_auth[i])

                    if not cls.restore_instance:
                        cls.callxmrnodewallet(cls, i, 'create_wallet', {'filename': 'testwallet', 'language': 'English'})
                    cls.callxmrnodewallet(cls, i, 'open_wallet', {'filename': 'testwallet'})

            for i in range(NUM_NODES):
                # Hook for descendant classes
                cls.prepareExtraDataDir(i)

            logging.info('Preparing swap clients.')
            if not cls.restore_instance:
                eckey = ECKey()
                eckey.generate()
                cls.network_key = toWIF(PREFIX_SECRET_KEY_REGTEST, eckey.get_bytes())
                cls.network_pubkey = eckey.get_pubkey().get_bytes().hex()

            for i in range(NUM_NODES):
                start_nodes = set()
                if cls.start_ltc_nodes:
                    start_nodes.add(Coins.LTC)
                if cls.start_xmr_nodes:
                    start_nodes.add(Coins.XMR)
                if not cls.restore_instance:
                    prepare_swapclient_dir(TEST_DIR, i, cls.network_key, cls.network_pubkey, start_nodes, cls)
                basicswap_dir = os.path.join(os.path.join(TEST_DIR, 'basicswap_' + str(i)))
                settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
                with open(settings_path) as fs:
                    settings = json.load(fs)
                    if cls.restore_instance and i == 1:
                        cls.network_key = settings['network_key']
                        cls.network_pubkey = settings['network_pubkey']
                fp = open(os.path.join(basicswap_dir, 'basicswap.log'), 'w')
                sc = BasicSwap(fp, basicswap_dir, settings, 'regtest', log_name='BasicSwap{}'.format(i))
                cls.swap_clients.append(sc)
                sc.setDaemonPID(Coins.BTC, cls.btc_daemons[i].handle.pid)
                sc.setDaemonPID(Coins.PART, cls.part_daemons[i].handle.pid)

                if cls.start_ltc_nodes:
                    sc.setDaemonPID(Coins.LTC, cls.ltc_daemons[i].handle.pid)
                cls.addPIDInfo(sc, i)

                sc.start()
                if cls.start_xmr_nodes:
                    # Set XMR main wallet address
                    xmr_ci = sc.ci(Coins.XMR)
                    sc.setStringKV('main_wallet_addr_' + xmr_ci.coin_name().lower(), xmr_ci.getMainWalletAddress())

                t = HttpThread(sc.fp, TEST_HTTP_HOST, TEST_HTTP_PORT + i, False, sc)
                cls.http_threads.append(t)
                t.start()
            # Set future block rewards to nowhere (a random address), so wallet amounts stay constant
            void_block_rewards_pubkey = cls.getRandomPubkey()
            if cls.restore_instance:
                cls.btc_addr = cls.swap_clients[0].ci(Coins.BTC).pubkey_to_segwit_address(void_block_rewards_pubkey)
                if cls.start_ltc_nodes:
                    cls.ltc_addr = cls.swap_clients[0].ci(Coins.LTC).pubkey_to_address(void_block_rewards_pubkey)
                if cls.start_xmr_nodes:
                    cls.xmr_addr = cls.callxmrnodewallet(cls, 1, 'get_address')['address']
            else:
                cls.btc_addr = callnoderpc(0, 'getnewaddress', ['mining_addr', 'bech32'], base_rpc_port=BTC_BASE_RPC_PORT)
                num_blocks = 400  # Mine enough to activate segwit
                logging.info('Mining %d Bitcoin blocks to %s', num_blocks, cls.btc_addr)
                callnoderpc(0, 'generatetoaddress', [num_blocks, cls.btc_addr], base_rpc_port=BTC_BASE_RPC_PORT)

                btc_addr1 = callnoderpc(1, 'getnewaddress', ['initial addr'], base_rpc_port=BTC_BASE_RPC_PORT)
                for i in range(5):
                    callnoderpc(0, 'sendtoaddress', [btc_addr1, 100], base_rpc_port=BTC_BASE_RPC_PORT)

                # Switch addresses so wallet amounts stay constant
                num_blocks = 100
                cls.btc_addr = cls.swap_clients[0].ci(Coins.BTC).pubkey_to_segwit_address(void_block_rewards_pubkey)
                logging.info('Mining %d Bitcoin blocks to %s', num_blocks, cls.btc_addr)
                callnoderpc(0, 'generatetoaddress', [num_blocks, cls.btc_addr], base_rpc_port=BTC_BASE_RPC_PORT)

                major_version = int(str(callnoderpc(0, 'getnetworkinfo', base_rpc_port=BTC_BASE_RPC_PORT)['version'])[:2])
                if major_version >= 23:
                    checkForks(callnoderpc(0, 'getdeploymentinfo', base_rpc_port=BTC_BASE_RPC_PORT))
                else:
                    checkForks(callnoderpc(0, 'getblockchaininfo', base_rpc_port=BTC_BASE_RPC_PORT))

                if cls.start_ltc_nodes:
                    num_blocks = 400
                    cls.ltc_addr = callnoderpc(0, 'getnewaddress', ['mining_addr', 'bech32'], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')
                    logging.info('Mining %d Litecoin blocks to %s', num_blocks, cls.ltc_addr)
                    callnoderpc(0, 'generatetoaddress', [num_blocks, cls.ltc_addr], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')

                    num_blocks = 31
                    cls.ltc_addr = cls.swap_clients[0].ci(Coins.LTC).pubkey_to_address(void_block_rewards_pubkey)
                    logging.info('Mining %d Litecoin blocks to %s', num_blocks, cls.ltc_addr)
                    callnoderpc(0, 'generatetoaddress', [num_blocks, cls.ltc_addr], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')

                    # https://github.com/litecoin-project/litecoin/issues/807
                    # Block 432 is when MWEB activates. It requires a peg-in. You'll need to generate an mweb address and send some coins to it. Then it will allow you to mine the next block.
                    mweb_addr = callnoderpc(2, 'getnewaddress', ['mweb_addr', 'mweb'], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')
                    callnoderpc(0, 'sendtoaddress', [mweb_addr, 1], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')

                    ltc_addr1 = callnoderpc(1, 'getnewaddress', ['initial addr'], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')
                    for i in range(5):
                        callnoderpc(0, 'sendtoaddress', [ltc_addr1, 100], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')

                    num_blocks = 69
                    cls.ltc_addr = cls.swap_clients[0].ci(Coins.LTC).pubkey_to_address(void_block_rewards_pubkey)
                    callnoderpc(0, 'generatetoaddress', [num_blocks, cls.ltc_addr], base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat')

                    checkForks(callnoderpc(0, 'getblockchaininfo', base_rpc_port=LTC_BASE_RPC_PORT, wallet='wallet.dat'))

                num_blocks = 100
                if cls.start_xmr_nodes:
                    cls.xmr_addr = cls.callxmrnodewallet(cls, 1, 'get_address')['address']
                    if callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'] < num_blocks:
                        logging.info('Mining %d Monero blocks to %s.', num_blocks, cls.xmr_addr)
                        callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': num_blocks})
                    logging.info('XMR blocks: %d', callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'get_block_count')['count'])

                logging.info('Adding anon outputs')
                outputs = []
                for i in range(8):
                    sx_addr = callnoderpc(1, 'getnewstealthaddress')
                    outputs.append({'address': sx_addr, 'amount': 0.5})
                for i in range(7):
                    callnoderpc(0, 'sendtypeto', ['part', 'anon', outputs])

                part_addr1 = callnoderpc(1, 'getnewaddress', ['initial addr'])
                part_addr2 = callnoderpc(1, 'getnewaddress', ['initial addr 2'])
                callnoderpc(0, 'sendtypeto', ['part', 'part', [{'address': part_addr1, 'amount': 100}, {'address': part_addr2, 'amount': 100}]])

            cls.prepareExtraCoins()

            logging.info('Starting update thread.')
            signal.signal(signal.SIGINT, signal_handler)
            cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
            cls.update_thread.start()

            pause_event.set()
            cls.coins_update_thread = threading.Thread(target=run_coins_loop, args=(cls,))
            cls.coins_update_thread.start()

        except Exception:
            traceback.print_exc()
            cls.tearDownClass()
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
        logging.info('Stopping swap clients')
        for c in cls.swap_clients:
            c.finalise()
            c.fp.close()

        logging.info('Stopping coin nodes')
        stopDaemons(cls.xmr_daemons)
        stopDaemons(cls.part_daemons)
        stopDaemons(cls.btc_daemons)
        stopDaemons(cls.ltc_daemons)

        cls.http_threads.clear()
        cls.swap_clients.clear()
        cls.part_daemons.clear()
        cls.btc_daemons.clear()
        cls.ltc_daemons.clear()
        cls.xmr_daemons.clear()

        super(BaseTest, cls).tearDownClass()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        pass

    @classmethod
    def prepareExtraDataDir(cls, i):
        pass

    @classmethod
    def addPIDInfo(cls, sc, i):
        pass

    @classmethod
    def prepareExtraCoins(cls):
        pass

    @classmethod
    def coins_loop(cls):
        if cls.btc_addr is not None:
            btcCli('generatetoaddress 1 {}'.format(cls.btc_addr))
        if cls.ltc_addr is not None:
            ltcCli('generatetoaddress 1 {}'.format(cls.ltc_addr))
        if cls.xmr_addr is not None:
            callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': cls.xmr_addr, 'amount_of_blocks': 1})

    @classmethod
    def waitForParticlHeight(cls, num_blocks, node_id=0):
        logging.info(f'Waiting for Particl chain height {num_blocks}', )
        for i in range(60):
            if test_delay_event.is_set():
                raise ValueError('Test stopped.')
            particl_blocks = callnoderpc(0, 'getblockcount')
            print('particl_blocks', particl_blocks)
            if particl_blocks >= num_blocks:
                break
            test_delay_event.wait(1)
        logging.info('PART blocks: %d', callnoderpc(0, 'getblockcount'))
        assert particl_blocks >= num_blocks

    def callxmrnodewallet(self, node_id, method, params=None):
        return callrpc_xmr(XMR_BASE_WALLET_RPC_PORT + node_id, method, params, auth=self.xmr_wallet_auth[node_id])

    def getXmrBalance(self, js_wallets):
        return float(js_wallets[Coins.XMR.name]['unconfirmed']) + float(js_wallets[Coins.XMR.name]['balance'])

    def prepare_balance(self, coin, amount: float, port_target_node: int, port_take_from_node: int, test_balance: bool = True) -> None:
        delay_iterations = 100 if coin == Coins.NAV else 20
        delay_time = 5 if coin == Coins.NAV else 3
        if coin == Coins.PART_BLIND:
            coin_ticker: str = 'PART'
            balance_type: str = 'blind_balance'
            address_type: str = 'stealth_address'
            type_to: str = 'blind'
        elif coin == Coins.PART_ANON:
            coin_ticker: str = 'PART'
            balance_type: str = 'anon_balance'
            address_type: str = 'stealth_address'
            type_to: str = 'anon'
        else:
            coin_ticker: str = coin.name
            balance_type: str = 'balance'
            address_type: str = 'deposit_address'
        js_w = read_json_api(port_target_node, 'wallets')
        current_balance: float = float(js_w[coin_ticker][balance_type])

        if test_balance and current_balance >= amount:
            return
        post_json = {
            'value': amount,
            'address': js_w[coin_ticker][address_type],
            'subfee': False,
        }
        if coin in (Coins.XMR, Coins.WOW):
            post_json['sweepall'] = False
        if coin in (Coins.PART_BLIND, Coins.PART_ANON):
            post_json['type_to'] = type_to
        json_rv = read_json_api(port_take_from_node, 'wallets/{}/withdraw'.format(coin_ticker.lower()), post_json)
        assert (len(json_rv['txid']) == 64)
        wait_for_amount: float = amount
        if not test_balance:
            wait_for_amount += current_balance
        wait_for_balance(test_delay_event, 'http://127.0.0.1:{}/json/wallets/{}'.format(port_target_node, coin_ticker.lower()), balance_type, wait_for_amount, iterations=delay_iterations, delay_time=delay_time)


class Test(BaseTest):
    __test__ = True

    def notest_00_delay(self):
        test_delay_event.wait(100000)

    def test_010_txn_size(self):
        logging.info('---------- Test {} txn_size'.format(Coins.PART))

        swap_clients = self.swap_clients
        ci = swap_clients[0].ci(Coins.PART)
        pi = swap_clients[0].pi(SwapTypes.XMR_SWAP)

        amount: int = ci.make_int(random.uniform(0.1, 2.0), r=1)

        # Record unspents before createSCLockTx as the used ones will be locked
        unspents = ci.rpc('listunspent')

        # fee_rate is in sats/kvB
        fee_rate: int = 1000

        a = ci.getNewSecretKey()
        b = ci.getNewSecretKey()

        A = ci.getPubkey(a)
        B = ci.getPubkey(b)
        lock_tx_script = pi.genScriptLockTxScript(ci, A, B)

        lock_tx = ci.createSCLockTx(amount, lock_tx_script)
        lock_tx = ci.fundSCLockTx(lock_tx, fee_rate)
        lock_tx = ci.signTxWithWallet(lock_tx)

        unspents_after = ci.rpc('listunspent')
        assert (len(unspents) > len(unspents_after))

        tx_decoded = ci.rpc('decoderawtransaction', [lock_tx.hex()])
        txid = tx_decoded['txid']

        vsize = tx_decoded['vsize']
        expect_fee_int = round(fee_rate * vsize / 1000)
        expect_fee = ci.format_amount(expect_fee_int)

        out_value: int = 0
        for txo in tx_decoded['vout']:
            if 'value' in txo:
                out_value += ci.make_int(txo['value'])
        in_value: int = 0
        for txi in tx_decoded['vin']:
            for utxo in unspents:
                if 'vout' not in utxo:
                    continue
                if utxo['txid'] == txi['txid'] and utxo['vout'] == txi['vout']:
                    in_value += ci.make_int(utxo['amount'])
                    break
        fee_value = in_value - out_value

        ci.rpc('sendrawtransaction', [lock_tx.hex()])
        rv = ci.rpc('gettransaction', [txid])
        wallet_tx_fee = -ci.make_int(rv['fee'])

        assert (wallet_tx_fee == fee_value)
        assert (wallet_tx_fee == expect_fee_int)

        addr_out = ci.getNewAddress(True)
        pkh_out = ci.decodeAddress(addr_out)
        fee_info = {}
        lock_spend_tx = ci.createSCLockSpendTx(lock_tx, lock_tx_script, pkh_out, fee_rate, fee_info=fee_info)
        vsize_estimated: int = fee_info['vsize']

        tx_decoded = ci.rpc('decoderawtransaction', [lock_spend_tx.hex()])
        txid = tx_decoded['txid']

        witness_stack = [
            b'',
            ci.signTx(a, lock_spend_tx, 0, lock_tx_script, amount),
            ci.signTx(b, lock_spend_tx, 0, lock_tx_script, amount),
            lock_tx_script,
        ]
        lock_spend_tx = ci.setTxSignature(lock_spend_tx, witness_stack)
        tx_decoded = ci.rpc('decoderawtransaction', [lock_spend_tx.hex()])
        vsize_actual: int = tx_decoded['vsize']

        assert (vsize_actual <= vsize_estimated and vsize_estimated - vsize_actual < 4)
        assert (ci.rpc('sendrawtransaction', [lock_spend_tx.hex()]) == txid)

        expect_vsize: int = ci.xmr_swap_a_lock_spend_tx_vsize()
        assert (expect_vsize >= vsize_actual)
        assert (expect_vsize - vsize_actual < 10)

        # Test chain b (no-script) lock tx size
        v = ci.getNewSecretKey()
        s = ci.getNewSecretKey()
        S = ci.getPubkey(s)
        lock_tx_b_txid = ci.publishBLockTx(v, S, amount, fee_rate)

        addr_out = ci.getNewAddress(True)
        lock_tx_b_spend_txid = ci.spendBLockTx(lock_tx_b_txid, addr_out, v, s, amount, fee_rate, 0)
        lock_tx_b_spend = ci.getTransaction(lock_tx_b_spend_txid)
        if lock_tx_b_spend is None:
            lock_tx_b_spend = ci.getWalletTransaction(lock_tx_b_spend_txid)
        lock_tx_b_spend_decoded = ci.rpc('decoderawtransaction', [lock_tx_b_spend.hex()])

        expect_vsize: int = ci.xmr_swap_b_lock_spend_tx_vsize()
        assert (expect_vsize >= lock_tx_b_spend_decoded['vsize'])
        assert (expect_vsize - lock_tx_b_spend_decoded['vsize'] < 10)

    def test_010_xmr_txn_size(self):
        logging.info('---------- Test {} txn_size'.format(Coins.XMR))

        swap_clients = self.swap_clients
        ci = swap_clients[1].ci(Coins.XMR)
        pi = swap_clients[1].pi(SwapTypes.XMR_SWAP)

        amount: int = ci.make_int(random.uniform(0.1, 2.0), r=1)
        fee_rate: int = 1000  # TODO: How to set feerate for rpc functions?

        v = ci.getNewSecretKey()
        s = ci.getNewSecretKey()
        S = ci.getPubkey(s)
        lock_tx_b_txid = ci.publishBLockTx(v, S, amount, fee_rate)

        addr_out = ci.getNewAddress(True)
        for i in range(20):
            try:
                lock_tx_b_spend_txid = ci.spendBLockTx(lock_tx_b_txid, addr_out, v, s, amount, fee_rate, 0)
                break
            except Exception as e:
                if isinstance(e, TemporaryError):
                    continue
                else:
                    raise (e)
                test_delay_event.wait(1)

        lock_tx_b_spend = ci.getTransaction(lock_tx_b_spend_txid)

        actual_size: int = len(lock_tx_b_spend['txs_as_hex'][0]) // 2
        expect_size: int = ci.xmr_swap_b_lock_spend_tx_vsize()
        assert (expect_size >= actual_size)
        assert (expect_size - actual_size < 100)  # TODO

    def test_011_smsgaddresses(self):
        logging.info('---------- Test address management and private offers')
        swap_clients = self.swap_clients
        js_1 = read_json_api(1801, 'smsgaddresses')

        post_json = {
            'addressnote': 'testing',
        }
        json_rv = read_json_api(1801, 'smsgaddresses/new', post_json)
        new_address = json_rv['new_address']
        new_address_pk = json_rv['pubkey']

        js_2 = read_json_api(1801, 'smsgaddresses')
        assert (len(js_2) == len(js_1) + 1)
        found = False
        for addr in js_2:
            if addr['addr'] == new_address:
                assert (addr['note'] == 'testing')
                found = True
        assert (found is True)

        found = False
        lks = callnoderpc(1, 'smsglocalkeys')
        for key in lks['wallet_keys']:
            if key['address'] == new_address:
                assert (key['receive'] == '1')
                found = True
        assert (found is True)

        # Disable
        post_json = {
            'address': new_address,
            'addressnote': 'testing2',
            'active_ind': '0',
        }
        json_rv = read_json_api(1801, 'smsgaddresses/edit', post_json)
        assert (json_rv['edited_address'] == new_address)

        js_3 = read_json_api(1801, 'smsgaddresses')
        assert (len(js_3) == 0)

        post_json = {
            'exclude_inactive': False,
        }
        js_3 = read_json_api(1801, 'smsgaddresses', post_json)
        found = False
        for addr in js_3:
            if addr['addr'] == new_address:
                assert (addr['note'] == 'testing2')
                assert (addr['active_ind'] == 0)
                found = True
        assert (found is True)

        found = False
        lks = callnoderpc(1, 'smsglocalkeys')
        for key in lks['wallet_keys']:
            if key['address'] == new_address:
                found = True
        assert (found is False)

        # Re-enable
        post_json = {
            'address': new_address,
            'active_ind': '1',
        }
        json_rv = read_json_api(1801, 'smsgaddresses/edit', post_json)
        assert (json_rv['edited_address'] == new_address)

        found = False
        lks = callnoderpc(1, 'smsglocalkeys')
        for key in lks['wallet_keys']:
            if key['address'] == new_address:
                assert (key['receive'] == '1')
                found = True
        assert (found is True)

        post_json = {
            'addresspubkey': new_address_pk,
            'addressnote': 'testing_add_addr',
        }
        json_rv = read_json_api(1800, 'smsgaddresses/add', post_json)
        assert (json_rv['added_address'] == new_address)

        post_json = {
            'addr_to': new_address,
            'addr_from': -1,
            'coin_from': 1,
            'coin_to': 6,
            'amt_from': 1,
            'amt_to': 1,
            'lockhrs': 24}
        rv = read_json_api(1800, 'offers/new', post_json)
        offer_id_hex = rv['offer_id']

        wait_for_offer(test_delay_event, swap_clients[1], bytes.fromhex(offer_id_hex))

        rv = read_json_api(1801, f'offers/{offer_id_hex}')
        assert (rv[0]['addr_to'] == new_address)

        rv = read_json_api(1800, f'offers/{offer_id_hex}')
        assert (rv[0]['addr_to'] == new_address)

        # Disable all
        json_rv = read_json_api(1800, 'smsgaddresses/disableall')
        assert (json_rv['num_disabled'] >= 1)

    def test_01_part_xmr(self):
        logging.info('---------- Test PART to XMR')
        swap_clients = self.swap_clients

        start_xmr_amount = self.getXmrBalance(read_json_api(1800, 'wallets'))
        js_1 = read_json_api(1801, 'wallets')
        assert (self.getXmrBalance(js_1) > 0.0)

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, 100 * COIN, 0.11 * XMR_COIN, 100 * COIN, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        assert (len(offers) == 1)
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        js_0_end = read_json_api(1800, 'wallets')
        end_xmr_amount = self.getXmrBalance(js_0_end)
        xmr_amount_diff = end_xmr_amount - start_xmr_amount
        assert (xmr_amount_diff > 10.9 and xmr_amount_diff < 11.0)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        offerer_states = read_json_api(1800, path)
        bidder_states = read_json_api(1801, path)

        assert (compare_bid_states(offerer_states, self.states_offerer[0]) is True)
        assert (compare_bid_states(bidder_states, self.states_bidder[0]) is True)

        # Test remove_expired_data
        remove_expired_data(swap_clients[0], -swap_clients[0]._expire_db_records_after * 2)
        offers = swap_clients[0].listOffers(filters={'offer_id': offer_id})
        assert (len(offers) == 0)

    def test_02_leader_recover_a_lock_tx(self):
        logging.info('---------- Test PART to XMR leader recovers coin a lock tx')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.12 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=12)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, [BidStates.BID_STALLED_FOR_TEST, BidStates.XMR_SWAP_FAILED], sent=True)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        offerer_states = read_json_api(1800, path)

        assert (compare_bid_states(offerer_states, self.states_offerer[1]) is True)

    def test_03_follower_recover_a_lock_tx(self):
        logging.info('---------- Test PART to XMR follower recovers coin a lock tx')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.13 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=16)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[0].setBidDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_STALLED_FOR_TEST, wait_for=220)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_SWIPED, wait_for=80, sent=True)

        wait_for_none_active(test_delay_event, 1800)
        wait_for_none_active(test_delay_event, 1801)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        bidder_states = read_json_api(1801, path)

        bidder_states = [s for s in bidder_states if s[1] != 'Bid Stalled (debug)']
        assert (compare_bid_states(bidder_states, self.states_bidder[2]) is True)

    def test_04_follower_recover_b_lock_tx(self):
        logging.info('---------- Test PART to XMR follower recovers coin b lock tx')

        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PART, Coins.XMR, 101 * COIN, 0.14 * XMR_COIN, 101 * COIN, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=28)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

        bid_id_hex = bid_id.hex()
        path = f'bids/{bid_id_hex}/states'
        offerer_states = read_json_api(1800, path)
        bidder_states = read_json_api(1801, path)

        assert (compare_bid_states(offerer_states, self.states_offerer[1]) is True)
        assert (compare_bid_states(bidder_states, self.states_bidder[1]) is True)

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
        assert (xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        swap_clients[1].ci(Coins.XMR).setFeePriority(0)

    def test_06_multiple_swaps(self):
        logging.info('---------- Test Multiple concurrent swaps')
        swap_clients = self.swap_clients

        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        amt_1 = make_int(random.uniform(0.001, 19.0), scale=8, r=1)
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

        js_w0_after = read_json_api(1800, 'wallets')
        js_w1_after = read_json_api(1801, 'wallets')
        assert (make_int(js_w1_after['BTC']['balance'], scale=8, r=1) - (make_int(js_w1_before['BTC']['balance'], scale=8, r=1) + amt_1) < 1000)

    def test_07_revoke_offer(self):
        logging.info('---------- Test offer revocaction')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)

        swap_clients[0].revokeOffer(offer_id)

        wait_for_no_offer(test_delay_event, swap_clients[1], offer_id)

    def test_08_withdraw(self):
        logging.info('---------- Test XMR withdrawals')
        swap_clients = self.swap_clients
        js_0 = read_json_api(1800, 'wallets')
        address_to = js_0[Coins.XMR.name]['deposit_address']

        js_1 = read_json_api(1801, 'wallets')
        assert (float(js_1[Coins.XMR.name]['balance']) > 0.0)

        post_json = {
            'value': 1.1,
            'address': address_to,
            'sweepall': False,
        }
        rv = read_json_api(1801, 'wallets/xmr/withdraw', post_json)
        assert (len(rv['txid']) == 64)

    def test_09_auto_accept(self):
        logging.info('---------- Test BTC to XMR auto accept')
        swap_clients = self.swap_clients
        amt_swap = make_int(random.uniform(0.01, 11.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(10.0, 101.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].listOffers(filters={'offer_id': offer_id})[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

    def test_09_1_auto_accept_multiple(self):
        logging.info('---------- Test BTC to XMR auto accept multiple bids')
        swap_clients = self.swap_clients
        amt_swap = make_int(10, scale=8, r=1)
        rate_swap = make_int(100, scale=12, r=1)
        min_bid = make_int(1, scale=8, r=1)

        extra_options = {
            'amount_negotiable': True,
            'automation_id': 1,
        }
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.XMR, amt_swap, rate_swap, min_bid, SwapTypes.XMR_SWAP, extra_options=extra_options)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].listOffers(filters={'offer_id': offer_id})[0]

        below_min_bid = min_bid - 1

        # Ensure bids below the minimum amount fails on sender and recipient.
        try:
            bid_id = swap_clients[1].postBid(offer_id, below_min_bid)
        except Exception as e:
            assert ('Bid amount below minimum' in str(e))
        extra_bid_options = {
            'debug_skip_validation': True,
        }
        bid_id = swap_clients[1].postBid(offer_id, below_min_bid, extra_options=extra_bid_options)

        event = wait_for_event(test_delay_event, swap_clients[0], Concepts.NETWORK_MESSAGE, bid_id)
        assert ('Bid amount below minimum' in event.event_msg)

        bid_ids = []
        for i in range(5):
            bid_ids.append(swap_clients[1].postBid(offer_id, min_bid))

        # Should fail > max concurrent
        test_delay_event.wait(1.0)
        bid_id = swap_clients[1].postBid(offer_id, min_bid)
        logging.info('Waiting for bid {} to fail.'.format(bid_id.hex()))
        event = wait_for_event(test_delay_event, swap_clients[0], Concepts.BID, bid_id, event_type=EventLogTypes.AUTOMATION_CONSTRAINT)
        assert ('Already have 5 bids to complete' in event.event_msg)

        for bid_id in bid_ids:
            wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=240)
            wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        amt_bid = make_int(5, scale=8, r=1)

        # Should fail > total value
        amt_bid += 1
        bid_id = swap_clients[1].postBid(offer_id, amt_bid)
        event = wait_for_event(test_delay_event, swap_clients[0], Concepts.BID, bid_id, event_type=EventLogTypes.AUTOMATION_CONSTRAINT)
        assert ('Over remaining offer value' in event.event_msg)

        # Should pass
        amt_bid -= 1
        bid_id = swap_clients[1].postBid(offer_id, amt_bid)
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
        assert (xmr_swap)

        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED, wait_for=180)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        try:
            swap_clients[0].ci(Coins.BTC).publishTx(xmr_swap.a_lock_refund_tx)
            assert (False), 'Lock refund tx should be locked'
        except Exception as e:
            assert ('non-BIP68-final' in str(e))

    def test_11_particl_anon(self):
        logging.info('---------- Test Particl anon transactions')
        swap_clients = self.swap_clients

        js_0 = read_json_api(1800, 'wallets/part')
        assert (float(js_0['anon_balance']) == 0.0)
        node0_anon_before = js_0['anon_balance'] + js_0['anon_pending']

        wait_for_balance(test_delay_event, 'http://127.0.0.1:1801/json/wallets/part', 'balance', 200.0)
        js_1 = read_json_api(1801, 'wallets/part')
        assert (float(js_1['balance']) > 200.0)
        node1_anon_before = js_1['anon_balance'] + js_1['anon_pending']

        callnoderpc(1, 'reservebalance', [True, 1000000])  # Stop staking to avoid conflicts (input used by tx->anon staked before tx gets in the chain)
        post_json = {
            'value': 100,
            'address': js_1['stealth_address'],
            'subfee': False,
            'type_to': 'anon',
        }
        json_rv = json.loads(post_json_req('http://127.0.0.1:1801/json/wallets/part/withdraw', post_json))
        assert (len(json_rv['txid']) == 64)

        logging.info('Waiting for anon balance')
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1801/json/wallets/part', 'anon_balance', 100.0 + node1_anon_before)
        js_1 = read_json_api(1801, 'wallets/part')
        node1_anon_before = js_1['anon_balance'] + js_1['anon_pending']

        callnoderpc(1, 'reservebalance', [False])
        post_json = {
            'value': 10,
            'address': js_0['stealth_address'],
            'subfee': True,
            'type_from': 'anon',
            'type_to': 'blind',
        }
        json_rv = json.loads(post_json_req('http://127.0.0.1:1801/json/wallets/part/withdraw', post_json))
        assert (len(json_rv['txid']) == 64)

        logging.info('Waiting for blind balance')
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1800/json/wallets/part', 'blind_balance', 9.8)
        if float(js_0['blind_balance']) >= 10.0:
            raise ValueError('Expect blind balance < 10')

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(2.0, 20.0), scale=8, r=1)
        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.PART_ANON, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[0].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)
        amount_to = float(format_amount(bid.amount_to, 8))

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        js_1 = read_json_api(1801, 'wallets/part')
        assert (js_1['anon_balance'] < node1_anon_before - amount_to)

        js_0 = read_json_api(1800, 'wallets/part')
        assert (js_0['anon_balance'] + js_0['anon_pending'] > node0_anon_before + (amount_to - 0.05))

        # Test chain b (no-script) lock tx size
        ci = swap_clients[1].ci(Coins.PART_ANON)
        pi = swap_clients[1].pi(SwapTypes.XMR_SWAP)
        amount: int = ci.make_int(random.uniform(0.1, 2.0), r=1)
        fee_rate: int = 1000
        v = ci.getNewSecretKey()
        s = ci.getNewSecretKey()
        S = ci.getPubkey(s)
        lock_tx_b_txid = ci.publishBLockTx(v, S, amount, fee_rate)

        addr_out = ci.getNewStealthAddress()
        lock_tx_b_spend_txid = None
        for i in range(20):
            try:
                lock_tx_b_spend_txid = ci.spendBLockTx(lock_tx_b_txid, addr_out, v, s, amount, fee_rate, 0)
                break
            except Exception as e:
                print('spendBLockTx failed', str(e))
            test_delay_event.wait(2)
        assert (lock_tx_b_spend_txid is not None)

        lock_tx_b_spend = ci.getTransaction(lock_tx_b_spend_txid)
        if lock_tx_b_spend is None:
            lock_tx_b_spend = ci.getWalletTransaction(lock_tx_b_spend_txid)
        lock_tx_b_spend_decoded = ci.rpc('decoderawtransaction', [lock_tx_b_spend.hex()])

        expect_vsize: int = ci.xmr_swap_b_lock_spend_tx_vsize()
        assert (expect_vsize >= lock_tx_b_spend_decoded['vsize'])
        assert (expect_vsize - lock_tx_b_spend_decoded['vsize'] < 10)

    def test_12_particl_blind(self):
        logging.info('---------- Test Particl blind transactions')
        swap_clients = self.swap_clients

        js_0 = read_json_api(1800, 'wallets/part')
        node0_blind_before = js_0['blind_balance'] + js_0['blind_unconfirmed']

        wait_for_balance(test_delay_event, 'http://127.0.0.1:1801/json/wallets/part', 'balance', 200.0)
        js_1 = read_json_api(1801, 'wallets/part')
        assert (float(js_1['balance']) > 200.0)
        node1_blind_before = js_1['blind_balance'] + js_1['blind_unconfirmed']

        post_json = {
            'value': 100,
            'address': js_0['stealth_address'],
            'subfee': False,
            'type_to': 'blind',
        }
        json_rv = json.loads(post_json_req('http://127.0.0.1:1800/json/wallets/part/withdraw', post_json))
        assert (len(json_rv['txid']) == 64)

        logging.info('Waiting for blind balance')
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1800/json/wallets/part', 'blind_balance', 100.0 + node0_blind_before)
        js_0 = read_json_api(1800, 'wallets/part')
        node0_blind_before = js_0['blind_balance'] + js_0['blind_unconfirmed']

        coin_from = Coins.PART_BLIND
        coin_to = Coins.XMR
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)
        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[0].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        amount_from = float(format_amount(amt_swap, 8))
        js_1 = read_json_api(1801, 'wallets/part')
        node1_blind_after = js_1['blind_balance'] + js_1['blind_unconfirmed']
        assert (node1_blind_after > node1_blind_before + (amount_from - 0.05))

        js_0 = read_json_api(1800, 'wallets/part')
        node0_blind_after = js_0['blind_balance'] + js_0['blind_unconfirmed']
        assert (node0_blind_after < node0_blind_before - amount_from)

    def test_13_locked_xmr(self):
        logging.info('---------- Test PART to XMR leader recovers coin a lock tx')
        swap_clients = self.swap_clients

        amt_swap = make_int(random.uniform(0.1, 10.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(2.0, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.SEND_LOCKED_XMR)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_event(test_delay_event, swap_clients[0], Concepts.BID, bid_id, event_type=EventLogTypes.LOCK_TX_B_INVALID, wait_for=180)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED, sent=True)

        swap_clients[0].abandonBid(bid_id)
        swap_clients[1].abandonBid(bid_id)

    def test_14_sweep_balance(self):
        logging.info('---------- Test sweep balance offer')
        swap_clients = self.swap_clients

        # Disable staking
        walletsettings = callnoderpc(2, 'walletsettings', ['stakingoptions', ])
        walletsettings['enabled'] = False
        walletsettings = callnoderpc(2, 'walletsettings', ['stakingoptions', walletsettings])
        walletsettings = callnoderpc(2, 'walletsettings', ['stakingoptions', ])
        assert (walletsettings['stakingoptions']['enabled'] is False)

        # Prepare balance
        js_w2 = read_json_api(1802, 'wallets')
        if float(js_w2['PART']['balance']) < 100.0:
            post_json = {
                'value': 100,
                'address': js_w2['PART']['deposit_address'],
                'subfee': False,
            }
            json_rv = read_json_api(TEST_HTTP_PORT + 0, 'wallets/part/withdraw', post_json)
            assert (len(json_rv['txid']) == 64)
            wait_for_balance(test_delay_event, 'http://127.0.0.1:1802/json/wallets/part', 'balance', 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        assert (float(js_w2['PART']['balance']) >= 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        post_json = {
            'value': float(js_w2['PART']['balance']),
            'address': read_json_api(1802, 'wallets/part/nextdepositaddr'),
            'subfee': True,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 2, 'wallets/part/withdraw', post_json)
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1802/json/wallets/part', 'balance', 10.0)
        assert (len(json_rv['txid']) == 64)

        # Create prefunded ITX
        ci = swap_clients[2].ci(Coins.PART)
        pi = swap_clients[2].pi(SwapTypes.XMR_SWAP)
        js_w2 = read_json_api(1802, 'wallets')
        swap_value = ci.make_int(js_w2['PART']['balance'])

        itx = pi.getFundedInitiateTxTemplate(ci, swap_value, True)
        itx_decoded = ci.describeTx(itx.hex())
        n = pi.findMockVout(ci, itx_decoded)
        value_after_subfee = ci.make_int(itx_decoded['vout'][n]['value'])
        assert (value_after_subfee < swap_value)
        swap_value = value_after_subfee
        wait_for_unspent(test_delay_event, ci, swap_value)

        extra_options = {'prefunded_itx': itx}
        offer_id = swap_clients[2].postOffer(Coins.PART, Coins.XMR, swap_value, 2 * COIN, swap_value, SwapTypes.XMR_SWAP, extra_options=extra_options)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.BID_RECEIVED)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

        # Verify expected inputs were used
        bid, _, _, _, _ = swap_clients[2].getXmrBidAndOffer(bid_id)
        assert (bid.xmr_a_lock_tx)
        wtx = ci.rpc('gettransaction', [bid.xmr_a_lock_tx.txid.hex(),])
        itx_after = ci.describeTx(wtx['hex'])
        assert (len(itx_after['vin']) == len(itx_decoded['vin']))
        for i, txin in enumerate(itx_decoded['vin']):
            assert (txin['txid'] == itx_after['vin'][i]['txid'])
            assert (txin['vout'] == itx_after['vin'][i]['vout'])

    def test_15_missed_xmr_send(self):
        logging.info('---------- Test PART to XMR B lock tx is lost')
        swap_clients = self.swap_clients

        amt_swap = make_int(random.uniform(0.1, 10.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(2.0, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
                                             lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=28)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.B_LOCK_TX_MISSED_SEND)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=1800)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=30, sent=True)

    def test_16_new_subaddress(self):
        logging.info('---------- Test that new subaddresses are created')

        current_subaddress = read_json_api(1800, 'wallets/xmr')['deposit_address']
        first_subaddress = read_json_api(1800, 'wallets/xmr/nextdepositaddr')
        second_subaddress = read_json_api(1800, 'wallets/xmr/nextdepositaddr')
        assert (first_subaddress != second_subaddress)
        assert (first_subaddress != current_subaddress)
        assert (second_subaddress != current_subaddress)

    def test_17_edit_bid_state(self):
        logging.info('---------- Test manually changing the state of a bid')
        # Stall the bid by setting a debug token.  Once it's stalled, clear the debug token and fix the bid state.
        swap_clients = self.swap_clients

        amt_swap = make_int(random.uniform(0.1, 10.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(2.0, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        bid_id = swap_clients[1].postXmrBid(offer_id, amt_swap)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.BID_STALLED_FOR_TEST, sent=True, wait_for=90)
        data = {
            'debug_ind': int(DebugTypes.NONE),
            'bid_state': int(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX),
        }
        swap_clients[1].manualBidUpdate(bid_id, data)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

    def test_97_withdraw_all(self):
        logging.info('---------- Test XMR withdrawal all')

        wait_for_balance(test_delay_event, 'http://127.0.0.1:1800/json/wallets/xmr', 'unconfirmed', 0.0)
        wallets0 = read_json_api(TEST_HTTP_PORT + 0, 'wallets')
        xmr_total = float(wallets0[Coins.XMR.name]['balance'])

        if xmr_total < 10.0:
            address_to = read_json_api(1800, 'wallets')[Coins.XMR.name]['deposit_address']
            post_json = {
                'value': 10.0,
                'address': address_to,
                'sweepall': False,
            }
            json_rv = read_json_api(TEST_HTTP_PORT + 1, 'wallets/xmr/withdraw', post_json)
            wait_for_balance(test_delay_event, 'http://127.0.0.1:1800/json/wallets/xmr', 'balance', 10.0)

        post_json = {
            'address': read_json_api(1801, 'wallets')[Coins.XMR.name]['deposit_address'],
            'sweepall': True,
        }
        json_rv = json.loads(post_json_req('http://127.0.0.1:{}/json/wallets/xmr/withdraw'.format(TEST_HTTP_PORT + 0), post_json))
        assert (len(json_rv['txid']) == 64)

        try:
            logging.info('Disabling XMR mining')
            pause_event.clear()

            address_to = read_json_api(1800, 'wallets')[Coins.XMR.name]['deposit_address']

            wallets1 = read_json_api(TEST_HTTP_PORT + 1, 'wallets')
            xmr_total = float(wallets1[Coins.XMR.name]['balance'])
            assert (xmr_total > 10)

            post_json = {
                'address': address_to,
                'sweepall': True,
            }
            json_rv = json.loads(post_json_req('http://127.0.0.1:{}/json/wallets/xmr/withdraw'.format(TEST_HTTP_PORT + 1), post_json))
            assert ('Balance must be fully confirmed to use sweep all' in json_rv['error'])
        finally:
            logging.info('Restoring XMR mining')
            pause_event.set()


if __name__ == '__main__':
    unittest.main()
