#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/basicswap/extended/test_dash.py

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

import basicswap.config as cfg
from basicswap.basicswap import (
    BasicSwap,
    Coins,
    TxStates,
    SwapTypes,
    BidStates,
    DebugTypes,
)
from basicswap.util import (
    COIN,
)
from basicswap.basicswap_util import (
    TxLockTypes,
)
from basicswap.util.address import (
    toWIF,
)
from basicswap.rpc import (
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
    checkForks,
    stopDaemons,
    wait_for_offer,
    wait_for_bid,
    wait_for_balance,
    wait_for_unspent,
    wait_for_bid_tx_state,
    wait_for_in_progress,
    TEST_HTTP_HOST,
    TEST_HTTP_PORT,
    BASE_PORT,
    BASE_RPC_PORT,
    BASE_ZMQ_PORT,
    PREFIX_SECRET_KEY_REGTEST,
    waitForRPC,
)
from basicswap.bin.run import startDaemon


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

NUM_NODES = 3
DASH_NODE = 3
BTC_NODE = 4

delay_event = threading.Event()
stop_test = False

DASH_BINDIR = os.path.expanduser(os.getenv('DASH_BINDIR', os.path.join(cfg.DEFAULT_TEST_BINDIR, 'dash')))
DASHD = os.getenv('DASHD', 'dashd' + cfg.bin_suffix)
DASH_CLI = os.getenv('DASH_CLI', 'dash-cli' + cfg.bin_suffix)
DASH_TX = os.getenv('DASH_TX', 'dash-tx' + cfg.bin_suffix)


def prepareOtherDir(datadir, nodeId, conf_file='dash.conf'):
    node_dir = os.path.join(datadir, str(nodeId))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    filePath = os.path.join(node_dir, conf_file)

    with open(filePath, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('[regtest]\n')
        fp.write('port=' + str(BASE_PORT + nodeId) + '\n')
        fp.write('rpcport=' + str(BASE_RPC_PORT + nodeId) + '\n')

        fp.write('daemon=0\n')
        fp.write('printtoconsole=0\n')
        fp.write('server=1\n')
        fp.write('discover=0\n')
        fp.write('listenonion=0\n')
        fp.write('bind=127.0.0.1\n')
        fp.write('findpeers=0\n')
        fp.write('debug=1\n')
        fp.write('debugexclude=libevent\n')

        fp.write('fallbackfee=0.01\n')
        fp.write('acceptnonstdtxn=0\n')

        if conf_file == 'bitcoin.conf':
            fp.write('wallet=wallet.dat\n')


def prepareDir(datadir, nodeId, network_key, network_pubkey):
    node_dir = os.path.join(datadir, str(nodeId))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    filePath = os.path.join(node_dir, 'particl.conf')

    with open(filePath, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('[regtest]\n')
        fp.write('port=' + str(BASE_PORT + nodeId) + '\n')
        fp.write('rpcport=' + str(BASE_RPC_PORT + nodeId) + '\n')

        fp.write('daemon=0\n')
        fp.write('printtoconsole=0\n')
        fp.write('server=1\n')
        fp.write('discover=0\n')
        fp.write('listenonion=0\n')
        fp.write('bind=127.0.0.1\n')
        fp.write('findpeers=0\n')
        fp.write('debug=1\n')
        fp.write('debugexclude=libevent\n')
        fp.write('zmqpubsmsg=tcp://127.0.0.1:' + str(BASE_ZMQ_PORT + nodeId) + '\n')
        fp.write('wallet=wallet.dat\n')
        fp.write('fallbackfee=0.01\n')

        fp.write('acceptnonstdtxn=0\n')
        fp.write('minstakeinterval=5\n')
        fp.write('smsgsregtestadjust=0\n')

        for i in range(0, NUM_NODES):
            if nodeId == i:
                continue
            fp.write('addnode=127.0.0.1:%d\n' % (BASE_PORT + i))

        if nodeId < 2:
            fp.write('spentindex=1\n')
            fp.write('txindex=1\n')

    basicswap_dir = os.path.join(datadir, str(nodeId), 'basicswap')
    if not os.path.exists(basicswap_dir):
        os.makedirs(basicswap_dir)

    dashdatadir = os.path.join(datadir, str(DASH_NODE))
    btcdatadir = os.path.join(datadir, str(BTC_NODE))
    settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
    settings = {
        'debug': True,
        'zmqhost': 'tcp://127.0.0.1',
        'zmqport': BASE_ZMQ_PORT + nodeId,
        'htmlhost': '127.0.0.1',
        'htmlport': 12700 + nodeId,
        'network_key': network_key,
        'network_pubkey': network_pubkey,
        'chainclients': {
            'particl': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': BASE_RPC_PORT + nodeId,
                'datadir': node_dir,
                'bindir': cfg.PARTICL_BINDIR,
                'blocks_confirmed': 2,  # Faster testing
            },
            'dash': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': BASE_RPC_PORT + DASH_NODE,
                'datadir': dashdatadir,
                'bindir': DASH_BINDIR,
                'use_csv': True,
                'use_segwit': False,
            },
            'bitcoin': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': BASE_RPC_PORT + BTC_NODE,
                'datadir': btcdatadir,
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
        'max_delay_event': 3,
        'min_delay_event_short': 1,
        'max_delay_event_short': 3,
        'min_delay_retry': 2,
        'max_delay_retry': 10,
        'restrict_unknown_seed_wallets': False
    }
    with open(settings_path, 'w') as fp:
        json.dump(settings, fp, indent=4)


def partRpc(cmd, node_id=0):
    return callrpc_cli(cfg.PARTICL_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(node_id)), 'regtest', cmd, cfg.PARTICL_CLI)


def btcRpc(cmd):
    return callrpc_cli(cfg.BITCOIN_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(BTC_NODE)), 'regtest', cmd, cfg.BITCOIN_CLI)


def dashRpc(cmd, wallet=None):
    return callrpc_cli(DASH_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(DASH_NODE)), 'regtest', cmd, DASH_CLI, wallet=wallet)


def signal_handler(sig, frame):
    global stop_test
    print('signal {} detected.'.format(sig))
    stop_test = True
    delay_event.set()


def run_coins_loop(cls):
    while not stop_test:
        try:
            dashRpc('generatetoaddress 1 {}'.format(cls.dash_addr))
            btcRpc('generatetoaddress 1 {}'.format(cls.btc_addr))
        except Exception as e:
            logging.warning('run_coins_loop ' + str(e))
        time.sleep(1.0)


def run_loop(self):
    while not stop_test:
        for c in self.swap_clients:
            c.update()
        time.sleep(1)


def make_part_cli_rpc_func(node_id):
    node_id = node_id

    def rpc_func(method, params=None, wallet=None):
        nonlocal node_id
        cmd = method
        if params:
            for p in params:
                cmd += ' "' + p + '"'
        return partRpc(cmd, node_id)
    return rpc_func


class Test(unittest.TestCase):
    test_coin_from = Coins.DASH

    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        eckey = ECKey()
        eckey.generate()
        cls.network_key = toWIF(PREFIX_SECRET_KEY_REGTEST, eckey.get_bytes())
        cls.network_pubkey = eckey.get_pubkey().get_bytes().hex()

        if os.path.isdir(cfg.TEST_DATADIRS):
            logging.info('Removing ' + cfg.TEST_DATADIRS)
            shutil.rmtree(cfg.TEST_DATADIRS)

        for i in range(NUM_NODES):
            prepareDir(cfg.TEST_DATADIRS, i, cls.network_key, cls.network_pubkey)

        prepareOtherDir(cfg.TEST_DATADIRS, DASH_NODE)
        prepareOtherDir(cfg.TEST_DATADIRS, BTC_NODE, 'bitcoin.conf')

        cls.daemons = []
        cls.swap_clients = []
        cls.http_threads = []

        btc_data_dir = os.path.join(cfg.TEST_DATADIRS, str(BTC_NODE))
        if os.path.exists(os.path.join(cfg.BITCOIN_BINDIR, 'bitcoin-wallet')):
            logging.info('Creating BTC wallet.')
            try:
                callrpc_cli(cfg.BITCOIN_BINDIR, btc_data_dir, 'regtest', '-wallet=wallet.dat -legacy create', 'bitcoin-wallet')
            except Exception:
                callrpc_cli(cfg.BITCOIN_BINDIR, btc_data_dir, 'regtest', '-wallet=wallet.dat create', 'bitcoin-wallet')
        cls.daemons.append(startDaemon(btc_data_dir, cfg.BITCOIN_BINDIR, cfg.BITCOIND))
        logging.info('Started %s %d', cfg.BITCOIND, cls.daemons[-1].handle.pid)

        dash_data_dir = os.path.join(cfg.TEST_DATADIRS, str(DASH_NODE))
        '''
        dash-wallet does not seem to create valid wallet files.

        if os.path.exists(os.path.join(DASH_BINDIR, 'dash-wallet')):
            logging.info('Creating DASH wallet.')
            callrpc_cli(DASH_BINDIR, dash_data_dir, 'regtest', '-wallet=wallet.dat create', 'dash-wallet')
        '''
        cls.daemons.append(startDaemon(dash_data_dir, DASH_BINDIR, DASHD))
        logging.info('Started %s %d', DASHD, cls.daemons[-1].handle.pid)

        for i in range(NUM_NODES):
            data_dir = os.path.join(cfg.TEST_DATADIRS, str(i))
            if os.path.exists(os.path.join(cfg.PARTICL_BINDIR, 'particl-wallet')):
                try:
                    callrpc_cli(cfg.PARTICL_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat -legacy create', 'particl-wallet')
                except Exception:
                    callrpc_cli(cfg.PARTICL_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'particl-wallet')
            cls.daemons.append(startDaemon(data_dir, cfg.PARTICL_BINDIR, cfg.PARTICLD))
            logging.info('Started %s %d', cfg.PARTICLD, cls.daemons[-1].handle.pid)

        for i in range(NUM_NODES):
            rpc = make_part_cli_rpc_func(i)
            waitForRPC(rpc, delay_event)
            if i == 0:
                rpc('extkeyimportmaster', ['abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb'])
            elif i == 1:
                rpc('extkeyimportmaster', ['pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true'])
                rpc('getnewextaddress', ['lblExtTest'])
                rpc('rescanblockchain')
            else:
                rpc('extkeyimportmaster', [rpc('mnemonic', ['new'])['master']])
            rpc('walletsettings', ['stakingoptions', json.dumps({'stakecombinethreshold': 100, 'stakesplitthreshold': 200}).replace('"', '\\"')])
            rpc('reservebalance', ['false'])

            basicswap_dir = os.path.join(os.path.join(cfg.TEST_DATADIRS, str(i)), 'basicswap')
            settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
            with open(settings_path) as fs:
                settings = json.load(fs)
            fp = open(os.path.join(basicswap_dir, 'basicswap.log'), 'w')
            sc = BasicSwap(fp, basicswap_dir, settings, 'regtest', log_name='BasicSwap{}'.format(i))
            cls.swap_clients.append(sc)
            sc.setDaemonPID(Coins.BTC, cls.daemons[0].handle.pid)
            sc.setDaemonPID(Coins.DASH, cls.daemons[1].handle.pid)
            sc.setDaemonPID(Coins.PART, cls.daemons[2 + i].handle.pid)

            waitForRPC(dashRpc, delay_event, rpc_command='getblockchaininfo')
            if len(dashRpc('listwallets')) < 1:
                dashRpc('createwallet wallet.dat')

            sc.start()

            t = HttpThread(sc.fp, TEST_HTTP_HOST, TEST_HTTP_PORT + i, False, sc)
            cls.http_threads.append(t)
            t.start()

        waitForRPC(dashRpc, delay_event)
        num_blocks = 500
        logging.info('Mining %d dash blocks', num_blocks)
        cls.dash_addr = dashRpc('getnewaddress mining_addr')
        dashRpc('generatetoaddress {} {}'.format(num_blocks, cls.dash_addr))

        ro = dashRpc('getblockchaininfo')
        try:
            assert (ro['bip9_softforks']['csv']['status'] == 'active')
        except Exception:
            logging.info('dash: csv is not active')
        try:
            assert (ro['bip9_softforks']['segwit']['status'] == 'active')
        except Exception:
            logging.info('dash: segwit is not active')

        waitForRPC(btcRpc, delay_event)
        cls.btc_addr = btcRpc('getnewaddress mining_addr bech32')
        logging.info('Mining %d Bitcoin blocks to %s', num_blocks, cls.btc_addr)
        btcRpc('generatetoaddress {} {}'.format(num_blocks, cls.btc_addr))

        ro = btcRpc('getblockchaininfo')
        checkForks(ro)

        ro = dashRpc('getwalletinfo')
        print('dashRpc', ro)

        signal.signal(signal.SIGINT, signal_handler)
        cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
        cls.update_thread.start()

        cls.coins_update_thread = threading.Thread(target=run_coins_loop, args=(cls,))
        cls.coins_update_thread.start()

        # Wait for height, or sequencelock is thrown off by genesis blocktime
        num_blocks = 3
        logging.info('Waiting for Particl chain height %d', num_blocks)
        for i in range(60):
            particl_blocks = cls.swap_clients[0].callrpc('getblockcount')
            print('particl_blocks', particl_blocks)
            if particl_blocks >= num_blocks:
                break
            delay_event.wait(1)
        assert (particl_blocks >= num_blocks)

    @classmethod
    def tearDownClass(cls):
        global stop_test
        logging.info('Finalising')
        stop_test = True
        cls.update_thread.join()
        cls.coins_update_thread.join()
        for t in cls.http_threads:
            t.stop()
            t.join()
        for c in cls.swap_clients:
            c.finalise()
            c.fp.close()

        stopDaemons(cls.daemons)

        cls.http_threads.clear()
        cls.swap_clients.clear()
        cls.daemons.clear()

        super(Test, cls).tearDownClass()

    def test_02_part_dash(self):
        logging.info('---------- Test PART to DASH')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.DASH, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)

        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_03_dash_part(self):
        logging.info('---------- Test DASH to PART')
        swap_clients = self.swap_clients

        offer_id = swap_clients[1].postOffer(Coins.DASH, Coins.PART, 10 * COIN, 9.0 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[1], bid_id)
        swap_clients[1].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[0], bid_id, sent=True)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_04_dash_btc(self):
        logging.info('---------- Test DASH to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.DASH, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0bid = read_json_api(1800, 'bids/{}'.format(bid_id.hex()))

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)

        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_05_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info('---------- Test refund, DASH to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.DASH, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 10)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[1].abandonBid(bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.BID_ABANDONED, sent=True, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_06_self_bid(self):
        logging.info('---------- Test same client, BTC to DASH')
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(Coins.DASH, Coins.BTC, 10 * COIN, 10 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid_tx_state(delay_event, swap_clients[0], bid_id, TxStates.TX_REDEEMED, TxStates.TX_REDEEMED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = read_json_api(1800)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_0['num_recv_bids'] == js_0_before['num_recv_bids'] + 1 and js_0['num_sent_bids'] == js_0_before['num_sent_bids'] + 1)

    def test_07_error(self):
        logging.info('---------- Test error, BTC to DASH, set fee above bid value')
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(Coins.DASH, Coins.BTC, 0.001 * COIN, 1.0 * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        try:
            swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate'] = 10.0
            swap_clients[0].getChainClientSettings(Coins.DASH)['override_feerate'] = 10.0
            wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=60)
            swap_clients[0].abandonBid(bid_id)
        finally:
            del swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate']
            del swap_clients[0].getChainClientSettings(Coins.DASH)['override_feerate']

    def test_08_wallet(self):
        logging.info('---------- Test {} wallet'.format(self.test_coin_from.name))

        logging.info('Test withdrawal')
        addr = dashRpc('getnewaddress \"Withdrawal test\"')
        wallets = read_json_api(TEST_HTTP_PORT + 0, 'wallets')
        assert (float(wallets[self.test_coin_from.name]['balance']) > 100)

        post_json = {
            'value': 100,
            'address': addr,
            'subfee': False,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, 'wallets/{}/withdraw'.format(self.test_coin_from.name.lower()), post_json)
        assert (len(json_rv['txid']) == 64)

        logging.info('Test createutxo')
        post_json = {
            'value': 10,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, 'wallets/{}/createutxo'.format(self.test_coin_from.name.lower()), post_json)
        assert (len(json_rv['txid']) == 64)

    def test_09_initialise_wallet(self):
        logging.info('---------- Test DASH initialiseWallet')

        self.swap_clients[0].initialiseWallet(Coins.DASH, raise_errors=True)
        assert self.swap_clients[0].checkWalletSeed(Coins.DASH) is True

        addr = dashRpc('getnewaddress \"hd wallet test\"')
        assert addr == 'ybzWYJbZEhZai8kiKkTtPFKTuDNwhpiwac'

        logging.info('Test that getcoinseed returns a mnemonic for Dash')
        mnemonic = read_json_api(1800, 'getcoinseed', {'coin': 'DASH'})['mnemonic']
        new_wallet_name = random.randbytes(10).hex()
        dashRpc(f'createwallet \"{new_wallet_name}\"')
        dashRpc(f'upgradetohd \"{mnemonic}\"', wallet=new_wallet_name)
        addr_test = dashRpc('getnewaddress', wallet=new_wallet_name)
        dashRpc('unloadwallet', wallet=new_wallet_name)
        assert (addr_test == addr)

    def test_10_prefunded_itx(self):
        logging.info('---------- Test prefunded itx offer')

        swap_clients = self.swap_clients
        coin_from = Coins.DASH
        coin_to = Coins.BTC
        swap_type = SwapTypes.SELLER_FIRST
        ci_from = swap_clients[2].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)
        tla_from = coin_from.name

        # Prepare balance
        js_w2 = read_json_api(1802, 'wallets')
        if float(js_w2[tla_from]['balance']) < 100.0:
            post_json = {
                'value': 100,
                'address': js_w2[tla_from]['deposit_address'],
                'subfee': False,
            }
            json_rv = read_json_api(1800, 'wallets/{}/withdraw'.format(tla_from.lower()), post_json)
            assert (len(json_rv['txid']) == 64)
            wait_for_balance(delay_event, 'http://127.0.0.1:1802/json/wallets/{}'.format(tla_from.lower()), 'balance', 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        assert (float(js_w2[tla_from]['balance']) >= 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        post_json = {
            'value': 100.0,
            'address': read_json_api(1802, 'wallets/{}/nextdepositaddr'.format(tla_from.lower())),
            'subfee': True,
        }
        json_rv = read_json_api(1802, 'wallets/{}/withdraw'.format(tla_from.lower()), post_json)
        wait_for_balance(delay_event, 'http://127.0.0.1:1802/json/wallets/{}'.format(tla_from.lower()), 'balance', 10.0)
        assert (len(json_rv['txid']) == 64)

        # Create prefunded ITX
        pi = swap_clients[2].pi(SwapTypes.XMR_SWAP)
        js_w2 = read_json_api(1802, 'wallets')
        swap_value = 100.0
        if float(js_w2[tla_from]['balance']) < swap_value:
            swap_value = js_w2[tla_from]['balance']
        swap_value = ci_from.make_int(swap_value)
        assert (swap_value > ci_from.make_int(95))

        itx = pi.getFundedInitiateTxTemplate(ci_from, swap_value, True)
        itx_decoded = ci_from.describeTx(itx.hex())
        n = pi.findMockVout(ci_from, itx_decoded)
        value_after_subfee = ci_from.make_int(itx_decoded['vout'][n]['value'])
        assert (value_after_subfee < swap_value)
        swap_value = value_after_subfee
        wait_for_unspent(delay_event, ci_from, swap_value)

        extra_options = {'prefunded_itx': itx}
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[2].postOffer(coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type, extra_options=extra_options)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[2], bid_id, BidStates.BID_RECEIVED)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

        # Verify expected inputs were used
        bid, offer = swap_clients[2].getBidAndOffer(bid_id)
        assert (bid.initiate_tx)
        wtx = ci_from.rpc_wallet('gettransaction', [bid.initiate_tx.txid.hex(),])
        itx_after = ci_from.describeTx(wtx['hex'])
        assert (len(itx_after['vin']) == len(itx_decoded['vin']))
        for i, txin in enumerate(itx_decoded['vin']):
            assert (txin['txid'] == itx_after['vin'][i]['txid'])
            assert (txin['vout'] == itx_after['vin'][i]['vout'])

    def test_11_xmrswap_to(self):
        logging.info('---------- Test xmr swap protocol to')

        swap_clients = self.swap_clients
        coin_from = Coins.BTC
        coin_to = Coins.DASH
        swap_type = SwapTypes.XMR_SWAP
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

    def test_12_xmrswap_to_recover_b_lock_tx(self):
        coin_from = Coins.BTC
        coin_to = Coins.DASH
        logging.info('---------- Test {} to {} follower recovers coin b lock tx'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=32)
        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)


if __name__ == '__main__':
    unittest.main()
