#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/test_nmc.py

"""

import os
import sys
import unittest
import json
import logging
import shutil
import subprocess
import time
import signal
import threading
from urllib.request import urlopen

from basicswap.basicswap import (
    BasicSwap,
    Coins,
    SwapTypes,
    BidStates,
    TxStates,
    ABS_LOCK_BLOCKS,
    ABS_LOCK_TIME,
)
from basicswap.util import (
    COIN,
    toWIF,
    callrpc_cli,
)
from basicswap.key import (
    ECKey,
)
from basicswap.http_server import (
    HttpThread,
)

import basicswap.config as cfg

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

NUM_NODES = 3
BASE_PORT = 14792
BASE_RPC_PORT = 19792
BASE_ZMQ_PORT = 20792
PREFIX_SECRET_KEY_REGTEST = 0x2e
TEST_HTML_PORT = 1800
NMC_NODE = 3
BTC_NODE = 4
stop_test = False


def prepareOtherDir(datadir, nodeId, conf_file='namecoin.conf'):
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

        fp.write('acceptnonstdtxn=0\n')


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

        fp.write('acceptnonstdtxn=0\n')
        fp.write('minstakeinterval=5\n')

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

    nmcdatadir = os.path.join(datadir, str(NMC_NODE))
    btcdatadir = os.path.join(datadir, str(BTC_NODE))
    settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
    settings = {
        'zmqhost': 'tcp://127.0.0.1',
        'zmqport': BASE_ZMQ_PORT + nodeId,
        'htmlhost': 'localhost',
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
            'namecoin': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': BASE_RPC_PORT + NMC_NODE,
                'datadir': nmcdatadir,
                'bindir': cfg.NAMECOIN_BINDIR,
                'use_csv': False,
                # 'use_segwit': True,
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
        'check_expired_seconds': 60
    }
    with open(settings_path, 'w') as fp:
        json.dump(settings, fp, indent=4)


def startDaemon(nodeId, bin_dir=cfg.PARTICL_BINDIR, daemon_bin=cfg.PARTICLD):
    node_dir = os.path.join(cfg.TEST_DATADIRS, str(nodeId))
    daemon_bin = os.path.join(bin_dir, daemon_bin)

    args = [daemon_bin, '-datadir=' + node_dir]
    logging.info('Starting node ' + str(nodeId) + ' ' + daemon_bin + ' ' + '-datadir=' + node_dir)
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def partRpc(cmd, node_id=0):
    return callrpc_cli(cfg.PARTICL_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(node_id)), 'regtest', cmd, cfg.PARTICL_CLI)


def btcRpc(cmd):
    return callrpc_cli(cfg.BITCOIN_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(BTC_NODE)), 'regtest', cmd, cfg.BITCOIN_CLI)


def nmcRpc(cmd):
    return callrpc_cli(cfg.NAMECOIN_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(NMC_NODE)), 'regtest', cmd, cfg.NAMECOIN_CLI)


def signal_handler(sig, frame):
    global stop_test
    print('signal {} detected.'.format(sig))
    stop_test = True


def run_loop(self):
    while not stop_test:
        time.sleep(1)
        for c in self.swap_clients:
            c.update()
        nmcRpc('generatetoaddress 1 {}'.format(self.nmc_addr))
        btcRpc('generatetoaddress 1 {}'.format(self.btc_addr))


def waitForRPC(rpc_func, wallet=None):
    for i in range(5):
        try:
            rpc_func('getwalletinfo')
            return
        except Exception as ex:
            logging.warning('Can\'t connect to daemon RPC: %s.  Trying again in %d second/s.', str(ex), (1 + i))
            time.sleep(1 + i)
    raise ValueError('waitForRPC failed')


class Test(unittest.TestCase):

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

        prepareOtherDir(cfg.TEST_DATADIRS, NMC_NODE)
        prepareOtherDir(cfg.TEST_DATADIRS, BTC_NODE, 'bitcoin.conf')

        cls.daemons = []
        cls.swap_clients = []

        cls.daemons.append(startDaemon(BTC_NODE, cfg.BITCOIN_BINDIR, cfg.BITCOIND))
        logging.info('Started %s %d', cfg.BITCOIND, cls.daemons[-1].pid)
        cls.daemons.append(startDaemon(NMC_NODE, cfg.NAMECOIN_BINDIR, cfg.NAMECOIND))
        logging.info('Started %s %d', cfg.NAMECOIND, cls.daemons[-1].pid)

        for i in range(NUM_NODES):
            cls.daemons.append(startDaemon(i))
            logging.info('Started %s %d', cfg.PARTICLD, cls.daemons[-1].pid)
        time.sleep(1)
        for i in range(NUM_NODES):
            basicswap_dir = os.path.join(os.path.join(cfg.TEST_DATADIRS, str(i)), 'basicswap')
            settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
            with open(settings_path) as fs:
                settings = json.load(fs)
            fp = open(os.path.join(basicswap_dir, 'basicswap.log'), 'w')
            cls.swap_clients.append(BasicSwap(fp, basicswap_dir, settings, 'regtest', log_name='BasicSwap{}'.format(i)))
            cls.swap_clients[-1].setDaemonPID(Coins.BTC, cls.daemons[0].pid)
            cls.swap_clients[-1].setDaemonPID(Coins.NMC, cls.daemons[1].pid)
            cls.swap_clients[-1].setDaemonPID(Coins.PART, cls.daemons[2 + i].pid)
            cls.swap_clients[-1].start()
        cls.swap_clients[0].callrpc('extkeyimportmaster', ['abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb'])
        cls.swap_clients[1].callrpc('extkeyimportmaster', ['pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic', '', 'true'])
        cls.swap_clients[1].callrpc('getnewextaddress', ['lblExtTest'])
        cls.swap_clients[1].callrpc('rescanblockchain')

        waitForRPC(nmcRpc)
        num_blocks = 500
        logging.info('Mining %d namecoin blocks', num_blocks)
        cls.nmc_addr = nmcRpc('getnewaddress mining_addr legacy')
        nmcRpc('generatetoaddress {} {}'.format(num_blocks, cls.nmc_addr))

        ro = nmcRpc('getblockchaininfo')
        try:
            assert(ro['bip9_softforks']['csv']['status'] == 'active')
        except Exception:
            logging.info('nmc: csv is not active')
        try:
            assert(ro['bip9_softforks']['segwit']['status'] == 'active')
        except Exception:
            logging.info('nmc: segwit is not active')

        waitForRPC(btcRpc)
        cls.btc_addr = btcRpc('getnewaddress mining_addr bech32')
        logging.info('Mining %d bitcoin blocks to %s', num_blocks, cls.btc_addr)
        btcRpc('generatetoaddress {} {}'.format(num_blocks, cls.btc_addr))

        ro = btcRpc('getblockchaininfo')
        assert(ro['bip9_softforks']['csv']['status'] == 'active')
        assert(ro['bip9_softforks']['segwit']['status'] == 'active')

        ro = nmcRpc('getwalletinfo')
        print('nmcRpc', ro)

        cls.http_threads = []
        host = '0.0.0.0'  # All interfaces (docker)
        for i in range(3):
            t = HttpThread(cls.swap_clients[i].fp, host, TEST_HTML_PORT + i, False, cls.swap_clients[i])
            cls.http_threads.append(t)
            t.start()

        signal.signal(signal.SIGINT, signal_handler)
        cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
        cls.update_thread.start()

    @classmethod
    def tearDownClass(cls):
        global stop_test
        logging.info('Finalising')
        stop_test = True
        cls.update_thread.join()
        for t in cls.http_threads:
            t.stop()
            t.join()
        for c in cls.swap_clients:
            c.fp.close()
        for d in cls.daemons:
            logging.info('Terminating %d', d.pid)
            d.terminate()
            d.wait(timeout=10)
            if d.stdout:
                d.stdout.close()
            if d.stderr:
                d.stderr.close()
            if d.stdin:
                d.stdin.close()

        super(Test, cls).tearDownClass()

    def wait_for_offer(self, swap_client, offer_id):
        logging.info('wait_for_offer %s', offer_id.hex())
        for i in range(20):
            time.sleep(1)
            offers = swap_client.listOffers()
            for offer in offers:
                if offer.offer_id == offer_id:
                    return
        raise ValueError('wait_for_offer timed out.')

    def wait_for_bid(self, swap_client, bid_id):
        logging.info('wait_for_bid %s', bid_id.hex())
        for i in range(20):
            time.sleep(1)
            bids = swap_client.listBids()
            for bid in bids:
                if bid[1] == bid_id and int(bid[5]) == 1:
                    return
        raise ValueError('wait_for_bid timed out.')

    def wait_for_in_progress(self, swap_client, bid_id, sent=False):
        logging.info('wait_for_in_progress %s', bid_id.hex())
        for i in range(20):
            time.sleep(1)
            swaps = swap_client.listSwapsInProgress()
            for b in swaps:
                if b[0] == bid_id:
                    return
        raise ValueError('wait_for_in_progress timed out.')

    def wait_for_bid_state(self, swap_client, bid_id, state, sent=False, seconds_for=30):
        logging.info('wait_for_bid_state %s %s', bid_id.hex(), str(state))
        for i in range(seconds_for):
            time.sleep(1)
            bid = swap_client.getBid(bid_id)
            if bid.state >= state:
                return
        raise ValueError('wait_for_bid_state timed out.')

    def wait_for_bid_tx_state(self, swap_client, bid_id, initiate_state, participate_state, seconds_for=30):
        logging.info('wait_for_bid_tx_state %s %s %s', bid_id.hex(), str(initiate_state), str(participate_state))
        for i in range(seconds_for):
            time.sleep(1)
            bid = swap_client.getBid(bid_id)
            if (initiate_state is None or bid.getITxState() == initiate_state) \
               and (participate_state is None or bid.getPTxState() == participate_state):
                return
        raise ValueError('wait_for_bid_tx_state timed out.')

    def test_02_part_ltc(self):
        logging.info('---------- Test PART to NMC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.NMC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST, ABS_LOCK_TIME)

        self.wait_for_offer(swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        assert(len(offers) == 1)
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id)

        swap_clients[0].acceptBid(bid_id)

        self.wait_for_in_progress(swap_clients[1], bid_id, sent=True)

        self.wait_for_bid_state(swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, seconds_for=60)
        self.wait_for_bid_state(swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, seconds_for=60)

        js_0 = json.loads(urlopen('http://localhost:1800/json').read())
        js_1 = json.loads(urlopen('http://localhost:1801/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_03_nmc_part(self):
        logging.info('---------- Test NMC to PART')
        swap_clients = self.swap_clients

        offer_id = swap_clients[1].postOffer(Coins.NMC, Coins.PART, 10 * COIN, 9.0 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST, ABS_LOCK_TIME)

        self.wait_for_offer(swap_clients[0], offer_id)
        offers = swap_clients[0].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[1], bid_id)
        swap_clients[1].acceptBid(bid_id)

        self.wait_for_in_progress(swap_clients[0], bid_id, sent=True)

        self.wait_for_bid_state(swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, sent=True, seconds_for=60)
        self.wait_for_bid_state(swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, seconds_for=60)

        js_0 = json.loads(urlopen('http://localhost:1800/json').read())
        js_1 = json.loads(urlopen('http://localhost:1801/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_04_nmc_btc(self):
        logging.info('---------- Test NMC to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.NMC, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST, ABS_LOCK_TIME)

        self.wait_for_offer(swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        self.wait_for_in_progress(swap_clients[1], bid_id, sent=True)

        self.wait_for_bid_state(swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, seconds_for=60)
        self.wait_for_bid_state(swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, seconds_for=60)

        js_0bid = json.loads(urlopen('http://localhost:1800/json/bids/{}'.format(bid_id.hex())).read())

        js_0 = json.loads(urlopen('http://localhost:1800/json').read())
        js_1 = json.loads(urlopen('http://localhost:1801/json').read())

        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_05_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info('---------- Test refund, NMC to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.NMC, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST,
                                             ABS_LOCK_BLOCKS, 10)

        self.wait_for_offer(swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id)
        swap_clients[1].abandonBid(bid_id)
        swap_clients[0].acceptBid(bid_id)

        self.wait_for_bid_state(swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, seconds_for=60)
        self.wait_for_bid_state(swap_clients[1], bid_id, BidStates.BID_ABANDONED, sent=True, seconds_for=60)

        js_0 = json.loads(urlopen('http://localhost:1800/json').read())
        js_1 = json.loads(urlopen('http://localhost:1801/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_06_self_bid(self):
        logging.info('---------- Test same client, BTC to NMC')
        swap_clients = self.swap_clients

        js_0_before = json.loads(urlopen('http://localhost:1800/json').read())

        offer_id = swap_clients[0].postOffer(Coins.NMC, Coins.BTC, 10 * COIN, 10 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST, ABS_LOCK_TIME)

        self.wait_for_offer(swap_clients[0], offer_id)
        offers = swap_clients[0].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        self.wait_for_bid_tx_state(swap_clients[0], bid_id, TxStates.TX_REDEEMED, TxStates.TX_REDEEMED, seconds_for=60)
        self.wait_for_bid_state(swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, seconds_for=60)

        js_0 = json.loads(urlopen('http://localhost:1800/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_0['num_recv_bids'] == js_0_before['num_recv_bids'] + 1 and js_0['num_sent_bids'] == js_0_before['num_sent_bids'] + 1)

    def test_07_error(self):
        logging.info('---------- Test error, BTC to NMC, set fee above bid value')
        swap_clients = self.swap_clients

        js_0_before = json.loads(urlopen('http://localhost:1800/json').read())

        offer_id = swap_clients[0].postOffer(Coins.NMC, Coins.BTC, 0.001 * COIN, 1.0 * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST, ABS_LOCK_TIME)

        self.wait_for_offer(swap_clients[0], offer_id)
        offers = swap_clients[0].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        self.wait_for_bid(swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        swap_clients[0].coin_clients[Coins.BTC]['override_feerate'] = 10.0
        swap_clients[0].coin_clients[Coins.NMC]['override_feerate'] = 10.0

        self.wait_for_bid_state(swap_clients[0], bid_id, BidStates.BID_ERROR, seconds_for=60)

    def pass_99_delay(self):
        global stop_test
        logging.info('Delay')
        for i in range(60 * 5):
            if stop_test:
                break
            time.sleep(1)
            print('delay', i)
        stop_test = True


if __name__ == '__main__':
    unittest.main()
