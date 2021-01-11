#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ pytest

Run one test:
$ pytest -v -s tests/basicswap/test_run.py::Test::test_04_ltc_btc

"""

import os
import sys
import json
import time
import shutil
import signal
import logging
import unittest
import threading
from urllib.request import urlopen

import basicswap.config as cfg
from basicswap.basicswap import (
    BasicSwap,
    Coins,
    SwapTypes,
    BidStates,
    TxStates,
    SEQUENCE_LOCK_BLOCKS,
)
from basicswap.util import (
    COIN,
    toWIF,
    dumpje,
)
from basicswap.rpc import (
    callrpc_cli,
    waitForRPC,
)
from basicswap.contrib.key import (
    ECKey,
)
from basicswap.http_server import (
    HttpThread,
)
from tests.basicswap.common import (
    checkForks,
    stopDaemons,
    wait_for_offer,
    wait_for_bid,
    wait_for_bid_tx_state,
    wait_for_in_progress,
    TEST_HTTP_HOST,
    TEST_HTTP_PORT,
    BASE_PORT,
    BASE_RPC_PORT,
    BASE_ZMQ_PORT,
    PREFIX_SECRET_KEY_REGTEST,
)
from bin.basicswap_run import startDaemon


NUM_NODES = 3
LTC_NODE = 3
BTC_NODE = 4

delay_event = threading.Event()
stop_test = False


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def prepareOtherDir(datadir, nodeId, conf_file='litecoin.conf'):
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
        fp.write('fallbackfee=0.0002\n')

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
        fp.write('minstakeinterval=2\n')
        fp.write('stakethreadconddelayms=1000\n')

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

    ltcdatadir = os.path.join(datadir, str(LTC_NODE))
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
            'litecoin': {
                'connection_type': 'rpc',
                'manage_daemon': False,
                'rpcport': BASE_RPC_PORT + LTC_NODE,
                'datadir': ltcdatadir,
                'bindir': cfg.LITECOIN_BINDIR,
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
        'check_expired_seconds': 60,
        'check_events_seconds': 1,
        'min_delay_event': 1,
        'max_delay_event': 5
    }
    with open(settings_path, 'w') as fp:
        json.dump(settings, fp, indent=4)


def partRpc(cmd, node_id=0):
    return callrpc_cli(cfg.PARTICL_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(node_id)), 'regtest', cmd, cfg.PARTICL_CLI)


def btcRpc(cmd):
    return callrpc_cli(cfg.BITCOIN_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(BTC_NODE)), 'regtest', cmd, cfg.BITCOIN_CLI)


def ltcRpc(cmd):
    return callrpc_cli(cfg.LITECOIN_BINDIR, os.path.join(cfg.TEST_DATADIRS, str(LTC_NODE)), 'regtest', cmd, cfg.LITECOIN_CLI)


def signal_handler(sig, frame):
    global stop_test
    print('signal {} detected.'.format(sig))
    stop_test = True
    delay_event.set()


def run_coins_loop(cls):
    while not stop_test:
        try:
            ltcRpc('generatetoaddress 1 {}'.format(cls.ltc_addr))
            btcRpc('generatetoaddress 1 {}'.format(cls.btc_addr))
        except Exception as e:
            logging.warning('run_coins_loop ' + str(e))
        time.sleep(1.0)


def run_loop(cls):
    while not stop_test:
        for c in cls.swap_clients:
            c.update()
        time.sleep(1)


def make_part_cli_rpc_func(node_id):
    node_id = node_id

    def rpc_func(method, params=None, wallet=None):
        nonlocal node_id
        cmd = method
        if params:
            for p in params:
                if isinstance(p, dict) or isinstance(p, list):
                    cmd += ' "' + dumpje(p) + '"'
                elif isinstance(p, int):
                    cmd += ' ' + str(p)
                else:
                    cmd += ' "' + p + '"'
        return partRpc(cmd, node_id)
    return rpc_func


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

        prepareOtherDir(cfg.TEST_DATADIRS, LTC_NODE)
        prepareOtherDir(cfg.TEST_DATADIRS, BTC_NODE, 'bitcoin.conf')

        cls.daemons = []
        cls.swap_clients = []
        cls.http_threads = []

        cls.daemons.append(startDaemon(os.path.join(cfg.TEST_DATADIRS, str(BTC_NODE)), cfg.BITCOIN_BINDIR, cfg.BITCOIND))
        logging.info('Started %s %d', cfg.BITCOIND, cls.daemons[-1].pid)
        cls.daemons.append(startDaemon(os.path.join(cfg.TEST_DATADIRS, str(LTC_NODE)), cfg.LITECOIN_BINDIR, cfg.LITECOIND))
        logging.info('Started %s %d', cfg.LITECOIND, cls.daemons[-1].pid)

        for i in range(NUM_NODES):
            cls.daemons.append(startDaemon(os.path.join(cfg.TEST_DATADIRS, str(i)), cfg.PARTICL_BINDIR, cfg.PARTICLD))
            logging.info('Started %s %d', cfg.PARTICLD, cls.daemons[-1].pid)

        for i in range(NUM_NODES):
            # Load mnemonics after all nodes have started to avoid staking getting stuck in TryToSync
            rpc = make_part_cli_rpc_func(i)
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

            basicswap_dir = os.path.join(os.path.join(cfg.TEST_DATADIRS, str(i)), 'basicswap')
            settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
            with open(settings_path) as fs:
                settings = json.load(fs)
            fp = open(os.path.join(basicswap_dir, 'basicswap.log'), 'w')
            sc = BasicSwap(fp, basicswap_dir, settings, 'regtest', log_name='BasicSwap{}'.format(i))
            sc.setDaemonPID(Coins.BTC, cls.daemons[0].pid)
            sc.setDaemonPID(Coins.LTC, cls.daemons[1].pid)
            sc.setDaemonPID(Coins.PART, cls.daemons[2 + i].pid)
            sc.start()
            cls.swap_clients.append(sc)

            t = HttpThread(cls.swap_clients[i].fp, TEST_HTTP_HOST, TEST_HTTP_PORT + i, False, cls.swap_clients[i])
            cls.http_threads.append(t)
            t.start()

        waitForRPC(ltcRpc)
        num_blocks = 500
        logging.info('Mining %d litecoin blocks', num_blocks)
        cls.ltc_addr = ltcRpc('getnewaddress mining_addr legacy')
        ltcRpc('generatetoaddress {} {}'.format(num_blocks, cls.ltc_addr))

        ro = ltcRpc('getblockchaininfo')
        checkForks(ro)

        waitForRPC(btcRpc)
        cls.btc_addr = btcRpc('getnewaddress mining_addr bech32')
        logging.info('Mining %d Bitcoin blocks to %s', num_blocks, cls.btc_addr)
        btcRpc('generatetoaddress {} {}'.format(num_blocks, cls.btc_addr))

        ro = btcRpc('getblockchaininfo')
        checkForks(ro)

        ro = ltcRpc('getwalletinfo')
        print('ltcRpc', ro)

        signal.signal(signal.SIGINT, signal_handler)
        cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
        cls.update_thread.start()

        cls.coins_update_thread = threading.Thread(target=run_coins_loop, args=(cls,))
        cls.coins_update_thread.start()

        # Wait for height, or sequencelock is thrown off by genesis blocktime
        num_blocks = 3
        logging.info('Waiting for Particl chain height %d', num_blocks)
        for i in range(60):
            particl_blocks = cls.swap_clients[0].callrpc('getblockchaininfo')['blocks']
            print('particl_blocks', particl_blocks)
            if particl_blocks >= num_blocks:
                break
            delay_event.wait(1)
        assert(particl_blocks >= num_blocks)

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

        super(Test, cls).tearDownClass()

    def test_01_verifyrawtransaction(self):
        txn = '0200000001eb6e5c4ebba4efa32f40c7314cad456a64008e91ee30b2dd0235ab9bb67fbdbb01000000ee47304402200956933242dde94f6cf8f195a470f8d02aef21ec5c9b66c5d3871594bdb74c9d02201d7e1b440de8f4da672d689f9e37e98815fb63dbc1706353290887eb6e8f7235012103dc1b24feb32841bc2f4375da91fa97834e5983668c2a39a6b7eadb60e7033f9d205a803b28fe2f86c17db91fa99d7ed2598f79b5677ffe869de2e478c0d1c02cc7514c606382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914225fbfa4cb725b75e511810ac4d6f74069bdded26703520140b27576a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666888acffffffff01e0167118020000001976a9140044e188928710cecba8311f1cf412135b98145c88ac00000000'
        prevout = {
            'txid': 'bbbd7fb69bab3502ddb230ee918e00646a45ad4c31c7402fa3efa4bb4e5c6eeb',
            'vout': 1,
            'scriptPubKey': 'a9143d37191e8b864222d14952a14c85504677a0581d87',
            'redeemScript': '6382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914225fbfa4cb725b75e511810ac4d6f74069bdded26703520140b27576a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666888ac',
            'amount': 1.0}
        ro = partRpc('verifyrawtransaction {} "{}"'.format(txn, dumpje([prevout, ])))
        assert(ro['inputs_valid'] is False)
        assert(ro['validscripts'] == 1)

        prevout['amount'] = 100.0
        ro = partRpc('verifyrawtransaction {} "{}"'.format(txn, dumpje([prevout, ])))
        assert(ro['inputs_valid'] is True)
        assert(ro['validscripts'] == 1)

        txn = 'a000000000000128e8ba6a28673f2ebb5fd983b27a791fd1888447a47638b3cd8bfdd3f54a6f1e0100000000a90040000101e0c69a3b000000001976a9146c0f1ea47ca2bf84ed87bf3aa284e18748051f5788ac04473044022026b01f3a90e46883949404141467b741cd871722a4aaae8ddc8c4d6ab6fb1c77022047a2f3be2dcbe4c51837d2d5e0329aaa8a13a8186b03186b127cc51185e4f3ab012103dc1b24feb32841bc2f4375da91fa97834e5983668c2a39a6b7eadb60e7033f9d0100606382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666703a90040b27576a914225fbfa4cb725b75e511810ac4d6f74069bdded26888ac'
        prevout = {
            'txid': '1e6f4af5d3fd8bcdb33876a4478488d11f797ab283d95fbb2e3f67286abae828',
            'vout': 1,
            'scriptPubKey': 'a914129aee070317bbbd57062288849e85cf57d15c2687',
            'redeemScript': '6382012088a8201fe90717abb84b481c2a59112414ae56ec8acc72273642ca26cc7a5812fdc8f68876a914207eb66b2fd6ed9924d6217efc7fa7b38dfabe666703a90040b27576a914225fbfa4cb725b75e511810ac4d6f74069bdded26888ac',
            'amount': 1.0}
        ro = partRpc('verifyrawtransaction {} "{}"'.format(txn, dumpje([prevout, ])))
        assert(ro['inputs_valid'] is False)
        assert(ro['validscripts'] == 0)  # Amount covered by signature

        prevout['amount'] = 90.0
        ro = partRpc('verifyrawtransaction {} "{}"'.format(txn, dumpje([prevout, ])))
        assert(ro['inputs_valid'] is True)
        assert(ro['validscripts'] == 1)

    def test_02_part_ltc(self):
        logging.info('---------- Test PART to LTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.LTC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        assert(len(offers) == 1)
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)

        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json').read())
        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_03_ltc_part(self):
        logging.info('---------- Test LTC to PART')
        swap_clients = self.swap_clients

        offer_id = swap_clients[1].postOffer(Coins.LTC, Coins.PART, 10 * COIN, 9.0 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offers = swap_clients[0].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[1], bid_id)
        swap_clients[1].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[0], bid_id, sent=True)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json').read())
        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_04_ltc_btc(self):
        logging.info('---------- Test LTC to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.LTC, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0bid = json.loads(urlopen('http://127.0.0.1:1800/json/bids/{}'.format(bid_id.hex())).read())

        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json').read())
        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json').read())

        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_05_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info('---------- Test refund, LTC to BTC')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.LTC, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST,
                                             SEQUENCE_LOCK_BLOCKS, 10)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[1].abandonBid(bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.BID_ABANDONED, sent=True, wait_for=60)

        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json').read())
        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_06_self_bid(self):
        logging.info('---------- Test same client, BTC to LTC')
        swap_clients = self.swap_clients

        js_0_before = json.loads(urlopen('http://127.0.0.1:1800/json').read())

        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.LTC, 10 * COIN, 10 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offers = swap_clients[0].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid_tx_state(delay_event, swap_clients[0], bid_id, TxStates.TX_REDEEMED, TxStates.TX_REDEEMED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_0['num_recv_bids'] == js_0_before['num_recv_bids'] + 1 and js_0['num_sent_bids'] == js_0_before['num_sent_bids'] + 1)

    def test_07_error(self):
        logging.info('---------- Test error, BTC to LTC, set fee above bid value')
        swap_clients = self.swap_clients

        js_0_before = json.loads(urlopen('http://127.0.0.1:1800/json').read())

        offer_id = swap_clients[0].postOffer(Coins.BTC, Coins.LTC, 0.001 * COIN, 1.0 * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offers = swap_clients[0].listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        swap_clients[0].coin_clients[Coins.BTC]['override_feerate'] = 10.0
        swap_clients[0].coin_clients[Coins.LTC]['override_feerate'] = 10.0

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=60)

        swap_clients[0].abandonBid(bid_id)
        del swap_clients[0].coin_clients[Coins.BTC]['override_feerate']
        del swap_clients[0].coin_clients[Coins.LTC]['override_feerate']

    def test_08_part_ltc_buyer_first(self):
        logging.info('---------- Test PART to LTC, buyer first')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.LTC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.BUYER_FIRST)

        return  # TODO

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        assert(len(offers) == 1)
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)

        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0 = json.loads(urlopen('http://127.0.0.1:1800/json').read())
        js_1 = json.loads(urlopen('http://127.0.0.1:1801/json').read())
        assert(js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert(js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_09_part_ltc_auto_accept(self):
        logging.info('---------- Test PART to LTC, auto accept bid')
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, Coins.LTC, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST, auto_accept_bids=True)

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers()
        assert(len(offers) >= 1)
        for offer in offers:
            if offer.offer_id == offer_id:
                bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

    def pass_99_delay(self):
        global stop_test
        logging.info('Delay')
        for i in range(60 * 10):
            if stop_test:
                break
            time.sleep(1)
            print('delay', i)
            if i % 2 == 0:
                offer_id = self.swap_clients[0].postOffer(Coins.BTC, Coins.LTC, 0.001 * (i + 1) * COIN, 1.0 * (i + 1) * COIN, 0.001 * (i + 1) * COIN, SwapTypes.SELLER_FIRST)
            else:
                offer_id = self.swap_clients[1].postOffer(Coins.LTC, Coins.BTC, 0.001 * (i + 1) * COIN, 1.0 * (i + 1) * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST)

        stop_test = True


if __name__ == '__main__':
    unittest.main()
