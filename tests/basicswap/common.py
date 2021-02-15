#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import signal
import logging
import urllib
from urllib.request import urlopen

from basicswap.rpc import callrpc
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac


TEST_HTTP_HOST = os.getenv('TEST_HTTP_HOST', '127.0.0.1')  # Set to 0.0.0.0 when used in docker
TEST_HTTP_PORT = 1800

BASE_P2P_PORT = 12792

BASE_PORT = 14792
BASE_RPC_PORT = 19792
BASE_ZMQ_PORT = 20792

BTC_BASE_PORT = 31792
BTC_BASE_RPC_PORT = 32792
BTC_BASE_ZMQ_PORT = 33792

PREFIX_SECRET_KEY_REGTEST = 0x2e


def prepareDataDir(datadir, node_id, conf_file, dir_prefix, base_p2p_port=BASE_PORT, base_rpc_port=BASE_RPC_PORT, num_nodes=3):
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
        fp.write('wallet=wallet.dat\n')
        fp.write('findpeers=0\n')

        if base_p2p_port == BASE_PORT:  # Particl
            fp.write('zmqpubsmsg=tcp://127.0.0.1:{}\n'.format(BASE_ZMQ_PORT + node_id))
            # minstakeinterval=5  # Using walletsettings stakelimit instead
            fp.write('stakethreadconddelayms=1000\n')
            fp.write('smsgsregtestadjust=0\n')

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            fp.write('addnode=127.0.0.1:{}\n'.format(base_p2p_port + i))

    return node_dir


def checkForks(ro):
    if 'bip9_softforks' in ro:
        assert(ro['bip9_softforks']['csv']['status'] == 'active')
        assert(ro['bip9_softforks']['segwit']['status'] == 'active')
    else:
        assert(ro['softforks']['csv']['active'])
        assert(ro['softforks']['segwit']['active'])


def stopDaemons(daemons):
    for d in daemons:
        logging.info('Interrupting %d', d.pid)
        try:
            d.send_signal(signal.SIGINT)
        except Exception as e:
            logging.info('Interrupting %d, error %s', d.pid, str(e))
    for d in daemons:
        try:
            d.wait(timeout=20)
            for fp in (d.stdout, d.stderr, d.stdin):
                if fp:
                    fp.close()
        except Exception as e:
            logging.info('Closing %d, error %s', d.pid, str(e))


def wait_for_bid(delay_event, swap_client, bid_id, state=None, sent=False, wait_for=20):
    logging.info('wait_for_bid %s', bid_id.hex())
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)

        filters = {
            'bid_id': bid_id,
        }
        bids = swap_client.listBids(sent=sent, filters=filters)
        assert(len(bids) < 2)
        for bid in bids:
            if bid[2] == bid_id:
                if state is not None and state != bid[5]:
                    continue
                return
    raise ValueError('wait_for_bid timed out.')


def wait_for_bid_tx_state(delay_event, swap_client, bid_id, initiate_state, participate_state, wait_for=30):
    logging.info('wait_for_bid_tx_state %s %s %s', bid_id.hex(), str(initiate_state), str(participate_state))
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)
        bid = swap_client.getBid(bid_id)
        if (initiate_state is None or bid.getITxState() == initiate_state) \
           and (participate_state is None or bid.getPTxState() == participate_state):
            return
    raise ValueError('wait_for_bid_tx_state timed out.')


def wait_for_offer(delay_event, swap_client, offer_id, wait_for=20):
    logging.info('wait_for_offer %s', offer_id.hex())
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)
        offers = swap_client.listOffers()
        for offer in offers:
            if offer.offer_id == offer_id:
                return
    raise ValueError('wait_for_offer timed out.')


def wait_for_no_offer(delay_event, swap_client, offer_id, wait_for=20):
    logging.info('wait_for_no_offer %s', offer_id.hex())
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)
        offers = swap_client.listOffers()
        found_offer = False
        for offer in offers:
            if offer.offer_id == offer_id:
                found_offer = True
                break
        if not found_offer:
            return True
    raise ValueError('wait_for_offer timed out.')


def wait_for_in_progress(delay_event, swap_client, bid_id, sent=False):
    logging.info('wait_for_in_progress %s', bid_id.hex())
    for i in range(20):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)
        swaps = swap_client.listSwapsInProgress()
        for b in swaps:
            if b[0] == bid_id:
                return
    raise ValueError('wait_for_in_progress timed out.')


def wait_for_none_active(delay_event, port, wait_for=30):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)
        js = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
        if js['num_swapping'] == 0 and js['num_watched_outputs'] == 0:
            return
    raise ValueError('wait_for_none_active timed out.')


def waitForServer(delay_event, port, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        try:
            delay_event.wait(1)
            summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
            return
        except Exception as e:
            print('waitForServer, error:', str(e))
    raise ValueError('waitForServer failed')


def waitForNumOffers(delay_event, port, offers, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
        if summary['num_network_offers'] >= offers:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumOffers failed')


def waitForNumBids(delay_event, port, bids, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
        if summary['num_recv_bids'] >= bids:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumBids failed')


def waitForNumSwapping(delay_event, port, bids, wait_for=60):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = json.loads(urlopen('http://127.0.0.1:{}/json'.format(port)).read())
        if summary['num_swapping'] >= bids:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumSwapping failed')


def wait_for_balance(delay_event, url, balance_key, expect_amount, iterations=20, delay_time=3):
    i = 0
    while not delay_event.is_set():
        rv_js = json.loads(urlopen(url).read())
        if float(rv_js[balance_key]) >= expect_amount:
            break
        delay_event.wait(delay_time)
        i += 1
        if i > iterations:
            raise ValueError('Expect {} {}'.format(balance_key, expect_amount))


def post_json_req(url, json_data):
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    post_bytes = json.dumps(json_data).encode('utf-8')
    req.add_header('Content-Length', len(post_bytes))
    return urlopen(req, post_bytes).read()


def delay_for(delay_event, delay_for=60):
    logging.info('Delaying for {} seconds.'.format(delay_for))
    delay_event.wait(delay_for)


def make_rpc_func(node_id, base_rpc_port=BASE_RPC_PORT):
    node_id = node_id
    auth = 'test{0}:test_pass{0}'.format(node_id)

    def rpc_func(method, params=None, wallet=None):
        nonlocal node_id, auth
        return callrpc(base_rpc_port + node_id, auth, method, params, wallet)
    return rpc_func
