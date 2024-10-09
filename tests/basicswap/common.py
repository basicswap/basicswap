#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import signal
import logging
from urllib.request import urlopen

from .util import read_json_api
from basicswap.rpc import callrpc
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.bin.prepare import downloadPIVXParams


TEST_HTTP_HOST = os.getenv('TEST_HTTP_HOST', '127.0.0.1')  # Set to 0.0.0.0 when used in docker
TEST_HTTP_PORT = 1800

BASE_P2P_PORT = 12792

BASE_PORT = 14792
BASE_RPC_PORT = 19792
BASE_ZMQ_PORT = 20792

BTC_BASE_PORT = 31792
BTC_BASE_RPC_PORT = 32792
BTC_BASE_ZMQ_PORT = 33792
BTC_BASE_TOR_PORT = 33732

LTC_BASE_PORT = 34792
LTC_BASE_RPC_PORT = 35792
LTC_BASE_ZMQ_PORT = 36792

DCR_BASE_PORT = 18555
DCR_BASE_RPC_PORT = 9110


PIVX_BASE_PORT = 34892
PIVX_BASE_RPC_PORT = 35892
PIVX_BASE_ZMQ_PORT = 36892

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

        if base_p2p_port == BTC_BASE_PORT:
            fp.write('deprecatedrpc=create_bdb\n')
        elif base_p2p_port == BASE_PORT:  # Particl
            fp.write('zmqpubsmsg=tcp://127.0.0.1:{}\n'.format(BASE_ZMQ_PORT + node_id))
            # minstakeinterval=5  # Using walletsettings stakelimit instead
            fp.write('stakethreadconddelayms=1000\n')
            fp.write('smsgsregtestadjust=0\n')

        if conf_file == 'pivx.conf':
            params_dir = os.path.join(datadir, 'pivx-params')
            downloadPIVXParams(params_dir)
            fp.write(f'paramsdir={params_dir}\n')

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            fp.write('addnode=127.0.0.1:{}\n'.format(base_p2p_port + i))

    return node_dir


def checkForks(ro):
    try:
        if 'bip9_softforks' in ro:
            assert (ro['bip9_softforks']['csv']['status'] == 'active')
            assert (ro['bip9_softforks']['segwit']['status'] == 'active')
        else:
            assert (ro['softforks']['csv']['active'])
            assert (ro['softforks']['segwit']['active'])
    except Exception as e:
        logging.warning('Could not parse deployment info')


def stopDaemons(daemons):
    for d in daemons:
        logging.info('Interrupting %d', d.handle.pid)
        try:
            d.handle.send_signal(signal.SIGINT)
        except Exception as e:
            logging.info('Interrupting %d, error %s', d.handle.pid, str(e))
    for d in daemons:
        try:
            d.handle.wait(timeout=20)
            for fp in [d.handle.stdout, d.handle.stderr, d.handle.stdin] + d.files:
                if fp:
                    fp.close()
        except Exception as e:
            logging.info('Closing %d, error %s', d.handle.pid, str(e))


def wait_for_bid(delay_event, swap_client, bid_id, state=None, sent: bool = False, wait_for: int = 20) -> None:
    logging.info('wait_for_bid %s', bid_id.hex())
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)

        filters = {
            'bid_id': bid_id,
        }
        bids = swap_client.listBids(sent=sent, filters=filters)
        assert (len(bids) < 2)
        for bid in bids:
            if bid[2] == bid_id:
                if isinstance(state, list):
                    if bid[5] in state:
                        return
                    else:
                        continue
                elif state is not None and state != bid[5]:
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


def wait_for_event(delay_event, swap_client, linked_type, linked_id, event_type=None, wait_for=20):
    logging.info('wait_for_event')

    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        delay_event.wait(1)
        rv = swap_client.getEvents(linked_type, linked_id)

        for event in rv:
            if event_type is None or event.event_type == event_type:
                return event
    raise ValueError('wait_for_event timed out.')


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
        js = read_json_api(port)
        if js['num_swapping'] == 0 and js['num_watched_outputs'] == 0:
            return
    raise ValueError('wait_for_none_active timed out.')


def abandon_all_swaps(delay_event, swap_client) -> None:
    logging.info('abandon_all_swaps')
    for bid in swap_client.listBids(sent=True):
        swap_client.abandonBid(bid[2])
    for bid in swap_client.listBids(sent=False):
        swap_client.abandonBid(bid[2])


def waitForNumOffers(delay_event, port, offers, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = read_json_api(port)
        if summary['num_network_offers'] >= offers:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumOffers failed')


def waitForNumBids(delay_event, port, bids, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = read_json_api(port)
        if summary['num_recv_bids'] >= bids:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumBids failed')


def waitForNumSwapping(delay_event, port, bids, wait_for=60):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        summary = read_json_api(port)
        if summary['num_swapping'] >= bids:
            return
        delay_event.wait(1)
    raise ValueError('waitForNumSwapping failed')


def wait_for_balance(delay_event, url, balance_key, expect_amount, iterations=20, delay_time=3) -> None:
    i = 0
    while not delay_event.is_set():
        rv_js = json.loads(urlopen(url).read())
        if float(rv_js[balance_key]) >= expect_amount:
            return
        delay_event.wait(delay_time)
        i += 1
        if i > iterations:
            raise ValueError('Expect {} {}'.format(balance_key, expect_amount))


def wait_for_unspent(delay_event, ci, expect_amount, iterations=20, delay_time=1) -> None:
    logging.info(f'Waiting for unspent balance: {expect_amount}')
    i = 0
    while not delay_event.is_set():
        unspent_addr = ci.getUnspentsByAddr()
        for _, value in unspent_addr.items():
            if value >= expect_amount:
                return
        delay_event.wait(delay_time)
        i += 1
        if i > iterations:
            raise ValueError('wait_for_unspent {}'.format(expect_amount))


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


def waitForRPC(rpc_func, delay_event, rpc_command='getwalletinfo', max_tries=7):
    for i in range(max_tries + 1):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        try:
            rpc_func(rpc_command)
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning('Can\'t connect to RPC: %s. Retrying in %d second/s.', str(ex), (i + 1))
                delay_event.wait(i + 1)
    raise ValueError('waitForRPC failed')


def extract_states_from_xu_file(file_path, prefix):
    states = {}

    alt_counter = 0
    active_path = 0
    states[active_path] = []
    path_stack = [active_path, ]
    with open(file_path) as fp:
        for line in fp:
            line = line.strip()
            if line.startswith('#'):
                continue

            if line == '};':
                if len(path_stack) > 1:
                    path_stack.pop()
                    active_path = path_stack[-1]
                continue

            split_line = line.split('[')
            if len(split_line) < 2:
                continue

            definitions = split_line[0].split(' ')
            if len(definitions) < 2:
                continue

            if definitions[1] == 'alt':
                alt_counter += 1
                path_stack.append(alt_counter)

                states[alt_counter] = [s for s in states[active_path]]
                continue

            if definitions[0] == '---':
                active_path = path_stack[-1]
                continue

            if definitions[1] != 'abox':
                continue
            if definitions[0] != prefix:
                continue

            tag_start = 'label="'
            tag_end = '"'
            pos_start = split_line[1].find(tag_start)
            if pos_start < 0:
                continue
            pos_start += len(tag_start)
            pos_end = split_line[1].find(tag_end, pos_start)
            if pos_end < 0:
                continue
            label = split_line[1][pos_start:pos_end]

            if line.find('textbgcolor') > 0:
                # transaction status
                pass

            states[active_path].append(label)

    return states


def compare_bid_states(states, expect_states, exact_match: bool = True) -> bool:

    for i in range(len(states) - 1, -1, -1):
        if states[i][1] == 'Bid Delaying':
            del states[i]

    try:
        if exact_match:
            assert (len(states) == len(expect_states))
        else:
            assert (len(states) >= len(expect_states))

        for i in range(len(expect_states)):
            s = states[i]
            if s[1] != expect_states[i]:
                if 'Bid ' + expect_states[i] == s[1]:
                    logging.warning(f'Expected state {expect_states[i]} not an exact match to {s[1]}.')
                    continue
                if [s[0], expect_states[i]] in states:
                    logging.warning(f'Expected state {expect_states[i]} found out of order at the same time as {s[1]}.')
                    continue
                raise ValueError(f'Expected state {expect_states[i]}, found {s[1]}')
            assert (s[1] == expect_states[i])
    except Exception as e:
        logging.info('Expecting states: {}'.format(json.dumps(expect_states, indent=4)))
        logging.info('Have states: {}'.format(json.dumps(states, indent=4)))
        raise e
    return True


def compare_bid_states_unordered(states, expect_states, ignore_states=[]) -> bool:
    ignore_states.append('Bid Delaying')
    for i in range(len(states) - 1, -1, -1):
        if states[i][1] in ignore_states:
            del states[i]

    try:
        assert len(states) == len(expect_states)
        for state in expect_states:
            assert (any(state in s[1] for s in states))
    except Exception as e:
        logging.info('Expecting states: {}'.format(json.dumps(expect_states, indent=4)))
        logging.info('Have states: {}'.format(json.dumps(states, indent=4)))
        raise e
    return True
