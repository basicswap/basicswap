#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Start test_xmr_persistent.py

python tests/basicswap/extended/test_scripts.py

pytest -v -s tests/basicswap/extended/test_scripts.py::Test::test_bid_tracking

"""

import os
import sys
import json
import time
import math
import logging
import sqlite3
import unittest
import threading
import subprocess
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import parse

from tests.basicswap.util import (
    read_json_api,
    waitForServer,
)


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


PORT_OFS = int(os.getenv('PORT_OFS', 1))
UI_PORT = 12700 + PORT_OFS


class HttpHandler(BaseHTTPRequestHandler):

    def js_response(self, url_split, post_string, is_json):
        return bytes(json.dumps(self.server.return_data[url_split[3]]), 'UTF-8')

    def putHeaders(self, status_code, content_type):
        self.send_response(status_code)
        self.send_header('Content-Type', content_type)
        self.end_headers()

    def handle_http(self, status_code, path, post_string='', is_json=False):
        parsed = parse.urlparse(self.path)
        url_split = parsed.path.split('/')
        if post_string == '' and len(parsed.query) > 0:
            post_string = parsed.query
        if len(url_split) > 1 and url_split[1] == 'json':
            self.putHeaders(status_code, 'text/plain')
            return self.js_response(url_split, post_string, is_json)

        self.putHeaders(status_code, 'text/plain')
        return bytes('No response', 'UTF-8')

    def do_GET(self):
        response = self.handle_http(200, self.path)
        self.wfile.write(response)

    def do_POST(self):
        post_string = self.rfile.read(int(self.headers.get('Content-Length')))

        is_json = True if 'json' in self.headers.get('Content-Type', '') else False
        response = self.handle_http(200, self.path, post_string, is_json)
        self.wfile.write(response)

    def do_HEAD(self):
        self.putHeaders(200, 'text/html')


class HttpThread(threading.Thread, HTTPServer):
    host = '127.0.0.1'
    port_no = 12699
    stop_event = threading.Event()
    return_data = {'test': 1}

    def __init__(self):
        threading.Thread.__init__(self)

        HTTPServer.__init__(self, (self.host, self.port_no), HttpHandler)

    def stop(self):
        self.stop_event.set()

        # Send fake request
        conn = http.client.HTTPConnection(self.host, self.port_no)
        conn.connect()
        conn.request('GET', '/none')
        response = conn.getresponse()
        data = response.read()
        conn.close()

    def serve_forever(self):
        while not self.stop_event.is_set():
            self.handle_request()
        self.socket.close()

    def run(self):
        self.serve_forever()


def clear_offers(delay_event, node_id) -> None:
    logging.info(f'clear_offers node {node_id}')
    offers = read_json_api(UI_PORT + node_id, 'offers')

    for offer in offers:
        read_json_api(UI_PORT + node_id, 'revokeoffer/{}'.format(offer['offer_id']))

    for i in range(20):
        delay_event.wait(1)
        offers = read_json_api(UI_PORT + node_id, 'offers')
        if len(offers) == 0:
            return
    raise ValueError('clear_offers failed')


def wait_for_offers(delay_event, node_id, num_offers) -> None:
    logging.info(f'Waiting for {num_offers} offers on node {node_id}')
    for i in range(20):
        delay_event.wait(1)
        offers = read_json_api(UI_PORT + node_id, 'offers')
        if len(offers) >= num_offers:
            return
    raise ValueError('wait_for_offers failed')


def delete_file(filepath: str) -> None:
    if os.path.exists(filepath):
        os.remove(filepath)


def get_created_offers(rv_stdout):
    offers = []
    for line in rv_stdout:
        if line.startswith('New offer'):
            offers.append(line.split(':')[1].strip())
    return offers


def count_lines_with(rv_stdout, str_needle):
    lines_found = 0
    for line in rv_stdout:
        if str_needle in line:
            lines_found += 1
    return lines_found


def get_created_bids(rv_stdout):
    bids = []
    for line in rv_stdout:
        if line.startswith('New bid'):
            bids.append(line.split(':')[1].strip())
    return bids


def get_possible_bids(rv_stdout):
    bids = []
    tag = 'Would create bid: '
    for line in rv_stdout:
        if line.startswith(tag):
            bids.append(json.loads(line[len(tag):].replace("'", '"')))
    return bids


class Test(unittest.TestCase):
    delay_event = threading.Event()
    thread_http = HttpThread()

    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()
        cls.thread_http.start()

        script_path = 'scripts/createoffers.py'
        datadir = '/tmp/bsx_scripts'
        if not os.path.isdir(datadir):
            os.makedirs(datadir)

        cls.node0_configfile = os.path.join(datadir, 'node0.json')
        cls.node0_statefile = os.path.join(datadir, 'node0_state.json')
        cls.node0_args = [script_path, '--port', str(UI_PORT), '--configfile', cls.node0_configfile, '--statefile', cls.node0_statefile, '--oneshot', '--debug']

        cls.node1_configfile = os.path.join(datadir, 'node1.json')
        cls.node1_statefile = os.path.join(datadir, 'node1_state.json')
        cls.node1_args = [script_path, '--port', str(UI_PORT + 1), '--configfile', cls.node1_configfile, '--statefile', cls.node1_statefile, '--oneshot', '--debug']

    @classmethod
    def tearDownClass(cls):
        logging.info('Stopping test')
        cls.thread_http.stop()

    def test_enabled(self):

        waitForServer(self.delay_event, UI_PORT + 0)
        waitForServer(self.delay_event, UI_PORT + 1)

        # Test no 'Processing...' messages are shown without config
        node0_test_config = {}
        with open(self.node0_configfile, 'w') as fp:
            json.dump(node0_test_config, fp, indent=4)
        result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Processing') == 0)

        # Test that enabled templates are processed
        node0_test_config = {
            'test_mode': True,
            'offers': [
                {
                    'name': 'offer example 1',
                    'coin_from': 'Particl',
                    'coin_to': 'Monero',
                    'amount': 20,
                    'minrate': 0.05,
                    'ratetweakpercent': 5,
                    'amount_variable': True,
                    'address': -1,
                    'min_coin_from_amt': 20,
                    'max_coin_to_amt': -1
                },
            ],
            'bids': [
                {
                    'coin_from': 'PART',
                    'coin_to': 'XMR',
                    'amount': 10,
                    'maxrate': 0.04,
                    'amount_variable': True,
                    'address': -1,
                    'min_swap_amount': 0.1,
                    'max_coin_from_balance': -1,
                    'min_coin_to_balance': -1,
                },
            ],
            'stealthex': [
                {
                    'coin_from': 'XMR',
                    'coin_to': 'BTC',
                    'min_balance_from': 1,
                    'min_amount_tx': 1,
                    'max_amount_tx': 5,
                    'min_rate': 0.01,
                    'refund_address': 'auto',
                    'receive_address': 'auto',
                    'api_key': 'API_KEY_HERE'
                }
            ],
        }
        with open(self.node0_configfile, 'w') as fp:
            json.dump(node0_test_config, fp, indent=4)

        result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Processing 1 offer template') == 1)
        assert (count_lines_with(rv_stdout, 'Processing 1 bid template') == 1)
        assert (count_lines_with(rv_stdout, 'Processing 1 stealthex template') == 1)

        # Test that disabled templates are not processed
        node0_test_config['offers'][0]['enabled'] = False
        node0_test_config['bids'][0]['enabled'] = False
        node0_test_config['stealthex'][0]['enabled'] = False
        with open(self.node0_configfile, 'w') as fp:
            json.dump(node0_test_config, fp, indent=4)

        result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Processing 0 offer templates') == 1)
        assert (count_lines_with(rv_stdout, 'Processing 0 bid templates') == 1)
        assert (count_lines_with(rv_stdout, 'Processing 0 stealthex templates') == 1)

    def test_offers(self):

        waitForServer(self.delay_event, UI_PORT + 0)
        waitForServer(self.delay_event, UI_PORT + 1)

        # Reset test
        clear_offers(self.delay_event, 0)
        delete_file(self.node0_statefile)
        delete_file(self.node1_statefile)
        wait_for_offers(self.delay_event, 1, 0)

        node0_test1_config = {
            'offers': [
                {
                    'name': 'offer example 1',
                    'coin_from': 'Particl',
                    'coin_to': 'Monero',
                    'amount': 20,
                    'minrate': 0.05,
                    'ratetweakpercent': 5,
                    'amount_variable': True,
                    'address': -1,
                    'min_coin_from_amt': 20,
                    'max_coin_to_amt': -1
                },
                {
                    'name': 'offer example 1_2',
                    'coin_from': 'Particl',
                    'coin_to': 'Monero',
                    'amount': 21,
                    'minrate': 0.07,
                    'ratetweakpercent': 5,
                    'amount_variable': True,
                    'address': -1,
                    'min_coin_from_amt': 21,
                    'max_coin_to_amt': -1
                }
            ],
        }
        with open(self.node0_configfile, 'w') as fp:
            json.dump(node0_test1_config, fp, indent=4)

        logging.info('Test that an offer is created')
        result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (len(get_created_offers(rv_stdout)) == 1)

        offers = read_json_api(UI_PORT, 'offers')
        assert (len(offers) == 1)

        logging.info('Test that an offer is not created while delaying')
        result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (len(get_created_offers(rv_stdout)) == 0)

        with open(self.node0_statefile) as fs:
            node0_state = json.load(fs)
        node0_state['delay_next_offer_before'] = 0
        with open(self.node0_statefile, 'w') as fp:
            json.dump(node0_state, fp, indent=4)

        logging.info('Test that the second offer is created when not delaying')
        result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (len(get_created_offers(rv_stdout)) == 1)

        with open(self.node0_statefile) as fs:
            node0_state = json.load(fs)
        assert (len(node0_state['offers']['offer example 1']) == 1)
        assert (len(node0_state['offers']['offer example 1_2']) == 1)

        offers = read_json_api(UI_PORT, 'offers')
        assert (len(offers) == 2)

        addr_bid_from = read_json_api(UI_PORT + 1, 'smsgaddresses/new')['new_address']
        node1_test1_config = {
            'bids': [
                {
                    'name': 'bid example 1',
                    'coin_from': 'PART',
                    'coin_to': 'XMR',
                    'amount': 10,
                    'maxrate': 0.06,
                    'amount_variable': True,
                    'address': addr_bid_from,
                    'min_swap_amount': 0.1,
                    'max_coin_from_balance': -1,
                    'min_coin_to_balance': -1,
                    'max_concurrent': 4,
                },
                {
                    'coin_from': 'PART',
                    'coin_to': 'XMR',
                    'amount': 10,
                    'maxrate': 0.04,
                    'amount_variable': True,
                    'address': -1,
                    'min_swap_amount': 0.1,
                    'max_coin_from_balance': -1,
                    'min_coin_to_balance': -1,
                }
            ],
        }
        with open(self.node1_configfile, 'w') as fp:
            json.dump(node1_test1_config, fp, indent=4)

        wait_for_offers(self.delay_event, 1, 2)

        logging.info('Test that a bid is created')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (len(get_created_bids(rv_stdout)) == 1)

        logging.info('Test no bids are created while delaying')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Delaying bids until') == 1)

        with open(self.node1_statefile) as fs:
            node1_state = json.load(fs)
        node1_state['delay_next_bid_before'] = 0
        with open(self.node1_statefile, 'w') as fp:
            json.dump(node1_state, fp, indent=4)

        logging.info('Test that a bid is not created if one already exists on that offer')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Bid rate too low for offer') == 3)
        assert (count_lines_with(rv_stdout, 'Already bidding on offer') == 1)

        logging.info('Modifying node1 config')
        node1_test1_config['bids'][0]['maxrate'] = 0.07
        node1_test1_config['bids'][0]['max_coin_from_balance'] = 100
        node1_test1_config['bids'][0]['min_coin_to_balance'] = 100
        node1_test1_config['bids'][0]['min_swap_amount'] = 9
        node1_test1_config['wallet_port_override'] = 12699
        node1_test1_config['test_mode'] = True
        with open(self.node1_configfile, 'w') as fp:
            json.dump(node1_test1_config, fp, indent=4)

        self.thread_http.return_data = {
            'PART': {
                'balance': '0.0',
                'unconfirmed': '0.0',
                'expected_seed': True,
                'encrypted': False,
                'locked': False,
                'anon_balance': 0.0,
                'anon_pending': 0.0,
                'blind_balance': 0.0,
                'blind_unconfirmed': 0.0,
                'version': 23000300,
                'name': 'Particl',
                'blocks': 3556,
                'synced': '100.00'
            },
            'XMR': {
                'balance': '362299.12',
                'unconfirmed': '0.0',
                'expected_seed': True,
                'encrypted': False,
                'locked': False,
                'main_address': '',
                'version': 65562,
                'name': 'Monero',
                'blocks': 10470,
                'synced': '100.00',
                'known_block_count': 10470
            }
        }

        logging.info('Check max bid value')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        possible_bids = get_possible_bids(rv_stdout)
        assert (len(possible_bids) == 1)
        assert (float(possible_bids[0]['amount_from']) == 10.0)

        logging.info('Raise node1 bid0 value')
        node1_test1_config['bids'][0]['amount'] = 50
        with open(self.node1_configfile, 'w') as fp:
            json.dump(node1_test1_config, fp, indent=4)
        delete_file(self.node1_statefile)

        # Check max_coin_from_balance (bids increase coin_from)
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        possible_bids = get_possible_bids(rv_stdout)
        assert (len(possible_bids) == 1)
        assert (float(possible_bids[0]['amount_from']) == 21.0)

        # Test multiple bids are delayed
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Delaying bids until') == 1)

        delete_file(self.node1_statefile)
        self.thread_http.return_data['PART']['balance'] = 100.0
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Bid amount would exceed maximum wallet total') == 1)

        self.thread_http.return_data['PART']['balance'] = 90.0
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        possible_bids = get_possible_bids(rv_stdout)
        assert (len(possible_bids) == 1)
        assert (math.isclose(float(possible_bids[0]['amount_from']), 10.0))

        # Check min_swap_amount
        delete_file(self.node1_statefile)
        self.thread_http.return_data['PART']['balance'] = 95.0
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        possible_bids = get_possible_bids(rv_stdout)
        assert (count_lines_with(rv_stdout, 'Bid amount would exceed maximum wallet total') == 1)

        # Check min_coin_to_balance (bids decrease coin_to)
        self.thread_http.return_data['PART']['balance'] = 0.0
        self.thread_http.return_data['XMR']['balance'] = 101.0

        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        possible_bids = get_possible_bids(rv_stdout)
        possible_bids = get_possible_bids(rv_stdout)
        assert (len(possible_bids) == 1)
        assert (float(possible_bids[0]['amount_from'] < 20.0))

        logging.info('Adding mock data to node1 db for tests')
        rows = []
        offers = read_json_api(UI_PORT, 'offers')

        now = int(time.time())
        for offer in offers:
            rows.append((1, offer['addr_from'], 5, 5, now, now))
        db_path = '/tmp/test_persistent/client1/db_regtest.sqlite'
        with sqlite3.connect(db_path) as dbc:
            c = dbc.cursor()
            c.executemany('INSERT INTO knownidentities (active_ind, address, num_sent_bids_failed, num_recv_bids_failed, updated_at, created_at) VALUES (?,?,?,?,?,?)', rows)
            dbc.commit()

        delete_file(self.node1_statefile)
        self.thread_http.return_data['XMR']['balance'] = 10000.0
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (len(get_possible_bids(get_possible_bids(rv_stdout))) == 0)
        assert (count_lines_with(rv_stdout, 'too many failed bids') == 1)

        '''
        TODO
        node0_test1_config['stealthex'] = [
            {
                'coin_from': 'XMR',
                'coin_to': 'BTC',
                'min_balance_from': 1,
                'min_amount_tx': 1,
                'max_amount_tx': 5,
                'min_rate': 0.01,
                'refund_address': 'auto',
                'receive_address': 'auto',
                'api_key': 'API_KEY_HERE'
            }
        ]
        node0_test1_config['wallet_port_override'] = 12699
        node0_test1_config['test_mode'] = True
        with open(self.node0_configfile, 'w') as fp:
            json.dump(node0_test1_config, fp, indent=4)

        result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        '''

    def test_bid_tracking(self):

        waitForServer(self.delay_event, UI_PORT + 0)
        waitForServer(self.delay_event, UI_PORT + 1)

        # Reset test
        clear_offers(self.delay_event, 0)
        delete_file(self.node0_statefile)
        delete_file(self.node1_statefile)
        wait_for_offers(self.delay_event, 1, 0)

        addrs = []
        for i in range(2):
            addrs.append(read_json_api(UI_PORT, 'smsgaddresses/new')['new_address'])

        node0_test2_config = {
            'offers': [
                {
                    'name': 'offer example 1',
                    'coin_from': 'Particl',
                    'coin_to': 'Monero',
                    'amount': 20,
                    'minrate': 0.04,
                    'ratetweakpercent': 5,
                    'amount_variable': True,
                    'address': addrs[0],
                    'min_coin_from_amt': 20,
                    'max_coin_to_amt': -1
                },
                {
                    'name': 'offer example 1_2',
                    'coin_from': 'Particl',
                    'coin_to': 'Monero',
                    'amount': 21,
                    'minrate': 0.05,
                    'ratetweakpercent': 5,
                    'amount_variable': True,
                    'address': addrs[1],
                    'min_coin_from_amt': 21,
                    'max_coin_to_amt': -1
                },
                {
                    'name': 'offer example 1_3',
                    'coin_from': 'Particl',
                    'coin_to': 'Monero',
                    'amount': 22,
                    'minrate': 0.06,
                    'ratetweakpercent': 5,
                    'amount_variable': True,
                    'address': 'auto',
                    'min_coin_from_amt': 22,
                    'max_coin_to_amt': -1
                }
            ],
        }
        with open(self.node0_configfile, 'w') as fp:
            json.dump(node0_test2_config, fp, indent=4)

        offer_ids = []
        logging.info('Create three offers')

        for i in range(3):
            if i > 0:
                with open(self.node0_statefile) as fs:
                    node0_state = json.load(fs)
                node0_state['delay_next_offer_before'] = 0
                with open(self.node0_statefile, 'w') as fp:
                    json.dump(node0_state, fp, indent=4)

            result = subprocess.run(self.node0_args, stdout=subprocess.PIPE)
            rv_stdout = result.stdout.decode().split('\n')
            created_offers = get_created_offers(rv_stdout)
            assert (len(get_created_offers(rv_stdout)) == 1)
            offer_ids.append(created_offers[0])

        found_addrs = {}
        for offer_id in offer_ids:
            offer = read_json_api(UI_PORT, f'offers/{offer_id}')[0]
            found_addrs[offer['addr_from']] = found_addrs.get(offer['addr_from'], 0) + 1

        for addr in addrs:
            assert (found_addrs[addr] == 1)

        addr_bid_from = read_json_api(UI_PORT + 1, 'smsgaddresses/new')['new_address']
        node1_test1_config = {
            'bids': [
                {
                    'name': 'bid example 1',
                    'coin_from': 'PART',
                    'coin_to': 'XMR',
                    'amount': 50,
                    'maxrate': 0.08,
                    'amount_variable': False,
                    'address': addr_bid_from,
                    'min_swap_amount': 1,
                    'max_coin_from_balance': -1,
                    'min_coin_to_balance': -1
                }
            ],
        }
        with open(self.node1_configfile, 'w') as fp:
            json.dump(node1_test1_config, fp, indent=4)

        wait_for_offers(self.delay_event, 1, 3)

        logging.info('Check that no bids are created (offer values too low)')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (len(get_created_bids(rv_stdout)) == 0)
        assert (count_lines_with(rv_stdout, 'Bid amount too high for offer') == 3)

        node1_test1_config['bids'][0]['amount_variable'] = True
        with open(self.node1_configfile, 'w') as fp:
            json.dump(node1_test1_config, fp, indent=4)

        logging.info('Check that one bid is created at the best rate')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        created_bids = get_created_bids(rv_stdout)
        assert (len(created_bids) == 1)

        bid_id = created_bids[0].split(' ')[0]
        bid = read_json_api(UI_PORT + 1, f'bids/{bid_id}')
        assert (math.isclose(float(bid['bid_rate']), 0.04))
        assert (math.isclose(float(bid['amt_from']), 20.0))
        assert (bid['addr_from'] == addr_bid_from)

        logging.info('Check that bids are delayed')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (count_lines_with(rv_stdout, 'Delaying bids until') == 1)
        assert (len(get_created_bids(rv_stdout)) == 0)

        with open(self.node1_statefile) as fs:
            node1_state = json.load(fs)
        node1_state['delay_next_bid_before'] = 0
        with open(self.node1_statefile, 'w') as fp:
            json.dump(node1_state, fp, indent=4)

        logging.info('Test that a bid is not created while one is active')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        assert (len(get_created_bids(rv_stdout)) == 0)
        assert (count_lines_with(rv_stdout, 'Max concurrent bids') == 1)

        logging.info('Waiting for bid to complete')
        bid_complete: bool = False
        for i in range(60):
            self.delay_event.wait(5)
            bid = read_json_api(UI_PORT + 1, f'bids/{bid_id}')
            print('bid_state', bid['bid_state'])
            if bid['bid_state'] == 'Completed':
                bid_complete = True
                break

        assert bid_complete

        logging.info('Test that a bid is created after one expires')
        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        created_bids = get_created_bids(rv_stdout)
        assert (len(created_bids) == 1)
        assert (count_lines_with(rv_stdout, 'Marking bid inactive') == 1)

        logging.info('Test that two bids are created if max concurrent is raised')
        node1_test1_config['bids'][0]['max_concurrent'] = 2
        with open(self.node1_configfile, 'w') as fp:
            json.dump(node1_test1_config, fp, indent=4)

        with open(self.node1_statefile) as fs:
            node1_state = json.load(fs)
        node1_state['delay_next_bid_before'] = 0
        with open(self.node1_statefile, 'w') as fp:
            json.dump(node1_state, fp, indent=4)

        result = subprocess.run(self.node1_args, stdout=subprocess.PIPE)
        rv_stdout = result.stdout.decode().split('\n')
        created_bids = get_created_bids(rv_stdout)
        assert (len(created_bids) == 1)

        bid_id = created_bids[0].split(' ')[0]
        bid = read_json_api(UI_PORT + 1, f'bids/{bid_id}')
        assert (math.isclose(float(bid['bid_rate']), 0.05))
        assert (math.isclose(float(bid['amt_from']), 21.0))
        assert (bid['addr_from'] == addr_bid_from)


if __name__ == '__main__':
    unittest.main()
