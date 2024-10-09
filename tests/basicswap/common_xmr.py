#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import json
import shutil
import signal
import logging
import unittest
import threading
import multiprocessing
from io import StringIO
from urllib.request import urlopen
from unittest.mock import patch

from basicswap.rpc_xmr import (
    callrpc_xmr,
)
from tests.basicswap.mnemonics import mnemonics
from tests.basicswap.util import (
    waitForServer,
)
from tests.basicswap.common import (
    BASE_PORT, BASE_RPC_PORT,
    BTC_BASE_PORT, BTC_BASE_RPC_PORT, BTC_BASE_TOR_PORT,
    LTC_BASE_PORT, LTC_BASE_RPC_PORT,
    DCR_BASE_PORT, DCR_BASE_RPC_PORT,
    PIVX_BASE_PORT,
)
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac

import basicswap.config as cfg
import basicswap.bin.run as runSystem

TEST_PATH = os.path.expanduser(os.getenv('TEST_PATH', '~/test_basicswap1'))

PARTICL_PORT_BASE = int(os.getenv('PARTICL_PORT_BASE', BASE_PORT))
PARTICL_RPC_PORT_BASE = int(os.getenv('PARTICL_RPC_PORT_BASE', BASE_RPC_PORT))

BITCOIN_PORT_BASE = int(os.getenv('BITCOIN_PORT_BASE', BTC_BASE_PORT))
BITCOIN_RPC_PORT_BASE = int(os.getenv('BITCOIN_RPC_PORT_BASE', BTC_BASE_RPC_PORT))
BITCOIN_TOR_PORT_BASE = int(os.getenv('BITCOIN_TOR_PORT_BASE', BTC_BASE_TOR_PORT))

LITECOIN_RPC_PORT_BASE = int(os.getenv('LITECOIN_RPC_PORT_BASE', LTC_BASE_RPC_PORT))
DECRED_RPC_PORT_BASE = int(os.getenv('DECRED_RPC_PORT_BASE', DCR_BASE_RPC_PORT))

FIRO_BASE_PORT = 34832
FIRO_BASE_RPC_PORT = 35832
FIRO_RPC_PORT_BASE = int(os.getenv('FIRO_RPC_PORT_BASE', FIRO_BASE_RPC_PORT))


XMR_BASE_P2P_PORT = 17792
XMR_BASE_RPC_PORT = 29798
XMR_BASE_WALLET_RPC_PORT = 29998

EXTRA_CONFIG_JSON = json.loads(os.getenv('EXTRA_CONFIG_JSON', '{}'))


def waitForBidState(delay_event, port, bid_id, state_str, wait_for=60):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        bid = json.loads(urlopen('http://127.0.0.1:12700/json/bids/{}'.format(bid_id)).read())
        if bid['bid_state'] == state_str:
            return
        delay_event.wait(1)
    raise ValueError('waitForBidState failed')


def updateThread(xmr_addr, delay_event, xmr_auth):
    while not delay_event.is_set():
        try:
            callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr, 'amount_of_blocks': 1}, auth=xmr_auth)
        except Exception as e:
            print('updateThread error', str(e))
        delay_event.wait(2)


def recursive_update_dict(base, new_vals):
    for key, value in new_vals.items():
        if key in base and isinstance(value, dict):
            recursive_update_dict(base[key], value)
        else:
            base[key] = value


def run_prepare(node_id, datadir_path, bins_path, with_coins, mnemonic_in=None, num_nodes=3, use_rpcauth=False, extra_settings={}, port_ofs=0):
    config_path = os.path.join(datadir_path, cfg.CONFIG_FILENAME)

    os.environ['BSX_TEST_MODE'] = 'true'
    os.environ['PART_RPC_PORT'] = str(PARTICL_RPC_PORT_BASE)
    os.environ['BTC_RPC_PORT'] = str(BITCOIN_RPC_PORT_BASE)
    os.environ['LTC_RPC_PORT'] = str(LITECOIN_RPC_PORT_BASE)
    os.environ['DCR_RPC_PORT'] = str(DECRED_RPC_PORT_BASE)
    os.environ['FIRO_RPC_PORT'] = str(FIRO_RPC_PORT_BASE)

    os.environ['XMR_RPC_USER'] = 'xmr_user'
    os.environ['XMR_RPC_PWD'] = 'xmr_pwd'

    os.environ['DCR_RPC_PWD'] = 'dcr_pwd'

    import basicswap.bin.prepare as prepareSystem
    # Hack: Reload module to set env vars as the basicswap_prepare module is initialised if imported from elsewhere earlier
    from importlib import reload
    prepareSystem = reload(prepareSystem)

    testargs = [
        'basicswap-prepare',
        f'-datadir="{datadir_path}"',
        f'-bindir="{bins_path}"',
        f'-portoffset={(node_id + port_ofs)}',
        '-regtest',
        f'-withcoins={with_coins}',
        '-noextractover',
        '-xmrrestoreheight=0']
    if mnemonic_in:
        testargs.append(f'-particl_mnemonic="{mnemonic_in}"')

    keysdirpath = os.getenv('PGP_KEYS_DIR_PATH', None)
    if keysdirpath is not None:
        testargs.append('-keysdirpath="' + os.path.expanduser(keysdirpath) + '"')
    with patch.object(sys, 'argv', testargs), patch('sys.stdout', new=StringIO()) as mocked_stdout:
        prepareSystem.main()
        lines = mocked_stdout.getvalue().split('\n')
        if mnemonic_in is None:
            mnemonic_out = lines[-4]
        else:
            mnemonic_out = mnemonic_in

    with open(config_path) as fs:
        settings = json.load(fs)

    config_filename = os.path.join(datadir_path, 'particl', 'particl.conf')
    with open(config_filename, 'r') as fp:
        lines = fp.readlines()
    with open(config_filename, 'w') as fp:
        for line in lines:
            if not line.startswith('staking'):
                fp.write(line)
        fp.write('port={}\n'.format(PARTICL_PORT_BASE + node_id + port_ofs))
        fp.write('bind=127.0.0.1\n')
        fp.write('dnsseed=0\n')
        fp.write('discover=0\n')
        fp.write('listenonion=0\n')
        fp.write('upnp=0\n')
        fp.write('minstakeinterval=5\n')
        fp.write('stakethreadconddelayms=2000\n')
        fp.write('smsgsregtestadjust=0\n')
        if use_rpcauth:
            salt = generate_salt(16)
            rpc_user = 'test_part_' + str(node_id)
            rpc_pass = 'test_part_pwd_' + str(node_id)
            fp.write('rpcauth={}:{}${}\n'.format(rpc_user, salt, password_to_hmac(salt, rpc_pass)))
            settings['chainclients']['particl']['rpcuser'] = rpc_user
            settings['chainclients']['particl']['rpcpassword'] = rpc_pass
        for ip in range(num_nodes):
            if ip != node_id:
                fp.write('connect=127.0.0.1:{}\n'.format(PARTICL_PORT_BASE + ip + port_ofs))
        for opt in EXTRA_CONFIG_JSON.get('part{}'.format(node_id), []):
            fp.write(opt + '\n')

    coins_array = with_coins.split(',')

    if 'bitcoin' in coins_array:
        # Pruned nodes don't provide blocks
        config_filename = os.path.join(datadir_path, 'bitcoin', 'bitcoin.conf')
        with open(config_filename, 'r') as fp:
            lines = fp.readlines()
        with open(config_filename, 'w') as fp:
            for line in lines:
                if not line.startswith('prune'):
                    fp.write(line)
            fp.write('port={}\n'.format(BITCOIN_PORT_BASE + node_id + port_ofs))
            fp.write('bind=127.0.0.1\n')
            # listenonion=0 does not stop the node from trying to bind to the tor port
            # https://github.com/bitcoin/bitcoin/issues/22726
            fp.write('bind=127.0.0.1:{}=onion\n'.format(BITCOIN_TOR_PORT_BASE + node_id + port_ofs))
            fp.write('dnsseed=0\n')
            fp.write('discover=0\n')
            fp.write('listenonion=0\n')
            fp.write('upnp=0\n')
            if use_rpcauth:
                salt = generate_salt(16)
                rpc_user = 'test_btc_' + str(node_id)
                rpc_pass = 'test_btc_pwd_' + str(node_id)
                fp.write('rpcauth={}:{}${}\n'.format(rpc_user, salt, password_to_hmac(salt, rpc_pass)))
                settings['chainclients']['bitcoin']['rpcuser'] = rpc_user
                settings['chainclients']['bitcoin']['rpcpassword'] = rpc_pass
            for ip in range(num_nodes):
                if ip != node_id:
                    fp.write('connect=127.0.0.1:{}\n'.format(BITCOIN_PORT_BASE + ip + port_ofs))
            for opt in EXTRA_CONFIG_JSON.get('btc{}'.format(node_id), []):
                fp.write(opt + '\n')

    if 'litecoin' in coins_array:
        # Pruned nodes don't provide blocks
        config_filename = os.path.join(datadir_path, 'litecoin', 'litecoin.conf')
        with open(config_filename, 'r') as fp:
            lines = fp.readlines()
        with open(config_filename, 'w') as fp:
            for line in lines:
                if not line.startswith('prune'):
                    fp.write(line)
            fp.write('port={}\n'.format(LTC_BASE_PORT + node_id + port_ofs))
            fp.write('bind=127.0.0.1\n')
            fp.write('dnsseed=0\n')
            fp.write('discover=0\n')
            fp.write('listenonion=0\n')
            fp.write('upnp=0\n')
            if use_rpcauth:
                salt = generate_salt(16)
                rpc_user = 'test_ltc_' + str(node_id)
                rpc_pass = 'test_ltc_pwd_' + str(node_id)
                fp.write('rpcauth={}:{}${}\n'.format(rpc_user, salt, password_to_hmac(salt, rpc_pass)))
                settings['chainclients']['litecoin']['rpcuser'] = rpc_user
                settings['chainclients']['litecoin']['rpcpassword'] = rpc_pass
            for ip in range(num_nodes):
                if ip != node_id:
                    fp.write('connect=127.0.0.1:{}\n'.format(LTC_BASE_PORT + ip + port_ofs))
            for opt in EXTRA_CONFIG_JSON.get('ltc{}'.format(node_id), []):
                fp.write(opt + '\n')

    if 'decred' in coins_array:
        # Pruned nodes don't provide blocks
        config_filename = os.path.join(datadir_path, 'decred', 'dcrd.conf')
        with open(config_filename, 'r') as fp:
            lines = fp.readlines()
        with open(config_filename, 'w') as fp:
            for line in lines:
                if not line.startswith('prune'):
                    fp.write(line)
            fp.write('listen=127.0.0.1:{}\n'.format(DCR_BASE_PORT + node_id + port_ofs))
            fp.write('noseeders=1\n')
            fp.write('nodnsseed=1\n')
            fp.write('nodiscoverip=1\n')
            if node_id == 0:
                fp.write('miningaddr=SsYbXyjkKAEXXcGdFgr4u4bo4L8RkCxwQpH\n')
                for ip in range(num_nodes):
                    if ip != node_id:
                        fp.write('addpeer=127.0.0.1:{}\n'.format(DCR_BASE_PORT + ip + port_ofs))
        config_filename = os.path.join(datadir_path, 'decred', 'dcrwallet.conf')
        with open(config_filename, 'a') as fp:
            fp.write('enablevoting=1\n')

    if 'pivx' in coins_array:
        # Pruned nodes don't provide blocks
        config_filename = os.path.join(datadir_path, 'pivx', 'pivx.conf')
        with open(config_filename, 'r') as fp:
            lines = fp.readlines()
        with open(config_filename, 'w') as fp:
            for line in lines:
                if not line.startswith('prune'):
                    fp.write(line)
            fp.write('port={}\n'.format(PIVX_BASE_PORT + node_id + port_ofs))
            fp.write('bind=127.0.0.1\n')
            fp.write('dnsseed=0\n')
            fp.write('discover=0\n')
            fp.write('listenonion=0\n')
            fp.write('upnp=0\n')
            if use_rpcauth:
                salt = generate_salt(16)
                rpc_user = 'test_pivx_' + str(node_id)
                rpc_pass = 'test_pivx_pwd_' + str(node_id)
                fp.write('rpcauth={}:{}${}\n'.format(rpc_user, salt, password_to_hmac(salt, rpc_pass)))
                settings['chainclients']['pivx']['rpcuser'] = rpc_user
                settings['chainclients']['pivx']['rpcpassword'] = rpc_pass
            for ip in range(num_nodes):
                if ip != node_id:
                    fp.write('connect=127.0.0.1:{}\n'.format(PIVX_BASE_PORT + ip + port_ofs))
            for opt in EXTRA_CONFIG_JSON.get('pivx{}'.format(node_id), []):
                fp.write(opt + '\n')

    if 'firo' in coins_array:
        # Pruned nodes don't provide blocks
        config_filename = os.path.join(datadir_path, 'firo', 'firo.conf')
        with open(config_filename, 'r') as fp:
            lines = fp.readlines()
        with open(config_filename, 'w') as fp:
            for line in lines:
                if not line.startswith('prune'):
                    fp.write(line)
            fp.write('port={}\n'.format(FIRO_BASE_PORT + node_id + port_ofs))
            fp.write('bind=127.0.0.1\n')
            fp.write('dnsseed=0\n')
            fp.write('discover=0\n')
            fp.write('listenonion=0\n')
            fp.write('upnp=0\n')
            if use_rpcauth:
                salt = generate_salt(16)
                rpc_user = 'test_firo_' + str(node_id)
                rpc_pass = 'test_firo_pwd_' + str(node_id)
                fp.write('rpcauth={}:{}${}\n'.format(rpc_user, salt, password_to_hmac(salt, rpc_pass)))
                settings['chainclients']['firo']['rpcuser'] = rpc_user
                settings['chainclients']['firo']['rpcpassword'] = rpc_pass
            for ip in range(num_nodes):
                if ip != node_id:
                    fp.write('connect=127.0.0.1:{}\n'.format(FIRO_BASE_PORT + ip + port_ofs))
            for opt in EXTRA_CONFIG_JSON.get('firo{}'.format(node_id), []):
                fp.write(opt + '\n')

    if 'monero' in coins_array:
        with open(os.path.join(datadir_path, 'monero', 'monerod.conf'), 'a') as fp:
            fp.write('p2p-bind-ip=127.0.0.1\n')
            fp.write('p2p-bind-port={}\n'.format(XMR_BASE_P2P_PORT + node_id + port_ofs))
            for ip in range(num_nodes):
                if ip != node_id:
                    fp.write('add-exclusive-node=127.0.0.1:{}\n'.format(XMR_BASE_P2P_PORT + ip + port_ofs))

    with open(config_path) as fs:
        settings = json.load(fs)

    settings['min_delay_event'] = 1
    settings['max_delay_event'] = 4
    settings['min_delay_event_short'] = 1
    settings['max_delay_event_short'] = 4
    settings['min_delay_retry'] = 10
    settings['max_delay_retry'] = 20

    settings['check_progress_seconds'] = 5
    settings['check_watched_seconds'] = 5
    settings['check_expired_seconds'] = 60
    settings['check_events_seconds'] = 5
    settings['check_xmr_swaps_seconds'] = 5

    recursive_update_dict(settings, extra_settings)

    extra_config = EXTRA_CONFIG_JSON.get('sc{}'.format(node_id), {})
    recursive_update_dict(settings, extra_config)

    with open(config_path, 'w') as fp:
        json.dump(settings, fp, indent=4)

    return mnemonic_out


def prepare_nodes(num_nodes, extra_coins, use_rpcauth=False, extra_settings={}, port_ofs=0):
    bins_path = os.path.join(TEST_PATH, 'bin')
    for i in range(num_nodes):
        logging.info('Preparing node: %d.', i)
        client_path = os.path.join(TEST_PATH, 'client{}'.format(i))
        try:
            shutil.rmtree(client_path)
        except Exception as ex:
            logging.warning('setUpClass %s', str(ex))

        run_prepare(i, client_path, bins_path, extra_coins, mnemonics[i] if i < len(mnemonics) else None,
                    num_nodes=num_nodes, use_rpcauth=use_rpcauth, extra_settings=extra_settings, port_ofs=port_ofs)


class TestBase(unittest.TestCase):
    def setUpClass(cls):
        super(TestBase, cls).setUpClass()

        cls.delay_event = threading.Event()
        signal.signal(signal.SIGINT, lambda signal, frame: cls.signal_handler(cls, signal, frame))

    def signal_handler(self, sig, frame):
        logging.info('signal {} detected.'.format(sig))
        self.delay_event.set()

    def wait_seconds(self, seconds):
        self.delay_event.wait(seconds)
        if self.delay_event.is_set():
            raise ValueError('Test stopped.')

    def wait_for_particl_height(self, http_port, num_blocks=3):
        # Wait for height, or sequencelock is thrown off by genesis blocktime
        logging.info('Waiting for Particl chain height %d', num_blocks)
        for i in range(60):
            if self.delay_event.is_set():
                raise ValueError('Test stopped.')
            try:
                wallets = json.loads(urlopen(f'http://127.0.0.1:{http_port}/json/wallets').read())
                particl_blocks = wallets['PART']['blocks']
                print('particl_blocks', particl_blocks)
                if particl_blocks >= num_blocks:
                    return
            except Exception as e:
                print('Error reading wallets', str(e))

            self.delay_event.wait(1)
        raise ValueError(f'wait_for_particl_height failed http_port: {http_port}')


class XmrTestBase(TestBase):
    @classmethod
    def setUpClass(cls):
        super(XmrTestBase, cls).setUpClass(cls)

        cls.update_thread = None
        cls.processes = []

        prepare_nodes(3, 'monero')

    def run_thread(self, client_id):
        client_path = os.path.join(TEST_PATH, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def start_processes(self):
        self.delay_event.clear()

        for i in range(3):
            self.processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            self.processes[-1].start()

        waitForServer(self.delay_event, 12701)

        def waitForMainAddress():
            for i in range(20):
                if self.delay_event.is_set():
                    raise ValueError('Test stopped.')
                try:
                    wallets = json.loads(urlopen('http://127.0.0.1:12701/json/wallets').read())
                    return wallets['XMR']['main_address']
                except Exception as e:
                    print('Waiting for main address {}'.format(str(e)))
                self.delay_event.wait(1)
            raise ValueError('waitForMainAddress timedout')
        xmr_addr1 = waitForMainAddress()

        num_blocks = 100

        xmr_auth = None
        if os.getenv('XMR_RPC_USER', '') != '':
            xmr_auth = (os.getenv('XMR_RPC_USER', ''), os.getenv('XMR_RPC_PWD', ''))

        if callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'get_block_count', auth=xmr_auth)['count'] < num_blocks:
            logging.info('Mining {} Monero blocks to {}.'.format(num_blocks, xmr_addr1))
            callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'generateblocks', {'wallet_address': xmr_addr1, 'amount_of_blocks': num_blocks}, auth=xmr_auth)
        logging.info('XMR blocks: %d', callrpc_xmr(XMR_BASE_RPC_PORT + 1, 'get_block_count', auth=xmr_auth)['count'])

        self.update_thread = threading.Thread(target=updateThread, args=(xmr_addr1, self.delay_event, xmr_auth))
        self.update_thread.start()

        self.wait_for_particl_height(12701, num_blocks=3)

    @classmethod
    def tearDownClass(cls):
        logging.info('Stopping test')
        cls.delay_event.set()
        if cls.update_thread:
            cls.update_thread.join()
        for p in cls.processes:
            p.terminate()
        for p in cls.processes:
            p.join()
        cls.update_thread = None
        cls.processes = []
