#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/basicswap/extended/test_veil.py

"""

import os
import random
import logging
import unittest

import basicswap.config as cfg
from basicswap.basicswap import (
    Coins,
    SwapTypes,
    BidStates,
)
from basicswap.config import (
    bin_suffix,
    DEFAULT_TEST_BINDIR,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
)
from basicswap.contrib.test_framework.messages import (
    ToHex,
    FromHex,
    CTxIn,
    COutPoint,
    CTransaction,
    CTxInWitness,
)
from basicswap.util import (
    COIN,
)
from tests.basicswap.util import (
    read_json_api,
)
from basicswap.rpc import (
    waitForRPC,
)
from tests.basicswap.common import (
    stopDaemons,
    prepareDataDir,
    make_rpc_func,
    wait_for_bid,
    wait_for_offer,
    wait_for_in_progress,
)
from bin.basicswap_run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from tests.basicswap.test_xmr import BaseTest, test_delay_event, callnoderpc
from tests.basicswap.test_btc_xmr import TestFunctions

# Why won't this work!?
# from tests.basicswap.test_btc_xmr import BasicSwapTest

logger = logging.getLogger()

VEIL_BASE_PORT = 34842
VEIL_BASE_RPC_PORT = 35842
VEIL_BASE_ZMQ_PORT = 36842

VEIL_BINDIR = os.path.expanduser(os.getenv('VEIL_BINDIR', os.path.join(DEFAULT_TEST_BINDIR, 'veil')))
VEILD = os.getenv('VEILD', 'veild' + bin_suffix)
VEIL_CLI = os.getenv('VEIL_CLI', 'veil-cli' + bin_suffix)
VEIL_TX = os.getenv('VEIL_TX', 'veil-tx' + bin_suffix)


#class TestVEIL(BaseTest):
class TestVEIL(TestFunctions):
    __test__ = True
    test_coin_from = Coins.VEIL
    base_rpc_port = VEIL_BASE_RPC_PORT

    start_xmr_nodes = False
    test_atomic = True
    test_xmr = True

    veil_daemons = []
    veil_addr = None

    # Particl node mnemonics are set in test/basicswap/mnemonics.py
    veil_seeds = [
        'd90b7ed1be614e1c172653aee1f3b6230f43b7fa99cf07fa984a17966ad81de7',
        '6c81d6d74ba33a0db9e41518c2b6789fbe938e98018a4597dac661cfc5f2dfc1',
        'c5de2be44834e7e47ad7dc8e35c6b77c79f17c6bb40d5509a00fc3dff384a865',
    ]

    @classmethod
    def prepareExtraDataDir(cls, i):
        extra_opts = []
        if not cls.restore_instance:
            seed_hex = cls.veil_seeds[i]
            extra_opts.append(f'-importseed={seed_hex}')
            data_dir = prepareDataDir(cfg.TEST_DATADIRS, i, 'veil.conf', 'veil_', base_p2p_port=VEIL_BASE_PORT, base_rpc_port=VEIL_BASE_RPC_PORT)

        cls.veil_daemons.append(startDaemon(os.path.join(cfg.TEST_DATADIRS, 'veil_' + str(i)), VEIL_BINDIR, VEILD, opts=extra_opts))
        logging.info('Started %s %d', VEILD, cls.veil_daemons[-1].pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=VEIL_BASE_RPC_PORT), max_tries=12)

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.VEIL, cls.veil_daemons[i].pid)

    @classmethod
    def prepareExtraCoins(cls):
        if cls.restore_instance:
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.veil_addr = cls.swap_clients[0].ci(Coins.VEIL).pubkey_to_address(void_block_rewards_pubkey)
        else:
            num_blocks = 400
            cls.veil_addr = callnoderpc(0, 'getnewminingaddress', ['mining_addr'], base_rpc_port=VEIL_BASE_RPC_PORT)
            logging.info('Mining %d VEIL blocks to %s', num_blocks, cls.veil_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.veil_addr], base_rpc_port=VEIL_BASE_RPC_PORT)

            veil_addr1 = callnoderpc(1, 'getnewbasecoinaddress', ['initial addr'], base_rpc_port=VEIL_BASE_RPC_PORT)
            for i in range(5):
                callnoderpc(0, 'sendtoaddress', [veil_addr1, 1000], base_rpc_port=VEIL_BASE_RPC_PORT)

            # Set future block rewards to nowhere (a random address), so wallet balances stay constant
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.veil_addr = cls.swap_clients[0].ci(Coins.VEIL).pubkey_to_address(void_block_rewards_pubkey)
            num_blocks = 100
            logging.info('Mining %d VEIL blocks to %s', num_blocks, cls.veil_addr)
            # callnoderpc(0, 'generatetoaddress', [num_blocks, cls.veil_addr], base_rpc_port=VEIL_BASE_RPC_PORT)
            # ERROR: CreateNewBlock: TestBlockValidity failed: time-too-new, block timestamp too far in the future (code 16)
            for i in range(num_blocks):
                try:
                    callnoderpc(0, 'generatetoaddress', [1, cls.veil_addr], base_rpc_port=VEIL_BASE_RPC_PORT)
                except Exception as e:
                    test_delay_event.wait(1)
                    callnoderpc(0, 'generatetoaddress', [1, cls.veil_addr], base_rpc_port=VEIL_BASE_RPC_PORT)

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising VEIL Test')
        super(TestVEIL, cls).tearDownClass()

        stopDaemons(cls.veil_daemons)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings['chainclients']['veil'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': VEIL_BASE_RPC_PORT + node_id,
            'rpcuser': 'test' + str(node_id),
            'rpcpassword': 'test_pass' + str(node_id),
            'datadir': os.path.join(datadir, 'veil_' + str(node_id)),
            'bindir': VEIL_BINDIR,
            'use_csv': True,
            'use_segwit': True,
        }

    @classmethod
    def coins_loop(cls):
        super(TestVEIL, cls).coins_loop()
        callnoderpc(0, 'generatetoaddress', [1, cls.veil_addr], base_rpc_port=VEIL_BASE_RPC_PORT)

    def mineBlock(self, num_blocks=1):
        self.callnoderpc('generatetoaddress', [num_blocks, self.veil_addr])

    def test_002_native_segwit(self):
        logging.info('---------- Test {} p2sh native segwit'.format(self.test_coin_from.name))

        blockchain_info = self.callnoderpc('getblockchaininfo')

        addr_segwit = self.callnoderpc('getnewbasecoinaddress')

        addr_info = self.callnoderpc('getaddressinfo', [addr_segwit, ])
        assert addr_info['iswitness'] is True

        txid = self.callnoderpc('sendtoaddress', [addr_segwit, 1.0])
        assert len(txid) == 64
        tx_wallet = self.callnoderpc('gettransaction', [txid, ])['hex']
        tx = self.callnoderpc('decoderawtransaction', [tx_wallet, ])

        self.mineBlock()
        ro = self.callnoderpc('scantxoutset', ['start', ['addr({})'.format(addr_segwit)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

        prevout_n = -1
        for txo in tx['vout']:

            if addr_segwit == txo['scriptPubKey']['addresses'][0]:
                prevout_n = txo['vout.n']
                break
        assert prevout_n > -1

        tx_funded = self.callnoderpc('createrawtransaction', [[{'txid': txid, 'vout': prevout_n}], {addr_segwit: 0.99}])
        tx_signed = self.callnoderpc('signrawtransactionwithwallet', [tx_funded, ])['hex']
        tx_funded_decoded = self.callnoderpc('decoderawtransaction', [tx_funded, ])
        tx_signed_decoded = self.callnoderpc('decoderawtransaction', [tx_signed, ])
        print('[rm] tx_funded_decoded', tx_funded_decoded)
        print('[rm] tx_signed_decoded', tx_signed_decoded)
        assert tx_funded_decoded['txid'] == tx_signed_decoded['txid']


if __name__ == '__main__':
    unittest.main()
