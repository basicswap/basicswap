#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap_wallet_restore
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PGP_KEYS_DIR_PATH=$(pwd)/pgp/keys
export PYTHONPATH=$(pwd)
python tests/basicswap/extended/test_wallet_restore.py


"""

import os
import sys
import shutil
import logging
import unittest
import threading
import traceback
import multiprocessing
from unittest.mock import patch

from tests.basicswap.common import (
    read_json_api,
    post_json_api,
    waitForServer,
    waitForNumOffers,
    waitForNumBids,
)
from tests.basicswap.common_xmr import (
    TestBase,
    run_prepare,
    waitForBidState,
)
from basicswap.rpc import (
    callrpc,
)
from tests.basicswap.mnemonics import mnemonics
import bin.basicswap_run as runSystem
from bin.basicswap_prepare import LTC_RPC_PORT, BTC_RPC_PORT

TEST_PATH = os.path.expanduser(os.getenv('TEST_PATH', '~/test_basicswap1'))

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def callbtcnoderpc(node_id, method, params=[], wallet=None, base_rpc_port=BTC_RPC_PORT):
    auth = 'test_btc_{0}:test_btc_pwd_{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def callltcnoderpc(node_id, method, params=[], wallet=None, base_rpc_port=LTC_RPC_PORT):
    auth = 'test_ltc_{0}:test_ltc_pwd_{0}'.format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def updateThread(self):
    while not self.delay_event.is_set():
        callbtcnoderpc(2, 'generatetoaddress', [1, self.btc_addr])
        callltcnoderpc(1, 'generatetoaddress', [1, self.ltc_addr])
        self.delay_event.wait(2)


def prepare_node(node_id, mnemonic):
    logging.info('Preparing node: %d.', node_id)
    bins_path = os.path.join(TEST_PATH, 'bin')
    client_path = os.path.join(TEST_PATH, 'client{}'.format(node_id))
    try:
        shutil.rmtree(client_path)
    except Exception as ex:
        logging.warning('setUpClass %s', str(ex))
    return run_prepare(node_id, client_path, bins_path, 'monero,bitcoin,litecoin', mnemonic, 3, use_rpcauth=True)


class Test(TestBase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass(cls)
        cls.update_thread = None
        cls.used_mnemonics = []
        # Load wallets from random mnemonics, except node0 which needs to import PART from the genesis block
        for i in range(3):
            cls.used_mnemonics.append(prepare_node(i, mnemonics[0] if i == 0 else None))

    def run_thread(self, client_id):
        client_path = os.path.join(TEST_PATH, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def test_wallet(self):
        processes = []

        self.wait_seconds(5)
        for i in range(3):
            processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            processes[-1].start()

        try:
            waitForServer(self.delay_event, 12700)
            waitForServer(self.delay_event, 12701)
            waitForServer(self.delay_event, 12702)

            num_blocks = 500  # Mine enough to activate segwit
            self.btc_addr = callbtcnoderpc(2, 'getnewaddress', ['mining_addr', 'bech32'])
            logging.info('Mining %d Bitcoin blocks to %s', num_blocks, self.btc_addr)
            callbtcnoderpc(2, 'generatetoaddress', [num_blocks, self.btc_addr])

            num_blocks = 431
            self.ltc_addr = callltcnoderpc(1, 'getnewaddress', ['mining_addr', 'bech32'])
            logging.info('Mining %d Litecoin blocks to %s', num_blocks, self.ltc_addr)
            callltcnoderpc(1, 'generatetoaddress', [num_blocks, self.ltc_addr])

            mweb_addr = callltcnoderpc(1, 'getnewaddress', ['mweb_addr', 'mweb'])
            callltcnoderpc(1, 'sendtoaddress', [mweb_addr, 1])
            num_blocks = 69
            callltcnoderpc(1, 'generatetoaddress', [num_blocks, self.ltc_addr])

            self.update_thread = threading.Thread(target=updateThread, args=(self,))
            self.update_thread.start()

            data = {
                'addr_from': '-1',
                'coin_from': 'part',
                'coin_to': 'ltc',
                'amt_from': '1',
                'amt_to': '1',
                'lockhrs': '24',
                'automation_strat_id': 1}

            offer_id = post_json_api(12700, 'offers/new', data)['offer_id']
            summary = read_json_api(12700)
            assert(summary['num_sent_offers'] == 1)

            logger.info('Waiting for offer')
            waitForNumOffers(self.delay_event, 12701, 1)

            offers = read_json_api(12701, 'offers')
            offer = offers[0]

            data = {
                'offer_id': offer['offer_id'],
                'amount_from': offer['amount_from']}

            bid_id = post_json_api(12701, 'bids/new', data)['bid_id']

            waitForNumBids(self.delay_event, 12700, 1)

            waitForBidState(self.delay_event, 12700, bid_id, 'Completed')
            waitForBidState(self.delay_event, 12701, bid_id, 'Completed')

            logging.info('Starting a new node on the same mnemonic as the first')
            prepare_node(3, self.used_mnemonics[0])
            processes.append(multiprocessing.Process(target=self.run_thread, args=(3,)))
            processes[-1].start()
            waitForServer(self.delay_event, 12703)

            self.wait_seconds(5)

            # TODO: Attempt to detect past swaps

            ltc_original = read_json_api(12700, 'wallets/ltc')
            ltc_restored = read_json_api(12703, 'wallets/ltc')
            assert(float(ltc_original['balance']) + float(ltc_original['unconfirmed']) > 0.0)
            assert(float(ltc_original['balance']) + float(ltc_original['unconfirmed']) == float(ltc_restored['balance']) + float(ltc_restored['unconfirmed']))

            wallets_original = read_json_api(12700, 'wallets')
            # TODO: After restoring a new deposit address should be generated, should be automated
            #       Swaps should use a new key path, not the external path
            next_addr = read_json_api(12703, 'wallets/part/nextdepositaddr')
            next_addr = read_json_api(12703, 'wallets/part/nextdepositaddr')
            wallets_restored = read_json_api(12703, 'wallets')
            for k, w in wallets_original.items():
                assert(w['deposit_address'] == wallets_restored[k]['deposit_address'])

            logging.info('Test passed.')

        except Exception:
            traceback.print_exc()

        self.delay_event.set()
        if self.update_thread:
            self.update_thread.join()
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()


if __name__ == '__main__':
    unittest.main()
