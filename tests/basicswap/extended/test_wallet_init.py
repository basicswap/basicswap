#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap_wallet_init
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
python tests/basicswap/extended/test_wallet_init.py


"""

import os
import sys
import time
import shutil
import logging
import unittest
import threading
import traceback
import multiprocessing
from unittest.mock import patch

from tests.basicswap.mnemonics import mnemonics
from tests.basicswap.util import (
    read_json_api,
    waitForServer,
)
from tests.basicswap.common_xmr import (
    run_prepare,
)
import basicswap.bin.run as runSystem

TEST_PATH = os.path.expanduser(os.getenv('TEST_PATH', '~/test_basicswap1'))

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        cls.delay_event = threading.Event()

        # Load both wallets from the same mnemonic
        bins_path = os.path.join(TEST_PATH, 'bin')
        for i in range(2):
            logging.info('Preparing node: %d.', i)
            client_path = os.path.join(TEST_PATH, 'client{}'.format(i))
            try:
                shutil.rmtree(client_path)
            except Exception as ex:
                logging.warning('setUpClass %s', str(ex))

            run_prepare(i, client_path, bins_path, 'monero,bitcoin', mnemonics[0])

    def run_thread(self, client_id):
        client_path = os.path.join(TEST_PATH, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def test_wallet(self):
        update_thread = None
        processes = []

        time.sleep(5)
        for i in range(2):
            processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            processes[-1].start()

        try:
            waitForServer(self.delay_event, 12700)

            wallets_0 = read_json_api(12700, 'wallets')
            assert (wallets_0['PART']['expected_seed'] is True)
            assert (wallets_0['XMR']['expected_seed'] is True)

            waitForServer(self.delay_event, 12701)
            wallets_1 = read_json_api(12701, 'wallets')

            assert (wallets_0['PART']['expected_seed'] is True)
            assert (wallets_1['XMR']['expected_seed'] is True)

            # TODO: Check other coins

            assert (wallets_0['PART']['deposit_address'] == wallets_1['1']['deposit_address'])
            assert (wallets_0['XMR']['deposit_address'] == wallets_1['6']['deposit_address'])
        except Exception:
            traceback.print_exc()

        if update_thread:
            update_thread.join()
        for p in processes:
            p.terminate()
        for p in processes:
            p.join()


if __name__ == '__main__':
    unittest.main()
