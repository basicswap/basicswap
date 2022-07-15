#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap_wallet_restore
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
python tests/basicswap/extended/test_wallet_restore.py


"""

import os
import sys
import shutil
import logging
import unittest
import traceback
import multiprocessing
from unittest.mock import patch

from tests.basicswap.common import (
    read_json_api,
    waitForServer,
)
from tests.basicswap.common_xmr import (
    TestBase,
    run_prepare,
)
import bin.basicswap_run as runSystem

TEST_PATH = os.path.expanduser(os.getenv('TEST_PATH', '~/test_basicswap1'))

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def prepare_node(node_id, mnemonic):
    logging.info('Preparing node: %d.', node_id)
    bins_path = os.path.join(TEST_PATH, 'bin')
    client_path = os.path.join(TEST_PATH, 'client{}'.format(node_id))
    try:
        shutil.rmtree(client_path)
    except Exception as ex:
        logging.warning('setUpClass %s', str(ex))
    return run_prepare(node_id, client_path, bins_path, 'monero,bitcoin,litecoin', mnemonic)


class Test(TestBase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass(cls)

        cls.used_mnemonics = []
        # Load wallets from random mnemonics
        for i in range(3):
            cls.used_mnemonics.append(prepare_node(i, None))

    def run_thread(self, client_id):
        client_path = os.path.join(TEST_PATH, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def test_wallet(self):
        update_thread = None
        processes = []

        self.wait_seconds(5)
        for i in range(3):
            processes.append(multiprocessing.Process(target=self.run_thread, args=(i,)))
            processes[-1].start()

        try:
            waitForServer(self.delay_event, 12700)
            waitForServer(self.delay_event, 12701)
            # TODO: Add swaps

            ltc_before = read_json_api(12700, 'wallets/ltc')

            logging.info('Starting a new node on the same mnemonic as the first')
            prepare_node(3, self.used_mnemonics[0])
            processes.append(multiprocessing.Process(target=self.run_thread, args=(3,)))
            processes[-1].start()
            waitForServer(self.delay_event, 12703)
            ltc_after = read_json_api(12703, 'wallets/ltc')

            assert(ltc_before['deposit_address'] == ltc_after['deposit_address'])

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
