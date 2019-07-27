#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

"""

mkdir -p /tmp/test_basicswap/bin/{particl,bitcoin}
cp ~/tmp/particl-0.18.1.0-x86_64-linux-gnu.tar.gz /tmp/test_basicswap/bin/particl
cp ~/tmp/bitcoin-0.18.0-x86_64-linux-gnu.tar.gz /tmp/test_basicswap/bin/bitcoin



"""

import os
import sys
import time
import unittest
from unittest.mock import patch
import logging
import shutil
import threading

import bin.basicswap_prepare as prepareSystem
import bin.basicswap_run as runSystem
test_path = os.path.expanduser('/tmp/test_basicswap')

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        config_path = os.path.join(test_path, 'basicswap.json')
        try:
            os.remove(config_path)
            shutil.rmtree(os.path.join(test_path, 'particl'))
            shutil.rmtree(os.path.join(test_path, 'bitcoin'))
        except Exception as ex:
            logger.warning('setUpClass %s', str(ex))

        testargs = ['basicswap-prepare', '-datadir=' + test_path, '-regtest', '-withoutcoin=litecoin', '-withcoin=bitcoin']
        with patch.object(sys, 'argv', testargs):
            prepareSystem.main()

        assert(os.path.exists(config_path))

    def run_thread(self):
        testargs = ['basicswap-run', '-datadir=' + test_path, '-regtest', '-testmode']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def test_reload(self):

        thread = threading.Thread(target=self.run_thread)
        thread.start()

        logger.warning('TODO')
        time.sleep(5)

        runSystem.swap_client.stopRunning()

        thread.join()


if __name__ == '__main__':
    unittest.main()
