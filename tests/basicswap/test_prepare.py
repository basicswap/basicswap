#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import unittest
from unittest.mock import patch
from io import StringIO
import logging
import shutil
import json

import bin.basicswap_prepare as prepareSystem
test_path = os.path.expanduser('~/test_basicswap')

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(unittest.TestCase):
    @classmethod
    def tearDownClass(self):
        try:
            shutil.rmtree(test_path)
        except Exception as e:
            logger.warning('tearDownClass %s', str(e))

    def test(self):
        testargs = ['basicswap-prepare', '-datadir=' + test_path]
        with patch.object(sys, 'argv', testargs):
            prepareSystem.main()

        config_path = os.path.join(test_path, 'basicswap.json')
        self.assertTrue(os.path.exists(config_path))

        logger.info('Test no overwrite')
        testargs = ['basicswap-prepare', '-datadir=' + test_path]
        with patch('sys.stderr', new=StringIO()) as fake_stderr:
            with patch.object(sys, 'argv', testargs):
                with self.assertRaises(SystemExit) as cm:
                    prepareSystem.main()

        self.assertEqual(cm.exception.code, 1)
        logger.info('fake_stderr.getvalue() %s', fake_stderr.getvalue())
        self.assertTrue('exists, exiting' in fake_stderr.getvalue())

        logger.info('Test addcoin new')
        testargs = ['basicswap-prepare', '-datadir=' + test_path, '-addcoin=namecoin']
        with patch.object(sys, 'argv', testargs):
            prepareSystem.main()
        with open(config_path) as fs:
            settings = json.load(fs)
            self.assertTrue(settings['chainclients']['namecoin']['connection_type'] == 'rpc')

        logger.info('Test disablecoin')
        testargs = ['basicswap-prepare', '-datadir=' + test_path, '-disablecoin=namecoin']
        with patch.object(sys, 'argv', testargs):
            prepareSystem.main()
        with open(config_path) as fs:
            settings = json.load(fs)
            self.assertTrue(settings['chainclients']['namecoin']['connection_type'] == 'none')

        logger.info('Test addcoin existing')
        testargs = ['basicswap-prepare', '-datadir=' + test_path, '-addcoin=namecoin']
        with patch.object(sys, 'argv', testargs):
            prepareSystem.main()
        with open(config_path) as fs:
            settings = json.load(fs)
            self.assertTrue(settings['chainclients']['namecoin']['connection_type'] == 'rpc')


if __name__ == '__main__':
    unittest.main()
