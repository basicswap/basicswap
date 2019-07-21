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
import importlib

prepareSystem = importlib.import_module('bin.basicswap-prepare')
test_path = os.path.expanduser('~/test_basicswap')

logger = logging.getLogger()
logger.level = logging.DEBUG


class Test(unittest.TestCase):
    @classmethod
    def tearDownClass(self):
        try:
            shutil.rmtree(test_path)
        except Exception as e:
            logger.warning('tearDownClass %s', str(e))

    def test_no_overwrite(self):
        testargs = ['basicswap-prepare', '-datadir=' + test_path]
        with patch.object(sys, 'argv', testargs):
            prepareSystem.main()

        self.assertTrue(os.path.exists(os.path.join(test_path, 'basicswap.json')))

        testargs = ['basicswap-prepare', '-datadir=' + test_path]
        with patch('sys.stderr', new=StringIO()) as fake_stderr:
            with patch.object(sys, 'argv', testargs):
                with self.assertRaises(SystemExit) as cm:
                    prepareSystem.main()

        self.assertEqual(cm.exception.code, 1)
        logger.info('fake_stderr.getvalue() %s', fake_stderr.getvalue())
        self.assertTrue('exists, exiting' in fake_stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
