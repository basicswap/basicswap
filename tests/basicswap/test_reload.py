#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

"""

mkdir -p /tmp/test_basicswap/bin/{particl,bitcoin}
cp ~/tmp/particl-0.18.1.2-x86_64-linux-gnu.tar.gz /tmp/test_basicswap/bin/particl
cp ~/tmp/bitcoin-0.18.0-x86_64-linux-gnu.tar.gz /tmp/test_basicswap/bin/bitcoin


"""

import os
import sys
import time
import unittest
import logging
import shutil
import threading
import json
import traceback
from unittest.mock import patch
from urllib.request import urlopen
from urllib import parse


import bin.basicswap_prepare as prepareSystem
import bin.basicswap_run as runSystem
test_path = os.path.expanduser('~/test_basicswap1')

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def waitForServer():
    for i in range(20):
        try:
            time.sleep(1)
            summary = json.loads(urlopen('http://localhost:12700/json').read())
            break
        except Exception:
            traceback.print_exc()


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        mnemonics = [
            'abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb',
            'actuel comédie poésie noble facile éprouver brave cellule rotule académie hilarant chambre',
            'ちしき　いてざ　きおち　あしあと　ぽちぶくろ　こえる　さつえい　むえき　あける　ほんき　むさぼる　ねいろ',
        ]

        for i in range(3):
            client_path = os.path.join(test_path, 'client{}'.format(i))
            config_path = os.path.join(client_path, 'basicswap.json')
            try:
                shutil.rmtree(client_path)
            except Exception as ex:
                logger.warning('setUpClass %s', str(ex))
            testargs = ['basicswap-prepare',
                '-datadir="{}"'.format(client_path),
                '-bindir="{}"'.format(test_path + '/bin'),
                '-portoffset={}'.format(i),
                '-particl_mnemonic="{}"'.format(mnemonics[i]),
                '-regtest', '-withoutcoin=litecoin', '-withcoin=bitcoin']
            with patch.object(sys, 'argv', testargs):
                prepareSystem.main()

            assert(os.path.exists(config_path))

    def run_thread(self, client_id):
        client_path = os.path.join(test_path, 'client{}'.format(client_id))
        testargs = ['basicswap-run', '-datadir=' + client_path, '-regtest', '-testmode']
        with patch.object(sys, 'argv', testargs):
            runSystem.main()

    def test_reload(self):

        thread0 = threading.Thread(target=self.run_thread, args=(0,))
        thread0.start()

        try:
            waitForServer()
            data = parse.urlencode({
                'addr_from': '-1',
                'coin_from': '1',
                'coin_to': '2',
                'amt_from': '1',
                'amt_to': '1',
                'lockhrs': '24'}).encode()

            offer_id = json.loads(urlopen('http://localhost:12700/json/offers/new', data=data).read())
            summary = json.loads(urlopen('http://localhost:12700/json').read())
            assert(summary['num_sent_offers'] == 1)
        except Exception:
            traceback.print_exc()

        logger.warning('TODO')
        time.sleep(5)

        runSystem.swap_client.stopRunning()

        thread0.join()


if __name__ == '__main__':
    unittest.main()
