#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
...
export BTC_USE_DESCRIPTORS=true
export BTC_USE_LEGACY_KEY_PATHS=false
export EXTRA_CONFIG_JSON="{\"btc0\":[\"txindex=1\",\"rpcworkqueue=1100\"]}"
python tests/basicswap/extended/test_xmr_persistent.py


Start electrumx and electrum daemon

python tests/basicswap/extended/test_key_paths.py

"""

import logging
import os
import signal
import sys
import threading
import unittest

from tests.basicswap.util import (
    read_json_api,
    waitForServer,
)


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


PORT_OFS = int(os.getenv("PORT_OFS", 1))
UI_PORT = 12700 + PORT_OFS

ELECTRUM_PATH = os.getenv("ELECTRUM_PATH")
ELECTRUM_DATADIR = os.getenv("ELECTRUM_DATADIR")


def signal_handler(self, sig, frame):
    os.write(sys.stdout.fileno(), f"Signal {sig} detected.\n".encode("utf-8"))
    self.delay_event.set()


class Test(unittest.TestCase):
    delay_event = threading.Event()

    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()

        signal.signal(
            signal.SIGINT, lambda signal, frame: signal_handler(cls, signal, frame)
        )

    def test_export(self):

        waitForServer(self.delay_event, UI_PORT + 0)
        waitForServer(self.delay_event, UI_PORT + 1)

        coin_seed = read_json_api(UI_PORT, "getcoinseed", {"coin": "BTC"})
        assert coin_seed["account_key"].startswith("zprv")

        # override the prefix for testnet
        coin_seed = read_json_api(
            UI_PORT,
            "getcoinseed",
            {"coin": "BTC", "extkey_prefix": 0x045F18BC, "with_mnemonic": True},
        )
        assert (
            coin_seed["account_key"]
            == "vprv9K5NS8v2JWNxMeyKtfARGjUSW2zC6F6WbrJUo1HGyZ1NhRZpk6keXadq8XF25KgFMvT5AfXb6Ccn62c6wW2mbJTGfiDFPSE2oaQuvW6tSUX"
        )


if __name__ == "__main__":
    unittest.main()
