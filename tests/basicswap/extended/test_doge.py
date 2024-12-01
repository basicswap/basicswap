#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export RESET_TEST=true
export TEST_PATH=/tmp/test_doge
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
export TEST_COINS_LIST='bitcoin,dogecoin'
python tests/basicswap/extended/test_doge.py

"""

import os
import sys
import json
import time
import random
import signal
import logging
import unittest
import threading
import multiprocessing
from unittest.mock import patch

from tests.basicswap.extended.test_xmr_persistent import (
    BaseTestWithPrepare,
    UI_PORT,
)
from tests.basicswap.extended.test_scripts import (
    wait_for_offers,
)
from tests.basicswap.util import (
    read_json_api,
)


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class DOGETest(BaseTestWithPrepare):
    def test_a(self):
        read_json_api(UI_PORT + 0, "wallets/doge/reseed")
        read_json_api(UI_PORT + 1, "wallets/doge/reseed")

        offer_json = {
            "coin_from": "btc",
            "coin_to": "doge",
            "amt_from": 10.0,
            "amt_to": 100.0,
            "amt_var": True,
            "lockseconds": 3600,
        }
        offer_id = read_json_api(UI_PORT + 0, "offers/new", offer_json)["offer_id"]
        logging.debug(f"offer_id {offer_id}")

        wait_for_offers(self.delay_event, 1, 1, offer_id)


if __name__ == "__main__":
    unittest.main()
