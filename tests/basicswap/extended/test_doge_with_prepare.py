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

import sys
import logging
import unittest

from tests.basicswap.common import (
    wait_for_balance,
)
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


def wait_for_bid(
    delay_event, node_id, bid_id, state=None, sent: bool = False, num_tries: int = 40
) -> None:
    for i in range(num_tries):
        delay_event.wait(3)
        if delay_event.is_set():
            raise ValueError("Test stopped.")

        bid = read_json_api(UI_PORT + node_id, f"bids/{bid_id}")

        if "state" not in bid:
            continue
        if state is None:
            return
        if bid["state"].lower() == state.lower():
            return
    raise ValueError("wait_for_bid failed")


def prepare_balance(
    delay_event,
    node_id,
    node_id_take_from,
    coin_ticker,
    amount,
    wait_for: int = 20,
    test_balance: bool = True,
) -> None:
    print(f"prepare_balance on node {node_id}, {coin_ticker}: {amount}")
    balance_type: str = "balance"
    address_type: str = "deposit_address"
    js_w = read_json_api(UI_PORT + node_id, "wallets")
    current_balance: float = float(js_w[coin_ticker][balance_type])

    if test_balance and current_balance >= amount:
        return
    post_json = {
        "value": amount,
        "address": js_w[coin_ticker][address_type],
        "subfee": False,
    }
    json_rv = read_json_api(
        UI_PORT + node_id_take_from,
        "wallets/{}/withdraw".format(coin_ticker.lower()),
        post_json,
    )
    assert len(json_rv["txid"]) == 64

    wait_for_amount: float = amount
    if not test_balance:
        wait_for_amount += current_balance
    wait_for_balance(
        delay_event,
        f"http://127.0.0.1:{UI_PORT + node_id}/json/wallets/{coin_ticker.lower()}",
        balance_type,
        wait_for_amount,
        iterations=wait_for,
    )


class DOGETest(BaseTestWithPrepare):
    def test_a(self):

        amount_from = 10.0
        offer_json = {
            "coin_from": "btc",
            "coin_to": "doge",
            "amt_from": amount_from,
            "amt_to": 100.0,
            "amt_var": True,
            "lockseconds": 3600,
            "automation_strat_id": 1,
        }
        offer_id = read_json_api(UI_PORT + 0, "offers/new", offer_json)["offer_id"]
        logging.debug(f"offer_id {offer_id}")

        prepare_balance(self.delay_event, 1, 0, "DOGE", 1000.0)

        wait_for_offers(self.delay_event, 1, 1, offer_id)

        post_json = {"offer_id": offer_id, "amount_from": amount_from}
        bid_id = read_json_api(UI_PORT + 1, "bids/new", post_json)["bid_id"]

        wait_for_bid(self.delay_event, 0, bid_id, "completed", num_tries=240)
        wait_for_bid(self.delay_event, 1, bid_id, "completed")


if __name__ == "__main__":
    unittest.main()
