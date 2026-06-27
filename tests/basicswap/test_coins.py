#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
# Run test
export TEST_PATH=/tmp/test_coins
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin

export TEST_COINS_LIST="bitcoin,monero"
export TEST_COIN_A="bitcoin"
export TEST_COIN_B="monero"
export PYTHONPATH=$(pwd)
pytest -v -s --log-cli-level=DEBUG tests/basicswap/test_coins.py

# Run select test
TEST_COIN_A="monero" TEST_COIN_B="bitcoin" pytest -v -s --log-cli-level=DEBUG tests/basicswap/test_coins.py::Test::test_set_destination

# Optionally copy coin releases to permanent storage for faster subsequent startups
cp -r ${TEST_PATH}/bin/* ~/tmp/basicswap_bin/

"""

import logging
import os
import random
import shutil
import sys
import unittest

from basicswap.basicswap_util import (
    BidStates,
)
from basicswap.chainparams import (
    Coins,
    chainparams,
    getCoinIdFromName,
)

from tests.basicswap.common import (
    prepare_balance,
    wait_for_balance,
)
from tests.basicswap.test_electrum import (
    wait_for_bid_states,
    wait_for_offer,
    TestFunctions,
)
from tests.basicswap.common_xmr import run_prepare, TEST_PATH
from tests.basicswap.extended.test_xmr_persistent import (
    NUM_NODES,
    PORT_OFS,
)
from tests.basicswap.mnemonics import mnemonics
from tests.basicswap.util import (
    post_json_api,
    read_json_api,
)

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(TestFunctions):
    __test__ = True
    update_min = 0.7

    test_coin_a = getCoinIdFromName(os.getenv("TEST_COIN_A", "bitcoin"))
    test_coin_b = getCoinIdFromName(os.getenv("TEST_COIN_B", "monero"))

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        initial_amount: float = 200.0
        for should_wait in (False, True):
            for coin_id in (cls.test_coin_a, cls.test_coin_b):
                if coin_id == Coins.XMR:
                    node_to = cls.port_node_0
                    node_from = cls.port_node_1
                    if cls.test_coin_a != Coins.XMR:
                        continue
                else:
                    node_to = cls.port_node_1
                    node_from = cls.port_node_0
                if should_wait:
                    coin_ticker: str = chainparams[coin_id]["ticker"]
                    wait_for_balance(
                        cls.delay_event,
                        f"http://127.0.0.1:{node_to}/json/wallets/{coin_ticker.lower()}",
                        "balance",
                        initial_amount,
                        iterations=60,
                        delay_time=2,
                    )
                else:
                    prepare_balance(
                        cls.delay_event,
                        coin_id,
                        initial_amount,
                        node_to,
                        node_from,
                        True,
                        wait_until_spendable=False,
                    )

    @classmethod
    def setupNodes(cls):
        logger.info(f"Preparing {NUM_NODES} nodes.")

        bins_path = os.path.join(TEST_PATH, "bin")
        for i in range(NUM_NODES):
            logger.info(f"Preparing node: {i}.")
            client_path = os.path.join(TEST_PATH, f"client{i}")
            try:
                shutil.rmtree(client_path)
            except Exception as ex:
                logger.warning(f"setupNodes {ex}")

            extra_args = []
            run_prepare(
                i,
                client_path,
                bins_path,
                cls.test_coins_list,
                mnemonics[i] if i < len(mnemonics) else None,
                num_nodes=NUM_NODES,
                use_rpcauth=True,
                extra_settings={"min_sequence_lock_seconds": 10},
                port_ofs=PORT_OFS,
                extra_args=extra_args,
            )

    def test_01_a_full_swap_xmr(self):
        prepare_balance(
            self.delay_event,
            self.test_coin_b,
            100,
            self.port_node_1,
            self.port_node_0,
            True,
        )
        self.do_test_01_full_swap(self.test_coin_a, self.test_coin_b)

    def test_set_destination(self):
        prepare_balance(
            self.delay_event,
            self.test_coin_b,
            100,
            self.port_node_1,
            self.port_node_0,
            True,
        )
        coin_from, coin_to = (self.test_coin_a, self.test_coin_b)
        port_node_from, port_node_to = (self.port_node_0, self.port_node_1)
        logger.info(
            f"---------- Test {coin_from.name} ({port_node_from}) to {coin_to.name} ({port_node_to}) Set Destination"
        )

        ticker_from: str = chainparams[coin_from]["ticker"]
        ticker_to: str = chainparams[coin_to]["ticker"]

        amt_from_str = f"{random.uniform(0.5, 10.0):.{8}f}"
        amt_to_str = f"{random.uniform(0.5, 10.0):.{8}f}"
        data = {
            "addr_from": "-1",
            "coin_from": ticker_from,
            "coin_to": ticker_to,
            "amt_from": amt_from_str,
            "amt_to": amt_to_str,
            "lockhrs": "24",
            "swap_type": "adaptor_sig",
            "automation_strat_id": 1,
        }

        ticker_from: str = chainparams[coin_from]["ticker"]
        wallet_before = read_json_api(self.port_node_2, f"wallets/{ticker_from}")
        address_2: str = wallet_before["deposit_address"]

        logger.info(
            f"Creating offer {amt_from_str} {ticker_from} -> {amt_to_str} {ticker_to}"
        )
        offer_id: str = post_json_api(port_node_from, "offers/new", data)["offer_id"]
        wait_for_offer(self.delay_event, port_node_to, offer_id)
        offer = read_json_api(port_node_to, f"offers/{offer_id}")[0]
        data = {
            "offer_id": offer_id,
            "amount_from": offer["amount_from"],
            "validmins": 60,
            "destination_address": address_2,
        }
        logger.info(f"Sending bid with destination_address: {address_2}")
        rv = post_json_api(port_node_to, "bids/new", data)
        bid_id: str = rv["bid_id"]

        logger.info("Completing swap")
        wait_for_bid_states(
            self.delay_event,
            bid_id,
            port_node_from,
            BidStates.SWAP_COMPLETED,
            port_node_to,
            BidStates.SWAP_COMPLETED,
            240,
        )
        wait_for_balance(
            self.delay_event,
            f"http://127.0.0.1:{self.port_node_2}/json/wallets/{ticker_from}",
            ["balance", "unconfirmed"],
            float(wallet_before["balance"])
            + float(wallet_before["unconfirmed"])
            + 0.01,
            iterations=40,
            delay_time=1,
        )
        wallet_after = read_json_api(self.port_node_2, f"wallets/{ticker_from}")
        assert float(wallet_after["balance"]) + float(
            wallet_after["unconfirmed"]
        ) > float(wallet_before["balance"]) + float(wallet_before["unconfirmed"])


if __name__ == "__main__":
    unittest.main()
