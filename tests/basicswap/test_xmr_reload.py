#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
python tests/basicswap/test_xmr_reload.py


"""

import sys
import logging
import unittest
import multiprocessing

from tests.basicswap.util import (
    read_json_api,
    post_json_api,
    waitForServer,
)
from tests.basicswap.common import (
    waitForNumOffers,
    waitForNumBids,
    waitForNumSwapping,
)
from tests.basicswap.common_xmr import (
    XmrTestBase,
)

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


class Test(XmrTestBase):

    def test_reload(self):
        self.start_processes()

        waitForServer(self.delay_event, 12700)
        waitForServer(self.delay_event, 12701)
        wallets1 = read_json_api(12701, "wallets")
        assert float(wallets1["XMR"]["balance"]) > 0.0

        data = {
            "addr_from": "-1",
            "coin_from": "part",
            "coin_to": "xmr",
            "amt_from": "1",
            "amt_to": "1",
            "lockhrs": "24",
        }

        offer_id = post_json_api(12700, "offers/new", data)["offer_id"]
        summary = read_json_api(12700)
        assert summary["num_sent_offers"] == 1

        logger.info("Waiting for offer")
        waitForNumOffers(self.delay_event, 12701, 1)

        offers = read_json_api(12701, "offers")
        offer = offers[0]

        data = {"offer_id": offer["offer_id"], "amount_from": offer["amount_from"]}

        data["valid_for_seconds"] = 24 * 60 * 60 + 1
        bid = post_json_api(12701, "bids/new", data)
        assert bid["error"] == "Bid TTL too high"
        del data["valid_for_seconds"]
        data["validmins"] = 24 * 60 + 1
        bid = post_json_api(12701, "bids/new", data)
        assert bid["error"] == "Bid TTL too high"

        del data["validmins"]
        data["valid_for_seconds"] = 10
        bid = post_json_api(12701, "bids/new", data)
        assert bid["error"] == "Bid TTL too low"
        del data["valid_for_seconds"]
        data["validmins"] = 1
        bid = post_json_api(12701, "bids/new", data)
        assert bid["error"] == "Bid TTL too low"

        data["validmins"] = 60
        bid_id = post_json_api(12701, "bids/new", data)

        waitForNumBids(self.delay_event, 12700, 1)

        for i in range(10):
            bids = read_json_api(12700, "bids")
            bid = bids[0]
            if bid["bid_state"] == "Received":
                break
            self.delay_event.wait(1)
        assert bid["expire_at"] == bid["created_at"] + data["validmins"] * 60

        data = {"accept": True}
        rv = post_json_api(12700, "bids/{}".format(bid["bid_id"]), data)
        assert rv["bid_state"] == "Accepted"

        waitForNumSwapping(self.delay_event, 12701, 1)

        logger.info("Restarting client")
        c1 = self.processes[1]
        c1.terminate()
        c1.join()
        self.processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
        self.processes[1].start()

        waitForServer(self.delay_event, 12701)
        rv = read_json_api(12701)
        assert rv["num_swapping"] == 1

        rv = read_json_api(12700, "revokeoffer/{}".format(offer_id))
        assert rv["revoked_offer"] == offer_id

        logger.info("Completing swap")
        for i in range(240):
            if self.delay_event.is_set():
                raise ValueError("Test stopped.")
            self.delay_event.wait(4)

            rv = read_json_api(12700, "bids/{}".format(bid["bid_id"]))
            if rv["bid_state"] == "Completed":
                break
        assert rv["bid_state"] == "Completed"

        # Ensure offer was revoked
        summary = read_json_api(12700)
        assert summary["num_network_offers"] == 0

        # Wait for bid to be removed from in-progress
        waitForNumBids(self.delay_event, 12700, 0)


if __name__ == "__main__":
    unittest.main()
