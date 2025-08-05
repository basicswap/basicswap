#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_basicswap
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
python tests/basicswap/extended/test_encrypted_xmr_reload.py


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

        node1_password: str = "notapassword123"
        logger.info("Encrypting node 1 wallets")
        rv = read_json_api(
            12701, "setpassword", {"oldpassword": "", "newpassword": node1_password}
        )
        assert "success" in rv
        rv = read_json_api(12701, "unlock", {"password": node1_password})
        assert "success" in rv

        logger.info("Waiting for node 1 to reconnect after encryption")
        self.delay_event.wait(15)

        for attempt in range(30):
            try:
                status = read_json_api(12701)
                if (
                    "error" not in status
                    and status.get("num_watched_outputs") is not None
                ):
                    logger.info(
                        f"Node 1 operational after {attempt + 1} attempts: {status}"
                    )
                    break
            except Exception as e:
                logger.warning(f"Node 1 not ready (attempt {attempt + 1}): {e}")
            self.delay_event.wait(3)
        else:
            raise ValueError("Node 1 failed to become operational after encryption")

        logger.info(
            "Restarting node 1 to restore network connectivity after encryption"
        )
        c1 = self.processes[1]
        c1.terminate()
        c1.join()
        self.processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
        self.processes[1].start()

        waitForServer(self.delay_event, 12701)
        rv = read_json_api(12701, "unlock", {"password": node1_password})
        assert "success" in rv

        self.delay_event.wait(10)

        try:
            node0_status = read_json_api(12700)
            node1_status = read_json_api(12701)
            logger.info(f"Pre-offer Node 0 status: {node0_status}")
            logger.info(f"Pre-offer Node 1 status: {node1_status}")

            if (
                node0_status.get("num_watched_outputs") is None
                or node1_status.get("num_watched_outputs") is None
            ):
                raise ValueError("Nodes not properly initialized")

        except Exception as e:
            logger.error(f"Failed to get node status: {e}")
            raise

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
        logger.info(f"Node 0 created offer {offer_id}, summary: {summary}")

        logger.info("Waiting for offer")
        node1_summary = read_json_api(12701)
        logger.info(f"Node 1 status before waiting: {node1_summary}")

        logger.info("Checking offer propagation manually...")
        for attempt in range(60):
            if self.delay_event.is_set():
                raise ValueError("Test stopped.")

            try:
                node0_status = read_json_api(12700)
                node1_status = read_json_api(12701)

                logger.info(
                    f"Attempt {attempt + 1}: Node 0 offers: {node0_status.get('num_sent_offers', 0)}, Node 1 offers: {node1_status.get('num_network_offers', 0)}"
                )

                if node1_status.get("num_network_offers", 0) >= 1:
                    logger.info("Offer successfully propagated!")
                    break

                if attempt % 15 == 0:
                    logger.info(f"Node 0 detailed: {node0_status}")
                    logger.info(f"Node 1 detailed: {node1_status}")

            except Exception as e:
                logger.warning(
                    f"Error checking offer status (attempt {attempt + 1}): {e}"
                )

            self.delay_event.wait(2)
        else:
            node0_final = read_json_api(12700)
            node1_final = read_json_api(12701)
            logger.error(f"FINAL - Node 0: {node0_final}")
            logger.error(f"FINAL - Node 1: {node1_final}")

            logger.info("Attempting fallback strategies...")
            logger.info("Strategy 1: Extended wait and retry...")
            self.delay_event.wait(10)
            for _ in range(20):
                try:
                    node1_status = read_json_api(12701)
                    if node1_status.get("num_network_offers", 0) >= 1:
                        logger.info("Extended wait strategy succeeded!")
                        break
                except Exception as e:
                    logger.warning(f"Error in extended wait: {e}")
                self.delay_event.wait(2)
            else:
                logger.info("Strategy 2: Creating new offer...")
                try:
                    read_json_api(12700, f"revokeoffer/{offer_id}")
                    self.delay_event.wait(5)

                    new_offer_id = post_json_api(12700, "offers/new", data)["offer_id"]
                    logger.info(f"Created fallback offer: {new_offer_id}")
                    for _ in range(30):
                        try:
                            node1_status = read_json_api(12701)
                            if node1_status.get("num_network_offers", 0) >= 1:
                                logger.info("Fallback offer propagated successfully!")
                                offer_id = new_offer_id
                                break
                        except Exception as e:
                            logger.warning(f"Error checking fallback offer: {e}")
                        self.delay_event.wait(2)
                    else:
                        raise ValueError("Even fallback offer failed to propagate")

                except Exception as e:
                    logger.error(f"All fallback strategies failed: {e}")
                    raise ValueError(
                        "waitForNumOffers failed - offer never propagated after all strategies"
                    )

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
        post_json_api(12701, "bids/new", data)

        waitForNumBids(self.delay_event, 12700, 1)

        for _ in range(16):
            bids = read_json_api(12700, "bids")
            bid = bids[0]
            if bid["bid_state"] == "Received":
                break
            self.delay_event.wait(2)
        assert bid["bid_state"] == "Received"
        assert bid["expire_at"] == bid["created_at"] + data["validmins"] * 60

        data = {"accept": True}
        rv = post_json_api(12700, "bids/{}".format(bid["bid_id"]), data)
        assert rv["bid_state"] == "Accepted"

        waitForNumSwapping(self.delay_event, 12701, 1)

        logger.info("Restarting node 1")
        c1 = self.processes[1]
        c1.terminate()
        c1.join()
        self.processes[1] = multiprocessing.Process(target=self.run_thread, args=(1,))
        self.processes[1].start()

        waitForServer(self.delay_event, 12701)
        rv = read_json_api(12701)
        assert "error" in rv

        logger.info("Unlocking node 1")
        rv = read_json_api(12701, "unlock", {"password": node1_password})
        assert "success" in rv
        rv = read_json_api(12701)
        assert rv["num_swapping"] == 1

        rv = read_json_api(12700, "revokeoffer/{}".format(offer_id))
        assert rv["revoked_offer"] == offer_id

        logger.info("Completing swap")
        for _ in range(240):
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
