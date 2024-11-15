#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time

from tests.basicswap.util import (
    read_json_api,
)

from util import get_driver


def test_swap_dir(driver):
    node_1_port = 12701
    node_2_port = 12702
    node1_url = f"http://localhost:{node_1_port}"
    node2_url = f"http://localhost:{node_2_port}"

    offer_data = {
        "addr_from": -1,
        "coin_from": "PART",
        "coin_to": "XMR",
        "amt_from": 1,
        "amt_to": 2,
        "lockhrs": 24,
    }
    read_json_api(node_1_port, "offers/new", offer_data)

    offer_data = {
        "addr_from": -1,
        "coin_from": "PART",
        "coin_to": "BTC",
        "amt_from": 3,
        "amt_to": 4,
        "lockhrs": 24,
    }
    read_json_api(node_1_port, "offers/new", offer_data)

    # Wait for offer to propagate
    offers_api_1 = read_json_api(node_1_port, "offers")
    print("offers_api_1", offers_api_1)

    offers_api_2 = read_json_api(node_2_port, "offers")
    while len(offers_api_2) < 1:
        offers_api_2 = read_json_api(node_2_port, "offers")
        time.sleep(0.1)
    print("offers_api_2", offers_api_2)

    driver.get(f"{node1_url}/offers")
    time.sleep(1)

    driver.get(f"{node2_url}/offers")
    time.sleep(300)

    raise ValueError("TODO")

    print("Test Passed!")


def run_tests():
    driver = get_driver()
    try:
        test_swap_dir(driver)
    finally:
        driver.close()


if __name__ == "__main__":
    run_tests()
