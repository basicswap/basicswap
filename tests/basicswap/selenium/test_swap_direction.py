#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import time

from tests.basicswap.util import (
    read_json_api,
)
from util import get_driver
from selenium.webdriver.common.by import By


def clear_offers(port) -> None:
    logging.info(f"clear_offers {port}")
    offers = read_json_api(port, "offers")

    for offer in offers:
        read_json_api(port, "revokeoffer/{}".format(offer["offer_id"]))

    for i in range(20):
        time.sleep(1)
        offers = read_json_api(port, "offers")
        if len(offers) == 0:
            return
    raise ValueError("clear_offers failed")


def test_swap_dir(driver):
    node_1_port = 12701
    node_2_port = 12702
    node1_url = f"http://localhost:{node_1_port}"
    node2_url = f"http://localhost:{node_2_port}"

    clear_offers(node_1_port)
    clear_offers(node_2_port)

    offer_data = {
        "addr_from": -1,
        "coin_from": "PART",
        "coin_to": "XMR",
        "amt_from": 1,
        "amt_to": 2,
        "lockhrs": 24,
    }
    rv = read_json_api(node_1_port, "offers/new", offer_data)
    offer_1_id = rv["offer_id"]

    offer_data = {
        "addr_from": -1,
        "coin_from": "PART",
        "coin_to": "BTC",
        "amt_from": 3,
        "amt_to": 4,
        "lockhrs": 24,
    }
    rv = read_json_api(node_1_port, "offers/new", offer_data)
    offer_2_id = rv["offer_id"]

    # Wait for offer to propagate
    offers_1 = read_json_api(node_1_port, "offers")

    for offer in offers_1:
        if offer["offer_id"] == offer_1_id:
            assert offer["coin_to"] == "Monero"
        elif offer["offer_id"] == offer_2_id:
            assert offer["coin_to"] == "Bitcoin"
        else:
            raise ValueError("Unknown offer id")

    offers_2 = read_json_api(node_2_port, "offers")
    while len(offers_2) < 1:
        offers_2 = read_json_api(node_2_port, "offers")
        time.sleep(0.1)

    for offer in offers_2:
        if offer["offer_id"] == offer_1_id:
            assert offer["coin_to"] == "Monero"
        elif offer["offer_id"] == offer_2_id:
            assert offer["coin_to"] == "Bitcoin"
        else:
            raise ValueError("Unknown offer id")

    driver.get(f"{node1_url}/offers")

    found_rows = []
    for i in range(5):
        try:
            time.sleep(2)
            table = driver.find_element(By.XPATH, "//tbody[@id='offers-body']")
            for row in table.find_elements(By.XPATH, ".//tr"):
                found_rows.append(
                    [row.get_attribute("data-offer-id")]
                    + [
                        td.get_attribute("innerHTML")
                        for td in row.find_elements(By.XPATH, ".//td")
                    ]
                )
            break
        except Exception as e:
            print(e)

    assert len(found_rows) == 2
    for row in found_rows:
        if offer_1_id in row[0]:
            loc_xmr = row[5].find("Monero")
            loc_part = row[5].find("Particl")
            assert loc_xmr < loc_part
            assert "Edit" in row[9]
        elif offer_2_id in row[0]:
            loc_btc = row[5].find("Bitcoin")
            loc_part = row[5].find("Particl")
            assert loc_btc < loc_part
            assert "Edit" in row[9]
        else:
            raise ValueError("Unknown offer id")

    driver.get(f"{node2_url}/offers")

    found_rows = []
    for i in range(5):
        try:
            time.sleep(2)
            table = driver.find_element(By.XPATH, "//tbody[@id='offers-body']")
            for row in table.find_elements(By.XPATH, ".//tr"):
                found_rows.append(
                    [row.get_attribute("data-offer-id")]
                    + [
                        td.get_attribute("innerHTML")
                        for td in row.find_elements(By.XPATH, ".//td")
                    ]
                )
            break
        except Exception as e:
            print(e)

    assert len(found_rows) == 2
    for row in found_rows:
        if offer_1_id in row[0]:
            assert ("Monero") in row[5]
            loc_xmr = row[5].find("Monero")
            loc_part = row[5].find("Particl")
            assert loc_xmr < loc_part
            assert "Swap" in row[9]
        elif offer_2_id in row[0]:
            loc_btc = row[5].find("Bitcoin")
            loc_part = row[5].find("Particl")
            assert loc_btc < loc_part
            assert "Swap" in row[9]
        else:
            raise ValueError("Unknown offer id")

    print("Test Passed!")


def run_tests():
    driver = get_driver()
    try:
        test_swap_dir(driver)
    finally:
        driver.close()


if __name__ == "__main__":
    run_tests()
