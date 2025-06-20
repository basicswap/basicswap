#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import sys
import time

from tests.basicswap.util import (
    read_json_api,
)
from util import get_driver
from selenium.webdriver.common.by import By


logger = logging.getLogger()
logger.level = logging.INFO
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def clear_offers(port_list) -> None:
    logger.info(f"clear_offers {port_list}")

    for port in port_list:
        offers = read_json_api(port, "offers")
        for offer in offers:
            read_json_api(port, "revokeoffer/{}".format(offer["offer_id"]))

    for i in range(30):
        time.sleep(1)
        offers_sum: int = 0
        for port in port_list:
            offers = read_json_api(port, "offers")
            offers_sum += len(offers)
        if offers_sum == 0:
            return
    raise ValueError("clear_offers failed")


def test_swap_dir(driver):
    node_1_port = 12701
    node_2_port = 12702
    node1_url = f"http://localhost:{node_1_port}"
    node2_url = f"http://localhost:{node_2_port}"

    clear_offers((node_1_port, node_2_port))

    offer_data = {
        "addr_from": -1,
        "coin_from": "PART",
        "coin_to": "XMR",
        "amt_from": 1,
        "amt_to": 2,
        "lockhrs": 24,
        "automation_strat_id": 1,
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
        "automation_strat_id": 1,
    }
    rv = read_json_api(node_1_port, "offers/new", offer_data)
    offer_2_id = rv["offer_id"]

    offer_data = {
        "addr_from": -1,
        "coin_from": "XMR",
        "coin_to": "PART",
        "amt_from": 5,
        "amt_to": 6,
        "lockhrs": 24,
        "automation_strat_id": 1,
    }
    rv = read_json_api(node_2_port, "offers/new", offer_data)
    offer_3_id = rv["offer_id"]

    # Wait for offers to propagate
    for i in range(1000):
        offers_1 = read_json_api(node_1_port, "offers")
        if len(offers_1) >= 3:
            break
        time.sleep(0.1)
    assert len(offers_1) >= 3

    for offer in offers_1:
        if offer["offer_id"] == offer_1_id:
            assert offer["coin_to"] == "Monero"
        elif offer["offer_id"] == offer_2_id:
            assert offer["coin_to"] == "Bitcoin"
        elif offer["offer_id"] == offer_3_id:
            assert offer["coin_to"] == "Particl"
        else:
            raise ValueError("Unknown offer id")

    for i in range(1000):
        offers_2 = read_json_api(node_2_port, "offers")
        if len(offers_2) >= 3:
            break
        time.sleep(0.1)
    assert len(offers_2) >= 3

    for offer in offers_2:
        if offer["offer_id"] == offer_1_id:
            assert offer["coin_to"] == "Monero"
        elif offer["offer_id"] == offer_2_id:
            assert offer["coin_to"] == "Bitcoin"
        elif offer["offer_id"] == offer_3_id:
            assert offer["coin_to"] == "Particl"
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
            if len(found_rows) >= 3:
                break
        except Exception as e:
            print(e)

    assert len(found_rows) == 3
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
        elif offer_3_id in row[0]:
            loc_xmr = row[5].find("Monero")
            loc_part = row[5].find("Particl")
            assert loc_part < loc_xmr
            assert "Swap" in row[9]
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

    assert len(found_rows) == 3
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
        elif offer_3_id in row[0]:
            loc_xmr = row[5].find("Monero")
            loc_part = row[5].find("Particl")
            assert loc_part < loc_xmr
            assert "Edit" in row[9]
        else:
            raise ValueError("Unknown offer id")

    bid_data = {
        "offer_id": offer_1_id,
        "amount_from": 1,
    }
    rv = read_json_api(node_2_port, "bids/new", bid_data)
    bid_1_id = rv["bid_id"]
    bid_data = {
        "offer_id": offer_3_id,
        "amount_from": 5,
    }
    rv = read_json_api(node_1_port, "bids/new", bid_data)
    bid_3_id = rv["bid_id"]

    bid_ids = [bid_1_id, bid_3_id]
    # Wait for bids to propagate
    for i in range(1000):
        num_found: int = 0
        for bid_id in bid_ids:
            bid = read_json_api(node_1_port, f"bids/{bid_id}")
            if "error" not in bid:
                num_found += 1
        if num_found >= 2:
            break
        time.sleep(0.5)
    assert num_found >= 2

    for i in range(1000):
        num_found: int = 0
        for bid_id in bid_ids:
            bid = read_json_api(node_2_port, f"bids/{bid_id}")
            if "error" not in bid:
                num_found += 1
        if num_found >= 2:
            break
        time.sleep(0.5)
    assert num_found >= 2

    driver.get(f"{node1_url}/bid/{bid_1_id}")
    td_dir = driver.find_element(By.ID, "bidtype")
    assert "Received" == td_dir.get_attribute("innerHTML")
    td_ys = driver.find_element(
        "xpath", "//td[contains(text(), 'You Send')]/following-sibling::td"
    )
    assert "Particl" in td_ys.get_attribute("innerHTML")
    td_yg = driver.find_element(
        "xpath", "//td[contains(text(), 'You Get')]/following-sibling::td"
    )
    assert "Monero" in td_yg.get_attribute("innerHTML")

    driver.get(f"{node2_url}/bid/{bid_1_id}")
    td_dir = driver.find_element(By.ID, "bidtype")
    assert "Sent" == td_dir.get_attribute("innerHTML")
    td_ys = driver.find_element(
        "xpath", "//td[contains(text(), 'You Send')]/following-sibling::td"
    )
    assert "Monero" in td_ys.get_attribute("innerHTML")
    td_yg = driver.find_element(
        "xpath", "//td[contains(text(), 'You Get')]/following-sibling::td"
    )
    assert "Particl" in td_yg.get_attribute("innerHTML")

    driver.get(f"{node1_url}/bid/{bid_3_id}")
    td_dir = driver.find_element(By.ID, "bidtype")
    assert "Sent (Transposed)" == td_dir.get_attribute("innerHTML")
    td_ys = driver.find_element(
        "xpath", "//td[contains(text(), 'You Send')]/following-sibling::td"
    )
    assert "Particl" in td_ys.get_attribute("innerHTML")
    td_yg = driver.find_element(
        "xpath", "//td[contains(text(), 'You Get')]/following-sibling::td"
    )
    assert "Monero" in td_yg.get_attribute("innerHTML")

    driver.get(f"{node2_url}/bid/{bid_3_id}")
    td_dir = driver.find_element(By.ID, "bidtype")
    assert "Received (Transposed)" == td_dir.get_attribute("innerHTML")
    td_ys = driver.find_element(
        "xpath", "//td[contains(text(), 'You Send')]/following-sibling::td"
    )
    assert "Monero" in td_ys.get_attribute("innerHTML")
    td_yg = driver.find_element(
        "xpath", "//td[contains(text(), 'You Get')]/following-sibling::td"
    )
    assert "Particl" in td_yg.get_attribute("innerHTML")

    logger.info(f"Waiting for {node1_url}/active")
    driver.get(f"{node1_url}/active")
    bid_rows = dict()
    for i in range(120):
        try:
            bid_rows = dict()
            table = driver.find_element(By.XPATH, "//tbody[@id='active-swaps-body']")
            for row in table.find_elements(By.XPATH, ".//tr"):
                tds = row.find_elements(By.XPATH, ".//td")
                td_details = tds[2]
                td_send = tds[5]
                td_recv = tds[3]
                td_send_amount = td_send.find_element(
                    By.XPATH, ".//div[contains(@class, 'font-semibold')]"
                )
                td_recv_amount = td_recv.find_element(
                    By.XPATH, ".//div[contains(@class, 'font-semibold')]"
                )
                row_data = (
                    td_send.get_attribute("innerHTML"),
                    td_send_amount.get_attribute("innerHTML"),
                    td_recv.get_attribute("innerHTML"),
                    td_recv_amount.get_attribute("innerHTML"),
                )
                if bid_1_id in td_details.get_attribute("innerHTML"):
                    bid_rows[bid_1_id] = row_data
                elif bid_3_id in td_details.get_attribute("innerHTML"):
                    bid_rows[bid_3_id] = row_data
            if len(bid_rows) >= 2:
                break
        except Exception as e:
            print(e)
        time.sleep(2)
    assert "Particl" in bid_rows[bid_1_id][0]
    assert float(bid_rows[bid_1_id][1]) == 1.0
    assert "Monero" in bid_rows[bid_1_id][2]
    assert float(bid_rows[bid_1_id][3]) == 2.0

    assert "Particl" in bid_rows[bid_3_id][0]
    assert float(bid_rows[bid_3_id][1]) == 6.0
    assert "Monero" in bid_rows[bid_3_id][2]
    assert float(bid_rows[bid_3_id][3]) == 5.0

    logger.info(f"Waiting for {node2_url}/active")
    driver.get(f"{node2_url}/active")
    bid_rows = dict()
    for i in range(120):
        try:
            bid_rows = dict()
            table = driver.find_element(By.XPATH, "//tbody[@id='active-swaps-body']")
            for row in table.find_elements(By.XPATH, ".//tr"):
                tds = row.find_elements(By.XPATH, ".//td")
                td_details = tds[2]
                td_send = tds[5]
                td_recv = tds[3]
                td_send_amount = td_send.find_element(
                    By.XPATH, ".//div[contains(@class, 'font-semibold')]"
                )
                td_recv_amount = td_recv.find_element(
                    By.XPATH, ".//div[contains(@class, 'font-semibold')]"
                )
                row_data = (
                    td_send.get_attribute("innerHTML"),
                    td_send_amount.get_attribute("innerHTML"),
                    td_recv.get_attribute("innerHTML"),
                    td_recv_amount.get_attribute("innerHTML"),
                )
                if bid_1_id in td_details.get_attribute("innerHTML"):
                    bid_rows[bid_1_id] = row_data
                elif bid_3_id in td_details.get_attribute("innerHTML"):
                    bid_rows[bid_3_id] = row_data
            if len(bid_rows) >= 2:
                break
        except Exception as e:
            print(e)
        time.sleep(2)
    assert "Monero" in bid_rows[bid_1_id][0]
    assert float(bid_rows[bid_1_id][1]) == 2.0
    assert "Particl" in bid_rows[bid_1_id][2]
    assert float(bid_rows[bid_1_id][3]) == 1.0

    assert "Monero" in bid_rows[bid_3_id][0]
    assert float(bid_rows[bid_3_id][1]) == 5.0
    assert "Particl" in bid_rows[bid_3_id][2]
    assert float(bid_rows[bid_3_id][3]) == 6.0

    print("Test Passed!")


def run_tests():
    driver = get_driver()
    try:
        test_swap_dir(driver)
    finally:
        driver.close()


if __name__ == "__main__":
    run_tests()
