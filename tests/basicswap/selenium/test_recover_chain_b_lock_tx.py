#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time

from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support.select import Select
from selenium.webdriver.support import expected_conditions as EC

from util import (
    BSX_0_PORT,
    BSX_1_PORT,
    click_option,
    get_driver,
)
from tests.basicswap.util import read_json_api


base_url = "http://localhost"


def recover_chain_b_lock_tx(driver, offer_data, offerer_port, bidder_port):
    print("Test case: {} -> {}".format(offer_data["coin_from"], offer_data["coin_to"]))
    offerer_url = f"{base_url}:{offerer_port}"
    bidder_url = f"{base_url}:{bidder_port}"

    rv = read_json_api(offerer_port, "offers/new", offer_data)
    offer0_id = rv["offer_id"]

    for i in range(10):
        rv = read_json_api(bidder_port, f"offers/{offer0_id}")
        if len(rv) > 0:
            break
        print("Bidder: Waiting for offer")
        time.sleep(1)

    bid_data = {"offer_id": offer0_id, "amount_from": 1.0}
    rv = read_json_api(bidder_port, "bids/new", bid_data)
    bid0_id = rv["bid_id"]

    bid_state = None
    for i in range(10):
        rv = read_json_api(offerer_port, f"bids/{bid0_id}")
        if "error" not in rv:
            bid_state = rv["bid_state"]
            if bid_state == "Received":
                break
        print("Offerer: Waiting for bid")
        time.sleep(2)
    assert bid_state == "Received"

    # Set BID_STOP_AFTER_COIN_B_LOCK (13) debugind
    rv = read_json_api(offerer_port, f"bids/{bid0_id}", {"debugind": 13})
    assert "error" not in rv

    # Accept bid
    rv = read_json_api(offerer_port, f"bids/{bid0_id}", {"accept": 1})
    assert "error" not in rv

    for i in range(100):
        rv = read_json_api(bidder_port, f"bids/{bid0_id}")
        bid_state = rv["bid_state"]
        if bid_state == "Scriptless coin locked":
            break
        print("Bidder: Waiting for state")
        time.sleep(5)
    assert bid_state == "Scriptless coin locked"

    for i in range(100):
        rv = read_json_api(offerer_port, f"bids/{bid0_id}")
        bid_state = rv["bid_state"]
        if bid_state == "Stalled (debug)":
            break
        print("Offerer: Waiting for state")
        time.sleep(5)
    assert bid_state == "Stalled (debug)"

    # Show bid state history
    rv = read_json_api(offerer_port, f"bids/{bid0_id}/states")
    assert len(rv) > 1

    url = f"{bidder_url}/bid/{bid0_id}"
    driver.get(url)
    btn_more_info = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "show_txns"))
    )
    btn_more_info.click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, "hide_txns")))
    bidder_localkeyhalf = driver.find_element(By.ID, "localkeyhalf").text
    print("Bidder keyhalf", bidder_localkeyhalf)
    try:
        driver.find_element(By.ID, "remotekeyhalf")
    except Exception:
        pass
    else:
        raise ValueError("Nodes should not have remotekeyhalves yet.")

    url = f"{offerer_url}/bid/{bid0_id}"
    driver.get(url)
    btn_more_info = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "show_txns"))
    )
    btn_more_info.click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, "hide_txns")))
    offerer_localkeyhalf = driver.find_element(By.ID, "localkeyhalf").text
    print("Offerer keyhalf", offerer_localkeyhalf)

    print("Trying with the local key in place of remote")
    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    btn_edit.click()
    btn_submit = WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid_submit"))
    )
    kbs_other = driver.find_element(By.ID, "kbs_other")
    kbs_other.send_keys(offerer_localkeyhalf)
    btn_submit.click()

    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    elements = driver.find_elements(By.CLASS_NAME, "error_msg")
    expect_err_msg: str = "Provided key matches local key"
    assert any(expect_err_msg in el.text for el in elements)
    print("Found expected error: " + expect_err_msg)

    print("Trying with incorrect key")
    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    btn_edit.click()
    btn_submit = WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid_submit"))
    )
    kbs_other = driver.find_element(By.ID, "kbs_other")
    last_byte = bidder_localkeyhalf[-2:]
    invalid_byte = "01" if last_byte == "00" else "00"
    kbs_other.send_keys(bidder_localkeyhalf[:-2] + invalid_byte)
    btn_submit.click()

    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    elements = driver.find_elements(By.CLASS_NAME, "error_msg")
    expect_err_msg: str = "Summed key does not match expected wallet"
    assert any(expect_err_msg in el.text for el in elements)
    print("Found expected error: " + expect_err_msg)

    print("Trying with correct key")
    btn_edit.click()
    btn_submit = WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid_submit"))
    )

    lock_tx_b_depth = -1
    for i in range(100):
        # Check the non-stalled node
        rv = read_json_api(bidder_port, f"bids/{bid0_id}", {"show_extra": True})
        for tx in rv["txns"]:
            if tx["type"] == "Chain B Lock" and tx["confirms"] is not None:
                lock_tx_b_depth = tx["confirms"]
                break
        if lock_tx_b_depth >= 10:
            break
        print(f"Waiting for lock tx B depth, have {lock_tx_b_depth}")
        time.sleep(2)

    kbs_other = driver.find_element(By.ID, "kbs_other")
    kbs_other.send_keys(bidder_localkeyhalf)
    btn_submit.click()
    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    elements = driver.find_elements(By.CLASS_NAME, "infomsg")
    expect_msg: str = "Bid edited"
    assert any(expect_msg in el.text for el in elements)
    print("Found expected message: " + expect_msg)

    print(
        "Trying with nodes reversed (should fail as already spent)"
    )  # But should sum to the expected wallet key
    url = f"{bidder_url}/bid/{bid0_id}"
    driver.get(url)
    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    btn_edit.click()
    btn_submit = WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid_submit"))
    )

    driver.get(url)
    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    btn_edit.click()
    btn_submit = WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid_submit"))
    )

    kbs_other = driver.find_element(By.ID, "kbs_other")
    kbs_other.send_keys(offerer_localkeyhalf)
    btn_submit.click()
    btn_edit = WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.NAME, "edit_bid"))
    )
    # In log: "Balance is too low, checking for existing spend"
    # Should error here, but the code can't tell where the tx was sent, and treats any existing send as correct.
    elements = driver.find_elements(By.CLASS_NAME, "infomsg")
    expect_msg: str = "Bid edited"
    assert any(expect_msg in el.text for el in elements)


def enable_debug_ui(driver):
    for port in (BSX_0_PORT, BSX_1_PORT):
        url = f"{base_url}:{port}/settings"
        driver.get(url)
        driver.find_element(By.ID, "general-tab").click()

        btn_apply_general = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.NAME, "apply_general"))
        )

        el = driver.find_element(By.NAME, "debugmode")
        selected_option = Select(el).first_selected_option
        if selected_option.text != "True":
            click_option(el, "True")

        el = driver.find_element(By.NAME, "debugui")
        selected_option = Select(el).first_selected_option
        if selected_option.text != "True":
            click_option(el, "True")

        btn_apply_general.click()


def run_tests():
    driver = get_driver()
    try:
        enable_debug_ui(driver)

        offer_data = {
            "coin_from": "BTC",
            "coin_to": "XMR",
            "amt_from": 1.0,
            "amt_to": 2.0,
            "lockhrs": 24,
        }
        recover_chain_b_lock_tx(driver, offer_data, BSX_0_PORT, BSX_1_PORT)

        offer_data = {
            "coin_from": "XMR",
            "coin_to": "BTC",
            "amt_from": 1.0,
            "amt_to": 2.0,
            "lockhrs": 24,
        }
        recover_chain_b_lock_tx(driver, offer_data, BSX_1_PORT, BSX_0_PORT)

        print("Test Passed!")
    finally:
        driver.close()


if __name__ == "__main__":
    run_tests()
