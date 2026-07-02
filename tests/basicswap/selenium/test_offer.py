#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023-2024 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

from urllib.request import urlopen
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select

from util import get_driver


def select_coin(driver, select_id, coin_name):
    native = driver.find_element(By.ID, select_id)
    picker = native.find_element(By.XPATH, "./ancestor::div[@data-coin-picker][1]")
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable(
            picker.find_element(By.CSS_SELECTOR, ".coin-picker-button")
        )
    ).click()
    items = picker.find_elements(By.CSS_SELECTOR, ".coin-picker-item")
    for item in items:
        name = item.find_element(By.CSS_SELECTOR, ".coin-picker-name").text.strip()
        if name == coin_name:
            item.click()
            return
    raise AssertionError(f"Coin '{coin_name}' not found in picker '{select_id}'")


def get_published_offer_id(driver):
    el = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "[data-testid='view-offer']"))
    )
    href = el.get_attribute("href")
    return href.rstrip("/").split("/offer/")[-1]


def test_offer_wizard_ui(driver):
    node1_url = "http://localhost:12701"

    driver.get(node1_url + "/newoffer")
    time.sleep(1)

    body_text = driver.find_element(By.TAG_NAME, "body").text
    for label in ("Trade", "Terms", "Review"):
        assert label in body_text, f"stepper label '{label}' missing"

    select_coin(driver, "coin_from", "Bitcoin")
    select_coin(driver, "coin_to", "Monero")

    assert driver.find_element(By.ID, "summary-send-coin").text.strip() == "Bitcoin"
    assert driver.find_element(By.ID, "summary-get-coin").text.strip() == "Monero"

    driver.find_element(By.ID, "swap-coins-btn").click()
    time.sleep(0.5)
    assert driver.find_element(By.ID, "summary-send-coin").text.strip() == "Monero"
    assert driver.find_element(By.ID, "summary-get-coin").text.strip() == "Bitcoin"
    driver.find_element(By.ID, "swap-coins-btn").click()
    time.sleep(0.5)
    assert driver.find_element(By.ID, "summary-send-coin").text.strip() == "Bitcoin"

    continue_btn = driver.find_element(By.NAME, "continue")
    assert continue_btn.get_attribute("disabled"), "Continue should start disabled"

    driver.find_element(By.NAME, "amt_from").send_keys("1")
    driver.find_element(By.NAME, "amt_to").send_keys("2")
    time.sleep(0.6)
    assert not continue_btn.get_attribute(
        "disabled"
    ), "Continue should enable once valid"
    continue_btn.click()

    WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.NAME, "validhrs"))
    )
    assert "Bitcoin" in driver.find_element(By.TAG_NAME, "body").text

    driver.find_element(By.XPATH, "//button[@name='step1' and @form='form']").click()
    WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.ID, "coin_from"))
    )
    assert driver.find_element(By.ID, "summary-send-coin").text.strip() == "Bitcoin"


def test_offer(driver):
    node1_url = "http://localhost:12701"

    driver.get(node1_url + "/newoffer")
    time.sleep(1)

    select_coin(driver, "coin_from", "Bitcoin")
    select_coin(driver, "coin_to", "Monero")

    amt_from = driver.find_element(By.NAME, "amt_from")
    amt_to = driver.find_element(By.NAME, "amt_to")
    rate = driver.find_element(By.ID, "rate")
    amt_from.send_keys("1")
    amt_to.send_keys("2")
    amt_from.click()
    time.sleep(0.5)
    rate_value = rate.get_attribute("value")
    assert float(rate_value) == 2.0

    rate.clear()
    rate.send_keys("3")
    amt_from.click()
    time.sleep(0.5)
    amt_to_value = amt_to.get_attribute("value")
    assert float(amt_to_value) == 3.0

    amt_from.clear()
    amt_from.send_keys("2")
    amt_to.click()
    time.sleep(0.5)
    amt_to_value = amt_to.get_attribute("value")
    assert float(amt_to_value) == 6.0

    amt_from.clear()
    amt_to.clear()
    rate.clear()
    amt_to.send_keys("2")
    rate.send_keys("2")
    amt_to.click()
    time.sleep(0.2)
    amt_from_value = amt_from.get_attribute("value")
    assert float(amt_from_value) == 1.0

    driver.find_element(By.NAME, "continue").click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "check_offer"))
    ).click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "submit_offer"))
    ).click()

    offer1_id = get_published_offer_id(driver)

    driver.get(node1_url + "/newoffer")
    time.sleep(1)

    select_coin(driver, "coin_from", "Particl")
    select_coin(driver, "coin_to", "Monero")

    driver.find_element(By.NAME, "amt_from").send_keys("3")
    driver.find_element(By.NAME, "amt_to").send_keys("4")

    driver.find_element(By.NAME, "continue").click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "check_offer"))
    ).click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "submit_offer"))
    ).click()

    offer2_id = get_published_offer_id(driver)

    driver.get(node1_url + "/offer/" + offer1_id)
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "repeat_offer"))
    ).click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "check_offer"))
    ).click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "submit_offer"))
    ).click()

    offer3_id = get_published_offer_id(driver)

    offer3_json = json.loads(urlopen(node1_url + "/json/offers/" + offer3_id).read())[0]
    assert offer3_json["coin_from"] == "Bitcoin"
    assert offer3_json["coin_to"] == "Monero"

    driver.get(node1_url + "/offer/" + offer2_id)
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "repeat_offer"))
    ).click()
    time.sleep(1)  # Add time for setupCustomSelect to fire
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "check_offer"))
    ).click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "submit_offer"))
    ).click()

    offer4_id = get_published_offer_id(driver)

    offer4_json = json.loads(urlopen(node1_url + "/json/offers/" + offer4_id).read())[0]
    assert offer4_json["coin_from"] == "Particl"
    assert offer4_json["coin_to"] == "Monero"

    print("Test Passed!")


def test_offer_tracking_ui(driver):
    node1_url = "http://localhost:12701"

    driver.get(node1_url + "/newoffer")
    time.sleep(1)

    select_coin(driver, "coin_from", "Bitcoin")
    select_coin(driver, "coin_to", "Monero")

    driver.find_element(By.NAME, "amt_from").send_keys("1")
    driver.find_element(By.NAME, "amt_to").send_keys("2")
    time.sleep(0.5)

    mode_select = Select(driver.find_element(By.ID, "offer_mode"))
    mode_select.select_by_value("fixed_total")
    time.sleep(0.3)

    total_to_sell = driver.find_element(By.ID, "total_to_sell")
    total_to_sell.clear()
    total_to_sell.send_keys("5")

    driver.find_element(By.NAME, "continue").click()
    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "check_offer"))
    ).click()

    body_text = driver.find_element(By.TAG_NAME, "body").text
    assert "Fixed total" in body_text, "review summary should show the offer type"

    WebDriverWait(driver, 20).until(
        EC.element_to_be_clickable((By.NAME, "submit_offer"))
    ).click()

    offer_id = get_published_offer_id(driver)

    offer_json = json.loads(urlopen(node1_url + "/json/offers/" + offer_id).read())[0]
    assert offer_json.get("tracking_mode_str") == "Fixed total"
    assert "tracking_total_budget" in offer_json
    assert offer_json.get("tracking_exhausted") is False

    driver.get(node1_url + "/offer/" + offer_id)
    time.sleep(1)
    offer_page_text = driver.find_element(By.TAG_NAME, "body").text
    assert "Offer Type" in offer_page_text
    assert "Fill Progress" in offer_page_text

    print("Offer tracking UI test passed!")


def run_tests():
    driver = get_driver()
    try:
        test_offer_wizard_ui(driver)
        test_offer(driver)
        test_offer_tracking_ui(driver)
    finally:
        driver.close()


if __name__ == "__main__":
    run_tests()
