#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from urllib.request import urlopen

from basicswap.util import dumpje
from util import click_option, get_driver


def test_wallets(driver):
    base_url = "http://localhost:12701"
    node2_url = "http://localhost:12702"

    # Check json coins data
    coins = json.loads(urlopen(base_url + "/json/coins").read())
    part_coin = [f for f in coins if f["ticker"] == "PART"][0]
    part_id = part_coin["id"]
    assert part_id == 1

    # Check 404 pages
    url = base_url + "/unknown"
    driver.get(url)
    p1 = driver.find_element(By.TAG_NAME, "body")
    assert "Error 404" in p1.text

    url = base_url + "/static/nothing.png"
    driver.get(url)
    p1 = driver.find_element(By.TAG_NAME, "body")
    assert "Error 404" in p1.text

    url = base_url + "/wallet"
    driver.get(url)
    h2 = driver.find_element(By.TAG_NAME, "h2")
    assert "error" in h2.text.lower()
    p1 = driver.find_element(By.TAG_NAME, "p")
    assert "Wallet not specified" in p1.text

    url = base_url + "/wallet/NOCOIN"
    driver.get(url)
    h2 = driver.find_element(By.TAG_NAME, "h2")
    assert "error" in h2.text.lower()
    p1 = driver.find_element(By.TAG_NAME, "p")
    assert "Unknown coin" in p1.text

    driver.get(base_url + "/wallets")
    time.sleep(1)
    driver.refresh()
    driver.refresh()
    time.sleep(1)
    driver.refresh()

    print("Finding deposit address of node 2")
    driver.get(node2_url + "/wallet/PART")
    e = driver.find_element(By.ID, "main_deposit_address")
    node2_deposit_address = e.text

    print("Withdrawing from node 1")
    driver.get(base_url + "/wallet/PART")
    used_form_id = driver.execute_script(
        "return arguments[0].form.elements.namedItem('formid').value;",
        driver.find_element(By.NAME, f"withdraw_{part_id}"),
    )
    driver.find_element(By.NAME, f"to_{part_id}").send_keys(node2_deposit_address)
    driver.find_element(By.NAME, f"amt_{part_id}").send_keys("10")
    for name in (f"withdraw_type_from_{part_id}", f"withdraw_type_to_{part_id}"):
        click_option(driver.find_element(By.NAME, name), "Plain")
    driver.find_element(By.NAME, f"withdraw_{part_id}").click()
    WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.ID, "confirmYes"))
    ).click()
    WebDriverWait(driver, 30).until(
        lambda d: d.find_elements(By.CLASS_NAME, "infomsg")
        or d.find_elements(By.CLASS_NAME, "error_msg")
    )
    elements = driver.find_elements(By.CLASS_NAME, "infomsg")
    errors = [e.text for e in driver.find_elements(By.CLASS_NAME, "error_msg")]
    assert len(elements) == 1, errors
    e = elements[0]
    assert "Withdrew 10 rtPART (plain to plain) to address" in e.text

    print("Resubmitting the same withdrawal form")
    driver.execute_script(
        "arguments[0].form.elements.namedItem('formid').value = arguments[1];",
        driver.find_element(By.NAME, f"withdraw_{part_id}"),
        used_form_id,
    )
    for name, value in (
        (f"to_{part_id}", node2_deposit_address),
        (f"amt_{part_id}", "10"),
    ):
        el = driver.find_element(By.NAME, name)
        el.clear()
        el.send_keys(value)
    for name in (f"withdraw_type_from_{part_id}", f"withdraw_type_to_{part_id}"):
        click_option(driver.find_element(By.NAME, name), "Plain")
    result_page = driver.find_element(By.TAG_NAME, "html")
    driver.find_element(By.NAME, f"withdraw_{part_id}").click()
    WebDriverWait(driver, 10).until(
        EC.element_to_be_clickable((By.ID, "confirmYes"))
    ).click()
    WebDriverWait(driver, 30).until(EC.staleness_of(result_page))
    WebDriverWait(driver, 30).until(
        lambda d: d.find_elements(By.CLASS_NAME, "infomsg")
        or d.find_elements(By.CLASS_NAME, "error_msg")
    )
    infos = [e.text for e in driver.find_elements(By.CLASS_NAME, "infomsg")]
    errors = [e.text for e in driver.find_elements(By.CLASS_NAME, "error_msg")]
    assert not any("Withdrew" in m for m in infos), infos
    assert any("Prevented double submit" in m for m in errors), errors

    print("Locking UTXO")
    driver.get(base_url + "/rpc")
    el = driver.find_element(By.NAME, "coin_type")
    for option in el.find_elements(By.TAG_NAME, "option"):
        if option.text == "Particl":
            option.click()
            break
    driver.find_element(By.NAME, "cmd").send_keys("listunspent")
    driver.find_element(By.NAME, "apply").click()
    time.sleep(1)

    text_value = driver.find_element(By.NAME, "result").text
    utxos = json.loads(text_value.split("\n", 1)[1])

    lock_utxos = [{"txid": utxos[0]["txid"], "vout": utxos[0]["vout"]}]
    driver.find_element(By.NAME, "cmd").send_keys(
        'lockunspent false "{}"'.format(dumpje(lock_utxos))
    )
    driver.find_element(By.NAME, "apply").click()

    print("Check for locked UTXO count")
    driver.get(base_url + "/wallet/PART")
    found = False
    for i in range(20):
        if driver.find_elements(By.ID, "locked_utxos"):
            found = True
            break
        time.sleep(2)
        driver.refresh()
    assert found
    driver.refresh()

    print("Unlocking UTXO")
    driver.get(base_url + "/rpc")
    el = driver.find_element(By.NAME, "coin_type")
    for option in el.find_elements(By.TAG_NAME, "option"):
        if option.text == "Particl":
            option.click()
            break
    driver.find_element(By.NAME, "cmd").send_keys(
        'lockunspent true "{}"'.format(dumpje(lock_utxos))
    )
    driver.find_element(By.NAME, "apply").click()

    print("Test Passed!")


def run_tests():
    driver = get_driver()
    try:
        test_wallets(driver)
    finally:
        driver.close()


if __name__ == "__main__":
    run_tests()
