#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

from selenium.webdriver.common.by import By
from urllib.request import urlopen

from basicswap.util import dumpje
from util import get_driver


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
    assert "Error" in h2.text
    p1 = driver.find_element(By.TAG_NAME, "p")
    assert "Wallet not specified" in p1.text

    url = base_url + "/wallet/NOCOIN"
    driver.get(url)
    h2 = driver.find_element(By.TAG_NAME, "h2")
    assert "Error" in h2.text
    p1 = driver.find_element(By.TAG_NAME, "p")
    assert "Unknown coin" in p1.text

    driver.get(base_url + "/wallets")
    time.sleep(1)
    driver.refresh()
    driver.find_element(By.ID, "refresh").click()
    time.sleep(1)
    driver.refresh()

    print("Finding deposit address of node 2")
    driver.get(node2_url + "/wallet/PART")
    e = driver.find_element(By.ID, "deposit_address")
    node2_deposit_address = e.text

    print("Withdrawing from node 1")
    driver.get(base_url + "/wallet/PART")
    driver.find_element(By.NAME, f"to_{part_id}").send_keys(node2_deposit_address)
    driver.find_element(By.NAME, f"amt_{part_id}").send_keys("10")
    driver.find_element(By.NAME, f"withdraw_{part_id}").click()
    driver.switch_to.alert.accept()
    time.sleep(1)
    elements = driver.find_elements(By.CLASS_NAME, "infomsg")
    assert len(elements) == 1
    e = elements[0]
    assert "Withdrew 10 rtPART (plain to plain) to address" in e.text

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
    for i in range(5):
        try:
            el = driver.find_element(By.ID, "locked_utxos")
            found = True
            break
        except Exception:
            continue
        driver.find_element(By.ID, "refresh").click()
        time.sleep(2)
        found = True
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
