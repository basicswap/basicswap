#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

from urllib.request import urlopen
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from util import get_driver


def test_offer(driver):
    node1_url = 'http://localhost:12701'
    node2_url = 'http://localhost:12702'

    driver.get(node1_url + '/newoffer')
    time.sleep(1)

    select = Select(driver.find_element(By.ID, 'coin_from'))
    select.select_by_visible_text('Bitcoin')
    select = Select(driver.find_element(By.ID, 'coin_to'))
    select.select_by_visible_text('Monero')

    amt_from = driver.find_element(By.NAME, 'amt_from')
    amt_to = driver.find_element(By.NAME, 'amt_to')
    rate = driver.find_element(By.ID, 'rate')
    amt_from.send_keys('1')
    amt_to.send_keys('2')
    amt_from.click()
    time.sleep(0.5)
    rate_value = rate.get_attribute('value')
    assert (float(rate_value) == 2.0)

    rate.clear()
    rate.send_keys('3')
    amt_from.click()
    time.sleep(0.5)
    amt_to_value = amt_to.get_attribute('value')
    assert (float(amt_to_value) == 3.0)

    amt_from.clear()
    amt_from.send_keys('2')
    amt_to.click()
    time.sleep(0.5)
    amt_to_value = amt_to.get_attribute('value')
    assert (float(amt_to_value) == 6.0)

    amt_from.clear()
    amt_to.clear()
    rate.clear()
    amt_to.send_keys('2')
    rate.send_keys('2')
    amt_to.click()
    time.sleep(0.2)
    amt_from_value = amt_from.get_attribute('value')
    assert (float(amt_from_value) == 1.0)

    driver.find_element(By.NAME, 'continue').click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'check_offer'))).click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'submit_offer'))).click()
    time.sleep(1)

    offer_link = driver.find_element(By.XPATH, "//a[contains(text(),'Sent Offer')]")
    offer1_id = offer_link.text.split(' ')[2]

    driver.get(node1_url + '/newoffer')
    time.sleep(1)

    select = Select(driver.find_element(By.ID, 'coin_from'))
    select.select_by_visible_text('Particl')
    select = Select(driver.find_element(By.ID, 'coin_to'))
    select.select_by_visible_text('Monero')

    driver.find_element(By.NAME, 'amt_from').send_keys('3')
    driver.find_element(By.NAME, 'amt_to').send_keys('4')

    driver.find_element(By.NAME, 'continue').click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'check_offer'))).click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'submit_offer'))).click()
    time.sleep(1)

    offer_link = driver.find_element(By.XPATH, "//a[contains(text(),'Sent Offer')]")
    offer2_id = offer_link.text.split(' ')[2]

    driver.get(node1_url + '/offer/' + offer1_id)
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'repeat_offer'))).click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'check_offer'))).click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'submit_offer'))).click()
    time.sleep(1)

    offer_link = driver.find_element(By.XPATH, "//a[contains(text(),'Sent Offer')]")
    offer3_id = offer_link.text.split(' ')[2]

    offer3_json = json.loads(urlopen(node1_url + '/json/offers/' + offer3_id).read())[0]
    assert (offer3_json['coin_from'] == 'Bitcoin')
    assert (offer3_json['coin_to'] == 'Monero')

    driver.get(node1_url + '/offer/' + offer2_id)
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'repeat_offer'))).click()
    time.sleep(1)  # Add time for setupCustomSelect to fire
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'check_offer'))).click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'submit_offer'))).click()
    time.sleep(1)

    offer_link = driver.find_element(By.XPATH, "//a[contains(text(),'Sent Offer')]")
    offer4_id = offer_link.text.split(' ')[2]

    offer4_json = json.loads(urlopen(node1_url + '/json/offers/' + offer4_id).read())[0]
    assert (offer4_json['coin_from'] == 'Particl')
    assert (offer4_json['coin_to'] == 'Monero')

    print('Test Passed!')


def run_tests():
    driver = get_driver()
    try:
        test_offer(driver)
    finally:
        driver.close()


if __name__ == '__main__':
    run_tests()
