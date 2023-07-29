#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
cd /tmp
wget -4 https://chromedriver.storage.googleapis.com/114.0.5735.90/chromedriver_linux64.zip
7z x chromedriver_linux64.zip
sudo mv chromedriver /opt/chromedriver114

python tests/basicswap/extended/test_xmr_persistent.py
python tests/basicswap/selenium/test_offer.py

"""

import json
import time

from urllib.request import urlopen
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def test_html():
    node1_url = 'http://localhost:12701'
    node2_url = 'http://localhost:12702'

    driver = webdriver.Chrome(service=Service('/opt/chromedriver114'))

    driver.get(node1_url + '/newoffer')
    time.sleep(1)

    select = Select(driver.find_element(By.ID, 'coin_from'))
    select.select_by_visible_text('Bitcoin')
    select = Select(driver.find_element(By.ID, 'coin_to'))
    select.select_by_visible_text('Monero')

    driver.find_element(By.NAME, 'amt_from').send_keys('1')
    driver.find_element(By.NAME, 'amt_to').send_keys('2')

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

    driver.close()

    print('Done.')


if __name__ == '__main__':
    test_html()
