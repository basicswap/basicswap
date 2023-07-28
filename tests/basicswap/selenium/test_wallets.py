#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
cd /tmp
wget -4 https://chromedriver.storage.googleapis.com/114.0.5735.90/chromedriver_linux64.zip
7z x chromedriver_linux64.zip
sudo mv chromedriver /opt/chromedriver114

python tests/basicswap/extended/test_xmr_persistent.py
python tests/basicswap/selenium/test_wallets.py

"""

import json
import time

from urllib.request import urlopen
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service


def test_html():
    base_url = 'http://localhost:12701'
    node2_url = 'http://localhost:12702'

    driver = webdriver.Chrome(service=Service('/opt/chromedriver114'))

    # Check json coins data
    coins = json.loads(urlopen(base_url + '/json/coins').read())
    part_coin = [f for f in coins if f['ticker'] == 'PART'][0]
    part_id = part_coin['id']
    assert (part_id == 1)

    # Check 404 pages
    url = base_url + '/unknown'
    driver.get(url)
    p1 = driver.find_element(By.TAG_NAME, 'p')
    assert ('404' in p1.text)

    url = base_url + '/static/nothing.png'
    driver.get(url)
    p1 = driver.find_element(By.TAG_NAME, 'p')
    assert ('404' in p1.text)

    url = base_url + '/wallet'
    driver.get(url)
    h2 = driver.find_element(By.TAG_NAME, 'h2')
    assert ('Error' in h2.text)
    p1 = driver.find_element(By.TAG_NAME, 'p')
    assert ('Wallet not specified' in p1.text)

    url = base_url + '/wallet/NOCOIN'
    driver.get(url)
    h2 = driver.find_element(By.TAG_NAME, 'h2')
    assert ('Error' in h2.text)
    p1 = driver.find_element(By.TAG_NAME, 'p')
    assert ('Unknown coin' in p1.text)

    driver.get(base_url + '/wallets')
    time.sleep(1)
    driver.refresh()
    driver.find_element(By.ID, 'refresh').click()
    time.sleep(1)
    driver.refresh()

    print('Finding deposit address of node 2')
    driver.get(node2_url + '/wallet/PART')
    e = driver.find_element(By.ID, 'deposit_address')
    node2_deposit_address = e.text

    print('Withdrawing from node 1')
    driver.get(base_url + '/wallet/PART')
    driver.find_element(By.NAME, f'to_{part_id}').send_keys(node2_deposit_address)
    driver.find_element(By.NAME, f'amt_{part_id}').send_keys('10')
    driver.find_element(By.NAME, f'withdraw_{part_id}').click()
    driver.switch_to.alert.accept()
    time.sleep(1)
    elements = driver.find_elements(By.CLASS_NAME, "infomsg")
    assert (len(elements) == 1)
    e = elements[0]
    assert ('Withdrew 10 rtPART (plain to plain) to address' in e.text)

    driver.close()

    print('Done.')


if __name__ == '__main__':
    test_html()
