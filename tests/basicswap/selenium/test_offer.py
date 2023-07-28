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

import time

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
    driver.find_element(By.NAME, 'amt_to').send_keys('1')

    driver.find_element(By.NAME, 'continue').click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'check_offer'))).click()
    WebDriverWait(driver, 20).until(EC.element_to_be_clickable((By.NAME, 'submit_offer'))).click()

    driver.close()

    print('Done.')


if __name__ == '__main__':
    test_html()
