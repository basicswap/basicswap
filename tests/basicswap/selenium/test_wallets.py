#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
cd /tmp
wget -4 https://chromedriver.storage.googleapis.com/96.0.4664.45/chromedriver_linux64.zip
7z x chromedriver_linux64.zip
sudo mv chromedriver /opt/chromedriver96


python tests/basicswap/extended/test_xmr_persistent.py

python tests/basicswap/selenium/test_wallets.py

html = driver.page_source
print('html', html)

"""

import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service


def test_html():
    base_url = 'http://localhost:12701'

    driver = webdriver.Chrome(service=Service('/opt/chromedriver96'))
    url = base_url + '/wallets'
    driver.get(url)

    time.sleep(1)
    driver.refresh()

    driver.find_element(By.ID, "refresh").click()
    time.sleep(1)
    driver.refresh()

    driver.close()


if __name__ == '__main__':
    test_html()
