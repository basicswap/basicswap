#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://chromedriver.chromium.org/downloads
# 7z x chromedriver_linux64.zip
# sudo mv chromedriver /opt/chromedriver88

# Run test_xmr_persistent.py

import time
from urllib.parse import urljoin

from selenium import webdriver
from selenium.webdriver.support.ui import Select


def run_test():
    base_url = 'http://localhost:12701'
    driver = webdriver.Chrome('/opt/chromedriver88')

    driver.get(urljoin(base_url, 'newoffer'))
    html = driver.page_source
    print('html', html)

    select_coin_from = Select(driver.find_element_by_name('coin_from'))
    select_coin_from.select_by_visible_text('Particl')

    select_coin_to = Select(driver.find_element_by_name('coin_to'))
    select_coin_to.select_by_visible_text('Monero')

    from_value = driver.find_element_by_name('amt_from')
    from_value.send_keys('1')
    to_value = driver.find_element_by_name('amt_to')
    to_value.send_keys('2')

    submit_button = driver.find_element_by_name('continue')
    submit_button.click()

    submit_button = driver.find_element_by_name('check_offer')
    submit_button.click()

    submit_button = driver.find_element_by_name('submit_offer')
    submit_button.click()

    driver.get(urljoin(base_url))
    time.sleep(3)

    driver.quit()


if __name__ == '__main__':
    run_test()
