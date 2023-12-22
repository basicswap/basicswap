#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support.select import Select
from selenium.webdriver.support import expected_conditions as EC

from util import get_driver
from basicswap.ui.page_offers import default_chart_api_key


def test_settings(driver):
    base_url = 'http://localhost:12701'
    node2_url = 'http://localhost:12702'

    url = base_url + '/settings'
    driver.get(url)
    driver.find_element(By.ID, 'general-tab').click()

    wait = WebDriverWait(driver, 10)
    btn_apply_general = wait.until(EC.element_to_be_clickable((By.NAME, 'apply_general')))

    el = driver.find_element(By.NAME, 'debugmode')
    selected_option = Select(el).first_selected_option
    assert (selected_option.text == 'True')
    for option in el.find_elements(By.TAG_NAME, 'option'):
        if option.text == 'False':
            option.click()
            break

    el = driver.find_element(By.NAME, 'debugui')
    selected_option = Select(el).first_selected_option
    assert (selected_option.text == 'False')
    for option in el.find_elements(By.TAG_NAME, 'option'):
        if option.text == 'True':
            option.click()
            break

    btn_apply_general.click()
    time.sleep(1)

    settings_path_0 = '/tmp/test_persistent/client0/basicswap.json'
    with open(settings_path_0) as fs:
        settings = json.load(fs)

    assert (settings['debug'] is False)
    assert (settings['debug_ui'] is True)

    el = driver.find_element(By.NAME, 'showchart')
    selected_option = Select(el).first_selected_option
    assert (selected_option.text == 'True')
    for option in el.find_elements(By.TAG_NAME, 'option'):
        if option.text == 'False':
            option.click()
            break

    difficult_text = '`~!@#$%^&*()-_=+[{}]\\|;:\'",<>./? '
    el = driver.find_element(By.NAME, 'chartapikey')
    el.clear()
    el.send_keys(difficult_text)

    btn_apply_chart = wait.until(EC.element_to_be_clickable((By.NAME, 'apply_chart')))
    btn_apply_chart.click()
    time.sleep(1)

    with open(settings_path_0) as fs:
        settings = json.load(fs)

    assert (settings['show_chart'] is False)
    chart_api_key = bytes.fromhex(settings.get('chart_api_key_enc', '')).decode('utf-8')
    assert (chart_api_key == difficult_text)

    hex_text = default_chart_api_key
    el = driver.find_element(By.NAME, 'chartapikey')
    el.clear()
    el.send_keys(hex_text)
    btn_apply_chart = wait.until(EC.element_to_be_clickable((By.NAME, 'apply_chart')))
    btn_apply_chart.click()
    time.sleep(1)

    el = driver.find_element(By.NAME, 'chartapikey')
    assert el.get_property('value') == hex_text

    with open(settings_path_0) as fs:
        settings = json.load(fs)

    assert (settings.get('chart_api_key') == hex_text)

    # Apply XMR settings with blank nodes list
    driver.find_element(By.ID, 'coins-tab').click()
    btn_apply_monero = wait.until(EC.element_to_be_clickable((By.NAME, 'apply_monero')))
    el = driver.find_element(By.NAME, 'remotedaemonurls_monero')
    el.clear()
    btn_apply_monero.click()
    time.sleep(1)

    with open(settings_path_0) as fs:
        settings = json.load(fs)
    assert ('remote_daemon_urls' not in settings['chainclients']['monero'])

    btn_apply_monero = wait.until(EC.element_to_be_clickable((By.NAME, 'apply_monero')))
    el = driver.find_element(By.NAME, 'remotedaemonurls_monero')
    el.clear()
    el.send_keys('node.xmr.to:18081\nnode1.xmr.to:18082')
    btn_apply_monero.click()
    time.sleep(1)

    with open(settings_path_0) as fs:
        settings = json.load(fs)
    remotedaemonurls = settings['chainclients']['monero']['remote_daemon_urls']
    assert (len(remotedaemonurls) == 2)

    btn_apply_monero = wait.until(EC.element_to_be_clickable((By.NAME, 'apply_monero')))
    el = driver.find_element(By.NAME, 'remotedaemonurls_monero')
    el.clear()
    btn_apply_monero.click()
    time.sleep(1)

    with open(settings_path_0) as fs:
        settings = json.load(fs)
    assert ('remote_daemon_urls' not in settings['chainclients']['monero'])

    print('Test Passed!')


def run_tests():
    driver = get_driver()
    try:
        test_settings(driver)
    finally:
        driver.close()


if __name__ == '__main__':
    run_tests()
