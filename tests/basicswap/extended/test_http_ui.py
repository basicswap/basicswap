#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://chromedriver.chromium.org/downloads
# 7z x chromedriver_linux64.zip
# sudo mv chromedriver /opt/chromedriver88

# Run test_xmr_persistent.py
# python tests/basicswap/extended/test_http_ui.py

import time
import logging
from urllib.parse import urljoin

from selenium import webdriver
from selenium.webdriver.support.ui import Select, WebDriverWait

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def run_test():
    base_url = "http://localhost:12701"
    driver = webdriver.Chrome("/opt/chromedriver88")

    driver.get(base_url)
    link = driver.find_element_by_xpath('//a[@href="/offers"]')
    num_offers_start = int(link.text.split(":")[1].strip())
    logging.info("Offers: %d", num_offers_start)

    logging.info("Creating offer")
    driver.get(urljoin(base_url, "newoffer"))
    select_coin_from = Select(driver.find_element_by_name("coin_from"))
    select_coin_from.select_by_visible_text("Particl")

    select_coin_to = Select(driver.find_element_by_name("coin_to"))
    select_coin_to.select_by_visible_text("Monero")

    from_value = driver.find_element_by_name("amt_from")
    from_value.send_keys("1")
    to_value = driver.find_element_by_name("amt_to")
    to_value.send_keys("2")

    submit_button = driver.find_element_by_name("continue")
    submit_button.click()
    time.sleep(0.1)

    submit_button = driver.find_element_by_name("check_offer")
    submit_button.click()
    time.sleep(0.1)

    submit_button = driver.find_element_by_name("submit_offer")
    submit_button.click()
    time.sleep(0.1)

    link = WebDriverWait(driver, 5).until(
        lambda d: d.find_element_by_xpath("//a[contains(@href, '/offer')]")
    )
    offer_id = link.text.rsplit(" ", 1)[1]
    logging.info("Offer ID: %s", offer_id)

    driver.get(base_url)
    link = driver.find_element_by_xpath('//a[@href="/offers"]')
    num_offers_end = int(link.text.split(":")[1].strip())
    assert num_offers_end == num_offers_start + 1

    driver.quit()


if __name__ == "__main__":
    run_test()
