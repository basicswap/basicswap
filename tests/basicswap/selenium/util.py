#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
from selenium.webdriver.common.by import By


BSX_0_PORT = int(os.getenv("BSX_0_PORT", 12701))
BSX_1_PORT = int(os.getenv("BSX_1_PORT", BSX_0_PORT + 1))
BSX_2_PORT = int(os.getenv("BSX_1_PORT", BSX_0_PORT + 2))

BSX_SELENIUM_DRIVER = os.getenv("BSX_SELENIUM_DRIVER", "firefox")


def get_driver():
    if BSX_SELENIUM_DRIVER == "firefox":
        from selenium.webdriver import Firefox, FirefoxOptions
        options = FirefoxOptions()
        driver = Firefox(options=options)
    elif BSX_SELENIUM_DRIVER == "firefox-ci":
        from selenium.webdriver import Firefox, FirefoxOptions
        options = FirefoxOptions()
        options.headless = True
        options.add_argument("start-maximized")
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        driver = Firefox(options=options)
    elif BSX_SELENIUM_DRIVER == "chrome":
        from selenium.webdriver import Chrome, ChromeOptions
        driver = Chrome(options=ChromeOptions())
    elif BSX_SELENIUM_DRIVER == "safari":
        from selenium.webdriver import Safari, SafariOptions
        driver = Safari(options=SafariOptions())
    else:
        raise ValueError("Unknown driver " + BSX_SELENIUM_DRIVER)
    return driver


def click_option(el, option_text):
    for option in el.find_elements(By.TAG_NAME, "option"):
        if option.text == option_text:
            option.click()
            break
