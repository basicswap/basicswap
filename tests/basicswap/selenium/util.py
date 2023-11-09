#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from selenium.webdriver import Firefox


def get_driver():
    # driver = Chrome()  # 2023-11: Hangs here
    driver = Firefox()
    return driver
