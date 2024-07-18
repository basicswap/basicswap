# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import ipaddress


def is_private_ip_address(addr: str):
    # Will return false for all URLs
    if addr == "localhost":
        return True
    try:
        return ipaddress.ip_address(addr).is_private
    except Exception:
        return False
