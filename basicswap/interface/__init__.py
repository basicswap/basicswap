#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from enum import IntEnum


class Curves(IntEnum):
    secp256k1 = 1
    ed25519 = 2
