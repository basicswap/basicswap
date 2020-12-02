#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

'''
TODO:
'''


class Peer:
    pass


class Network:
    def __init__(self, network_port, network_key):
        self._network_port = network_port
        self._network_key = network_key
        self._peers = []
