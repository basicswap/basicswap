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
    def __init__(self, p2p_port, network_key):
        self._p2p_port = p2p_port
        self._network_key = network_key
        self._peers = []
