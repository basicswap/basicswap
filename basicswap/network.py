#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

'''
TODO:
'''

import select
import socket
import logging


class Peer:
    pass


class Network:
    def __init__(self, p2p_host, p2p_port, network_key):
        self._p2p_host = p2p_host
        self._p2p_port = p2p_port
        self._network_key = network_key
        self._peers = []

        self._max_connections = 10
        self._running = True

    def listen(self):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind((self._p2p_host, self._p2p_port))
        self._socket.listen(self._max_connections)

        while self._running:
            readable, writable, errored = select.select([self._socket], [], [])
            for s in readable:
                client_socket, address = self._socket.accept()
                    read_list.append(client_socket)
                    logging.info('Connection from %s', address)
