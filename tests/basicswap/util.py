#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import json
import urllib
from urllib.request import urlopen


def make_boolean(s):
    return s.lower() in ['1', 'true']


def post_json_req(url, json_data):
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    post_bytes = json.dumps(json_data).encode('utf-8')
    req.add_header('Content-Length', len(post_bytes))
    return urlopen(req, post_bytes, timeout=300).read()


def read_text_api(port, path=None):
    url = f'http://127.0.0.1:{port}/json'
    if path is not None:
        url += '/' + path
    return urlopen(url, timeout=300).read().decode('utf-8')


def read_json_api(port, path=None, json_data=None):
    url = f'http://127.0.0.1:{port}/json'
    if path is not None:
        url += '/' + path

    if json_data is not None:
        return json.loads(post_json_req(url, json_data))
    return json.loads(urlopen(url, timeout=300).read())


def post_json_api(port, path, json_data):
    url = f'http://127.0.0.1:{port}/json'
    if path is not None:
        url += '/' + path
    return json.loads(post_json_req(url, json_data))


def waitForServer(delay_event, port, wait_for=20):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError('Test stopped.')
        try:
            delay_event.wait(1)
            summary = read_json_api(port)
            return
        except Exception as e:
            print('waitForServer, error:', str(e))
    raise ValueError('waitForServer failed')
