# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import os
import urllib
from urllib.request import urlopen

PORT_OFS = int(os.getenv("PORT_OFS", 1))
UI_PORT = 12700 + PORT_OFS

REQUIRED_SETTINGS = {
    "blocks_confirmed": 1,
    "conf_target": 1,
    "use_segwit": True,
    "connection_type": "rpc",
}


def make_boolean(s) -> bool:
    if isinstance(s, bool):
        return s
    if isinstance(s, int):
        return False if s == 0 else True
    return s.lower() in ["1", "true"]


def post_json_req(url, json_data):
    req = urllib.request.Request(url)
    req.add_header("Content-Type", "application/json; charset=utf-8")
    post_bytes = json.dumps(json_data).encode("utf-8")
    req.add_header("Content-Length", len(post_bytes))
    return urlopen(req, post_bytes, timeout=300).read()


def read_text_api(port, path=None):
    url = f"http://127.0.0.1:{port}/json"
    if path is not None:
        url += "/" + path
    return urlopen(url, timeout=300).read().decode("utf-8")


def read_json_api(port, path=None, json_data=None):
    url = f"http://127.0.0.1:{port}/json"
    if path is not None:
        url += "/" + path

    if json_data is not None:
        return json.loads(post_json_req(url, json_data))
    return json.loads(urlopen(url, timeout=300).read())


def post_json_api(port, path, json_data):
    url = f"http://127.0.0.1:{port}/json"
    if path is not None:
        url += "/" + path
    return json.loads(post_json_req(url, json_data))


def waitForServer(delay_event, port, wait_for=40):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        try:
            delay_event.wait(1.0)
            _ = read_json_api(port)
            return
        except Exception as e:
            logging.error(f"waitForServer: {e}")
    raise ValueError("waitForServer failed")


def wait_for_offers(delay_event, node_id, num_offers, offer_id=None) -> None:
    logging.info(f"Waiting for {num_offers} offers on node {node_id}")
    for i in range(20):
        delay_event.wait(1)
        offers = read_json_api(
            UI_PORT + node_id, "offers" if offer_id is None else f"offers/{offer_id}"
        )
        if len(offers) >= num_offers:
            return
    raise ValueError("wait_for_offers failed")
