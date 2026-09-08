#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""Shared helpers for Nostr regtest integration tests."""

import logging
import os

from coincurve.keys import PrivateKey

from tests.basicswap.util.nostr_relay import MiniNostrRelay

NOSTR_TEST_RELAYS = os.getenv("NOSTR_TEST_RELAYS", "ws://127.0.0.1:8765")


def getNostrNetworkConfig(
    node_id: int,
    relay_url: str = None,
    private_key: str = None,
    bridged: list = None,
) -> dict:
    config = {
        "type": "nostr",
        "relays": [
            r.strip()
            for r in (relay_url or NOSTR_TEST_RELAYS).split(",")
            if r.strip()
        ],
        "private_key": private_key or PrivateKey().to_hex(),
        "enabled": True,
    }
    if bridged is not None:
        config["bridged"] = bridged
    return config


class NostrRelayFixture:
    """Start/stop an in-process mini relay for a test class."""

    relay = None
    relay_url = None

    @classmethod
    def startRelay(cls, host: str = "127.0.0.1", port: int = 0) -> str:
        if cls.relay is not None:
            return cls.relay_url
        cls.relay = MiniNostrRelay(host=host, port=port)
        cls.relay.start()
        cls.relay_url = cls.relay.url()
        os.environ["NOSTR_TEST_RELAYS"] = cls.relay_url
        logging.info(f"Started Nostr test relay at {cls.relay_url}")
        return cls.relay_url

    @classmethod
    def stopRelay(cls) -> None:
        if cls.relay is not None:
            cls.relay.stop()
            cls.relay = None
            cls.relay_url = None


def wait_for_portal(delay_event, swap_client, wait_for: int = 20) -> None:
    logging.info("wait_for_portal")
    for _ in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        delay_event.wait(1)
        if len(swap_client.known_portals) > 0:
            return
    raise ValueError("wait_for_portal timed out.")


def wait_for_nostr_route(
    delay_event, swap_client, addr_local: str, addr_remote: str, wait_for: int = 60
) -> None:
    """Wait until an active Nostr direct route exists between two addresses."""
    from basicswap.basicswap_util import MessageNetworks

    logging.info(
        f"wait_for_nostr_route {addr_local} -> {addr_remote} (max {wait_for}s)"
    )
    for _ in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        delay_event.wait(1)
        try:
            cursor = swap_client.openDB()
            route = swap_client.getMessageRoute(
                int(MessageNetworks.NOSTR),
                addr_local,
                addr_remote,
                cursor=cursor,
            )
        finally:
            swap_client.closeDB(cursor)
        if route is not None and route.active_ind == 1:
            return
    raise ValueError("wait_for_nostr_route timed out.")
