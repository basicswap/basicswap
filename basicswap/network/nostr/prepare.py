# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.prepare_util import PrepareContext
from basicswap.network.nostr.client import MAX_POW_TARGET_BITS
from basicswap.network.nostr.nostr import DEFAULT_NOSTR_RELAYS, newNostrRouteKey

# Unset leaves the value of an existing network entry unchanged
NOSTR_RELAYS = os.getenv("NOSTR_RELAYS", "")
NOSTR_POW_TARGET = os.getenv("NOSTR_POW_TARGET", "")


class NostrPrepare:
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {"type": "nostr", "enabled": True}
        if NOSTR_RELAYS:
            config["relays"] = [r.strip() for r in NOSTR_RELAYS.split(",") if r.strip()]
        if NOSTR_POW_TARGET:
            config["pow_target"] = max(
                0, min(int(NOSTR_POW_TARGET), MAX_POW_TARGET_BITS)
            )
        return config

    def getConfigDefaults(self) -> dict:
        return {
            "relays": list(DEFAULT_NOSTR_RELAYS),
            "pow_target": 0,
            "private_key": newNostrRouteKey()[0],
        }


prepare_module = NostrPrepare()
