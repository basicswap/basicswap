# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .util import listAvailableCoinsWithBalances
from basicswap.multibid import (
    ANCHOR_MARKET,
    DEFAULT_MAX_BIDS,
    DEFAULT_SLIP_PERCENT,
)


def page_smartbuy(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    coins_from, coins_to = listAvailableCoinsWithBalances(swap_client, split_from=True)

    batch_caps = {}
    for coin_id, _, _ in coins_to:
        try:
            cap = swap_client.ci(coin_id).max_batched_lock_outputs()
        except Exception:
            cap = None
        if cap is not None:
            batch_caps[coin_id] = cap

    template = server.env.get_template("smartbuy.html")
    return self.render_template(
        template,
        {
            "coins_from": coins_from,
            "coins": coins_to,
            "summary": summary,
            "default_anchor": ANCHOR_MARKET,
            "default_slip_percent": DEFAULT_SLIP_PERCENT,
            "default_max_bids": DEFAULT_MAX_BIDS,
            "batch_caps": batch_caps,
        },
    )
