# -*- coding: utf-8 -*-

# Copyright (c) 2023 The BSX Developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import traceback
from .util import (
    have_data_entry,
)
from basicswap.chainparams import (
    Coins,
)
from basicswap.db_util import (
    remove_expired_data,
)


def page_debug(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    result = None
    messages = []
    err_messages = []
    form_data = self.checkForm(post_string, "wallets", err_messages)
    if form_data:
        if have_data_entry(form_data, "reinit_xmr"):
            try:
                swap_client.initialiseWallet(Coins.XMR)
                messages.append("Done.")
            except Exception as e:
                err_messages.append("Failed.")

        if have_data_entry(form_data, "remove_expired"):
            try:
                swap_client.log.warning("Removing expired data.")
                remove_expired_data(swap_client)
                messages.append("Done.")
            except Exception as e:
                if swap_client.debug is True:
                    swap_client.log.error(traceback.format_exc())
                else:
                    swap_client.log.error(f"remove_expired_data: {e}")
                err_messages.append("Failed.")

    template = server.env.get_template("debug.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
            "result": result,
            "summary": summary,
        },
    )
