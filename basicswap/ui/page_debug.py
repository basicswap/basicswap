# -*- coding: utf-8 -*-

# Copyright (c) 2023-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
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
                swap_client.log.error(
                    traceback.format_exc() if swap_client.debug else f"reinit_xmr: {e}"
                )
                err_messages.append(f"Failed: {e}.")

        if have_data_entry(form_data, "remove_expired"):
            try:
                swap_client.log.warning("Removing expired data.")
                remove_expired_data(swap_client)
                messages.append("Done.")
            except Exception as e:
                swap_client.log.error(
                    traceback.format_exc()
                    if swap_client.debug
                    else f"remove_expired_data: {e}"
                )
                err_messages.append("Failed.")

        if have_data_entry(form_data, "list_non_segwit_prevouts"):
            try:
                rvj = {}
                rvj["BTC"] = swap_client.ci(Coins.BTC).getNonSegwitOutputs()
                rvj["LTC"] = swap_client.ci(Coins.LTC).getNonSegwitOutputs()

                # json.dumps indent=4 ends up in one line in html side
                message_output = "BTC:<br/>"
                for utxo in rvj["BTC"]:
                    message_output += json.dumps(utxo) + "<br/>"
                message_output += "LTC:<br/>"
                for utxo in rvj["LTC"]:
                    message_output += json.dumps(utxo) + "<br/>"
                messages.append(message_output)
            except Exception as e:
                swap_client.log.error(
                    traceback.format_exc()
                    if swap_client.debug
                    else f"list_non_segwit_prevouts: {e}"
                )
                err_messages.append(f"Failed: {e}.")
        if have_data_entry(form_data, "combine_non_segwit_prevouts_btc"):
            try:
                ci = swap_client.ci(Coins.BTC)
                txid = ci.combine_non_segwit_prevouts()
                messages.append(f"Combined non-segwit BTC UTXOs, txid: {txid}.")
            except Exception as e:
                swap_client.log.error(
                    traceback.format_exc()
                    if swap_client.debug
                    else f"combine_non_segwit_prevouts_btc: {e}"
                )
                err_messages.append(f"Failed: {e}.")
        if have_data_entry(form_data, "combine_non_segwit_prevouts_ltc"):
            try:
                ci = swap_client.ci(Coins.LTC)
                txid = ci.combine_non_segwit_prevouts()
                messages.append(f"Combined non-segwit LTC UTXOs, txid: {txid}.")
            except Exception as e:
                swap_client.log.error(
                    traceback.format_exc()
                    if swap_client.debug
                    else f"combine_non_segwit_prevouts_ltc: {e}"
                )
                err_messages.append(f"Failed: {e}.")

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
