# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.basicswap_util import (
    AutomationOverrideOptions,
    strAutomationOverrideOption,
)
from basicswap.util import (
    ensure,
    zeroIfNone,
)
from .util import (
    get_data_entry,
    get_data_entry_or,
    have_data_entry,
)


def page_identity(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    ensure(len(url_split) > 2, "Address not specified")
    identity_address = url_split[2]

    page_data = {"identity_address": identity_address}
    messages = []
    err_messages = []
    form_data = self.checkForm(post_string, "identity", err_messages)
    if form_data:
        if have_data_entry(form_data, "edit"):
            page_data["show_edit_form"] = True
        if have_data_entry(form_data, "apply"):
            try:
                data = {
                    "label": get_data_entry_or(form_data, "label", ""),
                    "note": get_data_entry_or(form_data, "note", ""),
                    "automation_override": get_data_entry(
                        form_data, "automation_override"
                    ),
                }
                swap_client.setIdentityData({"address": identity_address}, data)
                messages.append("Updated")
            except Exception as e:
                err_messages.append(str(e))

    try:
        identity = swap_client.getIdentity(identity_address)
        if identity is None:
            raise ValueError("Unknown address")

        automation_override = zeroIfNone(identity.automation_override)
        page_data.update(
            {
                "label": "" if identity.label is None else identity.label,
                "num_sent_bids_successful": zeroIfNone(
                    identity.num_sent_bids_successful
                ),
                "num_recv_bids_successful": zeroIfNone(
                    identity.num_recv_bids_successful
                ),
                "num_sent_bids_rejected": zeroIfNone(identity.num_sent_bids_rejected),
                "num_recv_bids_rejected": zeroIfNone(identity.num_recv_bids_rejected),
                "num_sent_bids_failed": zeroIfNone(identity.num_sent_bids_failed),
                "num_recv_bids_failed": zeroIfNone(identity.num_recv_bids_failed),
                "automation_override": automation_override,
                "str_automation_override": strAutomationOverrideOption(
                    automation_override
                ),
                "note": "" if identity.note is None else identity.note,
            }
        )
    except Exception as e:
        err_messages.append(e)

    template = server.env.get_template("identity.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
            "data": page_data,
            "automation_override_options": [
                (int(opt), strAutomationOverrideOption(opt))
                for opt in AutomationOverrideOptions
                if opt > 0
            ],
            "summary": summary,
        },
    )
