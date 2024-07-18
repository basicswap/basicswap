# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .util import (
    get_data_entry_or,
)


def page_changepassword(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()

    messages = []
    err_messages = []

    form_data = self.checkForm(post_string, "changepassword", err_messages)
    if form_data:
        old_password = get_data_entry_or(form_data, "oldpassword", "")
        new_password = get_data_entry_or(form_data, "newpassword", "")
        confirm_password = get_data_entry_or(form_data, "confirmpassword", "")

        try:
            if new_password == "":
                raise ValueError("New password must be entered.")
            if new_password != confirm_password:
                raise ValueError("New password and confirm password must match.")
            swap_client.changeWalletPasswords(old_password, new_password)
            messages.append("Password changed")
        except Exception as e:
            err_messages.append(str(e))

    template = server.env.get_template("changepassword.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
            "summary": swap_client.getSummary(),
        },
    )


def page_unlock(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client

    messages = [
        "Warning: This will unlock the system for all users!",
    ]
    err_messages = []

    form_data = self.checkForm(post_string, "unlock", err_messages)
    if form_data:
        password = get_data_entry_or(form_data, "password", "")

        try:
            if password == "":
                raise ValueError("Password must be entered.")
            swap_client.unlockWallets(password)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return bytes()
        except Exception as e:
            if swap_client.debug is True:
                swap_client.log.error(str(e))
            err_messages.append(str(e))

    template = server.env.get_template("unlock.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
        },
    )


def page_lock(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()

    swap_client.lockWallets()
    self.send_response(302)
    self.send_header("Location", "/")
    self.end_headers()
    return bytes()
