# -*- coding: utf-8 -*-
# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .util import get_data_entry, get_data_entry_or, have_data_entry


def onion_uri(settings, client_key=None) -> str:
    query = []
    if "wshost" in settings:
        query.append(f"ws={settings['wsport']}")
    if client_key:
        query.append(f"auth={client_key}")
    return f"basicswap://{settings['onion_host']}:{settings['htmlport']}" + (
        "?" + "&".join(query) if query else ""
    )


def extract_data(bytes_in):
    if bytes_in is None:
        return None
    str_in = bytes_in.decode("utf-8")
    start = str_in.find("=")
    if start < 0:
        return None
    start += 1
    end = str_in.find("\r", start)
    if end < 0:
        return None
    return str_in[start:end]


def get_tor_established_state(swap_client):
    rv = swap_client.torControl("GETINFO status/circuit-established")
    return extract_data(rv)


def page_tor(self, url_split, post_string):
    swap_client = self.server.swap_client
    err_messages = []
    form_data = self.checkForm(post_string, "tor", err_messages)
    new_client = None
    if form_data:
        name = get_data_entry_or(form_data, "client_name", "")
        try:
            if have_data_entry(form_data, "add_onion"):
                new_client = (name, swap_client.addOnion(name))
            elif have_data_entry(form_data, "remove_onion"):
                swap_client.removeOnion()
            elif have_data_entry(form_data, "add_onion_client"):
                new_client = (name, swap_client.addOnionClient(name))
            elif have_data_entry(form_data, "remove_onion_client"):
                swap_client.removeOnionClient(
                    get_data_entry(form_data, "remove_onion_client")
                )
            elif have_data_entry(form_data, "set_onion_require_auth"):
                # An unticked checkbox sends nothing.
                swap_client.setOnionRequiresAuth(
                    have_data_entry(form_data, "onion_require_auth")
                )
        except Exception as e:
            err_messages.append(str(e))
    summary = swap_client.getSummary()
    settings = swap_client.settings
    page_data = {
        "has_password": bool(settings.get("client_auth_hash")),
        "require_auth": swap_client.onionRequiresAuth(),
        "clients": settings.get("onion_clients", []),
    }
    host = settings.get("onion_host")
    if host:
        page_data["onion_url"] = f"http://{host}:{settings['htmlport']}"
        page_data["onion_uri"] = onion_uri(settings)
        if new_client and new_client[1]:
            # The private key is shown on this page only, and never stored.
            name, key = new_client
            page_data["new_client"] = {
                "name": name.strip(),
                "key": key,
                "uri": onion_uri(settings, key),
                "auth_private": f"{host.removesuffix('.onion')}:descriptor:x25519:{key}",
            }
    try:
        page_data["circuit_established"] = get_tor_established_state(swap_client)
    except Exception:
        page_data["circuit_established"] = "error"
    try:
        rv = swap_client.torControl("GETINFO traffic/read")
        page_data["bytes_written"] = extract_data(rv)
    except Exception:
        page_data["bytes_written"] = "error"
    try:
        rv = swap_client.torControl("GETINFO traffic/written")
        page_data["bytes_read"] = extract_data(rv)
    except Exception:
        page_data["bytes_read"] = "error"
    messages = []
    template = self.server.env.get_template("tor.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
            "data": page_data,
            "summary": summary,
        },
    )
