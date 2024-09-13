# -*- coding: utf-8 -*-
# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


def extract_data(bytes_in):
    if bytes_in is None:
        return None
    str_in = bytes_in.decode('utf-8')
    start = str_in.find('=')
    if start < 0:
        return None
    start += 1
    end = str_in.find('\r', start)
    if end < 0:
        return None
    return str_in[start: end]


def get_tor_established_state(swap_client):
    rv = swap_client.torControl('GETINFO status/circuit-established')
    return extract_data(rv)


def page_tor(self, url_split, post_string):
    swap_client = self.server.swap_client
    summary = swap_client.getSummary()
    page_data = {}
    try:
        page_data['circuit_established'] = get_tor_established_state(swap_client)
    except Exception:
        page_data['circuit_established'] = 'error'
    try:
        rv = swap_client.torControl('GETINFO traffic/read')
        page_data['bytes_written'] = extract_data(rv)
    except Exception:
        page_data['bytes_written'] = 'error'
    try:
        rv = swap_client.torControl('GETINFO traffic/written')
        page_data['bytes_read'] = extract_data(rv)
    except Exception:
        page_data['bytes_read'] = 'error'
    messages = []
    template = self.server.env.get_template('tor.html')
    return self.render_template(template, {
        'messages': messages,
        'data': page_data,
        'summary': summary,
    })
