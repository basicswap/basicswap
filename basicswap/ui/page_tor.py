# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os


def extract_data(bytes_in):
    str_in = bytes_in.decode('utf-8')
    start = str_in.find('=')
    if start < 0:
        return None
    start += 1
    end = str_in.find('\r', start)
    if end < 0:
        return None
    return str_in[start: end]


def page_tor(self, url_split, post_string):
    template = self.server.env.get_template('tor.html')

    swap_client = self.server.swap_client

    page_data = {}

    rv = swap_client.torControl('GETINFO status/circuit-established')
    page_data['circuit_established'] = extract_data(rv)

    rv = swap_client.torControl('GETINFO traffic/read')
    page_data['bytes_written'] = extract_data(rv)

    rv = swap_client.torControl('GETINFO traffic/written')
    page_data['bytes_read'] = extract_data(rv)

    messages = []

    return bytes(template.render(
        title=self.server.title,
        h2=self.server.title,
        messages=messages,
        data=page_data,
        form_id=os.urandom(8).hex(),
    ), 'UTF-8')
