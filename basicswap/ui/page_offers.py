# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from .util import (
    PAGE_LIMIT,
    setCoinFilter,
    get_data_entry,
    have_data_entry,
    listAvailableCoins,
    set_pagination_filters,
)
from basicswap.util import (
    ensure,
    format_timestamp,
)
from basicswap.chainparams import (
    Coins,
)


def page_offers(self, url_split, post_string, sent=False):
    server = self.server
    swap_client = server.swap_client

    filters = {
        'coin_from': -1,
        'coin_to': -1,
        'page_no': 1,
        'limit': PAGE_LIMIT,
        'sort_by': 'created_at',
        'sort_dir': 'desc',
        'sent_from': 'any' if sent is False else 'only',
    }
    messages = []
    form_data = self.checkForm(post_string, 'offers', messages)
    if form_data and have_data_entry(form_data, 'applyfilters'):
        filters['coin_from'] = setCoinFilter(form_data, 'coin_from')
        filters['coin_to'] = setCoinFilter(form_data, 'coin_to')

        if have_data_entry(form_data, 'sort_by'):
            sort_by = get_data_entry(form_data, 'sort_by')
            ensure(sort_by in ['created_at', 'rate'], 'Invalid sort by')
            filters['sort_by'] = sort_by
        if have_data_entry(form_data, 'sort_dir'):
            sort_dir = get_data_entry(form_data, 'sort_dir')
            ensure(sort_dir in ['asc', 'desc'], 'Invalid sort dir')
            filters['sort_dir'] = sort_dir
        if have_data_entry(form_data, 'sent_from'):
            sent_from = get_data_entry(form_data, 'sent_from')
            ensure(sent_from in ['any', 'only'], 'Invalid sent filter')
            filters['sent_from'] = sent_from

    set_pagination_filters(form_data, filters)

    if filters['sent_from'] == 'only':
        sent = True
    else:
        sent = False
    offers = swap_client.listOffers(sent, filters)

    formatted_offers = []
    for o in offers:
        ci_from = swap_client.ci(Coins(o.coin_from))
        ci_to = swap_client.ci(Coins(o.coin_to))
        formatted_offers.append((
            format_timestamp(o.created_at),
            o.offer_id.hex(),
            ci_from.coin_name(), ci_to.coin_name(),
            ci_from.format_amount(o.amount_from),
            ci_to.format_amount((o.amount_from * o.rate) // ci_from.COIN()),
            ci_to.format_amount(o.rate),
            'Public' if o.addr_to == swap_client.network_addr else o.addr_to,
            o.addr_from,
            o.was_sent))

    template = server.env.get_template('offers.html')
    return bytes(template.render(
        title=server.title,
        h2=server.title,
        coins=listAvailableCoins(swap_client),
        messages=messages,
        filters=filters,
        offers=formatted_offers,
        form_id=os.urandom(8).hex(),
    ), 'UTF-8')
