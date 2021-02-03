# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import urllib.parse

from .util import (
    format_timestamp,
)
from .basicswap import (
    strBidState,
    SwapTypes,
)
from .ui import (
    PAGE_LIMIT,
    inputAmount,
    describeBid,
    setCoinFilter,
    get_data_entry,
    have_data_entry,
)


def js_error(self, error_str):
    error_str_json = json.dumps({'error': error_str})
    return bytes(error_str_json, 'UTF-8')


def js_wallets(self, url_split, post_string, is_json):
    return bytes(json.dumps(self.server.swap_client.getWalletsInfo()), 'UTF-8')


def js_offers(self, url_split, post_string, is_json, sent=False):
    offer_id = None
    if len(url_split) > 3:
        if url_split[3] == 'new':
            if post_string == '':
                raise ValueError('No post data')
            if is_json:
                form_data = json.loads(post_string)
                form_data['is_json'] = True
            else:
                form_data = urllib.parse.parse_qs(post_string)
            offer_id = self.postNewOffer(form_data)
            rv = {'offer_id': offer_id.hex()}
            return bytes(json.dumps(rv), 'UTF-8')
        offer_id = bytes.fromhex(url_split[3])

    filters = {
        'coin_from': -1,
        'coin_to': -1,
        'page_no': 1,
        'limit': PAGE_LIMIT,
        'sort_by': 'created_at',
        'sort_dir': 'desc',
    }

    if offer_id:
        filters['offer_id'] = offer_id

    if post_string != '':
        if is_json:
            post_data = json.loads(post_string)
            post_data['is_json'] = True
        else:
            post_data = urllib.parse.parse_qs(post_string)
        filters['coin_from'] = setCoinFilter(post_data, 'coin_from')
        filters['coin_to'] = setCoinFilter(post_data, 'coin_to')

        if have_data_entry(post_data, 'sort_by'):
            sort_by = get_data_entry(post_data, 'sort_by')
            assert(sort_by in ['created_at', 'rate']), 'Invalid sort by'
            filters['sort_by'] = sort_by
        if have_data_entry(post_data, 'sort_dir'):
            sort_dir = get_data_entry(post_data, 'sort_dir')
            assert(sort_dir in ['asc', 'desc']), 'Invalid sort dir'
            filters['sort_dir'] = sort_dir

        if b'offset' in post_data:
            filters['offset'] = int(get_data_entry(post_data, 'offset'))
        if b'limit' in post_data:
            filters['limit'] = int(get_data_entry(post_data, 'limit'))
            assert(filters['limit'] > 0 and filters['limit'] <= PAGE_LIMIT), 'Invalid limit'

    offers = self.server.swap_client.listOffers(sent, filters)
    rv = []
    for o in offers:
        ci_from = self.server.swap_client.ci(o.coin_from)
        ci_to = self.server.swap_client.ci(o.coin_to)
        rv.append({
            'offer_id': o.offer_id.hex(),
            'created_at': format_timestamp(o.created_at),
            'coin_from': ci_from.coin_name(),
            'coin_to': ci_to.coin_name(),
            'amount_from': ci_from.format_amount(o.amount_from),
            'amount_to': ci_to.format_amount((o.amount_from * o.rate) // ci_from.COIN()),
            'rate': ci_to.format_amount(o.rate)
        })

    return bytes(json.dumps(rv), 'UTF-8')


def js_sentoffers(self, url_split, post_string, is_json):
    return self.js_offers(url_split, post_string, is_json, True)


def js_bids(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    if len(url_split) > 3:
        if url_split[3] == 'new':
            if post_string == '':
                raise ValueError('No post data')
            if is_json:
                post_data = json.loads(post_string)
                post_data['is_json'] = True
            else:
                post_data = urllib.parse.parse_qs(post_string)

            offer_id = bytes.fromhex(get_data_entry(post_data, 'offer_id'))
            assert(len(offer_id) == 28)

            offer = swap_client.getOffer(offer_id)
            assert(offer), 'Offer not found.'

            ci_from = swap_client.ci(offer.coin_from)
            amount_from = inputAmount(get_data_entry(post_data, 'amount_from'), ci_from)

            addr_from = None
            if have_data_entry(post_data, 'addr_from'):
                addr_from = get_data_entry(post_data, 'addr_from')
                if addr_from == '-1':
                    addr_from = None

            if offer.swap_type == SwapTypes.XMR_SWAP:
                bid_id = swap_client.postXmrBid(offer_id, amount_from, addr_send_from=addr_from)
            else:
                bid_id = swap_client.postBid(offer_id, amount_from, addr_send_from=addr_from)

            if have_data_entry(post_data, 'debugind'):
                swap_client.setBidDebugInd(bid_id, int(get_data_entry(post_data, 'debugind')))

            rv = {'bid_id': bid_id.hex()}
            return bytes(json.dumps(rv), 'UTF-8')

        bid_id = bytes.fromhex(url_split[3])
        assert(len(bid_id) == 28)

        if post_string != '':
            if is_json:
                post_data = json.loads(post_string)
                post_data['is_json'] = True
            else:
                post_data = urllib.parse.parse_qs(post_string)
            if have_data_entry(post_data, 'accept'):
                swap_client.acceptBid(bid_id)
            elif have_data_entry(post_data, 'debugind'):
                swap_client.setBidDebugInd(bid_id, int(get_data_entry(post_data, 'debugind')))

        bid, xmr_swap, offer, xmr_offer, events = swap_client.getXmrBidAndOffer(bid_id)
        assert(bid), 'Unknown bid ID'

        edit_bid = False
        show_txns = False
        data = describeBid(swap_client, bid, xmr_swap, offer, xmr_offer, events, edit_bid, show_txns)

        return bytes(json.dumps(data), 'UTF-8')

    bids = swap_client.listBids()
    return bytes(json.dumps([{
        'bid_id': b[1].hex(),
        'offer_id': b[2].hex(),
        'created_at': format_timestamp(b[0]),
        'coin_from': b[8],
        'amount_from': swap_client.ci(b[8]).format_amount(b[3]),
        'bid_state': strBidState(b[4])
    } for b in bids]), 'UTF-8')


def js_sentbids(self, url_split, post_string, is_json):
    return bytes(json.dumps(self.server.swap_client.listBids(sent=True)), 'UTF-8')


def js_network(self, url_split, post_string, is_json):
    return bytes(json.dumps(self.server.swap_client.get_network_info()), 'UTF-8')


def js_revokeoffer(self, url_split, post_string, is_json):
    offer_id = bytes.fromhex(url_split[3])
    assert(len(offer_id) == 28)
    self.server.swap_client.revokeOffer(offer_id)
    return bytes(json.dumps({'revoked_offer': offer_id.hex()}), 'UTF-8')


def js_index(self, url_split, post_string, is_json):
    return bytes(json.dumps(self.server.swap_client.getSummary()), 'UTF-8')
