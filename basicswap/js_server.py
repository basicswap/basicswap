# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import urllib.parse

from .util import (
    toBool,
)
from .basicswap_util import (
    strBidState,
    SwapTypes,
)
from .chainparams import (
    Coins,
)
from .ui import (
    PAGE_LIMIT,
    getCoinType,
    inputAmount,
    describeBid,
    setCoinFilter,
    get_data_entry,
    get_data_entry_or,
    have_data_entry,
    tickerToCoinId,
)


def js_error(self, error_str):
    error_str_json = json.dumps({'error': error_str})
    return bytes(error_str_json, 'UTF-8')


def withdraw_coin(swap_client, coin_type, post_string, is_json):
    if is_json:
        post_data = json.loads(post_string)
        post_data['is_json'] = True
    else:
        post_data = urllib.parse.parse_qs(post_string)

    value = get_data_entry(post_data, 'value')
    address = get_data_entry(post_data, 'address')
    subfee = get_data_entry(post_data, 'subfee')
    if not isinstance(subfee, bool):
        subfee = toBool(subfee)

    if coin_type == Coins.PART:
        type_from = get_data_entry_or(post_data, 'type_from', 'plain')
        type_to = get_data_entry_or(post_data, 'type_to', 'plain')
        txid_hex = swap_client.withdrawParticl(type_from, type_to, value, address, subfee)
    else:
        txid_hex = swap_client.withdrawCoin(coin_type, value, address, subfee)

    return {'txid': txid_hex}


def js_wallets(self, url_split, post_string, is_json):
    if len(url_split) > 3:
        ticker_str = url_split[3]
        coin_type = tickerToCoinId(ticker_str)

        if len(url_split) > 4:
            cmd = url_split[4]
            if cmd == 'withdraw':
                return bytes(json.dumps(withdraw_coin(self.server.swap_client, coin_type, post_string, is_json)), 'UTF-8')
            raise ValueError('Unknown command')
        return bytes(json.dumps(self.server.swap_client.getWalletInfo(coin_type)), 'UTF-8')
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
            'addr_from': o.addr_from,
            'addr_to': o.addr_to,
            'offer_id': o.offer_id.hex(),
            'created_at': o.created_at,
            'expire_at': o.expire_at,
            'coin_from': ci_from.coin_name(),
            'coin_to': ci_to.coin_name(),
            'amount_from': ci_from.format_amount(o.amount_from),
            'amount_to': ci_to.format_amount((o.amount_from * o.rate) // ci_from.COIN()),
            'rate': ci_to.format_amount(o.rate),
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

            if have_data_entry(post_data, 'validmins'):
                valid_for_seconds = int(get_data_entry(post_data, 'validmins')) * 60
            elif have_data_entry(post_data, 'valid_for_seconds'):
                valid_for_seconds = int(get_data_entry(post_data, 'valid_for_seconds'))
            else:
                valid_for_seconds = 10 * 60

            extra_options = {
                'valid_for_seconds': valid_for_seconds,
            }
            if offer.swap_type == SwapTypes.XMR_SWAP:
                bid_id = swap_client.postXmrBid(offer_id, amount_from, addr_send_from=addr_from, extra_options=extra_options)
            else:
                bid_id = swap_client.postBid(offer_id, amount_from, addr_send_from=addr_from, extra_options=extra_options)

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
        data = describeBid(swap_client, bid, xmr_swap, offer, xmr_offer, events, edit_bid, show_txns, for_api=True)
        return bytes(json.dumps(data), 'UTF-8')

    bids = swap_client.listBids()
    return bytes(json.dumps([{
        'bid_id': b[2].hex(),
        'offer_id': b[3].hex(),
        'created_at': b[0],
        'expire_at': b[1],
        'coin_from': b[9],
        'amount_from': swap_client.ci(b[9]).format_amount(b[4]),
        'bid_state': strBidState(b[5])
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


def js_smsgaddresses(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    if len(url_split) > 3:
        if post_string == '':
            raise ValueError('No post data')
        if is_json:
            post_data = json.loads(post_string)
            post_data['is_json'] = True
        else:
            post_data = urllib.parse.parse_qs(post_string)
        if url_split[3] == 'new':
            addressnote = get_data_entry_or(post_data, 'addressnote', '')
            new_addr, pubkey = swap_client.newSMSGAddress(addressnote)
            return bytes(json.dumps({'new_address': new_addr, 'pubkey': pubkey}), 'UTF-8')
        if url_split[3] == 'add':
            addressnote = get_data_entry_or(post_data, 'addressnote', '')
            pubkey_hex = get_data_entry(post_data, 'addresspubkey')
            added_address = swap_client.addSMSGAddress(pubkey_hex, addressnote)
            return bytes(json.dumps({'added_address': added_address, 'pubkey': pubkey_hex}), 'UTF-8')
        elif url_split[3] == 'edit':
            address = get_data_entry(post_data, 'address')
            activeind = int(get_data_entry(post_data, 'active_ind'))
            addressnote = get_data_entry_or(post_data, 'addressnote', '')
            new_addr = swap_client.editSMSGAddress(address, activeind, addressnote)
            return bytes(json.dumps({'edited_address': address}), 'UTF-8')

    return bytes(json.dumps(swap_client.listAllSMSGAddresses()), 'UTF-8')


def js_rates(self, url_split, post_string, is_json):
    if post_string == '':
        raise ValueError('No post data')
    if is_json:
        post_data = json.loads(post_string)
        post_data['is_json'] = True
    else:
        post_data = urllib.parse.parse_qs(post_string)

    sc = self.server.swap_client
    coin_from = get_data_entry(post_data, 'coin_from')
    coin_to = get_data_entry(post_data, 'coin_to')
    return bytes(json.dumps(sc.lookupRates(coin_from, coin_to)), 'UTF-8')


def js_rate(self, url_split, post_string, is_json):
    if post_string == '':
        raise ValueError('No post data')
    if is_json:
        post_data = json.loads(post_string)
        post_data['is_json'] = True
    else:
        post_data = urllib.parse.parse_qs(post_string)

    sc = self.server.swap_client
    coin_from = getCoinType(get_data_entry(post_data, 'coin_from'))
    ci_from = sc.ci(coin_from)
    coin_to = getCoinType(get_data_entry(post_data, 'coin_to'))
    ci_to = sc.ci(coin_to)

    # Set amount to if rate is provided
    rate = get_data_entry_or(post_data, 'rate', None)
    if rate is not None:
        amt_from_str = get_data_entry_or(post_data, 'amt_from', None)
        amt_to_str = get_data_entry_or(post_data, 'amt_to', None)

        if amt_from_str is not None:
            rate = ci_to.make_int(rate, r=1)
            amt_from = inputAmount(amt_from_str, ci_from)
            amount_to = ci_to.format_amount(int((amt_from * rate) // ci_from.COIN()), r=1)
            return bytes(json.dumps({'amount_to': amount_to}), 'UTF-8')
        if amt_to_str is not None:
            rate = ci_from.make_int(1.0 / float(rate), r=1)
            amt_to = inputAmount(amt_to_str, ci_to)
            amount_from = ci_from.format_amount(int((amt_to * rate) // ci_to.COIN()), r=1)
            return bytes(json.dumps({'amount_from': amount_from}), 'UTF-8')

    amt_from = inputAmount(get_data_entry(post_data, 'amt_from'), ci_from)
    amt_to = inputAmount(get_data_entry(post_data, 'amt_to'), ci_to)

    rate = ci_to.format_amount(ci_from.make_int(amt_to / amt_from, r=1))
    return bytes(json.dumps({'rate': rate}), 'UTF-8')


def js_index(self, url_split, post_string, is_json):
    return bytes(json.dumps(self.server.swap_client.getSummary()), 'UTF-8')
