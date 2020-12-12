# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import time
import struct
import traceback
import threading
import http.client
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from jinja2 import Environment, PackageLoader

from . import __version__
from .util import (
    dumpj,
    make_int,
)
from .chainparams import (
    chainparams,
    Coins,
)
from .basicswap import (
    SwapTypes,
    strOfferState,
    strBidState,
    strTxState,
    getLockName,
    SEQUENCE_LOCK_TIME,
    ABS_LOCK_TIME,
)
from .js_server import (
    js_error,
    js_wallets,
    js_offers,
    js_sentoffers,
    js_bids,
    js_sentbids,
    js_index,
)
from .ui import (
    PAGE_LIMIT,
    inputAmount,
    describeBid,
    setCoinFilter,
)


def format_timestamp(value):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(value))


env = Environment(loader=PackageLoader('basicswap', 'templates'))
env.filters['formatts'] = format_timestamp


def getCoinName(c):
    return chainparams[c]['name'].capitalize()


def listAvailableCoins(swap_client):
    coins = []
    for k, v in swap_client.coin_clients.items():
        if v['connection_type'] == 'rpc':
            coins.append((int(k), getCoinName(k)))
    return coins


def extractDomain(url):
    return url.split('://', 1)[1].split('/', 1)[0]


def listAvailableExplorers(swap_client):
    explorers = []
    for c in Coins:
        for i, e in enumerate(swap_client.coin_clients[c]['explorers']):
            explorers.append(('{}_{}'.format(int(c), i), swap_client.coin_clients[c]['name'].capitalize() + ' - ' + extractDomain(e.base_url)))
    return explorers


def listExplorerActions(swap_client):
    actions = [('height', 'Chain Height'),
               ('block', 'Get Block'),
               ('tx', 'Get Transaction'),
               ('balance', 'Address Balance'),
               ('unspent', 'List Unspent')]
    return actions


def html_content_start(title, h2=None, refresh=None):
    content = '<!DOCTYPE html><html lang="en">\n<head>' \
        + '<meta charset="UTF-8">' \
        + ('' if not refresh else '<meta http-equiv="refresh" content="{}">'.format(refresh)) \
        + '<title>' + title + '</title></head>\n' \
        + '<body>'
    if h2 is not None:
        content += '<h2>' + h2 + '</h2>'
    return content


class HttpHandler(BaseHTTPRequestHandler):
    def page_info(self, info_str):
        content = html_content_start('BasicSwap Info') \
            + '<p>Info: ' + info_str + '</p>' \
            + '<p><a href=\'/\'>home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def page_error(self, error_str):
        content = html_content_start('BasicSwap Error') \
            + '<p>Error: ' + error_str + '</p>' \
            + '<p><a href=\'/\'>home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def checkForm(self, post_string, name, messages):
        if post_string == '':
            return None
        form_data = urllib.parse.parse_qs(post_string)
        form_id = form_data[b'formid'][0].decode('utf-8')
        if self.server.last_form_id.get(name, None) == form_id:
            messages.append('Prevented double submit for form {}.'.format(form_id))
        else:
            self.server.last_form_id[name] = form_id
        return form_data

    def page_explorers(self, url_split, post_string):
        swap_client = self.server.swap_client

        result = None
        explorer = -1
        action = -1
        messages = []
        form_data = self.checkForm(post_string, 'explorers', messages)
        if form_data:

            explorer = form_data[b'explorer'][0].decode('utf-8')
            action = form_data[b'action'][0].decode('utf-8')

            args = '' if b'args' not in form_data else form_data[b'args'][0].decode('utf-8')
            try:
                c, e = explorer.split('_')
                exp = swap_client.coin_clients[Coins(int(c))]['explorers'][int(e)]
                if action == 'height':
                    result = str(exp.getChainHeight())
                elif action == 'block':
                    result = dumpj(exp.getBlock(args))
                elif action == 'tx':
                    result = dumpj(exp.getTransaction(args))
                elif action == 'balance':
                    result = dumpj(exp.getBalance(args))
                elif action == 'unspent':
                    result = dumpj(exp.lookupUnspentByAddress(args))
                else:
                    result = 'Unknown action'
            except Exception as ex:
                result = str(ex)

        template = env.get_template('explorers.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            explorers=listAvailableExplorers(swap_client),
            explorer=explorer,
            actions=listExplorerActions(swap_client),
            action=action,
            result=result,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_rpc(self, url_split, post_string):
        swap_client = self.server.swap_client

        result = None
        coin_type = -1
        messages = []
        form_data = self.checkForm(post_string, 'rpc', messages)
        if form_data:
            try:
                coin_type = Coins(int(form_data[b'coin_type'][0]))
            except Exception:
                raise ValueError('Unknown Coin Type')

            cmd = form_data[b'cmd'][0].decode('utf-8')
            try:
                result = cmd + '\n' + swap_client.callcoincli(coin_type, cmd)
            except Exception as ex:
                result = str(ex)

        template = env.get_template('rpc.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            coins=listAvailableCoins(swap_client),
            coin_type=coin_type,
            result=result,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_active(self, url_split, post_string):
        swap_client = self.server.swap_client
        active_swaps = swap_client.listSwapsInProgress()

        template = env.get_template('active.html')
        return bytes(template.render(
            title=self.server.title,
            refresh=30,
            h2=self.server.title,
            active_swaps=[(s[0].hex(), s[1], strBidState(s[2]), strTxState(s[3]), strTxState(s[4])) for s in active_swaps],
        ), 'UTF-8')

    def page_wallets(self, url_split, post_string):
        swap_client = self.server.swap_client

        messages = []
        form_data = self.checkForm(post_string, 'wallets', messages)
        if form_data:
            for c in Coins:
                cid = str(int(c))

                if bytes('newaddr_' + cid, 'utf-8') in form_data:
                    swap_client.cacheNewAddressForCoin(c)
                elif bytes('reseed_' + cid, 'utf-8') in form_data:
                    try:
                        swap_client.reseedWallet(c)
                        messages.append('Reseed complete ' + str(c))
                    except Exception as ex:
                        messages.append('Reseed failed ' + str(ex))
                elif bytes('withdraw_' + cid, 'utf-8') in form_data:
                    value = form_data[bytes('amt_' + cid, 'utf-8')][0].decode('utf-8')
                    address = form_data[bytes('to_' + cid, 'utf-8')][0].decode('utf-8')
                    subfee = True if bytes('subfee_' + cid, 'utf-8') in form_data else False
                    txid = swap_client.withdrawCoin(c, value, address, subfee)
                    ticker = swap_client.getTicker(c)
                    messages.append('Withdrew {} {} to address {}<br/>In txid: {}'.format(value, ticker, address, txid))

        wallets = swap_client.getWalletsInfo()

        wallets_formatted = []
        for k, w in wallets.items():
            if 'error' in w:
                wallets_formatted.append({
                    'cid': str(int(k)),
                    'error': w['error']
                })
                continue

            ci = swap_client.ci(k)
            fee_rate = swap_client.getFeeRateForCoin(k)
            est_fee = swap_client.estimateWithdrawFee(k, fee_rate)
            wallets_formatted.append({
                'name': w['name'],
                'version': w['version'],
                'cid': str(int(k)),
                'fee_rate': ci.format_amount(int(fee_rate * ci.COIN())),
                'est_fee': 'Unknown' if est_fee is None else ci.format_amount(int(est_fee * ci.COIN())),
                'balance': w['balance'],
                'blocks': w['blocks'],
                'synced': w['synced'],
                'deposit_address': w['deposit_address'],
                'expected_seed': w['expected_seed'],
                'balance_all': float(w['balance']) + float(w['unconfirmed']),
            })
            if float(w['unconfirmed']) > 0.0:
                wallets_formatted[-1]['unconfirmed'] = w['unconfirmed']

        template = env.get_template('wallets.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            wallets=wallets_formatted,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_settings(self, url_split, post_string):
        swap_client = self.server.swap_client

        messages = []
        form_data = self.checkForm(post_string, 'settings', messages)
        if form_data:
            for name, c in swap_client.settings['chainclients'].items():
                if bytes('apply_' + name, 'utf-8') in form_data:
                    data = {'lookups': form_data[bytes('lookups_' + name, 'utf-8')][0].decode('utf-8')}
                    swap_client.editSettings(name, data)
        chains_formatted = []

        for name, c in swap_client.settings['chainclients'].items():
            chains_formatted.append({
                'name': name,
                'lookups': c.get('chain_lookups', 'local')
            })

        template = env.get_template('settings.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            chains=chains_formatted,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def postNewOffer(self, form_data):
        swap_client = self.server.swap_client
        addr_from = form_data[b'addr_from'][0].decode('utf-8')
        if addr_from == '-1':
            addr_from = None

        try:
            coin_from = Coins(int(form_data[b'coin_from'][0]))
            ci_from = swap_client.ci(coin_from)
        except Exception:
            raise ValueError('Unknown Coin From')
        try:
            coin_to = Coins(int(form_data[b'coin_to'][0]))
            ci_to = swap_client.ci(coin_to)
        except Exception:
            raise ValueError('Unknown Coin To')

        value_from = inputAmount(form_data[b'amt_from'][0].decode('utf-8'), ci_from)
        value_to = inputAmount(form_data[b'amt_to'][0].decode('utf-8'), ci_to)

        min_bid = int(value_from)
        rate = int((value_to / value_from) * ci_from.COIN())
        autoaccept = True if b'autoaccept' in form_data else False
        lock_seconds = int(form_data[b'lockhrs'][0]) * 60 * 60
        # TODO: More accurate rate
        # assert(value_to == (value_from * rate) // COIN)

        if swap_client.coin_clients[coin_from]['use_csv'] and swap_client.coin_clients[coin_to]['use_csv']:
            lock_type = SEQUENCE_LOCK_TIME
        else:
            lock_type = ABS_LOCK_TIME

        swap_type = SwapTypes.SELLER_FIRST
        if coin_to == Coins.XMR:
            swap_type = SwapTypes.XMR_SWAP

        offer_id = swap_client.postOffer(coin_from, coin_to, value_from, rate, min_bid, swap_type, lock_type=lock_type, lock_value=lock_seconds, auto_accept_bids=autoaccept, addr_send_from=addr_from)
        return offer_id

    def page_newoffer(self, url_split, post_string):
        swap_client = self.server.swap_client

        messages = []
        form_data = self.checkForm(post_string, 'newoffer', messages)
        if form_data:
            offer_id = self.postNewOffer(form_data)
            messages.append('<a href="/offer/' + offer_id.hex() + '">Sent Offer {}</a>'.format(offer_id.hex()))

        template = env.get_template('offer_new.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            coins=listAvailableCoins(swap_client),
            addrs=swap_client.listSmsgAddresses('offer'),
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_offer(self, url_split, post_string):
        assert(len(url_split) > 2), 'Offer ID not specified'
        try:
            offer_id = bytes.fromhex(url_split[2])
            assert(len(offer_id) == 28)
        except Exception:
            raise ValueError('Bad offer ID')
        swap_client = self.server.swap_client
        offer, xmr_offer = swap_client.getXmrOffer(offer_id)
        assert(offer), 'Unknown offer ID'

        messages = []
        sent_bid_id = None
        show_bid_form = None
        form_data = self.checkForm(post_string, 'offer', messages)
        if form_data:
            if b'revoke_offer' in form_data:
                try:
                    swap_client.revokeOffer(offer_id)
                    messages.append('Offer revoked')
                except Exception as ex:
                    messages.append('Revoke offer failed ' + str(ex))
            elif b'newbid' in form_data:
                show_bid_form = True
            else:
                addr_from = form_data[b'addr_from'][0].decode('utf-8')
                if addr_from == '-1':
                    addr_from = None

                sent_bid_id = swap_client.postBid(offer_id, offer.amount_from, addr_send_from=addr_from).hex()

        ci_from = swap_client.ci(Coins(offer.coin_from))
        ci_to = swap_client.ci(Coins(offer.coin_to))

        data = {
            'tla_from': ci_from.ticker(),
            'tla_to': ci_to.ticker(),
            'state': strOfferState(offer.state),
            'coin_from': ci_from.coin_name(),
            'coin_to': ci_to.coin_name(),
            'amt_from': ci_from.format_amount(offer.amount_from),
            'amt_to': ci_to.format_amount((offer.amount_from * offer.rate) // ci_from.COIN()),
            'rate': ci_to.format_amount(offer.rate),
            'lock_type': getLockName(offer.lock_type),
            'lock_value': offer.lock_value,
            'addr_from': offer.addr_from,
            'created_at': offer.created_at,
            'expired_at': offer.expire_at,
            'sent': 'True' if offer.was_sent else 'False',
            'was_revoked': 'True' if offer.active_ind == 2 else 'False',
            'show_bid_form': show_bid_form,
        }

        if xmr_offer:
            int_fee_rate_now = make_int(ci_from.get_fee_rate(), ci_from.exp())
            data['xmr_type'] = True
            data['a_fee_rate'] = ci_from.format_amount(xmr_offer.a_fee_rate)
            data['a_fee_rate_verify'] = ci_from.format_amount(int_fee_rate_now)
            data['a_fee_warn'] = xmr_offer.a_fee_rate < int_fee_rate_now

        if offer.was_sent:
            data['auto_accept'] = 'True' if offer.auto_accept_bids else 'False'

        bids = swap_client.listBids(offer_id=offer_id)

        template = env.get_template('offer.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            offer_id=offer_id.hex(),
            sent_bid_id=sent_bid_id,
            messages=messages,
            data=data,
            bids=[(b[1].hex(), ci_from.format_amount(b[3]), strBidState(b[4]), strTxState(b[6]), strTxState(b[7])) for b in bids],
            addrs=None if show_bid_form is None else swap_client.listSmsgAddresses('bid'),
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_offers(self, url_split, post_string, sent=False):
        swap_client = self.server.swap_client

        filters = {
            'coin_from': -1,
            'coin_to': -1,
            'page_no': 1,
            'limit': PAGE_LIMIT,
            'sort_by': 'created_at',
            'sort_dir': 'desc',
        }
        messages = []
        form_data = self.checkForm(post_string, 'offers', messages)
        if form_data and b'applyfilters' in form_data:
            filters['coin_from'] = setCoinFilter(form_data, b'coin_from')
            filters['coin_to'] = setCoinFilter(form_data, b'coin_to')

            if b'sort_by' in form_data:
                sort_by = form_data[b'sort_by'][0].decode('utf-8')
                assert(sort_by in ['created_at', 'rate']), 'Invalid sort by'
                filters['sort_by'] = sort_by
            if b'sort_dir' in form_data:
                sort_dir = form_data[b'sort_dir'][0].decode('utf-8')
                assert(sort_dir in ['asc', 'desc']), 'Invalid sort dir'
                filters['sort_dir'] = sort_dir

        if form_data and b'pageback' in form_data:
            filters['page_no'] = int(form_data[b'pageno'][0]) - 1
            if filters['page_no'] < 1:
                filters['page_no'] = 1
        elif form_data and b'pageforwards' in form_data:
            filters['page_no'] = int(form_data[b'pageno'][0]) + 1

        if filters['page_no'] > 1:
            filters['offset'] = (filters['page_no'] - 1) * PAGE_LIMIT

        offers = swap_client.listOffers(sent, filters)

        formatted_offers = []
        for o in offers:
            ci_from = swap_client.ci(Coins(o.coin_from))
            ci_to = swap_client.ci(Coins(o.coin_to))
            formatted_offers.append((
                time.strftime('%Y-%m-%d %H:%M', time.localtime(o.created_at)),
                o.offer_id.hex(),
                ci_from.coin_name(), ci_to.coin_name(),
                ci_from.format_amount(o.amount_from),
                ci_to.format_amount((o.amount_from * o.rate) // ci_from.COIN()),
                ci_to.format_amount(o.rate)))

        template = env.get_template('offers.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            page_type='Sent' if sent else 'Received',
            coins=listAvailableCoins(swap_client),
            messages=messages,
            filters=filters,
            offers=formatted_offers,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_advance(self, url_split, post_string):
        assert(len(url_split) > 2), 'Bid ID not specified'
        try:
            bid_id = bytes.fromhex(url_split[2])
            assert(len(bid_id) == 28)
        except Exception:
            raise ValueError('Bad bid ID')
        swap_client = self.server.swap_client

        template = env.get_template('advance.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            bid_id=bid_id.hex(),
        ), 'UTF-8')

    def page_bid(self, url_split, post_string):
        assert(len(url_split) > 2), 'Bid ID not specified'
        try:
            bid_id = bytes.fromhex(url_split[2])
            assert(len(bid_id) == 28)
        except Exception:
            raise ValueError('Bad bid ID')
        swap_client = self.server.swap_client

        messages = []
        show_txns = False
        edit_bid = False
        view_tx_ind = None
        form_data = self.checkForm(post_string, 'bid', messages)
        if form_data:
            if b'abandon_bid' in form_data:
                try:
                    swap_client.abandonBid(bid_id)
                    messages.append('Bid abandoned')
                except Exception as ex:
                    messages.append('Abandon failed ' + str(ex))
            elif b'accept_bid' in form_data:
                try:
                    swap_client.acceptBid(bid_id)
                    messages.append('Bid accepted')
                except Exception as ex:
                    messages.append('Accept failed ' + str(ex))
            elif b'show_txns' in form_data:
                show_txns = True
            elif b'edit_bid' in form_data:
                edit_bid = True
            elif b'edit_bid_submit' in form_data:
                data = {
                    'bid_state': int(form_data[b'new_state'][0])
                }
                try:
                    swap_client.manualBidUpdate(bid_id, data)
                    messages.append('Bid edited')
                except Exception as ex:
                    messages.append('Edit failed ' + str(ex))
            elif b'view_tx_submit' in form_data:
                show_txns = True
                view_tx_ind = form_data[b'view_tx'][0].decode('utf-8')

        bid, xmr_swap, offer, xmr_offer, events = swap_client.getXmrBidAndOffer(bid_id)
        assert(bid), 'Unknown bid ID'

        data = describeBid(swap_client, bid, xmr_swap, offer, xmr_offer, events, edit_bid, show_txns, view_tx_ind)

        old_states = []
        num_states = len(bid.states) // 12
        for i in range(num_states):
            up = struct.unpack_from('<iq', bid.states[i * 12:(i + 1) * 12])
            old_states.append((up[1], 'Bid ' + strBidState(up[0])))
        if bid.initiate_tx and bid.initiate_tx.states is not None:
            num_states = len(bid.initiate_tx.states) // 12
            for i in range(num_states):
                up = struct.unpack_from('<iq', bid.initiate_tx.states[i * 12:(i + 1) * 12])
                old_states.append((up[1], 'ITX ' + strTxState(up[0])))
        if bid.participate_tx and bid.participate_tx.states is not None:
            num_states = len(bid.participate_tx.states) // 12
            for i in range(num_states):
                up = struct.unpack_from('<iq', bid.participate_tx.states[i * 12:(i + 1) * 12])
                old_states.append((up[1], 'PTX ' + strTxState(up[0])))
        if len(old_states) > 0:
            old_states.sort(key=lambda x: x[0])

        template = env.get_template('bid_xmr.html') if offer.swap_type == SwapTypes.XMR_SWAP else env.get_template('bid.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            bid_id=bid_id.hex(),
            messages=messages,
            data=data,
            edit_bid=edit_bid,
            form_id=os.urandom(8).hex(),
            old_states=old_states,
        ), 'UTF-8')

    def page_bids(self, url_split, post_string, sent=False):
        swap_client = self.server.swap_client
        bids = swap_client.listBids(sent=sent)

        template = env.get_template('bids.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            page_type='Sent' if sent else 'Received',
            bids=[(time.strftime('%Y-%m-%d %H:%M', time.localtime(b[0])),
                   b[1].hex(), b[2].hex(), strBidState(b[4]), strTxState(b[6]), strTxState(b[7])) for b in bids],
        ), 'UTF-8')

    def page_watched(self, url_split, post_string):
        swap_client = self.server.swap_client
        watched_outputs, last_scanned = swap_client.listWatchedOutputs()

        template = env.get_template('watched.html')
        return bytes(template.render(
            title=self.server.title,
            refresh=30,
            h2=self.server.title,
            last_scanned=[(getCoinName(ls[0]), ls[1]) for ls in last_scanned],
            watched_outputs=[(wo[1].hex(), getCoinName(wo[0]), wo[2], wo[3], int(wo[4])) for wo in watched_outputs],
        ), 'UTF-8')

    def page_shutdown(self, url_split, post_string):
        swap_client = self.server.swap_client
        swap_client.stopRunning()

        return self.page_info('Shutting down')

    def page_index(self, url_split):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        template = env.get_template('index.html')
        return bytes(template.render(
            title=self.server.title,
            refresh=30,
            h2=self.server.title,
            version=__version__,
            summary=summary
        ), 'UTF-8')

    def putHeaders(self, status_code, content_type):
        self.send_response(status_code)
        if self.server.allow_cors:
            self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', content_type)
        self.end_headers()

    def handle_http(self, status_code, path, post_string=''):
        url_split = self.path.split('/')
        if len(url_split) > 1 and url_split[1] == 'json':
            try:
                self.putHeaders(status_code, 'text/plain')
                func = js_index
                if len(url_split) > 2:
                    func = {'wallets': js_wallets,
                            'offers': js_offers,
                            'sentoffers': js_sentoffers,
                            'bids': js_bids,
                            'sentbids': js_sentbids,
                            }.get(url_split[2], js_index)
                return func(self, url_split, post_string)
            except Exception as ex:
                if self.server.swap_client.debug is True:
                    traceback.print_exc()
                return js_error(self, str(ex))
        try:
            self.putHeaders(status_code, 'text/html')
            if len(url_split) > 1:
                if url_split[1] == 'active':
                    return self.page_active(url_split, post_string)
                if url_split[1] == 'wallets':
                    return self.page_wallets(url_split, post_string)
                if url_split[1] == 'settings':
                    return self.page_settings(url_split, post_string)
                if url_split[1] == 'rpc':
                    return self.page_rpc(url_split, post_string)
                if url_split[1] == 'explorers':
                    return self.page_explorers(url_split, post_string)
                if url_split[1] == 'offer':
                    return self.page_offer(url_split, post_string)
                if url_split[1] == 'offers':
                    return self.page_offers(url_split, post_string)
                if url_split[1] == 'newoffer':
                    return self.page_newoffer(url_split, post_string)
                if url_split[1] == 'sentoffers':
                    return self.page_offers(url_split, post_string, sent=True)
                if url_split[1] == 'advance':
                    return self.page_advance(url_split, post_string)
                if url_split[1] == 'bid':
                    return self.page_bid(url_split, post_string)
                if url_split[1] == 'bids':
                    return self.page_bids(url_split, post_string)
                if url_split[1] == 'sentbids':
                    return self.page_bids(url_split, post_string, sent=True)
                if url_split[1] == 'watched':
                    return self.page_watched(url_split, post_string)
                if url_split[1] == 'shutdown':
                    return self.page_shutdown(url_split, post_string)
            return self.page_index(url_split)
        except Exception as ex:
            if self.server.swap_client.debug is True:
                traceback.print_exc()
            return self.page_error(str(ex))

    def do_GET(self):
        response = self.handle_http(200, self.path)
        self.wfile.write(response)

    def do_POST(self):
        post_string = self.rfile.read(int(self.headers['Content-Length']))
        response = self.handle_http(200, self.path, post_string)
        self.wfile.write(response)

    def do_HEAD(self):
        self.putHeaders(200, 'text/html')

    def do_OPTIONS(self):
        self.send_response(200, 'ok')
        if self.server.allow_cors:
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()


class HttpThread(threading.Thread, HTTPServer):
    def __init__(self, fp, host_name, port_no, allow_cors, swap_client):
        threading.Thread.__init__(self)

        self.stop_event = threading.Event()
        self.fp = fp
        self.host_name = host_name
        self.port_no = port_no
        self.allow_cors = allow_cors
        self.swap_client = swap_client
        self.title = 'Simple Atomic Swap Demo, ' + self.swap_client.chain
        self.last_form_id = dict()

        self.timeout = 60
        HTTPServer.__init__(self, (self.host_name, self.port_no), HttpHandler)

    def stop(self):
        self.stop_event.set()

        # Send fake request
        conn = http.client.HTTPConnection(self.host_name, self.port_no)
        conn.connect()
        conn.request('GET', '/none')
        response = conn.getresponse()
        data = response.read()
        conn.close()

    def stopped(self):
        return self.stop_event.is_set()

    def serve_forever(self):
        while not self.stopped():
            self.handle_request()
        self.socket.close()

    def run(self):
        self.serve_forever()
