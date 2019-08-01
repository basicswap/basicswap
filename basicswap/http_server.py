# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import json
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
    COIN,
    format8,
    makeInt,
)
from .chainparams import (
    chainparams,
    Coins,
)
from .basicswap import (
    SwapTypes,
    BidStates,
    TxStates,
    TxTypes,
    strOfferState,
    strBidState,
    strTxState,
    getLockName,
    SEQUENCE_LOCK_TIME,
    ABS_LOCK_TIME,
)


def format_timestamp(value):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(value))


env = Environment(loader=PackageLoader('basicswap', 'templates'))
env.filters['formatts'] = format_timestamp
PAGE_LIMIT = 50


def getCoinName(c):
    return chainparams[c]['name'].capitalize()


def listAvailableCoins(swap_client):
    coins = []
    for k, v in swap_client.coin_clients.items():
        if v['connection_type'] == 'rpc':
            coins.append((int(k), getCoinName(k)))
    return coins


def getTxIdHex(bid, tx_type, prefix):
    if tx_type == TxTypes.ITX:
        obj = bid.initiate_tx
    elif tx_type == TxTypes.PTX:
        obj = bid.participate_tx
    else:
        return 'Unknown Type'

    if not obj:
        return 'None'
    if not obj.txid:
        return 'None'
    return obj.txid.hex() + prefix


def getTxSpendHex(bid, tx_type):
    if tx_type == TxTypes.ITX:
        obj = bid.initiate_tx
    elif tx_type == TxTypes.PTX:
        obj = bid.participate_tx
    else:
        return 'Unknown Type'

    if not obj:
        return 'None'
    if not obj.spend_txid:
        return 'None'
    return obj.spend_txid.hex() + ' {}'.format(obj.spend_n)


def validateAmountString(amount):
    if type(amount) != str:
        return
    ar = amount.split('.')
    if len(ar) > 0 and len(ar[1]) > 8:
        raise ValueError('Too many decimal places in amount {}'.format(amount))


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

    def js_error(self, error_str):
        error_str_json = json.dumps({'error': error_str})
        return bytes(error_str_json, 'UTF-8')

    def js_wallets(self, url_split):
        return bytes(json.dumps(self.server.swap_client.getWalletsInfo()), 'UTF-8')

    def js_offers(self, url_split):
        assert(False), 'TODO'
        return bytes(json.dumps(self.server.swap_client.listOffers()), 'UTF-8')

    def js_sentoffers(self, url_split):
        assert(False), 'TODO'
        return bytes(json.dumps(self.server.swap_client.listOffers(sent=True)), 'UTF-8')

    def js_bids(self, url_split):
        if len(url_split) > 3:
            bid_id = bytes.fromhex(url_split[3])
            assert(len(bid_id) == 28)
            return bytes(json.dumps(self.server.swap_client.viewBid(bid_id)), 'UTF-8')
        assert(False), 'TODO'
        return bytes(json.dumps(self.server.swap_client.listBids()), 'UTF-8')

    def js_sentbids(self, url_split):
        return bytes(json.dumps(self.server.swap_client.listBids(sent=True)), 'UTF-8')

    def js_index(self, url_split):
        return bytes(json.dumps(self.server.swap_client.getSummary()), 'UTF-8')

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

                if bytes('withdraw_' + cid, 'utf-8') in form_data:
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
            fee_rate = swap_client.getFeeRateForCoin(k)
            tx_vsize = swap_client.getContractSpendTxVSize(k)
            est_fee = (fee_rate * tx_vsize) / 1000
            wallets_formatted.append({
                'name': w['name'],
                'cid': str(int(k)),
                'fee_rate': format8(fee_rate * COIN),
                'est_fee': format8(est_fee * COIN),
                'balance': w['balance'],
                'blocks': w['blocks'],
                'synced': w['synced'],
                'deposit_address': w['deposit_address'],
            })
            if float(w['unconfirmed']) > 0.0:
                wallets_formatted[-1]['unconfirmed'] = w['unconfirmed']

        template = env.get_template('wallets.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            wallets=wallets_formatted,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_newoffer(self, url_split, post_string):
        swap_client = self.server.swap_client

        messages = []
        form_data = self.checkForm(post_string, 'newoffer', messages)
        if form_data:
            addr_from = form_data[b'addr_from'][0].decode('utf-8')
            if addr_from == '-1':
                addr_from = None

            try:
                coin_from = Coins(int(form_data[b'coin_from'][0]))
            except Exception:
                raise ValueError('Unknown Coin From')
            try:
                coin_to = Coins(int(form_data[b'coin_to'][0]))
            except Exception:
                raise ValueError('Unknown Coin To')

            value_from = form_data[b'amt_from'][0].decode('utf-8')
            value_to = form_data[b'amt_to'][0].decode('utf-8')

            validateAmountString(value_from)
            validateAmountString(value_to)
            value_from = makeInt(value_from)
            value_to = makeInt(value_to)

            min_bid = int(value_from)
            rate = int((value_to / value_from) * COIN)
            autoaccept = True if b'autoaccept' in form_data else False
            lock_seconds = int(form_data[b'lockhrs'][0]) * 60 * 60
            # TODO: More accurate rate
            # assert(value_to == (value_from * rate) // COIN)

            if swap_client.coin_clients[coin_from]['use_csv'] and swap_client.coin_clients[coin_to]['use_csv']:
                lock_type = SEQUENCE_LOCK_TIME
            else:
                lock_type = ABS_LOCK_TIME

            offer_id = swap_client.postOffer(coin_from, coin_to, value_from, rate, min_bid, SwapTypes.SELLER_FIRST, lock_type=lock_type, lock_value=lock_seconds, auto_accept_bids=autoaccept, addr_send_from=addr_from)
            messages.append('<a href="/offer/' + offer_id.hex() + '">Sent Offer ' + offer_id.hex() + '</a><br/>Rate: ' + format8(rate))

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
        offer = swap_client.getOffer(offer_id)
        assert(offer), 'Unknown offer ID'

        messages = []
        sent_bid_id = None
        show_bid_form = None
        form_data = self.checkForm(post_string, 'offer', messages)
        if form_data:
            if b'newbid' in form_data:
                show_bid_form = True
            else:
                addr_from = form_data[b'addr_from'][0].decode('utf-8')
                if addr_from == '-1':
                    addr_from = None

                sent_bid_id = swap_client.postBid(offer_id, offer.amount_from).hex()

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ticker_from = swap_client.getTicker(coin_from)
        ticker_to = swap_client.getTicker(coin_to)
        data = {
            'tla_from': swap_client.getTicker(coin_from),
            'tla_to': swap_client.getTicker(coin_to),
            'state': strOfferState(offer.state),
            'coin_from': getCoinName(coin_from),
            'coin_to': getCoinName(coin_to),
            'amt_from': format8(offer.amount_from),
            'amt_to': format8((offer.amount_from * offer.rate) // COIN),
            'rate': format8(offer.rate),
            'lock_type': getLockName(offer.lock_type),
            'lock_value': offer.lock_value,
            'addr_from': offer.addr_from,
            'created_at': offer.created_at,
            'expired_at': offer.expire_at,
            'sent': 'True' if offer.was_sent else 'False',
            'show_bid_form': show_bid_form,
        }

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
            bids=[(b[1].hex(), format8(b[3]), strBidState(b[4]), strTxState(b[6]), strTxState(b[7])) for b in bids],
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
            coin_from = int(form_data[b'coin_from'][0])
            if coin_from > -1:
                try:
                    filters['coin_from'] = Coins(coin_from)
                except Exception:
                    raise ValueError('Unknown Coin From')
            coin_to = int(form_data[b'coin_to'][0])
            if coin_to > -1:
                try:
                    filters['coin_to'] = Coins(coin_to)
                except Exception:
                    raise ValueError('Unknown Coin From')

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
        if form_data and b'pageforwards' in form_data:
            filters['page_no'] = int(form_data[b'pageno'][0]) + 1

        if filters['page_no'] > 1:
            filters['offset'] = (filters['page_no'] - 1) * PAGE_LIMIT

        offers = swap_client.listOffers(sent, filters)

        template = env.get_template('offers.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            page_type='Sent' if sent else 'Received',
            coins=listAvailableCoins(swap_client),
            messages=messages,
            filters=filters,
            offers=[(time.strftime('%Y-%m-%d %H:%M', time.localtime(o.created_at)),
                     o.offer_id.hex(), getCoinName(Coins(o.coin_from)), getCoinName(Coins(o.coin_to)), format8(o.amount_from), format8((o.amount_from * o.rate) // COIN), format8(o.rate)) for o in offers],
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
        form_data = self.checkForm(post_string, 'bid', messages)
        if form_data:
            if b'abandon_bid' in form_data:
                try:
                    swap_client.abandonBid(bid_id)
                    messages.append('Bid abandoned')
                except Exception as ex:
                    messages.append('Error ' + str(ex))
            if b'accept_bid' in form_data:
                try:
                    swap_client.acceptBid(bid_id)
                    messages.append('Bid accepted')
                except Exception as ex:
                    messages.append('Error ' + str(ex))
            if b'show_txns' in form_data:
                show_txns = True

        bid, offer = swap_client.getBidAndOffer(bid_id)
        assert(bid), 'Unknown bid ID'

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ticker_from = swap_client.getTicker(coin_from)
        ticker_to = swap_client.getTicker(coin_to)

        if bid.state == BidStates.BID_SENT:
            state_description = 'Waiting for seller to accept.'
        elif bid.state == BidStates.BID_RECEIVED:
            state_description = 'Waiting for seller to accept.'
        elif bid.state == BidStates.BID_ACCEPTED:
            if not bid.initiate_tx:
                state_description = 'Waiting for seller to send initiate tx.'
            else:
                state_description = 'Waiting for initiate tx to confirm.'
        elif bid.state == BidStates.SWAP_INITIATED:
            state_description = 'Waiting for participate txn to be confirmed in {} chain'.format(ticker_to)
        elif bid.state == BidStates.SWAP_PARTICIPATING:
            state_description = 'Waiting for initiate txn to be spent in {} chain'.format(ticker_from)
        elif bid.state == BidStates.SWAP_COMPLETED:
            state_description = 'Swap completed'
            if bid.getITxState() == TxStates.TX_REDEEMED and bid.getPTxState() == TxStates.TX_REDEEMED:
                state_description += ' successfully'
            else:
                state_description += ', ITX ' + strTxState(bid.getITxState() + ', PTX ' + strTxState(bid.getPTxState()))
        elif bid.state == BidStates.SWAP_TIMEDOUT:
            state_description = 'Timed out waiting for initiate txn'
        elif bid.state == BidStates.BID_ABANDONED:
            state_description = 'Bid abandoned'
        elif bid.state == BidStates.BID_ERROR:
            state_description = bid.state_note
        else:
            state_description = ''

        data = {
            'amt_from': format8(bid.amount),
            'amt_to': format8((bid.amount * offer.rate) // COIN),
            'ticker_from': ticker_from,
            'ticker_to': ticker_to,
            'bid_state': strBidState(bid.state),
            'state_description': state_description,
            'itx_state': strTxState(bid.getITxState()),
            'ptx_state': strTxState(bid.getPTxState()),
            'offer_id': bid.offer_id.hex(),
            'addr_from': bid.bid_addr,
            'addr_fund_proof': bid.proof_address,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.created_at)),
            'expired_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.expire_at)),
            'was_sent': 'True' if bid.was_sent else 'False',
            'was_received': 'True' if bid.was_received else 'False',
            'initiate_tx': getTxIdHex(bid, TxTypes.ITX, ' ' + ticker_from),
            'initiate_conf': 'None' if (not bid.initiate_tx or not bid.initiate_tx.conf) else bid.initiate_tx.conf,
            'participate_tx': getTxIdHex(bid, TxTypes.PTX, ' ' + ticker_to),
            'participate_conf': 'None' if (not bid.participate_tx or not bid.participate_tx.conf) else bid.participate_tx.conf,
            'show_txns': show_txns,
        }

        if show_txns:
            data['initiate_tx_refund'] = 'None' if not bid.initiate_txn_refund else bid.initiate_txn_refund.hex()
            data['participate_tx_refund'] = 'None' if not bid.participate_txn_refund else bid.participate_txn_refund.hex()
            data['initiate_tx_spend'] = getTxSpendHex(bid, TxTypes.ITX)
            data['participate_tx_spend'] = getTxSpendHex(bid, TxTypes.PTX)

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

        template = env.get_template('bid.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            bid_id=bid_id.hex(),
            messages=messages,
            data=data,
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
                func = self.js_index
                if len(url_split) > 2:
                    func = {'wallets': self.js_wallets,
                            'offers': self.js_offers,
                            'sentoffers': self.js_sentoffers,
                            'bids': self.js_bids,
                            'sentbids': self.js_sentbids,
                            }.get(url_split[2], self.js_index)
                return func(url_split)
            except Exception as ex:
                return self.js_error(str(ex))
        try:
            self.putHeaders(status_code, 'text/html')
            if len(url_split) > 1:
                if url_split[1] == 'active':
                    return self.page_active(url_split, post_string)
                if url_split[1] == 'wallets':
                    return self.page_wallets(url_split, post_string)
                if url_split[1] == 'rpc':
                    return self.page_rpc(url_split, post_string)
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
            return self.page_index(url_split)
        except Exception as ex:
            traceback.print_exc()  # TODO: Remove
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
