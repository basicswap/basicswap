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
)
from .chainparams import (
    chainparams,
    Coins,
)
from .basicswap import (
    SwapTypes,
    BidStates,
    TxStates,
    getOfferState,
    getBidState,
    getTxState,
    getLockName,
    SEQUENCE_LOCK_TIME,
    ABS_LOCK_TIME,
)


def format_timestamp(value):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(value))


env = Environment(loader=PackageLoader('basicswap', 'templates'))
env.filters['formatts'] = format_timestamp


def getCoinName(c):
    return chainparams[c]['name'].capitalize()


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
        return bytes(json.dumps(self.server.swap_client.listBids()), 'UTF-8')

    def js_sentbids(self, url_split):
        return bytes(json.dumps(self.server.swap_client.listBids(sent=True)), 'UTF-8')

    def js_index(self, url_split):
        return bytes(json.dumps(self.server.swap_client.getSummary()), 'UTF-8')

    def page_active(self, url_split, post_string):
        swap_client = self.server.swap_client
        active_swaps = swap_client.listSwapsInProgress()

        template = env.get_template('active.html')
        return bytes(template.render(
            title=self.server.title,
            refresh=30,
            h2=self.server.title,
            active_swaps=[(s[0].hex(), s[1], getBidState(s[2])) for s in active_swaps],
        ), 'UTF-8')

    def page_wallets(self, url_split, post_string):
        swap_client = self.server.swap_client

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>Wallets</h3>'

        messages = []
        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('wallets', None) == form_id:
                messages.append('Prevented double submit for form {}.'.format(form_id))
            else:
                self.server.last_form_id['wallets'] = form_id

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
                'cid': str(int(k)),
                'fee_rate': format8(fee_rate * COIN),
                'est_fee': format8(est_fee * COIN),
                'balance': w['balance'],
                'blocks': w['blocks'],
                'synced': w['synced'],
                'deposit_address': w['deposit_address'],
            })

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
        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('newoffer', None) == form_id:
                messages.append('Prevented double submit for form {}.'.format(form_id))
            else:
                self.server.last_form_id['newoffer'] = form_id

                try:
                    coin_from = Coins(int(form_data[b'coin_from'][0]))
                except Exception:
                    raise ValueError('Unknown Coin From')
                try:
                    coin_to = Coins(int(form_data[b'coin_to'][0]))
                except Exception:
                    raise ValueError('Unknown Coin From')

                value_from = int(float(form_data[b'amt_from'][0]) * COIN)
                value_to = int(float(form_data[b'amt_to'][0]) * COIN)
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

                offer_id = swap_client.postOffer(coin_from, coin_to, value_from, rate, min_bid, SwapTypes.SELLER_FIRST, auto_accept_bids=autoaccept, lock_type=lock_type, lock_value=lock_seconds)
                messages.append('<a href="/offer/' + offer_id.hex() + '">Sent Offer ' + offer_id.hex() + '</a><br/>Rate: ' + format8(rate))

        coins = []
        for k, v in swap_client.coin_clients.items():
            if v['connection_type'] == 'rpc':
                coins.append((int(k), getCoinName(k)))

        template = env.get_template('offer_new.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            coins=coins,
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
        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('offer', None) == form_id:
                messages.append('Prevented double submit for form {}.'.format(form_id))
            else:
                self.server.last_form_id['offer'] = form_id
                sent_bid_id = swap_client.postBid(offer_id, offer.amount_from).hex()

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ticker_from = swap_client.getTicker(coin_from)
        ticker_to = swap_client.getTicker(coin_to)
        data = {
            'tla_from': swap_client.getTicker(coin_from),
            'tla_to': swap_client.getTicker(coin_to),
            'state': getOfferState(offer.state),
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
            'sent': 'True' if offer.was_sent else 'False'
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
            bids=[(b.bid_id.hex(), format8(b.amount), getBidState(b.state), getTxState(b.initiate_txn_state), getTxState(b.participate_txn_state)) for b in bids],
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_offers(self, url_split, sent=False):
        swap_client = self.server.swap_client
        offers = swap_client.listOffers(sent)

        template = env.get_template('offers.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            page_type='Sent' if sent else 'Received',
            offers=[(time.strftime('%Y-%m-%d %H:%M', time.localtime(o.created_at)),
                     o.offer_id.hex(), getCoinName(Coins(o.coin_from)), getCoinName(Coins(o.coin_to)), format8(o.amount_from), format8((o.amount_from * o.rate) // COIN), format8(o.rate)) for o in offers],
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
        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('bid', None) == form_id:
                messages.append('Prevented double submit for form {}.'.format(form_id))
            else:
                self.server.last_form_id['bid'] = form_id
                if b'abandon_bid' in form_data:
                    try:
                        swap_client.abandonBid(bid_id)
                        messages.append('Bid abandoned')
                    except Exception as e:
                        messages.append('Error ' + str(e))
                if b'accept_bid' in form_data:
                    try:
                        swap_client.acceptBid(bid_id)
                        messages.append('Bid accepted')
                    except Exception as e:
                        messages.append('Error ' + str(e))
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
            if not bid.initiate_txid:
                state_description = 'Waiting for seller to send initiate tx.'
            else:
                state_description = 'Waiting for initiate tx to confirm.'
        elif bid.state == BidStates.SWAP_INITIATED:
            state_description = 'Waiting for participate txn to be confirmed in {} chain'.format(ticker_to)
        elif bid.state == BidStates.SWAP_PARTICIPATING:
            state_description = 'Waiting for initiate txn to be spent in {} chain'.format(ticker_from)
        elif bid.state == BidStates.SWAP_COMPLETED:
            state_description = 'Swap completed'
            if bid.initiate_txn_state == TxStates.TX_REDEEMED and bid.participate_txn_state == TxStates.TX_REDEEMED:
                state_description += ' successfully'
            else:
                state_description += ', ITX ' + getTxState(bid.initiate_txn_state + ', PTX ' + getTxState(bid.participate_txn_state))
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
            'bid_state': getBidState(bid.state),
            'state_description': state_description,
            'itx_state': getTxState(bid.initiate_txn_state),
            'ptx_state': getTxState(bid.participate_txn_state),
            'offer_id': bid.offer_id.hex(),
            'addr_from': bid.bid_addr,
            'addr_fund_proof': bid.proof_address,
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.created_at)),
            'expired_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.expire_at)),
            'was_sent': 'True' if bid.was_sent else 'False',
            'was_received': 'True' if bid.was_received else 'False',
            'initiate_tx': 'None' if not bid.initiate_txid else (bid.initiate_txid.hex() + ' ' + ticker_from),
            'initiate_conf': 'None' if not bid.initiate_txn_conf else bid.initiate_txn_conf,
            'participate_tx': 'None' if not bid.participate_txid else (bid.participate_txid.hex() + ' ' + ticker_to),
            'participate_conf': 'None' if not bid.participate_txn_conf else bid.participate_txn_conf,
            'show_txns': show_txns,
        }

        if show_txns:
            data['initiate_tx_refund'] = 'None' if not bid.initiate_txn_refund else bid.initiate_txn_refund.hex()
            data['participate_tx_refund'] = 'None' if not bid.participate_txn_refund else bid.participate_txn_refund.hex()
            data['initiate_tx_spend'] = 'None' if not bid.initiate_spend_txid else (bid.initiate_spend_txid.hex() + ' {}'.format(bid.initiate_spend_n))
            data['participate_tx_spend'] = 'None' if not bid.participate_spend_txid else (bid.participate_spend_txid.hex() + ' {}'.format(bid.participate_spend_n))

        old_states = []
        num_states = len(bid.states) // 12
        for i in range(num_states):
            up = struct.unpack_from('<iq', bid.states[i * 12:(i + 1) * 12])
            old_states.append((up[1], 'Bid ' + getBidState(up[0])))
        if bid.initiate_txn_states is not None:
            num_states = len(bid.initiate_txn_states) // 12
            for i in range(num_states):
                up = struct.unpack_from('<iq', bid.initiate_txn_states[i * 12:(i + 1) * 12])
                old_states.append((up[1], 'ITX ' + getTxState(up[0])))
        if bid.participate_txn_states is not None:
            num_states = len(bid.participate_txn_states) // 12
            for i in range(num_states):
                up = struct.unpack_from('<iq', bid.participate_txn_states[i * 12:(i + 1) * 12])
                old_states.append((up[1], 'PTX ' + getTxState(up[0])))
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
            bids=[(time.strftime('%Y-%m-%d %H:%M', time.localtime(b.created_at)),
                   b.bid_id.hex(), b.offer_id.hex(), getBidState(b.state), getTxState(b.initiate_txn_state), getTxState(b.participate_txn_state)) for b in bids],
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
            except Exception as e:
                return self.js_error(str(e))
        try:
            self.putHeaders(status_code, 'text/html')
            if len(url_split) > 1:
                if url_split[1] == 'active':
                    return self.page_active(url_split, post_string)
                if url_split[1] == 'wallets':
                    return self.page_wallets(url_split, post_string)
                if url_split[1] == 'offer':
                    return self.page_offer(url_split, post_string)
                if url_split[1] == 'offers':
                    return self.page_offers(url_split)
                if url_split[1] == 'newoffer':
                    return self.page_newoffer(url_split, post_string)
                if url_split[1] == 'sentoffers':
                    return self.page_offers(url_split, sent=True)
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
        except Exception as e:
            traceback.print_exc()  # TODO: Remove
            return self.page_error(str(e))

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
