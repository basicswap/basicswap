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
)


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

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>Active Swaps</h3>'

        active_swaps = swap_client.listSwapsInProgress()

        content += '<table>'
        content += '<tr><th>Bid ID</th><th>Offer ID</th><th>Bid Status</th></tr>'
        for s in active_swaps:
            content += '<tr><td><a href=/bid/{0}>{0}</a></td><td><a href=/offer/{1}>{1}</a></td><td>{2}</td></tr>'.format(s[0].hex(), s[1], getBidState(s[2]))
        content += '</table>'

        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def page_wallets(self, url_split, post_string):
        swap_client = self.server.swap_client

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>Wallets</h3>'

        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('wallets', None) == form_id:
                content += '<p>Prevented double submit for form {}.</p>'.format(form_id)
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
                        content += '<p>Withdrew {} {} to address {}<br/>In txid: {}</p>'.format(value, ticker, address, txid)

        wallets = swap_client.getWalletsInfo()

        content += '<form method="post">'
        for k, w in wallets.items():
            cid = str(int(k))
            content += '<h4>' + w['name'] + '</h4>' \
                + '<table>' \
                + '<tr><td>Balance:</td><td>' + w['balance'] + '</td></tr>' \
                + '<tr><td>Blocks:</td><td>' + str(w['blocks']) + '</td></tr>' \
                + '<tr><td>Synced:</td><td>' + str(w['synced']) + '</td></tr>' \
                + '<tr><td><input type="submit" name="newaddr_' + cid + '" value="Deposit Address"></td><td>' + str(w['deposit_address']) + '</td></tr>' \
                + '<tr><td><input type="submit" name="withdraw_' + cid + '" value="Withdraw"></td><td>Amount: <input type="text" name="amt_' + cid + '"></td><td>Address: <input type="text" name="to_' + cid + '"></td><td>Subtract fee: <input type="checkbox" name="subfee_' + cid + '"></td></tr>' \
                + '</table>'

        content += '<input type="hidden" name="formid" value="' + os.urandom(8).hex() + '"></form>'
        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def make_coin_select(self, name, coins):
        s = '<select name="' + name + '"><option value="-1">-- Select Coin --</option>'
        for c in coins:
            s += '<option value="{}">{}</option>'.format(*c)
        s += '</select>'
        return s

    def page_newoffer(self, url_split, post_string):
        swap_client = self.server.swap_client

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>New Offer</h3>'

        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('newoffer', None) == form_id:
                content += '<p>Prevented double submit for form {}.</p>'.format(form_id)
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
                offer_id = swap_client.postOffer(coin_from, coin_to, value_from, rate, min_bid, SwapTypes.SELLER_FIRST, auto_accept_bids=autoaccept, lock_value=lock_seconds)
                content += '<p><a href="/offer/' + offer_id.hex() + '">Sent Offer ' + offer_id.hex() + '</a><br/>Rate: ' + format8(rate) + '</p>'

        coins = []

        for k, v in swap_client.coin_clients.items():
            if v['connection_type'] == 'rpc':
                coins.append((int(k), getCoinName(k)))

        content += '<form method="post">'

        content += '<table>'
        content += '<tr><td>Coin From</td><td>' + self.make_coin_select('coin_from', coins) + '</td><td>Amount From</td><td><input type="text" name="amt_from"></td></tr>'
        content += '<tr><td>Coin To</td><td>' + self.make_coin_select('coin_to', coins) + '</td><td>Amount To</td><td><input type="text" name="amt_to"></td></tr>'

        content += '<tr><td>Contract locked (hrs)</td><td><input type="number" name="lockhrs" min="2" max="96" value="48"></td><td colspan=2>Participate txn will be locked for half the time.</td></tr>'
        content += '<tr><td>Auto Accept Bids</td><td colspan=3><input type="checkbox" name="autoaccept" value="aa" checked></td></tr>'
        content += '</table>'

        content += '<input type="submit" value="Submit">'
        content += '<input type="hidden" name="formid" value="' + os.urandom(8).hex() + '"></form>'
        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

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

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>Offer: ' + offer_id.hex() + '</h3>'

        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('offer', None) == form_id:
                content += '<p>Prevented double submit for form {}.</p>'.format(form_id)
            else:
                self.server.last_form_id['offer'] = form_id
                bid_id = swap_client.postBid(offer_id, offer.amount_from)
                content += '<p><a href="/bid/' + bid_id.hex() + '">Sent Bid ' + bid_id.hex() + '</a></p>'

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ticker_from = swap_client.getTicker(coin_from)
        ticker_to = swap_client.getTicker(coin_to)

        tr = '<tr><td>{}</td><td>{}</td></tr>'
        content += '<table>'
        content += tr.format('Offer State', getOfferState(offer.state))
        content += tr.format('Coin From', getCoinName(coin_from))
        content += tr.format('Coin To', getCoinName(coin_to))
        content += tr.format('Amount From', format8(offer.amount_from) + ' ' + ticker_from)
        content += tr.format('Amount To', format8((offer.amount_from * offer.rate) // COIN) + ' ' + ticker_to)
        content += tr.format('Rate', format8(offer.rate) + ' ' + ticker_from + '/' + ticker_to)
        content += tr.format('Script Lock Type', getLockName(offer.lock_type))
        content += tr.format('Script Lock Value', offer.lock_value)
        content += tr.format('Address From', offer.addr_from)
        content += tr.format('Created At', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(offer.created_at)))
        content += tr.format('Expired At', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(offer.expire_at)))
        content += tr.format('Sent', 'True' if offer.was_sent else 'False')

        if offer.was_sent:
            content += tr.format('Auto Accept Bids', 'True' if offer.auto_accept_bids else 'False')
        content += '</table>'

        bids = swap_client.listBids(offer_id=offer_id)

        content += '<h4>Bids</h4><table>'
        content += '<tr><th>Bid ID</th><th>Bid Amount</th><th>Bid Status</th><th>ITX Status</th><th>PTX Status</th></tr>'
        for b in bids:
            content += '<tr><td><a href=/bid/{0}>{0}</a></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>'.format(b.bid_id.hex(), format8(b.amount), getBidState(b.state), getTxState(b.initiate_txn_state), getTxState(b.participate_txn_state))
        content += '</table>'

        content += '<form method="post">'
        content += '<input type="submit" value="Send Bid">'
        content += '<input type="hidden" name="formid" value="' + os.urandom(8).hex() + '"></form>'
        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def page_offers(self, url_split, sent=False):
        swap_client = self.server.swap_client
        offers = swap_client.listOffers(sent)

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>' + ('Sent ' if sent else '') + 'Offers</h3>'

        content += '<table>'
        content += '<tr><th>Offer ID</th><th>Coin From</th><th>Coin To</th><th>Amount From</th><th>Amount To</th><th>Rate</th></tr>'
        for o in offers:
            coin_from_name = getCoinName(Coins(o.coin_from))
            coin_to_name = getCoinName(Coins(o.coin_to))
            amount_to = (o.amount_from * o.rate) // COIN
            content += '<tr><td><a href=/offer/{0}>{0}</a></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>'.format(o.offer_id.hex(), coin_from_name, coin_to_name, format8(o.amount_from), format8(amount_to), format8(o.rate))

        content += '</table>'
        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def page_advance(self, url_split, post_string):
        assert(len(url_split) > 2), 'Bid ID not specified'
        try:
            bid_id = bytes.fromhex(url_split[2])
            assert(len(bid_id) == 28)
        except Exception:
            raise ValueError('Bad bid ID')
        swap_client = self.server.swap_client

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>Advance: ' + bid_id.hex() + '</h3>'

    def page_bid(self, url_split, post_string):
        assert(len(url_split) > 2), 'Bid ID not specified'
        try:
            bid_id = bytes.fromhex(url_split[2])
            assert(len(bid_id) == 28)
        except Exception:
            raise ValueError('Bad bid ID')
        swap_client = self.server.swap_client

        content = html_content_start(self.server.title, self.server.title, 30) \
            + '<h3>Bid: ' + bid_id.hex() + '</h3>' \
            + '<p>Page Refresh: 30 seconds</p>'

        show_txns = False
        if post_string != '':
            form_data = urllib.parse.parse_qs(post_string)
            form_id = form_data[b'formid'][0].decode('utf-8')
            if self.server.last_form_id.get('bid', None) == form_id:
                content += '<p>Prevented double submit for form {}.</p>'.format(form_id)
            else:
                self.server.last_form_id['bid'] = form_id
                if b'abandon_bid' in form_data:
                    try:
                        swap_client.abandonBid(bid_id)
                        content += '<p>Bid abandoned</p>'
                    except Exception as e:
                        content += '<p>Error' + str(e) + '</p>'
                if b'accept_bid' in form_data:
                    try:
                        swap_client.acceptBid(bid_id)
                        content += '<p>Bid accepted</p>'
                    except Exception as e:
                        content += '<p>Error' + str(e) + '</p>'
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

        tr = '<tr><td>{}</td><td>{}</td></tr>'
        content += '<table>'

        content += tr.format('Swap', format8(bid.amount) + ' ' + ticker_from + ' for ' + format8((bid.amount * offer.rate) // COIN) + ' ' + ticker_to)
        content += tr.format('Bid State', getBidState(bid.state))
        content += tr.format('State Description', state_description)
        content += tr.format('ITX State', getTxState(bid.initiate_txn_state))
        content += tr.format('PTX State', getTxState(bid.participate_txn_state))
        content += tr.format('Offer', '<a href="/offer/' + bid.offer_id.hex() + '">' + bid.offer_id.hex() + '</a>')
        content += tr.format('Address From', bid.bid_addr)
        content += tr.format('Proof of Funds', bid.proof_address)
        content += tr.format('Created At', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.created_at)))
        content += tr.format('Expired At', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.expire_at)))
        content += tr.format('Sent', 'True' if bid.was_sent else 'False')
        content += tr.format('Received', 'True' if bid.was_received else 'False')
        content += tr.format('Initiate Tx', 'None' if not bid.initiate_txid else (bid.initiate_txid.hex() + ' ' + ticker_from))
        content += tr.format('Initiate Conf', 'None' if not bid.initiate_txn_conf else bid.initiate_txn_conf)
        content += tr.format('Participate Tx', 'None' if not bid.participate_txid else (bid.participate_txid.hex() + ' ' + ticker_to))
        content += tr.format('Participate Conf', 'None' if not bid.participate_txn_conf else bid.participate_txn_conf)
        if show_txns:
            content += tr.format('Initiate Tx Refund', 'None' if not bid.initiate_txn_refund else bid.initiate_txn_refund.hex())
            content += tr.format('Participate Tx Refund', 'None' if not bid.participate_txn_refund else bid.participate_txn_refund.hex())
            content += tr.format('Initiate Spend Tx', 'None' if not bid.initiate_spend_txid else (bid.initiate_spend_txid.hex() + ' {}'.format(bid.initiate_spend_n)))
            content += tr.format('Participate Spend Tx', 'None' if not bid.participate_spend_txid else (bid.participate_spend_txid.hex() + ' {}'.format(bid.participate_spend_n)))
        content += '</table>'

        content += '<form method="post">'
        if bid.was_received:
            content += '<input name="accept_bid" type="submit" value="Accept Bid"><br/>'
        content += '<input name="abandon_bid" type="submit" value="Abandon Bid">'
        content += '<input name="show_txns" type="submit" value="Show More Info">'
        content += '<input type="hidden" name="formid" value="' + os.urandom(8).hex() + '"></form>'

        content += '<h4>Old States</h4><table><tr><th>State</th><th>Set At</th></tr>'
        num_states = len(bid.states) // 12
        for i in range(num_states):
            up = struct.unpack_from('<iq', bid.states[i * 12:(i + 1) * 12])
            content += '<tr><td>Bid {}</td><td>{}</td></tr>'.format(getBidState(up[0]), time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(up[1])))
        if bid.initiate_txn_states is not None:
            num_states = len(bid.initiate_txn_states) // 12
            for i in range(num_states):
                up = struct.unpack_from('<iq', bid.initiate_txn_states[i * 12:(i + 1) * 12])
                content += '<tr><td>ITX {}</td><td>{}</td></tr>'.format(getTxState(up[0]), time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(up[1])))
        if bid.participate_txn_states is not None:
            num_states = len(bid.participate_txn_states) // 12
            for i in range(num_states):
                up = struct.unpack_from('<iq', bid.participate_txn_states[i * 12:(i + 1) * 12])
                content += '<tr><td>PTX {}</td><td>{}</td></tr>'.format(getTxState(up[0]), time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(up[1])))
        content += '</table>'

        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def page_bids(self, url_split, post_string, sent=False):
        swap_client = self.server.swap_client
        bids = swap_client.listBids(sent=sent)

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>' + ('Sent ' if sent else '') + 'Bids</h3>'

        content += '<table>'
        content += '<tr><th>Bid ID</th><th>Offer ID</th><th>Bid Status</th><th>ITX Status</th><th>PTX Status</th></tr>'
        for b in bids:
            content += '<tr><td><a href=/bid/{0}>{0}</a></td><td><a href=/offer/{1}>{1}</a></td><td>{2}</td><td>{3}</td><td>{4}</td></tr>'.format(b.bid_id.hex(), b.offer_id.hex(), getBidState(b.state), getTxState(b.initiate_txn_state), getTxState(b.participate_txn_state))
        content += '</table>'

        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def page_watched(self, url_split, post_string):
        swap_client = self.server.swap_client
        watched_outputs, last_scanned = swap_client.listWatchedOutputs()

        content = html_content_start(self.server.title, self.server.title) \
            + '<h3>Watched Outputs</h3>'

        for c in last_scanned:
            content += '<p>' + getCoinName(c[0]) + ' Scanned Height: ' + str(c[1]) + '</p>'

        content += '<table>'
        content += '<tr><th>Bid ID</th><th>Chain</th><th>Txid</th><th>Index</th><th>Type</th></tr>'
        for o in watched_outputs:
            content += '<tr><td><a href=/bid/{0}>{0}</a></td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>'.format(o[1].hex(), getCoinName(o[0]), o[2], o[3], int(o[4]))
        content += '</table>'

        content += '<p><a href="/">home</a></p></body></html>'
        return bytes(content, 'UTF-8')

    def page_index(self, url_split):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        content = html_content_start(self.server.title, self.server.title, 30) \
            + '<p><a href="/wallets">View Wallets</a></p>' \
            + '<p>' \
            + 'Page Refresh: 30 seconds<br/>' \
            + 'Network: ' + str(summary['network']) + '<br/>' \
            + '<a href="/active">Swaps in progress: ' + str(summary['num_swapping']) + '</a><br/>' \
            + '<a href="/offers">Network Offers: ' + str(summary['num_network_offers']) + '</a><br/>' \
            + '<a href="/sentoffers">Sent Offers: ' + str(summary['num_sent_offers']) + '</a><br/>' \
            + '<a href="/bids">Received Bids: ' + str(summary['num_recv_bids']) + '</a><br/>' \
            + '<a href="/sentbids">Sent Bids: ' + str(summary['num_sent_bids']) + '</a><br/>' \
            + '<a href="/watched">Watched Outputs: ' + str(summary['num_watched_outputs']) + '</a><br/>' \
            + '</p>' \
            + '<p>' \
            + '<a href="/newoffer">New Offer</a><br/>' \
            + '</p>'
        content += '</body></html>'
        return bytes(content, 'UTF-8')

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
