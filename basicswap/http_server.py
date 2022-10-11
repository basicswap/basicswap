# -*- coding: utf-8 -*-

# Copyright (c) 2019-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import traceback
import threading
import http.client
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from jinja2 import Environment, PackageLoader

from . import __version__
from .util import (
    dumpj,
    ensure,
    format_timestamp,
)
from .chainparams import (
    Coins,
    chainparams,
)
from .basicswap_util import (
    strBidState,
    strTxState,
    strAddressType,
)

from .js_server import (
    js_error,
    js_url_to_function,
)
from .ui.util import (
    getCoinName,
    get_data_entry,
    have_data_entry,
    listAvailableCoins,
)
from .ui.page_automation import (
    page_automation_strategies,
    page_automation_strategy,
    page_automation_strategy_new,
)

from .ui.page_bids import page_bids, page_bid
from .ui.page_offers import page_offers, page_offer, page_newoffer
from .ui.page_tor import page_tor, get_tor_established_state
from .ui.page_wallet import page_wallets, page_wallet


env = Environment(loader=PackageLoader('basicswap', 'templates'))
env.filters['formatts'] = format_timestamp


def validateTextInput(text, name, messages, max_length=None):
    if max_length is not None and len(text) > max_length:
        messages.append(f'Error: {name} is too long')
        return False
    if len(text) > 0 and all(c.isalnum() or c.isspace() for c in text) is False:
        messages.append(f'Error: {name} must consist of only letters and digits')
        return False
    return True


def extractDomain(url):
    return url.split('://', 1)[1].split('/', 1)[0]


def listAvailableExplorers(swap_client):
    explorers = []
    for c in Coins:
        if c not in chainparams:
            continue
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


class HttpHandler(BaseHTTPRequestHandler):

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

    def render_template(self, template, args_dict):
        swap_client = self.server.swap_client
        if swap_client.ws_server:
            args_dict['ws_url'] = swap_client.ws_server.url
        if swap_client.debug:
            args_dict['debug_mode'] = True
        if swap_client.debug_ui:
            args_dict['debug_ui_mode'] = True
        if swap_client.use_tor_proxy:
            args_dict['use_tor_proxy'] = True
            # TODO: Cache value?
            try:
                args_dict['tor_established'] = True if get_tor_established_state(swap_client) == '1' else False
            except Exception:
                if swap_client.debug:
                    swap_client.log.error(traceback.format_exc())

        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            form_id=os.urandom(8).hex(),
            **args_dict,
        ), 'UTF-8')

    def render_simple_template(self, template, args_dict):
        swap_client = self.server.swap_client
        return bytes(template.render(
            title=self.server.title,
            **args_dict,
        ), 'UTF-8')

    def page_info(self, info_str, post_string):
        template = env.get_template('info.html')
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()
        return self.render_template(template, {
            'title_str': 'BasicSwap Info',
            'message_str': info_str,
            'summary': summary,
        })

    def page_error(self, error_str, post_string):
        template = env.get_template('error.html')
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()
        return self.render_template(template, {
            'title_str': 'BasicSwap Error',
            'message_str': error_str,
            'summary': summary,
        })

    def page_explorers(self, url_split, post_string):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

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
        return self.render_template(template, {
            'explorers': listAvailableExplorers(swap_client),
            'explorer': explorer,
            'actions': listExplorerActions(swap_client),
            'action': action,
            'result': result,
            'summary': summary,
        })

    def page_rpc(self, url_split, post_string):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        result = None
        coin_type = -1
        coin_id = -1
        messages = []
        form_data = self.checkForm(post_string, 'rpc', messages)
        if form_data:
            try:
                coin_id = int(form_data[b'coin_type'][0])
                if coin_id in (-2, -3, -4):
                    coin_type = Coins(Coins.XMR)
                else:
                    coin_type = Coins(coin_id)
            except Exception:
                raise ValueError('Unknown Coin Type')

            cmd = form_data[b'cmd'][0].decode('utf-8')

            try:
                if coin_type == Coins.XMR:
                    ci = swap_client.ci(coin_type)
                    arr = cmd.split(None, 1)
                    method = arr[0]
                    params = json.loads(arr[1]) if len(arr) > 1 else []
                    if coin_id == -4:
                        rv = ci.rpc_wallet_cb(method, params)
                    elif coin_id == -3:
                        rv = ci.rpc_cb(method, params)
                    elif coin_id == -2:
                        if params == []:
                            params = None
                        rv = ci.rpc_cb2(method, params)
                    else:
                        raise ValueError('Unknown XMR RPC variant')
                    result = json.dumps(rv, indent=4)
                else:
                    result = cmd + '\n' + swap_client.callcoincli(coin_type, cmd)
            except Exception as ex:
                result = str(ex)
                if self.server.swap_client.debug is True:
                    self.server.swap_client.log.error(traceback.format_exc())

        template = env.get_template('rpc.html')

        coins = listAvailableCoins(swap_client, with_variants=False)
        coins = [c for c in coins if c[0] != Coins.XMR]
        coins.append((-2, 'Monero'))
        coins.append((-3, 'Monero JSON'))
        coins.append((-4, 'Monero Wallet'))

        return self.render_template(template, {
            'coins': coins,
            'coin_type': coin_id,
            'result': result,
            'messages': messages,
            'summary': summary,
        })

    def page_debug(self, url_split, post_string):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        result = None
        messages = []
        form_data = self.checkForm(post_string, 'wallets', messages)
        if form_data:
            if have_data_entry(form_data, 'reinit_xmr'):
                try:
                    swap_client.initialiseWallet(Coins.XMR)
                    messages.append('Done.')
                except Exception as a:
                    messages.append('Failed.')

        template = env.get_template('debug.html')
        return self.render_template(template, {
            'messages': messages,
            'result': result,
            'summary': summary,
        })

    def page_active(self, url_split, post_string):
        swap_client = self.server.swap_client
        active_swaps = swap_client.listSwapsInProgress()
        summary = swap_client.getSummary()

        template = env.get_template('active.html')
        return self.render_template(template, {
            'refresh': 30,
            'active_swaps': [(s[0].hex(), s[1], strBidState(s[2]), strTxState(s[3]), strTxState(s[4])) for s in active_swaps],
            'summary': summary,
        })

    def page_settings(self, url_split, post_string):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        messages = []
        form_data = self.checkForm(post_string, 'settings', messages)
        if form_data:
            for name, c in swap_client.settings['chainclients'].items():
                if have_data_entry(form_data, 'apply_' + name):
                    data = {'lookups': get_data_entry(form_data, 'lookups_' + name)}
                    if name == 'monero':
                        data['fee_priority'] = int(get_data_entry(form_data, 'fee_priority_' + name))
                        data['manage_daemon'] = True if get_data_entry(form_data, 'managedaemon_' + name) == 'true' else False
                        data['rpchost'] = get_data_entry(form_data, 'rpchost_' + name)
                        data['rpcport'] = int(get_data_entry(form_data, 'rpcport_' + name))
                        data['remotedaemonurls'] = get_data_entry(form_data, 'remotedaemonurls_' + name)
                        data['automatically_select_daemon'] = True if get_data_entry(form_data, 'autosetdaemon_' + name) == 'true' else False
                    else:
                        data['conf_target'] = int(get_data_entry(form_data, 'conf_target_' + name))
                        if name == 'particl':
                            data['anon_tx_ring_size'] = int(get_data_entry(form_data, 'rct_ring_size_' + name))

                    settings_changed, suggest_reboot = swap_client.editSettings(name, data)
                    if settings_changed is True:
                        messages.append('Settings applied.')
                    if suggest_reboot is True:
                        messages.append('Please restart BasicSwap.')
                elif have_data_entry(form_data, 'enable_' + name):
                    swap_client.enableCoin(name)
                    messages.append(name.capitalize() + ' enabled, shutting down.')
                    swap_client.stopRunning()
                elif have_data_entry(form_data, 'disable_' + name):
                    swap_client.disableCoin(name)
                    messages.append(name.capitalize() + ' disabled, shutting down.')
                    swap_client.stopRunning()
        chains_formatted = []

        sorted_names = sorted(swap_client.settings['chainclients'].keys())
        for name in sorted_names:
            c = swap_client.settings['chainclients'][name]
            chains_formatted.append({
                'name': name,
                'lookups': c.get('chain_lookups', 'local'),
                'manage_daemon': c.get('manage_daemon', 'Unknown'),
                'connection_type': c.get('connection_type', 'Unknown'),
            })
            if name == 'monero':
                chains_formatted[-1]['fee_priority'] = c.get('fee_priority', 0)
                chains_formatted[-1]['manage_wallet_daemon'] = c.get('manage_wallet_daemon', 'Unknown')
                chains_formatted[-1]['rpchost'] = c.get('rpchost', 'localhost')
                chains_formatted[-1]['rpcport'] = int(c.get('rpcport', 18081))
                chains_formatted[-1]['remotedaemonurls'] = '\n'.join(c.get('remote_daemon_urls', []))
                chains_formatted[-1]['autosetdaemon'] = c.get('automatically_select_daemon', False)
            else:
                chains_formatted[-1]['conf_target'] = c.get('conf_target', 2)

            if name == 'particl':
                chains_formatted[-1]['anon_tx_ring_size'] = c.get('anon_tx_ring_size', 12)
            else:
                if c.get('connection_type', 'Unknown') == 'none':
                    if 'connection_type_prev' in c:
                        chains_formatted[-1]['can_reenable'] = True
                else:
                    chains_formatted[-1]['can_disable'] = True

        template = env.get_template('settings.html')
        return self.render_template(template, {
            'messages': messages,
            'chains': chains_formatted,
            'summary': summary,
        })

    def page_watched(self, url_split, post_string):
        swap_client = self.server.swap_client
        watched_outputs, last_scanned = swap_client.listWatchedOutputs()
        summary = swap_client.getSummary()

        template = env.get_template('watched.html')
        return self.render_template(template, {
            'refresh': 30,
            'last_scanned': [(getCoinName(ls[0]), ls[1]) for ls in last_scanned],
            'watched_outputs': [(wo[1].hex(), getCoinName(wo[0]), wo[2], wo[3], int(wo[4])) for wo in watched_outputs],
            'summary': summary,
        })

    def page_smsgaddresses(self, url_split, post_string):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        page_data = {}
        messages = []
        smsgaddresses = []

        listaddresses = True
        form_data = self.checkForm(post_string, 'smsgaddresses', messages)
        if form_data:
            edit_address_id = None
            for key in form_data:
                if key.startswith(b'editaddr_'):
                    edit_address_id = int(key.split(b'_')[1])
                    break
            if edit_address_id is not None:
                listaddresses = False
                page_data['edit_address'] = edit_address_id
                page_data['addr_data'] = swap_client.listAllSMSGAddresses(addr_id=edit_address_id)[0]
            elif b'saveaddr' in form_data:
                edit_address_id = int(form_data[b'edit_address_id'][0].decode('utf-8'))
                edit_addr = form_data[b'edit_address'][0].decode('utf-8')
                active_ind = int(form_data[b'active_ind'][0].decode('utf-8'))
                ensure(active_ind in (0, 1), 'Invalid sort by')
                addressnote = '' if b'addressnote' not in form_data else form_data[b'addressnote'][0].decode('utf-8')
                if not validateTextInput(addressnote, 'Address note', messages, max_length=30):
                    listaddresses = False
                    page_data['edit_address'] = edit_address_id
                else:
                    swap_client.editSMSGAddress(edit_addr, active_ind=active_ind, addressnote=addressnote)
                    messages.append(f'Edited address {edit_addr}')
            elif b'shownewaddr' in form_data:
                listaddresses = False
                page_data['new_address'] = True
            elif b'showaddaddr' in form_data:
                listaddresses = False
                page_data['new_send_address'] = True
            elif b'createnewaddr' in form_data:
                addressnote = '' if b'addressnote' not in form_data else form_data[b'addressnote'][0].decode('utf-8')
                if not validateTextInput(addressnote, 'Address note', messages, max_length=30):
                    listaddresses = False
                    page_data['new_address'] = True
                else:
                    new_addr, pubkey = swap_client.newSMSGAddress(addressnote=addressnote)
                    messages.append(f'Created address {new_addr}, pubkey {pubkey}')
            elif b'createnewsendaddr' in form_data:
                pubkey_hex = form_data[b'addresspubkey'][0].decode('utf-8')
                addressnote = '' if b'addressnote' not in form_data else form_data[b'addressnote'][0].decode('utf-8')
                if not validateTextInput(addressnote, 'Address note', messages, max_length=30) or \
                   not validateTextInput(pubkey_hex, 'Pubkey', messages, max_length=66):
                    listaddresses = False
                    page_data['new_send_address'] = True
                else:
                    new_addr = swap_client.addSMSGAddress(pubkey_hex, addressnote=addressnote)
                    messages.append(f'Added address {new_addr}')

        if listaddresses is True:
            smsgaddresses = swap_client.listAllSMSGAddresses()
        network_addr = swap_client.network_addr

        for addr in smsgaddresses:
            addr['type'] = strAddressType(addr['type'])

        template = env.get_template('smsgaddresses.html')
        return self.render_template(template, {
            'messages': messages,
            'data': page_data,
            'smsgaddresses': smsgaddresses,
            'network_addr': network_addr,
            'summary': summary,
        })

    def page_identity(self, url_split, post_string):
        ensure(len(url_split) > 2, 'Address not specified')
        identity_address = url_split[2]
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        page_data = {'identity_address': identity_address}
        messages = []
        form_data = self.checkForm(post_string, 'identity', messages)
        if form_data:
            if have_data_entry(form_data, 'edit'):
                page_data['show_edit_form'] = True
            if have_data_entry(form_data, 'apply'):
                new_label = get_data_entry(form_data, 'label')

                try:
                    swap_client.updateIdentity(identity_address, new_label)
                    messages.append('Updated')
                except Exception as e:
                    messages.append('Error')

        try:
            identity = swap_client.getIdentity(identity_address)
            if identity is None:
                raise ValueError('Unknown address')
            page_data['label'] = identity.label
            page_data['num_sent_bids_successful'] = identity.num_sent_bids_successful
            page_data['num_recv_bids_successful'] = identity.num_recv_bids_successful
            page_data['num_sent_bids_rejected'] = identity.num_sent_bids_rejected
            page_data['num_recv_bids_rejected'] = identity.num_recv_bids_rejected
            page_data['num_sent_bids_failed'] = identity.num_sent_bids_failed
            page_data['num_recv_bids_failed'] = identity.num_recv_bids_failed
        except Exception as e:
            messages.append(e)

        template = env.get_template('identity.html')
        return self.render_template(template, {
            'messages': messages,
            'data': page_data,
            'summary': summary,
        })

    def page_shutdown(self, url_split, post_string):
        swap_client = self.server.swap_client

        if len(url_split) > 2:
            token = url_split[2]
            expect_token = self.server.session_tokens.get('shutdown', None)
            if token != expect_token:
                return self.page_info('Unexpected token, still running.')

        swap_client.stopRunning()

        return self.page_info('Shutting down')

    def page_index(self, url_split):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()

        shutdown_token = os.urandom(8).hex()
        self.server.session_tokens['shutdown'] = shutdown_token

        template = env.get_template('index.html')
        return self.render_template(template, {
            'refresh': 30,
            'version': __version__,
            'summary': summary,
            'use_tor_proxy': swap_client.use_tor_proxy,
            'shutdown_token': shutdown_token
        })

    def page_404(self, url_split):
        template = env.get_template('404.html')
        return bytes(template.render(
            title=self.server.title,
        ), 'UTF-8')

    def putHeaders(self, status_code, content_type):
        self.send_response(status_code)
        if self.server.allow_cors:
            self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', content_type)
        self.end_headers()

    def handle_http(self, status_code, path, post_string='', is_json=False):
        parsed = urllib.parse.urlparse(self.path)
        url_split = parsed.path.split('/')
        if post_string == '' and len(parsed.query) > 0:
            post_string = parsed.query
        if len(url_split) > 1 and url_split[1] == 'json':
            try:
                self.putHeaders(status_code, 'text/plain')
                func = js_url_to_function(url_split)
                return func(self, url_split, post_string, is_json)
            except Exception as ex:
                if self.server.swap_client.debug is True:
                    self.server.swap_client.log.error(traceback.format_exc())
                return js_error(self, str(ex))

        if len(url_split) > 1 and url_split[1] == 'static':
            try:
                static_path = os.path.join(os.path.dirname(__file__), 'static')

                if len(url_split) > 3 and url_split[2] == 'sequence_diagrams':
                    with open(os.path.join(static_path, 'sequence_diagrams', url_split[3]), 'rb') as fp:
                        self.putHeaders(status_code, 'image/svg+xml')
                        return fp.read()
                elif len(url_split) > 3 and url_split[2] == 'images':
                    filename = os.path.join(*url_split[3:])
                    _, extension = os.path.splitext(filename)
                    mime_type = {
                        '.svg': 'image/svg+xml',
                        '.png': 'image/png',
                        '.jpg': 'image/jpeg',
                        '.gif': 'image/gif',
                        '.ico': 'image/x-icon',
                    }.get(extension, '')
                    if mime_type == '':
                        raise ValueError('Unknown file type ' + filename)
                    with open(os.path.join(static_path, 'images', filename), 'rb') as fp:
                        self.putHeaders(status_code, mime_type)
                        return fp.read()
                elif len(url_split) > 3 and url_split[2] == 'css':
                    filename = os.path.join(*url_split[3:])
                    with open(os.path.join(static_path, 'css', filename), 'rb') as fp:
                        self.putHeaders(status_code, 'text/css; charset=utf-8')
                        return fp.read()
                elif len(url_split) > 3 and url_split[2] == 'js':
                    filename = os.path.join(*url_split[3:])
                    with open(os.path.join(static_path, 'js', filename), 'rb') as fp:
                        self.putHeaders(status_code, 'application/javascript')
                        return fp.read()
                else:
                    self.putHeaders(status_code, 'text/html')
                    return self.page_404(url_split)
            except FileNotFoundError:
                self.putHeaders(status_code, 'text/html')
                return self.page_404(url_split)
            except Exception as ex:
                if self.server.swap_client.debug is True:
                    self.server.swap_client.log.error(traceback.format_exc())
                self.putHeaders(status_code, 'text/html')
                return self.page_error(str(ex))

        try:
            self.putHeaders(status_code, 'text/html')
            if len(url_split) > 1:
                page = url_split[1]
                if page == 'active':
                    return self.page_active(url_split, post_string)
                if page == 'wallets':
                    return page_wallets(self, url_split, post_string)
                if page == 'wallet':
                    return page_wallet(self, url_split, post_string)
                if page == 'settings':
                    return self.page_settings(url_split, post_string)
                if page == 'error':
                    return self.page_error(url_split, post_string)
                if page == 'info':
                    return self.page_info(url_split, post_string)
                if page == 'rpc':
                    return self.page_rpc(url_split, post_string)
                if page == 'debug':
                    return self.page_debug(url_split, post_string)
                if page == 'explorers':
                    return self.page_explorers(url_split, post_string)
                if page == 'offer':
                    return page_offer(self, url_split, post_string)
                if page == 'offers':
                    return page_offers(self, url_split, post_string)
                if page == 'newoffer':
                    return page_newoffer(self, url_split, post_string)
                if page == 'sentoffers':
                    return page_offers(self, url_split, post_string, sent=True)
                if page == 'bid':
                    return page_bid(self, url_split, post_string)
                if page == 'receivedbids':
                    return page_bids(self, url_split, post_string, received=True)
                if page == 'sentbids':
                    return page_bids(self, url_split, post_string, sent=True)
                if page == 'availablebids':
                    return page_bids(self, url_split, post_string, available=True)
                if page == 'watched':
                    return self.page_watched(url_split, post_string)
                if page == 'smsgaddresses':
                    return self.page_smsgaddresses(url_split, post_string)
                if page == 'identity':
                    return self.page_identity(url_split, post_string)
                if page == 'tor':
                    return page_tor(self, url_split, post_string)
                if page == 'automation':
                    return page_automation_strategies(self, url_split, post_string)
                if page == 'automationstrategy':
                    return page_automation_strategy(self, url_split, post_string)
                if page == 'newautomationstrategy':
                    return page_automation_strategy_new(self, url_split, post_string)
                if page == 'shutdown':
                    return self.page_shutdown(url_split, post_string)
                if page != '':
                    return self.page_404(url_split)
            return self.page_index(url_split)
        except Exception as ex:
            if self.server.swap_client.debug is True:
                self.server.swap_client.log.error(traceback.format_exc())
            return self.page_error(str(ex))

    def do_GET(self):
        response = self.handle_http(200, self.path)
        self.wfile.write(response)

    def do_POST(self):
        post_string = self.rfile.read(int(self.headers.get('Content-Length')))

        is_json = True if 'json' in self.headers.get('Content-Type', '') else False
        response = self.handle_http(200, self.path, post_string, is_json)
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
        self.title = 'BasicSwap - ' + __version__
        self.last_form_id = dict()
        self.session_tokens = dict()
        self.env = env

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
