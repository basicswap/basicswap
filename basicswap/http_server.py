# -*- coding: utf-8 -*-

# Copyright (c) 2019-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import json
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
    ensure,
    format_timestamp,
)
from .chainparams import (
    Coins,
    chainparams,
    getCoinIdFromTicker,
)
from .basicswap_util import (
    SwapTypes,
    DebugTypes,
    strBidState,
    strTxState,
    strAddressType,
)
from .js_server import (
    js_error,
    js_wallets,
    js_offers,
    js_sentoffers,
    js_bids,
    js_sentbids,
    js_network,
    js_revokeoffer,
    js_smsgaddresses,
    js_rates,
    js_rate,
    js_index,
)
from .ui.util import (
    PAGE_LIMIT,
    describeBid,
    getCoinName,
    get_data_entry,
    have_data_entry,
    get_data_entry_or,
    listAvailableCoins,
    set_pagination_filters,
)
from .ui.page_tor import page_tor
from .ui.page_offers import page_offers, page_offer, page_newoffer
from .ui.page_automation import (
    page_automation_strategies,
    page_automation_strategy,
    page_automation_strategy_new,
)


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
                if coin_type == Coins.XMR:
                    ci = swap_client.ci(coin_type)
                    arr = cmd.split(None, 1)
                    method = arr[0]
                    params = json.loads(arr[1]) if len(arr) > 1 else []
                    result = json.dumps(ci.rpc_wallet_cb(method, params), indent=4)
                else:
                    result = cmd + '\n' + swap_client.callcoincli(coin_type, cmd)
            except Exception as ex:
                result = str(ex)

        template = env.get_template('rpc.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            coins=listAvailableCoins(swap_client, with_variants=False),
            coin_type=coin_type,
            result=result,
            messages=messages,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_debug(self, url_split, post_string):
        swap_client = self.server.swap_client

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
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
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

        page_data = {}
        messages = []
        form_data = self.checkForm(post_string, 'wallets', messages)
        if form_data:
            for c in Coins:
                if c not in chainparams:
                    continue
                cid = str(int(c))

                if bytes('newaddr_' + cid, 'utf-8') in form_data:
                    swap_client.cacheNewAddressForCoin(c)
                elif bytes('reseed_' + cid, 'utf-8') in form_data:
                    try:
                        swap_client.reseedWallet(c)
                        messages.append('Reseed complete ' + str(c))
                    except Exception as ex:
                        messages.append('Reseed failed ' + str(ex))
                    swap_client.updateWalletsInfo(True, c)
                elif bytes('withdraw_' + cid, 'utf-8') in form_data:
                    try:
                        value = form_data[bytes('amt_' + cid, 'utf-8')][0].decode('utf-8')
                        page_data['wd_value_' + cid] = value
                    except Exception as e:
                        messages.append('Error: Missing value')
                    try:
                        address = form_data[bytes('to_' + cid, 'utf-8')][0].decode('utf-8')
                        page_data['wd_address_' + cid] = address
                    except Exception as e:
                        messages.append('Error: Missing address')

                    subfee = True if bytes('subfee_' + cid, 'utf-8') in form_data else False
                    page_data['wd_subfee_' + cid] = subfee

                    if c == Coins.PART:
                        try:
                            type_from = form_data[bytes('withdraw_type_from_' + cid, 'utf-8')][0].decode('utf-8')
                            type_to = form_data[bytes('withdraw_type_to_' + cid, 'utf-8')][0].decode('utf-8')
                            page_data['wd_type_from_' + cid] = type_from
                            page_data['wd_type_to_' + cid] = type_to
                        except Exception as e:
                            messages.append('Error: Missing type')

                    if len(messages) == 0:
                        ci = swap_client.ci(c)
                        ticker = ci.ticker()
                        if c == Coins.PART:
                            try:
                                txid = swap_client.withdrawParticl(type_from, type_to, value, address, subfee)
                                messages.append('Withdrew {} {} ({} to {}) to address {}<br/>In txid: {}'.format(value, ticker, type_from, type_to, address, txid))
                            except Exception as e:
                                messages.append('Error: {}'.format(str(e)))
                        else:
                            try:
                                txid = swap_client.withdrawCoin(c, value, address, subfee)
                                messages.append('Withdrew {} {} to address {}<br/>In txid: {}'.format(value, ticker, address, txid))
                            except Exception as e:
                                messages.append('Error: {}'.format(str(e)))
                        swap_client.updateWalletsInfo(True, c)

        swap_client.updateWalletsInfo()
        wallets = swap_client.getCachedWalletsInfo()

        wallets_formatted = []
        sk = sorted(wallets.keys())

        for k in sk:
            w = wallets[k]
            if 'error' in w:
                wallets_formatted.append({
                    'cid': str(int(k)),
                    'error': w['error']
                })
                continue

            if 'balance' not in w:
                wallets_formatted.append({
                    'name': w['name'],
                    'havedata': False,
                    'updating': w['updating'],
                })
                continue

            ci = swap_client.ci(k)
            cid = str(int(k))
            wf = {
                'name': w['name'],
                'version': w['version'],
                'ticker': ci.ticker_mainnet(),
                'cid': cid,
                'balance': w['balance'],
                'blocks': w['blocks'],
                'synced': w['synced'],
                'deposit_address': w['deposit_address'],
                'expected_seed': w['expected_seed'],
                'balance_all': float(w['balance']) + float(w['unconfirmed']),
                'updating': w['updating'],
                'lastupdated': format_timestamp(w['lastupdated']),
                'havedata': True,
            }
            if float(w['unconfirmed']) > 0.0:
                wf['unconfirmed'] = w['unconfirmed']

            if k == Coins.PART:
                wf['stealth_address'] = w['stealth_address']
                wf['blind_balance'] = w['blind_balance']
                if float(w['blind_unconfirmed']) > 0.0:
                    wf['blind_unconfirmed'] = w['blind_unconfirmed']
                wf['anon_balance'] = w['anon_balance']
                if float(w['anon_pending']) > 0.0:
                    wf['anon_pending'] = w['anon_pending']

            wallets_formatted.append(wf)

        template = env.get_template('wallets.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            wallets=wallets_formatted,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_wallet(self, url_split, post_string):
        ensure(len(url_split) > 2, 'Wallet not specified')
        wallet_ticker = url_split[2]
        swap_client = self.server.swap_client

        coin_id = getCoinIdFromTicker(wallet_ticker)

        page_data = {}
        messages = []
        form_data = self.checkForm(post_string, 'settings', messages)
        show_utxo_groups = False
        if form_data:
            cid = str(int(coin_id))

            if bytes('newaddr_' + cid, 'utf-8') in form_data:
                swap_client.cacheNewAddressForCoin(coin_id)
            elif bytes('reseed_' + cid, 'utf-8') in form_data:
                try:
                    swap_client.reseedWallet(coin_id)
                    messages.append('Reseed complete ' + str(coin_id))
                except Exception as ex:
                    messages.append('Reseed failed ' + str(ex))
                swap_client.updateWalletsInfo(True, coin_id)
            elif bytes('withdraw_' + cid, 'utf-8') in form_data:
                try:
                    value = form_data[bytes('amt_' + cid, 'utf-8')][0].decode('utf-8')
                    page_data['wd_value_' + cid] = value
                except Exception as e:
                    messages.append('Error: Missing value')
                try:
                    address = form_data[bytes('to_' + cid, 'utf-8')][0].decode('utf-8')
                    page_data['wd_address_' + cid] = address
                except Exception as e:
                    messages.append('Error: Missing address')

                subfee = True if bytes('subfee_' + cid, 'utf-8') in form_data else False
                page_data['wd_subfee_' + cid] = subfee

                if coin_id == Coins.PART:
                    try:
                        type_from = form_data[bytes('withdraw_type_from_' + cid, 'utf-8')][0].decode('utf-8')
                        type_to = form_data[bytes('withdraw_type_to_' + cid, 'utf-8')][0].decode('utf-8')
                        page_data['wd_type_from_' + cid] = type_from
                        page_data['wd_type_to_' + cid] = type_to
                    except Exception as e:
                        messages.append('Error: Missing type')

                if len(messages) == 0:
                    ci = swap_client.ci(coin_id)
                    ticker = ci.ticker()
                    if coin_id == Coins.PART:
                        try:
                            txid = swap_client.withdrawParticl(type_from, type_to, value, address, subfee)
                            messages.append('Withdrew {} {} ({} to {}) to address {}<br/>In txid: {}'.format(value, ticker, type_from, type_to, address, txid))
                        except Exception as e:
                            messages.append('Error: {}'.format(str(e)))
                    else:
                        try:
                            txid = swap_client.withdrawCoin(coin_id, value, address, subfee)
                            messages.append('Withdrew {} {} to address {}<br/>In txid: {}'.format(value, ticker, address, txid))
                        except Exception as e:
                            messages.append('Error: {}'.format(str(e)))
                    swap_client.updateWalletsInfo(True, coin_id)
            elif have_data_entry(form_data, 'showutxogroups'):
                show_utxo_groups = True
            elif have_data_entry(form_data, 'create_utxo'):
                show_utxo_groups = True
                try:
                    value = get_data_entry(form_data, 'utxo_value')
                    page_data['utxo_value'] = value

                    ci = swap_client.ci(coin_id)

                    value_sats = ci.make_int(value)

                    txid, address = ci.createUTXO(value_sats)
                    messages.append('Created new utxo of value {} and address {}<br/>In txid: {}'.format(value, address, txid))
                except Exception as e:
                    messages.append('Error: {}'.format(str(e)))
                    if swap_client.debug is True:
                        swap_client.log.error(traceback.format_exc())

        swap_client.updateWalletsInfo()
        wallets = swap_client.getCachedWalletsInfo({'coin_id': coin_id})
        for k in wallets.keys():
            w = wallets[k]
            if 'error' in w:
                wallet_data = {
                    'cid': str(int(k)),
                    'error': w['error']
                }
                continue

            if 'balance' not in w:
                wallet_data = {
                    'name': w['name'],
                    'havedata': False,
                    'updating': w['updating'],
                }
                continue

            ci = swap_client.ci(k)
            fee_rate, fee_src = swap_client.getFeeRateForCoin(k)
            est_fee = swap_client.estimateWithdrawFee(k, fee_rate)
            cid = str(int(k))
            wallet_data = {
                'name': w['name'],
                'version': w['version'],
                'ticker': ci.ticker_mainnet(),
                'cid': cid,
                'fee_rate': ci.format_amount(int(fee_rate * ci.COIN())),
                'fee_rate_src': fee_src,
                'est_fee': 'Unknown' if est_fee is None else ci.format_amount(int(est_fee * ci.COIN())),
                'balance': w['balance'],
                'blocks': w['blocks'],
                'synced': w['synced'],
                'deposit_address': w['deposit_address'],
                'expected_seed': w['expected_seed'],
                'balance_all': float(w['balance']) + float(w['unconfirmed']),
                'updating': w['updating'],
                'lastupdated': format_timestamp(w['lastupdated']),
                'havedata': True,
            }
            if float(w['unconfirmed']) > 0.0:
                wallet_data['unconfirmed'] = w['unconfirmed']

            if k == Coins.PART:
                wallet_data['stealth_address'] = w['stealth_address']
                wallet_data['blind_balance'] = w['blind_balance']
                if float(w['blind_unconfirmed']) > 0.0:
                    wallet_data['blind_unconfirmed'] = w['blind_unconfirmed']
                wallet_data['anon_balance'] = w['anon_balance']
                if float(w['anon_pending']) > 0.0:
                    wallet_data['anon_pending'] = w['anon_pending']

            elif k == Coins.XMR:
                wallet_data['main_address'] = w.get('main_address', 'Refresh necessary')

            if 'wd_type_from_' + cid in page_data:
                wallet_data['wd_type_from'] = page_data['wd_type_from_' + cid]
            if 'wd_type_to_' + cid in page_data:
                wallet_data['wd_type_to'] = page_data['wd_type_to_' + cid]

            if 'wd_value_' + cid in page_data:
                wallet_data['wd_value'] = page_data['wd_value_' + cid]
            if 'wd_address_' + cid in page_data:
                wallet_data['wd_address'] = page_data['wd_address_' + cid]
            if 'wd_subfee_' + cid in page_data:
                wallet_data['wd_subfee'] = page_data['wd_subfee_' + cid]
            if 'utxo_value' in page_data:
                wallet_data['utxo_value'] = page_data['utxo_value']

            if show_utxo_groups:
                utxo_groups = ''

                unspent_by_addr = swap_client.getUnspentsByAddr(k)

                sorted_unspent_by_addr = sorted(unspent_by_addr.items(), key=lambda x: x[1], reverse=True)
                for kv in sorted_unspent_by_addr:
                    utxo_groups += kv[0] + ' ' + ci.format_amount(kv[1]) + '\n'

                wallet_data['show_utxo_groups'] = True
                wallet_data['utxo_groups'] = utxo_groups

        template = env.get_template('wallet.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            w=wallet_data,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_settings(self, url_split, post_string):
        swap_client = self.server.swap_client

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
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            chains=chains_formatted,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

    def page_bid(self, url_split, post_string):
        ensure(len(url_split) > 2, 'Bid ID not specified')
        try:
            bid_id = bytes.fromhex(url_split[2])
            assert(len(bid_id) == 28)
        except Exception:
            raise ValueError('Bad bid ID')
        swap_client = self.server.swap_client

        messages = []
        show_txns = False
        show_lock_transfers = False
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
                    'bid_state': int(form_data[b'new_state'][0]),
                    'debug_ind': int(get_data_entry_or(form_data, 'debugind', -1)),
                    'kbs_other': get_data_entry_or(form_data, 'kbs_other', None),
                }
                try:
                    swap_client.manualBidUpdate(bid_id, data)
                    messages.append('Bid edited')
                except Exception as ex:
                    messages.append('Edit failed ' + str(ex))
            elif b'view_tx_submit' in form_data:
                show_txns = True
                view_tx_ind = form_data[b'view_tx'][0].decode('utf-8')
            elif b'view_lock_transfers' in form_data:
                show_txns = True
                show_lock_transfers = True

        bid, xmr_swap, offer, xmr_offer, events = swap_client.getXmrBidAndOffer(bid_id)
        ensure(bid, 'Unknown bid ID')

        data = describeBid(swap_client, bid, xmr_swap, offer, xmr_offer, events, edit_bid, show_txns, view_tx_ind, show_lock_transfers=show_lock_transfers)

        if bid.debug_ind is not None and bid.debug_ind > 0:
            messages.append('Debug flag set: {}, {}'.format(bid.debug_ind, DebugTypes(bid.debug_ind).name))

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

        if len(data['addr_from_label']) > 0:
            data['addr_from_label'] = '(' + data['addr_from_label'] + ')'

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

        filters = {
            'page_no': 1,
            'limit': PAGE_LIMIT,
            'sort_by': 'created_at',
            'sort_dir': 'desc',
        }
        messages = []
        form_data = self.checkForm(post_string, 'bids', messages)
        if form_data and have_data_entry(form_data, 'applyfilters'):
            if have_data_entry(form_data, 'sort_by'):
                sort_by = get_data_entry(form_data, 'sort_by')
                ensure(sort_by in ['created_at', ], 'Invalid sort by')
                filters['sort_by'] = sort_by
            if have_data_entry(form_data, 'sort_dir'):
                sort_dir = get_data_entry(form_data, 'sort_dir')
                ensure(sort_dir in ['asc', 'desc'], 'Invalid sort dir')
                filters['sort_dir'] = sort_dir

        set_pagination_filters(form_data, filters)

        bids = swap_client.listBids(sent=sent, filters=filters)

        template = env.get_template('bids.html')
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            page_type='Sent' if sent else 'Received',
            messages=messages,
            filters=filters,
            bids=[(format_timestamp(b[0]),
                   b[2].hex(), b[3].hex(), strBidState(b[5]), strTxState(b[7]), strTxState(b[8]), b[11]) for b in bids],
            form_id=os.urandom(8).hex(),
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

    def page_smsgaddresses(self, url_split, post_string):
        swap_client = self.server.swap_client

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
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            data=page_data,
            form_id=os.urandom(8).hex(),
            smsgaddresses=smsgaddresses,
            network_addr=network_addr,
        ), 'UTF-8')

    def page_identity(self, url_split, post_string):
        ensure(len(url_split) > 2, 'Address not specified')
        identity_address = url_split[2]
        swap_client = self.server.swap_client

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
        return bytes(template.render(
            title=self.server.title,
            h2=self.server.title,
            messages=messages,
            data=page_data,
            form_id=os.urandom(8).hex(),
        ), 'UTF-8')

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
        return bytes(template.render(
            title=self.server.title,
            refresh=30,
            h2=self.server.title,
            version=__version__,
            summary=summary,
            use_tor_proxy=swap_client.use_tor_proxy,
            shutdown_token=shutdown_token
        ), 'UTF-8')

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
                            'network': js_network,
                            'revokeoffer': js_revokeoffer,
                            'smsgaddresses': js_smsgaddresses,
                            'rate': js_rate,
                            'rates': js_rates,
                            }.get(url_split[2], js_index)
                return func(self, url_split, post_string, is_json)
            except Exception as ex:
                if self.server.swap_client.debug is True:
                    self.server.swap_client.log.error(traceback.format_exc())
                return js_error(self, str(ex))

        if len(url_split) > 1 and url_split[1] == 'static':
            try:
                static_path = os.path.join(os.path.dirname(__file__), 'static')

                if url_split[2] == 'favicon-32.png':
                    self.putHeaders(status_code, 'image/png')
                    with open(os.path.join(static_path, 'favicon-32.png'), 'rb') as fp:
                        return fp.read()
                elif url_split[2] == 'style.css':
                    self.putHeaders(status_code, 'text/css')
                    with open(os.path.join(static_path, 'style.css'), 'rb') as fp:
                        return fp.read()
                else:
                    self.putHeaders(status_code, 'text/html')
                    return self.page_404(url_split)
            except Exception as ex:
                self.putHeaders(status_code, 'text/html')
                if self.server.swap_client.debug is True:
                    self.server.swap_client.log.error(traceback.format_exc())
                return self.page_error(str(ex))

        try:
            self.putHeaders(status_code, 'text/html')
            if len(url_split) > 1:
                if url_split[1] == 'active':
                    return self.page_active(url_split, post_string)
                if url_split[1] == 'wallets':
                    return self.page_wallets(url_split, post_string)
                if url_split[1] == 'wallet':
                    return self.page_wallet(url_split, post_string)
                if url_split[1] == 'settings':
                    return self.page_settings(url_split, post_string)
                if url_split[1] == 'rpc':
                    return self.page_rpc(url_split, post_string)
                if url_split[1] == 'debug':
                    return self.page_debug(url_split, post_string)
                if url_split[1] == 'explorers':
                    return self.page_explorers(url_split, post_string)
                if url_split[1] == 'offer':
                    return page_offer(self, url_split, post_string)
                if url_split[1] == 'offers':
                    return page_offers(self, url_split, post_string)
                if url_split[1] == 'newoffer':
                    return page_newoffer(self, url_split, post_string)
                if url_split[1] == 'sentoffers':
                    return page_offers(self, url_split, post_string, sent=True)
                if url_split[1] == 'bid':
                    return self.page_bid(url_split, post_string)
                if url_split[1] == 'bids':
                    return self.page_bids(url_split, post_string)
                if url_split[1] == 'sentbids':
                    return self.page_bids(url_split, post_string, sent=True)
                if url_split[1] == 'watched':
                    return self.page_watched(url_split, post_string)
                if url_split[1] == 'smsgaddresses':
                    return self.page_smsgaddresses(url_split, post_string)
                if url_split[1] == 'identity':
                    return self.page_identity(url_split, post_string)
                if url_split[1] == 'tor':
                    return page_tor(self, url_split, post_string)
                if url_split[1] == 'automation':
                    return page_automation_strategies(self, url_split, post_string)
                if url_split[1] == 'automationstrategy':
                    return page_automation_strategy(self, url_split, post_string)
                if url_split[1] == 'newautomationstrategy':
                    return page_automation_strategy_new(self, url_split, post_string)
                if url_split[1] == 'shutdown':
                    return self.page_shutdown(url_split, post_string)
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
        self.title = 'BasicSwap, ' + self.swap_client.chain
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
