# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import traceback

from .util import (
    get_data_entry,
    have_data_entry,
    checkAddressesOwned,
)
from basicswap.util import (
    ensure,
    format_timestamp,
)
from basicswap.chainparams import (
    Coins,
    getCoinIdFromTicker,
)


def format_wallet_data(swap_client, ci, w):
    wf = {
        'name': ci.coin_name(),
        'version': w.get('version', '?'),
        'ticker': ci.ticker_mainnet(),
        'cid': str(int(ci.coin_type())),
        'balance': w.get('balance', '?'),
        'blocks': w.get('blocks', '?'),
        'synced': w.get('synced', '?'),
        'expected_seed': w.get('expected_seed', '?'),
        'encrypted': w.get('encrypted', '?'),
        'locked': w.get('locked', '?'),
        'updating': w.get('updating', '?'),
        'havedata': True,
    }

    if w.get('bootstrapping', False) is True:
        wf['bootstrapping'] = True
    if 'known_block_count' in w:
        wf['known_block_count'] = w['known_block_count']
    if 'locked_utxos' in w:
        wf['locked_utxos'] = w['locked_utxos']

    if 'balance' in w and 'unconfirmed' in w:
        wf['balance_all'] = float(w['balance']) + float(w['unconfirmed'])
    if 'lastupdated' in w:
        wf['lastupdated'] = format_timestamp(w['lastupdated'])

    pending: int = 0
    if 'unconfirmed' in w and float(w['unconfirmed']) > 0.0:
        pending += ci.make_int(w['unconfirmed'])
    if 'immature' in w and float(w['immature']) > 0.0:
        pending += ci.make_int(w['immature'])
    if pending > 0.0:
        wf['pending'] = ci.format_amount(pending)

    if ci.coin_type() == Coins.PART:
        wf['stealth_address'] = w.get('stealth_address', '?')
        wf['blind_balance'] = w.get('blind_balance', '?')
        if 'blind_unconfirmed' in w and float(w['blind_unconfirmed']) > 0.0:
            wf['blind_unconfirmed'] = w['blind_unconfirmed']
        wf['anon_balance'] = w.get('anon_balance', '?')
        if 'anon_pending' in w and float(w['anon_pending']) > 0.0:
            wf['anon_pending'] = w['anon_pending']
    elif ci.coin_type() == Coins.LTC:
        wf['mweb_address'] = w.get('mweb_address', '?')
        wf['mweb_balance'] = w.get('mweb_balance', '?')
        wf['mweb_pending'] = w.get('mweb_pending', '?')

    checkAddressesOwned(swap_client, ci, wf)
    return wf


def page_wallets(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    messages = []
    err_messages = []

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

        if 'no_data' in w:
            wallets_formatted.append({
                'name': w['name'],
                'havedata': False,
                'updating': w['updating'],
            })
            continue

        ci = swap_client.ci(k)
        wf = format_wallet_data(swap_client, ci, w)

        wallets_formatted.append(wf)

    template = server.env.get_template('wallets.html')
    return self.render_template(template, {
        'messages': messages,
        'err_messages': err_messages,
        'wallets': wallets_formatted,
        'summary': summary,
    })


def page_wallet(self, url_split, post_string):
    ensure(len(url_split) > 2, 'Wallet not specified')
    wallet_ticker = url_split[2]
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    coin_id = getCoinIdFromTicker(wallet_ticker)

    page_data = {}
    messages = []
    err_messages = []
    show_utxo_groups: bool = False
    withdrawal_successful: bool = False
    force_refresh: bool = False
    form_data = self.checkForm(post_string, 'wallet', err_messages)
    if form_data:
        cid = str(int(coin_id))

        estimate_fee: bool = have_data_entry(form_data, 'estfee_' + cid)
        withdraw: bool = have_data_entry(form_data, 'withdraw_' + cid)
        if have_data_entry(form_data, 'newaddr_' + cid):
            swap_client.cacheNewAddressForCoin(coin_id)
        elif have_data_entry(form_data, 'forcerefresh'):
            force_refresh = True
        elif have_data_entry(form_data, 'newmwebaddr_' + cid):
            swap_client.cacheNewStealthAddressForCoin(coin_id)
        elif have_data_entry(form_data, 'reseed_' + cid):
            try:
                swap_client.reseedWallet(coin_id)
                messages.append('Reseed complete ' + str(coin_id))
            except Exception as ex:
                err_messages.append('Reseed failed ' + str(ex))
            swap_client.updateWalletsInfo(True, coin_id)
        elif withdraw or estimate_fee:
            subfee = True if have_data_entry(form_data, 'subfee_' + cid) else False
            page_data['wd_subfee_' + cid] = subfee

            sweepall = True if have_data_entry(form_data, 'sweepall_' + cid) else False
            page_data['wd_sweepall_' + cid] = sweepall
            value = None
            if not sweepall:
                try:
                    value = form_data[bytes('amt_' + cid, 'utf-8')][0].decode('utf-8')
                    page_data['wd_value_' + cid] = value
                except Exception as e:
                    err_messages.append('Missing value')
            try:
                address = form_data[bytes('to_' + cid, 'utf-8')][0].decode('utf-8')
                page_data['wd_address_' + cid] = address
            except Exception as e:
                err_messages.append('Missing address')

            if estimate_fee and withdraw:
                err_messages.append('Estimate fee and withdraw can\'t be used together.')
            if estimate_fee and coin_id not in (Coins.XMR, Coins.WOW):
                ci = swap_client.ci(coin_id)
                ticker: str = ci.ticker()
                err_messages.append(f'Estimate fee unavailable for {ticker}.')

            if coin_id == Coins.PART:
                try:
                    type_from = form_data[bytes('withdraw_type_from_' + cid, 'utf-8')][0].decode('utf-8')
                    type_to = form_data[bytes('withdraw_type_to_' + cid, 'utf-8')][0].decode('utf-8')
                    page_data['wd_type_from_' + cid] = type_from
                    page_data['wd_type_to_' + cid] = type_to
                except Exception as e:
                    err_messages.append('Missing type')
            elif coin_id == Coins.LTC:
                try:
                    type_from = form_data[bytes('withdraw_type_from_' + cid, 'utf-8')][0].decode('utf-8')
                    page_data['wd_type_from_' + cid] = type_from
                except Exception as e:
                    err_messages.append('Missing type')

            if len(err_messages) == 0:
                ci = swap_client.ci(coin_id)
                ticker: str = ci.ticker()
                try:
                    if coin_id == Coins.PART:
                        txid = swap_client.withdrawParticl(type_from, type_to, value, address, subfee)
                        messages.append('Withdrew {} {} ({} to {}) to address {}<br/>In txid: {}'.format(value, ticker, type_from, type_to, address, txid))
                    elif coin_id == Coins.LTC:
                        txid = swap_client.withdrawLTC(type_from, value, address, subfee)
                        messages.append('Withdrew {} {} (from {}) to address {}<br/>In txid: {}'.format(value, ticker, type_from, address, txid))
                    elif coin_id in (Coins.XMR, Coins.WOW):
                        if estimate_fee:
                            fee_estimate = ci.estimateFee(value, address, sweepall)
                            suffix = 's' if fee_estimate['num_txns'] > 1 else ''
                            sum_fees = ci.format_amount(fee_estimate['sum_fee'])
                            value_str = ci.format_amount(fee_estimate['sum_amount'])
                            messages.append(f'Estimated fee for {value_str} {ticker} to address {address}: {sum_fees} in {fee_estimate["num_txns"]} transaction{suffix}.')
                            page_data['fee_estimate'] = fee_estimate
                        else:
                            txid = swap_client.withdrawCoin(coin_id, value, address, sweepall)
                            if sweepall:
                                messages.append('Swept all {} to address {}<br/>In txid: {}'.format(ticker, address, txid))
                            else:
                                messages.append('Withdrew {} {} to address {}<br/>In txid: {}'.format(value, ticker, address, txid))
                            messages.append('Note: The wallet balance can take a while to update.')
                    else:
                        txid = swap_client.withdrawCoin(coin_id, value, address, subfee)
                        messages.append('Withdrew {} {} to address {}<br/>In txid: {}'.format(value, ticker, address, txid))
                    if not estimate_fee:
                        withdrawal_successful = True
                except Exception as e:
                    if swap_client.debug is True:
                        swap_client.log.error(traceback.format_exc())
                    err_messages.append(str(e))
            if not estimate_fee:
                swap_client.updateWalletsInfo(True, only_coin=coin_id)
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
                err_messages.append(str(e))
                if swap_client.debug is True:
                    swap_client.log.error(traceback.format_exc())

    swap_client.updateWalletsInfo(force_refresh, only_coin=coin_id, wait_for_complete=True)
    wallets = swap_client.getCachedWalletsInfo({'coin_id': coin_id})
    wallet_data = {}
    for k in wallets.keys():
        w = wallets[k]
        if 'error' in w:
            wallet_data = {
                'cid': str(int(k)),
                'error': w['error']
            }
            continue

        if 'no_data' in w:
            wallet_data = {
                'name': w['name'],
                'havedata': False,
                'updating': w['updating'],
            }
            continue

        ci = swap_client.ci(k)
        cid = str(int(coin_id))

        wallet_data = format_wallet_data(swap_client, ci, w)

        fee_rate, fee_src = swap_client.getFeeRateForCoin(k)
        est_fee = swap_client.estimateWithdrawFee(k, fee_rate)
        wallet_data['fee_rate'] = ci.format_amount(int(fee_rate * ci.COIN()))
        wallet_data['fee_rate_src'] = fee_src
        wallet_data['est_fee'] = 'Unknown' if est_fee is None else ci.format_amount(int(est_fee * ci.COIN()))
        wallet_data['deposit_address'] = w.get('deposit_address', 'Refresh necessary')

        if k in (Coins.XMR, Coins.WOW):
            wallet_data['main_address'] = w.get('main_address', 'Refresh necessary')
        elif k == Coins.LTC:
            wallet_data['mweb_address'] = w.get('mweb_address', 'Refresh necessary')

        if 'wd_type_from_' + cid in page_data:
            wallet_data['wd_type_from'] = page_data['wd_type_from_' + cid]
        if 'wd_type_to_' + cid in page_data:
            wallet_data['wd_type_to'] = page_data['wd_type_to_' + cid]

        if 'utxo_value' in page_data:
            wallet_data['utxo_value'] = page_data['utxo_value']

        if not withdrawal_successful:
            if 'wd_value_' + cid in page_data:
                wallet_data['wd_value'] = page_data['wd_value_' + cid]
            if 'wd_address_' + cid in page_data:
                wallet_data['wd_address'] = page_data['wd_address_' + cid]
            if 'wd_subfee_' + cid in page_data:
                wallet_data['wd_subfee'] = page_data['wd_subfee_' + cid]
            if 'wd_sweepall_' + cid in page_data:
                wallet_data['wd_sweepall'] = page_data['wd_sweepall_' + cid]
            if 'fee_estimate' in page_data:
                wallet_data['est_fee'] = ci.format_amount(page_data['fee_estimate']['sum_fee'])
                wallet_data['fee_rate'] = ci.format_amount(page_data['fee_estimate']['sum_fee'] * 1000 // page_data['fee_estimate']['sum_weight'])

        if show_utxo_groups:
            utxo_groups = ''
            unspent_by_addr = ci.getUnspentsByAddr()

            sorted_unspent_by_addr = sorted(unspent_by_addr.items(), key=lambda x: x[1], reverse=True)
            for kv in sorted_unspent_by_addr:
                utxo_groups += kv[0] + ' ' + ci.format_amount(kv[1]) + '\n'

            wallet_data['show_utxo_groups'] = True
            wallet_data['utxo_groups'] = utxo_groups

        checkAddressesOwned(swap_client, ci, wallet_data)

    template = server.env.get_template('wallet.html')
    return self.render_template(template, {
        'messages': messages,
        'err_messages': err_messages,
        'w': wallet_data,
        'summary': summary,
        'block_unknown_seeds': swap_client._restrict_unknown_seed_wallets,
    })
