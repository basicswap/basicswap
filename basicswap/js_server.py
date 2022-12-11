# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import random
import urllib.parse

from .util import (
    toBool,
)
from .basicswap_util import (
    strBidState,
    SwapTypes,
    NotificationTypes as NT,
)
from .chainparams import (
    Coins,
    chainparams,
)
from .ui.util import (
    PAGE_LIMIT,
    getCoinName,
    getCoinType,
    inputAmount,
    describeBid,
    setCoinFilter,
    get_data_entry,
    get_data_entry_or,
    have_data_entry,
    tickerToCoinId,
    listOldBidStates,
    checkAddressesOwned,
)
from .ui.page_offers import postNewOffer
from .protocols.xmr_swap_1 import recoverNoScriptTxnWithKey, getChainBSplitKey


def getFormData(post_string, is_json):
    if post_string == '':
        raise ValueError('No post data')
    if is_json:
        form_data = json.loads(post_string)
        form_data['is_json'] = True
    else:
        form_data = urllib.parse.parse_qs(post_string)
    return form_data


def js_error(self, error_str):
    error_str_json = json.dumps({'error': error_str})
    return bytes(error_str_json, 'UTF-8')


def withdraw_coin(swap_client, coin_type, post_string, is_json):
    post_data = getFormData(post_string, is_json)

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


def js_coins(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client

    coins = []
    for coin in Coins:
        cc = swap_client.coin_clients[coin]
        entry = {
            'id': int(coin),
            'ticker': chainparams[cc['coin']]['ticker'],
            'name': getCoinName(coin),
            'active': False if cc['connection_type'] == 'none' else True,
        }
        if coin == Coins.PART_ANON:
            entry['variant'] = 'Anon'
        elif coin == Coins.PART_BLIND:
            entry['variant'] = 'Blind'
        coins.append(entry)

    return bytes(json.dumps(coins), 'UTF-8')


def js_wallets(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    if len(url_split) > 3:
        ticker_str = url_split[3]
        coin_type = tickerToCoinId(ticker_str)

        if len(url_split) > 4:
            cmd = url_split[4]
            if cmd == 'withdraw':
                return bytes(json.dumps(withdraw_coin(swap_client, coin_type, post_string, is_json)), 'UTF-8')
            if cmd == 'nextdepositaddr':
                return bytes(json.dumps(swap_client.cacheNewAddressForCoin(coin_type)), 'UTF-8')
            if cmd == 'createutxo':
                post_data = getFormData(post_string, is_json)
                ci = swap_client.ci(coin_type)
                value = ci.make_int(get_data_entry(post_data, 'value'))
                txid_hex, new_addr = ci.createUTXO(value)
                return bytes(json.dumps({'txid': txid_hex, 'address': new_addr}), 'UTF-8')

            raise ValueError('Unknown command')

        rv = swap_client.getWalletInfo(coin_type)
        rv.update(swap_client.getBlockchainInfo(coin_type))
        ci = swap_client.ci(coin_type)
        checkAddressesOwned(ci, rv)
        return bytes(json.dumps(rv), 'UTF-8')
    return bytes(json.dumps(swap_client.getWalletsInfo({'ticker_key': True})), 'UTF-8')


def js_offers(self, url_split, post_string, is_json, sent=False):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    offer_id = None
    if len(url_split) > 3:
        if url_split[3] == 'new':
            form_data = getFormData(post_string, is_json)
            offer_id = postNewOffer(swap_client, form_data)
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
        post_data = getFormData(post_string, is_json)
        filters['coin_from'] = setCoinFilter(post_data, 'coin_from')
        filters['coin_to'] = setCoinFilter(post_data, 'coin_to')

        if have_data_entry(post_data, 'sort_by'):
            sort_by = get_data_entry(post_data, 'sort_by')
            assert (sort_by in ['created_at', 'rate']), 'Invalid sort by'
            filters['sort_by'] = sort_by
        if have_data_entry(post_data, 'sort_dir'):
            sort_dir = get_data_entry(post_data, 'sort_dir')
            assert (sort_dir in ['asc', 'desc']), 'Invalid sort dir'
            filters['sort_dir'] = sort_dir

        if b'offset' in post_data:
            filters['offset'] = int(get_data_entry(post_data, 'offset'))
        if b'limit' in post_data:
            filters['limit'] = int(get_data_entry(post_data, 'limit'))
            assert (filters['limit'] > 0 and filters['limit'] <= PAGE_LIMIT), 'Invalid limit'

    offers = swap_client.listOffers(sent, filters)
    rv = []
    for o in offers:
        ci_from = swap_client.ci(o.coin_from)
        ci_to = swap_client.ci(o.coin_to)
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
    swap_client.checkSystemStatus()
    if len(url_split) > 3:
        if url_split[3] == 'new':
            post_data = getFormData(post_string, is_json)

            offer_id = bytes.fromhex(get_data_entry(post_data, 'offer_id'))
            assert (len(offer_id) == 28)

            offer = swap_client.getOffer(offer_id)
            assert (offer), 'Offer not found.'

            ci_from = swap_client.ci(offer.coin_from)
            ci_to = swap_client.ci(offer.coin_to)
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
            if have_data_entry(post_data, 'bid_rate'):
                extra_options['bid_rate'] = ci_to.make_int(get_data_entry(post_data, 'bid_rate'), r=1)
            if have_data_entry(post_data, 'bid_amount'):
                amount_from = inputAmount(get_data_entry(post_data, 'bid_amount'), ci_from)

            if offer.swap_type == SwapTypes.XMR_SWAP:
                bid_id = swap_client.postXmrBid(offer_id, amount_from, addr_send_from=addr_from, extra_options=extra_options)
            else:
                bid_id = swap_client.postBid(offer_id, amount_from, addr_send_from=addr_from, extra_options=extra_options)

            if have_data_entry(post_data, 'debugind'):
                swap_client.setBidDebugInd(bid_id, int(get_data_entry(post_data, 'debugind')))

            rv = {'bid_id': bid_id.hex()}
            return bytes(json.dumps(rv), 'UTF-8')

        bid_id = bytes.fromhex(url_split[3])
        assert (len(bid_id) == 28)

        show_txns = False
        if post_string != '':
            post_data = getFormData(post_string, is_json)
            if have_data_entry(post_data, 'accept'):
                swap_client.acceptBid(bid_id)
            elif have_data_entry(post_data, 'debugind'):
                swap_client.setBidDebugInd(bid_id, int(get_data_entry(post_data, 'debugind')))

            if have_data_entry(post_data, 'show_extra'):
                show_txns = True

        bid, xmr_swap, offer, xmr_offer, events = swap_client.getXmrBidAndOffer(bid_id)
        assert (bid), 'Unknown bid ID'

        if post_string != '':
            if have_data_entry(post_data, 'chainbkeysplit'):
                return bytes(json.dumps({'splitkey': getChainBSplitKey(swap_client, bid, xmr_swap, offer)}), 'UTF-8')
            elif have_data_entry(post_data, 'spendchainblocktx'):
                remote_key = get_data_entry(post_data, 'remote_key')
                return bytes(json.dumps({'txid': recoverNoScriptTxnWithKey(swap_client, bid_id, remote_key).hex()}), 'UTF-8')

        if len(url_split) > 4 and url_split[4] == 'states':
            old_states = listOldBidStates(bid)
            return bytes(json.dumps(old_states), 'UTF-8')

        edit_bid = False
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
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    return bytes(json.dumps(swap_client.listBids(sent=True)), 'UTF-8')


def js_network(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    return bytes(json.dumps(swap_client.get_network_info()), 'UTF-8')


def js_revokeoffer(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    offer_id = bytes.fromhex(url_split[3])
    assert (len(offer_id) == 28)
    swap_client.revokeOffer(offer_id)
    return bytes(json.dumps({'revoked_offer': offer_id.hex()}), 'UTF-8')


def js_smsgaddresses(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    if len(url_split) > 3:
        post_data = getFormData(post_string, is_json)
        if url_split[3] == 'new':
            addressnote = get_data_entry_or(post_data, 'addressnote', '')
            new_addr, pubkey = swap_client.newSMSGAddress(addressnote=addressnote)
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
    post_data = getFormData(post_string, is_json)

    sc = self.server.swap_client
    coin_from = get_data_entry(post_data, 'coin_from')
    coin_to = get_data_entry(post_data, 'coin_to')
    return bytes(json.dumps(sc.lookupRates(coin_from, coin_to)), 'UTF-8')


def js_rates_list(self, url_split, query_string, is_json):
    get_data = urllib.parse.parse_qs(query_string)

    sc = self.server.swap_client
    coin_from = getCoinType(get_data['from'][0])
    coin_to = getCoinType(get_data['to'][0])
    return bytes(json.dumps(sc.lookupRates(coin_from, coin_to, True)), 'UTF-8')


def js_rate(self, url_split, post_string, is_json):
    post_data = getFormData(post_string, is_json)

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
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    return bytes(json.dumps(swap_client.getSummary()), 'UTF-8')


def js_generatenotification(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client

    if not swap_client.debug:
        raise ValueError('Debug mode not active.')

    r = random.randint(0, 3)
    if r == 0:
        swap_client.notify(NT.OFFER_RECEIVED, {'offer_id': random.randbytes(28).hex()})
    elif r == 1:
        swap_client.notify(NT.BID_RECEIVED, {'type': 'atomic', 'bid_id': random.randbytes(28).hex(), 'offer_id': random.randbytes(28).hex()})
    elif r == 2:
        swap_client.notify(NT.BID_ACCEPTED, {'bid_id': random.randbytes(28).hex()})
    elif r == 3:
        swap_client.notify(NT.BID_RECEIVED, {'type': 'xmr', 'bid_id': random.randbytes(28).hex(), 'offer_id': random.randbytes(28).hex()})

    return bytes(json.dumps({'type': r}), 'UTF-8')


def js_notifications(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    swap_client.getNotifications()

    return bytes(json.dumps(swap_client.getNotifications()), 'UTF-8')


def js_vacuumdb(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    swap_client.vacuumDB()

    return bytes(json.dumps({'completed': True}), 'UTF-8')


def js_getcoinseed(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    post_data = getFormData(post_string, is_json)

    coin = getCoinType(get_data_entry(post_data, 'coin'))
    if coin in (Coins.PART, Coins.PART_ANON, Coins.PART_BLIND):
        raise ValueError('Particl wallet seed is set from the Basicswap mnemonic.')

    ci = swap_client.ci(coin)
    seed = swap_client.getWalletKey(coin, 1)
    if coin == Coins.DASH:
        return bytes(json.dumps({'coin': ci.ticker(), 'seed': seed.hex(), 'mnemonic': ci.seedToMnemonic(seed)}), 'UTF-8')
    return bytes(json.dumps({'coin': ci.ticker(), 'seed': seed.hex()}), 'UTF-8')


def js_setpassword(self, url_split, post_string, is_json):
    # Set or change wallet passwords
    # Only works with currently enabled coins
    # Will fail if any coin does not unlock on the old password
    swap_client = self.server.swap_client
    post_data = getFormData(post_string, is_json)

    old_password = get_data_entry(post_data, 'oldpassword')
    new_password = get_data_entry(post_data, 'newpassword')

    if have_data_entry(post_data, 'coin'):
        # Set password for one coin
        coin = getCoinType(get_data_entry(post_data, 'coin'))
        if coin in (Coins.PART_ANON, Coins.PART_BLIND):
            raise ValueError('Invalid coin.')
        swap_client.changeWalletPasswords(old_password, new_password, coin)
        return bytes(json.dumps({'success': True}), 'UTF-8')

    # Set password for all coins
    swap_client.changeWalletPasswords(old_password, new_password)
    return bytes(json.dumps({'success': True}), 'UTF-8')


def js_unlock(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    post_data = getFormData(post_string, is_json)

    password = get_data_entry(post_data, 'password')

    if have_data_entry(post_data, 'coin'):
        coin = getCoinType(str(get_data_entry(post_data, 'coin')))
        if coin in (Coins.PART_ANON, Coins.PART_BLIND):
            raise ValueError('Invalid coin.')
        swap_client.unlockWallets(password, coin)
        return bytes(json.dumps({'success': True}), 'UTF-8')

    swap_client.unlockWallets(password)
    return bytes(json.dumps({'success': True}), 'UTF-8')


def js_lock(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    post_data = {} if post_string == '' else getFormData(post_string, is_json)

    if have_data_entry(post_data, 'coin'):
        coin = getCoinType(get_data_entry(post_data, 'coin'))
        if coin in (Coins.PART_ANON, Coins.PART_BLIND):
            raise ValueError('Invalid coin.')
        swap_client.lockWallets(coin)
        return bytes(json.dumps({'success': True}), 'UTF-8')

    swap_client.lockWallets()
    return bytes(json.dumps({'success': True}), 'UTF-8')


def js_404(self, url_split, post_string, is_json):
    return bytes(json.dumps({'Error': 'path unknown'}), 'UTF-8')


def js_help(self, url_split, post_string, is_json):
    # TODO: Add details and examples
    commands = []
    for k in pages:
        commands.append(k)
    return bytes(json.dumps({'commands': commands}), 'UTF-8')


pages = {
    'coins': js_coins,
    'wallets': js_wallets,
    'offers': js_offers,
    'sentoffers': js_sentoffers,
    'bids': js_bids,
    'sentbids': js_sentbids,
    'network': js_network,
    'revokeoffer': js_revokeoffer,
    'smsgaddresses': js_smsgaddresses,
    'rate': js_rate,
    'rates': js_rates,
    'rateslist': js_rates_list,
    'generatenotification': js_generatenotification,
    'notifications': js_notifications,
    'vacuumdb': js_vacuumdb,
    'getcoinseed': js_getcoinseed,
    'setpassword': js_setpassword,
    'unlock': js_unlock,
    'lock': js_lock,
    'help': js_help,
}


def js_url_to_function(url_split):
    if len(url_split) > 2:
        return pages.get(url_split[2], js_404)
    return js_index
