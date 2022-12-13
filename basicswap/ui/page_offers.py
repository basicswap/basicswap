# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time
import traceback

from urllib import parse
from .util import (
    PAGE_LIMIT,
    getCoinType,
    inputAmount,
    setCoinFilter,
    get_data_entry,
    have_data_entry,
    get_data_entry_or,
    listAvailableCoins,
    set_pagination_filters,
)
from basicswap.db import (
    Concepts,
)
from basicswap.util import (
    ensure,
    format_amount,
    format_timestamp,
)
from basicswap.basicswap_util import (
    SwapTypes,
    DebugTypes,
    getLockName,
    strBidState,
    TxLockTypes,
    strOfferState,
)
from basicswap.chainparams import (
    Coins,
)


def value_or_none(v):
    if v == -1 or v == '-1':
        return None
    return v


def decode_offer_id(v):
    try:
        offer_id = bytes.fromhex(v)
        ensure(len(offer_id) == 28, 'Bad offer ID')
        return offer_id
    except Exception:
        raise ValueError('Bad offer ID')


def parseOfferFormData(swap_client, form_data, page_data, options={}):
    errors = []
    parsed_data = {}

    if have_data_entry(form_data, 'addr_to'):
        page_data['addr_to'] = get_data_entry(form_data, 'addr_to')
        addr_to = value_or_none(page_data['addr_to'])
        if addr_to is not None:
            parsed_data['addr_to'] = addr_to

    if have_data_entry(form_data, 'addr_from'):
        page_data['addr_from'] = get_data_entry(form_data, 'addr_from')
        parsed_data['addr_from'] = value_or_none(page_data['addr_from'])
    else:
        parsed_data['addr_from'] = None

    try:
        page_data['coin_from'] = getCoinType(get_data_entry(form_data, 'coin_from'))
        coin_from = Coins(page_data['coin_from'])
        ci_from = swap_client.ci(coin_from)
        if coin_from != Coins.XMR:
            page_data['fee_from_conf'] = ci_from._conf_target  # Set default value
        parsed_data['coin_from'] = coin_from
    except Exception:
        errors.append('Unknown Coin From')

    try:
        page_data['coin_to'] = getCoinType(get_data_entry(form_data, 'coin_to'))
        coin_to = Coins(page_data['coin_to'])
        ci_to = swap_client.ci(coin_to)
        if coin_to != Coins.XMR:
            page_data['fee_to_conf'] = ci_to._conf_target  # Set default value
        parsed_data['coin_to'] = coin_to
    except Exception:
        errors.append('Unknown Coin To')

    if parsed_data['coin_to'] in (Coins.XMR, Coins.PART_ANON):
        page_data['swap_style'] = 'xmr'
    else:
        page_data['swap_style'] = 'atomic'

    try:
        page_data['amt_from'] = get_data_entry(form_data, 'amt_from')
        parsed_data['amt_from'] = inputAmount(page_data['amt_from'], ci_from)
    except Exception:
        errors.append('Amount From')

    try:
        if 'amt_bid_min' not in page_data:
            if options.get('add_min_bid_amt', False) is True:
                parsed_data['amt_bid_min'] = ci_from.chainparams_network()['min_amount']
            else:
                raise ValueError('missing')
        else:
            page_data['amt_bid_min'] = get_data_entry(form_data, 'amt_bid_min')
            parsed_data['amt_bid_min'] = inputAmount(page_data['amt_bid_min'], ci_from)

            if parsed_data['amt_bid_min'] < 0 or parsed_data['amt_bid_min'] > parsed_data['amt_from']:
                errors.append('Minimum Bid Amount out of range')
    except Exception:
        errors.append('Minimum Bid Amount')

    try:
        page_data['amt_to'] = get_data_entry(form_data, 'amt_to')
        parsed_data['amt_to'] = inputAmount(page_data['amt_to'], ci_to)
    except Exception:
        errors.append('Amount To')

    if 'amt_to' in parsed_data and 'amt_from' in parsed_data:
        parsed_data['rate'] = ci_from.make_int(parsed_data['amt_to'] / parsed_data['amt_from'], r=1)
        page_data['rate'] = ci_to.format_amount(parsed_data['rate'])

    page_data['amt_var'] = True if have_data_entry(form_data, 'amt_var') else False
    parsed_data['amt_var'] = page_data['amt_var']
    page_data['rate_var'] = True if have_data_entry(form_data, 'rate_var') else False
    parsed_data['rate_var'] = page_data['rate_var']

    if have_data_entry(form_data, 'step1'):
        if len(errors) == 0 and have_data_entry(form_data, 'continue'):
            page_data['step2'] = True
        return parsed_data, errors

    page_data['step2'] = True

    if have_data_entry(form_data, 'fee_from_conf'):
        page_data['fee_from_conf'] = int(get_data_entry(form_data, 'fee_from_conf'))
        parsed_data['fee_from_conf'] = page_data['fee_from_conf']

    if have_data_entry(form_data, 'fee_from_extra'):
        page_data['fee_from_extra'] = int(get_data_entry(form_data, 'fee_from_extra'))
        parsed_data['fee_from_extra'] = page_data['fee_from_extra']

    if have_data_entry(form_data, 'fee_to_conf'):
        page_data['fee_to_conf'] = int(get_data_entry(form_data, 'fee_to_conf'))
        parsed_data['fee_to_conf'] = page_data['fee_to_conf']

    if have_data_entry(form_data, 'fee_to_extra'):
        page_data['fee_to_extra'] = int(get_data_entry(form_data, 'fee_to_extra'))
        parsed_data['fee_to_extra'] = page_data['fee_to_extra']

    if have_data_entry(form_data, 'check_offer'):
        page_data['check_offer'] = True
    if have_data_entry(form_data, 'submit_offer'):
        page_data['submit_offer'] = True

    if have_data_entry(form_data, 'lockhrs'):
        page_data['lockhrs'] = int(get_data_entry(form_data, 'lockhrs'))
        parsed_data['lock_seconds'] = page_data['lockhrs'] * 60 * 60
    elif have_data_entry(form_data, 'lockmins'):
        page_data['lockmins'] = int(get_data_entry(form_data, 'lockmins'))
        parsed_data['lock_seconds'] = page_data['lockmins'] * 60
    elif have_data_entry(form_data, 'lockseconds'):
        parsed_data['lock_seconds'] = int(get_data_entry(form_data, 'lockseconds'))

    if have_data_entry(form_data, 'validhrs'):
        page_data['validhrs'] = int(get_data_entry(form_data, 'validhrs'))
        parsed_data['valid_for_seconds'] = page_data['validhrs'] * 60 * 60
    elif have_data_entry(form_data, 'valid_for_seconds'):
        parsed_data['valid_for_seconds'] = int(get_data_entry(form_data, 'valid_for_seconds'))

    page_data['automation_strat_id'] = int(get_data_entry_or(form_data, 'automation_strat_id', -1))
    parsed_data['automation_strat_id'] = page_data['automation_strat_id']
    if have_data_entry(form_data, 'swap_type'):
        parsed_data['swap_type'] = get_data_entry(form_data, 'swap_type')
    if have_data_entry(form_data, 'subfee'):
        parsed_data['subfee'] = True

    try:
        if len(errors) == 0 and page_data['swap_style'] == 'xmr':
            if have_data_entry(form_data, 'fee_rate_from'):
                page_data['from_fee_override'] = get_data_entry(form_data, 'fee_rate_from')
                parsed_data['from_fee_override'] = page_data['from_fee_override']
            else:
                from_fee_override, page_data['from_fee_src'] = swap_client.getFeeRateForCoin(parsed_data['coin_from'], page_data['fee_from_conf'])
                if page_data['fee_from_extra'] > 0:
                    from_fee_override += from_fee_override * (float(page_data['fee_from_extra']) / 100.0)
                page_data['from_fee_override'] = ci_from.format_amount(ci_from.make_int(from_fee_override, r=1))
                parsed_data['from_fee_override'] = page_data['from_fee_override']

                lock_spend_tx_vsize = ci_from.xmr_swap_alock_spend_tx_vsize()
                lock_spend_tx_fee = ci_from.make_int(ci_from.make_int(from_fee_override, r=1) * lock_spend_tx_vsize / 1000, r=1)
                page_data['amt_from_lock_spend_tx_fee'] = ci_from.format_amount(lock_spend_tx_fee // ci_from.COIN())
                page_data['tla_from'] = ci_from.ticker()

            if coin_to == Coins.XMR:
                if have_data_entry(form_data, 'fee_rate_to'):
                    page_data['to_fee_override'] = get_data_entry(form_data, 'fee_rate_to')
                    parsed_data['to_fee_override'] = page_data['to_fee_override']
                else:
                    to_fee_override, page_data['to_fee_src'] = swap_client.getFeeRateForCoin(parsed_data['coin_to'], page_data['fee_to_conf'])
                    if page_data['fee_to_extra'] > 0:
                        to_fee_override += to_fee_override * (float(page_data['fee_to_extra']) / 100.0)
                    page_data['to_fee_override'] = ci_to.format_amount(ci_to.make_int(to_fee_override, r=1))
                    parsed_data['to_fee_override'] = page_data['to_fee_override']
    except Exception as e:
        print('Error setting fee', str(e))  # Expected if missing fields

    return parsed_data, errors


def postNewOfferFromParsed(swap_client, parsed_data):
    swap_type = SwapTypes.SELLER_FIRST

    if 'swap_type' in parsed_data:
        str_swap_type = parsed_data['swap_type'].lower()
        if str_swap_type == 'seller_first':
            swap_type = SwapTypes.SELLER_FIRST
        elif str_swap_type == 'xmr_swap':
            swap_type = SwapTypes.XMR_SWAP
        else:
            raise ValueError('Unknown swap type')
    elif parsed_data['coin_to'] in (Coins.XMR, Coins.PART_ANON):
        swap_type = SwapTypes.XMR_SWAP

    if swap_client.coin_clients[parsed_data['coin_from']]['use_csv'] and swap_client.coin_clients[parsed_data['coin_to']]['use_csv']:
        lock_type = TxLockTypes.SEQUENCE_LOCK_TIME
    else:
        lock_type = TxLockTypes.ABS_LOCK_TIME

    extra_options = {}

    if 'fee_from_conf' in parsed_data:
        extra_options['from_fee_conf_target'] = parsed_data['fee_from_conf']
    if 'from_fee_multiplier_percent' in parsed_data:
        extra_options['from_fee_multiplier_percent'] = parsed_data['fee_from_extra']
    if 'from_fee_override' in parsed_data:
        extra_options['from_fee_override'] = parsed_data['from_fee_override']

    if 'fee_to_conf' in parsed_data:
        extra_options['to_fee_conf_target'] = parsed_data['fee_to_conf']
    if 'to_fee_multiplier_percent' in parsed_data:
        extra_options['to_fee_multiplier_percent'] = parsed_data['fee_to_extra']
    if 'to_fee_override' in parsed_data:
        extra_options['to_fee_override'] = parsed_data['to_fee_override']
    if 'valid_for_seconds' in parsed_data:
        extra_options['valid_for_seconds'] = parsed_data['valid_for_seconds']

    if 'addr_to' in parsed_data:
        extra_options['addr_send_to'] = parsed_data['addr_to']

    if parsed_data.get('amt_var', False):
        extra_options['amount_negotiable'] = parsed_data['amt_var']
    if parsed_data.get('rate_var', False):
        extra_options['rate_negotiable'] = parsed_data['rate_var']

    if parsed_data.get('rate_var', None) is not None:
        extra_options['rate_negotiable'] = parsed_data['rate_var']

    if parsed_data.get('automation_strat_id', None) is not None:
        extra_options['automation_id'] = parsed_data['automation_strat_id']

    swap_value = parsed_data['amt_from']
    if parsed_data.get('subfee', False):
        ci_from = swap_client.ci(parsed_data['coin_from'])
        pi = swap_client.pi(swap_type)
        itx = pi.getFundedInitiateTxTemplate(ci_from, swap_value, True)
        itx_decoded = ci_from.describeTx(itx.hex())
        n = pi.findMockVout(ci_from, itx_decoded)
        swap_value = ci_from.make_int(itx_decoded['vout'][n]['value'])
        extra_options = {'prefunded_itx': itx}

    offer_id = swap_client.postOffer(
        parsed_data['coin_from'],
        parsed_data['coin_to'],
        swap_value,
        parsed_data['rate'],
        parsed_data['amt_bid_min'],
        swap_type,
        lock_type=lock_type,
        lock_value=parsed_data['lock_seconds'],
        addr_send_from=parsed_data['addr_from'],
        extra_options=extra_options)
    return offer_id


def postNewOffer(swap_client, form_data):
    page_data = {}
    parsed_data, errors = parseOfferFormData(swap_client, form_data, page_data, options={'add_min_bid_amt': True})
    if len(errors) > 0:
        raise ValueError('Parse errors: ' + ' '.join(errors))
    return postNewOfferFromParsed(swap_client, parsed_data)


def offer_to_post_string(self, swap_client, offer_id):

    offer, xmr_offer = swap_client.getXmrOffer(offer_id)
    ensure(offer, 'Unknown offer ID')

    ci_from = swap_client.ci(offer.coin_from)
    ci_to = swap_client.ci(offer.coin_to)
    offer_data = {
        'formid': self.generate_form_id(),
        'addr_to': offer.addr_to,
        'addr_from': offer.addr_from,
        'coin_from': offer.coin_from,
        'coin_to': offer.coin_to,
        # TODO store fee conf, or pass directly
        # 'fee_from_conf'
        # 'fee_to_conf'
        'amt_from': ci_from.format_amount(offer.amount_from),
        'amt_bid_min': ci_from.format_amount(offer.min_bid_amount),
        'rate': ci_to.format_amount(offer.rate),
        'amt_to': ci_to.format_amount((offer.amount_from * offer.rate) // ci_from.COIN()),
        'validhrs': offer.time_valid // (60 * 60),
    }

    if offer.amount_negotiable:
        offer_data['amt_var'] = True
    if offer.rate_negotiable:
        offer_data['rate_var'] = True

    if offer.lock_type == TxLockTypes.SEQUENCE_LOCK_TIME or offer.lock_type == TxLockTypes.ABS_LOCK_TIME:
        if offer.lock_value > 60 * 60:
            offer_data['lockhrs'] = offer.lock_value // (60 * 60)
        else:
            offer_data['lockhrs'] = offer.lock_value // 60
    try:
        strategy = swap_client.getLinkedStrategy(Concepts.OFFER, offer.offer_id)
        offer_data['automation_strat_id'] = strategy[0]
    except Exception:
        pass  # None found

    return parse.urlencode(offer_data).encode()


def page_newoffer(self, url_split, post_string):
    server = self.server
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    messages = []
    err_messages = []
    page_data = {
        # Set defaults
        'addr_to': -1,
        'fee_from_conf': 2,
        'fee_to_conf': 2,
        'validhrs': 1,
        'lockhrs': 32,
        'lockmins': 30,  # used in debug mode
        'debug_ui': swap_client.debug_ui,
        'automation_strat_id': -1,
        'amt_bid_min': format_amount(1000, 8),
    }

    post_data = parse.parse_qs(post_string)
    if 'offer_from' in post_data:
        offer_from_id_hex = post_data['offer_from'][0]
        offer_from_id = decode_offer_id(offer_from_id_hex)
        post_string = offer_to_post_string(self, swap_client, offer_from_id)

    form_data = self.checkForm(post_string, 'newoffer', err_messages)

    if form_data:
        try:
            parsed_data, errors = parseOfferFormData(swap_client, form_data, page_data)
            for e in errors:
                err_messages.append(str(e))
        except Exception as e:
            if swap_client.debug is True:
                swap_client.log.error(traceback.format_exc())
            err_messages.append(str(e))

    if len(err_messages) == 0 and 'submit_offer' in page_data:
        try:
            offer_id = postNewOfferFromParsed(swap_client, parsed_data)
            messages.append('<a href="/offer/' + offer_id.hex() + '">Sent Offer {}</a>'.format(offer_id.hex()))
            page_data = {}
        except Exception as e:
            if swap_client.debug is True:
                swap_client.log.error(traceback.format_exc())
            err_messages.append(str(e))

    if len(err_messages) == 0 and 'check_offer' in page_data:
        template = server.env.get_template('offer_confirm.html')
    elif 'step2' in page_data:
        template = server.env.get_template('offer_new_2.html')
    else:
        template = server.env.get_template('offer_new_1.html')

    if swap_client.debug_ui:
        messages.append('Debug mode active.')

    coins_from, coins_to = listAvailableCoins(swap_client, split_from=True)

    automation_filters = {}
    automation_filters['sort_by'] = 'label'
    automation_filters['type_ind'] = Concepts.OFFER
    automation_strategies = swap_client.listAutomationStrategies(automation_filters)

    return self.render_template(template, {
        'messages': messages,
        'err_messages': err_messages,
        'coins_from': coins_from,
        'coins': coins_to,
        'addrs': swap_client.listSmsgAddresses('offer_send_from'),
        'addrs_to': swap_client.listSmsgAddresses('offer_send_to'),
        'data': page_data,
        'automation_strategies': automation_strategies,
        'summary': summary,
    })


def page_offer(self, url_split, post_string):
    ensure(len(url_split) > 2, 'Offer ID not specified')
    offer_id = decode_offer_id(url_split[2])
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()
    offer, xmr_offer = swap_client.getXmrOffer(offer_id)
    ensure(offer, 'Unknown offer ID')

    extend_data = {  # Defaults
        'nb_validmins': 10,
    }
    messages = []
    err_messages = []
    if swap_client.debug_ui:
        messages.append('Debug mode active.')
    sent_bid_id = None
    show_bid_form = None
    form_data = self.checkForm(post_string, 'offer', err_messages)

    ci_from = swap_client.ci(Coins(offer.coin_from))
    ci_to = swap_client.ci(Coins(offer.coin_to))

    # Set defaults
    debugind = -1
    bid_amount = ci_from.format_amount(offer.amount_from)
    bid_rate = ci_to.format_amount(offer.rate)

    if form_data:
        if b'archive_offer' in form_data:
            try:
                swap_client.archiveOffer(offer_id)
                messages.append('Offer archived')
            except Exception as ex:
                err_messages.append('Archive offer failed: ' + str(ex))
        if b'revoke_offer' in form_data:
            try:
                swap_client.revokeOffer(offer_id)
                messages.append('Offer revoked')
            except Exception as ex:
                err_messages.append('Revoke offer failed: ' + str(ex))
        elif b'repeat_offer' in form_data:
            # Can't set the post data here as browsers will always resend the original post data when responding to redirects
            self.send_response(302)
            self.send_header('Location', '/newoffer?offer_from=' + offer_id.hex())
            self.end_headers()
            return bytes()
        elif b'newbid' in form_data:
            show_bid_form = True
        elif b'sendbid' in form_data:
            try:
                addr_from = form_data[b'addr_from'][0].decode('utf-8')
                extend_data['nb_addr_from'] = addr_from
                if addr_from == '-1':
                    addr_from = None

                minutes_valid = int(form_data[b'validmins'][0].decode('utf-8'))
                extend_data['nb_validmins'] = minutes_valid

                extra_options = {
                    'valid_for_seconds': minutes_valid * 60,
                }
                if have_data_entry(form_data, 'bid_rate'):
                    bid_rate = get_data_entry(form_data, 'bid_rate')
                    extra_options['bid_rate'] = ci_to.make_int(bid_rate, r=1)

                if have_data_entry(form_data, 'bid_amount'):
                    bid_amount = get_data_entry(form_data, 'bid_amount')
                    amount_from = inputAmount(bid_amount, ci_from)
                else:
                    amount_from = offer.amount_from
                debugind = int(get_data_entry_or(form_data, 'debugind', -1))

                sent_bid_id = swap_client.postBid(offer_id, amount_from, addr_send_from=addr_from, extra_options=extra_options).hex()

                if debugind > -1:
                    swap_client.setBidDebugInd(bytes.fromhex(sent_bid_id), debugind)
            except Exception as ex:
                if self.server.swap_client.debug is True:
                    self.server.swap_client.log.error(traceback.format_exc())
                err_messages.append('Send bid failed: ' + str(ex))
                show_bid_form = True

    now = int(time.time())
    data = {
        'tla_from': ci_from.ticker(),
        'tla_to': ci_to.ticker(),
        'state': strOfferState(offer.state),
        'coin_from': ci_from.coin_name(),
        'coin_to': ci_to.coin_name(),
        'coin_from_ind': int(ci_from.coin_type()),
        'coin_to_ind': int(ci_to.coin_type()),
        'amt_from': ci_from.format_amount(offer.amount_from),
        'amt_to': ci_to.format_amount((offer.amount_from * offer.rate) // ci_from.COIN()),
        'amt_bid_min': ci_from.format_amount(offer.min_bid_amount),
        'rate': ci_to.format_amount(offer.rate),
        'lock_type': getLockName(offer.lock_type),
        'lock_value': offer.lock_value,
        'addr_from': offer.addr_from,
        'addr_to': 'Public' if offer.addr_to == swap_client.network_addr else offer.addr_to,
        'created_at': offer.created_at,
        'expired_at': offer.expire_at,
        'sent': offer.was_sent,
        'was_revoked': 'True' if offer.active_ind == 2 else 'False',
        'show_bid_form': show_bid_form,
        'amount_negotiable': offer.amount_negotiable,
        'rate_negotiable': offer.rate_negotiable,
        'bid_amount': bid_amount,
        'bid_rate': bid_rate,
        'debug_ui': swap_client.debug_ui,
        'automation_strat_id': -1,
        'is_expired': offer.expire_at <= now,
        'active_ind': offer.active_ind
    }
    data.update(extend_data)

    if offer.lock_type == TxLockTypes.SEQUENCE_LOCK_TIME or offer.lock_type == TxLockTypes.ABS_LOCK_TIME:
        if offer.lock_value > 60 * 60:
            data['lock_value_hr'] = ' ({} hours)'.format(offer.lock_value / (60 * 60))
        else:
            data['lock_value_hr'] = ' ({} minutes)'.format(offer.lock_value / 60)

    addr_from_label, addr_to_label = swap_client.getAddressLabel([offer.addr_from, offer.addr_to])
    if len(addr_from_label) > 0:
        data['addr_from_label'] = '(' + addr_from_label + ')'
    if len(addr_to_label) > 0:
        data['addr_to_label'] = '(' + addr_to_label + ')'

    if swap_client.debug_ui:
        data['debug_ind'] = debugind
        data['debug_options'] = [(int(t), t.name) for t in DebugTypes]

    if xmr_offer:
        int_fee_rate_now, fee_source = ci_from.get_fee_rate()
        data['xmr_type'] = True
        data['a_fee_rate'] = ci_from.format_amount(xmr_offer.a_fee_rate)
        data['a_fee_rate_verify'] = ci_from.format_amount(int_fee_rate_now, conv_int=True)
        data['a_fee_rate_verify_src'] = fee_source
        data['a_fee_warn'] = xmr_offer.a_fee_rate < int_fee_rate_now

        lock_spend_tx_vsize = ci_from.xmr_swap_alock_spend_tx_vsize()
        lock_spend_tx_fee = ci_from.make_int(xmr_offer.a_fee_rate * lock_spend_tx_vsize / 1000, r=1)
        data['amt_from_lock_spend_tx_fee'] = ci_from.format_amount(lock_spend_tx_fee // ci_from.COIN())

    if offer.was_sent:
        try:
            strategy = swap_client.getLinkedStrategy(Concepts.OFFER, offer_id)
            data['automation_strat_id'] = strategy[0]
            data['automation_strat_label'] = strategy[1]
        except Exception:
            pass  # None found

    bids = swap_client.listBids(offer_id=offer_id)
    formatted_bids = []
    amt_swapped = 0
    for b in bids:
        amt_swapped += b[4]
        formatted_bids.append((b[2].hex(), ci_from.format_amount(b[4]), strBidState(b[5]), ci_to.format_amount(b[10]), b[11]))
    data['amt_swapped'] = ci_from.format_amount(amt_swapped)

    template = server.env.get_template('offer.html')
    return self.render_template(template, {
        'offer_id': offer_id.hex(),
        'sent_bid_id': sent_bid_id,
        'messages': messages,
        'err_messages': err_messages,
        'data': data,
        'bids': formatted_bids,
        'addrs': None if show_bid_form is None else swap_client.listSmsgAddresses('bid'),
        'summary': summary,
    })


def page_offers(self, url_split, post_string, sent=False):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    filters = {
        'coin_from': -1,
        'coin_to': -1,
        'page_no': 1,
        'limit': PAGE_LIMIT,
        'sort_by': 'created_at',
        'sort_dir': 'desc',
        'sent_from': 'any' if sent is False else 'only',
        'active': 'any',
    }
    messages = []
    form_data = self.checkForm(post_string, 'offers', messages)
    if form_data and have_data_entry(form_data, 'applyfilters'):
        filters['coin_from'] = setCoinFilter(form_data, 'coin_from')
        filters['coin_to'] = setCoinFilter(form_data, 'coin_to')

        if have_data_entry(form_data, 'sort_by'):
            sort_by = get_data_entry(form_data, 'sort_by')
            ensure(sort_by in ['created_at', 'rate'], 'Invalid sort by')
            filters['sort_by'] = sort_by
        if have_data_entry(form_data, 'sort_dir'):
            sort_dir = get_data_entry(form_data, 'sort_dir')
            ensure(sort_dir in ['asc', 'desc'], 'Invalid sort dir')
            filters['sort_dir'] = sort_dir
        if have_data_entry(form_data, 'sent_from'):
            sent_from = get_data_entry(form_data, 'sent_from')
            ensure(sent_from in ['any', 'only'], 'Invalid sent filter')
            filters['sent_from'] = sent_from
        if have_data_entry(form_data, 'active'):
            active_filter = get_data_entry(form_data, 'active')
            ensure(active_filter in ['any', 'active', 'expired', 'revoked', 'archived'], 'Invalid active filter')
            filters['active'] = active_filter

    set_pagination_filters(form_data, filters)

    if filters['sent_from'] == 'only':
        sent = True
    else:
        sent = False
    offers = swap_client.listOffers(sent, filters, with_bid_info=True)

    now = int(time.time())
    formatted_offers = []
    for row in offers:
        o, completed_amount = row
        ci_from = swap_client.ci(Coins(o.coin_from))
        ci_to = swap_client.ci(Coins(o.coin_to))
        is_expired = o.expire_at <= now
        formatted_offers.append((
            format_timestamp(o.created_at),
            o.offer_id.hex(),
            ci_from.coin_name(),
            ci_to.coin_name(),
            ci_from.format_amount(o.amount_from),
            ci_to.format_amount((o.amount_from * o.rate) // ci_from.COIN()),
            ci_to.format_amount(o.rate),
            'Public' if o.addr_to == swap_client.network_addr else o.addr_to,
            o.addr_from,
            o.was_sent,
            ci_from.format_amount(completed_amount),
            is_expired,
            o.active_ind))

    coins_from, coins_to = listAvailableCoins(swap_client, split_from=True)

    chart_api_key = swap_client.settings.get('chart_api_key', '')
    if chart_api_key == '':
        chart_api_key_enc = swap_client.settings.get('chart_api_key_enc', '')
        chart_api_key = 'cd7600e7b5fdd99c6f900673ff0ee8f64d6d4219a4bb87191ad4a2e3fc65d7f4' if chart_api_key_enc == '' else bytes.fromhex(chart_api_key_enc).decode('utf-8')

    template = server.env.get_template('offers.html')
    return self.render_template(template, {
        'page_type': 'Your Offers' if sent else 'Network Order Book',
        'page_button': 'hidden' if sent else '',
        'page_type_description': 'Your entire offer history.' if sent else 'Consult available offers in the order book and initiate a coin swap.',
        'messages': messages,
        'show_chart': False if sent else swap_client.settings.get('show_chart', True),
        'chart_api_key': chart_api_key,
        'coins_from': coins_from,
        'coins': coins_to,
        'messages': messages,
        'filters': filters,
        'offers': formatted_offers,
        'summary': summary,
        'sent_offers': sent,
    })
