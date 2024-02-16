#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Create offers
"""

__version__ = '0.2'

import os
import json
import time
import random
import shutil
import signal
import urllib
import logging
import argparse
import threading
from urllib.request import urlopen

delay_event = threading.Event()

DEFAULT_CONFIG_FILE: str = 'createoffers.json'
DEFAULT_STATE_FILE: str = 'createoffers_state.json'


def post_req(url: str, json_data=None):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    if json_data:
        req.add_header('Content-Type', 'application/json; charset=utf-8')
        post_bytes = json.dumps(json_data).encode('utf-8')
        req.add_header('Content-Length', len(post_bytes))
    else:
        post_bytes = None
    return urlopen(req, data=post_bytes, timeout=300).read()


def make_json_api_func(host: str, port: int):
    host = host
    port = port

    def api_func(path=None, json_data=None, timeout=300):
        nonlocal host, port
        url = f'http://{host}:{port}/json'
        if path is not None:
            url += '/' + path
        if json_data is not None:
            return json.loads(post_req(url, json_data))
        response = urlopen(url, timeout=300).read()
        return json.loads(response)
    return api_func


def signal_handler(sig, frame) -> None:
    logging.info('Signal {} detected.'.format(sig))
    delay_event.set()


def findCoin(coin: str, known_coins) -> str:
    for known_coin in known_coins:
        if known_coin['name'].lower() == coin.lower() or known_coin['ticker'].lower() == coin.lower():
            if known_coin['active'] is False:
                raise ValueError(f'Inactive coin {coin}')
            return known_coin['name']
    raise ValueError(f'Unknown coin {coin}')


def readConfig(args, known_coins):
    config_path: str = args.configfile
    num_changes: int = 0
    with open(config_path) as fs:
        config = json.load(fs)

    if 'offers' not in config:
        config['offers'] = []
    if 'bids' not in config:
        config['bids'] = []
    if 'stealthex' not in config:
        config['stealthex'] = []

    if 'min_seconds_between_offers' not in config:
        config['min_seconds_between_offers'] = 60
        print('Set min_seconds_between_offers', config['min_seconds_between_offers'])
        num_changes += 1
    if 'max_seconds_between_offers' not in config:
        config['max_seconds_between_offers'] = config['min_seconds_between_offers'] * 4
        print('Set max_seconds_between_offers', config['max_seconds_between_offers'])
        num_changes += 1

    if 'min_seconds_between_bids' not in config:
        config['min_seconds_between_bids'] = 60
        print('Set min_seconds_between_bids', config['min_seconds_between_bids'])
        num_changes += 1
    if 'max_seconds_between_bids' not in config:
        config['max_seconds_between_bids'] = config['min_seconds_between_bids'] * 4
        print('Set max_seconds_between_bids', config['max_seconds_between_bids'])
        num_changes += 1

    offer_templates = config['offers']
    offer_templates_map = {}
    num_enabled = 0
    for i, offer_template in enumerate(offer_templates):
        num_enabled += 1 if offer_template.get('enabled', True) else 0
        if 'name' not in offer_template:
            print('Naming offer template', i)
            offer_template['name'] = f'Offer {i}'
            num_changes += 1
        if offer_template['name'] in offer_templates_map:
            print('Renaming offer template', offer_template['name'])
            original_name = offer_template['name']
            offset = 2
            while f'{original_name}_{offset}' in offer_templates_map:
                offset += 1
            offer_template['name'] = f'{original_name}_{offset}'
            num_changes += 1
        offer_templates_map[offer_template['name']] = offer_template

        if offer_template.get('min_coin_from_amt', 0) < offer_template['amount']:
            print('Setting min_coin_from_amt for', offer_template['name'])
            offer_template['min_coin_from_amt'] = offer_template['amount']
            num_changes += 1

        if 'address' not in offer_template:
            print('Setting address to auto for offer', offer_template['name'])
            offer_template['address'] = 'auto'
            num_changes += 1
        if 'ratetweakpercent' not in offer_template:
            print('Setting ratetweakpercent to 0 for offer', offer_template['name'])
            offer_template['ratetweakpercent'] = 0
            num_changes += 1
        if 'amount_variable' not in offer_template:
            print('Setting amount_variable to True for offer', offer_template['name'])
            offer_template['amount_variable'] = True
            num_changes += 1

        if offer_template.get('enabled', True) is False:
            continue
        offer_template['coin_from'] = findCoin(offer_template['coin_from'], known_coins)
        offer_template['coin_to'] = findCoin(offer_template['coin_to'], known_coins)
    config['num_enabled_offers'] = num_enabled

    bid_templates = config['bids']
    bid_templates_map = {}
    num_enabled = 0
    for i, bid_template in enumerate(bid_templates):
        num_enabled += 1 if bid_template.get('enabled', True) else 0
        if 'name' not in bid_template:
            print('Naming bid template', i)
            bid_template['name'] = f'Bid {i}'
            num_changes += 1
        if bid_template['name'] in bid_templates_map:
            print('Renaming bid template', bid_template['name'])
            original_name = bid_template['name']
            offset = 2
            while f'{original_name}_{offset}' in bid_templates_map:
                offset += 1
            bid_template['name'] = f'{original_name}_{offset}'
            num_changes += 1
        bid_templates_map[bid_template['name']] = bid_template

        if bid_template.get('min_swap_amount', 0.0) < 0.00001:
            print('Setting min_swap_amount for bid template', bid_template['name'])
            bid_template['min_swap_amount'] = 0.00001

        if 'address' not in bid_template:
            print('Setting address to auto for bid', bid_template['name'])
            bid_template['address'] = 'auto'
            num_changes += 1

        if bid_template.get('enabled', True) is False:
            continue
        bid_template['coin_from'] = findCoin(bid_template['coin_from'], known_coins)
        bid_template['coin_to'] = findCoin(bid_template['coin_to'], known_coins)
    config['num_enabled_bids'] = num_enabled

    num_enabled = 0
    stealthex_swaps = config['stealthex']
    for i, swap in enumerate(stealthex_swaps):
        num_enabled += 1 if swap.get('enabled', True) else 0
        if swap.get('enabled', True) is False:
            continue
        swap['coin_from'] = findCoin(swap['coin_from'], known_coins)
    config['num_enabled_swaps'] = num_enabled

    if num_changes > 0:
        shutil.copyfile(config_path, config_path + '.last')
        with open(config_path, 'w') as fp:
            json.dump(config, fp, indent=4)

    return config


def write_state(statefile, script_state):
    if os.path.exists(statefile):
        shutil.copyfile(statefile, statefile + '.last')
    with open(statefile, 'w') as fp:
        json.dump(script_state, fp, indent=4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))
    parser.add_argument('--host', dest='host', help='RPC host (default=127.0.0.1)', type=str, default='127.0.0.1', required=False)
    parser.add_argument('--port', dest='port', help='RPC port (default=12700)', type=int, default=12700, required=False)
    parser.add_argument('--oneshot', dest='oneshot', help='Exit after one iteration (default=false)', required=False, action='store_true')
    parser.add_argument('--debug', dest='debug', help='Print extra debug messages (default=false)', required=False, action='store_true')
    parser.add_argument('--configfile', dest='configfile', help=f'config file path (default={DEFAULT_CONFIG_FILE})', type=str, default=DEFAULT_CONFIG_FILE, required=False)
    parser.add_argument('--statefile', dest='statefile', help=f'state file path (default={DEFAULT_STATE_FILE})', type=str, default=DEFAULT_STATE_FILE, required=False)
    args = parser.parse_args()

    read_json_api = make_json_api_func(args.host, args.port)

    if not os.path.exists(args.configfile):
        raise ValueError(f'Config file "{args.configfile}" not found.')

    known_coins = read_json_api('coins')
    coins_map = {}
    for known_coin in known_coins:
        coins_map[known_coin['name']] = known_coin

    script_state = {}
    if os.path.exists(args.statefile):
        with open(args.statefile) as fs:
            script_state = json.load(fs)

    signal.signal(signal.SIGINT, signal_handler)
    while not delay_event.is_set():
        # Read config each iteration so they can be modified without restarting
        config = readConfig(args, known_coins)
        offer_templates = config['offers']
        random.shuffle(offer_templates)

        bid_templates = config['bids']
        random.shuffle(bid_templates)

        stealthex_swaps = config['stealthex']
        random.shuffle(bid_templates)

        # override wallet api calls for testing
        if 'wallet_port_override' in config:
            wallet_api_port = int(config['wallet_port_override'])
            print(f'Overriding wallet api port: {wallet_api_port}')
            read_json_api_wallet = make_json_api_func(args.host, wallet_api_port)
        else:
            read_json_api_wallet = read_json_api

        try:
            sent_offers = read_json_api('sentoffers', {'active': 'active'})

            if args.debug and len(offer_templates) > 0:
                print('Processing {} offer template{}'.format(config['num_enabled_offers'], 's' if config['num_enabled_offers'] != 1 else ''))
            for offer_template in offer_templates:
                if offer_template.get('enabled', True) is False:
                    continue
                offers_found = 0

                coin_from_data = coins_map[offer_template['coin_from']]
                coin_to_data = coins_map[offer_template['coin_to']]

                wallet_from = read_json_api_wallet('wallets/{}'.format(coin_from_data['ticker']))

                for offer in sent_offers:
                    created_offers = script_state.get('offers', {})
                    prev_template_offers = created_offers.get(offer_template['name'], {})

                    if next((x for x in prev_template_offers if x['offer_id'] == offer['offer_id']), None):
                        offers_found += 1
                        if float(wallet_from['balance']) <= float(offer_template['min_coin_from_amt']):
                            offer_id = offer['offer_id']
                            print('Revoking offer {}, wallet from balance below minimum'.format(offer_id))
                            result = read_json_api(f'revokeoffer/{offer_id}')
                            print('revokeoffer', result)

                if offers_found > 0:
                    continue

                if float(wallet_from['balance']) <= float(offer_template['min_coin_from_amt']):
                    print('Skipping template {}, wallet from balance below minimum'.format(offer_template['name']))
                    continue

                delay_next_offer_before = script_state.get('delay_next_offer_before', 0)
                if delay_next_offer_before > int(time.time()):
                    print('Delaying offers until {}'.format(delay_next_offer_before))
                    break

                """
                received_offers = read_json_api(args.port, 'offers', {'active': 'active', 'include_sent': False, 'coin_from': coin_from_data['id'], 'coin_to': coin_to_data['id']})
                print('received_offers', received_offers)

                TODO - adjust rates based on existing offers
                """

                rates = read_json_api('rates', {'coin_from': coin_from_data['id'], 'coin_to': coin_to_data['id']})
                print('Rates', rates)
                coingecko_rate = float(rates['coingecko']['rate_inferred'])
                use_rate = coingecko_rate

                if offer_template['ratetweakpercent'] != 0:
                    print('Adjusting rate {} by {}%.'.format(use_rate, offer_template['ratetweakpercent']))
                    tweak = offer_template['ratetweakpercent'] / 100.0
                    use_rate += use_rate * tweak

                if use_rate < offer_template['minrate']:
                    print('Warning: Clamping rate to minimum.')
                    use_rate = offer_template['minrate']

                print('Creating offer for: {} at rate: {}'.format(offer_template, use_rate))
                template_from_addr = offer_template['address']
                offer_data = {
                    'addr_from': -1 if template_from_addr == 'auto' else template_from_addr,
                    'coin_from': coin_from_data['ticker'],
                    'coin_to': coin_to_data['ticker'],
                    'amt_from': offer_template['amount'],
                    'amt_var': offer_template['amount_variable'],
                    'valid_for_seconds': offer_template.get('offer_valid_seconds', config.get('offer_valid_seconds', 3600)),
                    'rate': use_rate,
                    'swap_type': offer_template.get('swap_type', 'adaptor_sig'),
                    'lockhrs': '24',
                    'automation_strat_id': 1}
                if args.debug:
                    print('offer data {}'.format(offer_data))
                new_offer = read_json_api('offers/new', offer_data)
                if 'error' in new_offer:
                    raise ValueError('Server failed to create offer: {}'.format(new_offer['error']))
                print('New offer: {}'.format(new_offer['offer_id']))
                if 'offers' not in script_state:
                    script_state['offers'] = {}
                template_name = offer_template['name']
                if template_name not in script_state['offers']:
                    script_state['offers'][template_name] = []
                script_state['offers'][template_name].append({'offer_id': new_offer['offer_id'], 'time': int(time.time())})
                max_seconds_between_offers = config['max_seconds_between_offers']
                min_seconds_between_offers = config['min_seconds_between_offers']
                if max_seconds_between_offers > min_seconds_between_offers:
                    time_between_offers = random.randint(min_seconds_between_offers, max_seconds_between_offers)
                else:
                    time_between_offers = min_seconds_between_offers
                script_state['delay_next_offer_before'] = int(time.time()) + time_between_offers
                write_state(args.statefile, script_state)

            if args.debug and len(bid_templates) > 0:
                print('Processing {} bid template{}'.format(config['num_enabled_bids'], 's' if config['num_enabled_bids'] != 1 else ''))
            for bid_template in bid_templates:
                if bid_template.get('enabled', True) is False:
                    continue
                delay_next_bid_before = script_state.get('delay_next_bid_before', 0)
                if delay_next_bid_before > int(time.time()):
                    print('Delaying bids until {}'.format(delay_next_bid_before))
                    break

                # Check bids in progress
                max_concurrent = bid_template.get('max_concurrent', 1)
                if 'bids' not in script_state:
                    script_state['bids'] = {}
                template_name = bid_template['name']
                if template_name not in script_state['bids']:
                    script_state['bids'][template_name] = []
                previous_bids = script_state['bids'][template_name]

                bids_in_progress: int = 0
                for previous_bid in previous_bids:
                    if not previous_bid['active']:
                        continue
                    previous_bid_id = previous_bid['bid_id']
                    previous_bid_info = read_json_api(f'bids/{previous_bid_id}')
                    bid_state = previous_bid_info['bid_state']
                    if bid_state in ('Completed', 'Timed-out', 'Abandoned', 'Error', 'Rejected'):
                        print(f'Marking bid inactive {previous_bid_id}, state {bid_state}')
                        previous_bid['active'] = False
                        write_state(args.statefile, script_state)
                        continue
                    if bid_state in ('Sent', 'Received') and previous_bid_info['expired_at'] < int(time.time()):
                        print(f'Marking bid inactive {previous_bid_id}, expired')
                        previous_bid['active'] = False
                        write_state(args.statefile, script_state)
                        continue
                    bids_in_progress += 1

                if bids_in_progress >= max_concurrent:
                    print('Max concurrent bids reached for template')
                    continue

                # Bidder sends coin_to and receives coin_from
                coin_from_data = coins_map[bid_template['coin_from']]
                coin_to_data = coins_map[bid_template['coin_to']]

                offers_options = {
                    'active': 'active',
                    'include_sent': False,
                    'coin_from': coin_from_data['id'],
                    'coin_to': coin_to_data['id'],
                    'with_extra_info': True,
                    'sort_by': 'rate',
                    'sort_dir': 'asc',
                }

                received_offers = read_json_api('offers', offers_options)
                if args.debug:
                    print('Received Offers', received_offers)

                for offer in received_offers:
                    offer_id = offer['offer_id']
                    offer_amount = float(offer['amount_from'])
                    offer_rate = float(offer['rate'])
                    bid_amount = bid_template['amount']

                    min_swap_amount = bid_template.get('min_swap_amount', 0.01)  # TODO: Make default vary per coin
                    can_adjust_offer_amount: bool = offer['amount_negotiable']
                    can_adjust_bid_amount: bool = bid_template.get('amount_variable', True)
                    can_adjust_amount: bool = can_adjust_offer_amount and can_adjust_bid_amount

                    if offer_amount < min_swap_amount:
                        if args.debug:
                            print(f'Offer amount below min swap amount bid {offer_id}')
                        continue

                    if can_adjust_offer_amount is False and offer_amount > bid_amount:
                        if args.debug:
                            print(f'Bid amount too low for offer {offer_id}')
                        continue

                    if bid_amount > offer_amount:
                        if can_adjust_bid_amount:
                            bid_amount = offer_amount
                        else:
                            if args.debug:
                                print(f'Bid amount too high for offer {offer_id}')
                            continue

                    if offer_rate > bid_template['maxrate']:
                        if args.debug:
                            print(f'Bid rate too low for offer {offer_id}')
                        continue

                    sent_bids = read_json_api('sentbids', {'offer_id': offer['offer_id'], 'with_available_or_active': True})
                    if len(sent_bids) > 0:
                        if args.debug:
                            print(f'Already bidding on offer {offer_id}')
                        continue

                    offer_identity = read_json_api('identities/{}'.format(offer['addr_from']))
                    if len(offer_identity) > 0:
                        id_offer_from = offer_identity[0]
                        automation_override = id_offer_from['automation_override']
                        if automation_override == 2:
                            if args.debug:
                                print(f'Not bidding on offer {offer_id}, automation_override ({automation_override}).')
                            continue
                        if automation_override == 1:
                            if args.debug:
                                print('Offer address from {}, set to always accept.'.format(offer['addr_from']))
                        else:
                            successful_sent_bids = id_offer_from['num_sent_bids_successful']
                            failed_sent_bids = id_offer_from['num_sent_bids_failed']
                            if failed_sent_bids > 3 and failed_sent_bids > successful_sent_bids:
                                if args.debug:
                                    print(f'Not bidding on offer {offer_id}, too many failed bids ({failed_sent_bids}).')
                                continue

                    validateamount: bool = False
                    max_coin_from_balance = bid_template.get('max_coin_from_balance', -1)
                    if max_coin_from_balance > 0:
                        wallet_from = read_json_api_wallet('wallets/{}'.format(coin_from_data['ticker']))
                        total_balance_from = float(wallet_from['balance']) + float(wallet_from['unconfirmed'])
                        if args.debug:
                            print(f'Total coin from balance {total_balance_from}')
                        if total_balance_from + bid_amount > max_coin_from_balance:
                            if can_adjust_amount and max_coin_from_balance - total_balance_from > min_swap_amount:
                                bid_amount = max_coin_from_balance - total_balance_from
                                validateamount = True
                                print(f'Reduced bid amount to {bid_amount}')
                            else:
                                if args.debug:
                                    print(f'Bid amount would exceed maximum wallet total for offer {offer_id}')
                                continue

                    min_coin_to_balance = bid_template['min_coin_to_balance']
                    if min_coin_to_balance > 0:
                        wallet_to = read_json_api_wallet('wallets/{}'.format(coin_to_data['ticker']))

                        total_balance_to = float(wallet_to['balance']) + float(wallet_to['unconfirmed'])
                        if args.debug:
                            print(f'Total coin to balance {total_balance_to}')

                        swap_amount_to = bid_amount * offer_rate
                        if total_balance_to - swap_amount_to < min_coin_to_balance:
                            if can_adjust_amount:
                                adjusted_swap_amount_to = total_balance_to - min_coin_to_balance
                                adjusted_bid_amount = adjusted_swap_amount_to / offer_rate

                                if adjusted_bid_amount > min_swap_amount:
                                    bid_amount = adjusted_bid_amount
                                    validateamount = True
                                    print(f'Reduced bid amount to {bid_amount}')
                                    swap_amount_to = adjusted_bid_amount * offer_rate

                        if total_balance_to - swap_amount_to < min_coin_to_balance:
                            if args.debug:
                                print(f'Bid amount would exceed minimum coin to wallet total for offer {offer_id}')
                            continue

                    if validateamount:
                        bid_amount = read_json_api('validateamount', {'coin': coin_from_data['ticker'], 'amount': bid_amount, 'method': 'rounddown'})
                    bid_data = {
                        'offer_id': offer['offer_id'],
                        'amount_from': bid_amount}

                    if 'address' in bid_template:
                        addr_from = bid_template['address']
                        if addr_from != -1 and addr_from != 'auto':
                            bid_data['addr_from'] = addr_from

                    if config.get('test_mode', False):
                        print('Would create bid: {}'.format(bid_data))
                        bid_id = 'simulated'
                    else:
                        if args.debug:
                            print('Creating bid: {}'.format(bid_data))
                        new_bid = read_json_api('bids/new', bid_data)
                        if 'error' in new_bid:
                            raise ValueError('Server failed to create bid: {}'.format(new_bid['error']))
                        print('New bid: {} on offer {}'.format(new_bid['bid_id'], offer['offer_id']))
                        bid_id = new_bid['bid_id']

                    script_state['bids'][template_name].append({'bid_id': bid_id, 'time': int(time.time()), 'active': True})

                    max_seconds_between_bids = config['max_seconds_between_bids']
                    min_seconds_between_bids = config['min_seconds_between_bids']
                    if max_seconds_between_bids > min_seconds_between_bids:
                        time_between_bids = random.randint(min_seconds_between_bids, max_seconds_between_bids)
                    else:
                        time_between_bids = min_seconds_between_bids
                    script_state['delay_next_bid_before'] = int(time.time()) + time_between_bids
                    write_state(args.statefile, script_state)
                    break  # Create max one bid per iteration

            if args.debug and len(stealthex_swaps) > 0:
                print('Processing {} stealthex template{}'.format(config['num_enabled_swaps'], 's' if config['num_enabled_swaps'] != 1 else ''))
            for stealthex_swap in stealthex_swaps:
                if stealthex_swap.get('enabled', True) is False:
                    continue
                coin_from_data = coins_map[stealthex_swap['coin_from']]

                wallet_from = read_json_api_wallet('wallets/{}'.format(coin_from_data['ticker']))

                current_balance = float(wallet_from['balance'])

                min_balance_from = float(stealthex_swap['min_balance_from'])
                min_swap_amount = float(stealthex_swap['min_amount_tx'])
                max_swap_amount = float(stealthex_swap['max_amount_tx'])

                # TODO: Check range limits

                if current_balance >= min_balance_from + min_swap_amount:
                    swap_amount = max_swap_amount
                    if current_balance - swap_amount < min_balance_from:
                        swap_amount = max(min_swap_amount, current_balance - min_balance_from)

                    estimate_url = 'https://api.stealthex.io/api/v2/estimate/{}/{}?amount={}&api_key={}&fixed=true'.format(coin_from_data['ticker'].lower(), stealthex_swap['coin_to'].lower(), swap_amount, stealthex_swap['api_key'])
                    if args.debug:
                        print(f'Estimate URL: {estimate_url}')
                    estimate_response = json.loads(post_req(estimate_url))

                    amount_to = float(estimate_response['estimated_amount'])
                    rate = swap_amount / amount_to
                    min_rate = float(stealthex_swap['min_rate'])
                    if rate < min_rate:
                        if args.debug:
                            print('Stealthex rate {} below minimum {} for {} to {}'.format(rate, min_rate, coin_from_data['ticker'], stealthex_swap['coin_to']))
                        continue

                    exchange_url = 'https://api.stealthex.io/api/v2/exchange?api_key={}'.format(stealthex_swap['api_key'])

                    address_to = stealthex_swap.get('receive_address', 'auto')
                    if address_to == 'auto':
                        address_to = read_json_api('wallets/{}/nextdepositaddr'.format(stealthex_swap['coin_to']))

                    address_refund = stealthex_swap.get('refund_address', 'auto')
                    if address_refund == 'auto':
                        address_refund = read_json_api('wallets/{}/nextdepositaddr'.format(coin_from_data['ticker']))

                    exchange_data = {
                        'currency_from': coin_from_data['ticker'].lower(),
                        'currency_to': stealthex_swap['coin_to'].lower(),
                        'address_to': address_to,
                        'amount_from': swap_amount,
                        'fixed': True,
                        # 'extra_id_to':
                        # 'referral':
                        'refund_address': address_refund,
                        # 'refund_extra_id':
                        'rate_id': estimate_response['rate_id'],
                    }

                    if args.debug:
                        print(f'Exchange URL: {estimate_url}')
                        print(f'Exchange data: {exchange_data}')

                    exchange_response = json.loads(post_req(exchange_url, exchange_data))

                    if 'Error' in estimate_response:
                        raise ValueError('Exchange error ' + estimate_response)

                    raise ValueError('TODO')

        except Exception as e:
            print(f'Error: {e}.')

        if args.oneshot:
            break
        print('Looping indefinitely, ctrl+c to exit.')
        delay_event.wait(60)

    print('Done.')


if __name__ == '__main__':
    main()
