#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Create offers
"""

__version__ = '0.1'

import os
import json
import signal
import urllib
import logging
import argparse
import threading
from urllib.request import urlopen

delay_event = threading.Event()


def post_json_req(url, json_data):
    req = urllib.request.Request(url)
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    post_bytes = json.dumps(json_data).encode('utf-8')
    req.add_header('Content-Length', len(post_bytes))
    return urlopen(req, post_bytes, timeout=300).read()


def read_json_api(port, path=None, json_data=None):
    url = f'http://127.0.0.1:{port}/json'
    if path is not None:
        url += '/' + path

    if json_data is not None:
        return json.loads(post_json_req(url, json_data))
    return json.loads(urlopen(url, timeout=300).read())


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


def readTemplates(known_coins):
    offer_templates = []
    with open('offer_rules.csv', 'r') as fp:
        for i, line in enumerate(fp):
            if i < 1:
                continue
            line = line.strip()
            if line[0] == '#':
                continue
            row_data = line.split(',')
            try:
                if len(row_data) < 6:
                    raise ValueError('missing data')
                offer_template = {}
                offer_template['coin_from'] = findCoin(row_data[0], known_coins)
                offer_template['coin_to'] = findCoin(row_data[1], known_coins)
                offer_template['amount'] = row_data[2]
                offer_template['minrate'] = float(row_data[3])
                offer_template['ratetweakpercent'] = float(row_data[4])
                offer_template['amount_variable'] = row_data[5].lower() in ('true', 1)
                offer_template['address'] = row_data[6]
                offer_templates.append(offer_template)
            except Exception as e:
                print(f'Warning: Skipping row {i}, {e}')
                continue
    return offer_templates


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))
    parser.add_argument('--port', dest='port', help='RPC port (default=12700)', type=int, default=12700, required=False)
    args = parser.parse_args()

    if not os.path.exists('offer_rules.csv'):
        with open('offer_rules.csv', 'w') as fp:
            # Set address to -1 to use new addresses
            fp.write('coin from,coin to,offer value,min rate,rate tweak percent,amount variable,address')

    known_coins = read_json_api(args.port, 'coins')
    coins_map = {}
    for known_coin in known_coins:
        coins_map[known_coin['name']] = known_coin

    signal.signal(signal.SIGINT, signal_handler)
    while not delay_event.is_set():
        # Read templates each iteration so they can be modified without restarting
        offer_templates = readTemplates(known_coins)

        try:
            recieved_offers = read_json_api(args.port, 'offers', {'active': 'active', 'include_sent': False})
            print('recieved_offers', recieved_offers)

            sent_offers = read_json_api(args.port, 'sentoffers', {'active': 'active'})

            for offer_template in offer_templates:
                offers_found = 0
                for offer in sent_offers:
                    if offer['coin_from'] == offer_template['coin_from'] and offer['coin_to'] == offer_template['coin_to']:
                        offers_found += 1

                if offers_found > 0:
                    continue
                coin_from_data = coins_map[offer_template['coin_from']]
                coin_to_data = coins_map[offer_template['coin_to']]

                rates = read_json_api(args.port, 'rates', {'coin_from': coin_from_data['id'], 'coin_to': coin_to_data['id']})
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
                offer_data = {
                    'addr_from': offer_template['address'],
                    'coin_from': coin_from_data['ticker'],
                    'coin_to': coin_to_data['ticker'],
                    'amt_from': offer_template['amount'],
                    'amt_var': offer_template['amount_variable'],
                    'rate': use_rate,
                    'swap_type': 'adaptor_sig',
                    'lockhrs': '24',
                    'automation_strat_id': 1}
                new_offer = read_json_api(args.port, 'offers/new', offer_data)
                print('New offer: {}'.format(new_offer))
        except Exception as e:
            print('Error: Clamping rate to minimum.')

        print('Looping indefinitely, ctrl+c to exit.')
        delay_event.wait(60)

    print('Done.')


if __name__ == '__main__':
    main()
