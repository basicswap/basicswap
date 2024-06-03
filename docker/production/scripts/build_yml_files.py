#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Join docker compose fragments
"""

__version__ = '0.1'

import os
import argparse


def get_bkp_offset(filename, ext='yml'):
    for i in range(1000):
        if not os.path.exists(f'{filename}_bkp_{i}.{ext}'):
            return i
    raise ValueError(f'Unable to get backup filename for: {filename}.{ext}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s {version}'.format(version=__version__))
    parser.add_argument('-c', '--coins', nargs='+', help='<Required> Select coins', required=True)
    parser.add_argument('--withscript', dest='withscript', help='Add container to run createoffers.py (default=false)', required=False, action='store_true')
    args = parser.parse_args()

    with_coins = ['particl', ]
    for coin_name in args.coins:
        parsed_name = coin_name.lower()
        if parsed_name not in with_coins:
            with_coins.append(parsed_name)

    print('Preparing docker compose files with coins:', ','.join(with_coins))

    num_docker_compose = get_bkp_offset('docker-compose')
    num_docker_compose_prepare = get_bkp_offset('docker-compose-prepare')

    if os.path.exists('docker-compose.yml'):
        os.rename('docker-compose.yml', f'docker-compose_bkp_{num_docker_compose}.yml')
    if os.path.exists('docker-compose-prepare.yml'):
        os.rename('docker-compose-prepare.yml', f'docker-compose-prepare_bkp_{num_docker_compose_prepare}.yml')

    fragments_dir = 'compose-fragments'
    with open('docker-compose.yml', 'wb') as fp, open('docker-compose-prepare.yml', 'wb') as fpp:
        with open(os.path.join(fragments_dir, '0_start.yml'), 'rb') as fp_in:
            for line in fp_in:
                fp.write(line)
                fpp.write(line)

        for coin_name in with_coins:
            if coin_name == 'particl':
                # Nothing to do
                continue
            if coin_name in ('monero', 'wownero'):
                with open(os.path.join(fragments_dir, '1_{coin_name}-wallet.yml'), 'rb') as fp_in:
                    for line in fp_in:
                        fp.write(line)
                        fpp.write(line)
                with open(os.path.join(fragments_dir, '8_{coin_name}-daemon.yml'), 'rb') as fp_in:
                    for line in fp_in:
                        fp.write(line)
                continue
            if coin_name == 'decred':
                with open(os.path.join(fragments_dir, '1_decred-wallet.yml'), 'rb') as fp_in:
                    for line in fp_in:
                        fp.write(line)
                        fpp.write(line)
                with open(os.path.join(fragments_dir, '8_decred-daemon.yml'), 'rb') as fp_in:
                    for line in fp_in:
                        fp.write(line)
                continue
            with open(os.path.join(fragments_dir, f'1_{coin_name}.yml'), 'rb') as fp_in:
                for line in fp_in:
                    fp.write(line)
                    fpp.write(line)

        with open(os.path.join(fragments_dir, '8_swapclient.yml'), 'rb') as fp_in:
            for line in fp_in:
                fp.write(line)

        if args.withscript:
            with open(os.path.join(fragments_dir, '8_script.yml'), 'rb') as fp_in:
                for line in fp_in:
                    fp.write(line)

        with open(os.path.join(fragments_dir, '9_swapprepare.yml'), 'rb') as fp_in:
            for line in fp_in:
                fpp.write(line)
    print('Done.')


if __name__ == '__main__':
    main()
