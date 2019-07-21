#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

"""
Particl Atomic Swap - Proof of Concept

sudo pip install python-gnupg

"""

import sys
import os
import subprocess
import time
import json
import hashlib
import mmap
import tarfile
import urllib.request
import urllib.parse
import logging

import gnupg


logger = logging.getLogger()
logger.level = logging.DEBUG


def printVersion():
    from basicswap import __version__
    logger.info('Basicswap version:', __version__)


def printHelp():
    logger.info('Usage: basicswap-prepare ')
    logger.info('\n--help, -h               Print help.')
    logger.info('\n--version, -v            Print version.')
    logger.info('\n--datadir=PATH           Path to basicswap data directory, default:~/.basicswap.')
    logger.info('\n--mainnet                Run in mainnet mode.')
    logger.info('\n--testnet                Run in testnet mode.')
    logger.info('\n--regtest                Run in regtest mode.')
    logger.info('\n--particl_mnemonic=      Recovery phrase to use for the Particl wallet, default is randomly generated.')


def main():
    print('main')
    data_dir = None
    chain = 'mainnet'
    particl_wallet_mnemonic = None

    for v in sys.argv[1:]:
        if len(v) < 2 or v[0] != '-':
            logger.warning('Unknown argument', v)
            continue

        s = v.split('=')
        name = s[0].strip()

        for i in range(2):
            if name[0] == '-':
                name = name[1:]

        if name == 'v' or name == 'version':
            printVersion()
            return 0
        if name == 'h' or name == 'help':
            printHelp()
            return 0
        if name == 'mainnet':
            continue
        if name == 'testnet':
            chain = 'testnet'
            continue
        if name == 'regtest':
            chain = 'regtest'
            continue

        if len(s) == 2:
            if name == 'datadir':
                data_dir = os.path.expanduser(s[1])
                continue
            if name == 'particl_mnemonic':
                particl_wallet_mnemonic = s[1]
                continue

        logger.warning('Unknown argument', v)

    if data_dir is None:
        default_datadir = '~/.basicswap'
        data_dir = os.path.join(os.path.expanduser(default_datadir))
    logger.info('Using datadir: %s', data_dir)
    logger.info('Chain: %s', chain)

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    config_path = os.path.join(data_dir, 'basicswap.json')
    if os.path.exists(config_path):
        sys.stderr.write('Error: {} exists, exiting.'.format(config_path))
        exit(1)

    settings = {
        'debug': True,
    }

    with open(config_path, 'w') as fp:
        json.dump(settings, fp, indent=4)

    logger.info('Done.')

if __name__ == '__main__':
    main()
