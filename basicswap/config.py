# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os

DEBUG = True

CONFIG_FILENAME = 'basicswap.json'
DEFAULT_DATADIR = '~/.basicswap'
TEST_DATADIRS = os.path.expanduser(os.getenv('DATADIRS', '/tmp/basicswap'))

PARTICL_BINDIR = os.path.expanduser(os.getenv('PARTICL_BINDIR', ''))
PARTICLD = os.getenv('PARTICLD', 'particld' + ('.exe' if os.name == 'nt' else ''))
PARTICL_CLI = os.getenv('PARTICL_CLI', 'particl-cli' + ('.exe' if os.name == 'nt' else ''))
PARTICL_TX = os.getenv('PARTICL_TX', 'particl-tx' + ('.exe' if os.name == 'nt' else ''))

BITCOIN_BINDIR = os.path.expanduser(os.getenv('BITCOIN_BINDIR', ''))
BITCOIND = os.getenv('BITCOIND', 'bitcoind' + ('.exe' if os.name == 'nt' else ''))
BITCOIN_CLI = os.getenv('BITCOIN_CLI', 'bitcoin-cli' + ('.exe' if os.name == 'nt' else ''))
BITCOIN_TX = os.getenv('BITCOIN_TX', 'bitcoin-tx' + ('.exe' if os.name == 'nt' else ''))

LITECOIN_BINDIR = os.path.expanduser(os.getenv('LITECOIN_BINDIR', ''))
LITECOIND = os.getenv('LITECOIND', 'litecoind' + ('.exe' if os.name == 'nt' else ''))
LITECOIN_CLI = os.getenv('LITECOIN_CLI', 'litecoin-cli' + ('.exe' if os.name == 'nt' else ''))
LITECOIN_TX = os.getenv('LITECOIN_TX', 'litecoin-tx' + ('.exe' if os.name == 'nt' else ''))

NAMECOIN_BINDIR = os.path.expanduser(os.getenv('NAMECOIN_BINDIR', ''))
NAMECOIND = os.getenv('NAMECOIND', 'namecoind' + ('.exe' if os.name == 'nt' else ''))
NAMECOIN_CLI = os.getenv('NAMECOIN_CLI', 'namecoin-cli' + ('.exe' if os.name == 'nt' else ''))
NAMECOIN_TX = os.getenv('NAMECOIN_TX', 'namecoin-tx' + ('.exe' if os.name == 'nt' else ''))
