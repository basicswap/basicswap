# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os

DATADIRS = os.path.expanduser(os.getenv('DATADIRS', '/tmp/basicswap'))

PARTICL_BINDIR = os.path.expanduser(os.getenv('PARTICL_BINDIR', ''))
PARTICLD = os.getenv('PARTICLD', 'particld')
PARTICL_CLI = os.getenv('PARTICL_CLI', 'particl-cli')
PARTICL_TX = os.getenv('PARTICL_TX', 'particl-tx')

BITCOIN_BINDIR = os.path.expanduser(os.getenv('BITCOIN_BINDIR', ''))
BITCOIND = os.getenv('BITCOIND', 'bitcoind')
BITCOIN_CLI = os.getenv('BITCOIN_CLI', 'bitcoin-cli')
BITCOIN_TX = os.getenv('BITCOIN_TX', 'bitcoin-tx')

LITECOIN_BINDIR = os.path.expanduser(os.getenv('LITECOIN_BINDIR', ''))
LITECOIND = os.getenv('LITECOIND', 'litecoind')
LITECOIN_CLI = os.getenv('LITECOIN_CLI', 'litecoin-cli')
LITECOIN_TX = os.getenv('LITECOIN_TX', 'litecoin-tx')
