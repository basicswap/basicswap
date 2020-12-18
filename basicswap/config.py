# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

CONFIG_FILENAME = 'basicswap.json'
DEFAULT_DATADIR = '~/.basicswap'
DEFAULT_ALLOW_CORS = False
TEST_DATADIRS = os.path.expanduser(os.getenv('DATADIRS', '/tmp/basicswap'))

bin_suffix = ('.exe' if os.name == 'nt' else '')
PARTICL_BINDIR = os.path.expanduser(os.getenv('PARTICL_BINDIR', ''))
PARTICLD = os.getenv('PARTICLD', 'particld' + bin_suffix)
PARTICL_CLI = os.getenv('PARTICL_CLI', 'particl-cli' + bin_suffix)
PARTICL_TX = os.getenv('PARTICL_TX', 'particl-tx' + bin_suffix)

BITCOIN_BINDIR = os.path.expanduser(os.getenv('BITCOIN_BINDIR', ''))
BITCOIND = os.getenv('BITCOIND', 'bitcoind' + bin_suffix)
BITCOIN_CLI = os.getenv('BITCOIN_CLI', 'bitcoin-cli' + bin_suffix)
BITCOIN_TX = os.getenv('BITCOIN_TX', 'bitcoin-tx' + bin_suffix)

LITECOIN_BINDIR = os.path.expanduser(os.getenv('LITECOIN_BINDIR', ''))
LITECOIND = os.getenv('LITECOIND', 'litecoind' + bin_suffix)
LITECOIN_CLI = os.getenv('LITECOIN_CLI', 'litecoin-cli' + bin_suffix)
LITECOIN_TX = os.getenv('LITECOIN_TX', 'litecoin-tx' + bin_suffix)

NAMECOIN_BINDIR = os.path.expanduser(os.getenv('NAMECOIN_BINDIR', ''))
NAMECOIND = os.getenv('NAMECOIND', 'namecoind' + bin_suffix)
NAMECOIN_CLI = os.getenv('NAMECOIN_CLI', 'namecoin-cli' + bin_suffix)
NAMECOIN_TX = os.getenv('NAMECOIN_TX', 'namecoin-tx' + bin_suffix)

XMR_BINDIR = os.path.expanduser(os.getenv('XMR_BINDIR', ''))
XMRD = os.getenv('XMRD', 'monerod' + bin_suffix)
XMR_WALLET_RPC = os.getenv('XMR_WALLET_RPC', 'monero-wallet-rpc' + bin_suffix)
