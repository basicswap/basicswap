# -*- coding: utf-8 -*-

# Copyright (c) 2019-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import threading

from enum import IntEnum
from .util import (
    COIN,
    make_int,
    format_amount,
    TemporaryError,
)

XMR_COIN = 10 ** 12


class Coins(IntEnum):
    PART = 1
    BTC = 2
    LTC = 3
    # DCR = 4
    NMC = 5
    XMR = 6
    PART_BLIND = 7
    PART_ANON = 8
    # ZANO = 9
    # NDAU = 10
    PIVX = 11
    DASH = 12
    FIRO = 13
    NAV = 14
    LTC_MWEB = 15


chainparams = {
    Coins.PART: {
        'name': 'particl',
        'ticker': 'PART',
        'message_magic': 'Bitcoin Signed Message:\n',
        'blocks_target': 60 * 2,
        'decimal_places': 8,
        'mainnet': {
            'rpcport': 51735,
            'pubkey_address': 0x38,
            'script_address': 0x3c,
            'key_prefix': 0x6c,
            'stealth_key_prefix': 0x14,
            'hrp': 'pw',
            'bip44': 44,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 51935,
            'pubkey_address': 0x76,
            'script_address': 0x7a,
            'key_prefix': 0x2e,
            'stealth_key_prefix': 0x15,
            'hrp': 'tpw',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'regtest': {
            'rpcport': 51936,
            'pubkey_address': 0x76,
            'script_address': 0x7a,
            'key_prefix': 0x2e,
            'stealth_key_prefix': 0x15,
            'hrp': 'rtpw',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
    Coins.BTC: {
        'name': 'bitcoin',
        'ticker': 'BTC',
        'message_magic': 'Bitcoin Signed Message:\n',
        'blocks_target': 60 * 10,
        'decimal_places': 8,
        'mainnet': {
            'rpcport': 8332,
            'pubkey_address': 0,
            'script_address': 5,
            'key_prefix': 128,
            'hrp': 'bc',
            'bip44': 0,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 18332,
            'pubkey_address': 111,
            'script_address': 196,
            'key_prefix': 239,
            'hrp': 'tb',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
            'name': 'testnet3',
        },
        'regtest': {
            'rpcport': 18443,
            'pubkey_address': 111,
            'script_address': 196,
            'key_prefix': 239,
            'hrp': 'bcrt',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
    Coins.LTC: {
        'name': 'litecoin',
        'ticker': 'LTC',
        'message_magic': 'Litecoin Signed Message:\n',
        'blocks_target': 60 * 1,
        'decimal_places': 8,
        'mainnet': {
            'rpcport': 9332,
            'pubkey_address': 48,
            'script_address': 5,
            'script_address2': 50,
            'key_prefix': 176,
            'hrp': 'ltc',
            'bip44': 2,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 19332,
            'pubkey_address': 111,
            'script_address': 196,
            'script_address2': 58,
            'key_prefix': 239,
            'hrp': 'tltc',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
            'name': 'testnet4',
        },
        'regtest': {
            'rpcport': 19443,
            'pubkey_address': 111,
            'script_address': 196,
            'script_address2': 58,
            'key_prefix': 239,
            'hrp': 'rltc',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
    Coins.NMC: {
        'name': 'namecoin',
        'ticker': 'NMC',
        'message_magic': 'Namecoin Signed Message:\n',
        'blocks_target': 60 * 10,
        'decimal_places': 8,
        'mainnet': {
            'rpcport': 8336,
            'pubkey_address': 52,
            'script_address': 13,
            'hrp': 'nc',
            'bip44': 7,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 18336,
            'pubkey_address': 111,
            'script_address': 196,
            'hrp': 'tn',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
            'name': 'testnet3',
        },
        'regtest': {
            'rpcport': 18443,
            'pubkey_address': 111,
            'script_address': 196,
            'hrp': 'ncrt',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
    Coins.XMR: {
        'name': 'monero',
        'ticker': 'XMR',
        'client': 'xmr',
        'decimal_places': 12,
        'mainnet': {
            'rpcport': 18081,
            'walletrpcport': 18082,
            'min_amount': 100000,
            'max_amount': 10000 * XMR_COIN,
        },
        'testnet': {
            'rpcport': 28081,
            'walletrpcport': 28082,
            'min_amount': 100000,
            'max_amount': 10000 * XMR_COIN,
        },
        'regtest': {
            'rpcport': 18081,
            'walletrpcport': 18082,
            'min_amount': 100000,
            'max_amount': 10000 * XMR_COIN,
        }
    },
    Coins.PIVX: {
        'name': 'pivx',
        'ticker': 'PIVX',
        'message_magic': 'DarkNet Signed Message:\n',
        'blocks_target': 60 * 1,
        'decimal_places': 8,
        'has_cltv': True,
        'has_csv': False,
        'has_segwit': False,
        'use_ticker_as_name': True,
        'mainnet': {
            'rpcport': 51473,
            'pubkey_address': 30,
            'script_address': 13,
            'key_prefix': 212,
            'bip44': 119,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 51475,
            'pubkey_address': 139,
            'script_address': 19,
            'key_prefix': 239,
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
            'name': 'testnet4',
        },
        'regtest': {
            'rpcport': 51477,
            'pubkey_address': 139,
            'script_address': 19,
            'key_prefix': 239,
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
    Coins.DASH: {
        'name': 'dash',
        'ticker': 'DASH',
        'message_magic': 'DarkCoin Signed Message:\n',
        'blocks_target': 60 * 2.5,
        'decimal_places': 8,
        'has_csv': True,
        'has_segwit': False,
        'mainnet': {
            'rpcport': 9998,
            'pubkey_address': 76,
            'script_address': 16,
            'key_prefix': 204,
            'hrp': '',
            'bip44': 5,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 19998,
            'pubkey_address': 140,
            'script_address': 19,
            'key_prefix': 239,
            'hrp': '',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'regtest': {
            'rpcport': 18332,
            'pubkey_address': 140,
            'script_address': 19,
            'key_prefix': 239,
            'hrp': '',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
    Coins.FIRO: {
        'name': 'firo',
        'ticker': 'FIRO',
        'message_magic': 'Zcoin Signed Message:\n',
        'blocks_target': 60 * 10,
        'decimal_places': 8,
        'has_cltv': False,
        'has_csv': False,
        'has_segwit': False,
        'mainnet': {
            'rpcport': 8888,
            'pubkey_address': 82,
            'script_address': 7,
            'key_prefix': 210,
            'hrp': '',
            'bip44': 136,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 18888,
            'pubkey_address': 65,
            'script_address': 178,
            'key_prefix': 185,
            'hrp': '',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'regtest': {
            'rpcport': 28888,
            'pubkey_address': 65,
            'script_address': 178,
            'key_prefix': 239,
            'hrp': '',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
    Coins.NAV: {
        'name': 'navcoin',
        'ticker': 'NAV',
        'message_magic': 'Navcoin Signed Message:\n',
        'blocks_target': 30,
        'decimal_places': 8,
        'has_csv': True,
        'has_segwit': True,
        'mainnet': {
            'rpcport': 44444,
            'pubkey_address': 53,
            'script_address': 85,
            'key_prefix': 150,
            'hrp': '',
            'bip44': 130,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 44445,
            'pubkey_address': 111,
            'script_address': 196,
            'key_prefix': 239,
            'hrp': '',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'regtest': {
            'rpcport': 44446,
            'pubkey_address': 111,
            'script_address': 196,
            'key_prefix': 239,
            'hrp': '',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    }
}
ticker_map = {}


for c, params in chainparams.items():
    ticker_map[params['ticker'].lower()] = c


def getCoinIdFromTicker(ticker):
    try:
        return ticker_map[ticker.lower()]
    except Exception:
        raise ValueError('Unknown coin')


class CoinInterface:
    def __init__(self, network):
        self.setDefaults()
        self._network = network
        self._mx_wallet = threading.Lock()

    def setDefaults(self):
        self._unknown_wallet_seed = True
        self._restore_height = None

    def make_int(self, amount_in: int, r: int = 0) -> int:
        return make_int(amount_in, self.exp(), r=r)

    def format_amount(self, amount_in, conv_int=False, r=0):
        amount_int = make_int(amount_in, self.exp(), r=r) if conv_int else amount_in
        return format_amount(amount_int, self.exp())

    def coin_name(self) -> str:
        coin_chainparams = chainparams[self.coin_type()]
        if coin_chainparams.get('use_ticker_as_name', False):
            return coin_chainparams['ticker']
        return coin_chainparams['name'].capitalize()

    def ticker(self) -> str:
        ticker = chainparams[self.coin_type()]['ticker']
        if self._network == 'testnet':
            ticker = 't' + ticker
        elif self._network == 'regtest':
            ticker = 'rt' + ticker
        return ticker

    def getExchangeTicker(self, exchange_name: str) -> str:
        return chainparams[self.coin_type()]['ticker']

    def getExchangeName(self, exchange_name: str) -> str:
        return chainparams[self.coin_type()]['name']

    def ticker_mainnet(self) -> str:
        ticker = chainparams[self.coin_type()]['ticker']
        return ticker

    def min_amount(self) -> int:
        return chainparams[self.coin_type()][self._network]['min_amount']

    def max_amount(self) -> int:
        return chainparams[self.coin_type()][self._network]['max_amount']

    def setWalletSeedWarning(self, value: bool) -> None:
        self._unknown_wallet_seed = value

    def setWalletRestoreHeight(self, value: int) -> None:
        self._restore_height = value

    def knownWalletSeed(self) -> bool:
        return not self._unknown_wallet_seed

    def chainparams(self):
        return chainparams[self.coin_type()]

    def chainparams_network(self):
        return chainparams[self.coin_type()][self._network]

    def has_segwit(self) -> bool:
        return chainparams[self.coin_type()].get('has_segwit', True)

    def is_transient_error(self, ex) -> bool:
        if isinstance(ex, TemporaryError):
            return True
        str_error: str = str(ex).lower()
        if 'not enough unlocked money' in str_error:
            return True
        if 'no unlocked balance' in str_error:
            return True
        if 'transaction was rejected by daemon' in str_error:
            return True
        if 'invalid unlocked_balance' in str_error:
            return True
        if 'daemon is busy' in str_error:
            return True
        if 'timed out' in str_error:
            return True
        if 'request-sent' in str_error:
            return True
        return False
