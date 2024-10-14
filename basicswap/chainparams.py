# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from enum import IntEnum
from .util import (
    COIN,
)

XMR_COIN = 10 ** 12
WOW_COIN = 10 ** 11


class Coins(IntEnum):
    PART = 1
    BTC = 2
    LTC = 3
    DCR = 4
    NMC = 5
    XMR = 6
    PART_BLIND = 7
    PART_ANON = 8
    WOW = 9
    # NDAU = 10
    PIVX = 11
    DASH = 12
    FIRO = 13
    NAV = 14
    LTC_MWEB = 15
    # ZANO = 16
    BCH = 17


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
    Coins.DCR: {
        'name': 'decred',
        'ticker': 'DCR',
        'message_magic': 'Decred Signed Message:\n',
        'blocks_target': 60 * 5,
        'decimal_places': 8,
        'mainnet': {
            'rpcport': 9109,
            'pubkey_address': 0x073f,
            'script_address': 0x071a,
            'key_prefix': 0x22de,
            'bip44': 42,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 19109,
            'pubkey_address': 0x0f21,
            'script_address': 0x0efc,
            'key_prefix': 0x230e,
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
            'name': 'testnet3',
        },
        'regtest': {  # simnet
            'rpcport': 18656,
            'pubkey_address': 0x0e91,
            'script_address': 0x0e6c,
            'key_prefix': 0x2307,
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
            'address_prefix': 18,
        },
        'testnet': {
            'rpcport': 28081,
            'walletrpcport': 28082,
            'min_amount': 100000,
            'max_amount': 10000 * XMR_COIN,
            'address_prefix': 18,
        },
        'regtest': {
            'rpcport': 18081,
            'walletrpcport': 18082,
            'min_amount': 100000,
            'max_amount': 10000 * XMR_COIN,
            'address_prefix': 18,
        }
    },
    Coins.WOW: {
        'name': 'wownero',
        'ticker': 'WOW',
        'client': 'wow',
        'decimal_places': 11,
        'mainnet': {
            'rpcport': 34568,
            'walletrpcport': 34572,  # todo
            'min_amount': 100000,
            'max_amount': 10000 * WOW_COIN,
            'address_prefix': 4146,
        },
        'testnet': {
            'rpcport': 44568,
            'walletrpcport': 44572,
            'min_amount': 100000,
            'max_amount': 10000 * WOW_COIN,
            'address_prefix': 4146,
        },
        'regtest': {
            'rpcport': 54568,
            'walletrpcport': 54572,
            'min_amount': 100000,
            'max_amount': 10000 * WOW_COIN,
            'address_prefix': 4146,
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
    },
    Coins.BCH: {
        'name': 'bitcoincash',
        'ticker': 'BCH',
        'message_magic': 'Bitcoin Signed Message:\n',
        'blocks_target': 60 * 2,
        'decimal_places': 8,
        'has_cltv': True,
        'has_csv': True,
        'has_segwit': False,
        'mainnet': {
            'rpcport': 8332,
            'pubkey_address': 0,
            'script_address': 5,
            'key_prefix': 128,
            'hrp': 'bitcoincash',
            'bip44': 0,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 18332,
            'pubkey_address': 111,
            'script_address': 196,
            'key_prefix': 239,
            'hrp': 'bchtest',
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
            'hrp': 'bchreg',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        }
    },
}
ticker_map = {}


for c, params in chainparams.items():
    ticker_map[params['ticker'].lower()] = c


def getCoinIdFromTicker(ticker: str) -> str:
    try:
        return ticker_map[ticker.lower()]
    except Exception:
        raise ValueError('Unknown coin')
