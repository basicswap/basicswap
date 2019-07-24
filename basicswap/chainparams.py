# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

from enum import IntEnum
from .util import (
    COIN,
)


class Coins(IntEnum):
    PART = 1
    BTC = 2
    LTC = 3
    # DCR = 4
    NMC = 5


chainparams = {
    Coins.PART: {
        'name': 'particl',
        'ticker': 'PART',
        'message_magic': 'Bitcoin Signed Message:\n',
        'mainnet': {
            'rpcport': 51735,
            'pubkey_address': 0x38,
            'script_address': 0x3c,
            'key_prefix': 0x6c,
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
        'mainnet': {
            'rpcport': 8332,
            'pubkey_address': 0,
            'script_address': 5,
            'hrp': 'bc',
            'bip44': 0,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 18332,
            'pubkey_address': 111,
            'script_address': 196,
            'hrp': 'tb',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
            'name': 'testnet4',
        },
        'regtest': {
            'rpcport': 18443,
            'pubkey_address': 111,
            'script_address': 196,
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
        'mainnet': {
            'rpcport': 9332,
            'pubkey_address': 48,
            'script_address': 50,
            'hrp': 'ltc',
            'bip44': 2,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
        },
        'testnet': {
            'rpcport': 19332,
            'pubkey_address': 111,
            'script_address': 58,
            'hrp': 'tltc',
            'bip44': 1,
            'min_amount': 1000,
            'max_amount': 100000 * COIN,
            'name': 'testnet4',
        },
        'regtest': {
            'rpcport': 19443,
            'pubkey_address': 111,
            'script_address': 58,
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
    }
}
