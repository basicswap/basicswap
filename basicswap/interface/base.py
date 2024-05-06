#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import threading

from enum import IntEnum

from basicswap.chainparams import (
    chainparams,
)
from basicswap.util import (
    ensure,
    i2b, b2i,
    make_int,
    format_amount,
    TemporaryError,
)
from basicswap.util.ecc import (
    ep,
    getSecretInt,
)
from coincurve.dleag import (
    verify_secp256k1_point
)
from coincurve.keys import (
    PublicKey,
)


class Curves(IntEnum):
    secp256k1 = 1
    ed25519 = 2


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

    def setConfTarget(self, new_conf_target: int) -> None:
        ensure(new_conf_target >= 1 and new_conf_target < 33, 'Invalid conf_target value')
        self._conf_target = new_conf_target

    def walletRestoreHeight(self) -> int:
        return self._restore_height


class Secp256k1Interface(CoinInterface):
    @staticmethod
    def curve_type():
        return Curves.secp256k1

    def getNewSecretKey(self) -> bytes:
        return i2b(getSecretInt())

    def getPubkey(self, privkey):
        return PublicKey.from_secret(privkey).format()

    def verifyKey(self, k: bytes) -> bool:
        i = b2i(k)
        return (i < ep.o and i > 0)

    def verifyPubkey(self, pubkey_bytes: bytes) -> bool:
        return verify_secp256k1_point(pubkey_bytes)
