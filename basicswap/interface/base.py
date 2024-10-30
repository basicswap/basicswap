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
from basicswap.util.crypto import (
    hash160,
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
    @staticmethod
    def watch_blocks_for_scripts() -> bool:
        return False

    @staticmethod
    def compareFeeRates(a, b) -> bool:
        return abs(a - b) < 20

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
        if coin_chainparams['name'] == 'bitcoincash':
            return 'Bitcoin Cash'
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

    def use_p2shp2wsh(self) -> bool:
        # p2sh-p2wsh
        return False

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

    def get_connection_type(self):
        return self._connection_type

    def using_segwit(self) -> bool:
        # Using btc native segwit
        return self._use_segwit

    def use_tx_vsize(self) -> bool:
        return self._use_segwit

    def getLockTxSwapOutputValue(self, bid, xmr_swap) -> int:
        return bid.amount

    def getLockRefundTxSwapOutputValue(self, bid, xmr_swap) -> int:
        return xmr_swap.a_swap_refund_value

    def getLockRefundTxSwapOutput(self, xmr_swap) -> int:
        # Only one prevout exists
        return 0

    def checkWallets(self) -> int:
        return 1


class AdaptorSigInterface():
    def getScriptLockTxDummyWitness(self, script: bytes):
        return [
            b'',
            bytes(72),
            bytes(72),
            bytes(len(script))
        ]

    def getScriptLockRefundSpendTxDummyWitness(self, script: bytes):
        return [
            b'',
            bytes(72),
            bytes(72),
            bytes((1,)),
            bytes(len(script))
        ]

    def getScriptLockRefundSwipeTxDummyWitness(self, script: bytes):
        return [
            bytes(72),
            b'',
            bytes(len(script))
        ]


class Secp256k1Interface(CoinInterface, AdaptorSigInterface):
    @staticmethod
    def curve_type():
        return Curves.secp256k1

    def getNewSecretKey(self) -> bytes:
        return i2b(getSecretInt())

    def getPubkey(self, privkey: bytes) -> bytes:
        return PublicKey.from_secret(privkey).format()

    def pkh(self, pubkey: bytes) -> bytes:
        return hash160(pubkey)

    def verifyKey(self, k: bytes) -> bool:
        i = b2i(k)
        return (i < ep.o and i > 0)

    def verifyPubkey(self, pubkey_bytes: bytes) -> bool:
        return verify_secp256k1_point(pubkey_bytes)

    def isValidAddressHash(self, address_hash: bytes) -> bool:
        hash_len = len(address_hash)
        if hash_len == 20:
            return True

    def isValidPubkey(self, pubkey: bytes) -> bool:
        try:
            self.verifyPubkey(pubkey)
            return True
        except Exception:
            return False

    def verifySig(self, pubkey: bytes, signed_hash: bytes, sig: bytes) -> bool:
        pubkey = PublicKey(pubkey)
        return pubkey.verify(sig, signed_hash, hasher=None)

    def sumKeys(self, ka: bytes, kb: bytes) -> bytes:
        # TODO: Add to coincurve
        return i2b((b2i(ka) + b2i(kb)) % ep.o)

    def sumPubkeys(self, Ka: bytes, Kb: bytes) -> bytes:
        return PublicKey.combine_keys([PublicKey(Ka), PublicKey(Kb)]).format()
