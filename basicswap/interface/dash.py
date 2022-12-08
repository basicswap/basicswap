#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins
from basicswap.util.address import decodeAddress
from mnemonic import Mnemonic


class DASHInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.DASH

    def seedToMnemonic(self, key):
        return Mnemonic('english').to_mnemonic(key)

    def initialiseWallet(self, key):
        words = self.seedToMnemonic(key)
        self.rpc_callback('upgradetohd', [words, ])

    def decodeAddress(self, address):
        return decodeAddress(address)[1:]

    def checkExpectedSeed(self, key_hash):
        try:
            rv = self.rpc_callback('dumphdinfo')
            entropy = Mnemonic('english').to_entropy(rv['mnemonic'].split(' '))
            entropy_hash = self.getAddressHashFromKey(entropy)[::-1].hex()
            return entropy_hash == key_hash
        except Exception as e:
            self._log.warning('checkExpectedSeed failed: {}'.format(str(e)))
        return False

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee]
        return self.rpc_callback('sendtoaddress', params)

    def getSpendableBalance(self):
        return self.make_int(self.rpc_callback('getwalletinfo')['balance'])
