#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from enum import IntEnum

from .contrib.test_framework.messages import (
    CTxOutPart,
)
from .contrib.test_framework.script import (
    CScript,
    OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
)

from .interface_btc import BTCInterface
from .chainparams import Coins


class BalanceTypes(IntEnum):
    PLAIN = 1
    BLIND = 2
    ANON = 3


class PARTInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.PART

    @staticmethod
    def balance_type():
        return BalanceTypes.PLAIN

    @staticmethod
    def witnessScaleFactor():
        return 2

    @staticmethod
    def txVersion():
        return 0xa0

    @staticmethod
    def xmr_swap_alock_spend_tx_vsize():
        return 213

    @staticmethod
    def txoType():
        return CTxOutPart

    def setDefaults(self):
        super().setDefaults()
        self._anon_tx_ring_size = 8  # TODO: Make option

    def knownWalletSeed(self):
        # TODO: Double check
        return True

    def getNewAddress(self, use_segwit):
        return self.rpc_callback('getnewaddress', ['swap_receive'])

    def getNewStealthAddress(self):
        return self.rpc_callback('getnewstealthaddress', ['swap_stealth'])

    def haveSpentIndex(self):
        version = self.getDaemonVersion()
        index_info = self.rpc_callback('getinsightinfo' if int(str(version)[:2]) > 19 else 'getindexinfo')
        return index_info['spentindex']

    def initialiseWallet(self, key):
        raise ValueError('TODO')

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee, '', True, self._conf_target]
        return self.rpc_callback('sendtoaddress', params)

    def sendTypeTo(self, type_from, type_to, value, addr_to, subfee):
        params = [type_from, type_to,
                  [{'address': addr_to, 'amount': value, 'subfee': subfee}, ],
                  '', '', self._anon_tx_ring_size, 1, False,
                  {'conf_target': self._conf_target}]
        return self.rpc_callback('sendtypeto', params)

    def getScriptForPubkeyHash(self, pkh):
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])


class PARTInterfaceBlind(PARTInterface):
    @staticmethod
    def balance_type():
        return BalanceTypes.BLIND


class PARTInterfaceAnon(PARTInterface):
    @staticmethod
    def balance_type():
        return BalanceTypes.ANON
