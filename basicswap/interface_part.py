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

from .util import encodeStealthAddress
from .chainparams import Coins, chainparams
from .interface_btc import BTCInterface


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
    def witnessScaleFactor() -> int:
        return 2

    @staticmethod
    def txVersion() -> int:
        return 0xa0

    @staticmethod
    def xmr_swap_alock_spend_tx_vsize() -> int:
        return 213

    @staticmethod
    def txoType():
        return CTxOutPart

    def setDefaults(self) -> None:
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

    def formatStealthAddress(self, scan_pubkey, spend_pubkey):
        prefix_byte = chainparams[self.coin_type()][self._network]['stealth_key_prefix']

        return encodeStealthAddress(prefix_byte, scan_pubkey, spend_pubkey)


class PARTInterfaceBlind(PARTInterface):
    @staticmethod
    def balance_type():
        return BalanceTypes.BLIND


class PARTInterfaceAnon(PARTInterface):
    @staticmethod
    def balance_type():
        return BalanceTypes.ANON

    def publishBLockTx(self, Kbv, Kbs, output_amount, feerate):
        sx_addr = self.formatStealthAddress(Kbv, Kbs)
        self._log.debug('sx_addr: {}'.format(sx_addr))

        # TODO: Fund from other balances
        params = ['anon', 'anon',
                  [{'address': sx_addr, 'amount': self.format_amount(output_amount)}, ],
                  '', '', self._anon_tx_ring_size, 1, False,
                  {'conf_target': self._conf_target, 'blind_watchonly_visible': True}]

        txid = self.rpc_callback('sendtypeto', params)
        return bytes.fromhex(txid)

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):
        raise ValueError('TODO - new core release')

    def spendBLockTx(self, address_to, kbv, kbs, cb_swap_value, b_fee, restore_height):
        raise ValueError('TODO - new core release')
