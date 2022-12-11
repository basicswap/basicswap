#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins
from basicswap.util.address import decodeAddress
from mnemonic import Mnemonic
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG
)


class DASHInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.DASH

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__(coin_settings, network, swap_client)
        self._wallet_passphrase = ''
        self._have_checked_seed = False

    def seedToMnemonic(self, key):
        return Mnemonic('english').to_mnemonic(key)

    def initialiseWallet(self, key):
        words = self.seedToMnemonic(key)

        mnemonic_passphrase = ''
        self.rpc_callback('upgradetohd', [words, mnemonic_passphrase, self._wallet_passphrase])
        self._have_checked_seed = False
        if self._wallet_passphrase != '':
            self.unlockWallet(self._wallet_passphrase)

    def decodeAddress(self, address):
        return decodeAddress(address)[1:]

    def checkExpectedSeed(self, key_hash):
        try:
            rv = self.rpc_callback('dumphdinfo')
            entropy = Mnemonic('english').to_entropy(rv['mnemonic'].split(' '))
            entropy_hash = self.getAddressHashFromKey(entropy)[::-1].hex()
            self._have_checked_seed = True
            return entropy_hash == key_hash
        except Exception as e:
            self._log.warning('checkExpectedSeed failed: {}'.format(str(e)))
        return False

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, '', '', subfee, False, False, self._conf_target]
        return self.rpc_callback('sendtoaddress', params)

    def getSpendableBalance(self):
        return self.make_int(self.rpc_callback('getwalletinfo')['balance'])

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        add_bytes = 107
        size = len(tx.serialize_with_witness()) + add_bytes
        pay_fee = int(fee_rate * size // 1000)
        self._log.info(f'BLockSpendTx  fee_rate, size, fee: {fee_rate}, {size}, {pay_fee}.')
        return pay_fee

    def findTxnByHash(self, txid_hex: str):
        # Only works for wallet txns
        try:
            rv = self.rpc_callback('gettransaction', [txid_hex])
        except Exception as ex:
            self._log.debug('findTxnByHash getrawtransaction failed: {}'.format(txid_hex))
            return None
        if 'confirmations' in rv and rv['confirmations'] >= self.blocks_confirmed:
            block_height = self.getBlockHeader(rv['blockhash'])['height']
            return {'txid': txid_hex, 'amount': 0, 'height': block_height}

        return None

    def unlockWallet(self, password: str):
        super().unlockWallet(password)
        # Store password for initialiseWallet
        self._wallet_passphrase = password
        if not self._have_checked_seed:
            self._sc.checkWalletSeed(self.coin_type())

    def lockWallet(self):
        super().lockWallet()
        self._wallet_passphrase = ''
