#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins, chainparams


class LTCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.LTC

    def __init__(self, coin_settings, network, swap_client=None):
        super(LTCInterface, self).__init__(coin_settings, network, swap_client)
        self._rpc_wallet_mweb = 'mweb'
        self.rpc_wallet_mweb = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host, wallet=self._rpc_wallet_mweb)

    def getNewMwebAddress(self, use_segwit=False, label='swap_receive') -> str:
        return self.rpc_wallet_mweb('getnewaddress', [label, 'mweb'])

    def getNewStealthAddress(self, label=''):
        return self.getNewMwebAddress(False, label)

    def withdrawCoin(self, value, type_from: str, addr_to: str, subfee: bool) -> str:
        params = [addr_to, value, '', '', subfee, True, self._conf_target]
        if type_from == 'mweb':
            return self.rpc_wallet_mweb('sendtoaddress', params)
        return self.rpc_wallet('sendtoaddress', params)

    def getWalletInfo(self):
        rv = super(LTCInterface, self).getWalletInfo()

        mweb_info = self.rpc_wallet_mweb('getwalletinfo')
        rv['mweb_balance'] = mweb_info['balance']
        rv['mweb_unconfirmed'] = mweb_info['unconfirmed_balance']
        rv['mweb_immature'] = mweb_info['immature_balance']
        return rv


class LTCInterfaceMWEB(LTCInterface):
    @staticmethod
    def coin_type():
        return Coins.LTC_MWEB

    def __init__(self, coin_settings, network, swap_client=None):
        super(LTCInterfaceMWEB, self).__init__(coin_settings, network, swap_client)
        self._rpc_wallet = 'mweb'
        self.rpc_wallet = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host, wallet=self._rpc_wallet)

    def chainparams(self):
        return chainparams[Coins.LTC]

    def chainparams_network(self):
        return chainparams[Coins.LTC][self._network]

    def coin_name(self) -> str:
        coin_chainparams = chainparams[Coins.LTC]
        if coin_chainparams.get('use_ticker_as_name', False):
            return coin_chainparams['ticker'] + ' MWEB'
        return coin_chainparams['name'].capitalize() + ' MWEB'

    def ticker(self) -> str:
        ticker = chainparams[Coins.LTC]['ticker']
        if self._network == 'testnet':
            ticker = 't' + ticker
        elif self._network == 'regtest':
            ticker = 'rt' + ticker
        return ticker + '_MWEB'

    def getNewAddress(self, use_segwit=False, label='swap_receive') -> str:
        return self.getNewMwebAddress()

    def has_mweb_wallet(self) -> bool:
        return 'mweb' in self.rpc('listwallets')

    def init_wallet(self, password=None):
        # If system is encrypted mweb wallet will be created at first unlock

        self._log.info('init_wallet - {}'.format(self.ticker()))

        self._log.info('Creating mweb wallet for {}.'.format(self.coin_name()))
        # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup
        self.rpc('createwallet', ['mweb', False, True, password, False, False, True])

        if password is not None:
            # Max timeout value, ~3 years
            self.rpc_wallet('walletpassphrase', [password, 100000000])

        if self.getWalletSeedID() == 'Not found':
            self._sc.initialiseWallet(self.coin_type())

            # Workaround to trigger mweb_spk_man->LoadMWEBKeychain()
            self.rpc('unloadwallet', ['mweb'])
            self.rpc('loadwallet', ['mweb'])
            if password is not None:
                self.rpc_wallet('walletpassphrase', [password, 100000000])
            self.rpc_wallet('keypoolrefill')

    def unlockWallet(self, password: str):
        if password == '':
            return
        self._log.info('unlockWallet - {}'.format(self.ticker()))

        if not self.has_mweb_wallet():
            self.init_wallet(password)
        else:
            # Max timeout value, ~3 years
            self.rpc_wallet('walletpassphrase', [password, 100000000])

        self._sc.checkWalletSeed(self.coin_type())
