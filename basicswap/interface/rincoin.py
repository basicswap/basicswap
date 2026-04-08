#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .ltc import LTCInterface
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins, chainparams


class RINCOINInterface(LTCInterface):
    @staticmethod
    def coin_type():
        return Coins.RINCOIN

    def __init__(self, coin_settings, network, swap_client=None):
        super(RINCOINInterface, self).__init__(coin_settings, network, swap_client)
        # Rincoin inherits all Litecoin functionality including MWEB support


class RINCOINInterfaceMWEB(RINCOINInterface):

    def interface_type(self) -> int:
        return Coins.RINCOIN_MWEB

    def __init__(self, coin_settings, network, swap_client=None):
        super(RINCOINInterfaceMWEB, self).__init__(coin_settings, network, swap_client)
        self._rpc_wallet = coin_settings.get("mweb_wallet_name", "mweb")
        self.rpc_wallet = make_rpc_func(
            self._rpcport, self._rpcauth, host=self._rpc_host, wallet=self._rpc_wallet
        )
        self.rpc_wallet_watch = self.rpc_wallet

    def chainparams(self):
        return chainparams[Coins.RINCOIN]

    def chainparams_network(self):
        return chainparams[Coins.RINCOIN][self._network]

    def coin_name(self) -> str:
        coin_chainparams = chainparams[Coins.RINCOIN]
        if self._network == "mainnet":
            return coin_chainparams["name"].capitalize()
        return coin_chainparams["name"].capitalize() + " " + self._network

    def ticker(self) -> str:
        ticker = chainparams[Coins.RINCOIN]["ticker"]
        if self._network == "mainnet":
            return ticker
        return ticker + " " + self._network.capitalize()

    def format_amount(self, amount, conv_int=False, r=0) -> str:
        return super(RINCOINInterfaceMWEB, self).format_amount(amount, conv_int, r)

    def init_wallet(self, password=None):
        # If system is encrypted mweb wallet will be created at first unlock

        self._log.info("init_wallet - {}".format(self.ticker()))

        self._log.info(f"Creating wallet {self._rpc_wallet} for {self.coin_name()}.")
        # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup
        self.rpc("createwallet", ["mweb", False, True, password, False, False, True])

        if password is not None:
            # Max timeout value, ~3 years
            self.rpc_wallet("walletpassphrase", [password, 100000000])

        if self.getWalletSeedID() == "Not found":
            self._sc.initialiseWallet(self.interface_type())

            # Workaround to trigger mweb_spk_man->LoadMWEBKeychain()
            self.rpc("unloadwallet", ["mweb"])
            self.rpc("loadwallet", ["mweb"])
            if password is not None:
                self.rpc_wallet("walletpassphrase", [password, 100000000])
            self.rpc_wallet("keypoolrefill")

    def unlockWallet(self, password: str, check_seed: bool = True) -> None:
        if password == "":
            return
        self._log.info("unlockWallet - {}".format(self.ticker()))

        if not self.has_mweb_wallet():
            self.init_wallet(password)
        else:
            # Max timeout value, ~3 years
            self.rpc_wallet("walletpassphrase", [password, 100000000])
        if check_seed:
            self._sc.checkWalletSeed(self.coin_type())


