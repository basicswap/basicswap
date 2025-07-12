#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.chainparams import WOW_COIN, Coins
from .xmr import XMRInterface


class WOWInterface(XMRInterface):

    @staticmethod
    def coin_type():
        return Coins.WOW

    @staticmethod
    def ticker_str() -> int:
        return Coins.WOW.name

    @staticmethod
    def COIN():
        return WOW_COIN

    @staticmethod
    def exp() -> int:
        return 11

    @staticmethod
    def depth_spendable() -> int:
        return 4

    # below only needed until wow is rebased to monero v0.18.4.0+
    def openWallet(self, filename):
        params = {"filename": filename}
        if self._wallet_password is not None:
            params["password"] = self._wallet_password

        try:
            self.rpc_wallet("open_wallet", params)
        except Exception as e:
            if "no connection to daemon" in str(e):
                self._log.debug(f"{self.coin_name()} {e}")
                return  # bypass refresh error to allow startup with a busy daemon

            try:
                # TODO Remove `store` after upstream fix to autosave on close_wallet
                self.rpc_wallet("store")
                self.rpc_wallet("close_wallet")
                self._log.debug(f"Attempt to save and close {self.coin_name()} wallet")
            except Exception as e:  # noqa: F841
                pass

            self.rpc_wallet("open_wallet", params)
            self._log.debug(f"Reattempt to open {self.coin_name()} wallet")
