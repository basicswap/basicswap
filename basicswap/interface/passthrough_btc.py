# -*- coding: utf-8 -*-

# Copyright (c) 2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.interface.btc.btc import BTCInterface
from basicswap.contrib.test_framework.messages import CTxOut


class PassthroughBTCInterface(BTCInterface):
    def __init__(self, coin_settings, network, swap_client=None, **kwargs):
        super().__init__(
            coin_settings=coin_settings,
            network=network,
            swap_client=swap_client,
            **kwargs,
        )
        self.txoType = CTxOut
        self._network = network
        self.blocks_confirmed = coin_settings["blocks_confirmed"]
        self.setConfTarget(coin_settings["conf_target"])
