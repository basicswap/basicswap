#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import unittest

from basicswap.basicswap import (
    Coins,
)
from tests.basicswap.util import (
    REQUIRED_SETTINGS,
)
from tests.basicswap.common import (
    stopDaemons,
)
from tests.basicswap.test_xmr import BaseTest
from basicswap.interface.dcr import DCRInterface

logger = logging.getLogger()


class Test(BaseTest):
    __test__ = True
    test_coin_from = Coins.DCR
    decred_daemons = []
    start_ltc_nodes = False
    start_xmr_nodes = False

    @classmethod
    def prepareExtraCoins(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising Decred Test')
        super(Test, cls).tearDownClass()

        stopDaemons(cls.decred_daemons)

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()

    def test_001_decred(self):
        logging.info('---------- Test {}'.format(self.test_coin_from.name))

        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(REQUIRED_SETTINGS)

        ci = DCRInterface(coin_settings, 'mainnet')

        k = ci.getNewSecretKey()
        K = ci.getPubkey(k)

        pkh = ci.pkh(K)
        address = ci.pkh_to_address(pkh)
        assert (address.startswith('Ds'))

        data = ci.decode_address(address)
        assert (data[2:] == pkh)


if __name__ == '__main__':
    unittest.main()
