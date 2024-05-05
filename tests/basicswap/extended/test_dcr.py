#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import os
import unittest

import basicswap.config as cfg

from basicswap.basicswap import (
    Coins,
)
from basicswap.rpc import (
    waitForRPC,
)
from tests.basicswap.common import (
    stopDaemons,
    make_rpc_func,
)
from tests.basicswap.util import (
    REQUIRED_SETTINGS,
)

from tests.basicswap.test_xmr import BaseTest
from basicswap.interface.dcr import DCRInterface
from bin.basicswap_run import startDaemon

logger = logging.getLogger()

DCR_BINDIR = os.path.expanduser(os.getenv('DCR_BINDIR', os.path.join(cfg.DEFAULT_TEST_BINDIR, 'decred')))
DCRD = os.getenv('DCRD', 'dcrd' + cfg.bin_suffix)
DCR_WALLET = os.getenv('DCR_WALLET', 'dcrwallet' + cfg.bin_suffix)
DCR_CLI = os.getenv('DCR_CLI', 'dcrctl' + cfg.bin_suffix)

DCR_BASE_PORT = 44932
DCR_BASE_RPC_PORT = 45932


def prepareDCDDataDir(datadir, node_id, conf_file, dir_prefix, base_p2p_port, base_rpc_port, num_nodes=3):
    node_dir = os.path.join(datadir, dir_prefix + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        config = [
            'regnet=1\n',  # or simnet?
            'debuglevel=debug\n',
            f'listen=127.0.0.1:{base_p2p_port}\n',
            f'rpclisten=127.0.0.1:{base_rpc_port}\n',
            f'rpcuser=test{node_id}\n',
            f'rpcpass=test_pass{node_id}\n',]

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            config.append('addpeer=127.0.0.1:{}\n'.format(base_p2p_port + i))

        for line in config:
            fp.write(line)


class Test(BaseTest):
    __test__ = True
    test_coin_from = Coins.DCR
    dcr_daemons = []
    start_ltc_nodes = False
    start_xmr_nodes = False

    @classmethod
    def prepareExtraCoins(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising Decred Test')
        super(Test, cls).tearDownClass()

        stopDaemons(cls.dcr_daemons)
        cls.dcr_daemons.clear()

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()

    @classmethod
    def prepareExtraDataDir(cls, i):
        extra_opts = []
        if not cls.restore_instance:
            data_dir = prepareDCDDataDir(cfg.TEST_DATADIRS, i, 'dcrd.conf', 'dcr_', base_p2p_port=DCR_BASE_PORT, base_rpc_port=DCR_BASE_RPC_PORT)

        appdata = os.path.join(cfg.TEST_DATADIRS, 'dcr_' + str(i))
        datadir = os.path.join(appdata, 'data')
        extra_opts.append(f'--appdata="{appdata}"')
        cls.dcr_daemons.append(startDaemon(appdata, DCR_BINDIR, DCRD, opts=extra_opts, extra_config={'add_datadir': False, 'stdout_to_file': True, 'stdout_filename': 'dcrd_stdout.log'}))
        logging.info('Started %s %d', DCRD, cls.dcr_daemons[-1].handle.pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=DCR_BASE_RPC_PORT), max_tries=12)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings['chainclients']['decred'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': DCR_BASE_RPC_PORT + node_id,
            'rpcuser': 'test' + str(node_id),
            'rpcpassword': 'test_pass' + str(node_id),
            'datadir': os.path.join(datadir, 'dcr_' + str(node_id)),
            'bindir': DCR_BINDIR,
            'use_csv': True,
            'use_segwit': True,
            'blocks_confirmed': 1,
        }

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
