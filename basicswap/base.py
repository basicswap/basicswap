# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import logging
import threading
import subprocess

import basicswap.config as cfg
import basicswap.contrib.segwit_addr as segwit_addr

from .rpc import (
    callrpc,
)
from .util import (
    pubkeyToAddress,
)
from .chainparams import (
    Coins,
    chainparams,
)


class BaseApp:
    def __init__(self, fp, data_dir, settings, chain, log_name='BasicSwap'):
        self.log_name = log_name
        self.fp = fp
        self.is_running = True
        self.fail_code = 0

        self.data_dir = data_dir
        self.chain = chain
        self.settings = settings
        self.coin_clients = {}
        self.mxDB = threading.RLock()
        self.debug = self.settings.get('debug', False)
        self._network = None

        self.prepareLogging()
        self.log.info('Network: {}'.format(self.chain))

    def stopRunning(self, with_code=0):
        self.fail_code = with_code
        self.is_running = False

    def prepareLogging(self):
        self.log = logging.getLogger(self.log_name)
        self.log.propagate = False

        # Remove any existing handlers
        self.log.handlers = []

        formatter = logging.Formatter('%(asctime)s %(levelname)s : %(message)s')
        stream_stdout = logging.StreamHandler()
        if self.log_name != 'BasicSwap':
            stream_stdout.setFormatter(logging.Formatter('%(asctime)s %(name)s %(levelname)s : %(message)s'))
        else:
            stream_stdout.setFormatter(formatter)
        stream_fp = logging.StreamHandler(self.fp)
        stream_fp.setFormatter(formatter)

        self.log.setLevel(logging.DEBUG if self.debug else logging.INFO)
        self.log.addHandler(stream_fp)
        self.log.addHandler(stream_stdout)

    def getChainClientSettings(self, coin):
        try:
            return self.settings['chainclients'][chainparams[coin]['name']]
        except Exception:
            return {}

    def setDaemonPID(self, name, pid):
        if isinstance(name, Coins):
            self.coin_clients[name]['pid'] = pid
            return
        for c, v in self.coin_clients.items():
            if v['name'] == name:
                v['pid'] = pid

    def getChainDatadirPath(self, coin):
        datadir = self.coin_clients[coin]['datadir']
        testnet_name = '' if self.chain == 'mainnet' else chainparams[coin][self.chain].get('name', self.chain)
        return os.path.join(datadir, testnet_name)

    def getCoinIdFromName(self, coin_name):
        for c, params in chainparams.items():
            if coin_name.lower() == params['name'].lower():
                return c
        raise ValueError('Unknown coin: {}'.format(coin_name))

    def getTicker(self, coin_type):
        ticker = chainparams[coin_type]['ticker']
        if self.chain == 'testnet':
            ticker = 't' + ticker
        if self.chain == 'regtest':
            ticker = 'rt' + ticker
        return ticker

    def encodeSegwitP2WSH(self, coin_type, p2wsh):
        return segwit_addr.encode(chainparams[coin_type][self.chain]['hrp'], 0, p2wsh[2:])

    def encodeSegwit(self, coin_type, raw):
        return segwit_addr.encode(chainparams[coin_type][self.chain]['hrp'], 0, raw)

    def decodeSegwit(self, coin_type, addr):
        return bytes(segwit_addr.decode(chainparams[coin_type][self.chain]['hrp'], addr)[1])

    def getScriptAddress(self, coin_type, script):
        return pubkeyToAddress(chainparams[coin_type][self.chain]['script_address'], script)

    def callrpc(self, method, params=[], wallet=None):
        return callrpc(self.coin_clients[Coins.PART]['rpcport'], self.coin_clients[Coins.PART]['rpcauth'], method, params, wallet)

    def callcoinrpc(self, coin, method, params=[], wallet=None):
        return callrpc(self.coin_clients[coin]['rpcport'], self.coin_clients[coin]['rpcauth'], method, params, wallet)

    def calltx(self, cmd):
        bindir = self.coin_clients[Coins.PART]['bindir']
        command_tx = os.path.join(bindir, cfg.PARTICL_TX)
        chainname = '' if self.chain == 'mainnet' else (' -' + self.chain)
        args = command_tx + chainname + ' ' + cmd
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out = p.communicate()
        if len(out[1]) > 0:
            raise ValueError('TX error ' + str(out[1]))
        return out[0].decode('utf-8').strip()

    def callcoincli(self, coin_type, params, wallet=None, timeout=None):
        bindir = self.coin_clients[coin_type]['bindir']
        datadir = self.coin_clients[coin_type]['datadir']
        command_cli = os.path.join(bindir, chainparams[coin_type]['name'] + '-cli' + ('.exe' if os.name == 'nt' else ''))
        chainname = '' if self.chain == 'mainnet' else (' -' + self.chain)
        args = command_cli + chainname + ' ' + '-datadir=' + datadir + ' ' + params
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out = p.communicate(timeout=timeout)
        if len(out[1]) > 0:
            raise ValueError('CLI error ' + str(out[1]))
        return out[0].decode('utf-8').strip()
