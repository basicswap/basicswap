# -*- coding: utf-8 -*-

# Copyright (c) 2019-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import time
import shlex
import socks
import socket
import urllib
import logging
import threading
import traceback
import subprocess

from sockshandler import SocksiPyHandler

import basicswap.config as cfg

from .rpc import (
    callrpc,
)
from .util import (
    TemporaryError,
)
from .chainparams import (
    Coins,
    chainparams,
)


def getaddrinfo_tor(*args):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (args[0], args[1]))]


class BaseApp:
    def __init__(self, fp, data_dir, settings, chain, log_name='BasicSwap'):
        self.log_name = log_name
        self.fp = fp
        self.is_running = True
        self.fail_code = 0
        self.mock_time_offset = 0

        self.data_dir = data_dir
        self.chain = chain
        self.settings = settings
        self.coin_clients = {}
        self.coin_interfaces = {}
        self.mxDB = threading.RLock()
        self.debug = self.settings.get('debug', False)
        self.delay_event = threading.Event()
        self._network = None
        self.prepareLogging()
        self.log.info('Network: {}'.format(self.chain))

        self.use_tor_proxy = self.settings.get('use_tor', False)
        self.tor_proxy_host = self.settings.get('tor_proxy_host', '127.0.0.1')
        self.tor_proxy_port = self.settings.get('tor_proxy_port', 9050)
        self.tor_control_password = self.settings.get('tor_control_password', None)
        self.tor_control_port = self.settings.get('tor_control_port', 9051)
        self.default_socket = socket.socket
        self.default_socket_timeout = socket.getdefaulttimeout()
        self.default_socket_getaddrinfo = socket.getaddrinfo

    def stopRunning(self, with_code=0):
        self.fail_code = with_code
        with self.mxDB:
            self.is_running = False
            self.delay_event.set()

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

    def setDaemonPID(self, name, pid) -> None:
        if isinstance(name, Coins):
            self.coin_clients[name]['pid'] = pid
            return
        for c, v in self.coin_clients.items():
            if v['name'] == name:
                v['pid'] = pid

    def getChainDatadirPath(self, coin) -> str:
        datadir = self.coin_clients[coin]['datadir']
        testnet_name = '' if self.chain == 'mainnet' else chainparams[coin][self.chain].get('name', self.chain)
        return os.path.join(datadir, testnet_name)

    def getCoinIdFromName(self, coin_name: str):
        for c, params in chainparams.items():
            if coin_name.lower() == params['name'].lower():
                return c
        raise ValueError('Unknown coin: {}'.format(coin_name))

    def callrpc(self, method, params=[], wallet=None):
        cc = self.coin_clients[Coins.PART]
        return callrpc(cc['rpcport'], cc['rpcauth'], method, params, wallet, cc['rpchost'])

    def callcoinrpc(self, coin, method, params=[], wallet=None):
        cc = self.coin_clients[coin]
        return callrpc(cc['rpcport'], cc['rpcauth'], method, params, wallet, cc['rpchost'])

    def calltx(self, cmd):
        bindir = self.coin_clients[Coins.PART]['bindir']
        args = [os.path.join(bindir, cfg.PARTICL_TX), ]
        if self.chain != 'mainnet':
            args.append('-' + self.chain)
        args += shlex.split(cmd)
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = p.communicate()
        if len(out[1]) > 0:
            raise ValueError('TX error ' + str(out[1]))
        return out[0].decode('utf-8').strip()

    def callcoincli(self, coin_type, params, wallet=None, timeout=None):
        bindir = self.coin_clients[coin_type]['bindir']
        datadir = self.coin_clients[coin_type]['datadir']
        command_cli = os.path.join(bindir, chainparams[coin_type]['name'] + '-cli' + ('.exe' if os.name == 'nt' else ''))
        args = [command_cli, ]
        if self.chain != 'mainnet':
            args.append('-' + self.chain)
        args.append('-datadir=' + datadir)
        args += shlex.split(params)
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out = p.communicate(timeout=timeout)
        if len(out[1]) > 0:
            raise ValueError('CLI error ' + str(out[1]))
        return out[0].decode('utf-8').strip()

    def is_transient_error(self, ex) -> bool:
        if isinstance(ex, TemporaryError):
            return True
        str_error = str(ex).lower()
        return 'read timed out' in str_error or 'no connection to daemon' in str_error

    def setConnectionParameters(self, timeout=120):
        opener = urllib.request.build_opener()
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        urllib.request.install_opener(opener)

        if self.use_tor_proxy:
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, self.tor_proxy_host, self.tor_proxy_port, rdns=True)
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo_tor  # Without this accessing .onion links would fail

        socket.setdefaulttimeout(timeout)

    def popConnectionParameters(self) -> None:
        if self.use_tor_proxy:
            socket.socket = self.default_socket
            socket.getaddrinfo = self.default_socket_getaddrinfo
        socket.setdefaulttimeout(self.default_socket_timeout)

    def readURL(self, url: str, timeout: int = 120, headers=None) -> bytes:
        open_handler = None
        if self.use_tor_proxy:
            open_handler = SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, self.tor_proxy_host, self.tor_proxy_port)
        opener = urllib.request.build_opener(open_handler) if self.use_tor_proxy else urllib.request.build_opener()
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        request = urllib.request.Request(url, headers=headers)
        return opener.open(request, timeout=timeout).read()

    def logException(self, message) -> None:
        self.log.error(message)
        if self.debug:
            self.log.error(traceback.format_exc())

    def torControl(self, query):
        try:
            command = 'AUTHENTICATE "{}"\r\n{}\r\nQUIT\r\n'.format(self.tor_control_password, query).encode('utf-8')
            c = socket.create_connection((self.tor_proxy_host, self.tor_control_port))
            c.send(command)
            response = bytearray()
            while True:
                rv = c.recv(1024)
                if not rv:
                    break
                response += rv
            c.close()
            return response
        except Exception as e:
            self.log.error(f'torControl {e}')
            return

    def getTime(self) -> int:
        return int(time.time()) + self.mock_time_offset
