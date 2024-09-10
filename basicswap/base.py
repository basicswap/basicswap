import os
import time
import shlex
import socks
import random
import socket
import urllib
import logging
import threading
import traceback
import subprocess
import urllib.request
import urllib.error
import json

from sockshandler import SocksiPyHandler

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
        self.fail_code = 0
        self.mock_time_offset = 0

        self.data_dir = data_dir
        self.chain = chain
        self.settings = settings
        self.coin_clients = {}
        self.coin_interfaces = {}
        self.mxDB = threading.Lock()
        self.debug = self.settings.get('debug', False)
        self.delay_event = threading.Event()
        self.chainstate_delay_event = threading.Event()

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
            self.chainstate_delay_event.set()
            self.delay_event.set()

    def prepareLogging(self):
        self.log = logging.getLogger(self.log_name)
        self.log.propagate = False

        # Remove any existing handlers
        self.log.handlers = []

        formatter = logging.Formatter('%(asctime)s %(levelname)s : %(message)s', '%Y-%m-%d %H:%M:%S')
        stream_stdout = logging.StreamHandler()
        if self.log_name != 'BasicSwap':
            stream_stdout.setFormatter(logging.Formatter('%(asctime)s %(name)s %(levelname)s : %(message)s', '%Y-%m-%d %H:%M:%S'))
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

    def is_tor_available(self):
        if not hasattr(self, 'use_tor_proxy'):
            return False
        if not self.use_tor_proxy:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((self.tor_proxy_host, self.tor_proxy_port))
            sock.close()
            return result == 0
        except:
            return False

    def readURL(self, url: str, timeout: int = 120, headers={}, debug: bool = False) -> bytes:
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        default_headers.update(headers)

        use_tor = self.is_tor_available()
        if debug:
            print(f"Debug: Tor is {'available and will be used' if use_tor else 'not available or not configured. Using clearnet'}.")
            print(f"Debug: Attempting to connect to {url}")

        try:
            if use_tor:
                if debug:
                    print(f"Debug: Using Tor proxy at {self.tor_proxy_host}:{self.tor_proxy_port}")
                proxy_handler = SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, self.tor_proxy_host, self.tor_proxy_port)
                opener = urllib.request.build_opener(proxy_handler)
            else:
                if debug:
                    print("Debug: Using clearnet connection")
                opener = urllib.request.build_opener()

            opener.addheaders = [(key, value) for key, value in default_headers.items()]
            request = urllib.request.Request(url)
            
            with opener.open(request, timeout=timeout) as response:
                return response.read()

        except urllib.error.URLError as e:
            if isinstance(e.reason, ConnectionRefusedError) and use_tor:
                error_msg = f"Connection refused. Tor proxy might not be running. Error: {str(e)}"
            else:
                error_msg = f"URLError: {str(e)}"
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"

        if debug:
            print(f"Debug: Error occurred - {error_msg}")
        return json.dumps({"Error": error_msg}).encode()

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

    def setMockTimeOffset(self, new_offset: int) -> None:
        self.log.warning(f'Setting mocktime to {new_offset}')
        self.mock_time_offset = new_offset

    def get_int_setting(self, name: str, default_v: int, min_v: int, max_v) -> int:
        value: int = self.settings.get(name, default_v)
        if value < min_v:
            self.log.warning(f'Setting {name} to {min_v}')
            value = min_v
        if value > max_v:
            self.log.warning(f'Setting {name} to {max_v}')
            value = max_v
        return value

    def get_delay_event_seconds(self):
        if self.min_delay_event == self.max_delay_event:
            return self.min_delay_event
        return random.randrange(self.min_delay_event, self.max_delay_event)

    def get_short_delay_event_seconds(self):
        if self.min_delay_event_short == self.max_delay_event_short:
            return self.min_delay_event_short
        return random.randrange(self.min_delay_event_short, self.max_delay_event_short)

    def get_delay_retry_seconds(self):
        if self.min_delay_retry == self.max_delay_retry:
            return self.min_delay_retry
        return random.randrange(self.min_delay_retry, self.max_delay_retry)
