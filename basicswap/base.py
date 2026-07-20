# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import os
import random
import shlex
import shutil
import socket
import socks
import subprocess
import sys
import threading
import time
import traceback
import urllib
import urllib.error
import urllib.parse
import urllib.request

from sockshandler import SocksiPyHandler

from .db import (
    DBMethods,
)
from .rpc import (
    callrpc,
)
from .util import (
    TemporaryError,
)
from .util.network import (
    is_public_url,
    is_url_scheme_allowed,
)
from .util.logging import (
    BSXLogger,
    LogCategories as LC,
)
from .chainparams import (
    Coins,
    chainparams,
)


def getaddrinfo_tor(*args):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (args[0], args[1]))]


class PublicOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    # Re-validate each redirect target so a public URL can't 30x-bounce to an
    # internal host (loopback, LAN, cloud-metadata).
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_public_url(newurl):
            raise urllib.error.HTTPError(
                newurl, code, "Redirect to non-public address blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class BaseApp(DBMethods):
    def __init__(self, data_dir, settings, chain, log_name="BasicSwap", **kwargs):
        self.fp = None
        self.log_name = log_name
        self.fail_code = 0
        self.mock_time_offset = 0

        self.data_dir = data_dir
        self.chain = chain
        self.settings = settings
        self.coin_clients = {}
        self.coin_interfaces = {}
        self.mxDB = threading.RLock()
        self.debug = self.settings.get("debug", False)
        self.delay_event = threading.Event()
        self.chainstate_delay_event = threading.Event()

        self._network = None
        self.prepareLogging()
        self.log.info(f"Network: {self.chain}")

        self.use_tor_proxy = self.settings.get("use_tor", False)
        self.tor_proxy_host = self.settings.get("tor_proxy_host", "127.0.0.1")
        self.tor_proxy_port = self.settings.get("tor_proxy_port", 9050)
        self.tor_control_password = self.settings.get("tor_control_password", None)
        self.tor_control_port = self.settings.get("tor_control_port", 9051)
        self.default_socket = socket.socket
        self.default_socket_timeout = socket.getdefaulttimeout()
        self.default_socket_getaddrinfo = socket.getaddrinfo
        self._force_db_upgrade = False

        self._enabled_log_categories = set()
        for category in self.settings.get("enabled_log_categories", []):
            category = category.lower()
            if category == "net":
                self._enabled_log_categories.add(LC.NET)
            else:
                self.log.warning(
                    f'Unknown entry "{category}" in "enabled_log_categories"'
                )

        if len(self._enabled_log_categories) > 0:
            self.log.info(
                "Enabled logging categories: {}".format(
                    ",".join(sorted([c.name for c in self._enabled_log_categories]))
                )
            )

        super().__init__(
            data_dir=data_dir,
            settings=settings,
            chain=chain,
            log_name=log_name,
            **kwargs,
        )

    def __del__(self):
        if self.fp:
            self.fp.close()

    def stopRunning(self, with_code=0):
        self.fail_code = with_code

        # Wait for lock to shutdown gracefully.
        if self.mxDB.acquire(timeout=5):
            self.chainstate_delay_event.set()
            self.delay_event.set()
            self.mxDB.release()
        else:
            # Waiting for lock timed out, stop anyway
            self.chainstate_delay_event.set()
            self.delay_event.set()

    def openLogFile(self):
        self.fp = open(os.path.join(self.data_dir, "basicswap.log"), "a")

    def prepareLogging(self):
        logging.setLoggerClass(BSXLogger)
        self.log = logging.getLogger(self.log_name)
        self.log.propagate = False

        self.openLogFile()

        # Remove any existing handlers
        self.log.handlers = []

        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s : %(message)s", "%Y-%m-%d %H:%M:%S"
        )
        stream_stdout = logging.StreamHandler(sys.stdout)
        if self.log_name != "BasicSwap":
            stream_stdout.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(name)s %(levelname)s : %(message)s",
                    "%Y-%m-%d %H:%M:%S",
                )
            )
        else:
            stream_stdout.setFormatter(formatter)
        self.log_formatter = formatter
        stream_fp = logging.StreamHandler(self.fp)
        stream_fp.setFormatter(formatter)

        self.log.setLevel(logging.DEBUG if self.debug else logging.INFO)
        self.log.addHandler(stream_fp)
        self.log.addHandler(stream_stdout)

    def getChainClientSettings(self, coin):
        try:
            return self.settings["chainclients"][chainparams[coin]["name"]]
        except Exception:
            return {}

    def getElectrumAddressIndex(self, coin_name: str) -> tuple:
        try:
            chain_settings = self.settings["chainclients"].get(coin_name, {})
            ext_idx = chain_settings.get("electrum_address_index", 0)
            int_idx = chain_settings.get("electrum_internal_address_index", 0)
            return (ext_idx, int_idx)
        except Exception:
            return (0, 0)

    def updateElectrumAddressIndex(
        self, coin_name: str, ext_idx: int, int_idx: int
    ) -> None:
        try:
            if coin_name not in self.settings["chainclients"]:
                self.log.debug(
                    f"updateElectrumAddressIndex: {coin_name} not in chainclients"
                )
                return

            chain_settings = self.settings["chainclients"][coin_name]
            current_ext = chain_settings.get("electrum_address_index", 0)
            current_int = chain_settings.get("electrum_internal_address_index", 0)

            if ext_idx <= current_ext and int_idx <= current_int:
                return

            if ext_idx > current_ext:
                chain_settings["electrum_address_index"] = ext_idx
            if int_idx > current_int:
                chain_settings["electrum_internal_address_index"] = int_idx

            self.log.debug(
                f"Persisting electrum address index for {coin_name}: ext={ext_idx}, int={int_idx}"
            )
            self._saveSettings()
        except Exception as e:
            self.log.warning(
                f"Failed to update electrum address index for {coin_name}: {e}"
            )

    def _normalizeSettingsPaths(self, settings: dict) -> dict:
        if "chainclients" in settings:
            for coin_name, cc in settings["chainclients"].items():
                for path_key in ("datadir", "bindir", "walletsdir"):
                    if path_key in cc and isinstance(cc[path_key], str):
                        cc[path_key] = os.path.normpath(cc[path_key])
        return settings

    def _saveSettings(self) -> None:
        from basicswap import config as cfg

        self._normalizeSettingsPaths(self.settings)

        settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
        settings_path_new = settings_path + ".new"
        try:
            if os.path.exists(settings_path):
                shutil.copyfile(settings_path, settings_path + ".last")
            with open(settings_path_new, "w") as fp:
                json.dump(self.settings, fp, indent=4)
            shutil.move(settings_path_new, settings_path)
            self.log.debug(f"Settings saved to {settings_path}")
        except Exception as e:
            self.log.warning(f"Failed to save settings: {e}")

    def setDaemonPID(self, name, pid) -> None:
        if isinstance(name, Coins):
            self.coin_clients[name]["pid"] = pid
            return
        for c, v in self.coin_clients.items():
            if v["name"] == name:
                v["pid"] = pid

    def getChainDatadirPath(self, coin) -> str:
        datadir = self.coin_clients[coin]["datadir"]
        testnet_name = (
            ""
            if self.chain == "mainnet"
            else chainparams[coin][self.chain].get("name", self.chain)
        )
        return os.path.join(datadir, testnet_name)

    def getCoinIdFromName(self, coin_name: str):
        for c, params in chainparams.items():
            if coin_name.lower() == params["name"].lower():
                return c
        raise ValueError(f"Unknown coin: {coin_name}")

    def callrpc(self, method, params=[], wallet=None, timeout=10):
        cc = self.coin_clients[Coins.PART]
        return callrpc(
            cc["rpcport"],
            cc["rpcauth"],
            method,
            params,
            wallet,
            cc["rpchost"],
            timeout=timeout,
        )

    def callcoinrpc(self, coin, method, params=[], wallet=None):
        cc = self.coin_clients[coin]
        return callrpc(
            cc["rpcport"], cc["rpcauth"], method, params, wallet, cc["rpchost"]
        )

    def callcoincli(self, coin_type, params, wallet=None, timeout=None):
        bindir = self.coin_clients[coin_type]["bindir"]
        datadir = self.coin_clients[coin_type]["datadir"]
        cli_bin: str = chainparams[coin_type].get(
            "cli_binname", chainparams[coin_type]["name"] + "-cli"
        )
        command_cli = os.path.join(
            bindir, cli_bin + (".exe" if os.name == "nt" else "")
        )
        args = [
            command_cli,
        ]
        if self.chain != "mainnet":
            args.append("-" + self.chain)
        args.append("-datadir=" + datadir)
        args += shlex.split(params)
        p = subprocess.Popen(
            args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out = p.communicate(timeout=timeout)
        if len(out[1]) > 0:
            raise ValueError("CLI error " + str(out[1]))
        return out[0].decode("utf-8").strip()

    transient_error_markers = (
        "read timed out",
        "no connection to daemon",
        # Connection-class faults, daemon restarting or briefly unreachable.
        "connection refused",
        "connection reset",
        "connection aborted",
        "broken pipe",
        "remote end closed",
        "temporarily unavailable",
        # Core warmup (-28) messages, matching the startup wait loop.
        "loading block index",
        "verifying blocks",
        "rewinding blocks",
        "activating best chain",
        "loading wallet",
        "starting network threads",
        "upgrading",
        "reaccepting wallet transactions",
        # Electrum server backend/rate-limit faults.
        "excessive resource usage",
        "server busy",
    )

    def is_transient_error(self, ex) -> bool:
        if isinstance(ex, TemporaryError):
            return True
        if isinstance(ex, socks.ProxyError):
            return True
        str_error = str(ex).lower()
        return any(marker in str_error for marker in self.transient_error_markers)

    def setConnectionParameters(self, timeout=120):
        opener = urllib.request.build_opener()
        opener.addheaders = [("User-agent", "Mozilla/5.0")]
        urllib.request.install_opener(opener)

        if self.use_tor_proxy:
            socks.setdefaultproxy(
                socks.PROXY_TYPE_SOCKS5,
                self.tor_proxy_host,
                self.tor_proxy_port,
                rdns=True,
            )
            socket.socket = socks.socksocket
            socket.getaddrinfo = (
                getaddrinfo_tor  # Without this accessing .onion links would fail
            )

        socket.setdefaulttimeout(timeout)

    def popConnectionParameters(self) -> None:
        if self.use_tor_proxy:
            socket.socket = self.default_socket
            socket.getaddrinfo = self.default_socket_getaddrinfo
        socket.setdefaulttimeout(self.default_socket_timeout)

    def readURL(
        self, url: str, timeout: int = 120, headers={}, check_public: bool = False
    ) -> bytes:
        if not is_url_scheme_allowed(url):
            raise ValueError("Unsupported URL scheme.")
        open_handler = None
        if self.use_tor_proxy:
            open_handler = SocksiPyHandler(
                socks.PROXY_TYPE_SOCKS5, self.tor_proxy_host, self.tor_proxy_port
            )
        # Tor egresses via the SOCKS proxy (rdns), so local resolution can't vet
        # the real destination; the scheme allowlist above still applies.
        build_args = [open_handler] if self.use_tor_proxy else []
        if check_public and not self.use_tor_proxy:
            build_args.append(PublicOnlyRedirectHandler())
        opener = urllib.request.build_opener(*build_args)
        if headers is None:
            opener.addheaders = [("User-agent", "Mozilla/5.0")]
        request = urllib.request.Request(url, headers=headers)
        return opener.open(request, timeout=timeout).read()

    def logException(self, message: str) -> None:
        self.log.error(message)
        if self.debug:
            self.log.error(traceback.format_exc())

    def logD(self, log_category: int, message: str) -> None:
        if log_category not in self._enabled_log_categories:
            return
        self.log.debug("(" + LC(log_category).name + ") " + message)

    def torControl(self, query):
        try:
            command = 'AUTHENTICATE "{}"\r\n{}\r\nQUIT\r\n'.format(
                self.tor_control_password, query
            ).encode("utf-8")
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
            self.log.error(f"torControl {e}")
            return

    def getTime(self) -> int:
        return int(time.time()) + self.mock_time_offset

    def setMockTimeOffset(self, new_offset: int) -> None:
        self.log.warning(f"Setting mocktime to {new_offset}")
        self.mock_time_offset = new_offset

    def get_clamped_int_from(
        self,
        settings: dict,
        name: str,
        default_v: int,
        min_v: int | None = None,
        max_v: int | None = None,
    ) -> int:
        value: int = settings.get(name, default_v)
        if type(value) is not int:
            raise ValueError(f'setting "{name}" must be integer type')
        if min_v is not None and value < min_v:
            self.log.warning(f"Setting {name} to {min_v}")
            value = min_v
        if max_v is not None and value > max_v:
            self.log.warning(f"Setting {name} to {max_v}")
            value = max_v
        return value

    def get_int_setting(
        self,
        name: str,
        default_v: int,
        min_v: int | None = None,
        max_v: int | None = None,
    ) -> int:
        return self.get_clamped_int_from(self.settings, name, default_v, min_v, max_v)

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
