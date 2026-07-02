#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import contextlib
import gnupg
import hashlib
import json
import logging
import os
import platform
import shutil
import signal
import socket
import socks
import sys
import time
import urllib.parse
import zmq

from typing import List
from urllib.request import urlopen

import basicswap.config as cfg
from basicswap import __version__
from basicswap.base import getaddrinfo_tor
from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins, chainparams, getCoinIdFromName
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.ui.util import getCoinName
from basicswap.util import toBool
from basicswap.util.network import urlretrieve, make_reporthook
from basicswap.util.rfc2440 import rfc2440_hash_password
from basicswap.bin.run import (
    startDaemon,
    startXmrWalletDaemon,
    getCoreBinName,
    getCoreBinArgs,
    getWalletBinName,
)

from basicswap.interface.prepare_util import (
    ensureFileHashInFile,
    exitWithError,
    isValidSignature,
    PrepareContext,
    havePubkey,
    getFileHash,
)
from basicswap.interface.btc.core import prepare_module as btc_prepare
from basicswap.interface.ltc.core import prepare_module as ltc_prepare
from basicswap.interface.part.core import (
    PART_RPC_HOST,
    PART_ZMQ_PORT,
    prepare_module as part_prepare,
)
from basicswap.interface.bch.core import prepare_module as bch_prepare
from basicswap.interface.dash.core import prepare_module as dash_prepare
from basicswap.interface.dcr.core import prepare_module as dcr_prepare
from basicswap.interface.xmr.core import (
    DEFAULT_XMR_RESTORE_HEIGHT,
    prepare_module as xmr_prepare,
)
from basicswap.interface.wow.core import (
    DEFAULT_WOW_RESTORE_HEIGHT,
    prepare_module as wow_prepare,
)
from basicswap.interface.pivx.core import prepare_module as pivx_prepare
from basicswap.interface.firo.core import prepare_module as firo_prepare
from basicswap.interface.doge.core import prepare_module as doge_prepare
from basicswap.interface.nav.core import prepare_module as nav_prepare
from basicswap.interface.nmc.core import prepare_module as nmc_prepare

coin_prepare_modules = {
    "particl": part_prepare,
    "bitcoin": btc_prepare,
    "litecoin": ltc_prepare,
    "bitcoincash": bch_prepare,
    "dash": dash_prepare,
    "decred": dcr_prepare,
    "dogecoin": doge_prepare,
    "navcoin": nav_prepare,
    "namecoin": nmc_prepare,
    "monero": xmr_prepare,
    "wownero": wow_prepare,
    "pivx": pivx_prepare,
    "firo": firo_prepare,
}

known_coins = {
    "particl": (
        part_prepare.version,
        part_prepare.version_tag,
        part_prepare.signers.keys(),
    ),
    "bitcoin": (
        btc_prepare.version,
        btc_prepare.version_tag,
        btc_prepare.signers.keys(),
    ),
    "litecoin": (
        ltc_prepare.version,
        ltc_prepare.version_tag,
        ltc_prepare.signers.keys(),
    ),
    "decred": (
        dcr_prepare.version,
        dcr_prepare.version_tag,
        dcr_prepare.signers.keys(),
    ),
    "namecoin": (
        nmc_prepare.version,
        nmc_prepare.version_tag,
        nmc_prepare.signers.keys(),
    ),
    "monero": (
        xmr_prepare.version,
        xmr_prepare.version_tag,
        xmr_prepare.signers.keys(),
    ),
    "wownero": (
        wow_prepare.version,
        wow_prepare.version_tag,
        wow_prepare.signers.keys(),
    ),
    "pivx": (
        pivx_prepare.version,
        pivx_prepare.version_tag,
        pivx_prepare.signers.keys(),
    ),
    "dash": (
        dash_prepare.version,
        dash_prepare.version_tag,
        dash_prepare.signers.keys(),
    ),
    "firo": (
        firo_prepare.version,
        firo_prepare.version_tag,
        firo_prepare.signers.keys(),
    ),
    "navcoin": (
        nav_prepare.version,
        nav_prepare.version_tag,
        nav_prepare.signers.keys(),
    ),
    "bitcoincash": (
        bch_prepare.version,
        bch_prepare.version_tag,
        bch_prepare.signers.keys(),
    ),
    "dogecoin": (
        doge_prepare.version,
        doge_prepare.version_tag,
        doge_prepare.signers.keys(),
    ),
}

disabled_coins = [
    "navcoin",
]

# Network clients
SIMPLEX_CHAT_VERSION = os.getenv("SIMPLEX_CHAT_VERSION", "6.3.5")
SIMPLEX_WS_PORT = int(os.getenv("SIMPLEX_WS_PORT", 5225))
SIMPLEX_SERVER_ADDRESS = os.getenv(
    "SIMPLEX_CHAT_VERSION",
    "smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im",
)
SIMPLEX_SERVER_SOCKS_PROXY = os.getenv("SIMPLEX_SERVER_SOCKS_PROXY", "127.0.0.1:9150")
SIMPLEX_GROUP_LINK = os.getenv("SIMPLEX_GROUP_LINK", None)


known_networks = ["smsg", "simplex"]
disabled_networks = []


expected_key_ids = {
    "tecnovert": ("8E517DC12EC1CC37F6423A8A13F13651C9CF0D6B",),
    "nicolasdorier": (
        "AB4CFA9895ACA0DBE27F6B346618763EF09186FE",
        "015B4C837B245509E4AC8995223FDA69DEBEA82D",
        "7121BDE3555D9BE06BDDC68162FE85647DEDDA2E",
    ),
    "SimpleX_Chat": ("FB44AF81A45BDE327319797C85107E357D4A17FC",),
}

GUIX_SSL_CERT_DIR = None
OVERRIDE_DISABLED_COINS = toBool(os.getenv("OVERRIDE_DISABLED_COINS", False))

# If SKIP_GPG_VALIDATION is set to true the script will check hashes but not signatures
SKIP_GPG_VALIDATION = toBool(os.getenv("SKIP_GPG_VALIDATION", False))

USE_PLATFORM = os.getenv("USE_PLATFORM", platform.system())
if USE_PLATFORM == "Darwin":
    BIN_ARCH = "osx64"
    FILE_EXT = "tar.gz"
elif USE_PLATFORM == "Windows":
    BIN_ARCH = "win64"
    FILE_EXT = "zip"
else:
    machine: str = platform.machine()
    if "arm" in machine:
        BIN_ARCH = "arm-linux-gnueabihf"
    else:
        BIN_ARCH = machine + "-linux-gnu"
    FILE_EXT = "tar.gz"

# Allow manually overriding the arch tag
BIN_ARCH = os.getenv("BIN_ARCH", BIN_ARCH)
FILE_EXT = os.getenv("FILE_EXT", FILE_EXT)

logger = logging.getLogger("prepare")
LOG_LEVEL = logging.DEBUG
logger.propagate = False
logger.level = LOG_LEVEL
if not len(logger.handlers):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)s : %(message)s"))
    logger.addHandler(handler)
logging.getLogger("gnupg").setLevel(logging.INFO)

BSX_DOCKER_MODE = toBool(os.getenv("BSX_DOCKER_MODE", False))
BSX_LOCAL_TOR = toBool(os.getenv("BSX_LOCAL_TOR", False))
BSX_TEST_MODE = toBool(os.getenv("BSX_TEST_MODE", False))
BSX_UPDATE_UNMANAGED = toBool(
    os.getenv("BSX_UPDATE_UNMANAGED", True)
)  # Disable updating unmanaged coin cores.
UI_HTML_PORT = int(os.getenv("UI_HTML_PORT", 12700))
UI_WS_PORT = int(os.getenv("UI_WS_PORT", 11700))
COINS_RPCBIND_IP = os.getenv("COINS_RPCBIND_IP", "127.0.0.1")
DEFAULT_RESTORE_TIME = int(os.getenv("DEFAULT_RESTORE_TIME", 1577833261))  # 2020


TOR_PROXY_HOST = os.getenv("TOR_PROXY_HOST", "127.0.0.1")
TOR_PROXY_PORT = int(os.getenv("TOR_PROXY_PORT", 9050))
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", 9051))
TOR_DNS_PORT = int(os.getenv("TOR_DNS_PORT", 5353))


def setTorrcVars():
    global TOR_CONTROL_LISTEN_INTERFACE, TORRC_PROXY_HOST, TORRC_CONTROL_HOST, TORRC_DNS_HOST
    TOR_CONTROL_LISTEN_INTERFACE = os.getenv(
        "TOR_CONTROL_LISTEN_INTERFACE", "127.0.0.1" if BSX_LOCAL_TOR else "0.0.0.0"
    )
    TORRC_PROXY_HOST = os.getenv(
        "TORRC_PROXY_HOST", "127.0.0.1" if BSX_LOCAL_TOR else "0.0.0.0"
    )
    TORRC_CONTROL_HOST = os.getenv(
        "TORRC_CONTROL_HOST", "127.0.0.1" if BSX_LOCAL_TOR else "0.0.0.0"
    )
    TORRC_DNS_HOST = os.getenv(
        "TORRC_DNS_HOST", "127.0.0.1" if BSX_LOCAL_TOR else "0.0.0.0"
    )


TEST_TOR_PROXY = toBool(os.getenv("TEST_TOR_PROXY", True))  # Expects a known exit node
TEST_ONION_LINK = toBool(os.getenv("TEST_ONION_LINK", False))

# Encrypt new wallets with this password, must match the Particl wallet password when adding coins
WALLET_ENCRYPTION_PWD = os.getenv("WALLET_ENCRYPTION_PWD", "")

CHECK_FOR_BSX_UPDATES = toBool(os.getenv("CHECK_FOR_BSX_UPDATES", True))

use_tor_proxy: bool = False
with_coins_changed: bool = False

monerod_proxy_config = [
    f"proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}",
    "proxy-allow-dns-leaks=0",
    "no-igd=1",  # Disable UPnP port mapping
    "hide-my-port=1",  # Don't share the p2p port
    "p2p-bind-ip=127.0.0.1",  # Don't broadcast ip
    "in-peers=0",  # Changes "error" in log to "incoming connections disabled"
    "out-peers=24",
    f"tx-proxy=tor,{TOR_PROXY_HOST}:{TOR_PROXY_PORT},disable_noise,16",  # Outgoing tx relay to onion
]

monero_wallet_rpc_proxy_config = [
    #   'daemon-ssl-allow-any-cert=1', moved to startup flag
]

default_socket = socket.socket
default_socket_timeout = socket.getdefaulttimeout()
default_socket_getaddrinfo = socket.getaddrinfo


def shouldManageDaemon(prefix: str) -> bool:
    """
    If the user sets a COIN _RPC_HOST or PORT variable, set manage_daemon for COIN to false.
    The COIN _MANAGE_DAEMON variables can override this and set manage_daemon directly.
    If BSX_DOCKER_MODE is active COIN _MANAGE_DAEMON will default to false.
    """
    default_mode: str = (
        "false" if BSX_DOCKER_MODE else "true" if BSX_TEST_MODE else "auto"
    )
    manage_daemon: str = os.getenv(prefix + "_MANAGE_DAEMON", default_mode)

    if manage_daemon == "auto":
        host_was_set: bool = prefix + "_RPC_HOST" in os.environ
        port_was_set: bool = prefix + "_RPC_PORT" in os.environ

        if host_was_set or port_was_set:
            return False
        return True

    return toBool(manage_daemon)


def getWalletName(coin_params: str, default_name: str, prefix_override=None) -> str:
    prefix: str = coin_params["ticker"] if prefix_override is None else prefix_override
    env_var_name: str = prefix + "_WALLET_NAME"

    if env_var_name in os.environ and coin_params.get("has_multiwallet", True) is False:
        raise ValueError("Can't set wallet name for {}.".format(coin_params["ticker"]))

    wallet_name: str = os.getenv(env_var_name, default_name)
    assert len(wallet_name) > 0
    return wallet_name


def getDescriptorWalletOption(coin_params):
    ticker: str = coin_params["ticker"]
    default_option: bool = True if ticker in ("NMC",) else False
    return toBool(os.getenv(ticker + "_USE_DESCRIPTORS", default_option))


def getLegacyKeyPathOption(coin_params):
    ticker: str = coin_params["ticker"]
    default_option: bool = False
    return toBool(os.getenv(ticker + "_USE_LEGACY_KEY_PATHS", default_option))


def setConnectionParameters(timeout: int = 5, allow_set_tor: bool = True):
    opener = urllib.request.build_opener()
    opener.addheaders = [("User-agent", "Mozilla/5.0")]
    urllib.request.install_opener(opener)

    if use_tor_proxy:
        socks.setdefaultproxy(
            socks.PROXY_TYPE_SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT, rdns=True
        )
        socket.socket = socks.socksocket
        socket.getaddrinfo = (
            getaddrinfo_tor  # Without this accessing .onion links would fail
        )

    # Set low timeout for urlretrieve connections
    socket.setdefaulttimeout(timeout)
    logger.level = logging.INFO


def popConnectionParameters() -> None:
    if use_tor_proxy:
        socket.socket = default_socket
        socket.getaddrinfo = default_socket_getaddrinfo
    socket.setdefaulttimeout(default_socket_timeout)
    logger.level = LOG_LEVEL


def getRemoteFileLength(url: str) -> (int, bool):
    try:
        setConnectionParameters()
        with contextlib.closing(urlopen(url)) as fp:
            # NOTE: The test here is case insensitive, 'Accept-Ranges' will match
            can_resume = "accept-ranges" in fp.headers
            return fp.length, can_resume
    finally:
        popConnectionParameters()


def downloadRelease(
    url_in: str | List[str], path: str, extra_opts, timeout: int = 10
) -> None:
    # If file exists at path compare it's size to the content length at the url
    # and attempt to resume download if file size is below expected.

    release_filename: str = os.path.basename(path)
    urls = (
        url_in
        if isinstance(url_in, list)
        else [
            url_in,
        ]
    )
    for url in urls:
        try:
            resume_from: int = 0
            if os.path.exists(path):
                if extra_opts.get("redownload_releases", False):
                    logging.warning(f"Overwriting: {path}")
                elif extra_opts.get("verify_release_file_size", True):
                    file_size = os.stat(path).st_size
                    remote_file_length, can_resume = getRemoteFileLength(url)
                    if file_size < remote_file_length:
                        logger.warning(
                            f"{path} is an unexpected size, {file_size} < {remote_file_length}.  Attempting to resume download."
                        )
                        if can_resume:
                            resume_from = file_size
                        else:
                            logger.warning("Download can not be resumed, restarting.")
                    else:
                        return
                else:
                    # File exists and size check is disabled
                    return
            return downloadFile(url, path, timeout, resume_from)
        except Exception as e:
            logger.warning(f"Failed to download {release_filename} from {url}")
            logger.debug(f"Download error {e}")
    raise RuntimeError(f"Failed to download {release_filename}.")


def downloadFile(url: str, path: str, timeout: int = 5, resume_from: int = 0) -> None:
    logger.info(f"Downloading file {url}")
    logger.info(f"To {path}")
    try:
        setConnectionParameters(timeout=timeout)
        urlretrieve(
            url, path, make_reporthook(resume_from, logger), resume_from=resume_from
        )
    finally:
        popConnectionParameters()


def downloadBytes(url) -> None:
    try:
        setConnectionParameters()
        with contextlib.closing(urlopen(url)) as fp:
            return fp.read()
    finally:
        popConnectionParameters()


def getBasePath():
    base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(os.path.join(base_path, "basicswap", "pgp")):
        base_path = os.path.join(base_path, "basicswap")
    return base_path


def importPubkey(gpg, pubkey_filename, pubkeyurls):
    base_path = getBasePath()
    local_path = os.path.join(base_path, "pgp", "keys", pubkey_filename)
    if os.path.exists(local_path):
        logger.info("Importing public key from file: " + pubkey_filename)
        try:
            with open(local_path, "rb") as fp:
                rv = gpg.import_keys(fp.read())
            for key in rv.fingerprints:
                gpg.trust_keys(key, "TRUST_FULLY")
            return
        except Exception as e:
            logging.warning(f"Import from file failed: {e}")
    else:
        logger.warning(f"Public key file {pubkey_filename} not found locally.")

    for url in pubkeyurls:
        try:
            logger.info("Importing public key from url: " + url)
            rv = gpg.import_keys(downloadBytes(url))
            for key in rv.fingerprints:
                gpg.trust_keys(key, "TRUST_FULLY")
            break
        except Exception as e:
            logging.warning(f"Import from url failed: {e}")


def testTorConnection():
    test_url = "https://check.torproject.org/"
    logger.info("Testing TOR connection at: " + test_url)

    test_response = downloadBytes(test_url).decode("utf-8")
    assert "Congratulations. This browser is configured to use Tor." in test_response
    logger.info("TOR is working.")


def testOnionLink():
    test_url = "http://jqyzxhjk6psc6ul5jnfwloamhtyh7si74b4743k2qgpskwwxrzhsxmad.onion"
    logger.info("Testing onion site: " + test_url)
    test_response = downloadBytes(test_url).decode("utf-8")
    assert (
        "The Tor Project's free software protects your privacy online." in test_response
    )
    logger.info("Onion links work.")


def ensureValidSignatureBy(result, signing_key_name):
    if not isValidSignature(result):
        raise ValueError("Signature verification failed.")

    if result.fingerprint not in expected_key_ids[signing_key_name]:
        raise ValueError(
            "Signature made by unexpected key fingerprint: " + result.fingerprint
        )

    logger.debug(f"Found valid signature by {signing_key_name} ({result.key_id}).")


def prepareCore(coin, version_data, settings, data_dir, extra_opts={}):
    version, version_tag, signers = version_data

    passed: bool = False
    for signer in signers:
        try:
            tryPrepareCore(
                coin, version_data, signer, settings, data_dir, extra_opts=extra_opts
            )
            passed = True
            break
        except Exception as e:
            if len(signers) < 2:
                raise
            logger.warning(
                f"Prepare core failed: {coin} v{version}{version_tag} - Signer: {signer}. Error: {e}"
            )
    if passed is False:
        raise RuntimeError(f"Prepare core failed: {coin} v{version}{version_tag}")


def tryPrepareCore(coin, version_data, signer, settings, data_dir, extra_opts={}):
    version, version_tag, signers = version_data
    logger.info(f"Prepare core: {coin} v{version}{version_tag} - Signer: {signer}")

    bin_dir = os.path.expanduser(settings["chainclients"][coin]["bindir"])
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    signing_key_name = signer
    prepare_module = coin_prepare_modules.get(coin)
    if prepare_module is None:
        raise ValueError("Unknown coin")

    release_path, assert_path, assert_sig_path = prepare_module.downloadCore(
        extra_opts["prepare_ctx"],
        bin_dir,
        signing_key_name,
        extra_opts,
    )

    prepare_module.verifyCoreHash(extra_opts["prepare_ctx"], release_path, assert_path)

    if SKIP_GPG_VALIDATION:
        logger.warning(
            "Skipping binary signature check as SKIP_GPG_VALIDATION env var is set."
        )
        prepare_module.extractCore(
            extra_opts["prepare_ctx"], bin_dir, release_path, extra_opts
        )
        return

    gpg = gnupg.GPG()

    keysdirpath = extra_opts.get("keysdirpath", None)
    if keysdirpath is not None:
        logger.info(f"Loading PGP keys from: {keysdirpath}.")
        for path in os.scandir(keysdirpath):
            if path.is_file():
                with open(path, "rb") as fp:
                    rv = gpg.import_keys(fp.read())
                    for key in rv.fingerprints:
                        gpg.trust_keys(rv.fingerprints[0], "TRUST_FULLY")

    prepare_module.verifyCoreSignature(
        extra_opts["prepare_ctx"],
        gpg,
        release_path,
        assert_path,
        assert_sig_path,
        signing_key_name,
        extra_opts,
    )
    prepare_module.extractCore(
        extra_opts["prepare_ctx"], bin_dir, release_path, extra_opts
    )


def writeTorSettings(fp, coin, coin_settings, tor_control_password):
    """
    TOR_PROXY_HOST must be an ip address.
    BTC versions >21 and Particl with lookuptorcontrolhost=any can accept hostnames, XMR and LTC cannot
    """
    fp.write(f"proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}\n")
    if coin in ("decred",):
        return

    onionport = coin_settings["onionport"]
    fp.write(f"torpassword={tor_control_password}\n")
    fp.write(f"torcontrol={TOR_PROXY_HOST}:{TOR_CONTROL_PORT}\n")

    if coin_settings["core_version_group"] >= 21:
        fp.write(f"bind={TOR_CONTROL_LISTEN_INTERFACE}:{onionport}=onion\n")
    else:
        fp.write(f"bind={TOR_CONTROL_LISTEN_INTERFACE}:{onionport}\n")


def prepareDataDir(coin, settings, chain, particl_mnemonic, extra_opts={}):
    prepare_module = coin_prepare_modules.get(coin)
    if prepare_module is None:
        raise ValueError("Unknown coin")

    prepare_module.prepareDataDir(
        extra_opts["prepare_ctx"], settings, chain, extra_opts
    )


def write_torrc(data_dir, tor_control_password):
    tor_dir = os.path.join(data_dir, "tor")
    if not os.path.exists(tor_dir):
        os.makedirs(tor_dir)
    torrc_path = os.path.join(tor_dir, "torrc")

    tor_control_hash = rfc2440_hash_password(tor_control_password)
    with open(torrc_path, "w") as fp:
        fp.write(f"SocksPort {TORRC_PROXY_HOST}:{TOR_PROXY_PORT}\n")
        fp.write(f"ControlPort {TORRC_CONTROL_HOST}:{TOR_CONTROL_PORT}\n")
        fp.write(f"DNSPort {TORRC_DNS_HOST}:{TOR_DNS_PORT}\n")
        fp.write(f"HashedControlPassword {tor_control_hash}\n")


def addTorSettings(settings, tor_control_password):
    settings["use_tor"] = True
    settings["tor_proxy_host"] = TOR_PROXY_HOST
    settings["tor_proxy_port"] = TOR_PROXY_PORT
    settings["tor_control_password"] = tor_control_password
    settings["tor_control_port"] = TOR_CONTROL_PORT


def modify_tor_config(
    settings, coin, tor_control_password=None, enable=False, extra_opts={}
):
    coin_settings = settings["chainclients"][coin]
    data_dir = coin_settings["datadir"]

    if coin in ("monero", "wownero"):
        core_conf_name: str = coin_settings.get("config_filename", coin + "d.conf")
        core_conf_path = os.path.join(data_dir, core_conf_name)
        if not os.path.exists(core_conf_path):
            exitWithError(f"Daemon config file {core_conf_path} does not exist")

        wallets_dir = coin_settings.get("walletsdir", data_dir)
        wallet_conf_filename: str = coin_settings.get(
            "wallet_config_filename",
            "monero_wallet.conf" if coin == "monero" else (coin + "-wallet-rpc.conf"),
        )
        wallet_conf_path = os.path.join(wallets_dir, wallet_conf_filename)
        if not os.path.exists(wallet_conf_path):
            exitWithError(f"Wallet config file {wallet_conf_path} does not exist")

        # Backup
        shutil.copyfile(core_conf_path, core_conf_path + ".last")
        shutil.copyfile(wallet_conf_path, wallet_conf_path + ".last")

        with open(core_conf_path, "w") as fp:
            with open(core_conf_path + ".last") as fp_in:
                # Disable tor first
                for line in fp_in:
                    skip_line: bool = False
                    if coin in ("wownero", "monero"):
                        for opt_line in monerod_proxy_config:
                            setting: str = opt_line[0 : opt_line.find("=") + 1]
                            if line.startswith(setting):
                                skip_line = True
                                break
                    if not skip_line:
                        fp.write(line)
            if enable:
                if coin in ("wownero", "monero"):
                    for opt_line in monerod_proxy_config:
                        fp.write(opt_line + "\n")

        with open(wallet_conf_path, "w") as fp:
            with open(wallet_conf_path + ".last") as fp_in:
                # Disable tor first
                for line in fp_in:
                    skip_line = False
                    for opt_line in monero_wallet_rpc_proxy_config + [
                        "proxy=",
                    ]:
                        setting: str = opt_line[0 : opt_line.find("=") + 1]
                        if line.startswith(setting):
                            skip_line = True
                            break
                    if not skip_line:
                        fp.write(line)
            if enable:
                if not coin_settings["manage_daemon"]:
                    for opt_line in monero_wallet_rpc_proxy_config:
                        fp.write(opt_line + "\n")

            coin_settings["trusted_daemon"] = extra_opts.get(
                "trust_remote_node", "auto"
            )
        return

    core_conf_name: str = coin_settings.get(
        "config_filename", "dcrd.conf" if coin == "decred" else (coin + ".conf")
    )
    config_path = os.path.join(data_dir, core_conf_name)

    if not os.path.exists(config_path):
        exitWithError("{} does not exist".format(config_path))

    if "onionport" not in coin_settings:
        default_onionport = 0
        if coin == "bitcoin":
            default_onionport = btc_prepare.onion_port
        if coin == "bitcoincash":
            default_onionport = bch_prepare.onion_port
        elif coin == "particl":
            default_onionport = part_prepare.onion_port
        elif coin == "litecoin":
            default_onionport = ltc_prepare.onion_port
        elif coin == "dogecoin":
            default_onionport = doge_prepare.onion_port
        elif coin in ("decred",):
            pass
        else:
            exitWithError("Unknown default onion listening port for {}".format(coin))
        if default_onionport > 0:
            coin_settings["onionport"] = default_onionport

    # Backup
    shutil.copyfile(config_path, config_path + ".last")

    tor_settings = ("proxy=", "torpassword=", "torcontrol=", "bind=")
    with open(config_path, "w") as fp:
        with open(config_path + ".last") as fp_in:
            # Disable tor first
            for line in fp_in:
                skip_line = False
                for setting in tor_settings:
                    if line.startswith(setting):
                        skip_line = True
                        break
                if not skip_line:
                    fp.write(line)
        if enable:
            writeTorSettings(fp, coin, coin_settings, tor_control_password)


def printVersion(with_coins):
    print(f"Basicswap version: {__version__}")

    if len(with_coins) < 1:
        return
    print("Core versions:")
    for coin, version in known_coins.items():
        if with_coins_changed and coin not in with_coins:
            continue
        postfix = " (Disabled)" if coin in disabled_coins else ""
        print(f"\t{coin.capitalize()}: {version[0]}{version[1]}{postfix}")


def printHelp():
    print("Usage: basicswap-prepare ")
    print("\n--help, -h               Print help.")
    print("--version, -v            Print version.")
    print(
        "--datadir=PATH           Path to basicswap data directory, default:{}.".format(
            cfg.BASICSWAP_DATADIR
        )
    )
    print("--bindir=PATH            Path to cores directory, default:datadir/bin.")
    print("--mainnet                Run in mainnet mode.")
    print("--testnet                Run in testnet mode.")
    print("--regtest                Run in regtest mode.")
    print(
        "--particl_mnemonic=      Recovery phrase to use for the Particl wallet, default is randomly generated,\n"
        + '                         "auto" to create a wallet automatically - No mnemonic.'
        + '                         "none" to disable wallet initialisation.'
    )
    print("--withcoin=              Prepare system to run daemon for coin.")
    print("--withoutcoin=           Do not prepare system to run daemon for coin.")
    print("--addcoin=               Add coin to existing setup.")
    print("--disablecoin=           Make coin inactive.")
    print(
        "--upgradecores           Upgrade all coin cores present in basicswap.json. Optionally use alongside --withcoin= or --withoutcoin="
    )
    print("--preparebinonly         Don't prepare settings or datadirs.")
    print("--nocores                Don't download and extract any coin clients.")
    print("--addnetwork             Add network.")
    print("--disablenetwork         Remove network.")
    print("--usecontainers          Expect each core to run in a unique container.")
    print("--portoffset=n           Raise all ports by n.")
    print(
        "--htmlhost=              Interface to host html server on, default:127.0.0.1."
    )
    print(
        '--wshost=                Interface to host websocket server on, disable by setting to "none", default\'s to --htmlhost.'
    )
    print(
        "--xmrrestoreheight=n     Block height to restore Monero wallet from, default:{}.".format(
            DEFAULT_XMR_RESTORE_HEIGHT
        )
    )
    print(
        "--wowrestoreheight=n     Block height to restore Wownero wallet from, default:{}.".format(
            DEFAULT_WOW_RESTORE_HEIGHT
        )
    )
    print(
        "--walletrestoretime=n     Time to restore wallets from, default:{}, -1 for now.".format(
            DEFAULT_RESTORE_TIME
        )
    )
    print(
        "--trustremotenode        Set trusted-daemon for XMR, defaults to auto: true when daemon rpchost value is a private ip address else false"
    )
    print(
        "--noextractover          Prevent extracting cores if files exist.  Speeds up tests"
    )
    print(
        "--usetorproxy            Use TOR proxy during setup.  Note that some download links may be inaccessible over TOR."
    )
    print(
        "--notorproxy             Force usetorproxy off, usetorproxy is automatically set when tor is enabled"
    )
    print("--enabletor              Setup Basicswap instance to use TOR.")
    print("--disabletor             Setup Basicswap instance to not use TOR.")
    print(
        "--usebtcfastsync         Initialise the BTC chain with a snapshot from btcpayserver FastSync.\n"
        + "                         See https://github.com/btcpayserver/btcpayserver-docker/blob/master/contrib/FastSync/README.md"
    )
    print(
        "--skipbtcfastsyncchecks  Use the provided btcfastsync file without checking it's size or signature."
    )
    print("--initwalletsonly        Setup coin wallets only.")
    print(
        "--keysdirpath            Speed up tests by preloading all PGP keys in directory."
    )
    print(
        "--noreleasesizecheck     If unset the size of existing core release files will be compared to their size at their download url."
    )
    print("--redownloadreleases     If set core release files will be redownloaded.")
    print(
        "--dashv20compatible      Generate the same DASH wallet seed as for DASH v20 - Use only when importing an existing seed."
    )
    print("--client-auth-password=  Set or update the password to protect the web UI.")
    print("--disable-client-auth    Remove password protection from the web UI.")
    print(
        "--light                  Use light wallet mode (Electrum) for all supported coins."
    )
    print("--btc-mode=MODE          Set BTC connection mode: rpc, electrum, or remote.")
    print("--ltc-mode=MODE          Set LTC connection mode: rpc, electrum, or remote.")
    print("--btc-electrum-server=   Custom Electrum server for BTC (host:port:ssl).")
    print("--ltc-electrum-server=   Custom Electrum server for LTC (host:port:ssl).")

    active_coins = []
    for coin_name in known_coins.keys():
        if coin_name not in disabled_coins:
            active_coins.append(coin_name)
    print("\n" + "Known coins: {}".format(", ".join(active_coins)))


def finalise_daemon(d):
    logging.info(f"Interrupting {d.name} {d.handle.pid}")
    try:
        d.handle.send_signal(signal.CTRL_C_EVENT if os.name == "nt" else signal.SIGINT)
        d.handle.wait(timeout=120)
        for fp in [d.handle.stdout, d.handle.stderr, d.handle.stdin] + d.files:
            if fp:
                fp.close()
    except Exception as e:
        logging.info(f"Error stopping {d.name}, process {d.handle.pid}: {e}")


def test_particl_encryption(data_dir, settings, chain, use_tor_proxy, extra_opts):
    swap_client = None
    daemons = []
    daemon_args = ["-noconnect", "-nodnsseed", "-nofindpeers", "-nostaking"]
    try:
        swap_client = BasicSwap(data_dir, settings, chain, transient_instance=True)
        if not swap_client.use_tor_proxy:
            # Cannot set -bind or -whitebind together with -listen=0
            daemon_args.append("-nolisten")
        c = Coins.PART
        coin_name = "particl"
        coin_settings = settings["chainclients"][coin_name]
        daemon_args += getCoreBinArgs(c, coin_settings, prepare=True)
        extra_config = {"stdout_to_file": True, "coin_name": coin_name}
        if coin_settings["manage_daemon"]:
            filename: str = getCoreBinName(c, coin_settings, coin_name + "d")
            daemons.append(
                startDaemon(
                    coin_settings["datadir"],
                    coin_settings["bindir"],
                    filename,
                    daemon_args,
                    extra_config=extra_config,
                )
            )
            swap_client.setDaemonPID(c, daemons[-1].handle.pid)
        swap_client.setCoinRunParams(c)
        swap_client.createCoinInterface(c)
        swap_client.waitForDaemonRPC(c, with_wallet=True)

        if swap_client.ci(c).isWalletEncrypted():
            logger.info("Particl Wallet is encrypted")
            if WALLET_ENCRYPTION_PWD == "":
                raise ValueError(
                    "Must set WALLET_ENCRYPTION_PWD to add coin when Particl wallet is encrypted"
                )
            swap_client.ci(c).unlockWallet(WALLET_ENCRYPTION_PWD)
        extra_opts["particl_daemon"] = daemons[-1]
    finally:
        if swap_client:
            swap_client.finalise()
            del swap_client
        if "particl_daemon" not in extra_opts:
            for d in daemons:
                finalise_daemon(d)


def initialise_wallets(
    particl_wallet_mnemonic,
    with_coins,
    data_dir,
    settings,
    chain,
    use_tor_proxy,
    extra_opts={},
):
    prepare_ctx = extra_opts["prepare_ctx"]
    swap_client = None
    daemons = []
    daemon_args = ["-noconnect", "-nodnsseed"]
    generated_mnemonic: bool = False
    extended_keys = {}

    coins_failed_to_initialise = []

    try:
        swap_client = BasicSwap(data_dir, settings, chain, transient_instance=True)
        if not swap_client.use_tor_proxy:
            # Cannot set -bind or -whitebind together with -listen=0
            daemon_args.append("-nolisten")

        # The seed coin must always be started, even in addcoin mode, and must be
        # loaded first as subsequent coins are initialised from its mnemonic.
        seed_coin: str = next(
            name
            for name, module in coin_prepare_modules.items()
            if module.provides_master_key
        )
        start_daemons = [seed_coin] + [c for c in with_coins if c != seed_coin]
        for coin_name in start_daemons:
            module = coin_prepare_modules[coin_name]
            coin_settings = settings["chainclients"][coin_name]
            c = swap_client.getCoinIdFromName(coin_name)

            if not module.startsInitDaemon():
                pass
            elif module.usesWalletRpcDaemonForInit():
                if coin_settings["manage_wallet_daemon"]:
                    filename: str = getWalletBinName(
                        c, coin_settings, coin_name + "-wallet-rpc"
                    )
                    daemons.append(
                        startXmrWalletDaemon(
                            coin_settings["datadir"],
                            coin_settings["bindir"],
                            filename,
                        )
                    )
            elif coin_settings["manage_daemon"]:
                filename: str = getCoreBinName(c, coin_settings, coin_name + "d")
                coin_args = module.getWalletInitDaemonArgs(
                    prepare_ctx, swap_client, c, coin_settings
                )
                coin_args += getCoreBinArgs(c, coin_settings, prepare=True)

                extra_config = {"stdout_to_file": True, "coin_name": coin_name}

                if module.provides_master_key and "particl_daemon" in extra_opts:
                    daemons.append(extra_opts["particl_daemon"])
                    del extra_opts["particl_daemon"]
                else:
                    daemons.append(
                        startDaemon(
                            coin_settings["datadir"],
                            coin_settings["bindir"],
                            filename,
                            daemon_args + coin_args,
                            extra_config=extra_config,
                        )
                    )
                swap_client.setDaemonPID(c, daemons[-1].handle.pid)
            swap_client.setCoinRunParams(c)
            swap_client.createCoinInterface(c)

            if module.creates_wallet:
                if module.provides_master_key and coin_name not in with_coins:
                    # Running addcoin with an existing seed coin wallet
                    swap_client.waitForDaemonRPC(c, with_wallet=True)
                    # The seed coin wallet must be unlocked to call getWalletKey
                    if WALLET_ENCRYPTION_PWD != "":
                        swap_client.ci(c).unlockWallet(WALLET_ENCRYPTION_PWD)
                    continue
                module.ensureWallet(prepare_ctx, swap_client, c, coin_settings)

            if module.provides_master_key and coin_name in with_coins:
                particl_wallet_mnemonic, generated_mnemonic = (
                    module.loadMasterMnemonic(
                        prepare_ctx, swap_client, c, particl_wallet_mnemonic
                    )
                )

        for coin_name in with_coins:
            module = coin_prepare_modules[coin_name]
            coin_settings = settings["chainclients"][coin_name]
            c = swap_client.getCoinIdFromName(coin_name)
            if module.provides_master_key:
                continue
            if coin_settings.get("connection_type") == "electrum":
                logger.info(
                    f"Skipping daemon RPC wait for {getCoinName(c)} (electrum mode)."
                )
            elif module.startsInitDaemon():
                # initialiseWallet only sets main_wallet_seedid_
                swap_client.waitForDaemonRPC(c)
            try:
                default_restore_time = (
                    -1 if generated_mnemonic else DEFAULT_RESTORE_TIME
                )  # Set to -1 (now) if key is newly generated
                restore_time: int = extra_opts.get(
                    "walletrestoretime", default_restore_time
                )

                swap_client.initialiseWallet(
                    c, raise_errors=True, restore_time=restore_time
                )
                if c not in swap_client.xmr_based_coins:
                    if restore_time == -1:
                        restore_time = int(time.time())
                        coin_settings["restore_time"] = restore_time
            except Exception as e:
                coins_failed_to_initialise.append((coin_name, c, e))
            if WALLET_ENCRYPTION_PWD != "" and module.needsPostInitPasswordChange():
                try:
                    swap_client.ci(c).changeWalletPassword(
                        "", WALLET_ENCRYPTION_PWD, check_seed_if_encrypt=False
                    )
                except Exception as e:  # noqa: F841
                    logger.warning(f"changeWalletPassword failed for {coin_name}.")

        zprv_prefix = 0x04B2430C if chain == "mainnet" else 0x045F18BC
        for coin_name in with_coins:
            module = coin_prepare_modules[coin_name]
            c = swap_client.getCoinIdFromName(coin_name)
            if module.provides_master_key:
                continue
            try:
                ci = swap_client.ci(c)
                coin_settings = settings["chainclients"].get(coin_name, {})
                is_electrum = coin_settings.get("connection_type") == "electrum"
                can_export = (
                    hasattr(ci, "canExportToElectrum") and ci.canExportToElectrum()
                )
                if can_export or (is_electrum and hasattr(ci, "getAccountKey")):
                    seed_key = swap_client.getWalletKey(c, 1)
                    account_key = ci.getAccountKey(seed_key, zprv_prefix)
                    extended_keys[getCoinName(c)] = account_key
            except Exception as e:
                logger.debug(f"Could not generate extended key for {coin_name}: {e}")

    finally:
        if swap_client:
            swap_client.finalise()
            del swap_client
        for d in daemons:
            finalise_daemon(d)

    print("")
    for coin_name, c, e in coins_failed_to_initialise:
        if coin_prepare_modules[coin_name].reseed_note:
            print(
                f"NOTE - Unable to initialise wallet for {getCoinName(c)}.  To complete setup click 'Reseed Wallet' from the ui page once chain is synced."
            )
        else:
            raise ValueError(f"Failed to initialise wallet for {getCoinName(c)}: {e}")

    for coin_name in with_coins:
        warning = coin_prepare_modules[coin_name].getPostInitWarning(prepare_ctx)
        if warning is not None:
            print(warning)

    if particl_wallet_mnemonic is not None:
        if generated_mnemonic:
            # Print directly to stdout for tests
            print(
                "IMPORTANT - Save your particl wallet recovery phrase:\n{}\n".format(
                    particl_wallet_mnemonic
                )
            )

            if extended_keys:
                print("Extended private keys (for external wallet import):")
                for coin_name, key in extended_keys.items():
                    print(f"  {coin_name}: {key}")
                print("")
                print(
                    "NOTE: These keys can be imported into Electrum using 'Use a master key'."
                )
                print("WARNING: Write these down NOW. They will not be shown again.\n")

    return extended_keys


def load_config(config_path):
    if not os.path.exists(config_path):
        exitWithError("{} does not exist".format(config_path))
    with open(config_path) as fs:
        settings = json.load(fs)

    BSX_ALLOW_ENV_OVERRIDE = toBool(os.getenv("BSX_ALLOW_ENV_OVERRIDE", "false"))

    saved_env_var_settings = [
        ("setup_docker_mode", "BSX_DOCKER_MODE"),
        ("setup_local_tor", "BSX_LOCAL_TOR"),
        ("setup_tor_control_listen_interface", "TOR_CONTROL_LISTEN_INTERFACE"),
        ("setup_torrc_proxy_host", "TORRC_PROXY_HOST"),
        ("setup_torrc_control_host", "TORRC_CONTROL_HOST"),
        ("setup_torrc_dns_host", "TORRC_DNS_HOST"),
        ("tor_proxy_host", "TOR_PROXY_HOST"),
        ("tor_proxy_port", "TOR_PROXY_PORT"),
        ("tor_control_port", "TOR_CONTROL_PORT"),
    ]
    for setting in saved_env_var_settings:
        config_name, env_name = setting
        env_value = globals()[env_name]
        saved_config_value = settings.get(config_name, env_value)
        if saved_config_value != env_value:
            if os.getenv(env_name):
                # If the env var was manually set override the saved config if allowed else fail.
                if BSX_ALLOW_ENV_OVERRIDE:
                    logger.warning(
                        f"Env var {env_name} differs from saved config '{config_name}', overriding."
                    )
                else:
                    print(
                        f"Env var {env_name} differs from saved config '{config_name}', set 'BSX_ALLOW_ENV_OVERRIDE' to override.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            else:
                logger.info(f"Setting {env_name} from saved config '{config_name}'.")
                globals()[env_name] = saved_config_value
                # Recalculate env vars that depend on the changed var
                if env_name == "BSX_LOCAL_TOR":
                    setTorrcVars()
    return settings


def save_config(config_path, settings, add_options: bool = True) -> None:
    if add_options is True:
        # Add to config file only if manually set
        if os.getenv("BSX_DOCKER_MODE"):
            settings["setup_docker_mode"] = BSX_DOCKER_MODE
        if os.getenv("BSX_LOCAL_TOR"):
            settings["setup_local_tor"] = BSX_LOCAL_TOR
        if os.getenv("TOR_CONTROL_LISTEN_INTERFACE"):
            settings["setup_tor_control_listen_interface"] = (
                TOR_CONTROL_LISTEN_INTERFACE
            )
        if os.getenv("TORRC_PROXY_HOST"):
            settings["setup_torrc_proxy_host"] = TORRC_PROXY_HOST
        if os.getenv("TORRC_CONTROL_HOST"):
            settings["setup_torrc_control_host"] = TORRC_CONTROL_HOST
        if os.getenv("TORRC_DNS_HOST"):
            settings["setup_torrc_dns_host"] = TORRC_DNS_HOST

    with open(config_path, "w") as fp:
        json.dump(settings, fp, indent=4)


def signal_handler(sig, frame):
    os.write(sys.stdout.fileno(), f"Signal {sig} detected.\n".encode("utf-8"))


def ensure_coin_valid(coin_name: str, test_disabled: bool = True) -> None:
    if coin_name not in known_coins:
        exitWithError(f"Unknown coin {coin_name.capitalize()}")
    if test_disabled and not OVERRIDE_DISABLED_COINS and coin_name in disabled_coins:
        exitWithError(f"{coin_name.capitalize()} is disabled")


def ensure_network_valid(network_name: str, test_disabled: bool = True) -> None:
    if network_name not in known_networks:
        exitWithError(f"Unknown network {network_name.capitalize()}")
    if test_disabled and network_name in disabled_networks:
        exitWithError(f"{network_name.capitalize()} is disabled")


def main():
    global use_tor_proxy, with_coins_changed
    setTorrcVars()
    data_dir = None
    bin_dir = None
    port_offset = None
    chain = "mainnet"
    particl_wallet_mnemonic = None
    with_coins = {
        "particl",
    }
    add_coin = ""
    disable_coin = ""
    htmlhost = "127.0.0.1"
    xmr_restore_height = DEFAULT_XMR_RESTORE_HEIGHT
    wow_restore_height = DEFAULT_WOW_RESTORE_HEIGHT
    print_versions = False
    prepare_bin_only = False
    upgrade_cores = False
    no_cores = False
    enable_tor = False
    disable_tor = False
    initwalletsonly = False
    tor_control_password = None
    client_auth_pwd_value = None
    disable_client_auth_flag = False
    light_mode = False
    coin_modes = {}
    electrum_servers = {}
    extra_opts = {}

    if os.getenv("SSL_CERT_DIR", "") == "" and GUIX_SSL_CERT_DIR is not None:
        os.environ["SSL_CERT_DIR"] = GUIX_SSL_CERT_DIR

    if os.name == "nt":
        # On windows sending signal.CTRL_C_EVENT to a subprocess causes it to be sent to the parent process too
        signal.signal(signal.SIGINT, signal_handler)

    for v in sys.argv[1:]:
        if len(v) < 2 or v[0] != "-":
            exitWithError("Unknown argument {}".format(v))

        s = v.split("=")
        name = s[0].strip()

        for i in range(2):
            if name[0] == "-":
                name = name[1:]

        if name == "h" or name == "help":
            printHelp()
            return 0

        if name == "v" or name == "version":
            print_versions = True
            continue
        if name in ("mainnet", "testnet", "regtest"):
            chain = name
            continue
        if name == "preparebinonly":
            prepare_bin_only = True
            continue
        if name == "upgradecores":
            upgrade_cores = True
            continue
        if name == "nocores":
            no_cores = True
            continue
        if name == "usecontainers":
            extra_opts["use_containers"] = True
            continue
        if name == "noextractover":
            extra_opts["extract_core_overwrite"] = False
            continue
        if name == "usetorproxy":
            use_tor_proxy = True
            continue
        if name == "notorproxy":
            extra_opts["no_tor_proxy"] = True
            continue
        if name == "enabletor":
            enable_tor = True
            continue
        if name == "disabletor":
            disable_tor = True
            continue
        if name == "usebtcfastsync":
            extra_opts["use_btc_fastsync"] = True
            continue
        if name == "skipbtcfastsyncchecks":
            extra_opts["check_btc_fastsync"] = False
            continue
        if name == "trustremotenode":
            extra_opts["trust_remote_node"] = True
            continue
        if name == "noreleasesizecheck":
            extra_opts["verify_release_file_size"] = False
            continue
        if name == "redownloadreleases":
            extra_opts["redownload_releases"] = True
            continue
        if name == "initwalletsonly":
            initwalletsonly = True
            continue
        if name == "dashv20compatible":
            extra_opts["dash_v20_compatible"] = True
            continue
        if len(s) == 2:
            if name == "datadir":
                data_dir = os.path.abspath(os.path.expanduser(s[1].strip('"')))
                continue
            if name == "bindir":
                bin_dir = os.path.abspath(os.path.expanduser(s[1].strip('"')))
                continue
            if name == "portoffset":
                port_offset = int(s[1])
                continue
            if name == "particl_mnemonic":
                particl_wallet_mnemonic = s[1].strip('"')
                continue
            if name in ("withcoin", "withcoins"):
                for coin in [s.strip().lower() for s in s[1].split(",")]:
                    ensure_coin_valid(coin)
                    with_coins.add(coin)
                with_coins_changed = True
                continue
            if name in ("withoutcoin", "withoutcoins"):
                for coin in [s.strip().lower() for s in s[1].split(",")]:
                    ensure_coin_valid(coin, test_disabled=False)
                    with_coins.discard(coin)
                with_coins_changed = True
                continue
            if name == "addcoin":
                add_coin = s[1].strip().lower()
                ensure_coin_valid(add_coin)
                with_coins = {
                    add_coin,
                }
                continue
            if name == "disablecoin":
                disable_coin = s[1].strip().lower()
                ensure_coin_valid(disable_coin, test_disabled=False)
                continue
            if name == "addnetwork":
                network_name = s[1].strip().lower()
                ensure_network_valid(network_name)
                extra_opts["addnetwork"] = network_name
                continue
            if name == "disablenetwork":
                network_name = s[1].strip().lower()
                ensure_network_valid(network_name, test_disabled=False)
                extra_opts["disablenetwork"] = network_name
                continue
            if name == "htmlhost":
                htmlhost = s[1].strip('"')
                continue
            if name == "wshost":
                extra_opts["wshost"] = s[1].strip('"')
                continue
            if name == "xmrrestoreheight":
                xmr_restore_height = int(s[1])
                continue
            if name == "wowrestoreheight":
                wow_restore_height = int(s[1])
                continue
            if name == "walletrestoretime":
                extra_opts["walletrestoretime"] = int(s[1])
                continue
            if name == "keysdirpath":
                extra_opts["keysdirpath"] = os.path.abspath(
                    os.path.expanduser(s[1].strip('"'))
                )
                continue
            if name == "trustremotenode":
                extra_opts["trust_remote_node"] = toBool(s[1])
                continue
            if name == "client-auth-password":
                client_auth_pwd_value = s[1].strip('"')
                continue

        if name == "disable-client-auth":
            disable_client_auth_flag = True
            continue
        if name == "light":
            light_mode = True
            continue
        if name.endswith("-mode") and len(s) == 2:
            coin_prefix = name[:-5]
            mode_value = s[1].strip().lower()
            if mode_value not in ("rpc", "electrum", "remote"):
                exitWithError(
                    f"Invalid mode '{mode_value}' for {coin_prefix}. Use: rpc, electrum, or remote"
                )
            coin_modes[coin_prefix] = mode_value
            continue
        if name.endswith("-electrum-server") and len(s) == 2:
            coin_prefix = name[:-16]
            server_str = s[1].strip()
            parts = server_str.split(":")
            if len(parts) >= 2:
                if len(parts) >= 3:
                    server = f"{parts[0]}:{parts[1]}:{parts[2]}"
                else:
                    server = f"{parts[0]}:{parts[1]}"
                if coin_prefix not in electrum_servers:
                    electrum_servers[coin_prefix] = []
                electrum_servers[coin_prefix].append(server)
            continue
        if len(s) != 2:
            exitWithError("Unknown argument {}".format(v))
        exitWithError("Unknown argument {}".format(v))

    if print_versions:
        printVersion(with_coins)
        return 0

    if data_dir is None:
        data_dir = os.path.join(os.path.expanduser(cfg.BASICSWAP_DATADIR))
    if bin_dir is None:
        bin_dir = os.path.join(data_dir, "bin")

    logger.info(f"BasicSwap prepare script {__version__}\n")
    logger.info(f"Python version: {platform.python_version()}")
    logger.info(f"Data dir: {data_dir}")
    logger.info(f"Bin dir: {bin_dir}")
    logger.info(f"Chain: {chain}")
    logger.info(
        "WALLET_ENCRYPTION_PWD is {}set".format(
            "not " if WALLET_ENCRYPTION_PWD == "" else ""
        )
    )

    if port_offset is None:
        port_offset = 300 if chain == "testnet" else 0

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    config_path = os.path.join(data_dir, cfg.CONFIG_FILENAME)

    config_exists = os.path.exists(config_path)
    if config_exists and (
        client_auth_pwd_value is not None or disable_client_auth_flag
    ):
        try:
            settings = load_config(config_path)
            modified = False
            if client_auth_pwd_value is not None:
                settings["client_auth_hash"] = rfc2440_hash_password(
                    client_auth_pwd_value
                )
                logger.info("Client authentication password updated.")
                modified = True
            elif disable_client_auth_flag:
                if "client_auth_hash" in settings:
                    del settings["client_auth_hash"]
                    logger.info("Client authentication disabled.")
                    modified = True
                else:
                    logger.info("Client authentication is already disabled.")

            if modified:
                with open(config_path, "w") as fp:
                    json.dump(settings, fp, indent=4)
            return 0
        except Exception as e:
            exitWithError(f"Failed to update client auth settings: {e}")

    if use_tor_proxy and extra_opts.get("no_tor_proxy", False):
        exitWithError("Can't use --usetorproxy and --notorproxy together")

    # Automatically enable usetorproxy for certain commands if it's set in basicswap config
    if (
        not (initwalletsonly or enable_tor or disable_tor or disable_coin)
        and not use_tor_proxy
        and os.path.exists(config_path)
    ):
        settings = load_config(config_path)
        settings_use_tor = settings.get("use_tor", False)
        if settings_use_tor:
            logger.info("use_tor is set in the config")
            if extra_opts.get("no_tor_proxy", False):
                use_tor_proxy = False
                logger.warning(
                    "Not automatically setting --usetorproxy as --notorproxy is set"
                )
            else:
                use_tor_proxy = True
                logger.info("Automatically setting --usetorproxy")

    setConnectionParameters(allow_set_tor=False)

    if use_tor_proxy and TEST_TOR_PROXY:
        testTorConnection()

    if use_tor_proxy and TEST_ONION_LINK:
        testOnionLink()

    should_download_btc_fastsync = False
    if extra_opts.get("use_btc_fastsync", False) is True:
        if "bitcoin" in with_coins or add_coin == "bitcoin":
            should_download_btc_fastsync = True
        else:
            logger.warning("Ignoring usebtcfastsync option without Bitcoin selected.")

    prepare_ctx = PrepareContext(
        data_dir=data_dir,
        bin_dir=bin_dir,
        port_offset=port_offset,
        should_manage_daemon=shouldManageDaemon,
        bin_arch=BIN_ARCH,
        file_ext=FILE_EXT,
        download_release=downloadRelease,
        download_file=downloadFile,
        import_pubkey=importPubkey,
        logger=logger,
        rpcbind_ip=COINS_RPCBIND_IP,
        docker_mode=BSX_DOCKER_MODE,
        write_tor_settings=writeTorSettings,
        gnupg=gnupg,
        wallet_encryption_pwd=WALLET_ENCRYPTION_PWD,
        monerod_proxy_config=monerod_proxy_config,
        monero_wallet_rpc_proxy_config=monero_wallet_rpc_proxy_config,
    )
    extra_opts["prepare_ctx"] = prepare_ctx

    if should_download_btc_fastsync:
        try:
            btc_prepare.prepareFastsync(prepare_ctx, extra_opts)
        except Exception as e:
            logger.error(
                f"Failed to download BTC fastsync file: {e}\nRe-running the command should resume the download or try manually downloading"
            )
            return 1

    withchainclients = {}
    chainclients = {
        "particl": part_prepare.getConfigSegment(prepare_ctx),
        "bitcoin": btc_prepare.getConfigSegment(prepare_ctx),
        "litecoin": ltc_prepare.getConfigSegment(prepare_ctx),
        "decred": dcr_prepare.getConfigSegment(prepare_ctx),
        "namecoin": nmc_prepare.getConfigSegment(prepare_ctx),
        "monero": xmr_prepare.getConfigSegment(prepare_ctx),
        "wownero": wow_prepare.getConfigSegment(prepare_ctx),
        "pivx": pivx_prepare.getConfigSegment(prepare_ctx),
        "dash": dash_prepare.getConfigSegment(prepare_ctx),
        "firo": firo_prepare.getConfigSegment(prepare_ctx),
        "navcoin": nav_prepare.getConfigSegment(prepare_ctx),
        "bitcoincash": bch_prepare.getConfigSegment(prepare_ctx),
        "dogecoin": doge_prepare.getConfigSegment(prepare_ctx),
    }

    electrum_supported_coins = {
        "bitcoin": "btc",
        "litecoin": "ltc",
    }

    for coin_name, coin_prefix in electrum_supported_coins.items():
        if coin_name not in chainclients:
            continue

        use_electrum = False
        if light_mode and coin_name != "particl":
            use_electrum = True
        if coin_prefix in coin_modes:
            if coin_modes[coin_prefix] == "electrum":
                use_electrum = True
            elif coin_modes[coin_prefix] == "rpc":
                use_electrum = False

        if use_electrum:
            chainclients[coin_name]["connection_type"] = "electrum"
            chainclients[coin_name]["manage_daemon"] = False
            if coin_prefix in electrum_servers:
                chainclients[coin_name]["electrum_clearnet_servers"] = electrum_servers[
                    coin_prefix
                ]

    for coin_name, coin_settings in chainclients.items():
        coin_id = getCoinIdFromName(coin_name)
        coin_params = chainparams[coin_id]
        if coin_settings.get("core_type_group", "") == "xmr":
            default_name: str = "swap_wallet"
            use_name: str = default_name
        else:
            default_name: str = "wallet.dat"
            use_name: str = (
                "wallet.dat"
                if coin_id in (Coins.NAV, Coins.FIRO, Coins.DCR)
                else "bsx_wallet"
            )

        if coin_name == "litecoin":
            set_name: str = getWalletName(
                coin_params, "mweb", prefix_override="LTC_MWEB"
            )
            if set_name != "mweb":
                coin_settings["mweb_wallet_name"] = set_name

        set_name: str = getWalletName(coin_params, use_name)
        if set_name != default_name:
            coin_settings["wallet_name"] = set_name

        ticker: str = coin_params["ticker"]
        if getDescriptorWalletOption(coin_params):
            if coin_id not in (Coins.BTC, Coins.NMC):
                raise ValueError(f"Descriptor wallet unavailable for {coin_name}")

            coin_settings["use_descriptors"] = True
            coin_settings["watch_wallet_name"] = getWalletName(
                coin_params, "bsx_watch", prefix_override=f"{ticker}_WATCH"
            )
            if getLegacyKeyPathOption(coin_params) is True:
                coin_settings["use_legacy_key_paths"] = True

    chainclients["monero"]["restore_height"] = xmr_restore_height
    chainclients["monero"]["trusted_daemon"] = extra_opts.get("trust_remote_node", True)
    chainclients["wownero"]["restore_height"] = wow_restore_height
    chainclients["wownero"]["trusted_daemon"] = extra_opts.get(
        "trust_remote_node", True
    )

    if extra_opts.get("dash_v20_compatible", False):
        chainclients["dash"]["wallet_v20_compatible"] = True

    if initwalletsonly:
        logger.info("Initialising wallets")
        settings = load_config(config_path)

        init_coins = settings["chainclients"].keys()
        logger.info("Active coins: {}".format(", ".join(init_coins)))
        if with_coins_changed:
            init_coins = with_coins
            logger.info("Initialising coins: {}".format(", ".join(init_coins)))
        initialise_wallets(
            particl_wallet_mnemonic,
            init_coins,
            data_dir,
            settings,
            chain,
            use_tor_proxy,
            extra_opts=extra_opts,
        )

        print("Done.")
        return 0

    if enable_tor:
        logger.info("Enabling TOR")
        settings = load_config(config_path)

        tor_control_password = settings.get("tor_control_password", None)
        if tor_control_password is None:
            tor_control_password = generate_salt(24)
            settings["tor_control_password"] = tor_control_password
        write_torrc(data_dir, tor_control_password)

        addTorSettings(settings, tor_control_password)
        for coin in settings["chainclients"]:
            modify_tor_config(
                settings, coin, tor_control_password, enable=True, extra_opts=extra_opts
            )

        save_config(config_path, settings)
        logger.info("Done.")
        return 0

    if disable_tor:
        logger.info("Disabling TOR")
        settings = load_config(config_path)
        if not settings.get("use_tor", False):
            logger.info("TOR is not enabled.")  # Continue anyway to clear any config
        settings["use_tor"] = False
        for coin in settings["chainclients"]:
            modify_tor_config(
                settings,
                coin,
                tor_control_password=None,
                enable=False,
                extra_opts=extra_opts,
            )

        save_config(config_path, settings)
        logger.info("Done.")
        return 0

    if disable_coin != "":
        if "particl" in disable_coin:
            exitWithError("Cannot disable Particl (required for operation)")

        logger.info(f"Disabling coin: {disable_coin}")
        settings = load_config(config_path)

        if disable_coin not in settings["chainclients"]:
            exitWithError(f"{disable_coin} not configured")

        coin_settings = settings["chainclients"][disable_coin]
        if (
            coin_settings["connection_type"] == "none"
            and coin_settings["manage_daemon"] is False
        ):
            exitWithError(f"{disable_coin} is already disabled")
        coin_settings["connection_type"] = "none"
        coin_settings["manage_daemon"] = False
        if "manage_wallet_daemon" in coin_settings:
            coin_settings["manage_wallet_daemon"] = False

        save_config(config_path, settings)
        logger.info("Done.")
        return 0

    extra_opts["data_dir"] = data_dir
    extra_opts["tor_control_password"] = tor_control_password

    if add_coin != "":
        logger.info(f"Adding coin: {add_coin}")
        settings = load_config(config_path)

        if add_coin in settings["chainclients"]:
            coin_settings = settings["chainclients"][add_coin]
            if (
                coin_settings["connection_type"] == "none"
                and coin_settings["manage_daemon"] is False
            ):
                logger.info(f"Enabling coin: {add_coin}")
                coin_settings["connection_type"] = "rpc"
                coin_settings["manage_daemon"] = True
                if "manage_wallet_daemon" in coin_settings:
                    coin_settings["manage_wallet_daemon"] = True
                save_config(config_path, settings)
                logger.info("Done.")
                return 0
            exitWithError(f"{add_coin} is already in the settings file")

        if tor_control_password is None and settings.get("use_tor", False):
            extra_opts["tor_control_password"] = settings.get(
                "tor_control_password", None
            )

        try:
            if particl_wallet_mnemonic != "none":
                # Ensure Particl wallet is unencrypted or correct password is supplied
                # Keep daemon running to use in initialise_wallets
                test_particl_encryption(
                    data_dir, settings, chain, use_tor_proxy, extra_opts
                )

            settings["chainclients"][add_coin] = chainclients[add_coin]

            if not no_cores:
                prepareCore(
                    add_coin, known_coins[add_coin], settings, data_dir, extra_opts
                )

            if not (prepare_bin_only or upgrade_cores):
                prepareDataDir(
                    add_coin, settings, chain, particl_wallet_mnemonic, extra_opts
                )

                if particl_wallet_mnemonic != "none":
                    extended_keys = initialise_wallets(
                        None,
                        {
                            add_coin,
                        },
                        data_dir,
                        settings,
                        chain,
                        use_tor_proxy,
                        extra_opts=extra_opts,
                    )

                    if extended_keys:
                        print("\nExtended private key (for external wallet import):")
                        for coin_name, key in extended_keys.items():
                            print(f"  {coin_name}: {key}")
                        print("")
                        print(
                            "NOTE: This key can be imported into Electrum using 'Use a master key'."
                        )
                        print(
                            "WARNING: Write this down NOW. It will not be shown again.\n"
                        )

                save_config(config_path, settings)
        finally:
            if "particl_daemon" in extra_opts:
                finalise_daemon(extra_opts["particl_daemon"])
                del extra_opts["particl_daemon"]

        logger.info(f"Done. Coin {add_coin} successfully added.")
        return 0

    if "addnetwork" in extra_opts:
        network_name = extra_opts["addnetwork"]
        logger.info(f"Adding network: {network_name}")
        settings = load_config(config_path)
        network_config_list = settings.get("networks", [])
        if len(network_config_list) < 1:
            network_config_list = [{"type": "smsg", "enabled": True}]

        network_enabled: bool = False
        if network_name == "simplex":
            if SIMPLEX_GROUP_LINK is None:
                raise ValueError("SIMPLEX_GROUP_LINK must be set.")

            simplex_chat_bin_dir = os.path.join(bin_dir, "simplex")
            simplex_chat_client_path = os.path.join(
                simplex_chat_bin_dir, "simplex-chat"
            )
            simplex_chat_release_dir = os.path.join(
                simplex_chat_bin_dir, SIMPLEX_CHAT_VERSION
            )
            if not os.path.exists(simplex_chat_release_dir):
                os.makedirs(simplex_chat_release_dir)

            if USE_PLATFORM == "Linux":
                simplex_chat_release_file = "simplex-chat-ubuntu-24_04-x86-64"
            elif USE_PLATFORM == "Darwin":
                simplex_chat_release_file = "simplex-chat-macos-x86-64"
            elif USE_PLATFORM == "Windows":
                simplex_chat_release_file = "simplex-chat-windows-x86-64"
            else:
                raise ValueError(f"Unknown platform {USE_PLATFORM}")

            simplex_chat_release_url = f"https://github.com/simplex-chat/simplex-chat/releases/download/v{SIMPLEX_CHAT_VERSION}/{simplex_chat_release_file}"
            simplex_chat_release_path = os.path.join(
                simplex_chat_release_dir, simplex_chat_release_file
            )
            downloadRelease(
                simplex_chat_release_url, simplex_chat_release_path, extra_opts
            )

            assert_filename = "_sha256sums"
            assert_path = os.path.join(simplex_chat_release_dir, assert_filename)
            assert_url = f"https://github.com/simplex-chat/simplex-chat/releases/download/v{SIMPLEX_CHAT_VERSION}/_sha256sums"
            if not os.path.exists(assert_path):
                downloadFile(assert_url, assert_path)

            release_hash: str = getFileHash(simplex_chat_release_path)
            logger.info(f"{simplex_chat_release_file} hash: {release_hash}")
            ensureFileHashInFile(release_hash, assert_path, logger)

            assert_sig_filename = assert_filename + ".asc"
            assert_sig_url = assert_url + ".asc"
            assert_sig_path = os.path.join(bin_dir, assert_sig_filename)
            if not os.path.exists(assert_sig_path):
                downloadFile(assert_sig_url, assert_sig_path)

            gpg = gnupg.GPG()
            pubkey_filename = "SimpleX_Chat.pgp"
            pubkeyurls = []
            if not havePubkey(gpg, expected_key_ids["SimpleX_Chat"][0]):
                importPubkey(gpg, pubkey_filename, pubkeyurls)
            with open(assert_sig_path, "rb") as fp:
                verified = gpg.verify_file(fp, assert_path)
            ensureValidSignatureBy(verified, "SimpleX_Chat")

            shutil.copyfile(simplex_chat_release_path, simplex_chat_client_path)

            simplex_settings = {
                "type": "simplex",
                "server_address": SIMPLEX_SERVER_ADDRESS,
                "client_path": simplex_chat_client_path,
                "ws_port": SIMPLEX_WS_PORT,
                "group_link": SIMPLEX_GROUP_LINK,
                "enabled": True,
            }
            if SIMPLEX_SERVER_SOCKS_PROXY is not None:
                simplex_settings["socks_proxy_override"] = SIMPLEX_SERVER_SOCKS_PROXY

            found_network: bool = False
            for network in network_config_list:
                network_type: str = network.get("type", "unknown")
                if network_type == "simplex":
                    found_network = True
                    if network.get("enabled", False) is True:
                        logger.warning(f"Network {network_type} is already active.")
                    network = simplex_settings
                else:
                    # TODO: Allow multiple active networks
                    network["enabled"] = False
                    logger.info(f"Disabling network {network_type}.")
            if found_network is False:
                network_config_list.append(simplex_settings)
        elif network_name == "smsg":
            found_network: bool = False
            for network in network_config_list:
                network_type: str = network.get("type", "unknown")
                if network_type == "smsg":
                    found_network = True
                    if network.get("enabled", False) is True:
                        logger.warning(f"Network {network_type} is already active.")
                    else:
                        network["enabled"] = True
                else:
                    # TODO: Allow multiple active networks
                    network["enabled"] = False
                    logger.info(f"Disabling network {network_type}.")
            if found_network is False:
                network_config_list.append({"type": "smsg", "enabled": True})
        else:
            raise ValueError(f"Unknown network {network_name}")

        settings["networks"] = network_config_list
        save_config(config_path, settings)
        if network_enabled:
            logger.info(f"Done. Network {network_name} successfully added.")
        else:
            logger.info("Done.")
        return 0

    if "disablenetwork" in extra_opts:
        network_name = extra_opts["disablenetwork"]
        logger.info(f"Disable network: {network_name}")
        settings = load_config(config_path)
        network_config_list = settings.get("networks", [])
        if len(network_config_list) < 1:
            network_config_list = [{"type": "smsg", "enabled": True}]

        logger.info(f"Done. Network {network_name} successfully disabled.")
        return 0

    logger.info(
        "With coins: "
        + (", ".join(with_coins))
        + ("" if with_coins_changed else " (default)")
    )
    if os.path.exists(config_path):
        if prepare_bin_only:
            settings = load_config(config_path)

            # Add temporary default config for any coins that have not been added
            for c in with_coins:
                if c not in settings["chainclients"]:
                    settings["chainclients"][c] = chainclients[c]
        elif upgrade_cores:
            settings = load_config(config_path)

            with_coins_start = with_coins
            if not with_coins_changed:
                for coin_name, coin_settings in settings["chainclients"].items():
                    with_coins_start.add(coin_name)

            with_coins = set()
            for coin_name in with_coins_start:
                if coin_name not in chainclients:
                    logger.warning(f"Skipping unknown coin: {coin_name}.")
                    continue
                current_coin_settings = chainclients[coin_name]
                if coin_name not in settings["chainclients"]:
                    exitWithError(f"{coin_name} not found in basicswap.json")
                coin_settings = settings["chainclients"][coin_name]

                current_version = current_coin_settings["core_version_no"]
                have_version = coin_settings.get("core_version_no", "")

                current_version_group = current_coin_settings.get(
                    "core_version_group", ""
                )
                have_version_group = coin_settings.get("core_version_group", "")

                logger.info(
                    f"{coin_name}: have {have_version}, current {current_version}."
                )
                if not BSX_UPDATE_UNMANAGED and not (
                    coin_settings.get("manage_daemon", False)
                    or coin_settings.get("manage_wallet_daemon", False)
                ):
                    logger.info("  Unmanaged.")
                elif have_version != current_version:
                    logger.info(f"  Trying to update {coin_name}.")
                    with_coins.add(coin_name)
                elif have_version_group != current_version_group:
                    logger.info(
                        f"  Trying to update {coin_name}, version group differs."
                    )
                    with_coins.add(coin_name)

            if len(with_coins) < 1:
                logger.info("Nothing to do.")
                return 0

            # Run second loop to update, so all versions are logged together.
            # Backup settings
            old_config_path = config_path[:-5] + "_" + str(int(time.time())) + ".json"
            save_config(old_config_path, settings, add_options=False)

            for c in with_coins:
                prepareCore(c, known_coins[c], settings, data_dir, extra_opts)
                current_coin_settings = chainclients[c]
                current_version = current_coin_settings["core_version_no"]
                current_version_group = current_coin_settings.get(
                    "core_version_group", ""
                )
                settings["chainclients"][c]["core_version_no"] = current_version
                if current_version_group != "":
                    settings["chainclients"][c][
                        "core_version_group"
                    ] = current_version_group
                save_config(config_path, settings)

            logger.info("Done.")
            return 0
        else:
            exitWithError(f"{config_path} exists")
    else:
        if upgrade_cores:
            exitWithError(f"{config_path} not found")

        for c in with_coins:
            withchainclients[c] = chainclients[c]

        zmq_server_pubkey, zmq_server_key = zmq.curve_keypair()
        zmq_client_pubkey, zmq_client_key = zmq.curve_keypair()
        extra_opts["zmqsecret"] = base64.b64encode(zmq_server_key).decode("utf-8")

        settings = {
            "debug": True,
            "zmqhost": f"tcp://{PART_RPC_HOST}",
            "zmqport": PART_ZMQ_PORT + port_offset,
            "htmlhost": htmlhost,
            "htmlport": UI_HTML_PORT + port_offset,
            "network_key": "7sW2UEcHXvuqEjkpE5mD584zRaQYs6WXYohue4jLFZPTvMSxwvgs",
            "network_pubkey": "035758c4a22d7dd59165db02a56156e790224361eb3191f02197addcb3bde903d2",
            "chainclients": withchainclients,
            "min_delay_event": 5,  # Min delay in seconds before reacting to an event
            "max_delay_event": 50,  # Max delay in seconds before reacting to an event
            "check_progress_seconds": 60,
            "check_watched_seconds": 60,
            "check_expired_seconds": 60,
            "wallet_update_timeout": 10,  # Seconds to wait for wallet page update
            "zmq_client_key": base64.b64encode(zmq_client_key).decode("utf-8"),
            "zmq_client_pubkey": base64.b64encode(zmq_client_pubkey).decode("utf-8"),
            "zmq_server_pubkey": base64.b64encode(zmq_server_pubkey).decode("utf-8"),
            "enabled_log_categories": [
                "net",
            ],
        }

        wshost: str = extra_opts.get("wshost", htmlhost)
        if wshost != "none":
            settings["wshost"] = wshost
            settings["wsport"] = UI_WS_PORT + port_offset

        if "CHECK_FOR_BSX_UPDATES" in os.environ:
            settings["check_updates"] = CHECK_FOR_BSX_UPDATES
        elif BSX_TEST_MODE is True:
            settings["check_updates"] = False

    if use_tor_proxy:
        tor_control_password = generate_salt(24)
        addTorSettings(settings, tor_control_password)

    if client_auth_pwd_value is not None:
        settings["client_auth_hash"] = rfc2440_hash_password(client_auth_pwd_value)
        logger.info("Client authentication password set.")

    if not no_cores:
        for c in with_coins:
            prepareCore(c, known_coins[c], settings, data_dir, extra_opts)

    if prepare_bin_only:
        logger.info("Done.")
        return 0

    for c in with_coins:
        prepareDataDir(c, settings, chain, particl_wallet_mnemonic, extra_opts)

    if particl_wallet_mnemonic == "none":
        save_config(config_path, settings)
        logger.info("Done.")
        return 0

    initialise_wallets(
        particl_wallet_mnemonic,
        with_coins,
        data_dir,
        settings,
        chain,
        use_tor_proxy,
        extra_opts=extra_opts,
    )
    save_config(config_path, settings)
    print("Done.")


if __name__ == "__main__":
    main()
