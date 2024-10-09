#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import contextlib
import gnupg
import hashlib
import json
import logging
import mmap
import os
import platform
import random
import shutil
import signal
import socket
import socks
import stat
import sys
import tarfile
import threading
import urllib.parse
import zipfile

from urllib.request import urlopen

import basicswap.config as cfg
from basicswap import __version__
from basicswap.base import getaddrinfo_tor
from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.ui.util import getCoinName
from basicswap.util import toBool
from basicswap.util.network import urlretrieve, make_reporthook
from basicswap.util.rfc2440 import rfc2440_hash_password
from basicswap.bin.run import startDaemon, startXmrWalletDaemon

PARTICL_VERSION = os.getenv('PARTICL_VERSION', '23.2.7.0')
PARTICL_VERSION_TAG = os.getenv('PARTICL_VERSION_TAG', '')
PARTICL_LINUX_EXTRA = os.getenv('PARTICL_LINUX_EXTRA', 'nousb')

LITECOIN_VERSION = os.getenv('LITECOIN_VERSION', '0.21.3')
LITECOIN_VERSION_TAG = os.getenv('LITECOIN_VERSION_TAG', '')

BITCOIN_VERSION = os.getenv('BITCOIN_VERSION', '26.0')
BITCOIN_VERSION_TAG = os.getenv('BITCOIN_VERSION_TAG', '')

MONERO_VERSION = os.getenv('MONERO_VERSION', '0.18.3.4')
MONERO_VERSION_TAG = os.getenv('MONERO_VERSION_TAG', '')
XMR_SITE_COMMIT = '3751c0d7987a9e78324a718c32c008e2ec91b339'  # Lock hashes.txt to monero version

WOWNERO_VERSION = os.getenv('WOWNERO_VERSION', '0.11.1.0')
WOWNERO_VERSION_TAG = os.getenv('WOWNERO_VERSION_TAG', '')
WOW_SITE_COMMIT = '97e100e1605e9f59bc8ca82a5b237d5562c8a21c'  # Lock hashes.txt to wownero version

PIVX_VERSION = os.getenv('PIVX_VERSION', '5.6.1')
PIVX_VERSION_TAG = os.getenv('PIVX_VERSION_TAG', '')

DASH_VERSION = os.getenv('DASH_VERSION', '21.1.0')
DASH_VERSION_TAG = os.getenv('DASH_VERSION_TAG', '')

FIRO_VERSION = os.getenv('FIRO_VERSION', '0.14.14.0')
FIRO_VERSION_TAG = os.getenv('FIRO_VERSION_TAG', '')

NAV_VERSION = os.getenv('NAV_VERSION', '7.0.3')
NAV_VERSION_TAG = os.getenv('NAV_VERSION_TAG', '')

DCR_VERSION = os.getenv('DCR_VERSION', '1.8.1')
DCR_VERSION_TAG = os.getenv('DCR_VERSION_TAG', '')

GUIX_SSL_CERT_DIR = None

ADD_PUBKEY_URL = os.getenv('ADD_PUBKEY_URL', '')
OVERRIDE_DISABLED_COINS = toBool(os.getenv('OVERRIDE_DISABLED_COINS', 'false'))

# If SKIP_GPG_VALIDATION is set to true the script will check hashes but not signatures
SKIP_GPG_VALIDATION = toBool(os.getenv('SKIP_GPG_VALIDATION', 'false'))


known_coins = {
    'particl': (PARTICL_VERSION, PARTICL_VERSION_TAG, ('tecnovert',)),
    'bitcoin': (BITCOIN_VERSION, BITCOIN_VERSION_TAG, ('laanwj',)),
    'litecoin': (LITECOIN_VERSION, LITECOIN_VERSION_TAG, ('davidburkett38',)),
    'decred': (DCR_VERSION, DCR_VERSION_TAG, ('decred_release',)),
    'namecoin': ('0.18.0', '', ('JeremyRand',)),
    'monero': (MONERO_VERSION, MONERO_VERSION_TAG, ('binaryfate',)),
    'wownero': (WOWNERO_VERSION, WOWNERO_VERSION_TAG, ('wowario',)),
    'pivx': (PIVX_VERSION, PIVX_VERSION_TAG, ('fuzzbawls',)),
    'dash': (DASH_VERSION, DASH_VERSION_TAG, ('pasta',)),
    'firo': (FIRO_VERSION, FIRO_VERSION_TAG, ('reuben',)),
    'navcoin': (NAV_VERSION, NAV_VERSION_TAG, ('nav_builder',)),
}

disabled_coins = [
    'navcoin',
    'namecoin',  # Needs update
]

expected_key_ids = {
    'tecnovert': ('13F13651C9CF0D6B',),
    'thrasher': ('FE3348877809386C',),
    'laanwj': ('1E4AED62986CD25D',),
    'JeremyRand': ('2DBE339E29F6294C',),
    'binaryfate': ('F0AF4D462A0BDF92',),
    'wowario': ('793504B449C69220',),
    'davidburkett38': ('3620E9D387E55666',),
    'fuzzbawls': ('C1ABA64407731FD9',),
    'pasta': ('52527BEDABE87984',),
    'reuben': ('1290A1D0FA7EE109',),
    'nav_builder': ('2782262BF6E7FADB',),
    'decred_release': ('6D897EDF518A031D',),
}

USE_PLATFORM = os.getenv('USE_PLATFORM', platform.system())
if USE_PLATFORM == 'Darwin':
    BIN_ARCH = 'osx64'
    FILE_EXT = 'tar.gz'
elif USE_PLATFORM == 'Windows':
    BIN_ARCH = 'win64'
    FILE_EXT = 'zip'
else:
    machine: str = platform.machine()
    if 'arm' in machine:
        BIN_ARCH = 'arm-linux-gnueabihf'
    else:
        BIN_ARCH = machine + '-linux-gnu'
    FILE_EXT = 'tar.gz'

# Allow manually overriding the arch tag
BIN_ARCH = os.getenv('BIN_ARCH', BIN_ARCH)
FILE_EXT = os.getenv('FILE_EXT', FILE_EXT)

logger = logging.getLogger()
logger.level = logging.INFO
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

BSX_DOCKER_MODE = toBool(os.getenv('BSX_DOCKER_MODE', 'false'))
BSX_TEST_MODE = toBool(os.getenv('BSX_TEST_MODE', 'false'))
UI_HTML_PORT = int(os.getenv('UI_HTML_PORT', 12700))
UI_WS_PORT = int(os.getenv('UI_WS_PORT', 11700))
COINS_RPCBIND_IP = os.getenv('COINS_RPCBIND_IP', '127.0.0.1')

PART_ZMQ_PORT = int(os.getenv('PART_ZMQ_PORT', 20792))
PART_RPC_HOST = os.getenv('PART_RPC_HOST', '127.0.0.1')
PART_RPC_PORT = int(os.getenv('PART_RPC_PORT', 19792))
PART_ONION_PORT = int(os.getenv('PART_ONION_PORT', 51734))
PART_RPC_USER = os.getenv('PART_RPC_USER', '')
PART_RPC_PWD = os.getenv('PART_RPC_PWD', '')

XMR_RPC_HOST = os.getenv('XMR_RPC_HOST', '127.0.0.1')
XMR_RPC_PORT = int(os.getenv('XMR_RPC_PORT', 29798))
XMR_ZMQ_PORT = int(os.getenv('XMR_ZMQ_PORT', 30898))
XMR_WALLET_RPC_PORT = int(os.getenv('XMR_WALLET_RPC_PORT', 29998))
XMR_WALLET_RPC_HOST = os.getenv('XMR_WALLET_RPC_HOST', '127.0.0.1')
XMR_WALLET_RPC_USER = os.getenv('XMR_WALLET_RPC_USER', 'xmr_wallet_user')
XMR_WALLET_RPC_PWD = os.getenv('XMR_WALLET_RPC_PWD', 'xmr_wallet_pwd')
XMR_RPC_USER = os.getenv('XMR_RPC_USER', '')
XMR_RPC_PWD = os.getenv('XMR_RPC_PWD', '')
DEFAULT_XMR_RESTORE_HEIGHT = int(os.getenv('DEFAULT_XMR_RESTORE_HEIGHT', 2245107))

WOW_RPC_HOST = os.getenv('WOW_RPC_HOST', '127.0.0.1')
WOW_RPC_PORT = int(os.getenv('WOW_RPC_PORT', 34598))
WOW_ZMQ_PORT = int(os.getenv('WOW_ZMQ_PORT', 34698))
WOW_WALLET_RPC_PORT = int(os.getenv('WOW_WALLET_RPC_PORT', 34798))
WOW_WALLET_RPC_HOST = os.getenv('WOW_WALLET_RPC_HOST', '127.0.0.1')
WOW_WALLET_RPC_USER = os.getenv('WOW_WALLET_RPC_USER', 'wow_wallet_user')
WOW_WALLET_RPC_PWD = os.getenv('WOW_WALLET_RPC_PWD', 'wow_wallet_pwd')
WOW_RPC_USER = os.getenv('WOW_RPC_USER', '')
WOW_RPC_PWD = os.getenv('WOW_RPC_PWD', '')
DEFAULT_WOW_RESTORE_HEIGHT = int(os.getenv('DEFAULT_WOW_RESTORE_HEIGHT', 450000))

LTC_RPC_HOST = os.getenv('LTC_RPC_HOST', '127.0.0.1')
LTC_RPC_PORT = int(os.getenv('LTC_RPC_PORT', 19895))
LTC_ONION_PORT = int(os.getenv('LTC_ONION_PORT', 9333))
LTC_RPC_USER = os.getenv('LTC_RPC_USER', '')
LTC_RPC_PWD = os.getenv('LTC_RPC_PWD', '')

BTC_RPC_HOST = os.getenv('BTC_RPC_HOST', '127.0.0.1')
BTC_RPC_PORT = int(os.getenv('BTC_RPC_PORT', 19996))
BTC_ONION_PORT = int(os.getenv('BTC_ONION_PORT', 8334))
BTC_RPC_USER = os.getenv('BTC_RPC_USER', '')
BTC_RPC_PWD = os.getenv('BTC_RPC_PWD', '')

DCR_RPC_HOST = os.getenv('DCR_RPC_HOST', '127.0.0.1')
DCR_RPC_PORT = int(os.getenv('DCR_RPC_PORT', 9109))
DCR_WALLET_RPC_HOST = os.getenv('DCR_WALLET_RPC_HOST', '127.0.0.1')
DCR_WALLET_RPC_PORT = int(os.getenv('DCR_WALLET_RPC_PORT', 9209))
DCR_WALLET_PWD = os.getenv('DCR_WALLET_PWD', random.randbytes(random.randint(14, 18)).hex())
DCR_RPC_USER = os.getenv('DCR_RPC_USER', 'user')
DCR_RPC_PWD = os.getenv('DCR_RPC_PWD', random.randbytes(random.randint(14, 18)).hex())

NMC_RPC_HOST = os.getenv('NMC_RPC_HOST', '127.0.0.1')
NMC_RPC_PORT = int(os.getenv('NMC_RPC_PORT', 19698))

PIVX_RPC_HOST = os.getenv('PIVX_RPC_HOST', '127.0.0.1')
PIVX_RPC_PORT = int(os.getenv('PIVX_RPC_PORT', 51473))
PIVX_ONION_PORT = int(os.getenv('PIVX_ONION_PORT', 51472))  # nDefaultPort
PIVX_RPC_USER = os.getenv('PIVX_RPC_USER', '')
PIVX_RPC_PWD = os.getenv('PIVX_RPC_PWD', '')

DASH_RPC_HOST = os.getenv('DASH_RPC_HOST', '127.0.0.1')
DASH_RPC_PORT = int(os.getenv('DASH_RPC_PORT', 9998))
DASH_ONION_PORT = int(os.getenv('DASH_ONION_PORT', 9999))  # nDefaultPort
DASH_RPC_USER = os.getenv('DASH_RPC_USER', '')
DASH_RPC_PWD = os.getenv('DASH_RPC_PWD', '')

FIRO_RPC_HOST = os.getenv('FIRO_RPC_HOST', '127.0.0.1')
FIRO_RPC_PORT = int(os.getenv('FIRO_RPC_PORT', 8888))
FIRO_ONION_PORT = int(os.getenv('FIRO_ONION_PORT', 8168))  # nDefaultPort
FIRO_RPC_USER = os.getenv('FIRO_RPC_USER', '')
FIRO_RPC_PWD = os.getenv('FIRO_RPC_PWD', '')

NAV_RPC_HOST = os.getenv('NAV_RPC_HOST', '127.0.0.1')
NAV_RPC_PORT = int(os.getenv('NAV_RPC_PORT', 44444))
NAV_ONION_PORT = int(os.getenv('NAV_ONION_PORT', 8334))  # TODO?
NAV_RPC_USER = os.getenv('NAV_RPC_USER', '')
NAV_RPC_PWD = os.getenv('NAV_RPC_PWD', '')

TOR_PROXY_HOST = os.getenv('TOR_PROXY_HOST', '127.0.0.1')
TOR_PROXY_PORT = int(os.getenv('TOR_PROXY_PORT', 9050))
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', 9051))
TOR_DNS_PORT = int(os.getenv('TOR_DNS_PORT', 5353))
TEST_TOR_PROXY = toBool(os.getenv('TEST_TOR_PROXY', 'true'))  # Expects a known exit node
TEST_ONION_LINK = toBool(os.getenv('TEST_ONION_LINK', 'false'))

BITCOIN_FASTSYNC_URL = os.getenv('BITCOIN_FASTSYNC_URL', 'https://eu2.contabostorage.com/1f50a74c9dc14888a8664415dad3d020:utxosets/')
BITCOIN_FASTSYNC_FILE = os.getenv('BITCOIN_FASTSYNC_FILE', 'utxo-snapshot-bitcoin-mainnet-820852.tar')

# Encrypt new wallets with this password, must match the Particl wallet password when adding coins
WALLET_ENCRYPTION_PWD = os.getenv('WALLET_ENCRYPTION_PWD', '')

use_tor_proxy: bool = False

monerod_proxy_config = [
    f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}',
    'proxy-allow-dns-leaks=0',
    'no-igd=1',                 # Disable UPnP port mapping
    'hide-my-port=1',           # Don't share the p2p port
    'p2p-bind-ip=127.0.0.1',    # Don't broadcast ip
    'in-peers=0',               # Changes "error" in log to "incoming connections disabled"
    'out-peers=24',
    f'tx-proxy=tor,{TOR_PROXY_HOST}:{TOR_PROXY_PORT},disable_noise,16'  # Outgoing tx relay to onion
]

monero_wallet_rpc_proxy_config = [
    #   'daemon-ssl-allow-any-cert=1', moved to startup flag
]

wownerod_proxy_config = [
    f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}',
    'proxy-allow-dns-leaks=0',
    'no-igd=1',                 # Disable UPnP port mapping
    'hide-my-port=1',           # Don't share the p2p port
    'p2p-bind-ip=127.0.0.1',    # Don't broadcast ip
    'in-peers=0',               # Changes "error" in log to "incoming connections disabled"
    'out-peers=24',
    f'tx-proxy=tor,{TOR_PROXY_HOST}:{TOR_PROXY_PORT},disable_noise,16'  # Outgoing tx relay to onion
]

wownero_wallet_rpc_proxy_config = [
    #   'daemon-ssl-allow-any-cert=1', moved to startup flag
]

default_socket = socket.socket
default_socket_timeout = socket.getdefaulttimeout()
default_socket_getaddrinfo = socket.getaddrinfo


def shouldManageDaemon(prefix: str) -> bool:
    '''
    If the user sets a COIN _RPC_HOST or PORT variable, set manage_daemon for COIN to false.
    The COIN _MANAGE_DAEMON variables can override this and set manage_daemon directly.
    If BSX_DOCKER_MODE is active COIN _MANAGE_DAEMON will default to false.
    '''
    default_mode: str = 'false' if BSX_DOCKER_MODE else 'true' if BSX_TEST_MODE else 'auto'
    manage_daemon: str = os.getenv(prefix + '_MANAGE_DAEMON', default_mode)

    if manage_daemon == 'auto':
        host_was_set: bool = prefix + '_RPC_HOST' in os.environ
        port_was_set: bool = prefix + '_RPC_PORT' in os.environ

        if host_was_set or port_was_set:
            return False
        return True

    return toBool(manage_daemon)


def exitWithError(error_msg: str):
    sys.stderr.write('Error: {}, exiting.\n'.format(error_msg))
    sys.exit(1)


def setConnectionParameters(timeout: int = 5, allow_set_tor: bool = True):
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)

    if use_tor_proxy:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT, rdns=True)
        socket.socket = socks.socksocket
        socket.getaddrinfo = getaddrinfo_tor  # Without this accessing .onion links would fail

    # Set low timeout for urlretrieve connections
    socket.setdefaulttimeout(timeout)


def popConnectionParameters() -> None:
    if use_tor_proxy:
        socket.socket = default_socket
        socket.getaddrinfo = default_socket_getaddrinfo
    socket.setdefaulttimeout(default_socket_timeout)


def getRemoteFileLength(url: str) -> (int, bool):
    try:
        setConnectionParameters()
        with contextlib.closing(urlopen(url)) as fp:
            # NOTE: The test here is case insensitive, 'Accept-Ranges' will match
            can_resume = 'accept-ranges' in fp.headers
            return fp.length, can_resume
    finally:
        popConnectionParameters()


def downloadRelease(url: str, path: str, extra_opts, timeout: int = 10) -> None:
    """If file exists at path compare it's size to the content length at the url
       and attempt to resume download if file size is below expected.
    """
    resume_from: int = 0

    if os.path.exists(path):
        if extra_opts.get('redownload_releases', False):
            logging.warning(f'Overwriting: {path}')
        elif extra_opts.get('verify_release_file_size', True):
            file_size = os.stat(path).st_size
            remote_file_length, can_resume = getRemoteFileLength(url)
            if file_size < remote_file_length:
                logger.warning(f'{path} is an unexpected size, {file_size} < {remote_file_length}.  Attempting to resume download.')
                if can_resume:
                    resume_from = file_size
                else:
                    logger.warning('Download can not be resumed, restarting.')
            else:
                return
        else:
            # File exists and size check is disabled
            return

    return downloadFile(url, path, timeout, resume_from)


def downloadFile(url: str, path: str, timeout: int = 5, resume_from: int = 0) -> None:
    logger.info(f'Downloading file {url}')
    logger.info(f'To {path}')
    try:
        setConnectionParameters(timeout=timeout)
        urlretrieve(url, path, make_reporthook(resume_from, logger), resume_from=resume_from)
    finally:
        popConnectionParameters()


def downloadBytes(url) -> None:
    try:
        setConnectionParameters()
        with contextlib.closing(urlopen(url)) as fp:
            return fp.read()
    finally:
        popConnectionParameters()


def importPubkeyFromUrls(gpg, pubkeyurls):
    for url in pubkeyurls:
        try:
            logger.info('Importing public key from url: ' + url)
            rv = gpg.import_keys(downloadBytes(url))
            for key in rv.fingerprints:
                gpg.trust_keys(key, 'TRUST_FULLY')
            break
        except Exception as e:
            logging.warning('Import from url failed: %s', str(e))


def testTorConnection():
    test_url = 'https://check.torproject.org/'
    logger.info('Testing TOR connection at: ' + test_url)

    test_response = downloadBytes(test_url).decode('utf-8')
    assert ('Congratulations. This browser is configured to use Tor.' in test_response)
    logger.info('TOR is working.')


def testOnionLink():
    test_url = 'http://jqyzxhjk6psc6ul5jnfwloamhtyh7si74b4743k2qgpskwwxrzhsxmad.onion'
    logger.info('Testing onion site: ' + test_url)
    test_response = downloadBytes(test_url).decode('utf-8')
    assert ('The Tor Project\'s free software protects your privacy online.' in test_response)
    logger.info('Onion links work.')


def havePubkey(gpg, key_id):
    for key in gpg.list_keys():
        if key['keyid'] == key_id:
            return True
    return False


def downloadPIVXParams(output_dir):
    # util/fetch-params.sh

    if os.path.exists(output_dir):
        logger.info(f'Skipping PIVX params download, path exists: {output_dir}')
        return
    os.makedirs(output_dir)

    source_url = 'https://download.z.cash/downloads/'
    files = {
        'sapling-spend.params': '8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13',
        'sapling-output.params': '2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4',
    }

    try:
        setConnectionParameters()
        for k, v in files.items():
            url = urllib.parse.urljoin(source_url, k)
            path = os.path.join(output_dir, k)
            downloadFile(url, path)
        hasher = hashlib.sha256()
        with open(path, 'rb') as fp:
            hasher.update(fp.read())
        file_hash = hasher.hexdigest()
        logger.info('%s hash: %s', k, file_hash)
        assert file_hash == v
    finally:
        popConnectionParameters()


def isValidSignature(result):
    if result.valid is False \
       and (result.status == 'signature valid' and result.key_status == 'signing key has expired'):
        return True
    return result.valid


def ensureValidSignatureBy(result, signing_key_name):
    if not isValidSignature(result):
        raise ValueError('Signature verification failed.')

    if result.key_id not in expected_key_ids[signing_key_name]:
        raise ValueError('Signature made by unexpected keyid: ' + result.key_id)


def extractCore(coin, version_data, settings, bin_dir, release_path, extra_opts={}):
    version, version_tag, signers = version_data
    logger.info('extractCore %s v%s%s', coin, version, version_tag)
    extract_core_overwrite = extra_opts.get('extract_core_overwrite', True)

    if coin in ('monero', 'firo', 'wownero'):
        if coin in ('monero', 'wownero'):
            bins = [coin + 'd', coin + '-wallet-rpc']
        elif coin == 'firo':
            bins = [coin + 'd', coin + '-cli', coin + '-tx']
        else:
            raise ValueError('Unknown coin')

        if 'win32' in BIN_ARCH or 'win64' in BIN_ARCH:
            with zipfile.ZipFile(release_path) as fz:
                namelist = fz.namelist()
                for b in bins:
                    b += '.exe'
                    out_path = os.path.join(bin_dir, b)
                    if (not os.path.exists(out_path)) or extract_core_overwrite:
                        for entry in namelist:
                            if entry.endswith(b):
                                with open(out_path, 'wb') as fout:
                                    fout.write(fz.read(entry))
                                try:
                                    os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
                                except Exception as e:
                                    logging.warning('Unable to set file permissions: %s, for %s', str(e), out_path)
                                break
            return

        num_exist = 0
        for b in bins:
            out_path = os.path.join(bin_dir, b)
            if os.path.exists(out_path):
                num_exist += 1
        if not extract_core_overwrite and num_exist == len(bins):
            logger.info('Skipping extract, files exist.')
            return

        with tarfile.open(release_path) as ft:
            for member in ft.getmembers():
                if member.isdir():
                    continue
                bin_name = os.path.basename(member.name)
                if bin_name not in bins:
                    continue
                out_path = os.path.join(bin_dir, bin_name)
                if (not os.path.exists(out_path)) or extract_core_overwrite:
                    with open(out_path, 'wb') as fout, ft.extractfile(member) as fi:
                        fout.write(fi.read())
                    try:
                        os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
                    except Exception as e:
                        logging.warning('Unable to set file permissions: %s, for %s', str(e), out_path)
        return

    dir_name = 'dashcore' if coin == 'dash' else coin
    if coin == 'decred':
        bins = ['dcrd', 'dcrwallet']
    else:
        bins = [coin + 'd', coin + '-cli', coin + '-tx']
        versions = version.split('.')
        if int(versions[0]) >= 22 or int(versions[1]) >= 19:
            bins.append(coin + '-wallet')

    def get_archive_path(b):
        if coin == 'pivx':
            return '{}-{}/bin/{}'.format(dir_name, version, b)
        elif coin == 'particl' and '_nousb-' in release_path:
            return '{}-{}_nousb/bin/{}'.format(dir_name, version + version_tag, b)
        elif coin == 'decred':
            return '{}-{}-v{}/{}'.format(dir_name, extra_opts['arch_name'], version, b)
        else:
            return '{}-{}/bin/{}'.format(dir_name, version + version_tag, b)

    if 'win32' in BIN_ARCH or 'win64' in BIN_ARCH:
        with zipfile.ZipFile(release_path) as fz:
            for b in bins:
                b += '.exe'
                out_path = os.path.join(bin_dir, b)
                if (not os.path.exists(out_path)) or extract_core_overwrite:
                    with open(out_path, 'wb') as fout:
                        fout.write(fz.read(get_archive_path(b)))
                    try:
                        os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
                    except Exception as e:
                        logging.warning('Unable to set file permissions: %s, for %s', str(e), out_path)
    else:
        with tarfile.open(release_path) as ft:
            for b in bins:
                out_path = os.path.join(bin_dir, b)
                if not os.path.exists(out_path) or extract_core_overwrite:
                    with open(out_path, 'wb') as fout, ft.extractfile(get_archive_path(b)) as fi:
                        fout.write(fi.read())
                    try:
                        os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
                    except Exception as e:
                        logging.warning('Unable to set file permissions: %s, for %s', str(e), out_path)


def prepareCore(coin, version_data, settings, data_dir, extra_opts={}):
    version, version_tag, signers = version_data
    logger.info('prepareCore %s v%s%s', coin, version, version_tag)

    bin_dir = os.path.expanduser(settings['chainclients'][coin]['bindir'])
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    filename_extra = ''
    if 'osx' in BIN_ARCH:
        os_dir_name = 'osx-unsigned'
        os_name = 'osx'
    elif 'win32' in BIN_ARCH or 'win64' in BIN_ARCH:
        os_dir_name = 'win-unsigned'
        os_name = 'win'
    else:
        os_dir_name = 'linux'
        os_name = 'linux'
        if coin == 'particl':
            filename_extra = PARTICL_LINUX_EXTRA

    signing_key_name = signers[0]
    if coin == 'monero':
        use_file_ext = 'tar.bz2' if FILE_EXT == 'tar.gz' else FILE_EXT
        release_filename = '{}-{}-{}.{}'.format(coin, version, BIN_ARCH, use_file_ext)
        if os_name == 'osx':
            os_name = 'mac'

        architecture = 'x64'
        if 'aarch64' in BIN_ARCH:
            architecture = 'armv8'
        elif 'arm' in BIN_ARCH:
            architecture = 'armv7'

        release_url = 'https://downloads.getmonero.org/cli/monero-{}-{}-v{}.{}'.format(os_name, architecture, version, use_file_ext)
        release_path = os.path.join(bin_dir, release_filename)
        downloadRelease(release_url, release_path, extra_opts)

        assert_filename = 'monero-{}-hashes.txt'.format(version)
        # assert_url = 'https://www.getmonero.org/downloads/hashes.txt'
        assert_url = 'https://raw.githubusercontent.com/monero-project/monero-site/{}/downloads/hashes.txt'.format(XMR_SITE_COMMIT)
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            downloadFile(assert_url, assert_path)
    elif coin == 'wownero':
        use_file_ext = 'tar.bz2' if FILE_EXT == 'tar.gz' else FILE_EXT
        release_filename = '{}-{}-{}.{}'.format(coin, version, BIN_ARCH, use_file_ext)
        if os_name == 'osx':
            os_name = 'mac'

        architecture = 'x64'
        release_url = 'https://git.wownero.com/attachments/280753b0-3af0-4a78-a248-8b925e8f4593'
        if 'aarch64' in BIN_ARCH:
            architecture = 'armv8'
            release_url = 'https://git.wownero.com/attachments/0869ffe3-eeff-4240-a185-168ca80fa1e3'
        elif 'arm' in BIN_ARCH:
            architecture = 'armv7'  # 32bit doesn't work
            release_url = 'https://git.wownero.com/attachments/ff0c4886-3865-4670-9bc6-63dd60ded0e3'
        elif 'osx64' in BIN_ARCH:
            release_url = 'https://git.wownero.com/attachments/7e3fd17c-1bcd-442c-b82d-92a00cccffb8'
        elif 'win64' in BIN_ARCH:
            release_url = 'https://git.wownero.com/attachments/a1cf8611-1727-4b49-a8e5-1c66fe4f72a3'
        elif 'win32' in BIN_ARCH:
            release_url = 'https://git.wownero.com/attachments/007d606d-56e0-4c8a-92c1-d0974a781e80'

        release_path = os.path.join(bin_dir, release_filename)
        downloadRelease(release_url, release_path, extra_opts)

        assert_filename = 'wownero-{}-hashes.txt'.format(version)
        assert_url = 'https://git.wownero.com/wownero/wownero.org-website/raw/commit/{}/hashes.txt'.format(WOW_SITE_COMMIT)
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            downloadFile(assert_url, assert_path)

    elif coin == 'decred':
        arch_name = BIN_ARCH
        if USE_PLATFORM == 'Darwin':
            arch_name = 'darwin-amd64'
        elif USE_PLATFORM == 'Windows':
            arch_name = 'windows-amd64'
        else:
            machine: str = platform.machine()
            if 'arm' in machine:
                arch_name = 'linux-arm'
            else:
                arch_name = 'linux-amd64'

        extra_opts['arch_name'] = arch_name
        release_filename = '{}-{}-{}.{}'.format(coin, version, arch_name, FILE_EXT)
        release_page_url = 'https://github.com/decred/decred-binaries/releases/download/v{}'.format(version)
        release_url = release_page_url + '/' + 'decred-{}-v{}.{}'.format(arch_name, version, FILE_EXT)

        release_path = os.path.join(bin_dir, release_filename)
        downloadRelease(release_url, release_path, extra_opts)

        assert_filename = 'decred-v{}-manifest.txt'.format(version)
        assert_url = release_page_url + '/' + assert_filename
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            downloadFile(assert_url, assert_path)

        assert_sig_filename = assert_filename + '.asc'
        assert_sig_url = assert_url + '.asc'
        assert_sig_path = os.path.join(bin_dir, assert_sig_filename)
        if not os.path.exists(assert_sig_path):
            downloadFile(assert_sig_url, assert_sig_path)
    else:
        major_version = int(version.split('.')[0])

        use_guix: bool = coin in ('dash', ) or major_version >= 22
        arch_name = BIN_ARCH
        if os_name == 'osx' and use_guix:
            arch_name = 'x86_64-apple-darwin'
            if coin == 'particl':
                arch_name += '18'

        release_filename = '{}-{}-{}.{}'.format(coin, version + version_tag, arch_name, FILE_EXT)
        if filename_extra != '':
            if use_guix:
                release_filename = '{}-{}_{}-{}.{}'.format(coin, version + version_tag, filename_extra, arch_name, FILE_EXT)
            else:
                release_filename = '{}-{}-{}_{}.{}'.format(coin, version + version_tag, arch_name, filename_extra, FILE_EXT)
        if coin == 'particl':
            release_url = 'https://github.com/particl/particl-core/releases/download/v{}/{}'.format(version + version_tag, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version)
            if use_guix:
                assert_url = f'https://raw.githubusercontent.com/particl/guix.sigs/master/{version}/{signing_key_name}/all.SHA256SUMS'
            else:
                assert_url = 'https://raw.githubusercontent.com/particl/gitian.sigs/master/%s-%s/%s/%s' % (version + version_tag, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'litecoin':
            release_url = 'https://github.com/litecoin-project/litecoin/releases/download/v{}/{}'.format(version + version_tag, release_filename)
            assert_filename = '{}-core-{}-{}-build.assert'.format(coin, os_name, '.'.join(version.split('.')[:2]))
            assert_url = 'https://raw.githubusercontent.com/litecoin-project/gitian.sigs.ltc/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'bitcoin':
            release_url = 'https://bitcoincore.org/bin/bitcoin-core-{}/{}'.format(version, release_filename)
            assert_filename = '{}-core-{}-{}-build.assert'.format(coin, os_name, '.'.join(version.split('.')[:2]))
            if use_guix:
                assert_url = f'https://raw.githubusercontent.com/bitcoin-core/guix.sigs/main/{version}/{signing_key_name}/all.SHA256SUMS'
            else:
                assert_url = 'https://raw.githubusercontent.com/bitcoin-core/gitian.sigs/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'namecoin':
            release_url = 'https://beta.namecoin.org/files/namecoin-core/namecoin-core-{}/{}'.format(version, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
            assert_url = 'https://raw.githubusercontent.com/namecoin/gitian.sigs/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'pivx':
            release_filename = '{}-{}-{}.{}'.format(coin, version, BIN_ARCH, FILE_EXT)
            release_url = 'https://github.com/PIVX-Project/PIVX/releases/download/v{}/{}'.format(version + version_tag, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
            assert_url = 'https://raw.githubusercontent.com/PIVX-Project/gitian.sigs/master/%s-%s/%s/%s' % (version + version_tag, os_dir_name, signing_key_name.capitalize(), assert_filename)
        elif coin == 'dash':
            release_filename = '{}-{}-{}.{}'.format('dashcore', version + version_tag, arch_name, FILE_EXT)
            release_url = 'https://github.com/dashpay/dash/releases/download/v{}/{}'.format(version + version_tag, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, arch_name, major_version)
            sums_name = 'all' if major_version >= 21 else 'codesigned'
            assert_url = f'https://raw.githubusercontent.com/dashpay/guix.sigs/master/{version}/{signing_key_name}/{sums_name}.SHA256SUMS'
        elif coin == 'firo':
            arch_name = BIN_ARCH
            if BIN_ARCH == 'x86_64-linux-gnu':
                arch_name = 'linux64'
            elif BIN_ARCH == 'osx64':
                arch_name = 'macos'
            release_filename = '{}-{}-{}{}.{}'.format('firo', version + version_tag, arch_name, filename_extra, FILE_EXT)
            release_url = 'https://github.com/firoorg/firo/releases/download/v{}/{}'.format(version + version_tag, release_filename)
            assert_url = 'https://github.com/firoorg/firo/releases/download/v%s/SHA256SUMS' % (version + version_tag)
        elif coin == 'navcoin':
            release_filename = '{}-{}-{}.{}'.format(coin, version, BIN_ARCH, FILE_EXT)
            release_url = 'https://github.com/navcoin/navcoin-core/releases/download/{}/{}'.format(version + version_tag, release_filename)
            assert_filename = 'SHA256SUM_7.0.3.asc'
            assert_sig_filename = 'SHA256SUM_7.0.3.asc.sig'
            assert_url = 'https://github.com/navcoin/navcoin-core/releases/download/{}/{}'.format(version + version_tag, assert_filename)
        else:
            raise ValueError('Unknown coin')

        release_path = os.path.join(bin_dir, release_filename)
        downloadRelease(release_url, release_path, extra_opts)

        # Rename assert files with full version
        assert_filename = '{}-{}-{}-build-{}.assert'.format(coin, os_name, version, signing_key_name)
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            downloadFile(assert_url, assert_path)

        if coin not in ('firo', ):
            assert_sig_url = assert_url + ('.asc' if use_guix else '.sig')
            if coin not in ('nav', ):
                assert_sig_filename = '{}-{}-{}-build-{}.assert.sig'.format(coin, os_name, version, signing_key_name)
            assert_sig_path = os.path.join(bin_dir, assert_sig_filename)
            if not os.path.exists(assert_sig_path):
                downloadFile(assert_sig_url, assert_sig_path)

    hasher = hashlib.sha256()
    with open(release_path, 'rb') as fp:
        hasher.update(fp.read())
    release_hash = hasher.digest()

    logger.info('%s hash: %s', release_filename, release_hash.hex())
    with open(assert_path, 'rb', 0) as fp, mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as s:
        if s.find(bytes(release_hash.hex(), 'utf-8')) == -1:
            raise ValueError('Error: release hash %s not found in assert file.' % (release_hash.hex()))
        else:
            logger.info('Found release hash in assert file.')

    if SKIP_GPG_VALIDATION:
        logger.warning('Skipping binary signature check as SKIP_GPG_VALIDATION env var is set.')
        extractCore(coin, version_data, settings, bin_dir, release_path, extra_opts)
        return

    """
    gnupghome = os.path.join(data_dir, 'gpg')
    if not os.path.exists(gnupghome):
        os.makedirs(gnupghome)
    """
    gpg = gnupg.GPG()

    keysdirpath = extra_opts.get('keysdirpath', None)
    if keysdirpath is not None:
        logger.info(f'Loading PGP keys from: {keysdirpath}.')
        for path in os.scandir(keysdirpath):
            if path.is_file():
                with open(path, 'rb') as fp:
                    rv = gpg.import_keys(fp.read())
                    for key in rv.fingerprints:
                        gpg.trust_keys(rv.fingerprints[0], 'TRUST_FULLY')

    if coin in ('navcoin', ):
        pubkey_filename = '{}_builder.pgp'.format(coin)
    elif coin in ('decred', ):
        pubkey_filename = '{}_release.pgp'.format(coin)
    else:
        pubkey_filename = '{}_{}.pgp'.format(coin, signing_key_name)
    pubkeyurls = [
        'https://raw.githubusercontent.com/basicswap/basicswap/master/pgp/keys/' + pubkey_filename,
        'https://gitlab.com/particl/basicswap/-/raw/master/pgp/keys/' + pubkey_filename,
    ]
    if coin == 'dash':
        pubkeyurls.append('https://raw.githubusercontent.com/dashpay/dash/master/contrib/gitian-keys/pasta.pgp')
    if coin == 'monero':
        pubkeyurls.append('https://raw.githubusercontent.com/monero-project/monero/master/utils/gpg_keys/binaryfate.asc')
    if coin == 'wownero':
        pubkeyurls.append('https://git.wownero.com/wownero/wownero/raw/branch/master/utils/gpg_keys/wowario.asc')
    if coin == 'firo':
        pubkeyurls.append('https://firo.org/reuben.asc')

    if ADD_PUBKEY_URL != '':
        pubkeyurls.append(ADD_PUBKEY_URL + '/' + pubkey_filename)

    if coin in ('monero', 'wownero', 'firo'):
        with open(assert_path, 'rb') as fp:
            verified = gpg.verify_file(fp)

        if not isValidSignature(verified) and verified.username is None:
            logger.warning('Signature made by unknown key.')
            importPubkeyFromUrls(gpg, pubkeyurls)
            with open(assert_path, 'rb') as fp:
                verified = gpg.verify_file(fp)
    elif coin in ('navcoin'):
        with open(assert_sig_path, 'rb') as fp:
            verified = gpg.verify_file(fp)

        if not isValidSignature(verified) and verified.username is None:
            logger.warning('Signature made by unknown key.')
            importPubkeyFromUrls(gpg, pubkeyurls)
            with open(assert_sig_path, 'rb') as fp:
                verified = gpg.verify_file(fp)

        # .sig file is not a detached signature, recheck release hash in decrypted data
        logger.warning('Double checking Navcoin release hash.')
        with open(assert_sig_path, 'rb') as fp:
            decrypted = gpg.decrypt_file(fp)
            assert (release_hash.hex() in str(decrypted))
    else:
        with open(assert_sig_path, 'rb') as fp:
            verified = gpg.verify_file(fp, assert_path)

        if not isValidSignature(verified) and verified.username is None:
            logger.warning('Signature made by unknown key.')
            importPubkeyFromUrls(gpg, pubkeyurls)
            with open(assert_sig_path, 'rb') as fp:
                verified = gpg.verify_file(fp, assert_path)

    ensureValidSignatureBy(verified, signing_key_name)

    extractCore(coin, version_data, settings, bin_dir, release_path, extra_opts)


def writeTorSettings(fp, coin, coin_settings, tor_control_password):
    '''
    TOR_PROXY_HOST must be an ip address.
    BTC versions >21 and Particl with lookuptorcontrolhost=any can accept hostnames, XMR and LTC cannot
    '''
    fp.write(f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}\n')
    if coin in ('decred',):
        return

    onionport = coin_settings['onionport']
    fp.write(f'torpassword={tor_control_password}\n')
    fp.write(f'torcontrol={TOR_PROXY_HOST}:{TOR_CONTROL_PORT}\n')

    if coin_settings['core_version_group'] >= 21:
        fp.write(f'bind=0.0.0.0:{onionport}=onion\n')
    else:
        fp.write(f'bind=0.0.0.0:{onionport}\n')


def prepareDataDir(coin, settings, chain, particl_mnemonic, extra_opts={}):
    core_settings = settings['chainclients'][coin]
    bin_dir = core_settings['bindir']
    data_dir = core_settings['datadir']
    tor_control_password = extra_opts.get('tor_control_password', None)

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    if coin in ('wownero', 'monero'):
        core_conf_path = os.path.join(data_dir, coin + 'd.conf')
        if os.path.exists(core_conf_path):
            exitWithError('{} exists'.format(core_conf_path))
        with open(core_conf_path, 'w') as fp:
            if chain == 'regtest':
                fp.write('regtest=1\n')
                fp.write('keep-fakechain=1\n')
                fp.write('fixed-difficulty=1\n')
            else:
                fp.write('bootstrap-daemon-address=auto\n')
                fp.write('restricted-rpc=1\n')
            if chain == 'testnet':
                fp.write('testnet=1\n')
            config_datadir = data_dir
            if extra_opts.get('use_containers', False) is True:
                config_datadir = '/data'
            fp.write(f'data-dir={config_datadir}\n')
            fp.write('rpc-bind-port={}\n'.format(core_settings['rpcport']))
            fp.write('rpc-bind-ip={}\n'.format(COINS_RPCBIND_IP))
            fp.write('zmq-rpc-bind-port={}\n'.format(core_settings['zmqport']))
            fp.write('zmq-rpc-bind-ip={}\n'.format(COINS_RPCBIND_IP))
            fp.write('prune-blockchain=1\n')

            if coin == 'monero':
                if XMR_RPC_USER != '':
                    fp.write(f'rpc-login={XMR_RPC_USER}:{XMR_RPC_PWD}\n')
                if tor_control_password is not None:
                    for opt_line in monerod_proxy_config:
                        fp.write(opt_line + '\n')

            if coin == 'wownero':
                if WOW_RPC_USER != '':
                    fp.write(f'rpc-login={WOW_RPC_USER}:{WOW_RPC_PWD}\n')
                if tor_control_password is not None:
                    for opt_line in wownerod_proxy_config:
                        fp.write(opt_line + '\n')

    if coin in ('wownero', 'monero'):
        wallets_dir = core_settings.get('walletsdir', data_dir)
        if not os.path.exists(wallets_dir):
            os.makedirs(wallets_dir)

        wallet_conf_path = os.path.join(wallets_dir, coin + '-wallet-rpc.conf')
        if coin == 'monero':
            wallet_conf_path = os.path.join(wallets_dir, 'monero_wallet.conf')
        if os.path.exists(wallet_conf_path):
            exitWithError('{} exists'.format(wallet_conf_path))
        with open(wallet_conf_path, 'w') as fp:
            config_datadir = os.path.join(data_dir, 'wallets')
            if extra_opts.get('use_containers', False) is True:
                fp.write('daemon-address={}:{}\n'.format(core_settings['rpchost'], core_settings['rpcport']))
                config_datadir = '/data'

            fp.write('no-dns=1\n')
            fp.write('rpc-bind-port={}\n'.format(core_settings['walletrpcport']))
            fp.write('rpc-bind-ip={}\n'.format(COINS_RPCBIND_IP))
            fp.write(f'wallet-dir={config_datadir}\n')
            fp.write('log-file={}\n'.format(os.path.join(config_datadir, 'wallet.log')))
            fp.write('rpc-login={}:{}\n'.format(core_settings['walletrpcuser'], core_settings['walletrpcpassword']))
            if coin == 'monero':
                fp.write('shared-ringdb-dir={}\n'.format(os.path.join(config_datadir, 'shared-ringdb')))
            elif coin == 'wownero':
                fp.write('wow-shared-ringdb-dir={}\n'.format(os.path.join(config_datadir, 'shared-ringdb')))
            if chain == 'regtest':
                fp.write('allow-mismatched-daemon-version=1\n')

            if tor_control_password is not None:
                if not core_settings['manage_daemon']:
                    for opt_line in monero_wallet_rpc_proxy_config:
                        fp.write(opt_line + '\n')
        return

    if coin == 'decred':
        chainname = 'simnet' if chain == 'regtest' else chain
        core_conf_path = os.path.join(data_dir, 'dcrd.conf')
        if os.path.exists(core_conf_path):
            exitWithError('{} exists'.format(core_conf_path))
        with open(core_conf_path, 'w') as fp:
            if chain != 'mainnet':
                fp.write(chainname + '=1\n')
            fp.write('debuglevel=info\n')
            fp.write('notls=1\n')

            fp.write('rpclisten={}:{}\n'.format(core_settings['rpchost'], core_settings['rpcport']))

            fp.write('rpcuser={}\n'.format(core_settings['rpcuser']))
            fp.write('rpcpass={}\n'.format(core_settings['rpcpassword']))

            if tor_control_password is not None:
                writeTorSettings(fp, coin, core_settings, tor_control_password)

        wallet_conf_path = os.path.join(data_dir, 'dcrwallet.conf')
        if os.path.exists(wallet_conf_path):
            exitWithError('{} exists'.format(wallet_conf_path))
        with open(wallet_conf_path, 'w') as fp:
            if chain != 'mainnet':
                fp.write(chainname + '=1\n')
            fp.write('debuglevel=info\n')
            fp.write('noservertls=1\n')
            fp.write('noclienttls=1\n')

            fp.write('rpcconnect={}:{}\n'.format(core_settings['rpchost'], core_settings['rpcport']))
            fp.write('rpclisten={}:{}\n'.format(core_settings['walletrpchost'], core_settings['walletrpcport']))

            fp.write('username={}\n'.format(core_settings['rpcuser']))
            fp.write('password={}\n'.format(core_settings['rpcpassword']))

        return

    core_conf_path = os.path.join(data_dir, coin + '.conf')
    if os.path.exists(core_conf_path):
        exitWithError('{} exists'.format(core_conf_path))
    with open(core_conf_path, 'w') as fp:
        if chain != 'mainnet':
            if coin in ('navcoin',):
                chainname = 'devnet' if chain == 'regtest' else chain
                fp.write(chainname + '=1\n')
            else:
                fp.write(chain + '=1\n')
            if coin not in ('firo', 'navcoin'):
                if chain == 'testnet':
                    fp.write('[test]\n\n')
                elif chain == 'regtest':
                    fp.write('[regtest]\n\n')
                else:
                    logger.warning('Unknown chain %s', chain)

        if COINS_RPCBIND_IP != '127.0.0.1':
            fp.write('rpcallowip=127.0.0.1\n')
            if BSX_DOCKER_MODE:
                fp.write('rpcallowip=172.0.0.0/8\n')  # Allow 172.x.x.x, range used by docker
            fp.write('rpcbind={}\n'.format(COINS_RPCBIND_IP))

        fp.write('rpcport={}\n'.format(core_settings['rpcport']))
        fp.write('printtoconsole=0\n')
        fp.write('daemon=0\n')
        fp.write('wallet=wallet.dat\n')

        if tor_control_password is not None:
            writeTorSettings(fp, coin, core_settings, tor_control_password)

        salt = generate_salt(16)
        if coin == 'particl':
            fp.write('debugexclude=libevent\n')
            fp.write('zmqpubsmsg=tcp://{}:{}\n'.format(COINS_RPCBIND_IP, settings['zmqport']))
            fp.write('spentindex=1\n')
            fp.write('txindex=1\n')
            fp.write('staking=0\n')
            if PART_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(PART_RPC_USER, salt, password_to_hmac(salt, PART_RPC_PWD)))
        elif coin == 'litecoin':
            fp.write('prune=4000\n')
            fp.write('blockfilterindex=0\n')
            fp.write('peerblockfilters=0\n')
            if LTC_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(LTC_RPC_USER, salt, password_to_hmac(salt, LTC_RPC_PWD)))
        elif coin == 'bitcoin':
            fp.write('deprecatedrpc=create_bdb\n')
            fp.write('prune=2000\n')
            fp.write('fallbackfee=0.0002\n')
            if BTC_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(BTC_RPC_USER, salt, password_to_hmac(salt, BTC_RPC_PWD)))
        elif coin == 'namecoin':
            fp.write('prune=2000\n')
        elif coin == 'pivx':
            params_dir = os.path.join(data_dir, 'pivx-params')
            downloadPIVXParams(params_dir)
            PIVX_PARAMSDIR = os.getenv('PIVX_PARAMSDIR', '/data/pivx-params' if extra_opts.get('use_containers', False) else params_dir)
            fp.write(f'paramsdir={PIVX_PARAMSDIR}\n')
            if PIVX_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(PIVX_RPC_USER, salt, password_to_hmac(salt, PIVX_RPC_PWD)))
        elif coin == 'dash':
            fp.write('prune=4000\n')
            fp.write('fallbackfee=0.0002\n')
            if DASH_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(DASH_RPC_USER, salt, password_to_hmac(salt, DASH_RPC_PWD)))
        elif coin == 'firo':
            fp.write('prune=4000\n')
            fp.write('fallbackfee=0.0002\n')
            fp.write('txindex=0\n')
            fp.write('usehd=1\n')
            if FIRO_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(FIRO_RPC_USER, salt, password_to_hmac(salt, FIRO_RPC_PWD)))
        elif coin == 'navcoin':
            fp.write('prune=4000\n')
            fp.write('fallbackfee=0.0002\n')
            if NAV_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(NAV_RPC_USER, salt, password_to_hmac(salt, NAV_RPC_PWD)))
        else:
            logger.warning('Unknown coin %s', coin)

    if coin == 'bitcoin' and extra_opts.get('use_btc_fastsync', False) is True:
        logger.info('Initialising BTC chain with fastsync %s', BITCOIN_FASTSYNC_FILE)
        base_dir = extra_opts['data_dir']

        for dirname in ('blocks', 'chainstate'):
            if os.path.exists(os.path.join(data_dir, dirname)):
                raise ValueError(f'{dirname} directory already exists, not overwriting.')

        sync_file_path = os.path.join(base_dir, BITCOIN_FASTSYNC_FILE)
        if not os.path.exists(sync_file_path):
            raise ValueError(f'BTC fastsync file not found: {sync_file_path}')

        # Double check
        if extra_opts.get('check_btc_fastsync', True):
            check_btc_fastsync_data(base_dir, sync_file_path)

        with tarfile.open(sync_file_path) as ft:
            ft.extractall(path=data_dir)


def write_torrc(data_dir, tor_control_password):
    tor_dir = os.path.join(data_dir, 'tor')
    if not os.path.exists(tor_dir):
        os.makedirs(tor_dir)
    torrc_path = os.path.join(tor_dir, 'torrc')

    tor_control_hash = rfc2440_hash_password(tor_control_password)
    with open(torrc_path, 'w') as fp:
        fp.write(f'SocksPort 0.0.0.0:{TOR_PROXY_PORT}\n')
        fp.write(f'ControlPort 0.0.0.0:{TOR_CONTROL_PORT}\n')
        fp.write(f'DNSPort 0.0.0.0:{TOR_DNS_PORT}\n')
        fp.write(f'HashedControlPassword {tor_control_hash}\n')


def addTorSettings(settings, tor_control_password):
    settings['use_tor'] = True
    settings['tor_proxy_host'] = TOR_PROXY_HOST
    settings['tor_proxy_port'] = TOR_PROXY_PORT
    settings['tor_control_password'] = tor_control_password
    settings['tor_control_port'] = TOR_CONTROL_PORT


def modify_tor_config(settings, coin, tor_control_password=None, enable=False, extra_opts={}):
    coin_settings = settings['chainclients'][coin]
    data_dir = coin_settings['datadir']

    if coin in ('monero', 'wownero'):
        core_conf_path = os.path.join(data_dir, coin + 'd.conf')
        if not os.path.exists(core_conf_path):
            exitWithError('{} does not exist'.format(core_conf_path))

        wallets_dir = coin_settings.get('walletsdir', data_dir)
        wallet_conf_path = os.path.join(wallets_dir, coin + '-wallet-rpc.conf')
        if coin == 'monero':
            wallet_conf_path = os.path.join(wallets_dir, 'monero_wallet.conf')
        if not os.path.exists(wallet_conf_path):
            exitWithError('{} does not exist'.format(wallet_conf_path))

        # Backup
        shutil.copyfile(core_conf_path, core_conf_path + '.last')
        shutil.copyfile(wallet_conf_path, wallet_conf_path + '.last')

        with open(core_conf_path, 'w') as fp:
            with open(core_conf_path + '.last') as fp_in:
                # Disable tor first
                for line in fp_in:
                    skip_line: bool = False
                    if coin == 'monero':
                        for opt_line in monerod_proxy_config:
                            setting: str = opt_line[0: opt_line.find('=') + 1]
                            if line.startswith(setting):
                                skip_line = True
                                break
                    if coin == 'wownero':
                        for opt_line in wownerod_proxy_config:
                            setting: str = opt_line[0: opt_line.find('=') + 1]
                            if line.startswith(setting):
                                skip_line = True
                                break
                    if not skip_line:
                        fp.write(line)
            if enable:
                if coin == 'monero':
                    for opt_line in monerod_proxy_config:
                        fp.write(opt_line + '\n')
                if coin == 'wownero':
                    for opt_line in wownerod_proxy_config:
                        fp.write(opt_line + '\n')

        with open(wallet_conf_path, 'w') as fp:
            with open(wallet_conf_path + '.last') as fp_in:
                # Disable tor first
                for line in fp_in:
                    skip_line = False
                    for opt_line in monero_wallet_rpc_proxy_config + ['proxy=',]:
                        setting: str = opt_line[0: opt_line.find('=') + 1]
                        if line.startswith(setting):
                            skip_line = True
                            break
                    if not skip_line:
                        fp.write(line)
            if enable:
                if not coin_settings['manage_daemon']:
                    for opt_line in monero_wallet_rpc_proxy_config:
                        fp.write(opt_line + '\n')

            coin_settings['trusted_daemon'] = extra_opts.get('trust_remote_node', 'auto')
        return

    if coin == 'decred':
        config_path = os.path.join(data_dir, 'dcrd.conf')
    else:
        config_path = os.path.join(data_dir, coin + '.conf')

    if not os.path.exists(config_path):
        exitWithError('{} does not exist'.format(config_path))

    if 'onionport' not in coin_settings:
        default_onionport = 0
        if coin == 'bitcoin':
            default_onionport = BTC_ONION_PORT
        elif coin == 'particl':
            default_onionport = PART_ONION_PORT
        elif coin == 'litecoin':
            default_onionport = LTC_ONION_PORT
        elif coin in ('decred',):
            pass
        else:
            exitWithError('Unknown default onion listening port for {}'.format(coin))
        if default_onionport > 0:
            coin_settings['onionport'] = default_onionport

    # Backup
    shutil.copyfile(config_path, config_path + '.last')

    tor_settings = ('proxy=', 'torpassword=', 'torcontrol=', 'bind=')
    with open(config_path, 'w') as fp:
        with open(config_path + '.last') as fp_in:
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


def printVersion():
    logger.info(f'Basicswap version: {__version__}')

    logger.info('Core versions:')
    for coin, version in known_coins.items():
        postfix = ' (Disabled)' if coin in disabled_coins else ''
        logger.info('\t%s: %s%s%s', coin.capitalize(), version[0], version[1], postfix)


def printHelp():
    print('Usage: basicswap-prepare ')
    print('\n--help, -h               Print help.')
    print('--version, -v            Print version.')
    print('--datadir=PATH           Path to basicswap data directory, default:{}.'.format(cfg.BASICSWAP_DATADIR))
    print('--bindir=PATH            Path to cores directory, default:datadir/bin.')
    print('--mainnet                Run in mainnet mode.')
    print('--testnet                Run in testnet mode.')
    print('--regtest                Run in regtest mode.')
    print('--particl_mnemonic=      Recovery phrase to use for the Particl wallet, default is randomly generated,\n'
          + '                         "auto" to create a wallet automatically - No mnemonic.'
          + '                         "none" to disable wallet initialisation.')
    print('--withcoin=              Prepare system to run daemon for coin.')
    print('--withoutcoin=           Do not prepare system to run daemon for coin.')
    print('--addcoin=               Add coin to existing setup.')
    print('--disablecoin=           Make coin inactive.')
    print('--preparebinonly         Don\'t prepare settings or datadirs.')
    print('--nocores                Don\'t download and extract any coin clients.')
    print('--usecontainers          Expect each core to run in a unique container.')
    print('--portoffset=n           Raise all ports by n.')
    print('--htmlhost=              Interface to host html server on, default:127.0.0.1.')
    print('--wshost=                Interface to host websocket server on, disable by setting to "none", default\'s to --htmlhost.')
    print('--xmrrestoreheight=n     Block height to restore Monero wallet from, default:{}.'.format(DEFAULT_XMR_RESTORE_HEIGHT))
    print('--wowrestoreheight=n     Block height to restore Wownero wallet from, default:{}.'.format(DEFAULT_WOW_RESTORE_HEIGHT))
    print('--trustremotenode        Set trusted-daemon for XMR, defaults to auto: true when daemon rpchost value is a private ip address else false')
    print('--noextractover          Prevent extracting cores if files exist.  Speeds up tests')
    print('--usetorproxy            Use TOR proxy during setup.  Note that some download links may be inaccessible over TOR.')
    print('--notorproxy             Force usetorproxy off, usetorproxy is automatically set when tor is enabled')
    print('--enabletor              Setup Basicswap instance to use TOR.')
    print('--disabletor             Setup Basicswap instance to not use TOR.')
    print('--usebtcfastsync         Initialise the BTC chain with a snapshot from btcpayserver FastSync.\n'
          + '                         See https://github.com/btcpayserver/btcpayserver-docker/blob/master/contrib/FastSync/README.md')
    print('--skipbtcfastsyncchecks  Use the provided btcfastsync file without checking it\'s size or signature.')
    print('--initwalletsonly        Setup coin wallets only.')
    print('--keysdirpath            Speed up tests by preloading all PGP keys in directory.')
    print('--noreleasesizecheck     If unset the size of existing core release files will be compared to their size at their download url.')
    print('--redownloadreleases     If set core release files will be redownloaded.')
    print('--dashv20compatible      Generate the same DASH wallet seed as for DASH v20 - Use only when importing an existing seed.')

    active_coins = []
    for coin_name in known_coins.keys():
        if coin_name not in disabled_coins:
            active_coins.append(coin_name)
    print('\n' + 'Known coins: {}'.format(', '.join(active_coins)))


def finalise_daemon(d):
    logging.info('Interrupting {}'.format(d.handle.pid))
    try:
        d.handle.send_signal(signal.CTRL_C_EVENT if os.name == 'nt' else signal.SIGINT)
        d.handle.wait(timeout=120)
    except Exception as e:
        logging.info(f'Error {e} for process {d.handle.pid}')
    for fp in [d.handle.stdout, d.handle.stderr, d.handle.stdin] + d.files:
        if fp:
            fp.close()


def test_particl_encryption(data_dir, settings, chain, use_tor_proxy):
    swap_client = None
    daemons = []
    daemon_args = ['-noconnect', '-nodnsseed', '-nofindpeers', '-nostaking']
    with open(os.path.join(data_dir, 'basicswap.log'), 'a') as fp:
        try:
            swap_client = BasicSwap(fp, data_dir, settings, chain, transient_instance=True)
            if not swap_client.use_tor_proxy:
                # Cannot set -bind or -whitebind together with -listen=0
                daemon_args.append('-nolisten')
            c = Coins.PART
            coin_name = 'particl'
            coin_settings = settings['chainclients'][coin_name]
            if coin_settings['manage_daemon']:
                filename = coin_name + 'd' + ('.exe' if os.name == 'nt' else '')
                daemons.append(startDaemon(coin_settings['datadir'], coin_settings['bindir'], filename, daemon_args))
                swap_client.setDaemonPID(c, daemons[-1].handle.pid)
            swap_client.setCoinRunParams(c)
            swap_client.createCoinInterface(c)
            swap_client.waitForDaemonRPC(c, with_wallet=True)

            if swap_client.ci(c).isWalletEncrypted():
                logger.info('Particl Wallet is encrypted')
                if WALLET_ENCRYPTION_PWD == '':
                    raise ValueError('Must set WALLET_ENCRYPTION_PWD to add coin when Particl wallet is encrypted')
                swap_client.ci(c).unlockWallet(WALLET_ENCRYPTION_PWD)
        finally:
            if swap_client:
                swap_client.finalise()
                del swap_client
            for d in daemons:
                finalise_daemon(d)


def encrypt_wallet(swap_client, coin_type) -> None:
    ci = swap_client.ci(coin_type)
    ci.changeWalletPassword('', WALLET_ENCRYPTION_PWD)
    ci.unlockWallet(WALLET_ENCRYPTION_PWD)


def initialise_wallets(particl_wallet_mnemonic, with_coins, data_dir, settings, chain, use_tor_proxy):
    swap_client = None
    daemons = []
    daemon_args = ['-noconnect', '-nodnsseed']
    generated_mnemonic: bool = False

    coins_failed_to_initialise = []

    with open(os.path.join(data_dir, 'basicswap.log'), 'a') as fp:
        try:
            swap_client = BasicSwap(fp, data_dir, settings, chain, transient_instance=True)
            if not swap_client.use_tor_proxy:
                # Cannot set -bind or -whitebind together with -listen=0
                daemon_args.append('-nolisten')
            coins_to_create_wallets_for = (Coins.PART, Coins.BTC, Coins.LTC, Coins.DCR, Coins.DASH)
            # Always start Particl, it must be running to initialise a wallet in addcoin mode
            # Particl must be loaded first as subsequent coins are initialised from the Particl mnemonic
            start_daemons = ['particl', ] + [c for c in with_coins if c != 'particl']
            for coin_name in start_daemons:
                coin_settings = settings['chainclients'][coin_name]
                c = swap_client.getCoinIdFromName(coin_name)

                if c == Coins.XMR:
                    if coin_settings['manage_wallet_daemon']:
                        filename = coin_name + '-wallet-rpc' + ('.exe' if os.name == 'nt' else '')
                        daemons.append(startXmrWalletDaemon(coin_settings['datadir'], coin_settings['bindir'], filename))
                elif c == Coins.WOW:
                    if coin_settings['manage_wallet_daemon']:
                        filename = coin_name + '-wallet-rpc' + ('.exe' if os.name == 'nt' else '')
                        daemons.append(startXmrWalletDaemon(coin_settings['datadir'], coin_settings['bindir'], filename))
                elif c == Coins.DCR:
                    pass
                else:
                    if coin_settings['manage_daemon']:
                        filename = coin_name + 'd' + ('.exe' if os.name == 'nt' else '')
                        coin_args = ['-nofindpeers', '-nostaking'] if c == Coins.PART else []

                        if c == Coins.FIRO:
                            coin_args += ['-hdseed={}'.format(swap_client.getWalletKey(Coins.FIRO, 1).hex())]

                        daemons.append(startDaemon(coin_settings['datadir'], coin_settings['bindir'], filename, daemon_args + coin_args))
                        swap_client.setDaemonPID(c, daemons[-1].handle.pid)
                swap_client.setCoinRunParams(c)
                swap_client.createCoinInterface(c)

                if c in coins_to_create_wallets_for:
                    if c == Coins.DCR:
                        if coin_settings['manage_wallet_daemon'] is False:
                            continue
                        from basicswap.interface.dcr.util import createDCRWallet

                        dcr_password = coin_settings['wallet_pwd'] if WALLET_ENCRYPTION_PWD == '' else WALLET_ENCRYPTION_PWD
                        extra_opts = ['--appdata="{}"'.format(coin_settings['datadir']),
                                      '--pass={}'.format(dcr_password),
                                      ]

                        filename = 'dcrwallet' + ('.exe' if os.name == 'nt' else '')
                        args = [os.path.join(coin_settings['bindir'], filename), '--create'] + extra_opts
                        hex_seed = swap_client.getWalletKey(Coins.DCR, 1).hex()
                        createDCRWallet(args, hex_seed, logger, threading.Event())
                        continue
                    swap_client.waitForDaemonRPC(c, with_wallet=False)
                    # Create wallet if it doesn't exist yet
                    wallets = swap_client.callcoinrpc(c, 'listwallets')
                    if len(wallets) < 1:
                        logger.info('Creating wallet.dat for {}.'.format(getCoinName(c)))

                        if c in (Coins.BTC, Coins.LTC, Coins.DASH):
                            # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
                            swap_client.callcoinrpc(c, 'createwallet', ['wallet.dat', False, True, WALLET_ENCRYPTION_PWD, False, False])
                            swap_client.ci(c).unlockWallet(WALLET_ENCRYPTION_PWD)
                        else:
                            swap_client.callcoinrpc(c, 'createwallet', ['wallet.dat'])
                            if WALLET_ENCRYPTION_PWD != '':
                                encrypt_wallet(swap_client, c)

                        if c == Coins.LTC:
                            password = WALLET_ENCRYPTION_PWD if WALLET_ENCRYPTION_PWD != '' else None
                            swap_client.ci(Coins.LTC_MWEB).init_wallet(password)

                if c == Coins.PART:
                    if 'particl' in with_coins:
                        logger.info('Loading Particl mnemonic')
                        if particl_wallet_mnemonic is None:
                            particl_wallet_mnemonic = swap_client.callcoinrpc(Coins.PART, 'mnemonic', ['new'])['mnemonic']
                            generated_mnemonic = True
                        swap_client.callcoinrpc(Coins.PART, 'extkeyimportmaster', [particl_wallet_mnemonic])
                    # Particl wallet must be unlocked to call getWalletKey
                    if WALLET_ENCRYPTION_PWD != '':
                        swap_client.ci(c).unlockWallet(WALLET_ENCRYPTION_PWD)

            for coin_name in with_coins:
                c = swap_client.getCoinIdFromName(coin_name)
                if c in (Coins.PART, ):
                    continue
                if c not in (Coins.DCR, ):
                    # initialiseWallet only sets main_wallet_seedid_
                    swap_client.waitForDaemonRPC(c)
                try:
                    swap_client.initialiseWallet(c, raise_errors=True)
                except Exception as e:
                    coins_failed_to_initialise.append((c, e))
                if WALLET_ENCRYPTION_PWD != '' and c not in coins_to_create_wallets_for:
                    try:
                        swap_client.ci(c).changeWalletPassword('', WALLET_ENCRYPTION_PWD)
                    except Exception as e:
                        logger.warning(f'changeWalletPassword failed for {coin_name}.')

        finally:
            if swap_client:
                swap_client.finalise()
                del swap_client
            for d in daemons:
                finalise_daemon(d)

    print('')
    for pair in coins_failed_to_initialise:
        c, e = pair
        if c in (Coins.PIVX, ):
            print(f'NOTE - Unable to initialise wallet for {getCoinName(c)}.  To complete setup click \'Reseed Wallet\' from the ui page once chain is synced.')
        else:
            print(f'WARNING - Failed to initialise wallet for {getCoinName(c)}: {e}')

    if 'decred' in with_coins and WALLET_ENCRYPTION_PWD != '':
        print('WARNING - dcrwallet requires the password to be entered at the first startup when encrypted.\nPlease use basicswap-run with --startonlycoin=decred and the WALLET_ENCRYPTION_PWD environment var set for the initial sync.')

    if particl_wallet_mnemonic is not None:
        if generated_mnemonic:
            # Print directly to stdout for tests
            print('IMPORTANT - Save your particl wallet recovery phrase:\n{}\n'.format(particl_wallet_mnemonic))


def load_config(config_path):
    if not os.path.exists(config_path):
        exitWithError('{} does not exist'.format(config_path))
    with open(config_path) as fs:
        return json.load(fs)


def signal_handler(sig, frame):
    logger.info('Signal %d detected' % (sig))


def check_btc_fastsync_data(base_dir, sync_file_path):
    github_pgp_url = 'https://raw.githubusercontent.com/basicswap/basicswap/master/pgp'
    gitlab_pgp_url = 'https://gitlab.com/particl/basicswap/-/raw/master/pgp'
    asc_filename = BITCOIN_FASTSYNC_FILE + '.asc'
    asc_file_path = os.path.join(base_dir, asc_filename)
    if not os.path.exists(asc_file_path):
        asc_file_urls = (
            github_pgp_url + '/sigs/' + asc_filename,
            gitlab_pgp_url + '/sigs/' + asc_filename,
        )
        for url in asc_file_urls:
            try:
                downloadFile(url, asc_file_path)
                break
            except Exception as e:
                logging.warning('Download failed: %s', str(e))
    gpg = gnupg.GPG()
    pubkey_filename = '{}_{}.pgp'.format('particl', 'tecnovert')
    pubkeyurls = [
        github_pgp_url + '/keys/' + pubkey_filename,
        gitlab_pgp_url + '/keys/' + pubkey_filename,
    ]
    if not havePubkey(gpg, expected_key_ids['tecnovert'][0]):
        importPubkeyFromUrls(gpg, pubkeyurls)
    with open(asc_file_path, 'rb') as fp:
        verified = gpg.verify_file(fp, sync_file_path)

    ensureValidSignatureBy(verified, 'tecnovert')


def ensure_coin_valid(coin: str, test_disabled: bool = True) -> None:
    if coin not in known_coins:
        exitWithError(f'Unknown coin {coin.capitalize()}')
    if test_disabled and not OVERRIDE_DISABLED_COINS and coin in disabled_coins:
        exitWithError(f'{coin.capitalize()} is disabled')


def main():
    global use_tor_proxy
    data_dir = None
    bin_dir = None
    port_offset = None
    chain = 'mainnet'
    particl_wallet_mnemonic = None
    with_coins = {'particl', }
    add_coin = ''
    disable_coin = ''
    coins_changed = False
    htmlhost = '127.0.0.1'
    xmr_restore_height = DEFAULT_XMR_RESTORE_HEIGHT
    wow_restore_height = DEFAULT_WOW_RESTORE_HEIGHT
    prepare_bin_only = False
    no_cores = False
    enable_tor = False
    disable_tor = False
    initwalletsonly = False
    tor_control_password = None
    extra_opts = {}

    if os.getenv('SSL_CERT_DIR', '') == '' and GUIX_SSL_CERT_DIR is not None:
        os.environ['SSL_CERT_DIR'] = GUIX_SSL_CERT_DIR

    if os.name == 'nt':
        # On windows sending signal.CTRL_C_EVENT to a subprocess causes it to be sent to the parent process too
        signal.signal(signal.SIGINT, signal_handler)

    for v in sys.argv[1:]:
        if len(v) < 2 or v[0] != '-':
            exitWithError('Unknown argument {}'.format(v))

        s = v.split('=')
        name = s[0].strip()

        for i in range(2):
            if name[0] == '-':
                name = name[1:]

        if name == 'v' or name == 'version':
            printVersion()
            return 0
        if name == 'h' or name == 'help':
            printHelp()
            return 0

        if name in ('mainnet', 'testnet', 'regtest'):
            chain = name
            continue
        if name == 'preparebinonly':
            prepare_bin_only = True
            continue
        if name == 'nocores':
            no_cores = True
            continue
        if name == 'usecontainers':
            extra_opts['use_containers'] = True
            continue
        if name == 'noextractover':
            extra_opts['extract_core_overwrite'] = False
            continue
        if name == 'usetorproxy':
            use_tor_proxy = True
            continue
        if name == 'notorproxy':
            extra_opts['no_tor_proxy'] = True
            continue
        if name == 'enabletor':
            enable_tor = True
            continue
        if name == 'disabletor':
            disable_tor = True
            continue
        if name == 'usebtcfastsync':
            extra_opts['use_btc_fastsync'] = True
            continue
        if name == 'skipbtcfastsyncchecks':
            extra_opts['check_btc_fastsync'] = False
            continue
        if name == 'trustremotenode':
            extra_opts['trust_remote_node'] = True
            continue
        if name == 'noreleasesizecheck':
            extra_opts['verify_release_file_size'] = False
            continue
        if name == 'redownloadreleases':
            extra_opts['redownload_releases'] = True
            continue
        if name == 'initwalletsonly':
            initwalletsonly = True
            continue
        if name == 'dashv20compatible':
            extra_opts['dash_v20_compatible'] = True
            continue
        if len(s) == 2:
            if name == 'datadir':
                data_dir = os.path.expanduser(s[1].strip('"'))
                continue
            if name == 'bindir':
                bin_dir = os.path.expanduser(s[1].strip('"'))
                continue
            if name == 'portoffset':
                port_offset = int(s[1])
                continue
            if name == 'particl_mnemonic':
                particl_wallet_mnemonic = s[1].strip('"')
                continue
            if name in ('withcoin', 'withcoins'):
                for coin in [s.strip().lower() for s in s[1].split(',')]:
                    ensure_coin_valid(coin)
                    with_coins.add(coin)
                coins_changed = True
                continue
            if name in ('withoutcoin', 'withoutcoins'):
                for coin in [s.strip().lower() for s in s[1].split(',')]:
                    ensure_coin_valid(coin, test_disabled=False)
                    with_coins.discard(coin)
                coins_changed = True
                continue
            if name == 'addcoin':
                add_coin = s[1].strip().lower()
                ensure_coin_valid(add_coin)
                with_coins = {add_coin, }
                continue
            if name == 'disablecoin':
                disable_coin = s[1].strip().lower()
                ensure_coin_valid(disable_coin, test_disabled=False)
                continue
            if name == 'htmlhost':
                htmlhost = s[1].strip('"')
                continue
            if name == 'wshost':
                extra_opts['wshost'] = s[1].strip('"')
                continue
            if name == 'xmrrestoreheight':
                xmr_restore_height = int(s[1])
                continue
            if name == 'wowrestoreheight':
                wow_restore_height = int(s[1])
                continue
            if name == 'keysdirpath':
                extra_opts['keysdirpath'] = os.path.expanduser(s[1].strip('"'))
                continue
            if name == 'trustremotenode':
                extra_opts['trust_remote_node'] = toBool(s[1])
                continue

        exitWithError('Unknown argument {}'.format(v))

    if data_dir is None:
        data_dir = os.path.join(os.path.expanduser(cfg.BASICSWAP_DATADIR))
    if bin_dir is None:
        bin_dir = os.path.join(data_dir, 'bin')

    logger.info(f'BasicSwap prepare script {__version__}\n')
    logger.info(f'Python version: {platform.python_version()}')
    logger.info(f'Data dir: {data_dir}')
    logger.info(f'Bin dir: {bin_dir}')
    logger.info(f'Chain: {chain}')
    logger.info('WALLET_ENCRYPTION_PWD is {}set'.format('not ' if WALLET_ENCRYPTION_PWD == '' else ''))

    if port_offset is None:
        port_offset = 300 if chain == 'testnet' else 0

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    config_path = os.path.join(data_dir, cfg.CONFIG_FILENAME)

    if use_tor_proxy and extra_opts.get('no_tor_proxy', False):
        exitWithError('Can\'t use --usetorproxy and --notorproxy together')

    # Automatically enable usetorproxy for certain commands if it's set in basicswap config
    if not (initwalletsonly or enable_tor or disable_tor or disable_coin) and \
       not use_tor_proxy and os.path.exists(config_path):
        settings = load_config(config_path)
        settings_use_tor = settings.get('use_tor', False)
        if settings_use_tor:
            logger.info('use_tor is set in the config')
            if extra_opts.get('no_tor_proxy', False):
                use_tor_proxy = False
                logger.warning('Not automatically setting --usetorproxy as --notorproxy is set')
            else:
                use_tor_proxy = True
                logger.info('Automatically setting --usetorproxy')

    setConnectionParameters(allow_set_tor=False)

    if use_tor_proxy and TEST_TOR_PROXY:
        testTorConnection()

    if use_tor_proxy and TEST_ONION_LINK:
        testOnionLink()

    should_download_btc_fastsync = False
    if extra_opts.get('use_btc_fastsync', False) is True:
        if 'bitcoin' in with_coins or add_coin == 'bitcoin':
            should_download_btc_fastsync = True
        else:
            logger.warning('Ignoring usebtcfastsync option without Bitcoin selected.')

    if should_download_btc_fastsync:
        logger.info(f'Preparing BTC Fastsync file {BITCOIN_FASTSYNC_FILE}')
        sync_file_path = os.path.join(data_dir, BITCOIN_FASTSYNC_FILE)
        sync_file_url = os.path.join(BITCOIN_FASTSYNC_URL, BITCOIN_FASTSYNC_FILE)
        try:
            check_btc_fastsync = extra_opts.get('check_btc_fastsync', True)
            check_sig = False
            if not os.path.exists(sync_file_path):
                downloadFile(sync_file_url, sync_file_path, timeout=50)
                check_sig = check_btc_fastsync
            elif check_btc_fastsync:
                file_size = os.stat(sync_file_path).st_size
                remote_file_length, can_resume = getRemoteFileLength(sync_file_url)
                if file_size < remote_file_length:
                    logger.warning(f'{BITCOIN_FASTSYNC_FILE} is an unexpected size, {file_size} < {remote_file_length}')
                    if not can_resume:
                        logger.warning(f'{BITCOIN_FASTSYNC_URL} can not be resumed, restarting download.')
                        file_size = 0
                    downloadFile(sync_file_url, sync_file_path, timeout=50, resume_from=file_size)
                    check_sig = True

            if check_sig:
                check_btc_fastsync_data(data_dir, sync_file_path)
        except Exception as e:
            logger.error(f'Failed to download BTC fastsync file: {e}\nRe-running the command should resume the download or try manually downloading from {sync_file_url}')
            return 1

    withchainclients = {}
    chainclients = {
        'particl': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('PART'),
            'rpchost': PART_RPC_HOST,
            'rpcport': PART_RPC_PORT + port_offset,
            'onionport': PART_ONION_PORT + port_offset,
            'datadir': os.getenv('PART_DATA_DIR', os.path.join(data_dir, 'particl')),
            'bindir': os.path.join(bin_dir, 'particl'),
            'blocks_confirmed': 2,
            'override_feerate': 0.002,
            'conf_target': 2,
            'core_version_group': 21,
        },
        'bitcoin': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('BTC'),
            'rpchost': BTC_RPC_HOST,
            'rpcport': BTC_RPC_PORT + port_offset,
            'onionport': BTC_ONION_PORT + port_offset,
            'datadir': os.getenv('BTC_DATA_DIR', os.path.join(data_dir, 'bitcoin')),
            'bindir': os.path.join(bin_dir, 'bitcoin'),
            'use_segwit': True,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 22,
        },
        'litecoin': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('LTC'),
            'rpchost': LTC_RPC_HOST,
            'rpcport': LTC_RPC_PORT + port_offset,
            'onionport': LTC_ONION_PORT + port_offset,
            'datadir': os.getenv('LTC_DATA_DIR', os.path.join(data_dir, 'litecoin')),
            'bindir': os.path.join(bin_dir, 'litecoin'),
            'use_segwit': True,
            'blocks_confirmed': 2,
            'conf_target': 2,
            'core_version_group': 21,
            'min_relay_fee': 0.00001,
        },
        'decred': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('DCR'),
            'manage_wallet_daemon': shouldManageDaemon('DCR_WALLET'),
            'wallet_pwd': DCR_WALLET_PWD if WALLET_ENCRYPTION_PWD == '' else '',
            'rpchost': DCR_RPC_HOST,
            'rpcport': DCR_RPC_PORT + port_offset,
            'walletrpchost': DCR_WALLET_RPC_HOST,
            'walletrpcport': DCR_WALLET_RPC_PORT + port_offset,
            'rpcuser': DCR_RPC_USER,
            'rpcpassword': DCR_RPC_PWD,
            'datadir': os.getenv('DCR_DATA_DIR', os.path.join(data_dir, 'decred')),
            'bindir': os.path.join(bin_dir, 'decred'),
            'use_csv': True,
            'use_segwit': True,
            'blocks_confirmed': 2,
            'conf_target': 2,
            'core_type_group': 'dcr',
            'min_relay_fee': 0.00001,
        },
        'namecoin': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('NMC'),
            'rpchost': NMC_RPC_HOST,
            'rpcport': NMC_RPC_PORT + port_offset,
            'datadir': os.getenv('NMC_DATA_DIR', os.path.join(data_dir, 'namecoin')),
            'bindir': os.path.join(bin_dir, 'namecoin'),
            'use_segwit': False,
            'use_csv': False,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 18,
            'chain_lookups': 'local',
        },
        'monero': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('XMR'),
            'manage_wallet_daemon': shouldManageDaemon('XMR_WALLET'),
            'rpcport': XMR_RPC_PORT + port_offset,
            'zmqport': XMR_ZMQ_PORT + port_offset,
            'walletrpcport': XMR_WALLET_RPC_PORT + port_offset,
            'rpchost': XMR_RPC_HOST,
            'trusted_daemon': extra_opts.get('trust_remote_node', 'auto'),
            'walletrpchost': XMR_WALLET_RPC_HOST,
            'walletrpcuser': XMR_WALLET_RPC_USER,
            'walletrpcpassword': XMR_WALLET_RPC_PWD,
            'walletfile': 'swap_wallet',
            'datadir': os.getenv('XMR_DATA_DIR', os.path.join(data_dir, 'monero')),
            'bindir': os.path.join(bin_dir, 'monero'),
            'restore_height': xmr_restore_height,
            'blocks_confirmed': 3,
            'rpctimeout': 60,
            'walletrpctimeout': 120,
            'walletrpctimeoutlong': 600,
            'core_type_group': 'xmr',
        },
        'pivx': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('PIVX'),
            'rpchost': PIVX_RPC_HOST,
            'rpcport': PIVX_RPC_PORT + port_offset,
            'onionport': PIVX_ONION_PORT + port_offset,
            'datadir': os.getenv('PIVX_DATA_DIR', os.path.join(data_dir, 'pivx')),
            'bindir': os.path.join(bin_dir, 'pivx'),
            'use_segwit': False,
            'use_csv': False,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 17,
        },
        'dash': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('DASH'),
            'rpchost': DASH_RPC_HOST,
            'rpcport': DASH_RPC_PORT + port_offset,
            'onionport': DASH_ONION_PORT + port_offset,
            'datadir': os.getenv('DASH_DATA_DIR', os.path.join(data_dir, 'dash')),
            'bindir': os.path.join(bin_dir, 'dash'),
            'use_segwit': False,
            'use_csv': True,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 18,
        },
        'firo': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('FIRO'),
            'rpchost': FIRO_RPC_HOST,
            'rpcport': FIRO_RPC_PORT + port_offset,
            'onionport': FIRO_ONION_PORT + port_offset,
            'datadir': os.getenv('FIRO_DATA_DIR', os.path.join(data_dir, 'firo')),
            'bindir': os.path.join(bin_dir, 'firo'),
            'use_segwit': False,
            'use_csv': False,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 14,
            'min_relay_fee': 0.00001,
        },
        'navcoin': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('NAV'),
            'rpchost': NAV_RPC_HOST,
            'rpcport': NAV_RPC_PORT + port_offset,
            'onionport': NAV_ONION_PORT + port_offset,
            'datadir': os.getenv('NAV_DATA_DIR', os.path.join(data_dir, 'navcoin')),
            'bindir': os.path.join(bin_dir, 'navcoin'),
            'use_segwit': True,
            'use_csv': True,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 18,
            'chain_lookups': 'local',
            'startup_tries': 40,
        },
        'wownero': {
            'connection_type': 'rpc',
            'manage_daemon': shouldManageDaemon('WOW'),
            'manage_wallet_daemon': shouldManageDaemon('WOW_WALLET'),
            'rpcport': WOW_RPC_PORT + port_offset,
            'zmqport': WOW_ZMQ_PORT + port_offset,
            'walletrpcport': WOW_WALLET_RPC_PORT + port_offset,
            'rpchost': WOW_RPC_HOST,
            'trusted_daemon': extra_opts.get('trust_remote_node', 'auto'),
            'walletrpchost': WOW_WALLET_RPC_HOST,
            'walletrpcuser': WOW_WALLET_RPC_USER,
            'walletrpcpassword': WOW_WALLET_RPC_PWD,
            'walletfile': 'swap_wallet',
            'datadir': os.getenv('WOW_DATA_DIR', os.path.join(data_dir, 'wownero')),
            'bindir': os.path.join(bin_dir, 'wownero'),
            'restore_height': wow_restore_height,
            'blocks_confirmed': 2,
            'rpctimeout': 60,
            'walletrpctimeout': 120,
            'walletrpctimeoutlong': 300,
            'core_type_group': 'xmr',
        }
    }

    if PART_RPC_USER != '':
        chainclients['particl']['rpcuser'] = PART_RPC_USER
        chainclients['particl']['rpcpassword'] = PART_RPC_PWD
    if LTC_RPC_USER != '':
        chainclients['litecoin']['rpcuser'] = LTC_RPC_USER
        chainclients['litecoin']['rpcpassword'] = LTC_RPC_PWD
    if BTC_RPC_USER != '':
        chainclients['bitcoin']['rpcuser'] = BTC_RPC_USER
        chainclients['bitcoin']['rpcpassword'] = BTC_RPC_PWD
    if XMR_RPC_USER != '':
        chainclients['monero']['rpcuser'] = XMR_RPC_USER
        chainclients['monero']['rpcpassword'] = XMR_RPC_PWD
    if WOW_RPC_USER != '':
        chainclients['wownero']['rpcuser'] = WOW_RPC_USER
        chainclients['wownero']['rpcpassword'] = WOW_RPC_PWD
    if PIVX_RPC_USER != '':
        chainclients['pivx']['rpcuser'] = PIVX_RPC_USER
        chainclients['pivx']['rpcpassword'] = PIVX_RPC_PWD
    if DASH_RPC_USER != '':
        chainclients['dash']['rpcuser'] = DASH_RPC_USER
        chainclients['dash']['rpcpassword'] = DASH_RPC_PWD
    if FIRO_RPC_USER != '':
        chainclients['firo']['rpcuser'] = FIRO_RPC_USER
        chainclients['firo']['rpcpassword'] = FIRO_RPC_PWD
    if NAV_RPC_USER != '':
        chainclients['nav']['rpcuser'] = NAV_RPC_USER
        chainclients['nav']['rpcpassword'] = NAV_RPC_PWD

    chainclients['monero']['walletsdir'] = os.getenv('XMR_WALLETS_DIR', chainclients['monero']['datadir'])
    chainclients['wownero']['walletsdir'] = os.getenv('WOW_WALLETS_DIR', chainclients['wownero']['datadir'])

    if extra_opts.get('dash_v20_compatible', False):
        chainclients['dash']['wallet_v20_compatible'] = True

    if initwalletsonly:
        logger.info('Initialising wallets')
        settings = load_config(config_path)

        init_coins = settings['chainclients'].keys()
        logger.info('Active coins: %s', ', '.join(init_coins))
        if coins_changed:
            init_coins = with_coins
            logger.info('Initialising coins: %s', ', '.join(init_coins))
        initialise_wallets(particl_wallet_mnemonic, init_coins, data_dir, settings, chain, use_tor_proxy)

        print('Done.')
        return 0

    if enable_tor:
        logger.info('Enabling TOR')
        settings = load_config(config_path)

        tor_control_password = settings.get('tor_control_password', None)
        if tor_control_password is None:
            tor_control_password = generate_salt(24)
            settings['tor_control_password'] = tor_control_password
        write_torrc(data_dir, tor_control_password)

        addTorSettings(settings, tor_control_password)
        for coin in settings['chainclients']:
            modify_tor_config(settings, coin, tor_control_password, enable=True, extra_opts=extra_opts)

        with open(config_path, 'w') as fp:
            json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    if disable_tor:
        logger.info('Disabling TOR')
        settings = load_config(config_path)
        settings['use_tor'] = False
        for coin in settings['chainclients']:
            modify_tor_config(settings, coin, tor_control_password=None, enable=False, extra_opts=extra_opts)

        with open(config_path, 'w') as fp:
            json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    if disable_coin != '':
        logger.info('Disabling coin: %s', disable_coin)
        settings = load_config(config_path)

        if disable_coin not in settings['chainclients']:
            exitWithError(f'{disable_coin} not configured')

        coin_settings = settings['chainclients'][disable_coin]
        if coin_settings['connection_type'] == 'none' and coin_settings['manage_daemon'] is False:
            exitWithError(f'{disable_coin} is already disabled')
        coin_settings['connection_type'] = 'none'
        coin_settings['manage_daemon'] = False

        with open(config_path, 'w') as fp:
            json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    extra_opts['data_dir'] = data_dir
    extra_opts['tor_control_password'] = tor_control_password

    if add_coin != '':
        logger.info('Adding coin: %s', add_coin)
        settings = load_config(config_path)
        if tor_control_password is None and settings.get('use_tor', False):
            extra_opts['tor_control_password'] = settings.get('tor_control_password', None)

        if particl_wallet_mnemonic != 'none':
            # Ensure Particl wallet is unencrypted or correct password is supplied
            test_particl_encryption(data_dir, settings, chain, use_tor_proxy)

        if add_coin in settings['chainclients']:
            coin_settings = settings['chainclients'][add_coin]
            if coin_settings['connection_type'] == 'none' and coin_settings['manage_daemon'] is False:
                logger.info('Enabling coin: %s', add_coin)
                coin_settings['connection_type'] = 'rpc'
                coin_settings['manage_daemon'] = True
                with open(config_path, 'w') as fp:
                    json.dump(settings, fp, indent=4)
                logger.info('Done.')
                return 0
            exitWithError('{} is already in the settings file'.format(add_coin))

        settings['chainclients'][add_coin] = chainclients[add_coin]
        settings['use_tor_proxy'] = use_tor_proxy

        if not no_cores:
            prepareCore(add_coin, known_coins[add_coin], settings, data_dir, extra_opts)

        if not prepare_bin_only:
            prepareDataDir(add_coin, settings, chain, particl_wallet_mnemonic, extra_opts)

            if particl_wallet_mnemonic != 'none':
                initialise_wallets(None, {add_coin, }, data_dir, settings, chain, use_tor_proxy)

            with open(config_path, 'w') as fp:
                json.dump(settings, fp, indent=4)

        logger.info(f'Done. Coin {add_coin} successfully added.')
        return 0

    logger.info('With coins: %s', ', '.join(with_coins))
    if os.path.exists(config_path):
        if not prepare_bin_only:
            exitWithError('{} exists'.format(config_path))
        else:
            with open(config_path) as fs:
                settings = json.load(fs)

                # Add temporary default config for any coins that have not been added
                for c in with_coins:
                    if c not in settings['chainclients']:
                        settings['chainclients'][c] = chainclients[c]
    else:
        for c in with_coins:
            withchainclients[c] = chainclients[c]

        settings = {
            'debug': True,
            'zmqhost': f'tcp://{PART_RPC_HOST}',
            'zmqport': PART_ZMQ_PORT + port_offset,
            'htmlhost': htmlhost,
            'htmlport': UI_HTML_PORT + port_offset,
            'network_key': '7sW2UEcHXvuqEjkpE5mD584zRaQYs6WXYohue4jLFZPTvMSxwvgs',
            'network_pubkey': '035758c4a22d7dd59165db02a56156e790224361eb3191f02197addcb3bde903d2',
            'chainclients': withchainclients,
            'min_delay_event': 5,  # Min delay in seconds before reacting to an event
            'max_delay_event': 50,  # Max delay in seconds before reacting to an event
            'check_progress_seconds': 60,
            'check_watched_seconds': 60,
            'check_expired_seconds': 60,
            'wallet_update_timeout': 10,  # Seconds to wait for wallet page update
        }

        wshost: str = extra_opts.get('wshost', htmlhost)
        if wshost != 'none':
            settings['wshost'] = wshost
            settings['wsport'] = UI_WS_PORT + port_offset

    if use_tor_proxy:
        tor_control_password = generate_salt(24)
        addTorSettings(settings, tor_control_password)

    if not no_cores:
        for c in with_coins:
            prepareCore(c, known_coins[c], settings, data_dir, extra_opts)

    if prepare_bin_only:
        logger.info('Done.')
        return 0

    for c in with_coins:
        prepareDataDir(c, settings, chain, particl_wallet_mnemonic, extra_opts)

    with open(config_path, 'w') as fp:
        json.dump(settings, fp, indent=4)

    if particl_wallet_mnemonic == 'none':
        logger.info('Done.')
        return 0

    initialise_wallets(particl_wallet_mnemonic, with_coins, data_dir, settings, chain, use_tor_proxy)
    print('Done.')


if __name__ == '__main__':
    main()
