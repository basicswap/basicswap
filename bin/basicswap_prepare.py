#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import json
import mmap
import stat
import gnupg
import socks
import shutil
import signal
import socket
import hashlib
import tarfile
import zipfile
import logging
import platform
import urllib.parse
from urllib.request import urlretrieve

import basicswap.config as cfg
from basicswap.base import getaddrinfo_tor
from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from basicswap.util import toBool
from basicswap.util.rfc2440 import rfc2440_hash_password
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from bin.basicswap_run import startDaemon, startXmrWalletDaemon

PARTICL_VERSION = os.getenv('PARTICL_VERSION', '0.21.2.9')
PARTICL_VERSION_TAG = os.getenv('PARTICL_VERSION_TAG', '')
PARTICL_LINUX_EXTRA = os.getenv('PARTICL_LINUX_EXTRA', '_nousb')

LITECOIN_VERSION = os.getenv('LITECOIN_VERSION', '0.21.2')
LITECOIN_VERSION_TAG = os.getenv('LITECOIN_VERSION_TAG', '')

BITCOIN_VERSION = os.getenv('BITCOIN_VERSION', '22.0')
BITCOIN_VERSION_TAG = os.getenv('BITCOIN_VERSION_TAG', '')

MONERO_VERSION = os.getenv('MONERO_VERSION', '0.18.0.0')
MONERO_VERSION_TAG = os.getenv('MONERO_VERSION_TAG', '')
XMR_SITE_COMMIT = 'f093c0da2219d94e6bef5f3948ac61b4ecdcb95b'  # Lock hashes.txt to monero version

# version, version tag eg. "rc1", signers
known_coins = {
    'particl': (PARTICL_VERSION, PARTICL_VERSION_TAG, ('tecnovert',)),
    'litecoin': (LITECOIN_VERSION, LITECOIN_VERSION_TAG, ('davidburkett38',)),
    'bitcoin': (BITCOIN_VERSION, BITCOIN_VERSION_TAG, ('laanwj',)),
    'namecoin': ('0.18.0', '', ('JeremyRand',)),
    'monero': (MONERO_VERSION, MONERO_VERSION_TAG, ('binaryfate',)),
}

expected_key_ids = {
    'tecnovert': ('13F13651C9CF0D6B',),
    'thrasher': ('FE3348877809386C',),
    'laanwj': ('1E4AED62986CD25D',),
    'JeremyRand': ('2DBE339E29F6294C',),
    'binaryfate': ('F0AF4D462A0BDF92',),
    'davidburkett38': ('3620E9D387E55666',),
}

if platform.system() == 'Darwin':
    BIN_ARCH = 'osx64'
    FILE_EXT = 'tar.gz'
elif platform.system() == 'Windows':
    BIN_ARCH = 'win64'
    FILE_EXT = 'zip'
else:
    BIN_ARCH = 'x86_64-linux-gnu'
    FILE_EXT = 'tar.gz'

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

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
BASE_XMR_RPC_PORT = int(os.getenv('BASE_XMR_RPC_PORT', 29798))
BASE_XMR_ZMQ_PORT = int(os.getenv('BASE_XMR_ZMQ_PORT', 30898))
BASE_XMR_WALLET_PORT = int(os.getenv('BASE_XMR_WALLET_PORT', 29998))
XMR_WALLET_RPC_HOST = os.getenv('XMR_WALLET_RPC_HOST', '127.0.0.1')
XMR_WALLET_RPC_USER = os.getenv('XMR_WALLET_RPC_USER', 'xmr_wallet_user')
XMR_WALLET_RPC_PWD = os.getenv('XMR_WALLET_RPC_PWD', 'xmr_wallet_pwd')
DEFAULT_XMR_RESTORE_HEIGHT = int(os.getenv('DEFAULT_XMR_RESTORE_HEIGHT', 2245107))

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

NMC_RPC_HOST = os.getenv('NMC_RPC_HOST', '127.0.0.1')
NMC_RPC_PORT = int(os.getenv('NMC_RPC_PORT', 19698))

TOR_PROXY_HOST = os.getenv('TOR_PROXY_HOST', '127.0.0.1')
TOR_PROXY_PORT = int(os.getenv('TOR_PROXY_PORT', 9050))
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', 9051))
TOR_DNS_PORT = int(os.getenv('TOR_DNS_PORT', 5353))
TEST_TOR_PROXY = toBool(os.getenv('TEST_TOR_PROXY', 'true'))  # Expects a known exit node
TEST_ONION_LINK = toBool(os.getenv('TEST_ONION_LINK', 'false'))

BITCOIN_FASTSYNC_URL = os.getenv('BITCOIN_FASTSYNC_URL', 'http://utxosets.blob.core.windows.net/public/')
BITCOIN_FASTSYNC_FILE = os.getenv('BITCOIN_FASTSYNC_FILE', 'utxo-snapshot-bitcoin-mainnet-720179.tar')

use_tor_proxy = False

default_socket = socket.socket
default_socket_timeout = socket.getdefaulttimeout()
default_socket_getaddrinfo = socket.getaddrinfo


def make_reporthook():
    read = 0  # Number of bytes read so far
    last_percent_str = ''

    def reporthook(blocknum, blocksize, totalsize):
        nonlocal read
        nonlocal last_percent_str
        read += blocksize
        if totalsize > 0:
            percent_str = '%5.0f%%' % (read * 1e2 / totalsize)
            if percent_str != last_percent_str:
                logger.info(percent_str)
                last_percent_str = percent_str
        else:
            logger.info('read %d' % (read,))
    return reporthook


def setConnectionParameters():
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)

    if use_tor_proxy:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT, rdns=True)
        socket.socket = socks.socksocket
        socket.getaddrinfo = getaddrinfo_tor  # Without this accessing .onion links would fail

    # Set low timeout for urlretrieve connections
    socket.setdefaulttimeout(5)


def popConnectionParameters():
    if use_tor_proxy:
        socket.socket = default_socket
        socket.getaddrinfo = default_socket_getaddrinfo
    socket.setdefaulttimeout(default_socket_timeout)


def downloadFile(url, path):
    logger.info('Downloading file %s', url)
    logger.info('To %s', path)
    try:
        setConnectionParameters()
        urlretrieve(url, path, make_reporthook())
    finally:
        popConnectionParameters()


def downloadBytes(url):
    try:
        setConnectionParameters()
        return urllib.request.urlopen(url).read()
    finally:
        popConnectionParameters()


def testTorConnection():
    test_url = 'https://check.torproject.org/'
    logger.info('Testing TOR connection at: ' + test_url)

    test_response = downloadBytes(test_url).decode('utf-8')
    assert('Congratulations. This browser is configured to use Tor.' in test_response)
    logger.info('TOR is working.')


def testOnionLink():
    test_url = 'http://jqyzxhjk6psc6ul5jnfwloamhtyh7si74b4743k2qgpskwwxrzhsxmad.onion'
    logger.info('Testing onion site: ' + test_url)
    test_response = downloadBytes(test_url).decode('utf-8')
    assert('The Tor Project\'s free software protects your privacy online.' in test_response)
    logger.info('Onion links work.')


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

    if coin == 'monero':
        bins = ['monerod', 'monero-wallet-rpc']
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

    bins = [coin + 'd', coin + '-cli', coin + '-tx']
    versions = version.split('.')
    if int(versions[0]) >= 22 or int(versions[1]) >= 19:
        bins.append(coin + '-wallet')
    if 'win32' in BIN_ARCH or 'win64' in BIN_ARCH:
        with zipfile.ZipFile(release_path) as fz:
            for b in bins:
                b += '.exe'
                out_path = os.path.join(bin_dir, b)
                if (not os.path.exists(out_path)) or extract_core_overwrite:
                    with open(out_path, 'wb') as fout:
                        fout.write(fz.read('{}-{}/bin/{}'.format(coin, version, b)))
                    try:
                        os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
                    except Exception as e:
                        logging.warning('Unable to set file permissions: %s, for %s', str(e), out_path)
    else:
        with tarfile.open(release_path) as ft:
            for b in bins:
                out_path = os.path.join(bin_dir, b)
                if not os.path.exists(out_path) or extract_core_overwrite:
                    with open(out_path, 'wb') as fout, ft.extractfile('{}-{}/bin/{}'.format(coin, version + version_tag, b)) as fi:
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
        release_url = 'https://downloads.getmonero.org/cli/monero-{}-x64-v{}.{}'.format(os_name, version, use_file_ext)
        release_path = os.path.join(bin_dir, release_filename)
        if not os.path.exists(release_path):
            downloadFile(release_url, release_path)

        assert_filename = 'monero-{}-hashes.txt'.format(version)
        # assert_url = 'https://www.getmonero.org/downloads/hashes.txt'
        assert_url = 'https://raw.githubusercontent.com/monero-project/monero-site/{}/downloads/hashes.txt'.format(XMR_SITE_COMMIT)
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            downloadFile(assert_url, assert_path)
    else:
        major_version = int(version.split('.')[0])
        release_filename = '{}-{}-{}{}.{}'.format(coin, version + version_tag, BIN_ARCH, filename_extra, FILE_EXT)
        if coin == 'particl':
            release_url = 'https://github.com/particl/particl-core/releases/download/v{}/{}'.format(version + version_tag, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version)
            assert_url = 'https://raw.githubusercontent.com/particl/gitian.sigs/master/%s-%s/%s/%s' % (version + version_tag, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'litecoin':
            release_url = 'https://download.litecoin.org/litecoin-{}/{}/{}'.format(version, os_name, release_filename)
            assert_filename = '{}-core-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
            assert_url = 'https://raw.githubusercontent.com/litecoin-project/gitian.sigs.ltc/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'bitcoin':
            release_url = 'https://bitcoincore.org/bin/bitcoin-core-{}/{}'.format(version, release_filename)
            assert_filename = '{}-core-{}-{}-build.assert'.format(coin, os_name, '.'.join(version.split('.')[:2]))
            if major_version >= 22:
                assert_url = f'https://raw.githubusercontent.com/bitcoin-core/guix.sigs/main/{version}/{signing_key_name}/all.SHA256SUMS'
            else:
                assert_url = 'https://raw.githubusercontent.com/bitcoin-core/gitian.sigs/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'namecoin':
            release_url = 'https://beta.namecoin.org/files/namecoin-core/namecoin-core-{}/{}'.format(version, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
            assert_url = 'https://raw.githubusercontent.com/namecoin/gitian.sigs/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        else:
            raise ValueError('Unknown coin')

        assert_sig_filename = assert_filename + '.sig'
        assert_sig_url = assert_url + ('.asc' if major_version >= 22 else '.sig')

        release_path = os.path.join(bin_dir, release_filename)
        if not os.path.exists(release_path):
            downloadFile(release_url, release_path)

        # Rename assert files with full version
        assert_filename = '{}-{}-{}-build-{}.assert'.format(coin, os_name, version, signing_key_name)
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            downloadFile(assert_url, assert_path)

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

    if coin == 'monero':
        with open(assert_path, 'rb') as fp:
            verified = gpg.verify_file(fp)

        if not isValidSignature(verified) and verified.username is None:
            logger.warning('Signature made by unknown key.')

            pubkeyurl = 'https://raw.githubusercontent.com/monero-project/monero/master/utils/gpg_keys/binaryfate.asc'
            logger.info('Importing public key from url: ' + pubkeyurl)
            rv = gpg.import_keys(downloadBytes(pubkeyurl))
            gpg.trust_keys(rv.fingerprints[0], 'TRUST_FULLY')
            with open(assert_path, 'rb') as fp:
                verified = gpg.verify_file(fp)
    else:
        with open(assert_sig_path, 'rb') as fp:
            verified = gpg.verify_file(fp, assert_path)

        if not isValidSignature(verified) and verified.username is None:
            logger.warning('Signature made by unknown key.')

            filename = '{}_{}.pgp'.format(coin, signing_key_name)
            pubkeyurls = (
                'https://raw.githubusercontent.com/tecnovert/basicswap/master/pgp/keys/' + filename,
                'https://gitlab.com/particl/basicswap/-/raw/master/pgp/keys/' + filename,
            )
            for url in pubkeyurls:
                try:
                    logger.info('Importing public key from url: ' + url)
                    rv = gpg.import_keys(downloadBytes(url))
                    break
                except Exception as e:
                    logging.warning('Import from url failed: %s', str(e))

            for key in rv.fingerprints:
                gpg.trust_keys(key, 'TRUST_FULLY')

            with open(assert_sig_path, 'rb') as fp:
                verified = gpg.verify_file(fp, assert_path)

    ensureValidSignatureBy(verified, signing_key_name)

    extractCore(coin, version_data, settings, bin_dir, release_path, extra_opts)


def writeTorSettings(fp, coin, coin_settings, tor_control_password):
    onionport = coin_settings['onionport']
    '''
    TOR_PROXY_HOST must be an ip address.
    BTC versions >21 and Particl with lookuptorcontrolhost=any can accept hostnames, XMR and LTC cannot
    '''
    fp.write(f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}\n')
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

    if coin == 'monero':
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
            if core_settings['manage_daemon'] is False:
                # Assume conf file is for isolated coin docker setup
                config_datadir = '/data'
            fp.write(f'data-dir={config_datadir}\n')
            fp.write('rpc-bind-port={}\n'.format(core_settings['rpcport']))
            fp.write('rpc-bind-ip={}\n'.format(COINS_RPCBIND_IP))
            fp.write('zmq-rpc-bind-port={}\n'.format(core_settings['zmqport']))
            fp.write('zmq-rpc-bind-ip={}\n'.format(COINS_RPCBIND_IP))
            fp.write('prune-blockchain=1\n')

            if tor_control_password is not None:
                fp.write(f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}\n')
                fp.write('proxy-allow-dns-leaks=0\n')
                fp.write('no-igd=1\n')

        wallets_dir = core_settings.get('walletsdir', data_dir)
        if not os.path.exists(wallets_dir):
            os.makedirs(wallets_dir)

        wallet_conf_path = os.path.join(wallets_dir, coin + '_wallet.conf')
        if os.path.exists(wallet_conf_path):
            exitWithError('{} exists'.format(wallet_conf_path))
        with open(wallet_conf_path, 'w') as fp:
            if extra_opts.get('use_containers', False) is True:
                fp.write('daemon-address={}:{}\n'.format(core_settings['rpchost'], core_settings['rpcport']))
            fp.write('untrusted-daemon=1\n')
            fp.write('no-dns=1\n')
            fp.write('rpc-bind-port={}\n'.format(core_settings['walletrpcport']))
            fp.write('rpc-bind-ip={}\n'.format(COINS_RPCBIND_IP))
            config_datadir = os.path.join(data_dir, 'wallets')
            if core_settings['manage_wallet_daemon'] is False:
                # Assume conf file is for isolated coin docker setup
                config_datadir = '/data'
            fp.write(f'wallet-dir={config_datadir}\n')
            fp.write('log-file={}\n'.format(os.path.join(config_datadir, 'wallet.log')))
            fp.write('shared-ringdb-dir={}\n'.format(os.path.join(config_datadir, 'shared-ringdb')))
            fp.write('rpc-login={}:{}\n'.format(core_settings['walletrpcuser'], core_settings['walletrpcpassword']))

            if tor_control_password is not None:
                if not core_settings['manage_daemon']:
                    fp.write(f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}\n')
        return

    core_conf_path = os.path.join(data_dir, coin + '.conf')
    if os.path.exists(core_conf_path):
        exitWithError('{} exists'.format(core_conf_path))
    with open(core_conf_path, 'w') as fp:
        if chain != 'mainnet':
            fp.write(chain + '=1\n')
            if chain == 'testnet':
                fp.write('[test]\n\n')
            if chain == 'regtest':
                fp.write('[regtest]\n\n')
            else:
                logger.warning('Unknown chain %s', chain)

        if COINS_RPCBIND_IP != '127.0.0.1':
            fp.write('rpcallowip=127.0.0.1\n')
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
            if particl_mnemonic == 'auto':
                fp.write('createdefaultmasterkey=1')
        elif coin == 'litecoin':
            fp.write('prune=4000\n')
            fp.write('pid=litecoind.pid\n')
            if LTC_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(LTC_RPC_USER, salt, password_to_hmac(salt, LTC_RPC_PWD)))
        elif coin == 'bitcoin':
            fp.write('prune=2000\n')
            fp.write('fallbackfee=0.0002\n')
            if BTC_RPC_USER != '':
                fp.write('rpcauth={}:{}${}\n'.format(BTC_RPC_USER, salt, password_to_hmac(salt, BTC_RPC_PWD)))
        elif coin == 'namecoin':
            fp.write('prune=2000\n')
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
            sync_file_url = os.path.join(BITCOIN_FASTSYNC_URL, BITCOIN_FASTSYNC_FILE)
            downloadFile(sync_file_url, sync_file_path)

        asc_filename = BITCOIN_FASTSYNC_FILE + '.asc'
        asc_file_path = os.path.join(base_dir, asc_filename)
        if not os.path.exists(asc_file_path):
            asc_file_urls = (
                'https://raw.githubusercontent.com/tecnovert/basicswap/master/pgp/sigs/' + asc_filename,
                'https://gitlab.com/particl/basicswap/-/raw/master/pgp/sigs/' + asc_filename,
            )
            for url in asc_file_urls:
                try:
                    downloadFile(url, asc_file_path)
                    break
                except Exception as e:
                    logging.warning('Download failed: %s', str(e))
        gpg = gnupg.GPG()
        with open(asc_file_path, 'rb') as fp:
            verified = gpg.verify_file(fp, sync_file_path)

        ensureValidSignatureBy(verified, 'tecnovert')

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


def modify_tor_config(settings, coin, tor_control_password=None, enable=False):
    coin_settings = settings['chainclients'][coin]
    data_dir = coin_settings['datadir']

    if coin == 'monero':
        core_conf_path = os.path.join(data_dir, coin + 'd.conf')
        if not os.path.exists(core_conf_path):
            exitWithError('{} does not exist'.format(core_conf_path))
        wallets_dir = coin_settings.get('walletsdir', data_dir)
        wallet_conf_path = os.path.join(wallets_dir, coin + '_wallet.conf')
        if not os.path.exists(wallet_conf_path):
            exitWithError('{} does not exist'.format(wallet_conf_path))

        # Backup
        shutil.copyfile(core_conf_path, core_conf_path + '.last')
        shutil.copyfile(wallet_conf_path, wallet_conf_path + '.last')

        daemon_tor_settings = ('proxy=', 'proxy-allow-dns-leaks=', 'no-igd=')
        with open(core_conf_path, 'w') as fp:
            with open(core_conf_path + '.last') as fp_in:
                # Disable tor first
                for line in fp_in:
                    skip_line = False
                    for setting in daemon_tor_settings:
                        if line.startswith(setting):
                            skip_line = True
                            break
                    if not skip_line:
                        fp.write(line)
            if enable:
                fp.write(f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}\n')
                fp.write('proxy-allow-dns-leaks=0\n')
                fp.write('no-igd=1\n')

        wallet_tor_settings = ('proxy=',)
        with open(wallet_conf_path, 'w') as fp:
            with open(wallet_conf_path + '.last') as fp_in:
                # Disable tor first
                for line in fp_in:
                    skip_line = False
                    for setting in wallet_tor_settings:
                        if line.startswith(setting):
                            skip_line = True
                            break
                    if not skip_line:
                        fp.write(line)
            if enable:
                if not coin_settings['manage_daemon']:
                    fp.write(f'proxy={TOR_PROXY_HOST}:{TOR_PROXY_PORT}\n')
        return

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
        else:
            exitWithError('Unknown default onion listening port for {}'.format(coin))
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


def exitWithError(error_msg):
    sys.stderr.write('Error: {}, exiting.\n'.format(error_msg))
    sys.exit(1)


def printVersion():
    from basicswap import __version__
    logger.info('Basicswap version: %s', __version__)

    logger.info('Core versions:')
    for coin, version in known_coins.items():
        logger.info('\t%s: %s%s', coin, version[0], version[1])


def printHelp():
    logger.info('Usage: basicswap-prepare ')
    logger.info('\n--help, -h               Print help.')
    logger.info('--version, -v            Print version.')
    logger.info('--datadir=PATH           Path to basicswap data directory, default:{}.'.format(cfg.BASICSWAP_DATADIR))
    logger.info('--bindir=PATH            Path to cores directory, default:datadir/bin.')
    logger.info('--mainnet                Run in mainnet mode.')
    logger.info('--testnet                Run in testnet mode.')
    logger.info('--regtest                Run in regtest mode.')
    logger.info('--particl_mnemonic=      Recovery phrase to use for the Particl wallet, default is randomly generated,\n'
                + '                         "auto" to create a wallet automatically - No mnemonic.'
                + '                         "none" to disable wallet initialisation.')
    logger.info('--withcoin=              Prepare system to run daemon for coin.')
    logger.info('--withoutcoin=           Do not prepare system to run daemon for coin.')
    logger.info('--addcoin=               Add coin to existing setup.')
    logger.info('--disablecoin=           Make coin inactive.')
    logger.info('--preparebinonly         Don\'t prepare settings or datadirs.')
    logger.info('--nocores                Don\'t download and extract any coin clients.')
    logger.info('--usecontainers          Expect each core to run in a unique container.')
    logger.info('--portoffset=n           Raise all ports by n.')
    logger.info('--htmlhost=              Interface to host html server on, default:127.0.0.1.')
    logger.info('--wshost=                Interface to host websocket server on, disable by setting to "none", default:127.0.0.1.')
    logger.info('--xmrrestoreheight=n     Block height to restore Monero wallet from, default:{}.'.format(DEFAULT_XMR_RESTORE_HEIGHT))
    logger.info('--noextractover          Prevent extracting cores if files exist.  Speeds up tests')
    logger.info('--usetorproxy            Use TOR proxy during setup.  Note that some download links may be inaccessible over TOR.')
    logger.info('--enabletor              Setup Basicswap instance to use TOR.')
    logger.info('--disabletor             Setup Basicswap instance to not use TOR.')
    logger.info('--usebtcfastsync         Initialise the BTC chain with a snapshot from btcpayserver FastSync.\n'
                + '                         See https://github.com/btcpayserver/btcpayserver-docker/blob/master/contrib/FastSync/README.md')
    logger.info('--initwalletsonly        Setup coin wallets only.')
    logger.info('--keysdirpath            Speed up tests by preloading all PGP keys in directory.')

    logger.info('\n' + 'Known coins: %s', ', '.join(known_coins.keys()))


def finalise_daemon(d):
    logging.info('Interrupting {}'.format(d.pid))
    d.send_signal(signal.SIGINT)
    d.wait(timeout=120)
    for fp in (d.stdout, d.stderr, d.stdin):
        if fp:
            fp.close()


def initialise_wallets(particl_wallet_mnemonic, with_coins, data_dir, settings, chain, use_tor_proxy):
    daemons = []
    daemon_args = ['-noconnect', '-nodnsseed']
    if not use_tor_proxy:
        # Cannot set -bind or -whitebind together with -listen=0
        daemon_args.append('-nolisten')
    try:
        with open(os.path.join(data_dir, 'basicswap.log'), 'a') as fp:
            swap_client = BasicSwap(fp, data_dir, settings, chain)

            start_daemons = with_coins
            if 'particl' not in with_coins:
                # Particl must be running to initialise a wallet in addcoin mode
                start_daemons.append('particl')

            for coin_name in start_daemons:
                coin_settings = settings['chainclients'][coin_name]
                c = swap_client.getCoinIdFromName(coin_name)

                if c == Coins.XMR:
                    if coin_settings['manage_wallet_daemon']:
                        daemons.append(startXmrWalletDaemon(coin_settings['datadir'], coin_settings['bindir'], 'monero-wallet-rpc'))
                else:
                    if coin_settings['manage_daemon']:
                        filename = coin_name + 'd' + ('.exe' if os.name == 'nt' else '')
                        coin_args = ['-nofindpeers', '-nostaking'] if c == Coins.PART else []
                        daemons.append(startDaemon(coin_settings['datadir'], coin_settings['bindir'], filename, daemon_args + coin_args))
                        swap_client.setDaemonPID(c, daemons[-1].pid)
                swap_client.setCoinRunParams(c)
                swap_client.createCoinInterface(c)

                if c in (Coins.PART, Coins.BTC, Coins.LTC):
                    swap_client.waitForDaemonRPC(c, with_wallet=False)
                    # Create wallet if it doesn't exist yet
                    wallets = swap_client.callcoinrpc(c, 'listwallets')
                    if 'wallet.dat' not in wallets:
                        logger.info('Creating wallet.dat for {}.'.format(coin_name.capitalize()))
                        swap_client.callcoinrpc(c, 'createwallet', ['wallet.dat'])

            if 'particl' in with_coins:
                logger.info('Loading Particl mnemonic')
                if particl_wallet_mnemonic is None:
                    particl_wallet_mnemonic = swap_client.callcoinrpc(Coins.PART, 'mnemonic', ['new'])['mnemonic']
                swap_client.callcoinrpc(Coins.PART, 'extkeyimportmaster', [particl_wallet_mnemonic])

            for coin_name in with_coins:
                c = swap_client.getCoinIdFromName(coin_name)
                if c == Coins.PART:
                    continue
                swap_client.waitForDaemonRPC(c)
                swap_client.initialiseWallet(c)

            swap_client.finalise()
            del swap_client
    finally:
        for d in daemons:
            finalise_daemon(d)

    if particl_wallet_mnemonic is not None:
        if particl_wallet_mnemonic:
            # Print directly to stdout for tests
            print('IMPORTANT - Save your particl wallet recovery phrase:\n{}\n'.format(particl_wallet_mnemonic))


def load_config(config_path):
    if not os.path.exists(config_path):
        exitWithError('{} does not exist'.format(config_path))
    with open(config_path) as fs:
        return json.load(fs)


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
    htmlhost = '127.0.0.1'
    wshost = '127.0.0.1'
    xmr_restore_height = DEFAULT_XMR_RESTORE_HEIGHT
    prepare_bin_only = False
    no_cores = False
    enable_tor = False
    disable_tor = False
    initwalletsonly = False
    tor_control_password = None
    extra_opts = {}

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
        if name == 'mainnet':
            continue
        if name == 'testnet':
            chain = 'testnet'
            continue
        if name == 'regtest':
            chain = 'regtest'
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
        if name == 'enabletor':
            enable_tor = True
            continue
        if name == 'disabletor':
            disable_tor = True
            continue
        if name == 'usebtcfastsync':
            extra_opts['use_btc_fastsync'] = True
            continue
        if name == 'initwalletsonly':
            initwalletsonly = True
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
            if name == 'withcoin' or name == 'withcoins':
                coins = s[1].split(',')
                for coin in coins:
                    if coin not in known_coins:
                        exitWithError('Unknown coin {}'.format(coin))
                    with_coins.add(coin)
                continue
            if name == 'withoutcoin' or name == 'withoutcoins':
                coins = s[1].split(',')
                for coin in coins:
                    if coin not in known_coins:
                        exitWithError('Unknown coin {}'.format(coin))
                    with_coins.discard(coin)
                continue
            if name == 'addcoin':
                if s[1] not in known_coins:
                    exitWithError('Unknown coin {}'.format(s[1]))
                add_coin = s[1]
                with_coins = [add_coin, ]
                continue
            if name == 'disablecoin':
                if s[1] not in known_coins:
                    exitWithError('Unknown coin {}'.format(s[1]))
                disable_coin = s[1]
                continue
            if name == 'htmlhost':
                htmlhost = s[1].strip('"')
                continue
            if name == 'wshost':
                wshost = s[1].strip('"')
                continue
            if name == 'xmrrestoreheight':
                xmr_restore_height = int(s[1])
                continue
            if name == 'keysdirpath':
                extra_opts['keysdirpath'] = os.path.expanduser(s[1].strip('"'))
                continue

        exitWithError('Unknown argument {}'.format(v))

    setConnectionParameters()

    if use_tor_proxy and TEST_TOR_PROXY:
        testTorConnection()

    if use_tor_proxy and TEST_ONION_LINK:
        testOnionLink()

    if data_dir is None:
        data_dir = os.path.join(os.path.expanduser(cfg.BASICSWAP_DATADIR))
    if bin_dir is None:
        bin_dir = os.path.join(data_dir, 'bin')

    logger.info('datadir: %s', data_dir)
    logger.info('bindir:  %s', bin_dir)
    logger.info('Chain: %s', chain)

    if port_offset is None:
        port_offset = 300 if chain == 'testnet' else 0

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    config_path = os.path.join(data_dir, cfg.CONFIG_FILENAME)

    withchainclients = {}
    chainclients = {
        'particl': {
            'connection_type': 'rpc',
            'manage_daemon': True if ('particl' in with_coins and PART_RPC_HOST == '127.0.0.1') else False,
            'rpchost': PART_RPC_HOST,
            'rpcport': PART_RPC_PORT + port_offset,
            'onionport': PART_ONION_PORT + port_offset,
            'datadir': os.getenv('PART_DATA_DIR', os.path.join(data_dir, 'particl')),
            'bindir': os.path.join(bin_dir, 'particl'),
            'blocks_confirmed': 2,
            'override_feerate': 0.002,
            'conf_target': 2,
            'core_version_group': 21,
            'chain_lookups': 'local',
        },
        'litecoin': {
            'connection_type': 'rpc' if 'litecoin' in with_coins else 'none',
            'manage_daemon': True if ('litecoin' in with_coins and LTC_RPC_HOST == '127.0.0.1') else False,
            'rpchost': LTC_RPC_HOST,
            'rpcport': LTC_RPC_PORT + port_offset,
            'onionport': LTC_ONION_PORT + port_offset,
            'datadir': os.getenv('LTC_DATA_DIR', os.path.join(data_dir, 'litecoin')),
            'bindir': os.path.join(bin_dir, 'litecoin'),
            'use_segwit': True,
            'blocks_confirmed': 2,
            'conf_target': 2,
            'core_version_group': 21,
            'chain_lookups': 'local',
        },
        'bitcoin': {
            'connection_type': 'rpc' if 'bitcoin' in with_coins else 'none',
            'manage_daemon': True if ('bitcoin' in with_coins and BTC_RPC_HOST == '127.0.0.1') else False,
            'rpchost': BTC_RPC_HOST,
            'rpcport': BTC_RPC_PORT + port_offset,
            'onionport': BTC_ONION_PORT + port_offset,
            'datadir': os.getenv('BTC_DATA_DIR', os.path.join(data_dir, 'bitcoin')),
            'bindir': os.path.join(bin_dir, 'bitcoin'),
            'use_segwit': True,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 22,
            'chain_lookups': 'local',
        },
        'namecoin': {
            'connection_type': 'rpc' if 'namecoin' in with_coins else 'none',
            'manage_daemon': True if ('namecoin' in with_coins and NMC_RPC_HOST == '127.0.0.1') else False,
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
            'connection_type': 'rpc' if 'monero' in with_coins else 'none',
            'manage_daemon': True if ('monero' in with_coins and XMR_RPC_HOST == '127.0.0.1') else False,
            'manage_wallet_daemon': True if ('monero' in with_coins and XMR_WALLET_RPC_HOST == '127.0.0.1') else False,
            'rpcport': BASE_XMR_RPC_PORT + port_offset,
            'zmqport': BASE_XMR_ZMQ_PORT + port_offset,
            'walletrpcport': BASE_XMR_WALLET_PORT + port_offset,
            'rpchost': XMR_RPC_HOST,
            'walletrpchost': XMR_WALLET_RPC_HOST,
            'walletrpcuser': XMR_WALLET_RPC_USER,
            'walletrpcpassword': XMR_WALLET_RPC_PWD,
            'walletfile': 'swap_wallet',
            'datadir': os.getenv('XMR_DATA_DIR', os.path.join(data_dir, 'monero')),
            'bindir': os.path.join(bin_dir, 'monero'),
            'restore_height': xmr_restore_height,
            'blocks_confirmed': 7,  # TODO: 10?
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

    chainclients['monero']['walletsdir'] = os.getenv('XMR_WALLETS_DIR', chainclients['monero']['datadir'])

    if initwalletsonly:
        logger.info('Initialising wallets')
        settings = load_config(config_path)

        init_coins = settings['chainclients'].keys()
        logger.info('Active coins: %s', ', '.join(init_coins))
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
            modify_tor_config(settings, coin, tor_control_password, enable=True)

        with open(config_path, 'w') as fp:
            json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    if disable_tor:
        logger.info('Disabling TOR')
        settings = load_config(config_path)
        settings['use_tor'] = False
        for coin in settings['chainclients']:
            modify_tor_config(settings, coin, tor_control_password=None, enable=False)

        with open(config_path, 'w') as fp:
            json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    if disable_coin != '':
        logger.info('Disabling coin: %s', disable_coin)
        settings = load_config(config_path)

        if disable_coin not in settings['chainclients']:
            exitWithError('{} has not been prepared'.format(disable_coin))
        settings['chainclients'][disable_coin]['connection_type'] = 'none'
        settings['chainclients'][disable_coin]['manage_daemon'] = False

        with open(config_path, 'w') as fp:
            json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    extra_opts['data_dir'] = data_dir
    extra_opts['tor_control_password'] = tor_control_password

    if add_coin != '':
        logger.info('Adding coin: %s', add_coin)
        settings = load_config(config_path)

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

            if particl_wallet_mnemonic not in ('none', 'auto'):
                initialise_wallets(None, [add_coin, ], data_dir, settings, chain, use_tor_proxy)

            with open(config_path, 'w') as fp:
                json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    logger.info('With coins: %s', ', '.join(with_coins))
    if os.path.exists(config_path):
        if not prepare_bin_only:
            exitWithError('{} exists'.format(config_path))
        else:
            with open(config_path) as fs:
                settings = json.load(fs)
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
            'check_expired_seconds': 60
        }

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

    if particl_wallet_mnemonic in ('none', 'auto'):
        logger.info('Done.')
        return 0

    initialise_wallets(particl_wallet_mnemonic, with_coins, data_dir, settings, chain, use_tor_proxy)
    print('Done.')


if __name__ == '__main__':
    main()
