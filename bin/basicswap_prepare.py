#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import json
import mmap
import stat
import gnupg
import signal
import hashlib
import tarfile
import zipfile
import logging
import platform
import urllib.parse
from urllib.request import urlretrieve

import basicswap.config as cfg
from basicswap.rpc import (
    callrpc_cli,
    waitForRPC,
)
from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from bin.basicswap_run import startDaemon, startXmrWalletDaemon


if platform.system() == 'Darwin':
    BIN_ARCH = 'osx64'
    FILE_EXT = 'tar.gz'
elif platform.system() == 'Windows':
    BIN_ARCH = 'win64'
    FILE_EXT = 'zip'
else:
    BIN_ARCH = 'x86_64-linux-gnu'
    FILE_EXT = 'tar.gz'

known_coins = {
    'particl': '0.19.1.2',
    'litecoin': '0.18.1',
    'bitcoin': '0.20.1',
    'namecoin': '0.18.0',
    'monero': '0.17.1.9',
}

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

XMR_RPC_HOST = os.getenv('XMR_RPC_HOST', '127.0.0.1')
BASE_XMR_RPC_PORT = int(os.getenv('BASE_XMR_RPC_PORT', 29798))
BASE_XMR_ZMQ_PORT = int(os.getenv('BASE_XMR_ZMQ_PORT', 30898))
BASE_XMR_WALLET_PORT = int(os.getenv('BASE_XMR_WALLET_PORT', 29998))
XMR_WALLET_RPC_HOST = os.getenv('XMR_WALLET_RPC_HOST', '127.0.0.1')
XMR_WALLET_RPC_USER = os.getenv('XMR_WALLET_RPC_USER', 'xmr_wallet_user')
XMR_WALLET_RPC_PWD = os.getenv('XMR_WALLET_RPC_PWD', 'xmr_wallet_pwd')
XMR_SITE_COMMIT = 'd27c1eee9fe0e8daa011d07baae8b67dd2b62a04'  # Lock hashes.txt to monero version

DEFAULT_XMR_RESTORE_HEIGHT = 2245107

UI_HTML_PORT = int(os.getenv('BASE_XMR_RPC_PORT', 12700))
PART_ZMQ_PORT = int(os.getenv('PART_ZMQ_PORT', 20792))

PART_RPC_HOST = os.getenv('PART_RPC_HOST', '127.0.0.1')
LTC_RPC_HOST = os.getenv('LTC_RPC_HOST', '127.0.0.1')
BTC_RPC_HOST = os.getenv('BTC_RPC_HOST', '127.0.0.1')
NMC_RPC_HOST = os.getenv('NMC_RPC_HOST', '127.0.0.1')

PART_RPC_PORT = int(os.getenv('PART_RPC_PORT', 19792))
LTC_RPC_PORT = int(os.getenv('LTC_RPC_PORT', 19795))
BTC_RPC_PORT = int(os.getenv('BTC_RPC_PORT', 19796))
NMC_RPC_PORT = int(os.getenv('NMC_RPC_PORT', 19798))


extract_core_overwrite = True


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


def downloadFile(url, path):
    logger.info('Downloading file %s', url)
    logger.info('To %s', path)
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    urlretrieve(url, path, make_reporthook())


def extractCore(coin, version, settings, bin_dir, release_path):
    logger.info('extractCore %s v%s', coin, version)

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
                    fi = ft.extractfile(member)
                    with open(out_path, 'wb') as fout:
                        fout.write(fi.read())
                    fi.close()
                    os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
        return

    bins = [coin + 'd', coin + '-cli', coin + '-tx']
    versions = version.split('.')
    if coin == 'particl' and int(versions[1]) >= 19:
        bins.append(coin + '-wallet')
    if 'win32' in BIN_ARCH or 'win64' in BIN_ARCH:
        with zipfile.ZipFile(release_path) as fz:
            for b in bins:
                b += '.exe'
                out_path = os.path.join(bin_dir, b)
                if (not os.path.exists(out_path)) or extract_core_overwrite:
                    with open(out_path, 'wb') as fout:
                        fout.write(fz.read('{}-{}/bin/{}'.format(coin, version, b)))
                    os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
    else:
        with tarfile.open(release_path) as ft:
            for b in bins:
                out_path = os.path.join(bin_dir, b)
                if not os.path.exists(out_path) or extract_core_overwrite:
                    fi = ft.extractfile('{}-{}/bin/{}'.format(coin, version, b))
                    with open(out_path, 'wb') as fout:
                        fout.write(fi.read())
                    fi.close()
                    os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)


def prepareCore(coin, version, settings, data_dir):
    logger.info('prepareCore %s v%s', coin, version)

    bin_dir = os.path.expanduser(settings['chainclients'][coin]['bindir'])
    if not os.path.exists(bin_dir):
        os.makedirs(bin_dir)

    if 'osx' in BIN_ARCH:
        os_dir_name = 'osx-unsigned'
        os_name = 'osx'
    elif 'win32' in BIN_ARCH or 'win64' in BIN_ARCH:
        os_dir_name = 'win-unsigned'
        os_name = 'win'
    else:
        os_dir_name = 'linux'
        os_name = 'linux'

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
        release_filename = '{}-{}-{}.{}'.format(coin, version, BIN_ARCH, FILE_EXT)
        if coin == 'particl':
            signing_key_name = 'tecnovert'
            release_url = 'https://github.com/tecnovert/particl-core/releases/download/v{}/{}'.format(version, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version)
            assert_url = 'https://raw.githubusercontent.com/tecnovert/gitian.sigs/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'litecoin':
            signing_key_name = 'thrasher'
            release_url = 'https://download.litecoin.org/litecoin-{}/{}/{}'.format(version, os_name, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
            assert_url = 'https://raw.githubusercontent.com/litecoin-project/gitian.sigs.ltc/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'bitcoin':
            signing_key_name = 'laanwj'
            release_url = 'https://bitcoincore.org/bin/bitcoin-core-{}/{}'.format(version, release_filename)
            assert_filename = '{}-core-{}-{}-build.assert'.format(coin, os_name, '.'.join(version.split('.')[:2]))
            assert_url = 'https://raw.githubusercontent.com/bitcoin-core/gitian.sigs/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        elif coin == 'namecoin':
            signing_key_name = 'JeremyRand'
            release_url = 'https://beta.namecoin.org/files/namecoin-core/namecoin-core-{}/{}'.format(version, release_filename)
            assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
            assert_url = 'https://raw.githubusercontent.com/namecoin/gitian.sigs/master/%s-%s/%s/%s' % (version, os_dir_name, signing_key_name, assert_filename)
        else:
            raise ValueError('Unknown coin')

        assert_sig_filename = assert_filename + '.sig'
        assert_sig_url = assert_url + '.sig'

        release_path = os.path.join(bin_dir, release_filename)
        if not os.path.exists(release_path):
            downloadFile(release_url, release_path)

        # Rename assert files with full version
        assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version)
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            downloadFile(assert_url, assert_path)

        assert_sig_filename = '{}-{}-{}-build.assert.sig'.format(coin, os_name, version)
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

    if coin == 'monero':
        with open(assert_path, 'rb') as fp:
            verified = gpg.verify_file(fp)

        if verified.username is None:
            logger.warning('Signature not verified.')

            pubkeyurl = 'https://raw.githubusercontent.com/monero-project/monero/master/utils/gpg_keys/binaryfate.asc'
            logger.info('Importing public key from url: ' + pubkeyurl)
            rv = gpg.import_keys(urllib.request.urlopen(pubkeyurl).read())
            print('import_keys', rv)
            assert('F0AF4D462A0BDF92' in rv.fingerprints[0])
            gpg.trust_keys(rv.fingerprints[0], 'TRUST_FULLY')
            with open(assert_path, 'rb') as fp:
                verified = gpg.verify_file(fp)
    else:
        with open(assert_sig_path, 'rb') as fp:
            verified = gpg.verify_file(fp, assert_path)

        if verified.username is None:
            logger.warning('Signature not verified.')

            pubkeyurl = 'https://raw.githubusercontent.com/tecnovert/basicswap/master/gitianpubkeys/{}_{}.pgp'.format(coin, signing_key_name)
            logger.info('Importing public key from url: ' + pubkeyurl)
            rv = gpg.import_keys(urllib.request.urlopen(pubkeyurl).read())

            for key in rv.fingerprints:
                gpg.trust_keys(key, 'TRUST_FULLY')

            with open(assert_sig_path, 'rb') as fp:
                verified = gpg.verify_file(fp, assert_path)

    if verified.valid is False \
       and not (verified.status == 'signature valid' and verified.key_status == 'signing key has expired'):
        raise ValueError('Signature verification failed.')

    extractCore(coin, version, settings, bin_dir, release_path)


def prepareDataDir(coin, settings, chain, particl_mnemonic):
    core_settings = settings['chainclients'][coin]
    data_dir = core_settings['datadir']

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
            fp.write('data-dir={}\n'.format(data_dir))
            fp.write('rpc-bind-port={}\n'.format(core_settings['rpcport']))
            fp.write('rpc-bind-ip=127.0.0.1\n')
            fp.write('zmq-rpc-bind-port={}\n'.format(core_settings['zmqport']))
            fp.write('zmq-rpc-bind-ip=127.0.0.1\n')
            fp.write('prune-blockchain=1\n')

        wallet_conf_path = os.path.join(data_dir, coin + '_wallet.conf')
        if os.path.exists(wallet_conf_path):
            exitWithError('{} exists'.format(wallet_conf_path))
        with open(wallet_conf_path, 'w') as fp:
            fp.write('daemon-address={}:{}\n'.format(core_settings['rpchost'], core_settings['rpcport']))
            fp.write('no-dns=1\n')
            fp.write('rpc-bind-port={}\n'.format(core_settings['walletrpcport']))
            fp.write('wallet-dir={}\n'.format(os.path.join(data_dir, 'wallets')))
            fp.write('log-file={}\n'.format(os.path.join(data_dir, 'wallet.log')))
            fp.write('shared-ringdb-dir={}\n'.format(os.path.join(data_dir, 'shared-ringdb')))
            fp.write('rpc-login={}:{}\n'.format(core_settings['walletrpcuser'], core_settings['walletrpcpassword']))
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

        fp.write('rpcport={}\n'.format(core_settings['rpcport']))
        fp.write('printtoconsole=0\n')
        fp.write('daemon=0\n')

        if coin == 'particl':
            fp.write('debugexclude=libevent\n')
            fp.write('zmqpubsmsg=tcp://127.0.0.1:{}\n'.format(settings['zmqport']))
            fp.write('spentindex=1\n')
            fp.write('txindex=1\n')
            fp.write('staking=0\n')

            if particl_mnemonic == 'none':
                fp.write('createdefaultmasterkey=1')
        elif coin == 'litecoin':
            fp.write('prune=1000\n')
        elif coin == 'bitcoin':
            fp.write('prune=1000\n')
            fp.write('fallbackfee=0.0002\n')
        elif coin == 'namecoin':
            fp.write('prune=1000\n')
        else:
            logger.warning('Unknown coin %s', coin)


def printVersion():
    from basicswap import __version__
    logger.info('Basicswap version: %s', __version__)

    logger.info('Core versions:')
    for coin, version in known_coins.items():
        logger.info('\t%s: %s', coin, version)


def printHelp():
    logger.info('Usage: basicswap-prepare ')
    logger.info('\n--help, -h               Print help.')
    logger.info('--version, -v            Print version.')
    logger.info('--datadir=PATH           Path to basicswap data directory, default:{}.'.format(cfg.DEFAULT_DATADIR))
    logger.info('--bindir=PATH            Path to cores directory, default:datadir/bin.')
    logger.info('--mainnet                Run in mainnet mode.')
    logger.info('--testnet                Run in testnet mode.')
    logger.info('--regtest                Run in regtest mode.')
    logger.info('--particl_mnemonic=      Recovery phrase to use for the Particl wallet, default is randomly generated,\n'
                + '                         "none" to set autogenerate account mode.')
    logger.info('--withcoin=              Prepare system to run daemon for coin.')
    logger.info('--withoutcoin=           Do not prepare system to run daemon for coin.')
    logger.info('--addcoin=               Add coin to existing setup.')
    logger.info('--disablecoin=           Make coin inactive.')
    logger.info('--preparebinonly         Don\'t prepare settings or datadirs.')
    logger.info('--nocores                Don\'t download and extract any coin clients.')
    logger.info('--portoffset=n           Raise all ports by n.')
    logger.info('--htmlhost=              Interface to host on, default:127.0.0.1.')
    logger.info('--xmrrestoreheight=n     Block height to restore Monero wallet from, default:{}.'.format(DEFAULT_XMR_RESTORE_HEIGHT))
    logger.info('--noextractover          Prevent extracting cores if files exist.  Speeds up tests')

    logger.info('\n' + 'Known coins: %s', ', '.join(known_coins.keys()))


def make_rpc_func(bin_dir, data_dir, chain):
    bin_dir = bin_dir
    data_dir = data_dir
    chain = chain

    def rpc_func(cmd):
        nonlocal bin_dir
        nonlocal data_dir
        nonlocal chain

        return callrpc_cli(bin_dir, data_dir, chain, cmd, cfg.PARTICL_CLI)
    return rpc_func


def exitWithError(error_msg):
    sys.stderr.write('Error: {}, exiting.\n'.format(error_msg))
    sys.exit(1)


def main():
    global extract_core_overwrite
    data_dir = None
    bin_dir = None
    port_offset = None
    chain = 'mainnet'
    particl_wallet_mnemonic = None
    prepare_bin_only = False
    no_cores = False
    with_coins = {'particl'}
    add_coin = ''
    disable_coin = ''
    htmlhost = '127.0.0.1'
    xmr_restore_height = DEFAULT_XMR_RESTORE_HEIGHT

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
        if name == 'noextractover':
            extract_core_overwrite = False
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
            if name == 'xmrrestoreheight':
                xmr_restore_height = int(s[1])
                continue

        exitWithError('Unknown argument {}'.format(v))

    if data_dir is None:
        data_dir = os.path.join(os.path.expanduser(cfg.DEFAULT_DATADIR))
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
            'datadir': os.getenv('PART_DATA_DIR', os.path.join(data_dir, 'particl')),
            'bindir': os.path.join(bin_dir, 'particl'),
            'blocks_confirmed': 2,
            'override_feerate': 0.002,
            'conf_target': 2,
            'core_version_group': 18,
            'chain_lookups': 'local',
        },
        'litecoin': {
            'connection_type': 'rpc' if 'litecoin' in with_coins else 'none',
            'manage_daemon': True if ('litecoin' in with_coins and LTC_RPC_HOST == '127.0.0.1') else False,
            'rpchost': LTC_RPC_HOST,
            'rpcport': LTC_RPC_PORT + port_offset,
            'datadir': os.getenv('LTC_DATA_DIR', os.path.join(data_dir, 'litecoin')),
            'bindir': os.path.join(bin_dir, 'litecoin'),
            'use_segwit': True,
            'blocks_confirmed': 2,
            'conf_target': 2,
            'core_version_group': 18,
            'chain_lookups': 'local',
        },
        'bitcoin': {
            'connection_type': 'rpc' if 'bitcoin' in with_coins else 'none',
            'manage_daemon': True if ('bitcoin' in with_coins and BTC_RPC_HOST == '127.0.0.1') else False,
            'rpchost': BTC_RPC_HOST,
            'rpcport': BTC_RPC_PORT + port_offset,
            'datadir': os.getenv('BTC_DATA_DIR', os.path.join(data_dir, 'bitcoin')),
            'bindir': os.path.join(bin_dir, 'bitcoin'),
            'use_segwit': True,
            'blocks_confirmed': 1,
            'conf_target': 2,
            'core_version_group': 18,
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

    if disable_coin != '':
        logger.info('Disabling coin: %s', disable_coin)
        if not os.path.exists(config_path):
            exitWithError('{} does not exist'.format(config_path))
        with open(config_path) as fs:
            settings = json.load(fs)

        if disable_coin not in settings['chainclients']:
            exitWithError('{} has not been prepared'.format(disable_coin))
        settings['chainclients'][disable_coin]['connection_type'] = 'none'
        settings['chainclients'][disable_coin]['manage_daemon'] = False

        with open(config_path, 'w') as fp:
            json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    if add_coin != '':
        logger.info('Adding coin: %s', add_coin)
        if not os.path.exists(config_path):
            exitWithError('{} does not exist'.format(config_path))
        with open(config_path) as fs:
            settings = json.load(fs)

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

        if not no_cores:
            prepareCore(add_coin, known_coins[add_coin], settings, data_dir)

        if not prepare_bin_only:
            prepareDataDir(add_coin, settings, chain, particl_wallet_mnemonic)
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
            'zmqhost': 'tcp://127.0.0.1',
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

    if not no_cores:
        for c in with_coins:
            prepareCore(c, known_coins[c], settings, data_dir)

    if prepare_bin_only:
        logger.info('Done.')
        return 0

    for c in with_coins:
        prepareDataDir(c, settings, chain, particl_wallet_mnemonic)

    with open(config_path, 'w') as fp:
        json.dump(settings, fp, indent=4)

    if particl_wallet_mnemonic == 'none':
        logger.info('Done.')
        return 0

    logger.info('Loading Particl mnemonic')

    particl_settings = settings['chainclients']['particl']
    partRpc = make_rpc_func(particl_settings['bindir'], particl_settings['datadir'], chain)

    daemons = []
    daemons.append(startDaemon(particl_settings['datadir'], particl_settings['bindir'], cfg.PARTICLD, ['-noconnect', '-nofindpeers', '-nostaking', '-nodnsseed', '-nolisten']))
    try:
        waitForRPC(partRpc)

        if particl_wallet_mnemonic is None:
            particl_wallet_mnemonic = partRpc('mnemonic new')['mnemonic']
        partRpc('extkeyimportmaster "{}"'.format(particl_wallet_mnemonic))

        # Initialise wallets
        with open(os.path.join(data_dir, 'basicswap.log'), 'a') as fp:
            swap_client = BasicSwap(fp, data_dir, settings, chain)

            swap_client.setCoinConnectParams(Coins.PART)
            swap_client.setDaemonPID(Coins.PART, daemons[-1].pid)
            swap_client.setCoinRunParams(Coins.PART)
            swap_client.createCoinInterface(Coins.PART)

            for coin_name in with_coins:
                coin_settings = settings['chainclients'][coin_name]
                c = swap_client.getCoinIdFromName(coin_name)
                if c == Coins.PART:
                    continue

                swap_client.setCoinConnectParams(c)

                if c == Coins.XMR:
                    if not coin_settings['manage_wallet_daemon']:
                        continue
                    daemons.append(startXmrWalletDaemon(coin_settings['datadir'], coin_settings['bindir'], 'monero-wallet-rpc'))
                else:
                    if not coin_settings['manage_daemon']:
                        continue
                    filename = coin_name + 'd' + ('.exe' if os.name == 'nt' else '')
                    daemons.append(startDaemon(coin_settings['datadir'], coin_settings['bindir'], filename, ['-noconnect', '-nodnsseed', '-nolisten']))
                swap_client.setDaemonPID(c, daemons[-1].pid)
                swap_client.setCoinRunParams(c)
                swap_client.createCoinInterface(c)
                swap_client.waitForDaemonRPC(c)
                swap_client.initialiseWallet(c)
    finally:
        for d in daemons:
            logging.info('Interrupting {}'.format(d.pid))
            d.send_signal(signal.SIGINT)
            d.wait(timeout=120)
            for fp in (d.stdout, d.stderr, d.stdin):
                if fp:
                    fp.close()

    logger.info('IMPORTANT - Save your particl wallet recovery phrase:\n{}\n'.format(particl_wallet_mnemonic))
    logger.info('Done.')


if __name__ == '__main__':
    main()
