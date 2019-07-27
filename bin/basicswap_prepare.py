#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

"""
Atomic Swap Client - Proof of Concept

sudo pip install python-gnupg

"""

import sys
import os
import json
import hashlib
import mmap
import tarfile
import stat
import time
from urllib.request import urlretrieve
import urllib.parse
import logging
import platform

import gnupg

import basicswap.config as cfg
from basicswap.util import callrpc_cli
from bin.basicswap_run import startDaemon

if platform.system() == 'Darwin':
    BIN_ARCH = 'osx64.tar.gz'
else:
    BIN_ARCH = 'x86_64-linux-gnu.tar.gz'

known_coins = {
    'particl': '0.18.1.0',
    'litecoin': '0.17.1',
    'bitcoin': '0.18.0',
    'namecoin': '0.18.0',
}

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def make_reporthook():
    read = 0  # number of bytes read so far
    last_percent_str = ''

    def reporthook(blocknum, blocksize, totalsize):
        nonlocal read
        nonlocal last_percent_str
        read += blocksize
        if totalsize > 0:
            percent_str = '%5.1f%%' % (read * 1e2 / totalsize)
            if percent_str != last_percent_str:
                logger.info(percent_str)
                last_percent_str = percent_str
        else:
            logger.info('read %d' % (read,))
    return reporthook


def downloadFile(url, path):
    logger.info('Downloading file %s', url)
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent', 'Mozilla/5.0')]
    urllib.request.install_opener(opener)
    urlretrieve(url, path, make_reporthook())


def prepareCore(coin, version, settings, data_dir):
    logger.info('prepareCore %s v%s', coin, version)

    bin_dir = settings['chainclients'][coin]['bindir']
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

    release_filename = '{}-{}-{}'.format(coin, version, BIN_ARCH)
    if coin == 'particl':
        signing_key_name = 'tecnovert'
        release_url = 'https://github.com/particl/particl-core/releases/download/v{}/{}'.format(version, release_filename)
        assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version)
        assert_url = 'https://raw.githubusercontent.com/particl/gitian.sigs/master/%s-%s/%s/%s' % (version, os_name, signing_key_name, assert_filename)
    elif coin == 'litecoin':
        signing_key_name = 'thrasher'
        release_url = 'https://download.litecoin.org/litecoin-{}/{}/{}'.format(version, os_name, release_filename)
        assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
        assert_url = 'https://raw.githubusercontent.com/litecoin-project/gitian.sigs.ltc/master/%s-%s/%s/%s' % (version, os_name, signing_key_name, assert_filename)
    elif coin == 'bitcoin':
        signing_key_name = 'laanwj'
        release_url = 'https://bitcoincore.org/bin/bitcoin-core-{}/{}'.format(version, release_filename)
        assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
        assert_url = 'https://raw.githubusercontent.com/bitcoin-core/gitian.sigs/master/%s-%s/%s/%s' % (version, os_name, signing_key_name, assert_filename)
    elif coin == 'namecoin':
        signing_key_name = 'JeremyRand'
        release_url = 'https://beta.namecoin.org/files/namecoin-core/namecoin-core-{}/{}'.format(version, release_filename)
        assert_filename = '{}-{}-{}-build.assert'.format(coin, os_name, version.rsplit('.', 1)[0])
        assert_url = 'https://raw.githubusercontent.com/namecoin/gitian.sigs/master/%s-%s/%s/%s' % (version, os_name, signing_key_name, assert_filename)
    else:
        raise ValueError('Unknown coin')

    assert_sig_filename = assert_filename + '.sig'
    assert_sig_url = assert_url + '.sig'

    release_path = os.path.join(bin_dir, release_filename)
    if not os.path.exists(release_path):
        downloadFile(release_url, release_path)

    assert_path = os.path.join(bin_dir, assert_filename)
    if not os.path.exists(assert_path):
        downloadFile(assert_url, assert_path)

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

    with open(assert_sig_path, 'rb') as fp:
        verified = gpg.verify_file(fp, assert_path)

    if verified.username is None:
        logger.warning('Signature not verified.')

        pubkeyurl = 'https://raw.githubusercontent.com/tecnovert/basicswap/master/gitianpubkeys/{}_{}.pgp'.format(coin, signing_key_name)
        logger.info('Importing public key from url: ' + pubkeyurl)
        gpg.import_keys(urllib.request.urlopen(pubkeyurl).read())

        with open(assert_sig_path, 'rb') as fp:
            verified = gpg.verify_file(fp, assert_path)

        if verified.username is None:
            raise ValueError('Signature verification failed.')

    bins = [coin + 'd', coin + '-cli', coin + '-tx']
    with tarfile.open(release_path) as ft:
        for b in bins:
            out_path = os.path.join(bin_dir, b)
            fi = ft.extractfile('{}-{}/bin/{}'.format(coin, version, b))
            with open(out_path, 'wb') as fout:
                fout.write(fi.read())
            fi.close()
            os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)


def prepareDataDir(coin, settings, data_dir, chain, particl_mnemonic):
    core_settings = settings['chainclients'][coin]
    data_dir = core_settings['datadir']

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

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
            fp.write('spentindex=1')
            fp.write('txindex=1')

            if particl_mnemonic == 'none':
                fp.write('createdefaultmasterkey=1')
        elif coin == 'litecoin':
            fp.write('prune=1000\n')
        elif coin == 'bitcoin':
            fp.write('prune=1000\n')
        elif coin == 'namecoin':
            fp.write('prune=1000\n')
        else:
            logger.warning('Unknown coin %s', coin)


def extractCore(coin, version, settings):
    logger.info('extractCore %s v%s', coin, version)


def printVersion():
    from basicswap import __version__
    logger.info('Basicswap version:', __version__)


def printHelp():
    logger.info('Usage: basicswap-prepare ')
    logger.info('\n--help, -h               Print help.')
    logger.info('--version, -v            Print version.')
    logger.info('--datadir=PATH           Path to basicswap data directory, default:~/.basicswap.')
    logger.info('--mainnet                Run in mainnet mode.')
    logger.info('--testnet                Run in testnet mode.')
    logger.info('--regtest                Run in regtest mode.')
    logger.info('--particl_mnemonic=      Recovery phrase to use for the Particl wallet, default is randomly generated,\n' +
                '                         "none" to set autogenerate account mode.')
    logger.info('--withcoin=              Prepare system to run daemon for coin.')
    logger.info('--withoutcoin=           Do not prepare system to run daemon for coin.')
    logger.info('--addcoin=               Add coin to existing setup.')
    logger.info('--disablecoin=           Make coin inactive.')
    logger.info('--preparebinonly         Don\'t prepare settings or datadirs.')

    logger.info('\n' + 'Known coins: %s', ', '.join(known_coins.keys()))


def make_rpc_func(bin_dir, data_dir, chain):
    bin_dir = bin_dir
    data_dir = data_dir
    chain = '' if chain == 'mainnet' else chain

    def rpc_func(cmd):
        nonlocal bin_dir
        nonlocal data_dir
        nonlocal chain
        return callrpc_cli(bin_dir, data_dir, chain, cmd, cfg.PARTICL_CLI)
    return rpc_func


def waitForRPC(rpc_func, wallet=None):
    for i in range(5):
        try:
            rpc_func('getwalletinfo')
            return
        except Exception as ex:
            logging.warning('Can\'t connect to daemon RPC: %s.  Trying again in %d second/s.', str(ex), (1 + i))
            time.sleep(1 + i)
    raise ValueError('waitForRPC failed')


def exitWithError(error_msg):
    sys.stderr.write('Error: {}, exiting.\n'.format(error_msg))
    sys.exit(1)


def main():
    data_dir = None
    chain = 'mainnet'
    particl_wallet_mnemonic = None
    prepare_bin_only = False
    with_coins = {'particl', 'litecoin'}
    add_coin = ''
    disable_coin = ''

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

        if len(s) == 2:
            if name == 'datadir':
                data_dir = os.path.expanduser(s[1])
                continue
            if name == 'particl_mnemonic':
                particl_wallet_mnemonic = s[1]
                continue
            if name == 'withcoin':
                if s[1] not in known_coins:
                    exitWithError('Unknown coin {}'.format(s[1]))
                with_coins.add(s[1])
                continue
            if name == 'withoutcoin':
                if s[1] not in known_coins:
                    exitWithError('Unknown coin {}'.format(s[1]))
                with_coins.discard(s[1])
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

        exitWithError('Unknown argument {}'.format(v))

    if data_dir is None:
        default_datadir = '~/.basicswap'
        data_dir = os.path.join(os.path.expanduser(default_datadir))
    logger.info('Using datadir: %s', data_dir)
    logger.info('Chain: %s', chain)
    port_offset = 300 if chain == 'testnet' else 0

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    config_path = os.path.join(data_dir, 'basicswap.json')

    withchainclients = {}
    chainclients = {
        'particl': {
            'connection_type': 'rpc',
            'manage_daemon': True,
            'rpcport': 19792 + port_offset,
            'datadir': os.path.join(data_dir, 'particl'),
            'bindir': os.path.join(data_dir, 'bin', 'particl'),
            'blocks_confirmed': 2,
            'override_feerate': 0.002,
            'conf_target': 2,
        },
        'litecoin': {
            'connection_type': 'rpc' if 'litecoin' in with_coins else 'none',
            'manage_daemon': True if 'litecoin' in with_coins else False,
            'rpcport': 19795 + port_offset,
            'datadir': os.path.join(data_dir, 'litecoin'),
            'bindir': os.path.join(data_dir, 'bin', 'litecoin'),
            'use_segwit': True,
            'blocks_confirmed': 2,
            'conf_target': 2,
        },
        'bitcoin': {
            'connection_type': 'rpc' if 'bitcoin' in with_coins else 'none',
            'manage_daemon': True if 'bitcoin' in with_coins else False,
            'rpcport': 19796 + port_offset,
            'datadir': os.path.join(data_dir, 'bitcoin'),
            'bindir': os.path.join(data_dir, 'bin', 'bitcoin'),
            'use_segwit': True,
            'blocks_confirmed': 1,
            'conf_target': 2,
        },
        'namecoin': {
            'connection_type': 'rpc' if 'namecoin' in with_coins else 'none',
            'manage_daemon': True if 'namecoin' in with_coins else False,
            'rpcport': 19798 + port_offset,
            'datadir': os.path.join(data_dir, 'namecoin'),
            'bindir': os.path.join(data_dir, 'bin', 'namecoin'),
            'use_segwit': False,
            'use_csv': False,
            'blocks_confirmed': 1,
            'conf_target': 2,
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

        prepareCore(add_coin, known_coins[add_coin], settings, data_dir)

        if not prepare_bin_only:
            prepareDataDir(add_coin, settings, data_dir, chain, particl_wallet_mnemonic)
            with open(config_path, 'w') as fp:
                json.dump(settings, fp, indent=4)

        logger.info('Done.')
        return 0

    logger.info('With coins: %s', ', '.join(with_coins))
    if os.path.exists(config_path):
        exitWithError('{} exists'.format(config_path))

    for c in with_coins:
        withchainclients[c] = chainclients[c]

    settings = {
        'debug': True,
        'zmqhost': 'tcp://127.0.0.1',
        'zmqport': 20792 + port_offset,
        'htmlhost': 'localhost',
        'htmlport': 12700 + port_offset,
        'network_key': '7sW2UEcHXvuqEjkpE5mD584zRaQYs6WXYohue4jLFZPTvMSxwvgs',
        'network_pubkey': '035758c4a22d7dd59165db02a56156e790224361eb3191f02197addcb3bde903d2',
        'chainclients': withchainclients,
        'check_progress_seconds': 60,
        'check_watched_seconds': 60,
        'check_expired_seconds': 60
    }

    for c in with_coins:
        prepareCore(c, known_coins[c], settings, data_dir)

    if prepare_bin_only:
        logger.info('Done.')
        return 0

    for c in with_coins:
        prepareDataDir(c, settings, data_dir, chain, particl_wallet_mnemonic)

    with open(config_path, 'w') as fp:
        json.dump(settings, fp, indent=4)

    if particl_wallet_mnemonic == 'none':
        logger.info('Done.')
        return 0

    logger.info('Loading Particl mnemonic')

    particl_settings = settings['chainclients']['particl']
    partRpc = make_rpc_func(particl_settings['bindir'], particl_settings['datadir'], chain)
    d = startDaemon(particl_settings['datadir'], particl_settings['bindir'], cfg.PARTICLD, ['-noconnect', '-nofindpeers', '-nostaking', '-nodnsseed', '-nolisten'])
    try:
        waitForRPC(partRpc)

        if particl_wallet_mnemonic is None:
            particl_wallet_mnemonic = partRpc('mnemonic new')['mnemonic']
        partRpc('extkeyimportmaster "{}"'.format(particl_wallet_mnemonic))
    finally:
        logger.info('Terminating {}'.format(d.pid))
        d.terminate()
        d.wait(timeout=120)
        if d.stdout:
            d.stdout.close()
        if d.stderr:
            d.stderr.close()
        if d.stdin:
            d.stdin.close()

    logger.info('IMPORTANT - Save your particl wallet recovery phrase:\n{}\n'.format(particl_wallet_mnemonic))

    logger.info('Done.')


if __name__ == '__main__':
    main()
