#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import json
import shutil
import signal
import logging
import traceback
import subprocess

import basicswap.config as cfg
from basicswap import __version__
from basicswap.ui.util import getCoinName
from basicswap.basicswap import BasicSwap
from basicswap.chainparams import chainparams
from basicswap.http_server import HttpThread
from basicswap.contrib.websocket_server import WebsocketServer


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

swap_client = None


class Daemon:
    __slots__ = ('handle', 'files')

    def __init__(self, handle, files):
        self.handle = handle
        self.files = files


def is_known_coin(coin_name: str) -> bool:
    for k, v in chainparams.items():
        if coin_name == v['name']:
            return True
    return False


def signal_handler(sig, frame):
    global swap_client
    logger.info('Signal %d detected, ending program.' % (sig))
    if swap_client is not None:
        swap_client.stopRunning()


def startDaemon(node_dir, bin_dir, daemon_bin, opts=[], extra_config={}):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    datadir_path = os.path.expanduser(node_dir)

    # Rewrite litecoin.conf for 0.21.3
    ltc_conf_path = os.path.join(datadir_path, 'litecoin.conf')
    if os.path.exists(ltc_conf_path):
        config_to_add = ['blockfilterindex=0', 'peerblockfilters=0']
        with open(ltc_conf_path) as fp:
            for line in fp:
                line = line.strip()
                if line in config_to_add:
                    config_to_add.remove(line)

        if len(config_to_add) > 0:
            logging.info('Rewriting litecoin.conf')
            shutil.copyfile(ltc_conf_path, ltc_conf_path + '.last')
            with open(ltc_conf_path, 'a') as fp:
                for line in config_to_add:
                    fp.write(line + '\n')

    args = [daemon_bin, ]
    add_datadir: bool = extra_config.get('add_datadir', True)
    if add_datadir:
        args.append('-datadir=' + datadir_path)
    args += opts
    logging.info('Starting node ' + daemon_bin + ' ' + (('-datadir=' + node_dir) if add_datadir else ''))

    opened_files = []
    if extra_config.get('stdout_to_file', False):
        stdout_dest = open(os.path.join(datadir_path, extra_config.get('stdout_filename', 'core_stdout.log')), 'w')
        opened_files.append(stdout_dest)
        stderr_dest = stdout_dest
    else:
        stdout_dest = subprocess.PIPE
        stderr_dest = subprocess.PIPE

    if extra_config.get('use_shell', False):
        str_args = ' '.join(args)
        return Daemon(subprocess.Popen(str_args, shell=True, stdin=subprocess.PIPE, stdout=stdout_dest, stderr=stderr_dest, cwd=datadir_path), opened_files)
    return Daemon(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout_dest, stderr=stderr_dest, cwd=datadir_path), opened_files)


def startXmrDaemon(node_dir, bin_dir, daemon_bin, opts=[]):
    daemon_path = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    datadir_path = os.path.expanduser(node_dir)
    config_filename = 'wownerod.conf' if daemon_bin.startswith('wow') else 'monerod.conf'
    args = [daemon_path, '--non-interactive', '--config-file=' + os.path.join(datadir_path, config_filename)] + opts
    logging.info('Starting node {} --data-dir={}'.format(daemon_path, node_dir))

    # return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    file_stdout = open(os.path.join(datadir_path, 'core_stdout.log'), 'w')
    file_stderr = open(os.path.join(datadir_path, 'core_stderr.log'), 'w')
    return Daemon(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=file_stdout, stderr=file_stderr, cwd=datadir_path), [file_stdout, file_stderr])


def startXmrWalletDaemon(node_dir, bin_dir, wallet_bin, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, wallet_bin))
    args = [daemon_bin, '--non-interactive']

    needs_rewrite: bool = False
    config_to_remove = ['daemon-address=', 'untrusted-daemon=', 'trusted-daemon=', 'proxy=']

    data_dir = os.path.expanduser(node_dir)

    wallet_config_filename = 'wownero-wallet-rpc.conf' if wallet_bin.startswith('wow') else 'monero_wallet.conf'
    config_path = os.path.join(data_dir, wallet_config_filename)
    if os.path.exists(config_path):
        args += ['--config-file=' + config_path]
        with open(config_path) as fp:
            for line in fp:
                if any(line.startswith(config_line) for config_line in config_to_remove):
                    logging.warning('Found old config in monero_wallet.conf: {}'.format(line.strip()))
                    needs_rewrite = True
    args += opts

    if needs_rewrite:
        logging.info('Rewriting wallet config')
        shutil.copyfile(config_path, config_path + '.last')
        with open(config_path + '.last') as fp_from, open(config_path, 'w') as fp_to:
            for line in fp_from:
                if not any(line.startswith(config_line) for config_line in config_to_remove):
                    fp_to.write(line)

    logging.info('Starting wallet daemon {} --wallet-dir={}'.format(daemon_bin, node_dir))

    # TODO: return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=data_dir)
    wallet_stdout = open(os.path.join(data_dir, 'wallet_stdout.log'), 'w')
    wallet_stderr = open(os.path.join(data_dir, 'wallet_stderr.log'), 'w')
    return Daemon(subprocess.Popen(args, stdin=subprocess.PIPE, stdout=wallet_stdout, stderr=wallet_stderr, cwd=data_dir), [wallet_stdout, wallet_stderr])


def ws_new_client(client, server):
    if swap_client:
        swap_client.log.debug(f'ws_new_client {client["id"]}')


def ws_client_left(client, server):
    if client is None:
        return
    if swap_client:
        swap_client.log.debug(f'ws_client_left {client["id"]}')


def ws_message_received(client, server, message):
    if len(message) > 200:
        message = message[:200] + '..'
    if swap_client:
        swap_client.log.debug(f'ws_message_received {client["id"]} {message}')


def runClient(fp, data_dir, chain, start_only_coins):
    global swap_client
    daemons = []
    pids = []
    threads = []
    settings_path = os.path.join(data_dir, cfg.CONFIG_FILENAME)
    pids_path = os.path.join(data_dir, '.pids')

    if os.getenv('WALLET_ENCRYPTION_PWD', '') != '':
        if 'decred' in start_only_coins:
            # Workaround for dcrwallet requiring password for initial startup
            logger.warning('Allowing set WALLET_ENCRYPTION_PWD var with --startonlycoin=decred.')
        else:
            raise ValueError('Please unset the WALLET_ENCRYPTION_PWD environment variable.')

    if not os.path.exists(settings_path):
        raise ValueError('Settings file not found: ' + str(settings_path))

    with open(settings_path) as fs:
        settings = json.load(fs)

    swap_client = BasicSwap(fp, data_dir, settings, chain)

    if os.path.exists(pids_path):
        with open(pids_path) as fd:
            for ln in fd:
                # TODO: try close
                logger.warning('Found pid for daemon {} '.format(ln.strip()))

    # Ensure daemons are stopped
    swap_client.stopDaemons()

    # Settings may have been modified
    settings = swap_client.settings
    try:
        # Try start daemons
        for c, v in settings['chainclients'].items():
            if len(start_only_coins) > 0 and c not in start_only_coins:
                continue
            try:
                coin_id = swap_client.getCoinIdFromName(c)
                display_name = getCoinName(coin_id)
            except Exception as e:
                logger.warning('Not starting unknown coin: {}'.format(c))
                continue
            if c in ('monero', 'wownero'):
                if v['manage_daemon'] is True:
                    swap_client.log.info(f'Starting {display_name} daemon')
                    filename = c + 'd' + ('.exe' if os.name == 'nt' else '')
                    daemons.append(startXmrDaemon(v['datadir'], v['bindir'], filename))
                    pid = daemons[-1].handle.pid
                    swap_client.log.info('Started {} {}'.format(filename, pid))

                if v['manage_wallet_daemon'] is True:
                    swap_client.log.info(f'Starting {display_name} wallet daemon')
                    daemon_addr = '{}:{}'.format(v['rpchost'], v['rpcport'])
                    trusted_daemon: bool = swap_client.getXMRTrustedDaemon(coin_id, v['rpchost'])
                    opts = ['--daemon-address', daemon_addr, ]

                    proxy_log_str = ''
                    proxy_host, proxy_port = swap_client.getXMRWalletProxy(coin_id, v['rpchost'])
                    if proxy_host:
                        proxy_log_str = ' through proxy'
                        opts += ['--proxy', f'{proxy_host}:{proxy_port}', '--daemon-ssl-allow-any-cert', ]

                    swap_client.log.info('daemon-address: {} ({}){}'.format(daemon_addr, 'trusted' if trusted_daemon else 'untrusted', proxy_log_str))

                    daemon_rpcuser = v.get('rpcuser', '')
                    daemon_rpcpass = v.get('rpcpassword', '')
                    if daemon_rpcuser != '':
                        opts.append('--daemon-login')
                        opts.append(daemon_rpcuser + ':' + daemon_rpcpass)

                    opts.append('--trusted-daemon' if trusted_daemon else '--untrusted-daemon')
                    filename = c + '-wallet-rpc' + ('.exe' if os.name == 'nt' else '')
                    daemons.append(startXmrWalletDaemon(v['datadir'], v['bindir'], filename, opts))
                    pid = daemons[-1].handle.pid
                    swap_client.log.info('Started {} {}'.format(filename, pid))

                continue  # /monero

            if c == 'decred':
                appdata = v['datadir']
                extra_opts = [f'--appdata="{appdata}"', ]
                use_shell: bool = True if os.name == 'nt' else False
                if v['manage_daemon'] is True:
                    swap_client.log.info(f'Starting {display_name} daemon')
                    filename = 'dcrd' + ('.exe' if os.name == 'nt' else '')

                    extra_config = {'add_datadir': False, 'stdout_to_file': True, 'stdout_filename': 'dcrd_stdout.log', 'use_shell': use_shell}
                    daemons.append(startDaemon(appdata, v['bindir'], filename, opts=extra_opts, extra_config=extra_config))
                    pid = daemons[-1].handle.pid
                    swap_client.log.info('Started {} {}'.format(filename, pid))

                if v['manage_wallet_daemon'] is True:
                    swap_client.log.info(f'Starting {display_name} wallet daemon')
                    filename = 'dcrwallet' + ('.exe' if os.name == 'nt' else '')

                    wallet_pwd = v['wallet_pwd']
                    if wallet_pwd == '':
                        # Only set when in startonlycoin mode
                        wallet_pwd = os.getenv('WALLET_ENCRYPTION_PWD', '')
                    if wallet_pwd != '':
                        extra_opts.append(f'--pass="{wallet_pwd}"')
                    extra_config = {'add_datadir': False, 'stdout_to_file': True, 'stdout_filename': 'dcrwallet_stdout.log', 'use_shell': use_shell}
                    daemons.append(startDaemon(appdata, v['bindir'], filename, opts=extra_opts, extra_config=extra_config))
                    pid = daemons[-1].handle.pid
                    swap_client.log.info('Started {} {}'.format(filename, pid))

                continue  # /decred

            if v['manage_daemon'] is True:
                swap_client.log.info(f'Starting {display_name} daemon')

                filename = c + 'd' + ('.exe' if os.name == 'nt' else '')
                daemons.append(startDaemon(v['datadir'], v['bindir'], filename))
                pid = daemons[-1].handle.pid
                pids.append((c, pid))
                swap_client.setDaemonPID(c, pid)
                swap_client.log.info('Started {} {}'.format(filename, pid))
        if len(pids) > 0:
            with open(pids_path, 'w') as fd:
                for p in pids:
                    fd.write('{}:{}\n'.format(*p))

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        if len(start_only_coins) > 0:
            logger.info(f'Only running {start_only_coins}. Manually exit with Ctrl + c when ready.')
            while not swap_client.delay_event.wait(0.5):
                pass
        else:
            swap_client.start()
            if 'htmlhost' in settings:
                swap_client.log.info('Starting http server at http://%s:%d.' % (settings['htmlhost'], settings['htmlport']))
                allow_cors = settings['allowcors'] if 'allowcors' in settings else cfg.DEFAULT_ALLOW_CORS
                thread_http = HttpThread(fp, settings['htmlhost'], settings['htmlport'], allow_cors, swap_client)
                threads.append(thread_http)
                thread_http.start()

            if 'wshost' in settings:
                ws_url = 'ws://{}:{}'.format(settings['wshost'], settings['wsport'])
                swap_client.log.info(f'Starting ws server at {ws_url}.')

                swap_client.ws_server = WebsocketServer(host=settings['wshost'], port=settings['wsport'])
                swap_client.ws_server.set_fn_new_client(ws_new_client)
                swap_client.ws_server.set_fn_client_left(ws_client_left)
                swap_client.ws_server.set_fn_message_received(ws_message_received)
                swap_client.ws_server.run_forever(threaded=True)

            logger.info('Exit with Ctrl + c.')
            while not swap_client.delay_event.wait(0.5):
                swap_client.update()

    except Exception as ex:
        traceback.print_exc()

    if swap_client.ws_server:
        try:
            swap_client.log.info('Stopping websocket server.')
            swap_client.ws_server.shutdown_gracefully()
        except Exception as ex:
            traceback.print_exc()

    swap_client.finalise()
    swap_client.log.info('Stopping HTTP threads.')
    for t in threads:
        try:
            t.stop()
            t.join()
        except Exception as ex:
            traceback.print_exc()

    closed_pids = []
    for d in daemons:
        swap_client.log.info('Interrupting {}'.format(d.handle.pid))
        try:
            d.handle.send_signal(signal.CTRL_C_EVENT if os.name == 'nt' else signal.SIGINT)
        except Exception as e:
            swap_client.log.info('Interrupting %d, error %s', d.handle.pid, str(e))
    for d in daemons:
        try:
            d.handle.wait(timeout=120)
            for fp in [d.handle.stdout, d.handle.stderr, d.handle.stdin] + d.files:
                if fp:
                    fp.close()
            closed_pids.append(d.handle.pid)
        except Exception as ex:
            swap_client.log.error('Error: {}'.format(ex))

    if os.path.exists(pids_path):
        with open(pids_path) as fd:
            lines = fd.read().split('\n')
        still_running = ''
        for ln in lines:
            try:
                if not int(ln.split(':')[1]) in closed_pids:
                    still_running += ln + '\n'
            except Exception:
                pass
        with open(pids_path, 'w') as fd:
            fd.write(still_running)


def printVersion():
    logger.info('Basicswap version: %s', __version__)


def printHelp():
    print('Usage: basicswap-run ')
    print('\n--help, -h               Print help.')
    print('--version, -v            Print version.')
    print('--datadir=PATH           Path to basicswap data directory, default:{}.'.format(cfg.BASICSWAP_DATADIR))
    print('--mainnet                Run in mainnet mode.')
    print('--testnet                Run in testnet mode.')
    print('--regtest                Run in regtest mode.')
    print('--startonlycoin          Only start the provides coin daemon/s, use this if a chain requires extra processing.')


def main():
    data_dir = None
    chain = 'mainnet'
    start_only_coins = set()

    for v in sys.argv[1:]:
        if len(v) < 2 or v[0] != '-':
            logger.warning('Unknown argument %s', v)
            continue

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

        if len(s) == 2:
            if name == 'datadir':
                data_dir = os.path.expanduser(s[1])
                continue
        if name == 'startonlycoin':
            for coin in [s.lower() for s in s[1].split(',')]:
                if is_known_coin(coin) is False:
                    raise ValueError(f'Unknown coin: {coin}')
                start_only_coins.add(coin)
            continue

        logger.warning('Unknown argument %s', v)

    if os.name == 'nt':
        logger.warning('Running on windows is discouraged and windows support may be discontinued in the future.  Please consider using the WSL docker setup instead.')

    if data_dir is None:
        data_dir = os.path.join(os.path.expanduser(cfg.BASICSWAP_DATADIR))
    logger.info('Using datadir: %s', data_dir)
    logger.info('Chain: %s', chain)

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    with open(os.path.join(data_dir, 'basicswap.log'), 'a') as fp:
        logger.info(os.path.basename(sys.argv[0]) + ', version: ' + __version__ + '\n\n')
        runClient(fp, data_dir, chain, start_only_coins)

    logger.info('Done.')
    return swap_client.fail_code if swap_client is not None else 0


if __name__ == '__main__':
    main()
