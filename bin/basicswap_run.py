#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import json
import time
import signal
import logging
import traceback
import subprocess

import basicswap.config as cfg
from basicswap import __version__
from basicswap.basicswap import BasicSwap
from basicswap.http_server import HttpThread


logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

swap_client = None


def signal_handler(sig, frame):
    global swap_client
    logger.info('Signal %d detected, ending program.' % (sig))
    if swap_client is not None:
        swap_client.stopRunning()


def startDaemon(node_dir, bin_dir, daemon_bin, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    args = [daemon_bin, '-datadir=' + os.path.expanduser(node_dir)] + opts
    logging.info('Starting node ' + daemon_bin + ' ' + '-datadir=' + node_dir)
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def startXmrDaemon(node_dir, bin_dir, daemon_bin, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    args = [daemon_bin, '--config-file=' + os.path.join(os.path.expanduser(node_dir), 'monerod.conf')] + opts
    logging.info('Starting node {} --data-dir={}'.format(daemon_bin, node_dir))

    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def startXmrWalletDaemon(node_dir, bin_dir, wallet_bin, opts=[]):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, wallet_bin))

    data_dir = os.path.expanduser(node_dir)
    args = [daemon_bin, '--config-file=' + os.path.join(os.path.expanduser(node_dir), 'monero_wallet.conf')] + opts

    args += opts
    logging.info('Starting wallet daemon {} --wallet-dir={}'.format(daemon_bin, node_dir))

    # TODO: return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=data_dir)
    wallet_stdout = open(os.path.join(data_dir, 'wallet_stdout.log'), 'w')
    wallet_stderr = open(os.path.join(data_dir, 'wallet_stderr.log'), 'w')
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=wallet_stdout, stderr=wallet_stderr, cwd=data_dir)


def runClient(fp, data_dir, chain):
    global swap_client
    settings_path = os.path.join(data_dir, cfg.CONFIG_FILENAME)
    pids_path = os.path.join(data_dir, '.pids')

    if not os.path.exists(settings_path):
        raise ValueError('Settings file not found: ' + str(settings_path))

    with open(settings_path) as fs:
        settings = json.load(fs)

    swap_client = BasicSwap(fp, data_dir, settings, chain)

    daemons = []
    pids = []
    threads = []

    if os.path.exists(pids_path):
        with open(pids_path) as fd:
            for ln in fd:
                # TODO: try close
                logger.warning('Found pid for daemon {} '.format(ln.strip()))

    # Ensure daemons are stopped
    swap_client.stopDaemons()

    try:
        # Try start daemons
        for c, v in settings['chainclients'].items():
            if c == 'monero':
                if v['manage_daemon'] is True:
                    logger.info('Starting {} daemon'.format(c.capitalize()))
                    daemons.append(startXmrDaemon(v['datadir'], v['bindir'], 'monerod'))
                    pid = daemons[-1].pid
                    logger.info('Started {} {}'.format('monerod', pid))

                if v['manage_wallet_daemon'] is True:
                    logger.info('Starting {} wallet daemon'.format(c.capitalize()))
                    daemons.append(startXmrWalletDaemon(v['datadir'], v['bindir'], 'monero-wallet-rpc'))
                    pid = daemons[-1].pid
                    logger.info('Started {} {}'.format('monero-wallet-rpc', pid))

                continue
            if v['manage_daemon'] is True:
                logger.info('Starting {} daemon'.format(c.capitalize()))

                filename = c + 'd' + ('.exe' if os.name == 'nt' else '')
                daemons.append(startDaemon(v['datadir'], v['bindir'], filename))
                pid = daemons[-1].pid
                pids.append((c, pid))
                swap_client.setDaemonPID(c, pid)
                logger.info('Started {} {}'.format(filename, pid))
        if len(pids) > 0:
            with open(pids_path, 'w') as fd:
                for p in pids:
                    fd.write('{}:{}\n'.format(*p))

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        swap_client.start()

        if 'htmlhost' in settings:
            swap_client.log.info('Starting server at %s:%d.' % (settings['htmlhost'], settings['htmlport']))
            allow_cors = settings['allowcors'] if 'allowcors' in settings else cfg.DEFAULT_ALLOW_CORS
            tS1 = HttpThread(fp, settings['htmlhost'], settings['htmlport'], allow_cors, swap_client)
            threads.append(tS1)
            tS1.start()

        logger.info('Exit with Ctrl + c.')
        while swap_client.is_running:
            time.sleep(0.5)
            swap_client.update()
    except Exception as ex:
        traceback.print_exc()

    swap_client.finalise()
    swap_client.log.info('Stopping HTTP threads.')
    for t in threads:
        t.stop()
        t.join()

    closed_pids = []
    for d in daemons:
        logging.info('Interrupting {}'.format(d.pid))
        try:
            d.send_signal(signal.SIGINT)
        except Exception as e:
            logging.info('Interrupting %d, error %s', d.pid, str(e))
    for d in daemons:
        try:
            d.wait(timeout=120)
            for fp in (d.stdout, d.stderr, d.stdin):
                if fp:
                    fp.close()
            closed_pids.append(d.pid)
        except Exception as ex:
            logger.error('Error: {}'.format(ex))

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
    logger.info('Basicswap version:', __version__)


def printHelp():
    logger.info('Usage: basicswap-run ')
    logger.info('\n--help, -h               Print help.')
    logger.info('--version, -v            Print version.')
    logger.info('--datadir=PATH           Path to basicswap data directory, default:{}.'.format(cfg.DEFAULT_DATADIR))
    logger.info('--mainnet                Run in mainnet mode.')
    logger.info('--testnet                Run in testnet mode.')
    logger.info('--regtest                Run in regtest mode.')


def main():
    data_dir = None
    chain = 'mainnet'

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

        if name == 'testnet':
            chain = 'testnet'
            continue
        if name == 'regtest':
            chain = 'regtest'
            continue

        if len(s) == 2:
            if name == 'datadir':
                data_dir = os.path.expanduser(s[1])
                continue

        logger.warning('Unknown argument %s', v)

    if data_dir is None:
        data_dir = os.path.join(os.path.expanduser(cfg.DEFAULT_DATADIR))
    logger.info('Using datadir: %s', data_dir)
    logger.info('Chain: %s', chain)

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    with open(os.path.join(data_dir, 'basicswap.log'), 'a') as fp:
        logger.info(os.path.basename(sys.argv[0]) + ', version: ' + __version__ + '\n\n')
        runClient(fp, data_dir, chain)

    logger.info('Done.')
    return swap_client.fail_code if swap_client is not None else 0


if __name__ == '__main__':
    main()
