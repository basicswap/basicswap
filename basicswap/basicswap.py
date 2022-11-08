# -*- coding: utf-8 -*-

# Copyright (c) 2019-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import re
import sys
import zmq
import json
import time
import base64
import random
import shutil
import struct
import urllib.request
import hashlib
import secrets
import datetime as dt
import threading
import traceback
import sqlalchemy as sa
import collections
import concurrent.futures

from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.orm.session import close_all_sessions

from .interface.part import PARTInterface, PARTInterfaceAnon, PARTInterfaceBlind
from .interface.btc import BTCInterface
from .interface.ltc import LTCInterface
from .interface.nmc import NMCInterface
from .interface.xmr import XMRInterface
from .interface.pivx import PIVXInterface
from .interface.dash import DASHInterface
from .interface.firo import FIROInterface
from .interface.passthrough_btc import PassthroughBTCInterface

from . import __version__
from .rpc_xmr import make_xmr_rpc2_func
from .ui.util import getCoinName
from .util import (
    TemporaryError,
    InactiveCoin,
    AutomationConstraint,
    format_amount,
    format_timestamp,
    DeserialiseNum,
    make_int,
    ensure,
)
from .util.script import (
    getP2WSH,
    getP2SHScriptForHash,
)
from .util.address import (
    toWIF,
    getKeyID,
    decodeWif,
    decodeAddress,
    pubkeyToAddress,
)
from .chainparams import (
    Coins,
    chainparams,
)
from .script import (
    OpCodes,
)
from .messages_pb2 import (
    OfferMessage,
    BidMessage,
    BidAcceptMessage,
    XmrBidMessage,
    XmrBidAcceptMessage,
    XmrSplitMessage,
    XmrBidLockTxSigsMessage,
    XmrBidLockSpendTxMessage,
    XmrBidLockReleaseMessage,
    OfferRevokeMessage,
)
from .db import (
    CURRENT_DB_VERSION,
    Concepts,
    Base,
    DBKVInt,
    DBKVString,
    Offer,
    Bid,
    SwapTx,
    PooledAddress,
    SentOffer,
    SmsgAddress,
    Action,
    EventLog,
    XmrOffer,
    XmrSwap,
    XmrSplitData,
    Wallets,
    Notification,
    KnownIdentity,
    AutomationLink,
    AutomationStrategy,
)
from .db_upgrades import upgradeDatabase, upgradeDatabaseData
from .base import BaseApp
from .explorers import (
    ExplorerInsight,
    ExplorerBitAps,
    ExplorerChainz,
)
import basicswap.config as cfg
import basicswap.network as bsn
import basicswap.protocols.atomic_swap_1 as atomic_swap_1
from .basicswap_util import (
    KeyTypes,
    TxLockTypes,
    AddressTypes,
    MessageTypes,
    SwapTypes,
    OfferStates,
    BidStates,
    TxStates,
    TxTypes,
    ActionTypes,
    EventLogTypes,
    XmrSplitMsgTypes,
    DebugTypes,
    strBidState,
    describeEventEntry,
    getVoutByAddress,
    getVoutByP2WSH,
    replaceAddrPrefix,
    getOfferProofOfFundsHash,
    getLastBidState,
    isActiveBidState,
    NotificationTypes as NT,
)
from .protocols.xmr_swap_1 import (
    addLockRefundSigs,
    recoverNoScriptTxnWithKey)


non_script_type_coins = (Coins.XMR, Coins.PART_ANON)


def validOfferStateToReceiveBid(offer_state):
    if offer_state == OfferStates.OFFER_RECEIVED:
        return True
    if offer_state == OfferStates.OFFER_SENT:
        return True
    return False


def zeroIfNone(value):
    if value is None:
        return 0
    return value


def threadPollXMRChainState(swap_client, coin_type):
    ci = swap_client.ci(coin_type)
    cc = swap_client.coin_clients[coin_type]
    while not swap_client.delay_event.is_set():
        try:
            new_height = ci.getChainHeight()
            if new_height != cc['chain_height']:
                swap_client.log.debug('New {} block at height: {}'.format(ci.ticker(), new_height))
                with swap_client.mxDB:
                    cc['chain_height'] = new_height
        except Exception as e:
            swap_client.log.warning('threadPollXMRChainState {}, error: {}'.format(ci.ticker(), str(e)))
        swap_client.delay_event.wait(random.randrange(20, 30))  # random to stagger updates


def threadPollChainState(swap_client, coin_type):
    ci = swap_client.ci(coin_type)
    cc = swap_client.coin_clients[coin_type]
    while not swap_client.delay_event.is_set():
        try:
            chain_state = ci.getBlockchainInfo()
            if chain_state['bestblockhash'] != cc['chain_best_block']:
                swap_client.log.debug('New {} block at height: {}'.format(ci.ticker(), chain_state['blocks']))
                with swap_client.mxDB:
                    cc['chain_height'] = chain_state['blocks']
                    cc['chain_best_block'] = chain_state['bestblockhash']
                    if 'mediantime' in chain_state:
                        cc['chain_median_time'] = chain_state['mediantime']
        except Exception as e:
            swap_client.log.warning('threadPollChainState {}, error: {}'.format(ci.ticker(), str(e)))
        swap_client.delay_event.wait(random.randrange(20, 30))  # random to stagger updates


class WatchedOutput():  # Watch for spends
    __slots__ = ('bid_id', 'txid_hex', 'vout', 'tx_type', 'swap_type')

    def __init__(self, bid_id, txid_hex, vout, tx_type, swap_type):
        self.bid_id = bid_id
        self.txid_hex = txid_hex
        self.vout = vout
        self.tx_type = tx_type
        self.swap_type = swap_type


class WatchedTransaction():
    # TODO
    # Watch for presence in mempool (getrawtransaction)
    def __init__(self, bid_id, txid_hex, tx_type, swap_type):
        self.bid_id = bid_id
        self.txid_hex = txid_hex
        self.tx_type = tx_type
        self.swap_type = swap_type


class BasicSwap(BaseApp):
    ws_server = None

    def __init__(self, fp, data_dir, settings, chain, log_name='BasicSwap'):
        super().__init__(fp, data_dir, settings, chain, log_name)

        v = __version__.split('.')
        self._version = struct.pack('>HHH', int(v[0]), int(v[1]), int(v[2]))

        self.check_progress_seconds = self.settings.get('check_progress_seconds', 60)
        self.check_watched_seconds = self.settings.get('check_watched_seconds', 60)
        self.check_expired_seconds = self.settings.get('check_expired_seconds', 60 * 5)
        self.check_actions_seconds = self.settings.get('check_actions_seconds', 10)
        self.check_xmr_swaps_seconds = self.settings.get('check_xmr_swaps_seconds', 20)
        self.startup_tries = self.settings.get('startup_tries', 21)  # Seconds waited for will be (x(1 + x+1) / 2
        self.debug_ui = self.settings.get('debug_ui', False)
        self._last_checked_progress = 0
        self._last_checked_watched = 0
        self._last_checked_expired = 0
        self._last_checked_actions = 0
        self._last_checked_xmr_swaps = 0
        self._possibly_revoked_offers = collections.deque([], maxlen=48)  # TODO: improve
        self._updating_wallets_info = {}
        self._last_updated_wallets_info = 0

        self._notifications_enabled = self.settings.get('notifications_enabled', True)
        self._disabled_notification_types = self.settings.get('disabled_notification_types', [])
        self._keep_notifications = self.settings.get('keep_notifications', 50)
        self._show_notifications = self.settings.get('show_notifications', 10)
        self._notifications_cache = {}

        # TODO: Adjust ranges
        self.min_delay_event = self.settings.get('min_delay_event', 10)
        self.max_delay_event = self.settings.get('max_delay_event', 60)
        self.min_delay_event_short = self.settings.get('min_delay_event_short', 2)
        self.max_delay_event_short = self.settings.get('max_delay_event_short', 30)

        self.min_delay_retry = self.settings.get('min_delay_retry', 60)
        self.max_delay_retry = self.settings.get('max_delay_retry', 5 * 60)

        self.min_sequence_lock_seconds = self.settings.get('min_sequence_lock_seconds', 60 if self.debug else (1 * 60 * 60))
        self.max_sequence_lock_seconds = self.settings.get('max_sequence_lock_seconds', 96 * 60 * 60)

        self._bid_expired_leeway = 5

        self.swaps_in_progress = dict()

        self.SMSG_SECONDS_IN_HOUR = 60 * 60  # Note: Set smsgsregtestadjust=0 for regtest

        self.threads = []
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='bsp')

        # Encode key to match network
        wif_prefix = chainparams[Coins.PART][self.chain]['key_prefix']
        self.network_key = toWIF(wif_prefix, decodeWif(self.settings['network_key']))

        self.network_pubkey = self.settings['network_pubkey']
        self.network_addr = pubkeyToAddress(chainparams[Coins.PART][self.chain]['pubkey_address'], bytes.fromhex(self.network_pubkey))

        self.db_echo = self.settings.get('db_echo', False)
        self.sqlite_file = os.path.join(self.data_dir, 'db{}.sqlite'.format('' if self.chain == 'mainnet' else ('_' + self.chain)))
        db_exists = os.path.exists(self.sqlite_file)

        # HACK: create_all hangs when using tox, unless create_engine is called with echo=True
        if not db_exists:
            if os.getenv('FOR_TOX'):
                self.engine = sa.create_engine('sqlite:///' + self.sqlite_file, echo=True)
            else:
                self.engine = sa.create_engine('sqlite:///' + self.sqlite_file)
            close_all_sessions()
            Base.metadata.create_all(self.engine)
            self.engine.dispose()

        self.engine = sa.create_engine('sqlite:///' + self.sqlite_file, echo=self.db_echo)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

        session = scoped_session(self.session_factory)
        try:
            self.db_version = session.query(DBKVInt).filter_by(key='db_version').first().value
        except Exception:
            self.log.info('First run')
            self.db_version = CURRENT_DB_VERSION
            session.add(DBKVInt(
                key='db_version',
                value=self.db_version
            ))
            session.commit()
        try:
            self.db_data_version = session.query(DBKVInt).filter_by(key='db_data_version').first().value
        except Exception:
            self.db_data_version = 0
        try:
            self._contract_count = session.query(DBKVInt).filter_by(key='contract_count').first().value
        except Exception:
            self._contract_count = 0
            session.add(DBKVInt(
                key='contract_count',
                value=self._contract_count
            ))
            session.commit()

        session.close()
        session.remove()

        self.zmqContext = zmq.Context()
        self.zmqSubscriber = self.zmqContext.socket(zmq.SUB)

        self.zmqSubscriber.connect(self.settings['zmqhost'] + ':' + str(self.settings['zmqport']))
        self.zmqSubscriber.setsockopt_string(zmq.SUBSCRIBE, 'smsg')

        for c in Coins:
            if c in chainparams:
                self.setCoinConnectParams(c)

        if self.chain == 'mainnet':
            self.coin_clients[Coins.PART]['explorers'].append(ExplorerInsight(
                self, Coins.PART,
                'https://explorer.particl.io/particl-insight-api'))
            self.coin_clients[Coins.LTC]['explorers'].append(ExplorerBitAps(
                self, Coins.LTC,
                'https://api.bitaps.com/ltc/v1/blockchain'))
            self.coin_clients[Coins.LTC]['explorers'].append(ExplorerChainz(
                self, Coins.LTC,
                'http://chainz.cryptoid.info/ltc/api.dws'))
        elif self.chain == 'testnet':
            self.coin_clients[Coins.PART]['explorers'].append(ExplorerInsight(
                self, Coins.PART,
                'https://explorer-testnet.particl.io/particl-insight-api'))
            self.coin_clients[Coins.LTC]['explorers'].append(ExplorerBitAps(
                self, Coins.LTC,
                'https://api.bitaps.com/ltc/testnet/v1/blockchain'))

            # non-segwit
            # https://testnet.litecore.io/insight-api

        random.seed(secrets.randbits(128))

    def finalise(self):
        self.log.info('Finalise')

        with self.mxDB:
            self.is_running = False
            self.delay_event.set()

        if self._network:
            self._network.stopNetwork()
            self._network = None

        for t in self.threads:
            t.join()

        if sys.version_info[1] >= 9:
            self.thread_pool.shutdown(cancel_futures=True)
        else:
            self.thread_pool.shutdown()

        self.zmqContext.destroy()

        close_all_sessions()
        self.engine.dispose()

    def openSession(self, session=None):
        if session:
            return session
        self.mxDB.acquire()
        return scoped_session(self.session_factory)

    def closeSession(self, use_session, commit=True):
        if commit:
            use_session.commit()
        use_session.close()
        use_session.remove()
        self.mxDB.release()

    def setCoinConnectParams(self, coin):
        # Set anything that does not require the daemon to be running
        chain_client_settings = self.getChainClientSettings(coin)

        bindir = os.path.expanduser(chain_client_settings.get('bindir', ''))
        datadir = os.path.expanduser(chain_client_settings.get('datadir', os.path.join(cfg.TEST_DATADIRS, chainparams[coin]['name'])))

        connection_type = chain_client_settings.get('connection_type', 'none')
        rpcauth = None
        if connection_type == 'rpc':
            if 'rpcauth' in chain_client_settings:
                rpcauth = chain_client_settings['rpcauth']
                self.log.debug('Read %s rpc credentials from json settings', coin)
            elif 'rpcpassword' in chain_client_settings:
                rpcauth = chain_client_settings['rpcuser'] + ':' + chain_client_settings['rpcpassword']
                self.log.debug('Read %s rpc credentials from json settings', coin)

        session = scoped_session(self.session_factory)
        try:
            last_height_checked = session.query(DBKVInt).filter_by(key='last_height_checked_' + chainparams[coin]['name']).first().value
        except Exception:
            last_height_checked = 0
        session.close()
        session.remove()

        coin_chainparams = chainparams[coin]
        default_segwit = coin_chainparams.get('has_segwit', False)
        default_csv = coin_chainparams.get('has_csv', True)
        self.coin_clients[coin] = {
            'coin': coin,
            'name': coin_chainparams['name'],
            'connection_type': connection_type,
            'bindir': bindir,
            'datadir': datadir,
            'rpchost': chain_client_settings.get('rpchost', '127.0.0.1'),
            'rpcport': chain_client_settings.get('rpcport', coin_chainparams[self.chain]['rpcport']),
            'rpcauth': rpcauth,
            'blocks_confirmed': chain_client_settings.get('blocks_confirmed', 6),
            'conf_target': chain_client_settings.get('conf_target', 2),
            'watched_outputs': [],
            'last_height_checked': last_height_checked,
            'use_segwit': chain_client_settings.get('use_segwit', default_segwit),
            'use_csv': chain_client_settings.get('use_csv', default_csv),
            'core_version_group': chain_client_settings.get('core_version_group', 0),
            'pid': None,
            'core_version': None,
            'explorers': [],
            'chain_lookups': chain_client_settings.get('chain_lookups', 'local'),
            'restore_height': chain_client_settings.get('restore_height', 0),
            'fee_priority': chain_client_settings.get('fee_priority', 0),

            # Chain state
            'chain_height': None,
            'chain_best_block': None,
            'chain_median_time': None,
        }

        if coin == Coins.PART:
            self.coin_clients[coin]['anon_tx_ring_size'] = chain_client_settings.get('anon_tx_ring_size', 12)
            self.coin_clients[Coins.PART_ANON] = self.coin_clients[coin]
            self.coin_clients[Coins.PART_BLIND] = self.coin_clients[coin]

        if self.coin_clients[coin]['connection_type'] == 'rpc':
            if coin == Coins.XMR:
                if chain_client_settings.get('automatically_select_daemon', False):
                    self.selectXMRRemoteDaemon(coin)

                self.coin_clients[coin]['walletrpchost'] = chain_client_settings.get('walletrpchost', '127.0.0.1')
                self.coin_clients[coin]['walletrpcport'] = chain_client_settings.get('walletrpcport', chainparams[coin][self.chain]['walletrpcport'])
                if 'walletrpcpassword' in chain_client_settings:
                    self.coin_clients[coin]['walletrpcauth'] = (chain_client_settings['walletrpcuser'], chain_client_settings['walletrpcpassword'])
                else:
                    raise ValueError('Missing XMR wallet rpc credentials.')

    def selectXMRRemoteDaemon(self, coin):
        self.log.info('Selecting remote XMR daemon.')
        chain_client_settings = self.getChainClientSettings(coin)
        remote_daemon_urls = chain_client_settings.get('remote_daemon_urls', [])
        rpchost = self.coin_clients[coin]['rpchost']
        rpcport = self.coin_clients[coin]['rpcport']
        current_daemon_url = f'{rpchost}:{rpcport}'
        if current_daemon_url in remote_daemon_urls:
            self.log.info(f'Trying last used url {rpchost}:{rpcport}.')
            try:
                rpc_cb2 = make_xmr_rpc2_func(rpcport, rpchost)
                test = rpc_cb2('get_height', timeout=20)['height']
                return True
            except Exception as e:
                self.log.warning(f'Failed to set XMR remote daemon to {rpchost}:{rpcport}, {e}')
        random.shuffle(remote_daemon_urls)
        for url in remote_daemon_urls:
            self.log.info(f'Trying url {url}.')
            try:
                rpchost, rpcport = url.rsplit(':', 1)
                rpc_cb2 = make_xmr_rpc2_func(rpcport, rpchost)
                test = rpc_cb2('get_height', timeout=20)['height']
                self.coin_clients[coin]['rpchost'] = rpchost
                self.coin_clients[coin]['rpcport'] = rpcport
                data = {
                    'rpchost': rpchost,
                    'rpcport': rpcport,
                }
                self.editSettings(self.coin_clients[coin]['name'], data)
                return True
            except Exception as e:
                self.log.warning(f'Failed to set XMR remote daemon to {url}, {e}')

        raise ValueError('Failed to select a working XMR daemon url.')

    def ci(self, coin):  # Coin interface
        use_coinid = coin
        interface_ind = 'interface'
        if coin == Coins.PART_ANON:
            use_coinid = Coins.PART
            interface_ind = 'interface_anon'
        if coin == Coins.PART_BLIND:
            use_coinid = Coins.PART
            interface_ind = 'interface_blind'

        if use_coinid not in self.coin_clients:
            raise ValueError('Unknown coinid {}'.format(int(coin)))
        if interface_ind not in self.coin_clients[use_coinid]:
            raise InactiveCoin(int(coin))

        return self.coin_clients[use_coinid][interface_ind]

    def createInterface(self, coin):
        if coin == Coins.PART:
            return PARTInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.BTC:
            return BTCInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.LTC:
            return LTCInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.NMC:
            return NMCInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.XMR:
            xmr_i = XMRInterface(self.coin_clients[coin], self.chain, self)
            chain_client_settings = self.getChainClientSettings(coin)
            xmr_i.setWalletFilename(chain_client_settings['walletfile'])
            return xmr_i
        elif coin == Coins.PIVX:
            return PIVXInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.DASH:
            return DASHInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.FIRO:
            return FIROInterface(self.coin_clients[coin], self.chain, self)
        else:
            raise ValueError('Unknown coin type')

    def createPassthroughInterface(self, coin):
        if coin == Coins.BTC:
            return PassthroughBTCInterface(self.coin_clients[coin], self.chain)
        else:
            raise ValueError('Unknown coin type')

    def setCoinRunParams(self, coin):
        cc = self.coin_clients[coin]
        if coin == Coins.XMR:
            return
        if cc['connection_type'] == 'rpc' and cc['rpcauth'] is None:
            chain_client_settings = self.getChainClientSettings(coin)
            authcookiepath = os.path.join(self.getChainDatadirPath(coin), '.cookie')

            pidfilename = cc['name']
            if cc['name'] in ('bitcoin', 'litecoin', 'namecoin', 'dash', 'firo'):
                pidfilename += 'd'

            pidfilepath = os.path.join(self.getChainDatadirPath(coin), pidfilename + '.pid')
            self.log.debug('Reading %s rpc credentials from auth cookie %s', coin, authcookiepath)
            # Wait for daemon to start
            # Test pids to ensure authcookie is read for the correct process
            datadir_pid = -1
            for i in range(20):
                try:
                    # Workaround for mismatched pid file name in litecoin 0.21.2
                    # Also set with pid= in .conf
                    # TODO: Remove
                    if cc['name'] == 'litecoin' and (not os.path.exists(pidfilepath)) and \
                       os.path.exists(os.path.join(self.getChainDatadirPath(coin), 'bitcoind.pid')):
                        pidfilepath = os.path.join(self.getChainDatadirPath(coin), 'bitcoind.pid')

                    with open(pidfilepath, 'rb') as fp:
                        datadir_pid = int(fp.read().decode('utf-8'))
                    assert (datadir_pid == cc['pid']), 'Mismatched pid'
                    assert (os.path.exists(authcookiepath))
                    break
                except Exception as e:
                    if self.debug:
                        self.log.warning('Error, iteration %d: %s', i, str(e))
                    self.delay_event.wait(0.5)
            try:
                if os.name != 'nt' or cc['core_version_group'] > 17:  # Litecoin on windows doesn't write a pid file
                    assert (datadir_pid == cc['pid']), 'Mismatched pid'
                with open(authcookiepath, 'rb') as fp:
                    cc['rpcauth'] = fp.read().decode('utf-8')
            except Exception as e:
                self.log.error('Unable to read authcookie for %s, %s, datadir pid %d, daemon pid %s. Error: %s', str(coin), authcookiepath, datadir_pid, cc['pid'], str(e))
                raise ValueError('Error, terminating')

    def createCoinInterface(self, coin):
        if self.coin_clients[coin]['connection_type'] == 'rpc':
            self.coin_clients[coin]['interface'] = self.createInterface(coin)
            if coin == Coins.PART:
                self.coin_clients[coin]['interface_anon'] = PARTInterfaceAnon(self.coin_clients[coin], self.chain, self)
                self.coin_clients[coin]['interface_blind'] = PARTInterfaceBlind(self.coin_clients[coin], self.chain, self)
        elif self.coin_clients[coin]['connection_type'] == 'passthrough':
            self.coin_clients[coin]['interface'] = self.createPassthroughInterface(coin)

    def start(self):
        self.log.info('Starting BasicSwap %s, database v%d\n\n', __version__, self.db_version)
        self.log.info('sqlalchemy version %s', sa.__version__)
        self.log.info('timezone offset: %d (%s)', time.timezone, time.tzname[0])

        upgradeDatabase(self, self.db_version)
        upgradeDatabaseData(self, self.db_data_version)

        for c in Coins:
            if c not in chainparams:
                continue
            self.setCoinRunParams(c)
            self.createCoinInterface(c)

            if self.coin_clients[c]['connection_type'] == 'rpc':
                self.waitForDaemonRPC(c)
                ci = self.ci(c)
                core_version = ci.getDaemonVersion()
                self.log.info('%s Core version %d', ci.coin_name(), core_version)
                self.coin_clients[c]['core_version'] = core_version

                if c == Coins.XMR:
                    t = threading.Thread(target=threadPollXMRChainState, args=(self, c))
                else:
                    t = threading.Thread(target=threadPollChainState, args=(self, c))
                self.threads.append(t)
                t.start()

                if c == Coins.PART:
                    self.coin_clients[c]['have_spent_index'] = ci.haveSpentIndex()

                    try:
                        # Sanity checks
                        rv = self.callcoinrpc(c, 'extkey')
                        if 'result' in rv and 'No keys to list.' in rv['result']:
                            raise ValueError('No keys loaded.')

                        if self.callcoinrpc(c, 'getstakinginfo')['enabled'] is not False:
                            self.log.warning('%s staking is not disabled.', ci.coin_name())
                    except Exception as e:
                        self.log.error('Sanity checks failed: %s', str(e))

                elif c == Coins.XMR:
                    ci.ensureWalletExists()

                self.checkWalletSeed(c)

        if 'p2p_host' in self.settings:
            network_key = self.getNetworkKey(1)
            self._network = bsn.Network(self.settings['p2p_host'], self.settings['p2p_port'], network_key, self)
            self._network.startNetwork()

        self.initialise()

    def stopDaemon(self, coin):
        if coin == Coins.XMR:
            return
        num_tries = 10
        authcookiepath = os.path.join(self.getChainDatadirPath(coin), '.cookie')
        stopping = False
        try:
            for i in range(num_tries):
                rv = self.callcoincli(coin, 'stop', timeout=10)
                self.log.debug('Trying to stop %s', str(coin))
                stopping = True
                time.sleep(i + 1)
        except Exception as ex:
            str_ex = str(ex)
            if 'Could not connect' in str_ex or 'Could not locate RPC credentials' in str_ex or 'couldn\'t connect to server' in str_ex:
                if stopping:
                    for i in range(30):
                        # The lock file doesn't get deleted
                        # Using .cookie is a temporary workaround, will only work if rpc password is unset.
                        # TODO: Query lock on .lock properly
                        if os.path.exists(authcookiepath):
                            self.log.debug('Waiting on .cookie file %s', str(coin))
                            time.sleep(i + 1)
                    time.sleep(4)  # Extra time to settle
                return
            self.log.error('stopDaemon %s', str(ex))
            self.log.error(traceback.format_exc())
        raise ValueError('Could not stop {}'.format(str(coin)))

    def stopDaemons(self):
        for c in Coins:
            if c not in chainparams:
                continue
            chain_client_settings = self.getChainClientSettings(c)
            if self.coin_clients[c]['connection_type'] == 'rpc' and chain_client_settings['manage_daemon'] is True:
                self.stopDaemon(c)

    def waitForDaemonRPC(self, coin_type, with_wallet=True):
        for i in range(self.startup_tries):
            if not self.is_running:
                return
            try:
                self.coin_clients[coin_type]['interface'].testDaemonRPC(with_wallet)
                return
            except Exception as ex:
                self.log.warning('Can\'t connect to %s RPC: %s.  Trying again in %d second/s.', coin_type, str(ex), (1 + i))
                time.sleep(1 + i)
        self.log.error('Can\'t connect to %s RPC, exiting.', coin_type)
        self.stopRunning(1)  # systemd will try to restart the process if fail_code != 0

    def checkSynced(self, coin_from, coin_to):
        check_coins = (coin_from, coin_to)
        for c in check_coins:
            if self.coin_clients[c]['connection_type'] != 'rpc':
                continue
            if c == Coins.XMR:
                continue  # TODO
            synced = round(self.ci(c).getBlockchainInfo()['verificationprogress'], 3)
            if synced < 1.0:
                raise ValueError('{} chain is still syncing, currently at {}.'.format(self.coin_clients[c]['name'], synced))

    def initialiseWallet(self, coin_type, raise_errors=False):
        if coin_type == Coins.PART:
            return
        ci = self.ci(coin_type)
        self.log.info('Initialising {} wallet.'.format(ci.coin_name()))

        if coin_type == Coins.XMR:
            key_view = self.getWalletKey(coin_type, 1, for_ed25519=True)
            key_spend = self.getWalletKey(coin_type, 2, for_ed25519=True)
            ci.initialiseWallet(key_view, key_spend)
            root_address = ci.getAddressFromKeys(key_view, key_spend)

            key_str = 'main_wallet_addr_' + ci.coin_name().lower()
            self.setStringKV(key_str, root_address)
            return

        root_key = self.getWalletKey(coin_type, 1)
        root_hash = ci.getSeedHash(root_key)

        try:
            ci.initialiseWallet(root_key)
        except Exception as e:
            # <  0.21: sethdseed cannot set a new HD seed while still in Initial Block Download.
            self.log.error('initialiseWallet failed: {}'.format(str(e)))
            if raise_errors:
                raise e

        key_str = 'main_wallet_seedid_' + ci.coin_name().lower()
        self.setStringKV(key_str, root_hash.hex())

    def updateIdentityBidState(self, session, address, bid):
        identity_stats = session.query(KnownIdentity).filter_by(address=address).first()
        if not identity_stats:
            identity_stats = KnownIdentity(address=address, created_at=int(time.time()))

        if bid.state == BidStates.SWAP_COMPLETED:
            if bid.was_sent:
                identity_stats.num_sent_bids_successful = zeroIfNone(identity_stats.num_sent_bids_successful) + 1
            else:
                identity_stats.num_recv_bids_successful = zeroIfNone(identity_stats.num_recv_bids_successful) + 1
        elif bid.state in (BidStates.BID_ERROR, BidStates.XMR_SWAP_FAILED_REFUNDED, BidStates.XMR_SWAP_FAILED_SWIPED, BidStates.XMR_SWAP_FAILED):
            if bid.was_sent:
                identity_stats.num_sent_bids_failed = zeroIfNone(identity_stats.num_sent_bids_failed) + 1
            else:
                identity_stats.num_recv_bids_failed = zeroIfNone(identity_stats.num_recv_bids_failed) + 1

        identity_stats.updated_at = int(time.time())
        session.add(identity_stats)

    def setIntKVInSession(self, str_key, int_val, session):
        kv = session.query(DBKVInt).filter_by(key=str_key).first()
        if not kv:
            kv = DBKVInt(key=str_key, value=int_val)
        else:
            kv.value = int_val
        session.add(kv)

    def setIntKV(self, str_key, int_val):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            self.setIntKVInSession(str_key, int_val, session)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def setStringKV(self, str_key, str_val):
        with self.mxDB:
            try:
                session = scoped_session(self.session_factory)
                kv = session.query(DBKVString).filter_by(key=str_key).first()
                if not kv:
                    kv = DBKVString(key=str_key, value=str_val)
                else:
                    kv.value = str_val
                session.add(kv)
                session.commit()
            finally:
                session.close()
                session.remove()

    def getStringKV(self, str_key):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            v = session.query(DBKVString).filter_by(key=str_key).first()
            if not v:
                return None
            return v.value
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def activateBid(self, session, bid):
        if bid.bid_id in self.swaps_in_progress:
            self.log.debug('Bid %s is already in progress', bid.bid_id.hex())

        self.log.debug('Loading active bid %s', bid.bid_id.hex())

        offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
        if not offer:
            raise ValueError('Offer not found')

        self.loadBidTxns(bid, session)
        if offer.swap_type == SwapTypes.XMR_SWAP:
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
            self.watchXmrSwap(bid, offer, xmr_swap)
        else:
            self.swaps_in_progress[bid.bid_id] = (bid, offer)

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            if bid.initiate_tx and bid.initiate_tx.txid:
                self.addWatchedOutput(coin_from, bid.bid_id, bid.initiate_tx.txid.hex(), bid.initiate_tx.vout, BidStates.SWAP_INITIATED)
            if bid.participate_tx and bid.participate_tx.txid:
                self.addWatchedOutput(coin_to, bid.bid_id, bid.participate_tx.txid.hex(), bid.participate_tx.vout, BidStates.SWAP_PARTICIPATING)

            if self.coin_clients[coin_from]['last_height_checked'] < 1:
                if bid.initiate_tx and bid.initiate_tx.chain_height:
                    self.coin_clients[coin_from]['last_height_checked'] = bid.initiate_tx.chain_height
            if self.coin_clients[coin_to]['last_height_checked'] < 1:
                if bid.participate_tx and bid.participate_tx.chain_height:
                    self.coin_clients[coin_to]['last_height_checked'] = bid.participate_tx.chain_height

        # TODO process addresspool if bid has previously been abandoned

    def deactivateBid(self, session, offer, bid):
        # Remove from in progress
        self.log.debug('Removing bid from in-progress: %s', bid.bid_id.hex())
        self.swaps_in_progress.pop(bid.bid_id, None)

        bid.in_progress = 0
        if session is None:
            self.saveBid(bid.bid_id, bid)

        # Remove any watched outputs
        self.removeWatchedOutput(Coins(offer.coin_from), bid.bid_id, None)
        self.removeWatchedOutput(Coins(offer.coin_to), bid.bid_id, None)

        if bid.state == BidStates.BID_ABANDONED or bid.state == BidStates.SWAP_COMPLETED:
            # Return unused addrs to pool
            itx_state = bid.getITxState()
            ptx_state = bid.getPTxState()
            if itx_state is not None and itx_state != TxStates.TX_REDEEMED:
                self.returnAddressToPool(bid.bid_id, TxTypes.ITX_REDEEM)
            if itx_state is not None and itx_state != TxStates.TX_REFUNDED:
                self.returnAddressToPool(bid.bid_id, TxTypes.ITX_REFUND)
            if ptx_state is not None and ptx_state != TxStates.TX_REDEEMED:
                self.returnAddressToPool(bid.bid_id, TxTypes.PTX_REDEEM)
            if ptx_state is not None and ptx_state != TxStates.TX_REFUNDED:
                self.returnAddressToPool(bid.bid_id, TxTypes.PTX_REFUND)

        try:
            use_session = self.openSession(session)

            # Remove any delayed events
            if self.debug:
                use_session.execute('UPDATE actions SET active_ind = 2 WHERE linked_id = x\'{}\' '.format(bid.bid_id.hex()))
            else:
                use_session.execute('DELETE FROM actions WHERE linked_id = x\'{}\' '.format(bid.bid_id.hex()))

            # Unlock locked inputs (TODO)
            if offer.swap_type == SwapTypes.XMR_SWAP:
                xmr_swap = use_session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
                if xmr_swap:
                    try:
                        self.ci(offer.coin_from).unlockInputs(xmr_swap.a_lock_tx)
                    except Exception as e:
                        self.log.debug('unlockInputs failed {}'.format(str(e)))
                        pass  # Invalid parameter, unknown transaction
            elif SwapTypes.SELLER_FIRST:
                pass  # No prevouts are locked

            # Update identity stats
            if bid.state in (BidStates.BID_ERROR, BidStates.XMR_SWAP_FAILED_REFUNDED, BidStates.XMR_SWAP_FAILED_SWIPED, BidStates.XMR_SWAP_FAILED, BidStates.SWAP_COMPLETED):
                peer_address = offer.addr_from if bid.was_sent else bid.bid_addr
                self.updateIdentityBidState(use_session, peer_address, bid)

        finally:
            if session is None:
                self.closeSession(use_session)

    def loadFromDB(self):
        self.log.info('Loading data from db')
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            for bid in session.query(Bid):
                if bid.in_progress == 1 or (bid.state and bid.state > BidStates.BID_RECEIVED and bid.state < BidStates.SWAP_COMPLETED):
                    try:
                        self.activateBid(session, bid)
                    except Exception as ex:
                        self.logException(f'Failed to activate bid! Error: {ex}')
                        try:
                            bid.setState(BidStates.BID_ERROR, 'Failed to activate')
                            offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
                            self.deactivateBid(session, offer, bid)
                        except Exception as ex:
                            self.logException(f'Further error deactivating: {ex}')
            self.buildNotificationsCache(session)
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def initialise(self):
        self.log.debug('network_key %s\nnetwork_pubkey %s\nnetwork_addr %s',
                       self.network_key, self.network_pubkey, self.network_addr)

        ro = self.callrpc('smsglocalkeys')
        found = False
        for k in ro['smsg_keys']:
            if k['address'] == self.network_addr:
                found = True
                break
        if not found:
            self.log.info('Importing network key to SMSG')
            self.callrpc('smsgimportprivkey', [self.network_key, 'basicswap offers'])
            ro = self.callrpc('smsglocalkeys', ['anon', '-', self.network_addr])
            ensure(ro['result'] == 'Success.', 'smsglocalkeys failed')

        # TODO: Ensure smsg is enabled for the active wallet.

        self.loadFromDB()

        # Scan inbox
        # TODO: Redundant? small window for zmq messages to go unnoticed during startup?
        # options = {'encoding': 'hex'}
        options = {'encoding': 'none'}
        ro = self.callrpc('smsginbox', ['unread', '', options])
        nm = 0
        for msg in ro['messages']:
            # TODO: Remove workaround for smsginbox bug
            get_msg = self.callrpc('smsg', [msg['msgid'], {'encoding': 'hex', 'setread': True}])
            self.processMsg(get_msg)
            nm += 1
        self.log.info('Scanned %d unread messages.', nm)

    def getActiveBidMsgValidTime(self):
        return self.SMSG_SECONDS_IN_HOUR * 48

    def getAcceptBidMsgValidTime(self, bid):
        now = int(time.time())
        smsg_max_valid = self.SMSG_SECONDS_IN_HOUR * 48
        smsg_min_valid = self.SMSG_SECONDS_IN_HOUR * 1
        bid_valid = (bid.expire_at - now) + 10 * 60  # Add 10 minute buffer
        return max(smsg_min_valid, min(smsg_max_valid, bid_valid))

    def sendSmsg(self, addr_from, addr_to, payload_hex, msg_valid):
        options = {'decodehex': True, 'ttl_is_seconds': True}
        ro = self.callrpc('smsgsend', [addr_from, addr_to, payload_hex, False, msg_valid, False, options])
        return bytes.fromhex(ro['msgid'])

    def validateSwapType(self, coin_from, coin_to, swap_type):
        if coin_from == Coins.XMR:
            raise ValueError('TODO: XMR coin_from')
        if coin_to == Coins.XMR and swap_type != SwapTypes.XMR_SWAP:
            raise ValueError('Invalid swap type for XMR')
        if coin_from == Coins.PART_ANON:
            raise ValueError('TODO: PART_ANON coin_from')
        if coin_to == Coins.PART_ANON and swap_type != SwapTypes.XMR_SWAP:
            raise ValueError('Invalid swap type for PART_ANON')
        if (coin_from == Coins.PART_BLIND or coin_to == Coins.PART_BLIND) and swap_type != SwapTypes.XMR_SWAP:
            raise ValueError('Invalid swap type for PART_BLIND')
        if coin_from in (Coins.PIVX, Coins.DASH, Coins.FIRO, Coins.NMC) and swap_type == SwapTypes.XMR_SWAP:
            raise ValueError('TODO: {} -> XMR'.format(coin_from.name))

    def notify(self, event_type, event_data, session=None):

        show_event = event_type not in self._disabled_notification_types
        if event_type == NT.OFFER_RECEIVED:
            self.log.debug('Received new offer %s', event_data['offer_id'])
            if self.ws_server and show_event:
                event_data['event'] = 'new_offer'
                self.ws_server.send_message_to_all(json.dumps(event_data))
        elif event_type == NT.BID_RECEIVED:
            self.log.info('Received valid bid %s for %s offer %s', event_data['bid_id'], event_data['type'], event_data['offer_id'])
            if self.ws_server and show_event:
                event_data['event'] = 'new_bid'
                self.ws_server.send_message_to_all(json.dumps(event_data))
        elif event_type == NT.BID_ACCEPTED:
            self.log.info('Received valid bid accept for %s', event_data['bid_id'])
            if self.ws_server and show_event:
                event_data['event'] = 'bid_accepted'
                self.ws_server.send_message_to_all(json.dumps(event_data))
        else:
            self.log.warning(f'Unknown notification {event_type}')

        try:
            now = int(time.time())
            use_session = self.openSession(session)
            use_session.add(Notification(
                active_ind=1,
                created_at=now,
                event_type=int(event_type),
                event_data=bytes(json.dumps(event_data), 'UTF-8'),
            ))

            use_session.execute(f'DELETE FROM notifications WHERE record_id NOT IN (SELECT record_id FROM notifications WHERE active_ind=1 ORDER BY created_at ASC LIMIT {self._keep_notifications})')

            if show_event:
                self._notifications_cache[now] = (event_type, event_data)
            while len(self._notifications_cache) > self._show_notifications:
                # dicts preserve insertion order in Python 3.7+
                self._notifications_cache.pop(next(iter(self._notifications_cache)))

        finally:
            if session is None:
                self.closeSession(use_session)

    def buildNotificationsCache(self, session):
        q = session.execute(f'SELECT created_at, event_type, event_data FROM notifications WHERE active_ind=1 ORDER BY created_at ASC LIMIT {self._show_notifications}')
        for entry in q:
            self._notifications_cache[entry[0]] = (entry[1], json.loads(entry[2].decode('UTF-8')))

    def getNotifications(self):
        rv = []
        for k, v in self._notifications_cache.items():
            rv.append((time.strftime('%d-%m-%y %H:%M:%S', time.localtime(k)), int(v[0]), v[1]))
        return rv

    def vacuumDB(self):
        try:
            session = self.openSession()
            return session.execute('VACUUM')
        finally:
            self.closeSession(session)

    def validateOfferAmounts(self, coin_from, coin_to, amount, rate, min_bid_amount):
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        ensure(amount >= min_bid_amount, 'amount < min_bid_amount')
        ensure(amount > ci_from.min_amount(), 'From amount below min value for chain')
        ensure(amount < ci_from.max_amount(), 'From amount above max value for chain')

        amount_to = int((amount * rate) // ci_from.COIN())
        ensure(amount_to > ci_to.min_amount(), 'To amount below min value for chain')
        ensure(amount_to < ci_to.max_amount(), 'To amount above max value for chain')

    def validateOfferLockValue(self, coin_from, coin_to, lock_type, lock_value):
        coin_from_has_csv = self.coin_clients[coin_from]['use_csv']
        coin_to_has_csv = self.coin_clients[coin_to]['use_csv']

        if lock_type == OfferMessage.SEQUENCE_LOCK_TIME:
            ensure(lock_value >= self.min_sequence_lock_seconds and lock_value <= self.max_sequence_lock_seconds, 'Invalid lock_value time')
            ensure(coin_from_has_csv and coin_to_has_csv, 'Both coins need CSV activated.')
        elif lock_type == OfferMessage.SEQUENCE_LOCK_BLOCKS:
            ensure(lock_value >= 5 and lock_value <= 1000, 'Invalid lock_value blocks')
            ensure(coin_from_has_csv and coin_to_has_csv, 'Both coins need CSV activated.')
        elif lock_type == TxLockTypes.ABS_LOCK_TIME:
            # TODO: range?
            ensure(not coin_from_has_csv or not coin_to_has_csv, 'Should use CSV.')
            ensure(lock_value >= 4 * 60 * 60 and lock_value <= 96 * 60 * 60, 'Invalid lock_value time')
        elif lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
            # TODO: range?
            ensure(not coin_from_has_csv or not coin_to_has_csv, 'Should use CSV.')
            ensure(lock_value >= 10 and lock_value <= 1000, 'Invalid lock_value blocks')
        else:
            raise ValueError('Unknown locktype')

    def validateOfferValidTime(self, offer_type, coin_from, coin_to, valid_for_seconds):
        # TODO: adjust
        if valid_for_seconds < 10 * 60:
            raise ValueError('Offer TTL too low')
        if valid_for_seconds > 48 * 60 * 60:
            raise ValueError('Offer TTL too high')

    def validateBidValidTime(self, offer_type, coin_from, coin_to, valid_for_seconds):
        # TODO: adjust
        if valid_for_seconds < 10 * 60:
            raise ValueError('Bid TTL too low')
        if valid_for_seconds > 24 * 60 * 60:
            raise ValueError('Bid TTL too high')

    def validateBidAmount(self, offer, bid_amount, bid_rate):
        ensure(bid_amount >= offer.min_bid_amount, 'Bid amount below minimum')
        ensure(bid_amount <= offer.amount_from, 'Bid amount above offer amount')
        if not offer.amount_negotiable:
            ensure(offer.amount_from == bid_amount, 'Bid amount must match offer amount.')
        if not offer.rate_negotiable:
            ensure(offer.rate == bid_rate, 'Bid rate must match offer rate.')

    def getOfferAddressTo(self, extra_options):
        if 'addr_send_to' in extra_options:
            return extra_options['addr_send_to']
        return self.network_addr

    def postOffer(self, coin_from, coin_to, amount, rate, min_bid_amount, swap_type,
                  lock_type=TxLockTypes.SEQUENCE_LOCK_TIME, lock_value=48 * 60 * 60, auto_accept_bids=False, addr_send_from=None, extra_options={}):
        # Offer to send offer.amount_from of coin_from in exchange for offer.amount_from * offer.rate of coin_to

        ensure(coin_from != coin_to, 'coin_from == coin_to')
        try:
            coin_from_t = Coins(coin_from)
            ci_from = self.ci(coin_from_t)
        except Exception:
            raise ValueError('Unknown coin from type')
        try:
            coin_to_t = Coins(coin_to)
            ci_to = self.ci(coin_to_t)
        except Exception:
            raise ValueError('Unknown coin to type')

        valid_for_seconds = extra_options.get('valid_for_seconds', 60 * 60)

        self.validateSwapType(coin_from_t, coin_to_t, swap_type)
        self.validateOfferAmounts(coin_from_t, coin_to_t, amount, rate, min_bid_amount)
        self.validateOfferLockValue(coin_from_t, coin_to_t, lock_type, lock_value)
        self.validateOfferValidTime(swap_type, coin_from_t, coin_to_t, valid_for_seconds)

        offer_addr_to = self.getOfferAddressTo(extra_options)

        self.mxDB.acquire()
        session = None
        try:
            self.checkSynced(coin_from_t, coin_to_t)
            offer_addr = self.newSMSGAddress(use_type=AddressTypes.OFFER)[0] if addr_send_from is None else addr_send_from
            offer_created_at = int(time.time())

            msg_buf = OfferMessage()

            msg_buf.protocol_version = 1
            msg_buf.coin_from = int(coin_from)
            msg_buf.coin_to = int(coin_to)
            msg_buf.amount_from = int(amount)
            msg_buf.rate = int(rate)
            msg_buf.min_bid_amount = int(min_bid_amount)

            msg_buf.time_valid = valid_for_seconds
            msg_buf.lock_type = lock_type
            msg_buf.lock_value = lock_value
            msg_buf.swap_type = swap_type
            msg_buf.amount_negotiable = extra_options.get('amount_negotiable', False)
            msg_buf.rate_negotiable = extra_options.get('rate_negotiable', False)

            if msg_buf.amount_negotiable or msg_buf.rate_negotiable:
                ensure(auto_accept_bids is False, 'Auto-accept unavailable when amount or rate are variable')

            if 'from_fee_override' in extra_options:
                msg_buf.fee_rate_from = make_int(extra_options['from_fee_override'], self.ci(coin_from).exp())
            else:
                # TODO: conf_target = ci_from.settings.get('conf_target', 2)
                conf_target = 2
                if 'from_fee_conf_target' in extra_options:
                    conf_target = extra_options['from_fee_conf_target']
                fee_rate, fee_src = self.getFeeRateForCoin(coin_from, conf_target)
                if 'from_fee_multiplier_percent' in extra_options:
                    fee_rate *= extra_options['fee_multiplier'] / 100.0
                msg_buf.fee_rate_from = make_int(fee_rate, self.ci(coin_from).exp())

            if 'to_fee_override' in extra_options:
                msg_buf.fee_rate_to = make_int(extra_options['to_fee_override'], self.ci(coin_to).exp())
            else:
                # TODO: conf_target = ci_to.settings.get('conf_target', 2)
                conf_target = 2
                if 'to_fee_conf_target' in extra_options:
                    conf_target = extra_options['to_fee_conf_target']
                fee_rate, fee_src = self.getFeeRateForCoin(coin_to, conf_target)
                if 'to_fee_multiplier_percent' in extra_options:
                    fee_rate *= extra_options['fee_multiplier'] / 100.0
                msg_buf.fee_rate_to = make_int(fee_rate, self.ci(coin_to).exp())

            if swap_type == SwapTypes.XMR_SWAP:
                xmr_offer = XmrOffer()

                # Delay before the chain a lock refund tx can be mined
                xmr_offer.lock_time_1 = ci_from.getExpectedSequence(lock_type, lock_value)

                # Delay before the follower can spend from the chain a lock refund tx
                xmr_offer.lock_time_2 = ci_from.getExpectedSequence(lock_type, lock_value)

                xmr_offer.a_fee_rate = msg_buf.fee_rate_from
                xmr_offer.b_fee_rate = msg_buf.fee_rate_to  # Unused: TODO - Set priority?

            proof_of_funds_hash = getOfferProofOfFundsHash(msg_buf, offer_addr)
            proof_addr, proof_sig = self.getProofOfFunds(coin_from_t, int(amount), proof_of_funds_hash)
            # TODO: For now proof_of_funds is just a client side check, may need to be sent with offers in future however.

            offer_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.OFFER) + offer_bytes.hex()
            msg_valid = max(self.SMSG_SECONDS_IN_HOUR * 1, valid_for_seconds)
            offer_id = self.sendSmsg(offer_addr, offer_addr_to, payload_hex, msg_valid)

            security_token = extra_options.get('security_token', None)
            if security_token is not None and len(security_token) != 20:
                raise ValueError('Security token must be 20 bytes long.')

            session = scoped_session(self.session_factory)
            offer = Offer(
                offer_id=offer_id,
                active_ind=1,
                protocol_version=msg_buf.protocol_version,

                coin_from=msg_buf.coin_from,
                coin_to=msg_buf.coin_to,
                amount_from=msg_buf.amount_from,
                rate=msg_buf.rate,
                min_bid_amount=msg_buf.min_bid_amount,
                time_valid=msg_buf.time_valid,
                lock_type=int(msg_buf.lock_type),
                lock_value=msg_buf.lock_value,
                swap_type=msg_buf.swap_type,
                amount_negotiable=msg_buf.amount_negotiable,
                rate_negotiable=msg_buf.rate_negotiable,

                addr_to=offer_addr_to,
                addr_from=offer_addr,
                created_at=offer_created_at,
                expire_at=offer_created_at + msg_buf.time_valid,
                was_sent=True,
                security_token=security_token)
            offer.setState(OfferStates.OFFER_SENT)

            if swap_type == SwapTypes.XMR_SWAP:
                xmr_offer.offer_id = offer_id
                session.add(xmr_offer)

            automation_id = extra_options.get('automation_id', -1)
            if automation_id == -1 and auto_accept_bids:
                # Use default strategy
                automation_id = 1
            if automation_id != -1:
                auto_link = AutomationLink(
                    active_ind=1,
                    linked_type=Concepts.OFFER,
                    linked_id=offer_id,
                    strategy_id=automation_id,
                    created_at=offer_created_at,
                    repeat_limit=1,
                    repeat_count=0)
                session.add(auto_link)

            session.add(offer)
            session.add(SentOffer(offer_id=offer_id))
            session.commit()

        finally:
            if session:
                session.close()
                session.remove()
            self.mxDB.release()
        self.log.info('Sent OFFER %s', offer_id.hex())
        return offer_id

    def revokeOffer(self, offer_id, security_token=None):
        self.log.info('Revoking offer %s', offer_id.hex())

        session = None
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)

            offer = session.query(Offer).filter_by(offer_id=offer_id).first()

            if offer.security_token is not None and offer.security_token != security_token:
                raise ValueError('Mismatched security token')

            msg_buf = OfferRevokeMessage()
            msg_buf.offer_msg_id = offer_id

            signature_enc = self.callcoinrpc(Coins.PART, 'signmessage', [offer.addr_from, offer_id.hex() + '_revoke'])

            msg_buf.signature = base64.b64decode(signature_enc)

            msg_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.OFFER_REVOKE) + msg_bytes.hex()
            msg_id = self.sendSmsg(offer.addr_from, self.network_addr, payload_hex, offer.time_valid)
            self.log.debug('Revoked offer %s in msg %s', offer_id.hex(), msg_id.hex())
        finally:
            if session:
                session.close()
                session.remove()
            self.mxDB.release()

    def grindForEd25519Key(self, coin_type, evkey, key_path_base):
        ci = self.ci(coin_type)
        nonce = 1
        while True:
            key_path = key_path_base + '/{}'.format(nonce)
            extkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, key_path])['key_info']['result']
            privkey = decodeWif(self.callcoinrpc(Coins.PART, 'extkey', ['info', extkey])['key_info']['privkey'])

            if ci.verifyKey(privkey):
                return privkey
            nonce += 1
            if nonce > 1000:
                raise ValueError('grindForEd25519Key failed')

    def getWalletKey(self, coin_type, key_num, for_ed25519=False):
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']

        key_path_base = '44445555h/1h/{}/{}'.format(int(coin_type), key_num)

        if not for_ed25519:
            extkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, key_path_base])['key_info']['result']
            return decodeWif(self.callcoinrpc(Coins.PART, 'extkey', ['info', extkey])['key_info']['privkey'])

        return self.grindForEd25519Key(coin_type, evkey, key_path_base)

    def getPathKey(self, coin_from, coin_to, offer_created_at, contract_count, key_no, for_ed25519=False):
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']
        ci = self.ci(coin_to)

        days = offer_created_at // 86400
        secs = offer_created_at - days * 86400
        key_path_base = '44445555h/999999/{}/{}/{}/{}/{}/{}'.format(int(coin_from), int(coin_to), days, secs, contract_count, key_no)

        if not for_ed25519:
            extkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, key_path_base])['key_info']['result']
            return decodeWif(self.callcoinrpc(Coins.PART, 'extkey', ['info', extkey])['key_info']['privkey'])

        return self.grindForEd25519Key(coin_to, evkey, key_path_base)

    def getNetworkKey(self, key_num):
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']

        key_path = '44445556h/1h/{}'.format(int(key_num))

        extkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, key_path])['key_info']['result']
        return decodeWif(self.callcoinrpc(Coins.PART, 'extkey', ['info', extkey])['key_info']['privkey'])

    def getContractPubkey(self, date, contract_count):
        account = self.callcoinrpc(Coins.PART, 'extkey', ['account'])

        # Derive an address to use for a contract
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']

        # Should the coin path be included?
        path = '44445555h'
        path += '/' + str(date.year) + '/' + str(date.month) + '/' + str(date.day)
        path += '/' + str(contract_count)

        extkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, path])['key_info']['result']
        pubkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', extkey])['key_info']['pubkey']
        return bytes.fromhex(pubkey)

    def getContractPrivkey(self, date, contract_count):
        # Derive an address to use for a contract
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']

        path = '44445555h'
        path += '/' + str(date.year) + '/' + str(date.month) + '/' + str(date.day)
        path += '/' + str(contract_count)

        extkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, path])['key_info']['result']
        privkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', extkey])['key_info']['privkey']
        raw = decodeAddress(privkey)[1:]
        if len(raw) > 32:
            raw = raw[:32]
        return raw

    def getContractSecret(self, date, contract_count):
        # Derive a key to use for a contract secret
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']

        path = '44445555h/99999'
        path += '/' + str(date.year) + '/' + str(date.month) + '/' + str(date.day)
        path += '/' + str(contract_count)

        return hashlib.sha256(bytes(self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, path])['key_info']['result'], 'utf-8')).digest()

    def getReceiveAddressFromPool(self, coin_type, bid_id, tx_type):
        self.log.debug('Get address from pool bid_id {}, type {}, coin {}'.format(bid_id.hex(), tx_type, coin_type))
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            record = session.query(PooledAddress).filter(sa.and_(PooledAddress.coin_type == int(coin_type), PooledAddress.bid_id == None)).first()  # noqa: E712,E711
            if not record:
                address = self.getReceiveAddressForCoin(coin_type)
                record = PooledAddress(
                    addr=address,
                    coin_type=int(coin_type))
            record.bid_id = bid_id
            record.tx_type = tx_type
            addr = record.addr
            session.add(record)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()
        return addr

    def returnAddressToPool(self, bid_id, tx_type):
        self.log.debug('Return address to pool bid_id {}, type {}'.format(bid_id.hex(), tx_type))
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            try:
                record = session.query(PooledAddress).filter(sa.and_(PooledAddress.bid_id == bid_id, PooledAddress.tx_type == tx_type)).one()
                self.log.debug('Returning address to pool addr {}'.format(record.addr))
                record.bid_id = None
                session.commit()
            except Exception as ex:
                pass
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getReceiveAddressForCoin(self, coin_type):
        new_addr = self.ci(coin_type).getNewAddress(self.coin_clients[coin_type]['use_segwit'])
        self.log.debug('Generated new receive address %s for %s', new_addr, str(coin_type))
        return new_addr

    def getRelayFeeRateForCoin(self, coin_type):
        return self.callcoinrpc(coin_type, 'getnetworkinfo')['relayfee']

    def getFeeRateForCoin(self, coin_type, conf_target=2):
        chain_client_settings = self.getChainClientSettings(coin_type)
        override_feerate = chain_client_settings.get('override_feerate', None)
        if override_feerate:
            self.log.debug('Fee rate override used for %s: %f', str(coin_type), override_feerate)
            return override_feerate, 'override_feerate'

        return self.ci(coin_type).get_fee_rate(conf_target)

    def estimateWithdrawFee(self, coin_type, fee_rate):
        if coin_type == Coins.XMR:
            self.log.error('TODO: estimateWithdrawFee XMR')
            return None
        tx_vsize = self.getContractSpendTxVSize(coin_type)
        est_fee = (fee_rate * tx_vsize) / 1000
        return est_fee

    def withdrawCoin(self, coin_type, value, addr_to, subfee):
        ci = self.ci(coin_type)
        self.log.info('withdrawCoin %s %s to %s %s', value, ci.ticker(), addr_to, ' subfee' if subfee else '')

        txid = ci.withdrawCoin(value, addr_to, subfee)
        self.log.debug('In txn: {}'.format(txid))
        return txid

    def withdrawParticl(self, type_from, type_to, value, addr_to, subfee):
        self.log.info('withdrawParticl %s %s to %s %s %s', value, type_from, type_to, addr_to, ' subfee' if subfee else '')

        if type_from == 'plain':
            type_from = 'part'
        if type_to == 'plain':
            type_to = 'part'

        ci = self.ci(Coins.PART)
        txid = ci.sendTypeTo(type_from, type_to, value, addr_to, subfee)
        self.log.debug('In txn: {}'.format(txid))
        return txid

    def cacheNewAddressForCoin(self, coin_type):
        self.log.debug('cacheNewAddressForCoin %s', coin_type)
        key_str = 'receive_addr_' + chainparams[coin_type]['name']
        addr = self.getReceiveAddressForCoin(coin_type)
        self.setStringKV(key_str, addr)
        return addr

    def getCachedMainWalletAddress(self, ci):
        db_key = 'main_wallet_addr_' + ci.coin_name().lower()
        cached_addr = self.getStringKV(db_key)
        if cached_addr is not None:
            return cached_addr
        self.log.warning(f'Setting {db_key}')
        main_address = ci.getMainWalletAddress()
        self.setStringKV(db_key, main_address)
        return main_address

    def checkWalletSeed(self, c):
        ci = self.ci(c)
        if c == Coins.PART:
            return True  # TODO
        if c == Coins.XMR:
            expect_address = self.getCachedMainWalletAddress(ci)
            if expect_address is None:
                self.log.warning('Can\'t find expected main wallet address for coin {}'.format(ci.coin_name()))
                return False
            if expect_address == ci.getMainWalletAddress():
                ci.setWalletSeedWarning(False)
                return True
            self.log.warning('Wallet for coin {} not derived from swap seed.'.format(ci.coin_name()))
            return False

        expect_seedid = self.getStringKV('main_wallet_seedid_' + ci.coin_name().lower())
        if expect_seedid is None:
            self.log.warning('Can\'t find expected wallet seed id for coin {}'.format(ci.coin_name()))
            return False
        if ci.checkExpectedSeed(expect_seedid):
            ci.setWalletSeedWarning(False)
            return True
        self.log.warning('Wallet for coin {} not derived from swap seed.'.format(ci.coin_name()))
        return False

    def reseedWallet(self, coin_type):
        self.log.info('reseedWallet %s', coin_type)
        ci = self.ci(coin_type)
        if ci.knownWalletSeed():
            raise ValueError('{} wallet seed is already derived from the particl mnemonic'.format(ci.coin_name()))

        self.initialiseWallet(coin_type, raise_errors=True)

        # TODO: How to scan pruned blocks?

        if not self.checkWalletSeed(coin_type):
            if coin_type == Coins.XMR:
                raise ValueError('TODO: How to reseed XMR wallet?')
            else:
                raise ValueError('Wallet seed doesn\'t match expected.')

    def getCachedAddressForCoin(self, coin_type):
        self.log.debug('getCachedAddressForCoin %s', coin_type)
        # TODO: auto refresh after used

        key_str = 'receive_addr_' + chainparams[coin_type]['name']
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            try:
                addr = session.query(DBKVString).filter_by(key=key_str).first().value
            except Exception:
                addr = self.getReceiveAddressForCoin(coin_type)
                session.add(DBKVString(
                    key=key_str,
                    value=addr
                ))
                session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()
        return addr

    def getCachedStealthAddressForCoin(self, coin_type):
        self.log.debug('getCachedStealthAddressForCoin %s', coin_type)

        ci = self.ci(coin_type)
        key_str = 'stealth_addr_' + ci.coin_name().lower()
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            try:
                addr = session.query(DBKVString).filter_by(key=key_str).first().value
            except Exception:
                addr = ci.getNewStealthAddress()
                self.log.info('Generated new stealth address for %s', coin_type)
                session.add(DBKVString(
                    key=key_str,
                    value=addr
                ))
                session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()
        return addr

    def getCachedWalletRestoreHeight(self, ci):
        self.log.debug('getCachedWalletRestoreHeight %s', ci.coin_name())

        key_str = 'restore_height_' + ci.coin_name().lower()
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            try:
                wrh = session.query(DBKVInt).filter_by(key=key_str).first().value
            except Exception:
                wrh = ci.getWalletRestoreHeight()
                self.log.info('Found restore height for %s, block %d', ci.coin_name(), wrh)
                session.add(DBKVInt(
                    key=key_str,
                    value=wrh
                ))
                session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()
        return wrh

    def getWalletRestoreHeight(self, ci):
        wrh = ci._restore_height
        if wrh is not None:
            return wrh
        found_height = self.getCachedWalletRestoreHeight(ci)
        ci.setWalletRestoreHeight(found_height)
        return found_height

    def getNewContractId(self):
        self.mxDB.acquire()
        try:
            self._contract_count += 1
            session = scoped_session(self.session_factory)
            session.execute('UPDATE kv_int SET value = {} WHERE KEY="contract_count"'.format(self._contract_count))
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()
        return self._contract_count

    def getProofOfFunds(self, coin_type, amount_for, extra_commit_bytes):
        ci = self.ci(coin_type)
        self.log.debug('getProofOfFunds %s %s', ci.coin_name(), ci.format_amount(amount_for))

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return (None, None)

        return ci.getProofOfFunds(amount_for, extra_commit_bytes)

    def saveBidInSession(self, bid_id, bid, session, xmr_swap=None, save_in_progress=None):
        session.add(bid)
        if bid.initiate_tx:
            session.add(bid.initiate_tx)
        if bid.participate_tx:
            session.add(bid.participate_tx)
        if bid.xmr_a_lock_tx:
            session.add(bid.xmr_a_lock_tx)
        if bid.xmr_a_lock_spend_tx:
            session.add(bid.xmr_a_lock_spend_tx)
        if bid.xmr_b_lock_tx:
            session.add(bid.xmr_b_lock_tx)
        for tx_type, tx in bid.txns.items():
            session.add(tx)
        if xmr_swap is not None:
            session.add(xmr_swap)

        if save_in_progress is not None:
            if not isinstance(save_in_progress, Offer):
                raise ValueError('Must specify offer for save_in_progress')
            self.swaps_in_progress[bid_id] = (bid, save_in_progress)  # (bid, offer)

    def saveBid(self, bid_id, bid, xmr_swap=None):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            self.saveBidInSession(bid_id, bid, session, xmr_swap)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def saveToDB(self, db_record):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            session.add(db_record)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def createActionInSession(self, delay, action_type, linked_id, session):
        self.log.debug('createAction %d %s', action_type, linked_id.hex())
        now = int(time.time())
        action = Action(
            active_ind=1,
            created_at=now,
            trigger_at=now + delay,
            action_type=action_type,
            linked_id=linked_id)
        session.add(action)

    def createAction(self, delay, action_type, linked_id):
        # self.log.debug('createAction %d %s', action_type, linked_id.hex())
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            self.createActionInSession(delay, action_type, linked_id, session)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def logEvent(self, linked_type, linked_id, event_type, event_msg, session):
        entry = EventLog(
            active_ind=1,
            created_at=int(time.time()),
            linked_type=linked_type,
            linked_id=linked_id,
            event_type=int(event_type),
            event_msg=event_msg)

        if session is not None:
            session.add(entry)
            return
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            session.add(entry)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def logBidEvent(self, bid_id, event_type, event_msg, session):
        self.log.debug('logBidEvent %s %s', bid_id.hex(), event_type)
        self.logEvent(Concepts.BID, bid_id, event_type, event_msg, session)

    def countBidEvents(self, bid, event_type, session):
        q = session.execute('SELECT COUNT(*) FROM eventlog WHERE linked_type = {} AND linked_id = x\'{}\' AND event_type = {}'.format(int(Concepts.BID), bid.bid_id.hex(), int(event_type))).first()
        return q[0]

    def getEvents(self, linked_type, linked_id):
        events = []
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            for entry in session.query(EventLog).filter(sa.and_(EventLog.linked_type == linked_type, EventLog.linked_id == linked_id)):
                events.append(entry)
            return events
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def postBid(self, offer_id, amount, addr_send_from=None, extra_options={}):
        # Bid to send bid.amount * bid.rate of coin_to in exchange for bid.amount of coin_from
        self.log.debug('postBid %s', offer_id.hex())

        offer = self.getOffer(offer_id)
        ensure(offer, 'Offer not found: {}.'.format(offer_id.hex()))
        ensure(offer.expire_at > int(time.time()), 'Offer has expired')

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.postXmrBid(offer_id, amount, addr_send_from, extra_options)

        valid_for_seconds = extra_options.get('valid_for_seconds', 60 * 10)
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds)

        bid_rate = extra_options.get('bid_rate', offer.rate)
        self.validateBidAmount(offer, amount, bid_rate)

        self.mxDB.acquire()
        try:
            msg_buf = BidMessage()
            msg_buf.protocol_version = 1
            msg_buf.offer_msg_id = offer_id
            msg_buf.time_valid = valid_for_seconds
            msg_buf.amount = int(amount)  # amount of coin_from
            msg_buf.rate = bid_rate

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            self.checkSynced(coin_from, coin_to)

            amount_to = int((msg_buf.amount * bid_rate) // ci_from.COIN())

            now = int(time.time())
            if offer.swap_type == SwapTypes.SELLER_FIRST:
                proof_addr, proof_sig = self.getProofOfFunds(coin_to, amount_to, offer_id)
                msg_buf.proof_address = proof_addr
                msg_buf.proof_signature = proof_sig

                contract_count = self.getNewContractId()
                msg_buf.pkhash_buyer = getKeyID(self.getContractPubkey(dt.datetime.fromtimestamp(now).date(), contract_count))
            else:
                raise ValueError('TODO')

            bid_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.BID) + bid_bytes.hex()

            bid_addr = self.newSMSGAddress(use_type=AddressTypes.BID)[0] if addr_send_from is None else addr_send_from
            options = {'decodehex': True, 'ttl_is_seconds': True}
            msg_valid = max(self.SMSG_SECONDS_IN_HOUR * 1, valid_for_seconds)

            bid_id = self.sendSmsg(bid_addr, offer.addr_from, payload_hex, msg_valid)
            bid = Bid(
                protocol_version=msg_buf.protocol_version,
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                amount=msg_buf.amount,
                rate=msg_buf.rate,
                pkhash_buyer=msg_buf.pkhash_buyer,
                proof_address=msg_buf.proof_address,

                created_at=now,
                contract_count=contract_count,
                amount_to=amount_to,
                expire_at=now + msg_buf.time_valid,
                bid_addr=bid_addr,
                was_sent=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
            )
            bid.setState(BidStates.BID_SENT)

            try:
                session = scoped_session(self.session_factory)
                self.saveBidInSession(bid_id, bid, session)
                session.commit()
            finally:
                session.close()
                session.remove()

            self.log.info('Sent BID %s', bid_id.hex())
            return bid_id
        finally:
            self.mxDB.release()

    def getOffer(self, offer_id, sent=False):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            return session.query(Offer).filter_by(offer_id=offer_id).first()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def loadBidTxns(self, bid, session):
        bid.txns = {}
        for stx in session.query(SwapTx).filter(sa.and_(SwapTx.bid_id == bid.bid_id)):
            if stx.tx_type == TxTypes.ITX:
                bid.initiate_tx = stx
            elif stx.tx_type == TxTypes.PTX:
                bid.participate_tx = stx
            elif stx.tx_type == TxTypes.XMR_SWAP_A_LOCK:
                bid.xmr_a_lock_tx = stx
            elif stx.tx_type == TxTypes.XMR_SWAP_A_LOCK_SPEND:
                bid.xmr_a_lock_spend_tx = stx
            elif stx.tx_type == TxTypes.XMR_SWAP_B_LOCK:
                bid.xmr_b_lock_tx = stx
            else:
                bid.txns[stx.tx_type] = stx

    def getXmrBidFromSession(self, session, bid_id, sent=False):
        bid = session.query(Bid).filter_by(bid_id=bid_id).first()
        xmr_swap = None
        if bid:
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid_id).first()
            self.loadBidTxns(bid, session)
        return bid, xmr_swap

    def getXmrBid(self, bid_id, sent=False):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            return self.getXmrBidFromSession(session, bid_id, sent)
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getXmrOfferFromSession(self, session, offer_id, sent=False):
        offer = session.query(Offer).filter_by(offer_id=offer_id).first()
        xmr_offer = None
        if offer:
            xmr_offer = session.query(XmrOffer).filter_by(offer_id=offer_id).first()
        return offer, xmr_offer

    def getXmrOffer(self, offer_id, sent=False):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            return self.getXmrOfferFromSession(session, offer_id, sent)
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getBid(self, bid_id, session=None):
        try:
            use_session = self.openSession(session)
            bid = use_session.query(Bid).filter_by(bid_id=bid_id).first()
            if bid:
                self.loadBidTxns(bid, use_session)
            return bid
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def getBidAndOffer(self, bid_id, session=None):
        try:
            use_session = self.openSession(session)
            bid = use_session.query(Bid).filter_by(bid_id=bid_id).first()
            offer = None
            if bid:
                offer = use_session.query(Offer).filter_by(offer_id=bid.offer_id).first()
                self.loadBidTxns(bid, use_session)
            return bid, offer
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def getXmrBidAndOffer(self, bid_id, list_events=True):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            xmr_swap = None
            offer = None
            xmr_offer = None
            events = []

            bid = session.query(Bid).filter_by(bid_id=bid_id).first()
            if bid:
                offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
                if offer and offer.swap_type == SwapTypes.XMR_SWAP:
                    xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
                    xmr_offer = session.query(XmrOffer).filter_by(offer_id=bid.offer_id).first()
                self.loadBidTxns(bid, session)
                if list_events:
                    events = self.list_bid_events(bid.bid_id, session)

            return bid, xmr_swap, offer, xmr_offer, events
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getIdentity(self, address):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            identity = session.query(KnownIdentity).filter_by(address=address).first()
            return identity
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def updateIdentity(self, address, label):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            identity = session.query(KnownIdentity).filter_by(address=address).first()
            if identity is None:
                identity = KnownIdentity(address=address)
            identity.label = label
            session.add(identity)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def list_bid_events(self, bid_id, session):
        query_str = 'SELECT created_at, event_type, event_msg FROM eventlog ' + \
                    'WHERE active_ind = 1 AND linked_type = {} AND linked_id = x\'{}\' '.format(Concepts.BID, bid_id.hex())
        q = session.execute(query_str)
        events = []
        for row in q:
            events.append({'at': row[0], 'desc': describeEventEntry(row[1], row[2])})

        query_str = 'SELECT created_at, trigger_at FROM actions ' + \
                    'WHERE active_ind = 1 AND linked_id = x\'{}\' '.format(bid_id.hex())
        q = session.execute(query_str)
        for row in q:
            events.append({'at': row[0], 'desc': 'Delaying until: {}'.format(format_timestamp(row[1], with_seconds=True))})

        return events

    def acceptBid(self, bid_id):
        self.log.info('Accepting bid %s', bid_id.hex())

        bid, offer = self.getBidAndOffer(bid_id)
        ensure(bid, 'Bid not found')
        ensure(offer, 'Offer not found')

        # Ensure bid is still valid
        now = int(time.time())
        ensure(bid.expire_at > now, 'Bid expired')
        ensure(bid.state == BidStates.BID_RECEIVED, 'Wrong bid state: {}'.format(str(BidStates(bid.state))))

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.acceptXmrBid(bid_id)

        if bid.contract_count is None:
            bid.contract_count = self.getNewContractId()

        coin_from = Coins(offer.coin_from)
        ci_from = self.ci(coin_from)
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

        secret = self.getContractSecret(bid_date, bid.contract_count)
        secret_hash = hashlib.sha256(secret).digest()

        pubkey_refund = self.getContractPubkey(bid_date, bid.contract_count)
        pkhash_refund = getKeyID(pubkey_refund)

        if bid.initiate_tx is not None:
            self.log.warning('Initiate txn %s already exists for bid %s', bid.initiate_tx.txid, bid_id.hex())
            txid = bid.initiate_tx.txid
            script = bid.initiate_tx.script
        else:
            if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
                sequence = ci_from.getExpectedSequence(offer.lock_type, offer.lock_value)
                script = atomic_swap_1.buildContractScript(sequence, secret_hash, bid.pkhash_buyer, pkhash_refund)
            else:
                if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                    lock_value = self.callcoinrpc(coin_from, 'getblockcount') + offer.lock_value
                else:
                    lock_value = int(time.time()) + offer.lock_value
                self.log.debug('Initiate %s lock_value %d %d', coin_from, offer.lock_value, lock_value)
                script = atomic_swap_1.buildContractScript(lock_value, secret_hash, bid.pkhash_buyer, pkhash_refund, OpCodes.OP_CHECKLOCKTIMEVERIFY)

            p2sh = self.callcoinrpc(Coins.PART, 'decodescript', [script.hex()])['p2sh']

            bid.pkhash_seller = pkhash_refund

            txn = self.createInitiateTxn(coin_from, bid_id, bid, script)

            # Store the signed refund txn in case wallet is locked when refund is possible
            refund_txn = self.createRefundTxn(coin_from, txn, offer, bid, script)
            bid.initiate_txn_refund = bytes.fromhex(refund_txn)

            txid = ci_from.publishTx(bytes.fromhex(txn))
            self.log.debug('Submitted initiate txn %s to %s chain for bid %s', txid, ci_from.coin_name(), bid_id.hex())
            bid.initiate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.ITX,
                txid=bytes.fromhex(txid),
                tx_data=bytes.fromhex(txn),
                script=script,
            )
            bid.setITxState(TxStates.TX_SENT)

            # Check non-bip68 final
            try:
                txid = ci_from.publishTx(bid.initiate_txn_refund)
                self.log.error('Submit refund_txn unexpectedly worked: ' + txid)
            except Exception as ex:
                if 'non-BIP68-final' not in str(ex) and 'non-final' not in str(ex):
                    self.log.error('Submit refund_txn unexpected error' + str(ex))

        if txid is not None:
            msg_buf = BidAcceptMessage()
            msg_buf.bid_msg_id = bid_id
            msg_buf.initiate_txid = bytes.fromhex(txid)
            msg_buf.contract_script = bytes(script)

            bid_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.BID_ACCEPT) + bid_bytes.hex()

            msg_valid = self.getAcceptBidMsgValidTime(bid)
            bid.accept_msg_id = self.sendSmsg(offer.addr_from, bid.bid_addr, payload_hex, msg_valid)

            self.log.info('Sent BID_ACCEPT %s', bid.accept_msg_id.hex())
            bid.setState(BidStates.BID_ACCEPTED)

            self.saveBid(bid_id, bid)
            self.swaps_in_progress[bid_id] = (bid, offer)

    def postXmrBid(self, offer_id, amount, addr_send_from=None, extra_options={}):
        # Bid to send bid.amount * bid.rate of coin_to in exchange for bid.amount of coin_from
        # Send MSG1L F -> L
        self.log.debug('postXmrBid %s', offer_id.hex())

        self.mxDB.acquire()
        try:
            offer, xmr_offer = self.getXmrOffer(offer_id)

            ensure(offer, 'Offer not found: {}.'.format(offer_id.hex()))
            ensure(xmr_offer, 'XMR offer not found: {}.'.format(offer_id.hex()))
            ensure(offer.expire_at > int(time.time()), 'Offer has expired')

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            valid_for_seconds = extra_options.get('valid_for_seconds', 60 * 10)
            bid_rate = extra_options.get('bid_rate', offer.rate)
            amount_to = int((int(amount) * bid_rate) // ci_from.COIN())

            if not (self.debug and extra_options.get('debug_skip_validation', False)):
                self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds)
                self.validateBidAmount(offer, amount, bid_rate)

            self.checkSynced(coin_from, coin_to)

            balance_to = ci_to.getSpendableBalance()
            ensure(balance_to > amount_to, '{} spendable balance is too low: {}'.format(ci_to.coin_name(), ci_to.format_amount(balance_to)))

            msg_buf = XmrBidMessage()
            msg_buf.protocol_version = 1
            msg_buf.offer_msg_id = offer_id
            msg_buf.time_valid = valid_for_seconds
            msg_buf.amount = int(amount)  # Amount of coin_from
            msg_buf.rate = bid_rate

            address_out = self.getReceiveAddressFromPool(coin_from, offer_id, TxTypes.XMR_SWAP_A_LOCK)
            if coin_from == Coins.PART_BLIND:
                addrinfo = ci_from.rpc_callback('getaddressinfo', [address_out])
                msg_buf.dest_af = bytes.fromhex(addrinfo['pubkey'])
            else:
                msg_buf.dest_af = ci_from.decodeAddress(address_out)

            bid_created_at = int(time.time())
            if offer.swap_type != SwapTypes.XMR_SWAP:
                raise ValueError('TODO')

            # Follower to leader
            xmr_swap = XmrSwap()
            xmr_swap.contract_count = self.getNewContractId()
            xmr_swap.dest_af = msg_buf.dest_af

            for_ed25519 = True if coin_to == Coins.XMR else False
            kbvf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, KeyTypes.KBVF, for_ed25519)
            kbsf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)

            kaf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, KeyTypes.KAF)

            xmr_swap.vkbvf = kbvf
            xmr_swap.pkbvf = ci_to.getPubkey(kbvf)
            xmr_swap.pkbsf = ci_to.getPubkey(kbsf)

            xmr_swap.pkaf = ci_from.getPubkey(kaf)

            if coin_to == Coins.XMR:
                xmr_swap.kbsf_dleag = ci_to.proveDLEAG(kbsf)
            else:
                xmr_swap.kbsf_dleag = xmr_swap.pkbsf
            xmr_swap.pkasf = xmr_swap.kbsf_dleag[0: 33]
            assert (xmr_swap.pkasf == ci_from.getPubkey(kbsf))

            msg_buf.pkaf = xmr_swap.pkaf
            msg_buf.kbvf = kbvf
            if coin_to == Coins.XMR:
                msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag[:16000]
            else:
                msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag

            bid_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_FL) + bid_bytes.hex()

            bid_addr = self.newSMSGAddress(use_type=AddressTypes.BID)[0] if addr_send_from is None else addr_send_from
            options = {'decodehex': True, 'ttl_is_seconds': True}
            msg_valid = max(self.SMSG_SECONDS_IN_HOUR * 1, valid_for_seconds)
            xmr_swap.bid_id = self.sendSmsg(bid_addr, offer.addr_from, payload_hex, msg_valid)

            if coin_to == Coins.XMR:
                msg_buf2 = XmrSplitMessage(
                    msg_id=xmr_swap.bid_id,
                    msg_type=XmrSplitMsgTypes.BID,
                    sequence=2,
                    dleag=xmr_swap.kbsf_dleag[16000:32000]
                )
                msg_bytes = msg_buf2.SerializeToString()
                payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
                xmr_swap.bid_msg_id2 = self.sendSmsg(bid_addr, offer.addr_from, payload_hex, msg_valid)

                msg_buf3 = XmrSplitMessage(
                    msg_id=xmr_swap.bid_id,
                    msg_type=XmrSplitMsgTypes.BID,
                    sequence=3,
                    dleag=xmr_swap.kbsf_dleag[32000:]
                )
                msg_bytes = msg_buf3.SerializeToString()
                payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
                xmr_swap.bid_msg_id3 = self.sendSmsg(bid_addr, offer.addr_from, payload_hex, msg_valid)

            bid = Bid(
                protocol_version=msg_buf.protocol_version,
                active_ind=1,
                bid_id=xmr_swap.bid_id,
                offer_id=offer_id,
                amount=msg_buf.amount,
                rate=msg_buf.rate,
                created_at=bid_created_at,
                contract_count=xmr_swap.contract_count,
                amount_to=(msg_buf.amount * msg_buf.rate) // ci_from.COIN(),
                expire_at=bid_created_at + msg_buf.time_valid,
                bid_addr=bid_addr,
                was_sent=True,
            )

            bid.chain_a_height_start = ci_from.getChainHeight()
            bid.chain_b_height_start = ci_to.getChainHeight()

            wallet_restore_height = self.getWalletRestoreHeight(ci_to)
            if bid.chain_b_height_start < wallet_restore_height:
                bid.chain_b_height_start = wallet_restore_height
                self.log.warning('XMR swap restore height clamped to {}'.format(wallet_restore_height))

            bid.setState(BidStates.BID_SENT)

            try:
                session = scoped_session(self.session_factory)
                self.saveBidInSession(xmr_swap.bid_id, bid, session, xmr_swap)
                session.commit()
            finally:
                session.close()
                session.remove()

            self.log.info('Sent XMR_BID_FL %s', xmr_swap.bid_id.hex())
            return xmr_swap.bid_id
        finally:
            self.mxDB.release()

    def acceptXmrBid(self, bid_id):
        # MSG1F and MSG2F L -> F
        self.log.info('Accepting xmr bid %s', bid_id.hex())

        now = int(time.time())
        self.mxDB.acquire()
        try:
            bid, xmr_swap = self.getXmrBid(bid_id)
            ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
            ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))
            ensure(bid.expire_at > now, 'Bid expired')

            last_bid_state = bid.state
            if last_bid_state == BidStates.SWAP_DELAYING:
                last_bid_state = getLastBidState(bid.states)

            ensure(last_bid_state == BidStates.BID_RECEIVED, 'Wrong bid state: {}'.format(str(BidStates(last_bid_state))))

            offer, xmr_offer = self.getXmrOffer(bid.offer_id)
            ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(offer.expire_at > now, 'Offer has expired')

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            if xmr_swap.contract_count is None:
                xmr_swap.contract_count = self.getNewContractId()

            for_ed25519 = True if coin_to == Coins.XMR else False
            kbvl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBVL, for_ed25519)
            kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSL, for_ed25519)

            kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAL)

            xmr_swap.vkbvl = kbvl
            xmr_swap.pkbvl = ci_to.getPubkey(kbvl)
            xmr_swap.pkbsl = ci_to.getPubkey(kbsl)

            xmr_swap.vkbv = ci_to.sumKeys(kbvl, xmr_swap.vkbvf)
            ensure(ci_to.verifyKey(xmr_swap.vkbv), 'Invalid key, vkbv')
            xmr_swap.pkbv = ci_to.sumPubkeys(xmr_swap.pkbvl, xmr_swap.pkbvf)
            xmr_swap.pkbs = ci_to.sumPubkeys(xmr_swap.pkbsl, xmr_swap.pkbsf)

            xmr_swap.pkal = ci_from.getPubkey(kal)

            if coin_to == Coins.XMR:
                xmr_swap.kbsl_dleag = ci_to.proveDLEAG(kbsl)
            else:
                xmr_swap.kbsl_dleag = xmr_swap.pkbsl

            # MSG2F
            xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script = ci_from.createSCLockTx(
                bid.amount,
                xmr_swap.pkal, xmr_swap.pkaf, xmr_swap.vkbv
            )
            xmr_swap.a_lock_tx = ci_from.fundSCLockTx(xmr_swap.a_lock_tx, xmr_offer.a_fee_rate, xmr_swap.vkbv)

            xmr_swap.a_lock_tx_id = ci_from.getTxid(xmr_swap.a_lock_tx)
            a_lock_tx_dest = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)

            xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script, xmr_swap.a_swap_refund_value = ci_from.createSCLockRefundTx(
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.lock_time_1, xmr_offer.lock_time_2,
                xmr_offer.a_fee_rate, xmr_swap.vkbv
            )
            xmr_swap.a_lock_refund_tx_id = ci_from.getTxid(xmr_swap.a_lock_refund_tx)

            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.al_lock_refund_tx_sig = ci_from.signTx(kal, xmr_swap.a_lock_refund_tx, 0, xmr_swap.a_lock_tx_script, prevout_amount)
            v = ci_from.verifyTxSig(xmr_swap.a_lock_refund_tx, xmr_swap.al_lock_refund_tx_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, prevout_amount)
            ensure(v, 'Invalid coin A lock refund tx leader sig')

            pkh_refund_to = ci_from.decodeAddress(self.getReceiveAddressForCoin(coin_from))
            xmr_swap.a_lock_refund_spend_tx = ci_from.createSCLockRefundSpendTx(
                xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script,
                pkh_refund_to,
                xmr_offer.a_fee_rate, xmr_swap.vkbv
            )
            xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_refund_spend_tx)

            # Double check txns before sending
            self.log.debug('Bid: {} - Double checking chain A lock txns are valid before sending bid accept.'.format(bid_id.hex()))
            check_lock_tx_inputs = False  # TODO: check_lock_tx_inputs without txindex
            _, xmr_swap.a_lock_tx_vout = ci_from.verifySCLockTx(
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_tx_script,
                bid.amount,
                xmr_swap.pkal,
                xmr_swap.pkaf,
                xmr_offer.a_fee_rate,
                check_lock_tx_inputs,
                xmr_swap.vkbv)

            _, _, lock_refund_vout = ci_from.verifySCLockRefundTx(
                xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_refund_tx_script,
                xmr_swap.a_lock_tx_id,
                xmr_swap.a_lock_tx_vout,
                xmr_offer.lock_time_1,
                xmr_swap.a_lock_tx_script,
                xmr_swap.pkal,
                xmr_swap.pkaf,
                xmr_offer.lock_time_2,
                bid.amount,
                xmr_offer.a_fee_rate,
                xmr_swap.vkbv)

            ci_from.verifySCLockRefundSpendTx(
                xmr_swap.a_lock_refund_spend_tx, xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_id, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.pkal,
                lock_refund_vout, xmr_swap.a_swap_refund_value, xmr_offer.a_fee_rate,
                xmr_swap.vkbv)

            msg_buf = XmrBidAcceptMessage()
            msg_buf.bid_msg_id = bid_id
            msg_buf.pkal = xmr_swap.pkal
            msg_buf.kbvl = kbvl
            if coin_to == Coins.XMR:
                msg_buf.kbsl_dleag = xmr_swap.kbsl_dleag[:16000]
            else:
                msg_buf.kbsl_dleag = xmr_swap.kbsl_dleag

            # MSG2F
            msg_buf.a_lock_tx = xmr_swap.a_lock_tx
            msg_buf.a_lock_tx_script = xmr_swap.a_lock_tx_script
            msg_buf.a_lock_refund_tx = xmr_swap.a_lock_refund_tx
            msg_buf.a_lock_refund_tx_script = xmr_swap.a_lock_refund_tx_script
            msg_buf.a_lock_refund_spend_tx = xmr_swap.a_lock_refund_spend_tx
            msg_buf.al_lock_refund_tx_sig = xmr_swap.al_lock_refund_tx_sig

            msg_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_ACCEPT_LF) + msg_bytes.hex()

            msg_valid = self.getAcceptBidMsgValidTime(bid)
            bid.accept_msg_id = self.sendSmsg(offer.addr_from, bid.bid_addr, payload_hex, msg_valid)
            xmr_swap.bid_accept_msg_id = bid.accept_msg_id

            if coin_to == Coins.XMR:
                msg_buf2 = XmrSplitMessage(
                    msg_id=bid_id,
                    msg_type=XmrSplitMsgTypes.BID_ACCEPT,
                    sequence=2,
                    dleag=xmr_swap.kbsl_dleag[16000:32000]
                )
                msg_bytes = msg_buf2.SerializeToString()
                payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
                xmr_swap.bid_accept_msg_id2 = self.sendSmsg(offer.addr_from, bid.bid_addr, payload_hex, msg_valid)

                msg_buf3 = XmrSplitMessage(
                    msg_id=bid_id,
                    msg_type=XmrSplitMsgTypes.BID_ACCEPT,
                    sequence=3,
                    dleag=xmr_swap.kbsl_dleag[32000:]
                )
                msg_bytes = msg_buf3.SerializeToString()
                payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
                xmr_swap.bid_accept_msg_id3 = self.sendSmsg(offer.addr_from, bid.bid_addr, payload_hex, msg_valid)

            bid.setState(BidStates.BID_ACCEPTED)

            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

            # Add to swaps_in_progress only when waiting on txns
            self.log.info('Sent XMR_BID_ACCEPT_LF %s', bid_id.hex())
            return bid_id
        finally:
            self.mxDB.release()

    def abandonBid(self, bid_id):
        self.log.info('Abandoning Bid %s', bid_id.hex())
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            bid = session.query(Bid).filter_by(bid_id=bid_id).first()
            ensure(bid, 'Bid not found')
            offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
            ensure(offer, 'Offer not found')

            # Mark bid as abandoned, no further processing will be done
            bid.setState(BidStates.BID_ABANDONED)
            self.deactivateBid(session, offer, bid)
            session.add(bid)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def setBidError(self, bid_id, bid, error_str, save_bid=True, xmr_swap=None):
        self.log.error('Bid %s - Error: %s', bid_id.hex(), error_str)
        bid.setState(BidStates.BID_ERROR)
        bid.state_note = 'error msg: ' + error_str
        if save_bid:
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

    def createInitiateTxn(self, coin_type, bid_id, bid, initiate_script):
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None
        ci = self.ci(coin_type)

        if self.coin_clients[coin_type]['use_segwit']:
            addr_to = ci.encode_p2wsh(getP2WSH(initiate_script))
        else:
            addr_to = ci.encode_p2sh(initiate_script)
        self.log.debug('Create initiate txn for coin %s to %s for bid %s', str(coin_type), addr_to, bid_id.hex())

        txn_signed = ci.createRawSignedTransaction(addr_to, bid.amount)
        return txn_signed

    def deriveParticipateScript(self, bid_id, bid, offer):
        self.log.debug('deriveParticipateScript for bid %s', bid_id.hex())

        coin_to = Coins(offer.coin_to)
        ci_to = self.ci(coin_to)

        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        pkhash_seller = bid.pkhash_seller
        pkhash_buyer_refund = bid.pkhash_buyer

        # Participate txn is locked for half the time of the initiate txn
        lock_value = offer.lock_value // 2
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = ci_to.getExpectedSequence(offer.lock_type, lock_value)
            participate_script = atomic_swap_1.buildContractScript(sequence, secret_hash, pkhash_seller, pkhash_buyer_refund)
        else:
            # Lock from the height or time of the block containing the initiate txn
            coin_from = Coins(offer.coin_from)
            initiate_tx_block_hash = self.callcoinrpc(coin_from, 'getblockhash', [bid.initiate_tx.chain_height, ])
            initiate_tx_block_time = int(self.callcoinrpc(coin_from, 'getblock', [initiate_tx_block_hash, ])['time'])
            if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                # Walk the coin_to chain back until block time matches
                block_header_at = ci_to.getBlockHeaderAt(initiate_tx_block_time, block_after=True)
                cblock_hash = block_header_at['hash']
                cblock_height = block_header_at['height']

                self.log.debug('Setting lock value from height of block %s %s', coin_to, cblock_hash)
                contract_lock_value = cblock_height + lock_value
            else:
                self.log.debug('Setting lock value from time of block %s %s', coin_from, initiate_tx_block_hash)
                contract_lock_value = initiate_tx_block_time + lock_value
            self.log.debug('participate %s lock_value %d %d', coin_to, lock_value, contract_lock_value)
            participate_script = atomic_swap_1.buildContractScript(contract_lock_value, secret_hash, pkhash_seller, pkhash_buyer_refund, OpCodes.OP_CHECKLOCKTIMEVERIFY)
        return participate_script

    def createParticipateTxn(self, bid_id, bid, offer, participate_script):
        self.log.debug('createParticipateTxn')

        offer_id = bid.offer_id
        coin_to = Coins(offer.coin_to)

        if self.coin_clients[coin_to]['connection_type'] != 'rpc':
            return None
        ci = self.ci(coin_to)

        amount_to = bid.amount_to
        # Check required?
        assert (amount_to == (bid.amount * bid.rate) // self.ci(offer.coin_from).COIN())

        if bid.debug_ind == DebugTypes.MAKE_INVALID_PTX:
            amount_to -= 1
            self.log.debug('bid %s: Make invalid PTx for testing: %d.', bid_id.hex(), bid.debug_ind)
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), None)

        if self.coin_clients[coin_to]['use_segwit']:
            p2wsh = getP2WSH(participate_script)
            addr_to = ci.encode_p2wsh(p2wsh)
        else:
            addr_to = ci.encode_p2sh(participate_script)

        txn_signed = ci.createRawSignedTransaction(addr_to, amount_to)

        refund_txn = self.createRefundTxn(coin_to, txn_signed, offer, bid, participate_script, tx_type=TxTypes.PTX_REFUND)
        bid.participate_txn_refund = bytes.fromhex(refund_txn)

        chain_height = self.callcoinrpc(coin_to, 'getblockcount')
        txjs = self.callcoinrpc(coin_to, 'decoderawtransaction', [txn_signed])
        txid = txjs['txid']

        if self.coin_clients[coin_to]['use_segwit']:
            vout = getVoutByP2WSH(txjs, p2wsh.hex())
        else:
            vout = getVoutByAddress(txjs, addr_to)
        self.addParticipateTxn(bid_id, bid, coin_to, txid, vout, chain_height)
        bid.participate_tx.script = participate_script
        bid.participate_tx.tx_data = bytes.fromhex(txn_signed)

        return txn_signed

    def getContractSpendTxVSize(self, coin_type, redeem=True):
        tx_vsize = 5  # Add a few bytes, sequence in script takes variable amount of bytes
        if coin_type == Coins.PART:
            tx_vsize += 204 if redeem else 187
        if self.coin_clients[coin_type]['use_segwit']:
            tx_vsize += 143 if redeem else 134
        else:
            tx_vsize += 323 if redeem else 287
        return tx_vsize

    def createRedeemTxn(self, coin_type, bid, for_txn_type='participate', addr_redeem_out=None, fee_rate=None):
        self.log.debug('createRedeemTxn for coin %s', str(coin_type))
        ci = self.ci(coin_type)

        if for_txn_type == 'participate':
            prev_txnid = bid.participate_tx.txid.hex()
            prev_n = bid.participate_tx.vout
            txn_script = bid.participate_tx.script
            prev_amount = bid.amount_to
        else:
            prev_txnid = bid.initiate_tx.txid.hex()
            prev_n = bid.initiate_tx.vout
            txn_script = bid.initiate_tx.script
            prev_amount = bid.amount

        if self.coin_clients[coin_type]['use_segwit']:
            prev_p2wsh = getP2WSH(txn_script)
            script_pub_key = prev_p2wsh.hex()
        else:
            script_pub_key = getP2SHScriptForHash(getKeyID(txn_script)).hex()

        prevout = {
            'txid': prev_txnid,
            'vout': prev_n,
            'scriptPubKey': script_pub_key,
            'redeemScript': txn_script.hex(),
            'amount': ci.format_amount(prev_amount)}

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        wif_prefix = chainparams[Coins.PART][self.chain]['key_prefix']
        pubkey = self.getContractPubkey(bid_date, bid.contract_count)
        privkey = toWIF(wif_prefix, self.getContractPrivkey(bid_date, bid.contract_count))

        secret = bid.recovered_secret
        if secret is None:
            secret = self.getContractSecret(bid_date, bid.contract_count)
        ensure(len(secret) == 32, 'Bad secret length')

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None

        prevout_s = ' in={}:{}'.format(prev_txnid, prev_n)

        if fee_rate is None:
            fee_rate, fee_src = self.getFeeRateForCoin(coin_type)

        tx_vsize = self.getContractSpendTxVSize(coin_type)
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug('Redeem tx fee %s, rate %s', ci.format_amount(tx_fee, conv_int=True, r=1), str(fee_rate))

        amount_out = prev_amount - ci.make_int(tx_fee, r=1)
        ensure(amount_out > 0, 'Amount out <= 0')

        if addr_redeem_out is None:
            addr_redeem_out = self.getReceiveAddressFromPool(coin_type, bid.bid_id, TxTypes.PTX_REDEEM if for_txn_type == 'participate' else TxTypes.ITX_REDEEM)
        assert (addr_redeem_out is not None)

        if self.coin_clients[coin_type]['use_segwit']:
            # Change to part hrp
            addr_redeem_out = self.ci(Coins.PART).encodeSegwitAddress(ci.decodeSegwitAddress(addr_redeem_out))
        else:
            addr_redeem_out = replaceAddrPrefix(addr_redeem_out, Coins.PART, self.chain)
        self.log.debug('addr_redeem_out %s', addr_redeem_out)
        output_to = ' outaddr={}:{}'.format(ci.format_amount(amount_out), addr_redeem_out)
        if coin_type == Coins.PART:
            redeem_txn = self.calltx('-create' + prevout_s + output_to)
        else:
            redeem_txn = self.calltx('-btcmode -create nversion=2' + prevout_s + output_to)

        options = {}
        if self.coin_clients[coin_type]['use_segwit']:
            options['force_segwit'] = True
        redeem_sig = self.callcoinrpc(Coins.PART, 'createsignaturewithkey', [redeem_txn, prevout, privkey, 'ALL', options])
        if coin_type == Coins.PART or self.coin_clients[coin_type]['use_segwit']:
            witness_stack = [
                redeem_sig,
                pubkey.hex(),
                secret.hex(),
                '01',
                txn_script.hex()]
            redeem_txn = self.calltx(redeem_txn + ' witness=0:' + ':'.join(witness_stack))
        else:
            script = format(len(redeem_sig) // 2, '02x') + redeem_sig
            script += format(33, '02x') + pubkey.hex()
            script += format(32, '02x') + secret.hex()
            script += format(OpCodes.OP_1, '02x')
            script += format(OpCodes.OP_PUSHDATA1, '02x') + format(len(txn_script), '02x') + txn_script.hex()
            redeem_txn = self.calltx(redeem_txn + ' scriptsig=0:' + script)

        ro = self.callcoinrpc(Coins.PART, 'verifyrawtransaction', [redeem_txn, [prevout]])
        ensure(ro['inputs_valid'] is True, 'inputs_valid is false')
        # outputs_valid will be false if not a Particl txn
        # ensure(ro['complete'] is True, 'complete is false')
        ensure(ro['validscripts'] == 1, 'validscripts != 1')

        if self.debug:
            # Check fee
            if ci.get_connection_type() == 'rpc':
                redeem_txjs = self.callcoinrpc(coin_type, 'decoderawtransaction', [redeem_txn])
                if ci.using_segwit():
                    self.log.debug('vsize paid, actual vsize %d %d', tx_vsize, redeem_txjs['vsize'])
                    ensure(tx_vsize >= redeem_txjs['vsize'], 'underpaid fee')
                else:
                    self.log.debug('size paid, actual size %d %d', tx_vsize, redeem_txjs['size'])
                    ensure(tx_vsize >= redeem_txjs['size'], 'underpaid fee')

            redeem_txjs = self.callcoinrpc(Coins.PART, 'decoderawtransaction', [redeem_txn])
            self.log.debug('Have valid redeem txn %s for contract %s tx %s', redeem_txjs['txid'], for_txn_type, prev_txnid)

        return redeem_txn

    def createRefundTxn(self, coin_type, txn, offer, bid, txn_script, addr_refund_out=None, tx_type=TxTypes.ITX_REFUND):
        self.log.debug('createRefundTxn for coin %s', Coins(coin_type).name)
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None

        txjs = self.callcoinrpc(Coins.PART, 'decoderawtransaction', [txn])
        if self.coin_clients[coin_type]['use_segwit']:
            p2wsh = getP2WSH(txn_script)
            vout = getVoutByP2WSH(txjs, p2wsh.hex())
        else:
            addr_to = self.ci(Coins.PART).encode_p2sh(txn_script)
            vout = getVoutByAddress(txjs, addr_to)

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        wif_prefix = chainparams[Coins.PART][self.chain]['key_prefix']
        pubkey = self.getContractPubkey(bid_date, bid.contract_count)
        privkey = toWIF(wif_prefix, self.getContractPrivkey(bid_date, bid.contract_count))

        prev_amount = txjs['vout'][vout]['value']
        prevout = {
            'txid': txjs['txid'],
            'vout': vout,
            'scriptPubKey': txjs['vout'][vout]['scriptPubKey']['hex'],
            'redeemScript': txn_script.hex(),
            'amount': prev_amount}

        lock_value = DeserialiseNum(txn_script, 64)
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = lock_value
        else:
            sequence = 1
        prevout_s = ' in={}:{}:{}'.format(txjs['txid'], vout, sequence)

        fee_rate, fee_src = self.getFeeRateForCoin(coin_type)

        tx_vsize = self.getContractSpendTxVSize(coin_type, False)
        tx_fee = (fee_rate * tx_vsize) / 1000

        ci = self.ci(coin_type)
        self.log.debug('Refund tx fee %s, rate %s', ci.format_amount(tx_fee, conv_int=True, r=1), str(fee_rate))

        amount_out = ci.make_int(prev_amount, r=1) - ci.make_int(tx_fee, r=1)
        if amount_out <= 0:
            raise ValueError('Refund amount out <= 0')

        if addr_refund_out is None:
            addr_refund_out = self.getReceiveAddressFromPool(coin_type, bid.bid_id, tx_type)
        ensure(addr_refund_out is not None, 'addr_refund_out is null')
        if self.coin_clients[coin_type]['use_segwit']:
            # Change to part hrp
            addr_refund_out = self.ci(Coins.PART).encodeSegwitAddress(ci.decodeSegwitAddress(addr_refund_out))
        else:
            addr_refund_out = replaceAddrPrefix(addr_refund_out, Coins.PART, self.chain)
        self.log.debug('addr_refund_out %s', addr_refund_out)

        output_to = ' outaddr={}:{}'.format(ci.format_amount(amount_out), addr_refund_out)
        if coin_type == Coins.PART:
            refund_txn = self.calltx('-create' + prevout_s + output_to)
        else:
            refund_txn = self.calltx('-btcmode -create nversion=2' + prevout_s + output_to)

        if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS or offer.lock_type == TxLockTypes.ABS_LOCK_TIME:
            refund_txn = self.calltx('{} locktime={}'.format(refund_txn, lock_value))

        options = {}
        if self.coin_clients[coin_type]['use_segwit']:
            options['force_segwit'] = True
        refund_sig = self.callcoinrpc(Coins.PART, 'createsignaturewithkey', [refund_txn, prevout, privkey, 'ALL', options])
        if coin_type == Coins.PART or self.coin_clients[coin_type]['use_segwit']:
            witness_stack = [
                refund_sig,
                pubkey.hex(),
                '',  # SCRIPT_VERIFY_MINIMALIF
                txn_script.hex()]
            refund_txn = self.calltx(refund_txn + ' witness=0:' + ':'.join(witness_stack))
        else:
            script = format(len(refund_sig) // 2, '02x') + refund_sig
            script += format(33, '02x') + pubkey.hex()
            script += format(OpCodes.OP_0, '02x')
            script += format(OpCodes.OP_PUSHDATA1, '02x') + format(len(txn_script), '02x') + txn_script.hex()
            refund_txn = self.calltx(refund_txn + ' scriptsig=0:' + script)

        ro = self.callcoinrpc(Coins.PART, 'verifyrawtransaction', [refund_txn, [prevout]])
        ensure(ro['inputs_valid'] is True, 'inputs_valid is false')
        # outputs_valid will be false if not a Particl txn
        # ensure(ro['complete'] is True, 'complete is false')
        ensure(ro['validscripts'] == 1, 'validscripts != 1')

        if self.debug:
            # Check fee
            if ci.get_connection_type() == 'rpc':
                refund_txjs = self.callcoinrpc(coin_type, 'decoderawtransaction', [refund_txn])
                if ci.using_segwit():
                    self.log.debug('vsize paid, actual vsize %d %d', tx_vsize, refund_txjs['vsize'])
                    ensure(tx_vsize >= refund_txjs['vsize'], 'underpaid fee')
                else:
                    self.log.debug('size paid, actual size %d %d', tx_vsize, refund_txjs['size'])
                    ensure(tx_vsize >= refund_txjs['size'], 'underpaid fee')

            refund_txjs = self.callcoinrpc(Coins.PART, 'decoderawtransaction', [refund_txn])
            self.log.debug('Have valid refund txn %s for contract tx %s', refund_txjs['txid'], txjs['txid'])

        return refund_txn

    def initiateTxnConfirmed(self, bid_id, bid, offer):
        self.log.debug('initiateTxnConfirmed for bid %s', bid_id.hex())
        bid.setState(BidStates.SWAP_INITIATED)
        bid.setITxState(TxStates.TX_CONFIRMED)

        if bid.debug_ind == DebugTypes.BUYER_STOP_AFTER_ITX:
            self.log.debug('bid %s: Abandoning bid for testing: %d, %s.', bid_id.hex(), bid.debug_ind, DebugTypes(bid.debug_ind).name)
            bid.setState(BidStates.BID_ABANDONED)
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), None)
            return  # Bid saved in checkBidState

        # Seller first mode, buyer participates
        participate_script = self.deriveParticipateScript(bid_id, bid, offer)
        if bid.was_sent:
            if bid.participate_tx is not None:
                self.log.warning('Participate txn %s already exists for bid %s', bid.participate_tx.txid, bid_id.hex())
            else:
                self.log.debug('Preparing participate txn for bid %s', bid_id.hex())

                coin_to = Coins(offer.coin_to)
                txn = self.createParticipateTxn(bid_id, bid, offer, participate_script)
                txid = self.ci(coin_to).publishTx(bytes.fromhex(txn))
                self.log.debug('Submitted participate txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
                bid.setPTxState(TxStates.TX_SENT)
        else:
            bid.participate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.PTX,
                script=participate_script,
            )

        # Bid saved in checkBidState

    def setLastHeightChecked(self, coin_type, tx_height):
        coin_name = self.ci(coin_type).coin_name()
        if tx_height < 1:
            tx_height = self.lookupChainHeight(coin_type)

        if len(self.coin_clients[coin_type]['watched_outputs']) == 0:
            self.coin_clients[coin_type]['last_height_checked'] = tx_height
            self.log.debug('Start checking %s chain at height %d', coin_name, tx_height)

        if self.coin_clients[coin_type]['last_height_checked'] > tx_height:
            self.coin_clients[coin_type]['last_height_checked'] = tx_height
            self.log.debug('Rewind checking of %s chain to height %d', coin_name, tx_height)

        return tx_height

    def addParticipateTxn(self, bid_id, bid, coin_type, txid_hex, vout, tx_height):

        # TODO: Check connection type
        participate_txn_height = self.setLastHeightChecked(coin_type, tx_height)

        if bid.participate_tx is None:
            bid.participate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.PTX,
            )
        bid.participate_tx.txid = bytes.fromhex(txid_hex)
        bid.participate_tx.vout = vout
        bid.participate_tx.chain_height = participate_txn_height

        # Start checking for spends of participate_txn before fully confirmed
        self.log.debug('Watching %s chain for spend of output %s %d', chainparams[coin_type]['name'], txid_hex, vout)
        self.addWatchedOutput(coin_type, bid_id, txid_hex, vout, BidStates.SWAP_PARTICIPATING)

    def participateTxnConfirmed(self, bid_id, bid, offer):
        self.log.debug('participateTxnConfirmed for bid %s', bid_id.hex())
        bid.setState(BidStates.SWAP_PARTICIPATING)
        bid.setPTxState(TxStates.TX_CONFIRMED)

        # Seller redeems from participate txn
        if bid.was_received:
            ci_to = self.ci(offer.coin_to)
            txn = self.createRedeemTxn(ci_to.coin_type(), bid)
            txid = ci_to.publishTx(bytes.fromhex(txn))
            self.log.debug('Submitted participate redeem txn %s to %s chain for bid %s', txid, ci_to.coin_name(), bid_id.hex())
            # TX_REDEEMED will be set when spend is detected
            # TODO: Wait for depth?

        # bid saved in checkBidState

    def getAddressBalance(self, coin_type, address):
        if self.coin_clients[coin_type]['chain_lookups'] == 'explorer':
            explorers = self.coin_clients[coin_type]['explorers']

            # TODO: random offset into explorers, try blocks
            for exp in explorers:
                return exp.getBalance(address)
        return self.lookupUnspentByAddress(coin_type, address, sum_output=True)

    def lookupChainHeight(self, coin_type):
        return self.callcoinrpc(coin_type, 'getblockcount')

    def lookupUnspentByAddress(self, coin_type, address, sum_output=False, assert_amount=None, assert_txid=None):

        ci = self.ci(coin_type)
        if self.coin_clients[coin_type]['chain_lookups'] == 'explorer':
            explorers = self.coin_clients[coin_type]['explorers']

            # TODO: random offset into explorers, try blocks
            for exp in explorers:
                # TODO: ExplorerBitAps use only gettransaction if assert_txid is set
                rv = exp.lookupUnspentByAddress(address)

                if assert_amount is not None:
                    ensure(rv['value'] == int(assert_amount), 'Incorrect output amount in txn {}: {} != {}.'.format(assert_txid, rv['value'], int(assert_amount)))
                if assert_txid is not None:
                    ensure(rv['txid)'] == assert_txid, 'Incorrect txid')

                return rv

            raise ValueError('No explorer for lookupUnspentByAddress {}'.format(str(coin_type)))

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            raise ValueError('No RPC connection for lookupUnspentByAddress {}'.format(str(coin_type)))

        if assert_txid is not None:
            try:
                ro = self.callcoinrpc(coin_type, 'getmempoolentry', [assert_txid])
                self.log.debug('Tx %s found in mempool, fee %s', assert_txid, ro['fee'])
                # TODO: Save info
                return None
            except Exception:
                pass

        num_blocks = self.callcoinrpc(coin_type, 'getblockcount')

        sum_unspent = 0
        self.log.debug('[rm] scantxoutset start')  # scantxoutset is slow
        ro = self.callcoinrpc(coin_type, 'scantxoutset', ['start', ['addr({})'.format(address)]])  # TODO: Use combo(address) where possible
        self.log.debug('[rm] scantxoutset end')
        for o in ro['unspents']:
            if assert_txid and o['txid'] != assert_txid:
                continue
            # Verify amount
            if assert_amount:
                ensure(make_int(o['amount']) == int(assert_amount), 'Incorrect output amount in txn {}: {} != {}.'.format(assert_txid, make_int(o['amount']), int(assert_amount)))

            if not sum_output:
                if o['height'] > 0:
                    n_conf = num_blocks - o['height']
                else:
                    n_conf = -1
                return {
                    'txid': o['txid'],
                    'index': o['vout'],
                    'height': o['height'],
                    'n_conf': n_conf,
                    'value': ci.make_int(o['amount']),
                }
            else:
                sum_unspent += ci.make_int(o['amount'])
        if sum_output:
            return sum_unspent
        return None

    def checkXmrBidState(self, bid_id, bid, offer):
        rv = False

        ci_from = self.ci(Coins(offer.coin_from))
        ci_to = self.ci(Coins(offer.coin_to))

        session = None
        try:
            self.mxDB.acquire()
            session = scoped_session(self.session_factory)
            xmr_offer = session.query(XmrOffer).filter_by(offer_id=offer.offer_id).first()
            ensure(xmr_offer, 'XMR offer not found: {}.'.format(offer.offer_id.hex()))
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
            ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid.bid_id.hex()))

            if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                refund_tx = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND]
                if bid.was_received:
                    if bid.debug_ind == DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND:
                        self.log.debug('XMR bid %s: Stalling bid for testing: %d.', bid_id.hex(), bid.debug_ind)
                        bid.setState(BidStates.BID_STALLED_FOR_TEST)
                        rv = True
                        self.saveBidInSession(bid_id, bid, session, xmr_swap)
                        self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
                        session.commit()
                        return rv

                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND not in bid.txns:
                        try:
                            txid_str = ci_from.publishTx(xmr_swap.a_lock_refund_spend_tx)
                            self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_PUBLISHED, '', session)

                            self.log.info('Submitted coin a lock refund spend tx for bid {}, txid {}'.format(bid_id.hex(), txid_str))
                            bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND] = SwapTx(
                                bid_id=bid_id,
                                tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND,
                                txid=bytes.fromhex(txid_str),
                            )
                            self.saveBidInSession(bid_id, bid, session, xmr_swap)
                            session.commit()
                        except Exception as ex:
                            self.log.debug('Trying to publish coin a lock refund spend tx: %s', str(ex))

                if bid.was_sent:
                    if xmr_swap.a_lock_refund_swipe_tx is None:
                        self.createCoinALockRefundSwipeTx(ci_from, bid, offer, xmr_swap, xmr_offer)
                        self.saveBidInSession(bid_id, bid, session, xmr_swap)
                        session.commit()

                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE not in bid.txns:
                        try:
                            txid = ci_from.publishTx(xmr_swap.a_lock_refund_swipe_tx)
                            self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_SWIPE_TX_PUBLISHED, '', session)
                            self.log.info('Submitted coin a lock refund swipe tx for bid {}'.format(bid_id.hex()))
                            bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE] = SwapTx(
                                bid_id=bid_id,
                                tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE,
                                txid=bytes.fromhex(txid),
                            )
                            self.saveBidInSession(bid_id, bid, session, xmr_swap)
                            session.commit()
                        except Exception as ex:
                            self.log.debug('Trying to publish coin a lock refund swipe tx: %s', str(ex))

                if BidStates(bid.state) == BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED:
                    txid_hex = bid.xmr_b_lock_tx.spend_txid.hex()

                    found_tx = ci_to.findTxnByHash(txid_hex)
                    if found_tx is not None:
                        self.log.info('Found coin b lock recover tx bid %s', bid_id.hex())
                        rv = True  # Remove from swaps_in_progress
                        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)
                        self.saveBidInSession(bid_id, bid, session, xmr_swap)
                        session.commit()
                    return rv
            else:  # not XMR_SWAP_A_LOCK_REFUND in bid.txns
                if len(xmr_swap.al_lock_refund_tx_sig) > 0 and len(xmr_swap.af_lock_refund_tx_sig) > 0:
                    try:
                        txid = ci_from.publishTx(xmr_swap.a_lock_refund_tx)

                        self.log.info('Submitted coin a lock refund tx for bid {}'.format(bid_id.hex()))
                        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_TX_PUBLISHED, '', session)
                        bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND] = SwapTx(
                            bid_id=bid_id,
                            tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND,
                            txid=bytes.fromhex(txid),
                        )
                        self.saveBidInSession(bid_id, bid, session, xmr_swap)
                        session.commit()
                        return rv
                    except Exception as ex:
                        if 'Transaction already in block chain' in str(ex):
                            self.log.info('Found coin a lock refund tx for bid {}'.format(bid_id.hex()))
                            txid = ci_from.getTxid(xmr_swap.a_lock_refund_tx)
                            bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND] = SwapTx(
                                bid_id=bid_id,
                                tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND,
                                txid=txid,
                            )
                            self.saveBidInSession(bid_id, bid, session, xmr_swap)
                            session.commit()
                            return rv

            state = BidStates(bid.state)
            if state == BidStates.SWAP_COMPLETED:
                rv = True  # Remove from swaps_in_progress
            elif state == BidStates.XMR_SWAP_FAILED_REFUNDED:
                rv = True  # Remove from swaps_in_progress
            elif state == BidStates.XMR_SWAP_FAILED_SWIPED:
                rv = True  # Remove from swaps_in_progress
            elif state == BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX:
                if bid.xmr_a_lock_tx is None:
                    return rv

                # TODO: Timeout waiting for transactions
                bid_changed = False
                if offer.coin_from == Coins.FIRO:
                    lock_tx_chain_info = ci_from.getLockTxHeightFiro(bid.xmr_a_lock_tx.txid, xmr_swap.a_lock_tx_script, bid.amount, bid.chain_a_height_start)
                else:
                    a_lock_tx_addr = ci_from.getSCLockScriptAddress(xmr_swap.a_lock_tx_script)
                    lock_tx_chain_info = ci_from.getLockTxHeight(bid.xmr_a_lock_tx.txid, a_lock_tx_addr, bid.amount, bid.chain_a_height_start)

                if lock_tx_chain_info is None:
                    return rv

                if not bid.xmr_a_lock_tx.chain_height and lock_tx_chain_info['height'] != 0:
                    self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_SEEN, '', session)

                    block_header = ci_from.getBlockHeaderFromHeight(lock_tx_chain_info['height'])
                    bid.xmr_a_lock_tx.block_hash = bytes.fromhex(block_header['hash'])
                    bid.xmr_a_lock_tx.block_height = block_header['height']
                    bid.xmr_a_lock_tx.block_time = block_header['time']  # Or median_time?

                    bid_changed = True
                if bid.xmr_a_lock_tx.chain_height != lock_tx_chain_info['height'] and lock_tx_chain_info['height'] != 0:
                    bid.xmr_a_lock_tx.chain_height = lock_tx_chain_info['height']
                    bid_changed = True

                if lock_tx_chain_info['depth'] >= ci_from.blocks_confirmed:
                    self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_CONFIRMED, '', session)
                    bid.xmr_a_lock_tx.setState(TxStates.TX_CONFIRMED)
                    bid.setState(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
                    bid_changed = True

                    if bid.was_sent:
                        delay = random.randrange(self.min_delay_event, self.max_delay_event)
                        self.log.info('Sending xmr swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createActionInSession(delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, bid_id, session)
                        # bid.setState(BidStates.SWAP_DELAYING)

                if bid_changed:
                    self.saveBidInSession(bid_id, bid, session, xmr_swap)
                    session.commit()

            elif state == BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED:
                if bid.was_sent and bid.xmr_b_lock_tx is None:
                    return rv

                bid_changed = False
                # Have to use findTxB instead of relying on the first seen height to detect chain reorgs
                found_tx = ci_to.findTxB(xmr_swap.vkbv, xmr_swap.pkbs, bid.amount_to, ci_to.blocks_confirmed, bid.chain_b_height_start, bid.was_sent)

                if isinstance(found_tx, int) and found_tx == -1:
                    if self.countBidEvents(bid, EventLogTypes.LOCK_TX_B_INVALID, session) < 1:
                        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_INVALID, 'Detected invalid lock tx B', session)
                        bid_changed = True
                elif found_tx is not None:
                    if bid.xmr_b_lock_tx is None or not bid.xmr_b_lock_tx.chain_height:
                        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_SEEN, '', session)
                    if bid.xmr_b_lock_tx is None:
                        self.log.debug('Found {} lock tx in chain'.format(ci_to.coin_name()))
                        b_lock_tx_id = bytes.fromhex(found_tx['txid'])
                        bid.xmr_b_lock_tx = SwapTx(
                            bid_id=bid_id,
                            tx_type=TxTypes.XMR_SWAP_B_LOCK,
                            txid=b_lock_tx_id,
                            chain_height=found_tx['height'],
                        )
                        bid_changed = True
                    else:
                        bid.xmr_b_lock_tx.chain_height = found_tx['height']
                        bid_changed = True

                if bid.xmr_b_lock_tx and bid.xmr_b_lock_tx.chain_height is not None and bid.xmr_b_lock_tx.chain_height > 0:
                    chain_height = ci_to.getChainHeight()

                    if chain_height - bid.xmr_b_lock_tx.chain_height >= ci_to.blocks_confirmed:
                        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_CONFIRMED, '', session)
                        bid.xmr_b_lock_tx.setState(TxStates.TX_CONFIRMED)
                        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)

                        if bid.was_received:
                            delay = random.randrange(self.min_delay_event, self.max_delay_event)
                            self.log.info('Releasing xmr script coin lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                            self.createActionInSession(delay, ActionTypes.SEND_XMR_LOCK_RELEASE, bid_id, session)

                if bid_changed:
                    self.saveBidInSession(bid_id, bid, session, xmr_swap)
                    session.commit()
            elif state == BidStates.XMR_SWAP_LOCK_RELEASED:
                # Wait for script spend tx to confirm
                # TODO: Use explorer to get tx / block hash for getrawtransaction

                if bid.was_received:
                    try:
                        txn_hex = ci_from.getMempoolTx(xmr_swap.a_lock_spend_tx_id)
                        self.log.info('Found lock spend txn in %s mempool, %s', ci_from.coin_name(), xmr_swap.a_lock_spend_tx_id.hex())
                        self.process_XMR_SWAP_A_LOCK_tx_spend(bid_id, xmr_swap.a_lock_spend_tx_id.hex(), txn_hex)
                    except Exception as e:
                        self.log.debug('getrawtransaction lock spend tx failed: %s', str(e))
            elif state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
                if bid.was_received and self.countQueuedActions(session, bid_id, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B) < 1:
                    bid.setState(BidStates.SWAP_DELAYING)
                    delay = random.randrange(self.min_delay_event, self.max_delay_event)
                    self.log.info('Redeeming coin b lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                    self.createActionInSession(delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B, bid_id, session)
                    self.saveBidInSession(bid_id, bid, session, xmr_swap)
                    session.commit()
            elif state == BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED:
                txid_hex = bid.xmr_b_lock_tx.spend_txid.hex()

                found_tx = ci_to.findTxnByHash(txid_hex)
                if found_tx is not None:
                    self.log.info('Found coin b lock spend tx bid %s', bid_id.hex())
                    rv = True  # Remove from swaps_in_progress
                    bid.setState(BidStates.SWAP_COMPLETED)
                    self.saveBidInSession(bid_id, bid, session, xmr_swap)
                    session.commit()
            elif state == BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND:
                if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                    refund_tx = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND]
                    if refund_tx.block_time is None:
                        if offer.coin_from == Coins.FIRO:
                            lock_refund_tx_chain_info = ci_from.getLockTxHeightFiro(refund_tx.txid, xmr_swap.a_lock_refund_tx_script, 0, bid.chain_a_height_start)
                        else:
                            refund_tx_addr = ci_from.getSCLockScriptAddress(xmr_swap.a_lock_refund_tx_script)
                            lock_refund_tx_chain_info = ci_from.getLockTxHeight(refund_tx.txid, refund_tx_addr, 0, bid.chain_a_height_start)

                        if lock_refund_tx_chain_info is not None and lock_refund_tx_chain_info.get('height', 0) > 0:
                            block_header = ci_from.getBlockHeaderFromHeight(lock_refund_tx_chain_info['height'])
                            refund_tx.block_hash = bytes.fromhex(block_header['hash'])
                            refund_tx.block_height = block_header['height']
                            refund_tx.block_time = block_header['time']  # Or median_time?

                            self.saveBidInSession(bid_id, bid, session, xmr_swap)
                            session.commit()

        except Exception as ex:
            raise ex
        finally:
            if session:
                session.close()
                session.remove()
            self.mxDB.release()

        return rv

    def checkBidState(self, bid_id, bid, offer):
        # assert (self.mxDB.locked())
        # Return True to remove bid from in-progress list

        state = BidStates(bid.state)
        self.log.debug('checkBidState %s %s', bid_id.hex(), str(state))

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.checkXmrBidState(bid_id, bid, offer)

        save_bid = False
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        # TODO: Batch calls to scantxoutset
        # TODO: timeouts
        if state == BidStates.BID_ABANDONED:
            self.log.info('Deactivating abandoned bid: %s', bid_id.hex())
            return True  # Mark bid for archiving
        if state == BidStates.BID_ACCEPTED:
            # Waiting for initiate txn to be confirmed in 'from' chain
            initiate_txnid_hex = bid.initiate_tx.txid.hex()
            p2sh = ci_from.encode_p2sh(bid.initiate_tx.script)
            index = None
            tx_height = None
            last_initiate_txn_conf = bid.initiate_tx.conf
            if coin_from == Coins.PART:  # Has txindex
                try:
                    initiate_txn = self.callcoinrpc(coin_from, 'getrawtransaction', [initiate_txnid_hex, True])
                    # Verify amount
                    vout = getVoutByAddress(initiate_txn, p2sh)

                    out_value = make_int(initiate_txn['vout'][vout]['value'])
                    ensure(out_value == int(bid.amount), 'Incorrect output amount in initiate txn {}: {} != {}.'.format(initiate_txnid_hex, out_value, int(bid.amount)))

                    bid.initiate_tx.conf = initiate_txn['confirmations']
                    try:
                        tx_height = initiate_txn['height']
                    except Exception:
                        tx_height = -1
                    index = vout
                except Exception:
                    pass
            else:
                if self.coin_clients[coin_from]['use_segwit']:
                    addr = ci_from.encode_p2wsh(getP2WSH(bid.initiate_tx.script))
                else:
                    addr = p2sh

                ci_from = self.ci(coin_from)
                found = ci_from.getLockTxHeight(bytes.fromhex(initiate_txnid_hex), addr, bid.amount, bid.chain_a_height_start, find_index=True)
                if found:
                    bid.initiate_tx.conf = found['depth']
                    index = found['index']
                    tx_height = found['height']

            if bid.initiate_tx.conf != last_initiate_txn_conf:
                save_bid = True

            if bid.initiate_tx.conf is not None:
                self.log.debug('initiate_txnid %s confirms %d', initiate_txnid_hex, bid.initiate_tx.conf)

                if bid.initiate_tx.vout is None and tx_height > 0:
                    bid.initiate_tx.vout = index
                    # Start checking for spends of initiate_txn before fully confirmed
                    bid.initiate_tx.chain_height = self.setLastHeightChecked(coin_from, tx_height)
                    self.addWatchedOutput(coin_from, bid_id, initiate_txnid_hex, bid.initiate_tx.vout, BidStates.SWAP_INITIATED)
                    if bid.getITxState() is None or bid.getITxState() < TxStates.TX_SENT:
                        bid.setITxState(TxStates.TX_SENT)
                    save_bid = True

                if bid.initiate_tx.conf >= self.coin_clients[coin_from]['blocks_confirmed']:
                    self.initiateTxnConfirmed(bid_id, bid, offer)
                    save_bid = True

            # Bid times out if buyer doesn't see tx in chain within INITIATE_TX_TIMEOUT seconds
            if bid.initiate_tx is None and \
               bid.state_time + atomic_swap_1.INITIATE_TX_TIMEOUT < int(time.time()):
                self.log.info('Swap timed out waiting for initiate tx for bid %s', bid_id.hex())
                bid.setState(BidStates.SWAP_TIMEDOUT, 'Timed out waiting for initiate tx')
                self.saveBid(bid_id, bid)
                return True  # Mark bid for archiving
        elif state == BidStates.SWAP_INITIATED:
            # Waiting for participate txn to be confirmed in 'to' chain
            if self.coin_clients[coin_to]['use_segwit']:
                addr = ci_to.encode_p2wsh(getP2WSH(bid.participate_tx.script))
            else:
                addr = ci_to.encode_p2sh(bid.participate_tx.script)

            ci_to = self.ci(coin_to)
            participate_txid = None if bid.participate_tx is None or bid.participate_tx.txid is None else bid.participate_tx.txid
            found = ci_to.getLockTxHeight(participate_txid, addr, bid.amount_to, bid.chain_b_height_start, find_index=True)
            if found:
                if bid.participate_tx.conf != found['depth']:
                    save_bid = True
                bid.participate_tx.conf = found['depth']
                index = found['index']
                if bid.participate_tx is None or bid.participate_tx.txid is None:
                    self.log.debug('Found bid %s participate txn %s in chain %s', bid_id.hex(), found['txid'], coin_to)
                    self.addParticipateTxn(bid_id, bid, coin_to, found['txid'], found['index'], found['height'])
                    bid.setPTxState(TxStates.TX_SENT)
                    save_bid = True

            if bid.participate_tx.conf is not None:
                self.log.debug('participate txid %s confirms %d', bid.participate_tx.txid.hex(), bid.participate_tx.conf)
                if bid.participate_tx.conf >= self.coin_clients[coin_to]['blocks_confirmed']:
                    self.participateTxnConfirmed(bid_id, bid, offer)
                    save_bid = True
        elif state == BidStates.SWAP_PARTICIPATING:
            # Waiting for initiate txn spend
            pass
        elif state == BidStates.BID_ERROR:
            # Wait for user input
            pass
        else:
            self.log.warning('checkBidState unknown state %s', state)

        if state > BidStates.BID_ACCEPTED:
            # Wait for spend of all known swap txns
            itx_state = bid.getITxState()
            ptx_state = bid.getPTxState()
            if (itx_state is None or itx_state >= TxStates.TX_REDEEMED) and \
               (ptx_state is None or ptx_state >= TxStates.TX_REDEEMED):
                self.log.info('Swap completed for bid %s', bid_id.hex())

                self.returnAddressToPool(bid_id, TxTypes.ITX_REFUND if itx_state == TxStates.TX_REDEEMED else TxTypes.PTX_REDEEM)
                self.returnAddressToPool(bid_id, TxTypes.ITX_REFUND if ptx_state == TxStates.TX_REDEEMED else TxTypes.PTX_REDEEM)

                bid.setState(BidStates.SWAP_COMPLETED)
                self.saveBid(bid_id, bid)
                return True  # Mark bid for archiving

        if save_bid:
            self.saveBid(bid_id, bid)

        if bid.debug_ind == DebugTypes.SKIP_LOCK_TX_REFUND:
            return False  # Bid is still active

        # Try refund, keep trying until sent tx is spent
        if bid.getITxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED) \
           and bid.initiate_txn_refund is not None:
            try:
                txid = ci_from.publishTx(bid.initiate_txn_refund)
                self.log.debug('Submitted initiate refund txn %s to %s chain for bid %s', txid, chainparams[coin_from]['name'], bid_id.hex())
                # State will update when spend is detected
            except Exception as ex:
                if 'non-BIP68-final' not in str(ex) and 'non-final' not in str(ex):
                    self.log.warning('Error trying to submit initiate refund txn: %s', str(ex))

        if bid.getPTxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED) \
           and bid.participate_txn_refund is not None:
            try:
                txid = ci_to.publishTx(bid.participate_txn_refund)
                self.log.debug('Submitted participate refund txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
                # State will update when spend is detected
            except Exception as ex:
                if 'non-BIP68-final' not in str(ex) and 'non-final' not in str(ex):
                    self.log.warning('Error trying to submit participate refund txn: %s', str(ex))
        return False  # Bid is still active

    def extractSecret(self, coin_type, bid, spend_in):
        try:
            if coin_type == Coins.PART or self.coin_clients[coin_type]['use_segwit']:
                ensure(len(spend_in['txinwitness']) == 5, 'Bad witness size')
                return bytes.fromhex(spend_in['txinwitness'][2])
            else:
                script_sig = spend_in['scriptSig']['asm'].split(' ')
                ensure(len(script_sig) == 5, 'Bad witness size')
                return bytes.fromhex(script_sig[2])
        except Exception:
            return None

    def addWatchedOutput(self, coin_type, bid_id, txid_hex, vout, tx_type, swap_type=None):
        self.log.debug('Adding watched output %s bid %s tx %s type %s', coin_type, bid_id.hex(), txid_hex, tx_type)

        watched = self.coin_clients[coin_type]['watched_outputs']

        for wo in watched:
            if wo.bid_id == bid_id and wo.txid_hex == txid_hex and wo.vout == vout:
                self.log.debug('Output already being watched.')
                return

        watched.append(WatchedOutput(bid_id, txid_hex, vout, tx_type, swap_type))

    def removeWatchedOutput(self, coin_type, bid_id, txid_hex):
        # Remove all for bid if txid is None
        self.log.debug('removeWatchedOutput %s %s %s', str(coin_type), bid_id.hex(), txid_hex)
        old_len = len(self.coin_clients[coin_type]['watched_outputs'])
        for i in range(old_len - 1, -1, -1):
            wo = self.coin_clients[coin_type]['watched_outputs'][i]
            if wo.bid_id == bid_id and (txid_hex is None or wo.txid_hex == txid_hex):
                del self.coin_clients[coin_type]['watched_outputs'][i]
                self.log.debug('Removed watched output %s %s %s', str(coin_type), bid_id.hex(), wo.txid_hex)

    def initiateTxnSpent(self, bid_id, spend_txid, spend_n, spend_txn):
        self.log.debug('Bid %s initiate txn spent by %s %d', bid_id.hex(), spend_txid, spend_n)

        if bid_id in self.swaps_in_progress:
            bid = self.swaps_in_progress[bid_id][0]
            offer = self.swaps_in_progress[bid_id][1]

            bid.initiate_tx.spend_txid = bytes.fromhex(spend_txid)
            bid.initiate_tx.spend_n = spend_n
            spend_in = spend_txn['vin'][spend_n]

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            secret = self.extractSecret(coin_from, bid, spend_in)
            if secret is None:
                self.log.info('Bid %s initiate txn refunded by %s %d', bid_id.hex(), spend_txid, spend_n)
                # TODO: Wait for depth?
                bid.setITxState(TxStates.TX_REFUNDED)
            else:
                self.log.info('Bid %s initiate txn redeemed by %s %d', bid_id.hex(), spend_txid, spend_n)
                # TODO: Wait for depth?
                bid.setITxState(TxStates.TX_REDEEMED)

            self.removeWatchedOutput(coin_from, bid_id, bid.initiate_tx.txid.hex())
            self.saveBid(bid_id, bid)

    def participateTxnSpent(self, bid_id, spend_txid, spend_n, spend_txn):
        self.log.debug('Bid %s participate txn spent by %s %d', bid_id.hex(), spend_txid, spend_n)

        # TODO: More SwapTypes
        if bid_id in self.swaps_in_progress:
            bid = self.swaps_in_progress[bid_id][0]
            offer = self.swaps_in_progress[bid_id][1]

            bid.participate_tx.spend_txid = bytes.fromhex(spend_txid)
            bid.participate_tx.spend_n = spend_n
            spend_in = spend_txn['vin'][spend_n]

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            secret = self.extractSecret(coin_to, bid, spend_in)
            if secret is None:
                self.log.info('Bid %s participate txn refunded by %s %d', bid_id.hex(), spend_txid, spend_n)
                # TODO: Wait for depth?
                bid.setPTxState(TxStates.TX_REFUNDED)
            else:
                self.log.debug('Secret %s extracted from participate spend %s %d', secret.hex(), spend_txid, spend_n)
                bid.recovered_secret = secret
                # TODO: Wait for depth?
                bid.setPTxState(TxStates.TX_REDEEMED)

                if bid.was_sent:
                    if bid.debug_ind == DebugTypes.DONT_SPEND_ITX:
                        self.log.debug('bid %s: Abandoning bid for testing: %d, %s.', bid_id.hex(), bid.debug_ind, DebugTypes(bid.debug_ind).name)
                        bid.setState(BidStates.BID_ABANDONED)
                        self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), None)
                    else:
                        delay = random.randrange(self.min_delay_event_short, self.max_delay_event_short)
                        self.log.info('Redeeming ITX for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createAction(delay, ActionTypes.REDEEM_ITX, bid_id)
                # TODO: Wait for depth? new state SWAP_TXI_REDEEM_SENT?

            self.removeWatchedOutput(coin_to, bid_id, bid.participate_tx.txid.hex())
            self.saveBid(bid_id, bid)

    def process_XMR_SWAP_A_LOCK_tx_spend(self, bid_id, spend_txid_hex, spend_txn_hex):
        self.log.debug('Detected spend of XMR swap coin a lock tx for bid %s', bid_id.hex())
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
            ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
            ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

            offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
            ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            state = BidStates(bid.state)
            spending_txid = bytes.fromhex(spend_txid_hex)

            if spending_txid == xmr_swap.a_lock_spend_tx_id:
                if state == BidStates.XMR_SWAP_LOCK_RELEASED:
                    xmr_swap.a_lock_spend_tx = bytes.fromhex(spend_txn_hex)
                    bid.setState(BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)  # TODO: Wait for confirmation?

                    if not bid.was_received:
                        bid.setState(BidStates.SWAP_COMPLETED)
                else:
                    # Could already be processed if spend was detected in the mempool
                    self.log.warning('Coin a lock tx spend ignored due to bid state for bid {}'.format(bid_id.hex()))

            elif spending_txid == xmr_swap.a_lock_refund_tx_id:
                self.log.debug('Coin a lock tx spent by lock refund tx.')
                bid.setState(BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND)
                self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_TX_SEEN, '', session)
            else:
                self.setBidError(bid.bid_id, bid, 'Unexpected txn spent coin a lock tx: {}'.format(spend_txid_hex), save_bid=False)

            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            session.commit()
        except Exception as ex:
            self.logException(f'process_XMR_SWAP_A_LOCK_tx_spend {ex}')
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def process_XMR_SWAP_A_LOCK_REFUND_tx_spend(self, bid_id, spend_txid_hex, spend_txn):
        self.log.debug('Detected spend of XMR swap coin a lock refund tx for bid %s', bid_id.hex())
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
            ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
            ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

            offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
            ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            state = BidStates(bid.state)
            spending_txid = bytes.fromhex(spend_txid_hex)

            if spending_txid == xmr_swap.a_lock_refund_spend_tx_id:
                self.log.info('Found coin a lock refund spend tx, bid {}'.format(bid_id.hex()))
                self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_SEEN, '', session)

                if bid.was_sent:
                    xmr_swap.a_lock_refund_spend_tx = bytes.fromhex(spend_txn['hex'])  # Replace with fully signed tx
                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND not in bid.txns:
                        bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND] = SwapTx(
                            bid_id=bid_id,
                            tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND,
                            txid=xmr_swap.a_lock_refund_spend_tx_id,
                        )
                    if bid.xmr_b_lock_tx is not None:
                        delay = random.randrange(self.min_delay_event, self.max_delay_event)
                        self.log.info('Recovering xmr swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createActionInSession(delay, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, session)
                    else:
                        # Other side refunded before swap lock tx was sent
                        bid.setState(BidStates.XMR_SWAP_FAILED)

                if bid.was_received:
                    if not bid.was_sent:
                        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)

            else:
                self.log.info('Coin a lock refund spent by unknown tx, bid {}'.format(bid_id.hex()))
                bid.setState(BidStates.XMR_SWAP_FAILED_SWIPED)

            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            session.commit()
        except Exception as ex:
            self.logException(f'process_XMR_SWAP_A_LOCK_REFUND_tx_spend {ex}')
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def processSpentOutput(self, coin_type, watched_output, spend_txid_hex, spend_n, spend_txn):
        if watched_output.swap_type == SwapTypes.XMR_SWAP:
            if watched_output.tx_type == TxTypes.XMR_SWAP_A_LOCK:
                self.process_XMR_SWAP_A_LOCK_tx_spend(watched_output.bid_id, spend_txid_hex, spend_txn['hex'])
            elif watched_output.tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND:
                self.process_XMR_SWAP_A_LOCK_REFUND_tx_spend(watched_output.bid_id, spend_txid_hex, spend_txn)

            self.removeWatchedOutput(coin_type, watched_output.bid_id, watched_output.txid_hex)
            return

        if watched_output.tx_type == BidStates.SWAP_PARTICIPATING:
            self.participateTxnSpent(watched_output.bid_id, spend_txid_hex, spend_n, spend_txn)
        else:
            self.initiateTxnSpent(watched_output.bid_id, spend_txid_hex, spend_n, spend_txn)

    def checkForSpends(self, coin_type, c):
        # assert (self.mxDB.locked())
        self.log.debug('checkForSpends %s', coin_type)

        # TODO: Check for spends on watchonly txns where possible

        if 'have_spent_index' in self.coin_clients[coin_type] and self.coin_clients[coin_type]['have_spent_index']:
            # TODO: batch getspentinfo
            for o in c['watched_outputs']:
                found_spend = None
                try:
                    found_spend = self.callcoinrpc(Coins.PART, 'getspentinfo', [{'txid': o.txid_hex, 'index': o.vout}])
                except Exception as ex:
                    if 'Unable to get spent info' not in str(ex):
                        self.log.warning('getspentinfo %s', str(ex))
                if found_spend is not None:
                    self.log.debug('Found spend in spentindex %s %d in %s %d', o.txid_hex, o.vout, found_spend['txid'], found_spend['index'])
                    spend_txid = found_spend['txid']
                    spend_n = found_spend['index']
                    spend_txn = self.callcoinrpc(Coins.PART, 'getrawtransaction', [spend_txid, True])
                    self.processSpentOutput(coin_type, o, spend_txid, spend_n, spend_txn)
        else:
            ci = self.ci(coin_type)
            chain_blocks = ci.getChainHeight()
            last_height_checked = c['last_height_checked']
            self.log.debug('chain_blocks, last_height_checked %s %s', chain_blocks, last_height_checked)
            while last_height_checked < chain_blocks:
                block_hash = self.callcoinrpc(coin_type, 'getblockhash', [last_height_checked + 1])
                try:
                    block = ci.getBlockWithTxns(block_hash)
                except Exception as e:
                    if 'Block not available (pruned data)' in str(e):
                        # TODO: Better solution?
                        bci = self.callcoinrpc(coin_type, 'getblockchaininfo')
                        self.log.error('Coin %s last_height_checked %d set to pruneheight %d', self.ci(coin_type).coin_name(), last_height_checked, bci['pruneheight'])
                        last_height_checked = bci['pruneheight']
                        continue
                    else:
                        self.logException(f'getblock error {e}')
                        break

                for tx in block['tx']:
                    for i, inp in enumerate(tx['vin']):
                        for o in c['watched_outputs']:
                            inp_txid = inp.get('txid', None)
                            if inp_txid is None:  # Coinbase
                                continue
                            if inp_txid == o.txid_hex and inp['vout'] == o.vout:
                                self.log.debug('Found spend from search %s %d in %s %d', o.txid_hex, o.vout, tx['txid'], i)
                                self.processSpentOutput(coin_type, o, tx['txid'], i, tx)
                last_height_checked += 1
            if c['last_height_checked'] != last_height_checked:
                c['last_height_checked'] = last_height_checked
                self.setIntKV('last_height_checked_' + chainparams[coin_type]['name'], last_height_checked)

    def expireMessages(self):
        self.mxDB.acquire()
        rpc_conn = None
        try:
            ci_part = self.ci(Coins.PART)
            rpc_conn = ci_part.open_rpc()
            now = int(time.time())
            options = {'encoding': 'none'}
            ro = ci_part.json_request(rpc_conn, 'smsginbox', ['all', '', options])
            num_messages = 0
            num_removed = 0
            for msg in ro['messages']:
                try:
                    num_messages += 1
                    expire_at = msg['sent'] + msg['ttl']
                    if expire_at < now:
                        options = {'encoding': 'none', 'delete': True}
                        del_msg = ci_part.json_request(rpc_conn, 'smsg', [msg['msgid'], options])
                        num_removed += 1
                except Exception as e:
                    if self.debug:
                        self.log.error(traceback.format_exc())
                    continue

            if num_messages + num_removed > 0:
                self.log.info('Expired {} / {} messages.'.format(num_removed, num_messages))

            self.log.debug('TODO: Expire records from db')

        finally:
            if rpc_conn:
                ci_part.close_rpc(rpc_conn)
            self.mxDB.release()

    def countQueuedActions(self, session, bid_id, action_type):
        q = session.query(Action).filter(sa.and_(Action.active_ind == 1, Action.linked_id == bid_id, Action.action_type == int(action_type)))
        return q.count()

    def checkQueuedActions(self):
        self.mxDB.acquire()
        now = int(time.time())
        session = None
        try:
            session = scoped_session(self.session_factory)

            q = session.query(Action).filter(sa.and_(Action.active_ind == 1, Action.trigger_at <= now))
            for row in q:
                try:
                    if row.action_type == ActionTypes.ACCEPT_BID:
                        self.acceptBid(row.linked_id)
                    elif row.action_type == ActionTypes.ACCEPT_XMR_BID:
                        self.acceptXmrBid(row.linked_id)
                    elif row.action_type == ActionTypes.SIGN_XMR_SWAP_LOCK_TX_A:
                        self.sendXmrBidTxnSigsFtoL(row.linked_id, session)
                    elif row.action_type == ActionTypes.SEND_XMR_SWAP_LOCK_TX_A:
                        self.sendXmrBidCoinALockTx(row.linked_id, session)
                    elif row.action_type == ActionTypes.SEND_XMR_SWAP_LOCK_TX_B:
                        self.sendXmrBidCoinBLockTx(row.linked_id, session)
                    elif row.action_type == ActionTypes.SEND_XMR_LOCK_RELEASE:
                        self.sendXmrBidLockRelease(row.linked_id, session)
                    elif row.action_type == ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_A:
                        self.redeemXmrBidCoinALockTx(row.linked_id, session)
                    elif row.action_type == ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B:
                        self.redeemXmrBidCoinBLockTx(row.linked_id, session)
                    elif row.action_type == ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B:
                        self.recoverXmrBidCoinBLockTx(row.linked_id, session)
                    elif row.action_type == ActionTypes.SEND_XMR_SWAP_LOCK_SPEND_MSG:
                        self.sendXmrBidCoinALockSpendTxMsg(row.linked_id, session)
                    elif row.action_type == ActionTypes.REDEEM_ITX:
                        atomic_swap_1.redeemITx(self, row.linked_id, session)
                    else:
                        self.log.warning('Unknown event type: %d', row.event_type)
                except Exception as ex:
                    self.logException(f'checkQueuedActions failed: {ex}')

            if self.debug:
                session.execute('UPDATE actions SET active_ind = 2 WHERE trigger_at <= {}'.format(now))
            else:
                session.execute('DELETE FROM actions WHERE trigger_at <= {}'.format(now))

            session.commit()
        finally:
            if session:
                session.close()
                session.remove()
            self.mxDB.release()

    def checkXmrSwaps(self):
        self.mxDB.acquire()
        now = int(time.time())
        ttl_xmr_split_messages = 60 * 60
        session = None
        try:
            session = scoped_session(self.session_factory)
            q = session.query(Bid).filter(Bid.state == BidStates.BID_RECEIVING)
            for bid in q:
                q = session.execute('SELECT COUNT(*) FROM xmr_split_data WHERE bid_id = x\'{}\' AND msg_type = {}'.format(bid.bid_id.hex(), XmrSplitMsgTypes.BID)).first()
                num_segments = q[0]
                if num_segments > 1:
                    try:
                        self.receiveXmrBid(bid, session)
                    except Exception as ex:
                        self.log.info('Verify xmr bid {} failed: {}'.format(bid.bid_id.hex(), str(ex)))
                        if self.debug:
                            self.log.error(traceback.format_exc())
                        bid.setState(BidStates.BID_ERROR, 'Failed validation: ' + str(ex))
                        session.add(bid)
                        self.updateBidInProgress(bid)
                    continue
                if bid.created_at + ttl_xmr_split_messages < now:
                    self.log.debug('Expiring partially received bid: {}'.format(bid.bid_id.hex()))
                    bid.setState(BidStates.BID_ERROR, 'Timed out')
                    session.add(bid)

            q = session.query(Bid).filter(Bid.state == BidStates.BID_RECEIVING_ACC)
            for bid in q:
                q = session.execute('SELECT COUNT(*) FROM xmr_split_data WHERE bid_id = x\'{}\' AND msg_type = {}'.format(bid.bid_id.hex(), XmrSplitMsgTypes.BID_ACCEPT)).first()
                num_segments = q[0]
                if num_segments > 1:
                    try:
                        self.receiveXmrBidAccept(bid, session)
                    except Exception as ex:
                        if self.debug:
                            self.log.error(traceback.format_exc())
                        self.log.info('Verify xmr bid accept {} failed: {}'.format(bid.bid_id.hex(), str(ex)))
                        bid.setState(BidStates.BID_ERROR, 'Failed accept validation: ' + str(ex))
                        session.add(bid)
                        self.updateBidInProgress(bid)
                    continue
                if bid.created_at + ttl_xmr_split_messages < now:
                    self.log.debug('Expiring partially received bid accept: {}'.format(bid.bid_id.hex()))
                    bid.setState(BidStates.BID_ERROR, 'Timed out')
                    session.add(bid)

            # Expire old records
            q = session.query(XmrSplitData).filter(XmrSplitData.created_at + ttl_xmr_split_messages < now)
            q.delete(synchronize_session=False)

            session.commit()
        finally:
            if session:
                session.close()
                session.remove()
            self.mxDB.release()

    def processOffer(self, msg):
        offer_bytes = bytes.fromhex(msg['hex'][2:-2])
        offer_data = OfferMessage()
        offer_data.ParseFromString(offer_bytes)

        # Validate data
        now = int(time.time())
        coin_from = Coins(offer_data.coin_from)
        ci_from = self.ci(coin_from)
        coin_to = Coins(offer_data.coin_to)
        ci_to = self.ci(coin_to)
        ensure(offer_data.coin_from != offer_data.coin_to, 'coin_from == coin_to')

        self.validateSwapType(coin_from, coin_to, offer_data.swap_type)
        self.validateOfferAmounts(coin_from, coin_to, offer_data.amount_from, offer_data.rate, offer_data.min_bid_amount)
        self.validateOfferLockValue(coin_from, coin_to, offer_data.lock_type, offer_data.lock_value)
        self.validateOfferValidTime(offer_data.swap_type, coin_from, coin_to, offer_data.time_valid)

        ensure(msg['sent'] + offer_data.time_valid >= now, 'Offer expired')

        if offer_data.swap_type == SwapTypes.SELLER_FIRST:
            ensure(len(offer_data.proof_address) == 0, 'Unexpected data')
            ensure(len(offer_data.proof_signature) == 0, 'Unexpected data')
            ensure(len(offer_data.pkhash_seller) == 0, 'Unexpected data')
            ensure(len(offer_data.secret_hash) == 0, 'Unexpected data')
        elif offer_data.swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError('TODO')
        elif offer_data.swap_type == SwapTypes.XMR_SWAP:
            ensure(coin_from not in non_script_type_coins, 'Invalid coin from type')
            ensure(coin_to in non_script_type_coins, 'Invalid coin to type')
            ensure(len(offer_data.proof_address) == 0, 'Unexpected data')
            ensure(len(offer_data.proof_signature) == 0, 'Unexpected data')
            ensure(len(offer_data.pkhash_seller) == 0, 'Unexpected data')
            ensure(len(offer_data.secret_hash) == 0, 'Unexpected data')
        else:
            raise ValueError('Unknown swap type {}.'.format(offer_data.swap_type))

        offer_id = bytes.fromhex(msg['msgid'])

        if self.isOfferRevoked(offer_id, msg['from']):
            raise ValueError('Offer has been revoked {}.'.format(offer_id.hex()))

        session = scoped_session(self.session_factory)
        try:
            # Offers must be received on the public network_addr or manually created addresses
            if msg['to'] != self.network_addr:
                # Double check active_ind, shouldn't be possible to receive message if not active
                query_str = 'SELECT COUNT(addr_id) FROM smsgaddresses WHERE addr = "{}" AND use_type = {} AND active_ind = 1'.format(msg['to'], AddressTypes.RECV_OFFER)
                rv = session.execute(query_str).first()
                if rv[0] < 1:
                    raise ValueError('Offer received on incorrect address')

            # Check for sent
            existing_offer = self.getOffer(offer_id)
            if existing_offer is None:
                offer = Offer(
                    offer_id=offer_id,
                    active_ind=1,

                    protocol_version=offer_data.protocol_version,
                    coin_from=offer_data.coin_from,
                    coin_to=offer_data.coin_to,
                    amount_from=offer_data.amount_from,
                    rate=offer_data.rate,
                    min_bid_amount=offer_data.min_bid_amount,
                    time_valid=offer_data.time_valid,
                    lock_type=int(offer_data.lock_type),
                    lock_value=offer_data.lock_value,
                    swap_type=offer_data.swap_type,
                    amount_negotiable=offer_data.amount_negotiable,
                    rate_negotiable=offer_data.rate_negotiable,

                    addr_to=msg['to'],
                    addr_from=msg['from'],
                    created_at=msg['sent'],
                    expire_at=msg['sent'] + offer_data.time_valid,
                    was_sent=False)
                offer.setState(OfferStates.OFFER_RECEIVED)
                session.add(offer)

                if offer.swap_type == SwapTypes.XMR_SWAP:
                    xmr_offer = XmrOffer()

                    xmr_offer.offer_id = offer_id
                    xmr_offer.lock_time_1 = ci_from.getExpectedSequence(offer_data.lock_type, offer_data.lock_value)
                    xmr_offer.lock_time_2 = ci_from.getExpectedSequence(offer_data.lock_type, offer_data.lock_value)

                    xmr_offer.a_fee_rate = offer_data.fee_rate_from
                    xmr_offer.b_fee_rate = offer_data.fee_rate_to

                    session.add(xmr_offer)

                self.notify(NT.OFFER_RECEIVED, {'offer_id': offer_id.hex()}, session)
            else:
                existing_offer.setState(OfferStates.OFFER_RECEIVED)
                session.add(existing_offer)
            session.commit()
        finally:
            session.close()
            session.remove()

    def processOfferRevoke(self, msg):
        ensure(msg['to'] == self.network_addr, 'Message received on wrong address')

        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = OfferRevokeMessage()
        msg_data.ParseFromString(msg_bytes)

        now = int(time.time())
        self.mxDB.acquire()
        session = None
        try:
            session = scoped_session(self.session_factory)

            if len(msg_data.offer_msg_id) != 28:
                raise ValueError('Invalid msg_id length')
            if len(msg_data.signature) != 65:
                raise ValueError('Invalid signature length')

            offer = session.query(Offer).filter_by(offer_id=msg_data.offer_msg_id).first()
            if offer is None:
                self.storeOfferRevoke(msg_data.offer_msg_id, msg_data.signature)
                raise ValueError('Offer not found: {}'.format(msg_data.offer_msg_id.hex()))

            if offer.expire_at <= now:
                raise ValueError('Offer already expired: {}'.format(msg_data.offer_msg_id.hex()))

            signature_enc = base64.b64encode(msg_data.signature).decode('utf-8')

            passed = self.callcoinrpc(Coins.PART, 'verifymessage', [offer.addr_from, signature_enc, msg_data.offer_msg_id.hex() + '_revoke'])
            ensure(passed is True, 'Signature invalid')

            offer.active_ind = 2
            # TODO: Remove message, or wait for expire

            session.add(offer)
            session.commit()
        finally:
            if session:
                session.close()
                session.remove()
            self.mxDB.release()

    def getCompletedAndActiveBidsValue(self, offer, session):
        bids = []
        total_value = 0
        q = session.execute(
            '''SELECT bid_id, amount, state FROM bids
               JOIN bidstates ON bidstates.state_id = bids.state AND (bidstates.state_id = {1} OR bidstates.in_progress > 0)
               WHERE bids.active_ind = 1 AND bids.offer_id = x\'{0}\'
               UNION
               SELECT bid_id, amount, state FROM bids
               JOIN actions ON actions.linked_id = bids.bid_id AND actions.active_ind = 1 AND (actions.action_type = {2} OR actions.action_type = {3})
               WHERE bids.active_ind = 1 AND bids.offer_id = x\'{0}\'
            '''.format(offer.offer_id.hex(), BidStates.SWAP_COMPLETED, ActionTypes.ACCEPT_XMR_BID, ActionTypes.ACCEPT_BID))
        for row in q:
            bid_id, amount, state = row
            bids.append((bid_id, amount, state))
            total_value += amount
        return bids, total_value

    def shouldAutoAcceptBid(self, offer, bid, session=None):
        try:
            use_session = self.openSession(session)

            link = use_session.query(AutomationLink).filter_by(active_ind=1, linked_type=Concepts.OFFER, linked_id=offer.offer_id).first()
            if not link:
                return False

            strategy = use_session.query(AutomationStrategy).filter_by(active_ind=1, record_id=link.strategy_id).first()
            opts = json.loads(strategy.data.decode('utf-8'))

            self.log.debug('Evaluating against strategy {}'.format(strategy.record_id))

            if not offer.amount_negotiable:
                if bid.amount != offer.amount_from:
                    raise AutomationConstraint('Need exact amount match')

            if bid.amount < offer.min_bid_amount:
                raise AutomationConstraint('Bid amount below offer minimum')

            if opts.get('exact_rate_only', False) is True:
                if bid.rate != offer.rate:
                    raise AutomationConstraint('Need exact rate match')

            active_bids, total_bids_value = self.getCompletedAndActiveBidsValue(offer, use_session)

            if total_bids_value + bid.amount > offer.amount_from:
                raise AutomationConstraint('Over remaining offer value {}'.format(offer.amount_from - total_bids_value))

            num_not_completed = 0
            for active_bid in active_bids:
                if active_bid[2] != BidStates.SWAP_COMPLETED:
                    num_not_completed += 1
            max_concurrent_bids = opts.get('max_concurrent_bids', 1)
            if num_not_completed >= max_concurrent_bids:
                raise AutomationConstraint('Already have {} bids to complete'.format(num_not_completed))

            if strategy.only_known_identities:
                identity_stats = use_session.query(KnownIdentity).filter_by(address=bid.bid_addr).first()
                if not identity_stats:
                    raise AutomationConstraint('Unknown bidder')

                # TODO: More options
                if identity_stats.num_recv_bids_successful < 1:
                    raise AutomationConstraint('Bidder has too few successful swaps')
                if identity_stats.num_recv_bids_successful <= identity_stats.num_recv_bids_failed:
                    raise AutomationConstraint('Bidder has too many failed swaps')

            self.logEvent(Concepts.BID,
                          bid.bid_id,
                          EventLogTypes.AUTOMATION_ACCEPTING_BID,
                          '',
                          use_session)

            return True
        except AutomationConstraint as e:
            self.log.info('Not auto accepting bid {}, {}'.format(bid.bid_id.hex(), str(e)))
            if self.debug:
                self.logEvent(Concepts.AUTOMATION,
                              bid.bid_id,
                              EventLogTypes.AUTOMATION_CONSTRAINT,
                              str(e),
                              use_session)
            return False
        except Exception as e:
            self.logException(f'shouldAutoAcceptBid {e}')
            return False
        finally:
            if session is None:
                self.closeSession(use_session)

    def processBid(self, msg):
        self.log.debug('Processing bid msg %s', msg['msgid'])
        now = int(time.time())
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = BidMessage()
        bid_data.ParseFromString(bid_bytes)

        # Validate data
        ensure(len(bid_data.offer_msg_id) == 28, 'Bad offer_id length')

        offer_id = bid_data.offer_msg_id
        offer = self.getOffer(offer_id, sent=True)
        ensure(offer and offer.was_sent, 'Unknown offer')

        ensure(offer.state == OfferStates.OFFER_RECEIVED, 'Bad offer state')
        ensure(msg['to'] == offer.addr_from, 'Received on incorrect address')
        ensure(now <= offer.expire_at, 'Offer expired')
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid)
        ensure(now <= msg['sent'] + bid_data.time_valid, 'Bid expired')
        self.validateBidAmount(offer, bid_data.amount, bid_data.rate)

        # TODO: Allow higher bids
        # assert (bid_data.rate != offer['data'].rate), 'Bid rate mismatch'

        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(coin_to)

        amount_to = int((bid_data.amount * bid_data.rate) // ci_from.COIN())
        swap_type = offer.swap_type
        if swap_type == SwapTypes.SELLER_FIRST:
            ensure(len(bid_data.pkhash_buyer) == 20, 'Bad pkhash_buyer length')

            sum_unspent = ci_to.verifyProofOfFunds(bid_data.proof_address, bid_data.proof_signature, offer_id)
            self.log.debug('Proof of funds %s %s', bid_data.proof_address, self.ci(coin_to).format_amount(sum_unspent))
            ensure(sum_unspent >= amount_to, 'Proof of funds failed')

        elif swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError('TODO')
        else:
            raise ValueError('Unknown swap type {}.'.format(swap_type))

        bid_id = bytes.fromhex(msg['msgid'])

        bid = self.getBid(bid_id)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                protocol_version=bid_data.protocol_version,
                amount=bid_data.amount,
                rate=bid_data.rate,
                pkhash_buyer=bid_data.pkhash_buyer,

                created_at=msg['sent'],
                amount_to=amount_to,
                expire_at=msg['sent'] + bid_data.time_valid,
                bid_addr=msg['from'],
                was_received=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
            )
        else:
            ensure(bid.state == BidStates.BID_SENT, 'Wrong bid state: {}'.format(str(BidStates(bid.state))))
            bid.created_at = msg['sent']
            bid.expire_at = msg['sent'] + bid_data.time_valid
            bid.was_received = True
        if len(bid_data.proof_address) > 0:
            bid.proof_address = bid_data.proof_address

        bid.setState(BidStates.BID_RECEIVED)

        self.saveBid(bid_id, bid)
        self.notify(NT.BID_RECEIVED, {'type': 'atomic', 'bid_id': bid_id.hex(), 'offer_id': bid_data.offer_msg_id.hex()})

        if self.shouldAutoAcceptBid(offer, bid):
            delay = random.randrange(self.min_delay_event, self.max_delay_event)
            self.log.info('Auto accepting bid %s in %d seconds', bid_id.hex(), delay)
            self.createAction(delay, ActionTypes.ACCEPT_BID, bid_id)

    def processBidAccept(self, msg):
        self.log.debug('Processing bid accepted msg %s', msg['msgid'])
        now = int(time.time())
        bid_accept_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_accept_data = BidAcceptMessage()
        bid_accept_data.ParseFromString(bid_accept_bytes)

        ensure(len(bid_accept_data.bid_msg_id) == 28, 'Bad bid_msg_id length')
        ensure(len(bid_accept_data.initiate_txid) == 32, 'Bad initiate_txid length')
        ensure(len(bid_accept_data.contract_script) < 100, 'Bad contract_script length')

        self.log.debug('for bid %s', bid_accept_data.bid_msg_id.hex())

        bid_id = bid_accept_data.bid_msg_id
        bid, offer = self.getBidAndOffer(bid_id)
        ensure(bid is not None and bid.was_sent is True, 'Unknown bidid')
        ensure(offer, 'Offer not found ' + bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        ci_from = self.ci(coin_from)

        ensure(bid.expire_at > now + self._bid_expired_leeway, 'Bid expired')

        if bid.state >= BidStates.BID_ACCEPTED:
            if bid.was_received:  # Sent to self
                self.log.info('Received valid bid accept %s for bid %s sent to self', bid.accept_msg_id.hex(), bid_id.hex())
                return
            raise ValueError('Wrong bid state: {}'.format(str(BidStates(bid.state))))

        use_csv = True if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS else False

        # TODO: Verify script without decoding?
        decoded_script = self.callcoinrpc(Coins.PART, 'decodescript', [bid_accept_data.contract_script.hex()])
        lock_check_op = 'OP_CHECKSEQUENCEVERIFY' if use_csv else 'OP_CHECKLOCKTIMEVERIFY'
        prog = re.compile(r'OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 (\w+) OP_EQUALVERIFY OP_DUP OP_HASH160 (\w+) OP_ELSE (\d+) {} OP_DROP OP_DUP OP_HASH160 (\w+) OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG'.format(lock_check_op))
        rr = prog.match(decoded_script['asm'])
        if not rr:
            raise ValueError('Bad script')
        scriptvalues = rr.groups()

        ensure(len(scriptvalues[0]) == 64, 'Bad secret_hash length')
        ensure(bytes.fromhex(scriptvalues[1]) == bid.pkhash_buyer, 'pkhash_buyer mismatch')

        script_lock_value = int(scriptvalues[2])
        if use_csv:
            expect_sequence = ci_from.getExpectedSequence(offer.lock_type, offer.lock_value)
            ensure(script_lock_value == expect_sequence, 'sequence mismatch')
        else:
            if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                block_header_from = ci_from.getBlockHeaderAt(now)
                chain_height_at_bid_creation = block_header_from['height']
                ensure(script_lock_value <= chain_height_at_bid_creation + offer.lock_value + atomic_swap_1.ABS_LOCK_BLOCKS_LEEWAY, 'script lock height too high')
                ensure(script_lock_value >= chain_height_at_bid_creation + offer.lock_value - atomic_swap_1.ABS_LOCK_BLOCKS_LEEWAY, 'script lock height too low')
            else:
                ensure(script_lock_value <= now + offer.lock_value + atomic_swap_1.INITIATE_TX_TIMEOUT, 'script lock time too high')
                ensure(script_lock_value >= now + offer.lock_value - atomic_swap_1.ABS_LOCK_TIME_LEEWAY, 'script lock time too low')

        ensure(len(scriptvalues[3]) == 40, 'pkhash_refund bad length')

        ensure(bid.accept_msg_id is None, 'Bid already accepted')

        bid.accept_msg_id = bytes.fromhex(msg['msgid'])
        bid.initiate_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.ITX,
            txid=bid_accept_data.initiate_txid,
            script=bid_accept_data.contract_script,
        )
        bid.pkhash_seller = bytes.fromhex(scriptvalues[3])
        bid.setState(BidStates.BID_ACCEPTED)
        bid.setITxState(TxStates.TX_NONE)

        bid.offer_id.hex()

        self.saveBid(bid_id, bid)
        self.swaps_in_progress[bid_id] = (bid, offer)
        self.notify(NT.BID_ACCEPTED, {'bid_id': bid_id.hex()})

    def receiveXmrBid(self, bid, session):
        self.log.debug('Receiving xmr bid %s', bid.bid_id.hex())
        now = int(time.time())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=True)
        ensure(offer and offer.was_sent, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid.bid_id.hex()))

        ci_from = self.ci(Coins(offer.coin_from))
        ci_to = self.ci(Coins(offer.coin_to))

        if offer.coin_to == Coins.XMR:
            if len(xmr_swap.kbsf_dleag) < ci_to.lengthDLEAG():
                q = session.query(XmrSplitData).filter(sa.and_(XmrSplitData.bid_id == bid.bid_id, XmrSplitData.msg_type == XmrSplitMsgTypes.BID)).order_by(XmrSplitData.msg_sequence.asc())
                for row in q:
                    xmr_swap.kbsf_dleag += row.dleag

            if not ci_to.verifyDLEAG(xmr_swap.kbsf_dleag):
                raise ValueError('Invalid DLEAG proof.')

            # Extract pubkeys from MSG1L DLEAG
            xmr_swap.pkasf = xmr_swap.kbsf_dleag[0: 33]
            if not ci_from.verifyPubkey(xmr_swap.pkasf):
                raise ValueError('Invalid coin a pubkey.')
            xmr_swap.pkbsf = xmr_swap.kbsf_dleag[33: 33 + 32]
            if not ci_to.verifyPubkey(xmr_swap.pkbsf):
                raise ValueError('Invalid coin b pubkey.')
        else:
            xmr_swap.pkasf = xmr_swap.kbsf_dleag[0: 33]
            if not ci_from.verifyPubkey(xmr_swap.pkasf):
                raise ValueError('Invalid coin a pubkey.')
            xmr_swap.pkbsf = xmr_swap.pkasf

        ensure(ci_to.verifyKey(xmr_swap.vkbvf), 'Invalid key, vkbvf')
        ensure(ci_from.verifyPubkey(xmr_swap.pkaf), 'Invalid pubkey, pkaf')

        self.notify(NT.BID_RECEIVED, {'type': 'xmr', 'bid_id': bid.bid_id.hex(), 'offer_id': bid.offer_id.hex()}, session)

        bid.setState(BidStates.BID_RECEIVED)

        if self.shouldAutoAcceptBid(offer, bid, session):
            delay = random.randrange(self.min_delay_event, self.max_delay_event)
            self.log.info('Auto accepting xmr bid %s in %d seconds', bid.bid_id.hex(), delay)
            self.createActionInSession(delay, ActionTypes.ACCEPT_XMR_BID, bid.bid_id, session)
            bid.setState(BidStates.SWAP_DELAYING)

        self.saveBidInSession(bid.bid_id, bid, session, xmr_swap)

    def receiveXmrBidAccept(self, bid, session):
        # Follower receiving MSG1F and MSG2F
        self.log.debug('Receiving xmr bid accept %s', bid.bid_id.hex())
        now = int(time.time())

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=True)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid.bid_id.hex()))
        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(offer.coin_to)

        if offer.coin_to == Coins.XMR:
            if len(xmr_swap.kbsl_dleag) < ci_to.lengthDLEAG():
                q = session.query(XmrSplitData).filter(sa.and_(XmrSplitData.bid_id == bid.bid_id, XmrSplitData.msg_type == XmrSplitMsgTypes.BID_ACCEPT)).order_by(XmrSplitData.msg_sequence.asc())
                for row in q:
                    xmr_swap.kbsl_dleag += row.dleag
            if not ci_to.verifyDLEAG(xmr_swap.kbsl_dleag):
                raise ValueError('Invalid DLEAG proof.')

            # Extract pubkeys from MSG1F DLEAG
            xmr_swap.pkasl = xmr_swap.kbsl_dleag[0: 33]
            if not ci_from.verifyPubkey(xmr_swap.pkasl):
                raise ValueError('Invalid coin a pubkey.')
            xmr_swap.pkbsl = xmr_swap.kbsl_dleag[33: 33 + 32]
            if not ci_to.verifyPubkey(xmr_swap.pkbsl):
                raise ValueError('Invalid coin b pubkey.')
        else:
            xmr_swap.pkasl = xmr_swap.kbsl_dleag[0: 33]
            if not ci_from.verifyPubkey(xmr_swap.pkasl):
                raise ValueError('Invalid coin a pubkey.')
            xmr_swap.pkbsl = xmr_swap.pkasl

        # vkbv and vkbvl are verified in processXmrBidAccept
        xmr_swap.pkbv = ci_to.sumPubkeys(xmr_swap.pkbvl, xmr_swap.pkbvf)
        xmr_swap.pkbs = ci_to.sumPubkeys(xmr_swap.pkbsl, xmr_swap.pkbsf)

        if not ci_from.verifyPubkey(xmr_swap.pkal):
            raise ValueError('Invalid pubkey.')

        if xmr_swap.pkbvl == xmr_swap.pkbvf:
            raise ValueError('Duplicate scriptless view pubkey.')
        if xmr_swap.pkbsl == xmr_swap.pkbsf:
            raise ValueError('Duplicate scriptless spend pubkey.')
        if xmr_swap.pkal == xmr_swap.pkaf:
            raise ValueError('Duplicate script spend pubkey.')

        bid.setState(BidStates.BID_ACCEPTED)  # XMR
        self.saveBidInSession(bid.bid_id, bid, session, xmr_swap)
        self.notify(NT.BID_ACCEPTED, {'bid_id': bid.bid_id.hex()}, session)

        delay = random.randrange(self.min_delay_event, self.max_delay_event)
        self.log.info('Responding to xmr bid accept %s in %d seconds', bid.bid_id.hex(), delay)
        self.createActionInSession(delay, ActionTypes.SIGN_XMR_SWAP_LOCK_TX_A, bid.bid_id, session)

    def processXmrBid(self, msg):
        # MSG1L
        self.log.debug('Processing xmr bid msg %s', msg['msgid'])
        now = int(time.time())
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = XmrBidMessage()
        bid_data.ParseFromString(bid_bytes)

        # Validate data
        ensure(len(bid_data.offer_msg_id) == 28, 'Bad offer_id length')

        offer_id = bid_data.offer_msg_id
        offer, xmr_offer = self.getXmrOffer(offer_id, sent=True)
        ensure(offer and offer.was_sent, 'Offer not found: {}.'.format(offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(offer_id.hex()))

        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(offer.coin_to)

        if not validOfferStateToReceiveBid(offer.state):
            raise ValueError('Bad offer state')
        ensure(msg['to'] == offer.addr_from, 'Received on incorrect address')
        ensure(now <= offer.expire_at, 'Offer expired')
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid)
        ensure(now <= msg['sent'] + bid_data.time_valid, 'Bid expired')

        self.validateBidAmount(offer, bid_data.amount, bid_data.rate)

        ensure(ci_to.verifyKey(bid_data.kbvf), 'Invalid chain B follower view key')
        ensure(ci_from.verifyPubkey(bid_data.pkaf), 'Invalid chain A follower public key')

        bid_id = bytes.fromhex(msg['msgid'])

        bid, xmr_swap = self.getXmrBid(bid_id)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                protocol_version=bid_data.protocol_version,
                amount=bid_data.amount,
                rate=bid_data.rate,
                created_at=msg['sent'],
                amount_to=(bid_data.amount * bid_data.rate) // ci_from.COIN(),
                expire_at=msg['sent'] + bid_data.time_valid,
                bid_addr=msg['from'],
                was_received=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
            )

            xmr_swap = XmrSwap(
                bid_id=bid_id,
                dest_af=bid_data.dest_af,
                pkaf=bid_data.pkaf,
                vkbvf=bid_data.kbvf,
                pkbvf=ci_to.getPubkey(bid_data.kbvf),
                kbsf_dleag=bid_data.kbsf_dleag,
            )
            wallet_restore_height = self.getWalletRestoreHeight(ci_to)
            if bid.chain_b_height_start < wallet_restore_height:
                bid.chain_b_height_start = wallet_restore_height
                self.log.warning('XMR swap restore height clamped to {}'.format(wallet_restore_height))
        else:
            ensure(bid.state == BidStates.BID_SENT, 'Wrong bid state: {}'.format(str(BidStates(bid.state))))
            bid.created_at = msg['sent']
            bid.expire_at = msg['sent'] + bid_data.time_valid
            bid.was_received = True

        bid.setState(BidStates.BID_RECEIVING)

        self.log.info('Receiving xmr bid %s for offer %s', bid_id.hex(), bid_data.offer_msg_id.hex())
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

        if offer.coin_to != Coins.XMR:
            with self.mxDB:
                try:
                    session = scoped_session(self.session_factory)
                    self.receiveXmrBid(bid, session)
                    session.commit()
                finally:
                    session.close()
                    session.remove()

    def processXmrBidAccept(self, msg):
        # F receiving MSG1F and MSG2F
        self.log.debug('Processing xmr bid accept msg %s', msg['msgid'])
        now = int(time.time())
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidAcceptMessage()
        msg_data.ParseFromString(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, 'Bad bid_msg_id length')

        self.log.debug('for bid %s', msg_data.bid_msg_id.hex())
        bid, xmr_swap = self.getXmrBid(msg_data.bid_msg_id)
        ensure(bid, 'Bid not found: {}.'.format(msg_data.bid_msg_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(msg_data.bid_msg_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=True)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(offer.coin_to)

        try:
            xmr_swap.pkal = msg_data.pkal
            xmr_swap.vkbvl = msg_data.kbvl
            ensure(ci_to.verifyKey(xmr_swap.vkbvl), 'Invalid key, vkbvl')
            xmr_swap.vkbv = ci_to.sumKeys(xmr_swap.vkbvl, xmr_swap.vkbvf)
            ensure(ci_to.verifyKey(xmr_swap.vkbv), 'Invalid key, vkbv')

            xmr_swap.pkbvl = ci_to.getPubkey(msg_data.kbvl)
            xmr_swap.kbsl_dleag = msg_data.kbsl_dleag

            xmr_swap.a_lock_tx = msg_data.a_lock_tx
            xmr_swap.a_lock_tx_script = msg_data.a_lock_tx_script
            xmr_swap.a_lock_refund_tx = msg_data.a_lock_refund_tx
            xmr_swap.a_lock_refund_tx_script = msg_data.a_lock_refund_tx_script
            xmr_swap.a_lock_refund_spend_tx = msg_data.a_lock_refund_spend_tx
            xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_refund_spend_tx)
            xmr_swap.al_lock_refund_tx_sig = msg_data.al_lock_refund_tx_sig

            # TODO: check_lock_tx_inputs without txindex
            check_a_lock_tx_inputs = False
            xmr_swap.a_lock_tx_id, xmr_swap.a_lock_tx_vout = ci_from.verifySCLockTx(
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                bid.amount,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.a_fee_rate,
                check_a_lock_tx_inputs, xmr_swap.vkbv)
            a_lock_tx_dest = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)

            xmr_swap.a_lock_refund_tx_id, xmr_swap.a_swap_refund_value, lock_refund_vout = ci_from.verifySCLockRefundTx(
                xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_tx, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.a_lock_tx_id, xmr_swap.a_lock_tx_vout, xmr_offer.lock_time_1, xmr_swap.a_lock_tx_script,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.lock_time_2,
                bid.amount, xmr_offer.a_fee_rate, xmr_swap.vkbv)

            ci_from.verifySCLockRefundSpendTx(
                xmr_swap.a_lock_refund_spend_tx, xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_id, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.pkal,
                lock_refund_vout, xmr_swap.a_swap_refund_value, xmr_offer.a_fee_rate, xmr_swap.vkbv)

            self.log.info('Checking leader\'s lock refund tx signature')
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            v = ci_from.verifyTxSig(xmr_swap.a_lock_refund_tx, xmr_swap.al_lock_refund_tx_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, prevout_amount)
            ensure(v, 'Invalid coin A lock refund tx leader sig')

            bid.setState(BidStates.BID_RECEIVING_ACC)
            self.saveBid(bid.bid_id, bid, xmr_swap=xmr_swap)

            if offer.coin_to != Coins.XMR:
                with self.mxDB:
                    try:
                        session = scoped_session(self.session_factory)
                        self.receiveXmrBidAccept(bid, session)
                        session.commit()
                    finally:
                        session.close()
                        session.remove()
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid.bid_id, bid, str(ex), xmr_swap=xmr_swap)

    def watchXmrSwap(self, bid, offer, xmr_swap):
        self.log.debug('XMR swap in progress, bid %s', bid.bid_id.hex())
        self.swaps_in_progress[bid.bid_id] = (bid, offer)

        coin_from = Coins(offer.coin_from)
        self.setLastHeightChecked(coin_from, bid.chain_a_height_start)
        self.addWatchedOutput(coin_from, bid.bid_id, bid.xmr_a_lock_tx.txid.hex(), bid.xmr_a_lock_tx.vout, TxTypes.XMR_SWAP_A_LOCK, SwapTypes.XMR_SWAP)

        lock_refund_vout = self.ci(coin_from).getLockRefundTxSwapOutput(xmr_swap)
        self.addWatchedOutput(coin_from, bid.bid_id, xmr_swap.a_lock_refund_tx_id.hex(), lock_refund_vout, TxTypes.XMR_SWAP_A_LOCK_REFUND, SwapTypes.XMR_SWAP)
        bid.in_progress = 1

    def sendXmrBidTxnSigsFtoL(self, bid_id, session):
        # F -> L: Sending MSG3L
        self.log.debug('Signing xmr bid lock txns %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        try:
            kaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF)

            prevout_amount = ci_from.getLockRefundTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.af_lock_refund_spend_tx_esig = ci_from.signTxOtVES(kaf, xmr_swap.pkasl, xmr_swap.a_lock_refund_spend_tx, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount)
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.af_lock_refund_tx_sig = ci_from.signTx(kaf, xmr_swap.a_lock_refund_tx, 0, xmr_swap.a_lock_tx_script, prevout_amount)

            addLockRefundSigs(self, xmr_swap, ci_from)

            msg_buf = XmrBidLockTxSigsMessage(
                bid_msg_id=bid_id,
                af_lock_refund_spend_tx_esig=xmr_swap.af_lock_refund_spend_tx_esig,
                af_lock_refund_tx_sig=xmr_swap.af_lock_refund_tx_sig
            )

            msg_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_TXN_SIGS_FL) + msg_bytes.hex()

            msg_valid = self.getActiveBidMsgValidTime()
            xmr_swap.coin_a_lock_tx_sigs_l_msg_id = self.sendSmsg(bid.bid_addr, offer.addr_from, payload_hex, msg_valid)

            self.log.info('Sent XMR_BID_TXN_SIGS_FL %s', xmr_swap.coin_a_lock_tx_sigs_l_msg_id.hex())

            a_lock_tx_id = ci_from.getTxid(xmr_swap.a_lock_tx)
            a_lock_tx_vout = ci_from.getTxOutputPos(xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script)
            self.log.debug('Waiting for lock txn %s to %s chain for bid %s', a_lock_tx_id.hex(), ci_from.coin_name(), bid_id.hex())
            bid.xmr_a_lock_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.XMR_SWAP_A_LOCK,
                txid=a_lock_tx_id,
                vout=a_lock_tx_vout,
            )
            bid.xmr_a_lock_tx.setState(TxStates.TX_NONE)

            bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            self.watchXmrSwap(bid, offer, xmr_swap)
            self.saveBidInSession(bid_id, bid, session, xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())

    def sendXmrBidCoinALockTx(self, bid_id, session):
        # Offerer/Leader. Send coin A lock tx
        self.log.debug('Sending coin A lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAL)

        # Prove leader can sign for kal, sent in MSG4F
        xmr_swap.kal_sig = ci_from.signCompact(kal, 'proof key owned for swap')

        # Create Script lock spend tx
        xmr_swap.a_lock_spend_tx = ci_from.createSCLockSpendTx(
            xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
            xmr_swap.dest_af,
            xmr_offer.a_fee_rate, xmr_swap.vkbv)

        xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)
        prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
        xmr_swap.al_lock_spend_tx_esig = ci_from.signTxOtVES(kal, xmr_swap.pkasf, xmr_swap.a_lock_spend_tx, 0, xmr_swap.a_lock_tx_script, prevout_amount)

        delay = random.randrange(self.min_delay_event_short, self.max_delay_event_short)
        self.log.info('Sending lock spend tx message for bid %s in %d seconds', bid_id.hex(), delay)
        self.createActionInSession(delay, ActionTypes.SEND_XMR_SWAP_LOCK_SPEND_MSG, bid_id, session)

        # publishalocktx
        lock_tx_signed = ci_from.signTxWithWallet(xmr_swap.a_lock_tx)
        txid_hex = ci_from.publishTx(lock_tx_signed)

        vout_pos = ci_from.getTxOutputPos(xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script)

        self.log.debug('Submitted lock txn %s to %s chain for bid %s', txid_hex, ci_from.coin_name(), bid_id.hex())

        bid.xmr_a_lock_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.XMR_SWAP_A_LOCK,
            txid=bytes.fromhex(txid_hex),
            vout=vout_pos,
        )
        bid.xmr_a_lock_tx.setState(TxStates.TX_SENT)

        bid.setState(BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX)
        self.watchXmrSwap(bid, offer, xmr_swap)
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_PUBLISHED, '', session)

        self.saveBidInSession(bid_id, bid, session, xmr_swap)

    def sendXmrBidCoinBLockTx(self, bid_id, session):
        # Follower sending coin B lock tx
        self.log.debug('Sending coin B lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        if bid.debug_ind == DebugTypes.BID_STOP_AFTER_COIN_A_LOCK:
            self.log.debug('XMR bid %s: Stalling bid for testing: %d.', bid_id.hex(), bid.debug_ind)
            bid.setState(BidStates.BID_STALLED_FOR_TEST)
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            return

        if bid.debug_ind == DebugTypes.CREATE_INVALID_COIN_B_LOCK:
            bid.amount_to -= int(bid.amount_to * 0.1)
            self.log.debug('XMR bid %s: Debug %d - Reducing lock b txn amount by 10%% to %s.', bid_id.hex(), bid.debug_ind, ci_to.format_amount(bid.amount_to))
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
        try:
            b_lock_tx_id = ci_to.publishBLockTx(xmr_swap.pkbv, xmr_swap.pkbs, bid.amount_to, xmr_offer.b_fee_rate)
        except Exception as ex:
            error_msg = 'publishBLockTx failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            if num_retries < 5 and (ci_to.is_transient_error(ex) or self.is_transient_error(ex)):
                delay = random.randrange(self.min_delay_retry, self.max_delay_retry)
                self.log.info('Retrying sending xmr swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createActionInSession(delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'publishBLockTx failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid.bid_id, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, str(ex), session)
            return

        self.log.debug('Submitted lock txn %s to %s chain for bid %s', b_lock_tx_id.hex(), ci_to.coin_name(), bid_id.hex())
        bid.xmr_b_lock_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.XMR_SWAP_B_LOCK,
            txid=b_lock_tx_id,
        )
        bid.xmr_b_lock_tx.setState(TxStates.TX_NONE)
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_PUBLISHED, '', session)

        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def sendXmrBidLockRelease(self, bid_id, session):
        # Leader sending lock tx a release secret (MSG5F)
        self.log.debug('Sending bid secret for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)

        msg_buf = XmrBidLockReleaseMessage(
            bid_msg_id=bid_id,
            al_lock_spend_tx_esig=xmr_swap.al_lock_spend_tx_esig)

        msg_bytes = msg_buf.SerializeToString()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_LOCK_RELEASE_LF) + msg_bytes.hex()

        msg_valid = self.getActiveBidMsgValidTime()
        xmr_swap.coin_a_lock_release_msg_id = self.sendSmsg(offer.addr_from, bid.bid_addr, payload_hex, msg_valid)

        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def redeemXmrBidCoinALockTx(self, bid_id, session):
        # Follower redeeming A lock tx
        self.log.debug('Redeeming coin A lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        for_ed25519 = True if coin_to == Coins.XMR else False
        kbsf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)
        kaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF)

        al_lock_spend_sig = ci_from.decryptOtVES(kbsf, xmr_swap.al_lock_spend_tx_esig)
        prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
        v = ci_from.verifyTxSig(xmr_swap.a_lock_spend_tx, al_lock_spend_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, prevout_amount)
        ensure(v, 'Invalid coin A lock tx spend tx leader sig')

        af_lock_spend_sig = ci_from.signTx(kaf, xmr_swap.a_lock_spend_tx, 0, xmr_swap.a_lock_tx_script, prevout_amount)
        v = ci_from.verifyTxSig(xmr_swap.a_lock_spend_tx, af_lock_spend_sig, xmr_swap.pkaf, 0, xmr_swap.a_lock_tx_script, prevout_amount)
        ensure(v, 'Invalid coin A lock tx spend tx follower sig')

        witness_stack = [
            b'',
            al_lock_spend_sig,
            af_lock_spend_sig,
            xmr_swap.a_lock_tx_script,
        ]

        xmr_swap.a_lock_spend_tx = ci_from.setTxSignature(xmr_swap.a_lock_spend_tx, witness_stack)

        txid = bytes.fromhex(ci_from.publishTx(xmr_swap.a_lock_spend_tx))
        self.log.debug('Submitted lock spend txn %s to %s chain for bid %s', txid.hex(), ci_from.coin_name(), bid_id.hex())
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_SPEND_TX_PUBLISHED, '', session)
        bid.xmr_a_lock_spend_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.XMR_SWAP_A_LOCK_SPEND,
            txid=txid,
        )
        bid.xmr_a_lock_spend_tx.setState(TxStates.TX_NONE)

        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def redeemXmrBidCoinBLockTx(self, bid_id, session):
        # Leader redeeming B lock tx
        self.log.debug('Redeeming coin B lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        try:
            chain_height = ci_to.getChainHeight()
            lock_tx_depth = (chain_height - bid.xmr_b_lock_tx.chain_height) + 1
            if lock_tx_depth < ci_to.depth_spendable():
                raise TemporaryError(f'Chain B lock tx depth {lock_tx_depth} < required for spending.')

            # Extract the leader's decrypted signature and use it to recover the follower's privatekey
            xmr_swap.al_lock_spend_tx_sig = ci_from.extractLeaderSig(xmr_swap.a_lock_spend_tx)

            kbsf = ci_from.recoverEncKey(xmr_swap.al_lock_spend_tx_esig, xmr_swap.al_lock_spend_tx_sig, xmr_swap.pkasf)
            assert (kbsf is not None)

            for_ed25519 = True if coin_to == Coins.XMR else False
            kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSL, for_ed25519)
            vkbs = ci_to.sumKeys(kbsl, kbsf)

            if coin_to == Coins.XMR:
                address_to = self.getCachedMainWalletAddress(ci_to)
            else:
                address_to = self.getCachedStealthAddressForCoin(coin_to)
            txid = ci_to.spendBLockTx(xmr_swap.b_lock_tx_id, address_to, xmr_swap.vkbv, vkbs, bid.amount_to, xmr_offer.b_fee_rate, bid.chain_b_height_start)
            self.log.debug('Submitted lock B spend txn %s to %s chain for bid %s', txid.hex(), ci_to.coin_name(), bid_id.hex())
            self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED, '', session)
        except Exception as ex:
            error_msg = 'spendBLockTx failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_SPEND, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            if num_retries < 100 and (ci_to.is_transient_error(ex) or self.is_transient_error(ex)):
                delay = random.randrange(self.min_delay_retry, self.max_delay_retry)
                self.log.info('Retrying sending xmr swap chain B spend tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createActionInSession(delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'spendBLockTx failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid.bid_id, EventLogTypes.FAILED_TX_B_SPEND, str(ex), session)
            return

        bid.xmr_b_lock_tx.spend_txid = txid
        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
        # TODO: Why does using bid.txns error here?
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def recoverXmrBidCoinBLockTx(self, bid_id, session):
        # Follower recovering B lock tx
        self.log.debug('Recovering coin B lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        # Extract the follower's decrypted signature and use it to recover the leader's privatekey
        af_lock_refund_spend_tx_sig = ci_from.extractFollowerSig(xmr_swap.a_lock_refund_spend_tx)

        kbsl = ci_from.recoverEncKey(xmr_swap.af_lock_refund_spend_tx_esig, af_lock_refund_spend_tx_sig, xmr_swap.pkasl)
        assert (kbsl is not None)

        for_ed25519 = True if coin_to == Coins.XMR else False
        kbsf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)
        vkbs = ci_to.sumKeys(kbsl, kbsf)

        try:
            if offer.coin_to == Coins.XMR:
                address_to = self.getCachedMainWalletAddress(ci_to)
            else:
                address_to = self.getCachedStealthAddressForCoin(coin_to)
            txid = ci_to.spendBLockTx(xmr_swap.b_lock_tx_id, address_to, xmr_swap.vkbv, vkbs, bid.amount_to, xmr_offer.b_fee_rate, bid.chain_b_height_start)
            self.log.debug('Submitted lock B refund txn %s to %s chain for bid %s', txid.hex(), ci_to.coin_name(), bid_id.hex())
            self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_REFUND_TX_PUBLISHED, '', session)
        except Exception as ex:
            # TODO: Make min-conf 10?
            error_msg = 'spendBLockTx refund failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_REFUND, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            str_error = str(ex)
            if num_retries < 100 and (ci_to.is_transient_error(ex) or self.is_transient_error(ex)):
                delay = random.randrange(self.min_delay_retry, self.max_delay_retry)
                self.log.info('Retrying sending xmr swap chain B refund tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createActionInSession(delay, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'spendBLockTx for refund failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid.bid_id, EventLogTypes.FAILED_TX_B_REFUND, str_error, session)
            return

        bid.xmr_b_lock_tx.spend_txid = txid

        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def sendXmrBidCoinALockSpendTxMsg(self, bid_id, session):
        # Send MSG4F L -> F
        self.log.debug('Sending coin A lock spend tx msg for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        ci_from = self.ci(offer.coin_from)

        msg_buf = XmrBidLockSpendTxMessage(
            bid_msg_id=bid_id,
            a_lock_spend_tx=xmr_swap.a_lock_spend_tx,
            kal_sig=xmr_swap.kal_sig)

        msg_bytes = msg_buf.SerializeToString()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_LOCK_SPEND_TX_LF) + msg_bytes.hex()

        msg_valid = self.getActiveBidMsgValidTime()
        xmr_swap.coin_a_lock_refund_spend_tx_msg_id = self.sendSmsg(offer.addr_from, bid.bid_addr, payload_hex, msg_valid)

        bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def processXmrBidCoinALockSigs(self, msg):
        # Leader processing MSG3L
        self.log.debug('Processing xmr coin a follower lock sigs msg %s', msg['msgid'])
        now = int(time.time())
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockTxSigsMessage()
        msg_data.ParseFromString(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, 'Bad bid_msg_id length')
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        try:
            xmr_swap.af_lock_refund_spend_tx_esig = msg_data.af_lock_refund_spend_tx_esig
            xmr_swap.af_lock_refund_tx_sig = msg_data.af_lock_refund_tx_sig

            for_ed25519 = True if coin_to == Coins.XMR else False
            kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSL, for_ed25519)
            kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAL)

            xmr_swap.af_lock_refund_spend_tx_sig = ci_from.decryptOtVES(kbsl, xmr_swap.af_lock_refund_spend_tx_esig)
            prevout_amount = ci_from.getLockRefundTxSwapOutputValue(bid, xmr_swap)
            al_lock_refund_spend_tx_sig = ci_from.signTx(kal, xmr_swap.a_lock_refund_spend_tx, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount)

            self.log.debug('Setting lock refund spend tx sigs')
            witness_stack = [
                b'',
                al_lock_refund_spend_tx_sig,
                xmr_swap.af_lock_refund_spend_tx_sig,
                bytes((1,)),
                xmr_swap.a_lock_refund_tx_script,
            ]
            signed_tx = ci_from.setTxSignature(xmr_swap.a_lock_refund_spend_tx, witness_stack)
            ensure(signed_tx, 'setTxSignature failed')
            xmr_swap.a_lock_refund_spend_tx = signed_tx

            v = ci_from.verifyTxSig(xmr_swap.a_lock_refund_spend_tx, xmr_swap.af_lock_refund_spend_tx_sig, xmr_swap.pkaf, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount)
            ensure(v, 'Invalid signature for lock refund spend txn')
            addLockRefundSigs(self, xmr_swap, ci_from)

            delay = random.randrange(self.min_delay_event, self.max_delay_event)
            self.log.info('Sending coin A lock tx for xmr bid %s in %d seconds', bid_id.hex(), delay)
            self.createAction(delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_A, bid_id)

            bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))

    def processXmrBidLockSpendTx(self, msg):
        # Follower receiving MSG4F
        self.log.debug('Processing xmr bid lock spend tx msg %s', msg['msgid'])
        now = int(time.time())
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockSpendTxMessage()
        msg_data.ParseFromString(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, 'Bad bid_msg_id length')
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        ci_from = self.ci(Coins(offer.coin_from))
        ci_to = self.ci(Coins(offer.coin_to))

        try:
            xmr_swap.a_lock_spend_tx = msg_data.a_lock_spend_tx
            xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)
            xmr_swap.kal_sig = msg_data.kal_sig

            ci_from.verifySCLockSpendTx(
                xmr_swap.a_lock_spend_tx,
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                xmr_swap.dest_af, xmr_offer.a_fee_rate, xmr_swap.vkbv)

            ci_from.verifyCompactSig(xmr_swap.pkal, 'proof key owned for swap', xmr_swap.kal_sig)

            bid.setState(BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX)
            bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX)
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))

        # Update copy of bid in swaps_in_progress
        self.swaps_in_progress[bid_id] = (bid, offer)

    def processXmrSplitMessage(self, msg):
        self.log.debug('Processing xmr split msg %s', msg['msgid'])
        now = int(time.time())
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrSplitMessage()
        msg_data.ParseFromString(msg_bytes)

        # Validate data
        ensure(len(msg_data.msg_id) == 28, 'Bad msg_id length')

        if msg_data.msg_type == XmrSplitMsgTypes.BID or msg_data.msg_type == XmrSplitMsgTypes.BID_ACCEPT:
            try:
                session = scoped_session(self.session_factory)
                q = session.execute('SELECT COUNT(*) FROM xmr_split_data WHERE bid_id = x\'{}\' AND msg_type = {} AND msg_sequence = {}'.format(msg_data.msg_id.hex(), msg_data.msg_type, msg_data.sequence)).first()
                num_exists = q[0]
                if num_exists > 0:
                    self.log.warning('Ignoring duplicate xmr_split_data entry: ({}, {}, {})'.format(msg_data.msg_id.hex(), msg_data.msg_type, msg_data.sequence))
                    return

                dbr = XmrSplitData()
                dbr.bid_id = msg_data.msg_id
                dbr.msg_type = msg_data.msg_type
                dbr.msg_sequence = msg_data.sequence
                dbr.dleag = msg_data.dleag
                dbr.created_at = now
                session.add(dbr)
                session.commit()
            finally:
                session.close()
                session.remove()

    def processXmrLockReleaseMessage(self, msg):
        self.log.debug('Processing xmr secret msg %s', msg['msgid'])
        now = int(time.time())
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockReleaseMessage()
        msg_data.ParseFromString(msg_bytes)

        # Validate data
        ensure(len(msg_data.bid_msg_id) == 28, 'Bad msg_id length')

        bid_id = msg_data.bid_msg_id
        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        ci_from = self.ci(Coins(offer.coin_from))

        xmr_swap.al_lock_spend_tx_esig = msg_data.al_lock_spend_tx_esig
        try:
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            v = ci_from.verifyTxOtVES(
                xmr_swap.a_lock_spend_tx, xmr_swap.al_lock_spend_tx_esig,
                xmr_swap.pkal, xmr_swap.pkasf, 0, xmr_swap.a_lock_tx_script, prevout_amount)
            ensure(v, 'verifyTxOtVES failed for chain a lock tx leader esig')
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))
            self.swaps_in_progress[bid_id] = (bid, offer)
            return

        delay = random.randrange(self.min_delay_event, self.max_delay_event)
        self.log.info('Redeeming coin A lock tx for xmr bid %s in %d seconds', bid_id.hex(), delay)
        self.createAction(delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_A, bid_id)

        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        self.swaps_in_progress[bid_id] = (bid, offer)

    def processMsg(self, msg):
        self.mxDB.acquire()
        try:
            msg_type = int(msg['hex'][:2], 16)

            rv = None
            if msg_type == MessageTypes.OFFER:
                self.processOffer(msg)
            elif msg_type == MessageTypes.BID:
                self.processBid(msg)
            elif msg_type == MessageTypes.BID_ACCEPT:
                self.processBidAccept(msg)
            elif msg_type == MessageTypes.XMR_BID_FL:
                self.processXmrBid(msg)
            elif msg_type == MessageTypes.XMR_BID_ACCEPT_LF:
                self.processXmrBidAccept(msg)
            elif msg_type == MessageTypes.XMR_BID_TXN_SIGS_FL:
                self.processXmrBidCoinALockSigs(msg)
            elif msg_type == MessageTypes.XMR_BID_LOCK_SPEND_TX_LF:
                self.processXmrBidLockSpendTx(msg)
            elif msg_type == MessageTypes.XMR_BID_SPLIT:
                self.processXmrSplitMessage(msg)
            elif msg_type == MessageTypes.XMR_BID_LOCK_RELEASE_LF:
                self.processXmrLockReleaseMessage(msg)
            if msg_type == MessageTypes.OFFER_REVOKE:
                self.processOfferRevoke(msg)

        except InactiveCoin as ex:
            self.log.info('Ignoring message involving inactive coin {}, type {}'.format(Coins(ex.coinid).name, MessageTypes(msg_type).name))
        except Exception as ex:
            self.log.error('processMsg %s', str(ex))
            if self.debug:
                self.log.error(traceback.format_exc())
                self.logEvent(Concepts.NETWORK_MESSAGE,
                              bytes.fromhex(msg['msgid']),
                              EventLogTypes.ERROR,
                              str(ex),
                              None)

        finally:
            self.mxDB.release()

    def processZmqSmsg(self):
        message = self.zmqSubscriber.recv()
        clear = self.zmqSubscriber.recv()

        if message[0] == 3:  # Paid smsg
            return  # TODO: Switch to paid?

        msg_id = message[2:]
        options = {'encoding': 'hex', 'setread': True}
        num_tries = 5
        for i in range(num_tries + 1):
            try:
                msg = self.callrpc('smsg', [msg_id.hex(), options])
                break
            except Exception as e:
                if 'Unknown message id' in str(e) and i < num_tries:
                    time.sleep(1)
                else:
                    raise e

        self.processMsg(msg)

    def update(self):
        try:
            # while True:
            message = self.zmqSubscriber.recv(flags=zmq.NOBLOCK)
            if message == b'smsg':
                self.processZmqSmsg()
        except zmq.Again as ex:
            pass
        except Exception as ex:
            self.logException(f'smsg zmq {ex}')

        self.mxDB.acquire()
        try:
            # TODO: Wait for blocks / txns, would need to check multiple coins
            now = int(time.time())
            if now - self._last_checked_progress >= self.check_progress_seconds:
                to_remove = []
                for bid_id, v in self.swaps_in_progress.items():
                    try:
                        if self.checkBidState(bid_id, v[0], v[1]) is True:
                            to_remove.append((bid_id, v[0], v[1]))
                    except Exception as ex:
                        if self.debug:
                            self.log.error('checkBidState %s', traceback.format_exc())
                        if self.is_transient_error(ex):
                            self.log.warning('checkBidState %s %s', bid_id.hex(), str(ex))
                            self.logBidEvent(bid_id, EventLogTypes.SYSTEM_WARNING, 'No connection to daemon', session=None)
                        else:
                            self.log.error('checkBidState %s %s', bid_id.hex(), str(ex))
                            self.setBidError(bid_id, v[0], str(ex))

                for bid_id, bid, offer in to_remove:
                    self.deactivateBid(None, offer, bid)
                self._last_checked_progress = now

            if now - self._last_checked_watched >= self.check_watched_seconds:
                for k, c in self.coin_clients.items():
                    if k == Coins.PART_ANON or k == Coins.PART_BLIND:
                        continue
                    if len(c['watched_outputs']) > 0:
                        self.checkForSpends(k, c)
                self._last_checked_watched = now

            if now - self._last_checked_expired >= self.check_expired_seconds:
                self.expireMessages()
                self._last_checked_expired = now

            if now - self._last_checked_actions >= self.check_actions_seconds:
                self.checkQueuedActions()
                self._last_checked_actions = now

            if now - self._last_checked_xmr_swaps >= self.check_xmr_swaps_seconds:
                self.checkXmrSwaps()
                self._last_checked_xmr_swaps = now

        except Exception as ex:
            self.logException(f'update {ex}')
        finally:
            self.mxDB.release()

    def manualBidUpdate(self, bid_id, data):
        self.log.info('Manually updating bid %s', bid_id.hex())
        self.mxDB.acquire()
        try:
            bid, offer = self.getBidAndOffer(bid_id)
            ensure(bid, 'Bid not found {}'.format(bid_id.hex()))
            ensure(offer, 'Offer not found {}'.format(bid.offer_id.hex()))

            has_changed = False
            if bid.state != data['bid_state']:
                bid.setState(data['bid_state'])
                self.log.debug('Set state to %s', strBidState(bid.state))
                has_changed = True

            if bid.debug_ind != data['debug_ind']:
                if bid.debug_ind is None and data['debug_ind'] == -1:
                    pass  # Already unset
                else:
                    self.log.debug('Bid %s Setting debug flag: %s', bid_id.hex(), data['debug_ind'])
                    bid.debug_ind = data['debug_ind']
                    has_changed = True

            if data['kbs_other'] is not None:
                return recoverNoScriptTxnWithKey(self, bid_id, data['kbs_other'])

            if has_changed:
                session = scoped_session(self.session_factory)
                try:
                    activate_bid = False
                    if bid.state and isActiveBidState(bid.state):
                        activate_bid = True

                    if activate_bid:
                        self.activateBid(session, bid)
                    else:
                        self.deactivateBid(session, offer, bid)

                    self.saveBidInSession(bid_id, bid, session)
                    session.commit()
                finally:
                    session.close()
                    session.remove()
            else:
                raise ValueError('No changes')
        finally:
            self.mxDB.release()

    def editSettings(self, coin_name, data):
        self.log.info('Updating settings %s', coin_name)
        with self.mxDB:
            settings_cc = self.settings['chainclients'][coin_name]
            settings_changed = False
            suggest_reboot = False
            if 'lookups' in data:
                if settings_cc.get('chain_lookups', 'local') != data['lookups']:
                    settings_changed = True
                    settings_cc['chain_lookups'] = data['lookups']
                    for coin, cc in self.coin_clients.items():
                        if cc['name'] == coin_name:
                            cc['chain_lookups'] = data['lookups']
                            break

            for setting in ('manage_daemon', 'rpchost', 'rpcport', 'automatically_select_daemon'):
                if setting not in data:
                    continue
                if settings_cc.get(setting) != data[setting]:
                    settings_changed = True
                    suggest_reboot = True
                    settings_cc[setting] = data[setting]

            if 'remotedaemonurls' in data:
                remotedaemonurls_in = data['remotedaemonurls'].split('\n')
                remotedaemonurls = set()
                for url in remotedaemonurls_in:
                    if url.count(':') > 0:
                        remotedaemonurls.add(url.strip())

                if set(settings_cc.get('remote_daemon_urls', [])) != remotedaemonurls:
                    settings_cc['remote_daemon_urls'] = list(remotedaemonurls)
                    settings_changed = True
                    suggest_reboot = True

            if 'fee_priority' in data:
                new_fee_priority = data['fee_priority']
                ensure(new_fee_priority >= 0 and new_fee_priority < 4, 'Invalid priority')

                if settings_cc.get('fee_priority', 0) != new_fee_priority:
                    settings_changed = True
                    settings_cc['fee_priority'] = new_fee_priority
                    for coin, cc in self.coin_clients.items():
                        if cc['name'] == coin_name:
                            cc['fee_priority'] = new_fee_priority
                            self.ci(coin).setFeePriority(new_fee_priority)
                            break

            if 'conf_target' in data:
                new_conf_target = data['conf_target']
                ensure(new_conf_target >= 1 and new_conf_target < 33, 'Invalid conf_target')

                if settings_cc.get('conf_target', 2) != new_conf_target:
                    settings_changed = True
                    settings_cc['conf_target'] = new_conf_target
                    for coin, cc in self.coin_clients.items():
                        if cc['name'] == coin_name:
                            cc['conf_target'] = new_conf_target
                            self.ci(coin).setConfTarget(new_conf_target)
                            break

            if 'anon_tx_ring_size' in data:
                new_anon_tx_ring_size = data['anon_tx_ring_size']
                ensure(new_anon_tx_ring_size >= 3 and new_anon_tx_ring_size < 33, 'Invalid anon_tx_ring_size')

                if settings_cc.get('anon_tx_ring_size', 12) != new_anon_tx_ring_size:
                    settings_changed = True
                    settings_cc['anon_tx_ring_size'] = new_anon_tx_ring_size
                    for coin, cc in self.coin_clients.items():
                        if cc['name'] == coin_name:
                            cc['anon_tx_ring_size'] = new_anon_tx_ring_size
                            self.ci(coin).setAnonTxRingSize(new_anon_tx_ring_size)
                            break

            if settings_changed:
                settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
                shutil.copyfile(settings_path, settings_path + '.last')
                with open(settings_path, 'w') as fp:
                    json.dump(self.settings, fp, indent=4)
        return settings_changed, suggest_reboot

    def enableCoin(self, coin_name):
        self.log.info('Enabling coin %s', coin_name)

        coin_id = self.getCoinIdFromName(coin_name)
        if coin_id in (Coins.PART, Coins.PART_BLIND, Coins.PART_ANON):
            raise ValueError('Invalid coin')

        settings_cc = self.settings['chainclients'][coin_name]
        if 'connection_type_prev' not in settings_cc:
            raise ValueError('Can\'t find previous value.')
        settings_cc['connection_type'] = settings_cc['connection_type_prev']
        del settings_cc['connection_type_prev']
        if 'manage_daemon_prev' in settings_cc:
            settings_cc['manage_daemon'] = settings_cc['manage_daemon_prev']
            del settings_cc['manage_daemon_prev']
        if 'manage_wallet_daemon_prev' in settings_cc:
            settings_cc['manage_wallet_daemon'] = settings_cc['manage_wallet_daemon_prev']
            del settings_cc['manage_wallet_daemon_prev']

        settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
        shutil.copyfile(settings_path, settings_path + '.last')
        with open(settings_path, 'w') as fp:
            json.dump(self.settings, fp, indent=4)
        # Client must be restarted

    def disableCoin(self, coin_name):
        self.log.info('Disabling coin %s', coin_name)

        coin_id = self.getCoinIdFromName(coin_name)
        if coin_id in (Coins.PART, Coins.PART_BLIND, Coins.PART_ANON):
            raise ValueError('Invalid coin')

        settings_cc = self.settings['chainclients'][coin_name]

        if settings_cc['connection_type'] != 'rpc':
            raise ValueError('Already disabled.')

        settings_cc['manage_daemon_prev'] = settings_cc['manage_daemon']
        settings_cc['manage_daemon'] = False
        settings_cc['connection_type_prev'] = settings_cc['connection_type']
        settings_cc['connection_type'] = 'none'

        if 'manage_wallet_daemon' in settings_cc:
            settings_cc['manage_wallet_daemon_prev'] = settings_cc['manage_wallet_daemon']
            settings_cc['manage_wallet_daemon'] = False

        settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
        shutil.copyfile(settings_path, settings_path + '.last')
        with open(settings_path, 'w') as fp:
            json.dump(self.settings, fp, indent=4)
        # Client must be restarted

    def getSummary(self, opts=None):
        num_watched_outputs = 0
        for c, v in self.coin_clients.items():
            if c in (Coins.PART_ANON, Coins.PART_BLIND):
                continue
            num_watched_outputs += len(v['watched_outputs'])

        now = int(time.time())
        q_str = '''SELECT
                   COUNT(CASE WHEN was_sent THEN 1 ELSE NULL END) AS count_sent,
                   COUNT(CASE WHEN was_received THEN 1 ELSE NULL END) AS count_received,
                   COUNT(CASE WHEN was_received AND state = {} AND expire_at > {} THEN 1 ELSE NULL END) AS count_available
                   FROM bids WHERE active_ind = 1'''.format(BidStates.BID_RECEIVED, now)
        q = self.engine.execute(q_str).first()
        bids_sent = q[0]
        bids_received = q[1]
        bids_available = q[2]

        q_str = '''SELECT
                   COUNT(CASE WHEN expire_at > {} THEN 1 ELSE NULL END) AS count_active,
                   COUNT(CASE WHEN was_sent THEN 1 ELSE NULL END) AS count_sent
                   FROM offers WHERE active_ind = 1'''.format(now)
        q = self.engine.execute(q_str).first()
        num_offers = q[0]
        num_sent_offers = q[1]

        rv = {
            'network': self.chain,
            'num_swapping': len(self.swaps_in_progress),
            'num_network_offers': num_offers,
            'num_sent_offers': num_sent_offers,
            'num_recv_bids': bids_received,
            'num_sent_bids': bids_sent,
            'num_available_bids': bids_available,
            'num_watched_outputs': num_watched_outputs,
        }
        return rv

    def getBlockchainInfo(self, coin):
        ci = self.ci(coin)

        try:
            blockchaininfo = ci.getBlockchainInfo()

            rv = {
                'version': self.coin_clients[coin]['core_version'],
                'name': ci.coin_name(),
                'blocks': blockchaininfo['blocks'],
                'synced': '{:.2f}'.format(round(100 * blockchaininfo['verificationprogress'], 2)),
            }

            if 'known_block_count' in blockchaininfo:
                rv['known_block_count'] = blockchaininfo['known_block_count']
            if 'bootstrapping' in blockchaininfo:
                rv['bootstrapping'] = blockchaininfo['bootstrapping']

            return rv
        except Exception as e:
            self.log.warning('getWalletInfo failed with: %s', str(e))

    def getWalletInfo(self, coin):
        ci = self.ci(coin)

        try:
            walletinfo = ci.getWalletInfo()
            scale = chainparams[coin]['decimal_places']
            rv = {
                'deposit_address': self.getCachedAddressForCoin(coin),
                'balance': format_amount(make_int(walletinfo['balance'], scale), scale),
                'unconfirmed': format_amount(make_int(walletinfo.get('unconfirmed_balance'), scale), scale),
                'expected_seed': ci.knownWalletSeed(),
            }

            if coin == Coins.PART:
                rv['stealth_address'] = self.getCachedStealthAddressForCoin(Coins.PART)
                rv['anon_balance'] = walletinfo['anon_balance']
                rv['anon_pending'] = walletinfo['unconfirmed_anon'] + walletinfo['immature_anon_balance']
                rv['blind_balance'] = walletinfo['blind_balance']
                rv['blind_unconfirmed'] = walletinfo['unconfirmed_blind']
            elif coin == Coins.XMR:
                rv['main_address'] = self.getCachedMainWalletAddress(ci)

            return rv
        except Exception as e:
            self.log.warning('getWalletInfo failed with: %s', str(e))

    def addWalletInfoRecord(self, coin, info_type, wi):
        coin_id = int(coin)
        self.mxDB.acquire()
        try:
            now = int(time.time())
            session = scoped_session(self.session_factory)
            session.add(Wallets(coin_id=coin, balance_type=info_type, wallet_data=json.dumps(wi), created_at=now))
            query_str = f'DELETE FROM wallets WHERE (coin_id = {coin_id} AND balance_type = {info_type}) AND record_id NOT IN (SELECT record_id FROM wallets WHERE coin_id = {coin_id} AND balance_type = {info_type} ORDER BY created_at DESC LIMIT 3 )'
            session.execute(query_str)
            session.commit()
        except Exception as e:
            self.log.error(f'addWalletInfoRecord {e}')
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def updateWalletInfo(self, coin):
        # Store wallet info to db so it's available after startup
        try:
            bi = self.getBlockchainInfo(coin)
            if bi:
                self.addWalletInfoRecord(coin, 0, bi)

            # monero-wallet-rpc is slow/unresponsive while syncing
            wi = self.getWalletInfo(coin)
            if wi:
                self.addWalletInfoRecord(coin, 1, wi)
        except Exception as e:
            self.log.error(f'updateWalletInfo {e}')
        finally:
            self._updating_wallets_info[int(coin)] = False

    def updateWalletsInfo(self, force_update=False, only_coin=None, wait_for_complete=False):
        now = int(time.time())
        if not force_update and now - self._last_updated_wallets_info < 30:
            return
        for c in Coins:
            if only_coin is not None and c != only_coin:
                continue
            if c not in chainparams:
                continue
            cc = self.coin_clients[c]
            if cc['connection_type'] == 'rpc':
                if not force_update and now - cc.get('last_updated_wallet_info', 0) < 30:
                    return
                cc['last_updated_wallet_info'] = int(time.time())
                self._updating_wallets_info[int(c)] = True
                handle = self.thread_pool.submit(self.updateWalletInfo, c)
                if wait_for_complete:
                    try:
                        handle.result(timeout=10)
                    except Exception as e:
                        self.log.error(f'updateWalletInfo {e}')

    def getWalletsInfo(self, opts=None):
        rv = {}
        for c in Coins:
            if c not in chainparams:
                continue
            if self.coin_clients[c]['connection_type'] == 'rpc':
                key = chainparams[c]['ticker'] if opts.get('ticker_key', False) else c
                try:
                    rv[key] = self.getWalletInfo(c)
                    rv[key].update(self.getBlockchainInfo(c))
                except Exception as ex:
                    rv[key] = {'name': getCoinName(c), 'error': str(ex)}
        return rv

    def getCachedWalletsInfo(self, opts=None):
        rv = {}
        # Requires? self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            where_str = ''
            if opts is not None and 'coin_id' in opts:
                where_str = 'WHERE coin_id = {}'.format(opts['coin_id'])
            inner_str = f'SELECT coin_id, balance_type, MAX(created_at) as max_created_at FROM wallets {where_str} GROUP BY coin_id, balance_type'
            query_str = 'SELECT a.coin_id, a.balance_type, wallet_data, created_at FROM wallets a, ({}) b WHERE a.coin_id = b.coin_id AND a.balance_type = b.balance_type AND a.created_at = b.max_created_at'.format(inner_str)

            q = session.execute(query_str)
            for row in q:
                coin_id = row[0]

                if self.coin_clients[coin_id]['connection_type'] != 'rpc':
                    # Skip cached info if coin was disabled
                    continue

                wallet_data = json.loads(row[2])
                if row[1] == 1:
                    wallet_data['lastupdated'] = row[3]
                    wallet_data['updating'] = self._updating_wallets_info.get(coin_id, False)

                    # Ensure the latest deposit address is displayed
                    q = session.execute('SELECT value FROM kv_string WHERE key = "receive_addr_{}"'.format(chainparams[coin_id]['name']))
                    for row in q:
                        wallet_data['deposit_address'] = row[0]

                if coin_id in rv:
                    rv[coin_id].update(wallet_data)
                else:
                    rv[coin_id] = wallet_data
        finally:
            session.close()
            session.remove()

        if opts is not None and 'coin_id' in opts:
            return rv

        for c in Coins:
            if c not in chainparams:
                continue
            if self.coin_clients[c]['connection_type'] == 'rpc':
                coin_id = int(c)
                if coin_id not in rv:
                    rv[coin_id] = {
                        'name': getCoinName(c),
                        'no_data': True,
                        'updating': self._updating_wallets_info.get(coin_id, False),
                    }

        return rv

    def countAcceptedBids(self, offer_id=None):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            if offer_id:
                q = session.execute('SELECT COUNT(*) FROM bids WHERE state >= {} AND offer_id = x\'{}\''.format(BidStates.BID_ACCEPTED, offer_id.hex())).first()
            else:
                q = session.execute('SELECT COUNT(*) FROM bids WHERE state >= {}'.format(BidStates.BID_ACCEPTED)).first()
            return q[0]
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listOffers(self, sent=False, filters={}, with_bid_info=False):
        self.mxDB.acquire()
        try:
            rv = []
            now = int(time.time())
            session = scoped_session(self.session_factory)

            if with_bid_info:
                subquery = session.query(sa.func.sum(Bid.amount).label('completed_bid_amount')).filter(sa.and_(Bid.offer_id == Offer.offer_id, Bid.state == BidStates.SWAP_COMPLETED)).correlate(Offer).scalar_subquery()
                q = session.query(Offer, subquery)
            else:
                q = session.query(Offer)

            if sent:
                q = q.filter(Offer.was_sent == True)  # noqa: E712
            else:
                q = q.filter(sa.and_(Offer.expire_at > now, Offer.active_ind == 1))

            filter_offer_id = filters.get('offer_id', None)
            if filter_offer_id is not None:
                q = q.filter(Offer.offer_id == filter_offer_id)
            filter_coin_from = filters.get('coin_from', None)
            if filter_coin_from and filter_coin_from > -1:
                q = q.filter(Offer.coin_from == int(filter_coin_from))
            filter_coin_to = filters.get('coin_to', None)
            if filter_coin_to and filter_coin_to > -1:
                q = q.filter(Offer.coin_to == int(filter_coin_to))

            order_dir = filters.get('sort_dir', 'desc')
            order_by = filters.get('sort_by', 'created_at')

            if order_by == 'created_at':
                q = q.order_by(Offer.created_at.desc() if order_dir == 'desc' else Offer.created_at.asc())
            elif order_by == 'rate':
                q = q.order_by(Offer.rate.desc() if order_dir == 'desc' else Offer.rate.asc())

            limit = filters.get('limit', None)
            if limit is not None:
                q = q.limit(limit)
            offset = filters.get('offset', None)
            if offset is not None:
                q = q.offset(offset)
            for row in q:
                offer = row[0] if with_bid_info else row
                # Show offers for enabled coins only
                try:
                    ci_from = self.ci(offer.coin_from)
                    ci_to = self.ci(offer.coin_to)
                except Exception as e:
                    continue
                if with_bid_info:
                    rv.append((offer, 0 if row[1] is None else row[1]))
                else:
                    rv.append(offer)
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listBids(self, sent=False, offer_id=None, for_html=False, filters={}, with_identity_info=False):
        self.mxDB.acquire()
        try:
            rv = []
            now = int(time.time())
            session = scoped_session(self.session_factory)

            identity_fields = ''
            query_str = 'SELECT bids.created_at, bids.expire_at, bids.bid_id, bids.offer_id, bids.amount, bids.state, bids.was_received, tx1.state, tx2.state, offers.coin_from, bids.rate, bids.bid_addr {} FROM bids '.format(identity_fields) + \
                        'LEFT JOIN offers ON offers.offer_id = bids.offer_id ' + \
                        'LEFT JOIN transactions AS tx1 ON tx1.bid_id = bids.bid_id AND tx1.tx_type = {} '.format(TxTypes.ITX) + \
                        'LEFT JOIN transactions AS tx2 ON tx2.bid_id = bids.bid_id AND tx2.tx_type = {} '.format(TxTypes.PTX)

            query_str += 'WHERE bids.active_ind = 1 '
            filter_bid_id = filters.get('bid_id', None)
            if filter_bid_id is not None:
                query_str += 'AND bids.bid_id = x\'{}\' '.format(filter_bid_id.hex())
            if offer_id is not None:
                query_str += 'AND bids.offer_id = x\'{}\' '.format(offer_id.hex())
            elif sent:
                query_str += 'AND bids.was_sent = 1 '
            else:
                query_str += 'AND bids.was_received = 1 '

            bid_state_ind = filters.get('bid_state_ind', -1)
            if bid_state_ind != -1:
                query_str += 'AND bids.state = {} '.format(bid_state_ind)
            with_expired = filters.get('with_expired', True)
            if with_expired is not True:
                query_str += 'AND bids.expire_at > {} '.format(now)

            sort_dir = filters.get('sort_dir', 'DESC').upper()
            sort_by = filters.get('sort_by', 'created_at')
            query_str += f' ORDER BY bids.{sort_by} {sort_dir}'

            limit = filters.get('limit', None)
            if limit is not None:
                query_str += f' LIMIT {limit}'
            offset = filters.get('offset', None)
            if offset is not None:
                query_str += f' OFFSET {offset}'

            q = session.execute(query_str)
            for row in q:
                rv.append(row)
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listSwapsInProgress(self, for_html=False):
        self.mxDB.acquire()
        try:
            rv = []
            for k, v in self.swaps_in_progress.items():
                rv.append((k, v[0].offer_id.hex(), v[0].state, v[0].getITxState(), v[0].getPTxState()))
            return rv
        finally:
            self.mxDB.release()

    def listWatchedOutputs(self):
        self.mxDB.acquire()
        try:
            rv = []
            rv_heights = []
            for c, v in self.coin_clients.items():
                if c in (Coins.PART_ANON, Coins.PART_BLIND):  # exclude duplicates
                    continue
                if self.coin_clients[c]['connection_type'] == 'rpc':
                    rv_heights.append((c, v['last_height_checked']))
                for o in v['watched_outputs']:
                    rv.append((c, o.bid_id, o.txid_hex, o.vout, o.tx_type))
            return (rv, rv_heights)
        finally:
            self.mxDB.release()

    def listAllSMSGAddresses(self, addr_id=None):
        filters = ''
        if addr_id is not None:
            filters += f' WHERE addr_id = {addr_id} '
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            rv = []
            query_str = f'SELECT addr_id, addr, use_type, active_ind, created_at, note, pubkey FROM smsgaddresses {filters} ORDER BY created_at'

            q = session.execute(query_str)
            for row in q:
                rv.append({
                    'id': row[0],
                    'addr': row[1],
                    'type': row[2],
                    'active_ind': row[3],
                    'created_at': row[4],
                    'note': row[5],
                    'pubkey': row[6],
                })
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listAutomationStrategies(self, filters={}):
        self.mxDB.acquire()
        try:
            rv = []
            session = scoped_session(self.session_factory)

            query_str = 'SELECT strats.record_id, strats.label, strats.type_ind FROM automationstrategies AS strats'
            query_str += ' WHERE strats.active_ind = 1 '

            type_ind = filters.get('type_ind', None)
            if type_ind is not None:
                query_str += f' AND strats.type_ind = {type_ind} '

            sort_dir = filters.get('sort_dir', 'DESC').upper()
            sort_by = filters.get('sort_by', 'created_at')
            query_str += f' ORDER BY strats.{sort_by} {sort_dir}'

            limit = filters.get('limit', None)
            if limit is not None:
                query_str += f' LIMIT {limit}'
            offset = filters.get('offset', None)
            if offset is not None:
                query_str += f' OFFSET {offset}'

            q = session.execute(query_str)
            for row in q:
                rv.append(row)
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getAutomationStrategy(self, strategy_id):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            return session.query(AutomationStrategy).filter_by(record_id=strategy_id).first()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getLinkedStrategy(self, linked_type, linked_id):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            query_str = 'SELECT links.strategy_id, strats.label FROM automationlinks links' + \
                        ' LEFT JOIN automationstrategies strats ON strats.record_id = links.strategy_id' + \
                        ' WHERE links.linked_type = {} AND links.linked_id = x\'{}\' AND links.active_ind = 1'.format(int(linked_type), linked_id.hex())
            q = session.execute(query_str).first()
            return q
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def newSMSGAddress(self, use_type=AddressTypes.RECV_OFFER, addressnote=None, session=None):
        now = int(time.time())
        try:
            use_session = self.openSession(session)

            v = use_session.query(DBKVString).filter_by(key='smsg_chain_id').first()
            if not v:
                smsg_account = self.callrpc('extkey', ['deriveAccount', 'smsg keys', '78900'])
                smsg_account_id = smsg_account['account']
                self.log.info(f'Creating smsg keys account {smsg_account_id}')
                extkey = self.callrpc('extkey')

                # Disable receiving on all chains
                smsg_chain_id = None
                extkey = self.callrpc('extkey', ['account', smsg_account_id])
                for c in extkey['chains']:
                    rv = self.callrpc('extkey', ['options', c['id'], 'receive_on', 'false'])
                    if c['function'] == 'active_external':
                        smsg_chain_id = c['id']

                if not smsg_chain_id:
                    raise ValueError('External chain not found.')

                use_session.add(DBKVString(
                    key='smsg_chain_id',
                    value=smsg_chain_id))
            else:
                smsg_chain_id = v.value

            smsg_chain = self.callrpc('extkey', ['key', smsg_chain_id])
            num_derives = int(smsg_chain['num_derives'])

            new_addr = self.callrpc('deriverangekeys', [num_derives, num_derives, smsg_chain_id, False, True])[0]
            num_derives += 1
            rv = self.callrpc('extkey', ['options', smsg_chain_id, 'num_derives', str(num_derives)])

            addr_info = self.callrpc('getaddressinfo', [new_addr])
            self.callrpc('smsgaddlocaladdress', [new_addr])  # Enable receiving smsgs

            use_session.add(SmsgAddress(addr=new_addr, use_type=use_type, active_ind=1, created_at=now, note=addressnote, pubkey=addr_info['pubkey']))
            return new_addr, addr_info['pubkey']
        finally:
            if session is None:
                self.closeSession(use_session)

    def addSMSGAddress(self, pubkey_hex, addressnote=None):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            now = int(time.time())
            ci = self.ci(Coins.PART)
            add_addr = ci.pubkey_to_address(bytes.fromhex(pubkey_hex))
            self.callrpc('smsgaddaddress', [add_addr, pubkey_hex])

            session.add(SmsgAddress(addr=add_addr, use_type=AddressTypes.SEND_OFFER, active_ind=1, created_at=now, note=addressnote, pubkey=pubkey_hex))
            session.commit()
            return add_addr
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def editSMSGAddress(self, address, active_ind, addressnote):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            mode = '-' if active_ind == 0 else '+'
            self.callrpc('smsglocalkeys', ['recv', mode, address])

            session.execute('UPDATE smsgaddresses SET active_ind = {}, note = "{}" WHERE addr = "{}"'.format(active_ind, addressnote, address))
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listSmsgAddresses(self, use_type_str):
        if use_type_str == 'offer_send_from':
            use_type = AddressTypes.OFFER
        elif use_type_str == 'offer_send_to':
            use_type = AddressTypes.SEND_OFFER
        elif use_type_str == 'bid':
            use_type = AddressTypes.BID
        else:
            raise ValueError('Unknown address type')

        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            rv = []
            q = session.execute('SELECT sa.addr, ki.label FROM smsgaddresses AS sa LEFT JOIN knownidentities AS ki ON sa.addr = ki.address WHERE sa.use_type = {} AND sa.active_ind = 1 ORDER BY sa.addr_id DESC'.format(use_type))
            for row in q:
                rv.append((row[0], row[1]))
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def createCoinALockRefundSwipeTx(self, ci, bid, offer, xmr_swap, xmr_offer):
        self.log.debug('Creating %s lock refund swipe tx', ci.coin_name())

        pkh_dest = ci.decodeAddress(self.getReceiveAddressForCoin(ci.coin_type()))
        spend_tx = ci.createSCLockRefundSpendToFTx(
            xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script,
            pkh_dest,
            xmr_offer.a_fee_rate, xmr_swap.vkbv)

        vkaf = self.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF)
        prevout_amount = ci.getLockRefundTxSwapOutputValue(bid, xmr_swap)
        sig = ci.signTx(vkaf, spend_tx, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount)

        witness_stack = [
            sig,
            b'',
            xmr_swap.a_lock_refund_tx_script,
        ]

        xmr_swap.a_lock_refund_swipe_tx = ci.setTxSignature(spend_tx, witness_stack)

    def setBidDebugInd(self, bid_id, debug_ind):
        self.log.debug('Bid %s Setting debug flag: %s', bid_id.hex(), debug_ind)
        bid = self.getBid(bid_id)
        bid.debug_ind = debug_ind

        # Update in memory copy.  TODO: Improve
        bid_in_progress = self.swaps_in_progress.get(bid_id, None)
        if bid_in_progress:
            bid_in_progress[0].debug_ind = debug_ind

        self.saveBid(bid_id, bid)

    def storeOfferRevoke(self, offer_id, sig):
        self.log.debug('Storing revoke request for offer: %s', offer_id.hex())
        for pair in self._possibly_revoked_offers:
            if offer_id == pair[0]:
                return False
        self._possibly_revoked_offers.appendleft((offer_id, sig))
        return True

    def isOfferRevoked(self, offer_id, offer_addr_from):
        for pair in self._possibly_revoked_offers:
            if offer_id == pair[0]:
                signature_enc = base64.b64encode(pair[1]).decode('utf-8')
                passed = self.callcoinrpc(Coins.PART, 'verifymessage', [offer_addr_from, signature_enc, offer_id.hex() + '_revoke'])
                return True if passed is True else False  # _possibly_revoked_offers should not contain duplicates
        return False

    def updateBidInProgress(self, bid):
        swap_in_progress = self.swaps_in_progress.get(bid.bid_id, None)
        if swap_in_progress is None:
            return
        self.swaps_in_progress[bid.bid_id] = (bid, swap_in_progress[1])

    def getAddressLabel(self, addresses):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            rv = []
            for a in addresses:
                v = session.query(KnownIdentity).filter_by(address=a).first()
                rv.append('' if (not v or not v.label) else v.label)
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def add_connection(self, host, port, peer_pubkey):
        self.log.info('add_connection %s %d %s', host, port, peer_pubkey.hex())
        self._network.add_connection(host, port, peer_pubkey)

    def get_network_info(self):
        if not self._network:
            return {'Error': 'Not Initialised'}
        return self._network.get_info()

    def lookupRates(self, coin_from, coin_to, output_array=False):
        self.log.debug('lookupRates {}, {}'.format(coin_from, coin_to))

        rate_sources = self.settings.get('rate_sources', {})
        ci_from = self.ci(int(coin_from))
        ci_to = self.ci(int(coin_to))
        name_from = ci_from.chainparams()['name']
        name_to = ci_to.chainparams()['name']
        ticker_from = ci_from.chainparams()['ticker']
        ticker_to = ci_to.chainparams()['ticker']
        headers = {'Connection': 'close'}
        try:
            self.setConnectionParameters()
            rv = {}

            if rate_sources.get('coingecko.com', True):
                try:
                    url = 'https://api.coingecko.com/api/v3/simple/price?ids={},{}&vs_currencies=usd,btc'.format(name_from, name_to)
                    self.log.debug(f'lookupRates: {url}')
                    start = time.time()
                    req = urllib.request.Request(url, headers=headers)
                    js = json.loads(urllib.request.urlopen(req, timeout=10).read())
                    js['time_taken'] = time.time() - start
                    rate = float(js[name_from]['usd']) / float(js[name_to]['usd'])
                    js['rate_inferred'] = ci_to.format_amount(rate, conv_int=True, r=1)
                    rv['coingecko'] = js
                except Exception as e:
                    rv['coingecko_error'] = str(e)

            if rate_sources.get('bittrex.com', True):
                bittrex_api_v3 = 'https://api.bittrex.com/v3'
                try:
                    if ci_from.coin_type() == Coins.BTC:
                        pair = f'{ticker_to}-{ticker_from}'
                        url = f'{bittrex_api_v3}/markets/{pair}/ticker'
                        self.log.debug(f'lookupRates: {url}')
                        start = time.time()
                        req = urllib.request.Request(url, headers=headers)
                        js = json.loads(urllib.request.urlopen(req, timeout=10).read())
                        js['time_taken'] = time.time() - start
                        js['pair'] = pair
                        try:
                            rate_inverted = ci_from.make_int(1.0 / float(js['lastTradeRate']), r=1)
                            js['rate_inferred'] = ci_to.format_amount(rate_inverted)
                        except Exception as e:
                            self.log.warning('lookupRates error: %s', str(e))
                            js['rate_inferred'] = 'error'
                        js['from_btc'] = 1.0
                        js['to_btc'] = js['lastTradeRate']
                        rv['bittrex'] = js
                    elif ci_to.coin_type() == Coins.BTC:
                        pair = f'{ticker_from}-{ticker_to}'
                        url = f'{bittrex_api_v3}/markets/{pair}/ticker'
                        self.log.debug(f'lookupRates: {url}')
                        start = time.time()
                        req = urllib.request.Request(url, headers=headers)
                        js = json.loads(urllib.request.urlopen(req, timeout=10).read())
                        js['time_taken'] = time.time() - start
                        js['pair'] = pair
                        js['rate_last'] = js['lastTradeRate']
                        js['from_btc'] = js['lastTradeRate']
                        js['to_btc'] = 1.0
                        rv['bittrex'] = js
                    else:
                        pair = f'{ticker_from}-BTC'
                        url = f'{bittrex_api_v3}/markets/{pair}/ticker'
                        self.log.debug(f'lookupRates: {url}')
                        start = time.time()
                        req = urllib.request.Request(url, headers=headers)
                        js_from = json.loads(urllib.request.urlopen(req, timeout=10).read())
                        js_from['time_taken'] = time.time() - start
                        js_from['pair'] = pair

                        pair = f'{ticker_to}-BTC'
                        url = f'{bittrex_api_v3}/markets/{pair}/ticker'
                        self.log.debug(f'lookupRates: {url}')
                        start = time.time()
                        req = urllib.request.Request(url, headers=headers)
                        js_to = json.loads(urllib.request.urlopen(req, timeout=10).read())
                        js_to['time_taken'] = time.time() - start
                        js_to['pair'] = pair

                        try:
                            rate_inferred = float(js_from['lastTradeRate']) / float(js_to['lastTradeRate'])
                            rate_inferred = ci_to.format_amount(rate, conv_int=True, r=1)
                        except Exception as e:
                            rate_inferred = 'error'

                        rv['bittrex'] = {
                            'from': js_from,
                            'to': js_to,
                            'rate_inferred': rate_inferred,
                            'from_btc': js_from['lastTradeRate'],
                            'to_btc': js_to['lastTradeRate']
                        }
                except Exception as e:
                    rv['bittrex_error'] = str(e)

            if output_array:

                def format_float(f):
                    return '{:.12f}'.format(f).rstrip('0').rstrip('.')

                rv_array = []
                if 'coingecko_error' in rv:
                    rv_array.append(('coingecko.com', 'error', rv['coingecko_error']))
                if 'coingecko' in rv:
                    js = rv['coingecko']
                    rv_array.append((
                        'coingecko.com',
                        ticker_from,
                        ticker_to,
                        format_float(float(js[name_from]['usd'])),
                        format_float(float(js[name_to]['usd'])),
                        format_float(float(js[name_from]['btc'])),
                        format_float(float(js[name_to]['btc'])),
                        format_float(float(js['rate_inferred'])),
                    ))
                if 'bittrex_error' in rv:
                    rv_array.append(('bittrex.com', 'error', rv['bittrex_error']))
                if 'bittrex' in rv:
                    js = rv['bittrex']
                    rate = js['rate_last'] if 'rate_last' in js else js['rate_inferred']
                    rv_array.append((
                        'bittrex.com',
                        ticker_from,
                        ticker_to,
                        '',
                        '',
                        format_float(float(js['from_btc'])),
                        format_float(float(js['to_btc'])),
                        format_float(float(rate))
                    ))
                return rv_array

            return rv
        finally:
            self.popConnectionParameters()
