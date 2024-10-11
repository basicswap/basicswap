# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import zmq
import copy
import json
import time
import base64
import random
import shutil
import string
import struct
import secrets
import datetime as dt
import threading
import traceback
import sqlalchemy as sa
import collections
import concurrent.futures

from typing import Optional

from sqlalchemy.sql import text
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.orm.session import close_all_sessions

from .interface.base import Curves
from .interface.part import PARTInterface, PARTInterfaceAnon, PARTInterfaceBlind

from . import __version__
from .rpc import escape_rpcauth
from .rpc_xmr import make_xmr_rpc2_func
from .ui.util import getCoinName, known_chart_coins
from .util import (
    AutomationConstraint,
    LockedCoinError,
    TemporaryError,
    InactiveCoin,
    format_timestamp,
    DeserialiseNum,
    zeroIfNone,
    make_int,
    ensure,
)
from .util.script import (
    getP2SHScriptForHash,
)
from .util.address import (
    toWIF,
    decodeWif,
    decodeAddress,
    pubkeyToAddress,
)
from .util.crypto import (
    sha256,
)
from basicswap.util.network import is_private_ip_address
from .chainparams import (
    Coins,
    chainparams,
)
from .script import (
    OpCodes,
)
from .messages_npb import (
    ADSBidIntentAcceptMessage,
    ADSBidIntentMessage,
    BidAcceptMessage,
    BidMessage,
    OfferMessage,
    OfferRevokeMessage,
    XmrBidAcceptMessage,
    XmrBidLockReleaseMessage,
    XmrBidLockSpendTxMessage,
    XmrBidLockTxSigsMessage,
    XmrBidMessage,
    XmrSplitMessage,
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
    PrefundedTx,
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
    MessageLink,
    pack_state,
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
import basicswap.protocols.xmr_swap_1 as xmr_swap_1
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
    getVoutByScriptPubKey,
    getOfferProofOfFundsHash,
    getLastBidState,
    isActiveBidState,
    NotificationTypes as NT,
    AutomationOverrideOptions,
    VisibilityOverrideOptions,
    inactive_states,
)
from basicswap.db_util import (
    remove_expired_data,
)

PROTOCOL_VERSION_SECRET_HASH = 5
MINPROTO_VERSION_SECRET_HASH = 4

PROTOCOL_VERSION_ADAPTOR_SIG = 4
MINPROTO_VERSION_ADAPTOR_SIG = 4

MINPROTO_VERSION = min(MINPROTO_VERSION_SECRET_HASH, MINPROTO_VERSION_ADAPTOR_SIG)
MAXPROTO_VERSION = 10


def validOfferStateToReceiveBid(offer_state):
    if offer_state == OfferStates.OFFER_RECEIVED:
        return True
    if offer_state == OfferStates.OFFER_SENT:
        return True
    return False


def threadPollXMRChainState(swap_client, coin_type):
    ci = swap_client.ci(coin_type)
    cc = swap_client.coin_clients[coin_type]
    while not swap_client.chainstate_delay_event.is_set():
        try:
            new_height = ci.getChainHeight()
            if new_height != cc['chain_height']:
                swap_client.log.debug('New {} block at height: {}'.format(ci.ticker(), new_height))
                with swap_client.mxDB:
                    cc['chain_height'] = new_height
        except Exception as e:
            swap_client.log.warning('threadPollXMRChainState {}, error: {}'.format(ci.ticker(), str(e)))
        swap_client.chainstate_delay_event.wait(random.randrange(20, 30))  # Random to stagger updates


def threadPollWOWChainState(swap_client, coin_type):
    ci = swap_client.ci(coin_type)
    cc = swap_client.coin_clients[coin_type]
    while not swap_client.chainstate_delay_event.is_set():
        try:
            new_height = ci.getChainHeight()
            if new_height != cc['chain_height']:
                swap_client.log.debug('New {} block at height: {}'.format(ci.ticker(), new_height))
                with swap_client.mxDB:
                    cc['chain_height'] = new_height
        except Exception as e:
            swap_client.log.warning('threadPollWOWChainState {}, error: {}'.format(ci.ticker(), str(e)))
        swap_client.chainstate_delay_event.wait(random.randrange(20, 30))  # Random to stagger updates


def threadPollChainState(swap_client, coin_type):
    ci = swap_client.ci(coin_type)
    cc = swap_client.coin_clients[coin_type]
    while not swap_client.chainstate_delay_event.is_set():
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
        swap_client.chainstate_delay_event.wait(random.randrange(20, 30))  # Random to stagger updates


class WatchedOutput():  # Watch for spends
    __slots__ = ('bid_id', 'txid_hex', 'vout', 'tx_type', 'swap_type')

    def __init__(self, bid_id: bytes, txid_hex: str, vout, tx_type, swap_type):
        self.bid_id = bid_id
        self.txid_hex = txid_hex
        self.vout = vout
        self.tx_type = tx_type
        self.swap_type = swap_type


class WatchedScript():  # Watch for txns containing outputs
    __slots__ = ('bid_id', 'script', 'tx_type', 'swap_type')

    def __init__(self, bid_id: bytes, script: bytes, tx_type, swap_type):
        self.bid_id = bid_id
        self.script = script
        self.tx_type = tx_type
        self.swap_type = swap_type


class WatchedTransaction():
    # TODO
    # Watch for presence in mempool (getrawtransaction)
    def __init__(self, bid_id: bytes, txid_hex: str, tx_type, swap_type):
        self.bid_id = bid_id
        self.txid_hex = txid_hex
        self.tx_type = tx_type
        self.swap_type = swap_type


class BasicSwap(BaseApp):
    ws_server = None
    _read_zmq_queue: bool = True
    protocolInterfaces = {
        SwapTypes.SELLER_FIRST: atomic_swap_1.AtomicSwapInterface(),
        SwapTypes.XMR_SWAP: xmr_swap_1.XmrSwapInterface(),
    }

    def __init__(self, fp, data_dir, settings, chain, log_name='BasicSwap', transient_instance=False):
        super().__init__(fp, data_dir, settings, chain, log_name)

        v = __version__.split('.')
        self._version = struct.pack('>HHH', int(v[0]), int(v[1]), int(v[2]))

        self._transient_instance = transient_instance
        self.check_actions_seconds = self.get_int_setting('check_actions_seconds', 10, 1, 10 * 60)
        self.check_expired_seconds = self.get_int_setting('check_expired_seconds', 5 * 60, 1, 10 * 60)  # Expire DB records and smsg messages
        self.check_expiring_bids_offers_seconds = self.get_int_setting('check_expiring_bids_offers_seconds', 60, 1, 10 * 60)  # Set offer and bid states to expired
        self.check_progress_seconds = self.get_int_setting('check_progress_seconds', 60, 1, 10 * 60)
        self.check_smsg_seconds = self.get_int_setting('check_smsg_seconds', 10, 1, 10 * 60)
        self.check_watched_seconds = self.get_int_setting('check_watched_seconds', 60, 1, 10 * 60)
        self.check_xmr_swaps_seconds = self.get_int_setting('check_xmr_swaps_seconds', 20, 1, 10 * 60)
        self.startup_tries = self.get_int_setting('startup_tries', 21, 1, 100)  # Seconds waited for will be (x(1 + x+1) / 2
        self.debug_ui = self.settings.get('debug_ui', False)
        self._debug_cases = []
        self._last_checked_actions = 0
        self._last_checked_expired = 0
        self._last_checked_expiring_bids_offers = 0
        self._last_checked_progress = 0
        self._last_checked_smsg = 0
        self._last_checked_watched = 0
        self._last_checked_xmr_swaps = 0
        self._possibly_revoked_offers = collections.deque([], maxlen=48)  # TODO: improve
        self._expiring_bids = []  # List of bids expiring soon
        self._expiring_offers = []  # List of offers expiring soon
        self._updating_wallets_info = {}
        self._last_updated_wallets_info = 0
        self._zmq_queue_enabled = self.settings.get('zmq_queue_enabled', True)
        self._poll_smsg = self.settings.get('poll_smsg', False)

        self._notifications_enabled = self.settings.get('notifications_enabled', True)
        self._disabled_notification_types = self.settings.get('disabled_notification_types', [])
        self._keep_notifications = self.settings.get('keep_notifications', 50)
        self._show_notifications = self.settings.get('show_notifications', 10)
        self._expire_db_records = self.settings.get('expire_db_records', False)
        self._expire_db_records_after = self.get_int_setting('expire_db_records_after', 7 * 86400, 0, 31 * 86400)  # Seconds
        self._notifications_cache = {}
        self._is_encrypted = None
        self._is_locked = None

        # TODO: Set dynamically
        self.balance_only_coins = (Coins.LTC_MWEB, )
        self.scriptless_coins = (Coins.XMR, Coins.WOW, Coins.PART_ANON, Coins.FIRO)
        self.adaptor_swap_only_coins = self.scriptless_coins + (Coins.PART_BLIND, )
        self.coins_without_segwit = (Coins.PIVX, Coins.DASH, Coins.NMC)

        # TODO: Adjust ranges
        self.min_delay_event = self.get_int_setting('min_delay_event', 10, 0, 20 * 60)
        self.max_delay_event = self.get_int_setting('max_delay_event', 60, self.min_delay_event, 20 * 60)
        self.min_delay_event_short = self.get_int_setting('min_delay_event_short', 2, 0, 10 * 60)
        self.max_delay_event_short = self.get_int_setting('max_delay_event_short', 30, self.min_delay_event_short, 10 * 60)

        self.min_delay_retry = self.get_int_setting('min_delay_retry', 60, 0, 20 * 60)
        self.max_delay_retry = self.get_int_setting('max_delay_retry', 5 * 60, self.min_delay_retry, 20 * 60)

        self.min_sequence_lock_seconds = self.settings.get('min_sequence_lock_seconds', 60 if self.debug else (1 * 60 * 60))
        self.max_sequence_lock_seconds = self.settings.get('max_sequence_lock_seconds', 96 * 60 * 60)

        self._wallet_update_timeout = self.settings.get('wallet_update_timeout', 10)

        self._restrict_unknown_seed_wallets = self.settings.get('restrict_unknown_seed_wallets', True)
        self._max_check_loop_blocks = self.settings.get('max_check_loop_blocks', 100000)

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

        self.db_echo: bool = self.settings.get('db_echo', False)
        self.sqlite_file: str = os.path.join(self.data_dir, 'db{}.sqlite'.format('' if self.chain == 'mainnet' else ('_' + self.chain)))
        db_exists: bool = os.path.exists(self.sqlite_file)

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

        if self._zmq_queue_enabled:
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
            self.delay_event.set()
            self.chainstate_delay_event.set()

        if self._network:
            self._network.stopNetwork()
            self._network = None

        for t in self.threads:
            t.join()

        if sys.version_info[1] >= 9:
            self.thread_pool.shutdown(cancel_futures=True)
        else:
            self.thread_pool.shutdown()

        if self._zmq_queue_enabled:
            self.zmqContext.destroy()

        self.swaps_in_progress.clear()
        close_all_sessions()
        self.engine.dispose()

    def openSession(self, session=None):
        if session:
            return session

        self.mxDB.acquire()
        return scoped_session(self.session_factory)

    def closeSession(self, session, commit=True):
        if commit:
            session.commit()

        session.close()
        session.remove()
        self.mxDB.release()

    def handleSessionErrors(self, e, session, tag):
        if self.debug:
            self.log.error(traceback.format_exc())

        self.log.error(f'Error: {tag} - {e}')
        session.rollback()

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
                self.log.debug(f'Read {Coins(coin).name} rpc credentials from json settings')
            elif 'rpcpassword' in chain_client_settings:
                rpcauth = chain_client_settings['rpcuser'] + ':' + chain_client_settings['rpcpassword']
                self.log.debug(f'Read {Coins(coin).name} rpc credentials from json settings')

        try:
            session = self.openSession()
            try:
                last_height_checked = session.query(DBKVInt).filter_by(key='last_height_checked_' + chainparams[coin]['name']).first().value
            except Exception:
                last_height_checked = 0
            try:
                block_check_min_time = session.query(DBKVInt).filter_by(key='block_check_min_time_' + chainparams[coin]['name']).first().value
            except Exception:
                block_check_min_time = 0xffffffffffffffff
        finally:
            self.closeSession(session)

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
            'watched_scripts': [],
            'last_height_checked': last_height_checked,
            'block_check_min_time': block_check_min_time,
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

        if coin in (Coins.FIRO, Coins.LTC):
            if not chain_client_settings.get('min_relay_fee'):
                chain_client_settings['min_relay_fee'] = 0.00001

        if coin == Coins.PART:
            self.coin_clients[coin]['anon_tx_ring_size'] = chain_client_settings.get('anon_tx_ring_size', 12)
            self.coin_clients[Coins.PART_ANON] = self.coin_clients[coin]
            self.coin_clients[Coins.PART_BLIND] = self.coin_clients[coin]

        if coin == Coins.LTC:
            self.coin_clients[Coins.LTC_MWEB] = self.coin_clients[coin]

        if self.coin_clients[coin]['connection_type'] == 'rpc':
            if coin == Coins.DCR:
                self.coin_clients[coin]['walletrpcport'] = chain_client_settings['walletrpcport']
            elif coin in (Coins.XMR, Coins.WOW):
                self.coin_clients[coin]['rpctimeout'] = chain_client_settings.get('rpctimeout', 60)
                self.coin_clients[coin]['walletrpctimeout'] = chain_client_settings.get('walletrpctimeout', 120)
                self.coin_clients[coin]['walletrpctimeoutlong'] = chain_client_settings.get('walletrpctimeoutlong', 600)

                if not self._transient_instance and chain_client_settings.get('automatically_select_daemon', False):
                    self.selectXMRRemoteDaemon(coin)

                self.coin_clients[coin]['walletrpchost'] = chain_client_settings.get('walletrpchost', '127.0.0.1')
                self.coin_clients[coin]['walletrpcport'] = chain_client_settings.get('walletrpcport', chainparams[coin][self.chain]['walletrpcport'])
                if 'walletrpcpassword' in chain_client_settings:
                    self.coin_clients[coin]['walletrpcauth'] = (chain_client_settings['walletrpcuser'], chain_client_settings['walletrpcpassword'])
                else:
                    raise ValueError('Missing XMR wallet rpc credentials.')

                self.coin_clients[coin]['rpcuser'] = chain_client_settings.get('rpcuser', '')
                self.coin_clients[coin]['rpcpassword'] = chain_client_settings.get('rpcpassword', '')

    def getXMRTrustedDaemon(self, coin, node_host: str) -> bool:
        coin = Coins(coin)  # Errors for invalid coin value
        chain_client_settings = self.getChainClientSettings(coin)
        trusted_daemon_setting = chain_client_settings.get('trusted_daemon', 'auto')
        self.log.debug(f'\'trusted_daemon\' setting for {getCoinName(coin)}: {trusted_daemon_setting}.')
        if isinstance(trusted_daemon_setting, bool):
            return trusted_daemon_setting
        if trusted_daemon_setting == 'auto':
            return is_private_ip_address(node_host)
        self.log.warning(f'Unknown \'trusted_daemon\' setting for {getCoinName(coin)}: {trusted_daemon_setting}.')
        return False

    def getXMRWalletProxy(self, coin, node_host: str) -> (Optional[str], Optional[int]):
        coin = Coins(coin)  # Errors for invalid coin value
        chain_client_settings = self.getChainClientSettings(coin)
        proxy_host = None
        proxy_port = None
        if self.use_tor_proxy:
            have_cc_tor_opt = 'use_tor' in chain_client_settings
            if have_cc_tor_opt and chain_client_settings['use_tor'] is False:
                self.log.warning(f'use_tor is true for system but false for {coin.name}.')
            elif have_cc_tor_opt is False and is_private_ip_address(node_host):
                self.log.warning(f'Not using proxy for {coin.name} node at private ip address {node_host}.')
            else:
                proxy_host = self.tor_proxy_host
                proxy_port = self.tor_proxy_port
        return proxy_host, proxy_port

    def selectXMRRemoteDaemon(self, coin):
        self.log.info('Selecting remote XMR daemon.')
        chain_client_settings = self.getChainClientSettings(coin)
        remote_daemon_urls = chain_client_settings.get('remote_daemon_urls', [])

        coin_settings = self.coin_clients[coin]
        rpchost: str = coin_settings['rpchost']
        rpcport: int = coin_settings['rpcport']
        timeout: int = coin_settings['rpctimeout']

        def get_rpc_func(rpcport, daemon_login, rpchost):

            proxy_host, proxy_port = self.getXMRWalletProxy(coin, rpchost)
            if proxy_host:
                self.log.info(f'Connecting through proxy at {proxy_host}.')

            if coin in (Coins.XMR, Coins.WOW):
                return make_xmr_rpc2_func(rpcport, daemon_login, rpchost, proxy_host=proxy_host, proxy_port=proxy_port)

        daemon_login = None
        if coin_settings.get('rpcuser', '') != '':
            daemon_login = (coin_settings.get('rpcuser', ''), coin_settings.get('rpcpassword', ''))
        current_daemon_url = f'{rpchost}:{rpcport}'
        if current_daemon_url in remote_daemon_urls:
            self.log.info(f'Trying last used url {rpchost}:{rpcport}.')
            try:
                rpc2 = get_rpc_func(rpcport, daemon_login, rpchost)
                test = rpc2('get_height', timeout=timeout)['height']
                return True
            except Exception as e:
                self.log.warning(f'Failed to set XMR remote daemon to {rpchost}:{rpcport}, {e}')
        random.shuffle(remote_daemon_urls)
        for url in remote_daemon_urls:
            self.log.info(f'Trying url {url}.')
            try:
                rpchost, rpcport = url.rsplit(':', 1)
                rpc2 = get_rpc_func(rpcport, daemon_login, rpchost)
                test = rpc2('get_height', timeout=timeout)['height']
                coin_settings['rpchost'] = rpchost
                coin_settings['rpcport'] = rpcport
                data = {
                    'rpchost': rpchost,
                    'rpcport': rpcport,
                }
                self.editSettings(self.coin_clients[coin]['name'], data)
                return True
            except Exception as e:
                self.log.warning(f'Failed to set XMR remote daemon to {url}, {e}')

        raise ValueError('Failed to select a working XMR daemon url.')

    def isCoinActive(self, coin):
        use_coinid = coin
        interface_ind = 'interface'
        if coin == Coins.PART_ANON:
            use_coinid = Coins.PART
            interface_ind = 'interface_anon'
        if coin == Coins.PART_BLIND:
            use_coinid = Coins.PART
            interface_ind = 'interface_blind'
        if coin == Coins.LTC_MWEB:
            use_coinid = Coins.LTC
            interface_ind = 'interface_mweb'

        if use_coinid not in self.coin_clients:
            raise ValueError('Unknown coinid {}'.format(int(coin)))
        return interface_ind in self.coin_clients[use_coinid]

    def ci(self, coin):  # Coin interface
        use_coinid = coin
        interface_ind = 'interface'
        if coin == Coins.PART_ANON:
            use_coinid = Coins.PART
            interface_ind = 'interface_anon'
        if coin == Coins.PART_BLIND:
            use_coinid = Coins.PART
            interface_ind = 'interface_blind'
        if coin == Coins.LTC_MWEB:
            use_coinid = Coins.LTC
            interface_ind = 'interface_mweb'

        if use_coinid not in self.coin_clients:
            raise ValueError('Unknown coinid {}'.format(int(coin)))
        if interface_ind not in self.coin_clients[use_coinid]:
            raise InactiveCoin(int(coin))

        return self.coin_clients[use_coinid][interface_ind]

    def pi(self, protocol_ind):
        if protocol_ind not in self.protocolInterfaces:
            raise ValueError('Unknown protocol_ind {}'.format(int(protocol_ind)))
        return self.protocolInterfaces[protocol_ind]

    def createInterface(self, coin):
        if coin == Coins.PART:
            interface = PARTInterface(self.coin_clients[coin], self.chain, self)
            self.coin_clients[coin]['interface_anon'] = PARTInterfaceAnon(self.coin_clients[coin], self.chain, self)
            self.coin_clients[coin]['interface_blind'] = PARTInterfaceBlind(self.coin_clients[coin], self.chain, self)
            return interface
        elif coin == Coins.BTC:
            from .interface.btc import BTCInterface
            return BTCInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.LTC:
            from .interface.ltc import LTCInterface, LTCInterfaceMWEB
            interface = LTCInterface(self.coin_clients[coin], self.chain, self)
            self.coin_clients[coin]['interface_mweb'] = LTCInterfaceMWEB(self.coin_clients[coin], self.chain, self)
            return interface
        elif coin == Coins.DCR:
            from .interface.dcr import DCRInterface
            return DCRInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.NMC:
            from .interface.nmc import NMCInterface
            return NMCInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.XMR:
            from .interface.xmr import XMRInterface
            xmr_i = XMRInterface(self.coin_clients[coin], self.chain, self)
            chain_client_settings = self.getChainClientSettings(coin)
            xmr_i.setWalletFilename(chain_client_settings['walletfile'])
            return xmr_i
        elif coin == Coins.WOW:
            from .interface.wow import WOWInterface
            wow_i = WOWInterface(self.coin_clients[coin], self.chain, self)
            chain_client_settings = self.getChainClientSettings(coin)
            wow_i.setWalletFilename(chain_client_settings['walletfile'])
            return wow_i
        elif coin == Coins.PIVX:
            from .interface.pivx import PIVXInterface
            return PIVXInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.DASH:
            from .interface.dash import DASHInterface
            return DASHInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.FIRO:
            from .interface.firo import FIROInterface
            return FIROInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.NAV:
            from .interface.nav import NAVInterface
            return NAVInterface(self.coin_clients[coin], self.chain, self)
        else:
            raise ValueError('Unknown coin type')

    def createPassthroughInterface(self, coin):
        if coin == Coins.BTC:
            from .interface.passthrough_btc import PassthroughBTCInterface
            return PassthroughBTCInterface(self.coin_clients[coin], self.chain)
        else:
            raise ValueError('Unknown coin type')

    def setCoinRunParams(self, coin):
        cc = self.coin_clients[coin]
        if coin in (Coins.XMR, Coins.WOW):
            return
        if cc['connection_type'] == 'rpc' and cc['rpcauth'] is None:
            chain_client_settings = self.getChainClientSettings(coin)
            authcookiepath = os.path.join(self.getChainDatadirPath(coin), '.cookie')

            pidfilename = cc['name']
            if cc['name'] in ('bitcoin', 'litecoin', 'namecoin', 'dash', 'firo'):
                pidfilename += 'd'

            pidfilepath = os.path.join(self.getChainDatadirPath(coin), pidfilename + '.pid')
            self.log.debug('Reading %s rpc credentials from auth cookie %s', Coins(coin).name, authcookiepath)
            # Wait for daemon to start
            # Test pids to ensure authcookie is read for the correct process
            datadir_pid = -1
            for i in range(20):
                try:
                    if os.name == 'nt' and cc['core_version_group'] <= 17:
                        # Older core versions don't write a pid file on windows
                        pass
                    else:
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
                    cc['rpcauth'] = escape_rpcauth(fp.read().decode('utf-8'))
            except Exception as e:
                self.log.error('Unable to read authcookie for %s, %s, datadir pid %d, daemon pid %s. Error: %s', Coins(coin).name, authcookiepath, datadir_pid, cc['pid'], str(e))
                raise ValueError('Error, terminating')

    def createCoinInterface(self, coin):
        if self.coin_clients[coin]['connection_type'] == 'rpc':
            self.coin_clients[coin]['interface'] = self.createInterface(coin)
        elif self.coin_clients[coin]['connection_type'] == 'passthrough':
            self.coin_clients[coin]['interface'] = self.createPassthroughInterface(coin)

    def start(self):
        import platform
        self.log.info('Starting BasicSwap %s, database v%d\n\n', __version__, self.db_version)
        self.log.info(f'Python version: {platform.python_version()}')
        self.log.info('SQLAlchemy version: %s', sa.__version__)
        self.log.info('Timezone offset: %d (%s)', time.timezone, time.tzname[0])

        upgradeDatabase(self, self.db_version)
        upgradeDatabaseData(self, self.db_data_version)

        if self._zmq_queue_enabled and self._poll_smsg:
            self.log.warning('SMSG polling and zmq listener enabled.')

        for c in Coins:
            if c not in chainparams:
                continue
            self.setCoinRunParams(c)
            self.createCoinInterface(c)

            if self.coin_clients[c]['connection_type'] == 'rpc':
                ci = self.ci(c)
                self.waitForDaemonRPC(c)

                core_version = ci.getDaemonVersion()
                self.log.info('%s Core version %d', ci.coin_name(), core_version)
                self.coin_clients[c]['core_version'] = core_version
                # thread_func = threadPollXMRChainState if c in (Coins.XMR, Coins.WOW) else threadPollChainState
                if c == Coins.XMR:
                    thread_func = threadPollXMRChainState
                elif c == Coins.WOW:
                    thread_func = threadPollWOWChainState
                else:
                    thread_func = threadPollChainState

                t = threading.Thread(target=thread_func, args=(self, c))
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
                    try:
                        ci.ensureWalletExists()
                    except Exception as e:
                        self.log.warning('Can\'t open XMR wallet, could be locked.')
                        continue
                elif c == Coins.WOW:
                    try:
                        ci.ensureWalletExists()
                    except Exception as e:
                        self.log.warning('Can\'t open WOW wallet, could be locked.')
                        continue
                elif c == Coins.LTC:
                    ci_mweb = self.ci(Coins.LTC_MWEB)
                    is_encrypted, _ = self.getLockedState()
                    if not is_encrypted and not ci_mweb.has_mweb_wallet():
                        ci_mweb.init_wallet()

                self.checkWalletSeed(c)

        if 'p2p_host' in self.settings:
            network_key = self.getNetworkKey(1)
            self._network = bsn.Network(self.settings['p2p_host'], self.settings['p2p_port'], network_key, self)
            self._network.startNetwork()

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

        # Initialise locked state
        _, _ = self.getLockedState()

        # Re-load in-progress bids
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

    def stopDaemon(self, coin) -> None:
        if coin in (Coins.XMR, Coins.DCR, Coins.WOW):
            return
        num_tries = 10
        authcookiepath = os.path.join(self.getChainDatadirPath(coin), '.cookie')
        stopping = False
        try:
            for i in range(num_tries):
                rv = self.callcoincli(coin, 'stop', timeout=10)
                self.log.debug('Trying to stop %s', Coins(coin).name)
                stopping = True
                # self.delay_event will be set here
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
                            self.log.debug('Waiting on .cookie file %s', Coins(coin).name)
                            time.sleep(i + 1)
                    time.sleep(4)  # Extra time to settle
                return
            self.log.error('stopDaemon %s', str(ex))
            self.log.error(traceback.format_exc())
        raise ValueError('Could not stop {}'.format(Coins(coin).name))

    def stopDaemons(self) -> None:
        for c in self.activeCoins():
            chain_client_settings = self.getChainClientSettings(c)
            if chain_client_settings['manage_daemon'] is True:
                self.stopDaemon(c)

    def waitForDaemonRPC(self, coin_type, with_wallet: bool = True) -> None:

        if with_wallet:
            self.waitForDaemonRPC(coin_type, with_wallet=False)
            if coin_type in (Coins.XMR, Coins.WOW):
                return
            ci = self.ci(coin_type)
            # checkWallets can adjust the wallet name.
            if ci.checkWallets() < 1:
                self.log.error('No wallets found for coin {}.'.format(ci.coin_name()))
                self.stopRunning(1)  # systemd will try to restart the process if fail_code != 0

        startup_tries = self.startup_tries
        chain_client_settings = self.getChainClientSettings(coin_type)
        if 'startup_tries' in chain_client_settings:
            startup_tries = chain_client_settings['startup_tries']
        if startup_tries < 1:
            self.log.warning('startup_tries can\'t be less than 1.')
            startup_tries = 1
        for i in range(startup_tries):
            if self.delay_event.is_set():
                return
            try:
                self.coin_clients[coin_type]['interface'].testDaemonRPC(with_wallet)
                return
            except Exception as ex:
                self.log.warning('Can\'t connect to %s RPC: %s.  Trying again in %d second/s, %d/%d.', Coins(coin_type).name, str(ex), (1 + i), i + 1, startup_tries)
                self.delay_event.wait(1 + i)
        self.log.error('Can\'t connect to %s RPC, exiting.', Coins(coin_type).name)
        self.stopRunning(1)  # systemd will try to restart the process if fail_code != 0

    def checkCoinsReady(self, coin_from, coin_to) -> None:
        check_coins = (coin_from, coin_to)
        for c in check_coins:
            ci = self.ci(c)
            if self._restrict_unknown_seed_wallets and not ci.knownWalletSeed():
                raise ValueError('{} has an unexpected wallet seed and "restrict_unknown_seed_wallets" is enabled.'.format(ci.coin_name()))
            if self.coin_clients[c]['connection_type'] != 'rpc':
                continue
            if c in (Coins.XMR, Coins.WOW):
                continue  # TODO
            synced = round(ci.getBlockchainInfo()['verificationprogress'], 3)
            if synced < 1.0:
                raise ValueError('{} chain is still syncing, currently at {}.'.format(ci.coin_name(), synced))

    def isSystemUnlocked(self) -> bool:
        # TODO - Check all active coins
        ci = self.ci(Coins.PART)
        return not ci.isWalletLocked()

    def checkSystemStatus(self) -> None:
        ci = self.ci(Coins.PART)
        if ci.isWalletLocked():
            raise LockedCoinError(Coins.PART)

    def activeCoins(self):
        for c in Coins:
            if c not in chainparams:
                continue
            chain_client_settings = self.getChainClientSettings(c)
            if self.coin_clients[c]['connection_type'] == 'rpc':
                yield c

    def getListOfWalletCoins(self):
        # Always unlock Particl first
        coins_list = [Coins.PART, ] + [c for c in self.activeCoins() if c != Coins.PART]
        if Coins.LTC in coins_list:
            coins_list.append(Coins.LTC_MWEB)
        return coins_list

    def changeWalletPasswords(self, old_password: str, new_password: str, coin=None) -> None:
        # Only the main wallet password is changed for monero, avoid issues by preventing until active swaps are complete
        if len(self.swaps_in_progress) > 0:
            raise ValueError('Can\'t change passwords while swaps are in progress')

        if old_password == new_password:
            raise ValueError('Passwords must differ')

        if len(new_password) < 4:
            raise ValueError('New password is too short')

        coins_list = self.getListOfWalletCoins()

        # Unlock wallets to ensure they all have the same password.
        for c in coins_list:
            if coin and c != coin:
                continue
            ci = self.ci(c)
            try:
                ci.unlockWallet(old_password)
            except Exception as e:
                raise ValueError('Failed to unlock {}'.format(ci.coin_name()))

        for c in coins_list:
            if coin and c != coin:
                continue
            self.ci(c).changeWalletPassword(old_password, new_password)

        # Update cached state
        if coin is None or coin == Coins.PART:
            self._is_encrypted, self._is_locked = self.ci(Coins.PART).isWalletEncryptedLocked()

    def unlockWallets(self, password: str, coin=None) -> None:
        try:
            self._read_zmq_queue = False
            for c in self.getListOfWalletCoins():
                if coin and c != coin:
                    continue
                try:
                    self.ci(c).unlockWallet(password)
                except Exception as e:
                    self.log.warning('Failed to unlock wallet {}'.format(getCoinName(c)))
                    if coin is not None or c == Coins.PART:
                        raise e
                if c == Coins.PART:
                    self._is_locked = False

            self.loadFromDB()
        finally:
            self._read_zmq_queue = True

    def lockWallets(self, coin=None) -> None:
        try:
            self._read_zmq_queue = False
            self.swaps_in_progress.clear()

            for c in self.getListOfWalletCoins():
                if coin and c != coin:
                    continue
                self.ci(c).lockWallet()
                if c == Coins.PART:
                    self._is_locked = True
        finally:
            self._read_zmq_queue = True

    def initialiseWallet(self, coin_type, raise_errors: bool = False) -> None:
        if coin_type == Coins.PART:
            return
        ci = self.ci(coin_type)
        db_key_coin_name = ci.coin_name().lower()
        self.log.info('Initialising {} wallet.'.format(ci.coin_name()))

        if coin_type in (Coins.XMR, Coins.WOW):
            key_view = self.getWalletKey(coin_type, 1, for_ed25519=True)
            key_spend = self.getWalletKey(coin_type, 2, for_ed25519=True)
            ci.initialiseWallet(key_view, key_spend)
            root_address = ci.getAddressFromKeys(key_view, key_spend)

            key_str = 'main_wallet_addr_' + db_key_coin_name
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
            if self.debug:
                self.log.error(traceback.format_exc())
            return

        legacy_root_hash = None
        if coin_type == Coins.DCR:
            legacy_root_hash = ci.getSeedHash(root_key, 20)
        try:
            session = self.openSession()
            key_str = 'main_wallet_seedid_' + db_key_coin_name
            self.setStringKV(key_str, root_hash.hex(), session)

            if coin_type == Coins.DCR:
                # TODO: How to force getmasterpubkey to always return the new slip44 (42) key
                key_str = 'main_wallet_seedid_alt_' + db_key_coin_name
                self.setStringKV(key_str, legacy_root_hash.hex(), session)

            # Clear any saved addresses
            self.clearStringKV('receive_addr_' + db_key_coin_name, session)
            self.clearStringKV('stealth_addr_' + db_key_coin_name, session)

            coin_id = int(coin_type)
            info_type = 1  # wallet
            query_str = f'DELETE FROM wallets WHERE coin_id = {coin_id} AND balance_type = {info_type}'
            session.execute(text(query_str))
        finally:
            self.closeSession(session)

    def updateIdentityBidState(self, session, address: str, bid) -> None:
        identity_stats = session.query(KnownIdentity).filter_by(address=address).first()
        if not identity_stats:
            identity_stats = KnownIdentity(active_ind=1, address=address, created_at=self.getTime())

        if bid.state == BidStates.SWAP_COMPLETED:
            if bid.was_sent:
                identity_stats.num_sent_bids_successful = zeroIfNone(identity_stats.num_sent_bids_successful) + 1
            else:
                identity_stats.num_recv_bids_successful = zeroIfNone(identity_stats.num_recv_bids_successful) + 1
        elif bid.state in (BidStates.BID_ERROR, BidStates.XMR_SWAP_FAILED_REFUNDED, BidStates.XMR_SWAP_FAILED_SWIPED, BidStates.XMR_SWAP_FAILED, BidStates.SWAP_TIMEDOUT):
            if bid.was_sent:
                identity_stats.num_sent_bids_failed = zeroIfNone(identity_stats.num_sent_bids_failed) + 1
            else:
                identity_stats.num_recv_bids_failed = zeroIfNone(identity_stats.num_recv_bids_failed) + 1

        identity_stats.updated_at = self.getTime()
        session.add(identity_stats)

    def setIntKV(self, str_key: str, int_val: int, session=None) -> None:
        try:
            use_session = self.openSession(session)
            kv = use_session.query(DBKVInt).filter_by(key=str_key).first()
            if not kv:
                kv = DBKVInt(key=str_key, value=int_val)
            else:
                kv.value = int_val
            use_session.add(kv)
        finally:
            if session is None:
                self.closeSession(use_session)

    def setStringKV(self, str_key: str, str_val: str, session=None) -> None:
        try:
            use_session = self.openSession(session)
            kv = use_session.query(DBKVString).filter_by(key=str_key).first()
            if not kv:
                kv = DBKVString(key=str_key, value=str_val)
            else:
                kv.value = str_val
            use_session.add(kv)
        finally:
            if session is None:
                self.closeSession(use_session)

    def getStringKV(self, str_key: str, session=None) -> Optional[str]:
        try:
            use_session = self.openSession(session)
            v = use_session.query(DBKVString).filter_by(key=str_key).first()
            if not v:
                return None
            return v.value
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def clearStringKV(self, str_key: str, session=None) -> None:
        try:
            use_session = self.openSession(session)
            use_session.execute(text('DELETE FROM kv_string WHERE key = :key'), {'key': str_key})
        finally:
            if session is None:
                self.closeSession(use_session)

    def getPreFundedTx(self, linked_type: int, linked_id: bytes, tx_type: int, session=None) -> Optional[bytes]:
        try:
            use_session = self.openSession(session)
            tx = use_session.query(PrefundedTx).filter_by(linked_type=linked_type, linked_id=linked_id, tx_type=tx_type, used_by=None).first()
            if not tx:
                return None
            tx.used_by = linked_id
            use_session.add(tx)
            return tx.tx_data
        finally:
            if session is None:
                self.closeSession(use_session)

    def activateBid(self, session, bid) -> None:
        if bid.bid_id in self.swaps_in_progress:
            self.log.debug('Bid %s is already in progress', bid.bid_id.hex())

        self.log.debug('Loading active bid %s', bid.bid_id.hex())

        offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
        if not offer:
            raise ValueError('Offer not found')

        self.loadBidTxns(bid, session)

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)

        if offer.swap_type == SwapTypes.XMR_SWAP:
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
            self.watchXmrSwap(bid, offer, xmr_swap, session)
            if ci_to.watch_blocks_for_scripts() and bid.xmr_a_lock_tx and bid.xmr_a_lock_tx.chain_height:
                if not bid.xmr_b_lock_tx or not bid.xmr_b_lock_tx.txid:
                    chain_a_block_header = ci_from.getBlockHeaderFromHeight(bid.xmr_a_lock_tx.chain_height)
                    chain_b_block_header = ci_to.getBlockHeaderAt(chain_a_block_header['time'])
                    dest_script = ci_to.getPkDest(xmr_swap.pkbs)
                    self.setLastHeightCheckedStart(ci_to.coin_type(), chain_b_block_header['height'], session)
                    self.addWatchedScript(ci_to.coin_type(), bid.bid_id, dest_script, TxTypes.XMR_SWAP_B_LOCK)
        else:
            self.swaps_in_progress[bid.bid_id] = (bid, offer)

            if bid.initiate_tx and bid.initiate_tx.txid:
                self.addWatchedOutput(coin_from, bid.bid_id, bid.initiate_tx.txid.hex(), bid.initiate_tx.vout, BidStates.SWAP_INITIATED)
            if bid.participate_tx and bid.participate_tx.txid:
                self.addWatchedOutput(coin_to, bid.bid_id, bid.participate_tx.txid.hex(), bid.participate_tx.vout, BidStates.SWAP_PARTICIPATING)

            if ci_to.watch_blocks_for_scripts() and bid.participate_tx and bid.participate_tx.txid is None:
                if bid.initiate_tx and bid.initiate_tx.chain_height:
                    chain_a_block_header = ci_from.getBlockHeaderFromHeight(bid.initiate_tx.chain_height)
                    chain_b_block_header = ci_to.getBlockHeaderAt(chain_a_block_header['time'])
                    self.setLastHeightCheckedStart(coin_to, chain_b_block_header['height'], session)
                self.addWatchedScript(coin_to, bid.bid_id, ci_to.getScriptDest(bid.participate_tx.script), TxTypes.PTX)

            if self.coin_clients[coin_from]['last_height_checked'] < 1:
                if bid.initiate_tx and bid.initiate_tx.chain_height:
                    self.setLastHeightCheckedStart(coin_from, bid.initiate_tx.chain_height, session)
            if self.coin_clients[coin_to]['last_height_checked'] < 1:
                if bid.participate_tx and bid.participate_tx.chain_height:
                    self.setLastHeightCheckedStart(coin_to, bid.participate_tx.chain_height, session)

        # TODO process addresspool if bid has previously been abandoned

    def deactivateBid(self, session, offer, bid) -> None:
        # Remove from in progress
        self.log.debug('Removing bid from in-progress: %s', bid.bid_id.hex())
        self.swaps_in_progress.pop(bid.bid_id, None)

        bid.in_progress = 0
        if session is None:
            self.saveBid(bid.bid_id, bid)

        # Remove any watched outputs
        self.removeWatchedOutput(Coins(offer.coin_from), bid.bid_id, None)
        self.removeWatchedOutput(Coins(offer.coin_to), bid.bid_id, None)

        self.removeWatchedScript(Coins(offer.coin_from), bid.bid_id, None)
        self.removeWatchedScript(Coins(offer.coin_to), bid.bid_id, None)

        if bid.state in (BidStates.BID_ABANDONED, BidStates.SWAP_COMPLETED):
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
            query: str = 'DELETE FROM actions WHERE linked_id = x\'{}\' '.format(bid.bid_id.hex())
            if self.debug:
                query = 'UPDATE actions SET active_ind = 2 WHERE linked_id = x\'{}\' '.format(bid.bid_id.hex())
            use_session.execute(text(query))

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
            # Unlock locked inputs (TODO)
            if offer.swap_type == SwapTypes.XMR_SWAP:
                ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
                xmr_swap = use_session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
                if xmr_swap:
                    try:
                        ci_from.unlockInputs(xmr_swap.a_lock_tx)
                    except Exception as e:
                        self.log.debug('unlockInputs failed {}'.format(str(e)))
                        pass  # Invalid parameter, unknown transaction
            elif SwapTypes.SELLER_FIRST:
                pass  # No prevouts are locked

            # Update identity stats
            if bid.state in (BidStates.BID_ERROR, BidStates.XMR_SWAP_FAILED_REFUNDED, BidStates.XMR_SWAP_FAILED_SWIPED, BidStates.XMR_SWAP_FAILED, BidStates.SWAP_COMPLETED, BidStates.SWAP_TIMEDOUT):
                was_sent: bool = bid.was_received if reverse_bid else bid.was_sent
                peer_address = offer.addr_from if was_sent else bid.bid_addr
                self.updateIdentityBidState(use_session, peer_address, bid)

        finally:
            if session is None:
                self.closeSession(use_session)

    def loadFromDB(self) -> None:
        if self.isSystemUnlocked() is False:
            self.log.info('Not loading from db.  System is locked.')
            return
        self.log.info('Loading data from db')
        self.mxDB.acquire()
        self.swaps_in_progress.clear()
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

    def getActiveBidMsgValidTime(self) -> int:
        return self.SMSG_SECONDS_IN_HOUR * 48

    def getAcceptBidMsgValidTime(self, bid) -> int:
        now: int = self.getTime()
        smsg_max_valid = self.SMSG_SECONDS_IN_HOUR * 48
        smsg_min_valid = self.SMSG_SECONDS_IN_HOUR * 1
        bid_valid = (bid.expire_at - now) + 10 * 60  # Add 10 minute buffer
        return max(smsg_min_valid, min(smsg_max_valid, bid_valid))

    def sendSmsg(self, addr_from: str, addr_to: str, payload_hex: bytes, msg_valid: int) -> bytes:
        options = {'decodehex': True, 'ttl_is_seconds': True}
        try:
            ro = self.callrpc('smsgsend', [addr_from, addr_to, payload_hex, False, msg_valid, False, options])
            return bytes.fromhex(ro['msgid'])
        except Exception as e:
            if self.debug:
                self.log.error('smsgsend failed {}'.format(json.dumps(ro, indent=4)))
            raise e

    def is_reverse_ads_bid(self, coin_from) -> bool:
        return coin_from in self.scriptless_coins + self.coins_without_segwit

    def validateSwapType(self, coin_from, coin_to, swap_type):

        for coin in (coin_from, coin_to):
            if coin in self.balance_only_coins:
                raise ValueError('Invalid coin: {}'.format(coin.name))

        if swap_type == SwapTypes.XMR_SWAP:
            reverse_bid: bool = self.is_reverse_ads_bid(coin_from)
            itx_coin = coin_to if reverse_bid else coin_from
            ptx_coin = coin_from if reverse_bid else coin_to
            if itx_coin in self.coins_without_segwit + self.scriptless_coins:
                if ptx_coin in self.coins_without_segwit + self.scriptless_coins:
                    raise ValueError('{} -> {} is not currently supported'.format(coin_from.name, coin_to.name))
                raise ValueError('Invalid swap type for: {} -> {}'.format(coin_from.name, coin_to.name))
        else:
            if coin_from in self.adaptor_swap_only_coins or coin_to in self.adaptor_swap_only_coins:
                raise ValueError('Invalid swap type for: {} -> {}'.format(coin_from.name, coin_to.name))

    def notify(self, event_type, event_data, session=None) -> None:
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
            now: int = self.getTime()
            use_session = self.openSession(session)
            use_session.add(Notification(
                active_ind=1,
                created_at=now,
                event_type=int(event_type),
                event_data=bytes(json.dumps(event_data), 'UTF-8'),
            ))

            use_session.execute(text(f'DELETE FROM notifications WHERE record_id NOT IN (SELECT record_id FROM notifications WHERE active_ind=1 ORDER BY created_at ASC LIMIT {self._keep_notifications})'))

            if show_event:
                self._notifications_cache[now] = (event_type, event_data)
            while len(self._notifications_cache) > self._show_notifications:
                # dicts preserve insertion order in Python 3.7+
                self._notifications_cache.pop(next(iter(self._notifications_cache)))

        finally:
            if session is None:
                self.closeSession(use_session)

    def buildNotificationsCache(self, session):
        self._notifications_cache.clear()
        q = session.execute(text(f'SELECT created_at, event_type, event_data FROM notifications WHERE active_ind = 1 ORDER BY created_at ASC LIMIT {self._show_notifications}'))
        for entry in q:
            self._notifications_cache[entry[0]] = (entry[1], json.loads(entry[2].decode('UTF-8')))

    def getNotifications(self):
        rv = []
        for k, v in self._notifications_cache.items():
            rv.append((time.strftime('%d-%m-%y %H:%M:%S', time.localtime(k)), int(v[0]), v[1]))
        return rv

    def setIdentityData(self, filters, data):
        address = filters['address']
        ci = self.ci(Coins.PART)
        ensure(ci.isValidAddress(address), 'Invalid identity address')

        try:
            now: int = self.getTime()
            session = self.openSession()
            q = session.execute(text('SELECT COUNT(*) FROM knownidentities WHERE address = :address'), {'address': address}).first()
            if q[0] < 1:
                session.execute(text('INSERT INTO knownidentities (active_ind, address, created_at) VALUES (1, :address, :now)'), {'address': address, 'now': now})

            if 'label' in data:
                session.execute(text('UPDATE knownidentities SET label = :label WHERE address = :address'), {'address': address, 'label': data['label']})

            if 'automation_override' in data:
                new_value: int = 0
                data_value = data['automation_override']
                if isinstance(data_value, int):
                    new_value = data_value
                elif isinstance(data_value, str):
                    if data_value.isdigit():
                        new_value = int(data_value)
                    elif data_value == 'default':
                        new_value = 0
                    elif data_value == 'always_accept':
                        new_value = int(AutomationOverrideOptions.ALWAYS_ACCEPT)
                    elif data_value == 'never_accept':
                        new_value = int(AutomationOverrideOptions.NEVER_ACCEPT)
                    else:
                        raise ValueError('Unknown automation_override value')
                else:
                    raise ValueError('Unknown automation_override type')

                session.execute(text('UPDATE knownidentities SET automation_override = :new_value WHERE address = :address'), {'address': address, 'new_value': new_value})

            if 'visibility_override' in data:
                new_value: int = 0
                data_value = data['visibility_override']
                if isinstance(data_value, int):
                    new_value = data_value
                elif isinstance(data_value, str):
                    if data_value.isdigit():
                        new_value = int(data_value)
                    elif data_value == 'default':
                        new_value = 0
                    elif data_value == 'hide':
                        new_value = int(VisibilityOverrideOptions.HIDE)
                    elif data_value == 'block':
                        new_value = int(VisibilityOverrideOptions.BLOCK)
                    else:
                        raise ValueError('Unknown visibility_override value')
                else:
                    raise ValueError('Unknown visibility_override type')

                session.execute(text('UPDATE knownidentities SET visibility_override = :new_value WHERE address = :address'), {'address': address, 'new_value': new_value})

            if 'note' in data:
                session.execute(text('UPDATE knownidentities SET note = :note WHERE address = :address'), {'address': address, 'note': data['note']})

        finally:
            self.closeSession(session)

    def listIdentities(self, filters={}):
        try:
            session = self.openSession()

            query_str = 'SELECT address, label, num_sent_bids_successful, num_recv_bids_successful, ' + \
                        '       num_sent_bids_rejected, num_recv_bids_rejected, num_sent_bids_failed, num_recv_bids_failed, ' + \
                        '       automation_override, visibility_override, note ' + \
                        ' FROM knownidentities ' + \
                        ' WHERE active_ind = 1 '

            address = filters.get('address', None)
            if address is not None:
                query_str += f' AND address = "{address}" '

            sort_dir = filters.get('sort_dir', 'DESC').upper()
            sort_by = filters.get('sort_by', 'created_at')
            query_str += f' ORDER BY {sort_by} {sort_dir}'

            limit = filters.get('limit', None)
            if limit is not None:
                query_str += f' LIMIT {limit}'
            offset = filters.get('offset', None)
            if offset is not None:
                query_str += f' OFFSET {offset}'

            q = session.execute(text(query_str))
            rv = []
            for row in q:
                identity = {
                    'address': row[0],
                    'label': row[1],
                    'num_sent_bids_successful': zeroIfNone(row[2]),
                    'num_recv_bids_successful': zeroIfNone(row[3]),
                    'num_sent_bids_rejected': zeroIfNone(row[4]),
                    'num_recv_bids_rejected': zeroIfNone(row[5]),
                    'num_sent_bids_failed': zeroIfNone(row[6]),
                    'num_recv_bids_failed': zeroIfNone(row[7]),
                    'automation_override': zeroIfNone(row[8]),
                    'visibility_override': zeroIfNone(row[9]),
                    'note': row[10],
                }
                rv.append(identity)
            return rv
        finally:
            self.closeSession(session, commit=False)

    def vacuumDB(self):
        try:
            session = self.openSession()
            return session.execute(text('VACUUM'))
        finally:
            self.closeSession(session)

    def validateOfferAmounts(self, coin_from, coin_to, amount: int, amount_to: int, min_bid_amount: int) -> None:
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        ensure(amount >= min_bid_amount, 'amount < min_bid_amount')
        ensure(amount > ci_from.min_amount(), 'From amount below min value for chain')
        ensure(amount < ci_from.max_amount(), 'From amount above max value for chain')

        ensure(amount_to > ci_to.min_amount(), 'To amount below min value for chain')
        ensure(amount_to < ci_to.max_amount(), 'To amount above max value for chain')

    def validateOfferLockValue(self, swap_type, coin_from, coin_to, lock_type, lock_value: int) -> None:
        coin_from_has_csv = self.coin_clients[coin_from]['use_csv']
        coin_to_has_csv = self.coin_clients[coin_to]['use_csv']

        if lock_type == TxLockTypes.SEQUENCE_LOCK_TIME:
            ensure(lock_value >= self.min_sequence_lock_seconds and lock_value <= self.max_sequence_lock_seconds, 'Invalid lock_value time')
            if swap_type == SwapTypes.XMR_SWAP:
                reverse_bid: bool = self.is_reverse_ads_bid(coin_from)
                itx_coin_has_csv = coin_to_has_csv if reverse_bid else coin_from_has_csv
                ensure(itx_coin_has_csv, 'ITX coin needs CSV activated.')
            else:
                ensure(coin_from_has_csv and coin_to_has_csv, 'Both coins need CSV activated.')
        elif lock_type == TxLockTypes.SEQUENCE_LOCK_BLOCKS:
            ensure(lock_value >= 5 and lock_value <= 1000, 'Invalid lock_value blocks')
            if swap_type == SwapTypes.XMR_SWAP:
                reverse_bid: bool = self.is_reverse_ads_bid(coin_from)
                itx_coin_has_csv = coin_to_has_csv if reverse_bid else coin_from_has_csv
                ensure(itx_coin_has_csv, 'ITX coin needs CSV activated.')
            else:
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

    def validateOfferValidTime(self, offer_type, coin_from, coin_to, valid_for_seconds: int) -> None:
        # TODO: adjust
        if valid_for_seconds < 10 * 60:
            raise ValueError('Offer TTL too low')
        if valid_for_seconds > 48 * 60 * 60:
            raise ValueError('Offer TTL too high')

    def validateBidValidTime(self, offer_type, coin_from, coin_to, valid_for_seconds: int) -> None:
        # TODO: adjust
        if valid_for_seconds < 10 * 60:
            raise ValueError('Bid TTL too low')
        if valid_for_seconds > 24 * 60 * 60:
            raise ValueError('Bid TTL too high')

    def validateBidAmount(self, offer, bid_amount: int, bid_rate: int) -> None:
        ensure(bid_amount >= offer.min_bid_amount, 'Bid amount below minimum')
        ensure(bid_amount <= offer.amount_from, 'Bid amount above offer amount')
        if not offer.amount_negotiable:
            ensure(offer.amount_from == bid_amount, 'Bid amount must match offer amount.')
        if not offer.rate_negotiable:
            ensure(offer.rate == bid_rate, 'Bid rate must match offer rate.')

    def getOfferAddressTo(self, extra_options) -> str:
        if 'addr_send_to' in extra_options:
            return extra_options['addr_send_to']
        return self.network_addr

    def postOffer(self, coin_from, coin_to, amount: int, rate: int, min_bid_amount: int, swap_type,
                  lock_type=TxLockTypes.SEQUENCE_LOCK_TIME, lock_value: int = 48 * 60 * 60, auto_accept_bids: bool = False, addr_send_from: str = None, extra_options={}) -> bytes:
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

        valid_for_seconds: int = extra_options.get('valid_for_seconds', 60 * 60)
        amount_to: int = extra_options.get('amount_to', int((amount * rate) // ci_from.COIN()))

        # Recalculate the rate so it will match the bid rate
        rate = ci_from.make_int(amount_to / amount, r=1)

        self.validateSwapType(coin_from_t, coin_to_t, swap_type)
        self.validateOfferAmounts(coin_from_t, coin_to_t, amount, amount_to, min_bid_amount)
        self.validateOfferLockValue(swap_type, coin_from_t, coin_to_t, lock_type, lock_value)
        self.validateOfferValidTime(swap_type, coin_from_t, coin_to_t, valid_for_seconds)

        offer_addr_to = self.getOfferAddressTo(extra_options)

        reverse_bid: bool = self.is_reverse_ads_bid(coin_from)

        try:
            session = self.openSession()
            self.checkCoinsReady(coin_from_t, coin_to_t)
            offer_addr = self.prepareSMSGAddress(addr_send_from, AddressTypes.OFFER, session)

            offer_created_at = self.getTime()

            msg_buf = OfferMessage()

            msg_buf.protocol_version = PROTOCOL_VERSION_ADAPTOR_SIG if swap_type == SwapTypes.XMR_SWAP else PROTOCOL_VERSION_SECRET_HASH
            msg_buf.coin_from = int(coin_from)
            msg_buf.coin_to = int(coin_to)
            msg_buf.amount_from = int(amount)
            msg_buf.amount_to = int(amount_to)
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

                chain_a_ci = ci_to if reverse_bid else ci_from
                lock_value_2 = lock_value + 1000 if (None, DebugTypes.OFFER_LOCK_2_VALUE_INC) in self._debug_cases else lock_value
                # Delay before the chain a lock refund tx can be mined
                xmr_offer.lock_time_1 = chain_a_ci.getExpectedSequence(lock_type, lock_value)
                # Delay before the follower can spend from the chain a lock refund tx
                xmr_offer.lock_time_2 = chain_a_ci.getExpectedSequence(lock_type, lock_value_2)

                xmr_offer.a_fee_rate = msg_buf.fee_rate_from
                xmr_offer.b_fee_rate = msg_buf.fee_rate_to  # Unused: TODO - Set priority?

            if coin_from in self.scriptless_coins:
                ci_from.ensureFunds(msg_buf.amount_from)
            else:
                proof_of_funds_hash = getOfferProofOfFundsHash(msg_buf, offer_addr)
                proof_addr, proof_sig, proof_utxos = self.getProofOfFunds(coin_from_t, int(amount), proof_of_funds_hash)
                # TODO: For now proof_of_funds is just a client side check, may need to be sent with offers in future however.

            offer_bytes = msg_buf.to_bytes()
            payload_hex = str.format('{:02x}', MessageTypes.OFFER) + offer_bytes.hex()
            msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
            offer_id = self.sendSmsg(offer_addr, offer_addr_to, payload_hex, msg_valid)

            security_token = extra_options.get('security_token', None)
            if security_token is not None and len(security_token) != 20:
                raise ValueError('Security token must be 20 bytes long.')

            bid_reversed: bool = msg_buf.swap_type == SwapTypes.XMR_SWAP and self.is_reverse_ads_bid(msg_buf.coin_from)
            offer = Offer(
                offer_id=offer_id,
                active_ind=1,
                protocol_version=msg_buf.protocol_version,

                coin_from=msg_buf.coin_from,
                coin_to=msg_buf.coin_to,
                amount_from=msg_buf.amount_from,
                amount_to=msg_buf.amount_to,
                rate=rate,
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
                bid_reversed=bid_reversed,
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

            if 'prefunded_itx' in extra_options:
                prefunded_tx = PrefundedTx(
                    active_ind=1,
                    created_at=offer_created_at,
                    linked_type=Concepts.OFFER,
                    linked_id=offer_id,
                    tx_type=TxTypes.ITX_PRE_FUNDED,
                    tx_data=extra_options['prefunded_itx'])
                session.add(prefunded_tx)

            session.add(offer)
            session.add(SentOffer(offer_id=offer_id))
        finally:
            self.closeSession(session)
        self.log.info('Sent OFFER %s', offer_id.hex())
        return offer_id

    def revokeOffer(self, offer_id, security_token=None) -> None:
        self.log.info('Revoking offer %s', offer_id.hex())

        session = self.openSession()
        try:
            offer = session.query(Offer).filter_by(offer_id=offer_id).first()

            if offer.security_token is not None and offer.security_token != security_token:
                raise ValueError('Mismatched security token')

            msg_buf = OfferRevokeMessage()
            msg_buf.offer_msg_id = offer_id

            signature_enc = self.callcoinrpc(Coins.PART, 'signmessage', [offer.addr_from, offer_id.hex() + '_revoke'])

            msg_buf.signature = base64.b64decode(signature_enc)

            msg_bytes = msg_buf.to_bytes()
            payload_hex = str.format('{:02x}', MessageTypes.OFFER_REVOKE) + msg_bytes.hex()

            msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, offer.time_valid)
            msg_id = self.sendSmsg(offer.addr_from, self.network_addr, payload_hex, msg_valid)
            self.log.debug('Revoked offer %s in msg %s', offer_id.hex(), msg_id.hex())
        finally:
            self.closeSession(session, commit=False)

    def archiveOffer(self, offer_id) -> None:
        self.log.info('Archiving offer %s', offer_id.hex())
        session = self.openSession()
        try:
            offer = session.query(Offer).filter_by(offer_id=offer_id).first()

            if offer.active_ind != 1:
                raise ValueError('Offer is not active')

            offer.active_ind = 3
        finally:
            self.closeSession(session)

    def editOffer(self, offer_id, data) -> None:
        self.log.info('Editing offer %s', offer_id.hex())
        session = self.openSession()
        try:
            offer = session.query(Offer).filter_by(offer_id=offer_id).first()
            if 'automation_strat_id' in data:
                new_automation_strat_id = data['automation_strat_id']
                link = session.query(AutomationLink).filter_by(linked_type=Concepts.OFFER, linked_id=offer.offer_id).first()
                if not link:
                    if new_automation_strat_id > 0:
                        link = AutomationLink(
                            active_ind=1,
                            linked_type=Concepts.OFFER,
                            linked_id=offer_id,
                            strategy_id=new_automation_strat_id,
                            created_at=self.getTime())
                        session.add(link)
                else:
                    if new_automation_strat_id < 1:
                        link.active_ind = 0
                    else:
                        link.strategy_id = new_automation_strat_id
                        link.active_ind = 1
                    session.add(link)
        finally:
            self.closeSession(session)

    def grindForEd25519Key(self, coin_type, evkey, key_path_base) -> bytes:
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

    def getWalletKey(self, coin_type, key_num, for_ed25519=False) -> bytes:
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']

        key_path_base = '44445555h/1h/{}/{}'.format(int(coin_type), key_num)

        if not for_ed25519:
            extkey = self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, key_path_base])['key_info']['result']
            return decodeWif(self.callcoinrpc(Coins.PART, 'extkey', ['info', extkey])['key_info']['privkey'])

        return self.grindForEd25519Key(coin_type, evkey, key_path_base)

    def getPathKey(self, coin_from, coin_to, bid_created_at: int, contract_count: int, key_no: int, for_ed25519: bool = False) -> bytes:
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']
        ci = self.ci(coin_to)

        days = bid_created_at // 86400
        secs = bid_created_at - days * 86400
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

    def getContractPrivkey(self, date: dt.datetime, contract_count: int) -> bytes:
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

    def getContractSecret(self, date: dt.datetime, contract_count: int) -> bytes:
        # Derive a key to use for a contract secret
        evkey = self.callcoinrpc(Coins.PART, 'extkey', ['account', 'default', 'true'])['evkey']

        path = '44445555h/99999'
        path += '/' + str(date.year) + '/' + str(date.month) + '/' + str(date.day)
        path += '/' + str(contract_count)

        return sha256(bytes(self.callcoinrpc(Coins.PART, 'extkey', ['info', evkey, path])['key_info']['result'], 'utf-8'))

    def getReceiveAddressFromPool(self, coin_type, bid_id: bytes, tx_type, session=None):
        self.log.debug('Get address from pool bid_id {}, type {}, coin {}'.format(bid_id.hex(), tx_type, coin_type))
        try:
            use_session = self.openSession(session)
            record = use_session.query(PooledAddress).filter(sa.and_(PooledAddress.coin_type == int(coin_type), PooledAddress.bid_id == None)).first()  # noqa: E712,E711
            if not record:
                address = self.getReceiveAddressForCoin(coin_type)
                record = PooledAddress(
                    addr=address,
                    coin_type=int(coin_type))
            record.bid_id = bid_id
            record.tx_type = tx_type
            addr = record.addr
            ensure(self.ci(coin_type).isAddressMine(addr), 'Pool address not owned by wallet!')
            use_session.add(record)
            use_session.commit()
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)
        return addr

    def returnAddressToPool(self, bid_id: bytes, tx_type):
        self.log.debug('Return address to pool bid_id {}, type {}'.format(bid_id.hex(), tx_type))
        try:
            session = self.openSession()
            try:
                record = session.query(PooledAddress).filter(sa.and_(PooledAddress.bid_id == bid_id, PooledAddress.tx_type == tx_type)).one()
                self.log.debug('Returning address to pool addr {}'.format(record.addr))
                record.bid_id = None
                session.commit()
            except Exception as ex:
                pass
        finally:
            self.closeSession(session, commit=False)

    def getReceiveAddressForCoin(self, coin_type):
        new_addr = self.ci(coin_type).getNewAddress(self.coin_clients[coin_type]['use_segwit'])
        self.log.debug('Generated new receive address %s for %s', new_addr, Coins(coin_type).name)
        return new_addr

    def getFeeRateForCoin(self, coin_type, conf_target: int = 2):
        return self.ci(coin_type).get_fee_rate(conf_target)

    def estimateWithdrawFee(self, coin_type, fee_rate):
        if coin_type in (Coins.XMR, Coins.WOW):
            # Fee estimate must be manually initiated
            return None
        tx_vsize = self.ci(coin_type).getHTLCSpendTxVSize()
        est_fee = (fee_rate * tx_vsize) / 1000
        return est_fee

    def withdrawCoin(self, coin_type, value, addr_to, subfee: bool) -> str:
        ci = self.ci(coin_type)
        if subfee and coin_type in (Coins.XMR, Coins.WOW):
            self.log.info('withdrawCoin sweep all {} to {}'.format(ci.ticker(), addr_to))
        else:
            self.log.info('withdrawCoin {} {} to {} {}'.format(value, ci.ticker(), addr_to, ' subfee' if subfee else ''))

        txid = ci.withdrawCoin(value, addr_to, subfee)
        self.log.debug('In txn: {}'.format(txid))
        return txid

    def withdrawLTC(self, type_from, value, addr_to, subfee: bool) -> str:
        ci = self.ci(Coins.LTC)
        self.log.info('withdrawLTC {} {} to {} {}'.format(value, type_from, addr_to, ' subfee' if subfee else ''))

        txid = ci.withdrawCoin(value, type_from, addr_to, subfee)
        self.log.debug('In txn: {}'.format(txid))
        return txid

    def withdrawParticl(self, type_from: str, type_to: str, value, addr_to: str, subfee: bool) -> str:
        self.log.info('withdrawParticl {} {} to {} {} {}'.format(value, type_from, type_to, addr_to, ' subfee' if subfee else ''))

        if type_from == 'plain':
            type_from = 'part'
        if type_to == 'plain':
            type_to = 'part'

        ci = self.ci(Coins.PART)
        txid = ci.sendTypeTo(type_from, type_to, value, addr_to, subfee)
        self.log.debug('In txn: {}'.format(txid))
        return txid

    def cacheNewAddressForCoin(self, coin_type, session=None):
        self.log.debug('cacheNewAddressForCoin %s', Coins(coin_type).name)
        key_str = 'receive_addr_' + self.ci(coin_type).coin_name().lower()
        addr = self.getReceiveAddressForCoin(coin_type)
        self.setStringKV(key_str, addr, session)
        return addr

    def getCachedMainWalletAddress(self, ci, session=None):
        db_key = 'main_wallet_addr_' + ci.coin_name().lower()
        cached_addr = self.getStringKV(db_key, session)
        if cached_addr is not None:
            return cached_addr
        self.log.warning(f'Setting {db_key}')
        main_address = ci.getMainWalletAddress()
        self.setStringKV(db_key, main_address, session)
        return main_address

    def checkWalletSeed(self, c) -> bool:
        ci = self.ci(c)
        if c == Coins.PART:
            ci.setWalletSeedWarning(False)  # All keys should be be derived from the Particl mnemonic
            return True  # TODO
        if c in (Coins.XMR, Coins.WOW):
            expect_address = self.getCachedMainWalletAddress(ci)
            if expect_address is None:
                self.log.warning('Can\'t find expected main wallet address for coin {}'.format(ci.coin_name()))
                return False
            ci._have_checked_seed = True
            wallet_address: str = ci.getMainWalletAddress()
            if expect_address == wallet_address:
                ci.setWalletSeedWarning(False)
                return True
            self.log.warning('Wallet for coin {} not derived from swap seed.\n  Expected {}\n  Have     {}'.format(ci.coin_name(), expect_address, wallet_address))
            return False

        expect_seedid = self.getStringKV('main_wallet_seedid_' + ci.coin_name().lower())
        if expect_seedid is None:
            self.log.warning('Can\'t find expected wallet seed id for coin {}'.format(ci.coin_name()))
            return False
        if c == Coins.BTC and len(ci.rpc('listwallets')) < 1:
            self.log.warning('Missing wallet for coin {}'.format(ci.coin_name()))
            return False
        if ci.checkExpectedSeed(expect_seedid):
            ci.setWalletSeedWarning(False)
            return True
        if c == Coins.DCR:
            # Try the legacy extkey
            expect_seedid = self.getStringKV('main_wallet_seedid_alt_' + ci.coin_name().lower())
            if ci.checkExpectedSeed(expect_seedid):
                ci.setWalletSeedWarning(False)
                self.log.warning('{} is using the legacy extkey.'.format(ci.coin_name()))
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
            if coin_type in (Coins.XMR, Coins.WOW):
                raise ValueError('TODO: How to reseed XMR wallet?')
            else:
                raise ValueError('Wallet seed doesn\'t match expected.')

    def getCachedAddressForCoin(self, coin_type):
        self.log.debug('getCachedAddressForCoin %s', Coins(coin_type).name)
        # TODO: auto refresh after used

        ci = self.ci(coin_type)
        key_str = 'receive_addr_' + ci.coin_name().lower()
        session = self.openSession()
        try:
            try:
                addr = session.query(DBKVString).filter_by(key=key_str).first().value
            except Exception:
                addr = self.getReceiveAddressForCoin(coin_type)
                session.add(DBKVString(
                    key=key_str,
                    value=addr
                ))
        finally:
            self.closeSession(session)
        return addr

    def cacheNewStealthAddressForCoin(self, coin_type):
        self.log.debug('cacheNewStealthAddressForCoin %s', Coins(coin_type).name)

        if coin_type == Coins.LTC_MWEB:
            coin_type = Coins.LTC
        ci = self.ci(coin_type)
        key_str = 'stealth_addr_' + ci.coin_name().lower()
        addr = ci.getNewStealthAddress()
        self.setStringKV(key_str, addr)
        return addr

    def getCachedStealthAddressForCoin(self, coin_type, session=None):
        self.log.debug('getCachedStealthAddressForCoin %s', Coins(coin_type).name)

        if coin_type == Coins.LTC_MWEB:
            coin_type = Coins.LTC
        ci = self.ci(coin_type)
        key_str = 'stealth_addr_' + ci.coin_name().lower()
        use_session = self.openSession(session)
        try:
            try:
                addr = use_session.query(DBKVString).filter_by(key=key_str).first().value
            except Exception:
                addr = ci.getNewStealthAddress()
                self.log.info('Generated new stealth address for %s', coin_type)
                use_session.add(DBKVString(
                    key=key_str,
                    value=addr
                ))
        finally:
            if session is None:
                self.closeSession(use_session)
        return addr

    def getCachedWalletRestoreHeight(self, ci, session=None):
        self.log.debug('getCachedWalletRestoreHeight %s', ci.coin_name())

        key_str = 'restore_height_' + ci.coin_name().lower()
        use_session = self.openSession(session)
        try:
            try:
                wrh = use_session.query(DBKVInt).filter_by(key=key_str).first().value
            except Exception:
                wrh = ci.getWalletRestoreHeight()
                self.log.info('Found restore height for %s, block %d', ci.coin_name(), wrh)
                use_session.add(DBKVInt(
                    key=key_str,
                    value=wrh
                ))
        finally:
            if session is None:
                self.closeSession(use_session)
        return wrh

    def getWalletRestoreHeight(self, ci, session=None):
        wrh = ci._restore_height
        if wrh is not None:
            return wrh
        found_height = self.getCachedWalletRestoreHeight(ci, session=session)
        ci.setWalletRestoreHeight(found_height)
        return found_height

    def getNewContractId(self, session):
        self._contract_count += 1
        session.execute(text('UPDATE kv_int SET value = :value WHERE KEY="contract_count"'), {'value': self._contract_count})
        return self._contract_count

    def getProofOfFunds(self, coin_type, amount_for: int, extra_commit_bytes):
        ci = self.ci(coin_type)
        self.log.debug('getProofOfFunds %s %s', ci.coin_name(), ci.format_amount(amount_for))

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return (None, None, None)

        return ci.getProofOfFunds(amount_for, extra_commit_bytes)

    def saveBidInSession(self, bid_id: bytes, bid, session, xmr_swap=None, save_in_progress=None) -> None:
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

    def saveBid(self, bid_id: bytes, bid, xmr_swap=None) -> None:
        session = self.openSession()
        try:
            self.saveBidInSession(bid_id, bid, session, xmr_swap)
        finally:
            self.closeSession(session)

    def saveToDB(self, db_record) -> None:
        session = self.openSession()
        try:
            session.add(db_record)
        finally:
            self.closeSession(session)

    def createActionInSession(self, delay: int, action_type: int, linked_id: bytes, session) -> None:
        self.log.debug('createAction %d %s', action_type, linked_id.hex())
        now: int = self.getTime()
        action = Action(
            active_ind=1,
            created_at=now,
            trigger_at=now + delay,
            action_type=action_type,
            linked_id=linked_id)
        session.add(action)
        for debug_case in self._debug_cases:
            bid_id, debug_ind = debug_case
            if bid_id == linked_id and debug_ind == DebugTypes.DUPLICATE_ACTIONS:
                action = Action(
                    active_ind=1,
                    created_at=now,
                    trigger_at=now + delay + 3,
                    action_type=action_type,
                    linked_id=linked_id)
                session.add(action)

    def createAction(self, delay: int, action_type: int, linked_id: bytes) -> None:
        # self.log.debug('createAction %d %s', action_type, linked_id.hex())

        session = self.openSession()
        try:
            self.createActionInSession(delay, action_type, linked_id, session)
        finally:
            self.closeSession(session)

    def logEvent(self, linked_type: int, linked_id: bytes, event_type: int, event_msg: str, session) -> None:
        entry = EventLog(
            active_ind=1,
            created_at=self.getTime(),
            linked_type=linked_type,
            linked_id=linked_id,
            event_type=int(event_type),
            event_msg=event_msg)

        if session is not None:
            session.add(entry)
            return
        session = self.openSession()
        try:
            session.add(entry)
        finally:
            self.closeSession(session)

    def logBidEvent(self, bid_id: bytes, event_type: int, event_msg: str, session) -> None:
        self.log.debug('logBidEvent %s %s', bid_id.hex(), event_type)
        self.logEvent(Concepts.BID, bid_id, event_type, event_msg, session)

    def countBidEvents(self, bid, event_type, session):
        q = session.execute(text('SELECT COUNT(*) FROM eventlog WHERE linked_type = {} AND linked_id = x\'{}\' AND event_type = {}'.format(int(Concepts.BID), bid.bid_id.hex(), int(event_type)))).first()
        return q[0]

    def getEvents(self, linked_type: int, linked_id: bytes):
        events = []
        session = self.openSession()
        try:
            for entry in session.query(EventLog).filter(sa.and_(EventLog.linked_type == linked_type, EventLog.linked_id == linked_id)):
                events.append(entry)
            return events
        finally:
            self.closeSession(session, commit=False)

    def addMessageLink(self, linked_type: int, linked_id: int, msg_type: int, msg_id: bytes, msg_sequence: int = 0, session=None) -> None:
        entry = MessageLink(
            active_ind=1,
            created_at=self.getTime(),
            linked_type=linked_type,
            linked_id=linked_id,
            msg_type=int(msg_type),
            msg_sequence=msg_sequence,
            msg_id=msg_id)

        if session is not None:
            session.add(entry)
            return
        session = self.openSession()
        try:
            session.add(entry)
        finally:
            self.closeSession(session)

    def getLinkedMessageId(self, linked_type: int, linked_id: int, msg_type: int, msg_sequence: int = 0, session=None) -> bytes:
        try:
            use_session = self.openSession(session)
            q = use_session.execute(text('SELECT msg_id FROM message_links WHERE linked_type = :linked_type AND linked_id = :linked_id AND msg_type = :msg_type AND msg_sequence = :msg_sequence'),
                                    {'linked_type': linked_type, 'linked_id': linked_id, 'msg_type': msg_type, 'msg_sequence': msg_sequence}).first()
            return q[0]
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def countMessageLinks(self, linked_type: int, linked_id: int, msg_type: int, msg_sequence: int = 0, session=None) -> int:
        try:
            use_session = self.openSession(session)
            q = use_session.execute(text('SELECT COUNT(*) FROM message_links WHERE linked_type = :linked_type AND linked_id = :linked_id AND msg_type = :msg_type AND msg_sequence = :msg_sequence'),
                                    {'linked_type': linked_type, 'linked_id': linked_id, 'msg_type': msg_type, 'msg_sequence': msg_sequence}).first()
            return q[0]
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def setBidAmounts(self, amount: int, offer, extra_options, ci_from) -> (int, int, int):
        if 'amount_to' in extra_options:
            amount_to: int = extra_options['amount_to']
        elif 'bid_rate' in extra_options:
            bid_rate = extra_options['bid_rate']
            amount_to: int = int((amount * bid_rate) // ci_from.COIN())
            if not offer.rate_negotiable:
                self.log.warning('Fixed-rate offer bids should set amount to instead of bid rate.')
        else:
            amount_to: int = offer.amount_to
        bid_rate: int = ci_from.make_int(amount_to / amount, r=1)

        if offer.amount_negotiable and not offer.rate_negotiable:
            if bid_rate != offer.rate and extra_options.get('adjust_amount_for_rate', True):
                self.log.debug('Attempting to reduce amount to match offer rate.')

                adjust_tries: int = 10000 if ci_from.exp() > 8 else 1000
                for i in range(adjust_tries):
                    test_amount = amount - i
                    test_amount_to: int = int((test_amount * offer.rate) // ci_from.COIN())
                    test_bid_rate: int = ci_from.make_int(test_amount_to / test_amount, r=1)

                    if test_bid_rate != offer.rate:
                        test_amount_to -= 1
                        test_bid_rate: int = ci_from.make_int(test_amount_to / test_amount, r=1)

                    if test_bid_rate == offer.rate:
                        if amount != test_amount:
                            self.log.info('Reducing bid amount-from from {} to {} to match offer rate.'.format(amount, test_amount))
                        elif amount_to != test_amount_to:
                            # Only show on first loop iteration (amount from unchanged)
                            self.log.info('Reducing bid amount-to from {} to {} to match offer rate.'.format(amount_to, test_amount_to))
                        amount = test_amount
                        amount_to = test_amount_to
                        bid_rate = test_bid_rate
                        break
        return amount, amount_to, bid_rate

    def postBid(self, offer_id: bytes, amount: int, addr_send_from: str = None, extra_options={}) -> bytes:
        # Bid to send bid.amount * bid.rate of coin_to in exchange for bid.amount of coin_from
        self.log.debug('postBid for offer: %s', offer_id.hex())

        offer = self.getOffer(offer_id)
        ensure(offer, 'Offer not found: {}.'.format(offer_id.hex()))
        ensure(offer.expire_at > self.getTime(), 'Offer has expired')

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.postXmrBid(offer_id, amount, addr_send_from, extra_options)

        ensure(offer.protocol_version >= MINPROTO_VERSION_SECRET_HASH, 'Incompatible offer protocol version')
        valid_for_seconds = extra_options.get('valid_for_seconds', 60 * 10)
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds)

        if not isinstance(amount, int):
            amount = int(amount)
            self.log.warning('postBid amount should be an integer type.')

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        amount, amount_to, bid_rate = self.setBidAmounts(amount, offer, extra_options, ci_from)
        self.validateBidAmount(offer, amount, bid_rate)

        try:
            session = self.openSession()
            self.checkCoinsReady(coin_from, coin_to)

            msg_buf = BidMessage()
            msg_buf.protocol_version = PROTOCOL_VERSION_SECRET_HASH
            msg_buf.offer_msg_id = offer_id
            msg_buf.time_valid = valid_for_seconds
            msg_buf.amount = amount  # amount of coin_from
            msg_buf.amount_to = amount_to

            now: int = self.getTime()
            if offer.swap_type == SwapTypes.SELLER_FIRST:
                proof_addr, proof_sig, proof_utxos = self.getProofOfFunds(coin_to, amount_to, offer_id)
                msg_buf.proof_address = proof_addr
                msg_buf.proof_signature = proof_sig

                if len(proof_utxos) > 0:
                    msg_buf.proof_utxos = ci_to.encodeProofUtxos(proof_utxos)

                contract_count = self.getNewContractId(session)
                contract_pubkey = self.getContractPubkey(dt.datetime.fromtimestamp(now).date(), contract_count)
                msg_buf.pkhash_buyer = ci_from.pkh(contract_pubkey)
                pkhash_buyer_to = ci_to.pkh(contract_pubkey)
                if pkhash_buyer_to != msg_buf.pkhash_buyer:
                    # Different pubkey hash
                    msg_buf.pkhash_buyer_to = pkhash_buyer_to
            else:
                raise ValueError('TODO')

            bid_bytes = msg_buf.to_bytes()
            payload_hex = str.format('{:02x}', MessageTypes.BID) + bid_bytes.hex()

            bid_addr = self.prepareSMSGAddress(addr_send_from, AddressTypes.BID, session)
            msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
            bid_id = self.sendSmsg(bid_addr, offer.addr_from, payload_hex, msg_valid)

            bid = Bid(
                protocol_version=msg_buf.protocol_version,
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                amount=msg_buf.amount,
                amount_to=msg_buf.amount_to,
                rate=bid_rate,
                pkhash_buyer=msg_buf.pkhash_buyer,
                proof_address=msg_buf.proof_address,
                proof_utxos=msg_buf.proof_utxos,

                created_at=now,
                contract_count=contract_count,
                expire_at=now + msg_buf.time_valid,
                bid_addr=bid_addr,
                was_sent=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
            )
            bid.setState(BidStates.BID_SENT)

            if len(msg_buf.pkhash_buyer_to) > 0:
                bid.pkhash_buyer_to = msg_buf.pkhash_buyer_to

            self.saveBidInSession(bid_id, bid, session)

            self.log.info('Sent BID %s', bid_id.hex())
            return bid_id
        finally:
            self.closeSession(session)

    def getOffer(self, offer_id: bytes, sent: bool = False, session=None):
        try:
            use_session = self.openSession(session)
            return use_session.query(Offer).filter_by(offer_id=offer_id).first()
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def setTxBlockInfoFromHeight(self, ci, tx, height: int) -> None:
        try:
            tx.block_height = height
            block_header = ci.getBlockHeaderFromHeight(height)
            tx.block_hash = bytes.fromhex(block_header['hash'])
            tx.block_time = block_header['time']  # Or median_time?
        except Exception as e:
            self.log.warning(f'setTxBlockInfoFromHeight failed {e}')

    def loadBidTxns(self, bid, session) -> None:
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

    def getXmrBidFromSession(self, session, bid_id: bytes, sent: bool = False):
        bid = session.query(Bid).filter_by(bid_id=bid_id).first()
        xmr_swap = None
        if bid:
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid_id).first()
            self.loadBidTxns(bid, session)
        return bid, xmr_swap

    def getXmrBid(self, bid_id: bytes, sent: bool = False):
        try:
            session = self.openSession()
            return self.getXmrBidFromSession(session, bid_id, sent)
        finally:
            self.closeSession(session, commit=False)

    def getXmrOfferFromSession(self, session, offer_id: bytes, sent: bool = False):
        offer = session.query(Offer).filter_by(offer_id=offer_id).first()
        xmr_offer = None
        if offer:
            xmr_offer = session.query(XmrOffer).filter_by(offer_id=offer_id).first()
        return offer, xmr_offer

    def getXmrOffer(self, offer_id: bytes, sent: bool = False, session=None):
        try:
            use_session = self.openSession(session)
            return self.getXmrOfferFromSession(use_session, offer_id, sent)
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def getBid(self, bid_id: bytes, session=None):
        try:
            use_session = self.openSession(session)
            bid = use_session.query(Bid).filter_by(bid_id=bid_id).first()
            if bid:
                self.loadBidTxns(bid, use_session)
            return bid
        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

    def getBidAndOffer(self, bid_id: bytes, session=None):
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

    def getXmrBidAndOffer(self, bid_id: bytes, list_events=True):
        try:
            session = self.openSession()
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
            self.closeSession(session, commit=False)

    def getIdentity(self, address: str):
        try:
            session = self.openSession()
            identity = session.query(KnownIdentity).filter_by(address=address).first()
            return identity
        finally:
            self.closeSession(session, commit=False)

    def list_bid_events(self, bid_id: bytes, session):
        query_str = 'SELECT created_at, event_type, event_msg FROM eventlog ' + \
                    'WHERE active_ind = 1 AND linked_type = {} AND linked_id = x\'{}\' '.format(Concepts.BID, bid_id.hex())
        q = session.execute(text(query_str))
        events = []
        for row in q:
            events.append({'at': row[0], 'desc': describeEventEntry(row[1], row[2])})

        query_str = 'SELECT created_at, trigger_at FROM actions ' + \
                    'WHERE active_ind = 1 AND linked_id = x\'{}\' '.format(bid_id.hex())
        q = session.execute(text(query_str))
        for row in q:
            events.append({'at': row[0], 'desc': 'Delaying until: {}'.format(format_timestamp(row[1], with_seconds=True))})

        return events

    def acceptBid(self, bid_id: bytes, session=None) -> None:
        self.log.info('Accepting bid %s', bid_id.hex())

        try:
            use_session = self.openSession(session)

            bid, offer = self.getBidAndOffer(bid_id, use_session)
            ensure(bid, 'Bid not found')
            ensure(offer, 'Offer not found')

            # Ensure bid is still valid
            now: int = self.getTime()
            ensure(bid.expire_at > now, 'Bid expired')
            ensure(bid.state in (BidStates.BID_RECEIVED, ), 'Wrong bid state: {}'.format(BidStates(bid.state).name))

            if offer.swap_type == SwapTypes.XMR_SWAP:
                ensure(bid.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG, 'Incompatible bid protocol version')
                reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
                if reverse_bid:
                    return self.acceptADSReverseBid(bid_id, use_session)
                return self.acceptXmrBid(bid_id, use_session)

            ensure(bid.protocol_version >= MINPROTO_VERSION_SECRET_HASH, 'Incompatible bid protocol version')
            if bid.contract_count is None:
                bid.contract_count = self.getNewContractId(use_session)

            coin_from = Coins(offer.coin_from)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(offer.coin_to)
            bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

            secret = self.getContractSecret(bid_date, bid.contract_count)
            secret_hash = sha256(secret)

            pubkey_refund = self.getContractPubkey(bid_date, bid.contract_count)
            pkhash_refund = ci_from.pkh(pubkey_refund)

            if coin_from in (Coins.DCR, ):
                op_hash = OpCodes.OP_SHA256_DECRED
            else:
                op_hash = OpCodes.OP_SHA256

            if bid.initiate_tx is not None:
                self.log.warning('Initiate txn %s already exists for bid %s', bid.initiate_tx.txid, bid_id.hex())
                txid = bid.initiate_tx.txid
                script = bid.initiate_tx.script
            else:
                if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
                    sequence = ci_from.getExpectedSequence(offer.lock_type, offer.lock_value)
                    script = atomic_swap_1.buildContractScript(sequence, secret_hash, bid.pkhash_buyer, pkhash_refund, op_hash=op_hash)
                else:
                    if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                        lock_value = ci_from.getChainHeight() + offer.lock_value
                    else:
                        lock_value = self.getTime() + offer.lock_value
                    self.log.debug('Initiate %s lock_value %d %d', ci_from.coin_name(), offer.lock_value, lock_value)
                    script = atomic_swap_1.buildContractScript(lock_value, secret_hash, bid.pkhash_buyer, pkhash_refund, OpCodes.OP_CHECKLOCKTIMEVERIFY, op_hash=op_hash)

                bid.pkhash_seller = ci_to.pkh(pubkey_refund)

                prefunded_tx = self.getPreFundedTx(Concepts.OFFER, offer.offer_id, TxTypes.ITX_PRE_FUNDED, session=use_session)
                txn, lock_tx_vout = self.createInitiateTxn(coin_from, bid_id, bid, script, prefunded_tx)

                # Store the signed refund txn in case wallet is locked when refund is possible
                refund_txn = self.createRefundTxn(coin_from, txn, offer, bid, script, session=use_session)
                bid.initiate_txn_refund = bytes.fromhex(refund_txn)

                txid = ci_from.publishTx(bytes.fromhex(txn))
                self.log.debug('Submitted initiate txn %s to %s chain for bid %s', txid, ci_from.coin_name(), bid_id.hex())
                bid.initiate_tx = SwapTx(
                    bid_id=bid_id,
                    tx_type=TxTypes.ITX,
                    txid=bytes.fromhex(txid),
                    vout=lock_tx_vout,
                    tx_data=bytes.fromhex(txn),
                    script=script,
                )
                bid.setITxState(TxStates.TX_SENT)
                self.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.ITX_PUBLISHED, '', use_session)

                # Check non-bip68 final
                try:
                    txid = ci_from.publishTx(bid.initiate_txn_refund)
                    self.log.error('Submit refund_txn unexpectedly worked: ' + txid)
                except Exception as ex:
                    if ci_from.isTxNonFinalError(str(ex)) is False:
                        self.log.error('Submit refund_txn unexpected error' + str(ex))
                        raise ex

            if txid is not None:
                msg_buf = BidAcceptMessage()
                msg_buf.bid_msg_id = bid_id
                msg_buf.initiate_txid = bytes.fromhex(txid)
                msg_buf.contract_script = bytes(script)

                # pkh sent in script is hashed with sha256, Decred expects blake256
                if bid.pkhash_seller != pkhash_refund:
                    msg_buf.pkhash_seller = bid.pkhash_seller

                bid_bytes = msg_buf.to_bytes()
                payload_hex = str.format('{:02x}', MessageTypes.BID_ACCEPT) + bid_bytes.hex()

                msg_valid: int = self.getAcceptBidMsgValidTime(bid)
                accept_msg_id = self.sendSmsg(offer.addr_from, bid.bid_addr, payload_hex, msg_valid)

                self.addMessageLink(Concepts.BID, bid_id, MessageTypes.BID_ACCEPT, accept_msg_id, session=use_session)
                self.log.info('Sent BID_ACCEPT %s', accept_msg_id.hex())

                bid.setState(BidStates.BID_ACCEPTED)

                self.saveBidInSession(bid_id, bid, use_session)
                self.swaps_in_progress[bid_id] = (bid, offer)

        finally:
            if session is None:
                self.closeSession(use_session)

    def sendXmrSplitMessages(self, msg_type, addr_from: str, addr_to: str, bid_id: bytes, dleag: bytes, msg_valid: int, bid_msg_ids) -> None:
        msg_buf2 = XmrSplitMessage(
            msg_id=bid_id,
            msg_type=msg_type,
            sequence=1,
            dleag=dleag[16000:32000]
        )
        msg_bytes = msg_buf2.to_bytes()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
        bid_msg_ids[1] = self.sendSmsg(addr_from, addr_to, payload_hex, msg_valid)

        msg_buf3 = XmrSplitMessage(
            msg_id=bid_id,
            msg_type=msg_type,
            sequence=2,
            dleag=dleag[32000:]
        )
        msg_bytes = msg_buf3.to_bytes()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
        bid_msg_ids[2] = self.sendSmsg(addr_from, addr_to, payload_hex, msg_valid)

    def postXmrBid(self, offer_id: bytes, amount: int, addr_send_from: str = None, extra_options={}) -> bytes:
        # Bid to send bid.amount * bid.rate of coin_to in exchange for bid.amount of coin_from
        # Send MSG1L F -> L or MSG0F L -> F
        self.log.debug('postXmrBid %s', offer_id.hex())

        try:
            session = self.openSession()
            offer, xmr_offer = self.getXmrOffer(offer_id, session=session)

            ensure(offer, 'Offer not found: {}.'.format(offer_id.hex()))
            ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(offer_id.hex()))
            ensure(offer.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG, 'Incompatible offer protocol version')
            ensure(offer.expire_at > self.getTime(), 'Offer has expired')

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            valid_for_seconds: int = extra_options.get('valid_for_seconds', 60 * 10)

            amount, amount_to, bid_rate = self.setBidAmounts(amount, offer, extra_options, ci_from)

            bid_created_at: int = self.getTime()
            if offer.swap_type != SwapTypes.XMR_SWAP:
                raise ValueError('TODO: Unknown swap type ' + offer.swap_type.name)

            if not (self.debug and extra_options.get('debug_skip_validation', False)):
                self.validateBidValidTime(offer.swap_type, coin_from, coin_to, valid_for_seconds)
                self.validateBidAmount(offer, amount, bid_rate)

            self.checkCoinsReady(coin_from, coin_to)

            balance_to: int = ci_to.getSpendableBalance()
            ensure(balance_to > amount_to, '{} spendable balance is too low: {} < {}'.format(ci_to.coin_name(), ci_to.format_amount(balance_to), ci_to.format_amount(amount_to)))

            reverse_bid: bool = self.is_reverse_ads_bid(coin_from)
            if reverse_bid:
                reversed_rate: int = ci_to.make_int(amount / amount_to, r=1)

                msg_buf = ADSBidIntentMessage()
                msg_buf.protocol_version = PROTOCOL_VERSION_ADAPTOR_SIG
                msg_buf.offer_msg_id = offer_id
                msg_buf.time_valid = valid_for_seconds
                msg_buf.amount_from = amount
                msg_buf.amount_to = amount_to

                bid_bytes = msg_buf.to_bytes()
                payload_hex = str.format('{:02x}', MessageTypes.ADS_BID_LF) + bid_bytes.hex()

                xmr_swap = XmrSwap()
                xmr_swap.contract_count = self.getNewContractId(session)

                bid_addr = self.prepareSMSGAddress(addr_send_from, AddressTypes.BID, session)

                msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
                xmr_swap.bid_id = self.sendSmsg(bid_addr, offer.addr_from, payload_hex, msg_valid)

                bid = Bid(
                    protocol_version=msg_buf.protocol_version,
                    active_ind=1,
                    bid_id=xmr_swap.bid_id,
                    offer_id=offer_id,
                    amount=msg_buf.amount_to,
                    amount_to=msg_buf.amount_from,
                    rate=reversed_rate,
                    created_at=bid_created_at,
                    contract_count=xmr_swap.contract_count,
                    expire_at=bid_created_at + msg_buf.time_valid,
                    bid_addr=bid_addr,
                    was_sent=True,
                    was_received=False,
                )

                bid.setState(BidStates.BID_REQUEST_SENT)

                self.saveBidInSession(xmr_swap.bid_id, bid, session, xmr_swap)
                session.commit()

                self.log.info('Sent ADS_BID_LF %s', xmr_swap.bid_id.hex())
                return xmr_swap.bid_id

            msg_buf = XmrBidMessage()
            msg_buf.protocol_version = PROTOCOL_VERSION_ADAPTOR_SIG
            msg_buf.offer_msg_id = offer_id
            msg_buf.time_valid = valid_for_seconds
            msg_buf.amount = int(amount)  # Amount of coin_from
            msg_buf.amount_to = amount_to

            address_out = self.getReceiveAddressFromPool(coin_from, offer_id, TxTypes.XMR_SWAP_A_LOCK, session=session)
            if coin_from in (Coins.PART_BLIND, ):
                addrinfo = ci_from.rpc('getaddressinfo', [address_out])
                msg_buf.dest_af = bytes.fromhex(addrinfo['pubkey'])
            else:
                msg_buf.dest_af = ci_from.decodeAddress(address_out)

            xmr_swap = XmrSwap()
            xmr_swap.contract_count = self.getNewContractId(session)
            xmr_swap.dest_af = msg_buf.dest_af

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbvf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, KeyTypes.KBVF, for_ed25519)
            kbsf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)

            kaf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, KeyTypes.KAF)

            xmr_swap.vkbvf = kbvf
            xmr_swap.pkbvf = ci_to.getPubkey(kbvf)
            xmr_swap.pkbsf = ci_to.getPubkey(kbsf)

            xmr_swap.pkaf = ci_from.getPubkey(kaf)

            if ci_to.curve_type() == Curves.ed25519:
                xmr_swap.kbsf_dleag = ci_to.proveDLEAG(kbsf)
                xmr_swap.pkasf = xmr_swap.kbsf_dleag[0: 33]
                msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag[:16000]
            elif ci_to.curve_type() == Curves.secp256k1:
                for i in range(10):
                    xmr_swap.kbsf_dleag = ci_to.signRecoverable(kbsf, 'proof kbsf owned for swap')
                    pk_recovered = ci_to.verifySigAndRecover(xmr_swap.kbsf_dleag, 'proof kbsf owned for swap')
                    if pk_recovered == xmr_swap.pkbsf:
                        break
                    self.log.debug('kbsl recovered pubkey mismatch, retrying.')
                assert (pk_recovered == xmr_swap.pkbsf)
                xmr_swap.pkasf = xmr_swap.pkbsf
                msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag
            else:
                raise ValueError('Unknown curve')
            assert (xmr_swap.pkasf == ci_from.getPubkey(kbsf))

            msg_buf.pkaf = xmr_swap.pkaf
            msg_buf.kbvf = kbvf

            bid_bytes = msg_buf.to_bytes()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_FL) + bid_bytes.hex()

            bid_addr = self.prepareSMSGAddress(addr_send_from, AddressTypes.BID, session)

            msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
            xmr_swap.bid_id = self.sendSmsg(bid_addr, offer.addr_from, payload_hex, msg_valid)

            bid_msg_ids = {}
            if ci_to.curve_type() == Curves.ed25519:
                self.sendXmrSplitMessages(XmrSplitMsgTypes.BID, bid_addr, offer.addr_from, xmr_swap.bid_id, xmr_swap.kbsf_dleag, msg_valid, bid_msg_ids)

            bid = Bid(
                protocol_version=msg_buf.protocol_version,
                active_ind=1,
                bid_id=xmr_swap.bid_id,
                offer_id=offer_id,
                amount=msg_buf.amount,
                amount_to=msg_buf.amount_to,
                rate=bid_rate,
                created_at=bid_created_at,
                contract_count=xmr_swap.contract_count,
                expire_at=bid_created_at + msg_buf.time_valid,
                bid_addr=bid_addr,
                was_sent=True,
            )

            bid.chain_a_height_start = ci_from.getChainHeight()
            bid.chain_b_height_start = ci_to.getChainHeight()

            wallet_restore_height = self.getWalletRestoreHeight(ci_to, session)
            if bid.chain_b_height_start < wallet_restore_height:
                bid.chain_b_height_start = wallet_restore_height
                self.log.warning('Adaptor-sig swap restore height clamped to {}'.format(wallet_restore_height))

            bid.setState(BidStates.BID_SENT)

            self.saveBidInSession(xmr_swap.bid_id, bid, session, xmr_swap)
            for k, msg_id in bid_msg_ids.items():
                self.addMessageLink(Concepts.BID, xmr_swap.bid_id, MessageTypes.BID, msg_id, msg_sequence=k, session=session)

            self.log.info('Sent XMR_BID_FL %s', xmr_swap.bid_id.hex())
            return xmr_swap.bid_id
        finally:
            self.closeSession(session)

    def acceptXmrBid(self, bid_id: bytes, session=None) -> None:
        # MSG1F and MSG2F L -> F
        self.log.info('Accepting adaptor-sig bid %s', bid_id.hex())

        now: int = self.getTime()
        try:
            use_session = self.openSession(session)
            bid, xmr_swap = self.getXmrBidFromSession(use_session, bid_id)
            ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
            ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))
            ensure(bid.expire_at > now, 'Bid expired')

            last_bid_state = bid.state
            if last_bid_state == BidStates.SWAP_DELAYING:
                last_bid_state = getLastBidState(bid.states)

            ensure(last_bid_state == BidStates.BID_RECEIVED, 'Wrong bid state: {}'.format(str(BidStates(last_bid_state))))

            offer, xmr_offer = self.getXmrOffer(bid.offer_id, session=use_session)
            ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(offer.expire_at > now, 'Offer has expired')

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
            coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
            coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate
            b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate

            if xmr_swap.contract_count is None:
                xmr_swap.contract_count = self.getNewContractId(use_session)

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
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

            # MSG2F
            pi = self.pi(SwapTypes.XMR_SWAP)
            xmr_swap.a_lock_tx_script = pi.genScriptLockTxScript(ci_from, xmr_swap.pkal, xmr_swap.pkaf)
            prefunded_tx = self.getPreFundedTx(Concepts.OFFER, bid.offer_id, TxTypes.ITX_PRE_FUNDED, session=use_session)
            if prefunded_tx:
                xmr_swap.a_lock_tx = pi.promoteMockTx(ci_from, prefunded_tx, xmr_swap.a_lock_tx_script)
            else:
                xmr_swap.a_lock_tx = ci_from.createSCLockTx(
                    bid.amount,
                    xmr_swap.a_lock_tx_script, xmr_swap.vkbv
                )
                xmr_swap.a_lock_tx = ci_from.fundSCLockTx(xmr_swap.a_lock_tx, a_fee_rate, xmr_swap.vkbv)

            xmr_swap.a_lock_tx_id = ci_from.getTxid(xmr_swap.a_lock_tx)
            a_lock_tx_dest = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)

            xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script, xmr_swap.a_swap_refund_value = ci_from.createSCLockRefundTx(
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.lock_time_1, xmr_offer.lock_time_2,
                a_fee_rate, xmr_swap.vkbv
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
                a_fee_rate, xmr_swap.vkbv
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
                a_fee_rate,
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
                a_fee_rate,
                xmr_swap.vkbv)

            ci_from.verifySCLockRefundSpendTx(
                xmr_swap.a_lock_refund_spend_tx, xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_id, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.pkal,
                lock_refund_vout, xmr_swap.a_swap_refund_value, a_fee_rate,
                xmr_swap.vkbv)

            msg_buf = XmrBidAcceptMessage()
            msg_buf.bid_msg_id = bid_id
            msg_buf.pkal = xmr_swap.pkal
            msg_buf.kbvl = kbvl

            if ci_to.curve_type() == Curves.ed25519:
                xmr_swap.kbsl_dleag = ci_to.proveDLEAG(kbsl)
                msg_buf.kbsl_dleag = xmr_swap.kbsl_dleag[:16000]
            elif ci_to.curve_type() == Curves.secp256k1:
                for i in range(10):
                    xmr_swap.kbsl_dleag = ci_to.signRecoverable(kbsl, 'proof kbsl owned for swap')
                    pk_recovered = ci_to.verifySigAndRecover(xmr_swap.kbsl_dleag, 'proof kbsl owned for swap')
                    if pk_recovered == xmr_swap.pkbsl:
                        break
                    self.log.debug('kbsl recovered pubkey mismatch, retrying.')
                assert (pk_recovered == xmr_swap.pkbsl)
                msg_buf.kbsl_dleag = xmr_swap.kbsl_dleag
            else:
                raise ValueError('Unknown curve')

            # MSG2F
            msg_buf.a_lock_tx = xmr_swap.a_lock_tx
            msg_buf.a_lock_tx_script = xmr_swap.a_lock_tx_script
            msg_buf.a_lock_refund_tx = xmr_swap.a_lock_refund_tx
            msg_buf.a_lock_refund_tx_script = bytes(xmr_swap.a_lock_refund_tx_script)
            msg_buf.a_lock_refund_spend_tx = xmr_swap.a_lock_refund_spend_tx
            msg_buf.al_lock_refund_tx_sig = xmr_swap.al_lock_refund_tx_sig

            msg_bytes = msg_buf.to_bytes()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_ACCEPT_LF) + msg_bytes.hex()

            addr_from: str = bid.bid_addr if reverse_bid else offer.addr_from
            addr_to: str = offer.addr_from if reverse_bid else bid.bid_addr

            msg_valid: int = self.getAcceptBidMsgValidTime(bid)
            bid_msg_ids = {}
            bid_msg_ids[0] = self.sendSmsg(addr_from, addr_to, payload_hex, msg_valid)

            if ci_to.curve_type() == Curves.ed25519:
                self.sendXmrSplitMessages(XmrSplitMsgTypes.BID_ACCEPT, addr_from, addr_to, xmr_swap.bid_id, xmr_swap.kbsl_dleag, msg_valid, bid_msg_ids)

            bid.setState(BidStates.BID_ACCEPTED)  # ADS

            self.saveBidInSession(bid_id, bid, use_session, xmr_swap=xmr_swap)
            for k, msg_id in bid_msg_ids.items():
                self.addMessageLink(Concepts.BID, bid_id, MessageTypes.BID_ACCEPT, msg_id, msg_sequence=k, session=use_session)

            # Add to swaps_in_progress only when waiting on txns
            self.log.info('Sent XMR_BID_ACCEPT_LF %s', bid_id.hex())
            return bid_id
        finally:
            if session is None:
                self.closeSession(use_session)

    def acceptADSReverseBid(self, bid_id: bytes, session=None) -> None:
        self.log.info('Accepting reverse adaptor-sig bid %s', bid_id.hex())

        now: int = self.getTime()
        try:
            use_session = self.openSession(session)
            bid, xmr_swap = self.getXmrBidFromSession(use_session, bid_id)
            ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
            ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))
            ensure(bid.expire_at > now, 'Bid expired')

            last_bid_state = bid.state
            if last_bid_state == BidStates.SWAP_DELAYING:
                last_bid_state = getLastBidState(bid.states)

            ensure(last_bid_state == BidStates.BID_RECEIVED, 'Wrong bid state: {}'.format(str(BidStates(last_bid_state))))

            offer, xmr_offer = self.getXmrOffer(bid.offer_id, session=use_session)
            ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(offer.expire_at > now, 'Offer has expired')

            # Bid is reversed
            coin_from = Coins(offer.coin_to)
            coin_to = Coins(offer.coin_from)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            if xmr_swap.contract_count is None:
                xmr_swap.contract_count = self.getNewContractId(use_session)

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbvf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBVF, for_ed25519)
            kbsf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)

            kaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF)

            address_out = self.getReceiveAddressFromPool(coin_from, bid.offer_id, TxTypes.XMR_SWAP_A_LOCK, session=use_session)
            if coin_from == Coins.PART_BLIND:
                addrinfo = ci_from.rpc('getaddressinfo', [address_out])
                xmr_swap.dest_af = bytes.fromhex(addrinfo['pubkey'])
            else:
                xmr_swap.dest_af = ci_from.decodeAddress(address_out)

            xmr_swap.vkbvf = kbvf
            xmr_swap.pkbvf = ci_to.getPubkey(kbvf)
            xmr_swap.pkbsf = ci_to.getPubkey(kbsf)

            xmr_swap.pkaf = ci_from.getPubkey(kaf)

            xmr_swap_1.setDLEAG(xmr_swap, ci_to, kbsf)
            assert (xmr_swap.pkasf == ci_from.getPubkey(kbsf))

            msg_buf = ADSBidIntentAcceptMessage()
            msg_buf.bid_msg_id = bid_id
            msg_buf.dest_af = xmr_swap.dest_af
            msg_buf.pkaf = xmr_swap.pkaf
            msg_buf.kbvf = kbvf
            msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag if len(xmr_swap.kbsf_dleag) < 16000 else xmr_swap.kbsf_dleag[:16000]

            bid_bytes = msg_buf.to_bytes()
            payload_hex = str.format('{:02x}', MessageTypes.ADS_BID_ACCEPT_FL) + bid_bytes.hex()

            addr_from: str = offer.addr_from
            addr_to: str = bid.bid_addr
            msg_valid: int = self.getAcceptBidMsgValidTime(bid)
            bid_msg_ids = {}
            bid_msg_ids[0] = self.sendSmsg(addr_from, addr_to, payload_hex, msg_valid)

            if ci_to.curve_type() == Curves.ed25519:
                self.sendXmrSplitMessages(XmrSplitMsgTypes.BID, addr_from, addr_to, xmr_swap.bid_id, xmr_swap.kbsf_dleag, msg_valid, bid_msg_ids)

            bid.setState(BidStates.BID_REQUEST_ACCEPTED)

            for k, msg_id in bid_msg_ids.items():
                self.addMessageLink(Concepts.BID, bid_id, MessageTypes.ADS_BID_ACCEPT_FL, msg_id, msg_sequence=k, session=use_session)
            self.log.info('Sent ADS_BID_ACCEPT_FL %s', bid_msg_ids[0].hex())
            self.saveBidInSession(bid_id, bid, use_session, xmr_swap=xmr_swap)
        finally:
            if session is None:
                self.closeSession(use_session)

    def deactivateBidForReason(self, bid_id: bytes, new_state, session_in=None) -> None:
        try:
            session = self.openSession(session_in)
            bid = session.query(Bid).filter_by(bid_id=bid_id).first()
            ensure(bid, 'Bid not found')
            offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
            ensure(offer, 'Offer not found')

            bid.setState(new_state)
            self.deactivateBid(session, offer, bid)
            session.add(bid)
            session.commit()
        finally:
            if session_in is None:
                self.closeSession(session)

    def abandonBid(self, bid_id: bytes) -> None:
        if not self.debug:
            self.log.error('Can\'t abandon bid %s when not in debug mode.', bid_id.hex())
            return

        self.log.info('Abandoning Bid %s', bid_id.hex())
        self.deactivateBidForReason(bid_id, BidStates.BID_ABANDONED)

    def timeoutBid(self, bid_id: bytes, session_in=None) -> None:
        self.log.info('Bid %s timed-out', bid_id.hex())
        self.deactivateBidForReason(bid_id, BidStates.SWAP_TIMEDOUT, session_in=session_in)

    def setBidError(self, bid_id: bytes, bid, error_str: str, save_bid: bool = True, xmr_swap=None) -> None:
        self.log.error('Bid %s - Error: %s', bid_id.hex(), error_str)
        bid.setState(BidStates.BID_ERROR)
        bid.state_note = 'error msg: ' + error_str
        if save_bid:
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

    def createInitiateTxn(self, coin_type, bid_id: bytes, bid, initiate_script, prefunded_tx=None) -> (Optional[str], Optional[int]):
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None, None
        ci = self.ci(coin_type)

        if ci.using_segwit():
            p2wsh = ci.getScriptDest(initiate_script)
            addr_to = ci.encodeScriptDest(p2wsh)
        else:
            addr_to = ci.encode_p2sh(initiate_script)
        self.log.debug('Create initiate txn for coin %s to %s for bid %s', Coins(coin_type).name, addr_to, bid_id.hex())

        if prefunded_tx:
            pi = self.pi(SwapTypes.SELLER_FIRST)
            txn_signed = pi.promoteMockTx(ci, prefunded_tx, initiate_script).hex()
        else:
            txn_signed = ci.createRawSignedTransaction(addr_to, bid.amount)

        txjs = ci.describeTx(txn_signed)
        vout = getVoutByAddress(txjs, addr_to)
        assert (vout is not None)

        return txn_signed, vout

    def deriveParticipateScript(self, bid_id: bytes, bid, offer) -> bytearray:
        self.log.debug('deriveParticipateScript for bid %s', bid_id.hex())

        coin_to = Coins(offer.coin_to)
        ci_to = self.ci(coin_to)

        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        pkhash_seller = bid.pkhash_seller

        if bid.pkhash_buyer_to and len(bid.pkhash_buyer_to) > 0:
            pkhash_buyer_refund = bid.pkhash_buyer_to
        else:
            pkhash_buyer_refund = bid.pkhash_buyer

        if coin_to in (Coins.DCR, ):
            op_hash = OpCodes.OP_SHA256_DECRED
        else:
            op_hash = OpCodes.OP_SHA256

        # Participate txn is locked for half the time of the initiate txn
        lock_value = offer.lock_value // 2
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = ci_to.getExpectedSequence(offer.lock_type, lock_value)
            participate_script = atomic_swap_1.buildContractScript(sequence, secret_hash, pkhash_seller, pkhash_buyer_refund, op_hash=op_hash)
        else:
            # Lock from the height or time of the block containing the initiate txn
            coin_from = Coins(offer.coin_from)
            block_header = self.ci(coin_from).getBlockHeaderFromHeight(bid.initiate_tx.chain_height)
            initiate_tx_block_hash = block_header['hash']
            initiate_tx_block_time = block_header['time']
            if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                # Walk the coin_to chain back until block time matches
                block_header_at = ci_to.getBlockHeaderAt(initiate_tx_block_time, block_after=True)
                cblock_hash = block_header_at['hash']
                cblock_height = block_header_at['height']

                self.log.debug('Setting lock value from height of block %s %s', Coins(coin_to).name, cblock_hash)
                contract_lock_value = cblock_height + lock_value
            else:
                self.log.debug('Setting lock value from time of block %s %s', Coins(coin_from).name, initiate_tx_block_hash)
                contract_lock_value = initiate_tx_block_time + lock_value
            self.log.debug('participate %s lock_value %d %d', Coins(coin_to).name, lock_value, contract_lock_value)
            participate_script = atomic_swap_1.buildContractScript(contract_lock_value, secret_hash, pkhash_seller, pkhash_buyer_refund, OpCodes.OP_CHECKLOCKTIMEVERIFY, op_hash=op_hash)
        return participate_script

    def createParticipateTxn(self, bid_id: bytes, bid, offer, participate_script: bytearray):
        self.log.debug('createParticipateTxn')

        offer_id = bid.offer_id
        coin_to = Coins(offer.coin_to)

        if self.coin_clients[coin_to]['connection_type'] != 'rpc':
            return None
        ci = self.ci(coin_to)

        amount_to: int = bid.amount_to

        if bid.debug_ind == DebugTypes.MAKE_INVALID_PTX:
            amount_to -= 1
            self.log.debug('bid %s: Make invalid PTx for testing: %d.', bid_id.hex(), bid.debug_ind)
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), None)

        if ci.using_segwit():
            p2wsh = ci.getScriptDest(participate_script)
            addr_to = ci.encodeScriptDest(p2wsh)
        else:
            addr_to = ci.encode_p2sh(participate_script)

        txn_signed = ci.createRawSignedTransaction(addr_to, amount_to)

        refund_txn = self.createRefundTxn(coin_to, txn_signed, offer, bid, participate_script, tx_type=TxTypes.PTX_REFUND)
        bid.participate_txn_refund = bytes.fromhex(refund_txn)

        chain_height = ci.getChainHeight()
        txjs = self.callcoinrpc(coin_to, 'decoderawtransaction', [txn_signed])
        txid = txjs['txid']

        if ci.using_segwit():
            vout = getVoutByScriptPubKey(txjs, p2wsh.hex())
        else:
            vout = getVoutByAddress(txjs, addr_to)
        self.addParticipateTxn(bid_id, bid, coin_to, txid, vout, chain_height)
        bid.participate_tx.script = participate_script
        bid.participate_tx.tx_data = bytes.fromhex(txn_signed)

        return txn_signed

    def createRedeemTxn(self, coin_type, bid, for_txn_type='participate', addr_redeem_out=None, fee_rate=None, session=None):
        self.log.debug('createRedeemTxn for coin %s', Coins(coin_type).name)
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

        if ci.using_segwit():
            prev_p2wsh = ci.getScriptDest(txn_script)
            script_pub_key = prev_p2wsh.hex()
        else:
            script_pub_key = getP2SHScriptForHash(ci.pkh(txn_script)).hex()

        prevout = {
            'txid': prev_txnid,
            'vout': prev_n,
            'scriptPubKey': script_pub_key,
            'redeemScript': txn_script.hex(),
            'amount': ci.format_amount(prev_amount)}

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        privkey = self.getContractPrivkey(bid_date, bid.contract_count)
        pubkey = ci.getPubkey(privkey)

        secret = bid.recovered_secret
        if secret is None:
            secret = self.getContractSecret(bid_date, bid.contract_count)
        ensure(len(secret) == 32, 'Bad secret length')

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None

        if fee_rate is None:
            fee_rate, fee_src = self.getFeeRateForCoin(coin_type)

        tx_vsize = ci.getHTLCSpendTxVSize()
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug('Redeem tx fee %s, rate %s', ci.format_amount(tx_fee, conv_int=True, r=1), str(fee_rate))

        amount_out = prev_amount - ci.make_int(tx_fee, r=1)
        ensure(amount_out > 0, 'Amount out <= 0')

        if addr_redeem_out is None:
            addr_redeem_out = self.getReceiveAddressFromPool(coin_type, bid.bid_id, TxTypes.PTX_REDEEM if for_txn_type == 'participate' else TxTypes.ITX_REDEEM, session)
        assert (addr_redeem_out is not None)

        self.log.debug('addr_redeem_out %s', addr_redeem_out)

        redeem_txn = ci.createRedeemTxn(prevout, addr_redeem_out, amount_out, txn_script)
        options = {}
        if ci.using_segwit():
            options['force_segwit'] = True

        if coin_type in (Coins.NAV, Coins.DCR):
            privkey_wif = self.ci(coin_type).encodeKey(privkey)
            redeem_sig = ci.getTxSignature(redeem_txn, prevout, privkey_wif)
        else:
            privkey_wif = self.ci(Coins.PART).encodeKey(privkey)
            redeem_sig = self.callcoinrpc(Coins.PART, 'createsignaturewithkey', [redeem_txn, prevout, privkey_wif, 'ALL', options])

        if coin_type == Coins.PART or ci.using_segwit():
            witness_stack = [
                bytes.fromhex(redeem_sig),
                pubkey,
                secret,
                bytes((1,)),  # Converted to OP_1 in Decred push_script_data
                txn_script]
            redeem_txn = ci.setTxSignature(bytes.fromhex(redeem_txn), witness_stack).hex()
        else:
            script = (len(redeem_sig) // 2).to_bytes(1, 'big') + bytes.fromhex(redeem_sig)
            script += (33).to_bytes(1, 'big') + pubkey
            script += (32).to_bytes(1, 'big') + secret
            script += (OpCodes.OP_1).to_bytes(1, 'big')
            script += (OpCodes.OP_PUSHDATA1).to_bytes(1, 'big') + (len(txn_script)).to_bytes(1, 'big') + txn_script
            redeem_txn = ci.setTxScriptSig(bytes.fromhex(redeem_txn), 0, script).hex()

        if coin_type in (Coins.NAV, Coins.DCR):
            # Only checks signature
            ro = ci.verifyRawTransaction(redeem_txn, [prevout])
        else:
            ro = self.callcoinrpc(Coins.PART, 'verifyrawtransaction', [redeem_txn, [prevout]])

        ensure(ro['inputs_valid'] is True, 'inputs_valid is false')
        # outputs_valid will be false if not a Particl txn
        # ensure(ro['complete'] is True, 'complete is false')
        ensure(ro['validscripts'] == 1, 'validscripts != 1')

        if self.debug:
            # Check fee
            if ci.get_connection_type() == 'rpc':
                redeem_txjs = self.callcoinrpc(coin_type, 'decoderawtransaction', [redeem_txn])
                if coin_type in (Coins.DCR, ):
                    txsize = len(redeem_txn) // 2
                    self.log.debug('size paid, actual size %d %d', tx_vsize, txsize)
                    ensure(tx_vsize >= txsize, 'underpaid fee')
                elif ci.use_tx_vsize():
                    self.log.debug('vsize paid, actual vsize %d %d', tx_vsize, redeem_txjs['vsize'])
                    ensure(tx_vsize >= redeem_txjs['vsize'], 'underpaid fee')
                else:
                    self.log.debug('size paid, actual size %d %d', tx_vsize, redeem_txjs['size'])
                    ensure(tx_vsize >= redeem_txjs['size'], 'underpaid fee')

            redeem_txid = ci.getTxid(bytes.fromhex(redeem_txn))
            self.log.debug('Have valid redeem txn %s for contract %s tx %s', redeem_txid.hex(), for_txn_type, prev_txnid)
        return redeem_txn

    def createRefundTxn(self, coin_type, txn, offer, bid, txn_script: bytearray, addr_refund_out=None, tx_type=TxTypes.ITX_REFUND, session=None):
        self.log.debug('createRefundTxn for coin %s', Coins(coin_type).name)
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None

        ci = self.ci(coin_type)
        if coin_type in (Coins.NAV, Coins.DCR):
            prevout = ci.find_prevout_info(txn, txn_script)
        else:
            # TODO: Sign in bsx for all coins
            txjs = self.callcoinrpc(Coins.PART, 'decoderawtransaction', [txn])
            if ci.using_segwit():
                p2wsh = ci.getScriptDest(txn_script)
                vout = getVoutByScriptPubKey(txjs, p2wsh.hex())
            else:
                addr_to = self.ci(Coins.PART).encode_p2sh(txn_script)
                vout = getVoutByAddress(txjs, addr_to)

            prevout = {
                'txid': txjs['txid'],
                'vout': vout,
                'scriptPubKey': txjs['vout'][vout]['scriptPubKey']['hex'],
                'redeemScript': txn_script.hex(),
                'amount': txjs['vout'][vout]['value']
            }

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

        privkey = self.getContractPrivkey(bid_date, bid.contract_count)
        pubkey = ci.getPubkey(privkey)

        lock_value = DeserialiseNum(txn_script, 64)
        sequence: int = 1
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = lock_value

        fee_rate, fee_src = self.getFeeRateForCoin(coin_type)

        tx_vsize = ci.getHTLCSpendTxVSize(False)
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug('Refund tx fee %s, rate %s', ci.format_amount(tx_fee, conv_int=True, r=1), str(fee_rate))

        amount_out = ci.make_int(prevout['amount'], r=1) - ci.make_int(tx_fee, r=1)
        if amount_out <= 0:
            raise ValueError('Refund amount out <= 0')

        if addr_refund_out is None:
            addr_refund_out = self.getReceiveAddressFromPool(coin_type, bid.bid_id, tx_type, session)
        ensure(addr_refund_out is not None, 'addr_refund_out is null')
        self.log.debug('addr_refund_out %s', addr_refund_out)

        locktime: int = 0
        if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS or offer.lock_type == TxLockTypes.ABS_LOCK_TIME:
            locktime = lock_value

        refund_txn = ci.createRefundTxn(prevout, addr_refund_out, amount_out, locktime, sequence, txn_script)

        options = {}
        if self.coin_clients[coin_type]['use_segwit']:
            options['force_segwit'] = True
        if coin_type in (Coins.NAV, Coins.DCR):
            privkey_wif = ci.encodeKey(privkey)
            refund_sig = ci.getTxSignature(refund_txn, prevout, privkey_wif)
        else:
            privkey_wif = self.ci(Coins.PART).encodeKey(privkey)
            refund_sig = self.callcoinrpc(Coins.PART, 'createsignaturewithkey', [refund_txn, prevout, privkey_wif, 'ALL', options])
        if coin_type in (Coins.PART, Coins.DCR) or self.coin_clients[coin_type]['use_segwit']:
            witness_stack = [
                bytes.fromhex(refund_sig),
                pubkey,
                b'',
                txn_script]
            refund_txn = ci.setTxSignature(bytes.fromhex(refund_txn), witness_stack).hex()
        else:
            script = (len(refund_sig) // 2).to_bytes(1, 'big') + bytes.fromhex(refund_sig)
            script += (33).to_bytes(1, 'big') + pubkey
            script += (OpCodes.OP_0).to_bytes(1, 'big')
            script += (OpCodes.OP_PUSHDATA1).to_bytes(1, 'big') + (len(txn_script)).to_bytes(1, 'big') + txn_script
            refund_txn = ci.setTxScriptSig(bytes.fromhex(refund_txn), 0, script)

        if coin_type in (Coins.NAV, Coins.DCR):
            # Only checks signature
            ro = ci.verifyRawTransaction(refund_txn, [prevout])
        else:
            ro = self.callcoinrpc(Coins.PART, 'verifyrawtransaction', [refund_txn, [prevout]])

        ensure(ro['inputs_valid'] is True, 'inputs_valid is false')
        # outputs_valid will be false if not a Particl txn
        # ensure(ro['complete'] is True, 'complete is false')
        ensure(ro['validscripts'] == 1, 'validscripts != 1')

        if self.debug:
            # Check fee
            if ci.get_connection_type() == 'rpc':
                refund_txjs = self.callcoinrpc(coin_type, 'decoderawtransaction', [refund_txn,])
                if coin_type in (Coins.DCR, ):
                    txsize = len(refund_txn) // 2
                    self.log.debug('size paid, actual size %d %d', tx_vsize, txsize)
                    ensure(tx_vsize >= txsize, 'underpaid fee')
                elif ci.use_tx_vsize():
                    self.log.debug('vsize paid, actual vsize %d %d', tx_vsize, refund_txjs['vsize'])
                    ensure(tx_vsize >= refund_txjs['vsize'], 'underpaid fee')
                else:
                    self.log.debug('size paid, actual size %d %d', tx_vsize, refund_txjs['size'])
                    ensure(tx_vsize >= refund_txjs['size'], 'underpaid fee')

            refund_txid = ci.getTxid(bytes.fromhex(refund_txn))
            prev_txid = ci.getTxid(bytes.fromhex(txn))
            self.log.debug('Have valid refund txn %s for contract tx %s', refund_txid.hex(), prev_txid.hex())

        return refund_txn

    def initiateTxnConfirmed(self, bid_id: bytes, bid, offer) -> None:
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
                self.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.PTX_PUBLISHED, '', None)
        else:
            bid.participate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.PTX,
                script=participate_script,
            )
            ci = self.ci(offer.coin_to)
            if ci.watch_blocks_for_scripts() is True:
                chain_a_block_header = self.ci(offer.coin_from).getBlockHeaderFromHeight(bid.initiate_tx.chain_height)
                chain_b_block_header = self.ci(offer.coin_to).getBlockHeaderAt(chain_a_block_header['time'])
                self.setLastHeightCheckedStart(offer.coin_to, chain_b_block_header['height'])
                self.addWatchedScript(offer.coin_to, bid_id, ci.getScriptDest(participate_script), TxTypes.PTX)

        # Bid saved in checkBidState

    def setLastHeightCheckedStart(self, coin_type, tx_height: int, session=None) -> int:
        ci = self.ci(coin_type)
        coin_name = ci.coin_name()
        if tx_height < 1:
            tx_height = self.lookupChainHeight(coin_type)

        block_header = ci.getBlockHeaderFromHeight(tx_height)
        block_time = block_header['time']
        cc = self.coin_clients[coin_type]
        if len(cc['watched_outputs']) == 0 and len(cc['watched_scripts']) == 0:
            cc['last_height_checked'] = tx_height
            cc['block_check_min_time'] = block_time
            self.setIntKV('block_check_min_time_' + coin_name, block_time, session)
            self.log.debug('Start checking %s chain at height %d', coin_name, tx_height)
        elif cc['last_height_checked'] > tx_height:
            cc['last_height_checked'] = tx_height
            cc['block_check_min_time'] = block_time
            self.setIntKV('block_check_min_time_' + coin_name, block_time, session)
            self.log.debug('Rewind %s chain last height checked to %d', coin_name, tx_height)
        else:
            self.log.debug('Not setting %s chain last height checked to %d, leaving on %d', coin_name, tx_height, cc['last_height_checked'])

        return tx_height

    def addParticipateTxn(self, bid_id: bytes, bid, coin_type, txid_hex: str, vout, tx_height) -> None:

        # TODO: Check connection type
        participate_txn_height = self.setLastHeightCheckedStart(coin_type, tx_height)

        if bid.participate_tx is None:
            bid.participate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.PTX,
            )
        bid.participate_tx.txid = bytes.fromhex(txid_hex)
        bid.participate_tx.vout = vout
        bid.participate_tx.chain_height = participate_txn_height

        # Start checking for spends of participate_txn before fully confirmed
        ci = self.ci(coin_type)
        self.log.debug('Watching %s chain for spend of output %s %d', ci.coin_name().lower(), txid_hex, vout)
        self.addWatchedOutput(coin_type, bid_id, txid_hex, vout, BidStates.SWAP_PARTICIPATING)

    def participateTxnConfirmed(self, bid_id: bytes, bid, offer) -> None:
        self.log.debug('participateTxnConfirmed for bid %s', bid_id.hex())

        if bid.debug_ind == DebugTypes.DONT_CONFIRM_PTX:
            self.log.debug('Not confirming PTX for debugging', bid_id.hex())
            return

        bid.setState(BidStates.SWAP_PARTICIPATING)
        bid.setPTxState(TxStates.TX_CONFIRMED)

        # Seller redeems from participate txn
        if bid.was_received:
            ci_to = self.ci(offer.coin_to)
            txn = self.createRedeemTxn(ci_to.coin_type(), bid)
            txid = ci_to.publishTx(bytes.fromhex(txn))
            self.log.debug('Submitted participate redeem txn %s to %s chain for bid %s', txid, ci_to.coin_name(), bid_id.hex())
            self.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.PTX_REDEEM_PUBLISHED, '', None)
            # TX_REDEEMED will be set when spend is detected
            # TODO: Wait for depth?

        # bid saved in checkBidState

    def getAddressBalance(self, coin_type, address: str) -> int:
        if self.coin_clients[coin_type]['chain_lookups'] == 'explorer':
            explorers = self.coin_clients[coin_type]['explorers']

            # TODO: random offset into explorers, try blocks
            for exp in explorers:
                return exp.getBalance(address)
        return self.lookupUnspentByAddress(coin_type, address, sum_output=True)

    def lookupChainHeight(self, coin_type) -> int:
        return self.callcoinrpc(coin_type, 'getblockcount')

    def lookupUnspentByAddress(self, coin_type, address: str, sum_output: bool = False, assert_amount=None, assert_txid=None) -> int:

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

            raise ValueError('No explorer for lookupUnspentByAddress {}'.format(Coins(coin_type).name))

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            raise ValueError('No RPC connection for lookupUnspentByAddress {}'.format(Coins(coin_type).name))

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

    def findTxB(self, ci_to, xmr_swap, bid, session, bid_sender: bool) -> bool:
        bid_changed = False

        found_tx = None
        if ci_to.coin_type() in (Coins.DCR, ):
            if bid.xmr_b_lock_tx is None or bid.xmr_b_lock_tx.txid is None:
                # Watching chain for dest_address with WatchedScript
                pass
            else:
                dest_address = ci_to.pkh_to_address(ci_to.pkh(xmr_swap.pkbs))
                found_tx = ci_to.getLockTxHeight(bid.xmr_b_lock_tx.txid, dest_address, bid.amount_to, bid.chain_b_height_start, vout=bid.xmr_b_lock_tx.vout)
        else:
            # Have to use findTxB instead of relying on the first seen height to detect chain reorgs
            found_tx = ci_to.findTxB(xmr_swap.vkbv, xmr_swap.pkbs, bid.amount_to, ci_to.blocks_confirmed, bid.chain_b_height_start, bid_sender)

        if isinstance(found_tx, int) and found_tx == -1:
            if self.countBidEvents(bid, EventLogTypes.LOCK_TX_B_INVALID, session) < 1:
                self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_INVALID, 'Detected invalid lock tx B', session)
                bid_changed = True
        elif found_tx is not None:
            if found_tx['height'] != 0 and (bid.xmr_b_lock_tx is None or not bid.xmr_b_lock_tx.chain_height):
                self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_SEEN, '', session)

            if bid.xmr_b_lock_tx is None or bid.xmr_b_lock_tx.chain_height is None:
                self.log.debug('Found {} lock tx in chain'.format(ci_to.coin_name()))
                xmr_swap.b_lock_tx_id = bytes.fromhex(found_tx['txid'])
            if bid.xmr_b_lock_tx is None:
                bid.xmr_b_lock_tx = SwapTx(
                    bid_id=bid.bid_id,
                    tx_type=TxTypes.XMR_SWAP_B_LOCK,
                    txid=xmr_swap.b_lock_tx_id,
                )
            bid.xmr_b_lock_tx.chain_height = found_tx['height']
            bid_changed = True
        return bid_changed

    def checkXmrBidState(self, bid_id: bytes, bid, offer):
        rv = False

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)

        was_sent: bool = bid.was_received if reverse_bid else bid.was_sent
        was_received: bool = bid.was_sent if reverse_bid else bid.was_received

        session = None
        try:
            session = self.openSession()
            xmr_offer = session.query(XmrOffer).filter_by(offer_id=offer.offer_id).first()
            ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(offer.offer_id.hex()))
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
            ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid.bid_id.hex()))

            if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                refund_tx = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND]
                if was_received:
                    if bid.debug_ind == DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND:
                        self.log.debug('Adaptor-sig bid %s: Stalling bid for testing: %d.', bid_id.hex(), bid.debug_ind)
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

                if was_sent:
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
                        if ci_from.isTxExistsError(str(ex)):
                            self.log.info('Found coin a lock refund tx for bid {}'.format(bid_id.hex()))
                            txid = ci_from.getTxid(xmr_swap.a_lock_refund_tx)
                            if TxTypes.XMR_SWAP_A_LOCK_REFUND not in bid.txns:
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
            elif state == BidStates.XMR_SWAP_FAILED:
                if was_sent and bid.xmr_b_lock_tx:
                    if self.countQueuedActions(session, bid_id, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B) < 1:
                        delay = self.get_delay_event_seconds()
                        self.log.info('Recovering adaptor-sig swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createActionInSession(delay, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, session)
                        session.commit()
            elif state == BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX:
                if bid.xmr_a_lock_tx is None:
                    return rv

                # TODO: Timeout waiting for transactions
                bid_changed: bool = False
                a_lock_tx_addr = ci_from.getSCLockScriptAddress(xmr_swap.a_lock_tx_script)
                lock_tx_chain_info = ci_from.getLockTxHeight(bid.xmr_a_lock_tx.txid, a_lock_tx_addr, bid.amount, bid.chain_a_height_start, vout=bid.xmr_a_lock_tx.vout)

                if lock_tx_chain_info is None:
                    return rv

                if bid.xmr_a_lock_tx.state == TxStates.TX_NONE and lock_tx_chain_info['height'] == 0:
                    bid.xmr_a_lock_tx.setState(TxStates.TX_IN_MEMPOOL)

                if not bid.xmr_a_lock_tx.chain_height and lock_tx_chain_info['height'] != 0:
                    self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_SEEN, '', session)
                    self.setTxBlockInfoFromHeight(ci_from, bid.xmr_a_lock_tx, lock_tx_chain_info['height'])
                    bid.xmr_a_lock_tx.setState(TxStates.TX_IN_CHAIN)

                    bid_changed = True
                if bid.xmr_a_lock_tx.chain_height != lock_tx_chain_info['height'] and lock_tx_chain_info['height'] != 0:
                    bid.xmr_a_lock_tx.chain_height = lock_tx_chain_info['height']
                    bid_changed = True

                if lock_tx_chain_info['depth'] >= ci_from.blocks_confirmed:
                    self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_CONFIRMED, '', session)
                    bid.xmr_a_lock_tx.setState(TxStates.TX_CONFIRMED)

                    bid.setState(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
                    bid_changed = True

                    if was_sent:
                        delay = self.get_delay_event_seconds()
                        self.log.info('Sending adaptor-sig swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createActionInSession(delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, bid_id, session)
                        # bid.setState(BidStates.SWAP_DELAYING)
                    elif ci_to.watch_blocks_for_scripts():
                        chain_a_block_header = ci_from.getBlockHeaderFromHeight(bid.xmr_a_lock_tx.chain_height)
                        block_time = chain_a_block_header['time']
                        chain_b_block_header = ci_to.getBlockHeaderAt(block_time)
                        self.log.debug('chain a block_time {}, chain b block height {}'.format(block_time, chain_b_block_header['height']))
                        dest_script = ci_to.getPkDest(xmr_swap.pkbs)
                        self.setLastHeightCheckedStart(ci_to.coin_type(), chain_b_block_header['height'], session)
                        self.addWatchedScript(ci_to.coin_type(), bid.bid_id, dest_script, TxTypes.XMR_SWAP_B_LOCK)

                if bid_changed:
                    self.saveBidInSession(bid_id, bid, session, xmr_swap)
                    session.commit()

            elif state == BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED:
                bid_changed = self.findTxB(ci_to, xmr_swap, bid, session, was_sent)

                if bid.xmr_b_lock_tx and bid.xmr_b_lock_tx.chain_height is not None and bid.xmr_b_lock_tx.chain_height > 0:
                    chain_height = ci_to.getChainHeight()

                    if chain_height - bid.xmr_b_lock_tx.chain_height >= ci_to.blocks_confirmed:
                        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_CONFIRMED, '', session)
                        bid.xmr_b_lock_tx.setState(TxStates.TX_CONFIRMED)
                        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)

                        if was_received:
                            delay = self.get_delay_event_seconds()
                            self.log.info('Releasing ads script coin lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                            self.createActionInSession(delay, ActionTypes.SEND_XMR_LOCK_RELEASE, bid_id, session)

                if bid_changed:
                    self.saveBidInSession(bid_id, bid, session, xmr_swap)
                    session.commit()
            elif state == BidStates.XMR_SWAP_LOCK_RELEASED:
                # Wait for script spend tx to confirm
                # TODO: Use explorer to get tx / block hash for getrawtransaction

                if was_received:
                    try:
                        txn_hex = ci_from.getMempoolTx(xmr_swap.a_lock_spend_tx_id)
                        self.log.info('Found lock spend txn in %s mempool, %s', ci_from.coin_name(), xmr_swap.a_lock_spend_tx_id.hex())
                        self.process_XMR_SWAP_A_LOCK_tx_spend(bid_id, xmr_swap.a_lock_spend_tx_id.hex(), txn_hex, session)
                    except Exception as e:
                        self.log.debug('getrawtransaction lock spend tx failed: %s', str(e))
            elif state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
                if was_received and self.countQueuedActions(session, bid_id, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B) < 1:
                    bid.setState(BidStates.SWAP_DELAYING)
                    delay = self.get_delay_event_seconds()
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
                        refund_tx_addr = ci_from.getSCLockScriptAddress(xmr_swap.a_lock_refund_tx_script)
                        lock_refund_tx_chain_info = ci_from.getLockTxHeight(refund_tx.txid, refund_tx_addr, 0, bid.chain_a_height_start, vout=refund_tx.vout)

                        if lock_refund_tx_chain_info is not None and lock_refund_tx_chain_info.get('height', 0) > 0:
                            self.setTxBlockInfoFromHeight(ci_from, refund_tx, lock_refund_tx_chain_info['height'])

                            self.saveBidInSession(bid_id, bid, session, xmr_swap)
                            session.commit()

        except Exception as ex:
            raise ex
        finally:
            self.closeSession(session)

        return rv

    def checkBidState(self, bid_id: bytes, bid, offer):
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
            index = None
            tx_height = None
            initiate_txnid_hex = bid.initiate_tx.txid.hex()
            last_initiate_txn_conf = bid.initiate_tx.conf
            ci_from = self.ci(coin_from)
            if coin_from == Coins.PART:  # Has txindex
                try:
                    p2sh = ci_from.encode_p2sh(bid.initiate_tx.script)
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
                if ci_from.using_segwit():
                    dest_script = ci_from.getScriptDest(bid.initiate_tx.script)
                    addr = ci_from.encodeScriptDest(dest_script)
                else:
                    addr = ci_from.encode_p2sh(bid.initiate_tx.script)

                found = ci_from.getLockTxHeight(bid.initiate_tx.txid, addr, bid.amount, bid.chain_a_height_start, find_index=True, vout=bid.initiate_tx.vout)
                index = None
                if found:
                    bid.initiate_tx.conf = found['depth']
                    if 'index' in found:
                        index = found['index']
                    tx_height = found['height']

            if bid.initiate_tx.conf != last_initiate_txn_conf:
                save_bid = True

            if bid.initiate_tx.vout is None and index is not None:
                bid.initiate_tx.vout = index
                save_bid = True

            if bid.initiate_tx.conf is not None:
                self.log.debug('initiate_txnid %s confirms %d', initiate_txnid_hex, bid.initiate_tx.conf)

                if (last_initiate_txn_conf is None or last_initiate_txn_conf < 1) and tx_height > 0:
                    # Start checking for spends of initiate_txn before fully confirmed
                    bid.initiate_tx.chain_height = self.setLastHeightCheckedStart(coin_from, tx_height)
                    self.setTxBlockInfoFromHeight(ci_from, bid.initiate_tx, tx_height)

                    self.addWatchedOutput(coin_from, bid_id, initiate_txnid_hex, bid.initiate_tx.vout, BidStates.SWAP_INITIATED)
                    if bid.getITxState() is None or bid.getITxState() < TxStates.TX_SENT:
                        bid.setITxState(TxStates.TX_SENT)
                    save_bid = True

                if bid.initiate_tx.conf >= self.coin_clients[coin_from]['blocks_confirmed']:
                    self.initiateTxnConfirmed(bid_id, bid, offer)
                    save_bid = True

            # Bid times out if buyer doesn't see tx in chain within INITIATE_TX_TIMEOUT seconds
            if bid.initiate_tx is None and \
               bid.state_time + atomic_swap_1.INITIATE_TX_TIMEOUT < self.getTime():
                self.log.info('Swap timed out waiting for initiate tx for bid %s', bid_id.hex())
                bid.setState(BidStates.SWAP_TIMEDOUT, 'Timed out waiting for initiate tx')
                self.saveBid(bid_id, bid)
                return True  # Mark bid for archiving
        elif state == BidStates.SWAP_INITIATED:
            # Waiting for participate txn to be confirmed in 'to' chain
            if ci_to.using_segwit():
                p2wsh = ci_to.getScriptDest(bid.participate_tx.script)
                addr = ci_to.encodeScriptDest(p2wsh)
            else:
                addr = ci_to.encode_p2sh(bid.participate_tx.script)

            ci_to = self.ci(coin_to)
            participate_txid = None if bid.participate_tx is None or bid.participate_tx.txid is None else bid.participate_tx.txid
            participate_txvout = None if bid.participate_tx is None or bid.participate_tx.vout is None else bid.participate_tx.vout
            found = ci_to.getLockTxHeight(participate_txid, addr, bid.amount_to, bid.chain_b_height_start, find_index=True, vout=participate_txvout)
            if found:
                index = found.get('index', participate_txvout)
                if bid.participate_tx.conf != found['depth']:
                    save_bid = True
                if bid.participate_tx.conf is None and bid.participate_tx.state != TxStates.TX_SENT:
                    txid = found.get('txid', None if participate_txid is None else participate_txid.hex())
                    self.log.debug('Found bid %s participate txn %s in chain %s', bid_id.hex(), txid, Coins(coin_to).name)
                    self.addParticipateTxn(bid_id, bid, coin_to, txid, index, found['height'])

                    # Only update tx state if tx hasn't already been seen
                    if bid.participate_tx.state is None or bid.participate_tx.state < TxStates.TX_SENT:
                        bid.setPTxState(TxStates.TX_SENT)

                bid.participate_tx.conf = found['depth']
                if found['height'] > 0 and bid.participate_tx.block_height is None:
                    self.setTxBlockInfoFromHeight(ci_to, bid.participate_tx, found['height'])

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
                self.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.ITX_REFUND_PUBLISHED, '', None)
                # State will update when spend is detected
            except Exception as ex:
                if ci_from.isTxNonFinalError(str(ex)) is False:
                    self.log.warning('Error trying to submit initiate refund txn: %s', str(ex))

        if bid.getPTxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED) \
           and bid.participate_txn_refund is not None:
            try:
                txid = ci_to.publishTx(bid.participate_txn_refund)
                self.log.debug('Submitted participate refund txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
                self.logEvent(Concepts.BID, bid.bid_id, EventLogTypes.PTX_REFUND_PUBLISHED, '', None)
                # State will update when spend is detected
            except Exception as ex:
                if ci_to.isTxNonFinalError(str(ex)):
                    self.log.warning('Error trying to submit participate refund txn: %s', str(ex))
        return False  # Bid is still active

    def extractSecret(self, coin_type, bid, spend_in):
        try:
            if coin_type in (Coins.DCR, ):
                script_sig = spend_in['scriptSig']['asm'].split(' ')
                ensure(len(script_sig) == 5, 'Bad witness size')
                return bytes.fromhex(script_sig[2])
            elif coin_type in (Coins.PART, ) or self.coin_clients[coin_type]['use_segwit']:
                ensure(len(spend_in['txinwitness']) == 5, 'Bad witness size')
                return bytes.fromhex(spend_in['txinwitness'][2])
            else:
                script_sig = spend_in['scriptSig']['asm'].split(' ')
                ensure(len(script_sig) == 5, 'Bad witness size')
                return bytes.fromhex(script_sig[2])
        except Exception:
            return None

    def addWatchedOutput(self, coin_type, bid_id, txid_hex, vout, tx_type, swap_type=None):
        self.log.debug('Adding watched output %s bid %s tx %s type %s', Coins(coin_type).name, bid_id.hex(), txid_hex, tx_type)

        watched = self.coin_clients[coin_type]['watched_outputs']

        for wo in watched:
            if wo.bid_id == bid_id and wo.txid_hex == txid_hex and wo.vout == vout:
                self.log.debug('Output already being watched.')
                return

        watched.append(WatchedOutput(bid_id, txid_hex, vout, tx_type, swap_type))

    def removeWatchedOutput(self, coin_type, bid_id: bytes, txid_hex: str) -> None:
        # Remove all for bid if txid is None
        self.log.debug('removeWatchedOutput %s %s %s', Coins(coin_type).name, bid_id.hex(), txid_hex)
        old_len = len(self.coin_clients[coin_type]['watched_outputs'])
        for i in range(old_len - 1, -1, -1):
            wo = self.coin_clients[coin_type]['watched_outputs'][i]
            if wo.bid_id == bid_id and (txid_hex is None or wo.txid_hex == txid_hex):
                del self.coin_clients[coin_type]['watched_outputs'][i]
                self.log.debug('Removed watched output %s %s %s', Coins(coin_type).name, bid_id.hex(), wo.txid_hex)

    def addWatchedScript(self, coin_type, bid_id, script, tx_type, swap_type=None):
        self.log.debug('Adding watched script %s bid %s type %s', Coins(coin_type).name, bid_id.hex(), tx_type)

        watched = self.coin_clients[coin_type]['watched_scripts']

        for ws in watched:
            if ws.bid_id == bid_id and ws.tx_type == tx_type and ws.script == script:
                self.log.debug('Script already being watched.')
                return

        watched.append(WatchedScript(bid_id, script, tx_type, swap_type))

    def removeWatchedScript(self, coin_type, bid_id: bytes, script: bytes) -> None:
        # Remove all for bid if txid is None
        self.log.debug('removeWatchedScript %s %s', Coins(coin_type).name, bid_id.hex())
        old_len = len(self.coin_clients[coin_type]['watched_scripts'])
        for i in range(old_len - 1, -1, -1):
            ws = self.coin_clients[coin_type]['watched_scripts'][i]
            if ws.bid_id == bid_id and (script is None or ws.script == script):
                del self.coin_clients[coin_type]['watched_scripts'][i]
                self.log.debug('Removed watched script %s %s', Coins(coin_type).name, bid_id.hex())

    def initiateTxnSpent(self, bid_id: bytes, spend_txid: str, spend_n: int, spend_txn) -> None:
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

    def participateTxnSpent(self, bid_id: bytes, spend_txid: str, spend_n: int, spend_txn) -> None:
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
                        delay = self.get_short_delay_event_seconds()
                        self.log.info('Redeeming ITX for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createAction(delay, ActionTypes.REDEEM_ITX, bid_id)
                # TODO: Wait for depth? new state SWAP_TXI_REDEEM_SENT?

            self.removeWatchedOutput(coin_to, bid_id, bid.participate_tx.txid.hex())
            self.saveBid(bid_id, bid)

    def process_XMR_SWAP_A_LOCK_tx_spend(self, bid_id: bytes, spend_txid_hex, spend_txn_hex, session=None) -> None:
        self.log.debug('Detected spend of Adaptor-sig swap coin a lock tx for bid %s', bid_id.hex())
        try:
            use_session = self.openSession(session)
            bid, xmr_swap = self.getXmrBidFromSession(use_session, bid_id)
            ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
            ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

            if BidStates(bid.state) == BidStates.BID_STALLED_FOR_TEST:
                self.log.debug('Bid stalled %s', bid_id.hex())
                return

            offer, xmr_offer = self.getXmrOfferFromSession(use_session, bid.offer_id, sent=False)
            ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
            was_received: bool = bid.was_sent if reverse_bid else bid.was_received
            coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
            coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)

            state = BidStates(bid.state)
            spending_txid = bytes.fromhex(spend_txid_hex)

            bid.xmr_a_lock_tx.spend_txid = spending_txid
            if spending_txid == xmr_swap.a_lock_spend_tx_id:
                if state == BidStates.XMR_SWAP_LOCK_RELEASED:
                    xmr_swap.a_lock_spend_tx = bytes.fromhex(spend_txn_hex)
                    bid.setState(BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)  # TODO: Wait for confirmation?

                    if bid.xmr_a_lock_tx:
                        bid.xmr_a_lock_tx.setState(TxStates.TX_REDEEMED)

                    if not was_received:
                        bid.setState(BidStates.SWAP_COMPLETED)
                else:
                    # Could already be processed if spend was detected in the mempool
                    self.log.warning('Coin a lock tx spend ignored due to bid state for bid {}'.format(bid_id.hex()))

            elif spending_txid == xmr_swap.a_lock_refund_tx_id:
                self.log.debug('Coin a lock tx spent by lock refund tx.')
                bid.setState(BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND)
                self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_TX_SEEN, '', use_session)
            else:
                self.setBidError(bid.bid_id, bid, 'Unexpected txn spent coin a lock tx: {}'.format(spend_txid_hex), save_bid=False)

            self.saveBidInSession(bid_id, bid, use_session, xmr_swap, save_in_progress=offer)
        except Exception as ex:
            self.logException(f'process_XMR_SWAP_A_LOCK_tx_spend {ex}')
        finally:
            if session is None:
                self.closeSession(use_session)

    def process_XMR_SWAP_A_LOCK_REFUND_tx_spend(self, bid_id: bytes, spend_txid_hex, spend_txn) -> None:
        self.log.debug('Detected spend of Adaptor-sig swap coin a lock refund tx for bid %s', bid_id.hex())
        try:
            session = self.openSession()
            bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
            ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
            ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

            offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
            ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
            ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
            coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
            coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
            was_sent: bool = bid.was_received if reverse_bid else bid.was_sent
            was_received: bool = bid.was_sent if reverse_bid else bid.was_received

            state = BidStates(bid.state)
            spending_txid = bytes.fromhex(spend_txid_hex)

            if spending_txid == xmr_swap.a_lock_refund_spend_tx_id:
                self.log.info('Found coin a lock refund spend tx, bid {}'.format(bid_id.hex()))
                self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_SEEN, '', session)
                if bid.xmr_a_lock_tx:
                    bid.xmr_a_lock_tx.setState(TxStates.TX_REFUNDED)

                if was_sent:
                    xmr_swap.a_lock_refund_spend_tx = bytes.fromhex(spend_txn['hex'])  # Replace with fully signed tx
                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND not in bid.txns:
                        bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND] = SwapTx(
                            bid_id=bid_id,
                            tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND,
                            txid=xmr_swap.a_lock_refund_spend_tx_id,
                        )
                    if bid.xmr_b_lock_tx is not None:
                        delay = self.get_delay_event_seconds()
                        self.log.info('Recovering adaptor-sig swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createActionInSession(delay, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, session)
                    else:
                        # Other side refunded before swap lock tx was sent
                        bid.setState(BidStates.XMR_SWAP_FAILED)

                if was_received:
                    if not was_sent:
                        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)

            else:
                self.log.info('Coin a lock refund spent by unknown tx, bid {}'.format(bid_id.hex()))
                bid.setState(BidStates.XMR_SWAP_FAILED_SWIPED)

            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
        except Exception as ex:
            self.logException(f'process_XMR_SWAP_A_LOCK_REFUND_tx_spend {ex}')
        finally:
            self.closeSession(session)

    def processSpentOutput(self, coin_type, watched_output, spend_txid_hex, spend_n, spend_txn) -> None:
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

    def processFoundScript(self, coin_type, watched_script, txid: bytes, vout: int) -> None:
        if watched_script.tx_type == TxTypes.PTX:
            if watched_script.bid_id in self.swaps_in_progress:
                bid = self.swaps_in_progress[watched_script.bid_id][0]

                bid.participate_tx.txid = txid
                bid.participate_tx.vout = vout
                bid.setPTxState(TxStates.TX_IN_CHAIN)

                self.saveBid(watched_script.bid_id, bid)
            else:
                self.log.warning('Could not find active bid for found watched script: {}'.format(watched_script.bid_id.hex()))
        elif watched_script.tx_type == TxTypes.XMR_SWAP_B_LOCK:
            bid = self.swaps_in_progress[watched_script.bid_id][0]
            bid.xmr_b_lock_tx = SwapTx(
                bid_id=watched_script.bid_id,
                tx_type=TxTypes.XMR_SWAP_B_LOCK,
                txid=txid,
                vout=vout,
            )
            bid.xmr_b_lock_tx.setState(TxStates.TX_IN_CHAIN)
            self.saveBid(watched_script.bid_id, bid)
        else:
            self.log.warning('Unknown found watched script tx type for bid {}'.format(watched_script.bid_id.hex()))

        self.removeWatchedScript(coin_type, watched_script.bid_id, watched_script.script)

    def checkNewBlock(self, coin_type, c):
        pass

    def haveCheckedPrevBlock(self, ci, c, block, session=None) -> bool:
        previousblockhash = bytes.fromhex(block['previousblockhash'])
        try:
            use_session = self.openSession(session)

            q = use_session.execute(text('SELECT COUNT(*) FROM checkedblocks WHERE block_hash = :block_hash'), {'block_hash': previousblockhash}).first()
            if q[0] > 0:
                return True

        finally:
            if session is None:
                self.closeSession(use_session, commit=False)

        return False

    def updateCheckedBlock(self, ci, cc, block, session=None) -> None:
        now: int = self.getTime()
        try:
            use_session = self.openSession(session)

            block_height = int(block['height'])
            if cc['last_height_checked'] != block_height:
                cc['last_height_checked'] = block_height
                self.setIntKV('last_height_checked_' + ci.coin_name().lower(), block_height, session=use_session)

            query = '''INSERT INTO checkedblocks (created_at, coin_type, block_height, block_hash, block_time)
                       VALUES (:now, :coin_type, :block_height, :block_hash, :block_time)'''
            use_session.execute(text(query), {'now': now, 'coin_type': int(ci.coin_type()), 'block_height': block_height, 'block_hash': bytes.fromhex(block['hash']), 'block_time': int(block['time'])})

        finally:
            if session is None:
                self.closeSession(use_session)

    def checkForSpends(self, coin_type, c):
        # assert (self.mxDB.locked())
        self.log.debug('checkForSpends %s', Coins(coin_type).name)

        # TODO: Check for spends on watchonly txns where possible
        if self.coin_clients[coin_type].get('have_spent_index', False):
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
            return

        ci = self.ci(coin_type)
        chain_blocks = ci.getChainHeight()
        last_height_checked: int = c['last_height_checked']
        block_check_min_time: int = c['block_check_min_time']
        self.log.debug('{} chain_blocks, last_height_checked {} {}'.format(ci.ticker(), chain_blocks, last_height_checked))

        blocks_checked: int = 0
        while last_height_checked < chain_blocks:
            if self.delay_event.is_set():
                break
            blocks_checked += 1
            if blocks_checked % 10000 == 0:
                self.log.debug('{} chain_blocks, last_height_checked, blocks_checked {} {} {}'.format(ci.ticker(), chain_blocks, last_height_checked, blocks_checked))
            if blocks_checked > self._max_check_loop_blocks:
                self.log.debug('Hit max_check_loop_blocks for {} chain_blocks, last_height_checked {} {}'.format(ci.ticker(), chain_blocks, last_height_checked))
                break

            block_hash = ci.rpc('getblockhash', [last_height_checked + 1])
            try:
                block = ci.getBlockWithTxns(block_hash)
            except Exception as e:
                if 'Block not available (pruned data)' in str(e):
                    # TODO: Better solution?
                    bci = ci.getBlockchainInfo()
                    self.log.error('Coin %s last_height_checked %d set to pruneheight %d', ci.coin_name(), last_height_checked, bci['pruneheight'])
                    last_height_checked = bci['pruneheight']
                    continue
                else:
                    self.logException(f'getblock error {e}')
                    break

            if block_check_min_time > block['time'] or last_height_checked < 1:
                pass
            elif not self.haveCheckedPrevBlock(ci, c, block):
                last_height_checked -= 1
                self.log.debug('Have not seen previousblockhash {} for block {}'.format(block['previousblockhash'], block['hash']))
                continue

            for tx in block['tx']:
                for s in c['watched_scripts']:
                    for i, txo in enumerate(tx['vout']):
                        if 'scriptPubKey' in txo and 'hex' in txo['scriptPubKey']:
                            # TODO: Optimise by loading rawtx in CTransaction
                            if bytes.fromhex(txo['scriptPubKey']['hex']) == s.script:
                                self.log.debug('Found script from search for bid %s: %s %d', s.bid_id.hex(), tx['txid'], i)
                                self.processFoundScript(coin_type, s, bytes.fromhex(tx['txid']), i)

                for o in c['watched_outputs']:
                    for i, inp in enumerate(tx['vin']):
                        inp_txid = inp.get('txid', None)
                        if inp_txid is None:  # Coinbase
                            continue
                        if inp_txid == o.txid_hex and inp['vout'] == o.vout:
                            self.log.debug('Found spend from search %s %d in %s %d', o.txid_hex, o.vout, tx['txid'], i)
                            self.processSpentOutput(coin_type, o, tx['txid'], i, tx)

            last_height_checked += 1
            self.updateCheckedBlock(ci, c, block)

    def expireMessages(self) -> None:
        if self._is_locked is True:
            self.log.debug('Not expiring messages while system locked')
            return

        self.mxDB.acquire()
        rpc_conn = None
        try:
            ci_part = self.ci(Coins.PART)
            rpc_conn = ci_part.open_rpc()
            num_messages: int = 0
            num_removed: int = 0

            def remove_if_expired(msg):
                nonlocal num_messages, num_removed
                try:
                    num_messages += 1
                    expire_at: int = msg['sent'] + msg['ttl']
                    if expire_at < now:
                        options = {'encoding': 'none', 'delete': True}
                        del_msg = ci_part.json_request(rpc_conn, 'smsg', [msg['msgid'], options])
                        num_removed += 1
                except Exception as e:
                    if self.debug:
                        self.log.error(traceback.format_exc())
                        self.log.error(f'Failed to process message {msg}')

            now: int = self.getTime()
            options = {'encoding': 'none', 'setread': False}
            inbox_messages = ci_part.json_request(rpc_conn, 'smsginbox', ['all', '', options])['messages']
            for msg in inbox_messages:
                remove_if_expired(msg)
            outbox_messages = ci_part.json_request(rpc_conn, 'smsgoutbox', ['all', '', options])['messages']
            for msg in outbox_messages:
                remove_if_expired(msg)

            if num_messages + num_removed > 0:
                self.log.info('Expired {} / {} messages.'.format(num_removed, num_messages))

        finally:
            if rpc_conn:
                ci_part.close_rpc(rpc_conn)
            self.mxDB.release()

    def expireDBRecords(self) -> None:
        if self._is_locked is True:
            self.log.debug('Not expiring database records while system locked')
            return
        if not self._expire_db_records:
            return
        remove_expired_data(self, self._expire_db_records_after)

    def checkAcceptedBids(self) -> None:
        # Check for bids stuck as accepted (not yet in-progress)
        if self._is_locked is True:
            self.log.debug('Not checking accepted bids while system locked')
            return

        now: int = self.getTime()
        session = self.openSession()

        grace_period: int = 60 * 60
        try:
            query_str = 'SELECT bid_id FROM bids ' + \
                        'WHERE active_ind = 1 AND state = :accepted_state AND expire_at + :grace_period <= :now '
            q = session.execute(text(query_str), {'accepted_state': int(BidStates.BID_ACCEPTED), 'now': now, 'grace_period': grace_period})
            for row in q:
                bid_id = row[0]
                self.log.info('Timing out bid {}.'.format(bid_id.hex()))
                self.timeoutBid(bid_id, session)

        finally:
            self.closeSession(session)

    def countQueuedActions(self, session, bid_id: bytes, action_type) -> int:
        q = session.query(Action).filter(sa.and_(Action.active_ind == 1, Action.linked_id == bid_id))
        if action_type is not None:
            q.filter(Action.action_type == int(action_type))
        return q.count()

    def checkQueuedActions(self) -> None:
        now: int = self.getTime()
        reload_in_progress: bool = False
        try:
            session = self.openSession()

            q = session.query(Action).filter(sa.and_(Action.active_ind == 1, Action.trigger_at <= now))
            for row in q:
                accepting_bid: bool = False
                try:
                    if row.action_type == ActionTypes.ACCEPT_BID:
                        accepting_bid = True
                        self.acceptBid(row.linked_id, session)
                    elif row.action_type == ActionTypes.ACCEPT_XMR_BID:
                        accepting_bid = True
                        self.acceptXmrBid(row.linked_id, session)
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
                    elif row.action_type == ActionTypes.ACCEPT_AS_REV_BID:
                        accepting_bid = True
                        self.acceptADSReverseBid(row.linked_id, session)
                    else:
                        self.log.warning('Unknown event type: %d', row.event_type)
                except Exception as ex:
                    err_msg = f'checkQueuedActions failed: {ex}'
                    self.logException(err_msg)

                    bid_id = row.linked_id
                    # Failing to accept a bid should not set an error state as the bid has not begun yet
                    if accepting_bid:
                        self.logEvent(Concepts.BID,
                                      bid_id,
                                      EventLogTypes.ERROR,
                                      err_msg,
                                      session)

                        # If delaying with no (further) queued actions reset state
                        if self.countQueuedActions(session, bid_id, None) < 2:
                            bid, offer = self.getBidAndOffer(bid_id, session)
                            last_state = getLastBidState(bid.states)
                            if bid and bid.state == BidStates.SWAP_DELAYING and last_state == BidStates.BID_RECEIVED:
                                new_state = BidStates.BID_ERROR if offer.bid_reversed else BidStates.BID_RECEIVED
                                bid.setState(new_state)
                                self.saveBidInSession(bid_id, bid, session)
                    else:
                        bid = self.getBid(bid_id, session)
                        if bid:
                            bid.setState(BidStates.BID_ERROR, err_msg)
                            self.saveBidInSession(bid_id, bid, session)

            query: str = 'DELETE FROM actions WHERE trigger_at <= :now'
            if self.debug:
                query = 'UPDATE actions SET active_ind = 2 WHERE trigger_at <= :now'
            session.execute(text(query), {'now': now})

        except Exception as ex:
            self.handleSessionErrors(ex, session, 'checkQueuedActions')
            reload_in_progress = True
        finally:
            self.closeSession(session)

        if reload_in_progress:
            self.loadFromDB()

    def checkXmrSwaps(self) -> None:
        now: int = self.getTime()
        ttl_xmr_split_messages = 60 * 60
        try:
            session = self.openSession()
            q = session.query(Bid).filter(Bid.state == BidStates.BID_RECEIVING)
            for bid in q:
                q = session.execute(text('SELECT COUNT(*) FROM xmr_split_data WHERE bid_id = x\'{}\' AND msg_type = {}'.format(bid.bid_id.hex(), XmrSplitMsgTypes.BID))).first()
                num_segments = q[0]
                if num_segments > 1:
                    try:
                        self.receiveXmrBid(bid, session)
                    except Exception as ex:
                        self.log.info('Verify adaptor-sig bid {} failed: {}'.format(bid.bid_id.hex(), str(ex)))
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
                q = session.execute(text('SELECT COUNT(*) FROM xmr_split_data WHERE bid_id = x\'{}\' AND msg_type = {}'.format(bid.bid_id.hex(), XmrSplitMsgTypes.BID_ACCEPT))).first()
                num_segments = q[0]
                if num_segments > 1:
                    try:
                        self.receiveXmrBidAccept(bid, session)
                    except Exception as ex:
                        if self.debug:
                            self.log.error(traceback.format_exc())
                        self.log.info('Verify adaptor-sig bid accept {} failed: {}'.format(bid.bid_id.hex(), str(ex)))
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

        finally:
            self.closeSession(session)

    def processOffer(self, msg) -> None:
        offer_bytes = bytes.fromhex(msg['hex'][2:-2])

        offer_data = OfferMessage(init_all=False)
        try:
            offer_data.from_bytes(offer_bytes[:2], init_all=False)
            ensure(offer_data.protocol_version >= MINPROTO_VERSION and offer_data.protocol_version <= MAXPROTO_VERSION, 'protocol_version out of range')
        except Exception as e:
            self.log.warning('Incoming offer invalid protocol version: {}.'.format(getattr(offer_data, 'protocol_version', -1)))
            return
        try:
            offer_data.from_bytes(offer_bytes)
        except Exception as e:
            self.log.warning('Failed to decode offer, protocol version: {}, {}.'.format(getattr(offer_data, 'protocol_version', -1), str(e)))
            return

        # Validate offer data
        now: int = self.getTime()
        coin_from = Coins(offer_data.coin_from)
        ci_from = self.ci(coin_from)
        coin_to = Coins(offer_data.coin_to)
        ci_to = self.ci(coin_to)
        ensure(offer_data.coin_from != offer_data.coin_to, 'coin_from == coin_to')

        self.validateSwapType(coin_from, coin_to, offer_data.swap_type)
        self.validateOfferAmounts(coin_from, coin_to, offer_data.amount_from, offer_data.amount_to, offer_data.min_bid_amount)
        self.validateOfferLockValue(offer_data.swap_type, coin_from, coin_to, offer_data.lock_type, offer_data.lock_value)
        self.validateOfferValidTime(offer_data.swap_type, coin_from, coin_to, offer_data.time_valid)

        ensure(msg['sent'] + offer_data.time_valid >= now, 'Offer expired')

        offer_rate: int = ci_from.make_int(offer_data.amount_to / offer_data.amount_from, r=1)
        reverse_bid: bool = self.is_reverse_ads_bid(coin_from)

        if offer_data.swap_type == SwapTypes.SELLER_FIRST:
            ensure(offer_data.protocol_version >= MINPROTO_VERSION_SECRET_HASH, 'Invalid protocol version')
            ensure(len(offer_data.proof_address) == 0, 'Unexpected data')
            ensure(len(offer_data.proof_signature) == 0, 'Unexpected data')
            ensure(len(offer_data.pkhash_seller) == 0, 'Unexpected data')
            ensure(len(offer_data.secret_hash) == 0, 'Unexpected data')
        elif offer_data.swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError('TODO')
        elif offer_data.swap_type == SwapTypes.XMR_SWAP:
            ensure(offer_data.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG, 'Invalid protocol version')
            if reverse_bid:
                ensure(ci_to.has_segwit(), 'Coin-to must support segwit for reverse bid offers')
            else:
                ensure(ci_from.has_segwit(), 'Coin-from must support segwit')
            ensure(len(offer_data.proof_address) == 0, 'Unexpected data')
            ensure(len(offer_data.proof_signature) == 0, 'Unexpected data')
            ensure(len(offer_data.pkhash_seller) == 0, 'Unexpected data')
            ensure(len(offer_data.secret_hash) == 0, 'Unexpected data')
        else:
            raise ValueError('Unknown swap type {}.'.format(offer_data.swap_type))

        offer_id = bytes.fromhex(msg['msgid'])

        if self.isOfferRevoked(offer_id, msg['from']):
            raise ValueError('Offer has been revoked {}.'.format(offer_id.hex()))

        try:
            session = self.openSession()
            # Offers must be received on the public network_addr or manually created addresses
            if msg['to'] != self.network_addr:
                # Double check active_ind, shouldn't be possible to receive message if not active
                query_str = 'SELECT COUNT(addr_id) FROM smsgaddresses WHERE addr = "{}" AND use_type = {} AND active_ind = 1'.format(msg['to'], AddressTypes.RECV_OFFER)
                rv = session.execute(text(query_str)).first()
                if rv[0] < 1:
                    raise ValueError('Offer received on incorrect address')

            # Check for sent
            existing_offer = self.getOffer(offer_id, session=session)
            if existing_offer is None:
                bid_reversed: bool = offer_data.swap_type == SwapTypes.XMR_SWAP and self.is_reverse_ads_bid(offer_data.coin_from)
                offer = Offer(
                    offer_id=offer_id,
                    active_ind=1,

                    protocol_version=offer_data.protocol_version,
                    coin_from=offer_data.coin_from,
                    coin_to=offer_data.coin_to,
                    amount_from=offer_data.amount_from,
                    amount_to=offer_data.amount_to,
                    rate=offer_rate,
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
                    was_sent=False,
                    bid_reversed=bid_reversed)
                offer.setState(OfferStates.OFFER_RECEIVED)
                session.add(offer)

                if offer.swap_type == SwapTypes.XMR_SWAP:
                    xmr_offer = XmrOffer()

                    xmr_offer.offer_id = offer_id

                    chain_a_ci = ci_to if reverse_bid else ci_from
                    lock_value_2 = offer_data.lock_value
                    if (None, DebugTypes.OFFER_LOCK_2_VALUE_INC) in self._debug_cases:
                        lock_value_2 += 1000
                    xmr_offer.lock_time_1 = chain_a_ci.getExpectedSequence(offer_data.lock_type, offer_data.lock_value)
                    xmr_offer.lock_time_2 = chain_a_ci.getExpectedSequence(offer_data.lock_type, lock_value_2)

                    xmr_offer.a_fee_rate = offer_data.fee_rate_from
                    xmr_offer.b_fee_rate = offer_data.fee_rate_to

                    session.add(xmr_offer)

                self.notify(NT.OFFER_RECEIVED, {'offer_id': offer_id.hex()}, session)
            else:
                existing_offer.setState(OfferStates.OFFER_RECEIVED)
                session.add(existing_offer)
        finally:
            self.closeSession(session)

    def processOfferRevoke(self, msg) -> None:
        ensure(msg['to'] == self.network_addr, 'Message received on wrong address')

        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = OfferRevokeMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        now: int = self.getTime()
        try:
            session = self.openSession()

            if len(msg_data.offer_msg_id) != 28:
                raise ValueError('Invalid msg_id length')
            if len(msg_data.signature) != 65:
                raise ValueError('Invalid signature length')

            offer = session.query(Offer).filter_by(offer_id=msg_data.offer_msg_id).first()
            if offer is None:
                self.storeOfferRevoke(msg_data.offer_msg_id, msg_data.signature)

                # Offer may not have been received yet, or involved an inactive coin on this node.
                self.log.debug('Offer not found to revoke: {}'.format(msg_data.offer_msg_id.hex()))
                return

            if offer.expire_at <= now:
                self.log.debug('Offer is already expired, no need to revoke: {}'.format(msg_data.offer_msg_id.hex()))
                return

            signature_enc = base64.b64encode(msg_data.signature).decode('utf-8')

            passed = self.callcoinrpc(Coins.PART, 'verifymessage', [offer.addr_from, signature_enc, msg_data.offer_msg_id.hex() + '_revoke'])
            ensure(passed is True, 'Signature invalid')

            offer.active_ind = 2
            # TODO: Remove message, or wait for expire

            session.add(offer)
        finally:
            self.closeSession(session)

    def getCompletedAndActiveBidsValue(self, offer, session):
        bids = []
        total_value = 0
        q = session.execute(text(
            '''SELECT bid_id, amount, state FROM bids
               JOIN bidstates ON bidstates.state_id = bids.state AND (bidstates.state_id = {1} OR bidstates.in_progress > 0)
               WHERE bids.active_ind = 1 AND bids.offer_id = x\'{0}\'
               UNION
               SELECT bid_id, amount, state FROM bids
               JOIN actions ON actions.linked_id = bids.bid_id AND actions.active_ind = 1 AND (actions.action_type = {2} OR actions.action_type = {3})
               WHERE bids.active_ind = 1 AND bids.offer_id = x\'{0}\'
            '''.format(offer.offer_id.hex(), BidStates.SWAP_COMPLETED, ActionTypes.ACCEPT_XMR_BID, ActionTypes.ACCEPT_BID)))
        for row in q:
            bid_id, amount, state = row
            bids.append((bid_id, amount, state))
            total_value += amount
        return bids, total_value

    def evaluateKnownIdentityForAutoAccept(self, strategy, identity_stats) -> bool:
        if identity_stats:
            if identity_stats.automation_override == AutomationOverrideOptions.NEVER_ACCEPT:
                raise AutomationConstraint('From address is marked never accept')
            if identity_stats.automation_override == AutomationOverrideOptions.ALWAYS_ACCEPT:
                return True

        if strategy.only_known_identities:
            if not identity_stats:
                raise AutomationConstraint('Unknown bidder')

            # TODO: More options
            if identity_stats.num_recv_bids_successful < 1:
                raise AutomationConstraint('Bidder has too few successful swaps')
            if identity_stats.num_recv_bids_successful <= identity_stats.num_recv_bids_failed:
                raise AutomationConstraint('Bidder has too many failed swaps')
        return True

    def shouldAutoAcceptBid(self, offer, bid, session=None, options={}) -> bool:
        try:
            use_session = self.openSession(session)

            link = use_session.query(AutomationLink).filter_by(active_ind=1, linked_type=Concepts.OFFER, linked_id=offer.offer_id).first()
            if not link:
                return False

            strategy = use_session.query(AutomationStrategy).filter_by(active_ind=1, record_id=link.strategy_id).first()
            opts = json.loads(strategy.data.decode('utf-8'))

            coin_from = Coins(offer.coin_from)
            bid_amount: int = bid.amount
            bid_rate: int = bid.rate

            if options.get('reverse_bid', False):
                bid_amount = bid.amount_to
                bid_rate = options.get('bid_rate')

            self.log.debug('Evaluating against strategy {}'.format(strategy.record_id))

            if not offer.amount_negotiable:
                if bid_amount != offer.amount_from:
                    raise AutomationConstraint('Need exact amount match')

            if bid_amount < offer.min_bid_amount:
                raise AutomationConstraint('Bid amount below offer minimum')

            if opts.get('exact_rate_only', False) is True:
                if bid_rate != offer.rate:
                    raise AutomationConstraint('Need exact rate match')

            active_bids, total_bids_value = self.getCompletedAndActiveBidsValue(offer, use_session)

            total_bids_value_multiplier = opts.get('total_bids_value_multiplier', 1.0)
            if total_bids_value_multiplier > 0.0:
                if total_bids_value + bid_amount > offer.amount_from * total_bids_value_multiplier:
                    raise AutomationConstraint('Over remaining offer value {}'.format(offer.amount_from * total_bids_value_multiplier - total_bids_value))

            num_not_completed = 0
            for active_bid in active_bids:
                if active_bid[2] != BidStates.SWAP_COMPLETED:
                    num_not_completed += 1
            max_concurrent_bids = opts.get('max_concurrent_bids', 1)
            if num_not_completed >= max_concurrent_bids:
                raise AutomationConstraint('Already have {} bids to complete'.format(num_not_completed))

            identity_stats = use_session.query(KnownIdentity).filter_by(address=bid.bid_addr).first()
            self.evaluateKnownIdentityForAutoAccept(strategy, identity_stats)

            self.logEvent(Concepts.BID,
                          bid.bid_id,
                          EventLogTypes.AUTOMATION_ACCEPTING_BID,
                          '',
                          use_session)

            return True
        except AutomationConstraint as e:
            self.log.info('Not auto accepting bid {}, {}'.format(bid.bid_id.hex(), str(e)))
            if self.debug:
                self.logEvent(Concepts.BID,
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

    def processBid(self, msg) -> None:
        self.log.debug('Processing bid msg %s', msg['msgid'])
        now: int = self.getTime()
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = BidMessage(init_all=False)
        bid_data.from_bytes(bid_bytes)

        # Validate bid data
        ensure(bid_data.protocol_version >= MINPROTO_VERSION_SECRET_HASH, 'Invalid protocol version')
        ensure(len(bid_data.offer_msg_id) == 28, 'Bad offer_id length')

        offer_id = bid_data.offer_msg_id
        offer = self.getOffer(offer_id, sent=True)
        ensure(offer and offer.was_sent, 'Unknown offer')

        ensure(offer.state == OfferStates.OFFER_RECEIVED, 'Bad offer state')
        ensure(msg['to'] == offer.addr_from, 'Received on incorrect address')
        ensure(now <= offer.expire_at, 'Offer expired')
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid)
        ensure(now <= msg['sent'] + bid_data.time_valid, 'Bid expired')

        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(coin_to)
        bid_rate: int = ci_from.make_int(bid_data.amount_to / bid_data.amount, r=1)
        self.validateBidAmount(offer, bid_data.amount, bid_rate)

        # TODO: Allow higher bids
        # assert (bid_data.rate != offer['data'].rate), 'Bid rate mismatch'

        swap_type = offer.swap_type
        if swap_type == SwapTypes.SELLER_FIRST:
            ensure(len(bid_data.pkhash_buyer) == 20, 'Bad pkhash_buyer length')

            proof_utxos = ci_to.decodeProofUtxos(bid_data.proof_utxos)
            sum_unspent = ci_to.verifyProofOfFunds(bid_data.proof_address, bid_data.proof_signature, proof_utxos, offer_id)
            self.log.debug('Proof of funds %s %s', bid_data.proof_address, self.ci(coin_to).format_amount(sum_unspent))
            ensure(sum_unspent >= bid_data.amount_to, 'Proof of funds failed')

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
                amount_to=bid_data.amount_to,
                rate=bid_rate,
                pkhash_buyer=bid_data.pkhash_buyer,
                proof_address=bid_data.proof_address,
                proof_utxos=bid_data.proof_utxos,

                created_at=msg['sent'],
                expire_at=msg['sent'] + bid_data.time_valid,
                bid_addr=msg['from'],
                was_received=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
            )

            if len(bid_data.pkhash_buyer_to) > 0:
                bid.pkhash_buyer_to = bid_data.pkhash_buyer_to
        else:
            ensure(bid.state == BidStates.BID_SENT, 'Wrong bid state: {}'.format(BidStates(bid.state).name))
            bid.created_at = msg['sent']
            bid.expire_at = msg['sent'] + bid_data.time_valid
            bid.was_received = True
        if len(bid_data.proof_address) > 0:
            bid.proof_address = bid_data.proof_address

        bid.setState(BidStates.BID_RECEIVED)

        self.saveBid(bid_id, bid)
        self.notify(NT.BID_RECEIVED, {'type': 'secrethash', 'bid_id': bid_id.hex(), 'offer_id': bid_data.offer_msg_id.hex()})

        if self.shouldAutoAcceptBid(offer, bid):
            delay = self.get_delay_event_seconds()
            self.log.info('Auto accepting bid %s in %d seconds', bid_id.hex(), delay)
            self.createAction(delay, ActionTypes.ACCEPT_BID, bid_id)

    def processBidAccept(self, msg) -> None:
        self.log.debug('Processing bid accepted msg %s', msg['msgid'])
        now: int = self.getTime()
        bid_accept_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_accept_data = BidAcceptMessage(init_all=False)
        bid_accept_data.from_bytes(bid_accept_bytes)

        ensure(len(bid_accept_data.bid_msg_id) == 28, 'Bad bid_msg_id length')
        ensure(len(bid_accept_data.initiate_txid) == 32, 'Bad initiate_txid length')
        ensure(len(bid_accept_data.contract_script) < 100, 'Bad contract_script length')

        self.log.debug('for bid %s', bid_accept_data.bid_msg_id.hex())

        bid_id = bid_accept_data.bid_msg_id
        bid, offer = self.getBidAndOffer(bid_id)
        ensure(bid is not None and bid.was_sent is True, 'Unknown bid_id')
        ensure(offer, 'Offer not found ' + bid.offer_id.hex())

        ensure(bid.expire_at > now + self._bid_expired_leeway, 'Bid expired')
        ensure(msg['to'] == bid.bid_addr, 'Received on incorrect address')
        ensure(msg['from'] == offer.addr_from, 'Sent from incorrect address')

        coin_from = Coins(offer.coin_from)
        ci_from = self.ci(coin_from)

        if bid.state >= BidStates.BID_ACCEPTED:
            if bid.was_received:  # Sent to self
                accept_msg_id: bytes = self.getLinkedMessageId(Concepts.BID, bid_id, MessageTypes.BID_ACCEPT)

                self.log.info('Received valid bid accept %s for bid %s sent to self', accept_msg_id.hex(), bid_id.hex())
                return
            raise ValueError('Wrong bid state: {}'.format(BidStates(bid.state).name))

        use_csv = True if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS else False

        if coin_from in (Coins.DCR, ):
            op_hash = OpCodes.OP_SHA256_DECRED
        else:
            op_hash = OpCodes.OP_SHA256
        op_lock = OpCodes.OP_CHECKSEQUENCEVERIFY if use_csv else OpCodes.OP_CHECKLOCKTIMEVERIFY
        script_valid, script_hash, script_pkhash1, script_lock_val, script_pkhash2 = atomic_swap_1.verifyContractScript(bid_accept_data.contract_script, op_lock=op_lock, op_hash=op_hash)
        if not script_valid:
            raise ValueError('Bad script')

        ensure(script_pkhash1 == bid.pkhash_buyer, 'pkhash_buyer mismatch')

        if use_csv:
            expect_sequence = ci_from.getExpectedSequence(offer.lock_type, offer.lock_value)
            ensure(script_lock_val == expect_sequence, 'sequence mismatch')
        else:
            if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                block_header_from = ci_from.getBlockHeaderAt(now)
                chain_height_at_bid_creation = block_header_from['height']
                ensure(script_lock_val <= chain_height_at_bid_creation + offer.lock_value + atomic_swap_1.ABS_LOCK_BLOCKS_LEEWAY, 'script lock height too high')
                ensure(script_lock_val >= chain_height_at_bid_creation + offer.lock_value - atomic_swap_1.ABS_LOCK_BLOCKS_LEEWAY, 'script lock height too low')
            else:
                ensure(script_lock_val <= now + offer.lock_value + atomic_swap_1.INITIATE_TX_TIMEOUT, 'script lock time too high')
                ensure(script_lock_val >= now + offer.lock_value - atomic_swap_1.ABS_LOCK_TIME_LEEWAY, 'script lock time too low')

        ensure(self.countMessageLinks(Concepts.BID, bid_id, MessageTypes.BID_ACCEPT) == 0, 'Bid already accepted')

        bid_accept_msg_id = bytes.fromhex(msg['msgid'])
        self.addMessageLink(Concepts.BID, bid_id, MessageTypes.BID_ACCEPT, bid_accept_msg_id)

        bid.initiate_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.ITX,
            txid=bid_accept_data.initiate_txid,
            script=bid_accept_data.contract_script,
        )

        if len(bid_accept_data.pkhash_seller) == 20:
            bid.pkhash_seller = bid_accept_data.pkhash_seller
        else:
            bid.pkhash_seller = script_pkhash2

        bid.setState(BidStates.BID_ACCEPTED)
        bid.setITxState(TxStates.TX_NONE)

        bid.offer_id.hex()

        self.saveBid(bid_id, bid)
        self.swaps_in_progress[bid_id] = (bid, offer)
        self.notify(NT.BID_ACCEPTED, {'bid_id': bid_id.hex()})

    def receiveXmrBid(self, bid, session) -> None:
        self.log.debug('Receiving adaptor-sig bid %s', bid.bid_id.hex())
        now: int = self.getTime()

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=True)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))

        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))
        xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid.bid_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        addr_expect_from: str = ''
        if reverse_bid:
            ci_from = self.ci(Coins(offer.coin_to))
            ci_to = self.ci(Coins(offer.coin_from))
            addr_expect_from = bid.bid_addr
            addr_expect_to = offer.addr_from
        else:
            ensure(offer.was_sent, 'Offer not sent: {}.'.format(bid.offer_id.hex()))
            ci_from = self.ci(Coins(offer.coin_from))
            ci_to = self.ci(Coins(offer.coin_to))
            addr_expect_from = offer.addr_from
            addr_expect_to = bid.bid_addr

        if ci_to.curve_type() == Curves.ed25519:
            if len(xmr_swap.kbsf_dleag) < ci_to.lengthDLEAG():
                q = session.query(XmrSplitData).filter(sa.and_(XmrSplitData.bid_id == bid.bid_id, XmrSplitData.msg_type == XmrSplitMsgTypes.BID)).order_by(XmrSplitData.msg_sequence.asc())
                for row in q:
                    ensure(row.addr_to == addr_expect_from, 'Received on incorrect address, segment_id {}'.format(row.record_id))
                    ensure(row.addr_from == addr_expect_to, 'Sent from incorrect address, segment_id {}'.format(row.record_id))
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
        elif ci_to.curve_type() == Curves.secp256k1:
            xmr_swap.pkasf = ci_to.verifySigAndRecover(xmr_swap.kbsf_dleag, 'proof kbsf owned for swap')
            if not ci_from.verifyPubkey(xmr_swap.pkasf):
                raise ValueError('Invalid coin a pubkey.')
            xmr_swap.pkbsf = xmr_swap.pkasf
        else:
            raise ValueError('Unknown curve')

        ensure(ci_to.verifyKey(xmr_swap.vkbvf), 'Invalid key, vkbvf')
        ensure(ci_from.verifyPubkey(xmr_swap.pkaf), 'Invalid pubkey, pkaf')

        if not reverse_bid:  # notify already ran in processADSBidReversed
            self.notify(NT.BID_RECEIVED, {'type': 'ads', 'bid_id': bid.bid_id.hex(), 'offer_id': bid.offer_id.hex()}, session)

        bid.setState(BidStates.BID_RECEIVED)

        if reverse_bid or self.shouldAutoAcceptBid(offer, bid, session):
            delay = self.get_delay_event_seconds()
            self.log.info('Auto accepting %sadaptor-sig bid %s in %d seconds', 'reverse ' if reverse_bid else '', bid.bid_id.hex(), delay)
            self.createActionInSession(delay, ActionTypes.ACCEPT_XMR_BID, bid.bid_id, session)
            bid.setState(BidStates.SWAP_DELAYING)

        self.saveBidInSession(bid.bid_id, bid, session, xmr_swap)

    def receiveXmrBidAccept(self, bid, session) -> None:
        # Follower receiving MSG1F and MSG2F
        self.log.debug('Receiving adaptor-sig bid accept %s', bid.bid_id.hex())
        now: int = self.getTime()

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=True, session=session)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))
        xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid.bid_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)
        addr_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_to: str = offer.addr_from if reverse_bid else bid.bid_addr

        if ci_to.curve_type() == Curves.ed25519:
            if len(xmr_swap.kbsl_dleag) < ci_to.lengthDLEAG():
                q = session.query(XmrSplitData).filter(sa.and_(XmrSplitData.bid_id == bid.bid_id, XmrSplitData.msg_type == XmrSplitMsgTypes.BID_ACCEPT)).order_by(XmrSplitData.msg_sequence.asc())
                for row in q:
                    ensure(row.addr_to == addr_to, 'Received on incorrect address, segment_id {}'.format(row.record_id))
                    ensure(row.addr_from == addr_from, 'Sent from incorrect address, segment_id {}'.format(row.record_id))
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
        elif ci_to.curve_type() == Curves.secp256k1:
            xmr_swap.pkasl = ci_to.verifySigAndRecover(xmr_swap.kbsl_dleag, 'proof kbsl owned for swap')
            if not ci_from.verifyPubkey(xmr_swap.pkasl):
                raise ValueError('Invalid coin a pubkey.')
            xmr_swap.pkbsl = xmr_swap.pkasl
        else:
            raise ValueError('Unknown curve')

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

        bid.setState(BidStates.BID_ACCEPTED)  # ADS
        self.saveBidInSession(bid.bid_id, bid, session, xmr_swap)

        if reverse_bid is False:
            self.notify(NT.BID_ACCEPTED, {'bid_id': bid.bid_id.hex()}, session)

        delay = self.get_delay_event_seconds()
        self.log.info('Responding to adaptor-sig bid accept %s in %d seconds', bid.bid_id.hex(), delay)
        self.createActionInSession(delay, ActionTypes.SIGN_XMR_SWAP_LOCK_TX_A, bid.bid_id, session)

    def processXmrBid(self, msg) -> None:
        # MSG1L
        self.log.debug('Processing adaptor-sig bid msg %s', msg['msgid'])
        now: int = self.getTime()
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = XmrBidMessage(init_all=False)
        bid_data.from_bytes(bid_bytes)

        # Validate data
        ensure(bid_data.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG, 'Invalid protocol version')
        ensure(len(bid_data.offer_msg_id) == 28, 'Bad offer_id length')

        offer_id = bid_data.offer_msg_id
        offer, xmr_offer = self.getXmrOffer(offer_id, sent=True)
        ensure(offer and offer.was_sent, 'Offer not found: {}.'.format(offer_id.hex()))
        ensure(offer.swap_type == SwapTypes.XMR_SWAP, 'Bid/offer swap type mismatch')
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(offer_id.hex()))

        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(offer.coin_to)

        if not validOfferStateToReceiveBid(offer.state):
            raise ValueError('Bad offer state')
        ensure(msg['to'] == offer.addr_from, 'Received on incorrect address')
        ensure(now <= offer.expire_at, 'Offer expired')
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid)
        ensure(now <= msg['sent'] + bid_data.time_valid, 'Bid expired')

        bid_rate: int = ci_from.make_int(bid_data.amount_to / bid_data.amount, r=1)
        self.validateBidAmount(offer, bid_data.amount, bid_rate)

        ensure(ci_to.verifyKey(bid_data.kbvf), 'Invalid chain B follower view key')
        ensure(ci_from.verifyPubkey(bid_data.pkaf), 'Invalid chain A follower public key')
        ensure(ci_from.isValidAddressHash(bid_data.dest_af) or ci_from.isValidPubkey(bid_data.dest_af), 'Invalid destination address')

        if ci_to.curve_type() == Curves.ed25519:
            ensure(len(bid_data.kbsf_dleag) == 16000, 'Invalid kbsf_dleag size')

        bid_id = bytes.fromhex(msg['msgid'])

        bid, xmr_swap = self.getXmrBid(bid_id)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                protocol_version=bid_data.protocol_version,
                amount=bid_data.amount,
                amount_to=bid_data.amount_to,
                rate=bid_rate,
                created_at=msg['sent'],
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
                self.log.warning('Adaptor-sig swap restore height clamped to {}'.format(wallet_restore_height))
        else:
            ensure(bid.state == BidStates.BID_SENT, 'Wrong bid state: {}'.format(BidStates(bid.state).name))
            # Don't update bid.created_at, it's been used to derive kaf
            bid.expire_at = msg['sent'] + bid_data.time_valid
            bid.was_received = True

        bid.setState(BidStates.BID_RECEIVING)

        self.log.info('Receiving adaptor-sig bid %s for offer %s', bid_id.hex(), bid_data.offer_msg_id.hex())
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

        if ci_to.curve_type() != Curves.ed25519:
            try:
                session = self.openSession()
                self.receiveXmrBid(bid, session)
            finally:
                self.closeSession(session)

    def processXmrBidAccept(self, msg) -> None:
        # F receiving MSG1F and MSG2F
        self.log.debug('Processing adaptor-sig bid accept msg %s', msg['msgid'])
        now: int = self.getTime()
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidAcceptMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, 'Bad bid_msg_id length')

        self.log.debug('for bid %s', msg_data.bid_msg_id.hex())
        bid, xmr_swap = self.getXmrBid(msg_data.bid_msg_id)
        ensure(bid, 'Bid not found: {}.'.format(msg_data.bid_msg_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(msg_data.bid_msg_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=True)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)
        addr_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_to: str = offer.addr_from if reverse_bid else bid.bid_addr
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate
        b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate

        ensure(msg['to'] == addr_to, 'Received on incorrect address')
        ensure(msg['from'] == addr_from, 'Sent from incorrect address')

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
                a_fee_rate,
                check_a_lock_tx_inputs, xmr_swap.vkbv)
            a_lock_tx_dest = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)

            xmr_swap.a_lock_refund_tx_id, xmr_swap.a_swap_refund_value, lock_refund_vout = ci_from.verifySCLockRefundTx(
                xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_tx, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.a_lock_tx_id, xmr_swap.a_lock_tx_vout, xmr_offer.lock_time_1, xmr_swap.a_lock_tx_script,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.lock_time_2,
                bid.amount, a_fee_rate, xmr_swap.vkbv)

            ci_from.verifySCLockRefundSpendTx(
                xmr_swap.a_lock_refund_spend_tx, xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_id, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.pkal,
                lock_refund_vout, xmr_swap.a_swap_refund_value, a_fee_rate, xmr_swap.vkbv)

            self.log.info('Checking leader\'s lock refund tx signature')
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            v = ci_from.verifyTxSig(xmr_swap.a_lock_refund_tx, xmr_swap.al_lock_refund_tx_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, prevout_amount)
            ensure(v, 'Invalid coin A lock refund tx leader sig')

            allowed_states = [BidStates.BID_SENT, BidStates.BID_RECEIVED, BidStates.BID_REQUEST_ACCEPTED]
            if bid.was_sent and offer.was_sent:
                allowed_states.append(BidStates.BID_ACCEPTED)  # TODO: Split BID_ACCEPTED into received and sent
            ensure(bid.state in allowed_states, 'Invalid state for bid {}'.format(bid.state))
            bid.setState(BidStates.BID_RECEIVING_ACC)
            self.saveBid(bid.bid_id, bid, xmr_swap=xmr_swap)

            if ci_to.curve_type() != Curves.ed25519:
                try:
                    session = self.openSession()
                    self.receiveXmrBidAccept(bid, session)
                finally:
                    self.closeSession(session)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid.bid_id, bid, str(ex), xmr_swap=xmr_swap)

    def watchXmrSwap(self, bid, offer, xmr_swap, session=None) -> None:
        self.log.debug('Adaptor-sig swap in progress, bid %s', bid.bid_id.hex())
        self.swaps_in_progress[bid.bid_id] = (bid, offer)

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        self.setLastHeightCheckedStart(coin_from, bid.chain_a_height_start, session)
        self.addWatchedOutput(coin_from, bid.bid_id, bid.xmr_a_lock_tx.txid.hex(), bid.xmr_a_lock_tx.vout, TxTypes.XMR_SWAP_A_LOCK, SwapTypes.XMR_SWAP)

        lock_refund_vout = self.ci(coin_from).getLockRefundTxSwapOutput(xmr_swap)
        self.addWatchedOutput(coin_from, bid.bid_id, xmr_swap.a_lock_refund_tx_id.hex(), lock_refund_vout, TxTypes.XMR_SWAP_A_LOCK_REFUND, SwapTypes.XMR_SWAP)
        bid.in_progress = 1

    def sendXmrBidTxnSigsFtoL(self, bid_id, session) -> None:
        # F -> L: Sending MSG3L
        self.log.debug('Signing adaptor-sig bid lock txns %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        try:
            kaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF)

            prevout_amount = ci_from.getLockRefundTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.af_lock_refund_spend_tx_esig = ci_from.signTxOtVES(kaf, xmr_swap.pkasl, xmr_swap.a_lock_refund_spend_tx, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount)

            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.af_lock_refund_tx_sig = ci_from.signTx(kaf, xmr_swap.a_lock_refund_tx, 0, xmr_swap.a_lock_tx_script, prevout_amount)

            xmr_swap_1.addLockRefundSigs(self, xmr_swap, ci_from)

            msg_buf = XmrBidLockTxSigsMessage(
                bid_msg_id=bid_id,
                af_lock_refund_spend_tx_esig=xmr_swap.af_lock_refund_spend_tx_esig,
                af_lock_refund_tx_sig=xmr_swap.af_lock_refund_tx_sig
            )

            msg_bytes = msg_buf.to_bytes()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_TXN_SIGS_FL) + msg_bytes.hex()

            msg_valid: int = self.getActiveBidMsgValidTime()
            addr_send_from: str = offer.addr_from if reverse_bid else bid.bid_addr
            addr_send_to: str = bid.bid_addr if reverse_bid else offer.addr_from
            coin_a_lock_tx_sigs_l_msg_id = self.sendSmsg(addr_send_from, addr_send_to, payload_hex, msg_valid)
            self.addMessageLink(Concepts.BID, bid_id, MessageTypes.XMR_BID_TXN_SIGS_FL, coin_a_lock_tx_sigs_l_msg_id, session=session)
            self.log.info('Sent XMR_BID_TXN_SIGS_FL %s for bid %s', coin_a_lock_tx_sigs_l_msg_id.hex(), bid_id.hex())

            a_lock_tx_id = ci_from.getTxid(xmr_swap.a_lock_tx)
            a_lock_tx_vout = ci_from.getTxOutputPos(xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script)
            self.log.debug('Waiting for lock txn %s to %s chain for bid %s', a_lock_tx_id.hex(), ci_from.coin_name(), bid_id.hex())
            if bid.xmr_a_lock_tx is None:
                bid.xmr_a_lock_tx = SwapTx(
                    bid_id=bid_id,
                    tx_type=TxTypes.XMR_SWAP_A_LOCK,
                    txid=a_lock_tx_id,
                    vout=a_lock_tx_vout,
                )
            bid.xmr_a_lock_tx.setState(TxStates.TX_NONE)

            bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            self.watchXmrSwap(bid, offer, xmr_swap, session)
            self.saveBidInSession(bid_id, bid, session, xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())

    def sendXmrBidCoinALockTx(self, bid_id: bytes, session) -> None:
        # Offerer/Leader. Send coin A lock tx
        self.log.debug('Sending coin A lock tx for adaptor-sig bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate

        kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAL)

        # Prove leader can sign for kal, sent in MSG4F
        xmr_swap.kal_sig = ci_from.signCompact(kal, 'proof key owned for swap')

        # Create Script lock spend tx
        xmr_swap.a_lock_spend_tx = ci_from.createSCLockSpendTx(
            xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
            xmr_swap.dest_af,
            a_fee_rate, xmr_swap.vkbv)

        xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)
        if bid.xmr_a_lock_tx:
            bid.xmr_a_lock_tx.spend_txid = xmr_swap.a_lock_spend_tx_id
        prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
        xmr_swap.al_lock_spend_tx_esig = ci_from.signTxOtVES(kal, xmr_swap.pkasf, xmr_swap.a_lock_spend_tx, 0, xmr_swap.a_lock_tx_script, prevout_amount)
        '''
        # Double check a_lock_spend_tx is valid
        # Fails for part_blind
        ci_from.verifySCLockSpendTx(
            xmr_swap.a_lock_spend_tx,
            xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
            xmr_swap.dest_af, a_fee_rate, xmr_swap.vkbv)
        '''

        lock_tx_sent: bool = False
        # publishalocktx
        if bid.xmr_a_lock_tx and bid.xmr_a_lock_tx.state:
            if bid.xmr_a_lock_tx.state >= TxStates.TX_SENT:
                self.log.warning('Lock tx has already been sent {}'.format(bid.xmr_a_lock_tx.txid.hex()))
                lock_tx_sent = True

        if lock_tx_sent is False:
            lock_tx_signed = ci_from.signTxWithWallet(xmr_swap.a_lock_tx)
            txid_hex = ci_from.publishTx(lock_tx_signed)

            vout_pos = ci_from.getTxOutputPos(xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script)
            self.log.debug('Submitted lock txn %s to %s chain for bid %s', txid_hex, ci_from.coin_name(), bid_id.hex())

            if bid.xmr_a_lock_tx is None:
                bid.xmr_a_lock_tx = SwapTx(
                    bid_id=bid_id,
                    tx_type=TxTypes.XMR_SWAP_A_LOCK,
                    txid=bytes.fromhex(txid_hex),
                    vout=vout_pos,
                )
            bid.xmr_a_lock_tx.setState(TxStates.TX_SENT)
            self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_PUBLISHED, '', session)

        bid.setState(BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX)
        self.watchXmrSwap(bid, offer, xmr_swap, session)

        delay = self.get_short_delay_event_seconds()
        self.log.info('Sending lock spend tx message for bid %s in %d seconds', bid_id.hex(), delay)
        self.createActionInSession(delay, ActionTypes.SEND_XMR_SWAP_LOCK_SPEND_MSG, bid_id, session)

        self.saveBidInSession(bid_id, bid, session, xmr_swap)

    def sendXmrBidCoinBLockTx(self, bid_id: bytes, session) -> None:
        # Follower sending coin B lock tx
        self.log.debug('Sending coin B lock tx for adaptor-sig bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)
        b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate
        was_sent: bool = bid.was_received if reverse_bid else bid.was_sent

        if self.findTxB(ci_to, xmr_swap, bid, session, was_sent) is True:
            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            return

        if bid.xmr_b_lock_tx:
            self.log.warning('Coin B lock tx {} exists for adaptor-sig bid {}'.format(bid.xmr_b_lock_tx.b_lock_tx_id, bid_id.hex()))
            return

        if bid.debug_ind == DebugTypes.BID_STOP_AFTER_COIN_A_LOCK:
            self.log.debug('Adaptor-sig bid %s: Stalling bid for testing: %d.', bid_id.hex(), bid.debug_ind)
            bid.setState(BidStates.BID_STALLED_FOR_TEST)
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            return

        unlock_time = 0
        if bid.debug_ind in (DebugTypes.CREATE_INVALID_COIN_B_LOCK, DebugTypes.B_LOCK_TX_MISSED_SEND):
            bid.amount_to -= int(bid.amount_to * 0.1)
            self.log.debug('Adaptor-sig bid %s: Debug %d - Reducing lock b txn amount by 10%% to %s.', bid_id.hex(), bid.debug_ind, ci_to.format_amount(bid.amount_to))
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
        if bid.debug_ind == DebugTypes.SEND_LOCKED_XMR:
            unlock_time = 10000
            self.log.debug('Adaptor-sig bid %s: Debug %d - Sending locked XMR.', bid_id.hex(), bid.debug_ind)
            self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)

        try:
            b_lock_tx_id = ci_to.publishBLockTx(xmr_swap.vkbv, xmr_swap.pkbs, bid.amount_to, b_fee_rate, unlock_time=unlock_time)
            if bid.debug_ind == DebugTypes.B_LOCK_TX_MISSED_SEND:
                self.log.debug('Adaptor-sig bid %s: Debug %d - Losing xmr lock tx %s.', bid_id.hex(), bid.debug_ind, b_lock_tx_id.hex())
                self.logBidEvent(bid.bid_id, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
                raise TemporaryError('Fail for debug event')
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            error_msg = 'publishBLockTx failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            if num_retries < 5 and (ci_to.is_transient_error(ex) or self.is_transient_error(ex)):
                delay = self.get_delay_retry_seconds()
                self.log.info('Retrying sending adaptor-sig swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
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
        xmr_swap.b_lock_tx_id = b_lock_tx_id
        bid.xmr_b_lock_tx.setState(TxStates.TX_SENT)
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_PUBLISHED, '', session)

        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def sendXmrBidLockRelease(self, bid_id: bytes, session) -> None:
        # Leader sending lock tx a release secret (MSG5F)
        self.log.debug('Sending bid secret for adaptor-sig bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)

        msg_buf = XmrBidLockReleaseMessage(
            bid_msg_id=bid_id,
            al_lock_spend_tx_esig=xmr_swap.al_lock_spend_tx_esig)

        msg_bytes = msg_buf.to_bytes()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_LOCK_RELEASE_LF) + msg_bytes.hex()

        addr_send_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_send_to: str = offer.addr_from if reverse_bid else bid.bid_addr
        msg_valid: int = self.getActiveBidMsgValidTime()
        coin_a_lock_release_msg_id = self.sendSmsg(addr_send_from, addr_send_to, payload_hex, msg_valid)
        self.addMessageLink(Concepts.BID, bid_id, MessageTypes.XMR_BID_LOCK_RELEASE_LF, coin_a_lock_release_msg_id, session=session)

        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def redeemXmrBidCoinALockTx(self, bid_id: bytes, session) -> None:
        # Follower redeeming A lock tx
        self.log.debug('Redeeming coin A lock tx for adaptor-sig bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
        kbsf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)
        kaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF)

        al_lock_spend_sig = ci_from.decryptOtVES(kbsf, xmr_swap.al_lock_spend_tx_esig)
        prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
        v = ci_from.verifyTxSig(xmr_swap.a_lock_spend_tx, al_lock_spend_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, prevout_amount)
        ensure(v, 'Invalid coin A lock tx spend tx leader sig')

        af_lock_spend_sig = ci_from.signTx(kaf, xmr_swap.a_lock_spend_tx, 0, xmr_swap.a_lock_tx_script, prevout_amount)
        v = ci_from.verifyTxSig(xmr_swap.a_lock_spend_tx, af_lock_spend_sig, xmr_swap.pkaf, 0, xmr_swap.a_lock_tx_script, prevout_amount)
        ensure(v, 'Invalid coin A lock tx spend tx follower sig')

        witness_stack = []
        if coin_from not in (Coins.DCR,):
            witness_stack += [b'',]
        witness_stack += [
            al_lock_spend_sig,
            af_lock_spend_sig,
            xmr_swap.a_lock_tx_script,
        ]

        xmr_swap.a_lock_spend_tx = ci_from.setTxSignature(xmr_swap.a_lock_spend_tx, witness_stack)

        txid = bytes.fromhex(ci_from.publishTx(xmr_swap.a_lock_spend_tx))
        self.log.debug('Submitted lock spend txn %s to %s chain for bid %s', txid.hex(), ci_from.coin_name(), bid_id.hex())
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_SPEND_TX_PUBLISHED, '', session)
        if bid.xmr_a_lock_spend_tx is None:
            bid.xmr_a_lock_spend_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.XMR_SWAP_A_LOCK_SPEND,
                txid=txid,
            )
            bid.xmr_a_lock_spend_tx.setState(TxStates.TX_NONE)
        else:
            self.log.warning('Chain A lock TX %s already exists for bid %s', bid.xmr_a_lock_spend_tx.txid.hex(), bid_id.hex())

        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def redeemXmrBidCoinBLockTx(self, bid_id: bytes, session) -> None:
        # Leader redeeming B lock tx
        self.log.debug('Redeeming coin B lock tx for adaptor-sig bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate

        try:
            chain_height = ci_to.getChainHeight()
            lock_tx_depth = (chain_height - bid.xmr_b_lock_tx.chain_height) + 1
            if lock_tx_depth < ci_to.depth_spendable():
                raise TemporaryError(f'Chain B lock tx depth {lock_tx_depth} < required for spending.')

            # Extract the leader's decrypted signature and use it to recover the follower's privatekey
            xmr_swap.al_lock_spend_tx_sig = ci_from.extractLeaderSig(xmr_swap.a_lock_spend_tx)

            kbsf = ci_from.recoverEncKey(xmr_swap.al_lock_spend_tx_esig, xmr_swap.al_lock_spend_tx_sig, xmr_swap.pkasf)
            assert (kbsf is not None)

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSL, for_ed25519)
            vkbs = ci_to.sumKeys(kbsl, kbsf)

            if coin_to == (Coins.XMR, Coins.WOW):
                address_to = self.getCachedMainWalletAddress(ci_to, session)
            elif coin_to in (Coins.PART_BLIND, Coins.PART_ANON):
                address_to = self.getCachedStealthAddressForCoin(coin_to, session)
            else:
                address_to = self.getReceiveAddressFromPool(coin_to, bid_id, TxTypes.XMR_SWAP_B_LOCK_SPEND, session)

            lock_tx_vout = bid.getLockTXBVout()
            txid = ci_to.spendBLockTx(xmr_swap.b_lock_tx_id, address_to, xmr_swap.vkbv, vkbs, bid.amount_to, b_fee_rate, bid.chain_b_height_start, lock_tx_vout=lock_tx_vout)
            self.log.debug('Submitted lock B spend txn %s to %s chain for bid %s', txid.hex(), ci_to.coin_name(), bid_id.hex())
            self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED, '', session)
        except Exception as ex:
            error_msg = 'spendBLockTx failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_SPEND, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            if num_retries < 100 and (ci_to.is_transient_error(ex) or self.is_transient_error(ex)):
                delay = self.get_delay_retry_seconds()
                self.log.info('Retrying sending adaptor-sig swap chain B spend tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createActionInSession(delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'spendBLockTx failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid.bid_id, EventLogTypes.FAILED_TX_B_SPEND, str(ex), session)
            return

        bid.xmr_b_lock_tx.spend_txid = txid
        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
        if bid.xmr_b_lock_tx:
            bid.xmr_b_lock_tx.setState(TxStates.TX_REDEEMED)

        # TODO: Why does using bid.txns error here?
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def recoverXmrBidCoinBLockTx(self, bid_id: bytes, session) -> None:
        # Follower recovering B lock tx
        self.log.debug('Recovering coin B lock tx for adaptor-sig bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate

        # Extract the follower's decrypted signature and use it to recover the leader's privatekey
        af_lock_refund_spend_tx_sig = ci_from.extractFollowerSig(xmr_swap.a_lock_refund_spend_tx)

        kbsl = ci_from.recoverEncKey(xmr_swap.af_lock_refund_spend_tx_esig, af_lock_refund_spend_tx_sig, xmr_swap.pkasl)
        assert (kbsl is not None)

        for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
        kbsf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)
        vkbs = ci_to.sumKeys(kbsl, kbsf)

        try:
            if offer.coin_to in (Coins.XMR, Coins.WOW):
                address_to = self.getCachedMainWalletAddress(ci_to, session)
            elif coin_to in (Coins.PART_BLIND, Coins.PART_ANON):
                address_to = self.getCachedStealthAddressForCoin(coin_to, session)
            else:
                address_to = self.getReceiveAddressFromPool(coin_to, bid_id, TxTypes.XMR_SWAP_B_LOCK_REFUND, session)

            lock_tx_vout = bid.getLockTXBVout()
            txid = ci_to.spendBLockTx(xmr_swap.b_lock_tx_id, address_to, xmr_swap.vkbv, vkbs, bid.amount_to, b_fee_rate, bid.chain_b_height_start, lock_tx_vout=lock_tx_vout)
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
                delay = self.get_delay_retry_seconds()
                self.log.info('Retrying sending adaptor-sig swap chain B refund tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createActionInSession(delay, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'spendBLockTx for refund failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid.bid_id, EventLogTypes.FAILED_TX_B_REFUND, str_error, session)
            return

        bid.xmr_b_lock_tx.spend_txid = txid

        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED)
        if bid.xmr_b_lock_tx:
            bid.xmr_b_lock_tx.setState(TxStates.TX_REFUNDED)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def sendXmrBidCoinALockSpendTxMsg(self, bid_id: bytes, session) -> None:
        # Send MSG4F L -> F
        self.log.debug('Sending coin A lock spend tx msg for adaptor-sig bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        addr_send_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_send_to: str = offer.addr_from if reverse_bid else bid.bid_addr

        msg_buf = XmrBidLockSpendTxMessage(
            bid_msg_id=bid_id,
            a_lock_spend_tx=xmr_swap.a_lock_spend_tx,
            kal_sig=xmr_swap.kal_sig)

        msg_bytes = msg_buf.to_bytes()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_LOCK_SPEND_TX_LF) + msg_bytes.hex()

        msg_valid: int = self.getActiveBidMsgValidTime()
        xmr_swap.coin_a_lock_refund_spend_tx_msg_id = self.sendSmsg(addr_send_from, addr_send_to, payload_hex, msg_valid)

        bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def processXmrBidCoinALockSigs(self, msg) -> None:
        # Leader processing MSG3L
        self.log.debug('Processing xmr coin a follower lock sigs msg %s', msg['msgid'])
        now: int = self.getTime()
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockTxSigsMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, 'Bad bid_msg_id length')
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        addr_sent_from: str = offer.addr_from if reverse_bid else bid.bid_addr
        addr_sent_to: str = bid.bid_addr if reverse_bid else offer.addr_from
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        ensure(msg['to'] == addr_sent_to, 'Received on incorrect address')
        ensure(msg['from'] == addr_sent_from, 'Sent from incorrect address')

        try:
            allowed_states = [BidStates.BID_ACCEPTED, ]
            if bid.was_sent and offer.was_sent:
                allowed_states.append(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            ensure(bid.state in allowed_states, 'Invalid state for bid {}'.format(bid.state))
            xmr_swap.af_lock_refund_spend_tx_esig = msg_data.af_lock_refund_spend_tx_esig
            xmr_swap.af_lock_refund_tx_sig = msg_data.af_lock_refund_tx_sig

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSL, for_ed25519)
            kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAL)

            xmr_swap.af_lock_refund_spend_tx_sig = ci_from.decryptOtVES(kbsl, xmr_swap.af_lock_refund_spend_tx_esig)
            prevout_amount = ci_from.getLockRefundTxSwapOutputValue(bid, xmr_swap)
            al_lock_refund_spend_tx_sig = ci_from.signTx(kal, xmr_swap.a_lock_refund_spend_tx, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount)

            self.log.debug('Setting lock refund spend tx sigs')
            witness_stack = []
            if coin_from not in (Coins.DCR, ):
                witness_stack += [b'',]
            witness_stack += [
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
            xmr_swap_1.addLockRefundSigs(self, xmr_swap, ci_from)

            delay = self.get_delay_event_seconds()
            self.log.info('Sending coin A lock tx for adaptor-sig bid %s in %d seconds', bid_id.hex(), delay)
            self.createAction(delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_A, bid_id)

            bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))

    def processXmrBidLockSpendTx(self, msg) -> None:
        # Follower receiving MSG4F
        self.log.debug('Processing adaptor-sig bid lock spend tx msg %s', msg['msgid'])
        now: int = self.getTime()
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockSpendTxMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, 'Bad bid_msg_id length')
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)
        addr_sent_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_sent_to: str = offer.addr_from if reverse_bid else bid.bid_addr
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate

        ensure(msg['to'] == addr_sent_to, 'Received on incorrect address')
        ensure(msg['from'] == addr_sent_from, 'Sent from incorrect address')

        try:
            xmr_swap.a_lock_spend_tx = msg_data.a_lock_spend_tx
            xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)
            if bid.xmr_a_lock_tx:
                bid.xmr_a_lock_tx.spend_txid = xmr_swap.a_lock_spend_tx_id
            xmr_swap.kal_sig = msg_data.kal_sig

            ci_from.verifySCLockSpendTx(
                xmr_swap.a_lock_spend_tx,
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                xmr_swap.dest_af, a_fee_rate, xmr_swap.vkbv)

            ci_from.verifyCompactSig(xmr_swap.pkal, 'proof key owned for swap', xmr_swap.kal_sig)

            if bid.state == BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS:
                bid.setState(BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX)
                bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX)
            else:
                self.log.warning('processXmrBidLockSpendTx bid {} unexpected state {}'.format(bid_id.hex(), bid.state))
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))

        # Update copy of bid in swaps_in_progress
        self.swaps_in_progress[bid_id] = (bid, offer)

    def processXmrSplitMessage(self, msg) -> None:
        self.log.debug('Processing xmr split msg %s', msg['msgid'])
        now: int = self.getTime()
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrSplitMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        # Validate data
        ensure(len(msg_data.msg_id) == 28, 'Bad msg_id length')
        self.log.debug('for bid %s', msg_data.msg_id.hex())

        # TODO: Wait for bid msg to arrive first

        if msg_data.msg_type == XmrSplitMsgTypes.BID or msg_data.msg_type == XmrSplitMsgTypes.BID_ACCEPT:
            session = self.openSession()
            try:
                q = session.execute(text('SELECT COUNT(*) FROM xmr_split_data WHERE bid_id = x\'{}\' AND msg_type = {} AND msg_sequence = {}'.format(msg_data.msg_id.hex(), msg_data.msg_type, msg_data.sequence))).first()
                num_exists = q[0]
                if num_exists > 0:
                    self.log.warning('Ignoring duplicate xmr_split_data entry: ({}, {}, {})'.format(msg_data.msg_id.hex(), msg_data.msg_type, msg_data.sequence))
                    return

                dbr = XmrSplitData()
                dbr.addr_from = msg['from']
                dbr.addr_to = msg['to']
                dbr.bid_id = msg_data.msg_id
                dbr.msg_type = msg_data.msg_type
                dbr.msg_sequence = msg_data.sequence
                dbr.dleag = msg_data.dleag
                dbr.created_at = now
                session.add(dbr)
            finally:
                self.closeSession(session)

    def processXmrLockReleaseMessage(self, msg) -> None:
        self.log.debug('Processing adaptor-sig swap lock release msg %s', msg['msgid'])
        now: int = self.getTime()
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockReleaseMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        # Validate data
        ensure(len(msg_data.bid_msg_id) == 28, 'Bad msg_id length')

        bid_id = msg_data.bid_msg_id
        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        addr_sent_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_sent_to: str = offer.addr_from if reverse_bid else bid.bid_addr

        ensure(msg['to'] == addr_sent_to, 'Received on incorrect address')
        ensure(msg['from'] == addr_sent_from, 'Sent from incorrect address')

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

        delay = self.get_delay_event_seconds()
        self.log.info('Redeeming coin A lock tx for adaptor-sig bid %s in %d seconds', bid_id.hex(), delay)
        self.createAction(delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_A, bid_id)

        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        self.swaps_in_progress[bid_id] = (bid, offer)

    def processADSBidReversed(self, msg) -> None:
        self.log.debug('Processing adaptor-sig reverse bid msg %s', msg['msgid'])

        now: int = self.getTime()
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = ADSBidIntentMessage(init_all=False)
        bid_data.from_bytes(bid_bytes)

        # Validate data
        ensure(bid_data.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG, 'Invalid protocol version')
        ensure(len(bid_data.offer_msg_id) == 28, 'Bad offer_id length')

        offer_id = bid_data.offer_msg_id
        offer, xmr_offer = self.getXmrOffer(offer_id, sent=True)
        ensure(offer and offer.was_sent, 'Offer not found: {}.'.format(offer_id.hex()))
        ensure(offer.swap_type == SwapTypes.XMR_SWAP, 'Bid/offer swap type mismatch')
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(offer_id.hex()))

        ci_from = self.ci(offer.coin_to)
        ci_to = self.ci(offer.coin_from)

        if not validOfferStateToReceiveBid(offer.state):
            raise ValueError('Bad offer state')
        ensure(msg['to'] == offer.addr_from, 'Received on incorrect address')
        ensure(now <= offer.expire_at, 'Offer expired')
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid)
        ensure(now <= msg['sent'] + bid_data.time_valid, 'Bid expired')

        # ci_from/to are reversed
        bid_rate: int = ci_to.make_int(bid_data.amount_to / bid_data.amount_from, r=1)
        reversed_rate: int = ci_from.make_int(bid_data.amount_from / bid_data.amount_to, r=1)
        self.validateBidAmount(offer, bid_data.amount_from, bid_rate)

        bid_id = bytes.fromhex(msg['msgid'])

        bid, xmr_swap = self.getXmrBid(bid_id)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                protocol_version=bid_data.protocol_version,
                amount=bid_data.amount_to,
                amount_to=bid_data.amount_from,
                rate=reversed_rate,
                created_at=msg['sent'],
                expire_at=msg['sent'] + bid_data.time_valid,
                bid_addr=msg['from'],
                was_sent=False,
                was_received=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
            )

            xmr_swap = XmrSwap(
                bid_id=bid_id,
            )
            wallet_restore_height = self.getWalletRestoreHeight(ci_to)
            if bid.chain_b_height_start < wallet_restore_height:
                bid.chain_b_height_start = wallet_restore_height
                self.log.warning('Adaptor-sig swap restore height clamped to {}'.format(wallet_restore_height))
        else:
            ensure(bid.state == BidStates.BID_REQUEST_SENT, 'Wrong bid state: {}'.format(BidStates(bid.state).name))
            # Don't update bid.created_at, it's been used to derive kaf
            bid.expire_at = msg['sent'] + bid_data.time_valid
            bid.was_received = True

        bid.setState(BidStates.BID_RECEIVED)  # BID_REQUEST_RECEIVED

        self.log.info('Received reverse adaptor-sig bid %s for offer %s', bid_id.hex(), bid_data.offer_msg_id.hex())
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

        try:
            session = self.openSession()
            self.notify(NT.BID_RECEIVED, {'type': 'ads_reversed', 'bid_id': bid.bid_id.hex(), 'offer_id': bid.offer_id.hex()}, session)

            options = {'reverse_bid': True, 'bid_rate': bid_rate}
            if self.shouldAutoAcceptBid(offer, bid, session, options=options):
                delay = self.get_delay_event_seconds()
                self.log.info('Auto accepting reverse adaptor-sig bid %s in %d seconds', bid.bid_id.hex(), delay)
                self.createActionInSession(delay, ActionTypes.ACCEPT_AS_REV_BID, bid.bid_id, session)
                bid.setState(BidStates.SWAP_DELAYING)
        finally:
            self.closeSession(session)

    def processADSBidReversedAccept(self, msg) -> None:
        self.log.debug('Processing adaptor-sig reverse bid accept msg %s', msg['msgid'])

        now: int = self.getTime()
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = ADSBidIntentAcceptMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        bid_id = msg_data.bid_msg_id
        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))

        ensure(msg['to'] == bid.bid_addr, 'Received on incorrect address')
        ensure(msg['from'] == offer.addr_from, 'Sent from incorrect address')

        ci_from = self.ci(offer.coin_to)
        ci_to = self.ci(offer.coin_from)

        ensure(ci_to.verifyKey(msg_data.kbvf), 'Invalid chain B follower view key')
        ensure(ci_from.verifyPubkey(msg_data.pkaf), 'Invalid chain A follower public key')
        ensure(ci_from.isValidAddressHash(msg_data.dest_af) or ci_from.isValidPubkey(msg_data.dest_af), 'Invalid destination address')
        if ci_to.curve_type() == Curves.ed25519:
            ensure(len(msg_data.kbsf_dleag) == 16000, 'Invalid kbsf_dleag size')

        xmr_swap.dest_af = msg_data.dest_af
        xmr_swap.pkaf = msg_data.pkaf
        xmr_swap.vkbvf = msg_data.kbvf
        xmr_swap.pkbvf = ci_to.getPubkey(msg_data.kbvf)
        xmr_swap.kbsf_dleag = msg_data.kbsf_dleag

        bid.chain_a_height_start: int = ci_from.getChainHeight()
        bid.chain_b_height_start: int = ci_to.getChainHeight()

        wallet_restore_height: int = self.getWalletRestoreHeight(ci_to)
        if bid.chain_b_height_start < wallet_restore_height:
            bid.chain_b_height_start = wallet_restore_height
            self.log.warning('Reverse adaptor-sig swap restore height clamped to {}'.format(wallet_restore_height))

        bid.setState(BidStates.BID_RECEIVING)

        self.log.info('Receiving reverse adaptor-sig bid %s for offer %s', bid_id.hex(), bid.offer_id.hex())
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

        try:
            session = self.openSession()
            self.notify(NT.BID_ACCEPTED, {'bid_id': bid_id.hex()}, session)
            if ci_to.curve_type() != Curves.ed25519:
                self.receiveXmrBid(bid, session)
        finally:
            self.closeSession(session)

    def processMsg(self, msg) -> None:
        try:
            msg_type = int(msg['hex'][:2], 16)

            rv = None
            if msg_type == MessageTypes.OFFER:
                self.processOffer(msg)
            elif msg_type == MessageTypes.OFFER_REVOKE:
                self.processOfferRevoke(msg)
            # TODO: When changing from wallet keys (encrypted/locked) handle swap messages while locked
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
            elif msg_type == MessageTypes.ADS_BID_LF:
                self.processADSBidReversed(msg)
            elif msg_type == MessageTypes.ADS_BID_ACCEPT_FL:
                self.processADSBidReversedAccept(msg)

        except InactiveCoin as ex:
            self.log.debug('Ignoring message involving inactive coin {}, type {}'.format(Coins(ex.coinid).name, MessageTypes(msg_type).name))
        except Exception as ex:
            self.log.error('processMsg %s', str(ex))
            if self.debug:
                self.log.error(traceback.format_exc())
                self.logEvent(Concepts.NETWORK_MESSAGE,
                              bytes.fromhex(msg['msgid']),
                              EventLogTypes.ERROR,
                              str(ex),
                              None)

    def processZmqSmsg(self) -> None:
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
                    self.delay_event.wait(1)
                else:
                    raise e

        self.processMsg(msg)

    def expireBidsAndOffers(self, now) -> None:
        bids_to_expire = set()
        offers_to_expire = set()
        check_records: bool = False

        for i, (bid_id, expired_at) in enumerate(self._expiring_bids):
            if expired_at <= now:
                bids_to_expire.add(bid_id)
                self._expiring_bids.pop(i)
        for i, (offer_id, expired_at) in enumerate(self._expiring_offers):
            if expired_at <= now:
                offers_to_expire.add(offer_id)
                self._expiring_offers.pop(i)

        if now - self._last_checked_expiring_bids_offers >= self.check_expiring_bids_offers_seconds:
            check_records = True
            self._last_checked_expiring_bids = now

        if len(bids_to_expire) == 0 and len(offers_to_expire) == 0 and check_records is False:
            return

        bids_expired: int = 0
        offers_expired: int = 0
        try:
            session = self.openSession()

            if check_records:
                query = '''SELECT 1, bid_id, expire_at FROM bids WHERE active_ind = 1 AND state IN (:bid_received, :bid_sent) AND expire_at <= :check_time
                           UNION ALL
                           SELECT 2, offer_id, expire_at FROM offers WHERE active_ind = 1 AND state IN (:offer_received, :offer_sent) AND expire_at <= :check_time
                '''
                q = session.execute(text(query), {'bid_received': int(BidStates.BID_RECEIVED),
                                                  'offer_received': int(OfferStates.OFFER_RECEIVED),
                                                  'bid_sent': int(BidStates.BID_SENT),
                                                  'offer_sent': int(OfferStates.OFFER_SENT),
                                                  'check_time': now + self.check_expiring_bids_offers_seconds})
                for entry in q:
                    record_id = entry[1]
                    expire_at = entry[2]
                    if entry[0] == 1:
                        if expire_at > now:
                            self._expiring_bids.append((record_id, expire_at))
                        else:
                            bids_to_expire.add(record_id)
                    elif entry[0] == 2:
                        if expire_at > now:
                            self._expiring_offers.append((record_id, expire_at))
                        else:
                            offers_to_expire.add(record_id)

            for bid_id in bids_to_expire:
                query = text('SELECT expire_at, states FROM bids WHERE bid_id = :bid_id AND active_ind = 1 AND state IN (:bid_received, :bid_sent)')
                rows = session.execute(query, {'bid_id': bid_id,
                                               'bid_received': int(BidStates.BID_RECEIVED),
                                               'bid_sent': int(BidStates.BID_SENT)}).fetchall()
                if len(rows) > 0:
                    new_state: int = int(BidStates.BID_EXPIRED)
                    states = (bytes() if rows[0][1] is None else rows[0][1]) + pack_state(new_state, now)
                    query = 'UPDATE bids SET state = :new_state, states = :states WHERE bid_id = :bid_id'
                    session.execute(text(query), {'bid_id': bid_id, 'new_state': new_state, 'states': states})
                    bids_expired += 1
            for offer_id in offers_to_expire:
                query = 'SELECT expire_at, states FROM offers WHERE offer_id = :offer_id AND active_ind = 1 AND state IN (:offer_received, :offer_sent)'
                rows = session.execute(text(query), {'offer_id': offer_id,
                                                     'offer_received': int(OfferStates.OFFER_RECEIVED),
                                                     'offer_sent': int(OfferStates.OFFER_SENT)}).fetchall()
                if len(rows) > 0:
                    new_state: int = int(OfferStates.OFFER_EXPIRED)
                    states = (bytes() if rows[0][1] is None else rows[0][1]) + pack_state(new_state, now)
                    query = 'UPDATE offers SET state = :new_state, states = :states WHERE offer_id = :offer_id'
                    session.execute(text(query), {'offer_id': offer_id, 'new_state': new_state, 'states': states})
                    offers_expired += 1
        finally:
            self.closeSession(session)

        if bids_expired + offers_expired > 0:
            mb = '' if bids_expired == 1 else 's'
            mo = '' if offers_expired == 1 else 's'
            self.log.debug(f'Expired {bids_expired} bid{mb} and {offers_expired} offer{mo}')

    def update(self) -> None:
        if self._zmq_queue_enabled:
            try:
                if self._read_zmq_queue:
                    message = self.zmqSubscriber.recv(flags=zmq.NOBLOCK)
                    if message == b'smsg':
                        self.processZmqSmsg()
            except zmq.Again as ex:
                pass
            except Exception as ex:
                self.logException(f'smsg zmq {ex}')

        if self._poll_smsg:
            now: int = self.getTime()
            if now - self._last_checked_smsg >= self.check_smsg_seconds:
                self._last_checked_smsg = now
                options = {'encoding': 'hex', 'setread': True}
                msgs = self.callrpc('smsginbox', ['unread', '', options])
                for msg in msgs['messages']:
                    self.processMsg(msg)

        try:
            # TODO: Wait for blocks / txns, would need to check multiple coins
            now: int = self.getTime()
            self.expireBidsAndOffers(now)

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
                    if k == Coins.PART_ANON or k == Coins.PART_BLIND or k == Coins.LTC_MWEB:
                        continue
                    if len(c['watched_outputs']) > 0 or len(c['watched_scripts']):
                        self.checkForSpends(k, c)
                self._last_checked_watched = now

            if now - self._last_checked_expired >= self.check_expired_seconds:
                self.expireMessages()
                self.expireDBRecords()
                self.checkAcceptedBids()
                self._last_checked_expired = now

            if now - self._last_checked_actions >= self.check_actions_seconds:
                self.checkQueuedActions()
                self._last_checked_actions = now

            if now - self._last_checked_xmr_swaps >= self.check_xmr_swaps_seconds:
                self.checkXmrSwaps()
                self._last_checked_xmr_swaps = now

        except Exception as ex:
            self.logException(f'update {ex}')

    def manualBidUpdate(self, bid_id: bytes, data) -> None:
        self.log.info('Manually updating bid %s', bid_id.hex())

        add_bid_action = -1
        try:
            session = self.openSession()
            bid, offer = self.getBidAndOffer(bid_id, session)
            ensure(bid, 'Bid not found {}'.format(bid_id.hex()))
            ensure(offer, 'Offer not found {}'.format(bid.offer_id.hex()))

            has_changed = False
            if bid.state != data['bid_state']:
                bid.setState(data['bid_state'])
                self.log.warning('Set state to %s', strBidState(bid.state))
                has_changed = True

            if data.get('bid_action', -1) != -1:
                self.log.warning('Adding action', ActionTypes(data['bid_action']).name)
                add_bid_action = ActionTypes(data['bid_action'])
                has_changed = True

            if 'debug_ind' in data:
                if bid.debug_ind != data['debug_ind']:
                    if bid.debug_ind is None and data['debug_ind'] == -1:
                        pass  # Already unset
                    else:
                        self.log.debug('Bid %s Setting debug flag: %s', bid_id.hex(), data['debug_ind'])
                        bid.debug_ind = data['debug_ind']
                        has_changed = True

            if data.get('kbs_other', None) is not None:
                return xmr_swap_1.recoverNoScriptTxnWithKey(self, bid_id, data['kbs_other'])

            if has_changed:
                activate_bid = False
                if bid.state and isActiveBidState(bid.state):
                    activate_bid = True

                if add_bid_action > -1:
                    delay = self.get_delay_event_seconds()
                    self.createActionInSession(delay, add_bid_action, bid_id, session)

                if activate_bid:
                    self.activateBid(session, bid)
                else:
                    self.deactivateBid(session, offer, bid)

                self.saveBidInSession(bid_id, bid, session)
                session.commit()
            else:
                raise ValueError('No changes')
        finally:
            self.closeSession(session, commit=False)

    def editGeneralSettings(self, data):
        self.log.info('Updating general settings')
        settings_changed = False
        suggest_reboot = False
        settings_copy = copy.deepcopy(self.settings)
        with self.mxDB:
            if 'debug' in data:
                new_value = data['debug']
                ensure(isinstance(new_value, bool), 'New debug value not boolean')
                if settings_copy.get('debug', False) != new_value:
                    self.debug = new_value
                    settings_copy['debug'] = new_value
                    settings_changed = True

            if 'debug_ui' in data:
                new_value = data['debug_ui']
                ensure(isinstance(new_value, bool), 'New debug_ui value not boolean')
                if settings_copy.get('debug_ui', False) != new_value:
                    self.debug_ui = new_value
                    settings_copy['debug_ui'] = new_value
                    settings_changed = True

            if 'expire_db_records' in data:
                new_value = data['expire_db_records']
                ensure(isinstance(new_value, bool), 'New expire_db_records value not boolean')
                if settings_copy.get('expire_db_records', False) != new_value:
                    self._expire_db_records = new_value
                    settings_copy['expire_db_records'] = new_value
                    settings_changed = True

            if 'show_chart' in data:
                new_value = data['show_chart']
                ensure(isinstance(new_value, bool), 'New show_chart value not boolean')
                if settings_copy.get('show_chart', True) != new_value:
                    settings_copy['show_chart'] = new_value
                    settings_changed = True

            if 'chart_api_key' in data:
                new_value = data['chart_api_key']
                ensure(isinstance(new_value, str), 'New chart_api_key value not a string')
                ensure(len(new_value) <= 128, 'New chart_api_key value too long')
                if all(c in string.hexdigits for c in new_value):
                    if settings_copy.get('chart_api_key', '') != new_value:
                        settings_copy['chart_api_key'] = new_value
                        if 'chart_api_key_enc' in settings_copy:
                            settings_copy.pop('chart_api_key_enc')
                        settings_changed = True
                else:
                    # Encode value as hex to avoid escaping
                    new_value = new_value.encode('utf-8').hex()
                    if settings_copy.get('chart_api_key_enc', '') != new_value:
                        settings_copy['chart_api_key_enc'] = new_value
                        if 'chart_api_key' in settings_copy:
                            settings_copy.pop('chart_api_key')
                        settings_changed = True

            if 'coingecko_api_key' in data:
                new_value = data['coingecko_api_key']
                ensure(isinstance(new_value, str), 'New coingecko_api_key value not a string')
                ensure(len(new_value) <= 128, 'New coingecko_api_keyvalue too long')
                if all(c in string.hexdigits for c in new_value):
                    if settings_copy.get('coingecko_api_key', '') != new_value:
                        settings_copy['coingecko_api_key'] = new_value
                        if 'coingecko_api_key_enc' in settings_copy:
                            settings_copy.pop('coingecko_api_key_enc')
                        settings_changed = True
                else:
                    # Encode value as hex to avoid escaping
                    new_value = new_value.encode('utf-8').hex()
                    if settings_copy.get('coingecko_api_key_enc', '') != new_value:
                        settings_copy['coingecko_api_key_enc'] = new_value
                        if 'coingecko_api_key' in settings_copy:
                            settings_copy.pop('coingecko_api_key')
                        settings_changed = True

            if 'enabled_chart_coins' in data:
                new_value = data['enabled_chart_coins'].strip()
                ensure(isinstance(new_value, str), 'New enabled_chart_coins value not a string')
                if new_value.lower() == 'all' or new_value == '':
                    pass
                else:
                    tickers = new_value.split(',')
                    seen_tickers = []
                    for ticker in tickers:
                        upcased_ticker = ticker.strip().upper()
                        if upcased_ticker not in known_chart_coins:
                            raise ValueError(f'Unknown coin: {ticker}')
                        if upcased_ticker in seen_tickers:
                            raise ValueError(f'Duplicate coin: {ticker}')
                        seen_tickers.append(upcased_ticker)
                if settings_copy.get('enabled_chart_coins', '') != new_value:
                    settings_copy['enabled_chart_coins'] = new_value
                    settings_changed = True

            if settings_changed:
                settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
                settings_path_new = settings_path + '.new'
                shutil.copyfile(settings_path, settings_path + '.last')
                with open(settings_path_new, 'w') as fp:
                    json.dump(settings_copy, fp, indent=4)
                shutil.move(settings_path_new, settings_path)
                self.settings = settings_copy
        return settings_changed, suggest_reboot

    def editSettings(self, coin_name: str, data):
        self.log.info(f'Updating settings {coin_name}')
        settings_changed = False
        suggest_reboot = False
        settings_copy = copy.deepcopy(self.settings)
        with self.mxDB:
            settings_cc = settings_copy['chainclients'][coin_name]
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

            # Ensure remote_daemon_urls appears in settings if automatically_select_daemon is present
            if 'automatically_select_daemon' in settings_cc and 'remote_daemon_urls' not in settings_cc:
                settings_cc['remote_daemon_urls'] = []
                settings_changed = True

            if 'fee_priority' in data:
                new_fee_priority = data['fee_priority']
                ensure(new_fee_priority >= 0 and new_fee_priority < 4, 'Invalid priority')

                if settings_cc.get('fee_priority', 0) != new_fee_priority:
                    settings_changed = True
                    settings_cc['fee_priority'] = new_fee_priority
                    for coin, cc in self.coin_clients.items():
                        if cc['name'] == coin_name:
                            cc['fee_priority'] = new_fee_priority
                            if self.isCoinActive(coin):
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
                            if self.isCoinActive(coin):
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
                            if self.isCoinActive(coin):
                                self.ci(coin).setAnonTxRingSize(new_anon_tx_ring_size)
                            break

            if 'wallet_pwd' in data:
                new_wallet_pwd = data['wallet_pwd']
                if settings_cc.get('wallet_pwd', '') != new_wallet_pwd:
                    settings_changed = True
                    settings_cc['wallet_pwd'] = new_wallet_pwd

            if settings_changed:
                settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
                settings_path_new = settings_path + '.new'
                shutil.copyfile(settings_path, settings_path + '.last')
                with open(settings_path_new, 'w') as fp:
                    json.dump(settings_copy, fp, indent=4)
                shutil.move(settings_path_new, settings_path)
                self.settings = settings_copy
        return settings_changed, suggest_reboot

    def enableCoin(self, coin_name: str) -> None:
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

    def disableCoin(self, coin_name: str) -> None:
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

        now: int = self.getTime()
        q_bids_str = '''SELECT
                        COUNT(CASE WHEN b.was_sent THEN 1 ELSE NULL END) AS count_sent,
                        COUNT(CASE WHEN b.was_sent AND (s.in_progress OR (s.swap_ended = 0 AND b.expire_at > {} AND o.expire_at > {})) THEN 1 ELSE NULL END) AS count_sent_active,
                        COUNT(CASE WHEN b.was_received THEN 1 ELSE NULL END) AS count_received,
                        COUNT(CASE WHEN b.was_received AND b.state = {} AND b.expire_at > {} AND o.expire_at > {} THEN 1 ELSE NULL END) AS count_available,
                        COUNT(CASE WHEN b.was_received AND (s.in_progress OR (s.swap_ended = 0 AND b.expire_at > {} AND o.expire_at > {})) THEN 1 ELSE NULL END) AS count_recv_active
                        FROM bids b
                        JOIN offers o ON b.offer_id = o.offer_id
                        JOIN bidstates s ON b.state = s.state_id
                        WHERE b.active_ind = 1'''.format(now, now, BidStates.BID_RECEIVED, now, now, now, now)

        q_offers_str = '''SELECT
                          COUNT(CASE WHEN expire_at > {} THEN 1 ELSE NULL END) AS count_active,
                          COUNT(CASE WHEN was_sent THEN 1 ELSE NULL END) AS count_sent,
                          COUNT(CASE WHEN was_sent AND expire_at > {} THEN 1 ELSE NULL END) AS count_sent_active
                          FROM offers WHERE active_ind = 1'''.format(now, now)

        with self.engine.connect() as conn:
            q = conn.execute(text(q_bids_str)).first()
            bids_sent = q[0]
            bids_sent_active = q[1]
            bids_received = q[2]
            bids_available = q[3]
            bids_recv_active = q[4]

            q = conn.execute(text(q_offers_str)).first()
            num_offers = q[0]
            num_sent_offers = q[1]
            num_sent_active_offers = q[2]

        rv = {
            'network': self.chain,
            'num_swapping': len(self.swaps_in_progress),
            'num_network_offers': num_offers,
            'num_sent_offers': num_sent_offers,
            'num_sent_active_offers': num_sent_active_offers,
            'num_recv_bids': bids_received,
            'num_sent_bids': bids_sent,
            'num_sent_active_bids': bids_sent_active,
            'num_recv_active_bids': bids_recv_active,
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
            rv = {
                'deposit_address': self.getCachedAddressForCoin(coin),
                'balance': ci.format_amount(walletinfo['balance'], conv_int=True),
                'unconfirmed': ci.format_amount(walletinfo['unconfirmed_balance'], conv_int=True),
                'expected_seed': ci.knownWalletSeed(),
                'encrypted': walletinfo['encrypted'],
                'locked': walletinfo['locked'],
            }

            if 'immature_balance' in walletinfo:
                rv['immature'] = ci.format_amount(walletinfo['immature_balance'], conv_int=True)

            if 'locked_utxos' in walletinfo:
                rv['locked_utxos'] = walletinfo['locked_utxos']

            if coin == Coins.PART:
                rv['stealth_address'] = self.getCachedStealthAddressForCoin(Coins.PART)
                rv['anon_balance'] = walletinfo['anon_balance']
                rv['anon_pending'] = walletinfo['unconfirmed_anon'] + walletinfo['immature_anon_balance']
                rv['blind_balance'] = walletinfo['blind_balance']
                rv['blind_unconfirmed'] = walletinfo['unconfirmed_blind']
            elif coin in (Coins.XMR, Coins.WOW):
                rv['main_address'] = self.getCachedMainWalletAddress(ci)
            elif coin == Coins.NAV:
                rv['immature'] = walletinfo['immature_balance']
            elif coin == Coins.LTC:
                rv['mweb_address'] = self.getCachedStealthAddressForCoin(Coins.LTC_MWEB)
                rv['mweb_balance'] = walletinfo['mweb_balance']
                rv['mweb_pending'] = walletinfo['mweb_unconfirmed'] + walletinfo['mweb_immature']

            return rv
        except Exception as e:
            self.log.warning('getWalletInfo for %s failed with: %s', ci.coin_name(), str(e))

    def addWalletInfoRecord(self, coin, info_type, wi) -> None:
        coin_id = int(coin)
        session = self.openSession()
        try:
            now: int = self.getTime()
            session.add(Wallets(coin_id=coin, balance_type=info_type, wallet_data=json.dumps(wi), created_at=now))
            query_str = f'DELETE FROM wallets WHERE (coin_id = {coin_id} AND balance_type = {info_type}) AND record_id NOT IN (SELECT record_id FROM wallets WHERE coin_id = {coin_id} AND balance_type = {info_type} ORDER BY created_at DESC LIMIT 3 )'
            session.execute(text(query_str))
            session.commit()
        except Exception as e:
            self.log.error(f'addWalletInfoRecord {e}')
        finally:
            self.closeSession(session, commit=False)

    def updateWalletInfo(self, coin) -> None:
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

    def updateWalletsInfo(self, force_update: bool = False, only_coin: bool = None, wait_for_complete: bool = False) -> None:
        now: int = self.getTime()
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
                cc['last_updated_wallet_info'] = self.getTime()
                self._updating_wallets_info[int(c)] = True
                handle = self.thread_pool.submit(self.updateWalletInfo, c)
                if wait_for_complete:
                    try:
                        handle.result(timeout=self._wallet_update_timeout)
                    except Exception as e:
                        self.log.error(f'updateWalletInfo {e}')

    def getWalletsInfo(self, opts=None):
        rv = {}
        for c in self.activeCoins():
            key = chainparams[c]['ticker'] if opts.get('ticker_key', False) else c
            try:
                rv[key] = self.getWalletInfo(c)
                rv[key].update(self.getBlockchainInfo(c))
            except Exception as ex:
                rv[key] = {'name': getCoinName(c), 'error': str(ex)}
        return rv

    def getCachedWalletsInfo(self, opts=None):
        rv = {}
        try:
            session = self.openSession()
            where_str = ''
            if opts is not None and 'coin_id' in opts:
                where_str = 'WHERE coin_id = {}'.format(opts['coin_id'])
            inner_str = f'SELECT coin_id, balance_type, MAX(created_at) as max_created_at FROM wallets {where_str} GROUP BY coin_id, balance_type'
            query_str = 'SELECT a.coin_id, a.balance_type, wallet_data, created_at FROM wallets a, ({}) b WHERE a.coin_id = b.coin_id AND a.balance_type = b.balance_type AND a.created_at = b.max_created_at'.format(inner_str)

            q = session.execute(text(query_str))
            for row in q:
                coin_id = row[0]

                if self.coin_clients[coin_id]['connection_type'] != 'rpc':
                    # Skip cached info if coin was disabled
                    continue

                wallet_data = json.loads(row[2])
                if row[1] == 1:
                    wallet_data['lastupdated'] = row[3]
                    wallet_data['updating'] = self._updating_wallets_info.get(coin_id, False)

                    # Ensure the latest addresses are displayed
                    q = session.execute(text('SELECT key, value FROM kv_string WHERE key = "receive_addr_{0}" OR key = "stealth_addr_{0}"'.format(chainparams[coin_id]['name'])))
                    for row in q:

                        if row[0].startswith('stealth'):
                            if coin_id == Coins.LTC:
                                wallet_data['mweb_address'] = row[1]
                            else:
                                wallet_data['stealth_address'] = row[1]
                        else:
                            wallet_data['deposit_address'] = row[1]

                if coin_id in rv:
                    rv[coin_id].update(wallet_data)
                else:
                    rv[coin_id] = wallet_data
        finally:
            self.closeSession(session)

        if opts is not None and 'coin_id' in opts:
            return rv

        for c in self.activeCoins():
            coin_id = int(c)
            if coin_id not in rv:
                rv[coin_id] = {
                    'name': getCoinName(c),
                    'no_data': True,
                    'updating': self._updating_wallets_info.get(coin_id, False),
                }

        return rv

    def countAcceptedBids(self, offer_id: bytes = None) -> int:
        session = self.openSession()
        try:
            if offer_id:
                q = session.execute(text('SELECT COUNT(*) FROM bids WHERE state >= {} AND offer_id = x\'{}\''.format(BidStates.BID_ACCEPTED, offer_id.hex()))).first()
            else:
                q = session.execute(text('SELECT COUNT(*) FROM bids WHERE state >= {}'.format(BidStates.BID_ACCEPTED))).first()
            return q[0]
        finally:
            self.closeSession(session, commit=False)

    def listOffers(self, sent: bool = False, filters={}, with_bid_info: bool = False):
        session = self.openSession()
        try:
            rv = []
            now: int = self.getTime()

            if with_bid_info:
                subquery = session.query(sa.func.sum(Bid.amount).label('completed_bid_amount')).filter(sa.and_(Bid.offer_id == Offer.offer_id, Bid.state == BidStates.SWAP_COMPLETED)).correlate(Offer).scalar_subquery()
                q = session.query(Offer, subquery)
            else:
                q = session.query(Offer)

            if sent:
                q = q.filter(Offer.was_sent == True)  # noqa: E712

                active_state = filters.get('active', 'any')
                if active_state == 'active':
                    q = q.filter(Offer.expire_at > now, Offer.active_ind == 1)
                elif active_state == 'expired':
                    q = q.filter(Offer.expire_at <= now)
                elif active_state == 'revoked':
                    q = q.filter(Offer.active_ind != 1)
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

            filter_include_sent = filters.get('include_sent', None)
            if filter_include_sent is not None and filter_include_sent is not True:
                q = q.filter(Offer.was_sent == False)  # noqa: E712

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
            self.closeSession(session, commit=False)

    def activeBidsQueryStr(self, now: int, offer_table: str = 'offers', bids_table: str = 'bids') -> str:
        offers_inset = f' AND {offer_table}.expire_at > {now}' if offer_table != '' else ''

        inactive_states_str = ', '.join([str(int(s)) for s in inactive_states])
        return f' ({bids_table}.state NOT IN ({inactive_states_str}) AND ({bids_table}.state > {BidStates.BID_RECEIVED} OR ({bids_table}.expire_at > {now}{offers_inset}))) '

    def listBids(self, sent: bool = False, offer_id: bytes = None, for_html: bool = False, filters={}):
        session = self.openSession()
        try:
            rv = []
            now: int = self.getTime()

            query_str = 'SELECT ' + \
                        'bids.created_at, bids.expire_at, bids.bid_id, bids.offer_id, bids.amount, bids.state, bids.was_received, ' + \
                        'tx1.state, tx2.state, offers.coin_from, bids.rate, bids.bid_addr, offers.bid_reversed, bids.amount_to, offers.coin_to ' + \
                        'FROM bids ' + \
                        'LEFT JOIN offers ON offers.offer_id = bids.offer_id ' + \
                        'LEFT JOIN transactions AS tx1 ON tx1.bid_id = bids.bid_id AND tx1.tx_type = CASE WHEN offers.swap_type = :ads_swap THEN :al_type ELSE :itx_type END ' + \
                        'LEFT JOIN transactions AS tx2 ON tx2.bid_id = bids.bid_id AND tx2.tx_type = CASE WHEN offers.swap_type = :ads_swap THEN :bl_type ELSE :ptx_type END '

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

            with_available_or_active = filters.get('with_available_or_active', False)
            with_expired = filters.get('with_expired', True)
            if with_available_or_active:
                query_str += ' AND ' + self.activeBidsQueryStr(now)
            else:
                if with_expired is not True:
                    query_str += 'AND bids.expire_at > {} AND offers.expire_at > {} '.format(now, now)

            sort_dir = filters.get('sort_dir', 'DESC').upper()
            sort_by = filters.get('sort_by', 'created_at')
            query_str += f' ORDER BY bids.{sort_by} {sort_dir}'

            limit = filters.get('limit', None)
            if limit is not None:
                query_str += f' LIMIT {limit}'
            offset = filters.get('offset', None)
            if offset is not None:
                query_str += f' OFFSET {offset}'

            q = session.execute(text(query_str), {'ads_swap': SwapTypes.XMR_SWAP, 'itx_type': TxTypes.ITX, 'ptx_type': TxTypes.PTX, 'al_type': TxTypes.XMR_SWAP_A_LOCK, 'bl_type': TxTypes.XMR_SWAP_B_LOCK})
            for row in q:
                result = [x for x in row]
                coin_from = result[9]
                coin_to = result[14]
                # Show bids for enabled coins only
                try:
                    ci_from = self.ci(coin_from)
                    ci_to = self.ci(coin_to)
                except Exception as e:
                    continue
                if result[12]:  # Reversed
                    amount_from = result[13]
                    amount_to = result[4]
                    result[4] = amount_from
                    result[13] = amount_to
                    result[10] = ci_from.make_int(amount_to / amount_from, r=1)

                rv.append(result)
            return rv
        finally:
            self.closeSession(session, commit=False)

    def listSwapsInProgress(self, for_html=False):
        self.mxDB.acquire()
        try:
            rv = []
            for k, v in self.swaps_in_progress.items():
                bid, offer = v
                itx_state = None
                ptx_state = None

                if offer.swap_type == SwapTypes.XMR_SWAP:
                    itx_state = bid.xmr_a_lock_tx.state if bid.xmr_a_lock_tx else None
                    ptx_state = bid.xmr_b_lock_tx.state if bid.xmr_b_lock_tx else None
                else:
                    itx_state = bid.getITxState()
                    ptx_state = bid.getPTxState()

                rv.append((k, bid.offer_id.hex(), bid.state, itx_state, ptx_state))
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

    def listAllSMSGAddresses(self, filters={}, session=None):
        query_str = 'SELECT addr_id, addr, use_type, active_ind, created_at, note, pubkey FROM smsgaddresses'
        query_str += ' WHERE 1 = 1 '
        query_data = {}

        if filters.get('exclude_inactive', True) is True:
            query_str += ' AND active_ind = :active_ind '
            query_data['active_ind'] = 1
        if 'addr_id' in filters:
            query_str += ' AND addr_id = :addr_id '
            query_data['addr_id'] = filters['addr_id']
        if 'addressnote' in filters:
            query_str += ' AND note LIKE :note '
            query_data['note'] = '%' + filters['addressnote'] + '%'
        if 'addr_type' in filters and filters['addr_type'] > -1:
            query_str += ' AND use_type = :addr_type '
            query_data['addr_type'] = filters['addr_type']

        sort_dir = filters.get('sort_dir', 'DESC').upper()
        sort_by = filters.get('sort_by', 'created_at')
        query_str += f' ORDER BY {sort_by} {sort_dir}'
        limit = filters.get('limit', None)
        if limit is not None:
            query_str += f' LIMIT {limit}'
        offset = filters.get('offset', None)
        if offset is not None:
            query_str += f' OFFSET {offset}'

        try:
            use_session = self.openSession(session)
            rv = []
            q = use_session.execute(text(query_str), query_data)
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
            if session is None:
                self.closeSession(use_session, commit=False)

    def listSMSGAddresses(self, use_type_str: str):
        if use_type_str == 'offer_send_from':
            use_type = AddressTypes.OFFER
        elif use_type_str == 'offer_send_to':
            use_type = AddressTypes.SEND_OFFER
        elif use_type_str == 'bid':
            use_type = AddressTypes.BID
        else:
            raise ValueError('Unknown address type')

        try:
            session = self.openSession()
            rv = []
            q = session.execute(text('SELECT sa.addr, ki.label FROM smsgaddresses AS sa LEFT JOIN knownidentities AS ki ON sa.addr = ki.address WHERE sa.use_type = {} AND sa.active_ind = 1 ORDER BY sa.addr_id DESC'.format(use_type)))
            for row in q:
                rv.append((row[0], row[1]))
            return rv
        finally:
            self.closeSession(session, commit=False)

    def listAutomationStrategies(self, filters={}):
        try:
            session = self.openSession()
            rv = []

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

            q = session.execute(text(query_str))
            for row in q:
                rv.append(row)
            return rv
        finally:
            self.closeSession(session, commit=False)

    def getAutomationStrategy(self, strategy_id: int):
        try:
            session = self.openSession()
            return session.query(AutomationStrategy).filter_by(record_id=strategy_id).first()
        finally:
            self.closeSession(session, commit=False)

    def updateAutomationStrategy(self, strategy_id: int, data, note: str) -> None:
        try:
            session = self.openSession()
            strategy = session.query(AutomationStrategy).filter_by(record_id=strategy_id).first()
            strategy.data = json.dumps(data).encode('utf-8')
            strategy.note = note
            session.add(strategy)
        finally:
            self.closeSession(session)

    def getLinkedStrategy(self, linked_type: int, linked_id):
        try:
            session = self.openSession()
            query_str = 'SELECT links.strategy_id, strats.label FROM automationlinks links' + \
                        ' LEFT JOIN automationstrategies strats ON strats.record_id = links.strategy_id' + \
                        ' WHERE links.linked_type = {} AND links.linked_id = x\'{}\' AND links.active_ind = 1'.format(int(linked_type), linked_id.hex())
            q = session.execute(text(query_str)).first()
            return q
        finally:
            self.closeSession(session, commit=False)

    def newSMSGAddress(self, use_type=AddressTypes.RECV_OFFER, addressnote=None, session=None):
        now: int = self.getTime()
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
            self.callrpc('smsglocalkeys', ['anon', '-', new_addr])

            addr_obj = SmsgAddress(addr=new_addr, use_type=use_type, active_ind=1, created_at=now, pubkey=addr_info['pubkey'])
            if addressnote is not None:
                addr_obj.note = addressnote

            use_session.add(addr_obj)
            return new_addr, addr_info['pubkey']
        finally:
            if session is None:
                self.closeSession(use_session)

    def addSMSGAddress(self, pubkey_hex: str, addressnote: str = None) -> None:
        session = self.openSession()
        try:
            now: int = self.getTime()
            ci = self.ci(Coins.PART)
            add_addr = ci.pubkey_to_address(bytes.fromhex(pubkey_hex))
            self.callrpc('smsgaddaddress', [add_addr, pubkey_hex])
            self.callrpc('smsglocalkeys', ['anon', '-', add_addr])

            session.add(SmsgAddress(addr=add_addr, use_type=AddressTypes.SEND_OFFER, active_ind=1, created_at=now, note=addressnote, pubkey=pubkey_hex))
            return add_addr
        finally:
            self.closeSession(session)

    def editSMSGAddress(self, address: str, active_ind: int, addressnote: str = None, use_type=None, session=None) -> None:
        use_session = self.openSession(session)
        try:
            mode = '-' if active_ind == 0 else '+'
            rv = self.callrpc('smsglocalkeys', ['recv', mode, address])
            if 'not found' in rv['result']:
                self.callrpc('smsgaddlocaladdress', [address,])
                self.callrpc('smsglocalkeys', ['anon', '-', address])
            values = {'active_ind': active_ind, 'addr': address, 'use_type': use_type}
            query_str: str = 'UPDATE smsgaddresses SET active_ind = :active_ind'
            if addressnote is not None:
                values['note'] = addressnote
                query_str += ', note = :note'
            query_str += ' WHERE addr = :addr'

            rv = use_session.execute(text(query_str), values)
            if rv.rowcount < 1:
                query_str: str = 'INSERT INTO smsgaddresses (addr, active_ind, use_type) VALUES (:addr, :active_ind, :use_type)'
                use_session.execute(text(query_str), values)
        finally:
            if session is None:
                self.closeSession(use_session)

    def disableAllSMSGAddresses(self):
        filters = {
            'exclude_inactive': True,
        }
        session = self.openSession()
        rv = {}
        num_disabled = 0
        try:
            active_addresses = self.listAllSMSGAddresses(filters, session=session)
            for active_address in active_addresses:
                if active_address['addr'] == self.network_addr:
                    continue
                self.editSMSGAddress(active_address['addr'], active_ind=0, session=session)
            num_disabled += 1
        finally:
            self.closeSession(session)

        rv['num_disabled'] = num_disabled

        num_core_disabled = 0
        # Check localkeys
        smsg_localkeys = self.callrpc('smsglocalkeys')
        all_keys = smsg_localkeys['wallet_keys'] + smsg_localkeys['smsg_keys']
        for smsg_addr in all_keys:
            if smsg_addr['address'] == self.network_addr:
                continue
            if smsg_addr['receive'] != 0:
                self.log.warning('Disabling smsg key found in core and not bsx: {}'.format(smsg_addr['address']))
                self.callrpc('smsglocalkeys', ['recv', '-', smsg_addr['address']])
                num_core_disabled += 1

        if num_core_disabled > 0:
            rv['num_core_disabled'] = num_core_disabled
        return rv

    def prepareSMSGAddress(self, addr_send_from, use_type, session):
        if addr_send_from is None:
            return self.newSMSGAddress(use_type=use_type, session=session)[0]
        use_addr = addr_send_from
        self.editSMSGAddress(use_addr, 1, use_type=use_type, session=session)  # Ensure receive is active
        return use_addr

    def createCoinALockRefundSwipeTx(self, ci, bid, offer, xmr_swap, xmr_offer):
        self.log.debug('Creating %s lock refund swipe tx', ci.coin_name())

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)

        pkh_dest = ci.decodeAddress(self.getReceiveAddressForCoin(ci.coin_type()))
        spend_tx = ci.createSCLockRefundSpendToFTx(
            xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script,
            pkh_dest,
            a_fee_rate, xmr_swap.vkbv)

        vkaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF)
        prevout_amount = ci.getLockRefundTxSwapOutputValue(bid, xmr_swap)
        sig = ci.signTx(vkaf, spend_tx, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount)

        witness_stack = [
            sig,
            b'',
            xmr_swap.a_lock_refund_tx_script,
        ]

        xmr_swap.a_lock_refund_swipe_tx = ci.setTxSignature(spend_tx, witness_stack)

    def setBidDebugInd(self, bid_id: bytes, debug_ind, add_to_bid: bool = True) -> None:
        self.log.debug('Bid %s Setting debug flag: %s', bid_id.hex(), debug_ind)

        self._debug_cases.append((bid_id, debug_ind))
        if add_to_bid is False:
            return

        bid = self.getBid(bid_id)
        bid.debug_ind = debug_ind

        # Update in memory copy.  TODO: Improve
        bid_in_progress = self.swaps_in_progress.get(bid_id, None)
        if bid_in_progress:
            bid_in_progress[0].debug_ind = debug_ind

        self.saveBid(bid_id, bid)

    def storeOfferRevoke(self, offer_id: bytes, sig) -> bool:
        self.log.debug('Storing revoke request for offer: %s', offer_id.hex())
        for pair in self._possibly_revoked_offers:
            if offer_id == pair[0]:
                return False
        self._possibly_revoked_offers.appendleft((offer_id, sig))
        return True

    def isOfferRevoked(self, offer_id: bytes, offer_addr_from) -> bool:
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
        session = self.openSession()
        try:
            rv = []
            for a in addresses:
                v = session.query(KnownIdentity).filter_by(address=a).first()
                rv.append('' if (not v or not v.label) else v.label)
            return rv
        finally:
            self.closeSession(session, commit=False)

    def add_connection(self, host, port, peer_pubkey):
        self.log.info('add_connection %s %d %s', host, port, peer_pubkey.hex())
        self._network.add_connection(host, port, peer_pubkey)

    def get_network_info(self):
        if not self._network:
            return {'Error': 'Not Initialised'}
        return self._network.get_info()

    def getLockedState(self):
        if self._is_encrypted is None or self._is_locked is None:
            self._is_encrypted, self._is_locked = self.ci(Coins.PART).isWalletEncryptedLocked()
        return self._is_encrypted, self._is_locked

    def lookupRates(self, coin_from, coin_to, output_array=False):
        self.log.debug('lookupRates {}, {}'.format(Coins(int(coin_from)).name, Coins(int(coin_to)).name))

        rate_sources = self.settings.get('rate_sources', {})
        ci_from = self.ci(int(coin_from))
        ci_to = self.ci(int(coin_to))
        name_from = ci_from.chainparams()['name']
        name_to = ci_to.chainparams()['name']
        exchange_name_from = ci_from.getExchangeName('coingecko.com')
        exchange_name_to = ci_to.getExchangeName('coingecko.com')
        ticker_from = ci_from.chainparams()['ticker']
        ticker_to = ci_to.chainparams()['ticker']
        headers = {'User-Agent': 'Mozilla/5.0', 'Connection': 'close'}
        rv = {}

        if rate_sources.get('coingecko.com', True):
            try:
                url = 'https://api.coingecko.com/api/v3/simple/price?ids={},{}&vs_currencies=usd,btc'.format(exchange_name_from, exchange_name_to)
                self.log.debug(f'lookupRates: {url}')
                start = time.time()
                js = json.loads(self.readURL(url, timeout=10, headers=headers))
                js['time_taken'] = time.time() - start
                rate = float(js[exchange_name_from]['usd']) / float(js[exchange_name_to]['usd'])
                js['rate_inferred'] = ci_to.format_amount(rate, conv_int=True, r=1)
                rv['coingecko'] = js
            except Exception as e:
                rv['coingecko_error'] = str(e)
                if self.debug:
                    self.log.error(traceback.format_exc())

            if exchange_name_from != name_from:
                js[name_from] = js[exchange_name_from]
                js.pop(exchange_name_from)
            if exchange_name_to != name_to:
                js[name_to] = js[exchange_name_to]
                js.pop(exchange_name_to)

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
            return rv_array

        return rv

    def setFilters(self, prefix, filters):
        try:
            session = self.openSession()
            key_str = 'saved_filters_' + prefix
            value_str = json.dumps(filters)
            self.setStringKV(key_str, value_str, session)
        finally:
            self.closeSession(session)

    def getFilters(self, prefix):
        try:
            session = self.openSession()
            key_str = 'saved_filters_' + prefix
            value_str = self.getStringKV(key_str, session)
            return None if not value_str else json.loads(value_str)
        finally:
            self.closeSession(session, commit=False)

    def clearFilters(self, prefix) -> None:
        try:
            session = self.openSession()
            key_str = 'saved_filters_' + prefix
            query_str = 'DELETE FROM kv_string WHERE key = :key_str'
            session.execute(text(query_str), {'key_str': key_str})
        finally:
            self.closeSession(session)
