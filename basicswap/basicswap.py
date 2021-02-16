# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import re
import zmq
import json
import time
import base64
import random
import shutil
import struct
import hashlib
import secrets
import datetime as dt
import threading
import traceback
import sqlalchemy as sa
import collections

from enum import IntEnum, auto
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.orm.session import close_all_sessions

from .interface_part import PARTInterface, PARTInterfaceAnon
from .interface_btc import BTCInterface
from .interface_ltc import LTCInterface
from .interface_nmc import NMCInterface
from .interface_xmr import XMRInterface
from .interface_passthrough_btc import PassthroughBTCInterface

from . import __version__
from .util import (
    pubkeyToAddress,
    format_amount,
    format_timestamp,
    encodeAddress,
    decodeAddress,
    DeserialiseNum,
    decodeWif,
    toWIF,
    getKeyID,
    make_int,
    getP2SHScriptForHash,
    getP2WSH,
)
from .chainparams import (
    chainparams,
    Coins,
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
    TableTypes,
    Base,
    DBKVInt,
    DBKVString,
    Offer,
    Bid,
    SwapTx,
    PooledAddress,
    SentOffer,
    SmsgAddress,
    EventQueue,
    EventLog,
    XmrOffer,
    XmrSwap,
    XmrSplitData,
)
from .base import BaseApp
from .explorers import (
    ExplorerInsight,
    ExplorerBitAps,
    ExplorerChainz,
)
from .types import (
    SEQUENCE_LOCK_BLOCKS,
    SEQUENCE_LOCK_TIME,
    ABS_LOCK_BLOCKS,
    ABS_LOCK_TIME)
import basicswap.config as cfg
import basicswap.network as bsn
import basicswap.protocols.atomic_swap_1 as atomic_swap_1


class MessageTypes(IntEnum):
    OFFER = auto()
    BID = auto()
    BID_ACCEPT = auto()

    XMR_OFFER = auto()
    XMR_BID_FL = auto()
    XMR_BID_SPLIT = auto()
    XMR_BID_ACCEPT_LF = auto()
    XMR_BID_TXN_SIGS_FL = auto()
    XMR_BID_LOCK_SPEND_TX_LF = auto()
    XMR_BID_LOCK_RELEASE_LF = auto()
    OFFER_REVOKE = auto()


class SwapTypes(IntEnum):
    SELLER_FIRST = auto()
    BUYER_FIRST = auto()
    SELLER_FIRST_2MSG = auto()
    BUYER_FIRST_2MSG = auto()
    XMR_SWAP = auto()


class OfferStates(IntEnum):
    OFFER_SENT = auto()
    OFFER_RECEIVED = auto()
    OFFER_ABANDONED = auto()


class BidStates(IntEnum):
    BID_SENT = auto()
    BID_RECEIVING = auto()          # Partially received
    BID_RECEIVED = auto()
    BID_RECEIVING_ACC = auto()      # Partially received accept message
    BID_ACCEPTED = auto()           # BidAcceptMessage received/sent
    SWAP_INITIATED = auto()         # Initiate txn validated
    SWAP_PARTICIPATING = auto()     # Participate txn validated
    SWAP_COMPLETED = auto()         # All swap txns spent
    XMR_SWAP_SCRIPT_COIN_LOCKED = auto()
    XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX = auto()
    XMR_SWAP_NOSCRIPT_COIN_LOCKED = auto()
    XMR_SWAP_LOCK_RELEASED = auto()
    XMR_SWAP_SCRIPT_TX_REDEEMED = auto()
    XMR_SWAP_NOSCRIPT_TX_REDEEMED = auto()
    XMR_SWAP_NOSCRIPT_TX_RECOVERED = auto()
    XMR_SWAP_FAILED_REFUNDED = auto()
    XMR_SWAP_FAILED_SWIPED = auto()
    XMR_SWAP_FAILED = auto()
    SWAP_DELAYING = auto()
    SWAP_TIMEDOUT = auto()
    BID_ABANDONED = auto()          # Bid will no longer be processed
    BID_ERROR = auto()              # An error occurred
    BID_STALLED_FOR_TEST = auto()


class TxStates(IntEnum):
    TX_NONE = auto()
    TX_SENT = auto()
    TX_CONFIRMED = auto()
    TX_REDEEMED = auto()
    TX_REFUNDED = auto()


class TxTypes(IntEnum):
    ITX = auto()
    PTX = auto()
    ITX_REDEEM = auto()
    ITX_REFUND = auto()
    PTX_REDEEM = auto()
    PTX_REFUND = auto()

    XMR_SWAP_A_LOCK = auto()
    XMR_SWAP_A_LOCK_SPEND = auto()
    XMR_SWAP_A_LOCK_REFUND = auto()
    XMR_SWAP_A_LOCK_REFUND_SPEND = auto()
    XMR_SWAP_A_LOCK_REFUND_SWIPE = auto()
    XMR_SWAP_B_LOCK = auto()


class EventTypes(IntEnum):
    ACCEPT_BID = auto()
    ACCEPT_XMR_BID = auto()
    SIGN_XMR_SWAP_LOCK_TX_A = auto()
    SEND_XMR_SWAP_LOCK_TX_A = auto()
    SEND_XMR_SWAP_LOCK_TX_B = auto()
    SEND_XMR_LOCK_RELEASE = auto()
    REDEEM_XMR_SWAP_LOCK_TX_A = auto()  # Follower
    REDEEM_XMR_SWAP_LOCK_TX_B = auto()  # Leader
    RECOVER_XMR_SWAP_LOCK_TX_B = auto()


class EventLogTypes(IntEnum):
    FAILED_TX_B_LOCK_PUBLISH = auto()
    LOCK_TX_A_PUBLISHED = auto()
    LOCK_TX_B_PUBLISHED = auto()
    FAILED_TX_B_SPEND = auto()
    LOCK_TX_A_SEEN = auto()
    LOCK_TX_A_CONFIRMED = auto()
    LOCK_TX_B_SEEN = auto()
    LOCK_TX_B_CONFIRMED = auto()
    DEBUG_TWEAK_APPLIED = auto()
    FAILED_TX_B_REFUND = auto()
    LOCK_TX_B_INVALID = auto()
    LOCK_TX_A_REFUND_TX_PUBLISHED = auto()
    LOCK_TX_A_REFUND_SPEND_TX_PUBLISHED = auto()
    LOCK_TX_A_REFUND_SWIPE_TX_PUBLISHED = auto()
    LOCK_TX_B_REFUND_TX_PUBLISHED = auto()


class XmrSplitMsgTypes(IntEnum):
    BID = auto()
    BID_ACCEPT = auto()


class DebugTypes(IntEnum):
    BID_STOP_AFTER_COIN_A_LOCK = auto()
    BID_DONT_SPEND_COIN_A_LOCK_REFUND = auto()
    CREATE_INVALID_COIN_B_LOCK = auto()
    BUYER_STOP_AFTER_ITX = auto()
    MAKE_INVALID_PTX = auto()


def strOfferState(state):
    if state == OfferStates.OFFER_SENT:
        return 'Sent'
    if state == OfferStates.OFFER_RECEIVED:
        return 'Received'
    if state == OfferStates.OFFER_ABANDONED:
        return 'Abandoned'
    return 'Unknown'


def strBidState(state):
    if state == BidStates.BID_SENT:
        return 'Sent'
    if state == BidStates.BID_RECEIVING:
        return 'Receiving'
    if state == BidStates.BID_RECEIVING_ACC:
        return 'Receiving accept'
    if state == BidStates.BID_RECEIVED:
        return 'Received'
    if state == BidStates.BID_ACCEPTED:
        return 'Accepted'
    if state == BidStates.SWAP_INITIATED:
        return 'Initiated'
    if state == BidStates.SWAP_PARTICIPATING:
        return 'Participating'
    if state == BidStates.SWAP_COMPLETED:
        return 'Completed'
    if state == BidStates.SWAP_TIMEDOUT:
        return 'Timed-out'
    if state == BidStates.BID_ABANDONED:
        return 'Abandoned'
    if state == BidStates.BID_STALLED_FOR_TEST:
        return 'Stalled (debug)'
    if state == BidStates.BID_ERROR:
        return 'Error'
    if state == BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED:
        return 'Script coin locked'
    if state == BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX:
        return 'Script coin spend tx valid'
    if state == BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED:
        return 'Scriptless coin locked'
    if state == BidStates.XMR_SWAP_LOCK_RELEASED:
        return 'Script coin lock released'
    if state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
        return 'Script tx redeemed'
    if state == BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED:
        return 'Scriptless tx redeemed'
    if state == BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED:
        return 'Scriptless tx recovered'
    if state == BidStates.XMR_SWAP_FAILED_REFUNDED:
        return 'Failed, refunded'
    if state == BidStates.XMR_SWAP_FAILED_SWIPED:
        return 'Failed, swiped'
    if state == BidStates.XMR_SWAP_FAILED:
        return 'Failed'
    if state == BidStates.SWAP_DELAYING:
        return 'Delaying'
    return 'Unknown'


def strTxState(state):
    if state == TxStates.TX_NONE:
        return 'None'
    if state == TxStates.TX_SENT:
        return 'Sent'
    if state == TxStates.TX_CONFIRMED:
        return 'Confirmed'
    if state == TxStates.TX_REDEEMED:
        return 'Redeemed'
    if state == TxStates.TX_REFUNDED:
        return 'Refunded'
    return 'Unknown'


def strTxType(tx_type):
    if tx_type == TxTypes.XMR_SWAP_A_LOCK:
        return 'Chain A Lock Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_SPEND:
        return 'Chain A Lock Spend Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND:
        return 'Chain A Lock Refund Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND:
        return 'Chain A Lock Refund Spend Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE:
        return 'Chain A Lock Refund Swipe Tx'
    if tx_type == TxTypes.XMR_SWAP_B_LOCK:
        return 'Chain B Lock Tx'
    return 'Unknown'


def getLockName(lock_type):
    if lock_type == SEQUENCE_LOCK_BLOCKS:
        return 'Sequence lock, blocks'
    if lock_type == SEQUENCE_LOCK_TIME:
        return 'Sequence lock, time'
    if lock_type == ABS_LOCK_BLOCKS:
        return 'blocks'
    if lock_type == ABS_LOCK_TIME:
        return 'time'


def describeEventEntry(event_type, event_msg):
    if event_type == EventLogTypes.FAILED_TX_B_LOCK_PUBLISH:
        return 'Failed to publish lock tx B'
    if event_type == EventLogTypes.FAILED_TX_B_LOCK_PUBLISH:
        return 'Failed to publish lock tx B'
    if event_type == EventLogTypes.LOCK_TX_A_PUBLISHED:
        return 'Lock tx A published'
    if event_type == EventLogTypes.LOCK_TX_B_PUBLISHED:
        return 'Lock tx B published'
    if event_type == EventLogTypes.FAILED_TX_B_SPEND:
        return 'Failed to publish lock tx B spend'
    if event_type == EventLogTypes.LOCK_TX_A_SEEN:
        return 'Lock tx A seen in chain'
    if event_type == EventLogTypes.LOCK_TX_A_CONFIRMED:
        return 'Lock tx A confirmed in chain'
    if event_type == EventLogTypes.LOCK_TX_B_SEEN:
        return 'Lock tx B seen in chain'
    if event_type == EventLogTypes.LOCK_TX_B_CONFIRMED:
        return 'Lock tx B confirmed in chain'
    if event_type == EventLogTypes.DEBUG_TWEAK_APPLIED:
        return 'Debug tweak applied ' + event_msg
    if event_type == EventLogTypes.FAILED_TX_B_REFUND:
        return 'Failed to publish lock tx B refund'
    if event_type == EventLogTypes.LOCK_TX_B_INVALID:
        return 'Detected invalid lock Tx B'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_TX_PUBLISHED:
        return 'Lock tx A refund tx published'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_PUBLISHED:
        return 'Lock tx A refund spend tx published'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_SWIPE_TX_PUBLISHED:
        return 'Lock tx A refund swipe tx published'
    if event_type == EventLogTypes.LOCK_TX_B_REFUND_TX_PUBLISHED:
        return 'Lock tx B refund tx published'


def getVoutByAddress(txjs, p2sh):
    for o in txjs['vout']:
        try:
            if p2sh in o['scriptPubKey']['addresses']:
                return o['n']
        except Exception:
            pass
    raise ValueError('Address output not found in txn')


def getVoutByP2WSH(txjs, p2wsh_hex):
    for o in txjs['vout']:
        try:
            if p2wsh_hex == o['scriptPubKey']['hex']:
                return o['n']
        except Exception:
            pass
    raise ValueError('P2WSH output not found in txn')


def replaceAddrPrefix(addr, coin_type, chain_name, addr_type='pubkey_address'):
    return encodeAddress(bytes((chainparams[coin_type][chain_name][addr_type],)) + decodeAddress(addr)[1:])


def getOfferProofOfFundsHash(offer_msg, offer_addr):
    # TODO: Hash must not include proof_of_funds sig if it exists in offer_msg
    h = hashlib.sha256()
    h.update(offer_addr.encode('utf-8'))
    offer_bytes = offer_msg.SerializeToString()
    h.update(offer_bytes)
    return h.digest()


def threadPollChainState(swap_client, coin_type):
    while not swap_client.delay_event.is_set():
        try:
            ci = swap_client.ci(coin_type)
            if coin_type == Coins.XMR:
                new_height = ci.getChainHeight()
                if new_height != swap_client.coin_clients[coin_type]['chain_height']:
                    swap_client.log.debug('New {} block at height: {}'.format(str(coin_type), new_height))
                    with swap_client.mxDB:
                        swap_client.coin_clients[coin_type]['chain_height'] = new_height
            else:
                chain_state = ci.getBlockchainInfo()
                if chain_state['bestblockhash'] != swap_client.coin_clients[coin_type]['chain_best_block']:
                    swap_client.log.debug('New {} block at height: {}'.format(str(coin_type), chain_state['blocks']))
                    with swap_client.mxDB:
                        swap_client.coin_clients[coin_type]['chain_height'] = chain_state['blocks']
                        swap_client.coin_clients[coin_type]['chain_best_block'] = chain_state['bestblockhash']
                        swap_client.coin_clients[coin_type]['chain_median_time'] = chain_state['mediantime']
        except Exception as e:
            swap_client.log.warning('threadPollChainState error: {}'.format(str(e)))
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
    def __init__(self, fp, data_dir, settings, chain, log_name='BasicSwap'):
        super().__init__(fp, data_dir, settings, chain, log_name)

        v = __version__.split('.')
        self._version = struct.pack('>HHH', int(v[0]), int(v[1]), int(v[2]))

        self.check_progress_seconds = self.settings.get('check_progress_seconds', 60)
        self.check_watched_seconds = self.settings.get('check_watched_seconds', 60)
        self.check_expired_seconds = self.settings.get('check_expired_seconds', 60 * 5)
        self.check_events_seconds = self.settings.get('check_events_seconds', 10)
        self.check_xmr_swaps_seconds = self.settings.get('check_xmr_swaps_seconds', 20)
        self._last_checked_progress = 0
        self._last_checked_watched = 0
        self._last_checked_expired = 0
        self._last_checked_events = 0
        self._last_checked_xmr_swaps = 0
        self._possibly_revoked_offers = collections.deque([], maxlen=48)  # TODO: improve

        # TODO: Adjust ranges
        self.min_delay_event = self.settings.get('min_delay_event', 10)
        self.max_delay_event = self.settings.get('max_delay_event', 60)

        self.min_delay_retry = self.settings.get('min_delay_retry', 60)
        self.max_delay_retry = self.settings.get('max_delay_retry', 5 * 60)

        self.min_sequence_lock_seconds = self.settings.get('min_sequence_lock_seconds', 1 * 60 * 60)
        self.max_sequence_lock_seconds = self.settings.get('max_sequence_lock_seconds', 96 * 60 * 60)

        self._bid_expired_leeway = 5

        self.swaps_in_progress = dict()

        self.SMSG_SECONDS_IN_HOUR = 60 * 60  # Note: Set smsgsregtestadjust=0 for regtest

        self.threads = []

        # Encode key to match network
        wif_prefix = chainparams[Coins.PART][self.chain]['key_prefix']
        self.network_key = toWIF(wif_prefix, decodeWif(self.settings['network_key']))

        self.network_pubkey = self.settings['network_pubkey']
        self.network_addr = pubkeyToAddress(chainparams[Coins.PART][self.chain]['pubkey_address'], bytes.fromhex(self.network_pubkey))

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
        self.engine = sa.create_engine('sqlite:///' + self.sqlite_file)
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

        close_all_sessions()
        self.engine.dispose()

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

        self.coin_clients[coin] = {
            'coin': coin,
            'name': chainparams[coin]['name'],
            'connection_type': connection_type,
            'bindir': bindir,
            'datadir': datadir,
            'rpchost': chain_client_settings.get('rpchost', '127.0.0.1'),
            'rpcport': chain_client_settings.get('rpcport', chainparams[coin][self.chain]['rpcport']),
            'rpcauth': rpcauth,
            'blocks_confirmed': chain_client_settings.get('blocks_confirmed', 6),
            'conf_target': chain_client_settings.get('conf_target', 2),
            'watched_outputs': [],
            'last_height_checked': last_height_checked,
            'use_segwit': chain_client_settings.get('use_segwit', False),
            'use_csv': chain_client_settings.get('use_csv', True),
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
            self.coin_clients[Coins.PART_ANON] = self.coin_clients[coin]

        if self.coin_clients[coin]['connection_type'] == 'rpc':
            if coin == Coins.XMR:
                self.coin_clients[coin]['walletrpchost'] = chain_client_settings.get('walletrpchost', '127.0.0.1')
                self.coin_clients[coin]['walletrpcport'] = chain_client_settings.get('walletrpcport', chainparams[coin][self.chain]['walletrpcport'])
                if 'walletrpcpassword' in chain_client_settings:
                    self.coin_clients[coin]['walletrpcauth'] = (chain_client_settings['walletrpcuser'], chain_client_settings['walletrpcpassword'])
                else:
                    raise ValueError('Missing XMR wallet rpc credentials.')

    def ci(self, coin):  # Coin interface
        if coin == Coins.PART_ANON:
            return self.coin_clients[Coins.PART]['interface_anon']
        return self.coin_clients[coin]['interface']

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
            if cc['name'] == 'bitcoin' or cc['name'] == 'litecoin' or cc['name'] == 'namecoin':
                pidfilename += 'd'
            pidfilepath = os.path.join(self.getChainDatadirPath(coin), pidfilename + '.pid')
            self.log.debug('Reading %s rpc credentials from auth cookie %s', coin, authcookiepath)
            # Wait for daemon to start
            # Test pids to ensure authcookie is read for the correct process
            datadir_pid = -1
            for i in range(20):
                try:
                    with open(pidfilepath, 'rb') as fp:
                        datadir_pid = int(fp.read().decode('utf-8'))
                    assert(datadir_pid == cc['pid']), 'Mismatched pid'
                    assert(os.path.exists(authcookiepath))
                except Exception:
                    time.sleep(0.5)
            try:
                if os.name != 'nt' or cc['core_version_group'] > 17:  # Litecoin on windows doesn't write a pid file
                    assert(datadir_pid == cc['pid']), 'Mismatched pid'
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
        elif self.coin_clients[coin]['connection_type'] == 'passthrough':
            self.coin_clients[coin]['interface'] = self.createPassthroughInterface(coin)

    def start(self):
        self.log.info('Starting BasicSwap %s, database v%d\n\n', __version__, self.db_version)
        self.log.info('sqlalchemy version %s', sa.__version__)
        self.log.info('timezone offset: %d (%s)', time.timezone, time.tzname[0])

        self.upgradeDatabase(self.db_version)

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

                t = threading.Thread(target=threadPollChainState, args=(self, c))
                self.threads.append(t)
                t.start()

                if c == Coins.PART:
                    self.coin_clients[c]['have_spent_index'] = ci.haveSpentIndex()

                    # Sanity checks
                    rv = self.callcoinrpc(c, 'extkey')
                    if 'result' in rv and 'No keys to list.' in rv['result']:
                        raise ValueError('No keys loaded.')

                    if self.callcoinrpc(c, 'getstakinginfo')['enabled'] is not False:
                        self.log.warning('%s staking is not disabled.', ci.coin_name())
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
            if 'Could not connect' in str(ex):
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
            traceback.print_exc()
        raise ValueError('Could not stop {}'.format(str(coin)))

    def stopDaemons(self):
        for c in Coins:
            if c not in chainparams:
                continue
            chain_client_settings = self.getChainClientSettings(c)
            if self.coin_clients[c]['connection_type'] == 'rpc' and chain_client_settings['manage_daemon'] is True:
                self.stopDaemon(c)

    def upgradeDatabase(self, db_version):
        if db_version >= CURRENT_DB_VERSION:
            return

        self.log.info('Upgrading database from version %d to %d.', db_version, CURRENT_DB_VERSION)

        while True:
            if db_version == 6:
                session = scoped_session(self.session_factory)

                session.execute('ALTER TABLE bids ADD COLUMN security_token BLOB')
                session.execute('ALTER TABLE offers ADD COLUMN security_token BLOB')

                db_version += 1
                self.db_version = db_version
                self.setIntKVInSession('db_version', db_version, session)
                session.commit()
                session.close()
                session.remove()
                self.log.info('Upgraded database to version {}'.format(self.db_version))
                continue
            if db_version == 7:
                session = scoped_session(self.session_factory)

                session.execute('ALTER TABLE transactions ADD COLUMN block_hash BLOB')
                session.execute('ALTER TABLE transactions ADD COLUMN block_height INTEGER')
                session.execute('ALTER TABLE transactions ADD COLUMN block_time INTEGER')

                db_version += 1
                self.db_version = db_version
                self.setIntKVInSession('db_version', db_version, session)
                session.commit()
                session.close()
                session.remove()
                self.log.info('Upgraded database to version {}'.format(self.db_version))
                continue
            break

        if db_version != CURRENT_DB_VERSION:
            raise ValueError('Unable to upgrade database.')

    def waitForDaemonRPC(self, coin_type):
        for i in range(21):
            if not self.is_running:
                return
            try:
                self.coin_clients[coin_type]['interface'].testDaemonRPC()
                return
            except Exception as ex:
                self.log.warning('Can\'t connect to %s RPC: %s.  Trying again in %d second/s.', coin_type, str(ex), (1 + i))
                time.sleep(1 + i)
        self.log.error('Can\'t connect to %s RPC, exiting.', coin_type)
        self.stopRunning(1)  # systemd will try restart if fail_code != 0

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

    def initialiseWallet(self, coin_type):
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
        root_hash = ci.getAddressHashFromKey(root_key)[::-1]
        ci.initialiseWallet(root_key)

        key_str = 'main_wallet_seedid_' + ci.coin_name().lower()
        self.setStringKV(key_str, root_hash.hex())

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
        assert(offer), 'Offer not found'

        if offer.swap_type == SwapTypes.XMR_SWAP:
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
            self.loadBidTxns(bid, session)
            self.watchXmrSwap(bid, offer, xmr_swap)
        else:
            bid.initiate_tx = session.query(SwapTx).filter(sa.and_(SwapTx.bid_id == bid.bid_id, SwapTx.tx_type == TxTypes.ITX)).first()
            bid.participate_tx = session.query(SwapTx).filter(sa.and_(SwapTx.bid_id == bid.bid_id, SwapTx.tx_type == TxTypes.PTX)).first()

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

        use_session = None
        try:
            if session:
                use_session = session
            else:
                self.mxDB.acquire()
                use_session = scoped_session(self.session_factory)

            # Remove any delayed events
            if self.debug:
                use_session.execute('UPDATE eventqueue SET active_ind = 2 WHERE linked_id = x\'{}\' '.format(bid.bid_id.hex()))
            else:
                use_session.execute('DELETE FROM eventqueue WHERE linked_id = x\'{}\' '.format(bid.bid_id.hex()))

            # Unlock locked inputs (TODO)
            if offer.swap_type == SwapTypes.XMR_SWAP:
                xmr_swap = use_session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
                if xmr_swap:
                    try:
                        self.ci(offer.coin_from).unlockInputs(xmr_swap.a_lock_tx)
                    except Exception as e:
                        if self.debug:
                            self.log.info('unlockInputs failed {}'.format(str(e)))
                        pass  # Invalid parameter, unknown transaction
        finally:
            if session is None:
                use_session.commit()
                use_session.close()
                use_session.remove()
                self.mxDB.release()

    def loadFromDB(self):
        self.log.info('Loading data from db')
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            for bid in session.query(Bid):
                if bid.in_progress == 1 or (bid.state and bid.state > BidStates.BID_RECEIVED and bid.state < BidStates.SWAP_COMPLETED):
                    self.activateBid(session, bid)
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
            assert(ro['result'] == 'Success.'), 'smsglocalkeys failed'

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

    def validateSwapType(self, coin_from, coin_to, swap_type):
        if coin_from == Coins.XMR:
            raise ValueError('TODO: xmr coin_from')
        if coin_to == Coins.XMR and swap_type != SwapTypes.XMR_SWAP:
            raise ValueError('Invalid swap type for XMR')

    def validateOfferAmounts(self, coin_from, coin_to, amount, rate, min_bid_amount):
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        assert(amount >= min_bid_amount), 'amount < min_bid_amount'
        assert(amount > ci_from.min_amount()), 'From amount below min value for chain'
        assert(amount < ci_from.max_amount()), 'From amount above max value for chain'

        amount_to = int((amount * rate) // ci_from.COIN())
        assert(amount_to > ci_to.min_amount()), 'To amount below min value for chain'
        assert(amount_to < ci_to.max_amount()), 'To amount above max value for chain'

    def validateOfferLockValue(self, coin_from, coin_to, lock_type, lock_value):
        if lock_type == OfferMessage.SEQUENCE_LOCK_TIME:
            assert(lock_value >= self.min_sequence_lock_seconds and lock_value <= self.max_sequence_lock_seconds), 'Invalid lock_value time'
            assert(self.coin_clients[coin_from]['use_csv'] and self.coin_clients[coin_to]['use_csv']), 'Both coins need CSV activated.'
        elif lock_type == OfferMessage.SEQUENCE_LOCK_BLOCKS:
            assert(lock_value >= 5 and lock_value <= 1000), 'Invalid lock_value blocks'
            assert(self.coin_clients[coin_from]['use_csv'] and self.coin_clients[coin_to]['use_csv']), 'Both coins need CSV activated.'
        elif lock_type == ABS_LOCK_TIME:
            # TODO: range?
            assert(not self.coin_clients[coin_from]['use_csv'] or not self.coin_clients[coin_to]['use_csv']), 'Should use CSV.'
            assert(lock_value >= 4 * 60 * 60 and lock_value <= 96 * 60 * 60), 'Invalid lock_value time'
        elif lock_type == ABS_LOCK_BLOCKS:
            # TODO: range?
            assert(not self.coin_clients[coin_from]['use_csv'] or not self.coin_clients[coin_to]['use_csv']), 'Should use CSV.'
            assert(lock_value >= 10 and lock_value <= 1000), 'Invalid lock_value blocks'
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

    def postOffer(self, coin_from, coin_to, amount, rate, min_bid_amount, swap_type,
                  lock_type=SEQUENCE_LOCK_TIME, lock_value=48 * 60 * 60, auto_accept_bids=False, addr_send_from=None, extra_options={}):
        # Offer to send offer.amount_from of coin_from in exchange for offer.amount_from * offer.rate of coin_to

        assert(coin_from != coin_to), 'coin_from == coin_to'
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

        self.mxDB.acquire()
        session = None
        try:
            self.checkSynced(coin_from_t, coin_to_t)
            offer_addr = self.callrpc('getnewaddress') if addr_send_from is None else addr_send_from
            offer_created_at = int(time.time())

            msg_buf = OfferMessage()

            msg_buf.coin_from = int(coin_from)
            msg_buf.coin_to = int(coin_to)
            msg_buf.amount_from = int(amount)
            msg_buf.rate = int(rate)
            msg_buf.min_bid_amount = int(min_bid_amount)

            msg_buf.time_valid = valid_for_seconds
            msg_buf.lock_type = lock_type
            msg_buf.lock_value = lock_value
            msg_buf.swap_type = swap_type

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
            # TODO: For now proof_of_funds is just a client side checkm, may need to be sent with offers in future however.

            offer_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.OFFER) + offer_bytes.hex()

            self.callrpc('smsgaddlocaladdress', [offer_addr])  # Enable receiving smsg
            options = {'decodehex': True, 'ttl_is_seconds': True}
            msg_valid = max(self.SMSG_SECONDS_IN_HOUR * 1, valid_for_seconds)
            ro = self.callrpc('smsgsend', [offer_addr, self.network_addr, payload_hex, False, msg_valid, False, options])
            msg_id = ro['msgid']

            offer_id = bytes.fromhex(msg_id)

            security_token = extra_options.get('security_token', None)
            if security_token is not None and len(security_token) != 20:
                raise ValueError('Security token must be 20 bytes long.')

            session = scoped_session(self.session_factory)
            offer = Offer(
                offer_id=offer_id,
                active_ind=1,

                coin_from=msg_buf.coin_from,
                coin_to=msg_buf.coin_to,
                amount_from=msg_buf.amount_from,
                rate=msg_buf.rate,
                min_bid_amount=msg_buf.min_bid_amount,
                time_valid=msg_buf.time_valid,
                lock_type=int(msg_buf.lock_type),
                lock_value=msg_buf.lock_value,
                swap_type=msg_buf.swap_type,

                addr_from=offer_addr,
                created_at=offer_created_at,
                expire_at=offer_created_at + msg_buf.time_valid,
                was_sent=True,
                auto_accept_bids=auto_accept_bids,
                security_token=security_token)
            offer.setState(OfferStates.OFFER_SENT)

            if swap_type == SwapTypes.XMR_SWAP:
                xmr_offer.offer_id = offer_id
                session.add(xmr_offer)

            session.add(offer)
            session.add(SentOffer(offer_id=offer_id))
            if addr_send_from is None:
                session.add(SmsgAddress(addr=offer_addr, use_type=MessageTypes.OFFER))
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

            options = {'decodehex': True, 'ttl_is_seconds': True}
            ro = self.callrpc('smsgsend', [offer.addr_from, self.network_addr, payload_hex, False, offer.time_valid, False, options])
            msg_id = ro['msgid']
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

    def checkWalletSeed(self, c):
        ci = self.ci(c)
        if c == Coins.PART:
            return True  # TODO
        if c == Coins.XMR:
            expect_address = self.getStringKV('main_wallet_addr_' + ci.coin_name().lower())
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
        if expect_seedid == ci.getWalletSeedID():
            ci.setWalletSeedWarning(False)
            return True
        self.log.warning('Wallet for coin {} not derived from swap seed.'.format(ci.coin_name()))
        return False

    def reseedWallet(self, coin_type):
        self.log.info('reseedWallet %s', coin_type)
        ci = self.ci(coin_type)
        if ci.knownWalletSeed():
            raise ValueError('{} wallet seed is already derived from the particl mnemonic'.format(ci.coin_name()))

        self.initialiseWallet(coin_type)

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
                self.log.info('Found restore height for %s', ci.coin_name())
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

        # TODO: Lock unspent and use same output/s to fund bid
        unspent_addr = dict()
        unspent = self.callcoinrpc(coin_type, 'listunspent')
        for u in unspent:
            unspent_addr[u['address']] = unspent_addr.get(u['address'], 0) + ci.make_int(u['amount'], r=1)

        sign_for_addr = None
        for addr, value in unspent_addr.items():
            if value >= amount_for:
                sign_for_addr = addr
                break

        assert(sign_for_addr is not None), 'Could not find address with enough funds for proof'

        self.log.debug('sign_for_addr %s', sign_for_addr)
        if self.coin_clients[coin_type]['use_segwit']:
            # 'Address does not refer to key' for non p2pkh
            addrinfo = self.callcoinrpc(coin_type, 'getaddressinfo', [sign_for_addr])
            pkh = addrinfo['scriptPubKey'][4:]
            sign_for_addr = encodeAddress(bytes((chainparams[coin_type][self.chain]['pubkey_address'],)) + bytes.fromhex(pkh))
            self.log.debug('sign_for_addr converted %s', sign_for_addr)
        signature = self.callcoinrpc(coin_type, 'signmessage', [sign_for_addr, sign_for_addr + '_swap_proof_' + extra_commit_bytes.hex()])

        return (sign_for_addr, signature)

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

    def createEventInSession(self, delay, event_type, linked_id, session):
        self.log.debug('createEvent %d %s', event_type, linked_id.hex())
        now = int(time.time())
        event = EventQueue(
            active_ind=1,
            created_at=now,
            trigger_at=now + delay,
            event_type=event_type,
            linked_id=linked_id)
        session.add(event)

    def createEvent(self, delay, event_type, linked_id):
        # self.log.debug('createEvent %d %s', event_type, linked_id.hex())
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            self.createEventInSession(delay, event_type, linked_id, session)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def logBidEvent(self, bid, event_type, event_msg, session):
        self.log.debug('logBidEvent %s %s', bid.bid_id.hex(), event_type)
        entry = EventLog(
            active_ind=1,
            created_at=int(time.time()),
            linked_type=TableTypes.BID,
            linked_id=bid.bid_id,
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

    def countBidEvents(self, bid, event_type, session):
        q = session.execute('SELECT COUNT(*) FROM eventlog WHERE linked_type = {} AND linked_id = x\'{}\' AND event_type = {}'.format(int(TableTypes.BID), bid.bid_id.hex(), int(event_type))).first()
        return q[0]

    def postBid(self, offer_id, amount, addr_send_from=None, extra_options={}):
        # Bid to send bid.amount * offer.rate of coin_to in exchange for bid.amount of coin_from
        self.log.debug('postBid %s', offer_id.hex())

        offer = self.getOffer(offer_id)
        assert(offer), 'Offer not found: {}.'.format(offer_id.hex())
        assert(offer.expire_at > int(time.time())), 'Offer has expired'

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.postXmrBid(offer_id, amount, addr_send_from, extra_options)

        valid_for_seconds = extra_options.get('valid_for_seconds', 60 * 10)
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds)

        self.mxDB.acquire()
        try:
            msg_buf = BidMessage()
            msg_buf.offer_msg_id = offer_id
            msg_buf.time_valid = valid_for_seconds
            msg_buf.amount = int(amount)  # amount of coin_from

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            self.checkSynced(coin_from, coin_to)

            contract_count = self.getNewContractId()

            amount_to = int((msg_buf.amount * offer.rate) // self.ci(coin_from).COIN())

            now = int(time.time())
            if offer.swap_type == SwapTypes.SELLER_FIRST:
                msg_buf.pkhash_buyer = getKeyID(self.getContractPubkey(dt.datetime.fromtimestamp(now).date(), contract_count))

                proof_addr, proof_sig = self.getProofOfFunds(coin_to, amount_to, offer_id)
                msg_buf.proof_address = proof_addr
                msg_buf.proof_signature = proof_sig
            else:
                raise ValueError('TODO')

            bid_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.BID) + bid_bytes.hex()

            if addr_send_from is None:
                bid_addr = self.callrpc('getnewaddress')
            else:
                bid_addr = addr_send_from
            self.callrpc('smsgaddlocaladdress', [bid_addr])  # Enable receiving smsg
            options = {'decodehex': True, 'ttl_is_seconds': True}
            msg_valid = max(self.SMSG_SECONDS_IN_HOUR * 1, valid_for_seconds)
            ro = self.callrpc('smsgsend', [bid_addr, offer.addr_from, payload_hex, False, msg_valid, False, options])
            msg_id = ro['msgid']

            bid_id = bytes.fromhex(msg_id)
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                amount=msg_buf.amount,
                pkhash_buyer=msg_buf.pkhash_buyer,
                proof_address=msg_buf.proof_address,

                created_at=now,
                contract_count=contract_count,
                amount_to=amount_to,
                expire_at=now + msg_buf.time_valid,
                bid_addr=bid_addr,
                was_sent=True,
            )
            bid.setState(BidStates.BID_SENT)

            try:
                session = scoped_session(self.session_factory)
                self.saveBidInSession(bid_id, bid, session)
                if addr_send_from is None:
                    session.add(SmsgAddress(addr=bid_addr, use_type=MessageTypes.BID))
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

    def getBid(self, bid_id):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            bid = session.query(Bid).filter_by(bid_id=bid_id).first()
            if bid:
                self.loadBidTxns(bid, session)
            return bid
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getBidAndOffer(self, bid_id):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            bid = session.query(Bid).filter_by(bid_id=bid_id).first()
            offer = None
            if bid:
                offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
                if offer and offer.swap_type == SwapTypes.XMR_SWAP:
                    self.loadBidTxns(bid, session)
                else:
                    bid.initiate_tx = session.query(SwapTx).filter(sa.and_(SwapTx.bid_id == bid_id, SwapTx.tx_type == TxTypes.ITX)).first()
                    bid.participate_tx = session.query(SwapTx).filter(sa.and_(SwapTx.bid_id == bid_id, SwapTx.tx_type == TxTypes.PTX)).first()
            return bid, offer
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

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
                else:
                    bid.initiate_tx = session.query(SwapTx).filter(sa.and_(SwapTx.bid_id == bid_id, SwapTx.tx_type == TxTypes.ITX)).first()
                    bid.participate_tx = session.query(SwapTx).filter(sa.and_(SwapTx.bid_id == bid_id, SwapTx.tx_type == TxTypes.PTX)).first()
                if list_events:
                    events = self.list_bid_events(bid.bid_id, session)

            return bid, xmr_swap, offer, xmr_offer, events
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def list_bid_events(self, bid_id, session):
        query_str = 'SELECT created_at, event_type, event_msg FROM eventlog ' + \
                    'WHERE active_ind = 1 AND linked_type = {} AND linked_id = x\'{}\' '.format(TableTypes.BID, bid_id.hex())
        q = session.execute(query_str)
        events = []
        for row in q:
            events.append({'at': row[0], 'desc': describeEventEntry(row[1], row[2])})

        query_str = 'SELECT created_at, trigger_at FROM eventqueue ' + \
                    'WHERE active_ind = 1 AND linked_id = x\'{}\' '.format(bid_id.hex())
        q = session.execute(query_str)
        for row in q:
            events.append({'at': row[0], 'desc': 'Delaying until: {}'.format(format_timestamp(row[1], with_seconds=True))})

        return events

    def acceptBid(self, bid_id):
        self.log.info('Accepting bid %s', bid_id.hex())

        bid, offer = self.getBidAndOffer(bid_id)
        assert(bid), 'Bid not found'
        assert(offer), 'Offer not found'

        # Ensure bid is still valid
        now = int(time.time())
        assert(bid.expire_at > now), 'Bid expired'
        assert(bid.state == BidStates.BID_RECEIVED), 'Wrong bid state: {}'.format(str(BidStates(bid.state)))

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
            if offer.lock_type < ABS_LOCK_BLOCKS:
                sequence = ci_from.getExpectedSequence(offer.lock_type, offer.lock_value)
                script = atomic_swap_1.buildContractScript(sequence, secret_hash, bid.pkhash_buyer, pkhash_refund)
            else:
                if offer.lock_type == ABS_LOCK_BLOCKS:
                    lock_value = self.callcoinrpc(coin_from, 'getblockchaininfo')['blocks'] + offer.lock_value
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

            txid = self.submitTxn(coin_from, txn)
            self.log.debug('Submitted initiate txn %s to %s chain for bid %s', txid, ci_from.coin_name(), bid_id.hex())
            bid.initiate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.ITX,
                txid=bytes.fromhex(txid),
                script=script,
            )
            bid.setITxState(TxStates.TX_SENT)

            # Check non-bip68 final
            try:
                txid = self.submitTxn(coin_from, bid.initiate_txn_refund.hex())
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
            options = {'decodehex': True, 'ttl_is_seconds': True}
            # TODO: set msg_valid based on bid / offer parameters
            msg_valid = self.SMSG_SECONDS_IN_HOUR * 48
            ro = self.callrpc('smsgsend', [offer.addr_from, bid.bid_addr, payload_hex, False, msg_valid, False, options])
            msg_id = ro['msgid']

            accept_msg_id = bytes.fromhex(msg_id)

            bid.accept_msg_id = accept_msg_id
            bid.setState(BidStates.BID_ACCEPTED)

            self.log.info('Sent BID_ACCEPT %s', accept_msg_id.hex())

            self.saveBid(bid_id, bid)
            self.swaps_in_progress[bid_id] = (bid, offer)

    def postXmrBid(self, offer_id, amount, addr_send_from=None, extra_options={}):
        # Bid to send bid.amount * offer.rate of coin_to in exchange for bid.amount of coin_from
        # Send MSG1L F -> L
        self.log.debug('postXmrBid %s', offer_id.hex())

        self.mxDB.acquire()
        try:
            offer, xmr_offer = self.getXmrOffer(offer_id)

            assert(offer), 'Offer not found: {}.'.format(offer_id.hex())
            assert(xmr_offer), 'XMR offer not found: {}.'.format(offer_id.hex())
            assert(offer.expire_at > int(time.time())), 'Offer has expired'

            valid_for_seconds = extra_options.get('valid_for_seconds', 60 * 10)
            self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds)

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            self.checkSynced(coin_from, coin_to)

            msg_buf = XmrBidMessage()
            msg_buf.offer_msg_id = offer_id
            msg_buf.time_valid = valid_for_seconds
            msg_buf.amount = int(amount)  # Amount of coin_from

            address_out = self.getReceiveAddressFromPool(coin_from, offer_id, TxTypes.XMR_SWAP_A_LOCK)
            msg_buf.dest_af = ci_from.decodeAddress(address_out)

            bid_created_at = int(time.time())
            if offer.swap_type != SwapTypes.XMR_SWAP:
                raise ValueError('TODO')

            # Follower to leader
            xmr_swap = XmrSwap()
            xmr_swap.contract_count = self.getNewContractId()
            xmr_swap.dest_af = msg_buf.dest_af
            xmr_swap.start_chain_a_height = ci_from.getChainHeight()
            xmr_swap.b_restore_height = ci_to.getChainHeight()

            wallet_restore_height = self.getWalletRestoreHeight(ci_to)
            if xmr_swap.b_restore_height < wallet_restore_height:
                xmr_swap.b_restore_height = wallet_restore_height
                self.log.warning('XMR swap restore height clamped to {}'.format(wallet_restore_height))

            for_ed25519 = True if coin_to == Coins.XMR else False
            kbvf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, 1, for_ed25519)
            kbsf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, 2, for_ed25519)

            kaf = self.getPathKey(coin_from, coin_to, bid_created_at, xmr_swap.contract_count, 3)

            xmr_swap.vkbvf = kbvf
            xmr_swap.pkbvf = ci_to.getPubkey(kbvf)
            xmr_swap.pkbsf = ci_to.getPubkey(kbsf)

            xmr_swap.pkaf = ci_from.getPubkey(kaf)

            if coin_to == Coins.XMR:
                xmr_swap.kbsf_dleag = ci_to.proveDLEAG(kbsf)
            else:
                xmr_swap.kbsf_dleag = xmr_swap.pkbsf
            xmr_swap.pkasf = xmr_swap.kbsf_dleag[0: 33]
            assert(xmr_swap.pkasf == ci_from.getPubkey(kbsf))

            msg_buf.pkaf = xmr_swap.pkaf
            msg_buf.kbvf = kbvf
            if coin_to == Coins.XMR:
                msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag[:16000]
            else:
                msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag

            bid_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_FL) + bid_bytes.hex()

            if addr_send_from is None:
                bid_addr = self.callrpc('getnewaddress')
            else:
                bid_addr = addr_send_from
            self.callrpc('smsgaddlocaladdress', [bid_addr])  # Enable receiving smsg
            options = {'decodehex': True, 'ttl_is_seconds': True}
            msg_valid = max(self.SMSG_SECONDS_IN_HOUR * 1, valid_for_seconds)
            ro = self.callrpc('smsgsend', [bid_addr, offer.addr_from, payload_hex, False, msg_valid, False, options])
            xmr_swap.bid_id = bytes.fromhex(ro['msgid'])

            if coin_to == Coins.XMR:
                msg_buf2 = XmrSplitMessage(
                    msg_id=xmr_swap.bid_id,
                    msg_type=XmrSplitMsgTypes.BID,
                    sequence=2,
                    dleag=xmr_swap.kbsf_dleag[16000:32000]
                )
                msg_bytes = msg_buf2.SerializeToString()
                payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
                ro = self.callrpc('smsgsend', [bid_addr, offer.addr_from, payload_hex, False, msg_valid, False, options])
                xmr_swap.bid_msg_id2 = bytes.fromhex(ro['msgid'])

                msg_buf3 = XmrSplitMessage(
                    msg_id=xmr_swap.bid_id,
                    msg_type=XmrSplitMsgTypes.BID,
                    sequence=3,
                    dleag=xmr_swap.kbsf_dleag[32000:]
                )
                msg_bytes = msg_buf3.SerializeToString()
                payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
                ro = self.callrpc('smsgsend', [bid_addr, offer.addr_from, payload_hex, False, msg_valid, False, options])
                xmr_swap.bid_msg_id3 = bytes.fromhex(ro['msgid'])

            bid = Bid(
                active_ind=1,
                bid_id=xmr_swap.bid_id,
                offer_id=offer_id,
                amount=msg_buf.amount,
                created_at=bid_created_at,
                contract_count=xmr_swap.contract_count,
                amount_to=(msg_buf.amount * offer.rate) // ci_from.COIN(),
                expire_at=bid_created_at + msg_buf.time_valid,
                bid_addr=bid_addr,
                was_sent=True,
            )
            bid.setState(BidStates.BID_SENT)

            try:
                session = scoped_session(self.session_factory)
                self.saveBidInSession(xmr_swap.bid_id, bid, session, xmr_swap)
                if addr_send_from is None:
                    session.add(SmsgAddress(addr=bid_addr, use_type=MessageTypes.BID))
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
            assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
            assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())
            assert(bid.expire_at > now), 'Bid expired'
            assert(bid.state == BidStates.BID_RECEIVED), 'Wrong bid state: {}'.format(str(BidStates(bid.state)))

            offer, xmr_offer = self.getXmrOffer(bid.offer_id)
            assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
            assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
            assert(offer.expire_at > now), 'Offer has expired'

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            if xmr_swap.contract_count is None:
                xmr_swap.contract_count = self.getNewContractId()

            for_ed25519 = True if coin_to == Coins.XMR else False
            kbvl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 1, for_ed25519)
            kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 2, for_ed25519)

            kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 3)

            xmr_swap.vkbvl = kbvl
            xmr_swap.pkbvl = ci_to.getPubkey(kbvl)
            xmr_swap.pkbsl = ci_to.getPubkey(kbsl)

            xmr_swap.vkbv = ci_to.sumKeys(kbvl, xmr_swap.vkbvf)
            xmr_swap.pkbv = ci_to.sumPubkeys(xmr_swap.pkbvl, xmr_swap.pkbvf)
            xmr_swap.pkbs = ci_to.sumPubkeys(xmr_swap.pkbsl, xmr_swap.pkbsf)

            xmr_swap.pkal = ci_from.getPubkey(kal)

            if coin_to == Coins.XMR:
                xmr_swap.kbsl_dleag = ci_to.proveDLEAG(kbsl)
            else:
                xmr_swap.kbsl_dleag = xmr_swap.pkbsl

            # MSG2F
            xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script = ci_from.createScriptLockTx(
                bid.amount,
                xmr_swap.pkal, xmr_swap.pkaf,
            )
            xmr_swap.a_lock_tx = ci_from.fundTx(xmr_swap.a_lock_tx, xmr_offer.a_fee_rate)

            xmr_swap.a_lock_tx_id = ci_from.getTxHash(xmr_swap.a_lock_tx)
            a_lock_tx_dest = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)

            xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script, xmr_swap.a_swap_refund_value = ci_from.createScriptLockRefundTx(
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.lock_time_1, xmr_offer.lock_time_2,
                xmr_offer.a_fee_rate
            )
            xmr_swap.a_lock_refund_tx_id = ci_from.getTxHash(xmr_swap.a_lock_refund_tx)

            xmr_swap.al_lock_refund_tx_sig = ci_from.signTx(kal, xmr_swap.a_lock_refund_tx, 0, xmr_swap.a_lock_tx_script, bid.amount)
            v = ci_from.verifyTxSig(xmr_swap.a_lock_refund_tx, xmr_swap.al_lock_refund_tx_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, bid.amount)
            assert(v)

            pkh_refund_to = ci_from.decodeAddress(self.getReceiveAddressForCoin(coin_from))
            xmr_swap.a_lock_refund_spend_tx = ci_from.createScriptLockRefundSpendTx(
                xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script,
                pkh_refund_to,
                xmr_offer.a_fee_rate
            )
            xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxHash(xmr_swap.a_lock_refund_spend_tx)

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
            options = {'decodehex': True, 'ttl_is_seconds': True}
            msg_valid = self.SMSG_SECONDS_IN_HOUR * 48
            ro = self.callrpc('smsgsend', [offer.addr_from, bid.bid_addr, payload_hex, False, msg_valid, False, options])
            msg_id = ro['msgid']
            bid.accept_msg_id = bytes.fromhex(msg_id)
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
                ro = self.callrpc('smsgsend', [offer.addr_from, bid.bid_addr, payload_hex, False, msg_valid, False, options])
                xmr_swap.bid_accept_msg_id2 = bytes.fromhex(ro['msgid'])

                msg_buf3 = XmrSplitMessage(
                    msg_id=bid_id,
                    msg_type=XmrSplitMsgTypes.BID_ACCEPT,
                    sequence=3,
                    dleag=xmr_swap.kbsl_dleag[32000:]
                )
                msg_bytes = msg_buf3.SerializeToString()
                payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
                ro = self.callrpc('smsgsend', [offer.addr_from, bid.bid_addr, payload_hex, False, msg_valid, False, options])
                xmr_swap.bid_accept_msg_id3 = bytes.fromhex(ro['msgid'])

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
            assert(bid), 'Bid not found'
            offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
            assert(offer), 'Offer not found'

            # Mark bid as abandoned, no further processing will be done
            bid.setState(BidStates.BID_ABANDONED)
            self.deactivateBid(session, offer, bid)
            session.add(bid)
            session.commit()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def setBidError(self, bid_id, bid, error_str, save_bid=True):
        self.log.error('Bid %s - Error: %s', bid_id.hex(), error_str)
        bid.setState(BidStates.BID_ERROR)
        bid.state_note = 'error msg: ' + error_str
        if save_bid:
            self.saveBid(bid_id, bid)

    def createInitiateTxn(self, coin_type, bid_id, bid, initiate_script):
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None
        ci = self.ci(coin_type)

        if self.coin_clients[coin_type]['use_segwit']:
            addr_to = self.encodeSegwitP2WSH(coin_type, getP2WSH(initiate_script))
        else:
            addr_to = self.getScriptAddress(coin_type, initiate_script)
        self.log.debug('Create initiate txn for coin %s to %s for bid %s', str(coin_type), addr_to, bid_id.hex())
        txn = self.callcoinrpc(coin_type, 'createrawtransaction', [[], {addr_to: ci.format_amount(bid.amount)}])

        options = {
            'lockUnspents': True,
            'conf_target': self.coin_clients[coin_type]['conf_target'],
        }
        txn_funded = self.callcoinrpc(coin_type, 'fundrawtransaction', [txn, options])['hex']
        txn_signed = self.callcoinrpc(coin_type, 'signrawtransactionwithwallet', [txn_funded])['hex']
        return txn_signed

    def deriveParticipateScript(self, bid_id, bid, offer):
        self.log.debug('deriveParticipateScript for bid %s', bid_id.hex())

        coin_to = Coins(offer.coin_to)
        ci_to = self.ci(coin_to)

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        pkhash_seller = bid.pkhash_seller
        pkhash_buyer_refund = bid.pkhash_buyer

        # Participate txn is locked for half the time of the initiate txn
        lock_value = offer.lock_value // 2
        if offer.lock_type < ABS_LOCK_BLOCKS:
            sequence = ci_to.getExpectedSequence(offer.lock_type, lock_value)
            participate_script = atomic_swap_1.buildContractScript(sequence, secret_hash, pkhash_seller, pkhash_buyer_refund)
        else:
            # Lock from the height or time of the block containing the initiate txn
            coin_from = Coins(offer.coin_from)
            initiate_tx_block_hash = self.callcoinrpc(coin_from, 'getblockhash', [bid.initiate_tx.chain_height, ])
            initiate_tx_block_time = int(self.callcoinrpc(coin_from, 'getblock', [initiate_tx_block_hash, ])['time'])
            if offer.lock_type == ABS_LOCK_BLOCKS:
                # Walk the coin_to chain back until block time matches
                blockchaininfo = self.callcoinrpc(coin_to, 'getblockchaininfo')
                cblock_hash = blockchaininfo['bestblockhash']
                cblock_height = blockchaininfo['blocks']
                max_tries = 1000
                for i in range(max_tries):
                    prev_block = self.callcoinrpc(coin_to, 'getblock', [cblock_hash, ])
                    self.log.debug('prev_block %s', str(prev_block))

                    if prev_block['time'] <= initiate_tx_block_time:
                        break
                    # cblock_hash and height are out of step unless loop breaks
                    cblock_hash = prev_block['previousblockhash']
                    cblock_height = prev_block['height']

                assert(prev_block['time'] <= initiate_tx_block_time), 'Block not found for lock height'

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
        assert(amount_to == (bid.amount * offer.rate) // self.ci(offer.coin_from).COIN())

        if bid.debug_ind == DebugTypes.MAKE_INVALID_PTX:
            amount_to -= 1
            self.log.debug('bid %s: Make invalid PTx for testing: %d.', bid_id.hex(), bid.debug_ind)
            self.logBidEvent(bid, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), None)

        if self.coin_clients[coin_to]['use_segwit']:
            p2wsh = getP2WSH(participate_script)
            addr_to = self.encodeSegwitP2WSH(coin_to, p2wsh)
        else:
            addr_to = self.getScriptAddress(coin_to, participate_script)

        txn = self.callcoinrpc(coin_to, 'createrawtransaction', [[], {addr_to: ci.format_amount(amount_to)}])
        options = {
            'lockUnspents': True,
            'conf_target': self.coin_clients[coin_to]['conf_target'],
        }
        txn_funded = self.callcoinrpc(coin_to, 'fundrawtransaction', [txn, options])['hex']
        txn_signed = self.callcoinrpc(coin_to, 'signrawtransactionwithwallet', [txn_funded])['hex']

        refund_txn = self.createRefundTxn(coin_to, txn_signed, offer, bid, participate_script, tx_type=TxTypes.PTX_REFUND)
        bid.participate_txn_refund = bytes.fromhex(refund_txn)

        chain_height = self.callcoinrpc(coin_to, 'getblockchaininfo')['blocks']
        txjs = self.callcoinrpc(coin_to, 'decoderawtransaction', [txn_signed])
        txid = txjs['txid']

        if self.coin_clients[coin_to]['use_segwit']:
            vout = getVoutByP2WSH(txjs, p2wsh.hex())
        else:
            vout = getVoutByAddress(txjs, addr_to)
        self.addParticipateTxn(bid_id, bid, coin_to, txid, vout, chain_height)
        bid.participate_tx.script = participate_script

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
        assert(len(secret) == 32), 'Bad secret length'

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None

        prevout_s = ' in={}:{}'.format(prev_txnid, prev_n)

        if fee_rate is None:
            fee_rate, fee_src = self.getFeeRateForCoin(coin_type)

        tx_vsize = self.getContractSpendTxVSize(coin_type)
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug('Redeem tx fee %s, rate %s', ci.format_amount(tx_fee, conv_int=True, r=1), str(fee_rate))

        amount_out = prev_amount - ci.make_int(tx_fee, r=1)
        assert(amount_out > 0), 'Amount out <= 0'

        if addr_redeem_out is None:
            addr_redeem_out = self.getReceiveAddressFromPool(coin_type, bid.bid_id, TxTypes.PTX_REDEEM if for_txn_type == 'participate' else TxTypes.ITX_REDEEM)
        assert(addr_redeem_out is not None)

        if self.coin_clients[coin_type]['use_segwit']:
            # Change to btc hrp
            addr_redeem_out = self.encodeSegwit(Coins.PART, self.decodeSegwit(coin_type, addr_redeem_out))
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
        assert(ro['inputs_valid'] is True), 'inputs_valid is false'
        assert(ro['complete'] is True), 'complete is false'
        assert(ro['validscripts'] == 1), 'validscripts != 1'

        if self.debug:
            # Check fee
            if self.coin_clients[coin_type]['connection_type'] == 'rpc':
                redeem_txjs = self.callcoinrpc(coin_type, 'decoderawtransaction', [redeem_txn])
                self.log.debug('vsize paid, actual vsize %d %d', tx_vsize, redeem_txjs['vsize'])
                assert(tx_vsize >= redeem_txjs['vsize']), 'Underpaid fee'

            redeem_txjs = self.callcoinrpc(Coins.PART, 'decoderawtransaction', [redeem_txn])
            self.log.debug('Have valid redeem txn %s for contract %s tx %s', redeem_txjs['txid'], for_txn_type, prev_txnid)

        return redeem_txn

    def createRefundTxn(self, coin_type, txn, offer, bid, txn_script, addr_refund_out=None, tx_type=TxTypes.ITX_REFUND):
        self.log.debug('createRefundTxn')
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None

        txjs = self.callcoinrpc(Coins.PART, 'decoderawtransaction', [txn])
        if self.coin_clients[coin_type]['use_segwit']:
            p2wsh = getP2WSH(txn_script)
            vout = getVoutByP2WSH(txjs, p2wsh.hex())
        else:
            addr_to = self.getScriptAddress(Coins.PART, txn_script)
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
        if offer.lock_type < ABS_LOCK_BLOCKS:
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
        assert(addr_refund_out is not None), 'addr_refund_out is null'
        if self.coin_clients[coin_type]['use_segwit']:
            # Change to btc hrp
            addr_refund_out = self.encodeSegwit(Coins.PART, self.decodeSegwit(coin_type, addr_refund_out))
        else:
            addr_refund_out = replaceAddrPrefix(addr_refund_out, Coins.PART, self.chain)
        self.log.debug('addr_refund_out %s', addr_refund_out)

        output_to = ' outaddr={}:{}'.format(ci.format_amount(amount_out), addr_refund_out)
        if coin_type == Coins.PART:
            refund_txn = self.calltx('-create' + prevout_s + output_to)
        else:
            refund_txn = self.calltx('-btcmode -create nversion=2' + prevout_s + output_to)

        if offer.lock_type == ABS_LOCK_BLOCKS or offer.lock_type == ABS_LOCK_TIME:
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
        assert(ro['inputs_valid'] is True), 'inputs_valid is false'
        assert(ro['complete'] is True), 'complete is false'
        assert(ro['validscripts'] == 1), 'validscripts != 1'

        if self.debug:
            # Check fee
            if self.coin_clients[coin_type]['connection_type'] == 'rpc':
                refund_txjs = self.callcoinrpc(coin_type, 'decoderawtransaction', [refund_txn])
                self.log.debug('vsize paid, actual vsize %d %d', tx_vsize, refund_txjs['vsize'])
                assert(tx_vsize >= refund_txjs['vsize']), 'underpaid fee'

            refund_txjs = self.callcoinrpc(Coins.PART, 'decoderawtransaction', [refund_txn])
            self.log.debug('Have valid refund txn %s for contract tx %s', refund_txjs['txid'], txjs['txid'])

        return refund_txn

    def submitTxn(self, coin_type, txn):
        # self.log.debug('submitTxn %s', str(coin_type))
        if txn is None:
            return None
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None
        return self.callcoinrpc(coin_type, 'sendrawtransaction', [txn])

    def initiateTxnConfirmed(self, bid_id, bid, offer):
        self.log.debug('initiateTxnConfirmed for bid %s', bid_id.hex())
        bid.setState(BidStates.SWAP_INITIATED)
        bid.setITxState(TxStates.TX_CONFIRMED)

        if bid.debug_ind == DebugTypes.BUYER_STOP_AFTER_ITX:
            self.log.debug('bid %s: Abandoning bid for testing: %d.', bid_id.hex(), bid.debug_ind)
            bid.setState(BidStates.BID_ABANDONED)
            self.logBidEvent(bid, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), None)
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
                txid = self.submitTxn(coin_to, txn)
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
        chain_name = chainparams[coin_type]['name']
        if tx_height < 1:
            tx_height = self.lookupChainHeight(coin_type)

        if len(self.coin_clients[coin_type]['watched_outputs']) == 0:
            self.coin_clients[coin_type]['last_height_checked'] = tx_height
            self.log.debug('Start checking %s chain at height %d', chain_name, tx_height)

        if self.coin_clients[coin_type]['last_height_checked'] > tx_height:
            self.coin_clients[coin_type]['last_height_checked'] = tx_height
            self.log.debug('Rewind checking of %s chain to height %d', chain_name, tx_height)

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
            coin_to = Coins(offer.coin_to)
            txn = self.createRedeemTxn(coin_to, bid)
            txid = self.submitTxn(coin_to, txn)
            self.log.debug('Submitted participate redeem txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
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
        return self.callcoinrpc(coin_type, 'getblockchaininfo')['blocks']

    def lookupUnspentByAddress(self, coin_type, address, sum_output=False, assert_amount=None, assert_txid=None):

        ci = self.ci(coin_type)
        if self.coin_clients[coin_type]['chain_lookups'] == 'explorer':
            explorers = self.coin_clients[coin_type]['explorers']

            # TODO: random offset into explorers, try blocks
            for exp in explorers:

                # TODO: ExplorerBitAps use only gettransaction if assert_txid is set
                rv = exp.lookupUnspentByAddress(address)

                if assert_amount is not None:
                    assert(rv['value'] == int(assert_amount)), 'Incorrect output amount in txn {}: {} != {}.'.format(assert_txid, rv['value'], int(assert_amount))
                if assert_txid is not None:
                    assert(rv['txid)'] == assert_txid), 'Incorrect txid'

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

        num_blocks = self.callcoinrpc(coin_type, 'getblockchaininfo')['blocks']

        sum_unspent = 0
        self.log.debug('[rm] scantxoutset start')  # scantxoutset is slow
        ro = self.callcoinrpc(coin_type, 'scantxoutset', ['start', ['addr({})'.format(address)]])
        self.log.debug('[rm] scantxoutset end')
        for o in ro['unspents']:
            if assert_txid and o['txid'] != assert_txid:
                continue
            # Verify amount
            if assert_amount:
                assert(make_int(o['amount']) == int(assert_amount)), 'Incorrect output amount in txn {}: {} != {}.'.format(assert_txid, make_int(o['amount']), int(assert_amount))

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
            assert(xmr_offer), 'XMR offer not found: {}.'.format(offer.offer_id.hex())
            xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
            assert(xmr_swap), 'XMR swap not found: {}.'.format(bid.bid_id.hex())

            if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                refund_tx = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND]
                if bid.was_received:
                    if bid.debug_ind == DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND:
                        self.log.debug('XMR bid %s: Stalling bid for testing: %d.', bid_id.hex(), bid.debug_ind)
                        bid.setState(BidStates.BID_STALLED_FOR_TEST)
                        rv = True
                        self.saveBidInSession(bid_id, bid, session, xmr_swap)
                        self.logBidEvent(bid, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
                        session.commit()
                        return rv

                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND not in bid.txns:
                        try:
                            txid = ci_from.publishTx(xmr_swap.a_lock_refund_spend_tx)
                            self.logBidEvent(bid, EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_PUBLISHED, '', session)

                            self.log.info('Submitted coin a lock refund spend tx for bid {}'.format(bid_id.hex()))
                            bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND] = SwapTx(
                                bid_id=bid_id,
                                tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND,
                                txid=bytes.fromhex(txid),
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
                            self.logBidEvent(bid, EventLogTypes.LOCK_TX_A_REFUND_SWIPE_TX_PUBLISHED, '', session)
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
                        self.logBidEvent(bid, EventLogTypes.LOCK_TX_A_REFUND_TX_PUBLISHED, '', session)
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
                            txid = ci_from.getTxHash(xmr_swap.a_lock_refund_tx)
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
            elif state == BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX:
                if bid.xmr_a_lock_tx is None:
                    return rv

                # TODO: Timeout waiting for transactions
                bid_changed = False
                a_lock_tx_dest = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)
                utxos, chain_height = ci_from.getOutput(bid.xmr_a_lock_tx.txid, a_lock_tx_dest, bid.amount)

                if len(utxos) < 1:
                    return rv

                if len(utxos) > 1:
                    raise ValueError('Too many outputs for chain A lock tx')

                utxo = utxos[0]
                if not bid.xmr_a_lock_tx.chain_height and utxo['height'] != 0:
                    self.logBidEvent(bid, EventLogTypes.LOCK_TX_A_SEEN, '', session)

                    block_header = ci_from.getBlockHeaderFromHeight(utxo['height'])

                    bid.xmr_a_lock_tx.block_hash = bytes.fromhex(block_header['hash'])
                    bid.xmr_a_lock_tx.block_height = block_header['height']
                    bid.xmr_a_lock_tx.block_time = block_header['time']  # Or median_time?

                    bid_changed = True
                if bid.xmr_a_lock_tx.chain_height != utxo['height'] and utxo['height'] != 0:
                    bid.xmr_a_lock_tx.chain_height = utxo['height']
                    bid_changed = True

                if utxo['depth'] >= ci_from.blocks_confirmed:
                    self.logBidEvent(bid, EventLogTypes.LOCK_TX_A_CONFIRMED, '', session)
                    bid.xmr_a_lock_tx.setState(TxStates.TX_CONFIRMED)
                    bid.setState(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
                    bid_changed = True

                    if bid.was_sent:
                        delay = random.randrange(self.min_delay_event, self.max_delay_event)
                        self.log.info('Sending xmr swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createEventInSession(delay, EventTypes.SEND_XMR_SWAP_LOCK_TX_B, bid_id, session)
                        # bid.setState(BidStates.SWAP_DELAYING)

                if bid_changed:
                    self.saveBidInSession(bid_id, bid, session, xmr_swap)
                    session.commit()

            elif state == BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED:
                if bid.was_sent and bid.xmr_b_lock_tx is None:
                    return rv

                bid_changed = False
                # Have to use findTxB instead of relying on the first seen height to detect chain reorgs
                found_tx = ci_to.findTxB(xmr_swap.vkbv, xmr_swap.pkbs, bid.amount_to, ci_to.blocks_confirmed, xmr_swap.b_restore_height)

                if isinstance(found_tx, int) and found_tx == -1:
                    if self.countBidEvents(bid, EventLogTypes.LOCK_TX_B_INVALID, session) < 1:
                        self.logBidEvent(bid, EventLogTypes.LOCK_TX_B_INVALID, 'Detected invalid lock tx B', session)
                        bid_changed = True
                elif found_tx is not None:
                    if bid.xmr_b_lock_tx is None or not bid.xmr_b_lock_tx.chain_height:
                        self.logBidEvent(bid, EventLogTypes.LOCK_TX_B_SEEN, '', session)
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
                        self.logBidEvent(bid, EventLogTypes.LOCK_TX_B_CONFIRMED, '', session)
                        bid.xmr_b_lock_tx.setState(TxStates.TX_CONFIRMED)
                        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)

                        if bid.was_received:
                            delay = random.randrange(self.min_delay_event, self.max_delay_event)
                            self.log.info('Releasing xmr script coin lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                            self.createEventInSession(delay, EventTypes.SEND_XMR_LOCK_RELEASE, bid_id, session)

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
            elif state == BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED:
                txid_hex = bid.xmr_b_lock_tx.spend_txid.hex()

                found_tx = ci_to.findTxnByHash(txid_hex)
                if found_tx is not None:
                    self.log.info('Found coin b lock spend tx bid %s', bid_id.hex())
                    rv = True  # Remove from swaps_in_progress
                    bid.setState(BidStates.SWAP_COMPLETED)
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
        # assert(self.mxDB.locked())
        # Return True to remove bid from in-progress list

        state = BidStates(bid.state)
        self.log.debug('checkBidState %s %s', bid_id.hex(), str(state))

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.checkXmrBidState(bid_id, bid, offer)

        save_bid = False
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        # TODO: Batch calls to scantxoutset
        # TODO: timeouts
        if state == BidStates.BID_ABANDONED:
            self.log.info('Deactivating abandoned bid: %s', bid_id.hex())
            return True  # Mark bid for archiving
        if state == BidStates.BID_ACCEPTED:
            # Waiting for initiate txn to be confirmed in 'from' chain
            initiate_txnid_hex = bid.initiate_tx.txid.hex()
            p2sh = self.getScriptAddress(coin_from, bid.initiate_tx.script)
            index = None
            tx_height = None
            last_initiate_txn_conf = bid.initiate_tx.conf
            if coin_from == Coins.PART:  # Has txindex
                try:
                    initiate_txn = self.callcoinrpc(coin_from, 'getrawtransaction', [initiate_txnid_hex, True])
                    # Verify amount
                    vout = getVoutByAddress(initiate_txn, p2sh)

                    out_value = make_int(initiate_txn['vout'][vout]['value'])
                    assert(out_value == int(bid.amount)), 'Incorrect output amount in initiate txn {}: {} != {}.'.format(initiate_txnid_hex, out_value, int(bid.amount))

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
                    addr = self.encodeSegwitP2WSH(coin_from, getP2WSH(bid.initiate_tx.script))
                else:
                    addr = p2sh
                found = self.lookupUnspentByAddress(coin_from, addr, assert_amount=bid.amount, assert_txid=initiate_txnid_hex)
                if found:
                    bid.initiate_tx.conf = found['n_conf']
                    index = found['index']
                    tx_height = found['height']

            if bid.initiate_tx.conf != last_initiate_txn_conf:
                save_bid = True

            if bid.initiate_tx.conf is not None:
                self.log.debug('initiate_txnid %s confirms %d', initiate_txnid_hex, bid.initiate_tx.conf)

                if bid.initiate_tx.vout is None:
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
                addr = self.encodeSegwitP2WSH(coin_to, getP2WSH(bid.participate_tx.script))
            else:
                addr = self.getScriptAddress(coin_to, bid.participate_tx.script)

            found = self.lookupUnspentByAddress(coin_to, addr, assert_amount=bid.amount_to)
            if found:
                if bid.participate_tx.conf != found['n_conf']:
                    save_bid = True
                bid.participate_tx.conf = found['n_conf']
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
            if (bid.getITxState() is None or bid.getITxState() >= TxStates.TX_REDEEMED) \
               and (bid.getPTxState() is None or bid.getPTxState() >= TxStates.TX_REDEEMED):
                self.log.info('Swap completed for bid %s', bid_id.hex())

                if bid.getITxState() == TxStates.TX_REDEEMED:
                    self.returnAddressToPool(bid_id, TxTypes.ITX_REFUND)
                else:
                    self.returnAddressToPool(bid_id, TxTypes.ITX_REDEEM)
                if bid.getPTxState() == TxStates.TX_REDEEMED:
                    self.returnAddressToPool(bid_id, TxTypes.PTX_REFUND)
                else:
                    self.returnAddressToPool(bid_id, TxTypes.PTX_REDEEM)

                bid.setState(BidStates.SWAP_COMPLETED)
                self.saveBid(bid_id, bid)
                return True  # Mark bid for archiving

        if save_bid:
            self.saveBid(bid_id, bid)

        # Try refund, keep trying until sent tx is spent
        if (bid.getITxState() == TxStates.TX_SENT or bid.getITxState() == TxStates.TX_CONFIRMED) \
           and bid.initiate_txn_refund is not None:
            try:
                txid = self.submitTxn(coin_from, bid.initiate_txn_refund.hex())
                self.log.debug('Submitted initiate refund txn %s to %s chain for bid %s', txid, chainparams[coin_from]['name'], bid_id.hex())
                # State will update when spend is detected
            except Exception as ex:
                if 'non-BIP68-final (code 64)' not in str(ex) and 'non-final' not in str(ex):
                    self.log.warning('Error trying to submit initiate refund txn: %s', str(ex))
        if (bid.getPTxState() == TxStates.TX_SENT or bid.getPTxState() == TxStates.TX_CONFIRMED) \
           and bid.participate_txn_refund is not None:
            try:
                txid = self.submitTxn(coin_to, bid.participate_txn_refund.hex())
                self.log.debug('Submitted participate refund txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
                # State will update when spend is detected
            except Exception as ex:
                if 'non-BIP68-final (code 64)' not in str(ex) and 'non-final' not in str(ex):
                    self.log.warning('Error trying to submit participate refund txn: %s', str(ex))
        return False  # Bid is still active

    def extractSecret(self, coin_type, bid, spend_in):
        try:
            if coin_type == Coins.PART or self.coin_clients[coin_type]['use_segwit']:
                assert(len(spend_in['txinwitness']) == 5), 'Bad witness size'
                return bytes.fromhex(spend_in['txinwitness'][2])
            else:
                script_sig = spend_in['scriptSig']['asm'].split(' ')
                assert(len(script_sig) == 5), 'Bad witness size'
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
                    txn = self.createRedeemTxn(coin_from, bid, for_txn_type='initiate')
                    txid = self.submitTxn(coin_from, txn)

                    bid.initiate_tx.spend_txid = bytes.fromhex(txid)
                    # bid.initiate_txn_redeem = bytes.fromhex(txn)  # Worth keeping?
                    self.log.debug('Submitted initiate redeem txn %s to %s chain for bid %s', txid, chainparams[coin_from]['name'], bid_id.hex())

                # TODO: Wait for depth? new state SWAP_TXI_REDEEM_SENT?

            self.removeWatchedOutput(coin_to, bid_id, bid.participate_tx.txid.hex())
            self.saveBid(bid_id, bid)

    def process_XMR_SWAP_A_LOCK_tx_spend(self, bid_id, spend_txid_hex, spend_txn_hex):
        self.log.debug('Detected spend of XMR swap coin a lock tx for bid %s', bid_id.hex())
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
            assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
            assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

            offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
            assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
            assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
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
                    if bid.was_received:
                        bid.setState(BidStates.SWAP_DELAYING)
                        delay = random.randrange(self.min_delay_event, self.max_delay_event)
                        self.log.info('Redeeming coin b lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                        self.createEventInSession(delay, EventTypes.REDEEM_XMR_SWAP_LOCK_TX_B, bid_id, session)
                else:
                    # Could already be processed if spend was detected in the mempool
                    self.log.warning('Coin a lock tx spend ignored due to bid state for bid {}'.format(bid_id.hex()))

            elif spending_txid == xmr_swap.a_lock_refund_tx_id:
                self.log.debug('Coin a lock tx spent by lock refund tx.')
                pass
            else:
                self.setBidError(bid.bid_id, bid, 'Unexpected txn spent coin a lock tx: {}'.format(spend_txid_hex), save_bid=False)

            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            session.commit()
        except Exception as ex:
            self.log.error('process_XMR_SWAP_A_LOCK_tx_spend %s', str(ex))
            if self.debug:
                traceback.print_exc()
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
            assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
            assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

            offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
            assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
            assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            state = BidStates(bid.state)
            spending_txid = bytes.fromhex(spend_txid_hex)

            if spending_txid == xmr_swap.a_lock_refund_spend_tx_id:
                self.log.info('Found coin a lock refund spend tx, bid {}'.format(bid_id.hex()))

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
                        self.createEventInSession(delay, EventTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, session)
                    else:
                        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)

                if bid.was_received:
                    if not bid.was_sent:
                        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)

            else:
                self.log.info('Coin a lock refund spent by unknown tx, bid {}'.format(bid_id.hex()))
                bid.setState(BidStates.XMR_SWAP_FAILED_SWIPED)

            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            session.commit()
        except Exception as ex:
            self.log.error('process_XMR_SWAP_A_LOCK_REFUND_tx_spend %s', str(ex))
            if self.debug:
                traceback.print_exc()
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
        # assert(self.mxDB.locked())
        self.log.debug('checkForSpends %s', coin_type)

        if coin_type == Coins.PART and self.coin_clients[coin_type]['have_spent_index']:
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
            chain_blocks = self.callcoinrpc(coin_type, 'getblockchaininfo')['blocks']
            last_height_checked = c['last_height_checked']
            self.log.debug('chain_blocks, last_height_checked %s %s', chain_blocks, last_height_checked)
            while last_height_checked < chain_blocks:
                block_hash = self.callcoinrpc(coin_type, 'getblockhash', [last_height_checked + 1])
                try:
                    block = self.callcoinrpc(coin_type, 'getblock', [block_hash, 2])
                except Exception as e:
                    if 'Block not available (pruned data)' in str(e):
                        # TODO: Better solution?
                        bci = self.callcoinrpc(coin_type, 'getblockchaininfo')
                        self.log.error('Coin %s last_height_checked %d set to pruneheight %d', self.ci(coin_type).coin_name(), last_height_checked, bci['pruneheight'])
                        last_height_checked = bci['pruneheight']
                        continue

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
        try:
            now = int(time.time())
            options = {'encoding': 'none'}
            ro = self.callrpc('smsginbox', ['all', '', options])
            num_messages = 0
            num_removed = 0
            for msg in ro['messages']:
                num_messages += 1
                expire_at = msg['sent'] + msg['ttl']
                if expire_at < now:
                    options = {'encoding': 'none', 'delete': True}
                    del_msg = self.callrpc('smsg', [msg['msgid'], options])
                    num_removed += 1

            if num_messages + num_removed > 0:
                self.log.info('Expired {} / {} messages.'.format(num_removed, num_messages))

            self.log.debug('TODO: Expire records from db')

        finally:
            self.mxDB.release()

    def checkEvents(self):
        self.mxDB.acquire()
        now = int(time.time())
        session = None
        try:
            session = scoped_session(self.session_factory)

            q = session.query(EventQueue).filter(sa.and_(EventQueue.active_ind == 1, EventQueue.trigger_at <= now))
            for row in q:
                try:
                    if row.event_type == EventTypes.ACCEPT_BID:
                        self.acceptBid(row.linked_id)
                    elif row.event_type == EventTypes.ACCEPT_XMR_BID:
                        self.acceptXmrBid(row.linked_id)
                    elif row.event_type == EventTypes.SIGN_XMR_SWAP_LOCK_TX_A:
                        self.sendXmrBidTxnSigsFtoL(row.linked_id, session)
                    elif row.event_type == EventTypes.SEND_XMR_SWAP_LOCK_TX_A:
                        self.sendXmrBidCoinALockTx(row.linked_id, session)
                    elif row.event_type == EventTypes.SEND_XMR_SWAP_LOCK_TX_B:
                        self.sendXmrBidCoinBLockTx(row.linked_id, session)
                    elif row.event_type == EventTypes.SEND_XMR_LOCK_RELEASE:
                        self.sendXmrBidLockRelease(row.linked_id, session)
                    elif row.event_type == EventTypes.REDEEM_XMR_SWAP_LOCK_TX_A:
                        self.redeemXmrBidCoinALockTx(row.linked_id, session)
                    elif row.event_type == EventTypes.REDEEM_XMR_SWAP_LOCK_TX_B:
                        self.redeemXmrBidCoinBLockTx(row.linked_id, session)
                    elif row.event_type == EventTypes.RECOVER_XMR_SWAP_LOCK_TX_B:
                        self.recoverXmrBidCoinBLockTx(row.linked_id, session)
                    else:
                        self.log.warning('Unknown event type: %d', row.event_type)
                except Exception as ex:
                    if self.debug:
                        traceback.print_exc()
                    self.log.error('checkEvents failed: {}'.format(str(ex)))

            if self.debug:
                session.execute('UPDATE eventqueue SET active_ind = 2 WHERE trigger_at <= {}'.format(now))
            else:
                session.execute('DELETE FROM eventqueue WHERE trigger_at <= {}'.format(now))

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
        assert(msg['to'] == self.network_addr), 'Offer received on wrong address'

        offer_bytes = bytes.fromhex(msg['hex'][2:-2])
        offer_data = OfferMessage()
        offer_data.ParseFromString(offer_bytes)

        # Validate data
        now = int(time.time())
        coin_from = Coins(offer_data.coin_from)
        ci_from = self.ci(coin_from)
        coin_to = Coins(offer_data.coin_to)
        ci_to = self.ci(coin_to)
        chain_from = chainparams[coin_from][self.chain]
        assert(offer_data.coin_from != offer_data.coin_to), 'coin_from == coin_to'

        self.validateSwapType(coin_from, coin_to, offer_data.swap_type)
        self.validateOfferAmounts(coin_from, coin_to, offer_data.amount_from, offer_data.rate, offer_data.min_bid_amount)
        self.validateOfferLockValue(coin_from, coin_to, offer_data.lock_type, offer_data.lock_value)
        self.validateOfferValidTime(offer_data.swap_type, coin_from, coin_to, offer_data.time_valid)

        assert(msg['sent'] + offer_data.time_valid >= now), 'Offer expired'

        if offer_data.swap_type == SwapTypes.SELLER_FIRST:
            assert(len(offer_data.proof_address) == 0), 'Unexpected data'
            assert(len(offer_data.proof_signature) == 0), 'Unexpected data'
            assert(len(offer_data.pkhash_seller) == 0), 'Unexpected data'
            assert(len(offer_data.secret_hash) == 0), 'Unexpected data'
        elif offer_data.swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError('TODO')
        elif offer_data.swap_type == SwapTypes.XMR_SWAP:
            assert(coin_from not in (Coins.XMR, Coins.PART_ANON))
            assert(coin_to in (Coins.XMR, Coins.PART_ANON))
            self.log.debug('TODO - More restrictions')
        else:
            raise ValueError('Unknown swap type {}.'.format(offer_data.swap_type))

        offer_id = bytes.fromhex(msg['msgid'])

        if self.isOfferRevoked(offer_id, msg['from']):
            raise ValueError('Offer has been revoked {}.'.format(offer_id.hex()))

        session = scoped_session(self.session_factory)
        try:
            # Check for sent
            existing_offer = self.getOffer(offer_id)
            if existing_offer is None:
                offer = Offer(
                    offer_id=offer_id,
                    active_ind=1,

                    coin_from=offer_data.coin_from,
                    coin_to=offer_data.coin_to,
                    amount_from=offer_data.amount_from,
                    rate=offer_data.rate,
                    min_bid_amount=offer_data.min_bid_amount,
                    time_valid=offer_data.time_valid,
                    lock_type=int(offer_data.lock_type),
                    lock_value=offer_data.lock_value,
                    swap_type=offer_data.swap_type,

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

                self.log.debug('Received new offer %s', offer_id.hex())
            else:
                existing_offer.setState(OfferStates.OFFER_RECEIVED)
                session.add(existing_offer)
            session.commit()
        finally:
            session.close()
            session.remove()

    def processOfferRevoke(self, msg):
        assert(msg['to'] == self.network_addr), 'Message received on wrong address'

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
            assert(passed is True), 'Signature invalid'

            offer.active_ind = 2
            # TODO: Remove message, or wait for expire

            session.add(offer)
            session.commit()
        finally:
            if session:
                session.close()
                session.remove()
            self.mxDB.release()

    def processBid(self, msg):
        self.log.debug('Processing bid msg %s', msg['msgid'])
        now = int(time.time())
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = BidMessage()
        bid_data.ParseFromString(bid_bytes)

        # Validate data
        assert(len(bid_data.offer_msg_id) == 28), 'Bad offer_id length'

        offer_id = bid_data.offer_msg_id
        offer = self.getOffer(offer_id, sent=True)
        assert(offer and offer.was_sent), 'Unknown offer'

        assert(offer.state == OfferStates.OFFER_RECEIVED), 'Bad offer state'
        assert(msg['to'] == offer.addr_from), 'Received on incorrect address'
        assert(now <= offer.expire_at), 'Offer expired'
        assert(bid_data.amount >= offer.min_bid_amount), 'Bid amount below minimum'
        assert(bid_data.amount <= offer.amount_from), 'Bid amount above offer amount'
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid)
        assert(now <= msg['sent'] + bid_data.time_valid), 'Bid expired'

        # TODO: Allow higher bids
        # assert(bid_data.rate != offer['data'].rate), 'Bid rate mismatch'

        coin_to = Coins(offer.coin_to)

        amount_to = int((bid_data.amount * offer.rate) // self.ci(offer.coin_from).COIN())
        swap_type = offer.swap_type
        if swap_type == SwapTypes.SELLER_FIRST:
            assert(len(bid_data.pkhash_buyer) == 20), 'Bad pkhash_buyer length'

            # Verify proof of funds
            bid_proof_address = replaceAddrPrefix(bid_data.proof_address, Coins.PART, self.chain)
            mm = chainparams[coin_to]['message_magic']
            passed = self.ci(Coins.PART).verifyMessage(bid_proof_address, bid_data.proof_address + '_swap_proof_' + offer_id.hex(), bid_data.proof_signature, mm)
            assert(passed is True), 'Proof of funds signature invalid'

            if self.coin_clients[coin_to]['use_segwit']:
                addr_search = self.encodeSegwit(coin_to, decodeAddress(bid_data.proof_address)[1:])
            else:
                addr_search = bid_data.proof_address

            sum_unspent = self.getAddressBalance(coin_to, addr_search)
            self.log.debug('Proof of funds %s %s', bid_data.proof_address, self.ci(coin_to).format_amount(sum_unspent))
            assert(sum_unspent >= amount_to), 'Proof of funds failed'

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
                amount=bid_data.amount,
                pkhash_buyer=bid_data.pkhash_buyer,

                created_at=msg['sent'],
                amount_to=amount_to,
                expire_at=msg['sent'] + bid_data.time_valid,
                bid_addr=msg['from'],
                was_received=True,
            )
        else:
            assert(bid.state == BidStates.BID_SENT), 'Wrong bid state: {}'.format(str(BidStates(bid.state)))
            bid.created_at = msg['sent']
            bid.expire_at = msg['sent'] + bid_data.time_valid
            bid.was_received = True
        if len(bid_data.proof_address) > 0:
            bid.proof_address = bid_data.proof_address

        bid.setState(BidStates.BID_RECEIVED)

        self.log.info('Received valid bid %s for offer %s', bid_id.hex(), bid_data.offer_msg_id.hex())
        self.saveBid(bid_id, bid)

        # Auto accept bid if set and no other non-abandoned bid for this order exists
        if offer.auto_accept_bids:
            if self.countAcceptedBids(offer_id) > 0:
                self.log.info('Not auto accepting bid %s, already have', bid_id.hex())
            elif bid_data.amount != offer.amount_from:
                self.log.info('Not auto accepting bid %s, want exact amount match', bid_id.hex())
            else:
                delay = random.randrange(self.min_delay_event, self.max_delay_event)
                self.log.info('Auto accepting bid %s in %d seconds', bid_id.hex(), delay)
                self.createEvent(delay, EventTypes.ACCEPT_BID, bid_id)

    def processBidAccept(self, msg):
        self.log.debug('Processing bid accepted msg %s', msg['msgid'])
        now = int(time.time())
        bid_accept_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_accept_data = BidAcceptMessage()
        bid_accept_data.ParseFromString(bid_accept_bytes)

        assert(len(bid_accept_data.bid_msg_id) == 28), 'Bad bid_msg_id length'
        assert(len(bid_accept_data.initiate_txid) == 32), 'Bad initiate_txid length'
        assert(len(bid_accept_data.contract_script) < 100), 'Bad contract_script length'

        self.log.debug('for bid %s', bid_accept_data.bid_msg_id.hex())

        bid_id = bid_accept_data.bid_msg_id
        bid, offer = self.getBidAndOffer(bid_id)
        assert(bid is not None and bid.was_sent is True), 'Unknown bidid'
        assert(offer), 'Offer not found ' + bid.offer_id.hex()
        coin_from = Coins(offer.coin_from)
        ci_from = self.ci(coin_from)

        assert(bid.expire_at > now + self._bid_expired_leeway), 'Bid expired'

        if bid.state >= BidStates.BID_ACCEPTED:
            if bid.was_received:  # Sent to self
                self.log.info('Received valid bid accept %s for bid %s sent to self', bid.accept_msg_id.hex(), bid_id.hex())
                return
            raise ValueError('Wrong bid state: {}'.format(str(BidStates(bid.state))))

        use_csv = True if offer.lock_type < ABS_LOCK_BLOCKS else False

        # TODO: Verify script without decoding?
        decoded_script = self.callcoinrpc(Coins.PART, 'decodescript', [bid_accept_data.contract_script.hex()])
        lock_check_op = 'OP_CHECKSEQUENCEVERIFY' if use_csv else 'OP_CHECKLOCKTIMEVERIFY'
        prog = re.compile(r'OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 (\w+) OP_EQUALVERIFY OP_DUP OP_HASH160 (\w+) OP_ELSE (\d+) {} OP_DROP OP_DUP OP_HASH160 (\w+) OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG'.format(lock_check_op))
        rr = prog.match(decoded_script['asm'])
        if not rr:
            raise ValueError('Bad script')
        scriptvalues = rr.groups()

        assert(len(scriptvalues[0]) == 64), 'Bad secret_hash length'
        assert(bytes.fromhex(scriptvalues[1]) == bid.pkhash_buyer), 'pkhash_buyer mismatch'

        script_lock_value = int(scriptvalues[2])
        if use_csv:
            expect_sequence = ci_from.getExpectedSequence(offer.lock_type, offer.lock_value)
            assert(script_lock_value == expect_sequence), 'sequence mismatch'
        else:
            if offer.lock_type == ABS_LOCK_BLOCKS:
                self.log.warning('TODO: validate absolute lock values')
            else:
                assert(script_lock_value <= bid.created_at + offer.lock_value + atomic_swap_1.INITIATE_TX_TIMEOUT), 'script lock time too high'
                assert(script_lock_value >= bid.created_at + offer.lock_value), 'script lock time too low'

        assert(len(scriptvalues[3]) == 40), 'pkhash_refund bad length'

        assert(bid.accept_msg_id is None), 'Bid already accepted'

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

        self.log.info('Received valid bid accept %s for bid %s', bid.accept_msg_id.hex(), bid_id.hex())

        self.saveBid(bid_id, bid)
        self.swaps_in_progress[bid_id] = (bid, offer)

    def receiveXmrBid(self, bid, session):
        self.log.debug('Receiving xmr bid %s', bid.bid_id.hex())
        now = int(time.time())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=True)
        assert(offer and offer.was_sent), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid.bid_id.hex())

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

        if not ci_to.verifyKey(xmr_swap.vkbvf):
            raise ValueError('Invalid key.')

        if not ci_from.verifyPubkey(xmr_swap.pkaf):
            raise ValueError('Invalid pubkey.')

        self.log.info('Received valid bid %s for xmr offer %s', bid.bid_id.hex(), bid.offer_id.hex())

        bid.setState(BidStates.BID_RECEIVED)
        self.saveBidInSession(bid.bid_id, bid, session, xmr_swap)

        # Auto accept bid if set and no other non-abandoned bid for this order exists
        if offer.auto_accept_bids:
            if self.countAcceptedBids(bid.offer_id) > 0:
                self.log.info('Not auto accepting bid %s, already have', bid.bid_id.hex())
            elif bid.amount != offer.amount_from:
                self.log.info('Not auto accepting bid %s, want exact amount match', bid.bid_id.hex())
            else:
                delay = random.randrange(self.min_delay_event, self.max_delay_event)
                self.log.info('Auto accepting xmr bid %s in %d seconds', bid.bid_id.hex(), delay)
                self.createEventInSession(delay, EventTypes.ACCEPT_XMR_BID, bid.bid_id, session)

    def receiveXmrBidAccept(self, bid, session):
        # Follower receiving MSG1F and MSG2F
        self.log.debug('Receiving xmr bid accept %s', bid.bid_id.hex())
        now = int(time.time())

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=True)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        xmr_swap = session.query(XmrSwap).filter_by(bid_id=bid.bid_id).first()
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid.bid_id.hex())
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

        if not ci_to.verifyKey(xmr_swap.vkbvl):
            raise ValueError('Invalid key.')

        xmr_swap.vkbv = ci_to.sumKeys(xmr_swap.vkbvl, xmr_swap.vkbvf)
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

        bid.setState(BidStates.SWAP_DELAYING)
        self.saveBidInSession(bid.bid_id, bid, session, xmr_swap)

        delay = random.randrange(self.min_delay_event, self.max_delay_event)
        self.log.info('Responding to xmr bid accept %s in %d seconds', bid.bid_id.hex(), delay)
        self.createEventInSession(delay, EventTypes.SIGN_XMR_SWAP_LOCK_TX_A, bid.bid_id, session)

    def processXmrBid(self, msg):
        # MSG1L
        self.log.debug('Processing xmr bid msg %s', msg['msgid'])
        now = int(time.time())
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = XmrBidMessage()
        bid_data.ParseFromString(bid_bytes)

        # Validate data
        assert(len(bid_data.offer_msg_id) == 28), 'Bad offer_id length'

        offer_id = bid_data.offer_msg_id
        offer, xmr_offer = self.getXmrOffer(offer_id, sent=True)
        assert(offer and offer.was_sent), 'Offer not found: {}.'.format(offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(offer_id.hex())

        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(offer.coin_to)

        assert(offer.state == OfferStates.OFFER_RECEIVED), 'Bad offer state'
        assert(msg['to'] == offer.addr_from), 'Received on incorrect address'
        assert(now <= offer.expire_at), 'Offer expired'
        assert(bid_data.amount >= offer.min_bid_amount), 'Bid amount below minimum'
        assert(bid_data.amount <= offer.amount_from), 'Bid amount above offer amount'
        self.validateBidValidTime(offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid)
        assert(now <= msg['sent'] + bid_data.time_valid), 'Bid expired'

        assert(ci_to.verifyKey(bid_data.kbvf))
        assert(ci_from.verifyPubkey(bid_data.pkaf))

        bid_id = bytes.fromhex(msg['msgid'])

        bid, xmr_swap = self.getXmrBid(bid_id)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                amount=bid_data.amount,
                created_at=msg['sent'],
                amount_to=(bid_data.amount * offer.rate) // ci_from.COIN(),
                expire_at=msg['sent'] + bid_data.time_valid,
                bid_addr=msg['from'],
                was_received=True,
            )

            xmr_swap = XmrSwap(
                bid_id=bid_id,
                dest_af=bid_data.dest_af,
                pkaf=bid_data.pkaf,
                vkbvf=bid_data.kbvf,
                pkbvf=ci_to.getPubkey(bid_data.kbvf),
                kbsf_dleag=bid_data.kbsf_dleag,
                b_restore_height=ci_to.getChainHeight(),
                start_chain_a_height=ci_from.getChainHeight(),
            )
            wallet_restore_height = self.getWalletRestoreHeight(ci_to)
            if xmr_swap.b_restore_height < wallet_restore_height:
                xmr_swap.b_restore_height = wallet_restore_height
                self.log.warning('XMR swap restore height clamped to {}'.format(wallet_restore_height))
        else:
            assert(bid.state == BidStates.BID_SENT), 'Wrong bid state: {}'.format(str(BidStates(bid.state)))
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

        assert(len(msg_data.bid_msg_id) == 28), 'Bad bid_msg_id length'

        self.log.debug('for bid %s', msg_data.bid_msg_id.hex())
        bid, xmr_swap = self.getXmrBid(msg_data.bid_msg_id)
        assert(bid), 'Bid not found: {}.'.format(msg_data.bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(msg_data.bid_id.hex())

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=True)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(offer.coin_to)

        try:
            xmr_swap.pkal = msg_data.pkal
            xmr_swap.vkbvl = msg_data.kbvl
            xmr_swap.pkbvl = ci_to.getPubkey(msg_data.kbvl)
            xmr_swap.kbsl_dleag = msg_data.kbsl_dleag

            xmr_swap.a_lock_tx = msg_data.a_lock_tx
            xmr_swap.a_lock_tx_script = msg_data.a_lock_tx_script
            xmr_swap.a_lock_refund_tx = msg_data.a_lock_refund_tx
            xmr_swap.a_lock_refund_tx_script = msg_data.a_lock_refund_tx_script
            xmr_swap.a_lock_refund_spend_tx = msg_data.a_lock_refund_spend_tx
            xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxHash(xmr_swap.a_lock_refund_spend_tx)
            xmr_swap.al_lock_refund_tx_sig = msg_data.al_lock_refund_tx_sig

            # TODO: check_a_lock_tx_inputs without txindex
            check_a_lock_tx_inputs = False
            xmr_swap.a_lock_tx_id, xmr_swap.a_lock_tx_vout = ci_from.verifyLockTx(
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                bid.amount,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.a_fee_rate,
                check_a_lock_tx_inputs
            )
            a_lock_tx_dest = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)

            xmr_swap.a_lock_refund_tx_id, xmr_swap.a_swap_refund_value = ci_from.verifyLockRefundTx(
                xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.a_lock_tx_id, xmr_swap.a_lock_tx_vout, xmr_offer.lock_time_1, xmr_swap.a_lock_tx_script,
                xmr_swap.pkal, xmr_swap.pkaf,
                xmr_offer.lock_time_2,
                bid.amount, xmr_offer.a_fee_rate
            )

            ci_from.verifyLockRefundSpendTx(
                xmr_swap.a_lock_refund_spend_tx,
                xmr_swap.a_lock_refund_tx_id, xmr_swap.a_lock_refund_tx_script,
                xmr_swap.pkal,
                xmr_swap.a_swap_refund_value, xmr_offer.a_fee_rate
            )

            self.log.info('Checking leader\'s lock refund tx signature')
            v = ci_from.verifyTxSig(xmr_swap.a_lock_refund_tx, xmr_swap.al_lock_refund_tx_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, bid.amount)

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
                traceback.print_exc()
            self.setBidError(bid.bid_id, bid, str(ex))

    def watchXmrSwap(self, bid, offer, xmr_swap):
        self.log.debug('XMR swap in progress, bid %s', bid.bid_id.hex())
        self.swaps_in_progress[bid.bid_id] = (bid, offer)

        coin_from = Coins(offer.coin_from)
        self.setLastHeightChecked(coin_from, xmr_swap.start_chain_a_height)
        self.addWatchedOutput(coin_from, bid.bid_id, bid.xmr_a_lock_tx.txid.hex(), bid.xmr_a_lock_tx.vout, TxTypes.XMR_SWAP_A_LOCK, SwapTypes.XMR_SWAP)
        self.addWatchedOutput(coin_from, bid.bid_id, xmr_swap.a_lock_refund_tx_id.hex(), 0, TxTypes.XMR_SWAP_A_LOCK_REFUND, SwapTypes.XMR_SWAP)
        bid.in_progress = 1

    def sendXmrBidTxnSigsFtoL(self, bid_id, session):
        # F -> L: Sending MSG3L
        self.log.debug('Signing xmr bid lock txns %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        try:
            kaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 3)

            xmr_swap.af_lock_refund_spend_tx_esig = ci_from.signTxOtVES(kaf, xmr_swap.pkasl, xmr_swap.a_lock_refund_spend_tx, 0, xmr_swap.a_lock_refund_tx_script, xmr_swap.a_swap_refund_value)
            xmr_swap.af_lock_refund_tx_sig = ci_from.signTx(kaf, xmr_swap.a_lock_refund_tx, 0, xmr_swap.a_lock_tx_script, bid.amount)

            self.addLockRefundSigs(xmr_swap, ci_from)

            msg_buf = XmrBidLockTxSigsMessage(
                bid_msg_id=bid_id,
                af_lock_refund_spend_tx_esig=xmr_swap.af_lock_refund_spend_tx_esig,
                af_lock_refund_tx_sig=xmr_swap.af_lock_refund_tx_sig
            )

            msg_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_TXN_SIGS_FL) + msg_bytes.hex()

            options = {'decodehex': True, 'ttl_is_seconds': True}
            # TODO: set msg_valid based on bid / offer parameters
            msg_valid = self.SMSG_SECONDS_IN_HOUR * 48
            ro = self.callrpc('smsgsend', [bid.bid_addr, offer.addr_from, payload_hex, False, msg_valid, False, options])
            xmr_swap.coin_a_lock_tx_sigs_l_msg_id = bytes.fromhex(ro['msgid'])

            self.log.info('Sent XMR_BID_TXN_SIGS_FL %s', xmr_swap.coin_a_lock_tx_sigs_l_msg_id.hex())

            a_lock_tx_id = ci_from.getTxHash(xmr_swap.a_lock_tx)
            a_lock_tx_vout = ci_from.getTxOutputPos(xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script)
            self.log.debug('Waiting for lock txn %s to %s chain for bid %s', a_lock_tx_id.hex(), ci_from.coin_name(), bid_id.hex())
            bid.xmr_a_lock_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.XMR_SWAP_A_LOCK,
                txid=a_lock_tx_id,
                vout=a_lock_tx_vout,
            )
            bid.xmr_a_lock_tx.setState(TxStates.TX_NONE)

            bid.setState(BidStates.BID_ACCEPTED)  # XMR
            self.watchXmrSwap(bid, offer, xmr_swap)
            self.saveBidInSession(bid_id, bid, session, xmr_swap)
        except Exception as ex:
            if self.debug:
                traceback.print_exc()

    def sendXmrBidCoinALockTx(self, bid_id, session):
        # Send coin A lock tx and MSG4F L -> F
        self.log.debug('Sending coin A lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 3)

        xmr_swap.a_lock_spend_tx = ci_from.createScriptLockSpendTx(
            xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
            xmr_swap.dest_af,
            xmr_offer.a_fee_rate)

        xmr_swap.a_lock_spend_tx_id = ci_from.getTxHash(xmr_swap.a_lock_spend_tx)
        xmr_swap.al_lock_spend_tx_esig = ci_from.signTxOtVES(kal, xmr_swap.pkasf, xmr_swap.a_lock_spend_tx, 0, xmr_swap.a_lock_tx_script, bid.amount)  # self.a_swap_value

        # Proof leader can sign for kal
        xmr_swap.kal_sig = ci_from.signCompact(kal, 'proof key owned for swap')

        msg_buf = XmrBidLockSpendTxMessage(
            bid_msg_id=bid_id,
            a_lock_spend_tx=xmr_swap.a_lock_spend_tx,
            kal_sig=xmr_swap.kal_sig)

        msg_bytes = msg_buf.SerializeToString()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_LOCK_SPEND_TX_LF) + msg_bytes.hex()

        options = {'decodehex': True, 'ttl_is_seconds': True}
        # TODO: set msg_valid based on bid / offer parameters
        msg_valid = self.SMSG_SECONDS_IN_HOUR * 48
        ro = self.callrpc('smsgsend', [offer.addr_from, bid.bid_addr, payload_hex, False, msg_valid, False, options])
        xmr_swap.coin_a_lock_refund_spend_tx_msg_id = bytes.fromhex(ro['msgid'])

        # TODO: Separate MSG4F and txn sending

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
        self.logBidEvent(bid, EventLogTypes.LOCK_TX_A_PUBLISHED, '', session)

        self.saveBidInSession(bid_id, bid, session, xmr_swap)

    def sendXmrBidCoinBLockTx(self, bid_id, session):
        # Follower sending coin B lock tx
        self.log.debug('Sending coin B lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        if bid.debug_ind == DebugTypes.BID_STOP_AFTER_COIN_A_LOCK:
            self.log.debug('XMR bid %s: Stalling bid for testing: %d.', bid_id.hex(), bid.debug_ind)
            bid.setState(BidStates.BID_STALLED_FOR_TEST)
            self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)
            self.logBidEvent(bid, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
            return

        if bid.debug_ind == DebugTypes.CREATE_INVALID_COIN_B_LOCK:
            bid.amount_to -= int(bid.amount_to * 0.1)
            self.log.debug('XMR bid %s: Debug %d - Reducing lock b txn amount by 10%% to %s.', bid_id.hex(), bid.debug_ind, ci_to.format_amount(bid.amount_to))
            self.logBidEvent(bid, EventLogTypes.DEBUG_TWEAK_APPLIED, 'ind {}'.format(bid.debug_ind), session)
        try:
            b_lock_tx_id = ci_to.publishBLockTx(xmr_swap.pkbv, xmr_swap.pkbs, bid.amount_to, xmr_offer.b_fee_rate)
        except Exception as ex:
            error_msg = 'publishBLockTx failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            str_error = str(ex)
            if num_retries < 5 and ('not enough unlocked money' in str_error or 'transaction was rejected by daemon' in str_error):
                delay = random.randrange(self.min_delay_retry, self.max_delay_retry)
                self.log.info('Retrying sending xmr swap chain B lock tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createEventInSession(delay, EventTypes.SEND_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'publishBLockTx failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, str_error, session)
            return

        self.log.debug('Submitted lock txn %s to %s chain for bid %s', b_lock_tx_id.hex(), ci_to.coin_name(), bid_id.hex())
        bid.xmr_b_lock_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.XMR_SWAP_B_LOCK,
            txid=b_lock_tx_id,
        )
        bid.xmr_b_lock_tx.setState(TxStates.TX_NONE)
        self.logBidEvent(bid, EventLogTypes.LOCK_TX_B_PUBLISHED, '', session)

        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def sendXmrBidLockRelease(self, bid_id, session):
        # Leader sending lock tx a release secret (MSG5F)
        self.log.debug('Sending bid secret for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)

        msg_buf = XmrBidLockReleaseMessage(
            bid_msg_id=bid_id,
            al_lock_spend_tx_esig=xmr_swap.al_lock_spend_tx_esig)

        msg_bytes = msg_buf.SerializeToString()
        payload_hex = str.format('{:02x}', MessageTypes.XMR_BID_LOCK_RELEASE_LF) + msg_bytes.hex()

        options = {'decodehex': True, 'ttl_is_seconds': True}
        # TODO: set msg_valid based on bid / offer parameters
        msg_valid = self.SMSG_SECONDS_IN_HOUR * 48
        ro = self.callrpc('smsgsend', [offer.addr_from, bid.bid_addr, payload_hex, False, msg_valid, False, options])
        xmr_swap.coin_a_lock_refund_spend_tx_msg_id = bytes.fromhex(ro['msgid'])

        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def redeemXmrBidCoinALockTx(self, bid_id, session):
        # Follower redeeming A lock tx
        self.log.debug('Redeeming coin A lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        for_ed25519 = True if coin_to == Coins.XMR else False
        kbsf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 2, for_ed25519)
        kaf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 3)

        al_lock_spend_sig = ci_from.decryptOtVES(kbsf, xmr_swap.al_lock_spend_tx_esig)
        v = ci_from.verifyTxSig(xmr_swap.a_lock_spend_tx, al_lock_spend_sig, xmr_swap.pkal, 0, xmr_swap.a_lock_tx_script, bid.amount)
        assert(v)

        af_lock_spend_sig = ci_from.signTx(kaf, xmr_swap.a_lock_spend_tx, 0, xmr_swap.a_lock_tx_script, bid.amount)
        v = ci_from.verifyTxSig(xmr_swap.a_lock_spend_tx, af_lock_spend_sig, xmr_swap.pkaf, 0, xmr_swap.a_lock_tx_script, bid.amount)
        assert(v)

        witness_stack = [
            b'',
            al_lock_spend_sig,
            af_lock_spend_sig,
            xmr_swap.a_lock_tx_script,
        ]

        xmr_swap.a_lock_spend_tx = ci_from.setTxSignature(xmr_swap.a_lock_spend_tx, witness_stack)

        txid = bytes.fromhex(ci_from.publishTx(xmr_swap.a_lock_spend_tx))
        self.log.debug('Submitted lock spend txn %s to %s chain for bid %s', txid.hex(), ci_from.coin_name(), bid_id.hex())
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
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        # Extract the leader's decrypted signature and use it to recover the follower's privatekey
        xmr_swap.al_lock_spend_tx_sig = ci_from.extractLeaderSig(xmr_swap.a_lock_spend_tx)

        kbsf = ci_from.recoverEncKey(xmr_swap.al_lock_spend_tx_esig, xmr_swap.al_lock_spend_tx_sig, xmr_swap.pkasf)
        assert(kbsf is not None)

        for_ed25519 = True if coin_to == Coins.XMR else False
        kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 2, for_ed25519)
        vkbs = ci_to.sumKeys(kbsl, kbsf)

        address_to = ci_to.getMainWalletAddress()

        try:
            txid = ci_to.spendBLockTx(address_to, xmr_swap.vkbv, vkbs, bid.amount_to, xmr_offer.b_fee_rate, xmr_swap.b_restore_height)
            self.log.debug('Submitted lock B spend txn %s to %s chain for bid %s', txid.hex(), ci_to.coin_name(), bid_id.hex())
        except Exception as ex:
            # TODO: Make min-conf 10?
            error_msg = 'spendBLockTx failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_SPEND, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            str_error = str(ex)
            if num_retries < 100 and 'Invalid unlocked_balance' in str_error:
                delay = random.randrange(self.min_delay_retry, self.max_delay_retry)
                self.log.info('Retrying sending xmr swap chain B spend tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createEventInSession(delay, EventTypes.REDEEM_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'spendBLockTx failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid, EventLogTypes.FAILED_TX_B_SPEND, str_error, session)
            return

        bid.xmr_b_lock_tx.spend_txid = txid
        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
        # TODO: Why does using bid.txns error here?
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def recoverXmrBidCoinBLockTx(self, bid_id, session):
        # Follower recovering B lock tx
        self.log.debug('Recovering coin B lock tx for xmr bid %s', bid_id.hex())

        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        # Extract the follower's decrypted signature and use it to recover the leader's privatekey
        af_lock_refund_spend_tx_sig = ci_from.extractFollowerSig(xmr_swap.a_lock_refund_spend_tx)

        kbsl = ci_from.recoverEncKey(xmr_swap.af_lock_refund_spend_tx_esig, af_lock_refund_spend_tx_sig, xmr_swap.pkasl)
        assert(kbsl is not None)

        for_ed25519 = True if coin_to == Coins.XMR else False
        kbsf = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 2, for_ed25519)
        vkbs = ci_to.sumKeys(kbsl, kbsf)

        address_to = ci_to.getMainWalletAddress()

        try:
            txid = ci_to.spendBLockTx(address_to, xmr_swap.vkbv, vkbs, bid.amount_to, xmr_offer.b_fee_rate, xmr_swap.b_restore_height)
            self.log.debug('Submitted lock B refund txn %s to %s chain for bid %s', txid.hex(), ci_to.coin_name(), bid_id.hex())
            self.logBidEvent(bid, EventLogTypes.LOCK_TX_B_REFUND_TX_PUBLISHED, '', session)
        except Exception as ex:
            # TODO: Make min-conf 10?
            error_msg = 'spendBLockTx refund failed for bid {} with error {}'.format(bid_id.hex(), str(ex))
            num_retries = self.countBidEvents(bid, EventLogTypes.FAILED_TX_B_REFUND, session)
            if num_retries > 0:
                error_msg += ', retry no. {}'.format(num_retries)
            self.log.error(error_msg)

            str_error = str(ex)
            if num_retries < 100 and 'Invalid unlocked_balance' in str_error:
                delay = random.randrange(self.min_delay_retry, self.max_delay_retry)
                self.log.info('Retrying sending xmr swap chain B refund tx for bid %s in %d seconds', bid_id.hex(), delay)
                self.createEventInSession(delay, EventTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, session)
            else:
                self.setBidError(bid_id, bid, 'spendBLockTx for refund failed: ' + str(ex), save_bid=False)
                self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

            self.logBidEvent(bid, EventLogTypes.FAILED_TX_B_REFUND, str_error, session)
            return

        bid.xmr_b_lock_tx.spend_txid = txid

        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED)
        self.saveBidInSession(bid_id, bid, session, xmr_swap, save_in_progress=offer)

    def processXmrBidCoinALockSigs(self, msg):
        # Leader processing MSG3L
        self.log.debug('Processing xmr coin a follower lock sigs msg %s', msg['msgid'])
        now = int(time.time())
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockTxSigsMessage()
        msg_data.ParseFromString(msg_bytes)

        assert(len(msg_data.bid_msg_id) == 28), 'Bad bid_msg_id length'
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        try:
            xmr_swap.af_lock_refund_spend_tx_esig = msg_data.af_lock_refund_spend_tx_esig
            xmr_swap.af_lock_refund_tx_sig = msg_data.af_lock_refund_tx_sig

            for_ed25519 = True if coin_to == Coins.XMR else False
            kbsl = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 2, for_ed25519)
            kal = self.getPathKey(coin_from, coin_to, bid.created_at, xmr_swap.contract_count, 3)

            xmr_swap.af_lock_refund_spend_tx_sig = ci_from.decryptOtVES(kbsl, xmr_swap.af_lock_refund_spend_tx_esig)
            al_lock_refund_spend_tx_sig = ci_from.signTx(kal, xmr_swap.a_lock_refund_spend_tx, 0, xmr_swap.a_lock_refund_tx_script, xmr_swap.a_swap_refund_value)

            self.log.debug('Setting lock refund spend tx sigs')
            witness_stack = [
                b'',
                al_lock_refund_spend_tx_sig,
                xmr_swap.af_lock_refund_spend_tx_sig,
                bytes((1,)),
                xmr_swap.a_lock_refund_tx_script,
            ]
            signed_tx = ci_from.setTxSignature(xmr_swap.a_lock_refund_spend_tx, witness_stack)
            assert(signed_tx), 'setTxSignature failed'
            xmr_swap.a_lock_refund_spend_tx = signed_tx

            v = ci_from.verifyTxSig(xmr_swap.a_lock_refund_spend_tx, xmr_swap.af_lock_refund_spend_tx_sig, xmr_swap.pkaf, 0, xmr_swap.a_lock_refund_tx_script, xmr_swap.a_swap_refund_value)
            assert(v), 'Invalid signature for lock refund spend txn'
            self.addLockRefundSigs(xmr_swap, ci_from)

            delay = random.randrange(self.min_delay_event, self.max_delay_event)
            self.log.info('Sending coin A lock tx for xmr bid %s in %d seconds', bid_id.hex(), delay)
            self.createEvent(delay, EventTypes.SEND_XMR_SWAP_LOCK_TX_A, bid_id)

            bid.setState(BidStates.SWAP_DELAYING)
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                traceback.print_exc()
            self.setBidError(bid_id, bid, str(ex))

    def processXmrBidLockSpendTx(self, msg):
        # Follower receiving MSG4F
        self.log.debug('Processing xmr bid lock spend tx msg %s', msg['msgid'])
        now = int(time.time())
        msg_bytes = bytes.fromhex(msg['hex'][2:-2])
        msg_data = XmrBidLockSpendTxMessage()
        msg_data.ParseFromString(msg_bytes)

        assert(len(msg_data.bid_msg_id) == 28), 'Bad bid_msg_id length'
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        ci_from = self.ci(Coins(offer.coin_from))
        ci_to = self.ci(Coins(offer.coin_to))

        try:
            xmr_swap.a_lock_spend_tx = msg_data.a_lock_spend_tx
            xmr_swap.a_lock_spend_tx_id = ci_from.getTxHash(xmr_swap.a_lock_spend_tx)
            xmr_swap.kal_sig = msg_data.kal_sig

            ci_from.verifyLockSpendTx(
                xmr_swap.a_lock_spend_tx,
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
                xmr_swap.dest_af, xmr_offer.a_fee_rate)

            ci_from.verifyCompact(xmr_swap.pkal, 'proof key owned for swap', xmr_swap.kal_sig)

            bid.setState(BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX)
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                traceback.print_exc()
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
        assert(len(msg_data.msg_id) == 28), 'Bad msg_id length'

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
        assert(len(msg_data.bid_msg_id) == 28), 'Bad msg_id length'

        bid_id = msg_data.bid_msg_id
        bid, xmr_swap = self.getXmrBid(bid_id)
        assert(bid), 'Bid not found: {}.'.format(bid_id.hex())
        assert(xmr_swap), 'XMR swap not found: {}.'.format(bid_id.hex())

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, sent=False)
        assert(offer), 'Offer not found: {}.'.format(bid.offer_id.hex())
        assert(xmr_offer), 'XMR offer not found: {}.'.format(bid.offer_id.hex())
        ci_from = self.ci(Coins(offer.coin_from))

        xmr_swap.al_lock_spend_tx_esig = msg_data.al_lock_spend_tx_esig

        try:
            v = ci_from.verifyTxOtVES(
                xmr_swap.a_lock_spend_tx, xmr_swap.al_lock_spend_tx_esig,
                xmr_swap.pkal, xmr_swap.pkasf, 0, xmr_swap.a_lock_tx_script, bid.amount)
            assert(v), 'verifyTxOtVES failed'
        except Exception as ex:
            if self.debug:
                traceback.print_exc()
            self.setBidError(bid_id, bid, str(ex))
            self.swaps_in_progress[bid_id] = (bid, offer)
            return

        delay = random.randrange(self.min_delay_event, self.max_delay_event)
        self.log.info('Redeeming coin A lock tx for xmr bid %s in %d seconds', bid_id.hex(), delay)
        self.createEvent(delay, EventTypes.REDEEM_XMR_SWAP_LOCK_TX_A, bid_id)

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

        except Exception as ex:
            self.log.error('processMsg %s', str(ex))
            if self.debug:
                traceback.print_exc()
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
            self.log.error('smsg zmq %s', str(ex))
            if self.debug:
                traceback.print_exc()

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
                        self.log.error('checkBidState %s %s', bid_id.hex(), str(ex))
                        if self.debug:
                            traceback.print_exc()
                        self.setBidError(bid_id, v[0], str(ex))

                for bid_id, bid, offer in to_remove:
                    self.deactivateBid(None, offer, bid)
                self._last_checked_progress = now

            if now - self._last_checked_watched >= self.check_watched_seconds:
                for k, c in self.coin_clients.items():
                    if k == Coins.PART_ANON:
                        continue
                    if len(c['watched_outputs']) > 0:
                        self.checkForSpends(k, c)
                self._last_checked_watched = now

            if now - self._last_checked_expired >= self.check_expired_seconds:
                self.expireMessages()
                self._last_checked_expired = now

            if now - self._last_checked_events >= self.check_events_seconds:
                self.checkEvents()
                self._last_checked_events = now

            if now - self._last_checked_xmr_swaps >= self.check_xmr_swaps_seconds:
                self.checkXmrSwaps()
                self._last_checked_xmr_swaps = now

        except Exception as ex:
            self.log.error('update %s', str(ex))
            if self.debug:
                traceback.print_exc()
        finally:
            self.mxDB.release()

    def manualBidUpdate(self, bid_id, data):
        self.log.info('Manually updating bid %s', bid_id.hex())
        self.mxDB.acquire()
        try:
            bid, offer = self.getBidAndOffer(bid_id)
            assert(bid), 'Bid not found {}'.format(bid_id.hex())
            assert(offer), 'Offer not found {}'.format(bid.offer_id.hex())

            has_changed = False
            if bid.state != data['bid_state']:
                bid.setState(data['bid_state'])
                self.log.debug('Set state to %s', strBidState(bid.state))
                has_changed = True

            if has_changed:
                session = scoped_session(self.session_factory)
                try:
                    activate_bid = False
                    if offer.swap_type == SwapTypes.SELLER_FIRST:
                        if bid.state and bid.state > BidStates.BID_RECEIVED and bid.state < BidStates.SWAP_COMPLETED:
                            activate_bid = True
                    else:
                        self.log.debug('TODO - determine in-progress for manualBidUpdate')
                        if offer.swap_type == SwapTypes.XMR_SWAP:
                            if bid.state and bid.state in (BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX, BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED, BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED, BidStates.XMR_SWAP_LOCK_RELEASED, BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED):
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
            if 'lookups' in data:
                if settings_cc.get('chain_lookups', 'local') != data['lookups']:
                    settings_changed = True
                    settings_cc['chain_lookups'] = data['lookups']
                    for coin, cc in self.coin_clients.items():
                        if cc['name'] == coin_name:
                            cc['chain_lookups'] = data['lookups']
                            break

            if 'fee_priority' in data:
                new_fee_priority = data['fee_priority']
                assert(new_fee_priority >= 0 and new_fee_priority < 4), 'Invalid priority'

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
                assert(new_conf_target >= 1 and new_conf_target < 33), 'Invalid conf_target'

                if settings_cc.get('conf_target', 2) != new_conf_target:
                    settings_changed = True
                    settings_cc['conf_target'] = new_conf_target
                    for coin, cc in self.coin_clients.items():
                        if cc['name'] == coin_name:
                            cc['conf_target'] = new_conf_target
                            self.ci(coin).setConfTarget(new_conf_target)
                            break

            if settings_changed:
                settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
                shutil.copyfile(settings_path, settings_path + '.last')
                with open(settings_path, 'w') as fp:
                    json.dump(self.settings, fp, indent=4)
        return settings_changed

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
            num_watched_outputs += len(v['watched_outputs'])

        bids_sent = 0
        bids_received = 0
        q = self.engine.execute('SELECT was_sent, was_received, COUNT(*) FROM bids GROUP BY was_sent, was_received ')
        for r in q:
            if r[0]:
                bids_sent += r[2]
            if r[1]:
                bids_received += r[2]

        now = int(time.time())
        q = self.engine.execute('SELECT COUNT(*) FROM offers WHERE active_ind = 1 AND expire_at > {}'.format(now)).first()
        num_offers = q[0]

        q = self.engine.execute('SELECT COUNT(*) FROM offers WHERE was_sent = 1').first()
        num_sent_offers = q[0]

        rv = {
            'network': self.chain,
            'num_swapping': len(self.swaps_in_progress),
            'num_network_offers': num_offers,
            'num_sent_offers': num_sent_offers,
            'num_recv_bids': bids_received,
            'num_sent_bids': bids_sent,
            'num_watched_outputs': num_watched_outputs,
        }
        return rv

    def getWalletInfo(self, coin):

        ci = self.ci(coin)
        blockchaininfo = ci.getBlockchainInfo()
        walletinfo = ci.getWalletInfo()

        scale = chainparams[coin]['decimal_places']
        rv = {
            'version': self.coin_clients[coin]['core_version'],
            'deposit_address': self.getCachedAddressForCoin(coin),
            'name': ci.coin_name(),
            'blocks': blockchaininfo['blocks'],
            'balance': format_amount(make_int(walletinfo['balance'], scale), scale),
            'unconfirmed': format_amount(make_int(walletinfo.get('unconfirmed_balance'), scale), scale),
            'synced': '{0:.2f}'.format(round(blockchaininfo['verificationprogress'], 2)),
            'expected_seed': ci.knownWalletSeed(),
        }

        if coin == Coins.PART:
            rv['stealth_address'] = self.getCachedStealthAddressForCoin(Coins.PART)
            rv['anon_balance'] = walletinfo['anon_balance']
            rv['anon_pending'] = walletinfo['unconfirmed_anon'] + walletinfo['immature_anon_balance']
            rv['blind_balance'] = walletinfo['blind_balance']
            rv['blind_unconfirmed'] = walletinfo['unconfirmed_blind']

        return rv

    def getWalletsInfo(self, opts=None):
        rv = {}
        for c in Coins:
            if c not in chainparams:
                continue
            if self.coin_clients[c]['connection_type'] == 'rpc':
                try:
                    rv[c] = self.getWalletInfo(c)
                except Exception as ex:
                    rv[c] = {'name': chainparams[c]['name'].capitalize(), 'error': str(ex)}
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

    def listOffers(self, sent=False, filters={}):
        self.mxDB.acquire()
        try:
            rv = []
            now = int(time.time())
            session = scoped_session(self.session_factory)

            if sent:
                q = session.query(Offer).filter(Offer.was_sent == True)  # noqa: E712
            else:
                q = session.query(Offer).filter(sa.and_(Offer.expire_at > now, Offer.active_ind == 1))

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
                # Show offers for enabled coins only
                try:
                    ci_from = self.ci(row.coin_from)
                    ci_to = self.ci(row.coin_to)
                except Exception as e:
                    continue
                rv.append(row)
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listBids(self, sent=False, offer_id=None, for_html=False, filters={}):
        self.mxDB.acquire()
        try:
            rv = []
            now = int(time.time())
            session = scoped_session(self.session_factory)

            query_str = 'SELECT bids.created_at, bids.expire_at, bids.bid_id, bids.offer_id, bids.amount, bids.state, bids.was_received, tx1.state, tx2.state, offers.coin_from FROM bids ' + \
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
            query_str += ' ORDER BY bids.created_at DESC'

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
                if self.coin_clients[c]['connection_type'] == 'rpc':
                    rv_heights.append((c, v['last_height_checked']))
                for o in v['watched_outputs']:
                    rv.append((c, o.bid_id, o.txid_hex, o.vout, o.tx_type))
            return (rv, rv_heights)
        finally:
            self.mxDB.release()

    def listSmsgAddresses(self, use_type_str):
        use_type = MessageTypes.OFFER if use_type_str == 'offer' else MessageTypes.BID
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            rv = []
            q = session.execute('SELECT addr FROM smsgaddresses WHERE use_type = {} ORDER BY addr_id DESC'.format(use_type))
            for row in q:
                rv.append(row[0])
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def addLockRefundSigs(self, xmr_swap, ci):
        self.log.debug('Setting lock refund tx sigs')
        witness_stack = [
            b'',
            xmr_swap.al_lock_refund_tx_sig,
            xmr_swap.af_lock_refund_tx_sig,
            xmr_swap.a_lock_tx_script,
        ]

        signed_tx = ci.setTxSignature(xmr_swap.a_lock_refund_tx, witness_stack)
        assert(signed_tx), 'setTxSignature failed'
        xmr_swap.a_lock_refund_tx = signed_tx

    def createCoinALockRefundSwipeTx(self, ci, bid, offer, xmr_swap, xmr_offer):
        self.log.debug('Creating %s lock refund swipe tx', ci.coin_name())

        pkh_dest = ci.decodeAddress(self.getReceiveAddressForCoin(ci.coin_type()))
        spend_tx = ci.createScriptLockRefundSpendToFTx(
            xmr_swap.a_lock_refund_tx, xmr_swap.a_lock_refund_tx_script,
            pkh_dest,
            xmr_offer.a_fee_rate
        )

        vkaf = self.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, 3)
        sig = ci.signTx(vkaf, spend_tx, 0, xmr_swap.a_lock_refund_tx_script, xmr_swap.a_swap_refund_value)

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

    def add_connection(self, host, port, peer_pubkey):
        self.log.info('add_connection %s %d %s', host, port, peer_pubkey.hex())
        self._network.add_connection(host, port, peer_pubkey)

    def get_network_info(self):
        if not self._network:
            return {'Error': 'Not Initialised'}
        return self._network.get_info()
