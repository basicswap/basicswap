# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import os
import re
import time
import datetime as dt
import zmq
import threading
import traceback
import struct
import hashlib
import subprocess
import logging
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from enum import IntEnum, auto
from . import __version__
from .util import (
    COIN,
    callrpc,
    pubkeyToAddress,
    format8,
    encodeAddress,
    decodeAddress,
    SerialiseNum,
    DeserialiseNum,
    decodeWif,
    toWIF,
    getKeyID,
)

from .chainparams import (
    chainparams,
    Coins,
)

from .messages_pb2 import (
    OfferMessage,
    BidMessage,
    BidAcceptMessage,
)

import basicswap.config as cfg
import basicswap.segwit_addr as segwit_addr


DEBUG = True
SMSG_SECONDS_IN_DAY = 86400

CURRENT_DB_VERSION = 1


MIN_OFFER_VALID_TIME = 60 * 10
MAX_OFFER_VALID_TIME = 60 * 60 * 48
MIN_BID_VALID_TIME = 60 * 10
MAX_BID_VALID_TIME = 60 * 60 * 48


class MessageTypes(IntEnum):
    OFFER = auto()
    BID = auto()
    BID_ACCEPT = auto()


class SwapTypes(IntEnum):
    SELLER_FIRST = auto()
    BUYER_FIRST = auto()


class OfferStates(IntEnum):
    OFFER_SENT = auto()
    OFFER_RECEIVED = auto()
    OFFER_ABANDONED = auto()


class BidStates(IntEnum):
    BID_SENT = auto()
    BID_RECEIVED = auto()
    BID_ACCEPTED = auto()           # BidAcceptMessage received/sent
    SWAP_INITIATED = auto()         # Initiate txn validated
    SWAP_PARTICIPATING = auto()     # Participate txn validated
    SWAP_COMPLETED = auto()         # All swap txns spent
    SWAP_TIMEDOUT = auto()
    BID_ABANDONED = auto()          # Bid will no longer be processed


class TxStates(IntEnum):
    TX_NONE = auto()
    TX_SENT = auto()
    TX_CONFIRMED = auto()
    TX_REDEEMED = auto()
    TX_REFUNDED = auto()


class OpCodes(IntEnum):
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_1 = 0x51,
    OP_IF = 0x63,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_SIZE = 0x82,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_CHECKSIG = 0xac,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,


SEQUENCE_LOCK_BLOCKS = 1
SEQUENCE_LOCK_TIME = 2
SEQUENCE_LOCKTIME_GRANULARITY = 9  # 512 seconds
SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)
SEQUENCE_LOCKTIME_MASK = 0x0000ffff
INITIATE_TX_TIMEOUT = 20 * 60


def getOfferState(state):
    if state == OfferStates.OFFER_SENT:
        return 'Sent'
    if state == OfferStates.OFFER_RECEIVED:
        return 'Received'
    if state == OfferStates.OFFER_ABANDONED:
        return 'Abandoned'
    return 'Unknown'


def getBidState(state):
    if state == BidStates.BID_SENT:
        return 'Sent'
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
    return 'Unknown'


def getTxState(state):
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


def getLockName(lock_type):
    if lock_type == SEQUENCE_LOCK_BLOCKS:
        return 'Sequence lock, blocks'
    if lock_type == SEQUENCE_LOCK_TIME:
        return 'Sequence lock, time'


def getExpectedSequence(lockType, lockVal, coin_type):
    assert(lockVal >= 1), 'Bad lockVal'
    if lockType == SEQUENCE_LOCK_BLOCKS:
        return lockVal
    if lockType == SEQUENCE_LOCK_TIME:
        secondsLocked = lockVal
        # Ensure the locked time is never less than lockVal
        if secondsLocked % (1 << SEQUENCE_LOCKTIME_GRANULARITY) != 0:
            secondsLocked += (1 << SEQUENCE_LOCKTIME_GRANULARITY)
        secondsLocked >>= SEQUENCE_LOCKTIME_GRANULARITY
        return secondsLocked | SEQUENCE_LOCKTIME_TYPE_FLAG
    raise ValueError('Unknown lock type')


def decodeSequence(lock_value):
    # Return the raw value
    if lock_value & SEQUENCE_LOCKTIME_TYPE_FLAG:
        return (lock_value & SEQUENCE_LOCKTIME_MASK) << SEQUENCE_LOCKTIME_GRANULARITY
    return lock_value & SEQUENCE_LOCKTIME_MASK


def buildContractScriptCSV(sequence, secret_hash, pkh_redeem, pkh_refund):
    script = bytearray([
        OpCodes.OP_IF,
        OpCodes.OP_SIZE,
        0x01, 0x20,  # 32
        OpCodes.OP_EQUALVERIFY,
        OpCodes.OP_SHA256,
        0x20]) \
        + secret_hash \
        + bytearray([
            OpCodes.OP_EQUALVERIFY,
            OpCodes.OP_DUP,
            OpCodes.OP_HASH160,
            0x14]) \
        + pkh_redeem \
        + bytearray([OpCodes.OP_ELSE, ]) \
        + SerialiseNum(sequence) \
        + bytearray([
            OpCodes.OP_CHECKSEQUENCEVERIFY,
            OpCodes.OP_DROP,
            OpCodes.OP_DUP,
            OpCodes.OP_HASH160,
            0x14]) \
        + pkh_refund \
        + bytearray([
            OpCodes.OP_ENDIF,
            OpCodes.OP_EQUALVERIFY,
            OpCodes.OP_CHECKSIG])
    return script


def extractScriptSecretHash(script):
    return script[7:39]


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


def getP2SHScriptForHash(p2sh):
    return bytearray([OpCodes.OP_HASH160, 0x14]) \
        + p2sh \
        + bytearray([OpCodes.OP_EQUAL])


def getP2WSH(script):
    return bytearray([OpCodes.OP_0, 0x20]) + hashlib.sha256(script).digest()


def replaceAddrPrefix(addr, coin_type, chain_name, addr_type='pubkey_address'):
    return encodeAddress(bytes((chainparams[coin_type][chain_name][addr_type],)) + decodeAddress(addr)[1:])


Base = declarative_base()


class DBKVInt(Base):
    __tablename__ = 'kv_int'
    key = sa.Column(sa.String, primary_key=True)
    value = sa.Column(sa.Integer)


class DBKVString(Base):
    __tablename__ = 'kv_string'
    key = sa.Column(sa.String, primary_key=True)
    value = sa.Column(sa.String)


class Offer(Base):
    __tablename__ = 'offers'

    offer_id = sa.Column(sa.LargeBinary, primary_key=True)

    coin_from = sa.Column(sa.Integer)
    coin_to = sa.Column(sa.Integer)
    amount_from = sa.Column(sa.BigInteger)
    rate = sa.Column(sa.BigInteger)
    min_bid_amount = sa.Column(sa.BigInteger)
    time_valid = sa.Column(sa.BigInteger)
    lock_type = sa.Column(sa.Integer)
    lock_value = sa.Column(sa.Integer)
    swap_type = sa.Column(sa.Integer)

    proof_address = sa.Column(sa.String)
    proof_signature = sa.Column(sa.LargeBinary)
    pkhash_seller = sa.Column(sa.LargeBinary)
    secret_hash = sa.Column(sa.LargeBinary)

    addr_from = sa.Column(sa.String)
    created_at = sa.Column(sa.BigInteger)
    expire_at = sa.Column(sa.BigInteger)
    was_sent = sa.Column(sa.Boolean)

    auto_accept_bids = sa.Column(sa.Boolean)

    state = sa.Column(sa.Integer)
    states = sa.Column(sa.LargeBinary)  # Packed states and times

    def setState(self, new_state):
        now = int(time.time())
        self.state = new_state
        if self.states is None:
            self.states = struct.pack('<iq', new_state, now)
        else:
            self.states += struct.pack('<iq', new_state, now)


class Bid(Base):
    __tablename__ = 'bids'

    bid_id = sa.Column(sa.LargeBinary, primary_key=True)
    offer_id = sa.Column(sa.LargeBinary, sa.ForeignKey('offers.offer_id'))

    was_sent = sa.Column(sa.Boolean)
    was_received = sa.Column(sa.Boolean)
    contract_count = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)
    expire_at = sa.Column(sa.BigInteger)
    bid_addr = sa.Column(sa.String)
    proof_address = sa.Column(sa.String)

    recovered_secret = sa.Column(sa.LargeBinary)
    amount_to = sa.Column(sa.BigInteger)  # amount * offer.rate

    pkhash_buyer = sa.Column(sa.LargeBinary)
    amount = sa.Column(sa.BigInteger)

    accept_msg_id = sa.Column(sa.LargeBinary)
    pkhash_seller = sa.Column(sa.LargeBinary)

    initiate_script = sa.Column(sa.LargeBinary)  # contract_script
    initiate_txid = sa.Column(sa.LargeBinary)
    initiate_txn_n = sa.Column(sa.Integer)
    initiate_txn_conf = sa.Column(sa.Integer)
    initiate_txn_refund = sa.Column(sa.LargeBinary)

    initiate_spend_txid = sa.Column(sa.LargeBinary)
    initiate_spend_n = sa.Column(sa.Integer)

    initiate_txn_height = sa.Column(sa.Integer)
    initiate_txn_state = sa.Column(sa.Integer)
    initiate_txn_states = sa.Column(sa.LargeBinary)  # Packed states and times

    participate_script = sa.Column(sa.LargeBinary)
    participate_txid = sa.Column(sa.LargeBinary)
    participate_txn_n = sa.Column(sa.Integer)
    participate_txn_conf = sa.Column(sa.Integer)
    participate_txn_redeem = sa.Column(sa.LargeBinary)
    participate_txn_refund = sa.Column(sa.LargeBinary)

    participate_spend_txid = sa.Column(sa.LargeBinary)
    participate_spend_n = sa.Column(sa.Integer)

    participate_txn_height = sa.Column(sa.Integer)
    participate_txn_state = sa.Column(sa.Integer)
    participate_txn_states = sa.Column(sa.LargeBinary)  # Packed states and times

    state = sa.Column(sa.Integer)
    state_time = sa.Column(sa.BigInteger)  # timestamp of last state change
    states = sa.Column(sa.LargeBinary)  # Packed states and times

    state_note = sa.Column(sa.String)

    def setITXState(self, new_state):
        self.initiate_txn_state = new_state
        if self.initiate_txn_states is None:
            self.initiate_txn_states = struct.pack('<iq', new_state, int(time.time()))
        else:
            self.initiate_txn_states += struct.pack('<iq', new_state, int(time.time()))

    def setPTXState(self, new_state):
        self.participate_txn_state = new_state
        if self.participate_txn_states is None:
            self.participate_txn_states = struct.pack('<iq', new_state, int(time.time()))
        else:
            self.participate_txn_states += struct.pack('<iq', new_state, int(time.time()))

    def setState(self, new_state):
        now = int(time.time())
        self.state = new_state
        self.state_time = now
        if self.states is None:
            self.states = struct.pack('<iq', new_state, now)
        else:
            self.states += struct.pack('<iq', new_state, now)


class PooledAddress(Base):
    __tablename__ = 'addresspool'

    addr_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    coin_type = sa.Column(sa.Integer)
    addr = sa.Column(sa.String)


"""
class SwapTx(Base):
    def __init__(self):
        self.txid = None
        self.states = []
        self.script = None
        self.redeem_tx = None
        self.refund_tx = None
        self.p2sh = None
"""


class SentOffer(Base):
    __tablename__ = 'sentoffers'

    offer_id = sa.Column(sa.LargeBinary, primary_key=True)


class BasicSwap():
    def __init__(self, fp, data_dir, settings, chain, log_name='BasicSwap'):
        self.log_name = log_name
        self.fp = fp
        self.is_running = True
        self.fail_code = 0

        self.data_dir = data_dir
        self.chain = chain
        self.settings = settings

        # Encode key to match network
        wif_prefix = chainparams[Coins.PART][self.chain]['key_prefix']
        self.network_key = toWIF(wif_prefix, decodeWif(self.settings['network_key']))

        self.network_pubkey = self.settings['network_pubkey']
        self.network_addr = pubkeyToAddress(chainparams[Coins.PART][self.chain]['pubkey_address'], bytearray.fromhex(self.network_pubkey))
        self.wallet = self.settings.get('wallet', None)  # TODO: Move to coin_clients
        self.last_expired = 0

        self.debug = self.settings.get('debug', DEBUG)
        self.coin_clients = {}

        self.prepareLogging()

        self.sqlite_file = os.path.join(self.data_dir, 'db.sqlite')
        db_exists = os.path.exists(self.sqlite_file)
        self.engine = sa.create_engine('sqlite:///' + self.sqlite_file)
        if not db_exists:
            Base.metadata.create_all(self.engine)
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
        session.close()
        session.remove()

        self.zmqContext = zmq.Context()
        self.zmqSubscriber = self.zmqContext.socket(zmq.SUB)

        self.zmqSubscriber.connect(self.settings['zmqhost'] + ':' + str(self.settings['zmqport']))
        self.zmqSubscriber.setsockopt_string(zmq.SUBSCRIBE, 'smsg')

        # Defaults
        self.coin_clients = {}
        self.coin_clients[Coins.PART] = self.setDefaultConnectParams(Coins.PART)
        self.coin_clients[Coins.BTC] = self.setDefaultConnectParams(Coins.BTC)
        self.coin_clients[Coins.LTC] = self.setDefaultConnectParams(Coins.LTC)

        if self.chain == 'regtest':
            SMSG_SECONDS_IN_DAY = 600

        self.swaps_in_progress = dict()

        self.check_progress_seconds = self.settings.get('check_progress_seconds', 60)
        self.check_watched_seconds = self.settings.get('check_watched_seconds', 60)
        self.check_expired_seconds = self.settings.get('check_expired_seconds', 60 * 5)

        self.last_checked_progress = 0
        self.last_checked_watched = 0
        self.last_checked_expired = 0

        self.mxDB = threading.RLock()

        self.bidcount = 0

    def prepareLogging(self):
        self.log = logging.getLogger(self.log_name)
        self.log.propagate = False

        formatter = logging.Formatter('%(asctime)s %(levelname)s : %(message)s')
        stream_stdout = logging.StreamHandler()
        if self.log_name != 'BasicSwap':
            stream_stdout.setFormatter(logging.Formatter('%(asctime)s %(name)s %(levelname)s : %(message)s'))
        else:
            stream_stdout.setFormatter(formatter)
        stream_fp = logging.StreamHandler(self.fp)
        stream_fp.setFormatter(formatter)

        self.log.setLevel(logging.DEBUG if self.debug else logging.INFO)
        self.log.addHandler(stream_fp)
        self.log.addHandler(stream_stdout)

    def getChainClientSettings(self, coin):
        try:
            return self.settings['chainclients'][chainparams[coin]['name']]
        except Exception:
            return {}

    def setDefaultConnectParams(self, coin):
        chain_client_settings = self.getChainClientSettings(coin)

        bindir = os.path.expanduser(chain_client_settings.get('bindir', ''))
        datadir = os.path.expanduser(chain_client_settings.get('datadir', os.path.join(cfg.DATADIRS, chainparams[coin]['name'])))

        blocks_confirmed = chain_client_settings.get('blocks_confirmed', 6)
        connection_type = chain_client_settings.get('connection_type', 'none')
        use_segwit = chain_client_settings.get('use_segwit', False)

        rpcauth = None
        if connection_type == 'rpc':
            if 'rpcauth' in chain_client_settings:
                rpcauth = chain_client_settings['rpcauth']
            elif 'rpcpassword' in chain_client_settings:
                rpcauth = chain_client_settings['rpcuser'] + ':' + chain_client_settings['rpcpassword']
            if rpcauth is None:
                testnet_name = '' if self.chain == 'mainnet' else self.chain
                if testnet_name == 'testnet' and coin != Coins.PART:
                    testnet_name += '4'
                authcookiepath = os.path.join(datadir, testnet_name, '.cookie')
                # Wait for daemon to start
                for i in range(10):
                    if not os.path.exists(authcookiepath):
                        time.sleep(0.5)
                try:
                    with open(authcookiepath) as fp:
                        rpcauth = fp.read()
                except Exception:
                    self.log.warning('Unable to read authcookie for %s, %s', str(coin), authcookiepath)

        session = scoped_session(self.session_factory)
        try:
            last_height_checked = session.query(DBKVInt).filter_by(key='last_height_checked_' + chainparams[coin]['name']).first().value
        except Exception:
            last_height_checked = 0
        session.close()
        session.remove()

        return {
            'coin': coin,
            'connection_type': connection_type,
            'bindir': bindir,
            'datadir': datadir,
            'rpcport': chain_client_settings.get('rpcport', chainparams[coin][self.chain]['rpcport']),
            'rpcauth': rpcauth,
            'blocks_confirmed': blocks_confirmed,
            'watched_outputs': [],
            'last_height_checked': last_height_checked,
            'use_segwit': use_segwit,
        }

    def start(self):
        self.log.info('Starting BasicSwap %s\n\n', __version__)

        self.upgradeDatabase(self.db_version)
        self.waitForDaemonRPC()
        core_version = self.callcoinrpc(Coins.PART, 'getnetworkinfo')['version']
        self.log.info('Particl Core version %d', core_version)

        self.log.info('sqlalchemy version %s', sa.__version__)

        self.initialise()

    def stopRunning(self, with_code=0):
        self.fail_code = with_code
        self.is_running = False

    def upgradeDatabase(self, db_version):
        if db_version >= CURRENT_DB_VERSION:
            return

        self.log.info('Upgrading Database from version %d to %d.', db_version, CURRENT_DB_VERSION)

    def waitForDaemonRPC(self):
        for i in range(21):
            if not self.is_running:
                return
            try:
                self.callrpc('getwalletinfo', [], self.wallet)
                return
            except Exception as ex:
                logging.warning('Can\'t connect to daemon RPC: %s.  Trying again in %d second/s.', str(ex), (1 + i))
                time.sleep(1 + i)
        self.log.error('Can\'t connect to daemon RPC, exiting.')
        self.stopRunning(1)  # systemd will try restart if fail_code != 0

    def setIntKV(self, str_key, int_val):
        session = scoped_session(self.session_factory)
        kv = session.query(DBKVInt).filter_by(key=str_key).first()
        if not kv:
            kv = DBKVInt(key=str_key, value=int_val)
        session.add(kv)
        session.commit()
        session.close()
        session.remove()

    def loadFromDB(self):
        self.log.info('Loading data from db')
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            for bid in session.query(Bid):
                if bid.state and bid.state > BidStates.BID_RECEIVED and bid.state < BidStates.SWAP_COMPLETED:
                    self.log.debug('Loading active bid %s', bid.bid_id.hex())

                    offer = session.query(Offer).filter_by(offer_id=bid.offer_id).first()
                    assert(offer), 'Offer not found'
                    self.swaps_in_progress[bid.bid_id] = (bid, offer)

                    coin_from = Coins(offer.coin_from)
                    coin_to = Coins(offer.coin_to)
                    if bid.initiate_txid:
                        self.addWatchedOutput(coin_from, bid.bid_id, bid.initiate_txid.hex(), bid.initiate_txn_n, BidStates.SWAP_INITIATED)
                    if bid.participate_txid:
                        self.addWatchedOutput(coin_to, bid.bid_id, bid.participate_txid.hex(), bid.participate_txn_n, BidStates.SWAP_PARTICIPATING)

                    if self.coin_clients[coin_from]['last_height_checked'] < 1:
                        self.coin_clients[coin_from]['last_height_checked'] = bid.initiate_txn_height
                    if self.coin_clients[coin_to]['last_height_checked'] < 1:
                        self.coin_clients[coin_to]['last_height_checked'] = bid.participate_txn_height

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
        options = {'encoding': 'hex'}
        ro = self.callrpc('smsginbox', ['unread', '', options])
        nm = 0
        for msg in ro['messages']:
            self.processMsg(msg)
            nm += 1
        self.log.info('Scanned %d unread messages.', nm)

    def validateOfferAmounts(self, coin_from, coin_to, amount, rate, min_bid_amount):
        assert(amount >= min_bid_amount), 'amount < min_bid_amount'
        assert(amount > chainparams[coin_from][self.chain]['min_amount']), 'From amount below min value for chain'
        assert(amount < chainparams[coin_from][self.chain]['max_amount']), 'From amount above max value for chain'

        amount_to = (amount * rate) // COIN
        assert(amount_to > chainparams[coin_to][self.chain]['min_amount']), 'To amount below min value for chain'
        assert(amount_to < chainparams[coin_to][self.chain]['max_amount']), 'To amount above max value for chain'

    def validateOfferLockValue(self, coin_from, coin_to, lock_type, lock_value):
        if lock_type == OfferMessage.SEQUENCE_LOCK_TIME:
            assert(lock_value >= 2 * 60 * 60 and lock_value <= 96 * 60 * 60), 'Invalid lock_value time'
        elif lock_type == OfferMessage.SEQUENCE_LOCK_BLOCKS:
            assert(lock_value >= 5 and lock_value <= 1000), 'Invalid lock_value blocks'
        else:
            raise ValueError('Unknown locktype')

    def postOffer(self, coin_from, coin_to, amount, rate, min_bid_amount, swap_type,
                  lock_type=SEQUENCE_LOCK_TIME, lock_value=48 * 60 * 60, auto_accept_bids=False):

        # Offer to send offer.amount_from of coin_from in exchange for offer.amount_from * offer.rate of coin_to

        assert(coin_from != coin_to), 'coin_from == coin_to'
        try:
            coin_from_t = Coins(coin_from)
        except Exception:
            raise ValueError('Unknown coin from type')
        try:
            coin_to_t = Coins(coin_to)
        except Exception:
            raise ValueError('Unknown coin to type')

        self.validateOfferAmounts(coin_from_t, coin_to_t, amount, rate, min_bid_amount)
        self.validateOfferLockValue(coin_from_t, coin_to_t, lock_type, lock_value)

        self.mxDB.acquire()
        try:
            msg_buf = OfferMessage()
            msg_buf.coin_from = int(coin_from)
            msg_buf.coin_to = int(coin_to)
            msg_buf.amount_from = amount
            msg_buf.rate = int(rate)
            msg_buf.min_bid_amount = min_bid_amount

            msg_buf.time_valid = 60 * 60
            msg_buf.lock_type = lock_type
            msg_buf.lock_value = lock_value
            msg_buf.swap_type = swap_type

            offer_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.OFFER) + offer_bytes.hex()

            # TODO: reuse address?
            offer_addr = self.callrpc('getnewaddress')
            self.callrpc('smsgaddlocaladdress', [offer_addr])  # Enable receiving smsg
            ro = self.callrpc('smsgsend', [offer_addr, self.network_addr, payload_hex, False, 1, False, False, True])
            msg_id = ro['msgid']

            offer_id = bytes.fromhex(msg_id)

            session = scoped_session(self.session_factory)

            offer = Offer(
                offer_id=offer_id,

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
                created_at=int(time.time()),
                expire_at=int(time.time()) + msg_buf.time_valid,
                was_sent=True,
                auto_accept_bids=auto_accept_bids,)
            offer.setState(OfferStates.OFFER_SENT)
            session.add(offer)

            session.add(SentOffer(offer_id=offer_id))
            session.commit()
            session.close()
            session.remove()
        finally:
            self.mxDB.release()
        self.log.info('Sent OFFER %s', offer_id.hex())
        return offer_id

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

    def getReceiveAddressForCoin(self, coin_type):
        if coin_type == Coins.PART:
            new_addr = self.callcoinrpc(Coins.PART, 'getnewaddress')
        elif coin_type == Coins.LTC or coin_type == Coins.BTC:
            args = []
            if self.coin_clients[coin_type]['use_segwit']:
                args = ['swap_receive', 'bech32']
            new_addr = self.callcoinrpc(coin_type, 'getnewaddress', args)
        else:
            raise ValueError('Unknown coin type.')
        self.log.debug('Generated new receive address %s for %s', new_addr, str(coin_type))
        return new_addr

    def getFeeRateForCoin(self, coin_type):
        # TODO: Per coin settings to override feerate
        try:
            return self.callcoinrpc(coin_type, 'estimatesmartfee', [1])['feerate']
        except Exception:
            try:
                fee_rate = self.callcoinrpc(coin_type, 'getwalletinfo')['paytxfee']
                assert(fee_rate > 0.0), '0 feerate'
                return fee_rate
            except Exception:
                return self.callcoinrpc(coin_type, 'getnetworkinfo')['relayfee']

    def getTicker(self, coin_type):
        ticker = chainparams[coin_type]['ticker']
        if self.chain == 'testnet':
            ticker = 't' + ticker
        if self.chain == 'regtest':
            ticker = 'rt' + ticker
        return ticker

    def withdrawCoin(self, coin_type, value, addr_to, subfee):
        self.log.info('withdrawCoin %s %s to %s %s', value, self.getTicker(coin_type), addr_to, ' subfee' if subfee else '')
        return self.callcoinrpc(coin_type, 'sendtoaddress', [addr_to, value, '', '', subfee])

    def cacheNewAddressForCoin(self, coin_type):
        self.log.debug('cacheNewAddressForCoin %s', coin_type)
        key_str = 'receive_addr_' + chainparams[coin_type]['name']
        session = scoped_session(self.session_factory)
        addr = self.getReceiveAddressForCoin(coin_type)
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            try:
                kv = session.query(DBKVString).filter_by(key=key_str).first()
                kv.value = addr
            except Exception:
                kv = DBKVString(
                    key=key_str,
                    value=addr
                )
            session.add(kv)
            session.commit()
            session.close()
            session.remove()
        finally:
            self.mxDB.release()
        return addr

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
            session.close()
            session.remove()
        finally:
            self.mxDB.release()
        return addr

    def getNewContractId(self):
        self.mxDB.acquire()
        try:
            self._contract_count += 1
            session = scoped_session(self.session_factory)
            self.engine.execute('UPDATE kv_int SET value = {} WHERE KEY="contract_count"'.format(self._contract_count))
            session.commit()
            session.close()
            session.remove()
        finally:
            self.mxDB.release()

        return self._contract_count

    def getProofOfFunds(self, coin_type, amount_for):
        self.log.debug('getProofOfFunds %s %s', str(coin_type), format8(amount_for))

        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return (None, None)

        # TODO: Lock unspent and use same output/s to fund bid
        unspent_addr = dict()
        unspent = self.callcoinrpc(coin_type, 'listunspent')
        for u in unspent:
            unspent_addr[u['address']] = unspent_addr.get(u['address'], 0.0) * COIN + u['amount'] * COIN

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
        signature = self.callcoinrpc(coin_type, 'signmessage', [sign_for_addr, sign_for_addr + '_swap_proof'])

        return (sign_for_addr, signature)

    def saveBid(self, bid_id, bid):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            session.add(bid)
            session.commit()
            session.close()
            session.remove()
        finally:
            self.mxDB.release()

    def postBid(self, offer_id, amount):
        self.log.debug('postBid %s %s', offer_id.hex(), format8(amount))

        # Bid to send bid.amount * offer.rate of coin_to in exchange for bid.amount of coin_from

        offer = self.getOffer(offer_id)
        assert(offer), 'Offer not found: {}.'.format(offer_id.hex())

        # TODO: Assert offer still valid

        msg_buf = BidMessage()
        msg_buf.offer_msg_id = offer_id
        msg_buf.time_valid = 60 * 10
        msg_buf.amount = amount  # amount of coin_from

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)

        contract_count = self.getNewContractId()

        now = int(time.time())
        if offer.swap_type == SwapTypes.SELLER_FIRST:
            msg_buf.pkhash_buyer = getKeyID(self.getContractPubkey(dt.datetime.fromtimestamp(now).date(), contract_count))

            proof_addr, proof_sig = self.getProofOfFunds(coin_to, msg_buf.amount)
            msg_buf.proof_address = proof_addr
            msg_buf.proof_signature = proof_sig

        bid_bytes = msg_buf.SerializeToString()
        payload_hex = str.format('{:02x}', MessageTypes.BID) + bid_bytes.hex()

        # TODO: reuse address?
        bid_addr = self.callrpc('getnewaddress')
        self.callrpc('smsgaddlocaladdress', [bid_addr])  # Enable receiving smsg
        ro = self.callrpc('smsgsend', [bid_addr, offer.addr_from, payload_hex, False, 1, False, False, True])
        msg_id = ro['msgid']

        bid_id = bytes.fromhex(msg_id)
        bid = Bid(
            bid_id=bid_id,
            offer_id=offer_id,
            amount=msg_buf.amount,
            pkhash_buyer=msg_buf.pkhash_buyer,
            proof_address=msg_buf.proof_address,

            created_at=now,
            contract_count=contract_count,
            amount_to=(msg_buf.amount * offer.rate) // COIN,
            expire_at=now + msg_buf.time_valid,
            bid_addr=bid_addr,
            was_sent=True,
        )
        bid.setState(BidStates.BID_SENT)

        self.saveBid(bid_id, bid)

        self.log.info('Sent BID %s', bid_id.hex())
        return bid_id

    def getOffer(self, offer_id, sent=False):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            return session.query(Offer).filter_by(offer_id=offer_id).first()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getBid(self, bid_id):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            return session.query(Bid).filter_by(bid_id=bid_id).first()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def getBidAndOffer(self, bid_id):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            bid = session.query(Bid).filter_by(bid_id=bid_id).first()
            return bid, session.query(Offer).filter_by(offer_id=bid.offer_id).first()
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def acceptBid(self, bid_id):
        self.log.info('Accepting bid %s', bid_id.hex())

        bid, offer = self.getBidAndOffer(bid_id)
        assert(bid), 'Bid not found'
        assert(offer), 'Offer not found'

        # Ensure bid is still valid
        now = int(time.time())
        assert(bid.expire_at > now), 'Bid expired'
        assert(bid.state == BidStates.BID_RECEIVED), 'Wrong bid state: {}'.format(BidStates(bid.state))

        if bid.contract_count is None:
            bid.contract_count = self.getNewContractId()

        coin_from = Coins(offer.coin_from)
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

        # TODO: Use CLTV for coins without CSV
        sequence = getExpectedSequence(offer.lock_type, offer.lock_value, coin_from)
        secret = self.getContractSecret(bid_date, bid.contract_count)
        secret_hash = hashlib.sha256(secret).digest()

        pubkey_refund = self.getContractPubkey(bid_date, bid.contract_count)
        pkhash_refund = getKeyID(pubkey_refund)

        script = buildContractScriptCSV(sequence, secret_hash, bid.pkhash_buyer, pkhash_refund)

        p2sh = self.callcoinrpc(Coins.PART, 'decodescript', [script.hex()])['p2sh']

        bid.initiate_script = script
        bid.pkhash_seller = pkhash_refund

        txn = self.createInitiateTxn(coin_from, bid_id, bid)

        # Store the signed refund txn in case wallet is locked when refund is possible
        refund_txn = self.createRefundTxn(coin_from, txn, bid, script)
        bid.initiate_txn_refund = bytes.fromhex(refund_txn)

        txid = self.submitTxn(coin_from, txn)
        self.log.debug('Submitted initiate txn %s to %s chain for bid %s', txid, chainparams[coin_from]['name'], bid_id.hex())
        bid.setITXState(TxStates.TX_SENT)

        # Check non-bip68 final
        try:
            txid = self.submitTxn(coin_from, bid.initiate_txn_refund.hex())
            self.log.error('Submit refund_txn unexpectedly worked: ' + txid)
        except Exception as e:
            if 'non-BIP68-final' not in str(e):
                self.log.error('Submit refund_txn unexpected error' + str(e))

        if txid is not None:
            msg_buf = BidAcceptMessage()
            msg_buf.bid_msg_id = bid_id
            msg_buf.initiate_txid = bytes.fromhex(txid)
            msg_buf.contract_script = bytes(script)

            bid_bytes = msg_buf.SerializeToString()
            payload_hex = str.format('{:02x}', MessageTypes.BID_ACCEPT) + bid_bytes.hex()
            ro = self.callrpc('smsgsend', [offer.addr_from, bid.bid_addr, payload_hex, False, 1, False, False, True])
            msg_id = ro['msgid']

            accept_msg_id = bytes.fromhex(msg_id)

            bid.accept_msg_id = accept_msg_id
            bid.initiate_txid = bytes.fromhex(txid)
            bid.setState(BidStates.BID_ACCEPTED)

            self.log.info('Sent BID_ACCEPT %s', accept_msg_id.hex())

            self.saveBid(bid_id, bid)
            self.swaps_in_progress[bid_id] = (bid, offer)

    def abandonOffer(self, offer_id):
        self.log.info('Abandoning Offer %s', offer_id.hex())
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            offer = session.query(Offer).filter_by(offer_id=offer_id).first()
            assert(offer), 'Offer not found'

            # TODO: abandon linked bids?

            # Mark bid as abandoned, no further processing will be done
            offer.setState(OfferStates.OFFER_ABANDONED)
            session.commit()
        finally:
            session.close()
            session.remove()
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
            session.commit()

            # Remove from in progress
            self.swaps_in_progress.pop(bid_id, None)

            # Remove any watched outputs
            self.removeWatchedOutput(Coins(offer.coin_from), bid_id, None)
            self.removeWatchedOutput(Coins(offer.coin_to), bid_id, None)
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def encodeSegwitP2WSH(self, coin_type, p2wsh):
        return segwit_addr.encode(chainparams[coin_type][self.chain]['hrp'], 0, p2wsh[2:])

    def encodeSegwit(self, coin_type, raw):
        return segwit_addr.encode(chainparams[coin_type][self.chain]['hrp'], 0, raw)

    def decodeSegwit(self, coin_type, addr):
        return bytes(segwit_addr.decode(chainparams[coin_type][self.chain]['hrp'], addr)[1])

    def getScriptAddress(self, coin_type, script):
        return pubkeyToAddress(chainparams[coin_type][self.chain]['script_address'], script)

    def createInitiateTxn(self, coin_type, bid_id, bid):
        if self.coin_clients[coin_type]['connection_type'] != 'rpc':
            return None

        if self.coin_clients[coin_type]['use_segwit']:
            addr_to = self.encodeSegwitP2WSH(coin_type, getP2WSH(bid.initiate_script))
        else:
            addr_to = self.getScriptAddress(coin_type, bid.initiate_script)
        self.log.debug('Create initiate txn for coin %s to %s for bid %s', str(coin_type), addr_to, bid_id.hex())
        txn = self.callcoinrpc(coin_type, 'createrawtransaction', [[], {addr_to: format8(bid.amount)}])
        txn_funded = self.callcoinrpc(coin_type, 'fundrawtransaction', [txn, {'lockUnspents': True}])['hex']
        txn_signed = self.callcoinrpc(coin_type, 'signrawtransactionwithwallet', [txn_funded])['hex']
        return txn_signed

    def deriveParticipateScript(self, bid_id, bid, offer):
        self.log.debug('deriveParticipateScript for bid %s', bid_id.hex())

        coin_to = Coins(offer.coin_to)

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

        # Participate txn is locked for half the time of the initiate txn
        lock_value = decodeSequence(offer.lock_value) // 2
        sequence = getExpectedSequence(offer.lock_type, lock_value, coin_to)

        secret_hash = extractScriptSecretHash(bid.initiate_script)
        pkhash_seller = bid.pkhash_seller
        pkhash_buyer_refund = bid.pkhash_buyer
        bid.participate_script = buildContractScriptCSV(sequence, secret_hash, pkhash_seller, pkhash_buyer_refund)

    def createParticipateTxn(self, bid_id, bid, offer):
        self.log.debug('createParticipateTxn')

        offer_id = bid.offer_id
        coin_to = Coins(offer.coin_to)

        if self.coin_clients[coin_to]['connection_type'] != 'rpc':
            return None

        amount_to = bid.amount_to
        # Check required?
        assert(amount_to == (bid.amount * offer.rate) // COIN)

        if self.coin_clients[coin_to]['use_segwit']:
            p2wsh = getP2WSH(bid.participate_script)
            addr_to = self.encodeSegwitP2WSH(coin_to, p2wsh)
        else:
            addr_to = self.getScriptAddress(coin_to, bid.participate_script)

        txn = self.callcoinrpc(coin_to, 'createrawtransaction', [[], {addr_to: format8(amount_to)}])
        txn_funded = self.callcoinrpc(coin_to, 'fundrawtransaction', [txn, {'lockUnspents': True}])['hex']

        txn_signed = self.callcoinrpc(coin_to, 'signrawtransactionwithwallet', [txn_funded])['hex']

        refund_txn = self.createRefundTxn(coin_to, txn_signed, bid, bid.participate_script)
        bid.participate_txn_refund = bytes.fromhex(refund_txn)

        chain_height = self.callcoinrpc(coin_to, 'getblockchaininfo')['blocks']
        txjs = self.callcoinrpc(coin_to, 'decoderawtransaction', [txn_signed])
        txid = txjs['txid']

        if self.coin_clients[coin_to]['use_segwit']:
            vout = getVoutByP2WSH(txjs, p2wsh.hex())
        else:
            vout = getVoutByAddress(txjs, addr_to)
        self.addParticipateTxn(bid_id, bid, coin_to, txid, vout, chain_height)

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

        if for_txn_type == 'participate':
            prev_txnid = bid.participate_txid.hex()
            prev_n = bid.participate_txn_n
            txn_script = bid.participate_script
            prev_amount = bid.amount_to
        else:
            prev_txnid = bid.initiate_txid.hex()
            prev_n = bid.initiate_txn_n
            txn_script = bid.initiate_script
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
            'amount': format8(prev_amount)}

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
            fee_rate = self.getFeeRateForCoin(coin_type)

        tx_vsize = self.getContractSpendTxVSize(coin_type)
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug('Redeem tx fee %s, rate %s', format8(tx_fee * COIN), str(fee_rate))

        amount_out = prev_amount - tx_fee * COIN
        assert(amount_out > 0), 'Amount out <= 0'

        if addr_redeem_out is None:
            addr_redeem_out = self.getReceiveAddressForCoin(coin_type)
        assert(addr_redeem_out is not None)

        if self.coin_clients[coin_type]['use_segwit']:
            # Change to btc hrp
            addr_redeem_out = self.encodeSegwit(Coins.PART, self.decodeSegwit(coin_type, addr_redeem_out))
        else:
            addr_redeem_out = replaceAddrPrefix(addr_redeem_out, Coins.PART, self.chain)
        self.log.debug('addr_redeem_out %s', addr_redeem_out)
        output_to = ' outaddr={}:{}'.format(format8(amount_out), addr_redeem_out)
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

    def createRefundTxn(self, coin_type, txn, bid, txn_script, addr_refund_out=None, fee_rate=None):
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

        sequence = DeserialiseNum(txn_script, 64)
        prevout_s = ' in={}:{}:{}'.format(txjs['txid'], vout, sequence)

        if fee_rate is None:
            fee_rate = self.getFeeRateForCoin(coin_type)

        tx_vsize = self.getContractSpendTxVSize(coin_type, False)
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug('Refund tx fee %s, rate %s', format8(tx_fee * COIN), str(fee_rate))

        amount_out = prev_amount * COIN - tx_fee * COIN
        assert(amount_out > 0), 'Amount out <= 0'

        if addr_refund_out is None:
            addr_refund_out = self.getReceiveAddressForCoin(coin_type)
        assert(addr_refund_out is not None), 'addr_refund_out is null'
        if self.coin_clients[coin_type]['use_segwit']:
            # Change to btc hrp
            addr_refund_out = self.encodeSegwit(Coins.PART, self.decodeSegwit(coin_type, addr_refund_out))
        else:
            addr_refund_out = replaceAddrPrefix(addr_refund_out, Coins.PART, self.chain)
        self.log.debug('addr_refund_out %s', addr_refund_out)

        output_to = ' outaddr={}:{}'.format(format8(amount_out), addr_refund_out)
        if coin_type == Coins.PART:
            refund_txn = self.calltx('-create' + prevout_s + output_to)
        else:
            refund_txn = self.calltx('-btcmode -create nversion=2' + prevout_s + output_to)

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
        bid.setITXState(TxStates.TX_CONFIRMED)

        # Seller first mode, buyer participates
        self.deriveParticipateScript(bid_id, bid, offer)
        if bid.was_sent:
            self.log.debug('Preparing participate txn for bid %s', bid_id.hex())

            coin_to = Coins(offer.coin_to)
            txn = self.createParticipateTxn(bid_id, bid, offer)
            txid = self.submitTxn(coin_to, txn)
            self.log.debug('Submitted participate txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
            bid.setPTXState(TxStates.TX_SENT)

        # bid saved in checkBidState

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
        bid.participate_txid = bytes.fromhex(txid_hex)
        bid.participate_txn_n = vout
        # Start checking for spends of participate_txn before fully confirmed

        chain_name = chainparams[coin_type]['name']
        self.log.debug('Watching %s chain for spend of output %s %d', chain_name, txid_hex, vout)

        # TODO: Check connection type
        bid.participate_txn_height = self.setLastHeightChecked(coin_type, tx_height)

        self.addWatchedOutput(coin_type, bid_id, txid_hex, vout, BidStates.SWAP_PARTICIPATING)

    def participateTxnConfirmed(self, bid_id, bid, offer):
        self.log.debug('participateTxnConfirmed for bid %s', bid_id.hex())
        bid.setState(BidStates.SWAP_PARTICIPATING)
        bid.setPTXState(TxStates.TX_CONFIRMED)

        # Seller redeems from participate txn
        if bid.was_received:
            coin_to = Coins(offer.coin_to)
            txn = self.createRedeemTxn(coin_to, bid)
            txid = self.submitTxn(coin_to, txn)
            self.log.debug('Submitted participate redeem txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
            # TX_REDEEMED will be set when spend is detected
            # TODO: Wait for depth?

        # bid saved in checkBidState

    def lookupChainHeight(self, coin_type):
        return self.callcoinrpc(coin_type, 'getblockchaininfo')['blocks']

    def lookupUnspentByAddress(self, coin_type, address, sum_output=False, assert_amount=None, assert_txid=None):
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
                assert(int(o['amount'] * COIN) == int(assert_amount)), 'Incorrect output amount in txn {}.'.format(assert_txid)

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
                }
            else:
                sum_unspent += o['amount'] * COIN
        if sum_output:
            return sum_unspent
        return None

    def checkBidState(self, bid_id, bid, offer):
        # assert(self.mxDB.locked())
        # Return True to remove bid from in-progress list

        state = BidStates(bid.state)
        self.log.debug('checkBidState %s %s', bid_id.hex(), str(state))

        save_bid = False
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        # TODO: Batch calls to scantxoutset
        # TODO: timeouts
        if state == BidStates.BID_ACCEPTED:
            # Waiting for initiate txn to be confirmed in 'from' chain
            initiate_txnid_hex = bid.initiate_txid.hex()
            p2sh = self.getScriptAddress(coin_from, bid.initiate_script)
            index = None
            tx_height = None
            last_initiate_txn_conf = bid.initiate_txn_conf
            if coin_from == Coins.PART:  # Has txindex
                try:
                    initiate_txn = self.callcoinrpc(coin_from, 'getrawtransaction', [initiate_txnid_hex, True])
                    # Verify amount
                    vout = getVoutByAddress(initiate_txn, p2sh)
                    assert(int(initiate_txn['vout'][vout]['value'] * COIN) == int(bid.amount)), 'Incorrect output amount in initiate txn.'

                    bid.initiate_txn_conf = initiate_txn['confirmations']
                    try:
                        tx_height = initiate_txn['height']
                    except Exception:
                        tx_height = -1
                    index = vout
                except Exception:
                    pass
            else:
                if self.coin_clients[coin_from]['use_segwit']:
                    addr = self.encodeSegwitP2WSH(coin_from, getP2WSH(bid.initiate_script))
                else:
                    addr = p2sh
                found = self.lookupUnspentByAddress(coin_from, addr, assert_amount=bid.amount, assert_txid=initiate_txnid_hex)
                if found:
                    bid.initiate_txn_conf = found['n_conf']
                    index = found['index']
                    tx_height = found['height']

            if bid.initiate_txn_conf != last_initiate_txn_conf:
                save_bid = True

            if bid.initiate_txn_conf is not None:
                self.log.debug('initiate_txnid %s confirms %d', initiate_txnid_hex, bid.initiate_txn_conf)

                if bid.initiate_txn_n is None:
                    bid.initiate_txn_n = index
                    # Start checking for spends of initiate_txn before fully confirmed
                    bid.initiate_txn_height = self.setLastHeightChecked(coin_from, tx_height)
                    self.addWatchedOutput(coin_from, bid_id, initiate_txnid_hex, bid.initiate_txn_n, BidStates.SWAP_INITIATED)
                    if bid.initiate_txn_state is None or bid.initiate_txn_state < TxStates.TX_SENT:
                        bid.setITXState(TxStates.TX_SENT)
                    save_bid = True

                if bid.initiate_txn_conf >= self.coin_clients[coin_from]['blocks_confirmed']:
                    self.initiateTxnConfirmed(bid_id, bid, offer)
                    save_bid = True

            # Bid times out if buyer doesn't see tx in chain within
            if bid.state_time + INITIATE_TX_TIMEOUT < int(time.time()):
                self.log.info('Swap timed out waiting for initiate tx for bid %s', bid_id.hex())
                bid.setState(BidStates.SWAP_TIMEDOUT)
                self.saveBid(bid_id, bid)
                return True  # Mark bid for archiving
        elif state == BidStates.SWAP_INITIATED:
            # Waiting for participate txn to be confirmed in 'to' chain
            if self.coin_clients[coin_to]['use_segwit']:
                addr = self.encodeSegwitP2WSH(coin_to, getP2WSH(bid.participate_script))
            else:
                addr = self.getScriptAddress(coin_to, bid.participate_script)

            found = self.lookupUnspentByAddress(coin_to, addr, assert_amount=bid.amount_to)
            if found:
                if bid.participate_txn_conf != found['n_conf']:
                    save_bid = True
                bid.participate_txn_conf = found['n_conf']
                index = found['index']
                if bid.participate_txid is None:
                    self.log.debug('Found bid %s participate txn %s in chain %s', bid_id.hex(), found['txid'], coin_to)
                    self.addParticipateTxn(bid_id, bid, coin_to, found['txid'], found['index'], found['height'])
                    bid.setPTXState(TxStates.TX_SENT)
                    save_bid = True

            if bid.participate_txn_conf is not None:
                self.log.debug('participate_txid %s confirms %d', bid.participate_txid.hex(), bid.participate_txn_conf)
                if bid.participate_txn_conf >= self.coin_clients[coin_to]['blocks_confirmed']:
                    self.participateTxnConfirmed(bid_id, bid, offer)
                    save_bid = True
        elif state == BidStates.SWAP_PARTICIPATING:
            # Waiting for initiate txn spend
            pass
        else:
            self.log.warning('checkBidState unknown state %s', state)

        if state > BidStates.BID_ACCEPTED:
            # Wait for spend of all known swap txns
            if (bid.initiate_txn_state is None or bid.initiate_txn_state >= TxStates.TX_REDEEMED) \
               and (bid.participate_txn_state is None or bid.participate_txn_state >= TxStates.TX_REDEEMED):
                self.log.info('Swap completed for bid %s', bid_id.hex())
                bid.setState(BidStates.SWAP_COMPLETED)
                self.saveBid(bid_id, bid)
                return True  # Mark bid for archiving

        if save_bid:
            self.saveBid(bid_id, bid)

        # Try refund, keep trying until sent tx is spent
        if (bid.initiate_txn_state == TxStates.TX_SENT or bid.initiate_txn_state == TxStates.TX_CONFIRMED) \
           and bid.initiate_txn_refund is not None:
            try:
                txid = self.submitTxn(coin_from, bid.initiate_txn_refund.hex())
                self.log.debug('Submitted initiate refund txn %s to %s chain for bid %s', txid, chainparams[coin_from]['name'], bid_id.hex())
                # State will update when spend is detected
            except Exception as e:
                if 'non-BIP68-final (code 64)' not in str(e):
                    self.log.warning('Error trying to submit initiate refund txn: %s', str(e))
        if (bid.participate_txn_state == TxStates.TX_SENT or bid.participate_txn_state == TxStates.TX_CONFIRMED) \
           and bid.participate_txn_refund is not None:
            try:
                txid = self.submitTxn(coin_to, bid.participate_txn_refund.hex())
                self.log.debug('Submitted participate refund txn %s to %s chain for bid %s', txid, chainparams[coin_to]['name'], bid_id.hex())
                # State will update when spend is detected
            except Exception as e:
                if 'non-BIP68-final (code 64)' not in str(e):
                    self.log.warning('Error trying to submit participate refund txn: %s', str(e))
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

    def addWatchedOutput(self, coin_type, bid_id, txid_hex, vout, tx_type):
        self.log.debug('Adding watched output %s bid %s tx %s type %s', coin_type, bid_id.hex(), txid_hex, tx_type)
        self.coin_clients[coin_type]['watched_outputs'].append((bid_id, txid_hex, vout, tx_type))

    def removeWatchedOutput(self, coin_type, bid_id, txid_hex):
        # Remove all for bid if txid is None
        self.log.debug('removeWatchedOutput %s %s %s', str(coin_type), bid_id.hex(), txid_hex)
        old_len = len(self.coin_clients[coin_type]['watched_outputs'])
        for i in range(old_len - 1, -1, -1):
            wo = self.coin_clients[coin_type]['watched_outputs'][i]
            if wo[0] == bid_id and (txid_hex is None or wo[1] == txid_hex):
                del self.coin_clients[coin_type]['watched_outputs'][i]
                self.log.debug('Removed watched output %s %s %s', str(coin_type), bid_id.hex(), wo[1])

    def initiateTxnSpent(self, bid_id, spend_txid, spend_n, spend_txn):
        self.log.debug('Bid %s initiate txn spent by %s %d', bid_id.hex(), spend_txid, spend_n)

        if bid_id in self.swaps_in_progress:
            bid = self.swaps_in_progress[bid_id][0]
            offer = self.swaps_in_progress[bid_id][1]

            bid.initiate_spend_txid = bytes.fromhex(spend_txid)
            bid.initiate_spend_n = spend_n
            spend_in = spend_txn['vin'][spend_n]

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            secret = self.extractSecret(coin_from, bid, spend_in)
            if secret is None:
                self.log.info('Bid %s initiate txn refunded by %s %d', bid_id.hex(), spend_txid, spend_n)
                # TODO: Wait for depth?
                bid.setITXState(TxStates.TX_REFUNDED)
            else:
                self.log.info('Bid %s initiate txn redeemed by %s %d', bid_id.hex(), spend_txid, spend_n)
                # TODO: Wait for depth?
                bid.setITXState(TxStates.TX_REDEEMED)

            self.removeWatchedOutput(coin_from, bid_id, bid.initiate_txid.hex())
            self.saveBid(bid_id, bid)

    def participateTxnSpent(self, bid_id, spend_txid, spend_n, spend_txn):
        self.log.debug('Bid %s participate txn spent by %s %d', bid_id.hex(), spend_txid, spend_n)

        # TODO: More SwapTypes
        if bid_id in self.swaps_in_progress:
            bid = self.swaps_in_progress[bid_id][0]
            offer = self.swaps_in_progress[bid_id][1]

            bid.participate_spend_txid = bytes.fromhex(spend_txid)
            bid.participate_spend_n = spend_n
            spend_in = spend_txn['vin'][spend_n]

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)

            secret = self.extractSecret(coin_to, bid, spend_in)
            if secret is None:
                self.log.info('Bid %s participate txn refunded by %s %d', bid_id.hex(), spend_txid, spend_n)
                # TODO: Wait for depth?
                bid.setPTXState(TxStates.TX_REFUNDED)
            else:
                self.log.debug('Secret %s extracted from participate spend %s %d', secret.hex(), spend_txid, spend_n)
                bid.recovered_secret = secret
                # TODO: Wait for depth?
                bid.setPTXState(TxStates.TX_REDEEMED)

            if bid.was_sent:
                txn = self.createRedeemTxn(coin_from, bid, for_txn_type='initiate')
                txid = self.submitTxn(coin_from, txn)

                bid.initiate_spend_txid = bytes.fromhex(txid)
                # bid.initiate_txn_redeem = bytes.fromhex(txn)  # Worth keeping?
                self.log.debug('Submitted initiate redeem txn %s to %s chain for bid %s', txid, chainparams[coin_from]['name'], bid_id.hex())

                # TODO: Wait for depth? new state SWAP_TXI_REDEEM_SENT?

            self.removeWatchedOutput(coin_to, bid_id, bid.participate_txid.hex())
            self.saveBid(bid_id, bid)

    def checkForSpends(self, coin_type, c):
        # assert(self.mxDB.locked()) self.log.debug('checkForSpends %s', coin_type)

        if coin_type == Coins.PART:
            # TODO: batch getspentinfo
            for o in c['watched_outputs']:
                found_spend = None
                try:
                    found_spend = self.callcoinrpc(Coins.PART, 'getspentinfo', [{'txid': o[1], 'index': o[2]}])
                except Exception as e:
                    if 'Unable to get spent info' not in str(e):
                        self.log.warning('getspentinfo %s', str(e))
                if found_spend is not None:
                    self.log.debug('Found spend in spentindex %s %d in %s %d', o[1], o[2], found_spend['txid'], found_spend['index'])
                    bid_id = o[0]
                    spend_txid = found_spend['txid']
                    spend_n = found_spend['index']
                    spend_txn = self.callcoinrpc(Coins.PART, 'getrawtransaction', [spend_txid, True])
                    if o[3] == BidStates.SWAP_PARTICIPATING:
                        self.participateTxnSpent(bid_id, spend_txid, spend_n, spend_txn)
                    else:
                        self.initiateTxnSpent(bid_id, spend_txid, spend_n, spend_txn)
        else:
            chain_blocks = self.callcoinrpc(coin_type, 'getblockchaininfo')['blocks']
            last_height_checked = c['last_height_checked']
            self.log.debug('chain_blocks, last_height_checked %s %s', chain_blocks, last_height_checked)
            while last_height_checked < chain_blocks:
                block_hash = self.callcoinrpc(coin_type, 'getblockhash', [last_height_checked + 1])
                block = self.callcoinrpc(coin_type, 'getblock', [block_hash, 2])

                for tx in block['tx']:
                    for i, inp in enumerate(tx['vin']):
                        for o in c['watched_outputs']:
                            inp_txid = inp.get('txid', None)
                            if inp_txid is None:  # Coinbase
                                continue
                            if inp_txid == o[1] and inp['vout'] == o[2]:
                                self.log.debug('Found spend from search %s %d in %s %d', o[1], o[2], tx['txid'], i)
                                bid_id = o[0]
                                if o[3] == BidStates.SWAP_PARTICIPATING:
                                    self.participateTxnSpent(bid_id, tx['txid'], i, tx)
                                else:
                                    self.initiateTxnSpent(bid_id, tx['txid'], i, tx)
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
            for msg in ro['messages']:
                expire_at = msg['sent'] + msg['daysretention'] * SMSG_SECONDS_IN_DAY
                if expire_at < now:
                    options = {'encoding': 'none', 'delete': True}
                    del_msg = self.callrpc('smsg', [msg['msgid'], options])

            # TODO: remove offers from db

            self.last_checked_expired = now
        finally:
            self.mxDB.release()

    def processOffer(self, msg):
        assert(msg['to'] == self.network_addr), 'Offer received on wrong address'

        offer_bytes = bytes.fromhex(msg['hex'][2:-2])
        offer_data = OfferMessage()
        offer_data.ParseFromString(offer_bytes)

        # Validate data
        now = int(time.time())
        coin_from = Coins(offer_data.coin_from)
        coin_to = Coins(offer_data.coin_to)
        chain_from = chainparams[coin_from][self.chain]
        assert(offer_data.coin_from != offer_data.coin_to), 'coin_from == coin_to'

        self.validateOfferAmounts(coin_from, coin_to, offer_data.amount_from, offer_data.rate, offer_data.min_bid_amount)
        self.validateOfferLockValue(coin_from, coin_to, offer_data.lock_type, offer_data.lock_value)

        assert(offer_data.time_valid >= MIN_OFFER_VALID_TIME and offer_data.time_valid <= MAX_OFFER_VALID_TIME), 'Invalid time_valid'
        assert(msg['sent'] + offer_data.time_valid >= now), 'Offer expired'

        if offer_data.swap_type == SwapTypes.SELLER_FIRST:
            assert(len(offer_data.proof_address) == 0), 'Unexpected data'
            assert(len(offer_data.proof_signature) == 0), 'Unexpected data'
            assert(len(offer_data.pkhash_seller) == 0), 'Unexpected data'
            assert(len(offer_data.secret_hash) == 0), 'Unexpected data'
        elif offer_data.swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError('TODO')
        else:
            raise ValueError('Unknown swap type {}.'.format(offer_data.swap_type))

        offer_id = bytes.fromhex(msg['msgid'])

        session = scoped_session(self.session_factory)
        # Check for sent
        existing_offer = self.getOffer(offer_id)
        if existing_offer is None:
            offer = Offer(
                offer_id=offer_id,

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
            self.log.debug('Received new offer %s', offer_id.hex())
        else:
            existing_offer.setState(OfferStates.OFFER_RECEIVED)
            session.add(existing_offer)
        session.commit()
        session.close()
        session.remove()

    def processBid(self, msg):
        self.log.debug('Processing bid msg %s', msg['msgid'])
        now = int(time.time())
        bid_bytes = bytes.fromhex(msg['hex'][2:-2])
        bid_data = BidMessage()
        bid_data.ParseFromString(bid_bytes)

        # Validate data
        assert(len(bid_data.offer_msg_id) == 28), 'Bad offer_id length'
        assert(bid_data.time_valid >= MIN_BID_VALID_TIME and bid_data.time_valid <= MAX_BID_VALID_TIME), 'Invalid time_valid'

        offer_id = bid_data.offer_msg_id
        offer = self.getOffer(offer_id, sent=True)
        assert(offer and offer.was_sent), 'Unknown offerid'

        assert(offer.state == OfferStates.OFFER_RECEIVED), 'Bad offer state'

        assert(msg['to'] == offer.addr_from), 'Received on incorrect address'
        assert(now <= offer.expire_at), 'Offer expired'
        assert(bid_data.amount >= offer.min_bid_amount), 'Bid amount below minimum'
        assert(now <= msg['sent'] + bid_data.time_valid), 'Bid expired'

        # TODO: allow higher bids
        # assert(bid_data.rate != offer['data'].rate), 'Bid rate mismatch'

        coin_to = Coins(offer.coin_to)
        swap_type = offer.swap_type
        if swap_type == SwapTypes.SELLER_FIRST:
            assert(len(bid_data.pkhash_buyer) == 20), 'Bad pkhash_buyer length'

            # Verify proof of funds
            bid_proof_address = replaceAddrPrefix(bid_data.proof_address, Coins.PART, self.chain)
            mm = chainparams[coin_to]['message_magic']
            passed = self.callcoinrpc(Coins.PART, 'verifymessage', [bid_proof_address, bid_data.proof_signature, bid_data.proof_address + '_swap_proof', mm])
            assert(passed is True), 'Proof of funds signature invalid'

            if self.coin_clients[coin_to]['use_segwit']:
                addr_search = self.encodeSegwit(coin_to, decodeAddress(bid_data.proof_address)[1:])
            else:
                addr_search = bid_data.proof_address

            sum_unspent = self.lookupUnspentByAddress(coin_to, addr_search, sum_output=True)
            self.log.debug('Proof of funds %s %s', bid_data.proof_address, format8(sum_unspent))
            assert(sum_unspent >= bid_data.amount), 'Proof of funds failed'

        elif swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError('TODO')
        else:
            raise ValueError('Unknown swap type {}.'.format(swap_type))

        bid_id = bytes.fromhex(msg['msgid'])

        bid = self.getBid(bid_id)
        if bid is None:
            bid = Bid(
                bid_id=bid_id,
                offer_id=offer_id,
                amount=bid_data.amount,
                pkhash_buyer=bid_data.pkhash_buyer,

                created_at=msg['sent'],
                amount_to=(bid_data.amount * offer.rate) // COIN,
                expire_at=msg['sent'] + bid_data.time_valid,
                bid_addr=msg['from'],
                was_received=True,
            )
        else:
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
            else:
                self.log.info('Auto accepting bid %s', bid_id.hex())
                self.acceptBid(bid_id)

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

        decoded_script = self.callcoinrpc(Coins.PART, 'decodescript', [bid_accept_data.contract_script.hex()])

        # TODO: Verify script without decoding?
        prog = re.compile('OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 (\w+) OP_EQUALVERIFY OP_DUP OP_HASH160 (\w+) OP_ELSE (\d+) OP_CHECKSEQUENCEVERIFY OP_DROP OP_DUP OP_HASH160 (\w+) OP_ENDIF OP_EQUALVERIFY OP_CHECKSIG')
        rr = prog.match(decoded_script['asm'])
        if not rr:
            raise ValueError('Bad script')
        scriptvalues = rr.groups()

        bid_id = bid_accept_data.bid_msg_id
        bid, offer = self.getBidAndOffer(bid_id)
        assert(bid is not None and bid.was_sent is True), 'Unknown bidid'
        assert(offer), 'Offer not found ' + bid.offer_id.hex()

        # assert(bid.expire_at > now), 'Bid expired'  # How much time over to accept

        if bid.state >= BidStates.BID_ACCEPTED:
            if bid.was_received:  # Sent to self
                self.log.info('Received valid bid accept %s for bid %s sent to self', bid.accept_msg_id.hex(), bid_id.hex())
                return
            raise ValueError('Wrong bid state: {}'.format(str(BidStates(bid.state))))

        coin_from = Coins(offer.coin_from)
        expect_sequence = getExpectedSequence(offer.lock_type, offer.lock_value, coin_from)

        assert(len(scriptvalues[0]) == 64), 'Bad secret_hash length'
        assert(bytes.fromhex(scriptvalues[1]) == bid.pkhash_buyer), 'pkhash_buyer mismatch'
        assert(int(scriptvalues[2]) == expect_sequence), 'sequence mismatch'
        assert(len(scriptvalues[3]) == 40), 'pkhash_refund bad length'

        assert(bid.accept_msg_id is None), 'Bid already accepted'

        bid.accept_msg_id = bytes.fromhex(msg['msgid'])
        bid.initiate_txid = bid_accept_data.initiate_txid
        bid.initiate_script = bid_accept_data.contract_script
        bid.pkhash_seller = bytes.fromhex(scriptvalues[3])
        bid.setState(BidStates.BID_ACCEPTED)
        bid.setITXState(TxStates.TX_NONE)

        self.log.info('Received valid bid accept %s for bid %s', bid.accept_msg_id.hex(), bid_id.hex())

        self.saveBid(bid_id, bid)
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

        except Exception as ex:
            self.log.error('processMsg %s', str(ex))
            traceback.print_exc()
        finally:
            self.mxDB.release()

    def processZmqSmsg(self):
        message = self.zmqSubscriber.recv()
        clear = self.zmqSubscriber.recv()

        if message[0] == 3:  # Paid smsg
            return  # TODO: switch to paid?

        msg_id = message[2:]
        options = {'encoding': 'hex', 'setread': True}
        msg = self.callrpc('smsg', [msg_id.hex(), options])
        self.processMsg(msg)

    def update(self):
        try:
            # while True:
            message = self.zmqSubscriber.recv(flags=zmq.NOBLOCK)
            if message == b'smsg':
                self.processZmqSmsg()
        except zmq.Again as e:
            pass
        except Exception as e:
            self.log.error('smsg zmq %s', str(e))
            traceback.print_exc()

        self.mxDB.acquire()
        try:
            # TODO: Wait for blocks / txns, would need to check multiple coins
            now = int(time.time())
            if now - self.last_checked_progress > self.check_progress_seconds:
                to_remove = []
                for bid_id, v in self.swaps_in_progress.items():
                    if self.checkBidState(bid_id, v[0], v[1]) is True:
                        to_remove.append(bid_id)
                for bid_id in to_remove:
                    self.log.debug('Removing bid from in-progress: %s', bid_id.hex())
                    del self.swaps_in_progress[bid_id]
                self.last_checked_progress = now

            now = int(time.time())
            if now - self.last_checked_watched > self.check_watched_seconds:
                for k, c in self.coin_clients.items():
                    if len(c['watched_outputs']) > 0:
                        self.checkForSpends(k, c)
                self.last_checked_watched = now

            # Expire messages
            if int(time.time()) - self.last_checked_expired > self.check_expired_seconds:
                self.expireMessages()
        except Exception as e:
            self.log.error('update %s', str(e))
            traceback.print_exc()
        finally:
            self.mxDB.release()

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
        q = self.engine.execute('SELECT COUNT(*) FROM offers WHERE expire_at > {}'.format(now)).first()
        num_offers = q[0]

        q = self.engine.execute('SELECT COUNT(*) FROM offers WHERE was_sent = 1'.format(now)).first()
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

        blockchaininfo = self.callcoinrpc(coin, 'getblockchaininfo')
        walletinfo = self.callcoinrpc(coin, 'getwalletinfo')
        rv = {
            'deposit_address': self.getCachedAddressForCoin(coin),
            'name': chainparams[coin]['name'].capitalize(),
            'blocks': blockchaininfo['blocks'],
            'balance': format8(walletinfo.get('total_balance', walletinfo['balance']) * COIN),
            'synced': '{0:.2f}'.format(round(blockchaininfo['verificationprogress'], 2)),
        }
        return rv

    def getWalletsInfo(self, opts=None):
        rv = {}
        for c in Coins:
            if self.coin_clients[c]['connection_type'] == 'rpc':
                rv[c] = self.getWalletInfo(c)
        return rv

    def countAcceptedBids(self, offer_id=None):
        self.mxDB.acquire()
        try:
            session = scoped_session(self.session_factory)
            if offer_id:
                q = self.engine.execute('SELECT COUNT(*) FROM bids WHERE state >= {} AND offer_id = x\'{}\''.format(BidStates.BID_ACCEPTED, offer_id.hex())).first()
            else:
                q = self.engine.execute('SELECT COUNT(*) FROM bids WHERE state >= {}'.format(BidStates.BID_ACCEPTED)).first()
            return q[0]
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listOffers(self, sent=False):
        self.mxDB.acquire()
        try:
            rv = []
            now = int(time.time())
            session = scoped_session(self.session_factory)

            if sent:
                q = session.query(Offer).filter(Offer.was_sent == True).order_by(Offer.created_at.desc())  # noqa E712
            else:
                q = session.query(Offer).filter(Offer.expire_at > now).order_by(Offer.created_at.desc())
            for row in q:
                rv.append(row)
            return rv
        finally:
            session.close()
            session.remove()
            self.mxDB.release()

    def listBids(self, sent=False, offer_id=None, for_html=False):
        self.mxDB.acquire()
        try:
            rv = []
            now = int(time.time())
            session = scoped_session(self.session_factory)
            if offer_id is not None:
                q = session.query(Bid).filter(Bid.offer_id == offer_id)
            elif sent:
                q = session.query(Bid).filter(Bid.was_sent == True).order_by(Bid.created_at.desc())  # noqa E712
            else:
                q = session.query(Bid).filter(Bid.was_received == True).order_by(Bid.created_at.desc())  # noqa E712
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
                rv.append((k, v[0].offer_id.hex(), v[0].state))
            return rv
        finally:
            self.mxDB.release()

    def listWatchedOutputs(self):
        self.mxDB.acquire()
        try:
            rv = []
            rv_heights = []
            for c, v in self.coin_clients.items():
                rv_heights.append((c, v['last_height_checked']))
                for o in v['watched_outputs']:
                    rv.append((c, o[0], o[1], o[2], o[3]))
            return (rv, rv_heights)
        finally:
            self.mxDB.release()

    def callrpc(self, method, params=[], wallet=None):
        return callrpc(self.coin_clients[Coins.PART]['rpcport'], self.coin_clients[Coins.PART]['rpcauth'], method, params, wallet)

    def callcoinrpc(self, coin, method, params=[], wallet=None):
        return callrpc(self.coin_clients[coin]['rpcport'], self.coin_clients[coin]['rpcauth'], method, params, wallet)

    def calltx(self, cmd):
        bindir = self.coin_clients[Coins.PART]['bindir']
        command_cli = os.path.join(bindir, cfg.PARTICL_TX)
        chainname = '' if self.chain == 'mainnet' else (' -' + self.chain)
        args = command_cli + chainname + ' ' + cmd
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        out = p.communicate()
        if len(out[1]) > 0:
            raise ValueError('TX error ' + str(out[1]))
        return out[0].decode('utf-8').strip()
