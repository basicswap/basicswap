# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time
import sqlalchemy as sa

from enum import IntEnum, auto
from sqlalchemy.orm import declarative_base


CURRENT_DB_VERSION = 24
CURRENT_DB_DATA_VERSION = 4
Base = declarative_base()


class Concepts(IntEnum):
    OFFER = auto()
    BID = auto()
    NETWORK_MESSAGE = auto()
    AUTOMATION = auto()


def strConcepts(state):
    if state == Concepts.OFFER:
        return 'Offer'
    if state == Concepts.BID:
        return 'Bid'
    if state == Concepts.NETWORK_MESSAGE:
        return 'Network Message'
    return 'Unknown'


def pack_state(new_state: int, now: int) -> bytes:
    return int(new_state).to_bytes(4, 'little') + now.to_bytes(8, 'little')


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
    active_ind = sa.Column(sa.Integer)

    protocol_version = sa.Column(sa.Integer)
    coin_from = sa.Column(sa.Integer)
    coin_to = sa.Column(sa.Integer)
    amount_from = sa.Column(sa.BigInteger)
    amount_to = sa.Column(sa.BigInteger)
    rate = sa.Column(sa.BigInteger)
    min_bid_amount = sa.Column(sa.BigInteger)
    time_valid = sa.Column(sa.BigInteger)
    lock_type = sa.Column(sa.Integer)
    lock_value = sa.Column(sa.Integer)
    swap_type = sa.Column(sa.Integer)

    proof_address = sa.Column(sa.String)
    proof_signature = sa.Column(sa.LargeBinary)
    proof_utxos = sa.Column(sa.LargeBinary)
    pkhash_seller = sa.Column(sa.LargeBinary)
    secret_hash = sa.Column(sa.LargeBinary)

    addr_from = sa.Column(sa.String)
    addr_to = sa.Column(sa.String)
    created_at = sa.Column(sa.BigInteger)
    expire_at = sa.Column(sa.BigInteger)
    was_sent = sa.Column(sa.Boolean)  # Sent by node

    from_feerate = sa.Column(sa.BigInteger)
    to_feerate = sa.Column(sa.BigInteger)

    amount_negotiable = sa.Column(sa.Boolean)
    rate_negotiable = sa.Column(sa.Boolean)

    # Local fields
    auto_accept_bids = sa.Column(sa.Boolean)
    withdraw_to_addr = sa.Column(sa.String)  # Address to spend lock tx to - address from wallet if empty TODO
    security_token = sa.Column(sa.LargeBinary)
    bid_reversed = sa.Column(sa.Boolean)

    state = sa.Column(sa.Integer)
    states = sa.Column(sa.LargeBinary)  # Packed states and times

    def setState(self, new_state):
        now = int(time.time())
        self.state = new_state
        if self.states is None:
            self.states = pack_state(new_state, now)
        else:
            self.states += pack_state(new_state, now)


class Bid(Base):
    __tablename__ = 'bids'

    bid_id = sa.Column(sa.LargeBinary, primary_key=True)
    offer_id = sa.Column(sa.LargeBinary, sa.ForeignKey('offers.offer_id'))
    active_ind = sa.Column(sa.Integer)

    protocol_version = sa.Column(sa.Integer)
    was_sent = sa.Column(sa.Boolean)  # Sent by node
    was_received = sa.Column(sa.Boolean)
    contract_count = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)
    expire_at = sa.Column(sa.BigInteger)
    bid_addr = sa.Column(sa.String)
    proof_address = sa.Column(sa.String)
    proof_utxos = sa.Column(sa.LargeBinary)
    withdraw_to_addr = sa.Column(sa.String)  # Address to spend lock tx to - address from wallet if empty TODO

    recovered_secret = sa.Column(sa.LargeBinary)
    amount_to = sa.Column(sa.BigInteger)  # amount * offer.rate

    pkhash_buyer = sa.Column(sa.LargeBinary)
    pkhash_buyer_to = sa.Column(sa.LargeBinary)  # Used for the ptx if coin pubkey hashes differ
    amount = sa.Column(sa.BigInteger)
    rate = sa.Column(sa.BigInteger)

    pkhash_seller = sa.Column(sa.LargeBinary)

    initiate_txn_redeem = sa.Column(sa.LargeBinary)
    initiate_txn_refund = sa.Column(sa.LargeBinary)

    participate_txn_redeem = sa.Column(sa.LargeBinary)
    participate_txn_refund = sa.Column(sa.LargeBinary)

    in_progress = sa.Column(sa.Integer)
    state = sa.Column(sa.Integer)
    state_time = sa.Column(sa.BigInteger)  # Timestamp of last state change
    states = sa.Column(sa.LargeBinary)  # Packed states and times

    state_note = sa.Column(sa.String)

    debug_ind = sa.Column(sa.Integer)
    security_token = sa.Column(sa.LargeBinary)

    chain_a_height_start = sa.Column(sa.Integer)  # Height of script chain before the swap
    chain_b_height_start = sa.Column(sa.Integer)  # Height of scriptless chain before the swap

    reject_code = sa.Column(sa.Integer)

    initiate_tx = None
    participate_tx = None
    xmr_a_lock_tx = None
    xmr_a_lock_spend_tx = None
    xmr_b_lock_tx = None  # TODO: Can't move to txns due to error: Exception UPDATE statement on table expected to update 1 row(s); 0 were matched

    txns = {}

    def getITxState(self):
        if self.initiate_tx is None:
            return None
        return self.initiate_tx.state

    def setITxState(self, new_state):
        if self.initiate_tx is not None:
            self.initiate_tx.setState(new_state)

    def getPTxState(self):
        if self.participate_tx is None:
            return None
        return self.participate_tx.state

    def setPTxState(self, new_state):
        if self.participate_tx is not None:
            self.participate_tx.setState(new_state)

    def setState(self, new_state, state_note=None):
        now = int(time.time())
        self.state = new_state
        self.state_time = now

        if state_note is not None:
            self.state_note = state_note
        if self.states is None:
            self.states = pack_state(new_state, now)
        else:
            self.states += pack_state(new_state, now)

    def getLockTXBVout(self):
        if self.xmr_b_lock_tx:
            return self.xmr_b_lock_tx.vout
        return None


class SwapTx(Base):
    __tablename__ = 'transactions'

    bid_id = sa.Column(sa.LargeBinary, sa.ForeignKey('bids.bid_id'))
    tx_type = sa.Column(sa.Integer)  # TxTypes
    __table_args__ = (
        sa.PrimaryKeyConstraint('bid_id', 'tx_type'),
        {},
    )

    txid = sa.Column(sa.LargeBinary)
    vout = sa.Column(sa.Integer)
    tx_data = sa.Column(sa.LargeBinary)

    script = sa.Column(sa.LargeBinary)

    tx_fee = sa.Column(sa.BigInteger)
    chain_height = sa.Column(sa.Integer)
    conf = sa.Column(sa.Integer)

    spend_txid = sa.Column(sa.LargeBinary)
    spend_n = sa.Column(sa.Integer)

    block_hash = sa.Column(sa.LargeBinary)
    block_height = sa.Column(sa.Integer)
    block_time = sa.Column(sa.BigInteger)

    state = sa.Column(sa.Integer)
    states = sa.Column(sa.LargeBinary)  # Packed states and times

    def setState(self, new_state):
        if self.state == new_state:
            return
        self.state = new_state
        now: int = int(time.time())
        if self.states is None:
            self.states = pack_state(new_state, now)
        else:
            self.states += pack_state(new_state, now)


class PrefundedTx(Base):
    __tablename__ = 'prefunded_transactions'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)
    linked_type = sa.Column(sa.Integer)
    linked_id = sa.Column(sa.LargeBinary)
    tx_type = sa.Column(sa.Integer)  # TxTypes
    tx_data = sa.Column(sa.LargeBinary)
    used_by = sa.Column(sa.LargeBinary)


class PooledAddress(Base):
    __tablename__ = 'addresspool'

    addr_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    coin_type = sa.Column(sa.Integer)
    addr = sa.Column(sa.String)
    bid_id = sa.Column(sa.LargeBinary)
    tx_type = sa.Column(sa.Integer)


class SentOffer(Base):
    __tablename__ = 'sentoffers'

    offer_id = sa.Column(sa.LargeBinary, primary_key=True)


class SmsgAddress(Base):
    __tablename__ = 'smsgaddresses'

    addr_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)
    addr = sa.Column(sa.String, unique=True)
    pubkey = sa.Column(sa.String)
    use_type = sa.Column(sa.Integer)
    note = sa.Column(sa.String)


class Action(Base):
    __tablename__ = 'actions'

    action_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)
    trigger_at = sa.Column(sa.BigInteger)
    linked_id = sa.Column(sa.LargeBinary)
    action_type = sa.Column(sa.Integer)
    action_data = sa.Column(sa.LargeBinary)


class EventLog(Base):
    __tablename__ = 'eventlog'

    event_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)
    linked_type = sa.Column(sa.Integer)
    linked_id = sa.Column(sa.LargeBinary)
    event_type = sa.Column(sa.Integer)
    event_msg = sa.Column(sa.String)

    __table_args__ = (sa.Index('main_index', 'linked_type', 'linked_id'), )


class XmrOffer(Base):
    __tablename__ = 'xmr_offers'
    # TODO: Merge to Offer

    swap_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    offer_id = sa.Column(sa.LargeBinary, sa.ForeignKey('offers.offer_id'))

    a_fee_rate = sa.Column(sa.BigInteger)  # Chain a fee rate
    b_fee_rate = sa.Column(sa.BigInteger)  # Chain b fee rate

    lock_time_1 = sa.Column(sa.Integer)  # Delay before the chain a lock refund tx can be mined
    lock_time_2 = sa.Column(sa.Integer)  # Delay before the follower can spend from the chain a lock refund tx


class XmrSwap(Base):
    __tablename__ = 'xmr_swaps'

    swap_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    bid_id = sa.Column(sa.LargeBinary, sa.ForeignKey('bids.bid_id'))

    contract_count = sa.Column(sa.Integer)

    dest_af = sa.Column(sa.LargeBinary)  # Destination for coin A amount to follower when swap completes successfully

    pkal = sa.Column(sa.LargeBinary)
    pkasl = sa.Column(sa.LargeBinary)

    pkaf = sa.Column(sa.LargeBinary)
    pkasf = sa.Column(sa.LargeBinary)

    vkbvl = sa.Column(sa.LargeBinary)
    vkbsl = sa.Column(sa.LargeBinary)
    pkbvl = sa.Column(sa.LargeBinary)
    pkbsl = sa.Column(sa.LargeBinary)

    vkbvf = sa.Column(sa.LargeBinary)
    vkbsf = sa.Column(sa.LargeBinary)
    pkbvf = sa.Column(sa.LargeBinary)
    pkbsf = sa.Column(sa.LargeBinary)

    kbsl_dleag = sa.Column(sa.LargeBinary)
    kbsf_dleag = sa.Column(sa.LargeBinary)

    vkbv = sa.Column(sa.LargeBinary)        # chain b view private key
    pkbv = sa.Column(sa.LargeBinary)        # chain b view public key
    pkbs = sa.Column(sa.LargeBinary)        # chain b view spend key

    a_lock_tx = sa.Column(sa.LargeBinary)
    a_lock_tx_script = sa.Column(sa.LargeBinary)
    a_lock_tx_id = sa.Column(sa.LargeBinary)
    a_lock_tx_vout = sa.Column(sa.Integer)

    a_lock_refund_tx = sa.Column(sa.LargeBinary)
    a_lock_refund_tx_script = sa.Column(sa.LargeBinary)
    a_lock_refund_tx_id = sa.Column(sa.LargeBinary)
    a_swap_refund_value = sa.Column(sa.BigInteger)
    al_lock_refund_tx_sig = sa.Column(sa.LargeBinary)
    af_lock_refund_tx_sig = sa.Column(sa.LargeBinary)

    a_lock_refund_spend_tx = sa.Column(sa.LargeBinary)
    a_lock_refund_spend_tx_id = sa.Column(sa.LargeBinary)

    af_lock_refund_spend_tx_esig = sa.Column(sa.LargeBinary)
    af_lock_refund_spend_tx_sig = sa.Column(sa.LargeBinary)

    a_lock_spend_tx = sa.Column(sa.LargeBinary)
    a_lock_spend_tx_id = sa.Column(sa.LargeBinary)
    al_lock_spend_tx_esig = sa.Column(sa.LargeBinary)
    kal_sig = sa.Column(sa.LargeBinary)

    a_lock_refund_swipe_tx = sa.Column(sa.LargeBinary)  # Follower spends script coin lock refund tx

    b_lock_tx_id = sa.Column(sa.LargeBinary)


class XmrSplitData(Base):
    __tablename__ = 'xmr_split_data'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    addr_from = sa.Column(sa.String)
    addr_to = sa.Column(sa.String)
    bid_id = sa.Column(sa.LargeBinary)
    msg_type = sa.Column(sa.Integer)
    msg_sequence = sa.Column(sa.Integer)
    dleag = sa.Column(sa.LargeBinary)
    created_at = sa.Column(sa.BigInteger)

    __table_args__ = (sa.UniqueConstraint('bid_id', 'msg_type', 'msg_sequence', name='uc_1'),)


class RevokedMessage(Base):
    __tablename__ = 'revoked_messages'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    msg_id = sa.Column(sa.LargeBinary)
    created_at = sa.Column(sa.BigInteger)
    expires_at = sa.Column(sa.BigInteger)


class Wallets(Base):
    __tablename__ = 'wallets'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    coin_id = sa.Column(sa.Integer)
    wallet_name = sa.Column(sa.String)
    wallet_data = sa.Column(sa.String)
    balance_type = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)


class KnownIdentity(Base):
    __tablename__ = 'knownidentities'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    address = sa.Column(sa.String)
    label = sa.Column(sa.String)
    publickey = sa.Column(sa.LargeBinary)
    num_sent_bids_successful = sa.Column(sa.Integer)
    num_recv_bids_successful = sa.Column(sa.Integer)
    num_sent_bids_rejected = sa.Column(sa.Integer)
    num_recv_bids_rejected = sa.Column(sa.Integer)
    num_sent_bids_failed = sa.Column(sa.Integer)
    num_recv_bids_failed = sa.Column(sa.Integer)
    automation_override = sa.Column(sa.Integer)  # AutomationOverrideOptions
    visibility_override = sa.Column(sa.Integer)  # VisibilityOverrideOptions
    data = sa.Column(sa.LargeBinary)
    note = sa.Column(sa.String)
    updated_at = sa.Column(sa.BigInteger)
    created_at = sa.Column(sa.BigInteger)


class AutomationStrategy(Base):
    __tablename__ = 'automationstrategies'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)

    label = sa.Column(sa.String)
    type_ind = sa.Column(sa.Integer)
    only_known_identities = sa.Column(sa.Integer)
    num_concurrent = sa.Column(sa.Integer)
    data = sa.Column(sa.LargeBinary)

    note = sa.Column(sa.String)
    created_at = sa.Column(sa.BigInteger)


class AutomationLink(Base):
    __tablename__ = 'automationlinks'
    # Contains per order/bid options

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)

    linked_type = sa.Column(sa.Integer)
    linked_id = sa.Column(sa.LargeBinary)
    strategy_id = sa.Column(sa.Integer)

    data = sa.Column(sa.LargeBinary)
    repeat_limit = sa.Column(sa.Integer)
    repeat_count = sa.Column(sa.Integer)

    note = sa.Column(sa.String)
    created_at = sa.Column(sa.BigInteger)

    __table_args__ = (sa.Index('linked_index', 'linked_type', 'linked_id'), )


class History(Base):
    __tablename__ = 'history'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    concept_type = sa.Column(sa.Integer)
    concept_id = sa.Column(sa.Integer)

    changed_data = sa.Column(sa.LargeBinary)
    created_at = sa.Column(sa.BigInteger)


class BidState(Base):
    __tablename__ = 'bidstates'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    state_id = sa.Column(sa.Integer)
    label = sa.Column(sa.String)
    in_progress = sa.Column(sa.Integer)
    in_error = sa.Column(sa.Integer)
    swap_failed = sa.Column(sa.Integer)
    swap_ended = sa.Column(sa.Integer)

    note = sa.Column(sa.String)
    created_at = sa.Column(sa.BigInteger)


class Notification(Base):
    __tablename__ = 'notifications'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)
    event_type = sa.Column(sa.Integer)
    event_data = sa.Column(sa.LargeBinary)


class MessageLink(Base):
    __tablename__ = 'message_links'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    active_ind = sa.Column(sa.Integer)
    created_at = sa.Column(sa.BigInteger)

    linked_type = sa.Column(sa.Integer)
    linked_id = sa.Column(sa.LargeBinary)
    # linked_row_id = sa.Column(sa.Integer)  # TODO: Find a way to use table rowids

    msg_type = sa.Column(sa.Integer)
    msg_sequence = sa.Column(sa.Integer)
    msg_id = sa.Column(sa.LargeBinary)


class CheckedBlock(Base):
    __tablename__ = 'checkedblocks'

    record_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    created_at = sa.Column(sa.BigInteger)
    coin_type = sa.Column(sa.Integer)
    block_height = sa.Column(sa.Integer)
    block_hash = sa.Column(sa.LargeBinary)
    block_time = sa.Column(sa.BigInteger)
