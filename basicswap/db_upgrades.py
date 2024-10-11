# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

from sqlalchemy.sql import text
from sqlalchemy.orm import scoped_session
from .db import (
    BidState,
    Concepts,
    AutomationStrategy,
    CURRENT_DB_VERSION,
    CURRENT_DB_DATA_VERSION)

from .basicswap_util import (
    BidStates,
    strBidState,
    isActiveBidState,
    isErrorBidState,
    isFailingBidState,
    isFinalBidState,
)


def upgradeDatabaseData(self, data_version):
    if data_version >= CURRENT_DB_DATA_VERSION:
        return

    self.log.info('Upgrading database records from version %d to %d.', data_version, CURRENT_DB_DATA_VERSION)
    with self.mxDB:
        try:
            session = scoped_session(self.session_factory)

            now = int(time.time())

            if data_version < 1:
                session.add(AutomationStrategy(
                    active_ind=1,
                    label='Accept All',
                    type_ind=Concepts.OFFER,
                    data=json.dumps({'exact_rate_only': True,
                                     'max_concurrent_bids': 5}).encode('utf-8'),
                    only_known_identities=False,
                    created_at=now))
                session.add(AutomationStrategy(
                    active_ind=1,
                    label='Accept Known',
                    type_ind=Concepts.OFFER,
                    data=json.dumps({'exact_rate_only': True,
                                     'max_concurrent_bids': 5}).encode('utf-8'),
                    only_known_identities=True,
                    note='Accept bids from identities with previously successful swaps only',
                    created_at=now))

                for state in BidStates:
                    session.add(BidState(
                        active_ind=1,
                        state_id=int(state),
                        in_progress=isActiveBidState(state),
                        in_error=isErrorBidState(state),
                        swap_failed=isFailingBidState(state),
                        swap_ended=isFinalBidState(state),
                        label=strBidState(state),
                        created_at=now))

            if data_version > 0 and data_version < 2:
                for state in (BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS, BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX):
                    session.add(BidState(
                        active_ind=1,
                        state_id=int(state),
                        in_progress=isActiveBidState(state),
                        label=strBidState(state),
                        created_at=now))
            if data_version > 0 and data_version < 3:
                for state in BidStates:
                    in_error = isErrorBidState(state)
                    swap_failed = isFailingBidState(state)
                    swap_ended = isFinalBidState(state)
                    session.execute(text('UPDATE bidstates SET in_error = :in_error, swap_failed = :swap_failed, swap_ended = :swap_ended WHERE state_id = :state_id', {'in_error': in_error, 'swap_failed': swap_failed, 'swap_ended': swap_ended, 'state_id': int(state)}))
            if data_version > 0 and data_version < 4:
                for state in (BidStates.BID_REQUEST_SENT, BidStates.BID_REQUEST_ACCEPTED):
                    session.add(BidState(
                        active_ind=1,
                        state_id=int(state),
                        in_progress=isActiveBidState(state),
                        in_error=isErrorBidState(state),
                        swap_failed=isFailingBidState(state),
                        swap_ended=isFinalBidState(state),
                        label=strBidState(state),
                        created_at=now))

            self.db_data_version = CURRENT_DB_DATA_VERSION
            self.setIntKV('db_data_version', self.db_data_version, session)
            session.commit()
            self.log.info('Upgraded database records to version {}'.format(self.db_data_version))
        finally:
            session.close()
            session.remove()


def upgradeDatabase(self, db_version):
    if db_version >= CURRENT_DB_VERSION:
        return

    self.log.info('Upgrading database from version %d to %d.', db_version, CURRENT_DB_VERSION)

    while True:
        session = scoped_session(self.session_factory)

        current_version = db_version
        if current_version == 6:
            session.execute(text('ALTER TABLE bids ADD COLUMN security_token BLOB'))
            session.execute(text('ALTER TABLE offers ADD COLUMN security_token BLOB'))
            db_version += 1
        elif current_version == 7:
            session.execute(text('ALTER TABLE transactions ADD COLUMN block_hash BLOB'))
            session.execute(text('ALTER TABLE transactions ADD COLUMN block_height INTEGER'))
            session.execute(text('ALTER TABLE transactions ADD COLUMN block_time INTEGER'))
            db_version += 1
        elif current_version == 8:
            session.execute(text('''
                CREATE TABLE wallets (
                    record_id INTEGER NOT NULL,
                    coin_id INTEGER,
                    wallet_name VARCHAR,
                    wallet_data VARCHAR,
                    balance_type INTEGER,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))'''))
            db_version += 1
        elif current_version == 9:
            session.execute(text('ALTER TABLE wallets ADD COLUMN wallet_data VARCHAR'))
            db_version += 1
        elif current_version == 10:
            session.execute(text('ALTER TABLE smsgaddresses ADD COLUMN active_ind INTEGER'))
            session.execute(text('ALTER TABLE smsgaddresses ADD COLUMN created_at INTEGER'))
            session.execute(text('ALTER TABLE smsgaddresses ADD COLUMN note VARCHAR'))
            session.execute(text('ALTER TABLE smsgaddresses ADD COLUMN pubkey VARCHAR'))
            session.execute(text('UPDATE smsgaddresses SET active_ind = 1, created_at = 1'))

            session.execute(text('ALTER TABLE offers ADD COLUMN addr_to VARCHAR'))
            session.execute(text(f'UPDATE offers SET addr_to = "{self.network_addr}"'))
            db_version += 1
        elif current_version == 11:
            session.execute(text('ALTER TABLE bids ADD COLUMN chain_a_height_start INTEGER'))
            session.execute(text('ALTER TABLE bids ADD COLUMN chain_b_height_start INTEGER'))
            session.execute(text('ALTER TABLE bids ADD COLUMN protocol_version INTEGER'))
            session.execute(text('ALTER TABLE offers ADD COLUMN protocol_version INTEGER'))
            session.execute(text('ALTER TABLE transactions ADD COLUMN tx_data BLOB'))
            db_version += 1
        elif current_version == 12:
            session.execute(text('''
                CREATE TABLE knownidentities (
                    record_id INTEGER NOT NULL,
                    address VARCHAR,
                    label VARCHAR,
                    publickey BLOB,
                    num_sent_bids_successful INTEGER,
                    num_recv_bids_successful INTEGER,
                    num_sent_bids_rejected INTEGER,
                    num_recv_bids_rejected INTEGER,
                    num_sent_bids_failed INTEGER,
                    num_recv_bids_failed INTEGER,
                    note VARCHAR,
                    updated_at BIGINT,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))'''))
            session.execute(text('ALTER TABLE bids ADD COLUMN reject_code INTEGER'))
            session.execute(text('ALTER TABLE bids ADD COLUMN rate INTEGER'))
            session.execute(text('ALTER TABLE offers ADD COLUMN amount_negotiable INTEGER'))
            session.execute(text('ALTER TABLE offers ADD COLUMN rate_negotiable INTEGER'))
            db_version += 1
        elif current_version == 13:
            db_version += 1
            session.execute(text('''
                CREATE TABLE automationstrategies (
                    record_id INTEGER NOT NULL,
                    active_ind INTEGER,
                    label VARCHAR,
                    type_ind INTEGER,
                    only_known_identities INTEGER,
                    num_concurrent INTEGER,
                    data BLOB,

                    note VARCHAR,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))'''))

            session.execute(text('''
                CREATE TABLE automationlinks (
                    record_id INTEGER NOT NULL,
                    active_ind INTEGER,

                    linked_type INTEGER,
                    linked_id BLOB,
                    strategy_id INTEGER,

                    data BLOB,
                    repeat_limit INTEGER,
                    repeat_count INTEGER,

                    note VARCHAR,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))'''))

            session.execute(text('''
                CREATE TABLE history (
                    record_id INTEGER NOT NULL,
                    concept_type INTEGER,
                    concept_id INTEGER,
                    changed_data BLOB,

                    note VARCHAR,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))'''))

            session.execute(text('''
                CREATE TABLE bidstates (
                    record_id INTEGER NOT NULL,
                    active_ind INTEGER,
                    state_id INTEGER,
                    label VARCHAR,
                    in_progress INTEGER,

                    note VARCHAR,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))'''))

            session.execute(text('ALTER TABLE wallets ADD COLUMN active_ind INTEGER'))
            session.execute(text('ALTER TABLE knownidentities ADD COLUMN active_ind INTEGER'))
            session.execute(text('ALTER TABLE eventqueue RENAME TO actions'))
            session.execute(text('ALTER TABLE actions RENAME COLUMN event_id TO action_id'))
            session.execute(text('ALTER TABLE actions RENAME COLUMN event_type TO action_type'))
            session.execute(text('ALTER TABLE actions RENAME COLUMN event_data TO action_data'))
        elif current_version == 14:
            db_version += 1
            session.execute(text('ALTER TABLE xmr_swaps ADD COLUMN coin_a_lock_release_msg_id BLOB'))
            session.execute(text('ALTER TABLE xmr_swaps RENAME COLUMN coin_a_lock_refund_spend_tx_msg_id TO coin_a_lock_spend_tx_msg_id'))
        elif current_version == 15:
            db_version += 1
            session.execute(text('''
                CREATE TABLE notifications (
                    record_id INTEGER NOT NULL,
                    active_ind INTEGER,
                    event_type INTEGER,
                    event_data BLOB,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))'''))
        elif current_version == 16:
            db_version += 1
            session.execute(text('''
                CREATE TABLE prefunded_transactions (
                    record_id INTEGER NOT NULL,
                    active_ind INTEGER,
                    created_at BIGINT,
                    linked_type INTEGER,
                    linked_id BLOB,
                    tx_type INTEGER,
                    tx_data BLOB,
                    used_by BLOB,
                    PRIMARY KEY (record_id))'''))
        elif current_version == 17:
            db_version += 1
            session.execute(text('ALTER TABLE knownidentities ADD COLUMN automation_override INTEGER'))
            session.execute(text('ALTER TABLE knownidentities ADD COLUMN visibility_override INTEGER'))
            session.execute(text('ALTER TABLE knownidentities ADD COLUMN data BLOB'))
            session.execute(text('UPDATE knownidentities SET active_ind = 1'))
        elif current_version == 18:
            db_version += 1
            session.execute(text('ALTER TABLE xmr_split_data ADD COLUMN addr_from STRING'))
            session.execute(text('ALTER TABLE xmr_split_data ADD COLUMN addr_to STRING'))
        elif current_version == 19:
            db_version += 1
            session.execute(text('ALTER TABLE bidstates ADD COLUMN in_error INTEGER'))
            session.execute(text('ALTER TABLE bidstates ADD COLUMN swap_failed INTEGER'))
            session.execute(text('ALTER TABLE bidstates ADD COLUMN swap_ended INTEGER'))
        elif current_version == 20:
            db_version += 1
            session.execute(text('''
                CREATE TABLE message_links (
                    record_id INTEGER NOT NULL,
                    active_ind INTEGER,
                    created_at BIGINT,

                    linked_type INTEGER,
                    linked_id BLOB,

                    msg_type INTEGER,
                    msg_sequence INTEGER,
                    msg_id BLOB,
                    PRIMARY KEY (record_id))'''))
            session.execute(text('ALTER TABLE offers ADD COLUMN bid_reversed INTEGER'))
        elif current_version == 21:
            db_version += 1
            session.execute(text('ALTER TABLE offers ADD COLUMN proof_utxos BLOB'))
            session.execute(text('ALTER TABLE bids ADD COLUMN proof_utxos BLOB'))
        elif current_version == 22:
            db_version += 1
            session.execute(text('ALTER TABLE offers ADD COLUMN amount_to INTEGER'))
        elif current_version == 23:
            db_version += 1
            session.execute(text('''
                CREATE TABLE checkedblocks (
                    record_id INTEGER NOT NULL,
                    created_at BIGINT,
                    coin_type INTEGER,
                    block_height INTEGER,
                    block_hash BLOB,
                    block_time INTEGER,
                    PRIMARY KEY (record_id))'''))
            session.execute(text('ALTER TABLE bids ADD COLUMN pkhash_buyer_to BLOB'))
        if current_version != db_version:
            self.db_version = db_version
            self.setIntKV('db_version', db_version, session)
            session.commit()
            session.close()
            session.remove()
            self.log.info('Upgraded database to version {}'.format(self.db_version))
            continue
        break

    if db_version != CURRENT_DB_VERSION:
        raise ValueError('Unable to upgrade database.')
