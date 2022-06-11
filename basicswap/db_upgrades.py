# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

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
    isActiveBidState)


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
                        label=strBidState(state),
                        created_at=now))

            self.db_data_version = CURRENT_DB_DATA_VERSION
            self.setIntKVInSession('db_data_version', self.db_data_version, session)
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
            session.execute('ALTER TABLE bids ADD COLUMN security_token BLOB')
            session.execute('ALTER TABLE offers ADD COLUMN security_token BLOB')
            db_version += 1
        elif current_version == 7:
            session.execute('ALTER TABLE transactions ADD COLUMN block_hash BLOB')
            session.execute('ALTER TABLE transactions ADD COLUMN block_height INTEGER')
            session.execute('ALTER TABLE transactions ADD COLUMN block_time INTEGER')
            db_version += 1
        elif current_version == 8:
            session.execute('''
                CREATE TABLE wallets (
                    record_id INTEGER NOT NULL,
                    coin_id INTEGER,
                    wallet_name VARCHAR,
                    balance_type INTEGER,
                    amount BIGINT,
                    updated_at BIGINT,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))''')
            db_version += 1
        elif current_version == 9:
            session.execute('ALTER TABLE wallets ADD COLUMN wallet_data VARCHAR')
            db_version += 1
        elif current_version == 10:
            session.execute('ALTER TABLE smsgaddresses ADD COLUMN active_ind INTEGER')
            session.execute('ALTER TABLE smsgaddresses ADD COLUMN created_at INTEGER')
            session.execute('ALTER TABLE smsgaddresses ADD COLUMN note VARCHAR')
            session.execute('ALTER TABLE smsgaddresses ADD COLUMN pubkey VARCHAR')
            session.execute('UPDATE smsgaddresses SET active_ind = 1, created_at = 1')

            session.execute('ALTER TABLE offers ADD COLUMN addr_to VARCHAR')
            session.execute(f'UPDATE offers SET addr_to = "{self.network_addr}"')
            db_version += 1
        elif current_version == 11:
            session.execute('ALTER TABLE bids ADD COLUMN chain_a_height_start INTEGER')
            session.execute('ALTER TABLE bids ADD COLUMN chain_b_height_start INTEGER')
            session.execute('ALTER TABLE bids ADD COLUMN protocol_version INTEGER')
            session.execute('ALTER TABLE offers ADD COLUMN protocol_version INTEGER')
            session.execute('ALTER TABLE transactions ADD COLUMN tx_data BLOB')
            db_version += 1
        elif current_version == 12:
            session.execute('''
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
                    PRIMARY KEY (record_id))''')
            session.execute('ALTER TABLE bids ADD COLUMN reject_code INTEGER')
            session.execute('ALTER TABLE bids ADD COLUMN rate INTEGER')
            session.execute('ALTER TABLE offers ADD COLUMN amount_negotiable INTEGER')
            session.execute('ALTER TABLE offers ADD COLUMN rate_negotiable INTEGER')
            db_version += 1
        elif current_version == 13:
            db_version += 1
            session.execute('''
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
                    PRIMARY KEY (record_id))''')

            session.execute('''
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
                    PRIMARY KEY (record_id))''')

            session.execute('''
                CREATE TABLE history (
                    record_id INTEGER NOT NULL,
                    concept_type INTEGER,
                    concept_id INTEGER,
                    changed_data BLOB,

                    note VARCHAR,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))''')

            session.execute('''
                CREATE TABLE bidstates (
                    record_id INTEGER NOT NULL,
                    state_id INTEGER,
                    label VARCHAR,
                    in_progress INTEGER,

                    note VARCHAR,
                    created_at BIGINT,
                    PRIMARY KEY (record_id))''')

            session.execute('ALTER TABLE wallets ADD COLUMN active_ind INTEGER')
            session.execute('ALTER TABLE knownidentities ADD COLUMN active_ind INTEGER')
            session.execute('ALTER TABLE eventqueue RENAME TO actions')

        if current_version != db_version:
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
