# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time

from .db import (
    AutomationStrategy,
    BidState,
    Concepts,
    create_table,
    CURRENT_DB_DATA_VERSION,
    CURRENT_DB_VERSION,
    extract_schema,
)

from .basicswap_util import (
    BidStates,
    canAcceptBidState,
    canExpireBidState,
    canTimeoutBidState,
    isActiveBidState,
    isErrorBidState,
    isFailingBidState,
    isFinalBidState,
    strBidState,
)


def addBidState(self, state, now, cursor):
    self.add(
        BidState(
            active_ind=1,
            state_id=int(state),
            in_progress=isActiveBidState(state),
            in_error=isErrorBidState(state),
            swap_failed=isFailingBidState(state),
            swap_ended=isFinalBidState(state),
            can_accept=canAcceptBidState(state),
            can_expire=canExpireBidState(state),
            can_timeout=canTimeoutBidState(state),
            label=strBidState(state),
            created_at=now,
        ),
        cursor,
    )


def upgradeDatabaseData(self, data_version):
    if data_version >= CURRENT_DB_DATA_VERSION:
        return

    self.log.info(
        f"Upgrading database records from version {data_version} to {CURRENT_DB_DATA_VERSION}."
    )

    cursor = self.openDB()
    try:
        now = int(time.time())

        if data_version < 1:
            self.add(
                AutomationStrategy(
                    active_ind=1,
                    label="Accept All",
                    type_ind=Concepts.OFFER,
                    data=json.dumps(
                        {"exact_rate_only": True, "max_concurrent_bids": 5}
                    ).encode("utf-8"),
                    only_known_identities=False,
                    created_at=now,
                ),
                cursor,
            )
            self.add(
                AutomationStrategy(
                    active_ind=1,
                    label="Accept Known",
                    type_ind=Concepts.OFFER,
                    data=json.dumps(
                        {"exact_rate_only": True, "max_concurrent_bids": 5}
                    ).encode("utf-8"),
                    only_known_identities=True,
                    note="Accept bids from identities with previously successful swaps only",
                    created_at=now,
                ),
                cursor,
            )

            for state in BidStates:
                addBidState(self, state, now, cursor)

        if data_version > 0 and data_version < 2:
            for state in (
                BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS,
                BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX,
            ):
                self.add(
                    BidState(
                        active_ind=1,
                        state_id=int(state),
                        in_progress=isActiveBidState(state),
                        label=strBidState(state),
                        created_at=now,
                    ),
                    cursor,
                )
        if data_version > 0 and data_version < 7:
            for state in BidStates:
                in_error = isErrorBidState(state)
                swap_failed = isFailingBidState(state)
                swap_ended = isFinalBidState(state)
                can_accept = canAcceptBidState(state)
                can_expire = canExpireBidState(state)
                can_timeout = canTimeoutBidState(state)
                cursor.execute(
                    "UPDATE bidstates SET can_accept = :can_accept, can_expire = :can_expire, can_timeout = :can_timeout, in_error = :in_error, swap_failed = :swap_failed, swap_ended = :swap_ended WHERE state_id = :state_id",
                    {
                        "in_error": in_error,
                        "swap_failed": swap_failed,
                        "swap_ended": swap_ended,
                        "can_accept": can_accept,
                        "can_expire": can_expire,
                        "can_timeout": can_timeout,
                        "state_id": int(state),
                    },
                )
        if data_version > 0 and data_version < 4:
            for state in (
                BidStates.BID_REQUEST_SENT,
                BidStates.BID_REQUEST_ACCEPTED,
            ):
                addBidState(self, state, now, cursor)

        if data_version > 0 and data_version < 5:
            for state in (
                BidStates.BID_EXPIRED,
                BidStates.BID_AACCEPT_DELAY,
                BidStates.BID_AACCEPT_FAIL,
            ):
                addBidState(self, state, now, cursor)

        self.db_data_version = CURRENT_DB_DATA_VERSION
        self.setIntKV("db_data_version", self.db_data_version, cursor)
        self.commitDB()
        self.log.info(f"Upgraded database records to version {self.db_data_version}")
    finally:
        self.closeDB(cursor, commit=False)


def upgradeDatabase(self, db_version):
    if self._force_db_upgrade is False and db_version >= CURRENT_DB_VERSION:
        return

    self.log.info(
        f"Upgrading database from version {db_version} to {CURRENT_DB_VERSION}."
    )

    # db_version, tablename, oldcolumnname, newcolumnname
    rename_columns = [
        (13, "actions", "event_id", "action_id"),
        (13, "actions", "event_type", "action_type"),
        (13, "actions", "event_data", "action_data"),
        (
            14,
            "xmr_swaps",
            "coin_a_lock_refund_spend_tx_msg_id",
            "coin_a_lock_spend_tx_msg_id",
        ),
    ]

    expect_schema = extract_schema()
    have_tables = {}
    try:
        cursor = self.openDB()

        for rename_column in rename_columns:
            dbv, table_name, colname_from, colname_to = rename_column
            if db_version < dbv:
                cursor.execute(
                    f"ALTER TABLE {table_name} RENAME COLUMN {colname_from} TO {colname_to}"
                )

        query = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        tables = cursor.execute(query).fetchall()
        for table in tables:
            table_name = table[0]
            if table_name in ("sqlite_sequence",):
                continue

            have_table = {}
            have_columns = {}
            query = "SELECT * FROM PRAGMA_TABLE_INFO(:table_name) ORDER BY cid DESC;"
            columns = cursor.execute(query, {"table_name": table_name}).fetchall()
            for column in columns:
                cid, name, data_type, notnull, default_value, primary_key = column
                have_columns[name] = {"type": data_type, "primary_key": primary_key}

            have_table["columns"] = have_columns

            cursor.execute(f"PRAGMA INDEX_LIST('{table_name}');")
            indices = cursor.fetchall()
            for index in indices:
                seq, index_name, unique, origin, partial = index

                if origin == "pk":  # Created by a PRIMARY KEY constraint
                    continue

                cursor.execute(f"PRAGMA INDEX_INFO('{index_name}');")
                index_info = cursor.fetchall()

                add_index = {"index_name": index_name}
                for index_columns in index_info:
                    seqno, cid, name = index_columns
                    if origin == "u":  # Created by a UNIQUE constraint
                        have_columns[name]["unique"] = 1
                    else:
                        if "column_1" not in add_index:
                            add_index["column_1"] = name
                        elif "column_2" not in add_index:
                            add_index["column_2"] = name
                        elif "column_3" not in add_index:
                            add_index["column_3"] = name
                        else:
                            raise RuntimeError("Add more index columns.")
                if origin == "c":
                    if "indices" not in table:
                        have_table["indices"] = []
                    have_table["indices"].append(add_index)

            have_tables[table_name] = have_table

        for table_name, table in expect_schema.items():
            if table_name not in have_tables:
                self.log.info(f"Creating table {table_name}.")
                create_table(cursor, table_name, table)
                continue

            have_table = have_tables[table_name]
            have_columns = have_table["columns"]
            for colname, column in table["columns"].items():
                if colname not in have_columns:
                    col_type = column["type"]
                    self.log.info(f"Adding column {colname} to table {table_name}.")
                    cursor.execute(
                        f"ALTER TABLE {table_name} ADD COLUMN {colname} {col_type}"
                    )
            indices = table.get("indices", [])
            have_indices = have_table.get("indices", [])
            for index in indices:
                index_name = index["index_name"]
                if not any(
                    have_idx.get("index_name") == index_name
                    for have_idx in have_indices
                ):
                    self.log.info(f"Adding index {index_name} to table {table_name}.")
                    column_1 = index["column_1"]
                    column_2 = index.get("column_2", None)
                    column_3 = index.get("column_3", None)
                    query: str = (
                        f"CREATE INDEX {index_name} ON {table_name} ({column_1}"
                    )
                    if column_2:
                        query += f", {column_2}"
                    if column_3:
                        query += f", {column_3}"
                    query += ")"
                    cursor.execute(query)

        if CURRENT_DB_VERSION != db_version:
            self.db_version = CURRENT_DB_VERSION
            self.setIntKV("db_version", CURRENT_DB_VERSION, cursor)
            self.log.info(f"Upgraded database to version {self.db_version}")
        self.commitDB()
    except Exception as e:
        self.log.error(f"Upgrade failed {e}")
        self.rollbackDB()
    finally:
        self.closeDB(cursor, commit=False)
