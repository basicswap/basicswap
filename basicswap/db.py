# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import inspect
import sqlite3
import time

from enum import IntEnum, auto
from typing import Optional


CURRENT_DB_VERSION = 27
CURRENT_DB_DATA_VERSION = 6


class Concepts(IntEnum):
    OFFER = auto()
    BID = auto()
    NETWORK_MESSAGE = auto()
    AUTOMATION = auto()


def strConcepts(state):
    if state == Concepts.OFFER:
        return "Offer"
    if state == Concepts.BID:
        return "Bid"
    if state == Concepts.NETWORK_MESSAGE:
        return "Network Message"
    return "Unknown"


def firstOrNone(gen):
    all_rows = list(gen)
    return all_rows[0] if len(all_rows) > 0 else None


def validColumnName(name: str) -> bool:
    if not isinstance(name, str):
        return False
    if len(name) < 1:
        return False
    # First character must be alpha
    if not name[0].isalpha():
        return False
    # Rest can be alphanumeric or underscores
    for c in name[1:]:
        if not c.isalnum() and c != "_":
            return False
    return True


def getOrderByStr(
    filters: dict, default_sort_by: str = "created_at", table_name: str = ""
):
    sort_by = filters.get("sort_by", default_sort_by)
    if not validColumnName(sort_by):
        raise ValueError("Invalid sort by")
    if table_name != "":
        sort_by = table_name + "." + sort_by
    sort_dir = filters.get("sort_dir", "DESC").upper()
    if sort_dir not in ("ASC", "DESC"):
        raise ValueError("Invalid sort dir")
    return f" ORDER BY {sort_by} {sort_dir}"


def pack_state(new_state: int, now: int) -> bytes:
    return int(new_state).to_bytes(4, "little") + now.to_bytes(8, "little")


class Table:
    __sqlite3_table__ = True

    def __init__(self, **kwargs):
        for name, value in kwargs.items():
            if not hasattr(self, name):
                raise ValueError(f"Unknown attribute {name}")
            setattr(self, name, value)
        # Init any unset columns to None
        for mc in inspect.getmembers(self):
            mc_name, mc_obj = mc
            if hasattr(mc_obj, "__sqlite3_column__"):
                setattr(self, mc_name, None)

    def isSet(self, field: str):
        io = getattr(self, field)

        # Column is not set in instance
        if hasattr(io, "__sqlite3_column__"):
            return False
        return True if io is not None else False


class Column:
    __sqlite3_column__ = True

    def __init__(
        self, column_type, primary_key=False, autoincrement=False, unique=False
    ):
        self.column_type = column_type
        self.primary_key = primary_key
        self.autoincrement = autoincrement
        self.unique = unique


class PrimaryKeyConstraint:
    __sqlite3_primary_key__ = True

    def __init__(self, column_1, column_2=None, column_3=None):
        self.column_1 = column_1
        self.column_2 = column_2
        self.column_3 = column_3


class UniqueConstraint:
    __sqlite3_unique__ = True

    def __init__(self, column_1, column_2=None, column_3=None):
        self.column_1 = column_1
        self.column_2 = column_2
        self.column_3 = column_3


class Index:
    __sqlite3_index__ = True

    def __init__(self, name, column_1, column_2=None, column_3=None):
        self.name = name
        self.column_1 = column_1
        self.column_2 = column_2
        self.column_3 = column_3


class DBKVInt(Table):
    __tablename__ = "kv_int"

    key = Column("string", primary_key=True)
    value = Column("integer")


class DBKVString(Table):
    __tablename__ = "kv_string"

    key = Column("string", primary_key=True)
    value = Column("string")


class Offer(Table):
    __tablename__ = "offers"

    offer_id = Column("blob", primary_key=True)
    active_ind = Column("integer")

    protocol_version = Column("integer")
    coin_from = Column("integer")
    coin_to = Column("integer")
    amount_from = Column("integer")
    amount_to = Column("integer")
    rate = Column("integer")
    min_bid_amount = Column("integer")
    time_valid = Column("integer")
    lock_type = Column("integer")
    lock_value = Column("integer")
    swap_type = Column("integer")

    proof_address = Column("string")
    proof_signature = Column("blob")
    proof_utxos = Column("blob")
    pkhash_seller = Column("blob")
    secret_hash = Column("blob")

    addr_from = Column("string")
    addr_to = Column("string")
    created_at = Column("integer")
    expire_at = Column("integer")

    from_feerate = Column("integer")
    to_feerate = Column("integer")

    amount_negotiable = Column("bool")
    rate_negotiable = Column("bool")
    auto_accept_type = Column("integer")

    # Local fields
    auto_accept_bids = Column("bool")
    was_sent = Column("bool")  # Sent by node
    withdraw_to_addr = Column(
        "string"
    )  # Address to spend lock tx to - address from wallet if empty TODO
    security_token = Column("blob")
    bid_reversed = Column("bool")

    state = Column("integer")
    states = Column("blob")  # Packed states and times

    def setState(self, new_state):
        now = int(time.time())
        self.state = new_state
        if self.isSet("states") is False:
            self.states = pack_state(new_state, now)
        else:
            self.states += pack_state(new_state, now)


class Bid(Table):
    __tablename__ = "bids"

    bid_id = Column("blob", primary_key=True)
    offer_id = Column("blob")
    active_ind = Column("integer")
    protocol_version = Column("integer")
    created_at = Column("integer")
    expire_at = Column("integer")
    bid_addr = Column("string")
    proof_address = Column("string")
    proof_utxos = Column("blob")
    # Address to spend lock tx to - address from wallet if empty TODO
    withdraw_to_addr = Column("string")

    recovered_secret = Column("blob")
    amount_to = Column("integer")  # amount * offer.rate

    pkhash_buyer = Column("blob")
    pkhash_buyer_to = Column("blob")  # Used for the ptx if coin pubkey hashes differ
    amount = Column("integer")
    rate = Column("integer")

    pkhash_seller = Column("blob")

    initiate_txn_redeem = Column("blob")
    initiate_txn_refund = Column("blob")

    participate_txn_redeem = Column("blob")
    participate_txn_refund = Column("blob")

    in_progress = Column("integer")
    state = Column("integer")
    state_time = Column("integer")  # Timestamp of last state change
    states = Column("blob")  # Packed states and times

    state_note = Column("string")
    was_sent = Column("bool")  # Sent by node
    was_received = Column("bool")
    contract_count = Column("integer")
    debug_ind = Column("integer")
    security_token = Column("blob")

    chain_a_height_start = Column("integer")  # Height of script chain before the swap
    # Height of scriptless chain before the swap
    chain_b_height_start = Column("integer")

    reject_code = Column("integer")

    initiate_tx = None
    participate_tx = None
    xmr_a_lock_tx = None
    xmr_a_lock_spend_tx = None
    xmr_b_lock_tx = None  # TODO: Can't move to txns due to error: Exception UPDATE statement on table expected to update 1 row(s); 0 were matched

    txns = {}

    def getITxState(self):
        if self.isSet("initiate_tx") is False:
            return None
        return self.initiate_tx.state

    def setITxState(self, new_state):
        if self.isSet("initiate_tx"):
            self.initiate_tx.setState(new_state)

    def getPTxState(self):
        if self.isSet("participate_tx") is False:
            return None
        return self.participate_tx.state

    def setPTxState(self, new_state):
        if self.isSet("participate_tx"):
            self.participate_tx.setState(new_state)

    def setState(self, new_state, state_note=None):
        now = int(time.time())
        self.state = new_state
        self.state_time = now

        if self.isSet("state_note"):
            self.state_note = state_note
        if self.isSet("states") is False:
            self.states = pack_state(new_state, now)
        else:
            self.states += pack_state(new_state, now)

    def getLockTXBVout(self):
        if self.isSet("xmr_b_lock_tx"):
            return self.xmr_b_lock_tx.vout
        return None


class SwapTx(Table):
    __tablename__ = "transactions"

    bid_id = Column("blob")
    tx_type = Column("integer")  # TxTypes

    txid = Column("blob")
    vout = Column("integer")
    tx_data = Column("blob")

    script = Column("blob")

    tx_fee = Column("integer")
    chain_height = Column("integer")
    conf = Column("integer")

    spend_txid = Column("blob")
    spend_n = Column("integer")

    block_hash = Column("blob")
    block_height = Column("integer")
    block_time = Column("integer")

    state = Column("integer")
    states = Column("blob")  # Packed states and times

    primary_key = PrimaryKeyConstraint("bid_id", "tx_type")

    def setState(self, new_state):
        if self.state == new_state:
            return
        self.state = new_state
        now: int = int(time.time())
        if self.isSet("states") is False:
            self.states = pack_state(new_state, now)
        else:
            self.states += pack_state(new_state, now)


class PrefundedTx(Table):
    __tablename__ = "prefunded_transactions"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    created_at = Column("integer")
    linked_type = Column("integer")
    linked_id = Column("blob")
    tx_type = Column("integer")  # TxTypes
    tx_data = Column("blob")
    used_by = Column("blob")


class PooledAddress(Table):
    __tablename__ = "addresspool"

    addr_id = Column("integer", primary_key=True, autoincrement=True)
    coin_type = Column("integer")
    addr = Column("string")
    bid_id = Column("blob")
    tx_type = Column("integer")


class SentOffer(Table):
    __tablename__ = "sentoffers"

    offer_id = Column("blob", primary_key=True)


class SmsgAddress(Table):
    __tablename__ = "smsgaddresses"

    addr_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    created_at = Column("integer")
    addr = Column("string", unique=True)
    pubkey = Column("string")
    use_type = Column("integer")
    note = Column("string")


class Action(Table):
    __tablename__ = "actions"

    action_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    created_at = Column("integer")
    trigger_at = Column("integer")
    linked_id = Column("blob")
    action_type = Column("integer")
    action_data = Column("blob")


class EventLog(Table):
    __tablename__ = "eventlog"

    event_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    created_at = Column("integer")
    linked_type = Column("integer")
    linked_id = Column("blob")
    event_type = Column("integer")
    event_msg = Column("string")

    index = Index("main_index", "linked_type", "linked_id")


class XmrOffer(Table):
    __tablename__ = "xmr_offers"
    # TODO: Merge to Offer

    swap_id = Column("integer", primary_key=True, autoincrement=True)
    offer_id = Column("blob")

    a_fee_rate = Column("integer")  # Chain a fee rate
    b_fee_rate = Column("integer")  # Chain b fee rate

    # Delay before the chain a lock refund tx can be mined
    lock_time_1 = Column("integer")
    # Delay before the follower can spend from the chain a lock refund tx
    lock_time_2 = Column("integer")


class XmrSwap(Table):
    __tablename__ = "xmr_swaps"

    swap_id = Column("integer", primary_key=True, autoincrement=True)
    bid_id = Column("blob")

    contract_count = Column("integer")

    # Destination for coin A amount to follower when swap completes successfully
    dest_af = Column("blob")

    pkal = Column("blob")
    pkasl = Column("blob")

    pkaf = Column("blob")
    pkasf = Column("blob")

    vkbvl = Column("blob")
    vkbsl = Column("blob")
    pkbvl = Column("blob")
    pkbsl = Column("blob")

    vkbvf = Column("blob")
    vkbsf = Column("blob")
    pkbvf = Column("blob")
    pkbsf = Column("blob")

    kbsl_dleag = Column("blob")
    kbsf_dleag = Column("blob")

    vkbv = Column("blob")  # chain b view private key
    pkbv = Column("blob")  # chain b view public key
    pkbs = Column("blob")  # chain b spend public key

    a_lock_tx = Column("blob")
    a_lock_tx_script = Column("blob")
    a_lock_tx_id = Column("blob")
    a_lock_tx_vout = Column("integer")

    a_lock_refund_tx = Column("blob")
    a_lock_refund_tx_script = Column("blob")
    a_lock_refund_tx_id = Column("blob")
    a_swap_refund_value = Column("integer")
    al_lock_refund_tx_sig = Column("blob")
    af_lock_refund_tx_sig = Column("blob")

    a_lock_refund_spend_tx = Column("blob")
    a_lock_refund_spend_tx_id = Column("blob")

    af_lock_refund_spend_tx_esig = Column("blob")
    af_lock_refund_spend_tx_sig = Column("blob")

    a_lock_spend_tx = Column("blob")
    a_lock_spend_tx_id = Column("blob")
    al_lock_spend_tx_esig = Column("blob")
    kal_sig = Column("blob")

    # Follower spends script coin lock refund tx
    a_lock_refund_swipe_tx = Column("blob")

    b_lock_tx_id = Column("blob")


class XmrSplitData(Table):
    __tablename__ = "xmr_split_data"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    addr_from = Column("string")
    addr_to = Column("string")
    bid_id = Column("blob")
    msg_type = Column("integer")
    msg_sequence = Column("integer")
    dleag = Column("blob")
    created_at = Column("integer")

    uc_1 = UniqueConstraint("bid_id", "msg_type", "msg_sequence")


class RevokedMessage(Table):
    __tablename__ = "revoked_messages"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    msg_id = Column("blob")
    created_at = Column("integer")
    expires_at = Column("integer")


class Wallets(Table):
    __tablename__ = "wallets"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    coin_id = Column("integer")
    wallet_name = Column("string")
    wallet_data = Column("string")
    balance_type = Column("integer")
    created_at = Column("integer")


class KnownIdentity(Table):
    __tablename__ = "knownidentities"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    address = Column("string")
    label = Column("string")
    publickey = Column("blob")
    num_sent_bids_successful = Column("integer")
    num_recv_bids_successful = Column("integer")
    num_sent_bids_rejected = Column("integer")
    num_recv_bids_rejected = Column("integer")
    num_sent_bids_failed = Column("integer")
    num_recv_bids_failed = Column("integer")
    automation_override = Column("integer")  # AutomationOverrideOptions
    visibility_override = Column("integer")  # VisibilityOverrideOptions
    data = Column("blob")
    note = Column("string")
    updated_at = Column("integer")
    created_at = Column("integer")


class AutomationStrategy(Table):
    __tablename__ = "automationstrategies"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")

    label = Column("string")
    type_ind = Column("integer")
    only_known_identities = Column("integer")
    num_concurrent = Column("integer")  # Deprecated, use data["max_concurrent"]
    data = Column("blob")

    note = Column("string")
    created_at = Column("integer")


class AutomationLink(Table):
    __tablename__ = "automationlinks"
    # Contains per order/bid options

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")

    linked_type = Column("integer")
    linked_id = Column("blob")
    strategy_id = Column("integer")

    data = Column("blob")
    repeat_limit = Column("integer")
    repeat_count = Column("integer")

    note = Column("string")
    created_at = Column("integer")

    index = Index("linked_index", "linked_type", "linked_id")


class History(Table):
    __tablename__ = "history"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    concept_type = Column("integer")
    concept_id = Column("integer")

    changed_data = Column("blob")
    created_at = Column("integer")


class BidState(Table):
    __tablename__ = "bidstates"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    state_id = Column("integer")
    label = Column("string")
    in_progress = Column("integer")
    in_error = Column("integer")
    swap_failed = Column("integer")
    swap_ended = Column("integer")
    can_accept = Column("integer")

    note = Column("string")
    created_at = Column("integer")


class Notification(Table):
    __tablename__ = "notifications"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    created_at = Column("integer")
    event_type = Column("integer")
    event_data = Column("blob")


class MessageLink(Table):
    __tablename__ = "message_links"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    active_ind = Column("integer")
    created_at = Column("integer")

    linked_type = Column("integer")
    linked_id = Column("blob")
    # linked_row_id = sa.Column(sa.Integer)  # TODO: Find a way to use table rowids

    msg_type = Column("integer")
    msg_sequence = Column("integer")
    msg_id = Column("blob")


class CheckedBlock(Table):
    __tablename__ = "checkedblocks"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    created_at = Column("integer")
    coin_type = Column("integer")
    block_height = Column("integer")
    block_hash = Column("blob")
    block_time = Column("integer")


class CoinRates(Table):
    __tablename__ = "coinrates"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    currency_from = Column("integer")
    currency_to = Column("integer")
    rate = Column("string")
    source = Column("string")
    last_updated = Column("integer")


def create_db(db_path: str, log) -> None:
    con = None
    try:
        con = sqlite3.connect(db_path)
        c = con.cursor()

        g = globals().copy()
        for name, obj in g.items():
            if not inspect.isclass(obj):
                continue
            if not hasattr(obj, "__sqlite3_table__"):
                continue
            if not hasattr(obj, "__tablename__"):
                continue

            table_name: str = obj.__tablename__
            query: str = f"CREATE TABLE {table_name} ("

            primary_key = None
            constraints = []
            indices = []
            num_columns: int = 0
            for m in inspect.getmembers(obj):
                m_name, m_obj = m

                if hasattr(m_obj, "__sqlite3_primary_key__"):
                    primary_key = m_obj
                    continue
                if hasattr(m_obj, "__sqlite3_unique__"):
                    constraints.append(m_obj)
                    continue
                if hasattr(m_obj, "__sqlite3_index__"):
                    indices.append(m_obj)
                    continue
                if hasattr(m_obj, "__sqlite3_column__"):
                    if num_columns > 0:
                        query += ","

                    col_type: str = m_obj.column_type.upper()
                    if col_type == "BOOL":
                        col_type = "INTEGER"
                    query += f" {m_name} {col_type} "

                    if m_obj.primary_key:
                        query += "PRIMARY KEY ASC "
                    if m_obj.unique:
                        query += "UNIQUE "
                    num_columns += 1

            if primary_key is not None:
                query += f", PRIMARY KEY ({primary_key.column_1}"
                if primary_key.column_2:
                    query += f", {primary_key.column_2}"
                if primary_key.column_3:
                    query += f", {primary_key.column_3}"
                query += ") "

            for constraint in constraints:
                query += f", UNIQUE ({constraint.column_1}"
                if constraint.column_2:
                    query += f", {constraint.column_2}"
                if constraint.column_3:
                    query += f", {constraint.column_3}"
                query += ") "

            query += ")"
            c.execute(query)
            for i in indices:
                query: str = f"CREATE INDEX {i.name} ON {table_name} ({i.column_1}"
                if i.column_2 is not None:
                    query += f", {i.column_2}"
                if i.column_3 is not None:
                    query += f", {i.column_3}"
                query += ")"
                c.execute(query)

        con.commit()
    finally:
        if con:
            con.close()


class DBMethods:
    def openDB(self, cursor=None):
        if cursor:
            # assert(self._thread_debug == threading.get_ident())
            assert self.mxDB.locked()
            return cursor

        self.mxDB.acquire()
        # self._thread_debug = threading.get_ident()
        self._db_con = sqlite3.connect(self.sqlite_file)
        return self._db_con.cursor()

    def getNewDBCursor(self):
        assert self.mxDB.locked()
        return self._db_con.cursor()

    def commitDB(self):
        assert self.mxDB.locked()
        self._db_con.commit()

    def rollbackDB(self):
        assert self.mxDB.locked()
        self._db_con.rollback()

    def closeDBCursor(self, cursor):
        assert self.mxDB.locked()
        if cursor:
            cursor.close()

    def closeDB(self, cursor, commit=True):
        assert self.mxDB.locked()

        if commit:
            self._db_con.commit()

        cursor.close()
        self._db_con.close()
        self.mxDB.release()

    def setIntKV(self, str_key: str, int_val: int, cursor=None) -> None:
        try:
            use_cursor = self.openDB(cursor)
            use_cursor.execute(
                """INSERT INTO kv_int (key, value)
                   VALUES (:key, :value)
                   ON CONFLICT(key)
                   DO UPDATE SET value=:value
                   WHERE key=:key;""",
                {
                    "key": str_key,
                    "value": int(int_val),
                },
            )
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def getIntKV(
        self,
        str_key: str,
        cursor=None,
        default_val: int = None,
        update_if_default: bool = True,
    ) -> Optional[int]:
        try:
            use_cursor = self.openDB(cursor)
            rows = use_cursor.execute(
                "SELECT value FROM kv_int WHERE key = :key", {"key": str_key}
            ).fetchall()
            return rows[0][0]
        except Exception as e:
            if default_val is not None:
                if update_if_default:
                    use_cursor.execute(
                        """INSERT INTO kv_int (key, value)
                           VALUES (:key, :value)""",
                        {
                            "key": str_key,
                            "value": int(default_val),
                        },
                    )
                return default_val
            else:
                raise e
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def setStringKV(self, str_key: str, str_val: str, cursor=None) -> None:
        try:
            use_cursor = self.openDB(cursor)
            use_cursor.execute(
                """INSERT INTO kv_string (key, value)
                   VALUES (:key, :value)
                   ON CONFLICT(key)
                   DO UPDATE SET value=:value""",
                {
                    "key": str_key,
                    "value": str_val,
                },
            )
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def getStringKV(self, str_key: str, cursor=None) -> Optional[str]:
        try:
            use_cursor = self.openDB(cursor)
            rows = use_cursor.execute(
                "SELECT value FROM kv_string WHERE key = :key", {"key": str_key}
            ).fetchall()
            if len(rows) < 1:
                return None
            return rows[0][0]
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def clearStringKV(self, str_key: str, cursor=None) -> None:
        try:
            use_cursor = self.openDB(cursor)
            use_cursor.execute(
                "DELETE FROM kv_string WHERE key = :key", {"key": str_key}
            )
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def add(self, obj, cursor, upsert: bool = False):
        if cursor is None:
            raise ValueError("Cursor is null")
        if not hasattr(obj, "__tablename__"):
            raise ValueError("Adding invalid object")
        table_name: str = obj.__tablename__

        values = {}
        query: str = f"INSERT INTO {table_name} ("

        # See if the instance overwrote any class methods
        for mc in inspect.getmembers(obj.__class__):
            mc_name, mc_obj = mc

            if not hasattr(mc_obj, "__sqlite3_column__"):
                continue

            m_obj = getattr(obj, mc_name)

            # Column is not set in instance
            if hasattr(m_obj, "__sqlite3_column__"):
                continue

            values[mc_name] = m_obj

        query_values: str = " VALUES ("
        for i, key in enumerate(values):
            if i > 0:
                query += ", "
                query_values += ", "
            query += key
            query_values += ":" + key
        query += ") " + query_values + ")"

        if upsert:
            query += " ON CONFLICT DO UPDATE SET "
            for i, key in enumerate(values):
                if not validColumnName(key):
                    raise ValueError(f"Invalid column: {key}")
                if i > 0:
                    query += ", "
                query += f"{key}=:{key}"

        cursor.execute(query, values)

    def query(
        self,
        table_class,
        cursor,
        constraints={},
        order_by={},
        query_suffix=None,
        extra_query_data={},
    ):
        if cursor is None:
            raise ValueError("Cursor is null")
        if not hasattr(table_class, "__tablename__"):
            raise ValueError("Querying invalid class")
        table_name: str = table_class.__tablename__

        query: str = "SELECT "

        columns = []

        for mc in inspect.getmembers(table_class):
            mc_name, mc_obj = mc

            if not hasattr(mc_obj, "__sqlite3_column__"):
                continue

            if len(columns) > 0:
                query += ", "
            query += mc_name
            columns.append((mc_name, mc_obj.column_type))

        query += f" FROM {table_name} WHERE 1=1 "

        for ck in constraints:
            if not validColumnName(ck):
                raise ValueError(f"Invalid constraint column: {ck}")
            query += f" AND {ck} = :{ck} "

        for order_col, order_dir in order_by.items():
            if validColumnName(order_col) is False:
                raise ValueError(f"Invalid sort by: {order_col}")
            order_dir = order_dir.upper()
            if order_dir not in ("ASC", "DESC"):
                raise ValueError(f"Invalid sort dir: {order_dir}")
            query += f" ORDER BY {order_col} {order_dir}"

        if query_suffix:
            query += query_suffix

        query_data = constraints.copy()
        query_data.update(extra_query_data)
        rows = cursor.execute(query, query_data)
        for row in rows:
            obj = table_class()
            for i, column_info in enumerate(columns):
                colname, coltype = column_info
                value = row[i]
                if coltype == "bool":
                    if row[i] is not None:
                        value = False if row[i] == 0 else True
                setattr(obj, colname, value)
            yield obj

    def queryOne(
        self,
        table_class,
        cursor,
        constraints={},
        order_by={},
        query_suffix=None,
        extra_query_data={},
    ):
        return firstOrNone(
            self.query(
                table_class,
                cursor,
                constraints,
                order_by,
                query_suffix,
                extra_query_data,
            )
        )

    def updateDB(self, obj, cursor, constraints=[]):
        if cursor is None:
            raise ValueError("Cursor is null")
        if not hasattr(obj, "__tablename__"):
            raise ValueError("Updating invalid obj")
        table_name: str = obj.__tablename__

        query: str = f"UPDATE {table_name} SET "

        values = {}
        for mc in inspect.getmembers(obj.__class__):
            mc_name, mc_obj = mc

            if not hasattr(mc_obj, "__sqlite3_column__"):
                continue

            m_obj = getattr(obj, mc_name)
            # Column is not set in instance
            if hasattr(m_obj, "__sqlite3_column__"):
                continue

            if mc_name in constraints:
                values[mc_name] = m_obj
                continue

            if len(values) > 0:
                query += ", "
            query += f"{mc_name} = :{mc_name}"
            values[mc_name] = m_obj

        query += " WHERE 1=1 "

        for ck in constraints:
            query += f" AND {ck} = :{ck} "

        cursor.execute(query, values)
