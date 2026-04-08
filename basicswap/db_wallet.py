# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


from .db import Column, Index, Table, UniqueConstraint, extract_schema


class WalletAddress(Table):

    __tablename__ = "wallet_addresses"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    coin_type = Column("integer")
    derivation_index = Column("integer")
    is_internal = Column("bool")
    derivation_path = Column("string")
    address = Column("string")
    scripthash = Column("string")
    pubkey = Column("blob")
    is_funded = Column("bool")
    cached_balance = Column("integer")
    cached_balance_time = Column("integer")
    first_seen_height = Column("integer")
    created_at = Column("integer")

    __unique_1__ = UniqueConstraint("coin_type", "derivation_index", "is_internal")
    __index_address__ = Index("idx_wallet_address", "address")
    __index_scripthash__ = Index("idx_wallet_scripthash", "scripthash")
    __index_funded__ = Index("idx_wallet_funded", "coin_type", "is_funded")


class WalletState(Table):

    __tablename__ = "wallet_state"

    coin_type = Column("integer", primary_key=True)
    last_external_index = Column("integer")
    last_internal_index = Column("integer")
    derivation_path_type = Column("string")
    last_sync_height = Column("integer")
    migration_complete = Column("bool")
    created_at = Column("integer")
    updated_at = Column("integer")


class WalletWatchOnly(Table):

    __tablename__ = "wallet_watch_only"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    coin_type = Column("integer")
    address = Column("string")
    scripthash = Column("string")
    label = Column("string")
    source = Column("string")
    is_funded = Column("bool")
    cached_balance = Column("integer")
    cached_balance_time = Column("integer")
    private_key_encrypted = Column("blob")
    created_at = Column("integer")

    __unique_1__ = UniqueConstraint("coin_type", "address")
    __index_watch_address__ = Index("idx_watch_address", "address")
    __index_watch_scripthash__ = Index("idx_watch_scripthash", "scripthash")


class WalletLockedUTXO(Table):

    __tablename__ = "wallet_locked_utxos"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    coin_type = Column("integer")
    txid = Column("string")
    vout = Column("integer")
    value = Column("integer")
    address = Column("string")
    bid_id = Column("blob")
    locked_at = Column("integer")
    expires_at = Column("integer")

    __unique_1__ = UniqueConstraint("coin_type", "txid", "vout")
    __index_locked_coin__ = Index("idx_locked_coin", "coin_type")
    __index_locked_bid__ = Index("idx_locked_bid", "bid_id")


class WalletTxCache(Table):

    __tablename__ = "wallet_tx_cache"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    coin_type = Column("integer")
    txid = Column("string")
    block_height = Column("integer")
    confirmations = Column("integer")
    tx_data = Column("blob")
    cached_at = Column("integer")
    expires_at = Column("integer")

    __unique_1__ = UniqueConstraint("coin_type", "txid")
    __index_tx_cache__ = Index("idx_tx_cache", "coin_type", "txid")


class WalletPendingTx(Table):

    __tablename__ = "wallet_pending_txs"

    record_id = Column("integer", primary_key=True, autoincrement=True)
    coin_type = Column("integer")
    txid = Column("string")
    tx_type = Column("string")
    amount = Column("integer")
    fee = Column("integer")
    addresses = Column("string")
    bid_id = Column("blob")
    first_seen = Column("integer")
    confirmed_at = Column("integer")

    __unique_1__ = UniqueConstraint("coin_type", "txid")
    __index_pending_coin__ = Index("idx_pending_coin", "coin_type", "confirmed_at")


def extract_wallet_schema() -> dict:
    return extract_schema(input_globals=globals())
