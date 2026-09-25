"""Immutable negotiated fields for a recoverable HNS/BTC BasicSwap bid.

Callers write this row in the same BasicSwap database transaction as the
corresponding bid or message link. The row exists before any value action;
only fields representing newly observed or prepared actions may be filled.
"""

import hashlib
from io import BytesIO

from basicswap.contrib.test_framework.messages import CTransaction
from basicswap.db import HnsBtcSwap

from .btc_contract import PreparedBtcTransaction
from .swap_terms import HnsBtcSwapTerms
from .wallet_bridge import SESSION_DOMAIN

MAKER = 1
TAKER = 2


def _bytes(value, length, label):
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"invalid {label}")
    return value


def _set_once(record, field, value):
    old = getattr(record, field)
    if old is not None and old != value:
        raise ValueError(f"HNS/BTC {field} is already bound")
    setattr(record, field, value)


def new_trade_record(offer_id, session_nonce, role, bid_message, created_at):
    _bytes(offer_id, 28, "offer ID")
    _bytes(session_nonce, 32, "session nonce")
    if session_nonce == bytes(32):
        raise ValueError("invalid session nonce")
    if role not in (MAKER, TAKER):
        raise ValueError("invalid HNS/BTC role")
    if not isinstance(bid_message, bytes) or not 0 < len(bid_message) <= 4096:
        raise ValueError("invalid HNS/BTC bid message")
    if type(created_at) is not int or created_at < 0:
        raise ValueError("invalid HNS/BTC creation time")
    return HnsBtcSwap(
        session_id=hashlib.sha256(SESSION_DOMAIN + offer_id + session_nonce).digest(),
        offer_id=offer_id,
        session_nonce=session_nonce,
        role=role,
        bid_message=bid_message,
        created_at=created_at,
        updated_at=created_at,
    )


def bind_bid_id(record, bid_id):
    _set_once(record, "bid_id", _bytes(bid_id, 28, "bid ID"))


def bind_wallet_fingerprint(record, fingerprint):
    """Bind the recovery seed, whose wallet ID may change on restore."""
    _set_once(
        record,
        "hns_wallet_fingerprint",
        _bytes(fingerprint, 32, "HNS wallet fingerprint"),
    )


def bind_terms(record, terms, now_unix, hns_magic, hns_genesis):
    """Persist the exact descriptor and script before either chain is funded."""
    if (
        record.offer_id != terms.offer_id
        or record.bid_id != terms.bid_id
        or record.session_nonce != terms.session_nonce
    ):
        raise ValueError("HNS/BTC terms do not match persisted bid identity")
    terms.validate(
        now_unix,
        hns_magic,
        hns_genesis,
        require_funding_window=record.terms_commitment is None,
    )
    _set_once(record, "hns_descriptor", terms.hns_descriptor.encode())
    _set_once(record, "btc_contract_script", terms.btc_contract_script)
    _set_once(
        record,
        "terms_commitment",
        terms.commitment(now_unix, hns_magic, hns_genesis),
    )


def bind_message(record, field, raw):
    if field not in ("accept_message", "second_lock_message"):
        raise ValueError("invalid HNS/BTC message field")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= 4096:
        raise ValueError("invalid HNS/BTC message")
    _set_once(record, field, raw)


def bind_lock(record, coin, txid, vout):
    _bytes(txid, 32, "lock transaction ID")
    if txid == bytes(32) or type(vout) is not int or not 0 <= vout <= 0xFFFFFFFF:
        raise ValueError("invalid HNS/BTC lock outpoint")
    if record.terms_commitment is None:
        raise ValueError("HNS/BTC terms must be stored before a lock")
    if coin == "hns":
        if vout != 0:
            raise ValueError("HNS HTLC must occupy output zero")
        _set_once(record, "hns_lock_txid", txid)
    elif coin == "btc":
        _set_once(record, "btc_lock_txid", txid)
        _set_once(record, "btc_lock_vout", vout)
    else:
        raise ValueError("invalid HNS/BTC lock coin")


def bind_prepared_btc_tx(record, field, prepared):
    if field not in ("btc_funding_tx", "btc_redeem_tx", "btc_refund_tx"):
        raise ValueError("invalid Bitcoin transaction field")
    if record.terms_commitment is None:
        raise ValueError("HNS/BTC terms must be stored before a transaction")
    if (
        not isinstance(prepared, PreparedBtcTransaction)
        or not isinstance(prepared.raw, bytes)
        or not 0 < len(prepared.raw) <= 1_000_000
        or not isinstance(prepared.txid, bytes)
        or len(prepared.txid) != 32
    ):
        raise ValueError("invalid prepared Bitcoin transaction")
    stream = BytesIO(prepared.raw)
    tx = CTransaction()
    try:
        tx.deserialize(stream)
        tx.rehash()
    except (ValueError, IndexError, OverflowError) as exc:
        raise ValueError("invalid prepared Bitcoin transaction") from exc
    if stream.tell() != len(prepared.raw) or bytes.fromhex(tx.hash) != prepared.txid:
        raise ValueError("prepared Bitcoin transaction ID mismatch")
    if field == "btc_funding_tx":
        if prepared.contract_vout is None:
            raise ValueError("Bitcoin funding outpoint is missing")
        bind_lock(record, "btc", prepared.txid, prepared.contract_vout)
    _set_once(record, field, prepared.raw)


def bind_preimage(record, preimage):
    _bytes(preimage, 32, "swap preimage")
    if record.hns_descriptor is None:
        raise ValueError("HNS/BTC terms must be stored before a preimage")
    if hashlib.sha256(preimage).digest() != record.hns_descriptor[46:78]:
        raise ValueError("HNS/BTC preimage does not match hashlock")
    _set_once(record, "secret_preimage", preimage)


def restore_trade(
    record,
    hns_first,
    hns_amount,
    btc_amount,
    now_unix,
    hns_magic,
    hns_genesis,
):
    """Rebuild persisted terms after a restart, including after refund expiry."""
    if (
        record.bid_id is None
        or record.accept_message is None
        or record.terms_commitment is None
    ):
        raise ValueError("HNS/BTC trade terms are incomplete")
    terms, first_outpoint = HnsBtcSwapTerms.from_messages(
        record.bid_message,
        record.accept_message,
        record.offer_id,
        record.bid_id,
        hns_first,
        hns_amount,
        btc_amount,
        now_unix,
        hns_magic,
        hns_genesis,
        require_funding_window=False,
    )
    if (
        record.session_id != terms.hns_wallet_terms().session_id()
        or record.session_nonce != terms.session_nonce
        or record.hns_descriptor != terms.hns_descriptor.encode()
        or record.btc_contract_script != terms.btc_contract_script
        or record.terms_commitment != terms.commitment(now_unix, hns_magic, hns_genesis)
    ):
        raise ValueError("HNS/BTC persisted terms mismatch")
    first_txid = record.hns_lock_txid if hns_first else record.btc_lock_txid
    first_vout = 0 if hns_first else record.btc_lock_vout
    if first_txid is not None and first_outpoint != (first_txid, first_vout):
        raise ValueError("HNS/BTC persisted first outpoint mismatch")
    return terms, first_outpoint
