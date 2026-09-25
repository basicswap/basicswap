"""Durable HNS/BTC bid handoff around BasicSwap's message transport.

The caller persists each returned record in the same transaction as its Bid
and message link. Funding remains in :mod:`settlement`, after the accepted
terms have been stored. A retransmitted message must reproduce the same bytes.
"""

import hashlib

from coincurve import PrivateKey, PublicKey

from basicswap.messages_npb import (
    HnsBtcBidAcceptMessage,
    HnsBtcBidMessage,
    HnsBtcSecondLockMessage,
)
from basicswap.util.crypto import hash160

from .htlc import HnsHtlc
from .swap_terms import (
    SWAP_PROTOCOL_VERSION,
    HnsBtcSwapTerms,
    _decode_exact_message,
    _parse_btc_contract_script,
    hns_time_lock_at_or_after,
    make_btc_contract_script,
    new_session_nonce,
)
from .trade_record import (
    MAKER,
    TAKER,
    bind_bid_id,
    bind_lock,
    bind_message,
    bind_preimage,
    bind_terms,
    new_trade_record,
)


def _btc_key_hash(private_key):
    if not isinstance(private_key, bytes) or len(private_key) != 32:
        raise ValueError("invalid Bitcoin trade key")
    try:
        public_key = PrivateKey(private_key).public_key.format(compressed=True)
    except ValueError as exc:
        raise ValueError("invalid Bitcoin trade key") from exc
    return hash160(public_key)


def _hns_key(bridge, offer_id, session_nonce, refund):
    public_key = bridge.key(offer_id, session_nonce, refund)
    if not isinstance(public_key, bytes) or len(public_key) != 33:
        raise ValueError("invalid HNS trade key")
    try:
        if PublicKey(public_key).format(compressed=True) != public_key:
            raise ValueError("noncanonical HNS trade key")
    except ValueError as exc:
        raise ValueError("invalid HNS trade key") from exc
    return public_key


def prepare_taker_bid(
    offer_id,
    hns_first,
    hns_amount,
    btc_amount,
    bitcoin_private_key,
    hns_bridge,
    now_unix,
    valid_for_seconds=600,
    minimum_hns_confirmations=2,
    minimum_btc_confirmations=2,
    message_nets=None,
    session_nonce=None,
):
    """Return the pre-bid record and wire bytes to persist before send."""
    if type(hns_first) is not bool:
        raise ValueError("invalid HNS/BTC trade direction")
    if (
        type(hns_amount) is not int
        or not 0 < hns_amount <= 0xFFFFFFFFFFFFFFFF
        or type(btc_amount) is not int
        or not 0 < btc_amount <= 21_000_000 * 100_000_000
    ):
        raise ValueError("invalid HNS/BTC bid amount")
    if type(valid_for_seconds) is not int or not 1 <= valid_for_seconds <= 48 * 3600:
        raise ValueError("invalid HNS/BTC bid validity")
    for minimum in (minimum_hns_confirmations, minimum_btc_confirmations):
        if type(minimum) is not int or not 1 <= minimum <= 100:
            raise ValueError("invalid HNS/BTC confirmation minimum")
    nonce = new_session_nonce() if session_nonce is None else session_nonce
    if not isinstance(nonce, bytes) or len(nonce) != 32 or nonce == bytes(32):
        raise ValueError("invalid HNS/BTC session nonce")
    btc_hash = _btc_key_hash(bitcoin_private_key)
    hns_key = _hns_key(hns_bridge, offer_id, nonce, refund=not hns_first)
    message = HnsBtcBidMessage(
        protocol_version=SWAP_PROTOCOL_VERSION,
        offer_msg_id=offer_id,
        time_valid=valid_for_seconds,
        amount_from=hns_amount if hns_first else btc_amount,
        amount_to=btc_amount if hns_first else hns_amount,
        session_nonce=nonce,
        taker_hns_public_key=hns_key,
        taker_btc_key_hash=btc_hash,
        minimum_hns_confirmations=minimum_hns_confirmations,
        minimum_btc_confirmations=minimum_btc_confirmations,
    )
    if message_nets is not None:
        if not isinstance(message_nets, str):
            raise ValueError("invalid HNS/BTC message network")
        message.message_nets = message_nets
    raw = message.to_bytes()
    _decode_exact_message(HnsBtcBidMessage, raw)
    record = new_trade_record(offer_id, nonce, TAKER, raw, now_unix)
    return record, raw


def bind_sent_bid(record, bid_id):
    if record.role != TAKER:
        raise ValueError("only a taker can send an HNS/BTC bid")
    bind_bid_id(record, bid_id)


def receive_maker_bid(offer_id, bid_id, bid_raw, sent_at, now_unix):
    """Validate a received bid's identity before saving its maker record."""
    bid = _decode_exact_message(HnsBtcBidMessage, bid_raw)
    if bid.protocol_version != SWAP_PROTOCOL_VERSION or bid.offer_msg_id != offer_id:
        raise ValueError("HNS/BTC bid identity or protocol mismatch")
    if type(bid.time_valid) is not int or not 1 <= bid.time_valid <= 48 * 3600:
        raise ValueError("invalid HNS/BTC bid validity")
    if (
        type(sent_at) is not int
        or sent_at < 0
        or type(now_unix) is not int
        or now_unix < 0
        or now_unix > sent_at + bid.time_valid
    ):
        raise ValueError("invalid HNS/BTC bid receive time")
    if (
        type(bid.amount_from) is not int
        or type(bid.amount_to) is not int
        or not 0 < bid.amount_from <= 0xFFFFFFFFFFFFFFFF
        or not 0 < bid.amount_to <= 0xFFFFFFFFFFFFFFFF
        or not isinstance(bid.taker_btc_key_hash, bytes)
        or len(bid.taker_btc_key_hash) != 20
        or any(
            type(minimum) is not int or not 1 <= minimum <= 100
            for minimum in (
                bid.minimum_hns_confirmations,
                bid.minimum_btc_confirmations,
            )
        )
    ):
        raise ValueError("invalid HNS/BTC bid terms")
    try:
        if PublicKey(bid.taker_hns_public_key).format(compressed=True) != (
            bid.taker_hns_public_key
        ):
            raise ValueError("invalid HNS/BTC taker key")
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid HNS/BTC taker key") from exc
    record = new_trade_record(offer_id, bid.session_nonce, MAKER, bid_raw, sent_at)
    bind_bid_id(record, bid_id)
    return record


def restore_maker_terms(
    record, hns_first, hns_amount, btc_amount, now_unix, hns_magic, hns_genesis
):
    """Recover complete terms after a crash before acceptance was sent."""
    if record.role != MAKER or record.bid_id is None:
        raise ValueError("incomplete maker HNS/BTC bid")
    if record.hns_descriptor is None or record.btc_contract_script is None:
        raise ValueError("maker HNS/BTC terms have not been prepared")
    bid = _decode_exact_message(HnsBtcBidMessage, record.bid_message)
    descriptor = HnsHtlc.decode(record.hns_descriptor, hns_magic, hns_genesis)
    _, btc_receiver, _, btc_refund = _parse_btc_contract_script(
        record.btc_contract_script
    )
    terms = HnsBtcSwapTerms(
        offer_id=record.offer_id,
        bid_id=record.bid_id,
        session_nonce=record.session_nonce,
        hns_first=hns_first,
        hns_amount=hns_amount,
        btc_amount=btc_amount,
        hns_descriptor=descriptor,
        btc_contract_script=record.btc_contract_script,
        maker_hns_public_key=(
            descriptor.refund_public_key
            if hns_first
            else descriptor.receiver_public_key
        ),
        taker_hns_public_key=bid.taker_hns_public_key,
        maker_btc_key_hash=btc_receiver if hns_first else btc_refund,
        taker_btc_key_hash=bid.taker_btc_key_hash,
        minimum_hns_confirmations=bid.minimum_hns_confirmations,
        minimum_btc_confirmations=bid.minimum_btc_confirmations,
    )
    if (
        bid.protocol_version != SWAP_PROTOCOL_VERSION
        or bid.offer_msg_id != record.offer_id
        or bid.session_nonce != record.session_nonce
        or bid.amount_from != (hns_amount if hns_first else btc_amount)
        or bid.amount_to != (btc_amount if hns_first else hns_amount)
        or record.terms_commitment != terms.commitment(now_unix, hns_magic, hns_genesis)
    ):
        raise ValueError("persisted maker HNS/BTC terms mismatch")
    return terms


def prepare_maker_terms(
    record,
    hns_first,
    hns_amount,
    btc_amount,
    bitcoin_private_key,
    hns_bridge,
    secret_preimage,
    first_refund_unix,
    second_refund_unix,
    now_unix,
    hns_magic,
    hns_genesis,
):
    """Bind both exact contracts and the secret before funding the first leg."""
    if record.role != MAKER or record.bid_id is None:
        raise ValueError("incomplete maker HNS/BTC bid")
    if not isinstance(secret_preimage, bytes) or len(secret_preimage) != 32:
        raise ValueError("invalid HNS/BTC maker preimage")
    if record.terms_commitment is not None:
        terms = restore_maker_terms(
            record, hns_first, hns_amount, btc_amount, now_unix, hns_magic, hns_genesis
        )
        if record.secret_preimage != secret_preimage:
            raise ValueError("persisted maker HNS/BTC preimage mismatch")
        if (
            _btc_key_hash(bitcoin_private_key) != terms.maker_btc_key_hash
            or _hns_key(
                hns_bridge, record.offer_id, record.session_nonce, refund=hns_first
            )
            != terms.maker_hns_public_key
        ):
            raise ValueError("maker HNS/BTC wallet key changed")
        return terms
    bid = _decode_exact_message(HnsBtcBidMessage, record.bid_message)
    if (
        bid.protocol_version != SWAP_PROTOCOL_VERSION
        or bid.offer_msg_id != record.offer_id
        or bid.session_nonce != record.session_nonce
        or bid.amount_from != (hns_amount if hns_first else btc_amount)
        or bid.amount_to != (btc_amount if hns_first else hns_amount)
        or now_unix > record.created_at + bid.time_valid
    ):
        raise ValueError("maker HNS/BTC bid terms mismatch")
    maker_hns_key = _hns_key(
        hns_bridge, record.offer_id, record.session_nonce, refund=hns_first
    )
    maker_btc_hash = _btc_key_hash(bitcoin_private_key)
    hns_refund = first_refund_unix if hns_first else second_refund_unix
    btc_refund = second_refund_unix if hns_first else first_refund_unix
    descriptor = HnsHtlc(
        hns_magic,
        hns_genesis,
        hns_amount,
        hashlib.sha256(secret_preimage).digest(),
        bid.taker_hns_public_key if hns_first else maker_hns_key,
        maker_hns_key if hns_first else bid.taker_hns_public_key,
        hns_time_lock_at_or_after(hns_refund),
    )
    btc_script = make_btc_contract_script(
        btc_refund,
        descriptor.hashlock,
        maker_btc_hash if hns_first else bid.taker_btc_key_hash,
        bid.taker_btc_key_hash if hns_first else maker_btc_hash,
    )
    terms = HnsBtcSwapTerms(
        record.offer_id,
        record.bid_id,
        record.session_nonce,
        hns_first,
        hns_amount,
        btc_amount,
        descriptor,
        btc_script,
        maker_hns_key,
        bid.taker_hns_public_key,
        maker_btc_hash,
        bid.taker_btc_key_hash,
        bid.minimum_hns_confirmations,
        bid.minimum_btc_confirmations,
    )
    bind_terms(record, terms, now_unix, hns_magic, hns_genesis)
    bind_preimage(record, secret_preimage)
    return terms


def make_accept_message(record, terms, now_unix, hns_magic, hns_genesis):
    """The maker sends its persisted first outpoint and exact term commitment."""
    if record.role != MAKER or record.terms_commitment != terms.commitment(
        now_unix, hns_magic, hns_genesis
    ):
        raise ValueError("maker HNS/BTC terms are not persisted")
    first_txid = record.hns_lock_txid if terms.hns_first else record.btc_lock_txid
    first_vout = 0 if terms.hns_first else record.btc_lock_vout
    if first_txid is None or first_vout is None:
        raise ValueError("maker HNS/BTC first lock is not persisted")
    message = HnsBtcBidAcceptMessage(
        bid_msg_id=record.bid_id,
        first_txid=first_txid,
        first_vout=first_vout,
        hns_descriptor=record.hns_descriptor,
        btc_contract_script=record.btc_contract_script,
        maker_hns_public_key=terms.maker_hns_public_key,
        maker_btc_key_hash=terms.maker_btc_key_hash,
        terms_commitment=record.terms_commitment,
    )
    raw = message.to_bytes()
    bind_message(record, "accept_message", raw)
    return raw


def receive_accept_message(
    record,
    accept_raw,
    hns_first,
    hns_amount,
    btc_amount,
    now_unix,
    hns_magic,
    hns_genesis,
):
    """Bind a maker announcement before verifying and funding the second leg."""
    if record.role != TAKER or record.bid_id is None:
        raise ValueError("incomplete taker HNS/BTC bid")
    terms, outpoint = HnsBtcSwapTerms.from_messages(
        record.bid_message,
        accept_raw,
        record.offer_id,
        record.bid_id,
        hns_first,
        hns_amount,
        btc_amount,
        now_unix,
        hns_magic,
        hns_genesis,
        require_funding_window=record.accept_message is None,
    )
    if record.accept_message is not None and record.accept_message != accept_raw:
        raise ValueError("maker HNS/BTC acceptance changed")
    bind_terms(record, terms, now_unix, hns_magic, hns_genesis)
    bind_lock(record, "hns" if hns_first else "btc", *outpoint)
    bind_message(record, "accept_message", accept_raw)
    return terms


def make_second_lock_message(record, terms, now_unix, hns_magic, hns_genesis):
    if record.role != TAKER or record.terms_commitment != terms.commitment(
        now_unix, hns_magic, hns_genesis
    ):
        raise ValueError("taker HNS/BTC terms are not persisted")
    second_txid = record.btc_lock_txid if terms.hns_first else record.hns_lock_txid
    second_vout = record.btc_lock_vout if terms.hns_first else 0
    if second_txid is None or second_vout is None:
        raise ValueError("taker HNS/BTC second lock is not persisted")
    message = HnsBtcSecondLockMessage(
        bid_msg_id=record.bid_id,
        second_txid=second_txid,
        second_vout=second_vout,
        terms_commitment=record.terms_commitment,
    )
    raw = message.to_bytes()
    bind_message(record, "second_lock_message", raw)
    return raw


def receive_second_lock_message(
    record, terms, second_raw, now_unix, hns_magic, hns_genesis
):
    if record.role != MAKER or record.terms_commitment != terms.commitment(
        now_unix, hns_magic, hns_genesis
    ):
        raise ValueError("maker HNS/BTC terms are not persisted")
    outpoint = terms.second_lock_outpoint(second_raw, now_unix, hns_magic, hns_genesis)
    if (
        record.second_lock_message is not None
        and record.second_lock_message != second_raw
    ):
        raise ValueError("taker HNS/BTC second lock announcement changed")
    bind_lock(record, "btc" if terms.hns_first else "hns", *outpoint)
    bind_message(record, "second_lock_message", second_raw)
    return outpoint
