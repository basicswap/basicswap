"""Durable, exact-byte SMSG outbox for the HNS/BTC value protocol.

Encrypt first, atomically store this row with the bid/acceptance state, then
submit the same ciphertext. Recovery resubmits pending rows without changing
the message ID that binds a wallet settlement session.
"""

from basicswap.basicswap_util import MessageTypes
from basicswap.db import HnsBtcOutbox
from basicswap.util.smsg import SMSG_HDR_LEN, smsgGetID, smsgGetTimestamp, smsgGetTTL

MESSAGE_TYPES = frozenset(
    (
        MessageTypes.HNS_BTC_BID,
        MessageTypes.HNS_BTC_BID_ACCEPT,
        MessageTypes.HNS_BTC_SECOND_LOCK,
    )
)
MAX_ENCRYPTED_MESSAGE_BYTES = 16_384


def prepare_hns_outbox_message(
    session_id, message_type, message_bytes, created_at, expire_at
):
    if (
        not isinstance(session_id, bytes)
        or len(session_id) != 32
        or session_id == bytes(32)
    ):
        raise ValueError("invalid HNS/BTC outbox session")
    if message_type not in MESSAGE_TYPES:
        raise ValueError("invalid HNS/BTC outbox message type")
    if (
        not isinstance(message_bytes, bytes)
        or not 0 < len(message_bytes) <= MAX_ENCRYPTED_MESSAGE_BYTES
    ):
        raise ValueError("invalid HNS/BTC encrypted message")
    if (
        type(created_at) is not int
        or type(expire_at) is not int
        or created_at < 0
        or expire_at <= created_at
        or smsgGetTimestamp(message_bytes) != created_at
        or expire_at > created_at + smsgGetTTL(message_bytes)
    ):
        raise ValueError("invalid HNS/BTC outbox lifetime")
    message_id = smsgGetID(message_bytes)
    if len(message_id) != 28:
        raise ValueError("invalid HNS/BTC encrypted message ID")
    return HnsBtcOutbox(
        message_id=message_id,
        session_id=session_id,
        message_type=int(message_type),
        message_bytes=message_bytes,
        created_at=created_at,
        expire_at=expire_at,
    )


def deliver_hns_outbox_message(row, now, submit, persist):
    """Submit the stored bytes; mark delivered only after successful submission.

    A crash after submission but before marking delivered causes a duplicate
    exact-byte submission. The message ID and negotiated session do not change.
    """
    if not isinstance(row, HnsBtcOutbox):
        raise TypeError("invalid HNS/BTC outbox row")
    if type(now) is not int or now < 0:
        raise ValueError("invalid HNS/BTC outbox time")
    if row.delivered_at is not None and (
        type(row.delivered_at) is not int
        or row.delivered_at < row.created_at
        or row.delivered_at >= row.expire_at
    ):
        raise ValueError("invalid HNS/BTC outbox delivery time")
    if row.delivered_at is not None:
        return row.message_id
    if (
        not isinstance(row.session_id, bytes)
        or len(row.session_id) != 32
        or row.session_id == bytes(32)
        or type(row.created_at) is not int
        or type(row.expire_at) is not int
        or row.created_at < 0
        or row.expire_at <= row.created_at
        or row.message_type not in MESSAGE_TYPES
        or not isinstance(row.message_bytes, bytes)
        or len(row.message_bytes) <= SMSG_HDR_LEN
        or len(row.message_bytes) > MAX_ENCRYPTED_MESSAGE_BYTES
        or smsgGetID(row.message_bytes) != row.message_id
        or smsgGetTimestamp(row.message_bytes) != row.created_at
        or row.expire_at > row.created_at + smsgGetTTL(row.message_bytes)
    ):
        raise ValueError("HNS/BTC outbox message changed")
    if now >= row.expire_at:
        raise ValueError("HNS/BTC outbox message expired")
    if not callable(submit) or not callable(persist):
        raise TypeError("HNS/BTC outbox callbacks are required")
    submit(row.message_bytes)
    row.delivered_at = now
    persist(row)
    return row.message_id
