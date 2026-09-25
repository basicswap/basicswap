"""Exact terms for a seller-first Bitcoin/Handshake hashlock swap.

The seller funds the offered asset first with the later refund deadline. The
buyer funds the requested asset only after independently verifying that first
lock. The seller's redemption of the second lock reveals the shared preimage.
Both on-chain scripts are committed before either funding action is authorized.
"""

import hashlib
import secrets
from dataclasses import dataclass

from basicswap.interface.hns.htlc import HnsHtlc
from basicswap.interface.hns.wallet_bridge import HnsBridgeTerms
from basicswap.messages_npb import (
    HnsBtcBidAcceptMessage,
    HnsBtcBidMessage,
    HnsBtcSecondLockMessage,
)
from basicswap.script import OpCodes
from basicswap.util import SerialiseNum

HNS_TIME_FLAG = 0x80000000
HNS_TIME_MASK = 0x7FFFFFFF
HNS_TIME_UNIT = 512
BTC_TIME_THRESHOLD = 500_000_000
MINIMUM_REFUND_MARGIN_SECONDS = 2 * 60 * 60
SESSION_NONCE_SIZE = 32
_COMMITMENT_DOMAIN = b"basicswap/hns-btc-terms/v1\0"
_BTC_SCRIPT_PREFIX = bytes(
    (
        OpCodes.OP_IF,
        OpCodes.OP_SIZE,
        1,
        32,
        OpCodes.OP_EQUALVERIFY,
        OpCodes.OP_SHA256,
        32,
    )
)
_BTC_REDEEM_PREFIX = bytes(
    (OpCodes.OP_EQUALVERIFY, OpCodes.OP_DUP, OpCodes.OP_HASH160, 20)
)
_BTC_REFUND_PREFIX = bytes(
    (
        OpCodes.OP_CHECKLOCKTIMEVERIFY,
        OpCodes.OP_DROP,
        OpCodes.OP_DUP,
        OpCodes.OP_HASH160,
        20,
    )
)
_BTC_SCRIPT_SUFFIX = bytes(
    (OpCodes.OP_ENDIF, OpCodes.OP_EQUALVERIFY, OpCodes.OP_CHECKSIG)
)
MAX_SWAP_MESSAGE_BYTES = 4096
SWAP_PROTOCOL_VERSION = 1


def new_session_nonce():
    return secrets.token_bytes(SESSION_NONCE_SIZE)


def hns_time_lock_at_or_after(unix_time):
    if type(unix_time) is not int or unix_time <= 0:
        raise ValueError("invalid HNS refund time")
    units = (unix_time + HNS_TIME_UNIT - 1) // HNS_TIME_UNIT
    if units == 0 or units > HNS_TIME_MASK:
        raise ValueError("HNS refund time exceeds consensus range")
    return HNS_TIME_FLAG | units


def hns_time_lock_threshold(locktime):
    if (
        type(locktime) is not int
        or not 0 <= locktime <= 0xFFFFFFFF
        or locktime & HNS_TIME_FLAG == 0
        or locktime & HNS_TIME_MASK == 0
    ):
        raise ValueError("HNS swap requires a median-time refund lock")
    return (locktime & HNS_TIME_MASK) * HNS_TIME_UNIT


def _parse_btc_contract_script(script):
    if not isinstance(script, bytes) or not 97 <= len(script) <= 98:
        raise ValueError("invalid Bitcoin contract script")
    if script[:7] != _BTC_SCRIPT_PREFIX or script[39:43] != _BTC_REDEEM_PREFIX:
        raise ValueError("invalid Bitcoin contract script")
    if script[63] != OpCodes.OP_ELSE:
        raise ValueError("invalid Bitcoin contract script")
    number_length = script[64]
    if not 1 <= number_length <= 5:
        raise ValueError("invalid Bitcoin refund time push")
    number_bytes = script[65 : 65 + number_length]
    if len(number_bytes) != number_length or number_bytes[-1] & 0x80:
        raise ValueError("invalid Bitcoin refund time")
    refund_unix = int.from_bytes(number_bytes, "little")
    offset = 65 + number_length
    if (
        script[offset : offset + 5] != _BTC_REFUND_PREFIX
        or script[offset + 25 :] != _BTC_SCRIPT_SUFFIX
    ):
        raise ValueError("invalid Bitcoin contract script")
    return script[7:39], script[43:63], refund_unix, script[offset + 5 : offset + 25]


@dataclass(frozen=True)
class HnsBtcSwapTerms:
    offer_id: bytes
    bid_id: bytes
    session_nonce: bytes
    hns_first: bool
    hns_amount: int
    btc_amount: int
    hns_descriptor: HnsHtlc
    btc_contract_script: bytes
    maker_hns_public_key: bytes
    taker_hns_public_key: bytes
    maker_btc_key_hash: bytes
    taker_btc_key_hash: bytes
    minimum_hns_confirmations: int
    minimum_btc_confirmations: int

    def hns_wallet_terms(self):
        """Pass the identical negotiated session and descriptor to the wallet."""
        return HnsBridgeTerms(
            self.offer_id, self.bid_id, self.session_nonce, self.hns_descriptor
        )

    def second_lock_outpoint(
        self, message_bytes, now_unix, expected_hns_magic, expected_hns_genesis
    ):
        """Check the taker's lock hint against persisted negotiated terms."""
        message = _decode_exact_message(HnsBtcSecondLockMessage, message_bytes)
        if (
            message.bid_msg_id != self.bid_id
            or message.terms_commitment
            != self.commitment(now_unix, expected_hns_magic, expected_hns_genesis)
        ):
            raise ValueError("HNS/BTC second lock terms mismatch")
        if (
            not isinstance(message.second_txid, bytes)
            or len(message.second_txid) != 32
            or message.second_txid == bytes(32)
            or type(message.second_vout) is not int
            or not 0 <= message.second_vout <= 0xFFFFFFFF
        ):
            raise ValueError("invalid second lock outpoint")
        return message.second_txid, message.second_vout

    @classmethod
    def from_messages(
        cls,
        bid_bytes,
        accept_bytes,
        offer_id,
        bid_id,
        hns_first,
        expected_hns_amount,
        expected_btc_amount,
        now_unix,
        expected_hns_magic,
        expected_hns_genesis,
        require_funding_window=True,
    ):
        """Reject changed wire terms before trusting the announced first lock.

        The returned outpoint is only a hint. A chain adapter must verify its
        exact output, confirmations, and unspent state before funding the
        second chain.
        """
        bid = _decode_exact_message(HnsBtcBidMessage, bid_bytes)
        accept = _decode_exact_message(HnsBtcBidAcceptMessage, accept_bytes)
        if bid.protocol_version != SWAP_PROTOCOL_VERSION:
            raise ValueError("unsupported HNS/BTC swap protocol")
        if bid.offer_msg_id != offer_id or accept.bid_msg_id != bid_id:
            raise ValueError("HNS/BTC swap message identity mismatch")
        expected_from = expected_hns_amount if hns_first else expected_btc_amount
        expected_to = expected_btc_amount if hns_first else expected_hns_amount
        if bid.amount_from != expected_from or bid.amount_to != expected_to:
            raise ValueError("HNS/BTC bid amount mismatch")
        if (
            not isinstance(accept.first_txid, bytes)
            or len(accept.first_txid) != 32
            or accept.first_txid == bytes(32)
            or type(accept.first_vout) is not int
            or not 0 <= accept.first_vout <= 0xFFFFFFFF
        ):
            raise ValueError("invalid first lock outpoint")
        descriptor = HnsHtlc.decode(
            accept.hns_descriptor, expected_hns_magic, expected_hns_genesis
        )
        terms = cls(
            offer_id=offer_id,
            bid_id=bid_id,
            session_nonce=bid.session_nonce,
            hns_first=hns_first,
            hns_amount=expected_hns_amount,
            btc_amount=expected_btc_amount,
            hns_descriptor=descriptor,
            btc_contract_script=accept.btc_contract_script,
            maker_hns_public_key=accept.maker_hns_public_key,
            taker_hns_public_key=bid.taker_hns_public_key,
            maker_btc_key_hash=accept.maker_btc_key_hash,
            taker_btc_key_hash=bid.taker_btc_key_hash,
            minimum_hns_confirmations=bid.minimum_hns_confirmations,
            minimum_btc_confirmations=bid.minimum_btc_confirmations,
        )
        commitment = terms.commitment(
            now_unix, expected_hns_magic, expected_hns_genesis
        )
        if accept.terms_commitment != commitment:
            raise ValueError("HNS/BTC swap terms commitment mismatch")
        terms.validate(
            now_unix,
            expected_hns_magic,
            expected_hns_genesis,
            require_funding_window=require_funding_window,
        )
        return terms, (accept.first_txid, accept.first_vout)

    def validate(
        self,
        now_unix,
        expected_hns_magic,
        expected_hns_genesis,
        require_funding_window=True,
    ):
        if not isinstance(self.offer_id, bytes) or len(self.offer_id) != 28:
            raise ValueError("invalid offer ID")
        if not isinstance(self.bid_id, bytes) or len(self.bid_id) != 28:
            raise ValueError("invalid bid ID")
        if (
            not isinstance(self.session_nonce, bytes)
            or len(self.session_nonce) != SESSION_NONCE_SIZE
            or self.session_nonce == bytes(SESSION_NONCE_SIZE)
        ):
            raise ValueError("invalid HNS swap session nonce")
        if type(self.hns_first) is not bool:
            raise ValueError("invalid HNS swap direction")
        if (
            type(self.hns_amount) is not int
            or not 0 < self.hns_amount <= 0xFFFFFFFFFFFFFFFF
        ):
            raise ValueError("invalid HNS swap amount")
        if (
            type(self.btc_amount) is not int
            or not 0 < self.btc_amount <= 21_000_000 * 100_000_000
        ):
            raise ValueError("invalid Bitcoin swap amount")
        if type(now_unix) is not int or now_unix < BTC_TIME_THRESHOLD:
            raise ValueError("invalid current time")
        for count in (self.minimum_hns_confirmations, self.minimum_btc_confirmations):
            if type(count) is not int or not 1 <= count <= 100:
                raise ValueError("invalid swap confirmation minimum")

        descriptor = self.hns_descriptor
        if not isinstance(descriptor, HnsHtlc):
            raise TypeError("invalid HNS HTLC descriptor")
        descriptor.validate()
        expected_hns_receiver = (
            self.taker_hns_public_key if self.hns_first else self.maker_hns_public_key
        )
        expected_hns_refund = (
            self.maker_hns_public_key if self.hns_first else self.taker_hns_public_key
        )
        expected_btc_receiver = (
            self.maker_btc_key_hash if self.hns_first else self.taker_btc_key_hash
        )
        expected_btc_refund = (
            self.taker_btc_key_hash if self.hns_first else self.maker_btc_key_hash
        )
        if (
            descriptor.network_magic != expected_hns_magic
            or descriptor.genesis != expected_hns_genesis
            or descriptor.value != self.hns_amount
            or descriptor.receiver_public_key != expected_hns_receiver
            or descriptor.refund_public_key != expected_hns_refund
        ):
            raise ValueError("HNS descriptor differs from swap terms")
        hns_refund_unix = hns_time_lock_threshold(descriptor.refund_locktime)

        if not isinstance(self.btc_contract_script, bytes):
            raise TypeError("invalid Bitcoin contract script")
        hashlock, receiver, btc_refund_unix, refund = _parse_btc_contract_script(
            self.btc_contract_script
        )
        if (
            hashlock != descriptor.hashlock
            or receiver != expected_btc_receiver
            or refund != expected_btc_refund
        ):
            raise ValueError("Bitcoin contract differs from swap terms")
        if (
            type(btc_refund_unix) is not int
            or not BTC_TIME_THRESHOLD <= btc_refund_unix <= 0xFFFFFFFF
            or not isinstance(self.maker_btc_key_hash, bytes)
            or not isinstance(self.taker_btc_key_hash, bytes)
            or len(self.maker_btc_key_hash) != 20
            or len(self.taker_btc_key_hash) != 20
            or self.maker_btc_key_hash == self.taker_btc_key_hash
        ):
            raise ValueError("invalid Bitcoin refund terms")
        if self.btc_contract_script != make_btc_contract_script(
            btc_refund_unix,
            descriptor.hashlock,
            expected_btc_receiver,
            expected_btc_refund,
        ):
            raise ValueError("noncanonical Bitcoin contract script")

        first_deadline = hns_refund_unix if self.hns_first else btc_refund_unix
        second_deadline = btc_refund_unix if self.hns_first else hns_refund_unix
        if first_deadline < second_deadline + MINIMUM_REFUND_MARGIN_SECONDS or (
            require_funding_window
            and second_deadline <= now_unix + MINIMUM_REFUND_MARGIN_SECONDS
        ):
            raise ValueError("unsafe swap refund ordering")
        return first_deadline, second_deadline

    def commitment(self, now_unix, expected_hns_magic, expected_hns_genesis):
        # The commitment identifies immutable negotiated terms. A later
        # recovery or spend observation must still be able to compare it once
        # the initial funding window has closed.
        self.validate(
            now_unix,
            expected_hns_magic,
            expected_hns_genesis,
            require_funding_window=False,
        )
        payload = (
            self.offer_id
            + self.bid_id
            + self.session_nonce
            + bytes((int(self.hns_first),))
            + self.hns_amount.to_bytes(8, "little")
            + self.btc_amount.to_bytes(8, "little")
            + self.hns_descriptor.encode()
            + len(self.btc_contract_script).to_bytes(2, "little")
            + self.btc_contract_script
            + self.minimum_hns_confirmations.to_bytes(2, "little")
            + self.minimum_btc_confirmations.to_bytes(2, "little")
        )
        return hashlib.sha256(_COMMITMENT_DOMAIN + payload).digest()


def make_btc_contract_script(refund_unix, hashlock, receiver_key_hash, refund_key_hash):
    if (
        type(refund_unix) is not int
        or not BTC_TIME_THRESHOLD <= refund_unix <= 0xFFFFFFFF
    ):
        raise ValueError("invalid Bitcoin refund time")
    if not isinstance(hashlock, bytes) or len(hashlock) != 32 or hashlock == bytes(32):
        raise ValueError("invalid swap hashlock")
    if (
        not isinstance(receiver_key_hash, bytes)
        or len(receiver_key_hash) != 20
        or not isinstance(refund_key_hash, bytes)
        or len(refund_key_hash) != 20
        or receiver_key_hash == refund_key_hash
    ):
        raise ValueError("invalid Bitcoin swap keys")
    return (
        _BTC_SCRIPT_PREFIX
        + hashlock
        + _BTC_REDEEM_PREFIX
        + receiver_key_hash
        + bytes((OpCodes.OP_ELSE,))
        + SerialiseNum(refund_unix)
        + _BTC_REFUND_PREFIX
        + refund_key_hash
        + _BTC_SCRIPT_SUFFIX
    )


def _decode_exact_message(message_class, raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_SWAP_MESSAGE_BYTES:
        raise ValueError("invalid HNS/BTC swap message length")
    message = message_class()
    try:
        message.from_bytes(raw)
        if message.to_bytes() != raw:
            raise ValueError("noncanonical HNS/BTC swap message")
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid HNS/BTC swap message") from exc
    return message
