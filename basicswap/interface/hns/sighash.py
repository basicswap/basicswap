"""Handshake witness signature digest, independently checked against HSD.

This computes the message digest only. It does not sign or authorize a spend.
"""

import hashlib

from .transaction import HnsTransaction, HnsTransactionError

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_SINGLE_REVERSE = 4
SIGHASH_NOINPUT = 0x40
SIGHASH_ANYONE_CAN_PAY = 0x80
_ZERO = bytes(32)


def _hash(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def _u32(value):
    return value.to_bytes(4, "little")


def valid_sighash_type(hash_type):
    return (
        type(hash_type) is int
        and 0 <= hash_type <= 255
        and 1 <= (hash_type & ~(SIGHASH_NOINPUT | SIGHASH_ANYONE_CAN_PAY)) <= 4
    )


def signature_hash(
    transaction: HnsTransaction,
    input_index: int,
    previous_script: bytes,
    previous_value: int,
    hash_type: int,
) -> bytes:
    """Compute the hsd compatible digest for one Handshake witness input."""
    if not isinstance(transaction, HnsTransaction):
        raise HnsTransactionError("invalid Handshake transaction")
    if type(input_index) is not int or not 0 <= input_index < len(transaction.inputs):
        raise HnsTransactionError("signature input index is out of range")
    if not isinstance(previous_script, bytes) or len(previous_script) > 1_000_000:
        raise HnsTransactionError("invalid previous script")
    if type(previous_value) is not int or not 0 <= previous_value <= 0xFFFFFFFFFFFFFFFF:
        raise HnsTransactionError("invalid previous value")
    if not valid_sighash_type(hash_type):
        raise HnsTransactionError("invalid Handshake signature hash type")

    base = hash_type & 0x1F
    anyone_can_pay = bool(hash_type & SIGHASH_ANYONE_CAN_PAY)
    no_input = bool(hash_type & SIGHASH_NOINPUT)
    prevouts = _hash(
        b"".join(item.previous_output.encode() for item in transaction.inputs)
    )
    sequences = _hash(b"".join(_u32(item.sequence) for item in transaction.inputs))
    outputs = [item.encode() for item in transaction.outputs]
    if base == SIGHASH_NONE:
        hash_outputs = _ZERO
    elif base == SIGHASH_SINGLE:
        hash_outputs = (
            _hash(outputs[input_index]) if input_index < len(outputs) else _ZERO
        )
    elif base == SIGHASH_SINGLE_REVERSE:
        output_index = len(outputs) - input_index - 1
        hash_outputs = _hash(outputs[output_index]) if output_index >= 0 else _ZERO
    else:
        hash_outputs = _hash(b"".join(outputs))

    item = transaction.inputs[input_index]
    outpoint = (
        bytes(32) + _u32(0xFFFFFFFF) if no_input else item.previous_output.encode()
    )
    sequence = 0xFFFFFFFF if no_input else item.sequence
    preimage = (
        _u32(transaction.version)
        + (_ZERO if anyone_can_pay else prevouts)
        + (_ZERO if anyone_can_pay or base != SIGHASH_ALL else sequences)
        + outpoint
        + _encode_varbytes(previous_script)
        + previous_value.to_bytes(8, "little")
        + _u32(sequence)
        + hash_outputs
        + _u32(transaction.locktime)
        + _u32(hash_type)
    )
    return _hash(preimage)


def _encode_varbytes(value):
    length = len(value)
    if length < 0xFD:
        return bytes((length,)) + value
    if length <= 0xFFFF:
        return b"\xfd" + length.to_bytes(2, "little") + value
    return b"\xfe" + length.to_bytes(4, "little") + value
