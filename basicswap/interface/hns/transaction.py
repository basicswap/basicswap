"""Canonical Handshake transaction encoding needed by a native coin interface.

The format follows hns-primitives: inputs and outputs precede locktime, then
every input's witness follows. There is no Bitcoin witness marker or scriptSig.
This module does not authorize, sign, or broadcast transactions.
"""

import hashlib
from dataclasses import dataclass

MAX_TX_SIZE = 1_000_000
MAX_STACK_ITEMS = 1_000


class HnsTransactionError(ValueError):
    """Malformed or noncanonical Handshake transaction bytes."""


def _u32(value):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise HnsTransactionError("value is outside u32")
    return value.to_bytes(4, "little")


def _u64(value):
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise HnsTransactionError("value is outside u64")
    return value.to_bytes(8, "little")


def _varint(value):
    if type(value) is not int or value < 0:
        raise HnsTransactionError("invalid varint")
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + _u32(value)
    return b"\xff" + _u64(value)


def _varbytes(value):
    if not isinstance(value, bytes) or len(value) > MAX_TX_SIZE:
        raise HnsTransactionError("invalid variable bytes")
    return _varint(len(value)) + value


def _blake256(value):
    return hashlib.blake2b(value, digest_size=32).digest()


class _Reader:
    def __init__(self, raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_TX_SIZE:
            raise HnsTransactionError("invalid transaction size")
        self.raw = raw
        self.pos = 0

    def take(self, size):
        if size < 0 or size > len(self.raw) - self.pos:
            raise HnsTransactionError("truncated transaction")
        part = self.raw[self.pos : self.pos + size]
        self.pos += size
        return part

    def uint(self, size):
        return int.from_bytes(self.take(size), "little")

    def varint(self):
        prefix = self.uint(1)
        if prefix < 0xFD:
            return prefix
        size, minimum = {0xFD: (2, 0xFD), 0xFE: (4, 0x10000), 0xFF: (8, 0x100000000)}[
            prefix
        ]
        value = self.uint(size)
        if value < minimum:
            raise HnsTransactionError("noncanonical varint")
        return value

    def varbytes(self):
        size = self.varint()
        if size > MAX_TX_SIZE:
            raise HnsTransactionError("variable bytes exceed limit")
        return self.take(size)

    def finished(self):
        if self.pos != len(self.raw):
            raise HnsTransactionError("trailing transaction data")


@dataclass(frozen=True)
class HnsOutpoint:
    txid: bytes
    index: int

    def encode(self):
        if not isinstance(self.txid, bytes) or len(self.txid) != 32:
            raise HnsTransactionError("invalid outpoint hash")
        return self.txid + _u32(self.index)

    @classmethod
    def read(cls, reader):
        return cls(reader.take(32), reader.uint(4))


@dataclass(frozen=True)
class HnsAddress:
    version: int
    program: bytes

    def encode(self):
        if type(self.version) is not int or not 0 <= self.version <= 31:
            raise HnsTransactionError("invalid address version")
        if not isinstance(self.program, bytes) or not 2 <= len(self.program) <= 40:
            raise HnsTransactionError("invalid address program")
        if self.version == 0 and len(self.program) not in (20, 32):
            raise HnsTransactionError("invalid version zero witness program")
        return bytes((self.version, len(self.program))) + self.program

    @classmethod
    def read(cls, reader):
        obj = cls(reader.uint(1), reader.take(reader.uint(1)))
        obj.encode()
        return obj


@dataclass(frozen=True)
class HnsCovenant:
    kind: int
    items: tuple[bytes, ...] = ()

    def encode(self):
        if type(self.kind) is not int or not 0 <= self.kind <= 255:
            raise HnsTransactionError("invalid covenant kind")
        if len(self.items) > MAX_STACK_ITEMS:
            raise HnsTransactionError("too many covenant items")
        return (
            bytes((self.kind,))
            + _varint(len(self.items))
            + b"".join(_varbytes(item) for item in self.items)
        )

    @classmethod
    def read(cls, reader):
        kind = reader.uint(1)
        count = reader.varint()
        if count > MAX_STACK_ITEMS:
            raise HnsTransactionError("too many covenant items")
        return cls(kind, tuple(reader.varbytes() for _ in range(count)))


@dataclass(frozen=True)
class HnsOutput:
    value: int
    address: HnsAddress
    covenant: HnsCovenant

    def encode(self):
        return _u64(self.value) + self.address.encode() + self.covenant.encode()

    @classmethod
    def read(cls, reader):
        return cls(reader.uint(8), HnsAddress.read(reader), HnsCovenant.read(reader))


@dataclass(frozen=True)
class HnsInput:
    previous_output: HnsOutpoint
    sequence: int
    witness: tuple[bytes, ...] = ()

    def base_encode(self):
        return self.previous_output.encode() + _u32(self.sequence)

    def witness_encode(self):
        if len(self.witness) > MAX_STACK_ITEMS:
            raise HnsTransactionError("too many witness items")
        return _varint(len(self.witness)) + b"".join(
            _varbytes(item) for item in self.witness
        )

    @classmethod
    def read_base(cls, reader):
        return cls(HnsOutpoint.read(reader), reader.uint(4))


@dataclass(frozen=True)
class HnsTransaction:
    version: int
    inputs: tuple[HnsInput, ...]
    outputs: tuple[HnsOutput, ...]
    locktime: int

    def base_encode(self):
        return (
            _u32(self.version)
            + _varint(len(self.inputs))
            + b"".join(item.base_encode() for item in self.inputs)
            + _varint(len(self.outputs))
            + b"".join(item.encode() for item in self.outputs)
            + _u32(self.locktime)
        )

    def witness_encode(self):
        return b"".join(item.witness_encode() for item in self.inputs)

    def encode(self):
        raw = self.base_encode() + self.witness_encode()
        if len(raw) > MAX_TX_SIZE:
            raise HnsTransactionError("transaction exceeds size limit")
        return raw

    def txid(self):
        return _blake256(self.base_encode()).hex()

    def witness_hash(self):
        witness_data_hash = _blake256(self.witness_encode())
        return _blake256(bytes.fromhex(self.txid()) + witness_data_hash).hex()

    @classmethod
    def decode(cls, raw):
        reader = _Reader(raw)
        version = reader.uint(4)
        input_count = reader.varint()
        if input_count > (len(raw) - reader.pos) // 41:
            raise HnsTransactionError("impossible input count")
        inputs = [HnsInput.read_base(reader) for _ in range(input_count)]
        output_count = reader.varint()
        if output_count > (len(raw) - reader.pos) // 14:
            raise HnsTransactionError("impossible output count")
        outputs = tuple(HnsOutput.read(reader) for _ in range(output_count))
        locktime = reader.uint(4)
        inputs = tuple(
            HnsInput(item.previous_output, item.sequence, cls._read_witness(reader))
            for item in inputs
        )
        reader.finished()
        return cls(version, inputs, outputs, locktime)

    @staticmethod
    def _read_witness(reader):
        count = reader.varint()
        if count > MAX_STACK_ITEMS:
            raise HnsTransactionError("too many witness items")
        return tuple(reader.varbytes() for _ in range(count))
