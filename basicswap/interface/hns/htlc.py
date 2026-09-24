"""Read-only verifier for the hns-swap v1 native Handshake HTLC.

The hns-wallet-rs runtime owns key derivation, funding, signing, and settlement.
BasicSwap can use this module to reject a mismatched contract before treating a
wallet or peer observation as swap evidence. The wire layout and script are
pinned to hns-rs ``HnsHtlc`` version 1.
"""

import hashlib
from dataclasses import dataclass

from .address import witness_script_program
from .transaction import HnsAddress, HnsCovenant, HnsOutput

_VERSION = 1
_DESCRIPTOR_SIZE = 148
_HASH_DOMAIN = b"hns-rs/hns-swap/hns-htlc/v1/descriptor"
_SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


def _compressed_point_valid(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != 33:
        return False
    if public_key[0] not in (2, 3):
        return False
    x = int.from_bytes(public_key[1:], "big")
    if x >= _SECP256K1_P:
        return False
    y_squared = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
    y = pow(y_squared, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
    return y * y % _SECP256K1_P == y_squared and (y != 0 or public_key[0] == 2)


def _script_number(value):
    encoded = bytearray()
    while value:
        encoded.append(value & 0xFF)
        value >>= 8
    if encoded and encoded[-1] & 0x80:
        encoded.append(0)
    if len(encoded) == 1 and 1 <= encoded[0] <= 16:
        return bytes((0x50 + encoded[0],))
    return bytes((len(encoded),)) + encoded


@dataclass(frozen=True)
class HnsHtlc:
    network_magic: int
    genesis: bytes
    value: int
    hashlock: bytes
    receiver_public_key: bytes
    refund_public_key: bytes
    refund_locktime: int

    def validate(self):
        if (
            type(self.network_magic) is not int
            or not 0 <= self.network_magic <= 0xFFFFFFFF
        ):
            raise ValueError("invalid HNS network magic")
        if not isinstance(self.genesis, bytes) or len(self.genesis) != 32:
            raise ValueError("invalid HNS genesis hash")
        if type(self.value) is not int or not 0 < self.value <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("invalid HNS HTLC value")
        if (
            not isinstance(self.hashlock, bytes)
            or len(self.hashlock) != 32
            or self.hashlock == bytes(32)
        ):
            raise ValueError("invalid HNS HTLC hashlock")
        if not _compressed_point_valid(self.receiver_public_key):
            raise ValueError("invalid HNS receiver public key")
        if not _compressed_point_valid(self.refund_public_key):
            raise ValueError("invalid HNS refund public key")
        if self.receiver_public_key == self.refund_public_key:
            raise ValueError("reused HNS HTLC public key")
        if (
            type(self.refund_locktime) is not int
            or not 0 <= self.refund_locktime <= 0xFFFFFFFF
        ):
            raise ValueError("invalid HNS refund locktime")
        if self.refund_locktime & 0x7FFFFFFF == 0:
            raise ValueError("zero HNS refund locktime")

    def encode(self):
        self.validate()
        return (
            _VERSION.to_bytes(2, "little")
            + self.network_magic.to_bytes(4, "little")
            + self.genesis
            + self.value.to_bytes(8, "little")
            + self.hashlock
            + self.receiver_public_key
            + self.refund_public_key
            + self.refund_locktime.to_bytes(4, "little")
        )

    @classmethod
    def decode(cls, raw, expected_magic, expected_genesis):
        if not isinstance(raw, bytes) or len(raw) != _DESCRIPTOR_SIZE:
            raise ValueError("invalid HNS HTLC descriptor length")
        if int.from_bytes(raw[:2], "little") != _VERSION:
            raise ValueError("unsupported HNS HTLC descriptor version")
        descriptor = cls(
            int.from_bytes(raw[2:6], "little"),
            raw[6:38],
            int.from_bytes(raw[38:46], "little"),
            raw[46:78],
            raw[78:111],
            raw[111:144],
            int.from_bytes(raw[144:148], "little"),
        )
        descriptor.validate()
        if (
            descriptor.network_magic != expected_magic
            or descriptor.genesis != expected_genesis
        ):
            raise ValueError("HNS HTLC descriptor network mismatch")
        return descriptor

    def descriptor_hash(self):
        return hashlib.blake2b(_HASH_DOMAIN + self.encode(), digest_size=32).digest()

    def script(self):
        self.validate()
        return (
            b"\x63\xa8\x20"
            + self.hashlock
            + b"\x88\x21"
            + self.receiver_public_key
            + b"\x67"
            + _script_number(self.refund_locktime)
            + b"\xb1\x75\x21"
            + self.refund_public_key
            + b"\x68\xac"
        )

    def funding_address(self):
        return HnsAddress(0, witness_script_program(self.script()))

    def verify_funding_output(self, output):
        if (
            not isinstance(output, HnsOutput)
            or output.value != self.value
            or output.address != self.funding_address()
            or output.covenant != HnsCovenant(0)
        ):
            raise ValueError("HNS HTLC funding output mismatch")
