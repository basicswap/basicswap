"""Handshake version-zero payment and witness-script addresses."""

import hashlib

from basicswap.contrib.test_framework import segwit_addr

from .transaction import HnsAddress, HnsTransactionError

_HRP = {"mainnet": "hs", "testnet": "ts", "regtest": "rs"}


def _hrp(network):
    try:
        return _HRP[network]
    except (KeyError, TypeError) as exc:
        raise ValueError("unknown Handshake network") from exc


def payment_program(compressed_public_key: bytes) -> bytes:
    if (
        not isinstance(compressed_public_key, bytes)
        or len(compressed_public_key) != 33
        or compressed_public_key[0] not in (2, 3)
    ):
        raise ValueError("invalid compressed secp256k1 public key")
    return hashlib.blake2b(compressed_public_key, digest_size=20).digest()


def witness_script_program(script: bytes) -> bytes:
    if not isinstance(script, bytes) or not 1 <= len(script) <= 10_000:
        raise ValueError("invalid Handshake witness script")
    return hashlib.sha3_256(script).digest()


def encode_v0_address(network: str, program: bytes) -> str:
    address = HnsAddress(0, program)
    try:
        address.encode()
    except HnsTransactionError as exc:
        raise ValueError("invalid Handshake witness program") from exc
    result = segwit_addr.encode(_hrp(network), 0, program)
    if result is None:
        raise ValueError("could not encode Handshake address")
    return result


def decode_v0_address(network: str, text: str) -> HnsAddress:
    if not isinstance(text, str):
        raise ValueError("invalid Handshake address")
    version, program = segwit_addr.decode(_hrp(network), text)
    if version != 0 or program is None:
        raise ValueError("invalid Handshake version-zero address")
    return HnsAddress(0, bytes(program))
