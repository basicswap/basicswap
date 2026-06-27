# -*- coding: utf-8 -*-

import basicswap.contrib.Keccak as Keccak
from basicswap.util.integer import encode_varint
from .contrib.MoneroPy.base58 import (
    decode as xmr_b58decode,
    encode as xmr_b58encode,
)


def cn_fast_hash(s):
    k = Keccak.Keccak()
    return k.Keccak(
        (len(s) * 8, s.hex()), 1088, 512, 32 * 8, False
    ).lower()  # r = bitrate = 1088, c = capacity, n = output length in bits


def encode_address(view_point: bytes, spend_point: bytes, version=18) -> str:
    prefix_bytes = version if isinstance(version, bytes) else encode_varint(version)
    buf = prefix_bytes + spend_point + view_point
    h = cn_fast_hash(buf)
    buf = buf + bytes.fromhex(h[0:8])

    return xmr_b58encode(buf.hex())


def decode_address(address: str, version=18) -> (bytes, bytes):
    prefix_bytes = version if isinstance(version, bytes) else encode_varint(version)
    data: bytes = bytes.fromhex(xmr_b58decode(address))
    data_hash: bytes = data[-4:]
    data = data[:-4]

    data_prefix = data[: len(prefix_bytes)]
    if prefix_bytes != data_prefix:
        raise ValueError("Prefix mismatch")

    h = cn_fast_hash(data)
    check_hash: bytes = bytes.fromhex(h[0:8])
    if check_hash != data_hash:
        raise ValueError("Checksum mismatch")

    Ks = data[len(prefix_bytes) : len(prefix_bytes) + 32]
    Kv = data[len(prefix_bytes) + 32 : len(prefix_bytes) + 64]
    return Ks, Kv
