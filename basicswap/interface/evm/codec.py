# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""The swap contracts' ABIs hold only static types, so the ABI codec refuses any other."""

import re

from Crypto.Hash import keccak as _keccak


def keccak(data: bytes) -> bytes:
    return _keccak.new(digest_bits=256, data=bytes(data)).digest()


_HEX_ADDRESS = re.compile(r"^(0[xX])?[0-9a-fA-F]{40}$")


def _address_hex(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 20:
            raise ValueError("Address must be 20 bytes")
        return bytes(value).hex()
    if not isinstance(value, str) or not _HEX_ADDRESS.match(value):
        raise ValueError(f"Invalid address: {value!r}")
    return value[-40:].lower()


def to_checksum_address(value) -> str:
    """EIP-55."""
    lower: str = _address_hex(value)
    digest: str = keccak(lower.encode()).hex()
    return "0x" + "".join(
        c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c
        for i, c in enumerate(lower)
    )


def to_canonical_address(value) -> bytes:
    return bytes.fromhex(_address_hex(value))


def is_address(value) -> bool:
    """20 bytes, or 40 hex digits; mixed case must be the EIP-55 checksum."""
    if isinstance(value, (bytes, bytearray)):
        return len(value) == 20
    if not isinstance(value, str) or not _HEX_ADDRESS.match(value):
        return False
    digits: str = value[-40:]
    if digits.lower() == digits or digits.upper() == digits:
        return True
    return to_checksum_address(value)[2:] == digits


def filter_abi_by_type(abi_type: str, abi: list) -> list:
    return [e for e in abi if e.get("type") == abi_type]


def collapse_if_tuple(param: dict) -> str:
    t: str = param["type"]
    if not t.startswith("tuple"):
        return t
    inner: str = ",".join(collapse_if_tuple(c) for c in param["components"])
    return f"({inner}){t[len('tuple'):]}"


def get_abi_input_types(entry: dict) -> list:
    return [collapse_if_tuple(p) for p in entry.get("inputs", [])]


def get_abi_output_types(entry: dict) -> list:
    return [collapse_if_tuple(p) for p in entry.get("outputs", [])]


def _signature(entry: dict) -> str:
    return f"{entry['name']}({','.join(get_abi_input_types(entry))})"


def function_signature_to_4byte_selector(signature: str) -> bytes:
    return keccak(signature.encode())[:4]


def function_abi_to_4byte_selector(entry: dict) -> bytes:
    return function_signature_to_4byte_selector(_signature(entry))


def event_abi_to_log_topic(entry: dict) -> bytes:
    return keccak(_signature(entry).encode())


def _split_tuple(t: str) -> list:
    """The member types of "(a,(b,c),d)"."""
    parts, depth, start = [], 0, 1
    for i, c in enumerate(t[1:-1], 1):
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(t[start:i])
            start = i + 1
    if start < len(t) - 1:
        parts.append(t[start:-1])
    return parts


def _uint_bits(t: str) -> int:
    bits = int(t[4:]) if t != "uint" else 256
    if bits < 8 or bits > 256 or bits % 8 != 0:
        raise ValueError(f"Invalid ABI type {t}")
    return bits


def _static_words(t: str) -> int:
    if t.startswith("(") and t.endswith(")"):
        return sum(_static_words(m) for m in _split_tuple(t))
    if t in ("address", "bool", "bytes32") or re.fullmatch(r"uint\d*", t):
        if t.startswith("uint"):
            _uint_bits(t)
        return 1
    raise ValueError(f"Unsupported ABI type {t}")


def _encode_one(t: str, value) -> bytes:
    if t.startswith("("):
        members = _split_tuple(t)
        if len(members) != len(value):
            raise ValueError(f"{t} takes {len(members)} values, not {len(value)}")
        return b"".join(_encode_one(m, v) for m, v in zip(members, value))
    if t == "address":
        if not is_address(value):
            raise ValueError(f"Invalid address: {value!r}")
        return bytes(12) + to_canonical_address(value)
    if t == "bool":
        if not isinstance(value, bool):
            raise ValueError("bool value required")
        return int(value).to_bytes(32, "big")
    if t == "bytes32":
        value = bytes(value)
        if len(value) > 32:
            raise ValueError("bytes32 value longer than 32 bytes")
        return value.ljust(32, b"\x00")
    bits: int = _uint_bits(t)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{t} value must be an int")
    if value < 0 or value >= 1 << bits:
        raise ValueError(f"{t} value out of range")
    return value.to_bytes(32, "big")


def abi_encode(types: list, values) -> bytes:
    if len(types) != len(values):
        raise ValueError(f"{len(types)} types for {len(values)} values")
    for t in types:
        _static_words(t)
    return b"".join(_encode_one(t, v) for t, v in zip(types, values))


def _decode_one(t: str, data: bytes, offset: int):
    if t.startswith("("):
        values = []
        for m in _split_tuple(t):
            v, offset = _decode_one(m, data, offset)
            values.append(v)
        return tuple(values), offset
    word: bytes = data[offset : offset + 32]
    offset += 32
    if t == "bytes32":
        return word, offset
    n: int = int.from_bytes(word, "big")
    if t == "address":
        if n >> 160:
            raise ValueError("Address word has non-zero padding")
        return to_checksum_address(word[12:]), offset
    if t == "bool":
        if n > 1:
            raise ValueError("bool word is not 0 or 1")
        return n == 1, offset
    if n >> _uint_bits(t):
        raise ValueError(f"{t} word out of range")
    return n, offset


def abi_decode(types: list, data: bytes) -> tuple:
    data = bytes(data)
    if len(data) < 32 * sum(_static_words(t) for t in types):
        raise ValueError("Too few bytes to decode")
    values, offset = [], 0
    for t in types:
        v, offset = _decode_one(t, data, offset)
        values.append(v)
    return tuple(values)


def _rlp_length(length: int, short_base: int) -> bytes:
    if length <= 55:
        return bytes((short_base + length,))
    length_bytes: bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((short_base + 55 + len(length_bytes),)) + length_bytes


def rlp_encode(item) -> bytes:
    if isinstance(item, (list, tuple)):
        payload: bytes = b"".join(rlp_encode(i) for i in item)
        return _rlp_length(len(payload), 0xC0) + payload
    if isinstance(item, bool):
        raise ValueError("RLP has no bool")
    if isinstance(item, int):
        if item < 0:
            raise ValueError("RLP integers are unsigned")
        item = item.to_bytes((item.bit_length() + 7) // 8, "big")
    item = bytes(item)
    if len(item) == 1 and item[0] < 0x80:
        return item
    return _rlp_length(len(item), 0x80) + item


def _rlp_item(data: bytes, offset: int):
    """(item, end) for the canonical item at offset."""
    if offset >= len(data):
        raise ValueError("RLP item past the end")
    prefix: int = data[offset]
    if prefix < 0x80:
        return data[offset : offset + 1], offset + 1
    is_list: bool = prefix >= 0xC0
    base: int = 0xC0 if is_list else 0x80
    if prefix - base <= 55:
        length, start = prefix - base, offset + 1
    else:
        num: int = prefix - base - 55
        length_bytes: bytes = data[offset + 1 : offset + 1 + num]
        if len(length_bytes) != num or length_bytes[0] == 0:
            raise ValueError("Non-canonical RLP length")
        length, start = int.from_bytes(length_bytes, "big"), offset + 1 + num
        if length <= 55:
            raise ValueError("Non-canonical RLP length")
    end: int = start + length
    if end > len(data):
        raise ValueError("RLP item past the end")
    if not is_list:
        if length == 1 and data[start] < 0x80:
            raise ValueError("Non-canonical RLP single byte")
        return data[start:end], end
    items, pos = [], start
    while pos < end:
        item, pos = _rlp_item(data, pos)
        items.append(item)
    if pos != end:
        raise ValueError("RLP list overruns its length")
    return items, end


def rlp_decode(data: bytes):
    data = bytes(data)
    item, end = _rlp_item(data, 0)
    if end != len(data):
        raise ValueError("Trailing bytes after RLP item")
    return item
