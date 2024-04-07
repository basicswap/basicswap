# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.contrib.segwit_addr import bech32_decode, convertbits, bech32_encode
from basicswap.util.crypto import ripemd160, sha256

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58decode(v, length=None):
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        ofs = __b58chars.find(c)
        if ofs < 0:
            return None
        long_value += ofs * (58**i)
    result = bytes()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result = bytes((mod,)) + result
        long_value = div
    result = bytes((long_value,)) + result
    nPad = 0
    for c in v:
        if c == __b58chars[0]:
            nPad += 1
        else:
            break
    pad = bytes((0,)) * nPad
    result = pad + result
    if length is not None and len(result) != length:
        return None
    return result


def b58encode(v):
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * c

    result = ''
    while long_value >= 58:
        div, mod = divmod(long_value, 58)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0:
            nPad += 1
        else:
            break
    return (__b58chars[0] * nPad) + result


def encodeStealthAddress(prefix_byte: int, scan_pubkey: bytes, spend_pubkey: bytes) -> str:
    data = bytes((0x00,))
    data += scan_pubkey
    data += bytes((0x01,))
    data += spend_pubkey
    data += bytes((0x00,))  # number_signatures - unused
    data += bytes((0x00,))  # num prefix bits

    b = bytes((prefix_byte,)) + data
    b += sha256(sha256(b))[:4]
    return b58encode(b)


def decodeWif(encoded_key: str) -> bytes:
    key = b58decode(encoded_key)[1:-4]
    if len(key) == 33:
        return key[:-1]
    return key


def toWIF(prefix_byte: int, b: bytes, compressed: bool = True) -> str:
    b = bytes((prefix_byte,)) + b
    if compressed:
        b += bytes((0x01,))
    b += sha256(sha256(b))[:4]
    return b58encode(b)


def getKeyID(key_data: bytes) -> bytes:
    return ripemd160(sha256(key_data))


def bech32Decode(hrp, addr):
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return None
    decoded = convertbits(data, 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return None
    return bytes(decoded)


def bech32Encode(hrp, data):
    ret = bech32_encode(hrp, convertbits(data, 8, 5))
    if bech32Decode(hrp, ret) is None:
        return None
    return ret


def decodeAddress(address: str):
    addr_data = b58decode(address)
    if addr_data is None:
        return None
    prefixed_data = addr_data[:-4]
    checksum = addr_data[-4:]
    if sha256(sha256(prefixed_data))[:4] != checksum:
        raise ValueError('Checksum mismatch')
    return prefixed_data


def encodeAddress(address: bytes) -> str:
    checksum = sha256(sha256(address))
    return b58encode(address + checksum[0:4])


def pubkeyToAddress(prefix: int, pubkey: bytes) -> str:
    return encodeAddress(bytes((prefix,)) + getKeyID(pubkey))
