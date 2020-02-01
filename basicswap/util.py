# -*- coding: utf-8 -*-

# Copyright (c) 2018-2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import decimal
import json
import hashlib
from .segwit_addr import bech32_decode, convertbits, bech32_encode

COIN = 100000000
DCOIN = decimal.Decimal(COIN)


def makeInt(v):
    return int(dquantize(decimal.Decimal(v) * DCOIN).quantize(decimal.Decimal(1)))


def format8(i):
    n = abs(i)
    quotient = n // COIN
    remainder = n % COIN
    rv = "%d.%08d" % (quotient, remainder)
    if i < 0:
        rv = '-' + rv
    return rv


def toBool(s):
    return s.lower() in ["1", "true"]


def dquantize(n, places=8):
    return n.quantize(decimal.Decimal(10) ** -places)


def jsonDecimal(obj):
    if isinstance(obj, decimal.Decimal):
        return str(obj)
    raise TypeError


def dumpj(jin, indent=4):
    return json.dumps(jin, indent=indent, default=jsonDecimal)


def dumpje(jin):
    return json.dumps(jin, default=jsonDecimal).replace('"', '\\"')


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


def decodeWif(network_key):
    key = b58decode(network_key)[1:-4]
    if len(key) == 33:
        return key[:-1]
    return key


def toWIF(prefix_byte, b, compressed=True):
    b = bytes((prefix_byte, )) + b
    if compressed:
        b += bytes((0x01, ))
    b += hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    return b58encode(b)


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


def decodeAddress(address_str):
    b58_addr = b58decode(address_str)
    if b58_addr is not None:
        address = b58_addr[:-4]
        checksum = b58_addr[-4:]
        assert(hashlib.sha256(hashlib.sha256(address).digest()).digest()[:4] == checksum), 'Checksum mismatch'
        return b58_addr[:-4]
    return None


def encodeAddress(address):
    checksum = hashlib.sha256(hashlib.sha256(address).digest()).digest()
    return b58encode(address + checksum[0:4])


def getKeyID(bytes):
    data = hashlib.sha256(bytes).digest()
    return hashlib.new("ripemd160", data).digest()


def pubkeyToAddress(prefix, pubkey):
    return encodeAddress(bytes((prefix,)) + getKeyID(pubkey))


def SerialiseNum(n):
    if n == 0:
        return bytes([0x00])
    if n > 0 and n <= 16:
        return bytes([0x50 + n])
    rv = bytearray()
    neg = n < 0
    absvalue = -n if neg else n
    while(absvalue):
        rv.append(absvalue & 0xff)
        absvalue >>= 8
    if rv[-1] & 0x80:
        rv.append(0x80 if neg else 0)
    elif neg:
        rv[-1] |= 0x80
    return bytes([len(rv)]) + rv


def DeserialiseNum(b, o=0):
    if b[o] == 0:
        return 0
    if b[o] > 0x50 and b[o] <= 0x50 + 16:
        return b[o] - 0x50
    v = 0
    nb = b[o]
    o += 1
    for i in range(0, nb):
        v |= b[o + i] << (8 * i)
    # If the input vector's most significant byte is 0x80, remove it from the result's msb and return a negative.
    if b[o + nb - 1] & 0x80:
        return -(v & ~(0x80 << (8 * (nb - 1))))
    return v
