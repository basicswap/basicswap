# -*- coding: utf-8 -*-

# Copyright (c) 2018-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


import json
import time
import decimal


COIN = 100000000


decimal_ctx = decimal.Context()
decimal_ctx.prec = 20


class TemporaryError(ValueError):
    pass


class AutomationConstraint(ValueError):
    pass


class InactiveCoin(Exception):
    def __init__(self, coinid):
        self.coinid = coinid

    def __str__(self):
        return str(self.coinid)


class LockedCoinError(Exception):
    def __init__(self, coinid):
        self.coinid = coinid

    def __str__(self):
        return 'Coin must be unlocked: ' + str(self.coinid)


def ensure(v, err_string):
    if not v:
        raise ValueError(err_string)


def toBool(s) -> bool:
    if isinstance(s, bool):
        return s
    return s.lower() in ['1', 'true']


def jsonDecimal(obj):
    if isinstance(obj, decimal.Decimal):
        return str(obj)
    raise TypeError


def dumpj(jin, indent=4):
    return json.dumps(jin, indent=indent, default=jsonDecimal)


def dumpje(jin):
    return json.dumps(jin, default=jsonDecimal).replace('"', '\\"')


def SerialiseNum(n):
    if n == 0:
        return bytes((0x00,))
    if n > 0 and n <= 16:
        return bytes((0x50 + n,))
    rv = bytearray()
    neg = n < 0
    absvalue = -n if neg else n
    while (absvalue):
        rv.append(absvalue & 0xff)
        absvalue >>= 8
    if rv[-1] & 0x80:
        rv.append(0x80 if neg else 0)
    elif neg:
        rv[-1] |= 0x80
    return bytes((len(rv),)) + rv


def DeserialiseNum(b, o=0) -> int:
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


def float_to_str(f):
    # stackoverflow.com/questions/38847690
    d1 = decimal_ctx.create_decimal(repr(f))
    return format(d1, 'f')


def make_int(v, scale=8, r=0):  # r = 0, no rounding, fail, r > 0 round up, r < 0 floor
    if type(v) == float:
        v = float_to_str(v)
    elif type(v) == int:
        return v * 10 ** scale

    sign = 1
    if v[0] == '-':
        v = v[1:]
        sign = -1
    ep = 10 ** scale
    have_dp = False
    rv = 0
    for c in v:
        if c == '.':
            rv *= ep
            have_dp = True
            continue
        if not c.isdigit():
            raise ValueError('Invalid char: ' + c)
        if have_dp:
            ep //= 10
            if ep <= 0:
                if r == 0:
                    raise ValueError('Mantissa too long')
                if r > 0:
                    # Round up
                    if int(c) > 4:
                        rv += 1
                break
            rv += ep * int(c)
        else:
            rv = rv * 10 + int(c)
    if not have_dp:
        rv *= ep
    return rv * sign


def validate_amount(amount, scale=8) -> bool:
    str_amount = float_to_str(amount) if type(amount) == float else str(amount)
    has_decimal = False
    for c in str_amount:
        if c == '.' and not has_decimal:
            has_decimal = True
            continue
        if not c.isdigit():
            raise ValueError('Invalid amount')

    ar = str_amount.split('.')
    if len(ar) > 1 and len(ar[1]) > scale:
        raise ValueError('Too many decimal places in amount {}'.format(str_amount))
    return True


def format_amount(i, display_scale, scale=None):
    if not isinstance(i, int):
        raise ValueError('Amount must be an integer.')  # Raise error instead of converting as amounts should always be integers
    if scale is None:
        scale = display_scale
    ep = 10 ** scale
    n = abs(i)
    quotient = n // ep
    remainder = n % ep
    if display_scale != scale:
        remainder %= (10 ** display_scale)
    rv = '{}.{:0>{scale}}'.format(quotient, remainder, scale=display_scale)
    if i < 0:
        rv = '-' + rv
    return rv


def format_timestamp(value, with_seconds=False):
    str_format = '%Y-%m-%d %H:%M'
    if with_seconds:
        str_format += ':%S'
    str_format += ' %Z'
    return time.strftime(str_format, time.localtime(value))


def b2i(b) -> int:
    # bytes32ToInt
    return int.from_bytes(b, byteorder='big')


def i2b(i: int) -> bytes:
    # intToBytes32
    return i.to_bytes(32, byteorder='big')


def b2h(b: bytes) -> str:
    return b.hex()


def h2b(h: str) -> bytes:
    if h.startswith('0x'):
        h = h[2:]
    return bytes.fromhex(h)


def i2h(x):
    return b2h(i2b(x))
