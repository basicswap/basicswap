#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import codecs
import hashlib
import secrets

from .contrib.ellipticcurve import CurveFp, Point, INFINITY, jacobi_symbol


class ECCParameters():
    def __init__(self, p, a, b, Gx, Gy, o):
        self.p = p
        self.a = a
        self.b = b
        self.Gx = Gx
        self.Gy = Gy
        self.o = o


ep = ECCParameters( \
    p  = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, \
    a  = 0x0, \
    b  = 0x7, \
    Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, \
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, \
    o  = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141)  # noqa: E221,E251,E502

curve_secp256k1 = CurveFp(ep.p, ep.a, ep.b)
G = Point(curve_secp256k1, ep.Gx, ep.Gy, ep.o)
SECP256K1_ORDER_HALF = ep.o // 2


def ToDER(P):
    return bytes((4, )) + int(P.x()).to_bytes(32, byteorder='big') + int(P.y()).to_bytes(32, byteorder='big')


def bytes32ToInt(b):
    return int.from_bytes(b, byteorder='big')


def intToBytes32(i):
    return i.to_bytes(32, byteorder='big')


def intToBytes32_le(i):
    return i.to_bytes(32, byteorder='little')


def bytesToHexStr(b):
    return codecs.encode(b, 'hex').decode('utf-8')


def hexStrToBytes(h):
    if h.startswith('0x'):
        h = h[2:]
    return bytes.fromhex(h)


def getSecretBytes():
    i = 1 + secrets.randbelow(ep.o - 1)
    return intToBytes32(i)


def getSecretInt():
    return 1 + secrets.randbelow(ep.o - 1)


def getInsecureBytes():
    while True:
        s = os.urandom(32)

        s_test = int.from_bytes(s, byteorder='big')
        if s_test > 1 and s_test < ep.o:
            return s


def getInsecureInt():
    while True:
        s = os.urandom(32)

        s_test = int.from_bytes(s, byteorder='big')
        if s_test > 1 and s_test < ep.o:
            return s_test


def powMod(x, y, z):
    # Calculate (x ** y) % z efficiently.
    number = 1
    while y:
        if y & 1:
            number = number * x % z
        y >>= 1  # y //= 2

        x = x * x % z
    return number


def ExpandPoint(xb, sign):
    x = int.from_bytes(xb, byteorder='big')
    a = (powMod(x, 3, ep.p) + 7) % ep.p
    y = powMod(a, (ep.p + 1) // 4, ep.p)

    if sign:
        y = ep.p - y
    return Point(curve_secp256k1, x, y, ep.o)


def CPKToPoint(cpk):
    y_parity = cpk[0] - 2

    x = int.from_bytes(cpk[1:], byteorder='big')
    a = (powMod(x, 3, ep.p) + 7) % ep.p
    y = powMod(a, (ep.p + 1) // 4, ep.p)

    if y % 2 != y_parity:
        y = ep.p - y

    return Point(curve_secp256k1, x, y, ep.o)


def pointToCPK2(point, ind=0x09):
    # The function is_square(x), where x is an integer, returns whether or not x is a quadratic residue modulo p. Since p is prime, it is equivalent to the Legendre symbol (x / p) = x(p-1)/2 mod p being equal to 1[8].
    ind = bytes((ind ^ (1 if jacobi_symbol(point.y(), ep.p) == 1 else 0),))
    return ind + point.x().to_bytes(32, byteorder='big')


def pointToCPK(point):

    y = point.y().to_bytes(32, byteorder='big')
    ind = bytes((0x03,)) if y[31] % 2 else bytes((0x02,))

    cpk = ind + point.x().to_bytes(32, byteorder='big')
    return cpk


def secretToCPK(secret):
    secretInt = secret if isinstance(secret, int) \
        else int.from_bytes(secret, byteorder='big')

    R = G * secretInt

    Y = R.y().to_bytes(32, byteorder='big')
    ind = bytes((0x03,)) if Y[31] % 2 else bytes((0x02,))

    pubkey = ind + R.x().to_bytes(32, byteorder='big')

    return pubkey


def getKeypair():
    secretBytes = getSecretBytes()
    return secretBytes, secretToCPK(secretBytes)


def hashToCurve(pubkey):

    xBytes = hashlib.sha256(pubkey).digest()
    x = int.from_bytes(xBytes, byteorder='big')

    for k in range(0, 100):
        # get matching y element for point
        y_parity = 0  # always pick 0,
        a = (powMod(x, 3, ep.p) + 7) % ep.p
        y = powMod(a, (ep.p + 1) // 4, ep.p)

        # print("before parity %x" % (y))
        if y % 2 != y_parity:
            y = ep.p - y

        # If x is always mod P, can R ever not be on the curve?
        try:
            R = Point(curve_secp256k1, x, y, ep.o)
        except Exception:
            x = (x + 1) % ep.p  # % P?
            continue

        if R == INFINITY or R * ep.o != INFINITY:  # is R * O != INFINITY check necessary?  Validation of Elliptic Curve Public Keys says no if cofactor = 1
            x = (x + 1) % ep.p  # % P?
            continue
        return R

    raise ValueError('hashToCurve failed for 100 tries')


def hash256(inb):
    return hashlib.sha256(inb).digest()


i2b = intToBytes32
b2i = bytes32ToInt
b2h = bytesToHexStr
h2b = hexStrToBytes


def i2h(x):
    return b2h(i2b(x))


def testEccUtils():
    print('testEccUtils()')

    G_enc = ToDER(G)
    assert(G_enc.hex() == '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')

    G_enc = pointToCPK(G)
    assert(G_enc.hex() == '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    G_dec = CPKToPoint(G_enc)
    assert(G_dec == G)

    G_enc = pointToCPK2(G)
    assert(G_enc.hex() == '0879be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')

    H = hashToCurve(ToDER(G))
    assert(pointToCPK(H).hex() == '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0')

    print('Passed.')


if __name__ == "__main__":
    testEccUtils()
