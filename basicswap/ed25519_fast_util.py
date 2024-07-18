# -*- coding: utf-8 -*-

import secrets
import hashlib
import basicswap.contrib.ed25519_fast as edf


def get_secret():
    return 9 + secrets.randbelow(edf.l - 9)


def encodepoint(P):
    zi = edf.inv(P[2])
    x = (P[0] * zi) % edf.q
    y = (P[1] * zi) % edf.q
    y += (x & 1) << 255
    return y.to_bytes(32, byteorder="little")


def hashToEd25519(bytes_in):
    hashed = hashlib.sha256(bytes_in).digest()
    for i in range(1000):
        h255 = bytearray(hashed)
        x_sign = 0 if h255[31] & 0x80 == 0 else 1
        h255[31] &= 0x7F  # Clear top bit
        y = int.from_bytes(h255, byteorder="little")
        x = edf.xrecover(y, x_sign)
        if x == 0 and y == 1:  # Skip infinity point
            continue

        P = [x, y, 1, (x * y) % edf.q]
        # Keep trying until the point is in the correct subgroup
        if edf.isoncurve(P) and edf.is_identity(edf.scalarmult(P, edf.l)):
            return P
        hashed = hashlib.sha256(hashed).digest()
    raise ValueError("hashToEd25519 failed")
