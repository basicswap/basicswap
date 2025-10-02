#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import secrets

from . import i2b


class ECCParameters:
    def __init__(self, p, a, b, Gx, Gy, o):
        self.p = p
        self.a = a
        self.b = b
        self.Gx = Gx
        self.Gy = Gy
        self.o = o


ep = ECCParameters(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0x0,
    b=0x7,
    Gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    Gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    o=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


def getSecretBytes() -> bytes:
    i = 1 + secrets.randbelow(ep.o - 1)
    return i2b(i)


def getSecretInt() -> int:
    return 1 + secrets.randbelow(ep.o - 1)


def getInsecureBytes() -> bytes:
    while True:
        s = os.urandom(32)

        s_test = int.from_bytes(s, byteorder="big")
        if s_test > 1 and s_test < ep.o:
            return s


def getInsecureInt() -> int:
    while True:
        s = os.urandom(32)

        s_test = int.from_bytes(s, byteorder="big")
        if s_test > 1 and s_test < ep.o:
            return s_test
