#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hmac
import hashlib


zero = bytes((0,))
one = bytes((1,))


def rfc6979_hmac_sha256_initialize(key):
    rng_v = one * 32    # RFC6979 3.2.b.
    rng_k = zero * 32   # RFC6979 3.2.c.

    # RFC6979 3.2.d.
    h = hmac.new(rng_k, digestmod=hashlib.sha256)
    h.update(rng_v)
    h.update(zero)
    h.update(key)
    rng_k = h.digest()

    h = hmac.new(rng_k, digestmod=hashlib.sha256)
    h.update(rng_v)
    rng_v = h.digest()

    # RFC6979 3.2.f.
    h = hmac.new(rng_k, digestmod=hashlib.sha256)
    h.update(rng_v)
    h.update(one)
    h.update(key)
    rng_k = h.digest()
    h = hmac.new(rng_k, digestmod=hashlib.sha256)
    h.update(rng_v)
    rng_v = h.digest()

    return [rng_k, rng_v, False]


def rfc6979_hmac_sha256_generate(rng, n):
    if rng[2]:  # Retry
        h = hmac.new(rng[0], digestmod=hashlib.sha256)
        h.update(rng[1])
        h.update(zero)
        rng[0] = h.digest()
        h = hmac.new(rng[0], digestmod=hashlib.sha256)
        h.update(rng[1])
        rng[1] = h.digest()

    out = bytes()
    while n > 0:
        i = n if n < 32 else 32
        h = hmac.new(rng[0], digestmod=hashlib.sha256)
        h.update(rng[1])
        rng[1] = h.digest()
        out += rng[1][:i]
        n -= i

    rng[2] = True
    return out
