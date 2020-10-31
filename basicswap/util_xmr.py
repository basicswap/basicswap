# -*- coding: utf-8 -*-

import xmrswap.contrib.Keccak as Keccak
from .contrib.MoneroPy.base58 import encode as xmr_b58encode


def cn_fast_hash(s):
    k = Keccak.Keccak()
    return k.Keccak((len(s) * 8, s.hex()), 1088, 512, 32 * 8, False).lower()  # r = bitrate = 1088, c = capacity, n = output length in bits


def encode_address(view_point, spend_point, version=18):
    buf = bytes((version,)) + spend_point + view_point
    h = cn_fast_hash(buf)
    buf = buf + bytes.fromhex(h[0: 8])

    return xmr_b58encode(buf.hex())
