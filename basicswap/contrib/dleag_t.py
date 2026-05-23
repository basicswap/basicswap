#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""pure python dleag with parameterised generators, mirrors basicswap/secp256k1 src/modules/dleag/main_impl.h."""

import hashlib
import hmac
from typing import List, Tuple


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
ED25519_L = 2**252 + 27742317777372353535851937790883648493
_ED25519_P = 2**255 - 19
_ED25519_D = -121665 * pow(121666, -1, _ED25519_P) % _ED25519_P


# H y ends in 0x04 so prefix is 0x02.
SECP256K1_H_COMPRESSED = bytes.fromhex(
    "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)
ED25519_B2_COMPRESSED = bytes.fromhex(
    "13b663e5e06bf5301c77473bb2fc5beb51e4046e9b7efef2f6d1a324cb8b1094"
)
ED25519_B_COMPRESSED = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)
SECP256K1_G_COMPRESSED = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

DLEAG_SIG_MESSAGE = b"dleag message"


# secp256k1 scalars

def secp_scalar_from_bytes(b: bytes, *, allow_overflow: bool = False) -> int:
    if len(b) != 32:
        raise ValueError("secp256k1 scalar must be 32 bytes")
    v = int.from_bytes(b, "big")
    if v >= SECP256K1_N and not allow_overflow:
        raise ValueError("secp256k1 scalar overflow")
    return v % SECP256K1_N


def secp_scalar_to_bytes(s: int) -> bytes:
    return (s % SECP256K1_N).to_bytes(32, "big")


def secp_scalar_add(a: int, b: int) -> int:
    return (a + b) % SECP256K1_N


def secp_scalar_sub(a: int, b: int) -> int:
    return (a - b) % SECP256K1_N


def secp_scalar_mul(a: int, b: int) -> int:
    return (a * b) % SECP256K1_N


def secp_scalar_neg(a: int) -> int:
    return (-a) % SECP256K1_N


def secp_scalar_inv(a: int) -> int:
    if a % SECP256K1_N == 0:
        raise ValueError("Cannot invert zero")
    return pow(a, SECP256K1_N - 2, SECP256K1_N)


def secp_scalar_is_zero(a: int) -> bool:
    return (a % SECP256K1_N) == 0


# ed25519 scalars

def ed_scalar_from_bytes_be(b: bytes, *, allow_overflow: bool = False) -> int:
    if len(b) != 32:
        raise ValueError("ed25519 scalar must be 32 bytes")
    v = int.from_bytes(b, "big")
    if v >= ED25519_L and not allow_overflow:
        raise ValueError("ed25519 scalar overflow")
    return v % ED25519_L


def ed_scalar_to_bytes_be(s: int) -> bytes:
    return (s % ED25519_L).to_bytes(32, "big")


def ed_scalar_from_bytes_le(b: bytes) -> int:
    if len(b) != 32:
        raise ValueError("ed25519 scalar must be 32 bytes")
    return int.from_bytes(b, "little") % ED25519_L


def ed_scalar_to_bytes_le(s: int) -> bytes:
    return (s % ED25519_L).to_bytes(32, "little")


def ed_scalar_add(a: int, b: int) -> int:
    return (a + b) % ED25519_L


def ed_scalar_sub(a: int, b: int) -> int:
    return (a - b) % ED25519_L


def ed_scalar_mul(a: int, b: int) -> int:
    return (a * b) % ED25519_L


def ed_scalar_neg(a: int) -> int:
    return (-a) % ED25519_L


def ed_scalar_inv(a: int) -> int:
    if a % ED25519_L == 0:
        raise ValueError("Cannot invert zero")
    return pow(a, ED25519_L - 2, ED25519_L)


def ed_scalar_is_zero(a: int) -> bool:
    return (a % ED25519_L) == 0


def ed_decode_check_scalar(b: bytes) -> int:
    # Mirrors ed25519_decode_check_scalar: reject overflow and first 30 BE bytes all zero.
    if len(b) != 32:
        raise ValueError("ed25519 scalar must be 32 bytes")
    v = int.from_bytes(b, "big")
    if v >= ED25519_L:
        raise ValueError("ed25519 scalar overflow")
    if all(x == 0 for x in b[:30]):
        raise ValueError("ed25519 scalar below minimum")
    return v


# ed25519 points in extended twisted Edwards coords (X, Y, Z, T).

_ED25519_IDENTITY: Tuple[int, int, int, int] = (0, 1, 1, 0)


def _ed_recover_x(y: int, sign: int):
    if y >= _ED25519_P:
        return None
    x2 = (
        (y * y - 1)
        * pow(_ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P)
        % _ED25519_P
    )
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - x2) % _ED25519_P != 0:
        x = x * pow(2, (_ED25519_P - 1) // 4, _ED25519_P) % _ED25519_P
    if (x * x - x2) % _ED25519_P != 0:
        return None
    if (x & 1) != sign:
        x = _ED25519_P - x
    return x


def ed_decompress(b: bytes) -> Tuple[int, int, int, int]:
    if len(b) != 32:
        raise ValueError("Invalid ed25519 point length")
    y_bytes = bytearray(b)
    sign = y_bytes[31] >> 7
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    x = _ed_recover_x(y, sign)
    if x is None:
        raise ValueError("Point not on ed25519 curve")
    return (x, y, 1, x * y % _ED25519_P)


def ed_compress(P: Tuple[int, int, int, int]) -> bytes:
    x, y, z, _t = P
    zinv = pow(z, _ED25519_P - 2, _ED25519_P)
    x = x * zinv % _ED25519_P
    y = y * zinv % _ED25519_P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def ed_point_add(
    P: Tuple[int, int, int, int], Q: Tuple[int, int, int, int]
) -> Tuple[int, int, int, int]:
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    A = (y1 - x1) * (y2 - x2) % _ED25519_P
    B = (y1 + x1) * (y2 + x2) % _ED25519_P
    C = 2 * t1 * t2 * _ED25519_D % _ED25519_P
    D = 2 * z1 * z2 % _ED25519_P
    E = B - A
    F = D - C
    G = D + C
    H = B + A
    return (
        E * F % _ED25519_P,
        G * H % _ED25519_P,
        F * G % _ED25519_P,
        E * H % _ED25519_P,
    )


def ed_point_neg(P: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    x, y, z, t = P
    return ((-x) % _ED25519_P, y, z, (-t) % _ED25519_P)


def ed_point_sub(
    P: Tuple[int, int, int, int], Q: Tuple[int, int, int, int]
) -> Tuple[int, int, int, int]:
    return ed_point_add(P, ed_point_neg(Q))


def ed_point_mul(s: int, P: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    s = s % ED25519_L
    Q = _ED25519_IDENTITY
    if s == 0:
        return Q
    while s > 0:
        if s & 1:
            Q = ed_point_add(Q, P)
        P = ed_point_add(P, P)
        s >>= 1
    return Q


def ed_point_eq(
    P: Tuple[int, int, int, int], Q: Tuple[int, int, int, int]
) -> bool:
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    return (
        (x1 * z2 - x2 * z1) % _ED25519_P == 0
        and (y1 * z2 - y2 * z1) % _ED25519_P == 0
    )


ED25519_B_POINT = ed_decompress(ED25519_B_COMPRESSED)
ED25519_B2_POINT = ed_decompress(ED25519_B2_COMPRESSED)


def ed_canonical(b: bytes) -> bool:
    if len(b) != 32:
        return False
    bb = bytearray(b)
    bb[31] &= 0x7F
    y = int.from_bytes(bb, "little")
    return y < _ED25519_P


def ed_in_main_subgroup(P: Tuple[int, int, int, int]) -> bool:
    return ed_point_eq(ed_point_mul(ED25519_L, P), _ED25519_IDENTITY)


def ed_decode_check_point(b: bytes) -> Tuple[int, int, int, int]:
    # Reject non canonical, identity, small order, off curve, non main subgroup.
    if not ed_canonical(b):
        raise ValueError("Non canonical ed25519 point encoding")
    P = ed_decompress(b)
    if ed_point_eq(P, _ED25519_IDENTITY):
        raise ValueError("ed25519 identity point rejected")
    if not ed_in_main_subgroup(P):
        raise ValueError("ed25519 point not on main subgroup")
    return P


# secp256k1 points via coincurve, lazy imported.

def secp_point_from_bytes(b: bytes):
    if len(b) not in (33, 65):
        raise ValueError("secp256k1 point must be 33 or 65 bytes")
    from coincurve import PublicKey

    return PublicKey(b)


def secp_point_to_bytes(P) -> bytes:
    return P.format(compressed=True)


def secp_point_mul(s: int, P_bytes: bytes) -> bytes:
    s = s % SECP256K1_N
    if s == 0:
        raise ValueError("secp256k1 scalar mult by zero produces identity")
    from coincurve import PublicKey

    P = PublicKey(P_bytes)
    out = P.multiply(secp_scalar_to_bytes(s))
    return out.format(compressed=True)


def secp_point_add(P_bytes: bytes, Q_bytes: bytes) -> bytes:
    from coincurve import PublicKey

    combined = PublicKey.combine_keys([PublicKey(P_bytes), PublicKey(Q_bytes)])
    return combined.format(compressed=True)


def secp_point_neg(P_bytes: bytes) -> bytes:
    if len(P_bytes) != 33 or P_bytes[0] not in (0x02, 0x03):
        raise ValueError("Expected compressed secp256k1 point")
    return bytes([0x05 - P_bytes[0]]) + P_bytes[1:]


def secp_point_sub(P_bytes: bytes, Q_bytes: bytes) -> bytes:
    return secp_point_add(P_bytes, secp_point_neg(Q_bytes))


def secp_base_mul(s: int) -> bytes:
    return secp_point_mul(s, SECP256K1_G_COMPRESSED)


# Transcript hashing.

def dleag_hash(
    preimage: bytes, bJ: bytes, bK: bytes, ring_i: int, epos_j: int
) -> bytes:
    h = hashlib.sha256()
    h.update(preimage)
    h.update(bJ)
    h.update(bK)
    h.update(ring_i.to_bytes(4, "big"))
    h.update(epos_j.to_bytes(4, "big"))
    return h.digest()


def hash_sc_secp256k1(seed: bytes) -> int:
    cur = bytes(seed)
    for _ in range(1000):
        v = int.from_bytes(cur, "big")
        if v != 0 and v < SECP256K1_N:
            return v
        cur = hashlib.sha256(cur).digest()
    raise ValueError("hash_sc_secp256k1 failed to converge")


def hash_sc_ed25519(seed: bytes) -> int:
    cur = bytearray(seed)
    if len(cur) != 32:
        raise ValueError("hash_sc_ed25519 expects 32 input bytes")
    for _ in range(1000):
        cur[0] &= 0x1F
        v = int.from_bytes(bytes(cur), "big")
        if v < ED25519_L:
            return v
        cur = bytearray(hashlib.sha256(bytes(cur)).digest())
    raise ValueError("hash_sc_ed25519 failed to converge")


# RFC 6979 HMAC SHA256 RNG matching secp256k1_rfc6979_hmac_sha256.

class Rfc6979HmacSha256:

    def __init__(self, seed: bytes):
        self._v = b"\x01" * 32
        self._k = b"\x00" * 32
        self._k = hmac.new(
            self._k, self._v + b"\x00" + bytes(seed), hashlib.sha256
        ).digest()
        self._v = hmac.new(self._k, self._v, hashlib.sha256).digest()
        self._k = hmac.new(
            self._k, self._v + b"\x01" + bytes(seed), hashlib.sha256
        ).digest()
        self._v = hmac.new(self._k, self._v, hashlib.sha256).digest()
        self._retry = False

    def generate(self, n: int) -> bytes:
        if self._retry:
            self._k = hmac.new(
                self._k, self._v + b"\x00", hashlib.sha256
            ).digest()
            self._v = hmac.new(self._k, self._v, hashlib.sha256).digest()
        out = bytearray()
        while len(out) < n:
            self._v = hmac.new(self._k, self._v, hashlib.sha256).digest()
            out.extend(self._v)
        self._retry = True
        return bytes(out[:n])


def get_sc_secp256k1(rng: Rfc6979HmacSha256) -> int:
    while True:
        tmp = rng.generate(32)
        v = int.from_bytes(tmp, "big")
        if v != 0 and v < SECP256K1_N:
            return v


def get_sc_ed25519(rng: Rfc6979HmacSha256) -> int:
    while True:
        tmp = bytearray(rng.generate(32))
        tmp[0] &= 0x1F
        v = int.from_bytes(bytes(tmp), "big")
        if v < ED25519_L:
            return v


def key_bit(key_be: bytes, i: int) -> int:
    return (key_be[31 - (i // 8)] >> (i % 8)) & 1


def power_of_two_secp(i: int) -> int:
    return pow(2, i, SECP256K1_N)


def power_of_two_ed(i: int) -> int:
    return pow(2, i, ED25519_L)


# Parameterised eddsa, differs from RFC 8032 in that seckey is a raw scalar and gen is configurable.

def _is_ed_seckey_in_range(key_be32: bytes) -> bool:
    # C check: 0 < seckey < L and first 30 BE bytes not all zero.
    if len(key_be32) != 32:
        return False
    v = int.from_bytes(key_be32, "big")
    if v == 0 or v >= ED25519_L:
        return False
    if all(b == 0 for b in key_be32[:30]):
        return False
    return True


def _ed_has_small_order(P: Tuple[int, int, int, int]) -> bool:
    return ed_point_eq(ed_point_mul(8, P), _ED25519_IDENTITY)


def eddsa_sign_gen(key_be32: bytes, msg: bytes, gen_compressed: bytes) -> bytes:
    if not _is_ed_seckey_in_range(key_be32):
        raise ValueError("EdDSA seckey out of range")

    sc_le = key_be32[::-1]
    sc_int = int.from_bytes(sc_le, "little")

    gen = ed_decompress(gen_compressed)

    P = ed_point_mul(sc_int, gen)
    P_bytes = ed_compress(P)

    az = hashlib.sha512(sc_le).digest()
    nonce_pre = hashlib.sha512(az[32:] + msg).digest()
    nonce_int = int.from_bytes(nonce_pre, "little") % ED25519_L

    R = ed_point_mul(nonce_int, gen)
    R_bytes = ed_compress(R)

    hram_pre = hashlib.sha512(R_bytes + P_bytes + msg).digest()
    hram_int = int.from_bytes(hram_pre, "little") % ED25519_L

    response_int = (hram_int * sc_int + nonce_int) % ED25519_L
    response_bytes = response_int.to_bytes(32, "little")

    return R_bytes + response_bytes


def eddsa_verify_gen(
    sig: bytes, msg: bytes, pubkey: bytes, gen_compressed: bytes
) -> bool:
    if len(sig) != 64 or len(pubkey) != 32 or len(gen_compressed) != 32:
        return False

    response_bytes = sig[32:]
    response_int = int.from_bytes(response_bytes, "little")
    # C only checks canonicality when top 4 bits of last byte are non zero.
    if (sig[63] & 0xF0) != 0 and response_int >= ED25519_L:
        return False

    try:
        R = ed_decompress(sig[:32])
    except ValueError:
        return False
    if _ed_has_small_order(R):
        return False

    if not ed_canonical(pubkey):
        return False
    try:
        P = ed_decompress(pubkey)
    except ValueError:
        return False
    if _ed_has_small_order(P):
        return False

    try:
        gen = ed_decompress(gen_compressed)
    except ValueError:
        return False

    hram_pre = hashlib.sha512(sig[:32] + pubkey + msg).digest()
    hram_int = int.from_bytes(hram_pre, "little") % ED25519_L

    lhs = ed_point_mul(response_int % ED25519_L, gen)
    rhs = ed_point_add(R, ed_point_mul(hram_int, P))
    return ed_point_eq(lhs, rhs)


# Standard ecdsa on G, sign delegates to coincurve, verify is local to avoid DER conversion.

def ecdsa_sign_g(key_be32: bytes, msg_hash32: bytes) -> bytes:
    if len(key_be32) != 32 or len(msg_hash32) != 32:
        raise ValueError("ecdsa_sign_g expects 32 byte inputs")
    from coincurve import PrivateKey

    pk = PrivateKey(key_be32)
    sig65 = pk.sign_recoverable(msg_hash32, hasher=None)
    return sig65[:64]


def ecdsa_verify_g(
    sig64: bytes, msg_hash32: bytes, pubkey_compressed: bytes
) -> bool:
    if len(sig64) != 64 or len(msg_hash32) != 32 or len(pubkey_compressed) != 33:
        return False
    r = int.from_bytes(sig64[:32], "big")
    s = int.from_bytes(sig64[32:], "big")
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        return False

    e = int.from_bytes(msg_hash32, "big") % SECP256K1_N
    w = secp_scalar_inv(s)
    u1 = (e * w) % SECP256K1_N
    u2 = (r * w) % SECP256K1_N

    if u1 == 0 and u2 == 0:
        return False
    try:
        if u1 == 0:
            Rprime_bytes = secp_point_mul(u2, pubkey_compressed)
        elif u2 == 0:
            Rprime_bytes = secp_base_mul(u1)
        else:
            P1 = secp_base_mul(u1)
            P2 = secp_point_mul(u2, pubkey_compressed)
            Rprime_bytes = secp_point_add(P1, P2)
    except Exception:
        return False

    P_obj = secp_point_from_bytes(Rprime_bytes)
    x, _y = P_obj.point()
    return (x % SECP256K1_N) == r


def proof_len(n_bits: int = 252) -> int:
    if n_bits <= 0 or n_bits > 256:
        raise ValueError("n_bits must be in [1, 256]")
    return 65 + 64 + 64 + 64 + 193 * n_bits


def prove(
    key_be32: bytes,
    nonce_be32: bytes,
    *,
    n_bits: int = 252,
    gen_s_a: bytes = SECP256K1_G_COMPRESSED,
    gen_s_b: bytes = SECP256K1_H_COMPRESSED,
    gen_e_a: bytes = ED25519_B_COMPRESSED,
    gen_e_b: bytes = ED25519_B2_COMPRESSED,
) -> bytes:
    if len(key_be32) != 32 or len(nonce_be32) != 32:
        raise ValueError("key and nonce must each be 32 bytes")
    if n_bits <= 0 or n_bits > 256:
        raise ValueError("n_bits out of range")

    key_int = int.from_bytes(key_be32, "big")
    if key_int == 0 or key_int >= SECP256K1_N or key_int >= ED25519_L:
        raise ValueError("key out of range for both curves")

    K_G = secp_point_mul(key_int, gen_s_a)
    gen_e_a_point = ed_decompress(gen_e_a)
    K_B = ed_compress(ed_point_mul(key_int, gen_e_a_point))

    preimage_hash = hashlib.sha256(DLEAG_SIG_MESSAGE).digest()
    sig_ecdsa = ecdsa_sign_g(key_be32, preimage_hash)
    sig_eddsa = eddsa_sign_gen(key_be32, preimage_hash, gen_e_a)

    out = bytearray()
    out += K_G
    out += K_B
    out += sig_ecdsa
    out += sig_eddsa
    assert len(out) == 65 + 128

    rng = Rfc6979HmacSha256(nonce_be32 + K_G + K_B)

    r: List[int] = [0] * n_bits
    s: List[int] = [0] * n_bits
    sum_r = 0
    sum_s = 0
    for i in range(n_bits - 1):
        r[i] = get_sc_secp256k1(rng)
        s[i] = get_sc_ed25519(rng)
        if i == 0:
            sum_r = secp_scalar_add(sum_r, r[i])
            sum_s = ed_scalar_add(sum_s, s[i])
        else:
            sum_r = secp_scalar_add(
                sum_r, secp_scalar_mul(r[i], power_of_two_secp(i))
            )
            sum_s = ed_scalar_add(
                sum_s, ed_scalar_mul(s[i], power_of_two_ed(i))
            )

    # Close r and s so the weighted commitments sum to K_G and K_B.
    last = n_bits - 1
    inv_pow_secp = secp_scalar_inv(power_of_two_secp(last))
    inv_pow_ed = ed_scalar_inv(power_of_two_ed(last))
    r[last] = secp_scalar_mul(secp_scalar_neg(sum_r), inv_pow_secp)
    s[last] = ed_scalar_mul(ed_scalar_neg(sum_s), inv_pow_ed)
    if r[last] == 0 or s[last] == 0:
        raise ValueError(
            "Closing scalar collapsed to zero, retry with a different nonce"
        )

    preimage_state = hashlib.sha256()
    preimage_state.update(K_G)
    preimage_state.update(K_B)

    C_G_bytes: List[bytes] = [b""] * n_bits
    C_B_points: List[Tuple[int, int, int, int]] = [None] * n_bits
    C_B_bytes: List[bytes] = [b""] * n_bits

    gen_e_b_point = ed_decompress(gen_e_b)

    for i in range(n_bits):
        x_i = key_bit(key_be32, i)

        if x_i == 1:
            C_G_i = secp_point_add(gen_s_a, secp_point_mul(r[i], gen_s_b))
        else:
            C_G_i = secp_point_mul(r[i], gen_s_b)
        C_G_bytes[i] = C_G_i
        preimage_state.update(C_G_i)

        if x_i == 1:
            C_B_i_point = ed_point_add(
                gen_e_a_point, ed_point_mul(s[i], gen_e_b_point)
            )
        else:
            C_B_i_point = ed_point_mul(s[i], gen_e_b_point)
        C_B_points[i] = C_B_i_point
        C_B_i = ed_compress(C_B_i_point)
        C_B_bytes[i] = C_B_i
        preimage_state.update(C_B_i)

    preimage_hash_commit = preimage_state.digest()

    sc_j: List[int] = [0] * n_bits
    sc_k: List[int] = [0] * n_bits
    sc_a: List[List[int]] = [[0, 0] for _ in range(n_bits)]
    sc_b: List[List[int]] = [[0, 0] for _ in range(n_bits)]

    hash_J = hashlib.sha256()
    hash_K = hashlib.sha256()

    # OR proof phase 1: aggregate J K from the j = 1 position per ring.
    for i in range(n_bits):
        x_i = key_bit(key_be32, i)
        sc_j[i] = get_sc_secp256k1(rng)
        sc_k[i] = get_sc_ed25519(rng)

        bJ = secp_point_mul(sc_j[i], gen_s_b)
        bK_point = ed_point_mul(sc_k[i], gen_e_b_point)
        bK = ed_compress(bK_point)

        if x_i == 0:
            j = 1
            tag = dleag_hash(preimage_hash_commit, bJ, bK, i, j)
            ej = hash_sc_secp256k1(tag)
            ek = hash_sc_ed25519(tag)
            sc_a[i][j] = get_sc_secp256k1(rng)
            sc_b[i][j] = get_sc_ed25519(rng)

            term1 = secp_point_mul(sc_a[i][j], gen_s_b)
            cg_minus_g = secp_point_sub(C_G_bytes[i], gen_s_a)
            term2 = secp_point_mul(ej, cg_minus_g)
            bJ = secp_point_sub(term1, term2)

            term1_e = ed_point_mul(sc_b[i][j], gen_e_b_point)
            cb_minus_b = ed_point_sub(C_B_points[i], gen_e_a_point)
            term2_e = ed_point_mul(ek, cb_minus_b)
            bK_point = ed_point_sub(term1_e, term2_e)
            bK = ed_compress(bK_point)

        hash_J.update(bJ)
        hash_K.update(bK)

    J_hash = hash_J.digest()
    K_hash = hash_K.digest()

    # OR proof close: refresh challenge through the false branch if needed, close the true branch.
    for i in range(n_bits):
        x_i = key_bit(key_be32, i)

        tag = dleag_hash(preimage_hash_commit, J_hash, K_hash, i, 0)
        ej = hash_sc_secp256k1(tag)
        ek = hash_sc_ed25519(tag)

        if x_i == 1:
            j = 0
            sc_a[i][j] = get_sc_secp256k1(rng)
            sc_b[i][j] = get_sc_ed25519(rng)

            term1 = secp_point_mul(sc_a[i][j], gen_s_b)
            term2 = secp_point_mul(ej, C_G_bytes[i])
            bJ_sim = secp_point_sub(term1, term2)

            term1_e = ed_point_mul(sc_b[i][j], gen_e_b_point)
            term2_e = ed_point_mul(ek, C_B_points[i])
            bK_sim_point = ed_point_sub(term1_e, term2_e)
            bK_sim = ed_compress(bK_sim_point)

            tag = dleag_hash(preimage_hash_commit, bJ_sim, bK_sim, i, j + 1)
            ej = hash_sc_secp256k1(tag)
            ek = hash_sc_ed25519(tag)

        sc_a[i][x_i] = secp_scalar_add(sc_j[i], secp_scalar_mul(ej, r[i]))
        sc_b[i][x_i] = ed_scalar_add(sc_k[i], ed_scalar_mul(ek, s[i]))

    # Body write order matches the C reference.
    for i in range(n_bits):
        out += C_G_bytes[i]
    for i in range(n_bits):
        out += C_B_bytes[i]
    out += J_hash
    out += K_hash
    for i in range(n_bits):
        out += secp_scalar_to_bytes(sc_a[i][0])
    for i in range(n_bits):
        out += secp_scalar_to_bytes(sc_a[i][1])
    for i in range(n_bits):
        out += ed_scalar_to_bytes_be(sc_b[i][0])
    for i in range(n_bits):
        out += ed_scalar_to_bytes_be(sc_b[i][1])

    if len(out) != proof_len(n_bits):
        raise AssertionError(
            f"proof length {len(out)} does not match expected {proof_len(n_bits)}"
        )
    return bytes(out)


def verify(
    proof: bytes,
    *,
    n_bits: int = 252,
    gen_s_a: bytes = SECP256K1_G_COMPRESSED,
    gen_s_b: bytes = SECP256K1_H_COMPRESSED,
    gen_e_a: bytes = ED25519_B_COMPRESSED,
    gen_e_b: bytes = ED25519_B2_COMPRESSED,
) -> bool:
    expected_len = proof_len(n_bits)
    if len(proof) != expected_len:
        return False

    try:
        K_G = proof[0:33]
        K_B = proof[33:65]

        secp_point_from_bytes(K_G)
        ed_decode_check_point(K_B)

        sig_ecdsa = proof[65:129]
        sig_eddsa = proof[129:193]

        preimage_hash = hashlib.sha256(DLEAG_SIG_MESSAGE).digest()
        if not ecdsa_verify_g(sig_ecdsa, preimage_hash, K_G):
            return False
        if not eddsa_verify_gen(sig_eddsa, preimage_hash, K_B, gen_e_a):
            return False

        preimage_state = hashlib.sha256()
        preimage_state.update(K_G)
        preimage_state.update(K_B)

        offset = 193
        C_G_bytes: List[bytes] = [b""] * n_bits
        C_B_points: List[Tuple[int, int, int, int]] = [None] * n_bits
        C_B_bytes: List[bytes] = [b""] * n_bits

        gen_e_a_point = ed_decompress(gen_e_a)
        gen_e_b_point = ed_decompress(gen_e_b)

        sum_secp_bytes: bytes = b""
        sum_ed_point: Tuple[int, int, int, int] = (0, 1, 1, 0)

        for i in range(n_bits):
            sp = proof[offset + i * 33 : offset + (i + 1) * 33]
            ep = proof[
                offset + n_bits * 33 + i * 32 : offset + n_bits * 33 + (i + 1) * 32
            ]

            secp_point_from_bytes(sp)
            C_G_bytes[i] = sp
            cb_point = ed_decode_check_point(ep)
            C_B_points[i] = cb_point
            C_B_bytes[i] = ep

            preimage_state.update(sp)
            preimage_state.update(ep)

            if i == 0:
                sum_secp_bytes = sp
                sum_ed_point = cb_point
            else:
                weight = power_of_two_secp(i)
                term_secp = secp_point_mul(weight, sp)
                sum_secp_bytes = secp_point_add(sum_secp_bytes, term_secp)
                weight_e = power_of_two_ed(i)
                sum_ed_point = ed_point_add(
                    sum_ed_point, ed_point_mul(weight_e, cb_point)
                )

        if sum_secp_bytes != K_G:
            return False
        if ed_compress(sum_ed_point) != K_B:
            return False

        preimage_hash_commit = preimage_state.digest()

        ofs_J = 193 + 65 * n_bits
        ofs_K = ofs_J + 32
        ofs_a0 = ofs_K + 32
        ofs_a1 = ofs_a0 + 32 * n_bits
        ofs_b0 = ofs_a1 + 32 * n_bits
        ofs_b1 = ofs_b0 + 32 * n_bits
        pJ_hash = proof[ofs_J : ofs_J + 32]
        pK_hash = proof[ofs_K : ofs_K + 32]

        hash_J = hashlib.sha256()
        hash_K = hashlib.sha256()

        for i in range(n_bits):
            tag = dleag_hash(preimage_hash_commit, pJ_hash, pK_hash, i, 0)
            ej = hash_sc_secp256k1(tag)
            ek = hash_sc_ed25519(tag)

            bJ: bytes = b""
            bK: bytes = b""

            for j in range(2):
                a_bytes = proof[
                    (ofs_a0 if j == 0 else ofs_a1) + 32 * i :
                    (ofs_a0 if j == 0 else ofs_a1) + 32 * (i + 1)
                ]
                b_bytes = proof[
                    (ofs_b0 if j == 0 else ofs_b1) + 32 * i :
                    (ofs_b0 if j == 0 else ofs_b1) + 32 * (i + 1)
                ]

                a_int = secp_scalar_from_bytes(a_bytes, allow_overflow=False)
                if a_int == 0:
                    return False
                b_int = ed_decode_check_scalar(b_bytes)

                if j == 0:
                    term1 = secp_point_mul(a_int, gen_s_b)
                    term2 = secp_point_mul(ej, C_G_bytes[i])
                    bJ = secp_point_sub(term1, term2)

                    term1_e = ed_point_mul(b_int, gen_e_b_point)
                    term2_e = ed_point_mul(ek, C_B_points[i])
                    bK_point = ed_point_sub(term1_e, term2_e)
                    bK = ed_compress(bK_point)

                    tag = dleag_hash(preimage_hash_commit, bJ, bK, i, j + 1)
                    ej = hash_sc_secp256k1(tag)
                    ek = hash_sc_ed25519(tag)
                else:
                    term1 = secp_point_mul(a_int, gen_s_b)
                    cg_minus_g = secp_point_sub(C_G_bytes[i], gen_s_a)
                    term2 = secp_point_mul(ej, cg_minus_g)
                    bJ = secp_point_sub(term1, term2)

                    term1_e = ed_point_mul(b_int, gen_e_b_point)
                    cb_minus_b = ed_point_sub(C_B_points[i], gen_e_a_point)
                    term2_e = ed_point_mul(ek, cb_minus_b)
                    bK_point = ed_point_sub(term1_e, term2_e)
                    bK = ed_compress(bK_point)

            hash_J.update(bJ)
            hash_K.update(bK)

        if hash_J.digest() != pJ_hash:
            return False
        if hash_K.digest() != pK_hash:
            return False

        return True
    except Exception:
        return False


__all__: List[str] = [
    "SECP256K1_N",
    "ED25519_L",
    "SECP256K1_H_COMPRESSED",
    "SECP256K1_G_COMPRESSED",
    "ED25519_B_COMPRESSED",
    "ED25519_B2_COMPRESSED",
    "ED25519_B_POINT",
    "ED25519_B2_POINT",
    "DLEAG_SIG_MESSAGE",
    "secp_scalar_from_bytes",
    "secp_scalar_to_bytes",
    "secp_scalar_add",
    "secp_scalar_sub",
    "secp_scalar_mul",
    "secp_scalar_neg",
    "secp_scalar_inv",
    "secp_scalar_is_zero",
    "ed_scalar_from_bytes_be",
    "ed_scalar_to_bytes_be",
    "ed_scalar_from_bytes_le",
    "ed_scalar_to_bytes_le",
    "ed_scalar_add",
    "ed_scalar_sub",
    "ed_scalar_mul",
    "ed_scalar_neg",
    "ed_scalar_inv",
    "ed_scalar_is_zero",
    "ed_decode_check_scalar",
    "ed_decompress",
    "ed_compress",
    "ed_point_add",
    "ed_point_neg",
    "ed_point_sub",
    "ed_point_mul",
    "ed_point_eq",
    "ed_canonical",
    "ed_in_main_subgroup",
    "ed_decode_check_point",
    "secp_point_from_bytes",
    "secp_point_to_bytes",
    "secp_point_mul",
    "secp_point_add",
    "secp_point_neg",
    "secp_point_sub",
    "secp_base_mul",
    "dleag_hash",
    "hash_sc_secp256k1",
    "hash_sc_ed25519",
    "Rfc6979HmacSha256",
    "get_sc_secp256k1",
    "get_sc_ed25519",
    "key_bit",
    "power_of_two_secp",
    "power_of_two_ed",
    "eddsa_sign_gen",
    "eddsa_verify_gen",
    "ecdsa_sign_g",
    "ecdsa_verify_g",
    "proof_len",
    "prove",
    "verify",
]
