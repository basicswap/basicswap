#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""tests for basicswap.contrib.dleag_t."""

import hashlib
import secrets
import unittest

from basicswap.contrib import dleag_t as d


# Carrot T from basicswap.interface.sal, duplicated here to keep the suite standalone.
CARROT_T_COMPRESSED = bytes.fromhex(
    "966fc66b82cd56cf85eaec801c42845f5f408878d1561e00d3d7ded2794d094f"
)


def _random_ed_key() -> bytes:
    while True:
        k = secrets.token_bytes(32)
        k = bytes([k[0] & 0x1F]) + k[1:30] + bytes([k[30] | 1, k[31]])
        if d._is_ed_seckey_in_range(k):
            v = int.from_bytes(k, "big")
            if 0 < v < d.SECP256K1_N:
                return k


class TestConstants(unittest.TestCase):
    def test_proof_len(self):
        self.assertEqual(d.proof_len(252), 48893)
        self.assertEqual(
            d.proof_len(252),
            65 + 64 + 64 + 64 + 193 * 252,
        )

    def test_b_decompresses_and_in_subgroup(self):
        B = d.ed_decompress(d.ED25519_B_COMPRESSED)
        self.assertTrue(d.ed_in_main_subgroup(B))

    def test_b2_decompresses_and_in_subgroup(self):
        B2 = d.ed_decompress(d.ED25519_B2_COMPRESSED)
        self.assertTrue(d.ed_in_main_subgroup(B2))

    def test_carrot_t_decompresses_and_in_subgroup(self):
        T = d.ed_decompress(CARROT_T_COMPRESSED)
        self.assertTrue(d.ed_in_main_subgroup(T))
        self.assertFalse(
            d.ed_point_eq(d.ed_point_mul(8, T), (0, 1, 1, 0)),
            "Carrot T must not be small order",
        )


class TestEd25519PointArithmetic(unittest.TestCase):
    def test_compress_decompress_roundtrip(self):
        for src in (
            d.ED25519_B_COMPRESSED,
            d.ED25519_B2_COMPRESSED,
            CARROT_T_COMPRESSED,
        ):
            P = d.ed_decompress(src)
            self.assertEqual(d.ed_compress(P), src)

    def test_scalar_mul_zero_returns_identity(self):
        P = d.ed_point_mul(0, d.ED25519_B_POINT)
        self.assertTrue(d.ed_point_eq(P, (0, 1, 1, 0)))

    def test_scalar_mul_l_returns_identity(self):
        P = d.ed_point_mul(d.ED25519_L, d.ED25519_B_POINT)
        self.assertTrue(d.ed_point_eq(P, (0, 1, 1, 0)))

    def test_double_equals_add(self):
        twoB = d.ed_point_mul(2, d.ED25519_B_POINT)
        BpB = d.ed_point_add(d.ED25519_B_POINT, d.ED25519_B_POINT)
        self.assertTrue(d.ed_point_eq(twoB, BpB))

    def test_distributive(self):
        a = secrets.randbelow(d.ED25519_L - 1) + 1
        b = secrets.randbelow(d.ED25519_L - 1) + 1
        lhs = d.ed_point_mul((a + b) % d.ED25519_L, d.ED25519_B_POINT)
        rhs = d.ed_point_add(
            d.ed_point_mul(a, d.ED25519_B_POINT),
            d.ed_point_mul(b, d.ED25519_B_POINT),
        )
        self.assertTrue(d.ed_point_eq(lhs, rhs))

    def test_neg_add_is_identity(self):
        negB = d.ed_point_neg(d.ED25519_B_POINT)
        S = d.ed_point_add(d.ED25519_B_POINT, negB)
        self.assertTrue(d.ed_point_eq(S, (0, 1, 1, 0)))

    def test_ed_in_main_subgroup_rejects_small_order(self):
        P_small = bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
        )
        P = d.ed_decompress(P_small)
        self.assertFalse(d.ed_in_main_subgroup(P))

    def test_subgroup_check_rejects_small_order(self):
        # Order 8 point from libsodium small order table. Canonical, decompresses,
        # but not in the prime order subgroup. Must be rejected end to end.
        P_small = bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
        )
        with self.assertRaises(ValueError):
            d.ed_decode_check_point(P_small)


class TestEd25519Scalars(unittest.TestCase):
    def test_mod_l(self):
        self.assertEqual(d.ed_scalar_add(d.ED25519_L, 1), 1)
        self.assertEqual(d.ed_scalar_neg(0), 0)
        self.assertEqual(d.ed_scalar_mul(1, 7), 7)
        self.assertEqual(d.ed_scalar_inv(1), 1)

    def test_decode_check_scalar_rejects_overflow(self):
        with self.assertRaises(ValueError):
            d.ed_decode_check_scalar(bytes([0xFF] * 32))

    def test_decode_check_scalar_rejects_min_value(self):
        small = bytes(30) + b"\xab\xcd"
        with self.assertRaises(ValueError):
            d.ed_decode_check_scalar(small)

    def test_decode_check_scalar_accepts_valid(self):
        valid = bytes([0x01]) + bytes(31)
        self.assertEqual(d.ed_decode_check_scalar(valid), 1 << 248)


class TestKeyBitOrder(unittest.TestCase):
    def test_lsb_byte_lsb_first(self):
        key = bytes(31) + bytes([0x05])
        bits = [d.key_bit(key, i) for i in range(8)]
        self.assertEqual(bits, [1, 0, 1, 0, 0, 0, 0, 0])

    def test_high_bit_of_high_byte(self):
        key = bytes([0x80]) + bytes(31)
        self.assertEqual(d.key_bit(key, 255), 1)
        self.assertEqual(d.key_bit(key, 254), 0)


class TestRfc6979(unittest.TestCase):
    def test_deterministic(self):
        r1 = d.Rfc6979HmacSha256(b"seed").generate(96)
        r2 = d.Rfc6979HmacSha256(b"seed").generate(96)
        self.assertEqual(r1, r2)

    def test_different_seed_different_stream(self):
        r1 = d.Rfc6979HmacSha256(b"seed-a").generate(96)
        r2 = d.Rfc6979HmacSha256(b"seed-b").generate(96)
        self.assertNotEqual(r1, r2)

    def test_get_sc_secp256k1_in_range(self):
        rng = d.Rfc6979HmacSha256(b"x")
        for _ in range(50):
            v = d.get_sc_secp256k1(rng)
            self.assertTrue(0 < v < d.SECP256K1_N)

    def test_get_sc_ed25519_in_range(self):
        rng = d.Rfc6979HmacSha256(b"x")
        for _ in range(50):
            v = d.get_sc_ed25519(rng)
            self.assertTrue(0 <= v < d.ED25519_L)


class TestEdDSAOverB(unittest.TestCase):
    def setUp(self):
        self.key = _random_ed_key()
        self.msg = b"signing payload"
        self.key_int = int.from_bytes(self.key[::-1], "little")
        self.pubkey = d.ed_compress(d.ed_point_mul(self.key_int, d.ED25519_B_POINT))

    def test_sign_verify_roundtrip(self):
        sig = d.eddsa_sign_gen(self.key, self.msg, d.ED25519_B_COMPRESSED)
        self.assertTrue(
            d.eddsa_verify_gen(sig, self.msg, self.pubkey, d.ED25519_B_COMPRESSED)
        )

    def test_deterministic(self):
        sig1 = d.eddsa_sign_gen(self.key, self.msg, d.ED25519_B_COMPRESSED)
        sig2 = d.eddsa_sign_gen(self.key, self.msg, d.ED25519_B_COMPRESSED)
        self.assertEqual(sig1, sig2)

    def test_tampered_sig(self):
        sig = bytearray(d.eddsa_sign_gen(self.key, self.msg, d.ED25519_B_COMPRESSED))
        for offset in (0, 16, 31, 32, 48, 63):
            tampered = bytearray(sig)
            tampered[offset] ^= 0x01
            self.assertFalse(
                d.eddsa_verify_gen(
                    bytes(tampered), self.msg, self.pubkey, d.ED25519_B_COMPRESSED
                ),
                f"tampered at offset {offset} accepted",
            )

    def test_wrong_msg(self):
        sig = d.eddsa_sign_gen(self.key, self.msg, d.ED25519_B_COMPRESSED)
        self.assertFalse(
            d.eddsa_verify_gen(sig, b"other", self.pubkey, d.ED25519_B_COMPRESSED)
        )

    def test_wrong_pubkey(self):
        sig = d.eddsa_sign_gen(self.key, self.msg, d.ED25519_B_COMPRESSED)
        other = _random_ed_key()
        other_int = int.from_bytes(other[::-1], "little")
        other_pub = d.ed_compress(d.ed_point_mul(other_int, d.ED25519_B_POINT))
        self.assertFalse(
            d.eddsa_verify_gen(sig, self.msg, other_pub, d.ED25519_B_COMPRESSED)
        )

    def test_reject_zero_seckey(self):
        with self.assertRaises(ValueError):
            d.eddsa_sign_gen(bytes(32), self.msg, d.ED25519_B_COMPRESSED)

    def test_reject_overflow_seckey(self):
        with self.assertRaises(ValueError):
            d.eddsa_sign_gen(bytes([0xFF] * 32), self.msg, d.ED25519_B_COMPRESSED)


class TestEdDSAOverCarrotT(unittest.TestCase):
    def setUp(self):
        self.key = _random_ed_key()
        self.msg = b"sal dleag transcript"
        self.key_int = int.from_bytes(self.key[::-1], "little")
        T_point = d.ed_decompress(CARROT_T_COMPRESSED)
        self.pubkey = d.ed_compress(d.ed_point_mul(self.key_int, T_point))

    def test_sign_verify_with_t(self):
        sig = d.eddsa_sign_gen(self.key, self.msg, CARROT_T_COMPRESSED)
        self.assertTrue(
            d.eddsa_verify_gen(sig, self.msg, self.pubkey, CARROT_T_COMPRESSED)
        )

    def test_cross_gen_rejection(self):
        sig = d.eddsa_sign_gen(self.key, self.msg, CARROT_T_COMPRESSED)
        B_pub = d.ed_compress(d.ed_point_mul(self.key_int, d.ED25519_B_POINT))
        self.assertFalse(
            d.eddsa_verify_gen(sig, self.msg, B_pub, d.ED25519_B_COMPRESSED)
        )


class TestECDSAOnG(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            from coincurve import PrivateKey  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("coincurve not installed")

    def test_sign_verify_roundtrip(self):
        from coincurve import PrivateKey

        key = secrets.token_bytes(32)
        key_int = int.from_bytes(key, "big") % (d.SECP256K1_N - 1) + 1
        key = key_int.to_bytes(32, "big")

        msg_hash = hashlib.sha256(b"test").digest()
        sig = d.ecdsa_sign_g(key, msg_hash)

        pubkey = PrivateKey(key).public_key.format(compressed=True)
        self.assertTrue(d.ecdsa_verify_g(sig, msg_hash, pubkey))

    def test_tampered_sig(self):
        from coincurve import PrivateKey

        key_int = secrets.randbelow(d.SECP256K1_N - 1) + 1
        key = key_int.to_bytes(32, "big")
        msg_hash = hashlib.sha256(b"test").digest()
        sig = d.ecdsa_sign_g(key, msg_hash)
        pubkey = PrivateKey(key).public_key.format(compressed=True)

        for offset in (0, 31, 32, 63):
            tampered = bytearray(sig)
            tampered[offset] ^= 0x01
            self.assertFalse(
                d.ecdsa_verify_g(bytes(tampered), msg_hash, pubkey),
                f"tampered at offset {offset} accepted",
            )

    def test_wrong_msg(self):
        from coincurve import PrivateKey

        key_int = secrets.randbelow(d.SECP256K1_N - 1) + 1
        key = key_int.to_bytes(32, "big")
        sig = d.ecdsa_sign_g(key, hashlib.sha256(b"a").digest())
        pubkey = PrivateKey(key).public_key.format(compressed=True)
        self.assertFalse(d.ecdsa_verify_g(sig, hashlib.sha256(b"b").digest(), pubkey))

    def test_reject_zero_r_or_s(self):
        pubkey = bytes([0x02]) + bytes(32)
        self.assertFalse(
            d.ecdsa_verify_g(bytes(64), hashlib.sha256(b"x").digest(), pubkey)
        )


class TestDleagGB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            from coincurve import PrivateKey  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("coincurve not installed")

    def test_prove_verify_roundtrip(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof = d.prove(key, nonce)
        self.assertEqual(len(proof), d.proof_len())
        self.assertTrue(d.verify(proof))

    def test_deterministic_for_fixed_inputs(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        a = d.prove(key, nonce)
        b = d.prove(key, nonce)
        self.assertEqual(a, b)

    def test_tampered_proof_rejected(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof = d.prove(key, nonce)

        offsets = [
            0,
            33,
            65,
            129,
            193,
            193 + 33 * 252,
            193 + 65 * 252,
            193 + 65 * 252 + 32,
            193 + 65 * 252 + 64,
            len(proof) - 1,
        ]
        for offset in offsets:
            tampered = bytearray(proof)
            tampered[offset] ^= 0x01
            self.assertFalse(
                d.verify(bytes(tampered)),
                f"tampered proof at offset {offset} accepted",
            )

    def test_truncated_proof_rejected(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof = d.prove(key, nonce)
        self.assertFalse(d.verify(proof[:-1]))
        self.assertFalse(d.verify(proof + b"\x00"))

    def test_wrong_generator_rejected(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof = d.prove(key, nonce, gen_e_a=d.ED25519_B_COMPRESSED)
        self.assertFalse(d.verify(proof, gen_e_a=CARROT_T_COMPRESSED))


class TestDleagGT(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            from coincurve import PrivateKey  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("coincurve not installed")

    def test_prove_verify_roundtrip(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof = d.prove(key, nonce, gen_e_a=CARROT_T_COMPRESSED)
        self.assertEqual(len(proof), d.proof_len())
        self.assertTrue(d.verify(proof, gen_e_a=CARROT_T_COMPRESSED))

    def test_cross_gen_pubkey_mismatch(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof_T = d.prove(key, nonce, gen_e_a=CARROT_T_COMPRESSED)
        self.assertFalse(d.verify(proof_T, gen_e_a=d.ED25519_B_COMPRESSED))

    def test_different_nonce_different_proof(self):
        key = _random_ed_key()
        nonce_a = secrets.token_bytes(32)
        nonce_b = secrets.token_bytes(32)
        proof_a = d.prove(key, nonce_a, gen_e_a=CARROT_T_COMPRESSED)
        proof_b = d.prove(key, nonce_b, gen_e_a=CARROT_T_COMPRESSED)
        # Header is determined by the key alone, body by the nonce.
        self.assertEqual(proof_a[:65], proof_b[:65])
        self.assertNotEqual(proof_a[65:], proof_b[65:])
        self.assertTrue(d.verify(proof_a, gen_e_a=CARROT_T_COMPRESSED))
        self.assertTrue(d.verify(proof_b, gen_e_a=CARROT_T_COMPRESSED))


SMALL_ORDER_POINT = bytes.fromhex(
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
)


class TestInvalidGenerators(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            from coincurve import PrivateKey  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("coincurve not installed")

    def test_prove_rejects_small_order_gen_e_a(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        with self.assertRaises(ValueError):
            d.prove(key, nonce, gen_e_a=SMALL_ORDER_POINT)

    def test_prove_rejects_small_order_gen_e_b(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        with self.assertRaises(ValueError):
            d.prove(key, nonce, gen_e_b=SMALL_ORDER_POINT)

    def test_verify_rejects_small_order_gen_e_a(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof = d.prove(key, nonce)
        self.assertFalse(d.verify(proof, gen_e_a=SMALL_ORDER_POINT))

    def test_verify_rejects_small_order_gen_e_b(self):
        key = _random_ed_key()
        nonce = secrets.token_bytes(32)
        proof = d.prove(key, nonce)
        self.assertFalse(d.verify(proof, gen_e_b=SMALL_ORDER_POINT))


class TestDleagCoincurveCrossCheck(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        try:
            from coincurve.dleag import dleag_prove, dleag_verify  # noqa: F401
            from coincurve.keys import PrivateKey  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("coincurve.dleag not available")

    def test_bytewise_equality(self):
        from coincurve.dleag import dleag_prove
        from coincurve.keys import PrivateKey

        key = _random_ed_key()
        nonce = secrets.token_bytes(32)

        proof_py = d.prove(key, nonce)
        proof_cc = dleag_prove(PrivateKey(key), nonce_bytes=nonce)

        self.assertEqual(
            proof_py,
            proof_cc,
            "dleag_t.prove output differs from coincurve.dleag.dleag_prove",
        )

    def test_cross_verify(self):
        from coincurve.dleag import dleag_prove, dleag_verify
        from coincurve.keys import PrivateKey

        key = _random_ed_key()
        nonce = secrets.token_bytes(32)

        proof_py = d.prove(key, nonce)
        proof_cc = dleag_prove(PrivateKey(key), nonce_bytes=nonce)

        self.assertTrue(d.verify(proof_cc))
        self.assertTrue(dleag_verify(proof_py))


if __name__ == "__main__":
    unittest.main()
