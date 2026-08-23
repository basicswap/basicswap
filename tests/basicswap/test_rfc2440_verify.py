# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest

from basicswap.util.rfc2440 import rfc2440_hash_password, verify_rfc2440_password


class VerifyRfc2440PasswordTest(unittest.TestCase):
    def test_known_vector_verifies(self):
        stored = "16:B7A94A7E4988630E6095334BA67F06FBA509B2A7136A04C9C1B430F539"
        self.assertTrue(verify_rfc2440_password(stored, "test"))
        self.assertFalse(verify_rfc2440_password(stored, "wrong"))

    def test_salt_starting_with_60_verifies(self):
        salt = bytes.fromhex("60AABBCCDDEEFF11")
        stored = rfc2440_hash_password("password1", salt=salt)
        self.assertTrue(verify_rfc2440_password(stored, "password1"))
        self.assertFalse(verify_rfc2440_password(stored, "password2"))

    def test_salt_with_60_straddling_bytes_verifies(self):
        salt = bytes.fromhex("F60A112233445566")
        stored = rfc2440_hash_password("password1", salt=salt)
        self.assertTrue(verify_rfc2440_password(stored, "password1"))

    def test_all_salt_positions_verify(self):
        for i in range(8):
            salt = bytearray(b"\x11" * 8)
            salt[i] = 0x60
            stored = rfc2440_hash_password("password1", salt=bytes(salt))
            self.assertTrue(
                verify_rfc2440_password(stored, "password1"), f"salt offset {i}"
            )

    def test_malformed_hashes_rejected(self):
        stored = rfc2440_hash_password("test", salt=bytes.fromhex("B7A94A7E4988630E"))
        self.assertFalse(verify_rfc2440_password("", "test"))
        self.assertFalse(verify_rfc2440_password("16:", "test"))
        self.assertFalse(verify_rfc2440_password(stored.replace("16:", "17:"), "test"))
        self.assertFalse(verify_rfc2440_password(stored[:-2], "test"))
        self.assertFalse(verify_rfc2440_password(stored + "AA", "test"))
        bad_specifier = stored[:19] + "61" + stored[21:]
        self.assertFalse(verify_rfc2440_password(bad_specifier, "test"))
        non_hex_salt = "16:" + "ZZ" * 8 + "60" + "AA" * 20
        self.assertFalse(verify_rfc2440_password(non_hex_salt, "test"))


if __name__ == "__main__":
    unittest.main()
