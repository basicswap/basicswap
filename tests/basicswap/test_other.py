#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import logging
import random
import secrets
import threading
import unittest

import basicswap.contrib.ed25519_fast as edf
import basicswap.ed25519_fast_util as edu

from coincurve.ed25519 import ed25519_get_pubkey
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key,
)
from coincurve.keys import PrivateKey

from basicswap.contrib.mnemonic import Mnemonic
from basicswap.db import create_db_, DBMethods, KnownIdentity
from basicswap.util import i2b, h2b
from basicswap.util.address import decodeAddress
from basicswap.util.crypto import ripemd160, hash160, blake256
from basicswap.util.extkey import ExtKeyPair
from basicswap.util.integer import encode_varint, decode_varint
from basicswap.util.network import is_private_ip_address
from basicswap.util.rfc2440 import rfc2440_hash_password
from basicswap.util_xmr import encode_address as xmr_encode_address
from basicswap.interface.btc import BTCInterface
from basicswap.interface.xmr import XMRInterface
from tests.basicswap.mnemonics import mnemonics
from tests.basicswap.util import REQUIRED_SETTINGS

from basicswap.basicswap_util import TxLockTypes
from basicswap.util import (
    make_int,
    SerialiseNum,
    format_amount,
    DeserialiseNum,
    validate_amount,
)
from basicswap.messages_npb import (
    BidMessage,
)
from basicswap.contrib.test_framework.script import hash160 as hash160_btc


logger = logging.getLogger()


class Test(unittest.TestCase):

    def test_serialise_num(self):
        def test_case(v, nb=None):
            b = SerialiseNum(v)
            if nb is not None:
                assert len(b) == nb
            assert v == DeserialiseNum(b)

        test_case(0, 1)
        test_case(1, 1)
        test_case(16, 1)

        test_case(-1, 2)
        test_case(17, 2)

        test_case(500)
        test_case(-500)
        test_case(4194642)

    def test_sequence(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)

        ci = BTCInterface(coin_settings, "regtest")

        time_val = 48 * 60 * 60
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, time_val)
        decoded = ci.decodeSequence(encoded)
        assert decoded >= time_val
        assert decoded <= time_val + 512

        time_val = 24 * 60
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, time_val)
        decoded = ci.decodeSequence(encoded)
        assert decoded >= time_val
        assert decoded <= time_val + 512

        blocks_val = 123
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_BLOCKS, blocks_val)
        decoded = ci.decodeSequence(encoded)
        assert decoded == blocks_val

    def test_make_int(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs)
            assert i == expect_int and isinstance(i, int)
            i = make_int(vf)
            assert i == expect_int and isinstance(i, int)
            vs_out = format_amount(i, 8)
            # Strip
            for i in range(7):
                if vs_out[-1] == "0":
                    vs_out = vs_out[:-1]
            if "." in vs:
                assert vs_out == vs
            else:
                assert vs_out[:-2] == vs

        test_case("0", 0, 0)
        test_case("1", 1, 100000000)
        test_case("10", 10, 1000000000)
        test_case("0.00899999", 0.00899999, 899999)
        test_case("899999.0", 899999.0, 89999900000000)
        test_case("899999.00899999", 899999.00899999, 89999900899999)
        test_case("0.0", 0.0, 0)
        test_case("1.0", 1.0, 100000000)
        test_case("1.1", 1.1, 110000000)
        test_case("1.2", 1.2, 120000000)
        test_case("0.00899991", 0.00899991, 899991)
        test_case("0.0089999", 0.0089999, 899990)
        test_case("0.0089991", 0.0089991, 899910)
        test_case("0.123", 0.123, 12300000)
        test_case("123000.000123", 123000.000123, 12300000012300)

        try:
            make_int("0.123456789")
            assert False
        except Exception as e:
            assert str(e) == "Mantissa too long"
        validate_amount("0.12345678")

        # floor
        assert make_int("0.123456789", r=-1) == 12345678
        # Round up
        assert make_int("0.123456789", r=1) == 12345679

    def test_make_int12(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs, 12)
            assert i == expect_int and isinstance(i, int)
            i = make_int(vf, 12)
            assert i == expect_int and isinstance(i, int)
            vs_out = format_amount(i, 12)
            # Strip
            for i in range(7):
                if vs_out[-1] == "0":
                    vs_out = vs_out[:-1]
            if "." in vs:
                assert vs_out == vs
            else:
                assert vs_out[:-2] == vs

        test_case("0.123456789", 0.123456789, 123456789000)
        test_case("0.123456789123", 0.123456789123, 123456789123)
        try:
            make_int("0.1234567891234", 12)
            assert False
        except Exception as e:
            assert str(e) == "Mantissa too long"
        validate_amount("0.123456789123", 12)
        try:
            validate_amount("0.1234567891234", 12)
            assert False
        except Exception as e:
            assert "Too many decimal places" in str(e)
        try:
            validate_amount(0.1234567891234, 12)
            assert False
        except Exception as e:
            assert "Too many decimal places" in str(e)

    def test_ed25519(self):
        privkey = edu.get_secret()
        pubkey = edu.encodepoint(edf.scalarmult_B(privkey))

        privkey_bytes = i2b(privkey)
        pubkey_test = ed25519_get_pubkey(privkey_bytes)
        assert pubkey == pubkey_test

    def test_ecdsa_otves(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, "regtest")
        vk_sign = ci.getNewRandomKey()
        vk_encrypt = ci.getNewRandomKey()

        pk_sign = ci.getPubkey(vk_sign)
        pk_encrypt = ci.getPubkey(vk_encrypt)
        sign_hash = secrets.token_bytes(32)

        cipher_text = ecdsaotves_enc_sign(vk_sign, pk_encrypt, sign_hash)

        assert ecdsaotves_enc_verify(pk_sign, pk_encrypt, sign_hash, cipher_text)

        sig = ecdsaotves_dec_sig(vk_encrypt, cipher_text)

        assert ci.verifySig(pk_sign, sign_hash, sig)

        recovered_key = ecdsaotves_rec_enc_key(pk_encrypt, cipher_text, sig)

        assert vk_encrypt == recovered_key

    def test_sign(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, "regtest")

        vk = ci.getNewRandomKey()
        pk = ci.getPubkey(vk)

        message = "test signing message"
        message_hash = hashlib.sha256(bytes(message, "utf-8")).digest()
        eck = PrivateKey(vk)
        sig = eck.sign(message.encode("utf-8"))

        ci.verifySig(pk, message_hash, sig)

    def test_sign_compact(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, "regtest")

        vk = ci.getNewRandomKey()
        pk = ci.getPubkey(vk)
        sig = ci.signCompact(vk, "test signing message")
        assert len(sig) == 64
        ci.verifyCompactSig(pk, "test signing message", sig)

        # Nonce is set deterministically (using default libsecp256k1 method rfc6979)
        sig2 = ci.signCompact(vk, "test signing message")
        assert sig == sig2

    def test_sign_recoverable(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, "regtest")

        vk = ci.getNewRandomKey()
        pk = ci.getPubkey(vk)
        sig = ci.signRecoverable(vk, "test signing message")
        assert len(sig) == 65
        pk_rec = ci.verifySigAndRecover(sig, "test signing message")
        assert pk == pk_rec

        # Nonce is set deterministically (using default libsecp256k1 method rfc6979)
        sig2 = ci.signRecoverable(vk, "test signing message")
        assert sig == sig2

    def test_pubkey_to_address(self):
        coin_settings = {"rpcport": 0, "rpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, "regtest")
        pk = h2b("02c26a344e7d21bcc6f291532679559f2fd234c881271ff98714855edc753763a6")
        addr = ci.pubkey_to_address(pk)
        assert addr == "mj6SdSxmWRmdDqR5R3FfZmRiLmQfQAsLE8"

    def test_dleag(self):
        coin_settings = {"rpcport": 0, "walletrpcport": 0, "walletrpcauth": "none"}
        coin_settings.update(REQUIRED_SETTINGS)

        ci = XMRInterface(coin_settings, "regtest")

        key = ci.getNewRandomKey()
        proof = ci.proveDLEAG(key)
        assert ci.verifyDLEAG(proof)

    def test_rate(self):
        scale_from = 8
        scale_to = 12
        amount_from = make_int(100, scale_from)
        rate = make_int(0.1, scale_to)

        amount_to = int((amount_from * rate) // (10**scale_from))
        assert "100.00000000" == format_amount(amount_from, scale_from)
        assert "10.000000000000" == format_amount(amount_to, scale_to)

        rate_check = make_int((amount_to / amount_from), scale_from)
        assert rate == rate_check

        scale_from = 12
        scale_to = 8
        amount_from = make_int(1, scale_from)
        rate = make_int(12, scale_to)

        amount_to = int((amount_from * rate) // (10**scale_from))
        assert "1.000000000000" == format_amount(amount_from, scale_from)
        assert "12.00000000" == format_amount(amount_to, scale_to)

        rate_check = make_int((amount_to / amount_from), scale_from)
        assert rate == rate_check

        scale_from = 8
        scale_to = 8
        amount_from = make_int(0.073, scale_from)
        amount_to = make_int(10, scale_to)
        rate = make_int(amount_to / amount_from, scale_to, r=1)
        amount_to_recreate = int((amount_from * rate) // (10**scale_from))
        assert "10.00000000" == format_amount(amount_to_recreate, scale_to)

        scale_from = 8
        scale_to = 12
        amount_from = make_int(10.0, scale_from)
        amount_to = make_int(0.06935, scale_to)
        rate = make_int(amount_to / amount_from, scale_from, r=1)
        amount_to_recreate = int((amount_from * rate) // (10**scale_from))
        assert "0.069350000000" == format_amount(amount_to_recreate, scale_to)

        scale_from = 12
        scale_to = 8
        amount_from = make_int(0.06935, scale_from)
        amount_to = make_int(10.0, scale_to)
        rate = make_int(amount_to / amount_from, scale_from, r=1)
        amount_to_recreate = int((amount_from * rate) // (10**scale_from))
        assert "10.00000000" == format_amount(amount_to_recreate, scale_to)

        coin_settings = {
            "rpcport": 0,
            "rpcauth": "none",
            "walletrpcport": 0,
            "walletrpcauth": "none",
        }
        coin_settings.update(REQUIRED_SETTINGS)
        ci_xmr = XMRInterface(coin_settings, "regtest")
        ci_btc = BTCInterface(coin_settings, "regtest")

        for i in range(10000):
            test_pairs = random.randint(0, 3)
            if test_pairs == 0:
                ci_from = ci_btc
                ci_to = ci_xmr
            elif test_pairs == 1:
                ci_from = ci_xmr
                ci_to = ci_btc
            elif test_pairs == 2:
                ci_from = ci_xmr
                ci_to = ci_xmr
            else:
                ci_from = ci_btc
                ci_to = ci_btc

            test_range = random.randint(0, 5)
            if test_range == 0:
                amount_from = random.randint(10000, 1 * ci_from.COIN())
            elif test_range == 1:
                amount_from = random.randint(10000, 1000 * ci_from.COIN())
            elif test_range == 2:
                amount_from = random.randint(10000, 2100 * ci_from.COIN())
            elif test_range == 3:
                amount_from = random.randint(10000, 210000 * ci_from.COIN())
            elif test_range == 4:
                amount_from = random.randint(10000, 21000000 * ci_from.COIN())
            else:
                amount_from = random.randint(10000, 2100000000 * ci_from.COIN())

            test_range = random.randint(0, 5)
            if test_range == 0:
                amount_to = random.randint(10000, 1 * ci_to.COIN())
            elif test_range == 1:
                amount_to = random.randint(10000, 1000 * ci_to.COIN())
            elif test_range == 2:
                amount_to = random.randint(10000, 2100 * ci_to.COIN())
            elif test_range == 3:
                amount_to = random.randint(10000, 210000 * ci_to.COIN())
            elif test_range == 4:
                amount_to = random.randint(10000, 21000000 * ci_to.COIN())
            else:
                amount_to = random.randint(10000, 2100000000 * ci_to.COIN())

            offer_rate = ci_from.make_int(amount_to / amount_from, r=1)
            amount_to_from_rate: int = int(
                (int(amount_from) * offer_rate) // (10**scale_from)
            )

            scale_from = 24
            offer_rate = make_int(amount_to, scale_from) // amount_from
            amount_to_from_rate: int = int(
                (int(amount_from) * offer_rate) // (10**scale_from)
            )

            if abs(amount_to - amount_to_from_rate) == 1:
                offer_rate += 1

            offer_rate_human_read: int = int(
                offer_rate // (10 ** (scale_from - ci_from.exp()))
            )
            amount_to_from_rate: int = int(
                (int(amount_from) * offer_rate) // (10**scale_from)
            )

            if amount_to != amount_to_from_rate:
                print("from exp, amount", ci_from.exp(), amount_from)
                print("to exp, amount", ci_to.exp(), amount_to)
                print("offer_rate_human_read", offer_rate_human_read)
                print("amount_to_from_rate", amount_to_from_rate)
                raise ValueError("Bad amount_to")

            scale_to = 24
            reversed_rate = make_int(amount_from, scale_to) // amount_to

            amount_from_from_rate: int = int(
                (int(amount_to) * reversed_rate) // (10**scale_to)
            )
            if abs(amount_from - amount_from_from_rate) == 1:
                reversed_rate += 1

            amount_from_from_rate: int = int(
                (int(amount_to) * reversed_rate) // (10**scale_to)
            )

            if amount_from != amount_from_from_rate:
                print("from exp, amount", ci_from.exp(), amount_from)
                print("to exp, amount", ci_to.exp(), amount_to)
                print("amount_from_from_rate", amount_from_from_rate)
                raise ValueError("Bad amount_from")

    def test_rfc2440(self):
        password = "test"
        salt = bytes.fromhex("B7A94A7E4988630E")
        password_hash = rfc2440_hash_password(password, salt=salt)

        assert (
            password_hash
            == "16:B7A94A7E4988630E6095334BA67F06FBA509B2A7136A04C9C1B430F539"
        )

    def test_ripemd160(self):
        input_data = b"hash this"
        assert ripemd160(input_data).hex() == "d5443a154f167e2c1332f6de72cfb4c6ab9c8c17"

    def test_hash160(self):
        # hash160 is RIPEMD(SHA256(data))
        input_data = b"hash this"
        assert hash160(input_data).hex() == "072985b3583a4a71f548494a5e1d5f6b00d0fe13"
        assert (
            hash160_btc(input_data).hex() == "072985b3583a4a71f548494a5e1d5f6b00d0fe13"
        )

    def test_protobuf(self):
        msg_buf = BidMessage()
        msg_buf.protocol_version = 2
        msg_buf.time_valid = 1024
        serialised_msg = msg_buf.to_bytes()

        msg_buf_2 = BidMessage()
        msg_buf_2.from_bytes(serialised_msg)
        assert msg_buf_2.protocol_version == 2
        assert msg_buf_2.time_valid == 1024
        assert msg_buf_2.amount == 0
        assert msg_buf_2.pkhash_buyer is not None
        assert len(msg_buf_2.pkhash_buyer) == 0

        # Decode only the first field
        msg_buf_3 = BidMessage()
        msg_buf_3.from_bytes(serialised_msg[:2])
        assert msg_buf_3.protocol_version == 2
        assert msg_buf_3.time_valid == 0

        try:
            _ = BidMessage(doesnotexist=1)
        except Exception as e:
            assert "unexpected keyword argument" in str(e)
        else:
            raise ValueError("Should have errored.")

    def test_is_private_ip_address(self):
        test_addresses = [
            ("localhost", True),
            ("127.0.0.1", True),
            ("10.0.0.0", True),
            ("172.16.0.0", True),
            ("192.168.0.0", True),
            ("20.87.245.0", False),
            ("particl.io", False),
        ]
        for addr, is_private in test_addresses:
            assert is_private_ip_address(addr) is is_private

    def test_varint(self):
        test_vectors = [
            (0, 1),
            (1, 1),
            (127, 1),
            (128, 2),
            (253, 2),
            (8321, 2),
            (16383, 2),
            (16384, 3),
            (2097151, 3),
            (2097152, 4),
        ]
        for i, expect_length in test_vectors:
            b = encode_varint(i)
            assert len(b) == expect_length
            assert decode_varint(b) == (i, expect_length)

    def test_base58(self):
        kv = edu.get_secret()
        Kv = edu.encodepoint(edf.scalarmult_B(kv))
        ks = edu.get_secret()
        Ks = edu.encodepoint(edf.scalarmult_B(ks))

        addr = xmr_encode_address(Kv, Ks)
        assert addr.startswith("4")

        addr = xmr_encode_address(Kv, Ks, 4146)
        assert addr.startswith("Wo")

    def test_blake256(self):
        test_vectors = [
            ("716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a", b""),
            (
                "7576698ee9cad30173080678e5965916adbb11cb5245d386bf1ffda1cb26c9d7",
                b"The quick brown fox jumps over the lazy dog",
            ),
        ]
        for expect_hash, data in test_vectors:
            assert blake256(data).hex() == expect_hash

    def test_extkey(self):
        test_key = "XPARHAr37YxmFP8wyjkaHAQWmp84GiyLikL7EL8j9BCx4LkB8Q1Bw5Kr8sA1GA3Ym53zNLcaxxFHr6u81JVTeCaD61c6fKS1YRAuti8Zu5SzJCjh"
        test_key_c0 = "XPARHAt1XMcNYAwP5wEnQXknBAkGSzaetdZt2eoJZehdB4WXfV1xbSjpgHe44AivmumcSejW5KaYx6L5M6MyR1WyXrsWTwaiUEfHq2RrqCfXj3ZW"
        test_key_c0_p = "PPARTKPL4rp5WLnrYP6jZfuRjx6jrmvbsz5QdHofPfFqJdm918mQwdPLq6Dd9TkdbQeKUqjbHWkyzWe7Pftd7itzm7ETEoUMq4cbG4fY9FKH1YSU"
        test_key_c0h = "XPARHAt1XMcNgWbv48LwoQbjs1bC8kCXKomzvJLRT5xmbQ2GKf9e8Vfr1MMcfiWJC34RyDp5HvAfjeiNyLDfkFm1UrRCrPkVC9GGaAWa3nXMWew8"

        ek_data = decodeAddress(test_key)[4:]

        ek = ExtKeyPair()
        ek.decode(ek_data)
        assert ek.encode_v() == ek_data

        m_0 = ek.derive(0)

        ek_c0_data = decodeAddress(test_key_c0)[4:]
        assert m_0.encode_v() == ek_c0_data

        child_no: int = 0 | (1 << 31)
        m_0h = ek.derive(child_no)

        ek_c0h_data = decodeAddress(test_key_c0h)[4:]
        assert m_0h.encode_v() == ek_c0h_data

        ek.neuter()
        assert ek.has_key() is False
        m_0 = ek.derive(0)

        ek_c0_p_data = decodeAddress(test_key_c0_p)[4:]
        assert m_0.encode_p() == ek_c0_p_data

    def test_mnemonic(self):
        entropy0: bytes = Mnemonic("english").to_entropy(mnemonics[0])
        assert entropy0.hex() == "0002207e9b744ea2d7ab41702f31f000"
        mnemonic_recovered: str = Mnemonic("english").to_mnemonic(entropy0)
        assert mnemonic_recovered == mnemonics[0]

    def test_db(self):
        db_test = DBMethods()
        db_test.sqlite_file = ":memory:"
        db_test.mxDB = threading.Lock()
        cursor = db_test.openDB()
        try:
            create_db_(db_test._db_con, logger)
            # Test upsert
            ki = KnownIdentity()
            ki.address = "test"
            ki.label = "test"
            db_test.add(ki, cursor)
            ki.record_id = 1
            ki.address = "test1"
            ki.label = "test1"
            try:
                db_test.add(ki, cursor, upsert=False)
            except Exception as e:
                assert "UNIQUE constraint failed" in str(e)
            else:
                raise ValueError("Should have errored.")
            db_test.add(ki, cursor, upsert=True)
        finally:
            db_test.closeDB(cursor)


if __name__ == "__main__":
    unittest.main()
