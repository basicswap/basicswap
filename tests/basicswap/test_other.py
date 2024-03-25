#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import secrets
import unittest

import basicswap.contrib.ed25519_fast as edf
import basicswap.ed25519_fast_util as edu

from coincurve.ed25519 import ed25519_get_pubkey
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key)
from coincurve.keys import (
    PrivateKey)

from basicswap.util import i2b, h2b
from basicswap.util.integer import encode_varint, decode_varint
from basicswap.util.crypto import ripemd160, hash160
from basicswap.util.network import is_private_ip_address
from basicswap.util.rfc2440 import rfc2440_hash_password
from basicswap.util_xmr import encode_address as xmr_encode_address
from basicswap.interface.btc import BTCInterface
from basicswap.interface.xmr import XMRInterface

from basicswap.basicswap_util import (
    TxLockTypes)
from basicswap.util import (
    make_int,
    SerialiseNum,
    format_amount,
    DeserialiseNum,
    validate_amount)

from basicswap.messages_pb2 import (
    BidMessage,
    BidMessage_v1Deprecated,
)
from basicswap.contrib.test_framework.script import hash160 as hash160_btc


class Test(unittest.TestCase):
    REQUIRED_SETTINGS = {'blocks_confirmed': 1, 'conf_target': 1, 'use_segwit': True, 'connection_type': 'rpc'}

    def test_serialise_num(self):
        def test_case(v, nb=None):
            b = SerialiseNum(v)
            if nb is not None:
                assert (len(b) == nb)
            assert (v == DeserialiseNum(b))
        test_case(0, 1)
        test_case(1, 1)
        test_case(16, 1)

        test_case(-1, 2)
        test_case(17, 2)

        test_case(500)
        test_case(-500)
        test_case(4194642)

    def test_sequence(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(self.REQUIRED_SETTINGS)

        ci = BTCInterface(coin_settings, 'regtest')

        time_val = 48 * 60 * 60
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, time_val)
        decoded = ci.decodeSequence(encoded)
        assert (decoded >= time_val)
        assert (decoded <= time_val + 512)

        time_val = 24 * 60
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, time_val)
        decoded = ci.decodeSequence(encoded)
        assert (decoded >= time_val)
        assert (decoded <= time_val + 512)

        blocks_val = 123
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_BLOCKS, blocks_val)
        decoded = ci.decodeSequence(encoded)
        assert (decoded == blocks_val)

    def test_make_int(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs)
            assert (i == expect_int and isinstance(i, int))
            i = make_int(vf)
            assert (i == expect_int and isinstance(i, int))
            vs_out = format_amount(i, 8)
            # Strip
            for i in range(7):
                if vs_out[-1] == '0':
                    vs_out = vs_out[:-1]
            if '.' in vs:
                assert (vs_out == vs)
            else:
                assert (vs_out[:-2] == vs)
        test_case('0', 0, 0)
        test_case('1', 1, 100000000)
        test_case('10', 10, 1000000000)
        test_case('0.00899999', 0.00899999, 899999)
        test_case('899999.0', 899999.0, 89999900000000)
        test_case('899999.00899999', 899999.00899999, 89999900899999)
        test_case('0.0', 0.0, 0)
        test_case('1.0', 1.0, 100000000)
        test_case('1.1', 1.1, 110000000)
        test_case('1.2', 1.2, 120000000)
        test_case('0.00899991', 0.00899991, 899991)
        test_case('0.0089999', 0.0089999, 899990)
        test_case('0.0089991', 0.0089991, 899910)
        test_case('0.123', 0.123, 12300000)
        test_case('123000.000123', 123000.000123, 12300000012300)

        try:
            make_int('0.123456789')
            assert (False)
        except Exception as e:
            assert (str(e) == 'Mantissa too long')
        validate_amount('0.12345678')

        # floor
        assert (make_int('0.123456789', r=-1) == 12345678)
        # Round up
        assert (make_int('0.123456789', r=1) == 12345679)

    def test_make_int12(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs, 12)
            assert (i == expect_int and isinstance(i, int))
            i = make_int(vf, 12)
            assert (i == expect_int and isinstance(i, int))
            vs_out = format_amount(i, 12)
            # Strip
            for i in range(7):
                if vs_out[-1] == '0':
                    vs_out = vs_out[:-1]
            if '.' in vs:
                assert (vs_out == vs)
            else:
                assert (vs_out[:-2] == vs)
        test_case('0.123456789', 0.123456789, 123456789000)
        test_case('0.123456789123', 0.123456789123, 123456789123)
        try:
            make_int('0.1234567891234', 12)
            assert (False)
        except Exception as e:
            assert (str(e) == 'Mantissa too long')
        validate_amount('0.123456789123', 12)
        try:
            validate_amount('0.1234567891234', 12)
            assert (False)
        except Exception as e:
            assert ('Too many decimal places' in str(e))
        try:
            validate_amount(0.1234567891234, 12)
            assert (False)
        except Exception as e:
            assert ('Too many decimal places' in str(e))

    def test_ed25519(self):
        privkey = edu.get_secret()
        pubkey = edu.encodepoint(edf.scalarmult_B(privkey))

        privkey_bytes = i2b(privkey)
        pubkey_test = ed25519_get_pubkey(privkey_bytes)
        assert (pubkey == pubkey_test)

    def test_ecdsa_otves(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(self.REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, 'regtest')
        vk_sign = ci.getNewSecretKey()
        vk_encrypt = ci.getNewSecretKey()

        pk_sign = ci.getPubkey(vk_sign)
        pk_encrypt = ci.getPubkey(vk_encrypt)
        sign_hash = secrets.token_bytes(32)

        cipher_text = ecdsaotves_enc_sign(vk_sign, pk_encrypt, sign_hash)

        assert (ecdsaotves_enc_verify(pk_sign, pk_encrypt, sign_hash, cipher_text))

        sig = ecdsaotves_dec_sig(vk_encrypt, cipher_text)

        assert (ci.verifySig(pk_sign, sign_hash, sig))

        recovered_key = ecdsaotves_rec_enc_key(pk_encrypt, cipher_text, sig)

        assert (vk_encrypt == recovered_key)

    def test_sign(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(self.REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, 'regtest')

        vk = ci.getNewSecretKey()
        pk = ci.getPubkey(vk)

        message = 'test signing message'
        message_hash = hashlib.sha256(bytes(message, 'utf-8')).digest()
        eck = PrivateKey(vk)
        sig = eck.sign(message.encode('utf-8'))

        ci.verifySig(pk, message_hash, sig)

    def test_sign_compact(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(self.REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, 'regtest')

        vk = ci.getNewSecretKey()
        pk = ci.getPubkey(vk)
        sig = ci.signCompact(vk, 'test signing message')
        assert (len(sig) == 64)
        ci.verifyCompactSig(pk, 'test signing message', sig)

        # Nonce is set deterministically (using default libsecp256k1 method rfc6979)
        sig2 = ci.signCompact(vk, 'test signing message')
        assert (sig == sig2)

    def test_sign_recoverable(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(self.REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, 'regtest')

        vk = ci.getNewSecretKey()
        pk = ci.getPubkey(vk)
        sig = ci.signRecoverable(vk, 'test signing message')
        assert (len(sig) == 65)
        pk_rec = ci.verifySigAndRecover(sig, 'test signing message')
        assert (pk == pk_rec)

        # Nonce is set deterministically (using default libsecp256k1 method rfc6979)
        sig2 = ci.signRecoverable(vk, 'test signing message')
        assert (sig == sig2)

    def test_pubkey_to_address(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(self.REQUIRED_SETTINGS)
        ci = BTCInterface(coin_settings, 'regtest')
        pk = h2b('02c26a344e7d21bcc6f291532679559f2fd234c881271ff98714855edc753763a6')
        addr = ci.pubkey_to_address(pk)
        assert (addr == 'mj6SdSxmWRmdDqR5R3FfZmRiLmQfQAsLE8')

    def test_dleag(self):
        coin_settings = {'rpcport': 0, 'walletrpcport': 0, 'walletrpcauth': 'none'}
        coin_settings.update(self.REQUIRED_SETTINGS)

        ci = XMRInterface(coin_settings, 'regtest')

        key = ci.getNewSecretKey()
        proof = ci.proveDLEAG(key)
        assert (ci.verifyDLEAG(proof))

    def test_rate(self):
        scale_from = 8
        scale_to = 12
        amount_from = make_int(100, scale_from)
        rate = make_int(0.1, scale_to)

        amount_to = int((amount_from * rate) // (10 ** scale_from))
        assert ('100.00000000' == format_amount(amount_from, scale_from))
        assert ('10.000000000000' == format_amount(amount_to, scale_to))

        rate_check = make_int((amount_to / amount_from), scale_from)
        assert (rate == rate_check)

        scale_from = 12
        scale_to = 8
        amount_from = make_int(1, scale_from)
        rate = make_int(12, scale_to)

        amount_to = int((amount_from * rate) // (10 ** scale_from))
        assert ('1.000000000000' == format_amount(amount_from, scale_from))
        assert ('12.00000000' == format_amount(amount_to, scale_to))

        rate_check = make_int((amount_to / amount_from), scale_from)
        assert (rate == rate_check)

        scale_from = 8
        scale_to = 8
        amount_from = make_int(0.073, scale_from)
        amount_to = make_int(10, scale_to)
        rate = make_int(amount_to / amount_from, scale_to, r=1)
        amount_to_recreate = int((amount_from * rate) // (10 ** scale_from))
        assert ('10.00000000' == format_amount(amount_to_recreate, scale_to))

        scale_from = 8
        scale_to = 12
        amount_from = make_int(10.0, scale_from)
        amount_to = make_int(0.06935, scale_to)
        rate = make_int(amount_to / amount_from, scale_from, r=1)
        amount_to_recreate = int((amount_from * rate) // (10 ** scale_from))
        assert ('0.069350000000' == format_amount(amount_to_recreate, scale_to))

        scale_from = 12
        scale_to = 8
        amount_from = make_int(0.06935, scale_from)
        amount_to = make_int(10.0, scale_to)
        rate = make_int(amount_to / amount_from, scale_from, r=1)
        amount_to_recreate = int((amount_from * rate) // (10 ** scale_from))
        assert ('10.00000000' == format_amount(amount_to_recreate, scale_to))

    def test_rfc2440(self):
        password = 'test'
        salt = bytes.fromhex('B7A94A7E4988630E')
        password_hash = rfc2440_hash_password(password, salt=salt)

        assert (password_hash == '16:B7A94A7E4988630E6095334BA67F06FBA509B2A7136A04C9C1B430F539')

    def test_ripemd160(self):
        input_data = b'hash this'
        assert (ripemd160(input_data).hex() == 'd5443a154f167e2c1332f6de72cfb4c6ab9c8c17')

    def test_hash160(self):
        # hash160 is RIPEMD(SHA256(data))
        input_data = b'hash this'
        assert (hash160(input_data).hex() == '072985b3583a4a71f548494a5e1d5f6b00d0fe13')
        assert (hash160_btc(input_data).hex() == '072985b3583a4a71f548494a5e1d5f6b00d0fe13')

    def test_protobuf(self):
        # Ensure old protobuf templates can be read

        msg_buf = BidMessage_v1Deprecated()
        msg_buf.protocol_version = 2
        serialised_msg = msg_buf.SerializeToString()

        msg_buf_v2 = BidMessage()
        msg_buf_v2.ParseFromString(serialised_msg)

        assert (msg_buf_v2.protocol_version == 2)

    def test_is_private_ip_address(self):
        assert (is_private_ip_address('localhost'))
        assert (is_private_ip_address('127.0.0.1'))
        assert (is_private_ip_address('10.0.0.0'))
        assert (is_private_ip_address('172.16.0.0'))
        assert (is_private_ip_address('192.168.0.0'))

        assert (is_private_ip_address('20.87.245.0') is False)
        assert (is_private_ip_address('particl.io') is False)

    def test_varint(self):
        def test_case(i, expect_length):
            b = encode_varint(i)
            assert (len(b) == expect_length)
            assert (decode_varint(b) == i)

        test_case(0, 1)
        test_case(1, 1)
        test_case(127, 1)
        test_case(128, 2)
        test_case(253, 2)
        test_case(8321, 2)
        test_case(16383, 2)
        test_case(16384, 3)
        test_case(2097151, 3)
        test_case(2097152, 4)

    def test_base58(self):
        kv = edu.get_secret()
        Kv = edu.encodepoint(edf.scalarmult_B(kv))
        ks = edu.get_secret()
        Ks = edu.encodepoint(edf.scalarmult_B(ks))

        addr = xmr_encode_address(Kv, Ks)
        assert (addr.startswith('4'))

        addr = xmr_encode_address(Kv, Ks, 4146)
        assert (addr.startswith('Wo'))


if __name__ == '__main__':
    unittest.main()
