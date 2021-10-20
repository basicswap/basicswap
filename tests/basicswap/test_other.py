#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 tecnovert
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

from basicswap.ecc_util import i2b, h2b
from basicswap.interface_btc import BTCInterface
from basicswap.interface_xmr import XMRInterface

from basicswap.basicswap_util import (
    SEQUENCE_LOCK_BLOCKS,
    SEQUENCE_LOCK_TIME)
from basicswap.util import (
    SerialiseNum,
    DeserialiseNum,
    make_int,
    format_amount,
    validate_amount)


class Test(unittest.TestCase):
    def test_serialise_num(self):
        def test_case(v, nb=None):
            b = SerialiseNum(v)
            if nb is not None:
                assert(len(b) == nb)
            assert(v == DeserialiseNum(b))
        test_case(0, 1)
        test_case(1, 1)
        test_case(16, 1)

        test_case(-1, 2)
        test_case(17, 2)

        test_case(500)
        test_case(-500)
        test_case(4194642)

    def test_sequence(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none', 'blocks_confirmed': 1, 'conf_target': 1}
        ci = BTCInterface(coin_settings, 'regtest')

        time_val = 48 * 60 * 60
        encoded = ci.getExpectedSequence(SEQUENCE_LOCK_TIME, time_val)
        decoded = ci.decodeSequence(encoded)
        assert(decoded >= time_val)
        assert(decoded <= time_val + 512)

        time_val = 24 * 60
        encoded = ci.getExpectedSequence(SEQUENCE_LOCK_TIME, time_val)
        decoded = ci.decodeSequence(encoded)
        assert(decoded >= time_val)
        assert(decoded <= time_val + 512)

        blocks_val = 123
        encoded = ci.getExpectedSequence(SEQUENCE_LOCK_BLOCKS, blocks_val)
        decoded = ci.decodeSequence(encoded)
        assert(decoded == blocks_val)

    def test_make_int(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs)
            assert(i == expect_int and isinstance(i, int))
            i = make_int(vf)
            assert(i == expect_int and isinstance(i, int))
            vs_out = format_amount(i, 8)
            # Strip
            for i in range(7):
                if vs_out[-1] == '0':
                    vs_out = vs_out[:-1]
            if '.' in vs:
                assert(vs_out == vs)
            else:
                assert(vs_out[:-2] == vs)
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
            assert(False)
        except Exception as e:
            assert(str(e) == 'Mantissa too long')
        validate_amount('0.12345678')

        # floor
        assert(make_int('0.123456789', r=-1) == 12345678)
        # Round up
        assert(make_int('0.123456789', r=1) == 12345679)

    def test_make_int12(self):
        def test_case(vs, vf, expect_int):
            i = make_int(vs, 12)
            assert(i == expect_int and isinstance(i, int))
            i = make_int(vf, 12)
            assert(i == expect_int and isinstance(i, int))
            vs_out = format_amount(i, 12)
            # Strip
            for i in range(7):
                if vs_out[-1] == '0':
                    vs_out = vs_out[:-1]
            if '.' in vs:
                assert(vs_out == vs)
            else:
                assert(vs_out[:-2] == vs)
        test_case('0.123456789', 0.123456789, 123456789000)
        test_case('0.123456789123', 0.123456789123, 123456789123)
        try:
            make_int('0.1234567891234', 12)
            assert(False)
        except Exception as e:
            assert(str(e) == 'Mantissa too long')
        validate_amount('0.123456789123', 12)
        try:
            validate_amount('0.1234567891234', 12)
            assert(False)
        except Exception as e:
            assert('Too many decimal places' in str(e))
        try:
            validate_amount(0.1234567891234, 12)
            assert(False)
        except Exception as e:
            assert('Too many decimal places' in str(e))

    def test_ed25519(self):
        privkey = edu.get_secret()
        pubkey = edu.encodepoint(edf.scalarmult_B(privkey))

        privkey_bytes = i2b(privkey)
        pubkey_test = ed25519_get_pubkey(privkey_bytes)
        assert(pubkey == pubkey_test)

    def test_ecdsa_otves(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none', 'blocks_confirmed': 1, 'conf_target': 1}
        ci = BTCInterface(coin_settings, 'regtest')
        vk_sign = i2b(ci.getNewSecretKey())
        vk_encrypt = i2b(ci.getNewSecretKey())

        pk_sign = ci.getPubkey(vk_sign)
        pk_encrypt = ci.getPubkey(vk_encrypt)
        sign_hash = secrets.token_bytes(32)

        cipher_text = ecdsaotves_enc_sign(vk_sign, pk_encrypt, sign_hash)

        assert(ecdsaotves_enc_verify(pk_sign, pk_encrypt, sign_hash, cipher_text))

        sig = ecdsaotves_dec_sig(vk_encrypt, cipher_text)

        assert(ci.verifySig(pk_sign, sign_hash, sig))

        recovered_key = ecdsaotves_rec_enc_key(pk_encrypt, cipher_text, sig)

        assert(vk_encrypt == recovered_key)

    def test_sign(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none', 'blocks_confirmed': 1, 'conf_target': 1}
        ci = BTCInterface(coin_settings, 'regtest')

        vk = i2b(ci.getNewSecretKey())
        pk = ci.getPubkey(vk)

        message = 'test signing message'
        message_hash = hashlib.sha256(bytes(message, 'utf-8')).digest()
        eck = PrivateKey(vk)
        sig = eck.sign(message.encode('utf-8'))

        ci.verifySig(pk, message_hash, sig)

    def test_sign_compact(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none', 'blocks_confirmed': 1, 'conf_target': 1}
        ci = BTCInterface(coin_settings, 'regtest')

        vk = i2b(ci.getNewSecretKey())
        pk = ci.getPubkey(vk)
        sig = ci.signCompact(vk, 'test signing message')
        assert(len(sig) == 64)
        ci.verifyCompact(pk, 'test signing message', sig)

    def test_pubkey_to_address(self):
        coin_settings = {'rpcport': 0, 'rpcauth': 'none', 'blocks_confirmed': 1, 'conf_target': 1}
        ci = BTCInterface(coin_settings, 'regtest')
        pk = h2b('02c26a344e7d21bcc6f291532679559f2fd234c881271ff98714855edc753763a6')
        addr = ci.pubkey_to_address(pk)
        assert(addr == 'mj6SdSxmWRmdDqR5R3FfZmRiLmQfQAsLE8')

    def test_dleag(self):
        coin_settings = {'rpcport': 0, 'walletrpcport': 0, 'walletrpcauth': 'none', 'blocks_confirmed': 1, 'conf_target': 1}
        ci = XMRInterface(coin_settings, 'regtest')

        key = i2b(ci.getNewSecretKey())
        proof = ci.proveDLEAG(key)
        assert(ci.verifyDLEAG(proof))

    def test_rate(self):
        scale_from = 8
        scale_to = 12
        amount_from = make_int(100, scale_from)
        rate = make_int(0.1, scale_to)

        amount_to = int((amount_from * rate) // (10 ** scale_from))
        assert('100.00000000' == format_amount(amount_from, scale_from))
        assert('10.000000000000' == format_amount(amount_to, scale_to))

        rate_check = make_int((amount_to / amount_from), scale_from)
        assert(rate == rate_check)

        scale_from = 12
        scale_to = 8
        amount_from = make_int(1, scale_from)
        rate = make_int(12, scale_to)

        amount_to = int((amount_from * rate) // (10 ** scale_from))
        assert('1.000000000000' == format_amount(amount_from, scale_from))
        assert('12.00000000' == format_amount(amount_to, scale_to))

        rate_check = make_int((amount_to / amount_from), scale_from)
        assert(rate == rate_check)

        scale_from = 8
        scale_to = 8
        amount_from = make_int(0.073, scale_from)
        amount_to = make_int(10, scale_to)
        rate = make_int(amount_to / amount_from, scale_to, r=1)
        amount_to_recreate = int((amount_from * rate) // (10 ** scale_from))
        assert('10.00000000' == format_amount(amount_to_recreate, scale_to))

        scale_from = 8
        scale_to = 12
        amount_from = make_int(10.0, scale_from)
        amount_to = make_int(0.06935, scale_to)
        rate = make_int(amount_to / amount_from, scale_from, r=1)
        amount_to_recreate = int((amount_from * rate) // (10 ** scale_from))
        assert('0.069350000000' == format_amount(amount_to_recreate, scale_to))

        scale_from = 12
        scale_to = 8
        amount_from = make_int(0.06935, scale_from)
        amount_to = make_int(10.0, scale_to)
        rate = make_int(amount_to / amount_from, scale_from, r=1)
        amount_to_recreate = int((amount_from * rate) // (10 ** scale_from))
        assert('10.00000000' == format_amount(amount_to_recreate, scale_to))


if __name__ == '__main__':
    unittest.main()
