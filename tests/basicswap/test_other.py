#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from io import BytesIO
import base64
import collections
import hashlib
import logging
import os
import random
import secrets
import threading
import unittest

from coincurve.ed25519 import ed25519_get_pubkey
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key,
)
from coincurve.keys import PrivateKey

from basicswap.basicswap import (
    Coins,
    BasicSwap,
    SwapTypes,
)
from basicswap.base import BaseApp
from basicswap.chainparams import coins_without_segwit, scriptless_coins
from basicswap.contrib.mnemonic import Mnemonic
from basicswap.db import Bid, create_db_, DBMethods, KnownIdentity, Offer, SwapTx
from basicswap.util import h2b
from basicswap.util.address import decodeAddress, toWIF
from basicswap.util.crypto import ripemd160, hash160, blake256, sha256
from basicswap.util.extkey import ExtKeyPair
from basicswap.util.integer import encode_varint, decode_varint
from basicswap.util.network import (
    is_loopback_address,
    is_origin_allowed,
    is_private_ip_address,
    is_public_url,
    is_url_scheme_allowed,
)
from basicswap.util.rfc2440 import rfc2440_hash_password
from basicswap.util_xmr import (
    decode_address as xmr_decode_address,
    encode_address as xmr_encode_address,
)
from basicswap.interface.btc.btc import BTCInterface
from basicswap.interface.nmc.nmc import NMCInterface
from basicswap.interface.bch.bch import BCHInterface
from basicswap.interface.bch.contrib.cashaddress import Address
from basicswap.interface.bch.contrib.script import OP_HASH256
from basicswap.interface.dash.dash import DASHInterface
from basicswap.interface.doge.doge import DOGEInterface
from basicswap.interface.firo.firo import FIROInterface
from basicswap.interface.ltc.ltc import LTCInterface
from basicswap.interface.part.part import PARTInterface
from basicswap.interface.pivx.pivx import PIVXInterface
from basicswap.protocols.atomic_swap_1 import buildContractScript
from basicswap.protocols.xmr_swap_1 import XmrSwapInterface
from basicswap.script import OpCodes
from basicswap.interface.electrumx import scripthash_from_address
from basicswap.util.logging import BSXLogger
from basicswap.interface.xmr.xmr import XMRInterface
from tests.basicswap.util.mnemonics import mnemonics
from tests.basicswap.util.common import (
    REQUIRED_SETTINGS,
    PREFIX_SECRET_KEY_REGTEST,
)

from basicswap.config import DEFAULT_ALTRUISTIC
from basicswap.basicswap_util import (
    ADAPTOR_SIG_LOCK_SPEND_FEE_BUFFER,
    AddressTypes,
    MessageNetworks,
    TxLockTypes,
    XmrSplitMsgTypes,
)
from basicswap.util import (
    make_int,
    SerialiseNum,
    format_amount,
    DeserialiseNum,
    validate_amount,
)
from basicswap.rpc import Jsonrpc, escape_rpcauth
from basicswap.messages_npb import (
    BidMessage,
    MessagePortalOffer,
    OfferRevokeMessage,
    XmrSplitMessage,
)
from basicswap.network.bsx_network import BSXNetwork
from basicswap.contrib.test_framework import segwit_addr
from basicswap.contrib.test_framework.script import (
    CScript,
    CScriptOp,
    hash160 as hash160_btc,
    OP_CHECKMULTISIG,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    SegwitV0SignatureHash,
    SIGHASH_ALL,
)
from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    uint256_from_str,
)

logger = logging.getLogger()


class _FakeSwapClient:
    # Use the real lookup, BaseApp can't be instantiated without a datadir
    getBaseAltruistic = BaseApp.getBaseAltruistic

    def __init__(self, settings=None):
        self.settings = {"chainclients": {}}
        if settings:
            self.settings.update(settings)
        self.log = BSXLogger("test")

    def getChainClientSettings(self, coin):
        return {}


class Test(unittest.TestCase):

    @staticmethod
    def ci_btc():
        btc_coin_settings = {"rpcport": 0, "rpcauth": "none"}
        btc_coin_settings.update(REQUIRED_SETTINGS)
        ci = BTCInterface(btc_coin_settings, "regtest")
        # Without a swap client _log is the logging module, which has no id()
        ci._log = BSXLogger("test")
        return ci

    @staticmethod
    def ci_xmr():
        xmr_coin_settings = {"rpcport": 0, "walletrpcport": 0, "walletrpcauth": "none"}
        xmr_coin_settings.update(REQUIRED_SETTINGS)
        return XMRInterface(xmr_coin_settings, "regtest")

    def test_altruistic_setting(self):
        def ci_btc_with(coin_setting=None, swap_client=None):
            coin_settings = {"rpcport": 0, "rpcauth": "none"}
            coin_settings.update(REQUIRED_SETTINGS)
            if coin_setting is not None:
                coin_settings["altruistic"] = coin_setting
            ci = BTCInterface(coin_settings, "regtest", swap_client=swap_client)
            ci._log = BSXLogger("test")
            return ci

        sc_unset = _FakeSwapClient()
        sc_on = _FakeSwapClient({"altruistic": True})
        sc_off = _FakeSwapClient({"altruistic": False})

        # No swap client or base unset, no coin key → the shared default
        assert ci_btc_with()._altruistic is DEFAULT_ALTRUISTIC
        assert ci_btc_with(swap_client=sc_unset)._altruistic is DEFAULT_ALTRUISTIC

        # Base off, no coin key → off
        assert ci_btc_with(swap_client=sc_off)._altruistic is False

        # Base on, no coin key → on
        assert ci_btc_with(swap_client=sc_on)._altruistic is True

        # Coin key wins over base, both directions
        assert ci_btc_with(False, sc_on)._altruistic is False
        assert ci_btc_with(True, sc_off)._altruistic is True

    def test_altruistic_coin_setting_passthrough(self):
        logging.info("---------- Test altruistic coin setting passthrough")
        basicswap_dir = "/tmp/bsx_test_other"
        if not os.path.exists(basicswap_dir):
            os.makedirs(basicswap_dir)

        k = PrivateKey()
        settings = {
            "network_key": toWIF(PREFIX_SECRET_KEY_REGTEST, k.secret),
            "network_pubkey": k.public_key.format().hex(),
            "chainclients": {
                "bitcoin": {"altruistic": True},
                "decred": {"altruistic": False},
            },
        }

        sc = BasicSwap(
            basicswap_dir,
            settings,
            "regtest",
            log_name="bsx_test_other",
        )
        # setCoinConnectParams must forward the key, the interfaces read coin_clients
        assert sc.coin_clients[Coins.BTC]["altruistic"] is True
        assert sc.coin_clients[Coins.DCR]["altruistic"] is False
        assert "altruistic" not in sc.coin_clients[Coins.LTC]

        del sc

    def test_btc_wallet_info_balance_compatibility(self):
        ci = self.ci_btc()

        # Bitcoin Core < 30: getwalletinfo still returns balance fields.
        calls = []

        def legacy_rpc(method, params=None):
            calls.append(method)
            if method == "getwalletinfo":
                return {
                    "balance": 1.25,
                    "unconfirmed_balance": 0.5,
                    "immature_balance": 0.25,
                }
            if method == "listlockunspent":
                return []
            raise ValueError(f"Unexpected RPC call: {method}")

        ci.rpc_wallet = legacy_rpc
        wallet_info = ci.getWalletInfo()

        assert wallet_info["balance"] == 1.25
        assert wallet_info["unconfirmed_balance"] == 0.5
        assert wallet_info["immature_balance"] == 0.25
        assert "getbalances" not in calls

        # Bitcoin Core >= 30: balance fields moved to getbalances.
        calls.clear()

        def core30_rpc(method, params=None):
            calls.append(method)
            if method == "getwalletinfo":
                return {"walletname": "bsx_wallet"}
            if method == "getbalances":
                return {
                    "mine": {
                        "trusted": 1.25,
                        "untrusted_pending": 0.5,
                        "immature": 0.25,
                    }
                }
            if method == "listlockunspent":
                return []
            raise ValueError(f"Unexpected RPC call: {method}")

        ci.rpc_wallet = core30_rpc
        wallet_info = ci.getWalletInfo()

        assert wallet_info["balance"] == 1.25
        assert wallet_info["unconfirmed_balance"] == 0.5
        assert wallet_info["immature_balance"] == 0.25
        assert calls.count("getbalances") == 1

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
        ci = self.ci_btc()

        time_val = 48 * 60 * 60
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, time_val)
        decoded = ci.decodeSequence(encoded)
        assert encoded == 4194642
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

    def test_csv_lock_remaining(self):
        ci = self.ci_btc()

        parent_height: int = 100
        parent_time: int = 1700000000
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, 4 * 60 * 60)
        lock_value: int = ci.decodeSequence(encoded)

        assert (
            ci.csvLockRemaining(
                TxLockTypes.SEQUENCE_LOCK_TIME,
                encoded,
                parent_height,
                parent_time,
                chain_mtp=parent_time,
                coin_mtp=parent_time,
            )
            == lock_value
        )
        assert (
            ci.csvLockRemaining(
                TxLockTypes.SEQUENCE_LOCK_TIME,
                encoded,
                parent_height,
                parent_time,
                chain_mtp=parent_time + lock_value,
                coin_mtp=parent_time,
            )
            == 0
        )

        # A remaining value at or below zero must mean the lock has matured
        for offset in range(0, lock_value + 1024, 499):
            chain_mtp: int = parent_time + offset
            remaining = ci.csvLockRemaining(
                TxLockTypes.SEQUENCE_LOCK_TIME,
                encoded,
                parent_height,
                parent_time,
                chain_mtp=chain_mtp,
                coin_mtp=parent_time,
            )
            assert (remaining <= 0) == ci.isCsvLockMature(
                TxLockTypes.SEQUENCE_LOCK_TIME,
                encoded,
                parent_height,
                parent_time,
                chain_mtp=chain_mtp,
                coin_mtp=parent_time,
            )

        # Unknown until the lock tx is in a block
        assert (
            ci.csvLockRemaining(TxLockTypes.SEQUENCE_LOCK_TIME, encoded, None, None)
            is None
        )
        assert (
            ci.csvLockRemaining(
                TxLockTypes.SEQUENCE_LOCK_TIME, encoded, parent_height, None
            )
            is None
        )

        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_BLOCKS, 10)
        assert (
            ci.csvLockRemaining(
                TxLockTypes.SEQUENCE_LOCK_BLOCKS,
                encoded,
                parent_height,
                parent_time,
                chain_height=parent_height + 5,
            )
            == 4
        )

    def test_lock_spend_margin(self):
        # The margin the follower applies before publishing the lock spend tx
        ci = self.ci_btc()

        parent_height: int = 100
        parent_time: int = 1700000000
        margin: int = 3600
        encoded = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, 48 * 60 * 60)
        lock_value: int = ci.decodeSequence(encoded)

        def remaining_at(chain_mtp: int) -> int:
            return ci.csvLockRemaining(
                TxLockTypes.SEQUENCE_LOCK_TIME,
                encoded,
                parent_height,
                parent_time,
                chain_mtp=chain_mtp,
                coin_mtp=parent_time,
            )

        # Exactly at the margin must still publish, one second under must not
        assert remaining_at(parent_time + lock_value - margin) == margin
        assert remaining_at(parent_time + lock_value - margin) >= margin
        assert remaining_at(parent_time + lock_value - margin + 1) < margin

        # An expired lock must always be caught by the same comparison
        for offset in range(lock_value, lock_value + 2048, 499):
            assert remaining_at(parent_time + offset) < margin
            assert ci.isCsvLockMature(
                TxLockTypes.SEQUENCE_LOCK_TIME,
                encoded,
                parent_height,
                parent_time,
                chain_mtp=parent_time + offset,
                coin_mtp=parent_time,
            )

        # An honest leader releases well before its own margin, even on the shortest offer
        release_margin: int = 3600
        assert margin <= release_margin
        # min_sequence_lock_seconds less the wait for the coin b lock to be spendable
        assert (2 * 60 * 60) - (10 * 120) >= margin

    def test_lock_spend_tx_fee(self):
        # The lock spend tx must pay more than the lock refund tx, else the refund tx
        # can replace it by RBF once the spend tx has been broadcast
        ci = self.ci_btc()

        Kal = ci.getPubkey(ci.getNewRandomKey())
        Kaf = ci.getPubkey(ci.getNewRandomKey())
        script_lock = CScript([2, Kal, Kaf, 2, OP_CHECKMULTISIG])
        pkh_dest = ci.pkh(Kaf)

        locked_coin: int = ci.make_int(0.1)
        lock_tx = CTransaction()
        lock_tx.nVersion = ci.txVersion()
        lock_tx.vin.append(
            CTxIn(COutPoint(uint256_from_str(secrets.token_bytes(32)), 0))
        )
        lock_tx.vout.append(CTxOut(locked_coin, ci.getScriptDest(script_lock)))
        lock_tx.rehash()
        lock_tx_bytes = lock_tx.serialize()

        lock1_value = ci.getExpectedSequence(
            TxLockTypes.SEQUENCE_LOCK_TIME, 2 * 60 * 60
        )
        csv_val = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, 2 * 60 * 60)

        for fee_rate in (1000, 1013, 2500, 10000, 59999):
            refund_tx, _, refund_value = ci.createSCLockRefundTx(
                lock_tx_bytes,
                script_lock,
                Kal,
                Kaf,
                lock1_value,
                csv_val,
                fee_rate,
            )
            refund_fee: int = locked_coin - refund_value

            spend_tx = ci.createSCLockSpendTx(
                lock_tx_bytes,
                script_lock,
                pkh_dest,
                fee_rate,
                tx_lock_refund_bytes=refund_tx,
            )
            spend_fee: int = locked_coin - ci.loadTx(spend_tx).vout[0].nValue

            assert spend_fee == refund_fee + ADAPTOR_SIG_LOCK_SPEND_FEE_BUFFER
            # RBF rule 3 rejects the refund tx as a replacement while this holds
            assert spend_fee > refund_fee

            ci.verifySCLockSpendTx(
                spend_tx,
                lock_tx_bytes,
                script_lock,
                pkh_dest,
                fee_rate,
                tx_lock_refund_bytes=refund_tx,
            )

            # A spend tx paying the refund tx's fee must be rejected
            tx = ci.loadTx(spend_tx)
            tx.vout[0].nValue += ADAPTOR_SIG_LOCK_SPEND_FEE_BUFFER
            tx.rehash()
            try:
                ci.verifySCLockSpendTx(
                    tx.serialize(),
                    lock_tx_bytes,
                    script_lock,
                    pkh_dest,
                    fee_rate,
                    tx_lock_refund_bytes=refund_tx,
                )
                assert False, "Should fail"
            except Exception as e:
                assert "Bad fee" in str(e)

    def test_compare_fee_rates(self):
        # compareFeeRates must accept every fee feeForVSize can produce
        ci = self.ci_btc()

        for vsize in range(110, 400):
            for expected in range(500, 20000, 7):
                paid_rate: int = ci.feeForVSize(expected, vsize) * 1000 // vsize
                assert ci.compareFeeRates(paid_rate, expected)
                assert ci.compareFeeRates(expected - 1, expected) is False

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

        # Floor
        assert make_int("0.123456789", r=-1) == 12345678
        # Round up
        assert make_int("0.123456789", r=1) == 12345679

    def test_format_amount(self):
        # display_scale defaults to scale: fixed-precision, zero-padded
        assert format_amount(123456789, 8) == "1.23456789"
        assert format_amount(0, 8) == "0.00000000"
        assert format_amount(1, 8) == "0.00000001"
        assert format_amount(-100000000, 8) == "-1.00000000"
        assert format_amount(2100000000000000, 8) == "21000000.00000000"
        assert format_amount(10000000000000, 12) == "10.000000000000"

        # Amounts must be integers
        try:
            format_amount(1.0, 8)
            assert False
        except ValueError as e:
            assert str(e) == "Amount must be an integer."

        # display_scale < scale: show the first display_scale decimals (truncate, no rounding)
        assert format_amount(123456789, 4, 8) == "1.2345"
        assert format_amount(-123456789, 4, 8) == "-1.2345"
        assert format_amount(199999999, 2, 8) == "1.99"

        # display_scale > scale: pad the stored decimals out to display_scale places
        assert format_amount(123456789, 12, 8) == "1.234567890000"
        assert format_amount(150000000, 10, 8) == "1.5000000000"

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
        privkey = bytes.fromhex(
            "0b4c6e34c21b910f92c7985a8093de526f5f8677a112a8c672d1098139b70e0f"
        )
        pubkey = ed25519_get_pubkey(privkey)
        assert pubkey == bytes.fromhex(
            "5c26c518fb698e91a5858c33e9075488c55c235f391162fe9e6cbd4f694f80aa"
        )

    def test_key_summing(self):
        ci_btc = self.ci_btc()
        ci_xmr = self.ci_xmr()
        keys = [
            bytes.fromhex(
                "e6b8e7c2ca3a88fe4f28591aa0f91fec340179346559e4ec430c2531aecc19aa"
            ),
            bytes.fromhex(
                "b725b6359bd2b510d9d5a7bba7bdee17abbf113253f6338ea50a8f0cf45fd0d0"
            ),
        ]
        sum_secp256k1: bytes = ci_btc.sumKeys(keys[0], keys[1])
        assert (
            sum_secp256k1.hex()
            == "9dde9df8660d3e0f28fe00d648b70e052511ad800a07783f284455b1d2f5a939"
        )

        sum_ed25519: bytes = ci_xmr.sumKeys(keys[0], keys[1])
        assert (
            sum_ed25519.hex()
            == "0dde9df8660d3e0f28fe00d648b70e0323e9c192fe9b94f1cf7138515e877725"
        )

        pk_secp256k1 = ci_btc.sumPubkeys(
            ci_btc.getPubkey(keys[0]), ci_btc.getPubkey(keys[1])
        )
        assert (
            pk_secp256k1.hex()
            == "028c30392e35620af0787b363a03cf9a695336759664436e1f609481c869541a5c"
        )

        pk_ed25519 = ci_xmr.sumPubkeys(
            ci_xmr.getPubkey(keys[0]), ci_xmr.getPubkey(keys[1])
        )
        assert (
            pk_ed25519.hex()
            == "4b2dd2dc9acc9be7efed4fdbfb96f0002aeb9e4c8638c5b24562a7158b283626"
        )

        assert pk_secp256k1 == ci_btc.getPubkey(sum_secp256k1)

    def test_ecdsa_otves(self):
        ci = self.ci_btc()
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
        ci = self.ci_btc()

        vk = ci.getNewRandomKey()
        pk = ci.getPubkey(vk)

        message = "test signing message"
        message_hash = hashlib.sha256(bytes(message, "utf-8")).digest()
        eck = PrivateKey(vk)
        sig = eck.sign(message.encode("utf-8"))

        ci.verifySig(pk, message_hash, sig)

    def test_sign_compact(self):
        ci = self.ci_btc()

        vk = ci.getNewRandomKey()
        pk = ci.getPubkey(vk)
        sig = ci.signCompact(vk, "test signing message")
        assert len(sig) == 64
        ci.verifyCompactSig(pk, "test signing message", sig)

        # Nonce is set deterministically (using default libsecp256k1 method rfc6979)
        sig2 = ci.signCompact(vk, "test signing message")
        assert sig == sig2

    def test_sign_recoverable(self):
        ci = self.ci_btc()

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
        ci = self.ci_btc()
        pk = h2b("02c26a344e7d21bcc6f291532679559f2fd234c881271ff98714855edc753763a6")
        addr = ci.pubkey_to_address(pk)
        assert addr == "mj6SdSxmWRmdDqR5R3FfZmRiLmQfQAsLE8"

    def test_dest_for_address_keeps_the_witness_version(self):
        ci = self.ci_btc()
        hrp = ci.chainparams_network()["hrp"]
        program = bytes(range(32))
        for version in (0, 1):
            address = segwit_addr.encode_segwit_address(hrp, version, program)
            script = ci.getDestForAddress(address)
            assert script == CScript([CScriptOp.encode_op_n(version), program])

    def test_dest_for_address_accepts_uppercase(self):
        ci = self.ci_btc()
        hrp = ci.chainparams_network()["hrp"]
        address = segwit_addr.encode_segwit_address(hrp, 1, bytes(range(32)))
        assert ci.getDestForAddress(address.upper()) == ci.getDestForAddress(address)

    def test_scripthash_from_address_keeps_the_witness_version(self):
        ci = self.ci_btc()
        network_params = ci.chainparams_network()
        program = bytes(range(32))
        for version in (0, 1):
            address = segwit_addr.encode_segwit_address(
                network_params["hrp"], version, program
            )
            script = CScript([CScriptOp.encode_op_n(version), program])
            expected = sha256(bytes(script))[::-1].hex()
            assert scripthash_from_address(address, network_params) == expected

    def test_decode_address_refuses_non_v0(self):
        ci = self.ci_btc()
        hrp = ci.chainparams_network()["hrp"]
        program = bytes(range(20))
        v0_address = segwit_addr.encode_segwit_address(hrp, 0, program)
        assert ci.decodeAddress(v0_address) == program
        v1_address = segwit_addr.encode_segwit_address(hrp, 1, bytes(range(32)))
        with self.assertRaises(ValueError):
            ci.decodeAddress(v1_address)

    def test_dest_for_address_refuses_unpayable_versions(self):
        ci = self.ci_btc()
        hrp = ci.chainparams_network()["hrp"]
        for version, program in ((1, bytes(range(20))), (2, bytes(range(32)))):
            address = segwit_addr.encode_segwit_address(hrp, version, program)
            with self.assertRaises(ValueError):
                ci.getDestForAddress(address)

        nmc_coin_settings = {"rpcport": 0, "rpcauth": "none"}
        nmc_coin_settings.update(REQUIRED_SETTINGS)
        ci_nmc = NMCInterface(nmc_coin_settings, "regtest")
        nmc_hrp = ci_nmc.chainparams_network()["hrp"]
        taproot = segwit_addr.encode_segwit_address(nmc_hrp, 1, bytes(range(32)))
        with self.assertRaises(ValueError):
            ci_nmc.getDestForAddress(taproot)

    def test_is_valid_address_checks_the_witness_version(self):
        ci = self.ci_btc()
        hrp = ci.chainparams_network()["hrp"]
        taproot = segwit_addr.encode_segwit_address(hrp, 1, bytes(range(32)))
        future = segwit_addr.encode_segwit_address(hrp, 2, bytes(range(32)))

        ci.rpc_wallet = lambda method, params=None: {"isvalid": True}
        assert ci.isValidAddress(taproot) is True
        assert ci.isValidAddress(future) is False

        ci._connection_type = "electrum"
        assert ci.isValidAddress(taproot) is True
        assert ci.isValidAddress(future) is False

        nmc_coin_settings = {"rpcport": 0, "rpcauth": "none"}
        nmc_coin_settings.update(REQUIRED_SETTINGS)
        ci_nmc = NMCInterface(nmc_coin_settings, "regtest")
        ci_nmc.rpc_wallet = lambda method, params=None: {"isvalid": True}
        nmc_hrp = ci_nmc.chainparams_network()["hrp"]
        nmc_taproot = segwit_addr.encode_segwit_address(nmc_hrp, 1, bytes(range(32)))
        assert ci_nmc.isValidAddress(nmc_taproot) is False

    def test_describe_tx_names_taproot_outputs(self):
        ci = self.ci_btc()
        hrp = ci.chainparams_network()["hrp"]
        program = bytes(range(32))
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(1, 0)))
        tx.vout.append(CTxOut(1000, CScript([CScriptOp.encode_op_n(1), program])))
        rv = ci._describeTxLocal(tx.serialize().hex())
        expected = segwit_addr.encode_segwit_address(hrp, 1, program)
        assert rv["vout"][0]["scriptPubKey"]["address"] == expected

    def test_spend_b_lock_pays_what_the_address_means(self):
        ci = self.ci_btc()
        hrp = ci.chainparams_network()["hrp"]
        pk = ci.getPubkey(ci.getNewRandomKey())
        redeem_script = CScript([pk, OP_CHECKSIG])
        program = bytes(range(32))
        cases = (
            (
                ci.encode_p2sh(redeem_script),
                CScript([OP_HASH160, hash160(redeem_script), OP_EQUAL]),
            ),
            (
                ci.pubkey_to_address(pk),
                CScript([OP_DUP, OP_HASH160, hash160(pk), OP_EQUALVERIFY, OP_CHECKSIG]),
            ),
            (
                segwit_addr.encode_segwit_address(hrp, 0, hash160(pk)),
                CScript([CScriptOp.encode_op_n(0), hash160(pk)]),
            ),
            (
                segwit_addr.encode_segwit_address(hrp, 1, program),
                CScript([CScriptOp.encode_op_n(1), program]),
            ),
        )
        published = []
        ci.getBLockTxo = lambda txid, vout, script_pk: (0, 100000)
        ci.getBLockSpendTxFee = lambda tx, fee: 1000
        ci.signTxWithKey = lambda tx, key, prev_amount=None: tx
        ci.publishTx = lambda tx: published.append(tx) or "00" * 32
        for address, expected in cases:
            ci.spendBLockTx(
                bytes(32), address, None, ci.getNewRandomKey(), 100000, 1000, 0
            )
            tx = ci.loadTx(published[-1])
            assert bytes(tx.vout[0].scriptPubKey) == bytes(expected)

    def test_swap_dest_is_a_key_hash_or_a_script_peers_accept(self):
        settings = {"rpcport": 0, "rpcauth": "none"}
        settings.update(REQUIRED_SETTINGS)
        ci = self.ci_btc()
        ci_part = PARTInterface(settings, "regtest")
        ci_doge = DOGEInterface(settings, "regtest")
        ci_nmc = NMCInterface(settings, "regtest")

        pk = ci.getPubkey(ci.getNewRandomKey())
        pkh = hash160(pk)
        redeem_script = CScript([pk, OP_CHECKSIG])
        program = bytes(range(32))
        p2pkh = CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])
        p2sh = CScript([OP_HASH160, hash160(redeem_script), OP_EQUAL])
        p2wpkh = CScript([CScriptOp.encode_op_n(0), pkh])
        p2wsh = CScript([CScriptOp.encode_op_n(0), program])
        p2tr = CScript([CScriptOp.encode_op_n(1), program])

        def segwit(ci, version, data):
            hrp = ci.chainparams_network()["hrp"]
            return segwit_addr.encode_segwit_address(hrp, version, data)

        accepted = (
            (ci, ci.pubkey_to_address(pk), p2pkh),
            (ci, ci.encode_p2sh(redeem_script), p2sh),
            (ci, segwit(ci, 0, pkh), pkh),
            (ci, segwit(ci, 0, program), p2wsh),
            (ci, segwit(ci, 1, program), p2tr),
            (ci_part, ci_part.pubkey_to_address(pk), pkh),
            (ci_part, ci_part.encode_p2sh(redeem_script), p2sh),
            (ci_part, segwit(ci_part, 0, pkh), p2wpkh),
            (ci_part, segwit(ci_part, 0, program), p2wsh),
            (ci_doge, ci_doge.pubkey_to_address(pk), pkh),
            (ci_doge, ci_doge.encode_p2sh(redeem_script), p2sh),
        )
        for coin_ci, address, expected in accepted:
            assert coin_ci.decodeSwapDest(address) == bytes(expected), address

        refused = (
            (ci, segwit(ci, 2, program)),
            (ci_part, segwit(ci_part, 1, program)),
            (ci_doge, segwit(ci_doge, 0, pkh)),
            (ci_nmc, segwit(ci_nmc, 1, program)),
        )
        for coin_ci, address in refused:
            with self.assertRaises(ValueError):
                coin_ci.decodeSwapDest(address)
        for coin_ci in (ci_part, ci_nmc):
            with self.assertRaises(ValueError):
                coin_ci.getDestForAddress(segwit(coin_ci, 1, program))

    def test_lock_spend_pays_every_swap_dest_a_coin_accepts(self):
        def ci_for(cls):
            settings = {"rpcport": 0, "rpcauth": "none"}
            settings.update(REQUIRED_SETTINGS)
            ci = cls(settings, "regtest")
            ci._log = BSXLogger("test")
            return ci

        hash20 = bytes(range(20))
        hash32 = bytes(range(32))
        dests = [hash20] + [
            bytes(script)
            for script in (
                CScript([OP_DUP, OP_HASH160, hash20, OP_EQUALVERIFY, OP_CHECKSIG]),
                CScript([OP_HASH160, hash20, OP_EQUAL]),
                CScript([CScriptOp.encode_op_n(0), hash20]),
                CScript([CScriptOp.encode_op_n(0), hash32]),
                CScript([CScriptOp.encode_op_n(1), hash32]),
                CScript([CScriptOp.encode_op_n(2), hash32]),
            )
        ]
        fee = 1000
        for cls in (
            BTCInterface,
            LTCInterface,
            NMCInterface,
            PARTInterface,
            DOGEInterface,
            DASHInterface,
            FIROInterface,
            PIVXInterface,
            BCHInterface,
        ):
            ci = ci_for(cls)
            if ci.coin_type() in coins_without_segwit + scriptless_coins:
                continue
            for dest in dests:
                if not BasicSwap.isValidSwapDest(None, ci, dest):
                    continue
                Kal = ci.getPubkey(ci.getNewRandomKey())
                Kaf = ci.getPubkey(ci.getNewRandomKey())
                lock_args = {}
                if cls is BCHInterface:
                    refund_script = ci.genScriptLockTxScript(
                        ci,
                        Kal,
                        Kaf,
                        mining_fee=fee,
                        out_1=ci.getScriptForPubkeyHash(bytes(range(20, 40))),
                        out_2=ci.getScriptForPubkeyHash(dest),
                        public_key=Kaf,
                        timelock=24,
                    )
                    lock_args = {
                        "mining_fee": fee,
                        "out_1": ci.getScriptForPubkeyHash(dest),
                        "out_2": ci.scriptToP2SH32LockingBytecode(refund_script),
                        "public_key": Kal,
                        "timelock": 48,
                    }
                script_lock = XmrSwapInterface().genScriptLockTxScript(
                    ci, Kal, Kaf, **lock_args
                )
                lock_bytes = ci.createSCLockTx(200000, script_lock)
                tx_lock = ci.loadTx(lock_bytes, allow_witness=False)
                tx_lock.vin.append(CTxIn(COutPoint(1, 0)))
                tx_lock_bytes = tx_lock.serialize()
                spend_tx = ci.createSCLockSpendTx(tx_lock_bytes, script_lock, dest, fee)
                pays = dest
                if ci.isValidAddressHash(dest):
                    pays = bytes(ci.getScriptForPubkeyHash(dest))
                assert bytes(ci.loadTx(spend_tx).vout[0].scriptPubKey) == pays, (
                    ci.coin_name(),
                    dest.hex(),
                )
                assert ci.verifySCLockSpendTx(
                    spend_tx, tx_lock_bytes, script_lock, dest, fee
                ), (ci.coin_name(), dest.hex())

    def test_bch_dest_for_address_follows_the_address_type(self):
        bch_coin_settings = {"rpcport": 0, "rpcauth": "none"}
        bch_coin_settings.update(REQUIRED_SETTINGS)
        ci = BCHInterface(bch_coin_settings, "regtest")
        hash20 = bytes(range(20))
        hash32 = bytes(range(32))
        p2pkh = Address("P2PKH-REGTEST", list(hash20)).cash_address()
        p2sh20 = Address("P2SH20-REGTEST", list(hash20)).cash_address()
        p2sh32 = Address("P2SH32-REGTEST", list(hash32)).cash_address()
        assert ci.getDestForAddress(p2pkh) == ci.getScriptForPubkeyHash(hash20)
        assert ci.getDestForAddress(p2sh20) == CScript([OP_HASH160, hash20, OP_EQUAL])
        assert ci.getDestForAddress(p2sh32) == CScript([OP_HASH256, hash32, OP_EQUAL])
        assert ci.decodeSwapDest(p2pkh) == hash20
        with self.assertRaises(ValueError):
            ci.decodeSwapDest(p2sh20)

    def test_dleag(self):
        ci = self.ci_xmr()

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

    def test_rate_tolerance_precision(self):
        scale = 8
        amount_from = make_int("0.001", scale)
        offer_rate = make_int("0.354185354480", scale, r=1)
        amount_to = int((amount_from * offer_rate) // (10**scale))
        bid_rate = make_int(amount_to / amount_from, r=1)

        rate_tolerance = max(1, offer_rate // 10000)
        rate_diff = abs(bid_rate - offer_rate)
        assert (
            rate_diff <= rate_tolerance
        ), f"Rate difference {rate_diff} exceeds tolerance {rate_tolerance}"

        test_cases = [
            ("0.001", "0.123456789"),
            ("0.5", "1.23456789"),
            ("0.00001", "999.99999999"),
        ]

        for amount_str, rate_str in test_cases:
            amount_from = make_int(amount_str, scale)
            offer_rate = make_int(rate_str, scale, r=1)
            amount_to = int((amount_from * offer_rate) // (10**scale))
            bid_rate = make_int(amount_to / amount_from, r=1)

            rate_tolerance = max(1, offer_rate // 10000)
            rate_diff = abs(bid_rate - offer_rate)

            assert rate_diff <= rate_tolerance, (
                f"Rate difference {rate_diff} exceeds tolerance {rate_tolerance} "
                f"for amount {amount_str} at rate {rate_str}"
            )

        large_offer_rate = make_int("1.0", scale)
        large_tolerance = max(1, large_offer_rate // 10000)
        bad_bid_rate = large_offer_rate + large_tolerance + 1
        rate_diff = abs(bad_bid_rate - large_offer_rate)
        assert (
            rate_diff > large_tolerance
        ), "Test setup error: difference should exceed tolerance"

    def test_rate_tolerance_helper_functions(self):
        class MockBasicSwap:
            def calculateRateTolerance(self, offer_rate: int) -> int:
                return max(1, offer_rate // 10000)

            def ratesMatch(self, rate1: int, rate2: int, offer_rate: int) -> bool:
                tolerance = self.calculateRateTolerance(offer_rate)
                return abs(rate1 - rate2) <= tolerance

        mock_swap = MockBasicSwap()

        assert mock_swap.calculateRateTolerance(100000000) == 10000
        assert mock_swap.calculateRateTolerance(1000000) == 100
        assert mock_swap.calculateRateTolerance(100) == 1
        assert mock_swap.calculateRateTolerance(50) == 1

        offer_rate = 100000000
        tolerance = 10000

        assert mock_swap.ratesMatch(offer_rate, offer_rate, offer_rate)
        assert mock_swap.ratesMatch(offer_rate, offer_rate + tolerance, offer_rate)
        assert mock_swap.ratesMatch(offer_rate, offer_rate - tolerance, offer_rate)
        assert mock_swap.ratesMatch(offer_rate + tolerance // 2, offer_rate, offer_rate)

        assert not mock_swap.ratesMatch(
            offer_rate, offer_rate + tolerance + 1, offer_rate
        )
        assert not mock_swap.ratesMatch(
            offer_rate, offer_rate - tolerance - 1, offer_rate
        )

        small_rate = 1000
        assert mock_swap.ratesMatch(small_rate, small_rate + 1, small_rate)
        assert not mock_swap.ratesMatch(small_rate, small_rate + 2, small_rate)

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

        ci_xmr = self.ci_xmr()
        ci_btc = self.ci_btc()

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

    def test_is_loopback_address(self):
        test_addresses = [
            ("localhost", True),
            ("127.0.0.1", True),
            ("127.5.5.5", True),
            ("::1", True),
            ("::ffff:127.0.0.1", True),
            ("10.0.0.4", False),
            ("192.168.1.5", False),
            ("0.0.0.0", False),
            ("::ffff:10.0.0.4", False),
            ("", False),
            ("example.com", False),
        ]
        for addr, is_loopback in test_addresses:
            assert is_loopback_address(addr) is is_loopback

    def test_is_url_scheme_allowed(self):
        test_urls = [
            ("http://example.com", True),
            ("https://example.com/path", True),
            ("file:///etc/passwd", False),
            ("ftp://example.com", False),
            ("gopher://example.com", False),
            ("/etc/passwd", False),
        ]
        for url, allowed in test_urls:
            assert is_url_scheme_allowed(url) is allowed

    def test_redact_secrets_for_logs(self):
        from basicswap.bin.run import redactArgs
        from basicswap.rpc import redact_url

        args = [
            "/bin/firod",
            "-datadir=/data/firo",
            "-hdseed=00ff",
            '--pass="pwd"',
            "--daemon-login",
            "user:pwd",
            "--trusted-daemon",
        ]
        assert redactArgs(args) == (
            "/bin/firod -datadir=/data/firo -hdseed=*** --pass=*** "
            "--daemon-login *** --trusted-daemon"
        )
        assert (
            redact_url("http://user:pwd@127.0.0.1:19792/wallet/w")
            == "http://127.0.0.1:19792/wallet/w"
        )
        assert redact_url("http://127.0.0.1:19792/") == "http://127.0.0.1:19792/"
        assert (
            redact_url("http://user:p/w?x#y@z@127.0.0.1:19792/")
            == "http://127.0.0.1:19792/"
        )

    def test_prepare_stop_timeout_hides_args(self):
        import subprocess
        from types import SimpleNamespace
        from basicswap.bin.prepare import finalise_daemon

        def wait(timeout):
            raise subprocess.TimeoutExpired(["firod", "-hdseed=00ff"], timeout)

        handle = SimpleNamespace(pid=1, send_signal=lambda sig: None, wait=wait)
        with self.assertLogs(level="INFO") as logs:
            finalise_daemon(SimpleNamespace(name="firod", handle=handle, files=[]))
        assert "timed out after 120 seconds" in logs.output[-1]
        assert not any("00ff" in line for line in logs.output)

    def test_is_public_url(self):
        # Non-http(s) schemes and internal hosts must be rejected; a public IP
        # literal (resolves to itself, no DNS needed) must be accepted.
        test_urls = [
            ("file:///etc/passwd", False),
            ("ftp://a", False),
            ("http://127.0.0.1", False),
            ("http://localhost", False),
            ("http://169.254.169.254/latest/meta-data/", False),
            ("http://10.0.0.5", False),
            ("http://192.168.1.1/", False),
            ("https://[::1]/", False),
            ("http://100.64.0.1", False),
            ("http://224.0.0.1", False),
            ("http://[ff02::1]/", False),
            ("http://[::ffff:10.0.0.5]/", False),
            ("http://[64:ff9b::a00:5]/", False),
            ("https://8.8.8.8", True),
            ("http://[64:ff9b::808:808]/", True),
        ]
        for url, is_public in test_urls:
            assert is_public_url(url) is is_public

    def test_read_url_limits(self):
        import http.server
        import time
        from types import SimpleNamespace
        from unittest import mock

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                try:
                    if self.path == "/slowheaders":
                        self.flush_headers()
                        for _ in range(20):
                            self.wfile.write(b"X-Slow: x\r\n")
                            self.wfile.flush()
                            time.sleep(0.1)
                    self.end_headers()
                    if self.path == "/big":
                        self.wfile.write(b"x" * 2048)
                        return
                    for _ in range(20):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}"
        app = SimpleNamespace(use_tor_proxy=False)
        try:
            with mock.patch("basicswap.base.READ_URL_MAX_BYTES", 2048):
                assert BaseApp.readURL(app, url + "/big") == b"x" * 2048
            with mock.patch("basicswap.base.READ_URL_MAX_BYTES", 1024):
                with self.assertRaises(ValueError):
                    BaseApp.readURL(app, url + "/big")
            for path in ("/slow", "/slowheaders"):
                with self.assertRaises(TimeoutError):
                    BaseApp.readURL(app, url + path, timeout=0.5)
        finally:
            server.shutdown()
            server.server_close()

    def test_read_url_pinned(self):
        import http.server
        import socket
        from types import SimpleNamespace
        from unittest import mock

        hosts = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hosts.append(self.headers["Host"])
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        real_getaddrinfo = socket.getaddrinfo

        def getaddrinfo(host, *args, **kwargs):
            if host == "rebind.example":
                host = "127.0.0.1"
            return real_getaddrinfo(host, *args, **kwargs)

        url = f"http://rebind.example:{port}/"
        app = SimpleNamespace(use_tor_proxy=False)
        try:
            with (
                mock.patch("socket.getaddrinfo", getaddrinfo),
                mock.patch("urllib.request.getproxies", return_value={}),
            ):
                with self.assertRaises(ValueError):
                    BaseApp.readURL(app, url, check_public=True)
                assert hosts == []
                with mock.patch(
                    "basicswap.base.is_public_ip_address", return_value=True
                ):
                    assert BaseApp.readURL(app, url, check_public=True) == b"ok"
                assert hosts == [f"rebind.example:{port}"]
            with mock.patch(
                "urllib.request.getproxies",
                return_value={"http": f"http://127.0.0.1:{port}"},
            ):
                assert (
                    BaseApp.readURL(app, "http://rebind.example/", check_public=True)
                    == b"ok"
                )
            assert hosts[-1] == "rebind.example"
        finally:
            server.shutdown()
            server.server_close()

    def test_normalize_allowed_hosts(self):
        from basicswap.util.network import normalize_allowed_hosts

        self.assertEqual(normalize_allowed_hosts("*"), ["*"])
        self.assertEqual(
            normalize_allowed_hosts("swap.example.com"), ["swap.example.com"]
        )
        self.assertEqual(normalize_allowed_hosts(""), [])
        self.assertEqual(normalize_allowed_hosts(None), [])
        self.assertEqual(
            normalize_allowed_hosts(["swap.example.com"]), ["swap.example.com"]
        )
        self.assertEqual(normalize_allowed_hosts([]), [])

    def test_is_origin_allowed(self):
        # (origin, html_host, html_port, allowed_hosts, expected)
        cases = [
            ("http://127.0.0.1:12700", "127.0.0.1", 12700, [], True),
            ("http://localhost:12700", "127.0.0.1", 12700, [], True),
            ("http://[::1]:12700", "127.0.0.1", 12700, [], True),
            # Another port on an allowed host is rejected.
            ("http://127.0.0.1:8080", "127.0.0.1", 12700, [], False),
            # Scheme is enforced for the defaults.
            ("https://127.0.0.1:12700", "127.0.0.1", 12700, [], False),
            ("http://evil.com", "127.0.0.1", 12700, [], False),
            ("null", "127.0.0.1", 12700, [], False),
            ("not a url", "127.0.0.1", 12700, [], False),
            # Bare configured host -> any scheme/port on that host.
            (
                "https://swap.example.com",
                "127.0.0.1",
                12700,
                ["swap.example.com"],
                True,
            ),
            (
                "https://swap.example.com:8443",
                "127.0.0.1",
                12700,
                ["swap.example.com"],
                True,
            ),
            (
                "http://swap.example.com:9000",
                "127.0.0.1",
                12700,
                ["swap.example.com"],
                True,
            ),
            # Full-origin entry -> exact scheme+host+port match.
            (
                "https://swap.example.com",
                "127.0.0.1",
                12700,
                ["https://swap.example.com"],
                True,
            ),
            (
                "http://swap.example.com:12700",
                "127.0.0.1",
                12700,
                ["https://swap.example.com"],
                False,
            ),
            (
                "https://swap.example.com:8443",
                "127.0.0.1",
                12700,
                ["https://swap.example.com"],
                False,
            ),
            # "host:port" entry -> that host on that port, any scheme.
            (
                "http://abc.onion:12700",
                "127.0.0.1",
                12700,
                ["abc.onion:12700"],
                True,
            ),
            (
                "https://abc.onion:12700",
                "127.0.0.1",
                12700,
                ["abc.onion:12700"],
                True,
            ),
            (
                "http://abc.onion:8080",
                "127.0.0.1",
                12700,
                ["abc.onion:12700"],
                False,
            ),
            ("http://abc.onion", "127.0.0.1", 12700, ["abc.onion:12700"], False),
            # A bracketed IPv6 entry keeps working, with and without a port.
            ("http://[fd00::1]:12700", "127.0.0.1", 12700, ["[fd00::1]"], True),
            (
                "http://[fd00::1]:12700",
                "127.0.0.1",
                12700,
                ["[fd00::1]:12700"],
                True,
            ),
            (
                "http://[fd00::1]:8080",
                "127.0.0.1",
                12700,
                ["[fd00::1]:12700"],
                False,
            ),
            # Unbracketed IPv6 has no port to split off.
            ("http://[fd00::1]:8080", "127.0.0.1", 12700, ["fd00::1"], True),
            # A malformed port matches nothing.
            ("http://abc.onion", "127.0.0.1", 12700, ["abc.onion:nope"], False),
            # "*" is ignored by the origin check.
            ("http://evil.com", "127.0.0.1", 12700, ["*"], False),
            (
                "https://swap.example.com",
                "127.0.0.1",
                12700,
                ["*", "https://swap.example.com"],
                True,
            ),
            # Concrete bind host on the html port; bind-all is never a valid host.
            ("http://192.168.1.50:12700", "192.168.1.50", 12700, [], True),
            ("http://192.168.1.50:12700", "0.0.0.0", 12700, [], False),
            # html_port supplied as a string.
            ("http://127.0.0.1:12700", "127.0.0.1", "12700", [], True),
        ]
        for origin, hh, hp, ah, expected in cases:
            assert is_origin_allowed(origin, hh, hp, ah) is expected, (
                origin,
                hh,
                hp,
                ah,
            )

    def test_is_same_origin_request(self):
        from basicswap.http_server import HttpHandler

        class SwapClient:
            def __init__(self, settings):
                self.settings = settings

        class Srv:
            def __init__(self, host_name, port_no, settings):
                self.host_name = host_name
                self.port_no = port_no
                self.swap_client = SwapClient(settings)

        class Stub:
            def __init__(
                self, headers, host_name="127.0.0.1", port_no=12700, settings=None
            ):
                self.headers = headers
                self.server = Srv(host_name, port_no, settings or {})

        check = HttpHandler.is_same_origin_request
        # A present Origin/Referer is validated as a full origin (scheme+host+port)
        # against the allowed origins; "*" does not disable this check.
        cases = [
            ({}, {}, True),  # header-less (tests/curl/API scripts) -> allowed
            ({"Origin": "http://127.0.0.1:12700"}, {}, True),
            ({"Origin": "http://localhost:12700"}, {}, True),
            ({"Origin": "http://127.0.0.1:8080"}, {}, False),  # other port blocked
            ({"Origin": "http://evil.com"}, {}, False),
            ({"Origin": "null"}, {}, False),
            ({"Referer": "http://127.0.0.1:12700/rpc"}, {}, True),
            ({"Referer": "http://evil.com/x"}, {}, False),
            # Bare configured host -> any scheme/port on that host.
            (
                {"Origin": "https://swap.example.com"},
                {"allowed_hosts": ["swap.example.com"]},
                True,
            ),
            ({"Origin": "https://swap.example.com"}, {}, False),
            # Full-origin entry -> exact match.
            (
                {"Origin": "https://swap.example.com"},
                {"allowed_hosts": ["https://swap.example.com"]},
                True,
            ),
            (
                {"Origin": "http://swap.example.com:12700"},
                {"allowed_hosts": ["https://swap.example.com"]},
                False,
            ),
            # "*" no longer bypasses the origin check.
            (
                {"Origin": "http://evil.com", "Host": "evil.com"},
                {"allowed_hosts": ["*"], "client_auth_hash": "x"},
                False,
            ),
        ]
        for headers, settings, expected in cases:
            assert check(Stub(headers, settings=settings)) is expected, (
                headers,
                settings,
            )

    def test_ws_origin_allowed(self):
        # Cross-site WebSocket hijacking guard: the handshake Origin is validated
        # against the allowlist (verify-when-present). Headers use lowercased keys
        # as the contrib websocket server provides them.
        class Stub:
            def __init__(self, settings):
                self.settings = settings

        check = BasicSwap._ws_origin_allowed
        # The Origin is the html page that opened the socket, so it is matched
        # against htmlhost/htmlport (not the WebSocket port).
        loopback = {"htmlhost": "127.0.0.1", "htmlport": 12700}
        cases = [
            ({}, {}, True),  # no Origin (bots/scripts) -> allowed
            ({"origin": "http://127.0.0.1:12700"}, loopback, True),
            ({"origin": "http://localhost:12700"}, loopback, True),
            ({"origin": "http://127.0.0.1:8080"}, loopback, False),  # other port
            ({"origin": "http://evil.com"}, loopback, False),
            ({"origin": "null"}, loopback, False),
            (
                {"origin": "https://swap.example.com"},
                {"allowed_hosts": ["swap.example.com"]},
                True,
            ),
            ({"origin": "https://swap.example.com"}, {}, False),
            # Bind host (htmlhost) is accepted on the html port without an entry.
            (
                {"origin": "http://swap.example.com:12700"},
                {"htmlhost": "swap.example.com", "htmlport": 12700},
                True,
            ),
            # "*" does NOT disable the WS origin check.
            (
                {"origin": "http://evil.com"},
                {"allowed_hosts": ["*"], "htmlhost": "127.0.0.1", "htmlport": 12700},
                False,
            ),
        ]
        for headers, settings, expected in cases:
            assert check(Stub(settings), headers) is expected, (headers, settings)

    def test_ws_handshake_bad_request(self):
        # Anything that is not a websocket handshake (port scans, a client that
        # closes before sending, a TLS hello) must close the connection instead
        # of raising out of the request handler.
        import io
        from basicswap.contrib.websocket_server.websocket_server import (
            WebSocketHandler,
        )

        class Connection:
            def settimeout(self, timeout):
                pass

        class Server:
            _handshake_lock = threading.Lock()
            _pending_handshakes = 0
            max_pending_handshakes = None

        def make_handler(data: bytes):
            handler = WebSocketHandler.__new__(WebSocketHandler)
            handler._handshake_timer = threading.Timer(1000, lambda: None)
            handler.rfile = io.BytesIO(data)
            handler.connection = Connection()
            handler.server = Server()
            handler.keep_alive = True
            handler.handshake_done = False
            handler.valid_client = False
            return handler

        for data in (
            b"",
            b"\r\n",
            b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03",
            b"POST / HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
        ):
            handler = make_handler(data)
            assert handler.read_http_headers() is None
            handler.handshake()
            assert handler.keep_alive is False

        # A plain GET without the upgrade header is parsed, then rejected.
        handler = make_handler(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nbroken\r\n\r\n")
        assert handler.read_http_headers() == {"host": "127.0.0.1"}
        handler = make_handler(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        handler.handshake()
        assert handler.keep_alive is False

    def test_ws_handshake_limits(self):
        import socket
        import time
        from unittest import mock
        from basicswap.contrib.websocket_server import websocket_server as ws

        def handler_for(data):
            sock, peer = socket.socketpair()
            sock.settimeout(3)
            handler = ws.WebSocketHandler.__new__(ws.WebSocketHandler)
            handler.request = handler.connection = sock
            handler.rfile = sock.makefile("rb")
            handler.timeout = 1000
            handler._start_handshake_timer(sock)
            peer.sendall(data)
            return handler, peer

        request = b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\r\n"
        handler, peer = handler_for(request)
        assert handler.read_http_headers() == {
            "host": "localhost",
            "upgrade": "websocket",
        }
        peer.close()

        for data in (
            b"GET / HTTP/1.1\r\n" + b"X-Repeat: y\r\n" * 200 + b"\r\n",
            b"GET / HTTP/1.1\r\n" + b"no colon\r\n" * 200 + b"\r\n",
            b"GET / HTTP/1.1\r\n" + (b"X: " + b"y" * 4000 + b"\r\n") * 20 + b"\r\n",
        ):
            handler, peer = handler_for(data)
            assert handler.read_http_headers() is None
            peer.close()

        with mock.patch.object(ws, "HANDSHAKE_TIMEOUT", 0.2):
            handler, peer = handler_for(b"GET / HTTP/1.1\r\nHost: localhost\r\nX: ")
            stop = threading.Event()

            def trickle():
                while not stop.is_set():
                    try:
                        peer.sendall(b"y")
                    except OSError:
                        return
                    time.sleep(0.05)

            threading.Thread(target=trickle, daemon=True).start()
            start = time.monotonic()
            assert handler.read_http_headers() is None
            assert time.monotonic() - start < 2
            stop.set()
            peer.close()

        class Srv:
            _handshake_lock = threading.Lock()
            _pending_handshakes = ws.MAX_PENDING_HANDSHAKES
            max_pending_handshakes = ws.MAX_PENDING_HANDSHAKES

        handler, peer = handler_for(request)
        handler.server = Srv()
        handler.keep_alive = True
        handler.handshake()
        assert handler.keep_alive is False
        assert Srv._pending_handshakes == ws.MAX_PENDING_HANDSHAKES
        assert handler.rfile.readline() == b"GET / HTTP/1.1\r\n"
        peer.close()

        checked = []

        class Uncapped(Srv):
            max_pending_handshakes = None

            def origin_check(self, headers):
                checked.append(headers)
                return True

        handler, peer = handler_for(request)
        handler.server = Uncapped()
        handler.keep_alive = True
        handler.handshake()
        assert checked == [{"host": "localhost", "upgrade": "websocket"}]
        assert Uncapped._pending_handshakes == ws.MAX_PENDING_HANDSHAKES
        peer.close()

    def test_ws_tls_handshake_timeout(self):
        import socket
        import ssl
        from unittest import mock
        from basicswap.contrib.websocket_server import websocket_server as ws

        timeouts = []

        class Context:
            def __init__(self, protocol):
                pass

            def load_cert_chain(self, cert, key):
                pass

            def wrap_socket(self, sock, server_side):
                timeouts.append(sock.gettimeout())
                raise ssl.SSLError("handshake timed out")

        class Srv:
            key = "key.pem"
            cert = "cert.pem"

        sock, peer = socket.socketpair()
        try:
            with mock.patch.object(ws.ssl, "SSLContext", Context):
                ws.WebSocketHandler(sock, ("127.0.0.1", 1), Srv())
            assert timeouts == [ws.HANDSHAKE_TIMEOUT]
        finally:
            sock.close()
            peer.close()

    def test_http_post_limits(self):
        import base64
        from unittest import mock
        from basicswap import http_server
        from basicswap.http_server import HttpHandler

        class SwapClient:
            log = logging

            def __init__(self, settings):
                self.settings = settings

        class Srv:
            host_name = "127.0.0.1"
            port_no = 12700

            def __init__(self, settings):
                self.swap_client = SwapClient(settings)
                self.session_lock = threading.Lock()
                self.active_sessions = {}

        class Connection:
            def settimeout(self, timeout):
                pass

        class Stub(HttpHandler):
            def __init__(self, headers, body, settings):
                self.headers = {"Host": "127.0.0.1:12700", **headers}
                self.connection = Connection()
                self.rfile = BytesIO(body)
                self.wfile = BytesIO()
                self.path = "/json/coins"
                self.server = Srv(settings)
                self.errors = []
                self.handled = None

            def send_error(self, code, message=None, explain=None):
                self.errors.append(code)

            def handle_http(self, status_code, path, post_string="", is_json=False):
                self.handled = post_string
                return b""

        def post(headers, body=b"", settings=None):
            handler = Stub(headers, body, settings or {})
            handler.do_POST()
            return handler

        password = {"client_auth_hash": rfc2440_hash_password("password")}
        handler = post({"Content-Length": "5"}, b"hello")
        assert handler.handled == b"hello" and handler.errors == []
        handler = post({"Content-Length": "10"}, b"hello")
        assert handler.errors == [400] and handler.handled is None
        assert post({}).handled == b""
        for value in ("-1", "abc"):
            handler = post({"Content-Length": value}, b"hello")
            assert handler.errors == [400] and handler.handled is None, value
        with mock.patch.object(http_server, "MAX_POST_BYTES", 10):
            handler = post({"Content-Length": "11"}, b"x" * 11)
            assert handler.errors == [413] and handler.handled is None

        size = http_server.MAX_REFUSED_POST_BYTES + 1
        body = b"x" * size
        handler = post({"Content-Length": str(size)}, body, password)
        assert handler.errors == [413] and handler.handled is None
        for creds in ("x", base64.b64encode(b"user:wrong").decode()):
            handler = post(
                {"Content-Length": str(size), "Authorization": f"Basic {creds}"},
                body,
                password,
            )
            assert handler.errors == [413] and handler.handled is None, creds
        creds = base64.b64encode(b"user:password").decode()
        handler = post(
            {"Content-Length": str(size), "Authorization": f"Basic {creds}"},
            body,
            password,
        )
        assert handler.handled == body
        assert post({"Content-Length": "5"}, b"hello", password).handled == b"hello"
        handler = post({"Content-Length": str(size), "Host": "evil.example"}, body)
        assert handler.errors == [413] and handler.handled is None

    def test_http_post_body_deadline(self):
        import socket
        import time
        from unittest import mock
        from basicswap import http_server
        from basicswap.http_server import HttpHandler

        sock, peer = socket.socketpair()
        sock.settimeout(3)

        class SwapClient:
            settings = {}

        class Srv:
            host_name = "127.0.0.1"
            port_no = 12700
            swap_client = SwapClient()

        class Stub(HttpHandler):
            def __init__(self):
                self.headers = {"Host": "127.0.0.1:12700", "Content-Length": "100"}
                self.connection = sock
                self.rfile = sock.makefile("rb")
                self.server = Srv()
                self.errors = []
                self.handled = None

            def send_error(self, code, message=None, explain=None):
                self.errors.append(code)

            def handle_http(self, status_code, path, post_string="", is_json=False):
                self.handled = post_string
                return b""

        stop = threading.Event()

        def trickle():
            while not stop.is_set():
                try:
                    peer.sendall(b"x")
                except OSError:
                    return
                time.sleep(0.05)

        threading.Thread(target=trickle, daemon=True).start()
        try:
            with mock.patch.object(http_server, "POST_BODY_TIMEOUT", 0.3):
                handler = Stub()
                start = time.monotonic()
                handler.do_POST()
            assert handler.errors == [408] and handler.handled is None
            assert time.monotonic() - start < 2
        finally:
            stop.set()
            peer.close()
            sock.close()

    def test_http_handler_cap(self):
        import time
        from unittest import mock
        from basicswap.http_server import HttpThread

        class SwapClient:
            debug = False

        server = HttpThread("127.0.0.1", 0, False, SwapClient())
        try:
            server._handler_slots = threading.BoundedSemaphore(1)
            finished = threading.Event()
            with (
                mock.patch.object(
                    server, "finish_request", side_effect=lambda *a: finished.set()
                ),
                mock.patch.object(server, "shutdown_request") as shutdown,
            ):
                assert server._handler_slots.acquire(blocking=False)
                server.process_request("request", ("127.0.0.1", 1))
                assert not finished.wait(1)
                shutdown.assert_called_once_with("request")

                server._handler_slots.release()
                server.process_request("request", ("127.0.0.1", 1))
                assert finished.wait(5)
                for _ in range(50):
                    if server._handler_slots.acquire(blocking=False):
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("handler slot not released")
        finally:
            server.server_close()

    def test_is_allowed_host(self):
        from basicswap.http_server import HttpHandler

        class SwapClient:
            def __init__(self, settings):
                self.settings = settings

        class Srv:
            def __init__(self, host_name, settings):
                self.host_name = host_name
                self.swap_client = SwapClient(settings)

        class Stub(HttpHandler):
            def __init__(self, headers, host_name="127.0.0.1", settings=None):
                self.headers = headers
                self.server = Srv(host_name, settings or {})

        check = HttpHandler.is_allowed_host
        # (headers, host_name, settings, expected)
        cases = [
            ({"Host": "127.0.0.1:12700"}, "127.0.0.1", {}, True),
            ({"Host": "localhost:12700"}, "127.0.0.1", {}, True),
            ({"Host": "[::1]:12700"}, "127.0.0.1", {}, True),
            ({"Host": "evil.com"}, "127.0.0.1", {}, False),  # rebinding shape
            ({}, "127.0.0.1", {}, False),  # missing Host -> fail closed
            (
                {"Host": "swap.example.com"},
                "0.0.0.0",
                {"allowed_hosts": ["swap.example.com"]},
                True,
            ),
            (
                {"Host": "swap.example.com"},
                "0.0.0.0",
                {"allowed_hosts": ["https://swap.example.com"]},
                True,  # scheme-form entry still matches the schemeless Host
            ),
            (
                {"Host": "swap.example.com:8443"},
                "0.0.0.0",
                {"allowed_hosts": ["https://swap.example.com:8443"]},
                True,  # hostname extracted from a scheme+port entry
            ),
            (
                {"Host": "swap.example.com"},
                "0.0.0.0",
                {},
                False,  # not configured
            ),
            (
                {"Host": "0.0.0.0:12700"},
                "0.0.0.0",
                {},
                False,  # bind-all is never a valid Host
            ),
            (
                {"Host": "192.168.1.50:12700"},
                "0.0.0.0",
                {"allowed_hosts": ["192.168.1.50"]},
                True,
            ),
            (
                {"Host": "anything.example"},
                "0.0.0.0",
                {"allowed_hosts": ["*"]},
                False,  # "*" alone does not disable — client_auth_hash required
            ),
            (
                {"Host": "anything.example"},
                "0.0.0.0",
                {"allowed_hosts": ["*"], "client_auth_hash": "x"},
                True,  # opt-out takes effect only with auth configured
            ),
            (
                {},
                "127.0.0.1",
                {"allowed_hosts": ["*"], "client_auth_hash": "x"},
                True,  # opt-out with auth, no Host
            ),
            (
                {"Host": "anything.example"},
                "0.0.0.0",
                {"allowed_hosts": ["*"], "unsafe_allow_any_host_without_auth": True},
                True,  # explicit unsafe override, no auth required
            ),
            (
                {"Host": "anything.example"},
                "0.0.0.0",
                {"unsafe_allow_any_host_without_auth": True},
                False,  # override alone does nothing without "*"
            ),
        ]
        for headers, host_name, settings, expected in cases:
            assert check(Stub(headers, host_name, settings)) is expected, (
                headers,
                host_name,
                settings,
            )

    def test_amm_token_scope(self):
        import ast
        import base64
        from unittest import mock
        from basicswap.http_server import HttpHandler, amm_request_allowed

        script = os.path.join(
            os.path.dirname(__file__), "..", "..", "scripts", "createoffers.py"
        )
        with open(script) as fp:
            tree = ast.parse(fp.read())
        requests = set()
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("read_json_api", "read_json_api_wallet")
            ):
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant):
                path = arg.value
            elif isinstance(arg, ast.JoinedStr):
                path = "".join(
                    v.value if isinstance(v, ast.Constant) else "x" for v in arg.values
                )
            else:
                path = arg.func.value.value.replace("{}", "x")
            requests.add(("POST" if len(node.args) > 1 else "GET", path))
        assert len(requests) > 10
        for method, path in requests:
            assert amm_request_allowed(method, ["", "json"] + path.split("/")), (
                method,
                path,
            )

        class SwapClient:
            def __init__(self):
                self.settings = {"client_auth_hash": rfc2440_hash_password("password")}
                self._amm_api_token = "amm-token"
                self.log = logging

        class Srv:
            host_name = "127.0.0.1"
            port_no = 12700

            def __init__(self):
                self.swap_client = SwapClient()

        class Stub(HttpHandler):
            def __init__(self, command, path, password):
                creds = base64.b64encode(f"amm:{password}".encode()).decode()
                self.command = command
                self.path = path
                self.headers = {
                    "Host": "127.0.0.1:12700",
                    "Authorization": "Basic " + creds,
                }
                self.server = Srv()
                self.status = None

            def putHeaders(self, status_code, content_type, extra_headers=None):
                self.status = status_code

        def request(command, path, password="amm-token"):
            handler = Stub(command, path, password)
            post_string = b"{}" if command == "POST" else ""
            response = handler.handle_http(200, path, post_string, True)
            return handler.status, response

        with mock.patch(
            "basicswap.http_server.js_url_to_function",
            return_value=lambda *args: b"dispatched",
        ):
            assert request("GET", "/json/coins") == (200, b"dispatched")
            assert request("POST", "/json/offers/new") == (200, b"dispatched")
            for command, path in (
                ("POST", "/json/wallets/btc/withdraw"),
                ("POST", "/json/getcoinseed"),
                ("POST", "/json/identities/x"),
                ("POST", "/json/bids/x"),
                ("GET", "/json/wallettransactions/btc"),
                ("POST", "/rpc"),
                ("GET", "/settings"),
            ):
                status, response = request(command, path)
                assert status == 403, (command, path)
                assert b"AMM token" in response
            assert request("POST", "/json/wallets/btc/withdraw", "password") == (
                200,
                b"dispatched",
            )

    def test_checkform_csrf_token(self):
        from basicswap.http_server import HttpHandler

        class Srv:
            session_tokens = {"csrf": "the-server-token"}
            used_form_ids = {}
            form_id_lock = threading.Lock()

        class Stub:
            server = Srv()

        check = HttpHandler.checkForm
        msgs = []
        # Correct token -> returns parsed form data.
        fd = check(Stub(), b"formid=the-server-token.n1&x=1", "rpc", msgs)
        assert fd is not None and b"x" in fd
        assert check(Stub(), b"formid=the-server-token.n1&x=1", "rpc", msgs) is None
        assert "Prevented double submit for form rpc." in msgs
        assert check(Stub(), b"formid=the-server-token.n2&x=1", "rpc", msgs)
        # Wrong / missing / empty -> rejected (None).
        assert check(Stub(), b"formid=wrong&x=1", "rpc", msgs) is None
        assert check(Stub(), b"formid=the-server-token&x=1", "rpc", msgs) is None
        assert check(Stub(), b"x=1", "rpc", msgs) is None
        assert check(Stub(), "", "rpc", msgs) is None

    def test_json_smsgaddresses_requires_post(self):
        from basicswap.http_server import json_requires_post

        assert not json_requires_post(["", "json", "smsgaddresses"])
        assert not json_requires_post(["", "json", "smsgaddresses", ""])
        for mode in ("new", "add", "edit", "disableall"):
            assert json_requires_post(["", "json", "smsgaddresses", mode]), mode

    def test_tokens_not_rendered_before_login(self):
        from unittest import mock
        from basicswap.http_server import HttpHandler

        class SwapClient:
            ws_server = None
            debug = False
            debug_ui = False
            use_tor_proxy = False
            _show_notifications = False

            def __init__(self, settings):
                self.settings = settings

            def getSummary(self):
                from collections import defaultdict

                return defaultdict(int)

            def getLockedState(self):
                return True, False

        class Srv:
            title = "BasicSwap"

            def __init__(self, settings):
                self.swap_client = SwapClient(settings)
                self.session_lock = threading.Lock()
                self.msg_id_lock = threading.Lock()
                self.msg_id_counter = 0
                self.session_tokens = {"csrf": "csrf-token", "shutdown": "old-token"}

        class Stub(HttpHandler):
            def __init__(self, settings, basic_auth_ok=False):
                self.headers = {}
                self.path = "/static/missing"
                self.server = Srv(settings)
                self._basic_auth_ok = basic_auth_ok

            def putHeaders(self, status_code, content_type, extra_headers=None):
                pass

        def render_404(handler):
            rendered = {}
            get_template = env.get_template

            class Capture:
                def __init__(self, template):
                    self.template = template

                def render(self, **kwargs):
                    rendered.update(kwargs)
                    return self.template.render(**kwargs)

            def capture_404(name, *args, **kwargs):
                template = get_template(name, *args, **kwargs)
                return Capture(template) if name == "404.html" else template

            with mock.patch.object(env, "get_template", side_effect=capture_404):
                page = handler.page_404(["", "static", "missing"]).decode()
            return page, rendered

        from basicswap.http_server import env

        password = {"client_auth_hash": rfc2440_hash_password("password")}
        handler = Stub(password)
        page, rendered = render_404(handler)
        assert rendered["form_id"] == ""
        assert "old-token" not in page
        assert handler.server.session_tokens["shutdown"] == "old-token"

        authenticated = Stub(password)
        for handler in (Stub(password, basic_auth_ok=True), Stub({}), authenticated):
            with mock.patch.object(
                HttpHandler,
                "is_authenticated",
                return_value=handler is authenticated,
            ):
                page, rendered = render_404(handler)
            shutdown_token = handler.server.session_tokens["shutdown"]
            assert rendered["form_id"].startswith("csrf-token.")
            assert shutdown_token != "old-token"
            assert f"/shutdown/{shutdown_token}" in page

    def test_html_responses_deny_framing(self):
        from basicswap.http_server import HttpHandler

        class Srv:
            allow_cors = False

        class Stub(HttpHandler):
            def __init__(self):
                self.server = Srv()
                self.sent = []

            def send_response(self, code, message=None):
                pass

            def send_header(self, keyword, value):
                self.sent.append((keyword, value))

            def end_headers(self):
                pass

        handler = Stub()
        handler.putHeaders(200, "text/html")
        assert ("X-Frame-Options", "DENY") in handler.sent
        assert ("Content-Security-Policy", "frame-ancestors 'none'") in handler.sent

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

    def test_electrum_discover_drops_invalid_peer_hosts(self):
        import json
        from basicswap.interface.electrumx import is_valid_peer_host
        from basicswap.js_server import js_electrum_discover

        onion = "x" * 56 + ".onion"
        for host, valid in (
            ("electrum.example.com", True),
            ("1.2.3.4", True),
            ("2001:db8::1", True),
            (onion, True),
            ("", False),
            (None, False),
            ("a b", False),
            ('"><img src=x onerror=alert(1)>', False),
            ("a" * 254, False),
        ):
            assert is_valid_peer_host(host) is valid, host

        peers = [
            {"host": "electrum.example.com", "port": 50002, "is_onion": False},
            {"host": "<img src=x onerror=alert(1)>", "port": 50002, "is_onion": False},
            {"host": onion, "port": 50002, "is_onion": True},
        ]

        class Server:
            def get_current_server_info(self):
                return {"host": "electrum.example.org", "port": 50002}

            def discover_peers(self):
                return [dict(peer) for peer in peers]

        class Backend:
            _server = Server()

        class CI:
            _connection_type = "electrum"

            def getBackend(self):
                return Backend()

        class SwapClient:
            def ci(self, coin_type):
                return CI()

        class Srv:
            swap_client = SwapClient()

        class Handler:
            server = Srv()

        rv = json.loads(
            js_electrum_discover(Handler(), None, b'{"coin": "bitcoin"}', True)
        )
        assert [s["host"] for s in rv["clearnet_servers"]] == ["electrum.example.com"]
        assert [s["host"] for s in rv["onion_servers"]] == [onion]

    def test_oracle_rates_validated(self):
        from unittest import mock
        from basicswap.basicswap import BasicSwap
        from basicswap.oracles import filterValidRates, oracle_fetchers

        rates = {
            1: (100.5, 1000, -2.5),
            2: (float("nan"), 1, 1),
            3: ("inf", 1, 1),
            4: ("abc", 1, 1),
            5: (0, 1, 1),
            6: (-1, 1, 1),
            7: (True, 1, 1),
            8: ("12.5", "nan", "x"),
            9: (None, 1, 1),
        }
        assert filterValidRates(rates) == {
            1: (100.5, 1000.0, -2.5),
            8: (12.5, None, None),
        }

        class Cursor:
            rowcount = 1

            def __init__(self):
                self.rates = []

            def execute(self, query, params=None):
                if params and "rate" in params:
                    self.rates.append(params["currency_from"])

        class Stub:
            _price_cache_lock = threading.Lock()

            def __init__(self):
                self._price_cache = {}
                self._volume_cache = {}
                self.cursor = Cursor()

            def openDB(self):
                return self.cursor

            def commitDB(self):
                pass

            def closeDB(self, cursor, commit=True):
                pass

        stub = Stub()
        with mock.patch.dict(
            oracle_fetchers, {"test_oracle": lambda *args: dict(rates)}
        ):
            fetched = BasicSwap._fetchPricesAndVolumeForSource(
                stub, list(rates), "test_oracle", 1
            )
        assert fetched == {1, 8}
        assert sorted(key[0] for key in stub._price_cache) == [1, 8]
        assert stub.cursor.rates == [1, 8]

    def test_base58(self):
        k = bytes.fromhex(
            "0b4c6e34c21b910f92c7985a8093de526f5f8677a112a8c672d1098139b70e0f"
        )
        K = ed25519_get_pubkey(k)

        addr: str = xmr_encode_address(K, K)
        assert addr.startswith("4")
        Ks, Kv = xmr_decode_address(addr)
        assert Ks == K
        assert Kv == K

        addr = xmr_encode_address(K, K, 4146)
        assert addr.startswith("Wo")
        Ks, Kv = xmr_decode_address(addr, 4146)
        assert Ks == K
        assert Kv == K

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

    def test_extkey_set_seed(self):
        # BIP32 test vector 1, without the version prefix.
        ek = ExtKeyPair()
        ek.set_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        assert (
            ek.encode_v().hex()
            == "000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb4"
            "2ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        )

        # A master key of zero or above the group order is invalid, and BIP32 says
        # to discard the seed rather than clamp the key. No reachable seed hashes
        # to one, so the hmac output has to be driven directly to get there.
        import basicswap.util.extkey as extkey_module

        real_hmac_sha512 = extkey_module.hmac_sha512
        try:
            for bad_key in (
                bytes(32),
                bytes.fromhex(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
                ),
            ):
                extkey_module.hmac_sha512 = lambda k, d, key=bad_key: key + bytes(32)
                self.assertRaises(ValueError, ExtKeyPair().set_seed, b"seed")
        finally:
            extkey_module.hmac_sha512 = real_hmac_sha512

        # The patch must not have leaked into the module.
        ek_after = ExtKeyPair()
        ek_after.set_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
        assert ek_after.encode_v() == ek.encode_v()

    def test_mnemonic(self):
        entropy0: bytes = Mnemonic("english").to_entropy(mnemonics[0])
        assert entropy0.hex() == "0002207e9b744ea2d7ab41702f31f000"
        mnemonic_recovered: str = Mnemonic("english").to_mnemonic(entropy0)
        assert mnemonic_recovered == mnemonics[0]

    def test_db(self):
        db_test = DBMethods()
        db_test.sqlite_file = ":memory:"
        db_test.mxDB = threading.RLock()
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
            ki.note = "note1"
            try:
                db_test.add(ki, cursor, upsert=False)
            except Exception as e:
                assert "UNIQUE constraint failed" in str(e)
            else:
                raise ValueError("Should have errored.")
            db_test.add(ki, cursor, upsert=True)

            # Test columns list
            ki_test = db_test.queryOne(
                KnownIdentity,
                cursor,
                {"address": "test1"},
                columns_list=[
                    "label",
                ],
            )
            assert ki_test.label == "test1"
            assert ki_test.address is None

            # Test updating partial row
            ki_test.label = "test2"
            ki_test.record_id = 1
            db_test.add(
                ki_test,
                cursor,
                upsert=True,
                columns_list=[
                    "record_id",
                    "label",
                ],
            )
            ki_test = db_test.queryOne(KnownIdentity, cursor, {"address": "test1"})
            assert ki_test.record_id == 1
            assert ki_test.address == "test1"
            assert ki_test.label == "test2"
            assert ki_test.note == "note1"

            ki_test.note = "test2"
            ki_test.label = "test3"

            db_test.updateDB(
                ki_test,
                cursor,
                ["record_id"],
                columns_list=[
                    "label",
                ],
            )
            ki_test = db_test.queryOne(KnownIdentity, cursor, {"address": "test1"})
            assert ki_test.record_id == 1
            assert ki_test.address == "test1"
            assert ki_test.label == "test3"
            assert ki_test.note == "note1"

            # Test partially initialised object
            ki_test_p = KnownIdentity(
                _init_all_columns=False, record_id=1, label="test4"
            )
            db_test.add(ki_test_p, cursor, upsert=True)
            ki_test = db_test.queryOne(KnownIdentity, cursor, {"address": "test1"})
            assert ki_test.record_id == 1
            assert ki_test.address == "test1"
            assert ki_test.label == "test4"
            assert ki_test.note == "note1"

        finally:
            db_test.closeDB(cursor)

    def test_connect_request_limits(self):
        from types import SimpleNamespace
        from basicswap.network.bsx_network import BSXNetwork

        now: int = 1800000000
        sc = SimpleNamespace(
            getTime=lambda: now,
            _connect_request_times={},
            _sender_connect_request_times={},
            _max_connect_requests_per_hour=3,
            _max_connect_requests_per_sender_per_hour=2,
        )

        def check(addr_from: str, new_route: bool = True) -> None:
            BSXNetwork.checkConnectRequestRateLimit(sc, 1, addr_from, new_route)

        check("addr_a")
        check("addr_a")
        with self.assertRaisesRegex(ValueError, "exceeded for sender"):
            check("addr_a")
        check("addr_b")
        with self.assertRaisesRegex(ValueError, "rate limit exceeded$"):
            check("addr_c")
        check("addr_c", new_route=False)

        now += 3600
        check("addr_a")
        assert list(sc._sender_connect_request_times) == [(1, "addr_a")]

    def test_simplex_connect_request_finds_existing_route(self):
        from types import SimpleNamespace
        from unittest import mock
        from basicswap.db import DirectMessageRoute
        from basicswap.network.bsx_network import BSXNetwork
        from basicswap.network.simplex.routes import processSimplexConnectRequest

        sc = DBMethods()
        sc.sqlite_file = ":memory:"
        sc.mxDB = threading.RLock()
        sc.log = BSXLogger("test")
        sc.getMessageRoute = lambda *args, **kwargs: BSXNetwork.getMessageRoute(
            sc, *args, **kwargs
        )
        net_i = mock.MagicMock()
        offer = SimpleNamespace(
            offer_id=secrets.token_bytes(28), addr_from="offer_addr"
        )
        cursor = sc.openDB()
        try:
            create_db_(sc._db_con, logger)
            sc.add(
                DirectMessageRoute(
                    active_ind=1,
                    network_id=2,
                    smsg_addr_local="offer_addr",
                    smsg_addr_remote="bid_addr",
                    created_at=0,
                ),
                cursor,
            )
            req_data = {"bsx_address": "bid_addr", "connection_req": "simplex:/x"}
            with self.assertRaisesRegex(ValueError, "already exists"):
                processSimplexConnectRequest(sc, net_i, req_data, offer, cursor)
            net_i.send_command.assert_not_called()
        finally:
            sc.closeDB(cursor)

    def test_simplex_receive_queue_bounded(self):
        from unittest import mock
        from basicswap.network.simplex import simplex

        with mock.patch.object(simplex, "MAX_RECV_QUEUE_SIZE", 2):
            ws_thread = simplex.WebSocketThread("ws://127.0.0.1:1", logger=logger)
        for i in range(3):
            ws_thread.on_message(None, '{"resp": {}}')
        ws_thread.on_message(None, '{"corrId": "1"}')
        assert ws_thread.recv_queue.qsize() == 2
        assert ws_thread.cmd_recv_queue.qsize() == 1
        assert ws_thread.num_messages_dropped == 1

    def test_simplex_frame_limits_installed(self):
        from types import SimpleNamespace
        import websocket
        from basicswap.network.nostr.client import BoundedFrameBuffer
        from basicswap.network.simplex import simplex

        ws_thread = simplex.WebSocketThread("ws://127.0.0.1:1", logger=logger)
        ws_sock = websocket.WebSocket()
        ws_thread.on_open(SimpleNamespace(sock=ws_sock))
        assert isinstance(ws_sock.frame_buffer, BoundedFrameBuffer)
        assert ws_sock.frame_buffer.max_frame_len == simplex.MAX_EVENT_LEN

    def test_portal_smsg_difficulty_bound(self):
        from basicswap.basicswap_util import MessageNetworks
        from basicswap.messages_npb import MessagePortalOffer
        from basicswap.network.bsx_network import BSXNetwork

        sc = DBMethods()
        sc.sqlite_file = ":memory:"
        sc.mxDB = threading.RLock()
        sc.log = BSXLogger("test")
        now: int = 1800000000
        sc.getTime = lambda: now
        sc.getSmsgMsgBytes = lambda msg: msg["payload"]
        sc.getActiveNetwork = lambda network_id: {"bridged": [{"type": "simplex"}]}
        sc.own_portals = {}
        sc.known_portals = {}
        sc._portal_time_valid = 30 * 60
        sc._max_known_portals = 20
        sc._have_smsg_rpc = False

        cursor = sc.openDB()
        try:
            create_db_(sc._db_con, logger)

            def offer_portal(addr_portal: str, smsg_difficulty: int) -> int:
                msg_data = MessagePortalOffer(
                    network_type_from=MessageNetworks.SMSG,
                    network_type_to=MessageNetworks.SIMPLEX,
                    portal_address_to=b"network_addr",
                    time_valid=30 * 60,
                    smsg_difficulty=smsg_difficulty,
                )
                msg = {
                    "msgid": secrets.token_bytes(28).hex(),
                    "msg_net": "smsg",
                    "sent": now,
                    "from": addr_portal,
                    "pubkey_from": "02" + "11" * 32,
                    "payload": msg_data.to_bytes(),
                }
                BSXNetwork.processPortalOffer(sc, msg)
                return cursor.execute(
                    "SELECT COUNT(*) FROM network_portals"
                ).fetchone()[0]

            assert offer_portal("portal_1", 0x1EFFFFFF) == 1
            assert offer_portal("portal_2", 0x1E0FFFFF) == 1
            assert offer_portal("portal_3", 0x1E3FFFFF) == 2
            assert offer_portal("portal_4", 0) == 2
        finally:
            sc.closeDB(cursor)

    def test_db_savepoint(self):
        db_test = DBMethods()
        db_test.sqlite_file = ":memory:"
        db_test.mxDB = threading.RLock()
        cursor = db_test.openDB()
        try:
            cursor.execute("CREATE TABLE sp_test (v INTEGER)")
            cursor.execute("INSERT INTO sp_test VALUES (1)")
            try:
                with db_test.dbSavepoint(cursor, "sp"):
                    cursor.execute("INSERT INTO sp_test VALUES (2)")
                    raise ValueError("Roll back")
            except ValueError:
                pass
            assert db_test._db_con.in_transaction
            cursor.execute("INSERT INTO sp_test VALUES (3)")
            db_test.commitDB()

            # Release must not commit
            with db_test.dbSavepoint(cursor, "sp"):
                cursor.execute("INSERT INTO sp_test VALUES (4)")
            assert db_test._db_con.in_transaction
            db_test.rollbackDB()

            rows = [r[0] for r in cursor.execute("SELECT v FROM sp_test ORDER BY v")]
            assert rows == [1, 3]
        finally:
            db_test.closeDB(cursor)

    def test_tx_hashes(self):
        tx = CTransaction()
        tx.nVersion = 2
        tx.nLockTime = 0
        tx.vout.append(CTxOut(1, bytes.fromhex("a15143aa086e05e3b5a73046")))
        tx.vout.append(CTxOut(2, bytes.fromhex("eed7d63fd86225f7159ed7e5")))
        tx.vin.append(
            CTxIn(
                COutPoint(
                    uint256_from_str(
                        bytes.fromhex(
                            "0101010101010101010101010101010101010010101010101010101010101010"
                        )
                    ),
                    1,
                ),
                bytes.fromhex("c2dca8ecbcf058b79f188692"),
            )
        )
        assert (
            tx.rehash()
            == "28d0e9afad2740504eb9d0428352bc77a7b94eaafa364ef4cc07aeeff0c631a2"
        )
        sighash = SegwitV0SignatureHash(
            bytes.fromhex("a15143aa086e05e3b5a73046"), tx, 0, SIGHASH_ALL, 3
        )
        assert (
            sighash.hex()
            == "252cd6e85b99e0fd554c44d5fe638923f7ef563048362406a665cf3400feb1bd"
        )

    def test_tx_parser_rejects_short_data(self):
        from basicswap.contrib.test_framework.messages import ser_compact_size

        ci = self.ci_btc()
        many_inputs = (2).to_bytes(4, "little") + ser_compact_size(200000)
        with self.assertRaises(ValueError):
            ci.loadTx(many_inputs)
        with self.assertRaises(ValueError):
            ci.getTxid(many_inputs)

        tx = CTransaction()
        tx.nVersion = 2
        tx.vin.append(CTxIn(COutPoint(1, 0), b"\x51"))
        tx.vout.append(CTxOut(1000, b"\x51"))
        tx_bytes = tx.serialize()
        assert ci.loadTx(tx_bytes).serialize() == tx_bytes
        for cut in (1, 4, 20):
            with self.assertRaises(ValueError):
                ci.loadTx(tx_bytes[:-cut])

    def test_pivx_tx_parser_rejects_short_data(self):
        from basicswap.interface.pivx.contrib.messages import (
            COutPoint as PIVXOutPoint,
            CTransaction as PIVXTransaction,
            CTxIn as PIVXTxIn,
            CTxOut as PIVXTxOut,
            SaplingTxData,
        )

        sap_data = SaplingTxData()
        sap_data.pre = b"\x01"
        sap_data.valueBalance = 0
        sap_data.vShieldedSpend = []
        sap_data.vShieldedOutput = []
        sap_data.bindingSig = b"\x00" * 64
        pivx_tx = PIVXTransaction()
        pivx_tx.nVersion = 3
        pivx_tx.nType = 1
        pivx_tx.vin.append(PIVXTxIn(PIVXOutPoint(1, 0), b"\x51"))
        pivx_tx.vout.append(PIVXTxOut(1000, b"\x51"))
        pivx_tx.sapData = sap_data
        pivx_tx.extraData = b"hello"

        settings = {"rpcport": 0, "rpcauth": "none"}
        settings.update(REQUIRED_SETTINGS)
        ci = PIVXInterface(settings, "regtest")
        tx_bytes = pivx_tx.serialize()
        assert ci.loadTx(tx_bytes).serialize() == tx_bytes
        for cut in (1, 3):
            with self.assertRaises(ValueError):
                ci.loadTx(tx_bytes[:-cut])

    def test_part_tx_parser_witness_optional(self):
        from basicswap.contrib.test_framework.messages import (
            CTxInWitness,
            CTxOutPart,
            PARTICL_TX_VERSION,
        )

        ci = self.ci_btc()
        tx = CTransaction()
        tx.nVersion = PARTICL_TX_VERSION
        tx.vin.append(CTxIn(COutPoint(1, 0)))
        tx.vout.append(CTxOutPart(1000, b"\x51"))
        witness = CTxInWitness()
        witness.scriptWitness.stack = [b"\x01" * 72]
        tx.wit.vtxinwit = [witness]

        no_witness = ci.loadTx(tx.serialize_without_witness())
        assert no_witness.serialize_without_witness() == tx.serialize_without_witness()
        assert no_witness.wit.vtxinwit[0].scriptWitness.stack == []
        with_witness = ci.loadTx(tx.serialize())
        assert with_witness.serialize() == tx.serialize()
        with self.assertRaises(ValueError):
            ci.loadTx(tx.serialize()[:-1])

    def test_dcr_tx_parser_bounds_witness(self):
        from basicswap.interface.dcr.messages import (
            COutPoint as DCRCOutPoint,
            CTransaction as DCRTransaction,
            CTxIn as DCRTxIn,
            CTxOut as DCRTxOut,
            TxSerializeType,
        )
        from basicswap.util.integer import encode_compactsize

        version = 1 | (TxSerializeType.OnlyWitness << 16)
        many_witnesses = version.to_bytes(4, "little") + encode_compactsize(200000)
        with self.assertRaisesRegex(ValueError, "Witness count"):
            DCRTransaction().deserialize(many_witnesses)

        tx = DCRTransaction()
        txi = DCRTxIn(DCRCOutPoint(1, 0, 0))
        txi.signature_script = b"\x01" * 72
        tx.vin.append(txi)
        tx.vout.append(DCRTxOut(1000, b"\x51"))
        for ser_type in (
            TxSerializeType.Full,
            TxSerializeType.NoWitness,
            TxSerializeType.OnlyWitness,
        ):
            tx_bytes = tx.serialize(ser_type)
            loaded = DCRTransaction()
            loaded.deserialize(tx_bytes)
            assert loaded.serialize(ser_type) == tx_bytes
            with self.assertRaisesRegex(ValueError, "Truncated"):
                DCRTransaction().deserialize(tx_bytes[:-1])

    def test_electrum_response_len_capped(self):
        import socket
        from unittest import mock
        from basicswap.interface import electrumx
        from basicswap.interface.electrumx import ElectrumConnection, ElectrumServer

        def stub_connection():
            conn = ElectrumConnection("127.0.0.1", 0, use_ssl=False)
            conn._socket, peer = socket.socketpair()
            conn._connected = True
            oversized = []
            conn.register_misbehaving_callback(lambda reason: oversized.append(True))

            def send():
                try:
                    peer.sendall(b"x" * 70000)
                except OSError:
                    pass

            threading.Thread(target=send, daemon=True).start()
            return conn, peer, oversized

        with mock.patch.object(electrumx, "MAX_RESPONSE_LEN", 65536):
            for receive in (
                lambda c: c._receive_response_sync(1, timeout=2),
                lambda c: c._receive_batch_responses_sync([1, 2], timeout=2),
            ):
                conn, peer, oversized = stub_connection()
                try:
                    with self.assertRaises(ConnectionError):
                        receive(conn)
                finally:
                    peer.close()
                assert not conn.is_connected()
                assert oversized == [True]

            conn, peer, oversized = stub_connection()
            conn._start_listener()
            listener = conn._listener_thread
            listener.join(timeout=5)
            conn._listener_running = False
            peer.close()
            assert not listener.is_alive()
            assert not conn.is_connected()
            assert oversized == [True]

        server = ElectrumServer(
            "bitcoin",
            clearnet_servers=[
                "electrum1.example.com:50002",
                "electrum2.example.com:50002",
            ],
        )
        with (
            mock.patch.object(ElectrumConnection, "connect"),
            mock.patch.object(
                ElectrumConnection, "get_server_version", return_value=["test"]
            ),
            mock.patch.object(ElectrumServer, "_start_keepalive"),
            mock.patch.object(ElectrumServer, "_subscribe_headers"),
        ):
            assert server._try_connect_server(server._servers[0])
        server._connection._misbehaving_callback("test")
        assert [s["host"] for s in server.get_sorted_servers()] == [
            "electrum2.example.com"
        ]

    def test_electrum_sync_receive_deadline(self):
        import socket
        import time
        from basicswap.interface.electrumx import ElectrumConnection
        from basicswap.util import TemporaryError

        for receive in (
            lambda c: c._receive_response_sync(1, timeout=1),
            lambda c: c._receive_batch_responses_sync([1, 2], timeout=1),
        ):
            conn = ElectrumConnection("127.0.0.1", 0, use_ssl=False)
            conn._socket, peer = socket.socketpair()
            conn._connected = True
            stop = threading.Event()

            def drip():
                for _ in range(30):
                    if stop.wait(0.1):
                        return
                    try:
                        peer.sendall(b"x")
                    except OSError:
                        return

            threading.Thread(target=drip, daemon=True).start()
            start = time.time()
            try:
                with self.assertRaisesRegex(TemporaryError, "timed out"):
                    receive(conn)
                assert time.time() - start < 2
            finally:
                stop.set()
                peer.close()
                conn._socket.close()

    def test_electrum_discovery_skips_non_public_peers(self):
        from unittest import mock
        from basicswap.interface.electrumx import ElectrumServer

        server = ElectrumServer(
            "bitcoin", clearnet_servers=["electrum.example.com:50002"]
        )
        peers = [
            ["127.0.0.1", "", ["s50002"]],
            ["10.0.0.2", "", ["s50002"]],
            ["100.64.0.3", "", ["t50001"]],
            ["169.254.0.4", "", ["s50002"]],
            ["::1", "", ["s50002"]],
            ["fd00::5", "", ["s50002"]],
            ["::ffff:192.168.1.6", "", ["s50002"]],
            ["8.8.8.8", "localhost", ["s50002"]],
            ["8.8.8.8", "printer.local", ["s50002"]],
            ["8.8.8.8", "electrum.example.org", ["s50002"]],
            ["2606:4700::1111", "", ["s50002"]],
            ["", "abcdefghijklmnop.onion", ["t50001"]],
        ]
        with mock.patch.object(server, "call", return_value=peers):
            hosts = [p["host"] for p in server.discover_peers()]
        assert hosts == [
            "electrum.example.org",
            "2606:4700::1111",
            "abcdefghijklmnop.onion",
        ]

    def test_electrum_ping_refuses_non_public_destinations(self):
        import socket
        from unittest import mock
        from basicswap.interface.electrumx import ElectrumServer

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(0.5)
        port = listener.getsockname()[1]
        server = ElectrumServer(
            "bitcoin", clearnet_servers=["electrum.example.com:50002"]
        )
        real_getaddrinfo = socket.getaddrinfo

        def rebind(host, *args, **kwargs):
            if host == "rebind.example.com":
                host = "127.0.0.1"
            return real_getaddrinfo(host, *args, **kwargs)

        try:
            assert server.ping_server("127.0.0.1", port, ssl=False) is None
            with self.assertRaises(socket.timeout):
                listener.accept()

            with mock.patch("socket.getaddrinfo", side_effect=rebind):
                assert server.ping_server("rebind.example.com", port, ssl=False) is None
            with self.assertRaises(socket.timeout):
                listener.accept()
        finally:
            listener.close()

    def test_electrum_ping_writes_no_pins(self):
        from unittest import mock
        from basicswap.interface.electrumx import (
            CertPinStore,
            ElectrumConnection,
            ElectrumServer,
        )

        pins = CertPinStore()
        server = ElectrumServer(
            "bitcoin", clearnet_servers=["electrum.example.com:50002"], cert_pins=pins
        )

        def first_use_pin(conn):
            conn._cert_pins.set(conn._coin_name, conn.server_key(), "00" * 32)

        with (
            mock.patch.object(ElectrumConnection, "connect", first_use_pin),
            mock.patch.object(ElectrumConnection, "ping", return_value=1.0),
        ):
            assert server.ping_server("electrum.example.org", 50002) == 1.0
        assert pins.get("bitcoin", "electrum.example.org:50002") is None

    def test_electrum_txids_checked(self):
        import json
        import socket
        from basicswap.interface.electrumx import ElectrumConnection
        from basicswap.util import TemporaryError

        valid = [{"tx_hash": "ab" * 32, "height": 1}]
        invalid = (
            [{"tx_hash": "<img src=x onerror=alert(1)>", "height": 1}],
            [{"tx_hash": "ab" * 31, "height": 1}],
            [{"height": 1}],
        )

        dropped = []

        def stub_connection(results):
            conn = ElectrumConnection("127.0.0.1", 0, use_ssl=False)
            conn._socket, peer = socket.socketpair()
            conn._connected = True
            conn.register_misbehaving_callback(dropped.append)
            for request_id, result in enumerate(results, 1):
                response = {"jsonrpc": "2.0", "id": request_id, "result": result}
                peer.sendall((json.dumps(response) + "\n").encode())
            return conn, peer

        for method in (
            "blockchain.scripthash.get_history",
            "blockchain.scripthash.listunspent",
        ):
            conn, peer = stub_connection([valid])
            assert conn.call(method, ["00" * 32]) == valid
            peer.close()
            for result in invalid:
                conn, peer = stub_connection([result])
                with self.assertRaisesRegex(TemporaryError, "invalid txid"):
                    conn.call(method, ["00" * 32])
                assert not conn.is_connected()
                peer.close()

                conn, peer = stub_connection([valid, result])
                requests = [(method, ["00" * 32]), (method, ["11" * 32])]
                with self.assertRaisesRegex(TemporaryError, "invalid txid"):
                    conn.call_batch(requests)
                assert not conn.is_connected()
                peer.close()
        assert len(dropped) == 2 * 2 * len(invalid)

    def test_validateSwapType(self):
        logging.info("---------- Test validateSwapType")
        basicswap_dir = "/tmp/bsx_test_other"
        if not os.path.exists(basicswap_dir):
            os.makedirs(basicswap_dir)

        k = PrivateKey()
        settings = {
            "network_key": toWIF(PREFIX_SECRET_KEY_REGTEST, k.secret),
            "network_pubkey": k.public_key.format().hex(),
        }

        sc = BasicSwap(
            basicswap_dir,
            settings,
            "regtest",
            log_name="bsx_test_other",
        )

        should_pass = [
            (Coins.BTC, Coins.XMR, SwapTypes.XMR_SWAP),
            (Coins.XMR, Coins.BTC, SwapTypes.XMR_SWAP),
            (Coins.BTC, Coins.FIRO, SwapTypes.XMR_SWAP),
            (Coins.FIRO, Coins.BTC, SwapTypes.XMR_SWAP),
            (Coins.PIVX, Coins.BTC, SwapTypes.XMR_SWAP),
            (Coins.BTC, Coins.PIVX, SwapTypes.XMR_SWAP),
            (Coins.DASH, Coins.PIVX, SwapTypes.SELLER_FIRST),
            (Coins.PIVX, Coins.DASH, SwapTypes.SELLER_FIRST),
        ]
        should_fail = [
            (Coins.BTC, Coins.XMR, SwapTypes.SELLER_FIRST),
            (Coins.XMR, Coins.PART_ANON, SwapTypes.XMR_SWAP),
            (Coins.FIRO, Coins.PART_ANON, SwapTypes.XMR_SWAP),
            (Coins.PART_ANON, Coins.FIRO, SwapTypes.XMR_SWAP),
            (Coins.FIRO, Coins.BTC, SwapTypes.SELLER_FIRST),
            (Coins.BTC, Coins.FIRO, SwapTypes.SELLER_FIRST),
        ]

        for case in should_pass:
            sc.validateSwapType(case[0], case[1], case[2])
        for case in should_fail:
            self.assertRaises(
                ValueError, sc.validateSwapType, case[0], case[1], case[2]
            )
        sc.chain = "mainnet"
        for case in should_pass:
            try:
                sc.validateSwapType(case[0], case[1], case[2])
            except Exception as e:
                assert "Coin pair should use adaptor sig swap type" in str(e)
            else:
                if case[2] != SwapTypes.XMR_SWAP:
                    if (
                        case[0] not in sc.coins_without_segwit
                        or case[1] not in sc.coins_without_segwit
                    ):
                        raise ValueError(f"Invalid swap pair in strict mode {case}")
        for case in should_fail:
            self.assertRaises(
                ValueError, sc.validateSwapType, case[0], case[1], case[2]
            )

        sc.settings["strict_swap_type"] = False
        for case in should_pass:
            sc.validateSwapType(case[0], case[1], case[2])

        del sc

    def test_validateOfferLockValue(self):
        logging.info("---------- Test validateOfferLockValue")
        basicswap_dir = "/tmp/bsx_test_other"
        if not os.path.exists(basicswap_dir):
            os.makedirs(basicswap_dir)

        k = PrivateKey()
        settings = {
            "network_key": toWIF(PREFIX_SECRET_KEY_REGTEST, k.secret),
            "network_pubkey": k.public_key.format().hex(),
        }

        sc = BasicSwap(
            basicswap_dir,
            settings,
            "regtest",
            log_name="bsx_test_other",
        )

        # use_csv is the only coin_clients entry validateOfferLockValue reads
        sc.coin_clients[Coins.BTC] = {"use_csv": True}
        sc.coin_clients[Coins.XMR] = {"use_csv": True}
        sc.coin_clients[Coins.PIVX] = {"use_csv": False}

        seq_time = (
            SwapTypes.XMR_SWAP,
            Coins.BTC,
            Coins.XMR,
            TxLockTypes.SEQUENCE_LOCK_TIME,
        )
        seq_blocks = (
            SwapTypes.XMR_SWAP,
            Coins.BTC,
            Coins.XMR,
            TxLockTypes.SEQUENCE_LOCK_BLOCKS,
        )
        # The absolute lock types require at least one coin without CSV
        abs_time = (
            SwapTypes.SELLER_FIRST,
            Coins.PIVX,
            Coins.BTC,
            TxLockTypes.ABS_LOCK_TIME,
        )
        abs_blocks = (
            SwapTypes.SELLER_FIRST,
            Coins.PIVX,
            Coins.BTC,
            TxLockTypes.ABS_LOCK_BLOCKS,
        )

        time_locks = [seq_time + (24 * 60 * 60,), abs_time + (24 * 60 * 60,)]
        block_locks = [seq_blocks + (100,), abs_blocks + (100,)]

        for case in time_locks + block_locks:
            sc.validateOfferLockValue(*case)

        out_of_range = [
            seq_time + (sc.min_sequence_lock_seconds - 1,),
            seq_time + (sc.max_sequence_lock_seconds + 1,),
            seq_blocks + (4,),
            seq_blocks + (1001,),
            abs_time + (4 * 60 * 60 - 1,),
            abs_time + (96 * 60 * 60 + 1,),
            abs_blocks + (9,),
            abs_blocks + (1001,),
        ]
        for case in out_of_range:
            self.assertRaises(ValueError, sc.validateOfferLockValue, *case)

        self.assertRaises(
            ValueError,
            sc.validateOfferLockValue,
            SwapTypes.XMR_SWAP,
            Coins.BTC,
            Coins.XMR,
            0,
            100,
        )

        # Block count lock types are only valid on regtest
        sc.chain = "mainnet"
        for case in time_locks:
            sc.validateOfferLockValue(*case)
        for case in block_locks:
            self.assertRaisesRegex(
                ValueError,
                "for testing only",
                sc.validateOfferLockValue,
                *case,
            )

        del sc

    def test_ptx_lock_margin(self):
        basicswap_dir = "/tmp/bsx_test_other"
        if not os.path.exists(basicswap_dir):
            os.makedirs(basicswap_dir)

        k = PrivateKey()
        settings = {
            "network_key": toWIF(PREFIX_SECRET_KEY_REGTEST, k.secret),
            "network_pubkey": k.public_key.format().hex(),
        }
        sc = BasicSwap(
            basicswap_dir,
            settings,
            "regtest",
            log_name="bsx_test_other",
        )
        ci = self.ci_btc()
        ltc_coin_settings = {"rpcport": 0, "rpcauth": "none"}
        ltc_coin_settings.update(REQUIRED_SETTINGS)
        sc.coin_clients[Coins.BTC] = {"interface": ci}
        sc.coin_clients[Coins.LTC] = {
            "interface": LTCInterface(ltc_coin_settings, "regtest")
        }

        secret_hash = sha256(secrets.token_bytes(32))
        pkh_buyer = secrets.token_bytes(20)
        pkh_seller = secrets.token_bytes(20)
        lock_value: int = 4 * 60 * 60

        offer = Offer(
            coin_from=Coins.BTC,
            coin_to=Coins.LTC,
            lock_type=TxLockTypes.ABS_LOCK_TIME,
            lock_value=lock_value,
        )
        accepted_at: int = sc.getTime()
        bid = Bid()
        bid.initiate_tx = SwapTx(
            script=buildContractScript(
                accepted_at + lock_value,
                secret_hash,
                pkh_buyer,
                pkh_seller,
                OpCodes.OP_CHECKLOCKTIMEVERIFY,
            )
        )

        def abs_participate_script(itx_block_time: int) -> bytearray:
            return buildContractScript(
                itx_block_time + lock_value // 2,
                secret_hash,
                pkh_seller,
                pkh_buyer,
                OpCodes.OP_CHECKLOCKTIMEVERIFY,
            )

        sc.ensurePTxLockMargin(
            bid, offer, abs_participate_script(accepted_at + sc._sc_lock_tx_timeout)
        )
        # The seller held the initiate txn back for half the lock
        self.assertRaisesRegex(
            ValueError,
            "too close",
            sc.ensurePTxLockMargin,
            bid,
            offer,
            abs_participate_script(accepted_at + lock_value // 2),
        )
        sc.setMockTimeOffset(lock_value - 10 * 60)
        self.assertRaisesRegex(
            ValueError,
            "too close",
            sc.ensurePTxLockMargin,
            bid,
            offer,
            abs_participate_script(accepted_at + 60),
        )
        sc.setMockTimeOffset(0)

        offer = Offer(
            coin_from=Coins.BTC,
            coin_to=Coins.LTC,
            lock_type=TxLockTypes.SEQUENCE_LOCK_TIME,
            lock_value=lock_value,
        )
        itx_mtp: int = 1700000000
        bid = Bid()
        bid.initiate_tx = SwapTx(
            script=buildContractScript(
                ci.getExpectedSequence(offer.lock_type, lock_value),
                secret_hash,
                pkh_buyer,
                pkh_seller,
            ),
            block_height=100,
            block_time=itx_mtp,
        )
        participate_script = buildContractScript(
            ci.getExpectedSequence(offer.lock_type, lock_value // 2),
            secret_hash,
            pkh_seller,
            pkh_buyer,
        )
        ci.getMedianTimePastAtHeight = lambda height: itx_mtp

        ci.getChainMedianTime = lambda: itx_mtp + 10 * 60
        sc.ensurePTxLockMargin(bid, offer, participate_script)
        # The buyer was offline for half the lock
        ci.getChainMedianTime = lambda: itx_mtp + lock_value // 2
        self.assertRaisesRegex(
            ValueError,
            "too close",
            sc.ensurePTxLockMargin,
            bid,
            offer,
            participate_script,
        )

        del sc

    def test_jsonrpc(self):
        logging.info("---------- Test Jsonrpc")
        host = "127.0.0.1"
        port = 1234
        auth = escape_rpcauth("user:p@ss")
        url = Jsonrpc.constructUrl(auth, host, port)
        assert url == "http://user:p%40ss@127.0.0.1:1234/"

        host = "https://127.0.0.1"
        url = Jsonrpc.constructUrl(auth, host, port, "new_wallet")
        assert url == "https://user:p%40ss@127.0.0.1:1234/wallet/new_wallet"

    def test_prepare_refuses_empty_rpc_password(self):
        from unittest import mock
        import basicswap.bin.prepare as prepare

        prepare_module = prepare.coin_prepare_modules["bitcoin"]
        for core_settings, refused in (
            ({"rpcuser": "user", "rpcpassword": ""}, True),
            ({"walletrpcuser": "user", "walletrpcpassword": ""}, True),
            ({"rpcuser": "", "rpcpassword": ""}, False),
            ({"rpcuser": "user", "rpcpassword": "pwd"}, False),
        ):
            settings = {"chainclients": {"bitcoin": core_settings}}
            with mock.patch.object(prepare_module, "prepareDataDir") as prepare_dir:
                if refused:
                    with self.assertRaises(SystemExit):
                        prepare.prepareDataDir(
                            "bitcoin", settings, "regtest", None, {"prepare_ctx": None}
                        )
                    prepare_dir.assert_not_called()
                else:
                    prepare.prepareDataDir(
                        "bitcoin", settings, "regtest", None, {"prepare_ctx": None}
                    )
                    prepare_dir.assert_called_once()

    def test_entry_points_set_private_umask(self):
        import importlib.util
        from unittest import mock
        import basicswap.bin.prepare as prepare
        import basicswap.bin.run as run

        script_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "scripts", "createoffers.py"
        )
        spec = importlib.util.spec_from_file_location("createoffers", script_path)
        createoffers = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(createoffers)

        orig_umask = os.umask(0o022)
        try:
            for main in (prepare.main, run.main, createoffers.main):
                os.umask(0o022)
                with (
                    mock.patch("sys.argv", ["prog", "--version"]),
                    mock.patch("sys.stdout"),
                ):
                    try:
                        main()
                    except SystemExit:
                        pass
                assert os.umask(0o022) == 0o077, main.__module__
        finally:
            os.umask(orig_umask)

    def test_early_offer_revokes_keep_every_sender(self):
        settings = {"rpcport": 0, "rpcauth": "none"}
        settings.update(REQUIRED_SETTINGS)
        ci_part = PARTInterface(settings, "regtest")
        sc = _FakeSwapClient()
        sc._possibly_revoked_offers = collections.deque([], maxlen=1000)
        sc._expired_offer_revokes = set()
        sc.network_addr = "network_addr"
        sc.mock_time_offset = 0
        sc.ci = lambda coin: ci_part
        sc.getTime = lambda: BaseApp.getTime(sc)
        sc.openDB = lambda: None
        sc.closeDB = lambda cursor: None
        sc.getOffer = lambda offer_id, cursor: None
        sc.getSmsgMsgBytes = lambda msg: msg["payload"]
        sc.storeOfferRevoke = lambda *args: BasicSwap.storeOfferRevoke(sc, *args)

        offer_id = sc.getTime().to_bytes(8, "big") + secrets.token_bytes(20)
        maker, other = PrivateKey(), PrivateKey()
        maker_addr = ci_part.pubkey_to_address(maker.public_key.format())
        other_addr = ci_part.pubkey_to_address(other.public_key.format())

        def revoke(key: PrivateKey, addr_from: str) -> None:
            sig = ci_part._signMessageWithKeyLocal(
                ci_part.encodeKey(key.secret), offer_id.hex() + "_revoke"
            )
            msg_data = OfferRevokeMessage(
                offer_msg_id=offer_id, signature=base64.b64decode(sig)
            )
            msg = {
                "to": sc.network_addr,
                "from": addr_from,
                "payload": msg_data.to_bytes(),
            }
            BasicSwap.processOfferRevoke(sc, msg)

        revoke(other, maker_addr)
        assert len(sc._possibly_revoked_offers) == 0
        revoke(other, other_addr)
        assert BasicSwap.isOfferRevoked(sc, offer_id, maker_addr) is False
        revoke(maker, maker_addr)
        revoke(maker, maker_addr)
        assert len(sc._possibly_revoked_offers) == 2
        assert BasicSwap.isOfferRevoked(sc, offer_id, maker_addr) is True

    def test_split_chunks_need_their_bid_or_offer(self):
        sc = DBMethods()
        sc.sqlite_file = ":memory:"
        sc.mxDB = threading.RLock()
        sc.log = BSXLogger("test")
        sc._max_early_split_chunks = 1000
        sc._max_early_split_chunks_per_sender = 2
        sc._max_split_chunks_per_bid = 60
        now: int = 1800000000
        sc.getTime = lambda: now
        sc.getSmsgMsgBytes = lambda msg: msg["payload"]
        sc.getSplitChunkRefusal = lambda *args: BasicSwap.getSplitChunkRefusal(
            sc, *args
        )

        offer_id = secrets.token_bytes(28)
        bid_id = secrets.token_bytes(28)
        cursor = sc.openDB()
        try:
            create_db_(sc._db_con, logger)
            offer = Offer(
                offer_id=offer_id,
                addr_from="offer_addr",
                was_sent=True,
                active_ind=1,
                expire_at=now + 600,
            )
            sc.add(offer, cursor)
            sc.add(Bid(bid_id=bid_id, offer_id=offer_id, bid_addr="bid_addr"), cursor)

            def send_chunk(
                chunk_bid_id, msg_type, addr_from, addr_to, parent_msg_id=None
            ) -> int:
                msg_data = XmrSplitMessage(
                    msg_id=chunk_bid_id,
                    msg_type=msg_type,
                    sequence=1,
                    dleag=bytes(100),
                    parent_msg_id=parent_msg_id or chunk_bid_id,
                )
                msg = {
                    "msgid": secrets.token_bytes(28).hex(),
                    "from": addr_from,
                    "to": addr_to,
                    "sent": now,
                    "payload": msg_data.to_bytes(),
                }
                BasicSwap.processXmrSplitMessage(sc, msg)
                return cursor.execute("SELECT COUNT(*) FROM xmr_split_data").fetchone()[
                    0
                ]

            BID, ACCEPT = XmrSplitMsgTypes.BID, XmrSplitMsgTypes.BID_ACCEPT
            assert send_chunk(bid_id, ACCEPT, "other_addr", "bid_addr") == 0
            assert send_chunk(bid_id, ACCEPT, "offer_addr", "bid_addr") == 1
            assert send_chunk(bid_id, BID, "bid_addr", "offer_addr") == 2
            unknown_bid_id = secrets.token_bytes(28)
            assert send_chunk(unknown_bid_id, ACCEPT, "offer_addr", "bid_addr") == 2
            assert send_chunk(unknown_bid_id, BID, "early_addr", "other_addr") == 2
            assert send_chunk(unknown_bid_id, BID, "early_addr", "offer_addr") == 3
            assert (
                send_chunk(secrets.token_bytes(28), BID, "early_addr", "offer_addr")
                == 4
            )
            assert (
                send_chunk(secrets.token_bytes(28), BID, "early_addr", "offer_addr")
                == 4
            )
            assert (
                send_chunk(secrets.token_bytes(28), BID, "early_addr_2", "offer_addr")
                == 5
            )
            sc._max_early_split_chunks = 3
            assert (
                send_chunk(secrets.token_bytes(28), BID, "early_addr_3", "offer_addr")
                == 5
            )

            sc._max_split_chunks_per_bid = 3
            for expect_rows in (6, 6):
                assert (
                    send_chunk(
                        bid_id,
                        ACCEPT,
                        "offer_addr",
                        "bid_addr",
                        secrets.token_bytes(28),
                    )
                    == expect_rows
                )
        finally:
            sc.closeDB(cursor)

    def test_portals_capped_and_forgotten(self):
        sc = DBMethods()
        sc.sqlite_file = ":memory:"
        sc.mxDB = threading.RLock()
        sc.log = BSXLogger("test")
        now: int = 1800000000
        sc.getTime = lambda: now
        sc.getSmsgMsgBytes = lambda msg: msg["payload"]
        sc.getActiveNetwork = lambda network_id: {"bridged": [{"type": "simplex"}]}
        sc.own_portals = {}
        sc.known_portals = {}
        sc.active_networks = []
        sc._is_locked = False
        sc._have_smsg_rpc = False
        sc._portal_time_valid = 30 * 60
        sc._max_known_portals = 2
        sc._forget_portals_after = 86400 * 7

        cursor = sc.openDB()
        try:
            create_db_(sc._db_con, logger)

            def offer_portal(addr_portal: str, time_valid: int = 30 * 60) -> int:
                msg_data = MessagePortalOffer(
                    network_type_from=MessageNetworks.SMSG,
                    network_type_to=MessageNetworks.SIMPLEX,
                    portal_address_to=b"network_addr",
                    time_valid=time_valid,
                    smsg_difficulty=0x1EFFFFFF,
                )
                msg = {
                    "msgid": secrets.token_bytes(28).hex(),
                    "msg_net": "smsg",
                    "sent": now,
                    "from": addr_portal,
                    "pubkey_from": "02" + "11" * 32,
                    "payload": msg_data.to_bytes(),
                }
                BSXNetwork.processPortalOffer(sc, msg)
                return cursor.execute(
                    "SELECT COUNT(*) FROM network_portals"
                ).fetchone()[0]

            def portal_addrs() -> list:
                return [
                    r[0]
                    for r in cursor.execute(
                        "SELECT addr FROM smsgaddresses ORDER BY addr"
                    ).fetchall()
                ]

            def pick() -> str | None:
                portal = BSXNetwork.pickPortal(
                    sc, sc.known_portals[MessageNetworks.SMSG][MessageNetworks.SIMPLEX]
                )
                return None if portal is None else portal.address_from

            cursor.execute(
                "INSERT INTO smsgaddresses (addr, use_type) VALUES ('bid_addr', :use_type)",
                {"use_type": int(AddressTypes.BID)},
            )
            assert offer_portal("portal_1", time_valid=86400) == 1
            assert (
                cursor.execute("SELECT time_valid FROM network_portals").fetchone()[0]
                == 30 * 60
            )
            assert offer_portal("portal_2") == 2
            assert offer_portal("portal_3") == 2
            assert offer_portal("portal_1") == 2

            now += 3600
            assert offer_portal("portal_3") == 3
            assert pick() == "portal_3"
            now += 3600
            assert pick() == "portal_3"

            now += 86400 * 7
            assert offer_portal("portal_2") == 3
            BSXNetwork.updateNetworkBridges(sc, now)
            assert cursor.execute(
                "SELECT address_from FROM network_portals"
            ).fetchall() == [("portal_2",)]
            assert portal_addrs() == ["bid_addr", "portal_2"]
            assert pick() == "portal_2"
            assert (
                len(sc.known_portals[MessageNetworks.SMSG][MessageNetworks.SIMPLEX])
                == 1
            )
        finally:
            sc.closeDB(cursor)


if __name__ == "__main__":
    unittest.main()
