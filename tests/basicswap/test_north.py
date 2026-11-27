#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
TrueNorth checks that need no daemon.

pytest -v tests/basicswap/test_north.py

The keys, addresses and the signature below were made or checked by
TrueNorth Core v30.5.5 (deriveaddresses, signmessagewithprivkey) on each
chain.
"""

import hashlib
import io
import logging
import os
import shutil
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from basicswap.base import BaseApp
from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import (
    BidStates,
    EventLogTypes,
    SwapTypes,
    TxLockTypes,
    TxTypes,
)
from basicswap.chainparams import (
    Coins,
    chainparams,
    getCoinIdFromName,
    getCoinIdFromTicker,
)
from basicswap.contrib.test_framework import segwit_addr
from basicswap.contrib.test_framework.script import CScript, OP_0
from basicswap.db import Bid, Concepts, create_db_, DBMethods, EventLog, SwapTx
from basicswap.db_upgrades import addBidState
from basicswap.interface.btc.core import prepare_module as btc_prepare
from basicswap.interface.north.core import NORTHPrepare, prepare_module
from basicswap.interface.north.north import NORTHInterface
from basicswap.interface.prepare_util import PrepareContext
from basicswap.util.crypto import hash160
from basicswap.util.extkey import ExtKeyPair
from basicswap.util.logging import BSXLogger
from tests.basicswap.util.common import REQUIRED_SETTINGS

PRIMARY_KEY = "3F0BAE0458615427B8CA935E3E242DF5E4478AE5"
SIGNING_SUBKEY = "895B7591E9701E99D87D58A9B932A2FBD92C626D"

TEST_KEY = hashlib.sha256(b"basicswap truenorth test key").digest()
TEST_SEED = hashlib.sha256(b"basicswap truenorth test seed").digest()
TEST_MESSAGE = "BasicSwap TrueNorth test message"
# signmessagewithprivkey, the same on every chain
TEST_SIGNATURE = "H6TeE7lxRtwqIK6jN5uTb/p7Mg2/rkUXgbYNxMPXU/ijCPrvXEB4pzKefV1LhNUs9LQW/EUCD4yPQ8IXaYCzXv0="

VECTORS = {
    "mainnet": {
        "wif": "TiLfHc1LvErhKraHCRgRD75gHT4SqFWV5qvq6TjZMmsNhCJu6A4Y",
        "p2wpkh": "north1qqrq2eackd9u64sznld2csrhpy6qtmnc5z8g09g",
        "p2pkh": "NKyx16S5Z9DKvb4eMfid8HdB6sCrCLoDe3",
        "p2sh_p2wpkh": "TCsGzseHxAHgUhNaBVyAF2K4QVHWx4hohE",
        "xprv": "Tprv127AUUZj4XJtsC9qJhb1SxTKbGz1buuYLaXuBVH5sXQDdvebsCKpWwFnATcNoqa4JhNvrBit2zuQzyu9wcoJdZh8aXFQT16x9m52GsbbWNs9",
        "xpub": "Tpub17LTNxYHMGvdApk49xwYf9iKPmfrzo7zCRdjryEmz7CNfeZiCzgjCpLMQS6McFraT3CB8Et3afSe5mhi7MMuSGfx4rW5hpkShp3pPyD3VuUj",
        "account_path": "84h/1867h/0h",
        # account_path/0/0 of the seed
        "account_p2wpkh": "north1q6s9ggdl9f6mkml5lacjpkek2a7mc65f9psgfr5",
    },
    "testnet": {
        "wif": "efFKbYfuscesS9Z882tW7z5ihbvicDaH8Y2UW5NZhBe3Xgyy9sfm",
        "p2wpkh": "tnorth41qqrq2eackd9u64sznld2csrhpy6qtmnc5njusd3",
        "p2pkh": "sheyt2C7PK3HdEEy9J2tXSVc3h1i4Lt3QS",
        "p2sh_p2wpkh": "7teKjfLTsW3dDtgR1Myry1FJCGvEkr4mp5",
        "xprv": "tpruqxHasNhunKceKLSunKqj9tSUipYEcNuYVgYGhbAqbVs9iNR7UPgd3DweWWZ6C8gHFKRrL9LxY9aBDXcfR344HFArAUaAjZMyEeD1ztBgA9q",
        "xpub": "tpuavUyd1nk9vhJKCoUhfyWKZJ6bHr4Ami6T4z93z7D91mfYYrft6nWDDiZWgfai23zfJK4ow8LuNJhjCjLCMxTzvYcp8XHwZGKrwFgvax5f7fj",
        "account_path": "84h/1h/0h",
        "account_p2wpkh": "tnorth41q35p4vmptcv2axdtw69ujjn2vr36zslqqjdzqvw",
    },
    "regtest": {
        "wif": "eN64TDx7XJpbV7Xb1t6iXdtkCjXQwP2poenDPAgNiE8cy2eajtov",
        "p2wpkh": "rnorth1qqrq2eackd9u64sznld2csrhpy6qtmnc5j9dlxf",
        "p2pkh": "r6JZwazxYbBnMVgd3chcawQTXfywDY6qUD",
        "p2sh_p2wpkh": "rYUG7Aw18dAVuqTbbqHeNJ6gukEEBwVTSi",
        "xprv": "tpruZLtDPZhDAKMtyNYGD5aZ5M1igqBM6dyS5XBujKuTsdLKnzZsJgfwmqLsrniq9sYSQPRb7BYjnf5gksivsk3U8UoT6ZWAhDVbtvX3NFxkkQ3",
        "xpub": "tpuadsaFXyjTJh3Zrqa46jF9UkfqFrhHFyALepnh1qwmHu8idUpdw5VXxKxk2wkSynrpTP4YiAYgcpDEk5STpfTQmnFR4cDwWvTVbXzwxGk7keD",
        "account_path": "84h/1h/0h",
        "account_p2wpkh": "rnorth1q35p4vmptcv2axdtw69ujjn2vr36zslqqn6n08k",
    },
}


class FakeSwapClient:
    # An interface for mainnet or testnet reads its fee settings from the
    # swap client, BaseApp can't be instantiated without a datadir.
    getBaseAltruistic = BaseApp.getBaseAltruistic

    def __init__(self):
        self.settings = {"chainclients": {}}
        self.log = BSXLogger("test")

    def getChainClientSettings(self, coin):
        return {}


def make_ci(network: str) -> NORTHInterface:
    coin_settings = {"rpcport": 0, "rpcauth": "none"}
    coin_settings.update(REQUIRED_SETTINGS)
    swap_client = None if network == "regtest" else FakeSwapClient()
    ci = NORTHInterface(coin_settings, network, swap_client=swap_client)
    ci._log = BSXLogger("test")
    return ci


def make_ctx(bin_arch: str, file_ext: str, **kwargs) -> PrepareContext:
    return PrepareContext(
        data_dir="",
        bin_dir="",
        port_offset=0,
        should_manage_daemon=lambda ticker: True,
        bin_arch=bin_arch,
        file_ext=file_ext,
        logger=BSXLogger("test"),
        **kwargs,
    )


def make_prepare() -> NORTHPrepare:
    return NORTHPrepare(
        name="truenorth",
        ticker="NORTH",
        version="30.5.5",
        version_tag="",
        signers=prepare_module.signers,
    )


def make_timing_ci(blocks_confirmed: int, blocks_target: int):
    return SimpleNamespace(
        blocks_confirmed=blocks_confirmed,
        chainparams=lambda: {"blocks_target": blocks_target},
    )


class Test(unittest.TestCase):

    def test_chainparams(self):
        assert Coins.NORTH == 20
        assert getCoinIdFromName("truenorth") == Coins.NORTH
        assert getCoinIdFromTicker("NORTH") == Coins.NORTH
        params = chainparams[Coins.NORTH]
        assert params["ticker"] == "NORTH"
        assert params["display_name"] == "TrueNorth"
        assert params["message_magic"] == "TrueNorth Signed Message:\n"
        assert params["blocks_target"] == 120
        assert params["rate_ids"] == {}
        assert params["mainnet"]["hrp"] == "north"
        assert params["mainnet"]["bip44"] == 1867
        assert params["testnet"]["name"] == "testnet4"
        assert params["testnet"]["hrp"] == "tnorth4"
        assert params["regtest"]["hrp"] == "rnorth"
        assert make_ci("regtest").coin_name() == "TrueNorth"

    def test_max_money(self):
        ci = make_ci("regtest")
        assert ci.max_money() == 10000000000 * ci.COIN()
        assert ci.money_range(21000001 * ci.COIN())

    def test_keys_and_addresses(self):
        for network, v in VECTORS.items():
            ci = make_ci(network)
            pk = ci.getPubkey(TEST_KEY)
            assert ci.encodeKey(TEST_KEY) == v["wif"], network
            assert ci.decodeKey(v["wif"]) == TEST_KEY, network
            assert ci.pubkey_to_segwit_address(pk) == v["p2wpkh"], network
            assert ci.pubkey_to_address(pk) == v["p2pkh"], network
            redeem_script = CScript([OP_0, hash160(pk)])
            assert ci.encode_p2sh(redeem_script) == v["p2sh_p2wpkh"], network

            assert ci.decodeSegwitAddress(v["p2wpkh"]) == hash160(pk), network
            assert bytes(ci.getDestForAddress(v["p2wpkh"])) == bytes(
                redeem_script
            ), network
            assert ci.decodeSwapDest(v["p2wpkh"]) == hash160(pk), network

    def test_extkeys(self):
        for network, v in VECTORS.items():
            ci = make_ci(network)
            ek = ExtKeyPair()
            ek.set_seed(TEST_SEED)
            assert ci.encode_secret_extkey(ek.encode_v()) == v["xprv"], network
            assert ci.encode_public_extkey(ek.encode_p()) == v["xpub"], network
            path: str = ci.getWalletAccountPath()
            assert path == v["account_path"], network
            child = ek.derive_path(f"{path}/0/0")
            assert (
                ci.pubkey_to_segwit_address(child.get_pubkey()) == v["account_p2wpkh"]
            ), network

    def test_message_signature(self):
        for network, v in VECTORS.items():
            ci = make_ci(network)
            assert ci.verifyMessage(v["p2pkh"], TEST_MESSAGE, TEST_SIGNATURE)
            assert not ci.verifyMessage(v["p2pkh"], TEST_MESSAGE + ".", TEST_SIGNATURE)

    def test_p2qrh_is_not_a_swap_destination(self):
        # Witness v2 (P2QRH) is the TrueNorth wallet default.  Withdrawals go
        # through the node wallet, a swap output is only paid to the types
        # BasicSwap builds.
        ci = make_ci("mainnet")
        addr = segwit_addr.encode_segwit_address("north", 2, bytes(range(32)))
        assert addr.startswith("north1z")
        assert not ci.isValidAddress(addr)
        with self.assertRaises(ValueError):
            ci.getDestForAddress(addr)

    def test_release_names(self):
        pm = make_prepare()
        cases = (
            ("x86_64-linux-gnu", "tar.gz", "linux", "x86_64", "linux-x86_64"),
            ("win64", "zip", "win", "AMD64", "windows-x86_64"),
            ("osx64", "tar.gz", "osx", "arm64", "macos-arm64"),
        )
        for bin_arch, file_ext, os_name, machine, arch_name in cases:
            ctx = make_ctx(bin_arch, file_ext)
            with mock.patch(
                "basicswap.interface.north.core.platform.machine",
                return_value=machine,
            ):
                assert pm.getArchName(ctx, os_name, True) == arch_name
            filename = pm.getReleaseFilename(ctx, arch_name)
            assert filename == f"truenorth-v30.5.5-{arch_name}.{file_ext}"
            assert (
                pm.getReleaseUrl(ctx, filename)
                == f"https://github.com/truenorth-project/truenorth/releases/download/v30.5.5/{filename}"
            )
            bin_name = "truenorthd.exe" if os_name == "win" else "truenorthd"
            assert (
                pm.getExtractPath(ctx, bin_name, "/x/" + filename, {})
                == f"truenorth-v30.5.5-{arch_name}/bin/{bin_name}"
            )
        assert (
            pm.getAssertUrl(
                make_ctx("x86_64-linux-gnu", "tar.gz"),
                "linux",
                "linux",
                "septentrion-dev",
                True,
            )
            == "https://github.com/truenorth-project/truenorth/releases/download/v30.5.5/SHA256SUMS"
        )
        assert pm.useGuix()  # The signature is SHA256SUMS.asc
        assert pm.getExtractBins() == ["truenorthd", "truenorth-cli"]

    def test_unsupported_platforms(self):
        pm = make_prepare()
        cases = (
            ("aarch64-linux-gnu", "linux", "aarch64"),
            ("arm-linux-gnueabihf", "linux", "armv7l"),
            ("osx64", "osx", "x86_64"),
            ("win32", "win", "x86"),
        )
        for bin_arch, os_name, machine in cases:
            ctx = make_ctx(bin_arch, "tar.gz")
            with mock.patch(
                "basicswap.interface.north.core.platform.machine",
                return_value=machine,
            ):
                with self.assertRaises(ValueError):
                    pm.getArchName(ctx, os_name, True)

    def test_hash_is_bound_to_release_name(self):
        pm = make_prepare()
        ctx = make_ctx("x86_64-linux-gnu", "tar.gz")
        tmp_dir = tempfile.mkdtemp()
        try:
            release_path = os.path.join(
                tmp_dir, "truenorth-v30.5.5-linux-x86_64.tar.gz"
            )
            with open(release_path, "wb") as fp:
                fp.write(b"release")
            release_hash = hashlib.sha256(b"release").hexdigest()
            assert_path = os.path.join(tmp_dir, "SHA256SUMS")

            def write_sums(lines):
                with open(assert_path, "w") as fp:
                    fp.write("".join(line + "\n" for line in lines))

            write_sums(
                [
                    "0" * 64 + "  truenorth-v30.5.5-macos-arm64.tar.gz",
                    release_hash + "  truenorth-v30.5.5-linux-x86_64.tar.gz",
                ]
            )
            assert pm.verifyCoreHash(ctx, release_path, assert_path) == release_hash

            # The signed list of an older release, listing that release's archive
            write_sums([release_hash + "  truenorth-v30.5.4-linux-x86_64.tar.gz"])
            with self.assertRaises(ValueError):
                pm.verifyCoreHash(ctx, release_path, assert_path)

            write_sums(["0" * 64 + "  truenorth-v30.5.5-linux-x86_64.tar.gz"])
            with self.assertRaises(ValueError):
                pm.verifyCoreHash(ctx, release_path, assert_path)
        finally:
            shutil.rmtree(tmp_dir)

    def test_signers(self):
        assert prepare_module.signers == {
            "septentrion-dev": (PRIMARY_KEY, SIGNING_SUBKEY),
        }
        assert prepare_module.getPubkeyFilename("septentrion-dev") == (
            "truenorth_septentrion-dev.pgp"
        )
        key_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "basicswap",
            "pgp",
            "keys",
            "truenorth_septentrion-dev.pgp",
        )
        assert os.path.exists(key_path)
        if shutil.which("gpg") is None:
            return
        import gnupg

        gpg_home = tempfile.mkdtemp()
        try:
            gpg = gnupg.GPG(gnupghome=gpg_home)
            with open(key_path, "rb") as fp:
                rv = gpg.import_keys(fp.read())
            assert rv.fingerprints == [PRIMARY_KEY]
            keys = gpg.list_keys()
            assert len(keys) == 1
            assert keys[0]["fingerprint"] == PRIMARY_KEY
            assert SIGNING_SUBKEY in [s[2] for s in keys[0]["subkeys"]]
        finally:
            shutil.rmtree(gpg_home)

    def test_config(self):
        pm = make_prepare()
        ctx = make_ctx("x86_64-linux-gnu", "tar.gz")
        segment = pm.getConfigSegment(ctx)
        assert segment["blocks_confirmed"] == 100
        assert segment["use_csv"] is True
        assert segment["use_segwit"] is True

        for chain, expect in (
            ("mainnet", ""),
            ("testnet", "testnet4=1\n[testnet4]\n\n"),
            ("regtest", "regtest=1\n[regtest]\n\n"),
        ):
            fp = io.StringIO()
            pm.writeChainSelection(ctx, fp, chain)
            assert fp.getvalue() == expect, chain

        # Other coins keep the testnet3 style lines
        fp = io.StringIO()
        btc_prepare.writeChainSelection(ctx, fp, "testnet")
        assert fp.getvalue() == "testnet=1\n[test]\n\n"

        fp = io.StringIO()
        pm.writeCoinConfig(ctx, fp, "mainnet", "salt", {}, {})
        lines = fp.getvalue().splitlines()
        assert "addresstype=bech32" in lines
        assert "changetype=bech32" in lines

    def test_prepare_data_dir_testnet(self):
        pm = make_prepare()
        tmp_dir = tempfile.mkdtemp()
        try:
            ctx = make_ctx("x86_64-linux-gnu", "tar.gz")
            settings = {
                "chainclients": {
                    "truenorth": {
                        "datadir": tmp_dir,
                        "rpcport": 19954,
                        "wallet_name": "bsx_wallet",
                    }
                }
            }
            pm.prepareDataDir(ctx, settings, "testnet", {})
            with open(os.path.join(tmp_dir, "truenorth.conf")) as fp:
                lines = fp.read().splitlines()
            assert lines[0] == "testnet4=1"
            assert lines[1] == "[testnet4]"
            # Network options only apply inside the network's section
            assert lines.index("rpcport=19954") > 1
            assert "wallet=bsx_wallet" in lines
        finally:
            shutil.rmtree(tmp_dir)

    def test_cli_chain_arg(self):
        app = SimpleNamespace(
            coin_clients={
                c: {"bindir": "/bin", "datadir": "/data"}
                for c in (Coins.NORTH, Coins.BTC)
            }
        )

        def cli_args(coin_type, chain: str) -> list:
            app.chain = chain
            with mock.patch("basicswap.base.subprocess.Popen") as popen:
                popen.return_value.communicate.return_value = (b"7\n", b"")
                assert BaseApp.callcoincli(app, coin_type, "getblockcount") == "7"
            return popen.call_args[0][0]

        assert cli_args(Coins.NORTH, "testnet") == [
            "/bin/truenorth-cli",
            "-testnet4",
            "-datadir=/data",
            "getblockcount",
        ]
        assert cli_args(Coins.NORTH, "regtest")[1] == "-regtest"
        assert cli_args(Coins.NORTH, "mainnet")[1] == "-datadir=/data"
        assert cli_args(Coins.BTC, "testnet")[1] == "-testnet"

    def test_lock_margins(self):
        # The confirmation allowance is blocks_confirmed x blocks_target x 3
        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc._sc_lock_release_min_margin = 3600
        sc._sc_lock_spend_min_margin = 3600
        north = make_timing_ci(100, 120)
        btc = make_timing_ci(1, 600)
        assert sc.getConfirmAllowance(north) == 10 * 3600
        assert sc.getConfirmAllowance(btc) == 1800

        # NORTH as coin A raises the release and spend margins to its allowance
        assert sc.getLockReleaseMinMargin(north) == 10 * 3600
        assert sc.getLockSpendMinMargin(north) == 10 * 3600
        assert sc.getBLockMinMargin(btc, north) == 10 * 3600 + 1800
        # NORTH as coin B
        assert sc.getBLockMinMargin(north, btc) == 3600 + 10 * 3600

        # The settings stay the least margins
        assert sc.getLockReleaseMinMargin(btc) == 3600
        assert sc.getLockSpendMinMargin(btc) == 3600
        assert sc.getBLockMinMargin(btc, btc) == 3600 + 1800
        # Coin A has to be given, there is no fallback to the settings alone
        self.assertRaises(TypeError, sc.getBLockMinMargin, btc)

        # The bid plan's hold check allows 30 minutes for the coin B lock tx,
        # a slower coin B adds the rest of its allowance
        assert sc.getPlanBLockHoldMargin(btc, btc) == 3600
        assert sc.getPlanBLockHoldMargin(btc, north) == 10 * 3600
        assert sc.getPlanBLockHoldMargin(north, btc) == 3600 + 10 * 3600 - 1800
        # A held secret hash leg keeps both allowances on top of half its lock
        part = make_timing_ci(2, 120)
        ltc = make_timing_ci(2, 150)
        assert sc.getPlanPTxHoldMargin(part, ltc) == 1800
        assert sc.getPlanPTxHoldMargin(btc, btc) == 3600
        assert sc.getPlanPTxHoldMargin(north, part) == 10 * 3600 + 720

        sc._sc_lock_spend_min_margin = 12 * 3600
        assert sc.getLockSpendMinMargin(north) == 12 * 3600
        assert sc.getBLockMinMargin(btc, north) == 12 * 3600 + 1800

    def test_ptx_redeem_margin(self):
        # The seller doesn't reveal the secret with less than the coin's
        # confirmation allowance left on the participate txn refund timelock,
        # a reorg could swap the redeem for the refund
        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc.log = BSXLogger("test")
        north = make_timing_ci(100, 120)
        lock = {"remaining": None, "args": None}

        def csv_lock_remaining(lock_type, sequence, height, block_time):
            lock["args"] = (lock_type, sequence, height, block_time)
            return lock["remaining"]

        north.coin_type = lambda: Coins.NORTH
        north.coin_name = lambda: "TrueNorth"
        north.getExpectedSequence = lambda lock_type, lock_value: lock_value
        north.csvLockRemaining = csv_lock_remaining
        sc.ci = lambda coin_type: north
        published, events = [], []
        sc.createRedeemTxn = lambda coin_type, bid: "00"
        sc.publishRedeemTxn = lambda ci, bid, tx_type, txn: (
            published.append(tx_type) or SwapTx(bid_id=bid.bid_id, txid=bytes(32))
        )
        sc.logEvent = lambda concept, linked_id, event_type, msg, cursor: (
            events.append(event_type)
        )
        offer = SimpleNamespace(
            coin_to=Coins.NORTH,
            lock_type=TxLockTypes.SEQUENCE_LOCK_TIME,
            lock_value=48 * 3600,
        )

        def confirm(remaining):
            lock["remaining"] = remaining
            published.clear()
            events.clear()
            bid = Bid(bid_id=bytes(28), was_received=True)
            bid.participate_tx = SwapTx(
                bid_id=bid.bid_id,
                tx_type=int(TxTypes.PTX),
                block_height=1000,
                block_time=1800000000,
            )
            sc.participateTxnConfirmed(bid.bid_id, bid, offer)
            assert bid.state == int(BidStates.SWAP_PARTICIPATING)

        confirm(10 * 3600)
        assert published == [TxTypes.PTX_REDEEM]
        # The participate txn refund is locked for half the lock value
        assert lock["args"] == (
            TxLockTypes.SEQUENCE_LOCK_TIME,
            24 * 3600,
            1000,
            1800000000,
        )
        confirm(10 * 3600 - 1)
        assert published == []
        assert events == [EventLogTypes.PTX_REDEEM_ABANDONED_LOCK_CLOSE]
        # Unknown, as before
        confirm(None)
        assert published == [TxTypes.PTX_REDEEM]

    def test_offer_lock_value_fits(self):
        # Offers whose lock time the margin checks would refuse even with every
        # txn confirmed at once are refused when made or received
        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc._sc_lock_release_min_margin = 3600
        sc._sc_lock_spend_min_margin = 3600
        cis = {
            Coins.NORTH: make_timing_ci(100, 120),
            Coins.BTC: make_timing_ci(1, 600),
            Coins.BCH: make_timing_ci(1, 600),
            Coins.PART: make_timing_ci(2, 120),
            Coins.LTC: make_timing_ci(2, 150),
            Coins.DCR: make_timing_ci(2, 300),
            Coins.XMR: make_timing_ci(3, 120),
        }
        sc.ci = lambda coin_type: cis[coin_type]
        sc.scriptless_coins = (Coins.XMR,)
        sc.coins_without_segwit = ()
        ads, sh = SwapTypes.XMR_SWAP, SwapTypes.SELLER_FIRST
        time_lock = TxLockTypes.SEQUENCE_LOCK_TIME

        def fits(swap_type, coin_from, coin_to, lock_value, lock_type=time_lock):
            try:
                sc.ensureOfferLockValueFits(
                    swap_type, coin_from, coin_to, lock_type, lock_value
                )
            except ValueError:
                return False
            return True

        # Nothing changes for the other coins at the two hour minimum, except
        # secret hash between two coins with a 30 minute allowance:
        # ensurePTxLockMargin refuses those on every try
        for coin_from, coin_to in (
            (Coins.BTC, Coins.XMR),
            (Coins.XMR, Coins.BTC),
            (Coins.LTC, Coins.XMR),
            (Coins.DCR, Coins.BTC),
            (Coins.PART, Coins.LTC),
        ):
            assert fits(ads, coin_from, coin_to, 2 * 3600)
        for coin_from, coin_to in (
            (Coins.PART, Coins.BTC),
            (Coins.BTC, Coins.LTC),
            (Coins.LTC, Coins.DCR),
        ):
            assert fits(sh, coin_from, coin_to, 2 * 3600)
        assert not fits(sh, Coins.BTC, Coins.BCH, 2 * 3600)
        assert not fits(sh, Coins.DCR, Coins.BTC, 2 * 3600)
        assert fits(sh, Coins.BTC, Coins.BCH, 2 * 3600 + 1)

        # NORTH as coin A, then as coin B, then a reverse bid with NORTH as A
        needed = 10 * 3600 + 1080
        assert not fits(ads, Coins.NORTH, Coins.XMR, needed - 1)
        assert fits(ads, Coins.NORTH, Coins.XMR, needed)
        needed = 3600 + 10 * 3600
        assert not fits(ads, Coins.BTC, Coins.NORTH, needed - 1)
        assert fits(ads, Coins.BTC, Coins.NORTH, needed)
        assert not fits(ads, Coins.XMR, Coins.NORTH, 10 * 3600)
        assert fits(ads, Coins.XMR, Coins.NORTH, 24 * 3600)
        # Secret hash, either way
        needed = 2 * (10 * 3600 + 720) + 1
        assert not fits(sh, Coins.NORTH, Coins.PART, needed - 1)
        assert fits(sh, Coins.NORTH, Coins.PART, needed)
        assert not fits(sh, Coins.BTC, Coins.NORTH, 2 * (1800 + 10 * 3600))
        assert fits(sh, Coins.BTC, Coins.NORTH, 30 * 3600)
        # Block count locks are left alone
        assert fits(sh, Coins.NORTH, Coins.PART, 20, TxLockTypes.SEQUENCE_LOCK_BLOCKS)

    def make_adaptor_client(self, lock_remaining: int):
        # NORTH as coin A, XMR as coin B, lock_remaining seconds left on the
        # coin A refund timelock.  Proceeded is raised past the margin check.
        class Proceeded(Exception):
            pass

        def proceeded(*args, **kwargs):
            raise Proceeded()

        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc.log = BSXLogger("test")
        sc._sc_lock_release_min_margin = 3600
        sc._sc_lock_spend_min_margin = 3600
        north = make_timing_ci(100, 120)
        north.csvLockRemaining = lambda *args: lock_remaining
        xmr = make_timing_ci(3, 120)
        xmr.curve_type = proceeded
        cis = {Coins.NORTH: north, Coins.XMR: xmr}
        sc.ci = lambda coin_type: cis[coin_type]
        bid = SimpleNamespace(
            bid_id=bytes(28),
            offer_id=bytes(28),
            txns={},
            was_sent=False,
            was_received=True,
            xmr_a_lock_tx=SimpleNamespace(block_height=1000, block_time=1800000000),
            xmr_a_lock_spend_tx=None,
        )
        offer = SimpleNamespace(
            coin_from=Coins.NORTH,
            coin_to=Coins.XMR,
            lock_type=TxLockTypes.SEQUENCE_LOCK_TIME,
        )
        xmr_offer = SimpleNamespace(lock_time_1=24 * 3600)
        sc.getXmrBidFromSession = lambda cursor, bid_id: (bid, SimpleNamespace())
        sc.getXmrOfferFromSession = lambda cursor, offer_id: (offer, xmr_offer)
        sc.is_reverse_ads_bid = lambda coin_from, coin_to: False
        sc.findTxB = proceeded
        events = []
        sc.logBidEvent = lambda bid_id, event_type, msg, cursor: events.append(
            event_type
        )
        return sc, events, Proceeded

    def test_lock_release_and_spend_margins(self):
        # With NORTH as coin A the leader releases the lock tx secret, and the
        # follower spends the coin A lock, only with 10 hours left on the coin
        # A refund timelock
        for method, event in (
            (
                BasicSwap.sendXmrBidLockRelease,
                EventLogTypes.LOCK_RELEASE_ABANDONED_LOCK_CLOSE,
            ),
            (
                BasicSwap.redeemXmrBidCoinALockTx,
                EventLogTypes.LOCK_SPEND_ABANDONED_LOCK_CLOSE,
            ),
        ):
            sc, events, proceeded = self.make_adaptor_client(10 * 3600 - 1)
            method(sc, bytes(28), None)
            assert events == [event], method.__name__
            sc, events, proceeded = self.make_adaptor_client(10 * 3600)
            with self.assertRaises(proceeded):
                method(sc, bytes(28), None)
            assert events == [], method.__name__

    def test_mercy_watch_timeout(self):
        # The swiper sends the mercy tx once the swipe tx is blocks_confirmed deep
        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc._mercy_watch_timeout_blocks = 100
        assert sc.getMercyWatchTimeoutBlocks(make_timing_ci(100, 120)) == 200
        assert sc.getMercyWatchTimeoutBlocks(make_timing_ci(1, 600)) == 100
        sc._mercy_watch_timeout_blocks = 6
        assert sc.getMercyWatchTimeoutBlocks(make_timing_ci(1, 600)) == 6
        assert sc.getMercyWatchTimeoutBlocks(make_timing_ci(100, 120)) == 200

    def test_mercy_give_up(self):
        # The leader watches for a mercy tx, and the follower tries to send it,
        # for twice blocks_confirmed with NORTH as coin A
        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc.log = BSXLogger("test")
        sc._mercy_watch_timeout_blocks = 100
        events = []
        sc.logBidEvent = lambda bid_id, event_type, msg, cursor: events.append(
            event_type
        )
        sc.removeWatchedOutput = lambda *args: None
        sc._unlockMercyPrevout = lambda *args: None
        sc.removeQueuedActions = lambda *args: None
        sc._recoverSwipePayout = lambda *args: None
        sc.countQueuedActions = lambda *args: 1
        height = {"value": 0}
        north = make_timing_ci(100, 120)
        north.getChainHeight = lambda: height["value"]
        north.coin_type = lambda: Coins.NORTH

        def check(method, blocks: int) -> bool:
            height["value"] = 1000 + blocks
            bid = Bid(bid_id=bytes(28), state=int(BidStates.XMR_SWAP_FAILED))
            bid.txns = {
                TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE: SwapTx(
                    bid_id=bid.bid_id,
                    tx_type=int(TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE),
                    txid=bytes(32),
                    chain_height=1000,
                )
            }
            if method == "watch":
                changed = sc._checkMercyWatch(north, bid, None)
            else:
                changed = sc._checkMercySend(north, bid, None, None, None)
            assert changed == (bid.state == int(BidStates.XMR_SWAP_FAILED_SWIPED))
            return changed

        assert not check("watch", 199)
        assert check("watch", 200)
        assert events == [EventLogTypes.MERCY_TX_NOT_FOUND]
        events.clear()
        assert not check("send", 199)
        assert check("send", 200)
        assert events == [EventLogTypes.MERCY_TX_NOT_SENT]

    def test_accepted_bid_timeout(self):
        # 100 confirmations take longer than sc_lock_tx_timeout, a bid gets
        # sc_lock_tx_mempool_timeout once its coin A tx is seen
        sc = DBMethods()
        sc.sqlite_file = ":memory:"
        sc.mxDB = threading.RLock()
        sc.log = BSXLogger("test")
        now: int = 1800000000
        sc.getTime = lambda: now
        sc._is_locked = False
        sc._sc_lock_tx_timeout = 1200
        sc._sc_lock_tx_mempool_timeout = 12 * 3600
        timed_out = []
        sc.timeoutBid = lambda bid_id, cursor: timed_out.append(bid_id)
        state_time: int = now - 2 * 3600

        cursor = sc.openDB()
        try:
            create_db_(sc._db_con, logging.getLogger())
            addBidState(sc, BidStates.BID_ACCEPTED, now, cursor)
            addBidState(sc, BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS, now, cursor)

            def add_bid(
                n: int,
                tx_type=None,
                block_height=None,
                in_mempool=False,
                state=BidStates.BID_ACCEPTED,
                event_type=None,
            ):
                bid_id = bytes([n]) * 28
                sc.add(
                    Bid(
                        bid_id=bid_id,
                        active_ind=1,
                        state=int(state),
                        state_time=state_time,
                    ),
                    cursor,
                )
                if tx_type is not None:
                    sc.add(
                        SwapTx(
                            bid_id=bid_id,
                            tx_type=int(tx_type),
                            txid=bytes(32),
                            block_height=block_height,
                        ),
                        cursor,
                    )
                if in_mempool:
                    event_type = EventLogTypes.LOCK_TX_A_IN_MEMPOOL
                if event_type is not None:
                    sc.add(
                        EventLog(
                            active_ind=1,
                            created_at=state_time,
                            linked_type=int(Concepts.BID),
                            linked_id=bid_id,
                            event_type=int(event_type),
                        ),
                        cursor,
                    )
                return bid_id

            unseen = add_bid(1)
            lock_tx_unmined = add_bid(2, TxTypes.XMR_SWAP_A_LOCK)
            add_bid(3, in_mempool=True)
            add_bid(4, TxTypes.XMR_SWAP_A_LOCK, block_height=200)
            add_bid(5, TxTypes.ITX, block_height=200)
            # The other states a bid can time out in
            sigs = BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS
            add_bid(6, TxTypes.XMR_SWAP_A_LOCK, block_height=200, state=sigs)
            sigs_unseen = add_bid(7, state=sigs)
            # The side that sent the coin A lock tx doesn't time out waiting for it
            add_bid(8, event_type=EventLogTypes.LOCK_TX_A_PUBLISHED)

            BasicSwap.checkAcceptedBids(sc)
            assert sorted(timed_out) == [unseen, lock_tx_unmined, sigs_unseen]

            timed_out.clear()
            now += 12 * 3600
            BasicSwap.checkAcceptedBids(sc)
            assert len(timed_out) == 7
            assert bytes([8]) * 28 not in timed_out
        finally:
            sc.closeDB(cursor)

    def test_rates_without_source(self):
        sc = BasicSwap.__new__(BasicSwap)
        sc.fp = None
        sc.log = BSXLogger("test")
        sc.debug_logs = False
        sc.ci = lambda coin_type: SimpleNamespace(
            chainparams=lambda: chainparams[coin_type]
        )
        sc.getRateSources = lambda: [("coingecko.com", "CoinGecko", True)]
        sc.lookupFiatRates = mock.Mock(return_value={})
        rv = BasicSwap.lookupRates(sc, Coins.PART, Coins.NORTH)
        assert rv == {"oracle_error": "No rate source lists NORTH"}
        sc.lookupFiatRates.assert_not_called()


if __name__ == "__main__":
    unittest.main()
