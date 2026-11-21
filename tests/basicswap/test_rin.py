#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Rincoin checks that need no daemon.

pytest -v tests/basicswap/test_rin.py
"""

import hashlib
import os
import tempfile
import unittest

from basicswap.base import BaseApp
from basicswap.chainparams import Coins, chainparams, getCoinIdFromName
from basicswap.contrib.test_framework import segwit_addr
from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    StrictBytesIO,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_EQUAL,
    OP_HASH160,
)
from basicswap.interface.prepare_util import PrepareContext
from basicswap.interface.rin.core import RINPrepare, prepare_module
from basicswap.interface.rin.rin import RIN_FORK_TX_VERSION, RINInterface
from basicswap.util.address import encodeAddress
from basicswap.util.logging import BSXLogger
from tests.basicswap.util.common import REQUIRED_SETTINGS

SIGNING_SUBKEY = "0ED99C46B2192E375381EF4AC5BEF8A9FA06C16F"
PRIMARY_KEY = "ED20B6354EE4526D01F83B538B6E3BF45C714ECA"


class FakeSwapClient:
    # An interface for mainnet or testnet reads its fee settings from the
    # swap client, BaseApp can't be instantiated without a datadir.
    getBaseAltruistic = BaseApp.getBaseAltruistic

    def __init__(self):
        self.settings = {"chainclients": {}}
        self.log = BSXLogger("test")

    def getChainClientSettings(self, coin):
        return {}


def make_ci(network: str = "regtest") -> RINInterface:
    coin_settings = {"rpcport": 0, "rpcauth": "none"}
    coin_settings.update(REQUIRED_SETTINGS)
    swap_client = None if network == "regtest" else FakeSwapClient()
    ci = RINInterface(coin_settings, network, swap_client=swap_client)
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
        **kwargs,
    )


def make_prepare(version_tag: str) -> RINPrepare:
    return RINPrepare(
        name="rincoin",
        ticker="RIN",
        version="1.1.0",
        version_tag=version_tag,
        signers=prepare_module.signers,
    )


class Test(unittest.TestCase):

    def test_chainparams(self):
        assert Coins.RIN == 19
        assert getCoinIdFromName("rincoin") == Coins.RIN
        params = chainparams[Coins.RIN]
        assert params["ticker"] == "RIN"
        assert params["message_magic"] == "rincoin Signed Message:\n"
        assert params["blocks_target"] == 60
        assert params["mainnet"]["hrp"] == "rin"
        assert params["mainnet"]["bip44"] == 9555
        assert params["testnet"]["name"] == "testnet4"
        assert params["regtest"]["hrp"] == "rrin"

    def test_tx_version(self):
        assert RIN_FORK_TX_VERSION == 1380535859
        assert RINInterface.txVersion() == RIN_FORK_TX_VERSION
        assert bytes.fromhex("52494e33") == RIN_FORK_TX_VERSION.to_bytes(4, "big")

    def test_max_money(self):
        ci = make_ci()
        assert ci.max_money() == 168000000 * ci.COIN()

    def test_refuses_witness_v1(self):
        ci = make_ci()
        hrp = ci.chainparams_network()["hrp"]
        v0 = segwit_addr.encode_segwit_address(hrp, 0, bytes(range(20)))
        assert ci.decodeAddress(v0) == bytes(range(20))
        taproot = segwit_addr.encode_segwit_address(hrp, 1, bytes(range(32)))
        with self.assertRaises(ValueError):
            ci.getDestForAddress(taproot)
        ci.rpc_wallet = lambda method, params=None: {"isvalid": True}
        assert ci.isValidAddress(v0) is True
        assert ci.isValidAddress(taproot) is False

    def test_min_core_version(self):
        ci = make_ci()
        ci.rpc = lambda method, params=None, timeout=None: {"version": 1010000}
        assert ci.getDaemonVersion() == 1010000
        # v1.0.6 refuses transactions with the RIN3 version as non-standard
        ci = make_ci()
        ci.rpc = lambda method, params=None, timeout=None: {"version": 1000600}
        with self.assertRaises(ValueError):
            ci.getDaemonVersion()
        ci = make_ci()
        ci.rpc = lambda method, params=None, timeout=None: {"version": 1009999}
        with self.assertRaises(ValueError):
            ci.getDaemonVersion()

    def test_script_address2_is_p2sh(self):
        for network in ("mainnet", "testnet", "regtest"):
            ci = make_ci(network)
            prefix = ci.chainparams_network()["script_address2"]
            script_hash = bytes(range(20))
            address = encodeAddress(bytes((prefix,)) + script_hash)
            assert ci.getDestForAddress(address) == CScript(
                [OP_HASH160, script_hash, OP_EQUAL]
            )

    def test_funded_tx_carries_rin3(self):
        ci = make_ci()
        hrp = ci.chainparams_network()["hrp"]
        addr_to = segwit_addr.encode_segwit_address(hrp, 0, bytes(range(20)))
        calls = []

        def fund(version_after_funding):
            def rpc_wallet(method, params=None):
                calls.append((method, params))
                tx = CTransaction()
                tx.deserialize(StrictBytesIO(bytes.fromhex(params[0])), False)
                tx.vin.append(CTxIn(COutPoint(1, 0)))
                if version_after_funding is not None:
                    tx.nVersion = version_after_funding
                return {"hex": tx.serialize().hex()}

            return rpc_wallet

        ci.rpc_wallet = fund(None)
        funded_hex = ci.createRawFundedTransaction(addr_to, 100000, feerate=1000)
        method, params = calls[-1]
        assert method == "fundrawtransaction"
        sent = CTransaction()
        sent.deserialize(StrictBytesIO(bytes.fromhex(params[0])), False)
        assert sent.nVersion == RIN_FORK_TX_VERSION
        assert sent.vout[0].nValue == 100000
        assert sent.vout[0].scriptPubKey == ci.getDestForAddress(addr_to)
        assert params[1] == {"lockUnspents": True, "feeRate": ci.format_amount(1000)}
        assert ci.loadTx(bytes.fromhex(funded_hex)).nVersion == RIN_FORK_TX_VERSION

        # The change address of a preview is passed on.
        ci.createRawFundedTransaction(
            addr_to, 100000, feerate=1000, change_addr=addr_to
        )
        assert calls[-1][1][1]["changeAddress"] == addr_to

        # Both protocol callers pass sub_fee and lock_unspents.
        ci.createRawFundedTransaction(
            addr_to, 100000, True, lock_unspents=False, feerate=1000
        )
        assert calls[-1][1][1] == {
            "lockUnspents": False,
            "feeRate": ci.format_amount(1000),
            "subtractFeeFromOutputs": [0],
        }

        # An estimated rate above the configured maximum is refused.
        ci._high_feerate = 1000000
        ci.get_fee_rate = lambda conf_target=2: (0.02, "estimatesmartfee")
        with self.assertRaises(ValueError):
            ci.createRawFundedTransaction(addr_to, 100000)
        ci.get_fee_rate = lambda conf_target=2: (0.0002, "estimatesmartfee")
        ci.createRawFundedTransaction(addr_to, 100000)
        assert calls[-1][1][1]["feeRate"] == 0.0002

        # A node that drops the version must not produce a transaction.
        ci.rpc_wallet = fund(2)
        with self.assertRaises(ValueError):
            ci.createRawFundedTransaction(addr_to, 100000, feerate=1000)

    def test_release_names(self):
        rc = make_prepare("rc3")
        final = make_prepare("")
        base = "https://github.com/Rin-coin/rincoin/releases/download"

        ctx = make_ctx("x86_64-linux-gnu", "tar.gz")
        name = rc.getReleaseFilename(ctx, ctx.bin_arch)
        assert name == "rincoin-1.1.0rc3-x86_64-linux-gnu.tar.gz"
        assert rc.getReleaseUrl(ctx, name) == f"{base}/v1.1.0-rc3/{name}"
        assert rc.getAssertUrl(ctx, "linux", "linux", "aevust", False) == (
            f"{base}/v1.1.0-rc3/SHA256SUMS"
        )

        ctx = make_ctx("win64", "zip")
        name = final.getReleaseFilename(ctx, ctx.bin_arch)
        assert name == "rincoin-1.1.0-win64.zip"
        assert final.getReleaseUrl(ctx, name) == f"{base}/v1.1.0/{name}"
        assert final.getAssertUrl(ctx, "linux", "linux", "aevust", False) == (
            f"{base}/v1.1.0/SHA256SUMS"
        )

        ctx = make_ctx("aarch64-linux-gnu", "tar.gz")
        assert final.getReleaseFilename(ctx, ctx.bin_arch) == (
            "rincoin-1.1.0-aarch64-linux-gnu.tar.gz"
        )

        for bin_arch in ("osx64", "arm-linux-gnueabihf"):
            ctx = make_ctx(bin_arch, "tar.gz")
            with self.assertRaises(ValueError):
                final.getReleaseFilename(ctx, bin_arch)

        assert final.getExtractPath(ctx, "rincoind", "", {}) == "bin/rincoind"

    def test_download_names(self):
        urls = []
        with tempfile.TemporaryDirectory() as bin_dir:
            ctx = make_ctx(
                "x86_64-linux-gnu",
                "tar.gz",
                download_release=lambda url, path, extra_opts: urls.append(url),
                download_file=lambda url, path: urls.append(url),
            )
            release_path, assert_path, sig_path = make_prepare("rc3").downloadCore(
                ctx, bin_dir, "aevust", {}
            )
        assert os.path.basename(release_path) == (
            "rincoin-1.1.0rc3-x86_64-linux-gnu.tar.gz"
        )
        assert os.path.basename(assert_path) == "rincoin-1.1.0rc3-SHA256SUMS"
        assert sig_path == assert_path + ".asc"
        assert urls[1].endswith("/v1.1.0-rc3/SHA256SUMS")
        assert urls[2].endswith("/v1.1.0-rc3/SHA256SUMS.asc")

        # A platform without a release stops before any download.
        with self.assertRaises(ValueError):
            make_prepare("").downloadCore(make_ctx("osx64", "tar.gz"), "", "aevust", {})

    def test_hash_is_bound_to_release_name(self):
        rc = make_prepare("rc3")
        ctx = make_ctx("x86_64-linux-gnu", "tar.gz", logger=BSXLogger("test"))
        name = rc.getReleaseFilename(ctx, ctx.bin_arch)
        with tempfile.TemporaryDirectory() as bin_dir:
            release_path = os.path.join(bin_dir, name)
            assert_path = os.path.join(bin_dir, "rincoin-1.1.0rc3-SHA256SUMS")
            with open(release_path, "wb") as fp:
                fp.write(b"release")
            release_hash = hashlib.sha256(b"release").hexdigest()
            with open(assert_path, "w") as fp:
                fp.write(f"{release_hash} *{name}\n")
            assert rc.verifyCoreHash(ctx, release_path, assert_path) == release_hash
            # The SHA256SUMS of another release lists the hash under its own name.
            with open(assert_path, "w") as fp:
                fp.write(f"{release_hash} *{name.replace('rc3', 'rc1')}\n")
            with self.assertRaises(ValueError):
                rc.verifyCoreHash(ctx, release_path, assert_path)
            # The hash under another name, this name with another hash.
            with open(assert_path, "w") as fp:
                fp.write(f"{release_hash} *{name.replace('rc3', 'rc1')}\n")
                fp.write(f"{'0' * 64} *{name}\n")
            with self.assertRaises(ValueError):
                rc.verifyCoreHash(ctx, release_path, assert_path)

    def test_signers(self):
        assert prepare_module.signers == {"aevust": (SIGNING_SUBKEY, PRIMARY_KEY)}
        assert prepare_module.getPubkeyUrls(None)[0].endswith(PRIMARY_KEY)
        pubkey_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "basicswap",
            "pgp",
            "keys",
            prepare_module.getPubkeyFilename("aevust"),
        )
        assert os.path.exists(pubkey_path)


if __name__ == "__main__":
    unittest.main()
