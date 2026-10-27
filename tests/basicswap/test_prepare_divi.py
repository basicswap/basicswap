#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Tests for the Divi prepare module: the IronDivi release, rpc credentials and
wallet seeding.

export PYTHONPATH=$(pwd)
pytest -v tests/basicswap/test_prepare_divi.py
"""

import hashlib
import io
import logging
import os
import shutil
import tarfile
import tempfile
import unittest
import unittest.mock

from basicswap.contrib.mnemonic import Mnemonic
from basicswap.interface.divi import core as divi_core
from basicswap.interface.prepare_util import PrepareContext


class FakeSwapClient:
    def __init__(self, key: bytes):
        self.key = key
        self.rpc_waits = 0

    def getWalletKey(self, coin_id, key_num):
        assert key_num == 1
        return self.key

    def waitForDaemonRPC(self, coin_id, with_wallet=True):
        self.rpc_waits += 1


class TestDiviPrepare(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.ctx = PrepareContext(
            data_dir=self.tmp_dir,
            bin_dir=os.path.join(self.tmp_dir, "bin"),
            port_offset=0,
            should_manage_daemon=lambda ticker: True,
            logger=logging.getLogger(__name__),
            bin_arch="x86_64-linux-gnu",
        )
        self.module = divi_core.DIVIPrepare(
            name="divi",
            ticker="DIVI",
            version="0.2.7",
            version_tag="",
            signers=divi_core.divi_signers,
            reseed_note=True,
            creates_wallet=True,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir)

    def writeConf(self, segment: dict) -> str:
        os.makedirs(segment["datadir"], exist_ok=True)
        conf_path = os.path.join(segment["datadir"], "divi.conf")
        settings = {"chainclients": {"divi": segment}}
        with open(conf_path, "w") as fp:
            self.module.writeCoinConfig(self.ctx, fp, "regtest", "salt", settings, {})
        return conf_path

    def test_release_arch_names(self):
        for bin_arch, arch_name in (
            ("x86_64-linux-gnu", "x86_64-linux-gnu"),
            ("aarch64-linux-gnu", "aarch64-linux-gnu"),
            ("arm-linux-gnueabihf", "armv7-linux-gnueabihf"),
            ("ppc64le-linux-gnu", "powerpc64le-linux-gnu"),
        ):
            self.ctx.bin_arch = bin_arch
            assert self.module.getArchName(self.ctx, "linux", False) == arch_name
        for machine, arch_name in (
            ("arm64", "aarch64-macos"),
            ("x86_64", "x86_64-macos"),
        ):
            with unittest.mock.patch.object(
                divi_core.platform, "machine", return_value=machine
            ):
                assert self.module.getArchName(self.ctx, "osx", False) == arch_name
        with self.assertRaises(ValueError):
            self.module.getArchName(self.ctx, "win", False)
        self.ctx.bin_arch = "mips-linux-gnu"
        with self.assertRaises(ValueError):
            self.module.getArchName(self.ctx, "linux", False)

    def test_release_url(self):
        filename = self.module.getReleaseFilename(self.ctx, "x86_64-linux-gnu")
        assert filename == "irondivi-x86_64-linux-gnu.tar.gz"
        assert self.module.getReleaseUrl(self.ctx, filename) == (
            "https://github.com/DiviDomains/IronDivi/releases/download/"
            "v0.2.7/irondivi-x86_64-linux-gnu.tar.gz"
        )

    def writeRelease(self) -> str:
        # Laid out as an IronDivi release archive.
        release_path = os.path.join(self.tmp_dir, "irondivi-x86_64-linux-gnu.tar.gz")
        with tarfile.open(release_path, "w:gz") as ft:
            for name in ("irondivid", "irondivi-cli", "LICENSE"):
                data = name.encode()
                info = tarfile.TarInfo("irondivi-x86_64-linux-gnu/" + name)
                info.size = len(data)
                ft.addfile(info, io.BytesIO(data))
        return release_path

    def test_extract_renames_binaries(self):
        bin_dir = os.path.join(self.tmp_dir, "bin")
        os.makedirs(bin_dir)
        self.module.extractCore(self.ctx, bin_dir, self.writeRelease(), {})
        assert sorted(os.listdir(bin_dir)) == ["divi-cli", "divid"]
        with open(os.path.join(bin_dir, "divid"), "rb") as fp:
            assert fp.read() == b"irondivid"

    def test_release_hash_in_sums(self):
        release_path = self.writeRelease()
        with open(release_path, "rb") as fp:
            release_hash = hashlib.sha256(fp.read()).hexdigest()
        sums_path = os.path.join(self.tmp_dir, "SHA256SUMS")
        with open(sums_path, "w") as fp:
            fp.write(f"{release_hash}  irondivi-x86_64-linux-gnu.tar.gz\n")
        assert (
            self.module.verifyCoreHash(self.ctx, release_path, sums_path)
            == release_hash
        )
        with open(sums_path, "w") as fp:
            fp.write("00" * 32 + "  irondivi-x86_64-linux-gnu.tar.gz\n")
        with self.assertRaises(ValueError):
            self.module.verifyCoreHash(self.ctx, release_path, sums_path)

    def test_signature_by_unlisted_key_refused(self):
        result = unittest.mock.Mock(valid=True, fingerprint="AB" * 20, key_id="AB" * 8)
        with self.assertRaises(ValueError):
            self.module.ensureValidSignatureBy(
                self.ctx, result, "irondivi_builder", filepath="SHA256SUMS"
            )

    def test_generated_rpc_credentials(self):
        # divid has no cookie auth and no rpcauth, so credentials must exist
        # in both basicswap.json and divi.conf even when none are given.
        segment = self.module.getConfigSegment(self.ctx)
        assert segment["rpcuser"] != ""
        assert len(segment["rpcpassword"]) >= 24
        other = self.module.getConfigSegment(self.ctx)
        assert other["rpcpassword"] != segment["rpcpassword"]

        with open(self.writeConf(segment)) as fp:
            lines = fp.read().splitlines()
        assert "addressindex=1" in lines
        assert "txindex=1" in lines
        assert "rpcuser={}".format(segment["rpcuser"]) in lines
        assert "rpcpassword={}".format(segment["rpcpassword"]) in lines
        assert not any(line.startswith("rpcauth=") for line in lines)

    def test_given_rpc_credentials(self):
        self.module.rpc_user = "someuser"
        self.module.rpc_password = "somepassword"
        segment = self.module.getConfigSegment(self.ctx)
        assert segment["rpcuser"] == "someuser"
        assert segment["rpcpassword"] == "somepassword"

    def test_seed_through_pipe(self):
        segment = self.module.getConfigSegment(self.ctx)
        conf_path = self.writeConf(segment)
        with open(conf_path) as fp:
            conf_before = fp.read()
        key = bytes(range(32))
        swap_client = FakeSwapClient(key)

        args = self.module.getWalletInitDaemonArgs(self.ctx, swap_client, None, segment)
        # Nothing secret on the daemon command line, nothing secret on disk.
        fds = self.module.getWalletInitDaemonPassFds()
        assert len(fds) == 1
        assert args == ["-conf=/dev/fd/{}".format(fds[0])]
        with open(conf_path) as fp:
            assert fp.read() == conf_before

        # The pipe holds the whole conf plus the mnemonic line.
        piped = os.read(fds[0], 1 << 16).decode()
        lines = piped.splitlines()
        expect = "mnemonic={}".format(Mnemonic("english").to_mnemonic(key))
        assert lines.count(expect) == 1
        assert piped.startswith(conf_before)

        self.module.ensureWallet(self.ctx, swap_client, None, segment)
        assert swap_client.rpc_waits == 1
        assert self.module.getWalletInitDaemonPassFds() == ()
        with self.assertRaises(OSError):
            os.fstat(fds[0])

        # The backstop is harmless once the fd is closed.
        assert self.module.getPostInitWarning(self.ctx) is None
        with open(conf_path) as fp:
            assert fp.read() == conf_before

    def test_seed_backstop(self):
        segment = self.module.getConfigSegment(self.ctx)
        self.writeConf(segment)
        self.module.getWalletInitDaemonArgs(
            self.ctx, FakeSwapClient(bytes(32)), None, segment
        )
        (fd,) = self.module.getWalletInitDaemonPassFds()
        self.module.getPostInitWarning(self.ctx)
        assert self.module.getWalletInitDaemonPassFds() == ()
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_seed_config_filename_refused(self):
        segment = self.module.getConfigSegment(self.ctx)
        segment["config_filename"] = "other.conf"
        with self.assertRaises(ValueError):
            self.module.getWalletInitDaemonArgs(
                self.ctx, FakeSwapClient(bytes(32)), None, segment
            )

    def test_seed_refused_without_dev_fd(self):
        segment = self.module.getConfigSegment(self.ctx)
        conf_path = self.writeConf(segment)
        with open(conf_path) as fp:
            conf_before = fp.read()
        with unittest.mock.patch.object(divi_core.os, "name", "nt"):
            with self.assertRaises(ValueError):
                self.module.getWalletInitDaemonArgs(
                    self.ctx, FakeSwapClient(bytes(32)), None, segment
                )
        assert self.module.getWalletInitDaemonPassFds() == ()
        with open(conf_path) as fp:
            assert fp.read() == conf_before

    def test_password_change_still_runs(self):
        # creates_wallet is set only to reach ensureWallet; the wallet is
        # created unencrypted and must still be encrypted afterwards.
        assert self.module.needsPostInitPasswordChange()
        assert divi_core.prepare_module.creates_wallet


if __name__ == "__main__":
    unittest.main()
