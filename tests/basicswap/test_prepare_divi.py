#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Tests for the Divi prepare module: rpc credentials and wallet seeding.

export PYTHONPATH=$(pwd)
pytest -v tests/basicswap/test_prepare_divi.py
"""

import logging
import os
import shutil
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
        )
        self.module = divi_core.DIVIPrepare(
            name="divi",
            ticker="DIVI",
            version="3.0.0",
            version_tag="",
            signers={divi_core.DIVI_NO_SIGNER: ()},
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
