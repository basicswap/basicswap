#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Migrate legacy Bitcoin Core wallets made by basicswap-prepare on Core 29.x to
descriptor wallets on the current Core release.

export TEST_BIN_PATH=~/tmp/bsx_bins
basicswap-prepare --preparebinonly --bindir=${TEST_BIN_PATH} --withcoins=bitcoin
export TEST_BTC_LEGACY_BIN_PATH=~/tmp/bsx_bins_btc29
export TEST_BTC_LEGACY_VERSION=29.4
BITCOIN_VERSION=${TEST_BTC_LEGACY_VERSION} basicswap-prepare --preparebinonly --bindir=${TEST_BTC_LEGACY_BIN_PATH} --withcoins=bitcoin

python tests/basicswap/extended/test_btc_wallet_migration.py

"""

import json
import logging
import multiprocessing
import os
import shutil
import subprocess
import sys
import threading
import unittest

from unittest.mock import patch

from coincurve.keys import PrivateKey

from basicswap.contrib.test_framework.segwit_addr import encode_segwit_address
from basicswap.rpc import escape_rpcauth, make_rpc_func
from basicswap.util.crypto import hash160, sha256
from tests.basicswap.util.common import (
    read_json_api,
    waitForServer,
)

bin_path = os.path.expanduser(os.getenv("TEST_BIN_PATH", ""))
legacy_bin_path = os.path.expanduser(os.getenv("TEST_BTC_LEGACY_BIN_PATH", ""))
legacy_version = os.getenv("TEST_BTC_LEGACY_VERSION", "29.4")
test_base_path = os.path.expanduser(
    os.getenv("TEST_PATH", "/tmp/test_basicswap_btc_migration")
)

TEST_PWD = "test.123"
UI_PORT = 12700
BTC_BINS = ("bitcoind", "bitcoin-cli", "bitcoin-tx", "bitcoin-wallet")

delay_event = threading.Event()
logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

mp_ctx = multiprocessing.get_context("spawn")


def run_prepare(args, datadir, log_name):
    sys.stdout = open(os.path.join(datadir, log_name + ".stdout"), "w")
    sys.stderr = open(os.path.join(datadir, log_name + ".stderr"), "w")
    import basicswap.bin.prepare as prepare

    with patch.object(sys, "argv", args):
        prepare.main()


def run_bsx(args, datadir, log_name):
    sys.stdout = open(os.path.join(datadir, log_name + ".stdout"), "w")
    sys.stderr = open(os.path.join(datadir, log_name + ".stderr"), "w")
    import basicswap.bin.run as run

    with patch.object(sys, "argv", args):
        run.main()


def start_process(target, args, datadir, log_name, env):
    with patch.dict(os.environ, env):
        for name in ("WALLET_ENCRYPTION_PWD", "BITCOIN_VERSION"):
            if name not in env:
                os.environ.pop(name, None)
        process = mp_ctx.Process(target=target, args=(args, datadir, log_name))
        process.start()
    return process


def prepare(datadir, extra_args, log_name, env):
    args = ["basicswap-prepare", "-regtest=1", "-datadir=" + datadir] + extra_args
    process = start_process(run_prepare, args, datadir, log_name, env)
    process.join()
    with open(os.path.join(datadir, log_name + ".stdout")) as fp:
        stdout = fp.read()
    with open(os.path.join(datadir, log_name + ".stderr")) as fp:
        stderr = fp.read()
    return process.exitcode, stdout + stderr


def read_settings(datadir) -> dict:
    with open(os.path.join(datadir, "basicswap.json")) as fp:
        return json.load(fp)


def bitcoind_version(datadir) -> str:
    bitcoind = os.path.join(datadir, "bin", "bitcoin", "bitcoind")
    return subprocess.check_output([bitcoind, "-version"]).decode().split("\n")[0]


def foreign_address() -> str:
    pubkey = PrivateKey(sha256(b"btc wallet migration watch")).public_key.format()
    return encode_segwit_address("bcrt", 0, hash160(pubkey))


class BitcoinNode:
    def __init__(self, datadir):
        settings = read_settings(datadir)["chainclients"]["bitcoin"]
        self.bitcoind = os.path.join(datadir, "bin", "bitcoin", "bitcoind")
        self.datadir = settings["datadir"]
        self.rpcport = settings["rpcport"]
        self.process = None

    def start(self):
        self.process = subprocess.Popen(
            [
                self.bitcoind,
                "-datadir=" + self.datadir,
                "-listen=0",
                "-noconnect",
                "-nodnsseed",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cookie_path = os.path.join(self.datadir, "regtest", ".cookie")
        for i in range(60):
            if os.path.exists(cookie_path):
                try:
                    self.rpc("getnetworkinfo")
                    return
                except Exception:
                    pass
            delay_event.wait(1.0)
        raise ValueError("bitcoind did not start")

    def rpc(self, method, params=[], wallet=None):
        with open(os.path.join(self.datadir, "regtest", ".cookie")) as fp:
            auth = escape_rpcauth(fp.read())
        return make_rpc_func(self.rpcport, auth, wallet=wallet)(method, params)

    def stop(self):
        self.rpc("stop")
        self.process.wait(timeout=120)


class Test(unittest.TestCase):

    def setUp(self):
        if bin_path == "" or legacy_bin_path == "":
            self.skipTest("TEST_BIN_PATH and TEST_BTC_LEGACY_BIN_PATH must be set")

    def make_legacy_install(self, name, encrypt, wallet_name, watch_only):
        datadir = os.path.join(test_base_path, name)
        if os.path.exists(datadir):
            shutil.rmtree(datadir)
        os.makedirs(os.path.join(datadir, "bin"))
        os.symlink(
            os.path.join(bin_path, "particl"), os.path.join(datadir, "bin", "particl")
        )
        shutil.copytree(
            os.path.join(legacy_bin_path, "bitcoin"),
            os.path.join(datadir, "bin", "bitcoin"),
        )

        env = {
            "BITCOIN_VERSION": legacy_version,
            "BTC_USE_DESCRIPTORS": "false",
            "BTC_WALLET_NAME": wallet_name,
        }
        if encrypt:
            env["WALLET_ENCRYPTION_PWD"] = TEST_PWD
        exitcode, output = prepare(datadir, ["-withcoin=bitcoin"], "prepare", env)
        assert exitcode == 0, output
        settings = read_settings(datadir)["chainclients"]["bitcoin"]
        assert settings["core_version_no"] == legacy_version
        assert settings.get("use_descriptors", False) is False
        assert settings.get("wallet_name", "wallet.dat") == wallet_name

        node = BitcoinNode(datadir)
        node.start()
        try:
            wallet_info = node.rpc("getwalletinfo", wallet=wallet_name)
            assert wallet_info["descriptors"] is False
            assert ("unlocked_until" in wallet_info) is encrypt
            addr = node.rpc("getnewaddress", ["", "bech32"], wallet=wallet_name)
            node.rpc("generatetoaddress", [110, addr])
            watch_addr = None
            if watch_only:
                watch_addr = foreign_address()
                node.rpc(
                    "importaddress", [watch_addr, "bid", False], wallet=wallet_name
                )
                if encrypt:
                    node.rpc("walletpassphrase", [TEST_PWD, 60], wallet=wallet_name)
                node.rpc("sendtoaddress", [watch_addr, 1.5], wallet=wallet_name)
                node.rpc("generatetoaddress", [1, addr])
            balances = node.rpc("getbalances", wallet=wallet_name)["mine"]
        finally:
            node.stop()
        return datadir, addr, watch_addr, balances

    def add_current_release(self, datadir, with_bins):
        src_dir = os.path.join(bin_path, "bitcoin")
        dst_dir = os.path.join(datadir, "bin", "bitcoin")
        for file_name in os.listdir(src_dir):
            src_path = os.path.join(src_dir, file_name)
            if not os.path.isfile(src_path):
                continue
            if file_name in BTC_BINS and not with_bins:
                continue
            dst_path = os.path.join(dst_dir, file_name)
            if os.path.exists(dst_path):
                os.remove(dst_path)
            shutil.copy2(src_path, dst_path)

    def check_migrated(self, datadir, wallet_name, addr, watch_addr, balances, encrypt):
        settings = read_settings(datadir)["chainclients"]["bitcoin"]
        assert settings["use_descriptors"] is True
        assert "use_legacy_key_paths" not in settings
        expect_watch_name = wallet_name + "_watchonly" if watch_addr else "bsx_watch"
        assert settings["watch_wallet_name"] == expect_watch_name

        node = BitcoinNode(datadir)
        node.start()
        try:
            wallets = node.rpc("listwallets")
            assert wallet_name in wallets
            assert expect_watch_name in wallets
            wallet_info = node.rpc("getwalletinfo", wallet=wallet_name)
            assert wallet_info["descriptors"] is True
            assert ("unlocked_until" in wallet_info) is encrypt
            migrated_balances = node.rpc("getbalances", wallet=wallet_name)["mine"]
            assert migrated_balances["trusted"] == balances["trusted"]
            assert migrated_balances["immature"] == balances["immature"]
            assert node.rpc("getaddressinfo", [addr], wallet=wallet_name)["ismine"]
            if watch_addr:
                addr_info = node.rpc(
                    "getaddressinfo", [watch_addr], wallet=expect_watch_name
                )
                assert addr_info["ismine"] is True
                watch_balances = node.rpc("getbalances", wallet=expect_watch_name)
                assert watch_balances["mine"]["trusted"] == 1.5
        finally:
            node.stop()

        wallets_dir = os.path.join(settings["datadir"], "regtest", "wallets")
        assert any(
            f.startswith(wallet_name + "_") and f.endswith(".legacy.bak")
            for f in os.listdir(wallets_dir)
        )

        args = ["basicswap-run", "-regtest=1", "-datadir=" + datadir]
        process = start_process(run_bsx, args, datadir, "run", {})
        try:
            waitForServer(delay_event, UI_PORT, wait_for=60)
            if encrypt:
                rv = read_json_api(UI_PORT, "unlock", {"password": TEST_PWD})
                assert "success" in rv
            rv = read_json_api(UI_PORT, "getcoinseed", {"coin": "btc"})
            assert rv["seed_id"] == rv["expected_seed_id"]
            assert rv["seed_id"] == rv["current_seed_id"]
            rv = read_json_api(UI_PORT, "wallets/btc")
            assert rv["expected_seed"] is True
        finally:
            process.terminate()
            process.join()

    def test_upgrade_encrypted_with_watchonly(self):
        datadir, addr, watch_addr, balances = self.make_legacy_install(
            "upgrade_encrypted", True, "bsx_wallet", True
        )
        self.add_current_release(datadir, with_bins=False)
        exitcode, output = prepare(
            datadir,
            ["--upgradecores", "-withcoin=bitcoin"],
            "upgrade",
            {"WALLET_ENCRYPTION_PWD": TEST_PWD},
        )
        assert exitcode == 0, output
        assert legacy_version not in bitcoind_version(datadir)
        self.check_migrated(datadir, "bsx_wallet", addr, watch_addr, balances, True)

    def test_upgrade_encrypted_needs_password(self):
        datadir, addr, watch_addr, balances = self.make_legacy_install(
            "upgrade_needs_password", True, "bsx_wallet", False
        )
        self.add_current_release(datadir, with_bins=False)
        exitcode, output = prepare(
            datadir, ["--upgradecores", "-withcoin=bitcoin"], "upgrade_nopwd", {}
        )
        assert exitcode != 0
        assert "Must set WALLET_ENCRYPTION_PWD" in output
        assert "v" + legacy_version in bitcoind_version(datadir)
        settings = read_settings(datadir)["chainclients"]["bitcoin"]
        assert settings["core_version_no"] == legacy_version
        assert settings.get("use_descriptors", False) is False

        exitcode, output = prepare(
            datadir,
            ["--upgradecores", "-withcoin=bitcoin"],
            "upgrade",
            {"WALLET_ENCRYPTION_PWD": TEST_PWD},
        )
        assert exitcode == 0, output
        self.check_migrated(datadir, "bsx_wallet", addr, watch_addr, balances, True)

    def test_migrate_unencrypted_old_wallet_name(self):
        datadir, addr, watch_addr, balances = self.make_legacy_install(
            "migrate_unencrypted", False, "wallet.dat", False
        )
        self.add_current_release(datadir, with_bins=True)

        args = ["basicswap-run", "-regtest=1", "-datadir=" + datadir]
        process = start_process(run_bsx, args, datadir, "run_legacy", {})
        log_path = os.path.join(datadir, "basicswap.log")
        try:
            found = False
            for i in range(60):
                if os.path.exists(log_path):
                    with open(log_path) as fp:
                        if "is a legacy wallet" in fp.read():
                            found = True
                            break
                if not process.is_alive():
                    break
                delay_event.wait(1.0)
            assert found
        finally:
            process.terminate()
            process.join()

        exitcode, output = prepare(datadir, ["--migratewallets"], "migrate", {})
        assert exitcode == 0, output
        self.check_migrated(datadir, "wallet.dat", addr, watch_addr, balances, False)

        exitcode, output = prepare(datadir, ["--migratewallets"], "migrate_again", {})
        assert exitcode == 0, output
        assert "No legacy wallets to migrate." in output


if __name__ == "__main__":
    unittest.main()
