#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import mmap
import multiprocessing
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
import threading
import unittest


from unittest.mock import patch
from basicswap.util.ecc import (
    i2b,
    getSecretInt,
)
from basicswap.rpc import escape_rpcauth, make_rpc_func
from basicswap.interface.dcr.rpc import make_rpc_func as make_dcr_rpc_func
from tests.basicswap.util import (
    read_json_api,
    waitForServer,
)
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.util.address import (
    b58encode,
    toWIF,
)
from basicswap.util.crypto import (
    sha256,
)
from basicswap.util.extkey import ExtKeyPair
from basicswap.contrib.test_framework.descriptors import descsum_create

bin_path = os.path.expanduser(os.getenv("TEST_BIN_PATH", ""))
test_base_path = os.path.expanduser(os.getenv("TEST_PATH", "/tmp/test_basicswap"))

delay_event = threading.Event()
logger = logging.getLogger()
logger.level = logging.DEBUG
logger.addHandler(logging.StreamHandler(sys.stdout))


def start_prepare(args, datadir=None, env_pairs=[]):
    for pair in env_pairs:
        os.environ[pair[0]] = pair[1]
        print(pair[0], os.environ[pair[0]])
    if datadir:
        sys.stdout = open(os.path.join(datadir, "prepare.stdout"), "w")
        sys.stderr = open(os.path.join(datadir, "prepare.stderr"), "w")
    import basicswap.bin.prepare as prepareSystemThread

    with patch.object(sys, "argv", args):
        prepareSystemThread.main()
    del prepareSystemThread


def start_run(args, datadir=None, env_pairs=[]):
    for pair in env_pairs:
        os.environ[pair[0]] = pair[1]
        print(pair[0], os.environ[pair[0]])
    if datadir:
        sys.stdout = open(os.path.join(datadir, "run.stdout"), "w")
        sys.stderr = open(os.path.join(datadir, "run.stderr"), "w")
    import basicswap.bin.run as runSystemThread

    with patch.object(sys, "argv", args):
        runSystemThread.main()
    del runSystemThread


def callcoincli(binpath, datadir, params, wallet=None, timeout=None):
    args = [binpath, "-regtest", "-datadir=" + datadir]
    if wallet:
        args.append("-rpcwallet=" + wallet)
    args += shlex.split(params)
    p = subprocess.Popen(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out = p.communicate(timeout=timeout)
    if len(out[1]) > 0:
        raise ValueError("CLI error " + str(out[1]))
    return out[0].decode("utf-8").strip()


def encode_secret_extkey(prefix, ek_data: bytes) -> str:
    assert len(ek_data) == 74
    data: bytes = prefix.to_bytes(4, "big") + ek_data
    checksum = sha256(sha256(data))
    return b58encode(data + checksum[0:4])


test_seed: bytes = bytes.fromhex(
    "8e54a313e6df8918df6d758fafdbf127a115175fdd2238d0e908dd8093c9ac3b"
)
test_seedid = "3da5c0af91879e8ce97d9a843874601c08688078"
wif_prefix: int = 239
test_wif: str = toWIF(wif_prefix, test_seed)


class Test(unittest.TestCase):

    test_coins = [
        "particl",
        "bitcoin",
        "litecoin",
        "decred",
        "namecoin",
        "monero",
        "wownero",
        "pivx",
        "dash",
        "firo",
        "bitcoincash",
        "dogecoin",
    ]

    def test_coins_list(self):
        test_path = os.path.join(test_base_path, "coins_list")
        if os.path.exists(test_path):
            shutil.rmtree(test_path)
        os.makedirs(test_path)
        testargs = (
            "basicswap-prepare",
            "-help",
        )
        process = multiprocessing.Process(
            target=start_prepare, args=(testargs, test_path)
        )
        process.start()
        process.join()

        with open(os.path.join(test_path, "prepare.stdout"), "r") as fp:
            output = fp.read()

        known_coins_line = None
        for line in output.split("\n"):
            if line.startswith("Known coins: "):
                known_coins_line = line[13:]
        assert known_coins_line
        known_coins = known_coins_line.split(", ")

        for known_coin in known_coins:
            if known_coin not in self.test_coins:
                raise ValueError(f"Not testing: {known_coin}")
        for test_coin in self.test_coins:
            if test_coin not in known_coins:
                raise ValueError(f"Unknown coin: {test_coin}")

    def test_with_encrypt(self):
        test_path = os.path.join(test_base_path, "with_encrypt")
        if os.path.exists(test_path):
            shutil.rmtree(test_path)
        os.makedirs(test_path)
        if bin_path != "":
            os.symlink(bin_path, os.path.join(test_path, "bin"))

        env_vars = [
            ("WALLET_ENCRYPTION_PWD", "test.123"),
        ]
        testargs = [
            "basicswap-prepare",
            "-regtest=1",
            "-datadir=" + test_path,
            "-withcoin=" + ",".join(self.test_coins),
        ]
        process = multiprocessing.Process(
            target=start_prepare, args=(testargs, test_path, env_vars)
        )
        process.start()
        process.join()
        assert process.exitcode == 0

        with open(os.path.join(test_path, "prepare.stdout"), "r") as fp:
            output = fp.read()

        note_lines = []
        warning_lines = []
        for line in output.split("\n"):
            print("line", line)
            if line.startswith("NOTE -"):
                note_lines.append(line)
            if line.startswith("WARNING -"):
                warning_lines.append(line)

        assert len(warning_lines) == 1
        assert any(
            "WARNING - dcrwallet requires the password to be entered at the first startup when encrypted."
            in x
            for x in warning_lines
        )

        assert len(note_lines) == 2
        assert any("Unable to initialise wallet for PIVX." in x for x in note_lines)
        assert any(
            "Unable to initialise wallet for Bitcoin Cash." in x for x in note_lines
        )

        dcr_rpcport = None
        dcr_rpcuser = None
        dcr_rpcpass = None
        bch_rpcport = None
        pivx_rpcport = None
        # Make (regtest) ports unique
        settings_path = os.path.join(test_path, "basicswap.json")
        with open(settings_path) as fs:
            settings = json.load(fs)
        settings["chainclients"]["dogecoin"]["port"] = 12444
        dcr_rpcuser = settings["chainclients"]["decred"]["rpcuser"]
        dcr_rpcpass = settings["chainclients"]["decred"]["rpcpassword"]
        dcr_rpcport = settings["chainclients"]["decred"]["rpcport"]
        bch_rpcport = settings["chainclients"]["bitcoincash"]["rpcport"]
        pivx_rpcport = settings["chainclients"]["pivx"]["rpcport"]
        with open(settings_path, "w") as fp:
            json.dump(settings, fp, indent=4)

        dcr_conf_path = os.path.join(test_path, "decred", "dcrd.conf")
        with open(dcr_conf_path, "a") as fp:
            fp.write("miningaddr=SsjkQJHak5pRVUdUzqyFHKnojCVRZMU24w6\n")

        testargs = [
            "basicswap-run",
            "-regtest=1",
            "-datadir=" + test_path,
            "--startonlycoin=decred",
        ]
        process = multiprocessing.Process(
            target=start_run, args=(testargs, test_path, env_vars)
        )
        process.start()
        try:
            auth = f"{dcr_rpcuser}:{dcr_rpcpass}"
            dcr_rpc = make_dcr_rpc_func(dcr_rpcport, auth)
            for i in range(10):
                try:
                    rv = dcr_rpc("generate", [110])
                    break
                except Exception as e:  # noqa: F841
                    delay_event.wait(1.0)

        finally:
            process.terminate()
            process.join()
            assert process.exitcode == 0

        testargs = ["basicswap-run", "-regtest=1", "-datadir=" + test_path]
        process = multiprocessing.Process(target=start_run, args=(testargs, test_path))
        process.start()
        try:
            waitForServer(delay_event, 12700, wait_for=40)
            logging.info("Unlocking")
            rv = read_json_api(12700, "unlock", {"password": "test.123"})
            assert "success" in rv

            for coin in self.test_coins:
                if coin == "particl":
                    continue
                rv = read_json_api(12700, "getcoinseed", {"coin": coin})
                if coin in ("monero", "wownero"):
                    assert rv["address"] == rv["expected_address"]
                elif coin in ("bitcoincash", "pivx"):
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    # Reseed required
                    assert rv["seed_id"] != rv["current_seed_id"]
                else:
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] == rv["current_seed_id"]

            authcookiepath = os.path.join(
                test_path, "bitcoincash", "regtest", ".cookie"
            )
            with open(authcookiepath, "rb") as fp:
                bch_rpcauth = escape_rpcauth(fp.read().decode("utf-8"))

            bch_rpc = make_rpc_func(bch_rpcport, bch_rpcauth)

            bch_addr = bch_rpc("getnewaddress")
            rv = bch_rpc("generatetoaddress", [1, bch_addr])
            rv = read_json_api(12700, "wallets/bch/reseed")
            assert rv["reseeded"] is True

            authcookiepath = os.path.join(test_path, "pivx", "regtest", ".cookie")
            with open(authcookiepath, "rb") as fp:
                pivx_rpcauth = escape_rpcauth(fp.read().decode("utf-8"))

            pivx_rpc = make_rpc_func(pivx_rpcport, pivx_rpcauth)

            pivx_addr = pivx_rpc("getnewaddress")
            rv = pivx_rpc("generatetoaddress", [1, pivx_addr])
            rv = read_json_api(12700, "wallets/pivx/reseed")
            assert rv["reseeded"] is True

            for coin in self.test_coins:
                if coin == "particl":
                    continue
                rv = read_json_api(12700, "getcoinseed", {"coin": coin})
                if coin in ("monero", "wownero"):
                    assert rv["address"] == rv["expected_address"]
                else:
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] == rv["current_seed_id"]

            ltc_cli_path = os.path.join(test_path, "bin", "litecoin", "litecoin-cli")
            ltc_datadir = os.path.join(test_path, "litecoin")
            rv = json.loads(
                callcoincli(
                    ltc_cli_path, ltc_datadir, "getwalletinfo", wallet="wallet.dat"
                )
            )
            assert "unlocked_until" in rv
            rv = json.loads(
                callcoincli(ltc_cli_path, ltc_datadir, "getwalletinfo", wallet="mweb")
            )
            assert "unlocked_until" in rv
        finally:
            process.terminate()
            process.join()
            assert process.exitcode == 0

    def test_with_encrypt_addcoin(self):
        test_path = os.path.join(test_base_path, "encrypt_addcoin")
        if os.path.exists(test_path):
            shutil.rmtree(test_path)
        os.makedirs(test_path)
        if bin_path != "":
            os.symlink(bin_path, os.path.join(test_path, "bin"))

        env_vars = [
            ("WALLET_ENCRYPTION_PWD", "test.123"),
        ]
        testargs = [
            "basicswap-prepare",
            "-regtest=1",
            "-datadir=" + test_path,
        ]
        process = multiprocessing.Process(
            target=start_prepare, args=(testargs, test_path, env_vars)
        )
        process.start()
        process.join()
        assert process.exitcode == 0

        for coin in self.test_coins:
            if coin == "particl":
                continue
            testargs = [
                "basicswap-prepare",
                "-regtest=1",
                "-datadir=" + test_path,
                "-addcoin=" + coin,
            ]
            process = multiprocessing.Process(
                target=start_prepare, args=(testargs, test_path, env_vars)
            )
            process.start()
            process.join()
            assert process.exitcode == 0

        dcr_rpcport = None
        dcr_rpcuser = None
        dcr_rpcpass = None
        bch_rpcport = None
        pivx_rpcport = None
        # Make (regtest) ports unique
        settings_path = os.path.join(test_path, "basicswap.json")
        with open(settings_path) as fs:
            settings = json.load(fs)
        settings["chainclients"]["dogecoin"]["port"] = 12444
        dcr_rpcuser = settings["chainclients"]["decred"]["rpcuser"]
        dcr_rpcpass = settings["chainclients"]["decred"]["rpcpassword"]
        dcr_rpcport = settings["chainclients"]["decred"]["rpcport"]
        bch_rpcport = settings["chainclients"]["bitcoincash"]["rpcport"]
        pivx_rpcport = settings["chainclients"]["pivx"]["rpcport"]
        with open(settings_path, "w") as fp:
            json.dump(settings, fp, indent=4)

        dcr_conf_path = os.path.join(test_path, "decred", "dcrd.conf")
        with open(dcr_conf_path, "a") as fp:
            fp.write("miningaddr=SsjkQJHak5pRVUdUzqyFHKnojCVRZMU24w6\n")

        testargs = [
            "basicswap-run",
            "-regtest=1",
            "-datadir=" + test_path,
            "--startonlycoin=decred",
        ]
        process = multiprocessing.Process(
            target=start_run, args=(testargs, test_path, env_vars)
        )
        process.start()
        try:
            auth = f"{dcr_rpcuser}:{dcr_rpcpass}"
            dcr_rpc = make_dcr_rpc_func(dcr_rpcport, auth)
            for i in range(10):
                try:
                    rv = dcr_rpc("generate", [110])
                    break
                except Exception as e:  # noqa: F841
                    delay_event.wait(1.0)
        finally:
            process.terminate()
            process.join()
            assert process.exitcode == 0

        testargs = ["basicswap-run", "-regtest=1", "-datadir=" + test_path]
        process = multiprocessing.Process(target=start_run, args=(testargs, test_path))
        process.start()
        try:
            waitForServer(delay_event, 12700, wait_for=40)
            logging.info("Unlocking")
            rv = read_json_api(12700, "unlock", {"password": "test.123"})
            assert "success" in rv

            for coin in self.test_coins:
                if coin == "particl":
                    continue
                rv = read_json_api(12700, "getcoinseed", {"coin": coin})
                if coin in ("monero", "wownero"):
                    assert rv["address"] == rv["expected_address"]
                elif coin in ("bitcoincash", "pivx"):
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    # Reseed required
                    assert rv["seed_id"] != rv["current_seed_id"]
                else:
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] == rv["current_seed_id"]

            authcookiepath = os.path.join(
                test_path, "bitcoincash", "regtest", ".cookie"
            )
            with open(authcookiepath, "rb") as fp:
                bch_rpcauth = escape_rpcauth(fp.read().decode("utf-8"))

            bch_rpc = make_rpc_func(bch_rpcport, bch_rpcauth)

            logging.info("Reseeding BCH")
            bch_addr = bch_rpc("getnewaddress")
            rv = bch_rpc("generatetoaddress", [1, bch_addr])
            rv = read_json_api(12700, "wallets/bch/reseed")
            assert rv["reseeded"] is True

            logging.info("Reseeding PIVX")
            authcookiepath = os.path.join(test_path, "pivx", "regtest", ".cookie")
            with open(authcookiepath, "rb") as fp:
                pivx_rpcauth = escape_rpcauth(fp.read().decode("utf-8"))

            pivx_rpc = make_rpc_func(pivx_rpcport, pivx_rpcauth)

            pivx_addr = pivx_rpc("getnewaddress")
            rv = pivx_rpc("generatetoaddress", [1, pivx_addr])
            rv = read_json_api(12700, "wallets/pivx/reseed")
            assert rv["reseeded"] is True

            for coin in self.test_coins:
                if coin == "particl":
                    continue
                rv = read_json_api(12700, "getcoinseed", {"coin": coin})
                if coin in ("monero", "wownero"):
                    assert rv["address"] == rv["expected_address"]
                else:
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] == rv["current_seed_id"]

            ltc_cli_path = os.path.join(test_path, "bin", "litecoin", "litecoin-cli")
            ltc_datadir = os.path.join(test_path, "litecoin")
            rv = json.loads(
                callcoincli(
                    ltc_cli_path, ltc_datadir, "getwalletinfo", wallet="wallet.dat"
                )
            )
            assert "unlocked_until" in rv
            rv = json.loads(
                callcoincli(ltc_cli_path, ltc_datadir, "getwalletinfo", wallet="mweb")
            )
            assert "unlocked_until" in rv
        finally:
            process.terminate()
            process.join()
            assert process.exitcode == 0

        # Check that BSX starts up again
        testargs = ["basicswap-run", "-regtest=1", "-datadir=" + test_path]
        process = multiprocessing.Process(target=start_run, args=(testargs, test_path))
        process.start()
        try:
            waitForServer(delay_event, 12700, wait_for=40)

        finally:
            process.terminate()
            process.join()
            assert process.exitcode == 0

    def test_encrypt_after(self):
        test_path = os.path.join(test_base_path, "encrypt_after")
        if os.path.exists(test_path):
            shutil.rmtree(test_path)
        os.makedirs(test_path)
        if bin_path != "":
            os.symlink(bin_path, os.path.join(test_path, "bin"))

        testargs = [
            "basicswap-prepare",
            "-regtest=1",
            "-datadir=" + test_path,
            "-withcoin=" + ",".join(self.test_coins),
        ]
        process = multiprocessing.Process(
            target=start_prepare, args=(testargs, test_path)
        )
        process.start()
        process.join()
        assert process.exitcode == 0

        dcr_rpcport = None
        dcr_rpcuser = None
        dcr_rpcpass = None
        bch_rpcport = None
        pivx_rpcport = None
        # Make (regtest) ports unique
        settings_path = os.path.join(test_path, "basicswap.json")
        with open(settings_path) as fs:
            settings = json.load(fs)
        settings["chainclients"]["dogecoin"]["port"] = 12444
        dcr_rpcuser = settings["chainclients"]["decred"]["rpcuser"]
        dcr_rpcpass = settings["chainclients"]["decred"]["rpcpassword"]
        dcr_rpcport = settings["chainclients"]["decred"]["rpcport"]
        bch_rpcport = settings["chainclients"]["bitcoincash"]["rpcport"]
        pivx_rpcport = settings["chainclients"]["pivx"]["rpcport"]

        with open(settings_path, "w") as fp:
            json.dump(settings, fp, indent=4)

        dcr_conf_path = os.path.join(test_path, "decred", "dcrd.conf")
        with open(dcr_conf_path, "a") as fp:
            fp.write("miningaddr=SsjkQJHak5pRVUdUzqyFHKnojCVRZMU24w6\n")

        testargs = ["basicswap-run", "-regtest=1", "-datadir=" + test_path]
        process = multiprocessing.Process(target=start_run, args=(testargs, test_path))
        process.start()
        try:
            waitForServer(delay_event, 12700, wait_for=40)

            for coin in self.test_coins:
                if coin == "particl":
                    continue
                rv = read_json_api(12700, "getcoinseed", {"coin": coin})
                if coin in ("monero", "wownero"):
                    assert rv["address"] == rv["expected_address"]
                elif coin in ("bitcoincash", "pivx"):
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    # Reseed required
                    assert rv["seed_id"] != rv["current_seed_id"]
                else:
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] == rv["current_seed_id"]

            authcookiepath = os.path.join(
                test_path, "bitcoincash", "regtest", ".cookie"
            )
            with open(authcookiepath, "rb") as fp:
                bch_rpcauth = escape_rpcauth(fp.read().decode("utf-8"))

            bch_rpc = make_rpc_func(bch_rpcport, bch_rpcauth)

            bch_addr = bch_rpc("getnewaddress")
            rv = bch_rpc("generatetoaddress", [1, bch_addr])
            rv = read_json_api(12700, "wallets/bch/reseed")
            assert rv["reseeded"] is True

            authcookiepath = os.path.join(test_path, "pivx", "regtest", ".cookie")
            with open(authcookiepath, "rb") as fp:
                pivx_rpcauth = escape_rpcauth(fp.read().decode("utf-8"))

            pivx_rpc = make_rpc_func(pivx_rpcport, pivx_rpcauth)

            pivx_addr = pivx_rpc("getnewaddress")
            rv = pivx_rpc("generatetoaddress", [1, pivx_addr])
            rv = read_json_api(12700, "wallets/pivx/reseed")
            assert rv["reseeded"] is True

            for coin in self.test_coins:
                if coin == "particl":
                    continue
                rv = read_json_api(12700, "getcoinseed", {"coin": coin})
                if coin in ("monero", "wownero"):
                    assert rv["address"] == rv["expected_address"]
                else:
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] == rv["current_seed_id"]

            ltc_cli_path = os.path.join(test_path, "bin", "litecoin", "litecoin-cli")
            ltc_datadir = os.path.join(test_path, "litecoin")
            rv = json.loads(
                callcoincli(ltc_cli_path, ltc_datadir, "getwalletinfo", wallet="mweb")
            )
            ltc_mweb_seed_before: str = rv["hdseedid"]
            assert "unlocked_until" not in rv

            # Get Decred out of IBD, else first start after encryption will lock up with "Since this is your first time running we need to sync accounts."
            auth = f"{dcr_rpcuser}:{dcr_rpcpass}"
            dcr_rpc = make_dcr_rpc_func(dcr_rpcport, auth)
            for i in range(10):
                try:
                    rv = dcr_rpc("generate", [110])
                    break
                except Exception as e:  # noqa: F841
                    delay_event.wait(1.0)

            logging.info("setpassword (encrypt wallets)")
            rv = read_json_api(
                12700, "setpassword", {"oldpassword": "", "newpassword": "test.123"}
            )
            assert "success" in rv

            logging.info("Unlocking")
            rv = read_json_api(12700, "unlock", {"password": "test.123"})
            assert "success" in rv

            for coin in self.test_coins:
                logging.info(f"Coin: {coin}")
                if coin == "particl":
                    continue
                if coin == "firo":
                    # firo core shuts down after encryptwallet
                    continue
                rv = read_json_api(12700, "getcoinseed", {"coin": coin})
                if coin in ("monero", "wownero"):
                    assert rv["address"] == rv["expected_address"]
                elif coin in ("pivx"):
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] != rv["current_seed_id"]
                else:
                    assert rv["seed_id"] == rv["expected_seed_id"]
                    assert rv["seed_id"] == rv["current_seed_id"]

            # pivx seed has changed
            rv = read_json_api(12700, "wallets/pivx")
            assert rv["expected_seed"] is False

            logging.info("Try to reseed pivx (and fail).")
            rv = read_json_api(12700, "wallets/pivx/reseed")
            assert "Already have this key" in rv["error"]

            logging.info("Check both LTC wallets are encrypted and mweb seeds match.")
            rv = json.loads(
                callcoincli(
                    ltc_cli_path, ltc_datadir, "getwalletinfo", wallet="wallet.dat"
                )
            )
            assert "unlocked_until" in rv
            rv = json.loads(
                callcoincli(ltc_cli_path, ltc_datadir, "getwalletinfo", wallet="mweb")
            )
            assert "unlocked_until" in rv
            assert ltc_mweb_seed_before == rv["hdseedid"]

        finally:
            process.terminate()
            process.join()
            assert process.exitcode == 0

        logging.info("Starting BSX to check Firo")
        testargs = ["basicswap-run", "-regtest=1", "-datadir=" + test_path]
        process = multiprocessing.Process(target=start_run, args=(testargs, test_path))
        process.start()
        try:
            waitForServer(delay_event, 12700, wait_for=40)
            logging.info("Unlocking")
            rv = read_json_api(12700, "unlock", {"password": "test.123"})
            assert "success" in rv

            rv = read_json_api(12700, "getcoinseed", {"coin": "firo"})
            assert rv["seed_id"] == rv["expected_seed_id"]
            assert rv["seed_id"] == rv["current_seed_id"]

            rv = read_json_api(12700, "getcoinseed", {"coin": "dcr"})
            assert rv["seed_id"] == rv["expected_seed_id"]
            assert rv["seed_id"] == rv["current_seed_id"]

        finally:
            process.terminate()
            process.join()
            assert process.exitcode == 0

    def write_btc_conf(self, datadir):
        conf_path = os.path.join(datadir, "bitcoin.conf")
        with open(conf_path, "w") as fp:
            fp.write("regtest=1\n")
            fp.write("[regtest]\n")
            fp.write("printtoconsole=0\n")
            fp.write("server=1\n")
            fp.write("discover=0\n")
            fp.write("listenonion=0\n")
            fp.write("bind=127.0.0.1\n")
            fp.write("debug=1\n")
            fp.write("debugexclude=libevent\n")
            fp.write("deprecatedrpc=create_bdb\n")
            fp.write("rpcport=12223\n")
            salt = generate_salt(16)
            fp.write(
                "rpcauth={}:{}${}\n".format(
                    "test",
                    salt,
                    password_to_hmac(salt, "test_pass"),
                )
            )

    def test_btc_wallets_with_module(self):
        import berkeleydb

        if not os.path.exists(bin_path):
            raise ValueError("TEST_BIN_PATH not set.")
        test_path = os.path.join(test_base_path, "test_btc_wallets_with_module")
        if os.path.exists(test_path):
            shutil.rmtree(test_path)
        os.makedirs(test_path)
        self.write_btc_conf(test_path)
        daemon_path = os.path.join(bin_path, "bitcoin", "bitcoind")
        args = [
            daemon_path,
            "-datadir=" + test_path,
        ]
        bitcoind_process = subprocess.Popen(args)
        try:
            rpc = make_rpc_func(12223, "test:test_pass")
            for i in range(20):
                try:
                    rv = rpc("listwallets")
                    break
                except Exception as e:  # noqa: F841
                    delay_event.wait(1.0)

            # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
            rpc(
                "createwallet",
                ["bdb_wallet", False, True, "", False, False],
            )

            rpc("sethdseed", [True, test_wif], wallet_override="bdb_wallet")
            rv = rpc("getwalletinfo", wallet_override="bdb_wallet")
            assert rv["hdseedid"] == test_seedid

            new_addr = rpc("getnewaddress", wallet_override="bdb_wallet")
            logging.info(f"getnewaddress {new_addr}")
            rv = rpc(
                "getaddressinfo",
                [
                    new_addr,
                ],
                wallet_override="bdb_wallet",
            )
            logging.info(f"getaddressinfo before encrypt {rv}")
            assert rv["hdmasterfingerprint"] == "a55b7ea9"

            rpc(
                "unloadwallet",
                [
                    "bdb_wallet",
                ],
            )

            walletdir = os.path.join(test_path, "regtest", "wallets", "bdb_wallet")
            walletpath = os.path.join(walletdir, "wallet.dat")

            db = berkeleydb.db.DB()
            db.open(
                walletpath,
                "main",
                berkeleydb.db.DB_BTREE,
                berkeleydb.db.DB_THREAD | berkeleydb.db.DB_CREATE,
            )
            prev_hdchain_key = None
            prev_hdchain_value = None
            for k, v in db.items():
                if b"hdchain" in k:
                    prev_hdchain_key = k
                    prev_hdchain_value = v
            db.close()

            rpc(
                "loadwallet",
                [
                    "bdb_wallet",
                ],
            )

            rv = rpc(
                "encryptwallet",
                [
                    "test.123",
                ],
                wallet_override="bdb_wallet",
            )
            logging.info(f"encryptwallet {rv}")
            rv = rpc("getwalletinfo", wallet_override="bdb_wallet")
            logging.info(f"getwalletinfo {rv}")
            assert rv["hdseedid"] != test_seedid

            rpc(
                "unloadwallet",
                [
                    "bdb_wallet",
                ],
            )

            bkp_path = os.path.join(walletdir, "wallet.dat" + ".bkp")
            for i in range(1000):
                if os.path.exists(bkp_path):
                    bkp_path = os.path.join(walletdir, "wallet.dat" + f".bkp{i}")

            assert os.path.exists(bkp_path) is False
            if os.path.isfile(walletpath):
                shutil.copy(walletpath, bkp_path)
            else:
                shutil.copytree(walletpath, bkp_path)

            # Replace hdchain with previous value
            db = berkeleydb.db.DB()
            db.open(
                walletpath,
                "main",
                berkeleydb.db.DB_BTREE,
                berkeleydb.db.DB_THREAD | berkeleydb.db.DB_CREATE,
            )
            db[prev_hdchain_key] = prev_hdchain_value
            db.close()

            rpc(
                "loadwallet",
                [
                    "bdb_wallet",
                ],
            )

            rv = rpc("getwalletinfo", wallet_override="bdb_wallet")
            logging.info(f"getwalletinfo {rv}")
            assert rv["hdseedid"] == test_seedid

            # Picks from wrong keypool
            new_addr = rpc("getnewaddress", wallet_override="bdb_wallet")
            rv = rpc(
                "getaddressinfo",
                [
                    new_addr,
                ],
                wallet_override="bdb_wallet",
            )
            assert rv["hdmasterfingerprint"] != "a55b7ea9"

            rpc("walletpassphrase", ["test.123", 1000], wallet_override="bdb_wallet")
            rpc("newkeypool", wallet_override="bdb_wallet")

            new_addr = rpc("getnewaddress", wallet_override="bdb_wallet")
            rv = rpc(
                "getaddressinfo",
                [
                    new_addr,
                ],
                wallet_override="bdb_wallet",
            )
            assert rv["hdmasterfingerprint"] == "a55b7ea9"

        finally:
            rpc("stop")
            bitcoind_process.wait(timeout=30)

    def test_btc_wallets_without_module(self):
        if not os.path.exists(bin_path):
            raise ValueError("TEST_BIN_PATH not set.")
        test_path = os.path.join(test_base_path, "test_btc_wallets_without_module")
        if os.path.exists(test_path):
            shutil.rmtree(test_path)
        os.makedirs(test_path)
        self.write_btc_conf(test_path)
        daemon_path = os.path.join(bin_path, "bitcoin", "bitcoind")
        args = [
            daemon_path,
            "-datadir=" + test_path,
        ]
        bitcoind_process = subprocess.Popen(args)
        try:
            rpc = make_rpc_func(12223, "test:test_pass")
            for i in range(20):
                try:
                    rv = rpc("listwallets")
                    break
                except Exception as e:  # noqa: F841
                    delay_event.wait(1.0)

            rv = rpc(
                "createwallet",
                ["bdb_wallet2", False, True, "", False, False],
            )
            logging.info(f"createwallet {rv}")

            rpc("sethdseed", [True, test_wif], wallet_override="bdb_wallet2")

            new_addr = rpc("getnewaddress", wallet_override="bdb_wallet2")
            logging.info(f"getnewaddress {new_addr}")
            rv = rpc(
                "getaddressinfo",
                [
                    new_addr,
                ],
                wallet_override="bdb_wallet2",
            )
            logging.info(f"getaddressinfo before encrypt {rv}")
            assert rv["hdmasterfingerprint"] == "a55b7ea9"

            rv = rpc("getwalletinfo", wallet_override="bdb_wallet2")
            logging.info(f"getwalletinfo {rv}")
            assert rv["hdseedid"] == test_seedid

            seedid_bytes = bytes.fromhex(rv["hdseedid"])[::-1]
            # keypoolsize and keypoolsize_hd_internal are how many pre-generated keys remain unused.
            orig_hdchain_bytes_predicted = (
                int(2).to_bytes(4, "little")
                + int(1000).to_bytes(4, "little")
                + seedid_bytes
                + int(1000).to_bytes(4, "little")
            )
            logging.info(
                f"orig_hdchain_bytes_predicted {orig_hdchain_bytes_predicted.hex()}"
            )

            rv = rpc(
                "unloadwallet",
                [
                    "bdb_wallet2",
                ],
            )
            logging.info(f"Looking for hdchain for {seedid_bytes.hex()}")
            walletdir = os.path.join(test_path, "regtest", "wallets", "bdb_wallet2")
            walletpath = os.path.join(walletdir, "wallet.dat")
            found_hdchain = False
            max_key_count = 4000000  # arbitrary
            with open(walletpath, "rb") as fp:
                with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    pos = mm.find(seedid_bytes)
                    while pos != -1:
                        mm.seek(pos - 8)
                        hdchain_bytes = mm.read(12 + 20)
                        version = int.from_bytes(hdchain_bytes[:4], "little")
                        if version == 2:
                            external_counter = int.from_bytes(
                                hdchain_bytes[4:8], "little"
                            )
                            internal_counter = int.from_bytes(
                                hdchain_bytes[-4:], "little"
                            )
                            if (
                                external_counter > 0
                                and external_counter <= max_key_count
                                and internal_counter > 0
                                and internal_counter <= max_key_count
                            ):
                                orig_hdchain_bytes = hdchain_bytes
                                found_hdchain = True
                                break
                        pos = mm.find(seedid_bytes, pos + 1)
            logging.info(f"orig_hdchain_bytes {orig_hdchain_bytes.hex()}")
            assert found_hdchain

            rpc(
                "loadwallet",
                [
                    "bdb_wallet2",
                ],
            )

            rv = rpc(
                "encryptwallet",
                [
                    "test.123",
                ],
                wallet_override="bdb_wallet2",
            )
            logging.info(f"encryptwallet {rv}")
            rv = rpc("getwalletinfo", wallet_override="bdb_wallet2")
            logging.info(f"getwalletinfo {rv}")
            assert rv["hdseedid"] != test_seedid

            new_hdchain_bytes = (
                int(2).to_bytes(4, "little")
                + int(rv["keypoolsize"]).to_bytes(4, "little")
                + bytes.fromhex(rv["hdseedid"])[::-1]
                + int(rv["keypoolsize_hd_internal"]).to_bytes(4, "little")
            )

            rpc(
                "unloadwallet",
                [
                    "bdb_wallet2",
                ],
            )

            with open(walletpath, "r+b") as fp:
                with mmap.mmap(fp.fileno(), 0) as mm:
                    offset = mm.find(new_hdchain_bytes)
                    if offset != -1:
                        mm.seek(offset)
                        mm.write(orig_hdchain_bytes)
                        print(f"Replaced at offset: {offset}")
                    else:
                        print("Byte sequence not found.")

            rpc(
                "loadwallet",
                [
                    "bdb_wallet2",
                ],
            )

            rv = rpc("getwalletinfo", wallet_override="bdb_wallet2")
            logging.info(f"getwalletinfo {rv}")
            assert rv["hdseedid"] == test_seedid

            rpc("walletpassphrase", ["test.123", 1000], wallet_override="bdb_wallet2")
            rpc("newkeypool", wallet_override="bdb_wallet2")

            new_addr = rpc("getnewaddress", wallet_override="bdb_wallet2")
            rv = rpc(
                "getaddressinfo",
                [
                    new_addr,
                ],
                wallet_override="bdb_wallet2",
            )
            assert rv["hdmasterfingerprint"] == "a55b7ea9"
        finally:
            rpc("stop")
            bitcoind_process.wait(timeout=30)

    def test_btc_wallets_descriptors(self):
        if not os.path.exists(bin_path):
            raise ValueError("TEST_BIN_PATH not set.")
        test_path = os.path.join(test_base_path, "test_btc_wallets_descriptors")
        if os.path.exists(test_path):
            shutil.rmtree(test_path)
        os.makedirs(test_path)
        self.write_btc_conf(test_path)
        daemon_path = os.path.join(bin_path, "bitcoin", "bitcoind")
        args = [
            daemon_path,
            "-datadir=" + test_path,
        ]
        bitcoind_process = subprocess.Popen(args)
        try:
            rpc = make_rpc_func(12223, "test:test_pass")
            for i in range(20):
                try:
                    rv = rpc("listwallets")
                    break
                except Exception as e:  # noqa: F841
                    delay_event.wait(1.0)

            rpc(
                "createwallet",
                ["descr_wallet", False, True, "", False, True],
            )

            ek = ExtKeyPair()
            ek.set_seed(test_seed)
            ek_encoded: str = encode_secret_extkey(0x04358394, ek.encode_v())

            desc_external = descsum_create(f"wpkh({ek_encoded}/0h/0h/*h)")
            desc_internal = descsum_create(f"wpkh({ek_encoded}/0h/1h/*h)")
            rv = rpc(
                "importdescriptors",
                [
                    [
                        {
                            "desc": desc_external,
                            "timestamp": "now",
                            "active": True,
                            "range": [0, 10],
                            "next_index": 0,
                        },
                        {
                            "desc": desc_internal,
                            "timestamp": "now",
                            "active": True,
                            "internal": True,
                        },
                    ],
                ],
                wallet_override="descr_wallet",
            )
            logging.info(f"importdescriptors {rv}")
            addr = rpc(
                "getnewaddress", ["test descriptors"], wallet_override="descr_wallet"
            )
            addr_info = rpc(
                "getaddressinfo",
                [
                    addr,
                ],
                wallet_override="descr_wallet",
            )
            assert addr_info["hdmasterfingerprint"] == "a55b7ea9"

            descriptors_before = rpc(
                "listdescriptors", [], wallet_override="descr_wallet"
            )
            logging.info(f"descriptors_before {descriptors_before}")

            rv = rpc("getwalletinfo", wallet_override="descr_wallet")
            logging.info(f"getwalletinfo {rv}")

            new_addr = rpc("getnewaddress", wallet_override="descr_wallet")
            rv = rpc(
                "getaddressinfo",
                [
                    new_addr,
                ],
                wallet_override="descr_wallet",
            )
            assert rv["hdmasterfingerprint"] == "a55b7ea9"

            rpc(
                "unloadwallet",
                [
                    "descr_wallet",
                ],
            )

            walletdir = os.path.join(test_path, "regtest", "wallets", "descr_wallet")
            walletpath = os.path.join(walletdir, "wallet.dat")

            orig_active_descriptors = []
            with sqlite3.connect(walletpath) as conn:
                c = conn.cursor()
                rows = c.execute(
                    "SELECT * FROM main WHERE key in (:kext, :kint)",
                    {
                        "kext": bytes.fromhex("1161637469766565787465726e616c73706b02"),
                        "kint": bytes.fromhex("11616374697665696e7465726e616c73706b02"),
                    },
                )
                for row in rows:
                    k, v = row
                    orig_active_descriptors.append({"k": k, "v": v})

            assert len(orig_active_descriptors) == 2
            rpc(
                "loadwallet",
                [
                    "descr_wallet",
                ],
            )

            rv = rpc(
                "encryptwallet",
                [
                    "test.123",
                ],
                wallet_override="descr_wallet",
            )
            logging.info(f"encryptwallet {rv}")

            rv = rpc("listdescriptors", [], wallet_override="descr_wallet")
            logging.info(f"listdescriptors {rv}")

            # The descriptors don't seem to be replaced
            addr = rpc(
                "getnewaddress", ["test descriptors"], wallet_override="descr_wallet"
            )
            addr_info = rpc(
                "getaddressinfo",
                [
                    addr,
                ],
                wallet_override="descr_wallet",
            )
            assert addr_info["hdmasterfingerprint"] == "a55b7ea9"

            # Simulate, in case it changes
            rpc("walletpassphrase", ["test.123", 1000], wallet_override="descr_wallet")
            ek = ExtKeyPair()
            ek.set_seed(i2b(getSecretInt()))
            ek_encoded: str = encode_secret_extkey(0x04358394, ek.encode_v())

            desc_external = descsum_create(f"wpkh({ek_encoded}/0h/0h/*h)")
            desc_internal = descsum_create(f"wpkh({ek_encoded}/0h/1h/*h)")
            rv = rpc(
                "importdescriptors",
                [
                    [
                        {
                            "desc": desc_external,
                            "timestamp": "now",
                            "active": True,
                            "range": [0, 10],
                            "next_index": 0,
                        },
                        {
                            "desc": desc_internal,
                            "timestamp": "now",
                            "active": True,
                            "internal": True,
                        },
                    ],
                ],
                wallet_override="descr_wallet",
            )
            logging.info(f"importdescriptors {rv}")
            addr = rpc(
                "getnewaddress", ["test descriptors"], wallet_override="descr_wallet"
            )
            addr_info = rpc(
                "getaddressinfo",
                [
                    addr,
                ],
                wallet_override="descr_wallet",
            )
            assert addr_info["hdmasterfingerprint"] != "a55b7ea9"

            rv = rpc("getwalletinfo", [], wallet_override="descr_wallet")
            logging.info(f"getwalletinfo {rv}")

            rpc(
                "unloadwallet",
                [
                    "descr_wallet",
                ],
            )
            bkp_path = os.path.join(walletdir, "wallet.dat" + ".bkp")
            for i in range(1000):
                if os.path.exists(bkp_path):
                    bkp_path = os.path.join(walletdir, "wallet.dat" + f".bkp{i}")

            assert os.path.exists(bkp_path) is False
            if os.path.isfile(walletpath):
                shutil.copy(walletpath, bkp_path)
            else:
                shutil.copytree(walletpath, bkp_path)

            with sqlite3.connect(walletpath) as conn:
                c = conn.cursor()
                c.executemany(
                    "UPDATE main SET value = :v WHERE key = :k", orig_active_descriptors
                )
                conn.commit()

            rpc(
                "loadwallet",
                [
                    "descr_wallet",
                ],
            )
            addr = rpc("getnewaddress", wallet_override="descr_wallet")
            addr_info = rpc(
                "getaddressinfo",
                [
                    addr,
                ],
                wallet_override="descr_wallet",
            )
            logging.info(f"getaddressinfo {addr_info}")
            assert addr_info["hdmasterfingerprint"] == "a55b7ea9"

        finally:
            rpc("stop")
            bitcoind_process.wait(timeout=30)


if __name__ == "__main__":
    unittest.main()
