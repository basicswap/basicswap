#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import multiprocessing
import os
import shlex
import shutil
import subprocess
import sys
import threading
import unittest

from unittest.mock import patch
from basicswap.rpc import escape_rpcauth, make_rpc_func
from basicswap.interface.dcr.rpc import make_rpc_func as make_dcr_rpc_func
from tests.basicswap.util import (
    read_json_api,
    waitForServer,
)

bin_path = os.path.expanduser(os.getenv("TEST_BIN_PATH", ""))
test_base_path = os.path.expanduser(os.getenv("TEST_PATH", "~/test_basicswap"))

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


if __name__ == "__main__":
    unittest.main()
