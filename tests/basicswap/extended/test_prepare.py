#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import importlib
import json
import logging
import multiprocessing
import os
import shutil
import sys
import threading
import unittest

from io import StringIO
from unittest.mock import patch

import basicswap.config as cfg
from tests.basicswap.util import (
    make_boolean,
    read_json_api,
    waitForServer,
)

TEST_DELETE_DIRS = make_boolean(os.getenv("TEST_DELETE_DIRS", True))
bin_path = os.path.expanduser(os.getenv("TEST_BIN_PATH", ""))
test_base_path = os.path.expanduser(os.getenv("TEST_PREPARE_PATH", "~/test_basicswap"))
test_path_plain = os.path.join(test_base_path, "plain")
test_path_encrypted = os.path.join(test_base_path, "encrypted")
test_path_encrypt = os.path.join(test_base_path, "encrypt")


delay_event = threading.Event()
logger = logging.getLogger()
logger.level = logging.DEBUG
logger.addHandler(logging.StreamHandler(sys.stdout))


def start_prepare(args, env_pairs=[]):
    for pair in env_pairs:
        os.environ[pair[0]] = pair[1]
        print(pair[0], os.environ[pair[0]])
    import basicswap.bin.prepare as prepareSystemThread

    with patch.object(sys, "argv", args):
        prepareSystemThread.main()
    del prepareSystemThread


def start_run(args, env_pairs=[]):
    for pair in env_pairs:
        os.environ[pair[0]] = pair[1]
        print(pair[0], os.environ[pair[0]])
    import basicswap.bin.run as runSystemThread

    with patch.object(sys, "argv", args):
        runSystemThread.main()
    del runSystemThread


class Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()
        # Reset env vars
        reset_vars = ["BSX_ALLOW_ENV_OVERRIDE", "BSX_DOCKER_MODE", "BSX_LOCAL_TOR"]
        for var_name in reset_vars:
            if var_name in os.environ:
                del os.environ[var_name]

    @classmethod
    def tearDownClass(self):
        try:
            if TEST_DELETE_DIRS:
                for test_dir in (
                    test_path_plain,
                    test_path_encrypted,
                    test_path_encrypt,
                ):
                    if os.path.exists(test_dir):
                        shutil.rmtree(test_dir)
        except Exception as ex:
            logger.warning(f"tearDownClass {ex}")
        super(Test, self).tearDownClass()

    def test_plain(self):
        if os.path.exists(test_path_plain):
            shutil.rmtree(test_path_plain)
        if bin_path != "":
            os.makedirs(test_path_plain)
            os.symlink(bin_path, os.path.join(test_path_plain, "bin"))

        testargs = (
            "basicswap-prepare",
            "-datadir=" + test_path_plain,
            "-withcoin=litecoin",
        )
        process = multiprocessing.Process(target=start_prepare, args=(testargs,))
        process.start()
        process.join()

        config_path = os.path.join(test_path_plain, cfg.CONFIG_FILENAME)
        self.assertTrue(os.path.exists(config_path))

        import basicswap.bin.prepare as prepareSystem

        try:
            logging.info("Test no overwrite")
            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "-withcoin=litecoin",
            ]
            with patch("sys.stderr", new=StringIO()) as fake_stderr:
                with patch.object(sys, "argv", testargs):
                    with self.assertRaises(SystemExit) as cm:
                        prepareSystem.main()

            self.assertEqual(cm.exception.code, 1)
            self.assertTrue("exists, exiting" in fake_stderr.getvalue())

            logger.info("Test addcoin new")
            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "-addcoin=bitcoin",
            ]
            with patch.object(sys, "argv", testargs):
                prepareSystem.main()
            with open(config_path) as fs:
                settings = json.load(fs)
                self.assertTrue(
                    settings["chainclients"]["bitcoin"]["connection_type"] == "rpc"
                )

            logger.info("Test disablecoin")
            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "-disablecoin=bitcoin",
            ]
            with patch.object(sys, "argv", testargs):
                prepareSystem.main()
            with open(config_path) as fs:
                settings = json.load(fs)
                self.assertTrue(
                    settings["chainclients"]["bitcoin"]["connection_type"] == "none"
                )

            logger.info("Test addcoin existing")
            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "-addcoin=bitcoin",
            ]
            with patch.object(sys, "argv", testargs):
                prepareSystem.main()
            with open(config_path) as fs:
                settings = json.load(fs)
                self.assertTrue(
                    settings["chainclients"]["bitcoin"]["connection_type"] == "rpc"
                )
                assert settings.get("use_tor", False) is False

            logging.info("notorproxy")
            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "-addcoin=firo",
                "--usetorproxy",
                "--notorproxy",
            ]
            with patch("sys.stderr", new=StringIO()) as fake_stderr:
                with patch.object(sys, "argv", testargs):
                    with self.assertRaises(SystemExit) as cm:
                        prepareSystem.main()

            self.assertEqual(cm.exception.code, 1)
            self.assertTrue(
                "--usetorproxy and --notorproxy together" in fake_stderr.getvalue()
            )

            logger.info("Test persistent setup config.")

            with open(config_path) as fs:
                settings = json.load(fs)
            assert settings.get("use_tor", False) is False
            assert "setup_docker_mode" not in settings
            assert "setup_local_tor" not in settings
            assert "setup_tor_control_listen_interface" not in settings
            assert "setup_torrc_dns_host" not in settings

            # Set BSX_LOCAL_TOR to false
            os.environ["BSX_LOCAL_TOR"] = "false"
            # Reimport to reset globals and set env
            importlib.reload(prepareSystem)

            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "--disabletor",
            ]
            with patch.object(sys, "argv", testargs):
                prepareSystem.main()

            os.environ["BSX_LOCAL_TOR"] = "true"
            # Reimport to reset globals and set env
            importlib.reload(prepareSystem)

            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "--enabletor",
            ]
            with patch("sys.stderr", new=StringIO()) as fake_stderr:
                with patch.object(sys, "argv", testargs):
                    with self.assertRaises(SystemExit) as cm:
                        prepareSystem.main()

            self.assertEqual(cm.exception.code, 1)
            self.assertTrue(
                "Env var BSX_LOCAL_TOR differs from saved config"
                in fake_stderr.getvalue()
            )

            os.environ["BSX_ALLOW_ENV_OVERRIDE"] = "true"
            os.environ["TOR_CONTROL_LISTEN_INTERFACE"] = "127.1.1.1"
            importlib.reload(prepareSystem)

            with patch.object(sys, "argv", testargs):
                prepareSystem.main()

            with open(config_path) as fs:
                settings = json.load(fs)
            assert settings.get("use_tor", False) is True
            assert "setup_docker_mode" not in settings
            assert settings["setup_local_tor"] is True
            assert settings["setup_tor_control_listen_interface"] == "127.1.1.1"
            assert "setup_torrc_dns_host" not in settings

            particl_config_path = os.path.join(
                test_path_plain, "particl", "particl.conf"
            )
            with open(particl_config_path) as fs:
                particl_conf = fs.read()
                assert "bind=127.1.1.1:" in particl_conf

            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "-disablecoin=bitcoin",
            ]
            with patch.object(sys, "argv", testargs):
                prepareSystem.main()

            os.environ["TOR_PROXY_HOST"] = "127.2.2.2"
            del os.environ["BSX_ALLOW_ENV_OVERRIDE"]
            importlib.reload(prepareSystem)

            testargs = [
                "basicswap-prepare",
                "-datadir=" + test_path_plain,
                "-addcoin=bitcoin",
                "-notorproxy",  # Disable TOR connection check
            ]
            with patch("sys.stderr", new=StringIO()) as fake_stderr:
                with patch.object(sys, "argv", testargs):
                    with self.assertRaises(SystemExit) as cm:
                        prepareSystem.main()

            self.assertEqual(cm.exception.code, 1)
            self.assertTrue(
                "Env var TOR_PROXY_HOST differs from saved config"
                in fake_stderr.getvalue()
            )

        finally:
            del prepareSystem  # Does not cause next import to refresh globals and env (tested v3.13)

    def test_encrypted(self):
        if os.path.exists(test_path_encrypted):
            shutil.rmtree(test_path_encrypted)
        if bin_path != "":
            os.makedirs(test_path_encrypted)
            os.symlink(bin_path, os.path.join(test_path_encrypted, "bin"))

        env_vars = [
            ("WALLET_ENCRYPTION_PWD", "test123"),
        ]
        testargs = (
            "basicswap-prepare",
            "-datadir=" + test_path_encrypted,
            "-withcoin=litecoin,monero",
        )
        process = multiprocessing.Process(
            target=start_prepare, args=(testargs, env_vars)
        )
        process.start()
        process.join()
        assert process.exitcode == 0

        logger.info(
            "Should not be able to add a coin without setting WALLET_ENCRYPTION_PWD"
        )
        testargs = (
            "basicswap-prepare",
            "-datadir=" + test_path_encrypted,
            "-addcoin=bitcoin",
        )
        process = multiprocessing.Process(target=start_prepare, args=(testargs, []))
        process.start()
        process.join()
        assert process.exitcode == 1

        testargs = (
            "basicswap-prepare",
            "-datadir=" + test_path_encrypted,
            "-addcoin=bitcoin",
        )
        process = multiprocessing.Process(
            target=start_prepare, args=(testargs, env_vars)
        )
        process.start()
        process.join()
        assert process.exitcode == 0

    def test_encrypt(self):
        if os.path.exists(test_path_encrypt):
            shutil.rmtree(test_path_encrypt)
        if bin_path != "":
            os.makedirs(test_path_encrypt)
            os.symlink(bin_path, os.path.join(test_path_encrypt, "bin"))

        testargs = (
            "basicswap-prepare",
            "-regtest=1",
            "-datadir=" + test_path_encrypt,
            "-withcoin=litecoin,monero",
        )
        process = multiprocessing.Process(target=start_prepare, args=(testargs,))
        process.start()
        process.join()
        assert process.exitcode == 0

        logger.info("basicswap-run should fail if WALLET_ENCRYPTION_PWD is set")
        env_vars = [
            ("WALLET_ENCRYPTION_PWD", "test123"),
        ]
        testargs = ("basicswap-run", "-regtest=1", "-datadir=" + test_path_encrypt)
        process = multiprocessing.Process(target=start_run, args=(testargs, env_vars))
        process.start()
        process.join()
        assert process.exitcode == 1

        testargs = ("basicswap-run", "-regtest=1", "-datadir=" + test_path_encrypt)
        process = multiprocessing.Process(target=start_run, args=(testargs,))
        process.start()

        waitForServer(delay_event, 12700)
        rv = read_json_api(
            12700, "setpassword", {"oldpassword": "wrongpass", "newpassword": "test123"}
        )
        assert "error" in rv

        rv = read_json_api(
            12700, "setpassword", {"oldpassword": "", "newpassword": "test123"}
        )
        assert "success" in rv

        rv = read_json_api(
            12700, "setpassword", {"oldpassword": "test123", "newpassword": "next123"}
        )
        assert "success" in rv

        rv = read_json_api(12700, "lock")
        assert "success" in rv

        rv = read_json_api(12700, "wallets")
        assert "error" in rv

        rv = read_json_api(12700, "unlock", {"password": "next123"})
        assert "success" in rv

        rv = read_json_api(12700, "wallets")
        assert "PART" in rv

        process.terminate()
        process.join()
        assert process.exitcode == 0


if __name__ == "__main__":
    unittest.main()
