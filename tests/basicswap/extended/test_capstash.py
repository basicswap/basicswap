#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import os
import socket
import tempfile
import time
import unittest

from basicswap.bin.run import startDaemon
from basicswap.interface.capstash.capstash import CapStashInterface


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def close_daemon_files(daemon):
    for stream in (
        daemon.handle.stdin,
        daemon.handle.stdout,
        daemon.handle.stderr,
    ):
        if stream is not None and not stream.closed:
            stream.close()
    for fp in daemon.files:
        if not fp.closed:
            fp.close()


@unittest.skipUnless(
    os.getenv("CAPS_BINDIR") and os.getenv("CAPS_DAEMON_SHA256"),
    "set CAPS_BINDIR and CAPS_DAEMON_SHA256 for the isolated local-binary test",
)
class TestCapStashLocalBinary(unittest.TestCase):
    def test_daemon_wallet_address_and_mining(self):
        bindir = os.path.abspath(os.environ["CAPS_BINDIR"])
        daemon_name = "CapStashd.exe" if os.name == "nt" else "CapStashd"
        daemon_path = os.path.join(bindir, daemon_name)
        self.assertEqual(
            sha256_file(daemon_path).lower(),
            os.environ["CAPS_DAEMON_SHA256"].lower(),
        )

        rpc_port = int(os.getenv("CAPS_TEST_RPC_PORT", "29501"))
        p2p_port = int(os.getenv("CAPS_TEST_P2P_PORT", "29502"))
        for port in (rpc_port, p2p_port):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))

        with tempfile.TemporaryDirectory(prefix="basicswap-capstash-regtest-") as datadir:
            daemon = startDaemon(
                datadir,
                bindir,
                daemon_name,
                [
                    "-regtest",
                    "-server=1",
                    "-connect=0",
                    "-dnsseed=0",
                    "-discover=0",
                    "-rpcbind=127.0.0.1",
                    "-rpcallowip=127.0.0.1",
                    f"-rpcport={rpc_port}",
                    f"-bind=127.0.0.1:{p2p_port}",
                    "-fallbackfee=0.0002",
                ],
                {"coin_name": "capstash", "stdout_to_file": True},
            )
            ci = None
            try:
                cookie_path = os.path.join(datadir, "regtest", ".cookie")
                deadline = time.time() + 30
                while not os.path.exists(cookie_path):
                    if daemon.handle.poll() is not None:
                        self.fail("CapStash daemon exited during startup")
                    if time.time() >= deadline:
                        self.fail("CapStash RPC cookie was not created")
                    time.sleep(0.1)
                with open(cookie_path, encoding="utf-8") as fp:
                    cookie_auth = fp.read().strip()

                ci = CapStashInterface(
                    {
                        "rpcport": rpc_port,
                        "rpcauth": cookie_auth,
                        "wallet_name": "wallet.dat",
                        "blocks_confirmed": 1,
                        "conf_target": 2,
                        "use_segwit": True,
                        "use_csv": True,
                        "use_descriptors": True,
                        "connection_type": "rpc",
                    },
                    "regtest",
                )
                deadline = time.time() + 30
                while True:
                    try:
                        self.assertEqual(ci.rpc("getblockchaininfo")["chain"], "regtest")
                        break
                    except Exception:
                        if time.time() >= deadline:
                            raise
                        time.sleep(0.1)

                ci.rpc("createwallet", ["wallet.dat", False, False, "", False, True])
                wallet_info = ci.rpc_wallet("getwalletinfo")
                self.assertTrue(wallet_info["descriptors"])
                address = ci.rpc_wallet("getnewaddress", ["", "bech32"])
                self.assertTrue(address.startswith("rcap1"))
                hashes = ci.rpc("generatetoaddress", [1, address, 1000000])
                self.assertEqual(len(hashes), 1)
            finally:
                if ci is not None:
                    try:
                        ci.rpc("stop")
                    except Exception:
                        pass
                try:
                    daemon.handle.wait(timeout=20)
                except Exception:
                    daemon.handle.kill()
                    daemon.handle.wait(timeout=10)
                close_daemon_files(daemon)


if __name__ == "__main__":
    unittest.main()
