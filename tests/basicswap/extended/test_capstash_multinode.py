#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import os
import shutil
import socket
import tempfile
import time
import unittest

from basicswap.bin.run import startDaemon
from basicswap.interface.capstash.capstash import CapStashInterface


EXPECTED_DAEMON_SHA256 = (
    "3701ca15eedd780644bd40a7d820bfc64b5bd321ca78986434597db259773872"
)
EXPECTED_CLI_SHA256 = (
    "8f2704ab3314191a89860f7c444de04c8e141e69db54e64affb2f39db75c9e3b"
)


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wait_until(predicate, description, timeout=30):
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            if predicate():
                return
        except Exception as error:
            last_error = error
        time.sleep(0.1)
    raise TimeoutError(f"Timed out waiting for {description}: {last_error}")


@unittest.skipUnless(os.getenv("CAPS_BINDIR"), "set CAPS_BINDIR")
class TestCapStashMultiNode(unittest.TestCase):
    def test_two_node_regtest(self):
        bindir = os.path.abspath(os.environ["CAPS_BINDIR"])
        suffix = ".exe" if os.name == "nt" else ""
        daemon_name = "CapStashd" + suffix
        cli_name = "CapStash-cli" + suffix
        daemon_path = os.path.join(bindir, daemon_name)
        cli_path = os.path.join(bindir, cli_name)
        self.assertTrue(os.path.isdir(bindir))
        self.assertTrue(os.path.isfile(daemon_path))
        self.assertTrue(os.path.isfile(cli_path))
        self.assertEqual(file_hash(daemon_path), EXPECTED_DAEMON_SHA256)
        self.assertEqual(file_hash(cli_path), EXPECTED_CLI_SHA256)

        base_port = int(os.getenv("CAPS_TEST_BASE_PORT", "29600"))
        ports = [(base_port, base_port + 1), (base_port + 2, base_port + 3)]
        for rpc_port, p2p_port in ports:
            for port in (rpc_port, p2p_port):
                with socket.socket() as sock:
                    sock.bind(("127.0.0.1", port))

        preserve = os.getenv("CAPS_PRESERVE_TEST_DATADIRS", "0") == "1"
        root = tempfile.mkdtemp(prefix="basicswap-capstash-multinode-")
        daemons = []
        interfaces = []
        failed = True
        try:
            for node_id, (rpc_port, p2p_port) in enumerate(ports):
                datadir = os.path.join(root, f"node{node_id}")
                os.makedirs(datadir)
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
                        "-listenonion=0",
                        "-rpcbind=127.0.0.1",
                        "-rpcallowip=127.0.0.1",
                        f"-rpcport={rpc_port}",
                        f"-bind=127.0.0.1:{p2p_port}",
                        "-fallbackfee=0.0002",
                    ],
                    {"coin_name": "capstash", "stdout_to_file": True},
                )
                daemons.append(daemon)
                cookie_path = os.path.join(datadir, "regtest", ".cookie")
                wait_until(
                    lambda p=cookie_path: os.path.exists(p),
                    f"node {node_id} RPC cookie",
                )
                with open(cookie_path, encoding="utf-8") as fp:
                    auth = fp.read().strip()
                ci = CapStashInterface(
                    {
                        "rpcport": rpc_port,
                        "rpcauth": auth,
                        "wallet_name": f"node{node_id}_wallet",
                        "blocks_confirmed": 1,
                        "conf_target": 2,
                        "use_segwit": True,
                        "use_csv": True,
                        "use_descriptors": True,
                        "connection_type": "rpc",
                        "watch_wallet_name": f"node{node_id}_watch",
                    },
                    "regtest",
                )
                wait_until(
                    lambda c=ci: c.rpc("getblockchaininfo")["chain"] == "regtest",
                    f"node {node_id} RPC",
                )
                ci.rpc(
                    "createwallet",
                    [f"node{node_id}_wallet", False, False, "", False, True],
                )
                interfaces.append(ci)

            interfaces[0].rpc("addnode", [f"127.0.0.1:{ports[1][1]}", "onetry"])
            wait_until(
                lambda: interfaces[0].rpc("getconnectioncount") >= 1
                and interfaces[1].rpc("getconnectioncount") >= 1,
                "peer connection",
            )

            mining_address = interfaces[0].rpc_wallet(
                "getnewaddress", ["mining", "bech32"]
            )
            hashes = interfaces[0].rpc(
                "generatetoaddress", [102, mining_address, 1000000]
            )
            self.assertEqual(len(hashes), 102)
            wait_until(
                lambda: interfaces[1].rpc("getblockcount") == 102,
                "block propagation",
            )
            self.assertGreater(interfaces[0].rpc_wallet("getbalance"), 0)

            receive_address = interfaces[1].rpc_wallet(
                "getnewaddress", ["receive", "bech32"]
            )
            txid = interfaces[0].rpc_wallet("sendtoaddress", [receive_address, 1])
            wait_until(
                lambda: txid in interfaces[1].rpc("getrawmempool"),
                "transaction propagation",
            )
            interfaces[0].rpc("generatetoaddress", [1, mining_address, 1000000])
            wait_until(
                lambda: interfaces[1].rpc("getblockcount") == 103,
                "transaction confirmation",
            )
            self.assertGreaterEqual(interfaces[1].rpc_wallet("getbalance"), 1)

            watch_source = interfaces[0].rpc_wallet(
                "getnewaddress", ["watch_source", "bech32"]
            )
            watch_pubkey = interfaces[0].rpc_wallet(
                "getaddressinfo", [watch_source]
            )["pubkey"]
            watch_descriptor = interfaces[1].rpc(
                "getdescriptorinfo", [f"wsh(pk({watch_pubkey}))"]
            )["descriptor"]
            watch_address = interfaces[1].rpc(
                "deriveaddresses", [watch_descriptor]
            )[0]
            interfaces[1].rpc(
                "createwallet",
                ["node1_watch", True, True, "", False, True],
            )
            watch_info = interfaces[1].rpc_wallet_watch("getwalletinfo")
            self.assertFalse(watch_info["private_keys_enabled"])
            imported = interfaces[1].rpc_wallet_watch(
                "importdescriptors",
                [[{"desc": watch_descriptor, "timestamp": "now"}]],
            )
            self.assertTrue(imported[0]["success"])
            watch_txid = interfaces[0].rpc_wallet(
                "sendtoaddress", [watch_address, 0.25]
            )
            watch_block = interfaces[0].rpc(
                "generatetoaddress", [1, mining_address, 1000000]
            )[0]
            wait_until(
                lambda: interfaces[1].rpc("getblockcount") == 104,
                "watched output confirmation",
            )
            watched_utxos = interfaces[1].rpc_wallet_watch(
                "listunspent", [1, 9999999, [watch_address]],
            )
            self.assertEqual(len(watched_utxos), 1)
            self.assertEqual(watched_utxos[0]["txid"], watch_txid)
            self.assertTrue(watched_utxos[0]["solvable"])
            interfaces[1].rpc_wallet_watch("unloadwallet")
            self.assertNotIn("node1_watch", interfaces[1].rpc("listwallets"))

            # CapStash did not auto-load wallets in the standalone probe.
            interfaces[1].rpc("stop")
            daemons[1].handle.wait(timeout=20)
            if daemons[1].handle.stdin is not None:
                daemons[1].handle.stdin.close()
            for fp in daemons[1].files:
                fp.close()
            datadir = os.path.join(root, "node1")
            daemons[1] = startDaemon(
                datadir,
                bindir,
                daemon_name,
                [
                    "-regtest",
                    "-server=1",
                    "-connect=0",
                    "-rpcbind=127.0.0.1",
                    "-rpcallowip=127.0.0.1",
                    f"-rpcport={ports[1][0]}",
                    f"-bind=127.0.0.1:{ports[1][1]}",
                ],
                {"coin_name": "capstash", "stdout_to_file": True},
            )
            cookie_path = os.path.join(datadir, "regtest", ".cookie")
            wait_until(lambda: os.path.exists(cookie_path), "restarted RPC cookie")
            with open(cookie_path, encoding="utf-8") as fp:
                auth = fp.read().strip()
            restarted = CapStashInterface(
                {
                    "rpcport": ports[1][0],
                    "rpcauth": auth,
                    "wallet_name": "node1_wallet",
                    "blocks_confirmed": 1,
                    "conf_target": 2,
                    "use_segwit": True,
                    "use_csv": True,
                    "use_descriptors": True,
                    "connection_type": "rpc",
                    "watch_wallet_name": "node1_watch",
                },
                "regtest",
            )
            wait_until(lambda: restarted.rpc("getblockcount") == 104, "restart")
            self.assertNotIn("node1_wallet", restarted.rpc("listwallets"))
            self.assertNotIn("node1_watch", restarted.rpc("listwallets"))
            restarted.rpc("loadwallet", ["node1_wallet"])
            restarted.rpc("loadwallet", ["node1_watch"])
            self.assertGreaterEqual(restarted.rpc_wallet("getbalance"), 1)
            recovered_descriptors = restarted.rpc_wallet_watch("listdescriptors")[
                "descriptors"
            ]
            self.assertTrue(
                any(entry["desc"] == watch_descriptor for entry in recovered_descriptors)
            )
            recovered_utxos = restarted.rpc_wallet_watch(
                "listunspent", [1, 9999999, [watch_address]],
            )
            self.assertEqual(len(recovered_utxos), 1)
            self.assertEqual(recovered_utxos[0]["txid"], watch_txid)

            unsigned_destination = interfaces[0].rpc_wallet(
                "getnewaddress", ["unsigned_destination", "bech32"]
            )
            unsigned_raw = restarted.rpc(
                "createrawtransaction",
                [
                    [
                        {
                            "txid": recovered_utxos[0]["txid"],
                            "vout": recovered_utxos[0]["vout"],
                        }
                    ],
                    {unsigned_destination: 0.249},
                ],
            )
            unsigned_result = restarted.rpc_wallet_watch(
                "signrawtransactionwithwallet",
                [unsigned_raw],
            )
            self.assertFalse(unsigned_result["complete"])

            interfaces[1] = restarted

            restarted.rpc("addnode", [f"127.0.0.1:{ports[0][1]}", "onetry"])
            wait_until(
                lambda: restarted.rpc("getconnectioncount") >= 1,
                "restarted peer connection",
            )
            found = restarted.getLockTxHeight(
                bytes.fromhex(watch_txid),
                watch_address,
                restarted.make_int(0.25),
                0,
                vout=recovered_utxos[0]["vout"],
            )
            self.assertEqual(found["depth"], 1)

            # Remove the one-block confirmation on both controlled nodes.
            self.assertEqual(interfaces[0].rpc("getbestblockhash"), watch_block)
            interfaces[0].rpc("invalidateblock", [watch_block])
            restarted.rpc("invalidateblock", [watch_block])
            self.assertEqual(interfaces[0].rpc("getblockcount"), 103)
            self.assertEqual(restarted.rpc("getblockcount"), 103)
            self.assertIn(watch_txid, interfaces[0].rpc("getrawmempool"))
            self.assertIn(watch_txid, restarted.rpc("getrawmempool"))
            reorged = restarted.getLockTxHeight(
                bytes.fromhex(watch_txid),
                watch_address,
                restarted.make_int(0.25),
                0,
                vout=recovered_utxos[0]["vout"],
            )
            self.assertEqual(reorged["depth"], 0)

            replacement_address = interfaces[0].rpc_wallet(
                "getnewaddress", ["replacement_branch", "bech32"]
            )
            replacement_hashes = interfaces[0].rpc(
                "generatetoaddress", [2, replacement_address, 1000000]
            )
            self.assertEqual(len(replacement_hashes), 2)
            wait_until(
                lambda: restarted.rpc("getblockcount") == 105,
                "replacement branch propagation",
            )
            reconfirmed = restarted.getLockTxHeight(
                bytes.fromhex(watch_txid),
                watch_address,
                restarted.make_int(0.25),
                0,
                vout=recovered_utxos[0]["vout"],
            )
            self.assertGreaterEqual(reconfirmed["depth"], 1)
            self.assertEqual(reconfirmed["height"], 104)
            failed = False
        finally:
            for ci in interfaces:
                try:
                    ci.rpc("stop")
                except Exception:
                    pass
            for daemon in daemons:
                try:
                    daemon.handle.wait(timeout=20)
                except Exception:
                    try:
                        daemon.handle.kill()
                        daemon.handle.wait(timeout=10)
                    except Exception:
                        pass
                if daemon.handle.stdin is not None:
                    daemon.handle.stdin.close()
                for fp in daemon.files:
                    if not fp.closed:
                        fp.close()
            if not preserve and not failed:
                shutil.rmtree(root)
            elif failed:
                print(f"Preserved failed CapStash test datadirs at {root}")


if __name__ == "__main__":
    unittest.main()
