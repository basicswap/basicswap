"""Opt-in HSD/HSRD regtest check for the wallet and sync HTTP wire shapes."""

import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from basicswap.interface.hns.node_rpc import HnsNodeRpc
from basicswap.interface.hns.wallet_bridge import initialize_hns_wallet


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@unittest.skipUnless(
    os.getenv("HSD_BIN") and os.getenv("HSRD_BIN"),
    "set HSD_BIN and HSRD_BIN for isolated regtest",
)
class HnsNodeRpcRegtest(unittest.TestCase):
    def test_synced_hsrd_matches_wallet_chain_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="basicswap-hsrd-sync-") as directory:
            root = Path(directory)
            authorization = root / "authorization"
            authorization.write_text("Bearer isolated-regtest", encoding="ascii")
            authorization.chmod(0o600)
            hsd_rpc, hsd_p2p, hsrd_rpc, hsrd_p2p = (free_port() for _ in range(4))
            programs = (
                (
                    "hsd",
                    [
                        os.environ["HSD_BIN"],
                        "--network=regtest",
                        f"--prefix={root / 'hsd'}",
                        f"--http-port={hsd_rpc}",
                        f"--port={hsd_p2p}",
                        "--host=127.0.0.1",
                        "--http-host=127.0.0.1",
                        "--listen",
                        "--no-dns",
                        "--no-auth",
                    ],
                ),
                (
                    "hsrd",
                    [
                        os.environ["HSRD_BIN"],
                        "--network",
                        "regtest",
                        "--data-dir",
                        str(root / "hsrd"),
                        "--rpc-bind",
                        f"127.0.0.1:{hsrd_rpc}",
                        "--rpc-authorization-header-file",
                        str(authorization),
                        "--authority-mode",
                        "native",
                        "--native-sync",
                        "--wallet-index",
                        "--p2p-listen",
                        f"127.0.0.1:{hsrd_p2p}",
                        "--connect",
                        f"127.0.0.1:{hsd_p2p}",
                    ],
                ),
            )
            processes = []
            logs = []
            try:
                for name, command in programs:
                    log = (root / f"{name}.log").open("w", encoding="utf-8")
                    logs.append(log)
                    processes.append(
                        subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                    )
                client = HnsNodeRpc(hsrd_rpc, authorization.read_text())
                deadline = time.monotonic() + 60
                last_error = None
                while time.monotonic() < deadline:
                    if any(process.poll() is not None for process in processes):
                        break
                    try:
                        binding = client.bound_snapshot("regtest")
                        if client.sync_ready("regtest", binding):
                            self.assertGreaterEqual(binding.tip["height"], 0)
                            if os.getenv("HNS_BRIDGE_BIN"):
                                database = root / "hns-wallet.db"
                                _, fingerprint, _ = initialize_hns_wallet(
                                    os.environ["HNS_BRIDGE_BIN"],
                                    database,
                                    "regtest",
                                    0,
                                    "test passphrase",
                                )
                                coin_settings = {
                                    "connection_type": "rpc",
                                    "rpchost": "127.0.0.1",
                                    "rpcport": hsrd_rpc,
                                    "rpc_authorization_file": str(authorization),
                                    "bridge_executable": os.environ["HNS_BRIDGE_BIN"],
                                    "wallet_database": str(database),
                                    "wallet_seed_fingerprint": fingerprint.hex(),
                                }
                                app = SimpleNamespace(
                                    coin_clients={Coins.HNS: coin_settings},
                                    chain="regtest",
                                    getBaseAltruistic=lambda: False,
                                )
                                coin = BasicSwap.createInterface(app, Coins.HNS)
                                try:
                                    coin.testDaemonRPC()
                                    coin.unlockWallet("test passphrase")
                                    self.assertEqual(coin.getSpendableBalance(), 0)
                                    self.assertTrue(
                                        coin.getMainWalletAddress().startswith("rs1")
                                    )
                                    self.assertEqual(
                                        coin.getBlockchainInfo()[
                                            "verificationprogress"
                                        ],
                                        1.0,
                                    )
                                finally:
                                    coin.close()
                            return
                        last_error = "HSRD scheduler has not reached the wallet tip"
                    except Exception as exc:  # noqa: BLE001
                        last_error = str(exc)
                    time.sleep(0.5)
                diagnostics = "\n".join(
                    (root / f"{name}.log").read_text(encoding="utf-8")[-1500:]
                    for name, _ in programs
                )
                self.fail(f"HSRD did not become ready: {last_error}\n{diagnostics}")
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                for process in processes:
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                for log in logs:
                    log.close()
