"""Run the opt-in Rust HNS bridge value test on isolated HSD/HSRD regtest.

Example::

    python -m tests.basicswap.run_hns_bridge_regtest \
      --hsd ../hsd/bin/hsd --hsrd /path/to/hsrd \
      --wallet-repo ../hns-wallet-rs

HSD supplies a disposable miner and funding wallet. HSRD remains the node
backend used by the bridge under test. Nothing connects to a public network.
"""

import argparse
import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from basicswap.interface.hns.node_rpc import HnsNodeRpc


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hsd", type=Path, required=True)
    parser.add_argument("--hsrd", type=Path, required=True)
    parser.add_argument("--wallet-repo", type=Path, required=True)
    args = parser.parse_args()
    hsd = args.hsd.resolve(strict=True)
    hsrd = args.hsrd.resolve(strict=True)
    wallet_repo = args.wallet_repo.resolve(strict=True)
    hsd_cli = hsd.parent / "hsd-cli"
    hsw_cli = hsd.parent / "hsw-cli"
    for executable in (hsd, hsrd, hsd_cli, hsw_cli):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError(f"executable unavailable: {executable}")

    with tempfile.TemporaryDirectory(prefix="basicswap-hns-bridge-") as directory:
        root = Path(directory)
        hsd_prefix = root / "hsd"
        auth_file = root / "hsrd-auth"
        authorization = "Bearer isolated-regtest"
        auth_file.write_text(authorization, encoding="ascii")
        auth_file.chmod(0o600)
        hsd_rpc, hsd_p2p, hsw_rpc, hsrd_rpc, hsrd_p2p = (free_port() for _ in range(5))
        programs = (
            (
                "hsd",
                [
                    str(hsd),
                    "--network=regtest",
                    f"--prefix={hsd_prefix}",
                    "--host=127.0.0.1",
                    "--http-host=127.0.0.1",
                    f"--http-port={hsd_rpc}",
                    f"--port={hsd_p2p}",
                    "--wallet-http-host=127.0.0.1",
                    f"--wallet-http-port={hsw_rpc}",
                    "--wallet-no-auth",
                    "--no-auth",
                    "--no-dns",
                    "--listen",
                ],
            ),
            (
                "hsrd",
                [
                    str(hsrd),
                    "--network",
                    "regtest",
                    "--data-dir",
                    str(root / "hsrd"),
                    "--rpc-bind",
                    f"127.0.0.1:{hsrd_rpc}",
                    "--rpc-authorization-header-file",
                    str(auth_file),
                    "--authority-mode",
                    "native",
                    "--native-sync",
                    "--wallet-index",
                    "--transaction-relay",
                    "--mining-engine",
                    "--p2p-listen",
                    f"127.0.0.1:{hsrd_p2p}",
                    "--connect",
                    f"127.0.0.1:{hsd_p2p}",
                ],
            ),
        )
        processes = []
        logs = []

        def hsd_call(binary, port, *command):
            return subprocess.run(
                [
                    str(binary),
                    "--network=regtest",
                    f"--prefix={hsd_prefix}",
                    f"--http-port={port}",
                    *command,
                ],
                capture_output=True,
                text=True,
                timeout=180,
                check=True,
            ).stdout.strip()

        try:
            for name, command in programs:
                log = (root / f"{name}.log").open("w", encoding="utf-8")
                logs.append(log)
                processes.append(
                    subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                )
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError("HNS regtest node exited during startup")
                try:
                    hsd_call(hsd_cli, hsd_rpc, "rpc", "getblockchaininfo")
                    break
                except (OSError, subprocess.CalledProcessError):
                    time.sleep(0.5)
            else:
                raise RuntimeError("HSD regtest RPC did not start")
            miner_address = json.loads(
                hsd_call(hsw_cli, hsw_rpc, "address", "default")
            )["address"]
            if not miner_address.startswith("rs1"):
                raise ValueError("HSD wallet returned an invalid regtest address")
            hsd_call(hsd_cli, hsd_rpc, "rpc", "generatetoaddress", "110", miner_address)
            client = HnsNodeRpc(hsrd_rpc, authorization)
            deadline = time.monotonic() + 120
            last_error = None
            while time.monotonic() < deadline:
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError("HNS regtest node exited during synchronization")
                try:
                    binding = client.bound_snapshot("regtest")
                    if binding.tip["height"] >= 110 and client.sync_ready(
                        "regtest", binding
                    ):
                        break
                except Exception as exc:  # noqa: BLE001
                    last_error = exc
                time.sleep(0.5)
            else:
                raise RuntimeError(
                    f"HSRD did not synchronize to the funded HSD tip: {last_error}"
                )
            environment = os.environ.copy()
            environment.update(
                {
                    "BASICSWAP_HSD_CLI": str(hsd_cli),
                    "BASICSWAP_HSW_CLI": str(hsw_cli),
                    "BASICSWAP_HSD_REGTEST_PREFIX": str(hsd_prefix),
                    "BASICSWAP_HSD_REGTEST_RPC_PORT": str(hsd_rpc),
                    "BASICSWAP_HSW_REGTEST_RPC_PORT": str(hsw_rpc),
                    "BASICSWAP_HSD_MINER_ADDRESS": miner_address,
                    "BASICSWAP_HSRD_REGTEST_RPC": f"127.0.0.1:{hsrd_rpc}",
                    "BASICSWAP_HSRD_REGTEST_AUTH_FILE": str(auth_file),
                }
            )
            subprocess.run(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--manifest-path",
                    "integrations/basicswap-bridge/Cargo.toml",
                    "--test",
                    "process",
                    "funded_lock_uses_real_hsrd_wallet_index",
                    "--",
                    "--ignored",
                    "--nocapture",
                ],
                cwd=wallet_repo,
                env=environment,
                timeout=240,
                check=True,
            )
        except Exception:
            for log in logs:
                log.flush()
            for name, _ in programs:
                path = root / f"{name}.log"
                if path.exists():
                    print(
                        f"{name} log tail:\n{path.read_text(encoding='utf-8')[-2000:]}"
                    )
            raise
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


if __name__ == "__main__":
    main()
