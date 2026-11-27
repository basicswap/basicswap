# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Foundry anvil with SwapCreator deployed, for the EVM tests.

Needs anvil in ANVIL_BINDIR (default DEFAULT_TEST_BINDIR/foundry).
"""

import logging
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time

import basicswap.config as cfg
from basicswap.db import DBMethods, create_db
from basicswap.interface.eth.eth import ETHInterface
from basicswap.interface.evm import swapcreator
from basicswap.interface.evm.keys import LocalAccount
from basicswap.interface.evm.rpc import EthRpcClient, sign_tx
from basicswap.interface.evm.swapfactory import SwapFactory

# anvil deterministic accounts (mnemonic: test test ... junk)
KEY_0 = bytes.fromhex(
    "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)
KEY_1 = bytes.fromhex(
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
)
CHAIN_ID = 31337

ANVIL_BIN = os.path.join(
    os.getenv("ANVIL_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "foundry")),
    "anvil",
)
REQUIREMENTS_MET = os.path.exists(ANVIL_BIN)
SKIP_REASON = f"requires Foundry anvil ({ANVIL_BIN})"


def load_bytecode(design: str) -> bytes:
    path = os.path.join(os.path.dirname(swapcreator.__file__), f"{design}_bytecode.hex")
    with open(path) as fp:
        return bytes.fromhex(fp.read().strip())


class FactoryETHInterface(ETHInterface):
    SWAP_CONTRACT = SwapFactory


INTERFACES = {"swapcreator": ETHInterface, "swapfactory": FactoryETHInterface}


class WalletDB(DBMethods):
    """The swap-client surface an EVM interface uses, on its own sqlite file."""

    use_tor_proxy = False

    def __init__(self, sqlite_file: str):
        self.mxDB = threading.RLock()
        self.sqlite_file = sqlite_file
        self.log = logging.getLogger("evm-test")
        create_db(sqlite_file, self.log)

    def getChainClientSettings(self, coin_type) -> dict:
        return {}

    def getLockedState(self):
        return False, False


class Anvil:
    def __init__(self, port: int, design: str = "swapcreator"):
        self.port = port
        self.design = design
        self._db_dir = tempfile.mkdtemp(prefix="bsx-evm-")
        self.proc = subprocess.Popen(
            [ANVIL_BIN, "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.rpc = EthRpcClient([(f"http://127.0.0.1:{port}", None)], chain_id=CHAIN_ID)
        for _ in range(50):
            if self.rpc.is_connected():
                break
            time.sleep(0.2)
        assert self.rpc.is_connected(), "anvil did not start"
        self.contract_address = self._deploy(LocalAccount(KEY_0))

    def stop(self) -> None:
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self._db_dir, ignore_errors=True)

    def _deploy(self, owner) -> str:
        rpc = self.rpc
        gas_price: int = rpc.gas_price()
        tx_hash, raw = sign_tx(
            {
                "chainId": CHAIN_ID,
                "nonce": rpc.get_transaction_count(owner.address),
                "maxPriorityFeePerGas": gas_price,
                "maxFeePerGas": gas_price * 2,
                "gas": 6_000_000,
                "value": 0,
                "data": load_bytecode(self.design),
            },
            owner.key,
        )
        rpc.broadcast(tx_hash, raw)
        receipt = rpc.wait_receipt(tx_hash)
        return receipt["contractAddress"]

    def iface(self, key) -> ETHInterface:
        cs = {
            "blocks_confirmed": 1,
            "chain_id": CHAIN_ID,
            "rpcport": self.port,
            "rpchost": "127.0.0.1",
            "contract_address": self.contract_address,
        }
        db = WalletDB(tempfile.mktemp(suffix=".sqlite", dir=self._db_dir))
        ci = INTERFACES[self.design](cs, "regtest", swap_client=db)
        ci.setActiveAccount(key)
        return ci

    def warp(self, seconds: int) -> None:
        self.rpc.request("evm_increaseTime", [seconds])
        self.rpc.request("evm_mine")
