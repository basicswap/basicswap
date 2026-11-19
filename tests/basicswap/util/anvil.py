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

from eth_account import Account
from web3 import Web3

import basicswap.config as cfg
from basicswap.db import DBMethods, create_db
from basicswap.interface.eth.eth import ETHInterface
from basicswap.interface.evm import swapcreator

# anvil deterministic accounts (mnemonic: test test ... junk)
KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
KEY_1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

ANVIL_BIN = os.path.join(
    os.getenv("ANVIL_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "foundry")),
    "anvil",
)
REQUIREMENTS_MET = os.path.exists(ANVIL_BIN)
SKIP_REASON = f"requires Foundry anvil ({ANVIL_BIN})"
BYTECODE_PATH = os.path.join(
    os.path.dirname(swapcreator.__file__), "swapcreator_bytecode.hex"
)


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
    def __init__(self, port: int):
        self.port = port
        self._db_dir = tempfile.mkdtemp(prefix="bsx-evm-")
        self.proc = subprocess.Popen(
            [ANVIL_BIN, "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.w3 = Web3(Web3.HTTPProvider(f"http://127.0.0.1:{port}"))
        for _ in range(50):
            if self.w3.is_connected():
                break
            time.sleep(0.2)
        assert self.w3.is_connected(), "anvil did not start"
        self.contract_address = self._deploy(Account.from_key(KEY_0))

    def stop(self) -> None:
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self._db_dir, ignore_errors=True)

    def _deploy(self, owner) -> str:
        w3 = self.w3
        with open(BYTECODE_PATH) as fp:
            bytecode = fp.read().strip()
        C = w3.eth.contract(abi=swapcreator.load_abi(), bytecode=bytecode)
        tx = C.constructor().build_transaction(
            {
                "from": owner.address,
                "nonce": w3.eth.get_transaction_count(owner.address),
                "gas": 6_000_000,
                "maxFeePerGas": w3.eth.gas_price * 2,
                "maxPriorityFeePerGas": w3.eth.gas_price,
                "chainId": w3.eth.chain_id,
            }
        )
        signed = w3.eth.account.sign_transaction(tx, private_key=owner.key)
        rcpt = w3.eth.wait_for_transaction_receipt(
            w3.eth.send_raw_transaction(signed.raw_transaction)
        )
        assert rcpt.status == 1, "contract deploy failed"
        return rcpt.contractAddress

    def iface(self, key) -> ETHInterface:
        cs = {
            "blocks_confirmed": 1,
            "chain_id": 31337,
            "rpcport": self.port,
            "rpchost": "127.0.0.1",
            "contract_address": self.contract_address,
        }
        db = WalletDB(tempfile.mktemp(suffix=".sqlite", dir=self._db_dir))
        ci = ETHInterface(cs, "regtest", swap_client=db)
        ci.setActiveAccount(key)
        return ci

    def warp(self, seconds: int) -> None:
        self.w3.provider.make_request("evm_increaseTime", [seconds])
        self.w3.provider.make_request("evm_mine", [])
