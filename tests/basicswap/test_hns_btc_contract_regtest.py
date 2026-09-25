"""Opt-in Bitcoin Core regtest settlement for the HNS/BTC P2WSH leg.

Set BITCOIND_BIN to a local bitcoind and run this module directly. The test
starts an isolated regtest node and leaves no funds or keys on public chains.
"""

import base64
import hashlib
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from coincurve import PrivateKey

from basicswap.contrib.test_framework.messages import CTransaction
from basicswap.contrib.test_framework.script import SIGHASH_ALL, SegwitV0SignatureHash
from basicswap.interface.hns.btc_contract import BtcHtlcContract
from basicswap.interface.hns.swap_terms import (
    hns_time_lock_at_or_after,
    make_btc_contract_script,
)
from basicswap.util.crypto import hash160
from tests.basicswap.test_hns_btc_swap import GENESIS, MAGIC, terms


class CoreRegtest:
    def __init__(self, port, cookie):
        self.port = port
        self.cookie = cookie

    def call(self, method, params=(), wallet=None):
        token = base64.b64encode(self.cookie.read_bytes().strip()).decode()
        body = json.dumps(
            {"jsonrpc": "1.0", "id": "hns", "method": method, "params": params}
        )
        path = "/" if wallet is None else f"/wallet/{wallet}"
        request = Request(
            f"http://127.0.0.1:{self.port}{path}",
            body.encode(),
            {"Authorization": f"Basic {token}", "Content-Type": "application/json"},
        )
        with urlopen(request, timeout=30) as response:
            result = json.load(response)
        if result["error"] is not None:
            raise RuntimeError(result["error"])
        return result["result"]


class CoreContractInterface:
    def __init__(self, core):
        self.core = core

    def rpc(self, method, params=()):
        return self.core.call(method, params)

    def chainparams_network(self):
        return {"hrp": "bcrt"}

    def createRawFundedTransaction(self, address, amount, lock_unspents=True):
        raw = self.rpc("createrawtransaction", [[], {address: amount / 100_000_000}])
        return self.core.call(
            "fundrawtransaction", [raw, {"lockUnspents": lock_unspents}], "swap"
        )["hex"]

    def signTxWithWallet(self, raw):
        result = self.core.call("signrawtransactionwithwallet", [raw.hex()], "swap")
        if not result["complete"]:
            raise ValueError("Bitcoin Core did not sign the lock")
        return bytes.fromhex(result["hex"])

    def loadTx(self, raw):
        tx = CTransaction()
        tx.deserialize(BytesIO(raw))
        return tx

    def publishTx(self, raw):
        return self.rpc("sendrawtransaction", [raw.hex()])

    def getDestForAddress(self, address):
        return bytes.fromhex(self.rpc("validateaddress", [address])["scriptPubKey"])

    def getTxVSize(self, tx):
        base = len(tx.serialize_without_witness())
        full = len(tx.serialize_with_witness())
        return (3 * base + full + 3) // 4

    def getdustlimit(self):
        return 546

    def signTx(self, private_key, raw, input_index, script, amount):
        tx = self.loadTx(raw)
        digest = SegwitV0SignatureHash(script, tx, input_index, SIGHASH_ALL, amount)
        return PrivateKey(private_key).sign(digest, hasher=None) + bytes([SIGHASH_ALL])


@unittest.skipUnless(os.getenv("BITCOIND_BIN"), "set BITCOIND_BIN for regtest")
class BtcHtlcRegtest(unittest.TestCase):
    def test_funding_redeem_and_refund_on_core(self):
        binary = os.environ["BITCOIND_BIN"]
        with tempfile.TemporaryDirectory(prefix="basicswap-hns-btc-") as directory:
            port_sock = socket.socket()
            port_sock.bind(("127.0.0.1", 0))
            port = port_sock.getsockname()[1]
            port_sock.close()
            p2p_sock = socket.socket()
            p2p_sock.bind(("127.0.0.1", 0))
            p2p_port = p2p_sock.getsockname()[1]
            p2p_sock.close()
            node = subprocess.Popen(
                [
                    binary,
                    "-regtest",
                    f"-datadir={directory}",
                    f"-rpcport={port}",
                    f"-port={p2p_port}",
                    "-server=1",
                    "-txindex=1",
                    "-fallbackfee=0.0001",
                    "-printtoconsole=0",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            core = CoreRegtest(port, Path(directory) / "regtest" / ".cookie")
            try:
                for _ in range(100):
                    try:
                        core.call("getblockchaininfo")
                        break
                    except (OSError, URLError, FileNotFoundError):
                        time.sleep(0.1)
                else:
                    self.fail("Bitcoin Core did not start")
                core.call("createwallet", ["swap"])
                miner = core.call("getnewaddress", [], "swap")
                core.call("generatetoaddress", [105, miner])
                ci = CoreContractInterface(core)
                secret = bytes.fromhex("a4" * 32)
                hashlock = hashlib.sha256(secret).digest()
                receiver_key = bytes.fromhex("01" * 32)
                refund_key = bytes.fromhex("02" * 32)
                receiver_hash = hash160(PrivateKey(receiver_key).public_key.format())
                refund_hash = hash160(PrivateKey(refund_key).public_key.format())
                now = core.call("getblockchaininfo")["mediantime"]
                for hns_first in (True, False):
                    base = terms(hns_first)
                    btc_deadline = now + (12 if hns_first else 24) * 60 * 60
                    hns_deadline = now + (24 if hns_first else 12) * 60 * 60
                    script = make_btc_contract_script(
                        btc_deadline, hashlock, receiver_hash, refund_hash
                    )
                    trade = replace(
                        base,
                        hns_descriptor=replace(
                            base.hns_descriptor,
                            hashlock=hashlock,
                            refund_locktime=hns_time_lock_at_or_after(hns_deadline),
                        ),
                        btc_contract_script=script,
                        maker_btc_key_hash=receiver_hash if hns_first else refund_hash,
                        taker_btc_key_hash=refund_hash if hns_first else receiver_hash,
                    )
                    contract = BtcHtlcContract(ci, trade)
                    prepared = contract.prepare_funding(now, MAGIC, GENESIS)
                    self.assertIsNotNone(prepared.contract_vout)
                    contract.validate_prepared_funding(prepared, prepared.contract_vout)
                    with self.assertRaisesRegex(ValueError, "funding output mismatch"):
                        contract.validate_prepared_funding(
                            prepared, prepared.contract_vout + 1
                        )
                    self.assertEqual(contract.broadcast(prepared), prepared.txid)
                    self.assertEqual(contract.broadcast(prepared), prepared.txid)
                    core.call("generatetoaddress", [2, miner])
                    self.assertEqual(contract.broadcast(prepared), prepared.txid)
                    self.assertGreaterEqual(
                        contract.verify_lock(
                            prepared.txid, prepared.contract_vout, 2
                        ).confirmations,
                        2,
                    )
                    destination = core.call("getnewaddress", [], "swap")
                    redeem = contract.prepare_spend(
                        prepared.txid,
                        prepared.contract_vout,
                        destination,
                        receiver_key,
                        2,
                        10000,
                        preimage=secret,
                    )
                    contract.validate_prepared_spend(
                        redeem, prepared.txid, prepared.contract_vout, "redeem", secret
                    )
                    with self.assertRaisesRegex(ValueError, "redeem mismatch"):
                        contract.validate_prepared_spend(
                            redeem,
                            prepared.txid,
                            prepared.contract_vout,
                            "redeem",
                            bytes(32),
                        )
                    self.assertEqual(contract.broadcast(redeem), redeem.txid)
                    core.call("generatetoaddress", [1, miner])
                    tip = core.call("getblockcount")
                    observation = contract.scan_confirmed_spend(
                        prepared.txid, prepared.contract_vout, tip, tip
                    )
                    self.assertEqual(observation.branch, "redeem")
                    self.assertEqual(observation.preimage, secret)
                    with self.assertRaisesRegex(ValueError, "lost confirmations"):
                        contract.confirm_spend_observation(
                            observation, prepared.txid, prepared.contract_vout, 2
                        )
                    core.call("generatetoaddress", [1, miner])
                    contract.confirm_spend_observation(
                        observation, prepared.txid, prepared.contract_vout, 2
                    )

                    if not hns_first:
                        refund_prepared = contract.prepare_funding(now, MAGIC, GENESIS)
                        contract.broadcast(refund_prepared)
                        core.call("generatetoaddress", [1, miner])

                # Use mock time and fresh blocks to advance median time past
                # the refund CLTV threshold on the isolated regtest chain.
                core.call("setmocktime", [btc_deadline + 1800])
                core.call("generatetoaddress", [12, miner])
                with self.assertRaisesRegex(ValueError, "unsafe swap refund ordering"):
                    contract.prepare_funding(now, MAGIC, GENESIS)
                refund = contract.prepare_spend(
                    refund_prepared.txid,
                    refund_prepared.contract_vout,
                    core.call("getnewaddress", [], "swap"),
                    refund_key,
                    2,
                    10000,
                )
                contract.validate_prepared_spend(
                    refund,
                    refund_prepared.txid,
                    refund_prepared.contract_vout,
                    "refund",
                    None,
                )
                self.assertEqual(contract.broadcast(refund), refund.txid)
                core.call("generatetoaddress", [1, miner])
                tip = core.call("getblockcount")
                observation = contract.scan_confirmed_spend(
                    refund_prepared.txid, refund_prepared.contract_vout, tip, tip
                )
                self.assertEqual(observation.branch, "refund")
                self.assertIsNone(observation.preimage)
                core.call("invalidateblock", [observation.block_hash.hex()])
                with self.assertRaisesRegex(ValueError, "reorganized"):
                    contract.confirm_spend_observation(
                        observation, refund_prepared.txid, refund_prepared.contract_vout
                    )
            finally:
                try:
                    core.call("stop")
                except (OSError, URLError, FileNotFoundError):
                    pass
                try:
                    node.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    node.terminate()
                    node.wait(timeout=5)
                node.stderr.close()
