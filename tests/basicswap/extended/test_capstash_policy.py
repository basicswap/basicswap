#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import logging
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
class TestCapStashPolicy(unittest.TestCase):
    def test_fee_dust_and_funding_policy(self):
        bindir = os.path.abspath(os.environ["CAPS_BINDIR"])
        suffix = ".exe" if os.name == "nt" else ""
        daemon_path = os.path.join(bindir, "CapStashd" + suffix)
        cli_path = os.path.join(bindir, "CapStash-cli" + suffix)
        self.assertEqual(file_hash(daemon_path), EXPECTED_DAEMON_SHA256)
        self.assertEqual(file_hash(cli_path), EXPECTED_CLI_SHA256)

        rpc_port = int(os.getenv("CAPS_POLICY_RPC_PORT", "31400"))
        p2p_port = int(os.getenv("CAPS_POLICY_P2P_PORT", "31401"))
        for port in (rpc_port, p2p_port):
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))

        root = tempfile.mkdtemp(prefix="basicswap-capstash-policy-")
        preserve = os.getenv("CAPS_PRESERVE_TEST_DATADIRS", "0") == "1"
        daemon = None
        ci = None
        failed = True
        try:
            daemon = startDaemon(
                root,
                bindir,
                "CapStashd" + suffix,
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
            cookie_path = os.path.join(root, "regtest", ".cookie")
            wait_until(lambda: os.path.exists(cookie_path), "RPC cookie")
            with open(cookie_path, encoding="utf-8") as fp:
                auth = fp.read().strip()
            class PolicySwapContext:
                log = logging.getLogger("CapStashPolicy")
                settings = {}

                @staticmethod
                def getChainClientSettings(coin_type):
                    return {}

            ci = CapStashInterface(
                {
                    "rpcport": rpc_port,
                    "rpcauth": auth,
                    "wallet_name": "policy_wallet",
                    "blocks_confirmed": 1,
                    "conf_target": 2,
                    "use_segwit": True,
                    "use_csv": True,
                    "use_descriptors": True,
                    "connection_type": "rpc",
                },
                "regtest",
                PolicySwapContext(),
            )
            wait_until(
                lambda: ci.rpc("getblockchaininfo")["chain"] == "regtest",
                "regtest RPC",
            )
            ci.rpc("createwallet", ["policy_wallet", False, False, "", False, True])
            mining_address = ci.rpc_wallet(
                "getnewaddress", ["policy_mining", "bech32"]
            )
            ci.rpc("generatetoaddress", [105, mining_address, 1000000])

            network_info = ci.rpc("getnetworkinfo")
            relay_fee = network_info["relayfee"]
            incremental_fee = network_info["incrementalfee"]
            estimate = ci.rpc("estimatesmartfee", [2])
            fee_rate, fee_source = ci.get_fee_rate(2)
            self.assertGreater(relay_fee, 0)
            self.assertGreater(incremental_fee, 0)
            self.assertGreater(fee_rate, 0)
            self.assertIn(fee_source, ("estimatesmartfee", "paytxfee", "relayfee"))

            p2wpkh_address = ci.rpc_wallet(
                "getnewaddress", ["p2wpkh_boundary", "bech32"]
            )
            key_address = ci.rpc_wallet(
                "getnewaddress", ["p2wsh_key", "bech32"]
            )
            pubkey = ci.rpc_wallet("getaddressinfo", [key_address])["pubkey"]
            p2wsh_descriptor = ci.rpc(
                "getdescriptorinfo", [f"wsh(pk({pubkey}))"]
            )["descriptor"]
            p2wsh_address = ci.rpc("deriveaddresses", [p2wsh_descriptor])[0]

            def try_fund(address, value_sats):
                raw = ci.rpc(
                    "createrawtransaction",
                    [[], {address: value_sats / 100000000}],
                )
                try:
                    return ci.rpc_wallet("fundrawtransaction", [raw])
                except Exception:
                    return None

            def find_minimum(address):
                low, high = 0, 1000
                while low + 1 < high:
                    middle = (low + high) // 2
                    if try_fund(address, middle) is None:
                        low = middle
                    else:
                        high = middle
                return high

            p2wpkh_minimum = find_minimum(p2wpkh_address)
            p2wsh_minimum = find_minimum(p2wsh_address)
            self.assertIsNone(try_fund(p2wpkh_address, p2wpkh_minimum - 1))
            self.assertIsNone(try_fund(p2wsh_address, p2wsh_minimum - 1))

            for address, minimum in (
                (p2wpkh_address, p2wpkh_minimum),
                (p2wsh_address, p2wsh_minimum),
            ):
                funded = try_fund(address, minimum)
                self.assertIsNotNone(funded)
                signed = ci.rpc_wallet(
                    "signrawtransactionwithwallet", [funded["hex"]]
                )
                self.assertTrue(signed["complete"])
                accepted = ci.rpc(
                    "testmempoolaccept", [[signed["hex"]]]
                )[0]
                self.assertTrue(accepted["allowed"], accepted)

            low_fee_raw = ci.rpc(
                "createrawtransaction", [[], {p2wpkh_address: 0.01}]
            )
            low_fee_rejected = False
            try:
                low_funded = ci.rpc_wallet(
                    "fundrawtransaction", [low_fee_raw, {"fee_rate": 0.1}]
                )
                low_signed = ci.rpc_wallet(
                    "signrawtransactionwithwallet", [low_funded["hex"]]
                )
                low_result = ci.rpc(
                    "testmempoolaccept", [[low_signed["hex"]]]
                )[0]
                low_fee_rejected = not low_result["allowed"]
            except Exception:
                low_fee_rejected = True
            self.assertTrue(low_fee_rejected)

            input_addresses = [
                ci.rpc_wallet("getnewaddress", [f"input_{i}", "bech32"])
                for i in range(2)
            ]
            split_txid = ci.rpc_wallet(
                "sendmany",
                ["", {input_addresses[0]: 0.01, input_addresses[1]: 0.01}],
            )
            ci.rpc("generatetoaddress", [1, mining_address, 1000000])
            split_wallet_tx = ci.rpc_wallet("gettransaction", [split_txid])
            split_outputs = ci.rpc(
                "decoderawtransaction", [split_wallet_tx["hex"]]
            )["vout"]
            input_utxos = [
                {
                    "txid": split_txid,
                    "vout": output["n"],
                }
                for output in split_outputs
                if output["scriptPubKey"].get("address") in input_addresses
            ]
            self.assertEqual(len(input_utxos), 2)
            destination = ci.rpc_wallet(
                "getnewaddress", ["multi_input_destination", "bech32"]
            )
            multi_raw = ci.rpc(
                "createrawtransaction", [input_utxos, {destination: 0.015}]
            )
            multi_funded = ci.rpc_wallet(
                "fundrawtransaction", [multi_raw, {"add_inputs": False}]
            )
            self.assertGreaterEqual(multi_funded["changepos"], 0)
            multi_signed = ci.rpc_wallet(
                "signrawtransactionwithwallet", [multi_funded["hex"]]
            )
            self.assertTrue(multi_signed["complete"])
            self.assertTrue(
                ci.rpc("testmempoolaccept", [[multi_signed["hex"]]])[0]["allowed"]
            )

            subtract_raw = ci.rpc(
                "createrawtransaction", [input_utxos, {destination: 0.02}]
            )
            subtract_funded = ci.rpc_wallet(
                "fundrawtransaction",
                [
                    subtract_raw,
                    {"add_inputs": False, "subtractFeeFromOutputs": [0]},
                ],
            )
            subtract_decoded = ci.rpc(
                "decoderawtransaction", [subtract_funded["hex"]]
            )
            destination_value = next(
                output["value"]
                for output in subtract_decoded["vout"]
                if output["scriptPubKey"].get("address") == destination
            )
            self.assertLess(destination_value, 0.02)
            subtract_signed = ci.rpc_wallet(
                "signrawtransactionwithwallet", [subtract_funded["hex"]]
            )
            self.assertTrue(subtract_signed["complete"])
            self.assertTrue(
                ci.rpc("testmempoolaccept", [[subtract_signed["hex"]]])[0]["allowed"]
            )

            print(
                "CapStash policy evidence:",
                {
                    "relayfee": relay_fee,
                    "incrementalfee": incremental_fee,
                    "estimate": estimate,
                    "basicswap_fee_rate": fee_rate,
                    "basicswap_fee_source": fee_source,
                    "p2wpkh_minimum_sats": p2wpkh_minimum,
                    "p2wsh_minimum_sats": p2wsh_minimum,
                    "multi_input_count": len(input_utxos),
                    "change_position": multi_funded["changepos"],
                    "fee_subtracted_value": destination_value,
                },
            )
            failed = False
        finally:
            if ci is not None:
                try:
                    ci.rpc("stop")
                except Exception:
                    pass
            if daemon is not None:
                try:
                    daemon.handle.wait(timeout=20)
                except Exception:
                    try:
                        daemon.handle.kill()
                        daemon.handle.wait(timeout=10)
                    except Exception:
                        pass
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
            if not preserve and not failed:
                shutil.rmtree(root)
            elif failed:
                print(f"Preserved failed CapStash policy datadir at {root}")


if __name__ == "__main__":
    unittest.main()
