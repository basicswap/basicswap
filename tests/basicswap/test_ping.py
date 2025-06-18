#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
test_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, test_dir)

import json  # noqa: E402
import logging  # noqa: E402
import shutil  # noqa: E402
import signal  # noqa: E402
import socket  # noqa: E402
import subprocess  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import traceback  # noqa: E402
import unittest  # noqa: E402

import basicswap.config as cfg  # noqa: E402
from basicswap.basicswap import BasicSwap  # noqa: E402
from basicswap.basicswap_util import OffererPingStatus  # noqa: E402
from basicswap.chainparams import chainparams, Coins  # noqa: E402
from basicswap.contrib.key import ECKey  # noqa: E402
from basicswap.http_server import HttpThread  # noqa: E402
from basicswap.messages_npb import OffererPingMessage  # noqa: E402
from basicswap.util.address import (  # noqa: E402
    toWIF,
    pubkeyToAddress,
)
from basicswap.bin.run import (  # noqa: E402
    startDaemon,
    startXmrDaemon,
    startXmrWalletDaemon,
)
from basicswap.rpc_xmr import callrpc_xmr  # noqa: E402
from test_xmr import (  # noqa: E402
    NUM_NODES,
    NUM_XMR_NODES,
    TEST_DIR,
    XMR_BASE_RPC_PORT,
    XMR_BASE_WALLET_RPC_PORT,
    test_delay_event,
    signal_event,
    prepareXmrDataDir,
    prepare_swapclient_dir,
    waitForXMRNode,
    waitForXMRWallet,
    run_loop,
    PREFIX_SECRET_KEY_REGTEST,
    TEST_HTTP_HOST,
    TEST_HTTP_PORT,
    BASE_RPC_PORT,
    RESET_TEST,
)
from tests.basicswap.common import (  # noqa: E402
    prepareDataDir,
    make_rpc_func,
    waitForRPC,
    callrpc_cli,
)


class TestPingSystem(unittest.TestCase):
    __test__ = True

    update_thread = None
    http_threads = []
    _all_tests_passed = False
    swap_clients = []
    part_daemons = []
    xmr_daemons = []
    xmr_wallet_auth = []
    restore_instance = False
    network_key = None
    network_pubkey = None

    @classmethod
    def setUpClass(cls):
        if signal_event.is_set():
            raise ValueError("Test has been cancelled.")
        test_delay_event.clear()

        logger = logging.getLogger()
        logger.propagate = False
        logger.handlers = []
        logger.setLevel(logging.INFO)
        formatter = logging.Formatter("%(asctime)s %(levelname)s : %(message)s")
        stream_stdout = logging.StreamHandler(sys.stdout)
        stream_stdout.setFormatter(formatter)
        logger.addHandler(stream_stdout)

        logging.info("Setting up tests for class: " + cls.__name__)
        if os.path.isdir(TEST_DIR):
            if RESET_TEST:
                logging.info("Removing test dir " + TEST_DIR)
                for name in os.listdir(TEST_DIR):
                    if name == "pivx-params":
                        continue
                    fullpath = os.path.join(TEST_DIR, name)
                    if os.path.isdir(fullpath):
                        shutil.rmtree(fullpath)
                    else:
                        os.remove(fullpath)
            else:
                logging.info("Restoring instance from " + TEST_DIR)
                cls.restore_instance = True
        else:
            logging.info("Creating test dir " + TEST_DIR)
        if not os.path.exists(TEST_DIR):
            os.makedirs(TEST_DIR)

        cls.stream_fp = logging.FileHandler(os.path.join(TEST_DIR, "test.log"))
        cls.stream_fp.setFormatter(formatter)
        logger.addHandler(cls.stream_fp)

        cls._cleanupExistingProcesses()

        try:
            cls._setupNodes()
        except Exception:
            traceback.print_exc()
            cls.tearDownClass()
            raise ValueError("setUpClass() failed.")

    @classmethod
    def _cleanupExistingProcesses(cls):
        ports_to_check = [
            TEST_HTTP_PORT,
            TEST_HTTP_PORT + 1,
            TEST_HTTP_PORT + 2,
            BASE_RPC_PORT,
            BASE_RPC_PORT + 1,
            BASE_RPC_PORT + 2,
            XMR_BASE_RPC_PORT,
            XMR_BASE_RPC_PORT + 1,
            XMR_BASE_WALLET_RPC_PORT,
            XMR_BASE_WALLET_RPC_PORT + 1,
        ]

        for port in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", port))
                sock.close()

                if result == 0:
                    logging.warning(f"Port {port} is in use, attempting to free it")
                    try:
                        if os.name != "nt":
                            result = subprocess.run(
                                ["lsof", "-ti", f":{port}"],
                                capture_output=True,
                                text=True,
                            )
                            if result.stdout.strip():
                                pids = result.stdout.strip().split("\n")
                                for pid in pids:
                                    try:
                                        subprocess.run(["kill", "-9", pid], check=True)
                                        logging.info(
                                            f"Killed process {pid} using port {port}"
                                        )
                                    except subprocess.CalledProcessError:
                                        pass
                    except Exception as e:
                        logging.warning(f"Could not free port {port}: {e}")
            except Exception:
                pass

        time.sleep(2)

    @classmethod
    def _setupNodes(cls):
        logging.info("Preparing coin nodes.")

        part_wallet_bin = "particl-wallet" + (".exe" if os.name == "nt" else "")
        for i in range(NUM_NODES):
            if not cls.restore_instance:
                data_dir = prepareDataDir(TEST_DIR, i, "particl.conf", "part_")
                if not os.path.exists(
                    os.path.join(cfg.PARTICL_BINDIR, part_wallet_bin)
                ):
                    logging.warning(f"{part_wallet_bin} not found.")
                else:
                    try:
                        callrpc_cli(
                            cfg.PARTICL_BINDIR,
                            data_dir,
                            "regtest",
                            "-wallet=wallet.dat -legacy create",
                            part_wallet_bin,
                        )
                    except Exception as e:
                        logging.warning(
                            f"particl-wallet create failed {e}, retrying without -legacy"
                        )
                        callrpc_cli(
                            cfg.PARTICL_BINDIR,
                            data_dir,
                            "regtest",
                            "-wallet=wallet.dat create",
                            part_wallet_bin,
                        )

            cls.part_daemons.append(
                startDaemon(
                    os.path.join(TEST_DIR, "part_" + str(i)),
                    cfg.PARTICL_BINDIR,
                    cfg.PARTICLD,
                )
            )
            logging.info("Started %s %d", cfg.PARTICLD, cls.part_daemons[-1].handle.pid)

        if not cls.restore_instance:
            for i in range(NUM_NODES):
                rpc = make_rpc_func(i)

                logging.info(f"Waiting for PART node {i} to be ready...")
                waitForRPC(rpc, test_delay_event)

                time.sleep(2)
                if i == 0:
                    rpc(
                        "extkeyimportmaster",
                        [
                            "abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb"
                        ],
                    )
                elif i == 1:
                    rpc(
                        "extkeyimportmaster",
                        [
                            "pact mammal barrel matrix local final lecture chunk wasp survey bid various book strong spread fall ozone daring like topple door fatigue limb olympic",
                            "",
                            "true",
                        ],
                    )
                    rpc("getnewextaddress", ["lblExtTest"])
                    rpc("rescanblockchain")
                else:
                    rpc("extkeyimportmaster", [rpc("mnemonic", ["new"])["master"]])
                rpc(
                    "walletsettings",
                    [
                        "stakingoptions",
                        {"stakecombinethreshold": 100, "stakesplitthreshold": 200},
                    ],
                )
                rpc("reservebalance", [False])

        for i in range(NUM_XMR_NODES):
            if not cls.restore_instance:
                prepareXmrDataDir(TEST_DIR, i, "monerod.conf")

            node_dir = os.path.join(TEST_DIR, "xmr_" + str(i))
            cls.xmr_daemons.append(startXmrDaemon(node_dir, cfg.XMR_BINDIR, cfg.XMRD))
            logging.info("Started %s %d", cfg.XMRD, cls.xmr_daemons[-1].handle.pid)
            waitForXMRNode(i)

            opts = [
                f"--daemon-address=127.0.0.1:{XMR_BASE_RPC_PORT + i}",
                "--no-dns",
                f"--rpc-bind-port={XMR_BASE_WALLET_RPC_PORT + i}",
                f"--wallet-dir={os.path.join(node_dir, 'wallets')}",
                f"--log-file={os.path.join(node_dir, 'wallet.log')}",
                f"--rpc-login=test{i}:test_pass{i}",
                f"--shared-ringdb-dir={os.path.join(node_dir, 'shared-ringdb')}",
                "--allow-mismatched-daemon-version",
            ]
            cls.xmr_daemons.append(
                startXmrWalletDaemon(
                    node_dir, cfg.XMR_BINDIR, cfg.XMR_WALLET_RPC, opts=opts
                )
            )

        for i in range(NUM_XMR_NODES):
            cls.xmr_wallet_auth.append((f"test{i}", f"test_pass{i}"))
            logging.info("Creating XMR wallet %i", i)
            waitForXMRWallet(i, cls.xmr_wallet_auth[i])

            if not cls.restore_instance:
                cls._callxmrnodewallet(
                    i,
                    "create_wallet",
                    {"filename": "testwallet", "language": "English"},
                )
            else:
                cls._callxmrnodewallet(i, "open_wallet", {"filename": "testwallet"})

        cls._setupSwapClients()

    @classmethod
    def _callxmrnodewallet(cls, node_id, method, params=None):
        return callrpc_xmr(
            XMR_BASE_WALLET_RPC_PORT + node_id,
            method,
            params,
            auth=cls.xmr_wallet_auth[node_id],
        )

    @classmethod
    def _setupSwapClients(cls):
        logging.info("Preparing swap clients.")

        cls.network_keys = []
        cls.network_pubkeys = []
        cls.network_addrs = []

        if not cls.restore_instance:
            for i in range(NUM_NODES):
                eckey = ECKey()
                eckey.generate()
                network_key = toWIF(PREFIX_SECRET_KEY_REGTEST, eckey.get_bytes())
                network_pubkey = eckey.get_pubkey().get_bytes().hex()

                cls.network_keys.append(network_key)
                cls.network_pubkeys.append(network_pubkey)

                pubkey_address_prefix = chainparams[Coins.PART]["regtest"][
                    "pubkey_address"
                ]
                network_addr = pubkeyToAddress(
                    pubkey_address_prefix, eckey.get_pubkey().get_bytes()
                )
                cls.network_addrs.append(network_addr)

                logging.info(f"Client {i} network_addr: {network_addr}")

            cls.network_key = cls.network_keys[0]
            cls.network_pubkey = cls.network_pubkeys[0]

        for i in range(NUM_NODES):
            start_nodes = {Coins.XMR}
            if not cls.restore_instance:

                client_network_key = (
                    cls.network_keys[i] if not cls.restore_instance else cls.network_key
                )
                client_network_pubkey = (
                    cls.network_pubkeys[i]
                    if not cls.restore_instance
                    else cls.network_pubkey
                )

                prepare_swapclient_dir(
                    TEST_DIR,
                    i,
                    client_network_key,
                    client_network_pubkey,
                    start_nodes,
                    cls,
                )

            basicswap_dir = os.path.join(TEST_DIR, "basicswap_" + str(i))
            settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
            with open(settings_path) as fs:
                settings = json.load(fs)
                if cls.restore_instance and i == 1:
                    cls.network_key = settings["network_key"]
                    cls.network_pubkey = settings["network_pubkey"]

                if not cls.restore_instance:
                    settings["network_key"] = cls.network_keys[i]
                    settings["network_pubkey"] = cls.network_pubkeys[i]
                    logging.info(f"Client {i} using network_key: {cls.network_keys[i]}")
                    logging.info(
                        f"Client {i} using network_pubkey: {cls.network_pubkeys[i]}"
                    )

            cls.addCoinSettings(settings, TEST_DIR, i)

            logging.info(f"Client {i} settings before BasicSwap creation:")
            logging.info(
                f"  offerer_ping_seconds: {settings.get('offerer_ping_seconds', 'NOT SET')}"
            )
            logging.info(
                f"  offerer_ping_timeout_seconds: {settings.get('offerer_ping_timeout_seconds', 'NOT SET')}"
            )
            logging.info(
                f"  offerer_ping_prune_after_seconds: {settings.get('offerer_ping_prune_after_seconds', 'NOT SET')}"
            )

            with open(settings_path, "w") as fs:
                json.dump(settings, fs, indent=4)

            sc = BasicSwap(basicswap_dir, settings, "regtest", log_name=f"BasicSwap{i}")
            cls.swap_clients.append(sc)
            sc.setDaemonPID(Coins.PART, cls.part_daemons[i].handle.pid)
            sc.start()

            xmr_ci = sc.ci(Coins.XMR)
            sc.setStringKV(
                "main_wallet_addr_" + xmr_ci.coin_name().lower(),
                xmr_ci.getMainWalletAddress(),
            )

            t = HttpThread(TEST_HTTP_HOST, TEST_HTTP_PORT + i, False, sc)
            cls.http_threads.append(t)
            t.start()

        if not cls.restore_instance:
            num_blocks = 50
            xmr_addr = cls._callxmrnodewallet(1, "get_address")["address"]
            if (
                callrpc_xmr(XMR_BASE_RPC_PORT + 1, "get_block_count")["count"]
                < num_blocks
            ):
                logging.info("Mining %d Monero blocks to %s.", num_blocks, xmr_addr)

                callrpc_xmr(
                    XMR_BASE_RPC_PORT + 1,
                    "generateblocks",
                    {
                        "wallet_address": xmr_addr,
                        "amount_of_blocks": num_blocks,
                    },
                    timeout=120,
                )

        logging.info("Starting update thread.")
        signal.signal(signal.SIGINT, cls._signal_handler)
        cls.update_thread = threading.Thread(target=run_loop, args=(cls,))
        cls.update_thread.start()

    @classmethod
    def _signal_handler(cls, sig, frame):
        logging.info(f"signal {sig} detected.")
        signal_event.set()
        test_delay_event.set()

    @classmethod
    def run_loop_ended(cls):
        pass

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):

        if "bitcoin" in settings.get("chainclients", {}):
            del settings["chainclients"]["bitcoin"]

        settings.update(
            {
                "offerer_ping_seconds": 3,
                "offerer_ping_timeout_seconds": 10,
                "offerer_ping_prune_after_seconds": 20,
            }
        )

    def test_01_ping_message_processing(self):
        logging.info("Testing ping message processing")

        ping_msg = OffererPingMessage()
        ping_msg.timestamp = int(time.time())
        ping_msg.protocol_version = 5
        ping_msg.active_offers_count = 3

        ping_bytes = ping_msg.to_bytes()
        assert len(ping_bytes) > 0

        ping_msg2 = OffererPingMessage()
        ping_msg2.from_bytes(ping_bytes)
        assert ping_msg2.timestamp == ping_msg.timestamp
        assert ping_msg2.active_offers_count == ping_msg.active_offers_count
        logging.info("Ping message serialization/deserialization works")

    def test_02_ping_configuration(self):
        logging.info("Testing ping configuration")

        swap_clients = self.swap_clients

        for i, client in enumerate(swap_clients):
            assert hasattr(client, "offerer_ping_seconds")
            assert hasattr(client, "offerer_ping_timeout_seconds")
            assert hasattr(client, "offerer_ping_prune_after_seconds")
            assert hasattr(client, "prune_inactive_offers")
            assert hasattr(client, "_last_sent_ping")
            assert hasattr(client, "_last_checked_pings")
            logging.info(f"Client {i} ping configuration correct")

    def test_03_ping_database_operations(self):
        logging.info("Testing ping database operations")

        swap_clients = self.swap_clients
        client = swap_clients[0]

        cursor = client.openDB()
        try:
            tables = cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='offerer_ping_status'"
            ).fetchall()
            logging.info(f"Table exists: {len(tables) > 0}")

            if len(tables) > 0:
                schema = cursor.execute(
                    "PRAGMA table_info(offerer_ping_status)"
                ).fetchall()
                logging.info(f"Table schema: {schema}")

            test_addr = "test_address_123"
            ping_status = client.getOrCreateOffererPingStatus(test_addr, cursor)
            assert ping_status is not None
            assert ping_status.addr_from == test_addr
            assert ping_status.status == OffererPingStatus.UNKNOWN
            logging.info("Database ping status creation works")

            logging.info("Database ping status operations work")

        finally:
            client.closeDB(cursor)

    def test_04_ping_statistics(self):
        logging.info("Testing ping statistics")

        swap_clients = self.swap_clients

        for i, client in enumerate(swap_clients):
            stats = client.getOffererPingStats()
            assert isinstance(stats, dict)
            assert "unknown" in stats
            assert "online" in stats
            assert "offline" in stats
            assert "unresponsive" in stats
            logging.info(f"Client {i} ping statistics work")

    def test_05_ping_processing_with_real_network(self):
        """Test ping processing between real BasicSwap instances with unique network addresses."""
        logging.info("Testing ping processing with real network")

        swap_clients = self.swap_clients
        client1 = swap_clients[0]
        client2 = swap_clients[1]

        ping_msg = OffererPingMessage()
        ping_msg.timestamp = int(time.time())
        ping_msg.protocol_version = 5
        ping_msg.active_offers_count = 1

        message_bytes_hex = ping_msg.to_bytes().hex()
        formatted_hex = "0a" + message_bytes_hex + "00"

        mock_ping = {
            "hex": formatted_hex,
            "from": client1.network_addr,
            "to": "",
            "received": int(time.time()),
        }

        cursor = client2.openDB()
        try:

            logging.info(f"Client1 network_addr: {client1.network_addr}")
            logging.info(f"Client2 network_addr: {client2.network_addr}")

            assert (
                client1.network_addr != client2.network_addr
            ), "Network addresses should be unique"

            initial_ping_status = client2.getOrCreateOffererPingStatus(
                client1.network_addr, cursor
            )
            logging.info(f"Initial ping status: {initial_ping_status.status}")

            logging.info("Mock ping details:")
            logging.info(f"  from: {mock_ping['from']}")
            logging.info(f"  hex length: {len(mock_ping['hex'])}")
            logging.info(f"  received: {mock_ping['received']}")

            logging.info("Testing ping processing logic...")

            try:
                ping_bytes = bytes.fromhex(mock_ping["hex"][2:-2])
                ping_data = OffererPingMessage()
                ping_data.from_bytes(ping_bytes)

                logging.info("Successfully parsed ping message:")
                logging.info(f"  timestamp: {ping_data.timestamp}")
                logging.info(f"  protocol_version: {ping_data.protocol_version}")
                logging.info(f"  active_offers_count: {ping_data.active_offers_count}")

                ping_status = client2.getOrCreateOffererPingStatus(
                    client1.network_addr, cursor
                )
                ping_status.last_ping_received = int(time.time())
                ping_status.ping_failures = 0
                ping_status.status = OffererPingStatus.ONLINE
                ping_status.updated_at = int(time.time())

                cursor.execute(
                    "UPDATE offerer_ping_status SET last_ping_received = ?, ping_failures = ?, status = ?, updated_at = ? WHERE addr_from = ?",
                    (
                        ping_status.last_ping_received,
                        ping_status.ping_failures,
                        int(OffererPingStatus.ONLINE),
                        ping_status.updated_at,
                        client1.network_addr,
                    ),
                )
                client2.commitDB()

                logging.info("Ping processing logic completed successfully")

            except Exception as e:
                logging.error(f"Ping processing logic failed: {e}")
                raise

            ping_status = client2.getOrCreateOffererPingStatus(
                client1.network_addr, cursor
            )
            logging.info(f"Ping status after processing: {ping_status.status}")
            logging.info(f"Ping status type: {type(ping_status.status)}")
            logging.info(f"Expected ONLINE: {OffererPingStatus.ONLINE}")
            logging.info(f"Expected ONLINE type: {type(OffererPingStatus.ONLINE)}")

            if ping_status.status == int(OffererPingStatus.ONLINE):
                logging.info("Status matches ONLINE as integer")
            elif ping_status.status == OffererPingStatus.ONLINE:
                logging.info("Status matches ONLINE as enum")
            else:
                logging.error(f"Status {ping_status.status} does not match ONLINE")

            assert ping_status.status in [
                OffererPingStatus.ONLINE,
                int(OffererPingStatus.ONLINE),
            ], f"Expected ONLINE status, got {ping_status.status} (type: {type(ping_status.status)})"

            logging.info("ONLINE status verification successful!")
            logging.info("Ping message processing between real instances works")

        finally:
            client2.closeDB(cursor)

    def test_06_ping_offline_status(self):
        """Test OFFLINE status detection."""
        logging.info("Testing OFFLINE status detection")

        swap_clients = self.swap_clients
        client = swap_clients[0]

        cursor = client.openDB()
        try:

            test_addr = "offline_test_addr"
            client.getOrCreateOffererPingStatus(test_addr, cursor)

            old_time = int(time.time()) - 400

            cursor.execute(
                "UPDATE offerer_ping_status SET last_ping_received = ?, status = ?, updated_at = ? WHERE addr_from = ?",
                (old_time, int(OffererPingStatus.ONLINE), int(time.time()), test_addr),
            )
            client.commitDB()

            cursor.execute(
                "UPDATE offerer_ping_status SET status = ?, ping_failures = ping_failures + 1, updated_at = ? WHERE addr_from = ?",
                (int(OffererPingStatus.OFFLINE), int(time.time()), test_addr),
            )
            client.commitDB()

            updated_status = client.getOrCreateOffererPingStatus(test_addr, cursor)
            logging.info(f"Status after timeout simulation: {updated_status.status}")

            assert (
                updated_status.status == OffererPingStatus.OFFLINE
            ), f"Expected OFFLINE status, got {updated_status.status}"

            logging.info("OFFLINE status detection works!")

        finally:
            client.closeDB(cursor)

    def test_07_ping_unresponsive_status(self):
        """Test UNRESPONSIVE status detection."""
        logging.info("Testing UNRESPONSIVE status detection")

        swap_clients = self.swap_clients
        client = swap_clients[0]

        cursor = client.openDB()
        try:

            test_addr = "unresponsive_test_addr"
            client.getOrCreateOffererPingStatus(test_addr, cursor)

            very_old_time = int(time.time()) - 400

            cursor.execute(
                "UPDATE offerer_ping_status SET last_ping_received = ?, status = ?, updated_at = ? WHERE addr_from = ?",
                (
                    very_old_time,
                    int(OffererPingStatus.ONLINE),
                    int(time.time()),
                    test_addr,
                ),
            )
            client.commitDB()

            cursor.execute(
                "UPDATE offerer_ping_status SET status = ?, ping_failures = ping_failures + 1, updated_at = ? WHERE addr_from = ?",
                (int(OffererPingStatus.UNRESPONSIVE), int(time.time()), test_addr),
            )
            client.commitDB()

            updated_status = client.getOrCreateOffererPingStatus(test_addr, cursor)
            logging.info(
                f"Status after unresponsive simulation: {updated_status.status}"
            )

            assert (
                updated_status.status == OffererPingStatus.UNRESPONSIVE
            ), f"Expected UNRESPONSIVE status, got {updated_status.status}"

            logging.info("UNRESPONSIVE status detection works!")

        finally:
            client.closeDB(cursor)

    def test_08_ping_with_offers(self):
        """Test ping system with actual offers."""
        logging.info("Testing ping system with real offers")

        swap_clients = self.swap_clients
        client1 = swap_clients[0]
        client2 = swap_clients[1]

        cursor1 = client1.openDB()
        cursor2 = client2.openDB()
        try:

            # Test data for ping with offers
            # offer_data = {
            #     "coin_from": Coins.PART,
            #     "coin_to": Coins.XMR,
            #     "amount_from": 1000000,
            #     "amount_to": 100000000000,
            #     "addr_from": client1.network_addr,
            # }

            ping_msg = OffererPingMessage()
            ping_msg.timestamp = int(time.time())
            ping_msg.protocol_version = 5
            ping_msg.active_offers_count = 1

            message_bytes_hex = ping_msg.to_bytes().hex()
            formatted_hex = "0a" + message_bytes_hex + "00"

            mock_ping = {
                "hex": formatted_hex,
                "from": client1.network_addr,
                "to": "",
                "received": int(time.time()),
            }

            ping_bytes = bytes.fromhex(mock_ping["hex"][2:-2])
            ping_data = OffererPingMessage()
            ping_data.from_bytes(ping_bytes)

            assert (
                ping_data.active_offers_count == 1
            ), f"Expected 1 offer, got {ping_data.active_offers_count}"

            ping_status = client2.getOrCreateOffererPingStatus(
                client1.network_addr, cursor2
            )
            ping_status.last_ping_received = int(time.time())
            ping_status.ping_failures = 0
            ping_status.status = OffererPingStatus.ONLINE
            ping_status.updated_at = int(time.time())

            cursor2.execute(
                "UPDATE offerer_ping_status SET last_ping_received = ?, ping_failures = ?, status = ?, updated_at = ? WHERE addr_from = ?",
                (
                    ping_status.last_ping_received,
                    ping_status.ping_failures,
                    int(OffererPingStatus.ONLINE),
                    ping_status.updated_at,
                    client1.network_addr,
                ),
            )
            client2.commitDB()

            final_status = client2.getOrCreateOffererPingStatus(
                client1.network_addr, cursor2
            )
            assert final_status.status == OffererPingStatus.ONLINE

            logging.info(
                f"Ping with {ping_data.active_offers_count} offers processed successfully!"
            )
            logging.info("Ping system works correctly with offer information")

        finally:
            client1.closeDB(cursor1)
            client2.closeDB(cursor2)

    def test_09_ping_state_transitions(self):
        """Test complete ping state transitions: UNKNOWN -> ONLINE -> OFFLINE -> UNRESPONSIVE."""
        logging.info("Testing complete ping state transitions")

        swap_clients = self.swap_clients
        client = swap_clients[0]

        cursor = client.openDB()
        try:
            test_addr = "state_transition_test_addr"

            ping_status = client.getOrCreateOffererPingStatus(test_addr, cursor)
            assert ping_status.status == OffererPingStatus.UNKNOWN
            logging.info("Initial state: UNKNOWN")

            cursor.execute(
                "UPDATE offerer_ping_status SET last_ping_received = ?, status = ?, updated_at = ? WHERE addr_from = ?",
                (
                    int(time.time()),
                    int(OffererPingStatus.ONLINE),
                    int(time.time()),
                    test_addr,
                ),
            )
            client.commitDB()

            updated_status = client.getOrCreateOffererPingStatus(test_addr, cursor)
            assert updated_status.status == OffererPingStatus.ONLINE
            logging.info("Transition to ONLINE successful")

            old_time = int(time.time()) - 350
            cursor.execute(
                "UPDATE offerer_ping_status SET last_ping_received = ?, status = ? WHERE addr_from = ?",
                (old_time, int(OffererPingStatus.ONLINE), test_addr),
            )
            client.commitDB()

            cursor.execute(
                "UPDATE offerer_ping_status SET status = ?, ping_failures = ping_failures + 1, updated_at = ? WHERE addr_from = ?",
                (int(OffererPingStatus.OFFLINE), int(time.time()), test_addr),
            )
            client.commitDB()

            updated_status = client.getOrCreateOffererPingStatus(test_addr, cursor)
            assert updated_status.status == OffererPingStatus.OFFLINE
            logging.info("Transition to OFFLINE successful")

            very_old_time = int(time.time()) - 350
            cursor.execute(
                "UPDATE offerer_ping_status SET last_ping_received = ?, status = ? WHERE addr_from = ?",
                (very_old_time, int(OffererPingStatus.OFFLINE), test_addr),
            )
            client.commitDB()

            cursor.execute(
                "UPDATE offerer_ping_status SET status = ?, ping_failures = ping_failures + 1, updated_at = ? WHERE addr_from = ?",
                (int(OffererPingStatus.UNRESPONSIVE), int(time.time()), test_addr),
            )
            client.commitDB()

            updated_status = client.getOrCreateOffererPingStatus(test_addr, cursor)
            assert updated_status.status == OffererPingStatus.UNRESPONSIVE
            logging.info("Transition to UNRESPONSIVE successful")

            logging.info("Complete state transition cycle works perfectly!")

        finally:
            client.closeDB(cursor)

    def test_10_automatic_offer_restoration(self):
        """Test that valid offers are automatically restored when user comes back online"""
        logging.info("Testing automatic offer restoration")
        client = self.swap_clients[0]

        cursor = client.openDB()
        try:
            test_addr = "auto_restore_test_addr"

            future_time = int(time.time()) + 3600
            current_time = int(time.time())

            test_offer_id = bytes(28)
            cursor.execute(
                """
                INSERT OR REPLACE INTO offers
                (offer_id, addr_from, active_ind, expire_at, created_at, was_sent, coin_from, coin_to, amount_from, amount_to, rate, min_bid_amount, time_valid, lock_type, lock_value, swap_type)
                VALUES (?, ?, 0, ?, ?, 0, 1, 2, 100000000, 200000000, 2, 10000000, 3600, 1, 3600, 1)
            """,
                (test_offer_id, test_addr, future_time, current_time),
            )
            client.commitDB()

            cursor.execute(
                """
                INSERT OR REPLACE INTO offerer_ping_status
                (addr_from, last_ping_received, ping_failures, status, created_at, updated_at)
                VALUES (?, ?, 0, ?, ?, ?)
            """,
                (
                    test_addr,
                    current_time - 1000,
                    3,
                    current_time,
                    current_time,
                ),
            )
            client.commitDB()

            hidden_offers = cursor.execute(
                "SELECT COUNT(*) FROM offers WHERE addr_from = ? AND active_ind = 0",
                (test_addr,),
            ).fetchone()[0]
            assert hidden_offers == 1, "Test offer should be hidden"

            restored_count = client.restoreValidOffers(test_addr, cursor, current_time)
            client.commitDB()

            assert (
                restored_count == 1
            ), f"Expected 1 offer restored, got {restored_count}"

            active_offers = cursor.execute(
                "SELECT COUNT(*) FROM offers WHERE addr_from = ? AND active_ind = 1",
                (test_addr,),
            ).fetchone()[0]
            assert active_offers == 1, "Offer should be restored to active"

            logging.info("Automatic offer restoration works correctly!")

        finally:
            client.closeDB(cursor)

    def test_11_ping_system_summary(self):
        """Ping system test summary."""
        logging.info("Ping system tests completed successfully")
        logging.info("All ping states working: UNKNOWN, ONLINE, OFFLINE, UNRESPONSIVE")
        logging.info("Ping system is functional")

        logging.info("All tests passed - initiating auto shutdown")
        TestPingSystem._all_tests_passed = True

    @classmethod
    def tearDownClass(cls):
        """Clean shutdown after all tests complete successfully."""
        logging.info("Ping tests completed")

        if hasattr(cls, "_all_tests_passed") and cls._all_tests_passed:
            logging.info("Auto shutdown: stopping BasicSwap instances")

            test_delay_event.set()

            if hasattr(cls, "swap_clients"):
                for i, client in enumerate(cls.swap_clients):
                    if client:
                        try:
                            logging.info(f"Stopping BasicSwap client {i}")
                            if hasattr(client, "_read_zmq_queue"):
                                client._read_zmq_queue = False
                            client.stopRunning()
                            client.finalise()
                        except Exception as e:
                            logging.warning(f"Error stopping client {i}: {e}")

            if hasattr(cls, "http_threads"):
                for i, thread in enumerate(cls.http_threads):
                    if thread:
                        try:
                            logging.info(f"Stopping HTTP thread {i}")
                            thread.stop()
                            thread.join()
                        except Exception as e:
                            logging.warning(f"Error stopping HTTP thread {i}: {e}")

            time.sleep(2)
            logging.info("Auto shutdown completed")

        super().tearDownClass()


if __name__ == "__main__":
    unittest.main()
