#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import logging
import os
import secrets
import time
import unittest

import basicswap.config as cfg
from basicswap.basicswap import BasicSwap, BidStates, Coins, DebugTypes, SwapTypes
from basicswap.basicswap_util import TxLockTypes, TxStates
from basicswap.bin.run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.rpc import callrpc
from tests.basicswap.extended.test_dcr import (
    run_test_itx_refund,
    run_test_success_path,
)
from tests.basicswap.extended.test_nmc import TestNMC
from tests.basicswap.test_xmr import NUM_NODES, pause_event
from tests.basicswap.util.common import (
    TEST_HTTP_PORT,
    read_json_api,
    stopDaemons,
    wait_for_bid,
    wait_for_bid_tx_state,
    wait_for_offer,
    waitForRPC,
)
from tests.basicswap.test_btc_xmr import test_delay_event


EXPECTED_DAEMON_SHA256 = os.getenv("CAPS_DAEMON_SHA256", "").lower()
EXPECTED_CLI_SHA256 = os.getenv("CAPS_CLI_SHA256", "").lower()
CAPS_BINDIR = os.path.abspath(os.getenv("CAPS_BINDIR", ""))
CAPSTASHD = "CapStashd" + cfg.bin_suffix
CAPSTASH_CLI = "CapStash-cli" + cfg.bin_suffix
CAPS_BASE_PORT = int(os.getenv("CAPS_SWAP_BASE_PORT", "29700"))
CAPS_BASE_RPC_PORT = CAPS_BASE_PORT + 20
CAPS_BASE_TOR_PORT = CAPS_BASE_PORT + 40


def hash_file(path):
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


@unittest.skipUnless(CAPS_BINDIR, "set CAPS_BINDIR")
class TestCapStashSwaps(TestNMC):
    __test__ = True
    test_coin = Coins.CAPS
    test_coin_from = Coins.CAPS
    allow_bidder_fast_completion = True
    start_xmr_nodes = False
    base_rpc_port = CAPS_BASE_RPC_PORT
    nmc_daemons = []
    nmc_addr = None
    rpc_users = [f"caps_test_{i}" for i in range(NUM_NODES)]
    rpc_passwords = [secrets.token_urlsafe(24) for _ in range(NUM_NODES)]

    @classmethod
    def setUpClass(cls):
        if not EXPECTED_DAEMON_SHA256 or not EXPECTED_CLI_SHA256:
            raise RuntimeError(
                "set CAPS_DAEMON_SHA256 and CAPS_CLI_SHA256"
            )
        daemon_path = os.path.join(CAPS_BINDIR, CAPSTASHD)
        cli_path = os.path.join(CAPS_BINDIR, CAPSTASH_CLI)
        if not os.path.isfile(daemon_path) or not os.path.isfile(cli_path):
            raise RuntimeError("CAPS_BINDIR is missing CapStashd or CapStash-cli")
        if hash_file(daemon_path) != EXPECTED_DAEMON_SHA256:
            raise RuntimeError("CapStashd hash mismatch")
        if hash_file(cli_path) != EXPECTED_CLI_SHA256:
            raise RuntimeError("CapStash-cli hash mismatch")
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising CapStash swap test")
        daemon_handles = list(cls.nmc_daemons)
        stopDaemons(daemon_handles)
        for daemon in daemon_handles:
            close_daemon_files(daemon)
        cls.nmc_daemons.clear()
        inherited_daemons = (
            list(cls.part_daemons)
            + list(cls.btc_daemons)
            + list(cls.ltc_daemons)
            + list(cls.xmr_daemons)
        )
        try:
            super(TestNMC, cls).tearDownClass()
        finally:
            # BaseTest clears these lists immediately after stopping the
            # daemons. Retain and close the wrappers here so Python does not
            # report their process streams as leaked by this suite.
            for daemon in inherited_daemons:
                close_daemon_files(daemon)

    @classmethod
    def prepareExtraDataDir(cls, node_id):
        node_dir = os.path.join(cfg.TEST_DATADIRS, f"caps_{node_id}")
        os.makedirs(node_dir, exist_ok=True)
        conf_path = os.path.join(node_dir, "CapStash.conf")
        with open(conf_path, "w", encoding="utf-8") as fp:
            fp.write("regtest=1\n[regtest]\n")
            fp.write(f"port={CAPS_BASE_PORT + node_id}\n")
            fp.write(f"rpcport={CAPS_BASE_RPC_PORT + node_id}\n")
            salt = generate_salt(16)
            fp.write(
                "rpcauth={}:{}${}\n".format(
                    cls.rpc_users[node_id],
                    salt,
                    password_to_hmac(salt, cls.rpc_passwords[node_id]),
                )
            )
            fp.write("daemon=0\nprinttoconsole=0\nserver=1\n")
            fp.write("discover=0\ndnsseed=0\nlistenonion=0\n")
            fp.write("rpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n")
            fp.write("bind=127.0.0.1\nfallbackfee=0.0002\n")
            fp.write("addresstype=bech32\nchangetype=bech32\n")
            for peer_id in range(NUM_NODES):
                if peer_id != node_id:
                    fp.write(f"addnode=127.0.0.1:{CAPS_BASE_PORT + peer_id}\n")

        cls.nmc_daemons.append(
            startDaemon(node_dir, CAPS_BINDIR, CAPSTASHD, extra_config={"coin_name": "capstash"})
        )
        auth = f"{cls.rpc_users[node_id]}:{cls.rpc_passwords[node_id]}"

        def rpc(method, params=None, wallet=None):
            return callrpc(
                CAPS_BASE_RPC_PORT + node_id, auth, method, params, wallet
            )
        waitForRPC(rpc, test_delay_event, rpc_command="getnetworkinfo", max_tries=30)
        waitForRPC(rpc, test_delay_event, rpc_command="getblockchaininfo")
        if "bsx_wallet" not in rpc("listwallets"):
            rpc("createwallet", ["bsx_wallet", False, True, "", False, True])
            rpc("createwallet", ["bsx_watch", True, True, "", False, True])

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.CAPS, cls.nmc_daemons[i].handle.pid)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["capstash"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": CAPS_BASE_RPC_PORT + node_id,
            "rpcuser": cls.rpc_users[node_id],
            "rpcpassword": cls.rpc_passwords[node_id],
            "datadir": os.path.join(datadir, f"caps_{node_id}"),
            "bindir": CAPS_BINDIR,
            "use_csv": True,
            "use_segwit": True,
            "blocks_confirmed": 1,
            "use_descriptors": True,
            "wallet_name": "bsx_wallet",
            "watch_wallet_name": "bsx_watch",
        }

    @classmethod
    def prepareExtraCoins(cls):
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        for sc in cls.swap_clients:
            ci = sc.ci(cls.test_coin)
            ci.initialiseWallet(ci.getNewRandomKey())
        cls.nmc_addr = ci0.rpc_wallet("getnewaddress", ["mining_addr", "bech32"])
        while ci0.rpc("getblockcount") < 500:
            remaining = 500 - ci0.rpc("getblockcount")
            ci0.rpc(
                "generatetoaddress",
                [min(50, remaining), cls.nmc_addr, 1000000],
            )

    @classmethod
    def restartCapStashNode(cls, node_id):
        old_daemon = cls.nmc_daemons[node_id]
        ci = cls.swap_clients[node_id].ci(Coins.CAPS)
        ci.rpc("stop")
        old_daemon.handle.wait(timeout=30)
        close_daemon_files(old_daemon)

        node_dir = os.path.join(cfg.TEST_DATADIRS, f"caps_{node_id}")
        new_daemon = startDaemon(
            node_dir,
            CAPS_BINDIR,
            CAPSTASHD,
            extra_config={"coin_name": "capstash"},
        )
        cls.nmc_daemons[node_id] = new_daemon
        auth = f"{cls.rpc_users[node_id]}:{cls.rpc_passwords[node_id]}"

        def rpc(method, params=None, wallet=None):
            return callrpc(
                CAPS_BASE_RPC_PORT + node_id, auth, method, params, wallet
            )

        waitForRPC(rpc, test_delay_event, rpc_command="getnetworkinfo", max_tries=30)
        loaded_before = rpc("listwallets")
        for wallet_name in ("bsx_wallet", "bsx_watch"):
            if wallet_name not in loaded_before:
                rpc("loadwallet", [wallet_name])
        loaded_after = rpc("listwallets")
        assert "bsx_wallet" in loaded_after
        assert "bsx_watch" in loaded_after
        cls.swap_clients[node_id].setDaemonPID(Coins.CAPS, new_daemon.handle.pid)
        return loaded_before, loaded_after

    @classmethod
    def restartBasicSwapClient(cls, node_id):
        class PausedClient:
            @staticmethod
            def update():
                return

            @staticmethod
            def finalise():
                return

        pause_event.clear()
        test_delay_event.wait(1)
        old_client = cls.swap_clients[node_id]
        cls.swap_clients[node_id] = PausedClient()
        try:
            old_client.finalise()
            basicswap_dir = os.path.join(
                cfg.TEST_DATADIRS, f"basicswap_{node_id}"
            )
            settings_path = os.path.join(basicswap_dir, cfg.CONFIG_FILENAME)
            with open(settings_path, encoding="utf-8") as fp:
                settings = json.load(fp)
            new_client = BasicSwap(
                basicswap_dir,
                settings,
                "regtest",
                log_name=f"BasicSwap{node_id}Restarted",
            )
            new_client.setDaemonPID(
                Coins.PART, cls.part_daemons[node_id].handle.pid
            )
            new_client.setDaemonPID(
                Coins.BTC, cls.btc_daemons[node_id].handle.pid
            )
            new_client.setDaemonPID(
                Coins.CAPS, cls.nmc_daemons[node_id].handle.pid
            )
            new_client.start()
            cls.swap_clients[node_id] = new_client
            return new_client
        finally:
            pause_event.set()

    def waitForConfirmedBidTx(self, sc, bid_id, tx_name, timeout=90):
        deadline = time.time() + timeout
        while time.time() < deadline:
            bid, _ = sc.getBidAndOffer(bid_id)
            tx = getattr(bid, tx_name)
            if tx is not None and tx.txid is not None and (tx.conf or 0) >= 1:
                return bid, tx
            test_delay_event.wait(0.25)
        raise TimeoutError(f"Timed out waiting for confirmed {tx_name}")

    def waitForBidTx(self, sc, bid_id, tx_name, timeout=90):
        deadline = time.time() + timeout
        while time.time() < deadline:
            bid, _ = sc.getBidAndOffer(bid_id)
            tx = getattr(bid, tx_name)
            if tx is not None and tx.txid is not None:
                return bid, tx
            test_delay_event.wait(0.25)
        raise TimeoutError(f"Timed out waiting for {tx_name}")

    def findTransactionInRecentBlocks(self, ci, txid, block_count=25):
        tip = ci.rpc("getblockcount")
        for height in range(tip, max(-1, tip - block_count), -1):
            block_hash = ci.rpc("getblockhash", [height])
            block = ci.rpc("getblock", [block_hash, 1])
            if txid in block["tx"]:
                return {"blockhash": block_hash, "height": height}
        return None

    def countTransactionInRecentBlocks(self, ci, txid, block_count=100):
        tip = ci.rpc("getblockcount")
        count = 0
        for height in range(tip, max(-1, tip - block_count), -1):
            block_hash = ci.rpc("getblockhash", [height])
            block = ci.rpc("getblock", [block_hash, 1])
            count += block["tx"].count(txid)
        return count

    def runDaemonRestartSwap(self, coin_from, coin_to, capstash_node):
        node_from, node_to = 0, 1
        offerer = self.swap_clients[node_from]
        bidder = self.swap_clients[node_to]
        ci_from = offerer.ci(coin_from)
        ci_to = bidder.ci(coin_to)

        self.prepare_balance(coin_to, 100.0, 1801, 1800)
        self.prepare_balance(coin_from, 100.0, 1800, 1801)
        amount = ci_from.make_int(1.25, r=1)
        rate = ci_to.make_int(2.0, r=1)
        offer_id = offerer.postOffer(
            coin_from,
            coin_to,
            amount,
            rate,
            amount,
            SwapTypes.SELLER_FIRST,
        )
        wait_for_offer(test_delay_event, bidder, offer_id, wait_for=40)
        offer = bidder.getOffer(offer_id)
        bid_id = bidder.postBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, offerer, bid_id)

        # Hold the seller immediately before participate redemption so the
        # relevant lock is confirmed but no redeem transaction exists yet.
        offerer.setBidDebugInd(bid_id, DebugTypes.DONT_CONFIRM_PTX)
        offerer.acceptBid(bid_id)
        bid_before, ptx_before = self.waitForConfirmedBidTx(
            offerer, bid_id, "participate_tx"
        )
        self.assertIsNone(ptx_before.spend_txid)

        cap_ci = self.swap_clients[capstash_node].ci(Coins.CAPS)
        cap_lock = (
            bid_before.initiate_tx
            if coin_from == Coins.CAPS
            else bid_before.participate_tx
        )
        lock_txid = cap_lock.txid.hex()
        lock_before = cap_ci.rpc_wallet("gettransaction", [lock_txid])
        self.assertGreaterEqual(lock_before["confirmations"], 1)

        loaded_before, loaded_after = self.restartCapStashNode(capstash_node)
        self.assertIn("bsx_wallet", loaded_after)
        self.assertIn("bsx_watch", loaded_after)
        cap_ci = self.swap_clients[capstash_node].ci(Coins.CAPS)
        lock_after = cap_ci.rpc_wallet("gettransaction", [lock_txid])
        self.assertEqual(lock_after["txid"], lock_txid)
        self.assertGreaterEqual(lock_after["confirmations"], 1)

        offerer.setBidDebugInd(bid_id, DebugTypes.NONE)
        wait_for_bid(
            test_delay_event,
            offerer,
            bid_id,
            BidStates.SWAP_COMPLETED,
            wait_for=120,
        )
        wait_for_bid(
            test_delay_event,
            bidder,
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=30,
        )
        bid_after, _ = offerer.getBidAndOffer(bid_id)
        cap_lock_after = (
            bid_after.initiate_tx
            if coin_from == Coins.CAPS
            else bid_after.participate_tx
        )
        self.assertEqual(cap_lock_after.txid.hex(), lock_txid)
        self.assertIsNotNone(cap_lock_after.spend_txid)
        spend_txid = cap_lock_after.spend_txid.hex()
        spend = self.findTransactionInRecentBlocks(
            cap_ci, spend_txid
        )
        self.assertIsNotNone(spend)
        return {
            "offer_id": offer_id.hex(),
            "bid_id": bid_id.hex(),
            "lock_txid": lock_txid,
            "spend_txid": spend_txid,
            "spend_block": spend,
            "wallets_before": loaded_before,
            "wallets_after": loaded_after,
        }

    def runBasicSwapRestartSwap(self, coin_from, coin_to, capstash_node):
        node_from, node_to = 0, 1
        offerer = self.swap_clients[node_from]
        bidder = self.swap_clients[node_to]
        ci_from = offerer.ci(coin_from)
        ci_to = bidder.ci(coin_to)

        self.prepare_balance(coin_to, 100.0, 1801, 1800)
        self.prepare_balance(coin_from, 100.0, 1800, 1801)
        amount = ci_from.make_int(1.5, r=1)
        rate = ci_to.make_int(1.75, r=1)
        offer_id = offerer.postOffer(
            coin_from,
            coin_to,
            amount,
            rate,
            amount,
            SwapTypes.SELLER_FIRST,
        )
        wait_for_offer(test_delay_event, bidder, offer_id, wait_for=40)
        offer = bidder.getOffer(offer_id)
        bid_id = bidder.postBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, offerer, bid_id)
        offerer.setBidDebugInd(bid_id, DebugTypes.DONT_CONFIRM_PTX)
        offerer.acceptBid(bid_id)
        bid_before, _ = self.waitForConfirmedBidTx(
            offerer, bid_id, "participate_tx"
        )
        state_before = BidStates(bid_before.state)
        itx_before = bid_before.initiate_tx.txid.hex()
        ptx_before = bid_before.participate_tx.txid.hex()
        cap_height_before = self.swap_clients[capstash_node].ci(
            Coins.CAPS
        ).rpc("getblockcount")

        restarted = self.restartBasicSwapClient(capstash_node)
        recovered_bid, _ = restarted.getBidAndOffer(bid_id)
        self.assertEqual(recovered_bid.offer_id, offer_id)
        self.assertEqual(recovered_bid.initiate_tx.txid.hex(), itx_before)
        self.assertEqual(recovered_bid.participate_tx.txid.hex(), ptx_before)
        self.assertIn(
            BidStates(recovered_bid.state),
            (state_before, BidStates.SWAP_INITIATED, BidStates.SWAP_PARTICIPATING),
        )
        self.assertGreaterEqual(
            restarted.ci(Coins.CAPS).rpc("getblockcount"),
            cap_height_before,
        )

        offerer = self.swap_clients[node_from]
        bidder = self.swap_clients[node_to]
        offerer.setBidDebugInd(bid_id, DebugTypes.NONE)
        wait_for_bid(
            test_delay_event,
            offerer,
            bid_id,
            BidStates.SWAP_COMPLETED,
            wait_for=120,
        )
        wait_for_bid(
            test_delay_event,
            bidder,
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=30,
        )
        completed_bid, _ = offerer.getBidAndOffer(bid_id)
        self.assertEqual(completed_bid.initiate_tx.txid.hex(), itx_before)
        self.assertEqual(completed_bid.participate_tx.txid.hex(), ptx_before)
        self.assertIsNotNone(completed_bid.initiate_tx.spend_txid)
        self.assertIsNotNone(completed_bid.participate_tx.spend_txid)
        return {
            "offer_id": offer_id.hex(),
            "bid_id": bid_id.hex(),
            "state_before": state_before.name,
            "initiate_txid": itx_before,
            "participate_txid": ptx_before,
            "initiate_spend": completed_bid.initiate_tx.spend_txid.hex(),
            "participate_spend": completed_bid.participate_tx.spend_txid.hex(),
        }

    def runCapStashToPartRefundDaemonRestart(self):
        node_from, node_to = 0, 1
        offerer = self.swap_clients[node_from]
        bidder = self.swap_clients[node_to]
        ci_from = offerer.ci(Coins.CAPS)
        ci_to = bidder.ci(Coins.PART)

        self.prepare_balance(Coins.PART, 100.0, 1800, 1801)
        self.prepare_balance(Coins.CAPS, 100.0, 1801, 1800)
        swap_value = ci_from.make_int(2.5, r=1)
        rate = ci_to.make_int(0.5, r=1)
        # Keep enough headroom for the daemon restart without freezing one
        # chain while the Particl participate lock continues to age.
        lock_value = 30
        offer_id = offerer.postOffer(
            Coins.CAPS,
            Coins.PART,
            swap_value,
            rate,
            swap_value,
            SwapTypes.SELLER_FIRST,
            TxLockTypes.SEQUENCE_LOCK_BLOCKS,
            lock_value,
        )
        wait_for_offer(test_delay_event, bidder, offer_id, wait_for=40)
        offer = bidder.getOffer(offer_id)
        bid_id = bidder.postBid(offer_id, offer.amount_from)
        bidder.setBidDebugInd(bid_id, DebugTypes.DONT_SPEND_ITX)
        wait_for_bid(test_delay_event, offerer, bid_id)

        # Hold participate redemption until its CapStash daemon has been
        # restarted and both descriptor wallets have been explicitly loaded.
        offerer.setBidDebugInd(bid_id, DebugTypes.DONT_CONFIRM_PTX)
        offerer.acceptBid(bid_id)
        bid_with_itx, _ = self.waitForConfirmedBidTx(
            offerer, bid_id, "initiate_tx"
        )
        self.assertIsNotNone(bid_with_itx.initiate_txn_refund)
        refund_txid_expected = ci_from.getTxid(
            bid_with_itx.initiate_txn_refund
        ).hex()
        early_result = ci_from.rpc(
            "testmempoolaccept", [[bid_with_itx.initiate_txn_refund.hex()]]
        )[0]
        self.assertFalse(early_result["allowed"])
        reject_reason = early_result.get(
            "reject-reason", early_result.get("reject_reason", "")
        )
        self.assertIn("non-BIP68-final", reject_reason)

        # Let the bidder publish and confirm the PART participate transaction.
        # Pausing only CapStash here would let the Particl refund window age
        # asymmetrically and race the intended participate redeem path.
        self.waitForBidTx(offerer, bid_id, "participate_tx")
        bid_before, ptx_before = self.waitForConfirmedBidTx(
            offerer, bid_id, "participate_tx"
        )
        self.assertIsNone(ptx_before.spend_txid)
        self.assertEqual(
            ci_from.getTxid(bid_before.initiate_txn_refund).hex(),
            refund_txid_expected,
        )

        cap_lock_txid = bid_before.initiate_tx.txid.hex()
        cap_lock_vout = bid_before.initiate_tx.vout
        lock_before = ci_from.rpc("gettxout", [cap_lock_txid, cap_lock_vout])
        self.assertIsNotNone(lock_before)
        self.assertGreaterEqual(lock_before["confirmations"], 1)

        loaded_before, loaded_after = self.restartCapStashNode(node_from)
        self.assertIn("bsx_wallet", loaded_after)
        self.assertIn("bsx_watch", loaded_after)
        ci_from = offerer.ci(Coins.CAPS)
        lock_after = ci_from.rpc("gettxout", [cap_lock_txid, cap_lock_vout])
        self.assertIsNotNone(lock_after)
        self.assertGreaterEqual(lock_after["confirmations"], 1)
        self.assertLess(
            ci_from.rpc("getblockcount"),
            bid_before.initiate_tx.chain_height + lock_value,
        )

        # Release the seller. The restarted daemon must preserve refund
        # maturity and wallet state.
        offerer.setBidDebugInd(bid_id, DebugTypes.NONE)
        wait_for_bid_tx_state(
            test_delay_event,
            offerer,
            bid_id,
            TxStates.TX_REFUNDED,
            TxStates.TX_REDEEMED,
            wait_for=120,
        )
        wait_for_bid(
            test_delay_event,
            offerer,
            bid_id,
            BidStates.SWAP_COMPLETED,
            wait_for=60,
        )
        wait_for_bid(
            test_delay_event,
            bidder,
            bid_id,
            BidStates.BID_ABANDONED,
            sent=True,
            wait_for=30,
        )

        bid_after, _ = offerer.getBidAndOffer(bid_id)
        self.assertEqual(bid_after.initiate_tx.txid.hex(), cap_lock_txid)
        self.assertEqual(
            bid_after.initiate_tx.spend_txid.hex(), refund_txid_expected
        )
        self.assertIsNotNone(bid_after.participate_tx.spend_txid)
        part_spend_txid = bid_after.participate_tx.spend_txid.hex()
        part_ci = offerer.ci(Coins.PART)
        self.assertIsNotNone(
            self.findTransactionInRecentBlocks(part_ci, part_spend_txid, 100)
        )
        self.assertEqual(
            self.countTransactionInRecentBlocks(part_ci, part_spend_txid),
            1,
        )
        self.assertEqual(
            self.countTransactionInRecentBlocks(ci_from, refund_txid_expected),
            1,
        )
        self.assertIsNone(
            ci_from.rpc("gettxout", [cap_lock_txid, cap_lock_vout])
        )
        self.assertGreaterEqual(
            ci_from.rpc("getblockcount"),
            bid_after.initiate_tx.chain_height + lock_value,
        )
        refund_wallet_tx = ci_from.rpc_wallet(
            "gettransaction", [refund_txid_expected]
        )
        self.assertGreaterEqual(refund_wallet_tx["confirmations"], 1)

        for node_id in (node_from, node_to):
            summary = read_json_api(TEST_HTTP_PORT + node_id)
            self.assertEqual(summary["num_swapping"], 0)
            self.assertEqual(summary["num_watched_outputs"], 0)

        return {
            "offer_id": offer_id.hex(),
            "bid_id": bid_id.hex(),
            "capstash_lock_txid": cap_lock_txid,
            "capstash_refund_txid": refund_txid_expected,
            "particl_spend_txid": part_spend_txid,
            "early_reject_reason": reject_reason,
            "wallets_before": loaded_before,
            "wallets_after": loaded_after,
        }

    def test_02_sh_part_coin(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_success_path(self, Coins.PART, self.test_coin)

    def test_03_sh_coin_part(self):
        run_test_success_path(self, self.test_coin, Coins.PART)

    def test_06_sh_part_coin_itx_refund(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_itx_refund(self, Coins.PART, self.test_coin)

    def test_07_sh_coin_part_itx_refund(self):
        run_test_itx_refund(self, self.test_coin, Coins.PART)

    def test_10_sh_part_caps_daemon_restart(self):
        evidence = self.runDaemonRestartSwap(Coins.PART, Coins.CAPS, 1)
        logging.info("PART to CAPS daemon-restart evidence: %s", evidence)

    def test_11_sh_caps_part_daemon_restart(self):
        evidence = self.runDaemonRestartSwap(Coins.CAPS, Coins.PART, 0)
        logging.info("CAPS to PART daemon-restart evidence: %s", evidence)

    def test_12_sh_part_caps_basicswap_restart(self):
        evidence = self.runBasicSwapRestartSwap(Coins.PART, Coins.CAPS, 1)
        logging.info("PART to CAPS BasicSwap-restart evidence: %s", evidence)

    def test_13_sh_caps_part_basicswap_restart(self):
        evidence = self.runBasicSwapRestartSwap(Coins.CAPS, Coins.PART, 0)
        logging.info("CAPS to PART BasicSwap-restart evidence: %s", evidence)

    def test_14_sh_caps_part_refund_daemon_restart(self):
        evidence = self.runCapStashToPartRefundDaemonRestart()
        logging.info(
            "CAPS to PART refund daemon-restart evidence: %s", evidence
        )
