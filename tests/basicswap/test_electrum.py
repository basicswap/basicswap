#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""

# Ensure Electrumx is installed to a venv in ELECTRUMX_SRC_DIR/venv
# Example setup with default paths:

The leveldb system package may be required to install plyvel:
sudo pacman -S leveldb

cd ~/tmp/
git clone git@github.com:spesmilo/electrumx.git
cd electrumx
python3 -m venv venv
. venv/bin/activate
pip install ".[ujson]"

# Run test
export TEST_PATH=/tmp/test_electrum
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export ELECTRUMX_SRC_DIR="~/tmp/electrumx"
export EXTRA_CONFIG_JSON=$(cat <<EOF | jq -r @json
{
  "btc0":["txindex=1","rpcworkqueue=1100"]
}
EOF
)
export TEST_COINS_LIST="bitcoin,monero"
export PYTHONPATH=$(pwd)
pytest -v -s --log-cli-level=DEBUG tests/basicswap/test_electrum.py

# Run select test
pytest -v -s  --log-cli-level=DEBUG tests/basicswap/test_electrum.py::Test::test_01_b_full_swap_xmr

# Optionally copy coin releases to permanent storage for faster subsequent startups
cp -r ${TEST_PATH}/bin/* ~/tmp/basicswap_bin/

"""

import json
import logging
import os
import random
import shutil
import subprocess
import sys
import unittest

import basicswap.config as cfg
from basicswap.basicswap_util import (
    BidStates,
    DebugTypes,
    TxLockTypes,
    strBidState,
)
from basicswap.chainparams import (
    Coins,
    chainparams,
    getCoinIdFromName,
)
from basicswap.util.daemon import Daemon

from tests.basicswap.common import (
    prepare_balance,
    stopDaemons,
    waitForNumBids,
    waitForNumOffers,
)
from tests.basicswap.common_xmr import run_prepare, TEST_PATH
from tests.basicswap.extended.test_xmr_persistent import (
    BaseTestWithPrepare,
    NUM_NODES,
    PORT_OFS,
    RESET_TEST,
)
from tests.basicswap.mnemonics import mnemonics
from tests.basicswap.util import (
    read_json_api,
    post_json_api,
)

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def modifyConfig(test_path, i):
    if i == 1:
        config_path = os.path.join(test_path, f"client{i}", cfg.CONFIG_FILENAME)
        with open(config_path) as fp:
            settings = json.load(fp)

        settings["debug_ui"] = True
        settings["fetchpricesthread"] = False
        with open(config_path, "w") as fp:
            json.dump(settings, fp, indent=4)


class TestFunctions(BaseTestWithPrepare):
    __test__ = False

    port_node_0 = 12701
    port_node_1 = 12702

    def do_test_01_full_swap(
        self,
        coin_from: Coins,
        coin_to: Coins,
        port_node_from: int = port_node_0,
        port_node_to: int = port_node_1,
    ) -> None:
        logger.info(
            f"---------- Test {coin_from.name} ({port_node_from}) to {coin_to.name} ({port_node_to})"
        )

        ticker_from: str = chainparams[coin_from]["ticker"]
        ticker_to: str = chainparams[coin_to]["ticker"]

        amt_from_str = f"{random.uniform(0.5, 10.0):.{8}f}"
        amt_to_str = f"{random.uniform(0.5, 10.0):.{8}f}"
        data = {
            "addr_from": "-1",
            "coin_from": ticker_from,
            "coin_to": ticker_to,
            "amt_from": amt_from_str,
            "amt_to": amt_to_str,
            "lockhrs": "24",
            "swap_type": "adaptor_sig",
        }

        logger.info(
            f"Creating offer {amt_from_str} {ticker_from} -> {amt_to_str} {ticker_to}"
        )
        offer_id: str = post_json_api(port_node_from, "offers/new", data)["offer_id"]
        summary = read_json_api(port_node_from)
        assert summary["num_sent_offers"] == 1

        logger.info(f"Waiting for offer: {offer_id}")
        waitForNumOffers(self.delay_event, port_node_to, 1)

        offers = read_json_api(port_node_to, "offers")
        offer = offers[0]

        data = {
            "offer_id": offer["offer_id"],
            "amount_from": offer["amount_from"],
            "validmins": 60,
        }
        post_json_api(port_node_to, "bids/new", data)
        waitForNumBids(self.delay_event, port_node_from, 1)

        for i in range(20):
            bids = read_json_api(port_node_from, "bids")
            bid = bids[0]
            if bid["bid_state"] == "Received":
                break
            self.delay_event.wait(1)
        assert bid["bid_state"] == "Received"

        rv = post_json_api(
            port_node_from, "bids/{}".format(bid["bid_id"]), {"accept": True}
        )
        assert rv["bid_state"] in ("Accepted", "Request accepted")

        logger.info("Completing swap")
        for i in range(240):
            if self.delay_event.is_set():
                raise ValueError("Test stopped.")
            self.delay_event.wait(4)

            rv = read_json_api(port_node_from, "bids/{}".format(bid["bid_id"]))
            if rv["bid_state"] == "Completed":
                break
        assert rv["bid_state"] == "Completed"

        # Wait for bid to be removed from in-progress
        waitForNumBids(self.delay_event, port_node_from, 0)

    def do_test_02_leader_recover_a_lock_tx(
        self,
        coin_from: Coins,
        coin_to: Coins,
        port_node_from: int = port_node_0,
        port_node_to: int = port_node_1,
        lock_value: int = 12,
    ) -> None:
        logging.info(
            f"---------- Test {coin_from.name} ({port_node_from}) to {coin_to.name} ({port_node_to}) leader recovers coin a lock tx"
        )

        ticker_from: str = chainparams[coin_from]["ticker"]
        ticker_to: str = chainparams[coin_to]["ticker"]

        reverse_bid: bool = True if coin_from in (Coins.XMR,) else False
        port_offerer: int = port_node_from
        port_bidder: int = port_node_to
        port_leader: int = port_bidder if reverse_bid else port_offerer
        port_follower: int = port_offerer if reverse_bid else port_bidder
        logging.info(
            f"Offerer, bidder, leader, follower: {port_offerer}, {port_bidder}, {port_leader}, {port_follower}"
        )

        amt_from_str = f"{random.uniform(0.5, 10.0):.{8}f}"
        amt_to_str = f"{random.uniform(0.5, 10.0):.{8}f}"
        data = {
            "addr_from": "-1",
            "coin_from": ticker_from,
            "coin_to": ticker_to,
            "amt_from": amt_from_str,
            "amt_to": amt_to_str,
            "swap_type": "adaptor_sig",
            "lock_type": str(int(TxLockTypes.SEQUENCE_LOCK_BLOCKS)),
            "lock_blocks": str(lock_value),
        }

        logger.info(
            f"Creating offer {amt_from_str} {ticker_from} -> {amt_to_str} {ticker_to}"
        )
        offer_id: str = post_json_api(port_node_from, "offers/new", data)["offer_id"]
        summary = read_json_api(port_node_from)
        assert summary["num_sent_offers"] == 1

        logger.info(f"Waiting for offer: {offer_id}")
        waitForNumOffers(self.delay_event, port_node_to, 1)

        offers = read_json_api(port_node_to, "offers")
        offer = offers[0]

        data = {
            "offer_id": offer["offer_id"],
            "amount_from": offer["amount_from"],
            "validmins": 60,
        }
        rv = post_json_api(port_node_to, "bids/new", data)
        bid_id: str = rv["bid_id"]
        waitForNumBids(self.delay_event, port_node_from, 1)

        rv = post_json_api(
            port_follower,
            f"bids/{bid_id}",
            {"debugind": DebugTypes.BID_STOP_AFTER_COIN_A_LOCK},
        )
        assert "bid_state" in rv  # Test that the return didn't fail

        for i in range(20):
            bid = read_json_api(port_node_from, f"bids/{bid_id}")
            if bid["bid_state"] == "Received":
                break
            self.delay_event.wait(1)
        assert bid["bid_state"] == "Received"

        rv = post_json_api(port_offerer, f"bids/{bid_id}", {"accept": True})
        assert rv["bid_state"] in ("Accepted", "Request accepted")

        for i in range(100):
            if self.delay_event.is_set():
                raise ValueError("Test stopped.")
            self.delay_event.wait(4)
            rv = read_json_api(port_leader, f"bids/{bid_id}")
            if rv["bid_state"] == strBidState(BidStates.XMR_SWAP_FAILED_REFUNDED):
                break
        assert rv["bid_state"] == strBidState(BidStates.XMR_SWAP_FAILED_REFUNDED)


class Test(TestFunctions):
    __test__ = True
    update_min = 2
    daemons = []

    test_coin_a = Coins.PART
    test_coin_b = Coins.BTC
    test_coin_xmr = Coins.XMR

    @classmethod
    def addElectrumxDaemon(cls, coin_name: str, node_rpc_port: int, services_port: int):
        coin_type: Coins = getCoinIdFromName(coin_name)
        ticker: str = chainparams[coin_type]["ticker"]
        ticker_lc: str = ticker.lower()

        logger.info(f"Starting Electrumx for {ticker}")
        ELECTRUMX_SRC_DIR = os.path.expanduser(os.getenv("ELECTRUMX_SRC_DIR"))
        if ELECTRUMX_SRC_DIR is None:
            raise ValueError("Please set ELECTRUMX_SRC_DIR")
        ELECTRUMX_VENV = os.getenv(
            "ELECTRUMX_VENV", os.path.join(ELECTRUMX_SRC_DIR, "venv")
        )
        ELECTRUMX_DATADIR = os.getenv(
            f"ELECTRUMX_DATADIR_{ticker}", f"/tmp/electrumx_{ticker_lc}"
        )
        SSL_CERTFILE = f"{ELECTRUMX_DATADIR}/certfile.crt"
        SSL_KEYFILE = f"{ELECTRUMX_DATADIR}/keyfile.key"

        if os.path.isdir(ELECTRUMX_DATADIR):
            if RESET_TEST:
                logger.info("Removing " + ELECTRUMX_DATADIR)
                shutil.rmtree(ELECTRUMX_DATADIR)
        if not os.path.exists(ELECTRUMX_DATADIR):
            os.makedirs(os.path.join(ELECTRUMX_DATADIR, "db"))
            with open(os.path.join(ELECTRUMX_DATADIR, "banner"), "w") as fp:
                fp.write("TEST BANNER")
            try:
                stdout = subprocess.check_output(
                    [
                        "openssl",
                        "req",
                        "-nodes",
                        "-new",
                        "-x509",
                        "-keyout",
                        SSL_KEYFILE,
                        "-out",
                        SSL_CERTFILE,
                        "-subj",
                        '/C=CA/ST=Quebec/L=Montreal/O="Poutine LLC"/OU=devops/CN=*.poutine.net\n',
                    ],
                    text=True,
                )
                logger.info(f"openssl {stdout}")
            except subprocess.CalledProcessError as e:
                logger.info(f"Error openssl {e.output}")

        electrumx_env = {
            "COIN": coin_name.capitalize(),
            "NET": "regtest",
            "LOG_LEVEL": "debug",
            "SERVICES": f"tcp://:{services_port},ssl://:{services_port + 1},rpc://",
            "CACHE_MB": "400",
            "DAEMON_URL": f"http://test_{ticker_lc}_0:test_{ticker_lc}_pwd_0@127.0.0.1:{node_rpc_port}",
            "DB_DIRECTORY": f"{ELECTRUMX_DATADIR}/db",
            "SSL_CERTFILE": f"{ELECTRUMX_DATADIR}/certfile.crt",
            "SSL_KEYFILE": f"{ELECTRUMX_DATADIR}/keyfile.key",
            "BANNER_FILE": f"{ELECTRUMX_DATADIR}/banner",
            "DAEMON_POLL_INTERVAL_BLOCKS": "1000",
            "DAEMON_POLL_INTERVAL_MEMPOOL": "1000",
        }
        opened_files = []
        stdout_dest = open(f"{ELECTRUMX_DATADIR}/electrumx.log", "w")
        stderr_dest = stdout_dest
        cls.daemons.append(
            Daemon(
                subprocess.Popen(
                    [
                        os.path.join(ELECTRUMX_VENV, "bin", "python"),
                        os.path.join(ELECTRUMX_SRC_DIR, "electrumx_server"),
                    ],
                    shell=False,
                    stdin=subprocess.PIPE,
                    stdout=stdout_dest,
                    stderr=stderr_dest,
                    cwd=ELECTRUMX_SRC_DIR,
                    env=electrumx_env,
                ),
                [
                    opened_files,
                ],
                f"electrumx_{ticker_lc}",
            )
        )

    @classmethod
    def setUpClass(cls):
        cls.addElectrumxDaemon("bitcoin", 32793, 50001)
        super(Test, cls).setUpClass()

    @classmethod
    def modifyConfig(cls, test_path, i):
        modifyConfig(test_path, i)

    @classmethod
    def setupNodes(cls):
        logger.info(f"Preparing {NUM_NODES} nodes.")

        bins_path = os.path.join(TEST_PATH, "bin")
        for i in range(NUM_NODES):
            logger.info(f"Preparing node: {i}.")
            client_path = os.path.join(TEST_PATH, f"client{i}")
            try:
                shutil.rmtree(client_path)
            except Exception as ex:
                logger.warning(f"setupNodes {ex}")

            extra_args = []
            if i == 1:
                extra_args = [
                    "--btc-mode=electrum",
                    "--btc-electrum-server=127.0.0.1:50001",
                ]
            run_prepare(
                i,
                client_path,
                bins_path,
                cls.test_coins_list,
                mnemonics[i] if i < len(mnemonics) else None,
                num_nodes=NUM_NODES,
                use_rpcauth=True,
                extra_settings={"min_sequence_lock_seconds": 10},
                port_ofs=PORT_OFS,
                extra_args=extra_args,
            )

    @classmethod
    def tearDownClass(cls):
        logger.info("Finalising Test")
        super().tearDownClass()
        stopDaemons(cls.daemons)

    def test_01_a_full_swap_xmr(self):
        prepare_balance(
            self.delay_event,
            self.test_coin_b,
            100,
            self.port_node_1,
            self.port_node_0,
            True,
        )
        self.do_test_01_full_swap(self.test_coin_a, self.test_coin_b)

    def test_01_b_full_swap_xmr(self):
        prepare_balance(
            self.delay_event,
            self.test_coin_b,
            100,
            self.port_node_1,
            self.port_node_0,
            True,
        )
        self.do_test_01_full_swap(self.test_coin_b, self.test_coin_xmr)

    def test_01_c_full_swap_xmr_reverse(self):
        self.do_test_01_full_swap(
            self.test_coin_xmr, self.test_coin_b, self.port_node_1, self.port_node_0
        )

    def test_02_a_leader_recover_a_lock_tx(self):
        prepare_balance(
            self.delay_event,
            self.test_coin_b,
            100,
            self.port_node_1,
            self.port_node_0,
            True,
        )
        prepare_balance(
            self.delay_event,
            self.test_coin_xmr,
            100,
            self.port_node_0,
            self.port_node_1,
            True,
        )
        self.do_test_02_leader_recover_a_lock_tx(
            self.test_coin_b, Coins.XMR, self.port_node_1, self.port_node_0
        )


if __name__ == "__main__":
    unittest.main()
