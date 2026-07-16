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
from io import BytesIO

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
    coins_without_segwit,
    scriptless_coins,
)
from basicswap.util.daemon import Daemon
from basicswap.contrib.test_framework.messages import CTransaction

from tests.basicswap.util.common import (
    prepare_balance,
    stopDaemons,
    post_json_api,
    read_json_api,
)
from tests.basicswap.util.harness import run_prepare, TEST_PATH
from tests.basicswap.test_persistent import (
    BaseTestWithPrepare,
    NUM_NODES,
    PORT_OFS,
    RESET_TEST,
)
from tests.basicswap.util.mnemonics import mnemonics
from basicswap.interface.electrumx import ElectrumConnection

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def modify_config(test_path, i):
    config_path = os.path.join(test_path, f"client{i}", cfg.CONFIG_FILENAME)
    with open(config_path) as fp:
        settings = json.load(fp)

    if i == 1:
        settings["debug_ui"] = True
    settings.update(
        {
            "fetchpricesthread": False,
            "check_progress_seconds": 2,
            "check_watched_seconds": 3,
            "check_expired_seconds": 60,
            "check_events_seconds": 1,
            "check_xmr_swaps_seconds": 1,
            "min_delay_event": 1,
            "max_delay_event": 4,
            "min_delay_event_short": 1,
            "max_delay_event_short": 3,
            "min_delay_retry": 2,
            "max_delay_retry": 10,
        }
    )
    with open(config_path, "w") as fp:
        json.dump(settings, fp, indent=4)

    btc_config_path = os.path.join(test_path, f"client{i}", "bitcoin", "bitcoin.conf")
    with open(btc_config_path, "a") as fp:
        fp.write("minrelaytxfee=0.00001\n")


def wait_for_bid_state(
    delay_event, node_port: int, bid_id: str, state=None, wait_for: int = 30
) -> None:
    logger.info(f"TEST: wait_for_bid {bid_id}, node {node_port}, state {state}")

    pass_state_strs = []
    if isinstance(state, (list, tuple)):
        for s in state:
            pass_state_strs.append(strBidState(s))
    elif state is not None:
        pass_state_strs.append(strBidState(state))

    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        delay_event.wait(1)
        try:
            rv = read_json_api(node_port, f"bids/{bid_id}")
            if rv["bid_state"] in pass_state_strs or state is None:
                return
        except Exception as e:  # noqa: F841
            pass
            # logger.debug(f"TEST: wait_for_bid {bid_id}, error {e}")
    raise ValueError(f"wait_for_bid timed out {bid_id}.")


def wait_for_bid_states(
    delay_event,
    bid_id_hex: str,
    node_port_a: int,
    state_a,
    node_port_b: int,
    state_b,
    wait_for: int = 20,
    fail_fast_a: bool = True,
    fail_fast_b: bool = True,
    node_callback=None,
) -> None:
    for node_port, expect_state in (
        (node_port_a, state_a),
        (node_port_b, state_b),
    ):
        logger.info(
            f"TEST: wait_for_bid_states {bid_id_hex}, node {node_port}, state {expect_state}"
        )

    fail_fast = [fail_fast_a, fail_fast_b]
    pass_state_strs = [[], []]

    for n, state in enumerate(
        (
            state_a,
            state_b,
        )
    ):
        if isinstance(state, (list, tuple)):
            for s in state:
                pass_state_strs[n].append(strBidState(s))
            if BidStates.BID_ERROR in state:
                fail_fast[n] = False
        else:
            if state == BidStates.BID_ERROR:
                fail_fast[n] = False
            pass_state_strs[n].append(strBidState(state))

    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        delay_event.wait(1)

        num_passed: int = 0
        bid_states = [None] * 2
        for n, (node_port, expect_state) in enumerate(
            (
                (node_port_a, state_a),
                (node_port_b, state_b),
            )
        ):
            rv = read_json_api(node_port, f"bids/{bid_id_hex}")
            if "error" in rv and "Unknown bid id" in rv["error"]:
                continue
            bid_state = rv["bid_state"]
            bid_states[n] = bid_state
            if node_callback:
                node_callback(bid_id_hex, node_port, rv)
            if bid_state in pass_state_strs[n]:
                num_passed += 1
            else:
                if i > 0 and i % 10 == 0:
                    logger.debug(
                        f"TEST: wait_for_bid_states {bid_id_hex}, node {node_port}: Bid state {bid_state}, target {pass_state_strs[n]}."
                    )
                if fail_fast[n] and bid_state == strBidState(BidStates.BID_ERROR):
                    raise ValueError(
                        f"wait_for_bid_states {bid_id_hex}, node {node_port}: Bid state {bid_state}, target {pass_state_strs[n]}."
                    )

        if num_passed == 2:
            logger.debug(
                f"TEST: wait_for_bid_states found {bid_id_hex}, node {node_port}: Bid state {bid_states[0]}, target {pass_state_strs[0]}."
            )
            logger.debug(
                f"TEST: wait_for_bid_states found {bid_id_hex}, node {node_port}: Bid state {bid_states[1]}, target {pass_state_strs[1]}."
            )
            return

    raise ValueError(f"wait_for_bid_states timed out {bid_id_hex}.")


def wait_for_offer(
    delay_event, node_port: int, offer_id: str, state=None, wait_for: int = 30
) -> None:
    logger.info(f"TEST: wait_for_offer {offer_id}, node {node_port}, state {state}")

    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        delay_event.wait(1)
        try:
            rv = read_json_api(node_port, f"offers/{offer_id}")
            if any(offer["offer_id"] == offer_id for offer in rv):
                return
        except Exception as e:  # noqa: F841
            pass
            # logger.debug(f"TEST: wait_for_offer {offer_id}, error {e}")
    raise ValueError(f"wait_for_offer timed out {offer_id}.")


def is_reverse_bid(coin_from: Coins, coin_to: Coins):
    return True if coin_from in scriptless_coins + coins_without_segwit else False


def getTickerFromCoinId(coin_id: Coins) -> str:
    if coin_id in chainparams:
        return chainparams[coin_id]["ticker"]
    if isinstance(coin_id, Coins):
        return coin_id.name
    raise ValueError(f"TODO: getTickerFromCoinId {coin_id}")


class TestFunctions(BaseTestWithPrepare):
    __test__ = False

    port_node_0 = 12701
    port_node_1 = 12702
    port_node_2 = 12703

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

        ticker_from: str = getTickerFromCoinId(coin_from)
        ticker_to: str = getTickerFromCoinId(coin_to)

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
        wait_for_offer(self.delay_event, port_node_to, offer_id)
        offer = read_json_api(port_node_to, f"offers/{offer_id}")[0]
        assert offer["offer_id"] == offer_id

        data = {
            "offer_id": offer_id,
            "amount_from": offer["amount_from"],
            "validmins": 60,
        }
        rv = post_json_api(port_node_to, "bids/new", data)
        bid_id: str = rv["bid_id"]
        wait_for_bid_state(
            self.delay_event, port_node_from, bid_id, BidStates.BID_RECEIVED
        )

        rv = post_json_api(port_node_from, f"bids/{bid_id}", {"accept": True})
        assert rv["bid_state"] in ("Accepted", "Request accepted")

        logger.info("Completing swap")
        wait_for_bid_states(
            self.delay_event,
            bid_id,
            port_node_from,
            BidStates.SWAP_COMPLETED,
            port_node_to,
            BidStates.SWAP_COMPLETED,
            240,
        )

    def do_test_02_leader_recover_a_lock_tx(
        self,
        coin_from: Coins,
        coin_to: Coins,
        port_node_from: int = port_node_0,
        port_node_to: int = port_node_1,
        lock_value: int = 12,
    ) -> None:
        logger.info(
            f"---------- Test {coin_from.name} ({port_node_from}) to {coin_to.name} ({port_node_to}) leader recovers coin a lock tx"
        )

        ticker_from: str = getTickerFromCoinId(coin_from)
        ticker_to: str = getTickerFromCoinId(coin_to)

        reverse_bid: bool = is_reverse_bid(coin_from, coin_to)
        port_offerer: int = port_node_from
        port_bidder: int = port_node_to
        port_leader: int = port_bidder if reverse_bid else port_offerer
        port_follower: int = port_offerer if reverse_bid else port_bidder
        logger.info(
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
        wait_for_offer(self.delay_event, port_node_to, offer_id)
        offer = read_json_api(port_node_to, f"offers/{offer_id}")[0]
        assert offer["offer_id"] == offer_id

        data = {
            "offer_id": offer_id,
            "amount_from": offer["amount_from"],
            "validmins": 60,
        }
        rv = post_json_api(port_node_to, "bids/new", data)
        bid_id: str = rv["bid_id"]

        wait_for_bid_state(self.delay_event, port_follower, bid_id)
        rv = post_json_api(
            port_follower,
            f"bids/{bid_id}",
            {"debugind": DebugTypes.BID_STOP_AFTER_COIN_A_LOCK},
        )
        assert "bid_state" in rv  # Test that the return didn't fail

        wait_for_bid_state(
            self.delay_event, port_node_from, bid_id, BidStates.BID_RECEIVED
        )
        rv = post_json_api(port_offerer, f"bids/{bid_id}", {"accept": True})
        assert rv["bid_state"] in ("Accepted", "Request accepted")
        wait_for_bid_states(
            self.delay_event,
            bid_id,
            port_leader,
            BidStates.XMR_SWAP_FAILED_REFUNDED,
            port_follower,
            [BidStates.BID_STALLED_FOR_TEST, BidStates.XMR_SWAP_FAILED],
            240,
        )

    def do_test_03_follower_recover_a_lock_tx(
        self,
        coin_from: Coins,
        coin_to: Coins,
        port_node_from: int = port_node_0,
        port_node_to: int = port_node_1,
        lock_value: int = 12,
        with_mercy: bool = True,
    ) -> None:
        logger.info(
            "---------- Test {} ({}) to {} ({})  follower recovers coin a lock tx{}".format(
                coin_from.name,
                port_node_from,
                coin_to.name,
                port_node_to,
                " (with mercy tx)" if with_mercy else "",
            )
        )

        # Leader is too slow to recover the coin a lock tx and follower swipes it
        # Coin B lock tx remains unspent unless a mercy output revealing the follower's keyshare is sent

        ticker_from: str = getTickerFromCoinId(coin_from)
        ticker_to: str = getTickerFromCoinId(coin_to)

        reverse_bid: bool = is_reverse_bid(coin_from, coin_to)
        port_offerer: int = port_node_from
        port_bidder: int = port_node_to
        port_leader: int = port_bidder if reverse_bid else port_offerer
        port_follower: int = port_offerer if reverse_bid else port_bidder
        logger.info(
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
        wait_for_offer(self.delay_event, port_node_to, offer_id)

        offer = read_json_api(port_node_to, f"offers/{offer_id}")[0]
        assert offer["offer_id"] == offer_id

        data = {
            "offer_id": offer_id,
            "amount_from": offer["amount_from"],
            "validmins": 60,
        }
        rv = post_json_api(port_node_to, "bids/new", data)
        bid_id: str = rv["bid_id"]

        wait_for_bid_state(self.delay_event, port_leader, bid_id)
        wait_for_bid_state(self.delay_event, port_follower, bid_id)
        rv = post_json_api(
            port_leader,
            f"bids/{bid_id}",
            {"debugind": DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND2},
        )
        assert "bid_state" in rv  # Test that the return didn't fail
        rv = post_json_api(
            port_leader,
            f"bids/{bid_id}",
            {
                "debugind": DebugTypes.DONT_RELEASE_COIN_A_LOCK,
                "maindebugind": False,
            },
        )
        rv = post_json_api(
            port_follower,
            f"bids/{bid_id}",
            {"debugind": DebugTypes.BID_DONT_SPEND_COIN_B_LOCK},
        )
        assert "bid_state" in rv
        for node_port in (port_leader, port_follower):
            rv = post_json_api(
                port_follower,
                f"bids/{bid_id}",
                {
                    "debugind": DebugTypes.BID_DONT_SPEND_COIN_B_LOCK,
                    "maindebugind": False,
                },
            )
            assert "bid_state" in rv

        wait_for_bid_state(
            self.delay_event, port_node_from, bid_id, BidStates.BID_RECEIVED
        )
        rv = post_json_api(port_offerer, f"bids/{bid_id}", {"accept": True})
        assert rv["bid_state"] in ("Accepted", "Request accepted")

        expect_state = (
            (BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED, BidStates.SWAP_COMPLETED)
            if with_mercy
            else (BidStates.BID_STALLED_FOR_TEST, BidStates.XMR_SWAP_FAILED_SWIPED)
        )
        wait_for_bid_states(
            self.delay_event,
            bid_id,
            port_leader,
            expect_state,
            port_follower,
            BidStates.XMR_SWAP_FAILED_SWIPED,
            240,
        )
        rv = post_json_api(
            port_leader,
            f"bids/{bid_id}",
            {"show_extra": True, "with_events": True},
        )
        events = rv["events"]
        logger.info(f"Initiator events: {events}")
        if with_mercy:
            assert any(
                event["desc"] == "Lock tx B spend tx published" for event in events
            )
        rv = post_json_api(
            port_follower,
            f"bids/{bid_id}",
            {"show_extra": True, "with_events": True},
        )
        events = rv["events"]
        logger.info(f"Participant events: {events}")
        assert any(
            event["desc"] == "Lock tx A refund swipe tx published" for event in events
        )

    def do_test_04_follower_recover_b_lock_tx(
        self,
        coin_from: Coins,
        coin_to: Coins,
        port_node_from: int = port_node_0,
        port_node_to: int = port_node_1,
        lock_value: int = 16,
    ) -> None:
        logger.info(
            f"---------- Test {coin_from.name} ({port_node_from}) to {coin_to.name} ({port_node_to}) follower recovers coin b lock tx"
        )

        ticker_from: str = getTickerFromCoinId(coin_from)
        ticker_to: str = getTickerFromCoinId(coin_to)

        reverse_bid: bool = is_reverse_bid(coin_from, coin_to)
        port_offerer: int = port_node_from
        port_bidder: int = port_node_to
        port_leader: int = port_bidder if reverse_bid else port_offerer
        port_follower: int = port_offerer if reverse_bid else port_bidder
        logger.info(
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
        wait_for_offer(self.delay_event, port_node_to, offer_id)
        offer = read_json_api(port_node_to, f"offers/{offer_id}")[0]
        assert offer["offer_id"] == offer_id

        data = {
            "offer_id": offer_id,
            "amount_from": offer["amount_from"],
            "validmins": 60,
        }
        rv = post_json_api(port_node_to, "bids/new", data)
        bid_id: str = rv["bid_id"]

        wait_for_bid_state(self.delay_event, port_follower, bid_id)
        rv = post_json_api(
            port_follower,
            f"bids/{bid_id}",
            {"debugind": DebugTypes.CREATE_INVALID_COIN_B_LOCK},
        )
        assert "bid_state" in rv

        wait_for_bid_state(
            self.delay_event, port_node_from, bid_id, BidStates.BID_RECEIVED
        )
        rv = post_json_api(port_offerer, f"bids/{bid_id}", {"accept": True})
        assert rv["bid_state"] in ("Accepted", "Request accepted")
        wait_for_bid_states(
            self.delay_event,
            bid_id,
            port_leader,
            BidStates.XMR_SWAP_FAILED_REFUNDED,
            port_follower,
            BidStates.XMR_SWAP_FAILED_REFUNDED,
            240,
        )
        rv = post_json_api(
            port_leader,
            f"bids/{bid_id}",
            {"show_extra": True, "with_events": True},
        )
        events = rv["events"]
        logger.info(f"Initiator events: {events}")
        participating_coin = coin_from if reverse_bid else coin_to
        if participating_coin in (Coins.XMR,):
            assert any(
                event["desc"] == "Detected invalid lock Tx B" for event in events
            )
        assert any(
            event["desc"] == "Lock tx A refund spend tx published" for event in events
        )
        rv = post_json_api(
            port_follower,
            f"bids/{bid_id}",
            {"show_extra": True, "with_events": True},
        )
        events = rv["events"]
        logger.info(f"Participant events: {events}")
        assert any(event["desc"] == "Lock tx B refund tx published" for event in events)


class Test(TestFunctions):
    __test__ = True
    update_min = 1.5
    daemons = []

    electrumx_port = 50001
    test_coin_a = Coins.PART
    test_coin_b = Coins.BTC
    test_coin_xmr = Coins.XMR

    @classmethod
    def addElectrumxDaemon(cls, coin_name: str, node_rpc_port: int, services_port: int):
        coin_type: Coins = getCoinIdFromName(coin_name)
        ticker: str = getTickerFromCoinId(coin_type)
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
                    stdout_dest,
                ],
                f"electrumx_{ticker_lc}",
            )
        )

    @classmethod
    def setUpClass(cls):
        cls.addElectrumxDaemon("bitcoin", 32793, cls.electrumx_port)
        super().setUpClass()

    @classmethod
    def modifyConfig(cls, test_path, i):
        modify_config(test_path, i)

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
            wallets_password: str = os.getenv("TEST_WALLET_ENCRYPTION_PWD", None)
            if wallets_password is not None:
                assert isinstance(wallets_password, str)
                logging.info("Using wallets password.")
                os.environ["WALLET_ENCRYPTION_PWD"] = wallets_password
            run_prepare(
                i,
                client_path,
                bins_path,
                ",".join(cls.test_coins_list),
                mnemonics[i] if i < len(mnemonics) else None,
                num_nodes=NUM_NODES,
                use_rpcauth=True,
                extra_settings={"min_sequence_lock_seconds": 10},
                port_ofs=PORT_OFS,
                extra_args=extra_args,
            )
            if wallets_password is not None:
                os.environ.pop("WALLET_ENCRYPTION_PWD", None)

    @classmethod
    def tearDownClass(cls):
        logger.info("Finalising Test")
        super().tearDownClass()
        stopDaemons(cls.daemons)

    def test_01_a_full_swap_xmr(self):
        prepare_balance(
            self.delay_event,
            self.test_coin_b,
            1000,
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
            1000,
            self.port_node_0,
            self.port_node_1,
            True,
        )
        self.do_test_01_full_swap(
            self.test_coin_xmr, self.test_coin_b, self.port_node_0, self.port_node_1
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
            self.test_coin_b, self.test_coin_xmr, self.port_node_1, self.port_node_0
        )

    def test_02_b_leader_recover_a_lock_tx_reverse(self):
        prepare_balance(
            self.delay_event,
            self.test_coin_b,
            100,
            self.port_node_0,
            self.port_node_1,
            True,
        )
        self.do_test_02_leader_recover_a_lock_tx(
            self.test_coin_xmr, self.test_coin_b, self.port_node_0, self.port_node_1
        )

    def test_03_a_follower_recover_a_lock_tx(self):
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
        self.do_test_03_follower_recover_a_lock_tx(
            self.test_coin_b, self.test_coin_xmr, self.port_node_0, self.port_node_1
        )

    def test_03_b_follower_recover_a_lock_tx_reverse(self):
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
        self.do_test_03_follower_recover_a_lock_tx(
            self.test_coin_xmr, self.test_coin_b, self.port_node_0, self.port_node_1
        )

    def test_04_a_follower_recover_b_lock_tx(self):
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
        self.do_test_04_follower_recover_b_lock_tx(
            self.test_coin_b, self.test_coin_xmr, self.port_node_1, self.port_node_0
        )

    def test_04_b_follower_recover_b_lock_tx_reverse(self):
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
        self.do_test_04_follower_recover_b_lock_tx(
            self.test_coin_xmr, self.test_coin_b, self.port_node_0, self.port_node_1
        )

    def test_06_preselect_bid_inputs(self):
        coin_from, coin_to = (self.test_coin_xmr, self.test_coin_b)
        logging.info(
            f"---------- Test {coin_from.name} to {coin_to.name} Preselected bid inputs"
        )

        port_node_from = self.port_node_0
        port_node_to = self.port_node_1

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

        ticker_from: str = getTickerFromCoinId(coin_from)
        ticker_to: str = getTickerFromCoinId(coin_to)

        reverse_bid: bool = is_reverse_bid(coin_from, coin_to)
        port_offerer: int = port_node_from
        port_bidder: int = port_node_to
        port_leader: int = port_bidder if reverse_bid else port_offerer
        port_follower: int = port_offerer if reverse_bid else port_bidder
        logger.info(
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
            "lockhrs": 24,
        }

        logger.info(
            f"Creating offer {amt_from_str} {ticker_from} -> {amt_to_str} {ticker_to}"
        )
        offer_id: str = post_json_api(port_node_from, "offers/new", data)["offer_id"]
        wait_for_offer(self.delay_event, port_node_to, offer_id)
        offer = read_json_api(port_node_to, f"offers/{offer_id}")[0]
        assert offer["offer_id"] == offer_id

        data = {
            "offer_id": offer_id,
            "amount_to": amt_to_str,
            "bid_rate": offer["rate"],
        }
        subfee_bid_data = read_json_api(port_node_to, "getsubfeebidtx", data)
        assert offer["offer_id"] == offer_id

        prefunded_bid_tx = CTransaction()
        prefunded_bid_tx.deserialize(BytesIO(bytes.fromhex(subfee_bid_data["bid_tx"])))

        data = {
            "offer_id": offer_id,
            "amount_from": subfee_bid_data["amount_from"],
            "amount_to": subfee_bid_data["amount_to"],
            "prefunded_bid_tx": subfee_bid_data["bid_tx"],
            "validmins": 60,
        }

        rv = post_json_api(port_node_to, "bids/new", data)
        bid_id: str = rv["bid_id"]

        wait_for_bid_state(
            self.delay_event, port_node_from, bid_id, BidStates.BID_RECEIVED
        )
        rv = post_json_api(port_offerer, f"bids/{bid_id}", {"accept": True})
        assert rv["bid_state"] in ("Accepted", "Request accepted")

        logger.info("Completing swap")
        wait_for_bid_states(
            self.delay_event,
            bid_id,
            port_node_from,
            BidStates.SWAP_COMPLETED,
            port_node_to,
            BidStates.SWAP_COMPLETED,
            240,
        )

        bid_info = read_json_api(port_node_to, f"bids/{bid_id}", {"show_extra": True})
        chain_a_lock_txid_hex: str = next(
            (t["txid"] for t in bid_info["txns"] if t["type"] == "Chain A Lock"), None
        )

        conn = ElectrumConnection("127.0.0.1", self.electrumx_port, use_ssl=False)
        conn.connect()
        try:
            _ = conn.call("server.version", ["2.0", "1.4"])
            chain_a_lock_txinfo = conn.call(
                "blockchain.transaction.get", [chain_a_lock_txid_hex, True]
            )
        finally:
            conn.disconnect()

        chain_a_lock_tx = CTransaction()
        chain_a_lock_tx.deserialize(BytesIO(bytes.fromhex(chain_a_lock_txinfo["hex"])))

        prefunded_inputs = {
            (vin.prevout.hash, vin.prevout.n) for vin in prefunded_bid_tx.vin
        }
        chain_inputs = {
            (vin.prevout.hash, vin.prevout.n) for vin in chain_a_lock_tx.vin
        }
        assert len(prefunded_inputs) == len(chain_inputs)
        for prefunded_input in prefunded_inputs:
            assert prefunded_input in chain_inputs


if __name__ == "__main__":
    unittest.main()
