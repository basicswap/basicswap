#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
export TEST_PATH=/tmp/test_persistent
mkdir -p ${TEST_PATH}/bin
cp -r ~/tmp/basicswap_bin/* ${TEST_PATH}/bin
export PYTHONPATH=$(pwd)
export XMR_RPC_USER=xmr_user
export XMR_RPC_PWD=xmr_pwd
python tests/basicswap/extended/test_xmr_persistent.py


# Copy coin releases to permanent storage for faster subsequent startups
cp -r ${TEST_PATH}/bin/* ~/tmp/basicswap_bin/


# Continue existing chains with
export RESET_TEST=false

"""

import json
import logging
import multiprocessing
import os
import random
import signal
import sys
import threading
import time
import unittest
from unittest.mock import patch

from basicswap.rpc_xmr import (
    callrpc_xmr,
)
from basicswap.rpc import (
    callrpc,
)
from tests.basicswap.common import (
    BASE_RPC_PORT,
    BTC_BASE_RPC_PORT,
    LTC_BASE_RPC_PORT,
)
from tests.basicswap.test_bch_xmr import (
    BCH_BASE_RPC_PORT,
)
from tests.basicswap.util import (
    make_boolean,
    read_json_api,
    waitForServer,
)
from tests.basicswap.common_xmr import (
    prepare_nodes,
    XMR_BASE_RPC_PORT,
    DOGE_BASE_RPC_PORT,
    NMC_BASE_RPC_PORT,
    FIRO_RPC_PORT_BASE,
)
from basicswap.interface.dcr.rpc import callrpc as callrpc_dcr
import basicswap.bin.run as runSystem

test_path = os.path.expanduser(os.getenv("TEST_PATH", "/tmp/test_persistent"))
RESET_TEST = make_boolean(os.getenv("RESET_TEST", "true"))

PORT_OFS = int(os.getenv("PORT_OFS", 1))
UI_PORT = 12700 + PORT_OFS

PARTICL_RPC_PORT_BASE = int(os.getenv("PARTICL_RPC_PORT_BASE", BASE_RPC_PORT))
BITCOIN_RPC_PORT_BASE = int(os.getenv("BITCOIN_RPC_PORT_BASE", BTC_BASE_RPC_PORT))
LITECOIN_RPC_PORT_BASE = int(os.getenv("LITECOIN_RPC_PORT_BASE", LTC_BASE_RPC_PORT))
DECRED_WALLET_RPC_PORT_BASE = int(os.getenv("DECRED_WALLET_RPC_PORT_BASE", 9210))
NAMECOIN_RPC_PORT_BASE = int(os.getenv("NAMECOIN_RPC_PORT_BASE", NMC_BASE_RPC_PORT))
XMR_BASE_RPC_PORT = int(os.getenv("XMR_BASE_RPC_PORT", XMR_BASE_RPC_PORT))
BITCOINCASH_RPC_PORT_BASE = int(
    os.getenv("BITCOINCASH_RPC_PORT_BASE", BCH_BASE_RPC_PORT)
)
DOGECOIN_RPC_PORT_BASE = int(os.getenv("DOGECOIN_RPC_PORT_BASE", DOGE_BASE_RPC_PORT))
TEST_COINS_LIST = os.getenv("TEST_COINS_LIST", "bitcoin,monero")

NUM_NODES = int(os.getenv("NUM_NODES", 3))
EXTRA_CONFIG_JSON = json.loads(os.getenv("EXTRA_CONFIG_JSON", "{}"))

SIMPLEX_SERVER_ADDRESS = os.getenv("SIMPLEX_SERVER_ADDRESS", "")
SIMPLEX_CLIENT_PATH = os.path.expanduser(os.getenv("SIMPLEX_CLIENT_PATH", ""))

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


def callpartrpc(
    node_id,
    method,
    params=[],
    wallet=None,
    base_rpc_port=PARTICL_RPC_PORT_BASE + PORT_OFS,
):
    auth = "test_part_{0}:test_part_pwd_{0}".format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def callbtcrpc(
    node_id,
    method,
    params=[],
    wallet=None,
    base_rpc_port=BITCOIN_RPC_PORT_BASE + PORT_OFS,
):
    auth = "test_btc_{0}:test_btc_pwd_{0}".format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def callltcrpc(
    node_id,
    method,
    params=[],
    wallet=None,
    base_rpc_port=LITECOIN_RPC_PORT_BASE + PORT_OFS,
):
    auth = "test_ltc_{0}:test_ltc_pwd_{0}".format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def calldcrrpc(
    node_id, method, params=[], base_rpc_port=DECRED_WALLET_RPC_PORT_BASE + PORT_OFS
):
    auth = "user:dcr_pwd"
    return callrpc_dcr(base_rpc_port + node_id, auth, method, params)


def callnmcrpc(
    node_id,
    method,
    params=[],
    wallet="wallet.dat",
    base_rpc_port=NAMECOIN_RPC_PORT_BASE + PORT_OFS,
):
    auth = "test_nmc_{0}:test_nmc_pwd_{0}".format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def callfirorpc(
    node_id,
    method,
    params=[],
    base_rpc_port=FIRO_RPC_PORT_BASE + PORT_OFS,
):
    auth = "test_firo_{0}:test_firo_pwd_{0}".format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params)


def callbchrpc(
    node_id,
    method,
    params=[],
    wallet=None,
    base_rpc_port=BITCOINCASH_RPC_PORT_BASE + PORT_OFS,
):
    auth = "test_bch_{0}:test_bch_pwd_{0}".format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def calldogerpc(
    node_id,
    method,
    params=[],
    wallet=None,
    base_rpc_port=DOGECOIN_RPC_PORT_BASE + PORT_OFS,
):
    auth = "test_doge_{0}:test_doge_pwd_{0}".format(node_id)
    return callrpc(base_rpc_port + node_id, auth, method, params, wallet)


def updateThread(cls):
    while not cls.delay_event.is_set():
        try:
            if cls.btc_addr is not None:
                callbtcrpc(0, "generatetoaddress", [1, cls.btc_addr])
            if cls.ltc_addr is not None:
                callltcrpc(0, "generatetoaddress", [1, cls.ltc_addr])
            if cls.nmc_addr is not None:
                callnmcrpc(0, "generatetoaddress", [1, cls.nmc_addr])
            if cls.firo_addr is not None:
                callfirorpc(0, "generatetoaddress", [1, cls.firo_addr])
            if cls.bch_addr is not None:
                callbchrpc(0, "generatetoaddress", [1, cls.bch_addr])
            if cls.doge_addr is not None:
                calldogerpc(0, "generatetoaddress", [1, cls.doge_addr])
        except Exception as e:
            print("updateThread error", str(e))
        cls.delay_event.wait(random.randrange(cls.update_min, cls.update_max))


def updateThreadXMR(cls):
    xmr_auth = None
    if os.getenv("XMR_RPC_USER", "") != "":
        xmr_auth = (os.getenv("XMR_RPC_USER", ""), os.getenv("XMR_RPC_PWD", ""))

    while not cls.delay_event.is_set():
        try:
            if cls.xmr_addr is not None:
                callrpc_xmr(
                    XMR_BASE_RPC_PORT + 1,
                    "generateblocks",
                    {"wallet_address": cls.xmr_addr, "amount_of_blocks": 1},
                    auth=xmr_auth,
                )
        except Exception as e:
            print("updateThreadXMR error", str(e))
        cls.delay_event.wait(random.randrange(cls.xmr_update_min, cls.xmr_update_max))


def updateThreadDCR(cls):
    while not cls.delay_event.is_set():
        try:
            pass
            num_passed: int = 0
            for i in range(30):
                try:
                    calldcrrpc(0, "purchaseticket", [cls.dcr_acc, 0.1, 0])
                    num_passed += 1
                    if num_passed >= 5:
                        break
                    cls.delay_event.wait(0.1)
                except Exception as e:
                    if "double spend" in str(e):
                        pass
                    else:
                        logging.warning("updateThreadDCR purchaseticket {}".format(e))
                    cls.delay_event.wait(0.5)
            try:
                if num_passed >= 5:
                    calldcrrpc(
                        0,
                        "generate",
                        [
                            1,
                        ],
                    )
            except Exception as e:
                logging.warning("updateThreadDCR generate {}".format(e))
        except Exception as e:
            print("updateThreadDCR error", str(e))
        cls.delay_event.wait(random.randrange(cls.dcr_update_min, cls.dcr_update_max))


def signal_handler(self, sig, frame):
    os.write(sys.stdout.fileno(), f"Signal {sig} detected.\n".encode("utf-8"))
    self.delay_event.set()


def run_thread(self, client_id):
    client_path = os.path.join(test_path, "client{}".format(client_id))
    testargs = [
        "basicswap-run",
        "-datadir=" + client_path,
        "-regtest",
        f"-logprefix=BSX{client_id}",
    ]
    with patch.object(sys, "argv", testargs):
        runSystem.main()


def start_processes(self):
    self.delay_event.clear()

    for i in range(NUM_NODES):
        self.processes.append(
            multiprocessing.Process(
                target=run_thread,
                args=(
                    self,
                    i,
                ),
            )
        )
        self.processes[-1].start()

    for i in range(NUM_NODES):
        waitForServer(self.delay_event, UI_PORT + i)

    wallets = read_json_api(UI_PORT + 1, "wallets")

    if "monero" in TEST_COINS_LIST:
        xmr_auth = None
        if os.getenv("XMR_RPC_USER", "") != "":
            xmr_auth = (os.getenv("XMR_RPC_USER", ""), os.getenv("XMR_RPC_PWD", ""))

        self.xmr_addr = wallets["XMR"]["main_address"]
        num_blocks = 100
        if (
            callrpc_xmr(XMR_BASE_RPC_PORT + 1, "get_block_count", auth=xmr_auth)[
                "count"
            ]
            < num_blocks
        ):
            logging.info(
                "Mining {} Monero blocks to {}.".format(num_blocks, self.xmr_addr)
            )
            callrpc_xmr(
                XMR_BASE_RPC_PORT + 1,
                "generateblocks",
                {"wallet_address": self.xmr_addr, "amount_of_blocks": num_blocks},
                auth=xmr_auth,
            )
        logging.info(
            "XMR blocks: %d",
            callrpc_xmr(XMR_BASE_RPC_PORT + 1, "get_block_count", auth=xmr_auth)[
                "count"
            ],
        )

    self.btc_addr = callbtcrpc(0, "getnewaddress", ["mining_addr", "bech32"])
    num_blocks: int = 500  # Mine enough to activate segwit
    if callbtcrpc(0, "getblockcount") < num_blocks:
        logging.info("Mining %d Bitcoin blocks to %s", num_blocks, self.btc_addr)
        callbtcrpc(0, "generatetoaddress", [num_blocks, self.btc_addr])
    logging.info("BTC blocks: %d", callbtcrpc(0, "getblockcount"))

    if "litecoin" in TEST_COINS_LIST:
        self.ltc_addr = callltcrpc(
            0, "getnewaddress", ["mining_addr"], wallet="wallet.dat"
        )
        num_blocks: int = 431
        have_blocks: int = callltcrpc(0, "getblockcount")
        if have_blocks < 500:
            logging.info("Mining %d Litecoin blocks to %s", num_blocks, self.ltc_addr)
            callltcrpc(
                0,
                "generatetoaddress",
                [num_blocks - have_blocks, self.ltc_addr],
                wallet="wallet.dat",
            )

            # https://github.com/litecoin-project/litecoin/issues/807
            # Block 432 is when MWEB activates. It requires a peg-in. You'll need to generate an mweb address and send some coins to it. Then it will allow you to mine the next block.
            mweb_addr = callltcrpc(
                0, "getnewaddress", ["mweb_addr", "mweb"], wallet="mweb"
            )
            callltcrpc(0, "sendtoaddress", [mweb_addr, 1.0], wallet="wallet.dat")
            num_blocks = 69

            have_blocks: int = callltcrpc(0, "getblockcount")
            callltcrpc(
                0,
                "generatetoaddress",
                [500 - have_blocks, self.ltc_addr],
                wallet="wallet.dat",
            )

    if "decred" in TEST_COINS_LIST:
        if RESET_TEST:
            _ = calldcrrpc(0, "getnewaddress")
            # assert (addr == self.dcr_addr)
            self.dcr_acc = calldcrrpc(
                0,
                "getaccount",
                [
                    self.dcr_addr,
                ],
            )
            calldcrrpc(
                0,
                "generate",
                [
                    110,
                ],
            )
        else:
            self.dcr_acc = calldcrrpc(
                0,
                "getaccount",
                [
                    self.dcr_addr,
                ],
            )

        self.update_thread_dcr = threading.Thread(target=updateThreadDCR, args=(self,))
        self.update_thread_dcr.start()

    if "firo" in TEST_COINS_LIST:
        self.firo_addr = callfirorpc(0, "getnewaddress", ["mining_addr"])
        num_blocks: int = 200
        have_blocks: int = callfirorpc(0, "getblockcount")
        if have_blocks < num_blocks:
            logging.info(
                "Mining %d Firo blocks to %s",
                num_blocks - have_blocks,
                self.firo_addr,
            )
            callfirorpc(
                0,
                "generatetoaddress",
                [num_blocks - have_blocks, self.firo_addr],
            )

    if "bitcoincash" in TEST_COINS_LIST:
        self.bch_addr = callbchrpc(
            0, "getnewaddress", ["mining_addr"], wallet="wallet.dat"
        )
        num_blocks: int = 200
        have_blocks: int = callbchrpc(0, "getblockcount")
        if have_blocks < num_blocks:
            logging.info(
                "Mining %d Bitcoincash blocks to %s",
                num_blocks - have_blocks,
                self.bch_addr,
            )
            callbchrpc(
                0,
                "generatetoaddress",
                [num_blocks - have_blocks, self.bch_addr],
                wallet="wallet.dat",
            )

    if "dogecoin" in TEST_COINS_LIST:
        self.doge_addr = calldogerpc(0, "getnewaddress", ["mining_addr"])
        num_blocks: int = 200
        have_blocks: int = calldogerpc(0, "getblockcount")
        if have_blocks < num_blocks:
            logging.info(
                "Mining %d Dogecoin blocks to %s",
                num_blocks - have_blocks,
                self.doge_addr,
            )
            calldogerpc(
                0, "generatetoaddress", [num_blocks - have_blocks, self.doge_addr]
            )

    if "namecoin" in TEST_COINS_LIST:
        self.nmc_addr = callnmcrpc(0, "getnewaddress", ["mining_addr", "bech32"])
        num_blocks: int = 500
        have_blocks: int = callnmcrpc(0, "getblockcount")
        if have_blocks < num_blocks:
            logging.info(
                f"Mining {num_blocks - have_blocks} Namecoin blocks to {self.nmc_addr}"
            )
            callnmcrpc(
                0, "generatetoaddress", [num_blocks - have_blocks, self.nmc_addr]
            )

    if RESET_TEST:
        # Lower output split threshold for more stakeable outputs
        for i in range(NUM_NODES):
            callpartrpc(
                i,
                "walletsettings",
                [
                    "stakingoptions",
                    {"stakecombinethreshold": 100, "stakesplitthreshold": 200},
                ],
            )
    self.update_thread = threading.Thread(target=updateThread, args=(self,))
    self.update_thread.start()

    self.update_thread_xmr = threading.Thread(target=updateThreadXMR, args=(self,))
    self.update_thread_xmr.start()

    # Wait for height, or sequencelock is thrown off by genesis blocktime
    num_blocks = 3
    logging.info(f"Waiting for Particl chain height {num_blocks}")
    for i in range(60):
        if self.delay_event.is_set():
            raise ValueError("Test stopped.")
        particl_blocks = callpartrpc(0, "getblockcount")
        print("particl_blocks", particl_blocks)
        if particl_blocks >= num_blocks:
            break
        self.delay_event.wait(1)
    logging.info("PART blocks: %d", callpartrpc(0, "getblockcount"))
    assert particl_blocks >= num_blocks


class BaseTestWithPrepare(unittest.TestCase):
    __test__ = False

    update_min = int(os.getenv("UPDATE_THREAD_MIN_WAIT", "1"))
    update_max = update_min * 4

    xmr_update_min = int(os.getenv("XMR_UPDATE_THREAD_MIN_WAIT", "1"))
    xmr_update_max = xmr_update_min * 4

    dcr_update_min = int(os.getenv("DCR_UPDATE_THREAD_MIN_WAIT", "1"))
    dcr_update_max = dcr_update_min * 4

    delay_event = threading.Event()
    update_thread = None
    update_thread_xmr = None
    update_thread_dcr = None
    processes = []
    btc_addr = None
    ltc_addr = None
    dcr_addr = "SsYbXyjkKAEXXcGdFgr4u4bo4L8RkCxwQpH"
    dcr_acc = None
    nmc_addr = None
    xmr_addr = None
    firo_addr = None
    bch_addr = None
    doge_addr = None
    initialised = False

    @classmethod
    def setUpClass(cls):
        super(BaseTestWithPrepare, cls).setUpClass()

        random.seed(time.time())

        if os.path.exists(test_path) and not RESET_TEST:
            logging.info(f"Continuing with existing directory: {test_path}")
        else:
            logging.info(f"Preparing {NUM_NODES} nodes.")
            prepare_nodes(
                NUM_NODES,
                TEST_COINS_LIST,
                True,
                {"min_sequence_lock_seconds": 60},
                PORT_OFS,
            )

        signal.signal(
            signal.SIGINT, lambda signal, frame: signal_handler(cls, signal, frame)
        )

    @classmethod
    def tearDownClass(cls):
        logging.info("Stopping test")
        cls.delay_event.set()
        if cls.update_thread:
            cls.update_thread.join()
        if cls.update_thread_xmr:
            cls.update_thread_xmr.join()
        if cls.update_thread_dcr:
            cls.update_thread_dcr.join()
        for p in cls.processes:
            p.terminate()
        for p in cls.processes:
            p.join()
        cls.update_thread = None
        cls.update_thread_xmr = None
        cls.update_thread_dcr = None
        cls.processes = []

    def setUp(self):
        if self.initialised:
            return
        start_processes(self)
        waitForServer(self.delay_event, UI_PORT + 0)
        waitForServer(self.delay_event, UI_PORT + 1)
        self.initialised = True


class Test(BaseTestWithPrepare):
    def test_persistent(self):

        while not self.delay_event.is_set():
            logging.info("Looping indefinitely, ctrl+c to exit.")
            self.delay_event.wait(10)


if __name__ == "__main__":
    unittest.main()
