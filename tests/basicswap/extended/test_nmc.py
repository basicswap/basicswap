#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/basicswap/extended/test_nmc.py

"""

import logging
import os
import random
import sys
import unittest

import basicswap.config as cfg
from basicswap.basicswap import (
    Coins,
)
from basicswap.util import (
    toBool,
)
from basicswap.bin.run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from tests.basicswap.common import (
    stopDaemons,
    waitForRPC,
    make_rpc_func,
)

from tests.basicswap.test_btc_xmr import BasicSwapTest, test_delay_event
from tests.basicswap.test_xmr import NUM_NODES
from tests.basicswap.extended.test_dcr import (
    run_test_success_path,
    run_test_bad_ptx,
    run_test_itx_refund,
)


logger = logging.getLogger("BSX Tests")

if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


NAMECOIN_BINDIR = os.path.expanduser(
    os.getenv("NAMECOIN_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "namecoin"))
)
NAMECOIND = os.getenv("NAMECOIND", "namecoind" + cfg.bin_suffix)
NAMECOIN_CLI = os.getenv("NAMECOIN_CLI", "namecoin-cli" + cfg.bin_suffix)
NAMECOIN_TX = os.getenv("NAMECOIN_TX", "namecoin-tx" + cfg.bin_suffix)

USE_DESCRIPTOR_WALLETS = toBool(os.getenv("USE_DESCRIPTOR_WALLETS", False))

NMC_BASE_PORT = 8136
NMC_BASE_RPC_PORT = 8146


def prepareNMCDataDir(datadir, nodeId, conf_file="namecoin.conf"):
    node_dir = os.path.join(datadir, "nmc_" + str(nodeId))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    filePath = os.path.join(node_dir, conf_file)

    with open(filePath, "w+") as fp:
        fp.write("regtest=1\n")
        fp.write("[regtest]\n")

        fp.write("port=" + str(NMC_BASE_PORT + nodeId) + "\n")
        fp.write("rpcport=" + str(NMC_BASE_RPC_PORT + nodeId) + "\n")
        salt = generate_salt(16)
        fp.write(
            "rpcauth={}:{}${}\n".format(
                "test" + str(nodeId),
                salt,
                password_to_hmac(salt, "test_pass" + str(nodeId)),
            )
        )

        fp.write("daemon=0\n")
        fp.write("printtoconsole=0\n")
        fp.write("server=1\n")
        fp.write("discover=0\n")
        fp.write("listenonion=0\n")
        fp.write("bind=127.0.0.1\n")
        fp.write("debug=1\n")
        fp.write("debugexclude=libevent\n")

        fp.write("fallbackfee=0.01\n")
        fp.write("acceptnonstdtxn=0\n")
        fp.write("deprecatedrpc=create_bdb\n")
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")

        for i in range(0, NUM_NODES):
            if nodeId == i:
                continue
            fp.write("addnode=127.0.0.1:{}\n".format(NMC_BASE_PORT + i))


class TestNMC(BasicSwapTest):
    __test__ = True
    test_coin = Coins.NMC
    test_coin_from = Coins.NMC
    nmc_daemons = []
    start_ltc_nodes = False
    start_xmr_nodes = True
    base_rpc_port = NMC_BASE_RPC_PORT
    nmc_addr = None
    max_fee: int = 200000
    test_fee_rate: int = 10000  # sats/kvB

    def mineBlock(self, num_blocks: int = 1) -> None:
        self.callnoderpc("generatetoaddress", [num_blocks, self.nmc_addr])

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Namecoin Test")
        stopDaemons(cls.nmc_daemons)
        cls.nmc_daemons.clear()

        super(TestNMC, cls).tearDownClass()

    @classmethod
    def coins_loop(cls):
        super(TestNMC, cls).coins_loop()
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        try:
            if cls.nmc_addr is not None:
                ci0.rpc_wallet("generatetoaddress", [1, cls.nmc_addr])
        except Exception as e:
            logging.warning(f"coins_loop generate {e}")

    @classmethod
    def prepareExtraDataDir(cls, i: int) -> None:
        if not cls.restore_instance:
            prepareNMCDataDir(cfg.TEST_DATADIRS, i)

        cls.nmc_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "nmc_" + str(i)),
                NAMECOIN_BINDIR,
                NAMECOIND,
            )
        )
        logging.info("Started {} {}".format(NAMECOIND, cls.nmc_daemons[-1].handle.pid))

        nmc_rpc = make_rpc_func(i, base_rpc_port=NMC_BASE_RPC_PORT)
        waitForRPC(
            nmc_rpc,
            test_delay_event,
            rpc_command="getnetworkinfo",
            max_tries=12,
        )
        waitForRPC(nmc_rpc, test_delay_event, rpc_command="getblockchaininfo")
        if len(nmc_rpc("listwallets")) < 1:
            nmc_rpc(
                "createwallet",
                ["wallet.dat", False, False, "", False, USE_DESCRIPTOR_WALLETS],
            )

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.DCR, cls.nmc_daemons[i].handle.pid)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["namecoin"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": NMC_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "nmc_" + str(node_id)),
            "bindir": NAMECOIN_BINDIR,
            "use_csv": True,
            "use_segwit": True,
            "blocks_confirmed": 1,
        }

    @classmethod
    def prepareExtraCoins(cls):
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        if not cls.restore_instance:
            cls.nmc_addr = ci0.rpc_wallet("getnewaddress", ["mining_addr", "bech32"])
        else:
            addrs = ci0.rpc_wallet(
                "getaddressesbylabel",
                [
                    "mining_addr",
                ],
            )
            cls.nmc_addr = addrs.keys()[0]

        num_blocks: int = 500
        if ci0.rpc("getblockcount") < num_blocks:
            logging.info(f"Mining {num_blocks} Namecoin blocks to {cls.nmc_addr}")
            ci0.rpc("generatetoaddress", [num_blocks, cls.nmc_addr])
        logging.info("NMC blocks: {}".format(ci0.rpc("getblockcount")))

    def test_007_hdwallet(self):
        logging.info("---------- Test {} hdwallet".format(self.test_coin_from.name))

        test_seed = "8e54a313e6df8918df6d758fafdbf127a115175fdd2238d0e908dd8093c9ac3b"
        test_wif = (
            self.swap_clients[0]
            .ci(self.test_coin_from)
            .encodeKey(bytes.fromhex(test_seed))
        )
        new_wallet_name = random.randbytes(10).hex()
        self.callnoderpc(
            "createwallet",
            [new_wallet_name, False, False, "", False, USE_DESCRIPTOR_WALLETS],
        )
        self.callnoderpc("sethdseed", [True, test_wif], wallet=new_wallet_name)
        addr = self.callnoderpc(
            "getnewaddress", ["add test", "bech32"], wallet=new_wallet_name
        )
        self.callnoderpc("unloadwallet", [new_wallet_name])
        assert addr == "ncrt1qps7hnjd866e9ynxadgseprkc2l56m00dxkl7pk"

    def test_012_p2sh_p2wsh(self):
        # Fee rate
        pass

    def test_02_sh_part_coin(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_success_path(self, Coins.PART, self.test_coin)

    def test_03_sh_coin_part(self):
        run_test_success_path(self, self.test_coin, Coins.PART)

    def test_04_sh_part_coin_bad_ptx(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_bad_ptx(self, Coins.PART, self.test_coin)

    def test_05_sh_coin_part_bad_ptx(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_bad_ptx(self, self.test_coin, Coins.PART)

    def test_06_sh_part_coin_itx_refund(self):
        run_test_itx_refund(self, Coins.PART, self.test_coin)

    def test_07_sh_coin_part_itx_refund(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_itx_refund(self, self.test_coin, Coins.PART)

    def test_01_b_full_swap_reverse(self):
        self.prepare_balance(self.test_coin, 100.0, 1801, 1800)
        self.do_test_01_full_swap(Coins.XMR, self.test_coin_from)


if __name__ == "__main__":
    unittest.main()
