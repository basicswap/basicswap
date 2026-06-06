#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/basicswap/extended/test_pivx.py

"""

import logging
import os
import random
import sys
import unittest

import basicswap.config as cfg
from basicswap.basicswap import (
    Coins,
    SwapTypes,
    BidStates,
    TxStates,
    DebugTypes,
)
from basicswap.util import (
    COIN,
)
from basicswap.basicswap_util import (
    TxLockTypes,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    callrpc_cli,
    stopDaemons,
    wait_for_bid,
    wait_for_offer,
    wait_for_balance,
    wait_for_in_progress,
    wait_for_bid_tx_state,
    TEST_HTTP_PORT,
    waitForRPC,
    make_rpc_func,
)
from tests.basicswap.test_xmr import (
    BaseTest,
    test_delay_event as delay_event,
    callnoderpc,
)
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.bin.run import startDaemon
from basicswap.bin.prepare import downloadPIVXParams

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

NUM_NODES = 3

PIVX_BINDIR = os.path.expanduser(
    os.getenv("PIVX_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "pivx"))
)
PIVXD = os.getenv("PIVXD", "pivxd" + cfg.bin_suffix)
PIVX_CLI = os.getenv("PIVX_CLI", "pivx-cli" + cfg.bin_suffix)
PIVX_TX = os.getenv("PIVX_TX", "pivx-tx" + cfg.bin_suffix)

PIVX_BASE_PORT = 34832
PIVX_BASE_RPC_PORT = 35832
PIVX_BASE_ZMQ_PORT = 36832


def pivxCli(cmd, node_id=0):
    return callrpc_cli(
        PIVX_BINDIR,
        os.path.join(cfg.TEST_DATADIRS, "pivx_" + str(node_id)),
        "regtest",
        cmd,
        PIVX_CLI,
    )


def prepareDataDir(
    datadir, node_id, conf_file, dir_prefix, base_p2p_port, base_rpc_port, num_nodes=3
):
    node_dir = os.path.join(datadir, dir_prefix + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, "w+") as fp:
        fp.write("regtest=1\n")
        fp.write("[regtest]\n")
        fp.write("port=" + str(base_p2p_port + node_id) + "\n")
        fp.write("rpcport=" + str(base_rpc_port + node_id) + "\n")

        salt = generate_salt(16)
        fp.write(
            "rpcauth={}:{}${}\n".format(
                "test" + str(node_id),
                salt,
                password_to_hmac(salt, "test_pass" + str(node_id)),
            )
        )

        fp.write("daemon=0\n")
        fp.write("printtoconsole=0\n")
        fp.write("server=1\n")
        fp.write("discover=0\n")
        fp.write("listenonion=0\n")
        fp.write("bind=127.0.0.1\n")
        fp.write("findpeers=0\n")
        fp.write("debug=1\n")
        fp.write("debugexclude=libevent\n")

        fp.write("fallbackfee=0.01\n")
        fp.write("acceptnonstdtxn=0\n")

        params_dir = os.path.join(datadir, "pivx-params")
        downloadPIVXParams(params_dir)
        fp.write(f"paramsdir={params_dir}\n")

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            fp.write("addnode=127.0.0.1:{}\n".format(base_p2p_port + i))

    return node_dir


class Test(BaseTest):
    __test__ = True
    test_coin_from = Coins.PIVX
    pivx_daemons = []
    pivx_addr = None
    start_ltc_nodes = False
    start_xmr_nodes = False

    @classmethod
    def prepareExtraDataDir(cls, i):
        extra_opts = []
        if not cls.restore_instance:
            prepareDataDir(
                cfg.TEST_DATADIRS,
                i,
                "pivx.conf",
                "pivx_",
                base_p2p_port=PIVX_BASE_PORT,
                base_rpc_port=PIVX_BASE_RPC_PORT,
            )
        cls.pivx_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "pivx_" + str(i)),
                PIVX_BINDIR,
                PIVXD,
                opts=extra_opts,
            )
        )
        logging.info("Started %s %d", PIVXD, cls.pivx_daemons[-1].handle.pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=PIVX_BASE_RPC_PORT), delay_event)

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.PIVX, cls.pivx_daemons[i].handle.pid)

    @classmethod
    def prepareExtraCoins(cls):

        if cls.restore_instance:
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.pivx_addr = (
                cls.swap_clients[0]
                .ci(Coins.PIVX)
                .pubkey_to_address(void_block_rewards_pubkey)
            )
        else:
            num_blocks = 1352  # CHECKLOCKTIMEVERIFY soft-fork activates at (regtest) block height 1351.
            logging.info(f"Mining {num_blocks} pivx blocks")
            cls.pivx_addr = pivxCli("getnewaddress mining_addr")
            pivxCli(f"generatetoaddress {num_blocks} {cls.pivx_addr}")

            ro = pivxCli("getblockchaininfo")
            try:
                assert ro["bip9_softforks"]["csv"]["status"] == "active"
            except Exception:
                logging.info("pivx: csv is not active")
            try:
                assert ro["bip9_softforks"]["segwit"]["status"] == "active"
            except Exception:
                logging.info("pivx: segwit is not active")

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising PIVX Test")
        super().tearDownClass()

        stopDaemons(cls.pivx_daemons)
        cls.pivx_daemons.clear()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["pivx"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": PIVX_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "pivx_" + str(node_id)),
            "bindir": PIVX_BINDIR,
            "use_csv": False,
            "use_segwit": False,
            "wallet_name": "",
        }

    @classmethod
    def coins_loop(cls):
        super().coins_loop()
        callnoderpc(
            0, "generatetoaddress", [1, cls.pivx_addr], base_rpc_port=PIVX_BASE_RPC_PORT
        )

    @classmethod
    def prepareBalances(cls):
        super().prepareBalances()

        cls.prepare_balance(
            cls,
            Coins.PIVX,
            10000.0,
            1801,
            1800,
        )

    def test_02_part_pivx(self):
        logging.info("---------- Test PART to PIVX")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PART,
            Coins.PIVX,
            100 * COIN,
            0.1 * COIN,
            100 * COIN,
            SwapTypes.SELLER_FIRST,
            TxLockTypes.ABS_LOCK_TIME,
        )

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)

        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=80
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=80,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_03_pivx_part(self):
        logging.info("---------- Test PIVX to PART")
        swap_clients = self.swap_clients

        offer_id = swap_clients[1].postOffer(
            Coins.PIVX,
            Coins.PART,
            10 * COIN,
            9.0 * COIN,
            10 * COIN,
            SwapTypes.SELLER_FIRST,
            TxLockTypes.ABS_LOCK_TIME,
        )

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[1], bid_id)
        swap_clients[1].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[0], bid_id, sent=True)

        wait_for_bid(
            delay_event,
            swap_clients[0],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=60,
        )
        wait_for_bid(
            delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=80
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_04_pivx_btc(self):
        logging.info("---------- Test PIVX to BTC")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PIVX,
            Coins.BTC,
            10 * COIN,
            0.1 * COIN,
            10 * COIN,
            SwapTypes.SELLER_FIRST,
            TxLockTypes.ABS_LOCK_TIME,
        )

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=80
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=60,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)

        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_05_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info("---------- Test refund, PIVX to BTC")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PIVX,
            Coins.BTC,
            10 * COIN,
            0.1 * COIN,
            10 * COIN,
            SwapTypes.SELLER_FIRST,
            TxLockTypes.ABS_LOCK_BLOCKS,
            10,
        )

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[1].abandonBid(bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.BID_ABANDONED,
            sent=True,
            wait_for=60,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_06_self_bid(self):
        logging.info("---------- Test same client, BTC to PIVX")
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(
            Coins.PIVX,
            Coins.BTC,
            10 * COIN,
            10 * COIN,
            10 * COIN,
            SwapTypes.SELLER_FIRST,
            TxLockTypes.ABS_LOCK_TIME,
        )

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid_tx_state(
            delay_event,
            swap_clients[0],
            bid_id,
            TxStates.TX_REDEEMED,
            TxStates.TX_REDEEMED,
            wait_for=60,
        )
        wait_for_bid(
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60
        )

        js_0 = read_json_api(1800)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert (
            js_0["num_recv_bids"] == js_0_before["num_recv_bids"] + 1
            and js_0["num_sent_bids"] == js_0_before["num_sent_bids"] + 1
        )

    def test_07_error(self):
        logging.info("---------- Test error, BTC to PIVX, set fee above bid value")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PIVX,
            Coins.BTC,
            0.01 * COIN,
            1.0 * COIN,
            0.01 * COIN,
            SwapTypes.SELLER_FIRST,
            TxLockTypes.ABS_LOCK_TIME,
        )

        wait_for_offer(delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        try:
            swap_clients[0].getChainClientSettings(Coins.BTC)["override_feerate"] = 10.0
            swap_clients[0].getChainClientSettings(Coins.PIVX)[
                "override_feerate"
            ] = 100.0
            wait_for_bid(
                delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=60
            )
            swap_clients[0].abandonBid(bid_id)
        finally:
            del swap_clients[0].getChainClientSettings(Coins.BTC)["override_feerate"]
            del swap_clients[0].getChainClientSettings(Coins.PIVX)["override_feerate"]

    def test_08_wallet(self):
        logging.info("---------- Test {} wallet".format(self.test_coin_from.name))

        logging.info("Test withdrawal")
        addr = pivxCli('getnewaddress "Withdrawal test"')
        wallets = read_json_api(TEST_HTTP_PORT + 0, "wallets")
        assert float(wallets[self.test_coin_from.name]["balance"]) > 100

        post_json = {
            "value": 100,
            "address": addr,
            "subfee": False,
        }
        json_rv = read_json_api(
            TEST_HTTP_PORT + 0,
            "wallets/{}/withdraw".format(self.test_coin_from.name.lower()),
            post_json,
        )
        assert len(json_rv["txid"]) == 64

        logging.info("Test createutxo")
        post_json = {
            "value": 10,
        }
        json_rv = read_json_api(
            TEST_HTTP_PORT + 0,
            "wallets/{}/createutxo".format(self.test_coin_from.name.lower()),
            post_json,
        )
        assert len(json_rv["txid"]) == 64

    def test_09_v3_tx(self):
        logging.info("---------- Test PIVX v3 txns")

        generate_addr = pivxCli('getnewaddress "generate test"')
        pivx_addr = pivxCli('getnewaddress "Sapling test"')
        pivx_sapling_addr = pivxCli('getnewshieldaddress "shield addr"')

        pivxCli(f'sendtoaddress "{pivx_addr}" 6.0')
        pivxCli(f'generatetoaddress 1 "{generate_addr}"')

        txid = pivxCli(
            'shieldsendmany "{}" "[{{\\"address\\": \\"{}\\", \\"amount\\": 1}}]"'.format(
                pivx_addr, pivx_sapling_addr
            )
        )
        rtx = pivxCli(f'getrawtransaction "{txid}" true')
        assert rtx["version"] == 3

        block_hash = None
        for i in range(15):
            rtx = pivxCli(f'getrawtransaction "{txid}" true')
            if "blockhash" in rtx:
                block_hash = rtx["blockhash"]
                logging.info(f"Shielded tx confirmed in block {block_hash} after {i}s")
                break
            if i == 5:
                pivxCli(f'generatetoaddress 1 "{generate_addr}"')
            delay_event.wait(1)
        assert block_hash is not None, "Shielded tx was not confirmed"

        ci = self.swap_clients[0].ci(Coins.PIVX)
        block = ci.getBlockWithTxns(block_hash)

        found = False
        for tx in block["tx"]:
            if txid == tx["txid"]:
                found = True
                break
        assert found

    def ensure_balance(self, coin_type, node_id, amount):
        tla = coin_type.name
        js_w = read_json_api(1800 + node_id, "wallets")
        if float(js_w[tla]["balance"]) < amount:
            post_json = {
                "value": amount,
                "address": js_w[tla]["deposit_address"],
                "subfee": False,
            }
            json_rv = read_json_api(
                1800, "wallets/{}/withdraw".format(tla.lower()), post_json
            )
            assert len(json_rv["txid"]) == 64
            wait_for_balance(
                delay_event,
                "http://127.0.0.1:{}/json/wallets/{}".format(
                    1800 + node_id, tla.lower()
                ),
                "balance",
                amount,
            )

    def test_10_prefunded_itx(self):
        logging.info("---------- Test prefunded itx offer")

        swap_clients = self.swap_clients
        coin_from = Coins.PIVX
        coin_to = Coins.BTC
        swap_type = SwapTypes.SELLER_FIRST
        ci_from = swap_clients[2].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)
        tla_from = coin_from.name

        # Prepare balance
        self.ensure_balance(coin_from, 2, 10.0)
        self.ensure_balance(coin_to, 1, 100.0)

        js_w2 = read_json_api(1802, "wallets")
        post_json = {
            "value": 10.0,
            "address": read_json_api(
                1802, "wallets/{}/nextdepositaddr".format(tla_from.lower())
            ),
            "subfee": True,
        }
        json_rv = read_json_api(
            1802, "wallets/{}/withdraw".format(tla_from.lower()), post_json
        )
        wait_for_balance(
            delay_event,
            "http://127.0.0.1:1802/json/wallets/{}".format(tla_from.lower()),
            "balance",
            9.0,
        )
        assert len(json_rv["txid"]) == 64

        # Create prefunded ITX
        pi = swap_clients[2].pi(SwapTypes.XMR_SWAP)
        js_w2 = read_json_api(1802, "wallets")
        swap_value = 10.0
        if float(js_w2[tla_from]["balance"]) < swap_value:
            swap_value = js_w2[tla_from]["balance"]
        swap_value = ci_from.make_int(swap_value)
        assert swap_value > ci_from.make_int(9)

        addr_to = pi.getMockScriptAddr(ci_from)
        funded_tx = ci_from.createRawFundedTransaction(
            addr_to, swap_value, True, lock_unspents=True
        )
        itx = bytes.fromhex(funded_tx)
        itx_decoded = ci_from.describeTx(itx.hex())

        n = pi.findMockVout(ci_from, itx_decoded)
        value_after_subfee = ci_from.make_int(itx_decoded["vout"][n]["value"])
        assert value_after_subfee < swap_value
        swap_value = value_after_subfee

        extra_options = {"prefunded_itx": itx}
        rate_swap = ci_to.make_int(random.uniform(0.2, 10.0), r=1)
        offer_id = swap_clients[2].postOffer(
            coin_from,
            coin_to,
            swap_value,
            rate_swap,
            swap_value,
            swap_type,
            TxLockTypes.ABS_LOCK_TIME,
            extra_options=extra_options,
        )

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[2], bid_id, BidStates.BID_RECEIVED)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(
            delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=120
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=120,
        )

        # Verify expected inputs were used
        bid, offer = swap_clients[2].getBidAndOffer(bid_id)
        assert bid.initiate_tx
        wtx = ci_from.rpc(
            "gettransaction",
            [
                bid.initiate_tx.txid.hex(),
            ],
        )
        itx_after = ci_from.describeTx(wtx["hex"])
        assert len(itx_after["vin"]) == len(itx_decoded["vin"])
        for i, txin in enumerate(itx_decoded["vin"]):
            assert txin["txid"] == itx_after["vin"][i]["txid"]
            assert txin["vout"] == itx_after["vin"][i]["vout"]

    def test_11_xmrswap_to(self):
        logging.info("---------- Test xmr swap protocol to")

        swap_clients = self.swap_clients
        coin_from = Coins.BTC
        coin_to = Coins.PIVX
        swap_type = SwapTypes.XMR_SWAP
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type
        )

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=120
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=120,
        )

    def test_12_xmrswap_to_recover_b_lock_tx(self):
        coin_from = Coins.BTC
        coin_to = Coins.PIVX
        logging.info(
            "---------- Test {} to {} follower recovers coin b lock tx".format(
                coin_from.name, coin_to.name
            )
        )

        swap_clients = self.swap_clients
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from,
            coin_to,
            amt_swap,
            rate_swap,
            amt_swap,
            SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS,
            lock_value=32,
        )
        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(
            delay_event,
            swap_clients[0],
            bid_id,
            BidStates.XMR_SWAP_FAILED_REFUNDED,
            wait_for=180,
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.XMR_SWAP_FAILED_REFUNDED,
            sent=True,
        )


if __name__ == "__main__":
    unittest.main()
