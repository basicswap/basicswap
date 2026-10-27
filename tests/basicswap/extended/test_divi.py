#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/basicswap/extended/test_divi.py

Modelled on test_pivx.py.  Divi is a PIVX fork, but its daemon is older and the
harness has to work around several gaps:

  * No generatetoaddress.  Mining is `setgenerate <n>`, which is regtest-only
    and always pays the node's own wallet, so there is no mining address.
  * No rpcauth.  The conf uses rpcuser/rpcpassword.
  * No [regtest] config sections (that syntax postdates this codebase), and no
    acceptnonstdtxn, fallbackfee or findpeers options.
  * No shielded pool, so no params directory to download.
  * CLTV is in Divi's mandatory script flags rather than behind a soft fork, so
    unlike PIVX there is no activation height to mine past.

Only the absolute-locktime (CLTV) swap path is exercised: Divi has no CSV.
"""

import logging
import os
import random
import sys
import unittest
from urllib.request import urlopen

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
from tests.basicswap.util.common import (
    read_json_api,
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
from basicswap.bin.run import startDaemon

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))

NUM_NODES = 3

DIVI_BINDIR = os.path.expanduser(
    os.getenv("DIVI_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "divi"))
)
DIVID = os.getenv("DIVID", "divid" + cfg.bin_suffix)
DIVI_CLI = os.getenv("DIVI_CLI", "divi-cli" + cfg.bin_suffix)

DIVI_BASE_PORT = 34852
DIVI_BASE_RPC_PORT = 35852


def diviCli(cmd, node_id=0):
    return callrpc_cli(
        DIVI_BINDIR,
        os.path.join(cfg.TEST_DATADIRS, "divi_" + str(node_id)),
        "regtest",
        cmd,
        DIVI_CLI,
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
        # Flat options only: divid predates [section] config syntax.
        fp.write("regtest=1\n")
        fp.write("port=" + str(base_p2p_port + node_id) + "\n")
        fp.write("rpcport=" + str(base_rpc_port + node_id) + "\n")
        # divid has no rpcauth option.
        fp.write("rpcuser=test{}\n".format(node_id))
        fp.write("rpcpassword=test_pass{}\n".format(node_id))
        fp.write("daemon=0\n")
        fp.write("printtoconsole=0\n")
        fp.write("server=1\n")
        fp.write("discover=0\n")
        fp.write("listenonion=0\n")
        fp.write("bind=127.0.0.1\n")
        fp.write("debug=1\n")
        fp.write("debugexclude=libevent\n")
        # listunspent omits watch-only outputs on divid, so swap outputs are
        # found through the address index instead.
        fp.write("addressindex=1\n")
        fp.write("txindex=1\n")

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            fp.write("addnode=127.0.0.1:{}\n".format(base_p2p_port + i))

    return node_dir


class Test(BaseTest):
    __test__ = True
    test_coin_from = Coins.DIVI
    divi_daemons = []
    divi_addr = None
    start_ltc_nodes = True
    start_xmr_nodes = False

    @classmethod
    def prepareExtraDataDir(cls, i):
        extra_opts = []
        if not cls.restore_instance:
            prepareDataDir(
                cfg.TEST_DATADIRS,
                i,
                "divi.conf",
                "divi_",
                base_p2p_port=DIVI_BASE_PORT,
                base_rpc_port=DIVI_BASE_RPC_PORT,
            )
        cls.divi_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "divi_" + str(i)),
                DIVI_BINDIR,
                DIVID,
                opts=extra_opts,
            )
        )
        logging.info("Started %s %d", DIVID, cls.divi_daemons[-1].handle.pid)

        # divid builds a 2000 key keypool on first start, which takes a while.
        waitForRPC(
            make_rpc_func(i, base_rpc_port=DIVI_BASE_RPC_PORT),
            delay_event,
            max_tries=30,
        )

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemon(Coins.DIVI, cls.divi_daemons[i])

    @classmethod
    def prepareExtraCoins(cls):
        if cls.restore_instance:
            cls.divi_addr = diviCli("getnewaddress mining_addr")
            return
        # setgenerate always pays the node's own wallet, so just record an
        # address from node 0 for reference.  No CLTV activation height to mine
        # past: Divi has CLTV in its mandatory script flags.
        cls.divi_addr = diviCli("getnewaddress mining_addr")
        num_blocks = 200
        logging.info(f"Mining {num_blocks} divi blocks to node 0")
        diviCli(f"setgenerate {num_blocks}")

        ro = diviCli("getblockchaininfo")
        logging.info("divi: height %d", ro["blocks"])
        # Divi reports no softfork section at all; CLTV is always on.
        assert "bip9_softforks" not in ro

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Divi Test")
        super().tearDownClass()

        stopDaemons(cls.divi_daemons)
        cls.divi_daemons.clear()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["divi"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": DIVI_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "divi_" + str(node_id)),
            "bindir": DIVI_BINDIR,
            "use_csv": False,
            "use_segwit": False,
            "wallet_name": "",
        }

    @classmethod
    def coins_loop(cls):
        super().coins_loop()
        # No generatetoaddress; setgenerate mines to node 0's own wallet.
        callnoderpc(0, "setgenerate", [1], base_rpc_port=DIVI_BASE_RPC_PORT)

    @classmethod
    def waitForWalletInfo(cls, port: int, ticker: str = "DIVI", timeout: int = 120):
        """Wait until the cached wallets info has a balance for this coin.

        /wallets serves a cache filled by a background thread.  Until that
        first pass completes the coin is reported as {"no_data": True}, and
        prepare_balance reads ["balance"] straight off it.  Touching
        /wallets/<coin> first forces a live getWalletInfo, which seeds the
        cache.
        """
        for i in range(timeout):
            if delay_event.is_set():
                raise ValueError("Test stopped.")
            try:
                read_json_api(port, f"wallets/{ticker.lower()}")
                js = read_json_api(port, "wallets")
                if "balance" in js.get(ticker, {}):
                    logging.info(
                        "%s wallet info ready on port %d after %ds", ticker, port, i
                    )
                    return
            except Exception as e:  # noqa: BLE001 - keep polling
                logging.debug(f"waitForWalletInfo: {e}")
            delay_event.wait(1)
        raise ValueError(f"waitForWalletInfo timed out for {ticker} on port {port}")

    @classmethod
    def prepareBalances(cls):
        super().prepareBalances()

        cls.waitForWalletInfo(1800)
        cls.waitForWalletInfo(1801)

        cls.prepare_balance(
            cls,
            Coins.DIVI,
            10000.0,
            1801,
            1800,
        )

    def test_01_coin_registered(self):
        logging.info("---------- Test Divi is registered and the interface loads")
        swap_clients = self.swap_clients
        ci = swap_clients[0].ci(Coins.DIVI)

        assert ci.coin_type() == Coins.DIVI
        assert ci.using_segwit() is False
        assert ci.txVersion() == 1

        height = ci.getChainHeight()
        logging.info("divi chain height %d", height)
        assert height > 0

        # median time past is computed locally, divid reports no mediantime
        mtp = ci.getChainMedianTime()
        assert mtp > 0
        logging.info("divi median time past %d", mtp)

    def test_02_part_divi(self):
        logging.info("---------- Test PART to DIVI")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.PART,
            Coins.DIVI,
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
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=180,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_03_divi_part(self):
        logging.info("---------- Test DIVI to PART")
        swap_clients = self.swap_clients

        offer_id = swap_clients[1].postOffer(
            Coins.DIVI,
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
            wait_for=180,
        )
        wait_for_bid(
            delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_04_divi_btc(self):
        logging.info("---------- Test DIVI to BTC")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.DIVI,
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
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=180,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_05_divi_ltc(self):
        logging.info("---------- Test DIVI to LTC")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.DIVI,
            Coins.LTC,
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
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=180,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_06_ltc_divi(self):
        logging.info("---------- Test LTC to DIVI")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.LTC,
            Coins.DIVI,
            0.1 * COIN,
            10 * COIN,
            0.1 * COIN,
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
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=180,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_07_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info("---------- Test refund, DIVI to BTC")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.DIVI,
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

    def test_08_self_bid(self):
        logging.info("---------- Test same client, BTC to DIVI")
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(
            Coins.DIVI,
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

    def test_09_error(self):
        logging.info("---------- Test error, BTC to DIVI, set fee above bid value")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.DIVI,
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
            swap_clients[0].getChainClientSettings(Coins.DIVI)[
                "override_feerate"
            ] = 100.0
            wait_for_bid(
                delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=60
            )
            swap_clients[0].abandonBid(bid_id)
        finally:
            del swap_clients[0].getChainClientSettings(Coins.BTC)["override_feerate"]
            del swap_clients[0].getChainClientSettings(Coins.DIVI)["override_feerate"]

    def test_10_wallet(self):
        logging.info("---------- Test {} wallet".format(self.test_coin_from.name))

        logging.info("Test withdrawal")
        addr = diviCli('getnewaddress "Withdrawal test"')
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

    def test_11_prefunded_itx(self):
        logging.info("---------- Test prefunded itx offer")

        swap_clients = self.swap_clients
        coin_from = Coins.DIVI
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
                1802, "wallets/{}/nextdepositaddr".format(tla_from.lower()), {}
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

    def test_12_xmrswap_to(self):
        logging.info("---------- Test xmr swap protocol to")

        swap_clients = self.swap_clients
        coin_from = Coins.BTC
        coin_to = Coins.DIVI
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

    def test_13_xmrswap_to_recover_b_lock_tx(self):
        coin_from = Coins.BTC
        coin_to = Coins.DIVI
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

    def test_14_xmrswap_reverse_from_divi(self):
        # Outside regtest strict_swap_type rejects secret-hash for DIVI with a
        # segwit coin, so offering DIVI uses a reverse adaptor-sig bid.
        logging.info("---------- Test xmr swap protocol reverse, DIVI to BTC")

        swap_clients = self.swap_clients
        coin_from = Coins.DIVI
        coin_to = Coins.BTC
        swap_type = SwapTypes.XMR_SWAP
        assert swap_clients[0].is_reverse_ads_bid(coin_from, coin_to)
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(1.0, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.01, 0.1), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type
        )

        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=180,
        )

    def test_15_xmrswap_reverse_divi_part_strict(self):
        # The mainnet shape: 1000 DIVI offered for 1 PART with the mainnet
        # default strict_swap_type, which leaves only the reverse adaptor bid.
        logging.info("---------- Test xmr swap protocol reverse, DIVI to PART, strict")

        swap_clients = self.swap_clients
        coin_from = Coins.DIVI
        coin_to = Coins.PART
        for sc in swap_clients:
            sc.settings["strict_swap_type"] = True
        try:
            with self.assertRaises(ValueError):
                swap_clients[0].validateSwapType(
                    coin_from, coin_to, SwapTypes.SELLER_FIRST
                )
            assert swap_clients[0].is_reverse_ads_bid(coin_from, coin_to)

            ci_divi_1 = swap_clients[1].ci(coin_from)
            divi_before = ci_divi_1.getSpendableBalance()

            offer_id = swap_clients[0].postOffer(
                coin_from,
                coin_to,
                1000 * COIN,
                COIN // 1000,
                1000 * COIN,
                SwapTypes.XMR_SWAP,
            )

            wait_for_offer(delay_event, swap_clients[1], offer_id)
            offer = swap_clients[1].getOffer(offer_id)
            bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

            wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
            swap_clients[0].acceptBid(bid_id)

            wait_for_bid(
                delay_event,
                swap_clients[0],
                bid_id,
                BidStates.SWAP_COMPLETED,
                wait_for=180,
            )
            wait_for_bid(
                delay_event,
                swap_clients[1],
                bid_id,
                BidStates.SWAP_COMPLETED,
                sent=True,
                wait_for=180,
            )

            # Node 1 does not mine DIVI, so its whole gain is the swap: 1000
            # DIVI less at most the 0.1 DIVI margin the mainnet deposit allows.
            for _ in range(30):
                divi_gain = ci_divi_1.getSpendableBalance() - divi_before
                if divi_gain > 0:
                    break
                delay_event.wait(1)
            logging.info("DIVI received by node 1: %d sat", divi_gain)
            assert 1000 * COIN - COIN // 10 <= divi_gain <= 1000 * COIN

            # On a reverse bid chain B is the offer's coin_from, so the
            # extra bid view must show a DIVI P2PKH lock address, not PART.
            for port in (1800, 1801):
                js = read_json_api(port, f"bids/{bid_id.hex()}", {"show_extra": True})
                assert "error" not in js, js
                assert js["xmr_b_shared_address"][0] in ("y", "x"), js
        finally:
            for sc in swap_clients:
                sc.settings.pop("strict_swap_type", None)

    def test_20_btc_divi(self):
        logging.info("---------- Test BTC to DIVI")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.BTC,
            Coins.DIVI,
            0.1 * COIN,
            10 * COIN,
            0.1 * COIN,
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
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=180,
        )

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert js_0["num_swapping"] == 0 and js_0["num_watched_outputs"] == 0
        assert js_1["num_swapping"] == 0 and js_1["num_watched_outputs"] == 0

    def test_21_web_ui_pages(self):
        # Every HTML page that shows DIVI must render without the error
        # template.  Errors are rendered with status 200, so check the body.
        logging.info("---------- Test DIVI web UI pages")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.DIVI,
            Coins.PART,
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

        # page_wallets starts a refresh without waiting, so fill the cache
        # first or DIVI may be missing from the first render.
        swap_clients[0].updateWalletsInfo(force_update=True, wait_for_complete=True)

        pages = (
            "wallets",
            "wallet/DIVI",
            "wallet/divi",
            "newoffer",
            "offers",
            "sentoffers",
            f"offer/{offer_id.hex()}",
            "bids",
            f"bid/{bid_id.hex()}",
            "settings",
            "rpc",
            "explorers",
        )
        # Pages whose html is filled in by the server.  The others load their
        # lists by javascript, so only the error check applies to them.
        names_divi = (
            "wallets",
            "wallet/DIVI",
            "wallet/divi",
            "newoffer",
            f"offer/{offer_id.hex()}",
            f"bid/{bid_id.hex()}",
            "settings",
        )
        for page in pages:
            with urlopen(f"http://127.0.0.1:1800/{page}") as resp:
                assert resp.status == 200, f"{page}: HTTP {resp.status}"
                body = resp.read().decode("utf-8")
            assert ">ERROR:</h2>" not in body, f"{page} rendered the error page"
            if page in names_divi:
                assert "Divi" in body or "DIVI" in body, f"{page} does not show DIVI"
            logging.info("Web UI page /%s rendered", page)

        swap_clients[0].abandonBid(bid_id)
        swap_clients[0].revokeOffer(offer_id)

    def test_22_fee_and_size(self):
        # divid has no estimatesmartfee or fundrawtransaction: the fee rate
        # falls back through get_fee_rate and DIVIInterface sizes the
        # transaction by hand.  Check both against a real signed transaction
        # that divid accepts.
        logging.info("---------- Test DIVI fee rate and tx size")
        swap_clients = self.swap_clients
        ci0 = swap_clients[0].ci(Coins.DIVI)
        ci1 = swap_clients[1].ci(Coins.DIVI)

        fee_rate, fee_src = ci0.get_fee_rate(ci0._conf_target)
        fee_rate_sats: int = ci0.make_int(fee_rate)
        relay_fee_sats: int = ci0.make_int(ci0.rpc("getnetworkinfo")["relayfee"])
        logging.info(
            "DIVI fee rate %s from %s, relay fee %d sat/kB",
            fee_rate,
            fee_src,
            relay_fee_sats,
        )
        assert fee_rate_sats >= relay_fee_sats

        addr_to = ci1.getNewAddress(False)
        tx_hex = ci0.createRawSignedTransaction(addr_to, 1 * COIN)
        tx = ci0.rpc("decoderawtransaction", [tx_hex])
        num_in: int = len(tx["vin"])
        num_out: int = len(tx["vout"])
        size: int = len(tx_hex) // 2

        estimated_size: int = (
            ci0.TX_OVERHEAD_BYTES
            + ci0.TX_P2PKH_INPUT_BYTES * num_in
            + ci0.TX_OUTPUT_BYTES * num_out
        )
        logging.info(
            "DIVI tx %d in / %d out: estimated %d bytes, actual %d bytes",
            num_in,
            num_out,
            estimated_size,
            size,
        )
        # The estimate may only overshoot, and by no more than the DER
        # signature length variation of a byte or two per input.
        assert estimated_size >= size
        assert estimated_size - size <= 3 * num_in

        value_in: int = 0
        for txin in tx["vin"]:
            prevout = ci0.rpc("gettxout", [txin["txid"], txin["vout"]])
            assert prevout is not None
            value_in += ci0.make_int(prevout["value"])
        value_out: int = sum(ci0.make_int(o["value"]) for o in tx["vout"])
        fee_paid: int = value_in - value_out
        logging.info("DIVI tx fee paid %d sat for %d bytes", fee_paid, size)
        assert fee_paid >= ci0._estimateTxFee(num_in, num_out, fee_rate_sats)
        assert fee_paid * 1000 >= relay_fee_sats * size

        txid = ci0.rpc("sendrawtransaction", [tx_hex])
        # Mempool or already mined: either way divid accepted it.
        assert ci0.rpc("getrawtransaction", [txid, 1])["txid"] == txid

    def test_23_refund_divi_part(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info("---------- Test refund, DIVI to PART")
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.DIVI,
            Coins.PART,
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

    def test_24_xmrswap_part_divi_recover_b_lock_tx(self):
        coin_from = Coins.PART
        coin_to = Coins.DIVI
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

    def run_part_divi_adaptor_strict(self, offer_id, amt_from, amt_to):
        # Node 1 bids on node 0's PART->DIVI offer and both sides run the
        # forward adaptor-sig swap to completion: PART is the script-locked
        # coin A, DIVI the scriptless coin B.
        swap_clients = self.swap_clients
        wait_for_offer(delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        assert offer.swap_type == SwapTypes.XMR_SWAP
        assert offer.amount_from == amt_from
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(
            delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180
        )
        wait_for_bid(
            delay_event,
            swap_clients[1],
            bid_id,
            BidStates.SWAP_COMPLETED,
            sent=True,
            wait_for=180,
        )
        bid = swap_clients[0].getBid(bid_id)
        assert bid.amount == amt_from
        assert bid.amount_to == amt_to

        # The extra bid view shows the chain B lock address; for DIVI that
        # is P2PKH, not bech32 (this used to fail with KeyError('hrp')).
        for port in (1800, 1801):
            js = read_json_api(port, f"bids/{bid_id.hex()}", {"show_extra": True})
            assert "error" not in js, js
            assert js["xmr_b_shared_address"][0] in ("y", "x"), js
        return bid_id

    def test_25_xmrswap_part_divi_strict(self):
        # The reverse of the mainnet swap: PART offered for DIVI with the
        # mainnet default strict_swap_type, which leaves only the forward
        # adaptor-sig swap.  The offer goes to the public network address.
        logging.info("---------- Test xmr swap protocol, PART to DIVI, strict")

        swap_clients = self.swap_clients
        coin_from = Coins.PART
        coin_to = Coins.DIVI
        for sc in swap_clients:
            sc.settings["strict_swap_type"] = True
        try:
            with self.assertRaises(ValueError):
                swap_clients[0].validateSwapType(
                    coin_from, coin_to, SwapTypes.SELLER_FIRST
                )
            swap_clients[0].validateSwapType(coin_from, coin_to, SwapTypes.XMR_SWAP)
            assert not swap_clients[0].is_reverse_ads_bid(coin_from, coin_to)

            amt_from = 99 * COIN // 100
            offer_id = swap_clients[0].postOffer(
                coin_from,
                coin_to,
                amt_from,
                1000 * COIN,
                amt_from,
                SwapTypes.XMR_SWAP,
            )
            # Public: the third node sees it too.
            wait_for_offer(delay_event, swap_clients[2], offer_id)
            self.run_part_divi_adaptor_strict(offer_id, amt_from, 990 * COIN)
        finally:
            for sc in swap_clients:
                sc.settings.pop("strict_swap_type", None)

    def test_26_xmrswap_part_divi_private_offer(self):
        # The planned second mainnet run: 0.99 PART for 990 DIVI, strict, sent
        # through the JSON API to a receive address only node 1 holds, so no
        # other node can read the offer.
        logging.info("---------- Test PART to DIVI adaptor swap, private offer")

        swap_clients = self.swap_clients
        for sc in swap_clients:
            sc.settings["strict_swap_type"] = True
        try:
            js = read_json_api(1801, "smsgaddresses/new", {"addressnote": "from A"})
            recv_addr = js["new_address"]
            js = read_json_api(
                1800,
                "smsgaddresses/add",
                {"addresspubkey": js["pubkey"], "addressnote": "B private"},
            )
            assert js["added_address"] == recv_addr

            rv = read_json_api(
                1800,
                "offers/new",
                {
                    "addr_to": recv_addr,
                    "addr_from": -1,
                    "coin_from": int(Coins.PART),
                    "coin_to": int(Coins.DIVI),
                    "amt_from": "0.99",
                    "amt_to": "990",
                    "swap_type": "adaptor_sig",
                    "lockhrs": 24,
                },
            )
            offer_id = bytes.fromhex(rv["offer_id"])

            # The offer can't be read by anyone but node 1, so node 1 lists it
            # as private and node 2 never stores it.
            wait_for_offer(delay_event, swap_clients[1], offer_id)
            rv = read_json_api(1801, f"offers/{offer_id.hex()}")
            assert rv[0]["addr_to"] == recv_addr
            assert rv[0]["is_public"] is False
            delay_event.wait(20)
            assert swap_clients[2].getOffer(offer_id) is None

            self.run_part_divi_adaptor_strict(offer_id, 99 * COIN // 100, 990 * COIN)
        finally:
            for sc in swap_clients:
                sc.settings.pop("strict_swap_type", None)

    def stop_and_restart_client(self, sc, seconds):
        # Stand-in for stopping the instance's BasicSwap mid-swap: no update
        # ticks for a while (the coin daemons keep running), then the
        # in-memory swap state is dropped and rebuilt from the database as a
        # fresh start would.
        sc.update = lambda: None
        try:
            delay_event.wait(seconds)
            for coin in (Coins.PART, Coins.DIVI):
                cc = sc.coin_clients[coin]
                cc["watched_transactions"].clear()
                cc["watched_outputs"].clear()
                cc["watched_scripts"].clear()
            sc.loadFromDB()
        finally:
            del sc.update

    def wait_for_bid_state_in(self, sc, bid_id, states, wait_for=180):
        for _ in range(wait_for * 5):
            bid = sc.getBid(bid_id)
            if bid is not None and bid.state in states:
                return bid.state
            delay_event.wait(0.2)
        raise ValueError(f"Bid {bid_id.hex()} never reached {states}")

    def test_27_xmrswap_part_divi_stop_mid_swap(self):
        # Stop switch: each side is stopped once mid-swap, after a coin is
        # locked, and the swap must still finish once it is started again.
        logging.info("---------- Test PART to DIVI adaptor swap, stop mid-swap")

        swap_clients = self.swap_clients
        for sc in swap_clients:
            sc.settings["strict_swap_type"] = True
        try:
            amt_from = COIN // 2
            offer_id = swap_clients[0].postOffer(
                Coins.PART,
                Coins.DIVI,
                amt_from,
                1000 * COIN,
                amt_from,
                SwapTypes.XMR_SWAP,
            )
            wait_for_offer(delay_event, swap_clients[1], offer_id)
            bid_id = swap_clients[1].postBid(offer_id, amt_from)
            wait_for_bid(delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
            swap_clients[0].acceptBid(bid_id)

            # Bidder (DIVI side) stopped once the PART lock is seen.
            state = self.wait_for_bid_state_in(
                swap_clients[0],
                bid_id,
                (
                    BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED,
                    BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED,
                ),
            )
            logging.info("Stopping node 1 at offerer state %s", BidStates(state).name)
            self.stop_and_restart_client(swap_clients[1], 30)

            # Offerer (PART side) stopped once the DIVI lock is seen.
            state = self.wait_for_bid_state_in(
                swap_clients[1],
                bid_id,
                (
                    BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED,
                    BidStates.XMR_SWAP_LOCK_RELEASED,
                    BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED,
                    BidStates.SWAP_COMPLETED,
                ),
            )
            logging.info("Stopping node 0 at bidder state %s", BidStates(state).name)
            self.stop_and_restart_client(swap_clients[0], 30)

            wait_for_bid(
                delay_event,
                swap_clients[0],
                bid_id,
                BidStates.SWAP_COMPLETED,
                wait_for=240,
            )
            wait_for_bid(
                delay_event,
                swap_clients[1],
                bid_id,
                BidStates.SWAP_COMPLETED,
                sent=True,
                wait_for=240,
            )
        finally:
            for sc in swap_clients:
                sc.settings.pop("strict_swap_type", None)


if __name__ == "__main__":
    unittest.main()
