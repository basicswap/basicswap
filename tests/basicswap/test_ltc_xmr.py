#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import logging
import unittest

from basicswap.basicswap import (
    Coins,
    SwapTypes,
    BidStates,
)
from basicswap.util import (
    COIN,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    wait_for_bid,
    wait_for_offer,
    wait_for_in_progress,
    TEST_HTTP_PORT,
    LTC_BASE_RPC_PORT,
)
from .test_btc_xmr import BasicSwapTest, test_delay_event
from .test_xmr import pause_event

logger = logging.getLogger()


class TestLTC(BasicSwapTest):
    __test__ = True
    test_coin_from = Coins.LTC
    start_ltc_nodes = True
    base_rpc_port = LTC_BASE_RPC_PORT

    def mineBlock(self, num_blocks=1):
        self.callnoderpc("generatetoaddress", [num_blocks, self.ltc_addr])

    def check_softfork_active(self, feature_name):
        deploymentinfo = self.callnoderpc("getblockchaininfo")
        assert deploymentinfo["softforks"][feature_name]["active"] is True

    def test_001_nested_segwit(self):
        logging.info(
            "---------- Test {} p2sh nested segwit".format(self.test_coin_from.name)
        )
        logging.info("Skipped")

    def test_002_native_segwit(self):
        logging.info(
            "---------- Test {} p2sh native segwit".format(self.test_coin_from.name)
        )

        ci = self.swap_clients[0].ci(self.test_coin_from)
        addr_segwit = ci.rpc_wallet("getnewaddress", ["segwit test", "bech32"])
        addr_info = ci.rpc_wallet(
            "getaddressinfo",
            [
                addr_segwit,
            ],
        )
        assert addr_info["iswitness"] is True

        txid = ci.rpc_wallet("sendtoaddress", [addr_segwit, 1.0])
        assert len(txid) == 64
        tx_wallet = ci.rpc_wallet(
            "gettransaction",
            [
                txid,
            ],
        )["hex"]
        tx = ci.rpc(
            "decoderawtransaction",
            [
                tx_wallet,
            ],
        )

        self.mineBlock()
        ro = ci.rpc("scantxoutset", ["start", ["addr({})".format(addr_segwit)]])
        assert len(ro["unspents"]) == 1
        assert ro["unspents"][0]["txid"] == txid

        prevout_n = -1
        for txo in tx["vout"]:
            if addr_segwit in txo["scriptPubKey"]["addresses"]:
                prevout_n = txo["n"]
                break
        assert prevout_n > -1

        tx_funded = ci.rpc(
            "createrawtransaction",
            [[{"txid": txid, "vout": prevout_n}], {addr_segwit: 0.99}],
        )
        tx_signed = ci.rpc_wallet(
            "signrawtransactionwithwallet",
            [
                tx_funded,
            ],
        )["hex"]
        tx_funded_decoded = ci.rpc(
            "decoderawtransaction",
            [
                tx_funded,
            ],
        )
        tx_signed_decoded = ci.rpc(
            "decoderawtransaction",
            [
                tx_signed,
            ],
        )
        assert tx_funded_decoded["txid"] == tx_signed_decoded["txid"]

    def test_007_hdwallet(self):
        logging.info("---------- Test {} hdwallet".format(self.test_coin_from.name))

        test_seed = "8e54a313e6df8918df6d758fafdbf127a115175fdd2238d0e908dd8093c9ac3b"
        test_wif = (
            self.swap_clients[0]
            .ci(self.test_coin_from)
            .encodeKey(bytes.fromhex(test_seed))
        )
        new_wallet_name = random.randbytes(10).hex()
        self.callnoderpc("createwallet", [new_wallet_name])
        self.callnoderpc("sethdseed", [True, test_wif], wallet=new_wallet_name)
        addr = self.callnoderpc("getnewaddress", wallet=new_wallet_name)
        self.callnoderpc("unloadwallet", [new_wallet_name])
        assert addr == "rltc1qps7hnjd866e9ynxadgseprkc2l56m00djr82la"

    def test_20_btc_coin(self):
        logging.info("---------- Test BTC to {}".format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(
            Coins.BTC,
            self.test_coin_from,
            100 * COIN,
            0.1 * COIN,
            100 * COIN,
            SwapTypes.SELLER_FIRST,
        )

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[1], bid_id, sent=True)
        wait_for_bid(
            test_delay_event,
            swap_clients[0],
            bid_id,
            BidStates.SWAP_COMPLETED,
            wait_for=60,
        )
        wait_for_bid(
            test_delay_event,
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

    def test_21_mweb(self):
        logging.info("---------- Test MWEB {}".format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        ci0 = swap_clients[0].ci(self.test_coin_from)
        ci1 = swap_clients[1].ci(self.test_coin_from)

        mweb_addr_0 = ci0.rpc_wallet("getnewaddress", ["mweb addr test 0", "mweb"])
        mweb_addr_1 = ci1.rpc_wallet("getnewaddress", ["mweb addr test 1", "mweb"])

        addr_info0 = ci0.rpc_wallet(
            "getaddressinfo",
            [
                mweb_addr_0,
            ],
        )
        assert addr_info0["ismweb"] is True

        addr_info1 = ci1.rpc_wallet(
            "getaddressinfo",
            [
                mweb_addr_1,
            ],
        )
        assert addr_info1["ismweb"] is True

        trusted_before = ci0.rpc_wallet("getbalances")["mine"]["trusted"]
        ci0.rpc_wallet("sendtoaddress", [mweb_addr_0, 10.0])
        assert (
            trusted_before - float(ci0.rpc_wallet("getbalances")["mine"]["trusted"])
            < 0.1
        )

        try:
            pause_event.clear()  # Stop mining
            ci0.rpc_wallet("sendtoaddress", [mweb_addr_1, 10.0])

            found_unconfirmed: bool = False
            for i in range(20):
                test_delay_event.wait(1)
                ltc_wallet = read_json_api(TEST_HTTP_PORT + 1, "wallets/ltc")
                if float(ltc_wallet["unconfirmed"]) == 10.0:
                    found_unconfirmed = True
                    break
        finally:
            pause_event.set()
        assert found_unconfirmed

        self.mineBlock()

        txns = ci0.rpc_wallet("listtransactions")

        utxos = ci0.rpc_wallet("listunspent")
        balances = ci0.rpc_wallet("getbalances")
        wi = ci0.rpc_wallet("getwalletinfo")

        txid = ci0.rpc_wallet("sendtoaddress", [mweb_addr_1, 10.0])

        self.mineBlock()

        txns = ci1.rpc_wallet("listtransactions")

        utxos = ci1.rpc_wallet("listunspent")
        balances = ci1.rpc_wallet("getbalances")
        wi = ci1.rpc_wallet("getwalletinfo")

        mweb_tx = None
        for utxo in utxos:
            if utxo.get("address", "") == mweb_addr_1:
                mweb_tx = utxo
        assert mweb_tx is not None

        tx = ci1.rpc_wallet(
            "gettransaction",
            [
                mweb_tx["txid"],
            ],
        )

        blockhash = tx["blockhash"]
        block3 = ci1.rpc("getblock", [blockhash, 3])
        block0 = ci1.rpc("getblock", [blockhash, 0])

        require_amount: int = ci1.make_int(1)
        unspent_addr = ci1.getUnspentsByAddr()
        assert len(unspent_addr) > 0
        for addr, _ in unspent_addr.items():
            if "mweb1" in addr:
                raise ValueError("getUnspentsByAddr should exclude mweb UTXOs.")

        # TODO

    def test_22_mweb_balance(self):
        logging.info("---------- Test MWEB balance {}".format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        ci_mweb = swap_clients[0].ci(Coins.LTC_MWEB)
        mweb_addr_0 = ci_mweb.getNewAddress()
        addr_info0 = ci_mweb.rpc_wallet(
            "getaddressinfo",
            [
                mweb_addr_0,
            ],
        )
        assert addr_info0["ismweb"] is True

        ltc_addr = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc/nextdepositaddr")
        ltc_mweb_addr = read_json_api(
            TEST_HTTP_PORT + 0, "wallets/ltc_mweb/nextdepositaddr"
        )
        ltc_mweb_addr2 = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc/newmwebaddress")

        assert (
            ci_mweb.rpc_wallet(
                "getaddressinfo",
                [
                    ltc_addr,
                ],
            )["ismweb"]
            is False
        )
        assert (
            ci_mweb.rpc_wallet(
                "getaddressinfo",
                [
                    ltc_mweb_addr,
                ],
            )["ismweb"]
            is True
        )
        assert (
            ci_mweb.rpc_wallet(
                "getaddressinfo",
                [
                    ltc_mweb_addr2,
                ],
            )["ismweb"]
            is True
        )

        post_json = {
            "value": 10,
            "address": ltc_mweb_addr,
            "subfee": False,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc/withdraw", post_json)
        assert len(json_rv["txid"]) == 64

        self.mineBlock()

        json_rv = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc", post_json)
        assert json_rv["mweb_balance"] == 10.0
        mweb_address = json_rv["mweb_address"]

        post_json = {
            "value": 11,
            "address": mweb_address,
            "subfee": False,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc/withdraw", post_json)
        assert len(json_rv["txid"]) == 64

        self.mineBlock()

        json_rv = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc_mweb", post_json)
        assert json_rv["mweb_balance"] == 21.0
        assert json_rv["mweb_address"] == mweb_address
        ltc_address = json_rv["deposit_address"]

        # Check that spending the mweb balance takes from the correct wallet
        post_json = {
            "value": 1,
            "address": ltc_address,
            "subfee": False,
            "type_from": "mweb",
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc/withdraw", post_json)
        assert len(json_rv["txid"]) == 64

        json_rv = read_json_api(TEST_HTTP_PORT + 0, "wallets/ltc", post_json)
        assert json_rv["mweb_balance"] <= 20.0


if __name__ == "__main__":
    unittest.main()
