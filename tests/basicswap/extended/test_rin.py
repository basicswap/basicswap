#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
basicswap]$ python tests/basicswap/extended/test_rin.py

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
)
from basicswap.bin.run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.contrib.test_framework.messages import CTransaction, from_hex
from basicswap.contrib.test_framework.script import CScript, OP_EQUAL, OP_HASH160
from basicswap.util.address import decodeAddress
from basicswap.util.extkey import ExtKeyPair
from tests.basicswap.util.common import (
    stopDaemons,
    wait_for_no_offer,
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


RINCOIN_BINDIR = os.path.expanduser(
    os.getenv("RINCOIN_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "rincoin"))
)
RINCOIND = os.getenv("RINCOIND", "rincoind" + cfg.bin_suffix)

RIN_BASE_PORT = 46892
RIN_BASE_RPC_PORT = 46992

# Regtest activates CSV at 432, RIN3 (RIP-0009) at 840 and BIP65 at 1351.
RIN_REGTEST_BLOCKS = 1352
# Below the RIN3 height, with block rewards to spend
RIN_PRE_FORK_BLOCKS = 500


def prepareRINDataDir(datadir, nodeId, conf_file="rincoin.conf"):
    node_dir = os.path.join(datadir, "rin_" + str(nodeId))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    filePath = os.path.join(node_dir, conf_file)

    with open(filePath, "w+") as fp:
        fp.write("regtest=1\n")
        fp.write("[regtest]\n")

        fp.write("port=" + str(RIN_BASE_PORT + nodeId) + "\n")
        fp.write("rpcport=" + str(RIN_BASE_RPC_PORT + nodeId) + "\n")
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

        # Wallet sends pay the relay fee.  At a higher rate the node that sent
        # them gets a fee estimate above what the other nodes accept.
        fp.write("fallbackfee=0.00001\n")
        fp.write("mintxfee=0.00001\n")
        fp.write("acceptnonstdtxn=0\n")
        fp.write("txindex=1\n")
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")
        # MWEB is not active on Rincoin mainnet, keep it off on regtest.
        fp.write("vbparams=mweb:9999999999:9999999999\n")

        for i in range(0, NUM_NODES):
            if nodeId == i:
                continue
            fp.write("addnode=127.0.0.1:{}\n".format(RIN_BASE_PORT + i))


class TestRIN(BasicSwapTest):
    __test__ = True
    test_coin = Coins.RIN
    test_coin_from = Coins.RIN
    rin_daemons = []
    start_ltc_nodes = False
    start_xmr_nodes = True
    base_rpc_port = RIN_BASE_RPC_PORT
    rin_addr = None
    max_fee: int = 10000

    def mineBlock(self, num_blocks: int = 1) -> None:
        if self.rin_addr is None:
            logging.info("RIN mining paused")
            return
        self.callnoderpc("generatetoaddress", [num_blocks, self.rin_addr])

    def getMiningAddr(self):
        return self.rin_addr

    def pauseMining(self):
        logging.info(f"Pausing RIN mining to {self.rin_addr}")
        self.old_rin_addr: str = self.__class__.rin_addr
        self.__class__.rin_addr = None

    def continueMining(self):
        logging.info(f"Resuming RIN mining to {self.old_rin_addr}")
        self.__class__.rin_addr = self.old_rin_addr

    def check_softfork_active(self, feature_name):
        # Rincoin Core is based on Litecoin Core 0.21, without getdeploymentinfo
        deploymentinfo = self.callnoderpc("getblockchaininfo")
        assert deploymentinfo["softforks"][feature_name]["active"] is True

    def _assert_mercy_waits_for_swipe(
        self, bid_id, id_leader: int, id_follower: int, chain_a_coin
    ) -> None:
        # The follower sends the mercy tx once the swipe tx has blocks_confirmed
        # confirmations, and the inherited check has to pause mining before
        # then.  With a block every second the swipe tx was 2 to 4 blocks deep
        # at the pause, so the follower uses a larger depth from here to the
        # end of the test.
        ci = self.swap_clients[id_follower].ci(chain_a_coin)
        self.addCleanup(setattr, ci, "blocks_confirmed", ci.blocks_confirmed)
        ci.blocks_confirmed = 12
        super()._assert_mercy_waits_for_swipe(
            bid_id, id_leader, id_follower, chain_a_coin
        )

    def spend_new_address(self, address_type: str) -> tuple:
        # Fund a new address of the type and sign a transaction spending it.
        # Rincoin Core lists the addresses of an output in "addresses".
        ci = self.swap_clients[0].ci(self.test_coin_from)
        addr = ci.rpc_wallet("getnewaddress", ["segwit test", address_type])
        txid = ci.rpc_wallet("sendtoaddress", [addr, 1.0])
        assert len(txid) == 64
        self.mineBlock()
        ro = ci.rpc("scantxoutset", ["start", ["addr({})".format(addr)]])
        assert len(ro["unspents"]) == 1
        assert ro["unspents"][0]["txid"] == txid

        tx_hex = ci.rpc_wallet("gettransaction", [txid])["hex"]
        tx = ci.rpc("decoderawtransaction", [tx_hex])
        prevout_n = -1
        for txo in tx["vout"]:
            if addr in txo["scriptPubKey"].get("addresses", []):
                prevout_n = txo["n"]
                break
        assert prevout_n > -1

        tx_funded = ci.rpc(
            "createrawtransaction",
            [[{"txid": txid, "vout": prevout_n}], {addr: 0.99}],
        )
        tx_signed = ci.rpc_wallet("signrawtransactionwithwallet", [tx_funded])["hex"]
        return addr, tx_funded, tx_signed

    def test_001_nested_segwit(self):
        logging.info(f"---------- Test {self.test_coin_from.name} p2sh nested segwit")
        ci = self.swap_clients[0].ci(self.test_coin_from)
        addr, tx_funded, tx_signed = self.spend_new_address("p2sh-segwit")
        addr_info = ci.rpc_wallet("getaddressinfo", [addr])
        assert addr_info["script"] == "witness_v0_keyhash"
        # Regtest p2sh-segwit addresses use the script_address2 prefix
        assert decodeAddress(addr)[0] == ci.chainparams_network()["script_address2"]
        assert ci.getDestForAddress(addr) == CScript(
            [OP_HASH160, decodeAddress(addr)[1:], OP_EQUAL]
        )

        tx_funded_decoded = ci.rpc("decoderawtransaction", [tx_funded])
        tx_signed_decoded = ci.rpc("decoderawtransaction", [tx_signed])
        assert tx_funded_decoded["txid"] != tx_signed_decoded["txid"]
        # Add scriptsig for txids to match
        decoded_tx = from_hex(CTransaction(), tx_funded)
        decoded_tx.vin[0].scriptSig = bytes.fromhex("16" + addr_info["hex"])
        assert decoded_tx.rehash() == tx_signed_decoded["txid"]

    def test_002_native_segwit(self):
        logging.info(f"---------- Test {self.test_coin_from.name} native segwit")
        ci = self.swap_clients[0].ci(self.test_coin_from)
        addr, tx_funded, tx_signed = self.spend_new_address("bech32")
        assert ci.rpc_wallet("getaddressinfo", [addr])["iswitness"] is True

        tx_funded_decoded = ci.rpc("decoderawtransaction", [tx_funded])
        tx_signed_decoded = ci.rpc("decoderawtransaction", [tx_signed])
        vin = tx_signed_decoded["vin"][0]
        prev_tx_hex = ci.rpc_wallet("gettransaction", [vin["txid"]])["hex"]
        prev_txo = ci.rpc("decoderawtransaction", [prev_tx_hex])["vout"][vin["vout"]]
        assert ci.isScriptP2WPKH(bytes.fromhex(prev_txo["scriptPubKey"]["hex"])) is True
        txin_witness = vin["txinwitness"]
        assert len(txin_witness) == 2
        txin_witness_0 = bytes.fromhex(txin_witness[0])
        assert len(txin_witness_0) > 68 and len(txin_witness_0) <= 72
        assert len(bytes.fromhex(txin_witness[1])) == 33
        assert tx_funded_decoded["txid"] == tx_signed_decoded["txid"]

    def test_008_gettxout(self):
        logging.info(f"---------- Test {self.test_coin_from.name} gettxout")
        ci = self.swap_clients[0].ci(self.test_coin_from)

        addr_1 = ci.getNewAddress(True, "gettxout test 1")
        txid = ci.rpc_wallet("sendtoaddress", [addr_1, 1.0])
        assert len(txid) == 64
        self.mineBlock()

        unspents = ci.rpc_wallet("listunspent", [0, 999999999, [addr_1]])
        assert len(unspents) == 1
        utxo = unspents[0]
        txout = ci.rpc("gettxout", [utxo["txid"], utxo["vout"]])
        assert addr_1 in txout["scriptPubKey"]["addresses"]

        addr_2 = ci.getNewAddress(True, "gettxout test 2")
        tx_hex = ci.rpc(
            "createrawtransaction",
            [[{"txid": utxo["txid"], "vout": utxo["vout"]}], {addr_2: 0.99}],
        )
        # Past height 840 the node refuses a transaction with version 2
        tx_v2 = ci.rpc_wallet("signrawtransactionwithwallet", [tx_hex])["hex"]
        try:
            ci.rpc("sendrawtransaction", [tx_v2])
        except Exception as e:
            assert "bad-tx-rinhash-version" in str(e)
            logging.info(f"Version 2 transaction refused: {e}")
        else:
            assert False, "Should fail"

        tx = ci.loadTx(bytes.fromhex(tx_hex))
        tx.nVersion = ci.txVersion()
        tx_signed = ci.rpc_wallet(
            "signrawtransactionwithwallet", [tx.serialize().hex()]
        )["hex"]
        ci.rpc("sendrawtransaction", [tx_signed])

        # utxo should be unavailable when spent in the mempool
        assert ci.rpc("gettxout", [utxo["txid"], utxo["vout"]]) is None

    def test_013_descriptor_wallet(self):
        # createwallet refuses a descriptor wallet
        self.skipTest("Rincoin Core does not support descriptor wallets")

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Rincoin Test")
        try:
            super(TestRIN, cls).tearDownClass()
        finally:
            stopDaemons(cls.rin_daemons)
            cls.rin_daemons.clear()

    @classmethod
    def coins_loop(cls):
        super(TestRIN, cls).coins_loop()
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        try:
            if cls.rin_addr is not None:
                ci0.rpc_wallet("generatetoaddress", [1, cls.rin_addr])
        except Exception as e:
            logging.warning(f"coins_loop generate {e}")

    @classmethod
    def prepareExtraDataDir(cls, i: int) -> None:
        if not cls.restore_instance:
            prepareRINDataDir(cfg.TEST_DATADIRS, i)

        cls.rin_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "rin_" + str(i)),
                RINCOIN_BINDIR,
                RINCOIND,
            )
        )
        logging.info("Started {} {}".format(RINCOIND, cls.rin_daemons[-1].handle.pid))

        rin_rpc = make_rpc_func(i, base_rpc_port=RIN_BASE_RPC_PORT)
        waitForRPC(
            rin_rpc,
            test_delay_event,
            rpc_command="getnetworkinfo",
            max_tries=12,
        )
        waitForRPC(rin_rpc, test_delay_event, rpc_command="getblockchaininfo")
        if len(rin_rpc("listwallets")) < 1:
            rin_rpc("createwallet", ["bsx_wallet", False, True, "", False, False])

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemon(Coins.RIN, cls.rin_daemons[i])

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        # Turns the price fetching thread off, as for the BTC tests
        super(TestRIN, cls).addCoinSettings(settings, datadir, node_id)
        settings["chainclients"]["rincoin"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": RIN_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "rin_" + str(node_id)),
            "bindir": RINCOIN_BINDIR,
            "use_csv": True,
            "use_segwit": True,
            "blocks_confirmed": 1,
            "wallet_name": "bsx_wallet",
        }

    @classmethod
    def prepareExtraCoins(cls):
        # Keeps sent messages in the smsg outbox, the full swap tests count them
        super(TestRIN, cls).prepareExtraCoins()
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        if not cls.restore_instance:
            for sc in cls.swap_clients:
                ci = sc.ci(cls.test_coin)
                ci.initialiseWallet(ci.getNewRandomKey())
            cls.rin_addr = ci0.rpc_wallet("getnewaddress", ["mining_addr", "bech32"])
        else:
            addrs = ci0.rpc_wallet(
                "getaddressesbylabel",
                [
                    "mining_addr",
                ],
            )
            cls.rin_addr = next(iter(addrs))

        if ci0.rpc("getblockcount") < RIN_REGTEST_BLOCKS:
            logging.info(
                f"Mining {RIN_REGTEST_BLOCKS} Rincoin blocks to {cls.rin_addr}"
            )
            ci0.rpc(
                "generatetoaddress", [RIN_PRE_FORK_BLOCKS, cls.rin_addr], timeout=60
            )

            # Fund the second node, as for BTC, while the chain is below the
            # RIN3 height.  The node wallet still builds version 2 there, so
            # the version of these transactions is the one set by
            # createRawFundedTransaction.
            ci1 = cls.swap_clients[1].ci(cls.test_coin)
            rin_addr1 = ci1.rpc_wallet("getnewaddress", ["initial addr"])
            txids = []
            for i in range(5):
                tx_hex = ci0.createRawSignedTransaction(rin_addr1, ci0.make_int(100))
                assert ci0.loadTx(bytes.fromhex(tx_hex)).nVersion == ci0.txVersion()
                txids.append(ci0.rpc("sendrawtransaction", [tx_hex]))
            ci0.rpc("generatetoaddress", [1, cls.rin_addr])
            for txid in txids:
                assert ci0.rpc_wallet("gettransaction", [txid])["confirmations"] == 1
            logging.info(
                "Mined {} RIN3 transactions at height {}".format(
                    len(txids), ci0.rpc("getblockcount")
                )
            )
            ci0.rpc(
                "generatetoaddress",
                [RIN_REGTEST_BLOCKS - RIN_PRE_FORK_BLOCKS - 1, cls.rin_addr],
                timeout=60,
            )

        # Later block rewards go to a random address, as for BTC, so the balance
        # of node 0 only changes through the tests.
        cls.rin_addr = ci0.pubkey_to_segwit_address(cls.getRandomPubkey())
        if ci0.rpc("getblockcount") < RIN_REGTEST_BLOCKS + 100:
            # Mature the rewards mined to the wallet
            ci0.rpc("generatetoaddress", [100, cls.rin_addr], timeout=60)
        logging.info("RIN blocks: {}".format(ci0.rpc("getblockcount")))

    def test_007_hdwallet(self):
        logging.info("---------- Test {} hdwallet".format(self.test_coin_from.name))

        ci = self.swap_clients[0].ci(self.test_coin_from)
        test_seed = "8e54a313e6df8918df6d758fafdbf127a115175fdd2238d0e908dd8093c9ac3b"
        test_wif = ci.encodeKey(bytes.fromhex(test_seed))
        new_wallet_name = random.randbytes(10).hex()
        self.callnoderpc(
            "createwallet",
            [new_wallet_name, False, False, "", False, False],
        )
        self.callnoderpc("sethdseed", [True, test_wif], wallet=new_wallet_name)
        addr = self.callnoderpc(
            "getnewaddress", ["add test", "bech32"], wallet=new_wallet_name
        )
        self.callnoderpc("unloadwallet", [new_wallet_name])

        # The first key of a legacy HD wallet is m/0h/0h/0h, derived here
        # without the node.
        ek = ExtKeyPair()
        ek.set_seed(bytes.fromhex(test_seed))
        pubkey = ek.derive_path("s/0h/0h/0h").get_pubkey()
        assert addr == ci.pubkey_to_segwit_address(pubkey)
        assert addr.startswith("rrin1")

    def hold_ptx_redeem(self, coin_to) -> None:
        # run_test_success_path compares the full state history of the bidder,
        # which records "PTX Confirmed" only if it sees the participate tx
        # confirmed before the redeem tx of the offerer spends it.  The
        # offerer waits for more confirmations until the end of the test.
        coin_client = self.swap_clients[0].coin_clients[coin_to]
        self.addCleanup(
            coin_client.__setitem__, "blocks_confirmed", coin_client["blocks_confirmed"]
        )
        coin_client["blocks_confirmed"] += 20

    def revoke_sent_offers(self, coin_from, coin_to) -> None:
        # run_test_bad_ptx leaves an offer that accepts bids automatically for
        # an hour, test_20_multi_offer_batched_btc plans over every such offer
        # of its pair.
        swap_clients = self.swap_clients
        filters = {
            "coin_from": int(coin_from),
            "coin_to": int(coin_to),
            "active": "active",
        }
        for offer in swap_clients[0].listOffers(sent=True, filters=filters):
            swap_clients[0].revokeOffer(offer.offer_id)
            wait_for_no_offer(test_delay_event, swap_clients[1], offer.offer_id)

    def test_02_sh_part_coin(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        self.hold_ptx_redeem(self.test_coin)
        run_test_success_path(self, Coins.PART, self.test_coin)

    def test_03_sh_coin_part(self):
        self.hold_ptx_redeem(Coins.PART)
        run_test_success_path(self, self.test_coin, Coins.PART)

    def test_04_sh_part_coin_bad_ptx(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_bad_ptx(self, Coins.PART, self.test_coin)
        self.revoke_sent_offers(Coins.PART, self.test_coin)

    def test_05_sh_coin_part_bad_ptx(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_bad_ptx(self, self.test_coin, Coins.PART)
        self.revoke_sent_offers(self.test_coin, Coins.PART)

    def test_06_sh_part_coin_itx_refund(self):
        run_test_itx_refund(self, Coins.PART, self.test_coin)

    def test_07_sh_coin_part_itx_refund(self):
        self.prepare_balance(self.test_coin, 200.0, 1801, 1800)
        run_test_itx_refund(self, self.test_coin, Coins.PART)

    def test_11_fee_validation(self):
        # The inherited test asserts the relay fee of Bitcoin Core, 100 since v29.1.
        # Rincoin Core has 1000, the same checks are made with 10x rates.
        coin_from, coin_to = (self.test_coin_from, Coins.XMR)
        logging.info(
            f"---------- Test {coin_from.name} to {coin_to.name} fee validation"
        )

        swap_clients = self.swap_clients
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)
        from_clients = [
            (sc.ci(coin_from), sc.getChainClientSettings(coin_from))
            for sc in swap_clients[:2]
        ]
        old_values = [
            (
                settings.get("override_feerate"),
                ci._low_feerate,
                ci._high_feerate,
                ci._high_estimated_feerate_multiplier,
            )
            for ci, settings in from_clients
        ]

        networkinfo = ci_from.rpc("getnetworkinfo")
        assert ci_from.make_int(networkinfo["relayfee"]) == 1000
        # get_fee_rate() returns the relay fee without a fee estimate, and the
        # wallet sends of these tests pay no more than that
        for ci, _ in from_clients:
            fee_rate, fee_src = ci.get_fee_rate()
            assert ci.make_int(fee_rate) == 1000, fee_src

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        amt_swap_rev = ci_to.make_int(random.uniform(0.1, 2.0), r=1)

        def post_offer(reverse: bool = False) -> bytes:
            if reverse:
                return swap_clients[1].postOffer(
                    coin_to,
                    coin_from,
                    amt_swap_rev,
                    rate_swap,
                    amt_swap_rev,
                    SwapTypes.XMR_SWAP,
                )
            return swap_clients[0].postOffer(
                coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP
            )

        offer_id = post_offer()
        offer_id_rev = post_offer(reverse=True)

        def post_bid(reverse: bool = False) -> bytes:
            if reverse:
                return swap_clients[1].postXmrBid(offer_id_rev, amt_swap_rev)
            return swap_clients[0].postXmrBid(offer_id, amt_swap)

        def expect_error(func, expected: str) -> None:
            # The first client uses its offer, the second its reverse offer
            for reverse in (False, True):
                try:
                    func(reverse)
                except Exception as e:
                    assert expected in str(e), str(e)
                else:
                    assert False, "Should fail"

        try:
            # Set override_feerate to increase feerate from get_fee_rate()
            for ci, settings in from_clients:
                settings["override_feerate"] = ci.format_amount(1200)
            expect_error(post_bid, "Fee rate too low, 1000 < 1200, override_feerate")

            # Clear override_feerate, set low_feerate (validateFeeRate())
            for ci, settings in from_clients:
                settings["override_feerate"] = None
                ci._low_feerate = 1200
            expect_error(post_offer, "Fee rate too low, 1000 < 1200, set_value")

            # Clear low_feerate, disable high fee from estimate, set high_feerate
            for ci, _ in from_clients:
                ci._low_feerate = 0
                ci._high_estimated_feerate_multiplier = 0
                ci._high_feerate = 800
            expect_error(post_bid, "Fee rate too high, 1000 > 800, set_value")
            expect_error(post_offer, "Fee rate too high, 1000 > 800, set_value")
        finally:
            for (ci, settings), old in zip(from_clients, old_values):
                if old[0] is None:
                    settings.pop("override_feerate", None)
                else:
                    settings["override_feerate"] = old[0]
                ci._low_feerate = old[1]
                ci._high_feerate = old[2]
                ci._high_estimated_feerate_multiplier = old[3]


if __name__ == "__main__":
    unittest.main()
