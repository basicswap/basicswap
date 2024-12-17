#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import random
import logging
import unittest

import basicswap.config as cfg
from basicswap.basicswap import (
    Coins,
)
from basicswap.util.address import (
    toWIF,
)
from tests.basicswap.common import (
    stopDaemons,
    make_rpc_func,
    waitForRPC,
)

from basicswap.bin.run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from tests.basicswap.test_xmr import test_delay_event, callnoderpc
from basicswap.contrib.test_framework.messages import (
    CTransaction,
    CTxIn,
    COutPoint,
    ToHex,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_CHECKLOCKTIMEVERIFY,
)


from tests.basicswap.test_btc_xmr import TestFunctions

logger = logging.getLogger()

DOGE_BINDIR = os.path.expanduser(
    os.getenv("DOGE_BINDIR", os.path.join(cfg.DEFAULT_TEST_BINDIR, "dogecoin"))
)
DOGED = os.getenv("DOGED", "dogecoind" + cfg.bin_suffix)
DOGE_CLI = os.getenv("DOGE_CLI", "dogecoin-cli" + cfg.bin_suffix)
DOGE_TX = os.getenv("DOGE_TX", "dogecoin-tx" + cfg.bin_suffix)


DOGE_BASE_PORT = 22556
DOGE_BASE_RPC_PORT = 18442


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

        fp.write("acceptnonstdtxn=0\n")

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            fp.write("addnode=127.0.0.1:{}\n".format(base_p2p_port + i))

    return node_dir


class Test(TestFunctions):
    __test__ = True
    test_coin = Coins.DOGE
    test_coin_from = Coins.BTC
    test_coin_to = Coins.DOGE
    doge_daemons = []
    doge_addr = None
    start_ltc_nodes = False
    start_xmr_nodes = False

    test_atomic = False
    test_xmr = True

    pause_chain = False

    doge_seeds = [
        "516b471da2a67bcfd42a1da7f7ae8f9a1b02c34f6a2d6a943ceec5dca68e7fa1",
        "a8c0911fba070d5cc2784703afeb0f7c3b9b524b8a53466c04e01933d9fede78",
        "7b3b533ac3a27114ae17c8cca0d2cd9f736e7519ae52b8ec8f1f452e8223d082",
    ]

    @classmethod
    def prepareExtraDataDir(cls, i):
        if not cls.restore_instance:
            prepareDataDir(
                cfg.TEST_DATADIRS,
                i,
                "dogecoin.conf",
                "doge_",
                base_p2p_port=DOGE_BASE_PORT,
                base_rpc_port=DOGE_BASE_RPC_PORT,
            )
        cls.doge_daemons.append(
            startDaemon(
                os.path.join(cfg.TEST_DATADIRS, "doge_" + str(i)),
                DOGE_BINDIR,
                DOGED,
            )
        )
        logging.info("Started %s %d", DOGED, cls.doge_daemons[-1].handle.pid)

        dogeRpc = make_rpc_func(i, base_rpc_port=DOGE_BASE_RPC_PORT)
        waitForRPC(dogeRpc, test_delay_event, rpc_command="getblockchaininfo")
        if len(dogeRpc("listwallets")) < 1:
            dogeRpc("createwallet", ["wallet.dat", False, True, "", False, False])
            wif_prefix: int = 239
            wif = toWIF(wif_prefix, bytes.fromhex(cls.doge_seeds[i]), False)
            dogeRpc("sethdseed", [True, wif])

        waitForRPC(
            dogeRpc,
            test_delay_event,
            max_tries=12,
        )

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.DOGE, cls.doge_daemons[i].handle.pid)

    @classmethod
    def sync_blocks(cls, wait_for: int = 20, num_nodes: int = 3) -> None:
        logging.info("Syncing blocks")
        for i in range(wait_for):
            if test_delay_event.is_set():
                raise ValueError("Test stopped.")
            block_hash0 = callnoderpc(
                0, "getbestblockhash", base_rpc_port=DOGE_BASE_RPC_PORT
            )
            matches: int = 0
            for i in range(1, num_nodes):
                block_hash = callnoderpc(
                    i, "getbestblockhash", base_rpc_port=DOGE_BASE_RPC_PORT
                )
                if block_hash == block_hash0:
                    matches += 1
            if matches == num_nodes - 1:
                return
            test_delay_event.wait(1)
        raise ValueError("sync_blocks timed out.")

    @classmethod
    def prepareExtraCoins(cls):
        if cls.restore_instance:
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.doge_addr = (
                cls.swap_clients[0]
                .ci(Coins.DOGE)
                .pubkey_to_address(void_block_rewards_pubkey)
            )
        else:
            num_blocks = 400
            cls.doge_addr = callnoderpc(
                0, "getnewaddress", ["mining_addr"], base_rpc_port=DOGE_BASE_RPC_PORT
            )

            logging.info("Mining %d DOGE blocks to %s", num_blocks, cls.doge_addr)
            callnoderpc(
                0,
                "generatetoaddress",
                [num_blocks, cls.doge_addr],
                base_rpc_port=DOGE_BASE_RPC_PORT,
            )

            doge_addr1 = callnoderpc(
                1, "getnewaddress", ["initial addr"], base_rpc_port=DOGE_BASE_RPC_PORT
            )
            for i in range(5):
                callnoderpc(
                    0,
                    "sendtoaddress",
                    [doge_addr1, 1000],
                    base_rpc_port=DOGE_BASE_RPC_PORT,
                )

            # Set future block rewards to nowhere (a random address), so wallet amounts stay constant
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.doge_addr = (
                cls.swap_clients[0]
                .ci(Coins.DOGE)
                .pubkey_to_address(void_block_rewards_pubkey)
            )
            num_blocks = 100
            logging.info("Mining %d DOGE blocks to %s", num_blocks, cls.doge_addr)
            callnoderpc(
                0,
                "generatetoaddress",
                [num_blocks, cls.doge_addr],
                base_rpc_port=DOGE_BASE_RPC_PORT,
            )

        cls.sync_blocks()

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising DOGE Test")
        super(Test, cls).tearDownClass()

        stopDaemons(cls.doge_daemons)
        cls.doge_daemons.clear()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings["chainclients"]["dogecoin"] = {
            "connection_type": "rpc",
            "manage_daemon": False,
            "rpcport": DOGE_BASE_RPC_PORT + node_id,
            "rpcuser": "test" + str(node_id),
            "rpcpassword": "test_pass" + str(node_id),
            "datadir": os.path.join(datadir, "doge_" + str(node_id)),
            "bindir": DOGE_BINDIR,
            "use_csv": False,
            "use_segwit": False,
            "blocks_confirmed": 1,
            "min_relay_fee": 0.01,  # RECOMMENDED_MIN_TX_FEE
        }

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()
        if cls.pause_chain:
            return
        ci0 = cls.swap_clients[0].ci(cls.test_coin)
        try:
            if cls.doge_addr is not None:
                ci0.rpc_wallet("generatetoaddress", [1, cls.doge_addr])
        except Exception as e:
            logging.warning("coins_loop generate {}".format(e))

    def callnoderpc(self, method, params=[], wallet=None, node_id=0):
        return callnoderpc(
            node_id, method, params, wallet, base_rpc_port=DOGE_BASE_RPC_PORT
        )

    def mineBlock(self, num_blocks: int = 1):
        self.callnoderpc("generatetoaddress", [num_blocks, self.doge_addr])

    def test_003_cltv(self):
        logging.info("---------- Test {} cltv".format(self.test_coin.name))
        ci = self.swap_clients[0].ci(self.test_coin)

        self.pause_chain = True
        try:
            start_height: int = self.callnoderpc("getblockcount")

            num_blocks: int = 1351  # consensus.BIP65Height = 1351;

            if start_height < num_blocks:
                to_mine = num_blocks - start_height
                logging.info("Mining %d DOGE blocks to %s", to_mine, self.doge_addr)
                ci.rpc("generatetoaddress", [to_mine, self.doge_addr])

            # self.check_softfork_active("bip65")  # TODO: Re-enable next version

            chain_height: int = self.callnoderpc("getblockcount")

            script = CScript(
                [
                    chain_height + 3,
                    OP_CHECKLOCKTIMEVERIFY,
                ]
            )
            script_dest = ci.getScriptDest(script)
            script_info = ci.rpc_wallet(
                "decodescript",
                [
                    script_dest.hex(),
                ],
            )
            script_addr = ci.encodeScriptDest(script_dest)
            assert script_info["address"] == script_addr

            prevout_amount: int = ci.make_int(1.1)
            tx = CTransaction()
            tx.nVersion = ci.txVersion()
            tx.vout.append(ci.txoType()(prevout_amount, script_dest))
            tx_hex = tx.serialize().hex()

            tx = CTransaction()
            tx.nVersion = ci.txVersion()
            tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
            tx_hex = ToHex(tx)
            tx_funded = ci.rpc_wallet("fundrawtransaction", [tx_hex])
            utxo_pos = 0 if tx_funded["changepos"] == 1 else 1
            tx_signed = ci.rpc_wallet(
                "signrawtransactionwithwallet",
                [
                    tx_funded["hex"],
                ],
            )["hex"]
            txid = ci.rpc(
                "sendrawtransaction",
                [
                    tx_signed,
                ],
            )

            addr_out = ci.rpc_wallet(
                "getnewaddress",
                [
                    "cltv test",
                ],
            )
            pkh = ci.decodeAddress(addr_out)
            script_out = ci.getScriptForPubkeyHash(pkh)

            tx_spend = CTransaction()
            tx_spend.nVersion = ci.txVersion()
            tx_spend.nLockTime = chain_height + 3
            tx_spend.vin.append(
                CTxIn(
                    COutPoint(int(txid, 16), utxo_pos),
                    scriptSig=CScript(
                        [
                            script,
                        ]
                    ),
                )
            )
            tx_spend.vout.append(ci.txoType()(ci.make_int(1.099), script_out))
            tx_spend_hex = ToHex(tx_spend)

            tx_spend.nLockTime = chain_height + 2
            tx_spend_invalid_hex = ToHex(tx_spend)

            for tx_hex in [tx_spend_invalid_hex, tx_spend_hex]:
                try:
                    txid = self.callnoderpc(
                        "sendrawtransaction",
                        [
                            tx_hex,
                        ],
                    )
                except Exception as e:
                    assert "non-final" in str(
                        e
                    ) or "Locktime requirement not satisfied" in str(e)
                else:
                    assert False, "Should fail"

            self.mineBlock(5)

            txid = ci.rpc(
                "sendrawtransaction",
                [
                    tx_spend_hex,
                ],
            )
            self.mineBlock()
            ci.rpc("syncwithvalidationinterfacequeue")
            # Ensure tx was mined
            tx_wallet = ci.rpc_wallet(
                "gettransaction",
                [
                    txid,
                ],
            )
            assert len(tx_wallet["blockhash"]) == 64
        finally:
            self.pause_chain = False

    def test_010_txn_size(self):
        logging.info("---------- Test {} txn size".format(self.test_coin.name))

        swap_clients = self.swap_clients
        ci = swap_clients[0].ci(self.test_coin)

        amount: int = ci.make_int(random.uniform(0.1, 2.0), r=1)

        # fee_rate is in sats/kvB
        fee_rate: int = 1000000

        # Test chain b (no-script) lock tx size
        v = ci.getNewRandomKey()
        s = ci.getNewRandomKey()
        S = ci.getPubkey(s)
        lock_tx_b_txid = ci.publishBLockTx(v, S, amount, fee_rate)
        test_delay_event.wait(1)

        addr_out = ci.getNewAddress(False)
        lock_tx_b_spend_txid = ci.spendBLockTx(
            lock_tx_b_txid, addr_out, v, s, amount, fee_rate, 0
        )
        test_delay_event.wait(1)

        lock_tx_b_spend = ci.getWalletTransaction(lock_tx_b_spend_txid)
        if lock_tx_b_spend is None:
            lock_tx_b_spend = ci.getTransaction(lock_tx_b_spend_txid)
        assert lock_tx_b_spend is not None

        tx_obj = ci.loadTx(lock_tx_b_spend)
        tx_out_value: int = tx_obj.vout[0].nValue
        fee_paid = amount - tx_out_value

        actual_size = len(lock_tx_b_spend)
        expect_size: int = ci.xmr_swap_b_lock_spend_tx_vsize()
        fee_expect = round(fee_rate * expect_size / 1000)
        assert fee_expect == fee_paid
        assert expect_size >= actual_size
        assert expect_size - actual_size < 10

    def test_01_a_full_swap(self):
        self.do_test_01_full_swap(self.test_coin_from, self.test_coin_to)

    def test_01_b_full_swap_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1801)
        self.do_test_01_full_swap(self.test_coin_to, self.test_coin_from)

    def test_01_c_full_swap_to_part(self):
        self.do_test_01_full_swap(self.test_coin, Coins.PART)

    def test_01_d_full_swap_from_part(self):
        self.do_test_01_full_swap(Coins.PART, self.test_coin)

    def test_02_a_leader_recover_a_lock_tx(self):
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_from, self.test_coin_to)

    def test_02_b_leader_recover_a_lock_tx_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1801)
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_to, self.test_coin_from)

    def test_03_a_follower_recover_a_lock_tx(self):
        self.do_test_03_follower_recover_a_lock_tx(
            self.test_coin_from, self.test_coin_to
        )

    def test_03_b_follower_recover_a_lock_tx_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1801)
        self.do_test_03_follower_recover_a_lock_tx(
            self.test_coin_to, self.test_coin_from
        )

    def test_03_e_follower_recover_a_lock_tx_mercy_release(self):
        self.do_test_03_follower_recover_a_lock_tx(
            self.test_coin_from, self.test_coin_to, with_mercy=True
        )

    def test_03_f_follower_recover_a_lock_tx_mercy_release_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1801)
        self.prepare_balance(self.test_coin_from, 100.0, 1801, 1800)
        self.do_test_03_follower_recover_a_lock_tx(
            self.test_coin_to, self.test_coin_from, with_mercy=True
        )

    def test_04_a_follower_recover_b_lock_tx(self):
        self.do_test_04_follower_recover_b_lock_tx(
            self.test_coin_from, self.test_coin_to
        )

    def test_04_b_follower_recover_b_lock_tx_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1801)
        self.do_test_04_follower_recover_b_lock_tx(
            self.test_coin_to, self.test_coin_from
        )

    def test_05_self_bid(self):
        self.do_test_05_self_bid(self.test_coin_from, self.test_coin_to)


if __name__ == "__main__":
    unittest.main()
