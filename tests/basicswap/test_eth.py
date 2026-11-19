# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
ETH coin interface and SwapCreator contract wrapper against a local anvil.

Run:
    python -m unittest tests.basicswap.test_eth
"""

import hashlib
import os
import secrets
import tempfile
import unittest

from unittest import mock

from coincurve import PrivateKey
from eth_account import Account

from basicswap.basicswap_util import BidStates
from basicswap.chainparams import Coins
from basicswap.db import Bid, EvmSignedTx, EvmXmrSwap
from basicswap.interface.eth.eth import ETHInterface
from basicswap.interface.evm import keys as evmkeys
from basicswap.util import TemporaryError
from basicswap.util.ecc import ep, getSecretBytes
from basicswap.interface.evm.swapcreator import make_swap, swap_id
from basicswap.interface.evm.base import nodesWithSelected, validateRpcUrl
from basicswap.interface.evm.rpc import EthRpcClient, WrongChainError
from basicswap.protocols.evm_xmr_swap_1 import evmAddressInOpenSwaps
from tests.basicswap.util.anvil import (
    Anvil,
    KEY_0,
    KEY_1,
    REQUIREMENTS_MET,
    SKIP_REASON,
    WalletDB,
)

ANVIL_PORT = int(os.environ.get("TEST_ANVIL_PORT", "8656"))
DURATION = 3600
# anvil's third deterministic account, left to the bump test
KEY_2 = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"


def _secret(small: bool = False) -> bytes:
    if small:
        return (secrets.randbelow(2**120) + 1).to_bytes(32, "big")
    return getSecretBytes()


def _commitment(secret: bytes) -> bytes:
    return evmkeys.commitment(PrivateKey(secret).public_key.format())


def _ready(ci, swap):
    c = ci.getContract()
    return ci.sendTx(lambda n: c.sign_set_ready(ci.account, swap, n), "ready")


def _claim(ci, swap, secret):
    c = ci.getContract()
    return ci.sendTx(lambda n: c.sign_claim(ci.account, swap, secret, n), "claim")


def _refund(ci, swap, secret):
    c = ci.getContract()
    return ci.sendTx(lambda n: c.sign_refund(ci.account, swap, secret, n), "refund")


@unittest.skipUnless(REQUIREMENTS_MET, SKIP_REASON)
class EthSettlementTest(unittest.TestCase):
    VALUE = 1 * 10**18

    @classmethod
    def setUpClass(cls):
        cls.anvil = Anvil(ANVIL_PORT)

    @classmethod
    def tearDownClass(cls):
        cls.anvil.stop()

    def _new_swap(self, owner, claimer, claim_secret, refund_secret):
        contract = owner.getContract()
        nonce: int = secrets.randbits(64)
        receipt = owner.sendTx(
            lambda tx_nonce: contract.sign_new_swap(
                owner.account,
                claim_commitment=_commitment(claim_secret),
                refund_commitment=_commitment(refund_secret),
                claimer=claimer.account.address,
                duration1=DURATION,
                duration2=DURATION,
                duration3=DURATION,
                value=self.VALUE,
                nonce=nonce,
                tx_nonce=tx_nonce,
            ),
            "lock",
        )
        sid, t1, t2, t3 = contract.new_swap_event(receipt)
        swap = make_swap(
            owner.account.address,
            claimer.account.address,
            _commitment(claim_secret),
            _commitment(refund_secret),
            t1,
            t2,
            t3,
            self.VALUE,
            nonce,
        )
        self.assertEqual(sid, swap_id(swap))
        self.assertEqual((t2 - t1, t3 - t2), (DURATION, DURATION))
        self.assertEqual(contract.stage(sid), "PENDING")
        return swap, sid, receipt["blockNumber"]

    def test_01_wallet_and_chain(self):
        ci = self.anvil.iface(KEY_0)
        self.assertTrue(ci.rpc.is_connected())
        self.assertGreaterEqual(ci.getChainHeight(), 1)
        self.assertGreater(ci.getSpendableBalance(), 0)
        self.assertTrue(ci.isAddressMine(ci.getNewAddress()))

    def test_01b_wallets_page_info(self):
        ci = self.anvil.iface(KEY_0)

        bi = ci.getBlockchainInfo()
        self.assertIn("blocks", bi)
        self.assertIn("verificationprogress", bi)

        wi = ci.getWalletInfo()
        for k in ("balance", "unconfirmed_balance", "encrypted", "locked"):
            self.assertIn(k, wi)
        self.assertFalse(wi["encrypted"])
        self.assertFalse(wi["locked"])
        self.assertEqual(ci.make_int(wi["balance"]), ci.getSpendableBalance())

        self.assertTrue(ci.getDaemonVersion())
        ci.testDaemonRPC()

        fee_rate, fee_src = ci.get_fee_rate()
        self.assertGreater(fee_rate, 0)
        self.assertEqual(fee_src, "gas_price")
        est_fee = fee_rate * ci.WITHDRAW_GAS
        self.assertEqual(
            round(est_fee * ci.COIN() * ci.WEI_PER_UNIT),
            ci.rpc.gas_price() * ci.WITHDRAW_GAS,
        )

    def test_02_ready_and_claim(self):
        owner = self.anvil.iface(KEY_0)
        claimer = self.anvil.iface(KEY_1)
        claim_secret, refund_secret = _secret(), _secret()
        swap, sid, lock_block = self._new_swap(
            owner, claimer, claim_secret, refund_secret
        )

        _ready(owner, swap)
        self.assertEqual(owner.getContract().stage(sid), "READY")

        balance_before = claimer.getSpendableBalance()
        _claim(claimer, swap, claim_secret)
        self.assertEqual(owner.getContract().stage(sid), "COMPLETED")
        self.assertGreater(claimer.getSpendableBalance(), balance_before)
        self.assertEqual(
            owner.getContract().find_completion(sid, lock_block),
            ("CLAIMED", claim_secret),
        )

    def test_03_refund_before_timeout1(self):
        owner = self.anvil.iface(KEY_0)
        claimer = self.anvil.iface(KEY_1)
        claim_secret, refund_secret = _secret(), _secret()
        swap, sid, lock_block = self._new_swap(
            owner, claimer, claim_secret, refund_secret
        )

        with self.assertRaises(Exception):
            _refund(owner, swap, claim_secret)
        _refund(owner, swap, refund_secret)
        self.assertEqual(
            claimer.getContract().find_completion(sid, lock_block),
            ("REFUNDED", refund_secret),
        )

    def test_04_unreduced_secret_rejected(self):
        owner = self.anvil.iface(KEY_0)
        claimer = self.anvil.iface(KEY_1)
        claim_secret, refund_secret = _secret(small=True), _secret()
        swap, sid, lock_block = self._new_swap(
            owner, claimer, claim_secret, refund_secret
        )
        unreduced = (int.from_bytes(claim_secret, "big") + ep.o).to_bytes(32, "big")
        self.anvil.warp(DURATION + 1)
        with self.assertRaises(Exception):
            _claim(claimer, swap, unreduced)
        _claim(claimer, swap, claim_secret)
        self.assertEqual(
            owner.getContract().find_completion(sid, lock_block),
            ("CLAIMED", claim_secret),
        )

    def test_05_late_refund_then_late_claim(self):
        owner = self.anvil.iface(KEY_0)
        claimer = self.anvil.iface(KEY_1)

        claim_secret = _secret()
        swap, sid, lock_block = self._new_swap(owner, claimer, claim_secret, _secret())
        refund_secret = _secret()
        swap_b, sid_b, _ = self._new_swap(owner, claimer, _secret(), refund_secret)

        self.anvil.warp(DURATION + 1)
        with self.assertRaises(Exception):
            _refund(owner, swap_b, refund_secret)
        self.anvil.warp(DURATION)
        _refund(owner, swap_b, refund_secret)
        self.assertEqual(owner.getContract().stage(sid_b), "COMPLETED")
        with self.assertRaises(Exception):
            _claim(claimer, swap, claim_secret)

        self.anvil.warp(DURATION)
        balance_before = claimer.getSpendableBalance()
        _claim(claimer, swap, claim_secret)
        self.assertGreater(claimer.getSpendableBalance(), balance_before)
        self.assertEqual(
            owner.getContract().find_completion(sid, lock_block),
            ("CLAIMED", claim_secret),
        )

    def test_05b_fee_cap(self):
        rpc = self.anvil.iface(KEY_0).rpc
        fees = rpc.fee_params()
        needed: int = (
            self.anvil.w3.eth.fee_history(1, "latest")["baseFeePerGas"][-1]
            + fees["maxPriorityFeePerGas"]
        )
        rpc.max_fee_per_gas = needed - 1
        with self.assertRaises(TemporaryError):
            rpc.fee_params()
        rpc.max_fee_per_gas = needed + 1
        self.assertEqual(rpc.fee_params()["maxFeePerGas"], needed + 1)

        ci = self.anvil.iface(KEY_0)
        ci.setMaxFeePerGas(needed + 2)
        self.assertEqual(ci.rpc.max_fee_per_gas, needed + 2)
        ci.setMaxFeePerGas(None)
        self.assertEqual(ci.rpc.max_fee_per_gas, ci.MAX_FEE_PER_GAS)

    def test_05d_bump_stuck_txs(self):
        ci = self.anvil.iface(KEY_2)
        w3 = self.anvil.w3
        to = self.anvil.iface(KEY_1).account.address

        def transfer(n):
            return ci.rpc.sign_transfer(ci.account.address, ci.account.key, to, 1, n)

        def versions(handle):
            cursor = ci._swap_client.openDB()
            try:
                rows = ci._swap_client.query(EvmSignedTx, cursor, {"handle": handle})
                return [r.txid for r in rows]
            finally:
                ci._swap_client.closeDB(cursor, commit=False)

        def priceUp():
            # Above what any version so far was signed at
            base = 4 * ci.rpc.fee_params(capped=False)["maxFeePerGas"]
            w3.provider.make_request("anvil_setNextBlockBaseFeePerGas", [hex(base)])
            w3.provider.make_request("evm_mine", [])

        w3.provider.make_request("evm_setAutomine", [False])
        try:
            now = ci.rpc.get_block_time()
            blocker = ci.sendTx(transfer, "drip", b"bid", wait=False)
            urgent = ci.sendTx(
                transfer, "claim", b"bid", bump_at=now + DURATION, wait=False
            )
            priceUp()
            self.assertIsNone(ci.receiptFor(urgent))

            ci.bumpTxs()
            self.assertEqual(len(versions(blocker)), 1)
            self.assertEqual(len(versions(urgent)), 1)

            self.anvil.warp(DURATION)
            priceUp()
            ci.bumpTxs()
            self.assertEqual(len(versions(blocker)), 2)
            self.assertEqual(len(versions(urgent)), 2)

            w3.provider.make_request("evm_mine", [])
            receipt = ci.receiptFor(urgent)
            self.assertEqual(receipt["status"], 1)
            self.assertEqual(bytes(receipt["transactionHash"]), versions(urgent)[1])
            self.assertEqual(ci.receiptFor(blocker)["status"], 1)
            self.assertEqual(ci.sendTx(transfer, "claim", b"bid", wait=False), urgent)
            self.assertEqual(len(versions(urgent)), 2)
        finally:
            w3.provider.make_request("evm_setAutomine", [True])

    def test_05c_withdraw(self):
        sender = self.anvil.iface(KEY_0)
        to = self.anvil.iface(KEY_1).account.address
        w3 = self.anvil.w3

        before = w3.eth.get_balance(to)
        txid = sender.withdrawCoin("12.5", to, False)
        w3.eth.wait_for_transaction_receipt(txid)
        self.assertEqual(w3.eth.get_balance(to) - before, 125 * 10**17)

        before = w3.eth.get_balance(to)
        txid = sender.withdrawCoin("1", to, True)
        w3.eth.wait_for_transaction_receipt(txid)
        received = w3.eth.get_balance(to) - before
        self.assertTrue(0 < received < 10**18)

        with self.assertRaises(ValueError):
            sender.withdrawCoin("1", "0xnotanaddress", False)

        history = sender.listWalletTransactions()
        self.assertEqual([t["kind"] for t in history], ["withdraw", "withdraw"])
        self.assertEqual(history[0]["amount"], -12.5)
        self.assertTrue(all(t["confirmations"] >= 1 for t in history))
        self.assertTrue(all(t["address"] == to for t in history))

        sender.setActiveAccount(KEY_1)
        self.assertEqual(sender.listWalletTransactions(), [])

    def test_05d_rpc_failover(self):
        live = f"http://127.0.0.1:{ANVIL_PORT}"
        switched = []
        rpc = EthRpcClient(
            [("http://127.0.0.1:1", None), (live, None)],
            timeout=5,
            on_switch=lambda url, e: switched.append(url),
        )
        self.assertGreaterEqual(rpc.get_block_number(), 1)
        self.assertEqual(switched, [live])
        self.assertIn("error", rpc.w3.provider.make_request("no_such_method", []))
        self.assertEqual(rpc.w3.provider.current, 1)

        self.assertGreaterEqual(
            EthRpcClient([(live, None)], chain_id=31337).get_block_number(), 1
        )
        rejected = []
        wrong = EthRpcClient([(live, None)], chain_id=1, on_reject=rejected.append)
        for _ in range(2):
            with self.assertRaises(WrongChainError):
                wrong.get_block_number()
        self.assertEqual(len(rejected), 1)

        ci = self.anvil.iface(KEY_0)
        nodes = [
            {"url": live, "failover": True},
            {"url": "https://a.example", "failover": True},
            {"url": "https://b.example", "failover": False},
        ]
        ci.setNodes(nodes, True)
        self.assertEqual(ci.rpcUrls(), [live, "https://a.example"])
        ci.setNodes(nodes, False)
        self.assertEqual(ci.rpcUrls(), [live])

        self.assertEqual(
            nodesWithSelected(nodes[1:], live)[0], {"url": live, "failover": True}
        )
        self.assertEqual(nodesWithSelected(nodes, live), nodes)

        self.assertEqual(validateRpcUrl(" https://x.example "), "https://x.example")
        self.assertEqual(validateRpcUrl(live), live)
        for bad in ("rpc.example", "http://rpc.example", "127.0.0.1:8545"):
            with self.assertRaises(ValueError):
                validateRpcUrl(bad)

    def test_05e_accounts(self):
        coin: int = int(Coins.ETH)
        root_key: bytes = bytes.fromhex(KEY_0[2:])
        sc = mock.Mock(log=None)
        sc.getWalletKey.return_value = root_key
        sc.getWalletKeyAtPath.side_effect = lambda p: hashlib.sha256(
            p.encode()
        ).digest()

        def address(cs, network, path):
            ci = ETHInterface(cs, network, swap_client=sc)
            expect = Account.from_key(hashlib.sha256(path.encode()).digest()).address
            self.assertEqual(ci.account.address, expect)
            return ci

        # Every account is hardened, 0 included; the seed root is never one
        account_0 = address({}, "mainnet", f"44445555h/1h/{coin}h/0h")
        ci = address({"account": 3}, "mainnet", f"44445555h/1h/{coin}h/3h")
        self.assertNotEqual(
            account_0.account.address, Account.from_key(root_key).address
        )
        seed_id: str = account_0.getSeedHash(root_key).hex()
        self.assertEqual(account_0.getWalletSeedID(), seed_id)
        self.assertEqual(ci.getWalletSeedID(), seed_id)
        other = ci.account.address
        ci.setAccountIndex(0)
        self.assertEqual(ci.account.address, account_0.account.address)

        # Test chains have their own branch, as does a mainnet instance pointed at one
        test_0 = address({}, "regtest", f"44445555h/2h/{coin}h/31337h/0h")
        self.assertEqual(test_0.getWalletSeedID(), seed_id)
        address({"chain_id": 31337}, "mainnet", f"44445555h/2h/{coin}h/31337h/0h")

        with tempfile.TemporaryDirectory() as d:
            db = WalletDB(os.path.join(d, "db.sqlite"))
            mine = account_0.account.address
            cursor = db.openDB()
            try:
                for n, state in enumerate(
                    (BidStates.SWAP_COMPLETED, BidStates.BID_EXPIRED)
                ):
                    db.add(Bid(bid_id=bytes([n]), state=state), cursor)
                    db.add(
                        EvmXmrSwap(
                            bid_id=bytes([n]), evm_coin=int(Coins.ETH), evm_addr=mine
                        ),
                        cursor,
                    )
                self.assertFalse(evmAddressInOpenSwaps(db, Coins.ETH, mine, cursor))
                db.add(Bid(bid_id=b"\x09", state=BidStates.BID_SENT), cursor)
                db.add(
                    EvmXmrSwap(
                        bid_id=b"\x09",
                        evm_coin=int(Coins.ETH),
                        xmr_side_addr=mine.lower(),
                    ),
                    cursor,
                )
                self.assertTrue(evmAddressInOpenSwaps(db, Coins.ETH, mine, cursor))
                self.assertFalse(evmAddressInOpenSwaps(db, Coins.ETH, other, cursor))
                self.assertFalse(evmAddressInOpenSwaps(db, Coins.STABLE, mine, cursor))
            finally:
                db.closeDB(cursor, commit=False)

    def test_06_rpc_url_setter(self):
        ci = self.anvil.iface(KEY_0)
        old_rpc = ci.rpc
        old_contract = ci.getContract()
        ci.setRpcUrl(f"http://127.0.0.1:{ANVIL_PORT}")
        self.assertIsNot(ci.rpc, old_rpc)
        self.assertTrue(ci.rpc.is_connected())
        self.assertIs(ci.getContract().rpc, ci.rpc)
        self.assertIsNot(ci.getContract(), old_contract)


if __name__ == "__main__":
    unittest.main()
