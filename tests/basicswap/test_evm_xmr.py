# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
EVM<->XMR driver: both sides of a swap against SwapCreator on anvil, then
against SwapFactory.

Each side runs checkEvmXmrBidState and its queued actions on its own store;
the lock message passes between them. Keys and DLEAGs are real; the Monero
wallet is a shared in-memory ledger that only lets the joint keys spend.

Run:
    python -m unittest tests.basicswap.test_evm_xmr
"""

import json
import os
import secrets
import time
import unittest
from types import SimpleNamespace

from coincurve import PublicKey
from eth_account import Account
from web3 import Web3
from web3.exceptions import TimeExhausted

from basicswap.basicswap import BasicSwap
from basicswap.chainparams import Coins
from basicswap.interface.eth.chainparams import ETH_COIN
from basicswap.basicswap_util import ActionTypes, BidStates, MessageTypes, SwapTypes
from basicswap.db import Bid, EvmXmrSwap, Offer
from basicswap.interface.evm import keys as evmkeys
from basicswap.interface.evm.rpc import EthRpcClient
from basicswap.interface.evm.swapfactory import SwapFactory
from basicswap.interface.xmr.xmr import XMRInterface
from basicswap.messages_npb import EvmXmrLockMessage
import basicswap.protocols.evm_xmr_swap_1 as ethdrv
from basicswap.util import TemporaryError
from tests.basicswap.util.anvil import (
    Anvil,
    KEY_0,
    KEY_1,
    REQUIREMENTS_MET,
    SKIP_REASON,
)

ANVIL_PORT = int(os.environ.get("TEST_ANVIL_PORT", "8657"))
LOCK_DURATION = 7200
RELEASE_MARGIN = 600
B_LOCK_MARGIN = 1200
LOCK_WAIT = 1800
CONFIRM_ALLOWANCE = 300


class FakeLog:
    def id(self, x):
        return x.hex() if isinstance(x, (bytes, bytearray)) else str(x)

    def addr(self, x):
        return str(x)

    def info(self, *a, **k):
        pass

    debug = warning = error = info


class MoneroLedger:
    def __init__(self):
        self.locks = {}
        self.spends = {}


class FakeXmr(XMRInterface):
    """XMRInterface's key operations over a MoneroLedger instead of a wallet."""

    blocks_confirmed = 1

    def __init__(self, ledger, visible=True):
        self._addr_prefix = 18
        self._log = FakeLog()
        self.ledger = ledger
        self.visible = visible

    def _addr(self, kbv, Kbs) -> str:
        return self.encodeSharedAddress(self.getPubkey(kbv), Kbs)

    def getChainHeight(self):
        return 1000

    def publishBLockTx(self, kbv, Kbs, amount, feerate, unlock_time=0):
        txid = secrets.token_bytes(32)
        self.ledger.locks[self._addr(kbv, Kbs)] = (txid, amount)
        return txid

    def findTxB(
        self, kbv, Kbs, amount, confs, restore_height, bid_sender, check_amount=True
    ):
        lock = self.ledger.locks.get(self._addr(kbv, Kbs))
        if not self.visible or lock is None or lock[1] != amount:
            return None
        return {"txid": lock[0].hex(), "amount": amount, "height": 10}

    def createBLockSpendTx(
        self, txid, dest, kbv, kbs, amount, fee, restore_height, **k
    ):
        addr = self._addr(kbv, self.getPubkey(kbs))
        assert self.ledger.locks.get(addr) == (txid, amount), "spend of an unknown lock"
        return secrets.token_bytes(32), json.dumps([addr, dest]).encode()

    def publishTx(self, tx):
        addr, dest = json.loads(tx)
        self.ledger.locks.pop(addr)
        self.ledger.spends[tx] = dest

    def getTxDepth(self, txid):
        return None


class FakeNode:
    """The BasicSwap surface the driver uses, for one side and one bid."""

    SMSG_SECONDS_IN_HOUR = 3600
    evm_contract_coins = (Coins.ETH,)
    xmr_based_coins = (Coins.XMR,)
    sendBLockSpendTx = BasicSwap.sendBLockSpendTx
    saveBidInSession = BasicSwap.saveBidInSession
    getXmrBidFromSession = BasicSwap.getXmrBidFromSession
    recordTxB = BasicSwap.recordTxB
    setBidBLockTx = BasicSwap.setBidBLockTx
    _sc_lock_release_min_margin = RELEASE_MARGIN
    _evm_xmr_lock_wait = LOCK_WAIT

    def __init__(self, name, eth, xmr, offer, bid):
        self.name = name
        self.log = FakeLog()
        self._eth = eth
        self._xmr = xmr
        self._store = {Offer: offer, Bid: bid}
        self._txns = {}
        self.actions = []
        self.events = []
        self.sent = []
        self.swaps_in_progress = {}
        self._contract_count = 0

    def ci(self, coin):
        return {Coins.ETH: self._eth, Coins.XMR: self._xmr}[Coins(coin)]

    def openDB(self, cursor=None):
        return cursor

    def closeDB(self, cursor, commit=True):
        pass

    def commitDB(self):
        pass

    def queryOne(self, table, cursor, filt):
        return self._store.get(table)

    def add(self, obj, cursor, upsert=False):
        self._store[type(obj)] = obj

    def loadBidTxns(self, bid, cursor):
        bid.txns = self._txns

    def notifyBidChanged(self, bid_id):
        pass

    def clearStringKV(self, key, cursor):
        pass

    def getPathKey(
        self, coin_from, coin_to, created_at, contract_count, key_no, for_ed25519
    ):
        while True:
            key = secrets.token_bytes(32)
            if self._xmr.verifyKey(key):
                return key

    def getNewContractId(self, cursor):
        self._contract_count += 1
        return self._contract_count

    def getCachedMainWalletAddress(self, ci, cursor=None):
        return f"{self.name}_xmr_wallet"

    def createActionInSession(self, delay, action_type, bid_id, cursor):
        self.actions.append((action_type, bid_id))

    def countQueuedActions(self, cursor, bid_id, action_type):
        return sum(1 for a, b in self.actions if b == bid_id and a == action_type)

    def run_actions(self):
        dispatch = {
            ActionTypes.SEND_EVM_LOCK: ethdrv.sendEvmLock,
            ActionTypes.SEND_XMR_LOCK_FOR_EVM: ethdrv.sendXmrLockForEvm,
            ActionTypes.SEND_EVM_LOCK_READY: ethdrv.markEvmReady,
            ActionTypes.CLAIM_EVM_LOCK: ethdrv.claimEvmLock,
            ActionTypes.REDEEM_XMR_FOR_EVM: ethdrv.redeemXmrForEvm,
            ActionTypes.REFUND_EVM_LOCK: ethdrv.refundEvmLock,
            ActionTypes.RECOVER_XMR_FROM_EVM_REFUND: ethdrv.recoverXmrFromEvmRefund,
            ActionTypes.SEND_EVM_GAS_DRIP: ethdrv.sendGasDrip,
        }
        pending, self.actions = self.actions, []
        for action_type, bid_id in pending:
            dispatch[action_type](self, bid_id, None)

    def step(self):
        bid = self._store[Bid]
        ethdrv.checkEvmXmrBidState(self, bid.bid_id, bid, self._store[Offer])
        self.run_actions()
        return BidStates(bid.state)

    def get_delay_event_seconds(self):
        return 0

    def getTime(self):
        return int(time.time())

    def logBidEvent(self, bid_id, event_type, msg, cursor):
        self.events.append(event_type)

    def countBidEvents(self, bid, event_type, cursor):
        return self.events.count(event_type)

    def getBLockMinMargin(self, ci_to):
        return B_LOCK_MARGIN

    def getConfirmAllowance(self, ci):
        return CONFIRM_ALLOWANCE

    def notify(self, *a, **k):
        pass

    def getAcceptBidMsgValidTime(self, bid):
        return 3600

    def sendMessage(self, addr_from, addr_to, payload_hex, msg_valid, cursor, **k):
        self.sent.append(payload_hex)
        return secrets.token_bytes(28)

    def getSmsgMsgBytes(self, msg):
        return bytes.fromhex(msg["hex"][2:])


def lockMsg(payload_hex: str) -> dict:
    """The lock as the XMR side, the bidder, receives it from the offerer."""
    return {
        "msgid": "00" * 28,
        "hex": payload_hex,
        "from": "offerAddr",
        "to": "bidAddr",
    }


@unittest.skipUnless(REQUIREMENTS_MET, SKIP_REASON)
class EvmXmrDriverTest(unittest.TestCase):
    ETH_AMOUNT = 20 * ETH_COIN
    XMR_PICO = 500_000_000_000
    DESIGN = "swapcreator"

    @classmethod
    def setUpClass(cls):
        cls.anvil = Anvil(ANVIL_PORT, cls.DESIGN)

    @classmethod
    def tearDownClass(cls):
        cls.anvil.stop()

    def _pair(self, evm_sees_lock=True, xmr_key=KEY_1):
        """An ETH -> XMR offer: the EVM side made it, the XMR side bid; both accepted."""
        ledger = MoneroLedger()
        offer_id = secrets.token_bytes(28)
        bid_id = secrets.token_bytes(28)
        nodes = []
        for name, key, was_received in (("evm", KEY_0, True), ("xmr", xmr_key, False)):
            offer = Offer(
                offer_id=offer_id,
                swap_type=SwapTypes.EVM_XMR_SWAP,
                coin_from=int(Coins.ETH),
                coin_to=int(Coins.XMR),
                addr_from="offerAddr",
                lock_value=LOCK_DURATION,
                smsg_payload_version=1,
            )
            bid = Bid(
                bid_id=bid_id,
                offer_id=offer_id,
                amount=self.ETH_AMOUNT,
                amount_to=self.XMR_PICO,
                created_at=int(time.time()),
                was_sent=not was_received,
                was_received=was_received,
                bid_addr="bidAddr",
                chain_b_height_start=0,
            )
            bid.setState(BidStates.BID_ACCEPTED)
            xmr = FakeXmr(ledger, visible=(name != "evm" or evm_sees_lock))
            nodes.append(FakeNode(name, self.anvil.iface(key), xmr, offer, bid))
        evm, xmr = nodes

        handshake = []
        for node, we_are_evm in ((evm, True), (xmr, False)):
            evm_swap = EvmXmrSwap(
                bid_id=bid_id,
                evm_coin=int(Coins.ETH),
                contract_address=self.anvil.contract_address,
            )
            dleag = ethdrv._setOwnKeys(node, evm_swap, 0, we_are_evm, None)
            addr = node._eth.getNewAddress()
            if we_are_evm:
                evm_swap.evm_addr = addr
            else:
                evm_swap.xmr_side_addr = addr
            node._store[EvmXmrSwap] = evm_swap
            ours = "evm" if we_are_evm else "xmr"
            handshake.append(
                SimpleNamespace(
                    kbv=getattr(evm_swap, f"{ours}_kbv"),
                    kbs_dleag=dleag,
                    claimer_addr="" if we_are_evm else addr,
                    gas_request=(
                        0 if we_are_evm else ethdrv._gasRequest(node, Coins.ETH)
                    ),
                )
            )
        for node, peer_msg, peer_is_evm in (
            (evm, handshake[1], False),
            (xmr, handshake[0], True),
        ):
            evm_swap = node._store[EvmXmrSwap]
            ethdrv._storePeerMessage(node, evm_swap, peer_msg, peer_is_evm)
            ethdrv._checkPeerKeys(node, evm_swap, peer_is_evm)
            ethdrv._checkDistinctKeys(node, evm_swap)
        self.assertEqual(
            ethdrv.sharedKeys(evm, evm._store[EvmXmrSwap]),
            ethdrv.sharedKeys(xmr, xmr._store[EvmXmrSwap]),
        )
        return evm, xmr, ledger

    def _deliver_lock(self, evm, xmr, tamper=None):
        payload_hex = evm.sent[-1]
        if tamper:
            from basicswap.messages_npb import EvmXmrLockMessage

            m = EvmXmrLockMessage()
            m.from_bytes(bytes.fromhex(payload_hex[2:]))
            tamper(m)
            payload_hex = payload_hex[:2] + m.to_bytes().hex()
        ethdrv.processEvmXmrLock(xmr, lockMsg(payload_hex))

    def _hostile_lock(self, evm, xmr, contract=None, **override):
        """The EVM side escrows its own newSwap instead of the agreed one and announces it."""
        evm_swap = evm._store[EvmXmrSwap]
        bid = evm._store[Bid]
        ci = evm._eth
        contract = contract or ethdrv._contract(evm, evm_swap)
        evm_amount, _ = ethdrv.evmAmountsForBid(evm, evm._store[Offer], bid)
        params = dict(
            claim_commitment=evmkeys.commitment(evm_swap.xmr_pkas),
            refund_commitment=evmkeys.commitment(evm_swap.evm_pkas),
            claimer=evm_swap.xmr_side_addr,
            duration1=LOCK_DURATION,
            duration2=LOCK_DURATION,
            duration3=LOCK_DURATION,
            value=ci.toWei(evm_amount),
            nonce=ethdrv._nonce(bid.bid_id),
        )
        params.update(override)
        if isinstance(contract, SwapFactory):
            start: int = ci.rpc.get_block_time()
            t1 = start + params["duration1"]
            t2 = t1 + params["duration2"]
            t3 = t2 + params["duration3"]
            swap = contract.make_swap(
                evm_swap.evm_addr,
                params["claimer"],
                params["claim_commitment"],
                params["refund_commitment"],
                t1,
                t2,
                t3,
                params["value"],
                params["nonce"],
            )
            receipt = ci.sendTx(
                lambda tx_nonce: contract.sign_lock(
                    ci.account, swap, start + LOCK_WAIT, tx_nonce
                ),
                "lock",
            )
        else:
            receipt = ci.sendTx(
                lambda tx_nonce: contract.sign_new_swap(
                    ci.account, **params, tx_nonce=tx_nonce
                ),
                "lock",
            )
            _, t1, t2, t3 = contract.new_swap_event(receipt)
            start = t1 - params["duration1"]
        m = EvmXmrLockMessage()
        m.bid_msg_id = bid.bid_id
        m.owner = evm_swap.evm_addr
        m.timeout1, m.timeout2, m.timeout3 = t1, t2, t3
        m.lock_tx_id = bytes(receipt["transactionHash"])
        m.xmr_lock_deadline = start + LOCK_WAIT
        payload_hex = "{:02x}".format(MessageTypes.EVM_XMR_LOCK) + m.to_bytes().hex()
        ethdrv.processEvmXmrLock(xmr, lockMsg(payload_hex))

    def _locked(self, evm_sees_lock=True, xmr_key=KEY_1):
        evm, xmr, ledger = self._pair(evm_sees_lock, xmr_key)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self._deliver_lock(evm, xmr)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(len(ledger.locks), 1)
        return evm, xmr, ledger

    def test_01_happy_path(self):
        evm, xmr, ledger = self._locked()
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_LOCK_RELEASED)

        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        balance_before = xmr._eth.getSpendableBalance()
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
        self.assertGreater(xmr._eth.getSpendableBalance(), balance_before)
        self.assertEqual(xmr.step(), BidStates.SWAP_COMPLETED)

        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
        self.assertEqual(list(ledger.spends.values()), ["evm_xmr_wallet"])
        self.assertEqual(evm._store[EvmXmrSwap].xmr_kbs, xmr._store[EvmXmrSwap].xmr_kbs)
        self.assertEqual(evm.step(), BidStates.SWAP_COMPLETED)

        def history(node):
            return [
                (t["kind"], t["category"], t["amount"])
                for t in node._eth.listWalletTransactions()
            ]

        evm_amount = evm._store[Bid].amount / ETH_COIN
        self.assertEqual(
            history(evm),
            [("lock", "send", -evm_amount), ("ready", "send", 0.0)],
        )
        self.assertEqual(history(xmr), [("claim", "receive", evm_amount)])

    def test_02_refund_when_no_lock_is_mined(self):
        evm, xmr, ledger = self._locked(evm_sees_lock=False)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.anvil.warp(LOCK_WAIT - 60)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)

        self.anvil.warp(120)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_FAILED_REFUNDED)

        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_FAILED_REFUNDED)
        self.assertEqual(list(ledger.spends.values()), ["xmr_xmr_wallet"])
        self.assertEqual(xmr._store[EvmXmrSwap].evm_kbs, evm._store[EvmXmrSwap].evm_kbs)

    def test_10_no_xmr_lock_after_the_lock_wait(self):
        evm, xmr, ledger = self._pair()
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self._deliver_lock(evm, xmr)
        self.anvil.warp(LOCK_WAIT - CONFIRM_ALLOWANCE + 10)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(ledger.locks, {})
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(xmr.actions, [])
        self.anvil.warp(LOCK_DURATION)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_FAILED_NOTHING_TO_RECOVER)

    def test_12_lock_mined_after_the_send_deadline(self):
        # Sent just before a restart, mined after the XMR side gave up sending
        evm, xmr, ledger = self._pair()
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self._deliver_lock(evm, xmr)
        self.anvil.warp(LOCK_WAIT - CONFIRM_ALLOWANCE + 10)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(ledger.locks, {})

        kbv, Kbs = ethdrv.sharedKeys(xmr, xmr._store[EvmXmrSwap])
        xmr._xmr.publishBLockTx(kbv, Kbs, self.XMR_PICO, 0)
        xmr.step()
        self.assertIsNotNone(xmr._store[EvmXmrSwap].b_lock_tx_id)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)

    def test_03_claim_after_timeout1_without_ready(self):
        evm, xmr, ledger = self._locked()

        self.anvil.warp(LOCK_DURATION - 30)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.anvil.warp(60)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)

        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
        self.assertEqual(list(ledger.spends.values()), ["evm_xmr_wallet"])

    def test_04_tampered_lock_message(self):
        evm, xmr, ledger = self._pair()
        evm.step()

        def longer_claim_window(m):
            m.timeout2 += 1

        self._deliver_lock(evm, xmr, tamper=longer_claim_window)
        bid = xmr._store[Bid]
        ethdrv.checkEvmXmrBidState(xmr, bid.bid_id, bid, xmr._store[Offer])
        with self.assertRaisesRegex(ValueError, "EVM lock INVALID"):
            xmr.run_actions()
        self.assertEqual(ledger.locks, {})

    def test_13_hostile_evm_lock(self):
        other_key = evmkeys.commitment(PublicKey.from_secret(b"\x07" * 32).format())
        cases = (
            (
                "escrows less",
                lambda evm: {"value": evm._eth.toWei(self.ETH_AMOUNT) - 1},
                "EVM lock INVALID",
            ),
            (
                "other claim key",
                lambda evm: {"claim_commitment": other_key},
                "EVM lock INVALID",
            ),
            (
                "other refund key",
                lambda evm: {"refund_commitment": other_key},
                "EVM lock INVALID",
            ),
            (
                "other claimer",
                lambda evm: {"claimer": evm._eth.getNewAddress()},
                "EVM lock INVALID",
            ),
            ("other nonce", lambda evm: {"nonce": 1}, "EVM lock INVALID"),
            (
                "short timeouts",
                lambda evm: {f"duration{i}": LOCK_DURATION // 2 for i in (1, 2, 3)},
                "EVM lock timeouts differ from the offer",
            ),
        )
        for name, override, error in cases:
            with self.subTest(name):
                evm, xmr, ledger = self._pair()
                self._hostile_lock(evm, xmr, **override(evm))
                bid = xmr._store[Bid]
                ethdrv.checkEvmXmrBidState(xmr, bid.bid_id, bid, xmr._store[Offer])
                with self.assertRaisesRegex(ValueError, error):
                    xmr.run_actions()
                self.assertEqual(ledger.locks, {})

    def test_14_evm_lock_on_another_contract(self):
        evm, xmr, ledger = self._pair()
        design = type(ethdrv._contract(evm, evm._store[EvmXmrSwap]))
        other = design(evm._eth.rpc, self.anvil._deploy(Account.from_key(KEY_0)))
        self._hostile_lock(evm, xmr, contract=other)
        bid = xmr._store[Bid]
        ethdrv.checkEvmXmrBidState(xmr, bid.bid_id, bid, xmr._store[Offer])
        with self.assertRaisesRegex(ValueError, "EVM lock INVALID"):
            xmr.run_actions()
        self.assertEqual(ledger.locks, {})

    def test_15_no_xmr_lock_while_blocked(self):
        evm, xmr, ledger = self._pair()
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self._deliver_lock(evm, xmr)
        # A blocklist that blocks every address
        blocklist = Web3.to_checksum_address("0x" + "b1" * 20)
        self.anvil.w3.provider.make_request(
            "anvil_setCode", [blocklist, "0x600160005260206000f3"]
        )
        xmr._eth._blocklist = blocklist
        xmr._eth._blocklist_function = "isBlocked(address)"
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(ledger.locks, {})
        xmr._eth._blocklist = None
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(len(ledger.locks), 1)

    def test_05_bad_dleag(self):
        evm, _, _ = self._pair()
        evm_swap = evm._store[EvmXmrSwap]
        dleag = bytearray(evm_swap.peer_dleag)
        dleag[100] ^= 1
        evm_swap.peer_dleag = bytes(dleag)
        with self.assertRaisesRegex(ValueError, "Invalid DLEAG proof"):
            ethdrv._checkPeerKeys(evm, evm_swap, False)

    def test_06_lock_resent_after_crash(self):
        evm, _, _ = self._pair()
        broadcast = EthRpcClient.broadcast

        def sentThenCrash(rpc, tx_hash, raw, error_decoder=None):
            broadcast(rpc, tx_hash, raw, error_decoder)
            raise RuntimeError("stopped before saving the receipt")

        EthRpcClient.broadcast = sentThenCrash
        try:
            with self.assertRaises(RuntimeError):
                evm.step()
        finally:
            EthRpcClient.broadcast = broadcast
        balance = evm._eth.getSpendableBalance()
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(evm._eth.getSpendableBalance(), balance)

    def _released(self):
        evm, xmr, ledger = self._locked()
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        return evm, xmr, ledger

    def test_07_refund_after_timeout2(self):
        # The XMR side is offline for the whole claim window
        evm, xmr, ledger = self._released()
        self.anvil.warp(2 * LOCK_DURATION + 10)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_FAILED_REFUNDED)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_FAILED_REFUNDED)
        self.assertEqual(list(ledger.spends.values()), ["xmr_xmr_wallet"])

    def test_08_late_claim_after_timeout3(self):
        # The EVM side goes offline after setReady, the XMR side misses the claim window
        evm, xmr, ledger = self._released()
        self.anvil.warp(3 * LOCK_DURATION - RELEASE_MARGIN // 2)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        self.anvil.warp(RELEASE_MARGIN)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        balance_before = xmr._eth.getSpendableBalance()
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
        self.assertGreater(xmr._eth.getSpendableBalance(), balance_before)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
        self.assertEqual(list(ledger.spends.values()), ["evm_xmr_wallet"])

    def test_09_gas_drip(self):
        # An XMR side with no gas asks for it; the drip pays for its claim
        evm, xmr, ledger = self._locked(xmr_key="0x" + secrets.token_hex(32))
        self.assertEqual(xmr._eth.getSpendableBalance(), 0)
        self.assertGreater(evm._store[EvmXmrSwap].gas_request, 0)

        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        self.assertIsNotNone(evm._store[EvmXmrSwap].gas_drip_txid)
        drip = xmr._eth.getSpendableBalance()
        self.assertGreater(drip, 0)

        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_LOCK_RELEASED)
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
        self.assertGreater(xmr._eth.getSpendableBalance(), drip)
        evm.step()
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)

    def test_11_lock_before_accept_completes(self):
        evm, xmr, ledger = self._pair()
        xmr._store[Bid].setState(BidStates.BID_RECEIVING_ACC)
        self.assertEqual(evm.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self._deliver_lock(evm, xmr)
        self.assertEqual(BidStates(xmr._store[Bid].state), BidStates.BID_RECEIVING_ACC)

        ethdrv.receiveEvmXmrBidAccept(xmr, xmr._store[Bid], None)
        self.assertEqual(
            BidStates(xmr._store[Bid].state), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED
        )
        self.assertEqual(xmr.step(), BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
        self.assertEqual(len(ledger.locks), 1)


class EvmXmrFactoryDriverTest(EvmXmrDriverTest):
    DESIGN = "swapfactory"

    def test_16_lock_reverts_past_its_deadline(self):
        evm, xmr, ledger = self._pair()
        bid_id = evm._store[Bid].bid_id
        provider = self.anvil.w3.provider
        wait_receipt = EthRpcClient.wait_receipt

        def unmined(rpc, tx_hash, *args, **kwargs):
            raise TimeExhausted()

        provider.make_request("evm_setAutomine", [False])
        EthRpcClient.wait_receipt = unmined
        try:
            balance = evm._eth.getSpendableBalance()
            with self.assertRaisesRegex(TemporaryError, "not mined yet"):
                ethdrv.sendEvmLock(evm, bid_id, None)
            lock = evm._eth.signedHandle(bid_id, "lock")
            self.anvil.warp(LOCK_WAIT + 10)
        finally:
            EthRpcClient.wait_receipt = wait_receipt
            provider.make_request("evm_setAutomine", [True])
        self.assertEqual(evm._eth.receiptFor(lock)["status"], 0)
        ethdrv.sendEvmLock(evm, bid_id, None)
        self.assertEqual(
            BidStates(evm._store[Bid].state),
            BidStates.XMR_SWAP_FAILED_NOTHING_TO_RECOVER,
        )
        self.assertEqual(evm._eth.signedHandle(bid_id, "lock"), lock)
        self.assertGreater(evm._eth.getSpendableBalance(), balance - ETH_COIN)
        self.assertEqual(evm.sent, [])


class EvmClaimWindowTest(unittest.TestCase):
    def test_claim_window(self):
        s = SimpleNamespace(timeout1=1000, timeout2=2000, timeout3=3000)
        m = 100
        self.assertFalse(ethdrv._evmClaimable(s, "PENDING", 1010, 999, m))
        self.assertTrue(ethdrv._evmClaimable(s, "PENDING", 1010, 1000, m))
        self.assertTrue(ethdrv._evmClaimable(s, "READY", 500, 500, m))
        self.assertFalse(ethdrv._evmClaimable(s, "READY", 1900, 1900, m))
        self.assertFalse(ethdrv._evmClaimable(s, "READY", 3010, 2999, m))
        self.assertTrue(ethdrv._evmClaimable(s, "PENDING", 3010, 3000, m))
        self.assertFalse(ethdrv._evmClaimable(s, "CLAIMED", 3010, 3000, m))

    def test_refund_window(self):
        s = SimpleNamespace(timeout1=1000, timeout2=2000, timeout3=3000)
        m = 100
        self.assertTrue(ethdrv._evmRefundable(s, "PENDING", 899, 899, m))
        self.assertFalse(ethdrv._evmRefundable(s, "PENDING", 900, 900, m))
        self.assertFalse(ethdrv._evmRefundable(s, "READY", 500, 500, m))
        self.assertFalse(ethdrv._evmRefundable(s, "READY", 2010, 1999, m))
        self.assertTrue(ethdrv._evmRefundable(s, "READY", 2010, 2000, m))
        self.assertFalse(ethdrv._evmRefundable(s, "READY", 2900, 2900, m))


if __name__ == "__main__":
    unittest.main()
