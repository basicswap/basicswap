# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.interface.btc.btc import (
    BTCInterface,
)
from basicswap.chainparams import Coins
from basicswap.db import Concepts, SwapTx
from typing import Optional, Any, TypedDict
from basicswap.basicswap_util import (
    ActionTypes,
    EventLogTypes,
    MessageTypes,
    TxLockTypes,
    TxStates,
    TxTypes,
)
from basicswap.util import DeserialiseNum, TemporaryError, b2i, ensure
from basicswap.util.address import decodeWif
from basicswap.util.crypto import sha256
from coincurve.keys import PrivateKey
import datetime as dt
import basicswap.protocols.atomic_swap_1 as atomic_swap_1


class PrevOutInfo(TypedDict):
    outid: str
    amount: float  # NAV coins from decodeblsctrawtransaction
    gamma: str


class PrevOutInfoWithSpendingKey(PrevOutInfo):
    spending_key: str


class NAVInterface(BTCInterface):
    @staticmethod
    def coin_type() -> Coins:  # type: ignore[override]
        return Coins.NAV

    def acceptNavInitiate(
        self, bid_id, bid, offer, script, secret_hash, lock_value, bid_date, cursor
    ) -> bytes:
        (
            txn,
            lock_tx_vout,
            nav_addr_redeem,
            nav_addr_refund,
            blinding_key,
        ) = self.createInitiateTxn(
            bid_id, bid, lock_value, secret_hash, bid_date, cursor
        )

        # Store the signed refund txn in case wallet is locked when refund is possible
        refund_txn = self._sc.createRefundTxn(
            Coins.NAV,
            txn,
            offer,
            bid,
            script,
            addr_refund_out=nav_addr_refund,
            cursor=cursor,
            secret_hash=secret_hash,
        )
        bid.initiate_txn_refund = bytes.fromhex(refund_txn)

        txn = self.signBlsct(txn)

        txid = self.publishTx(bytes.fromhex(txn))
        self._sc.log.debug(
            f"Submitted initiate txn {self._sc.logIDT(txid)} to {self.coin_name()} chain for bid {self._sc.log.id(bid_id)}",
        )

        bid.initiate_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.ITX,
            txid=bytes.fromhex(txid),
            vout=lock_tx_vout,
            tx_data=bytes.fromhex(txn),
            script=self.createFakeNonNavHTLCScript(secret_hash, lock_value),
        )
        bid.setITxState(TxStates.TX_SENT)
        self._sc.logEvent(
            Concepts.BID,
            bid.bid_id,
            EventLogTypes.ITX_PUBLISHED,
            "",
            cursor,
        )
        return txid

    def buildNavRedeemPrevout(self, bid, nav_txn, privkey, txn_script, is_ptx) -> dict:
        secret_hash = atomic_swap_1.extractScriptSecretHash(txn_script)
        # Reconstruct the prevout from the on-chain HTLC output via listblsctunspent
        # (no off-chain tx_data_funded from the counterparty needed). The on-chain
        # outid is authoritative, handling the BLSCT-aggregation txid change after mining.
        prevout = self.getPrevOutInfoFromChain(secret_hash)

        ecdh_pubkey = (
            bid.nav_bidder_pubkey if bid.was_received else bid.nav_offerer_pubkey
        )
        blinding_key_int = self.deriveBlindingKey(privkey, ecdh_pubkey)
        blinding_key_hex = f"{blinding_key_int:064x}"
        if prevout.get("gamma") is None:
            # The HTLC output is watch-only for the redeemer, so listblsctunspent doesn't
            # expose gamma. Recover it from our blinding key + redeem address (address_a,
            # the hashlock branch the output is blinded to).
            nonce = self.rpc_wallet(
                "deriveblsctnonce", [blinding_key_hex, bid.nav_redeem_addr]
            )
            rec = self.rpc_wallet(
                "getblsctrecoverydatawithnonce", [prevout["outid"], nonce]
            )
            prevout["gamma"] = rec["outputs"][0]["gamma"]
        prevout["spending_key"] = self.deriveSpendingKey(
            blinding_key_hex, bid.nav_redeem_addr
        )
        return prevout

    def buildNavRefundPrevout(self, bid, txn, secret_hash, addr_refund_out) -> dict:
        # Decodes funded tx via decodeblsctrawtransaction, finds the HTLC output matching secret_hash,
        # returns {"outid", "amount", "gamma"}. No spending_key — caller must derive and set it.
        prevout = self.getPrevOutInfoFromOffChainTxn(txn, secret_hash)

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        local_privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        ecdh_cpty_pubkey = (
            bid.nav_bidder_pubkey if bid.was_received else bid.nav_offerer_pubkey
        )
        blinding_key_int = self.deriveBlindingKey(local_privkey, ecdh_cpty_pubkey)
        prevout["spending_key"] = self.deriveSpendingKey(
            f"{blinding_key_int:064x}", addr_refund_out
        )
        return prevout

    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        RPC_WALLET_BLANK = -37
        try:
            actual_seedid = self.getWalletSeedID()
        except Exception as e:
            if str(RPC_WALLET_BLANK) in str(e):
                return False
            raise
        return expect_seedid == actual_seedid

    def confirmWalletMinimumBalance(self) -> None:
        try:
            fee_rate, _ = self.get_fee_rate()
            min_bal = (fee_rate * self.getHTLCSpendTxVSize()) / 1000 * 1.3
            balance = self.getWalletInfo().get("balance", 0.0)
            if balance < min_bal:
                raise ValueError(
                    f"Navio wallet balance ({balance:.8f} NAV) too low to pay redeem fees. "
                    f"Minimum {min_bal:.8f} NAV required."
                )
        except ValueError:
            raise
        except Exception as e:
            self._sc.log.warning(f"could not check NAV balance: {e}")

    def createFakeNonNavHTLCScript(
        self, secret_hash: bytearray, lock_value: int
    ) -> bytearray:
        """
        Create a non-NAV HTLC script with zeroed-out fields,
        excluding the secret hash and lock_value.
        """
        padded_secret_hash = secret_hash.rjust(32, b"\x00")
        lock_value_bytes = lock_value.to_bytes(
            max(1, (lock_value.bit_length() + 7) // 8), byteorder="little"
        )
        fake_script = (
            b"\x00" * 7
            + padded_secret_hash
            + b"\x00" * 25
            + bytes([len(lock_value_bytes)])
            + lock_value_bytes
        )
        return bytearray(fake_script)

    def createFundedHTLCTxn(
        self,
        address_a: str,
        address_b: str,
        hash: bytes,
        locktime: int,
        blinding_key: int,
        amount: int,
    ) -> tuple[str, int]:
        param: dict[str, Any] = {
            "amount": amount,
            "address_a": address_a,
            "address_b": address_b,
            "blinding_key": f"{blinding_key:064x}",
            "hash": hash.hex(),
            "locktime": locktime,
            "timelock_opcode": "cltv",
            "type": "atomic_swap",
        }
        params = [param]
        txn = self.rpc("createblsctrawtransaction", [[], params])

        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, True])
        txjs = self.rpc_wallet("decodeblsctrawtransaction", [txn_funded])

        vout_index = None
        for index, output in enumerate(txjs["outputs"]):
            if self._isHTLCScript(output["scriptPubKey"]):
                vout_index = index
                break
        if vout_index is None:
            raise ValueError("Failed to find vout with HTLC script")
        self._log.info(f"vout index is {vout_index}")

        return txn_funded, vout_index

    def createInitiateTxn(
        self, bid_id, bid, locktime, secret_hash, bid_date, use_cursor
    ):
        ensure(
            bid.nav_redeem_addr is not None,
            "NAV ITX redeem address not set; bidder must send nav_redeem_addr in BID",
        )
        nav_addr_redeem = bid.nav_redeem_addr
        nav_addr_refund = self._sc.getReceiveAddressFromPool(
            Coins.NAV, bid_id, TxTypes.ITX_REFUND, use_cursor
        )
        seller_privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        blinding_key = self.deriveBlindingKey(seller_privkey, bid.nav_bidder_pubkey)

        txn, lock_tx_vout = self.createFundedHTLCTxn(
            nav_addr_redeem,
            nav_addr_refund,
            secret_hash,
            locktime,
            blinding_key,
            bid.amount,
        )

        return txn, lock_tx_vout, nav_addr_redeem, nav_addr_refund, blinding_key

    def _createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int,  # amount in navoshis
        script: Optional[bytearray] = None,
        sub_fee: bool = False,
        lock_unspents: bool = True,
    ) -> str:
        del sub_fee
        del lock_unspents

        param: dict[str, Any] = {
            "address": addr_to,
            "amount": amount,
        }
        if script is not None:
            param["script"] = bytes(script).hex()
        params = [param]

        txn = self.rpc("createblsctrawtransaction", [[], params])

        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, True])
        return txn_funded

    def createNavRedeemTxn(
        self,
        bid,
        for_txn_type: str = "participate",
        addr_redeem_out=None,
        fee_rate=None,
        cursor=None,
    ) -> str:
        if for_txn_type == "participate":
            nav_txn = bid.participate_tx
            is_ptx = True
            prev_amount = bid.amount_to
        else:
            nav_txn = bid.initiate_tx
            is_ptx = False
            prev_amount = bid.amount
        txn_script = nav_txn.script

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        prevout = self.buildNavRedeemPrevout(bid, nav_txn, privkey, txn_script, is_ptx)

        secret = bid.recovered_secret
        if secret is None:
            secret = self._sc.getContractSecret(bid_date, bid.contract_count)
        ensure(len(secret) == 32, "Bad secret length")

        if self._sc.coin_clients[Coins.NAV]["connection_type"] not in (
            "rpc",
            "electrum",
        ):
            return None

        if fee_rate is None:
            fee_rate, fee_src = self._sc.getFeeRateForCoin(Coins.NAV)

        tx_vsize = self.getHTLCSpendTxVSize()
        tx_fee = (fee_rate * tx_vsize) / 1000

        amount_out = prev_amount - self.make_int(tx_fee, r=1)
        ensure(amount_out > 0, "Amount out <= 0")

        if addr_redeem_out is None:
            addr_redeem_out = self._sc.getReceiveAddressFromPool(
                Coins.NAV,
                bid.bid_id,
                (
                    TxTypes.PTX_REDEEM
                    if for_txn_type == "participate"
                    else TxTypes.ITX_REDEEM
                ),
                cursor,
            )
        assert addr_redeem_out is not None

        # NAV redeem scriptSig pushes the secret then OP_1
        redeem_script = b"\x20" + secret + b"\x51"
        redeem_txn = self.createRedeemTxn(
            prevout, addr_redeem_out, amount_out, redeem_script
        )
        # signBlsct validates internally; NAV prevout fields (outid, spending_key)
        # are incompatible with verifyRawTransaction
        redeem_txn = self.signBlsct(redeem_txn)

        return redeem_txn

    def createNavRefundTxn(
        self,
        txn,
        offer,
        bid,
        txn_script: bytearray,
        addr_refund_out=None,
        tx_type=TxTypes.ITX_REFUND,
        cursor=None,
        secret_hash: bytes | None = None,
    ) -> str:
        prevout = self.buildNavRefundPrevout(bid, txn, secret_hash, addr_refund_out)

        lock_value = DeserialiseNum(txn_script, 64)
        sequence: int = 1
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = lock_value

        fee_rate, fee_src = self._sc.getFeeRateForCoin(Coins.NAV)
        tx_vsize = self.getHTLCSpendTxVSize(False)
        tx_fee = (fee_rate * tx_vsize) / 1000

        amount_out = self.make_int(prevout["amount"], r=1) - self.make_int(tx_fee, r=1)
        if amount_out <= 0:
            raise ValueError("Refund amount out <= 0")

        if addr_refund_out is None:
            addr_refund_out = self._sc.getReceiveAddressFromPool(
                Coins.NAV, bid.bid_id, tx_type, cursor
            )
        ensure(addr_refund_out is not None, "addr_refund_out is null")

        locktime: int = 0
        if offer.lock_type in (
            TxLockTypes.ABS_LOCK_BLOCKS,
            TxLockTypes.ABS_LOCK_TIME,
        ):
            locktime = lock_value

        refund_txn = self.createRefundTxn(
            prevout, addr_refund_out, amount_out, locktime, sequence, txn_script
        )
        # signBlsct validates internally; NAV prevout fields (outid, spending_key)
        # are incompatible with verifyRawTransaction
        refund_txn = self.signBlsct(refund_txn)

        return refund_txn

    def createParticipateTxn(self, bid_id, bid, offer) -> str:
        # Extract secret hash from ITX script and use offerer's nav address as redeem address and bidder's nav address as refund address
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        nav_addr_redeem = bid.nav_redeem_addr
        ensure(
            nav_addr_redeem is not None,
            "NAV redeem address not set; server must send nav_redeem_addr in BID_ACCEPT",
        )
        nav_addr_refund = self._sc.getReceiveAddressFromPool(
            Coins.NAV, bid_id, TxTypes.PTX_REFUND, None
        )

        # Derive blinding key via ECDH (bidder_privkey, offerer_pubkey)
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        bidder_privkey = self._sc.getContractPrivkey(bid_date, bid.contract_count)
        lock_value = self.getLockValue(offer, is_initiate=False)
        blinding_key = self.deriveBlindingKey(bidder_privkey, bid.nav_offerer_pubkey)
        # Create funded PTX and PTX refund txn
        txn_funded, vout_index = self.createFundedHTLCTxn(
            nav_addr_redeem,
            nav_addr_refund,
            secret_hash,
            lock_value,
            blinding_key,
            bid.amount_to,
        )
        participate_script = self.createFakeNonNavHTLCScript(secret_hash, lock_value)
        refund_txn = self._sc.createRefundTxn(
            Coins.NAV,
            txn_funded,
            offer,
            bid,
            participate_script,
            addr_refund_out=nav_addr_refund,
            secret_hash=secret_hash,
            tx_type=TxTypes.PTX_REFUND,
        )
        bid.participate_txn_refund = bytes.fromhex(refund_txn)

        # Sign PTX and get the txid
        txn_signed = self.signBlsct(txn_funded)
        txjs = self.rpc("decoderawtransaction", [txn_signed])
        txid = txjs["txid"]

        chain_height = self.getChainHeight()

        # Update bid participate_tx fields
        self._sc.addParticipateTxn(
            bid_id, bid, Coins.NAV, txid, vout_index, chain_height
        )
        bid.participate_tx.script = participate_script
        bid.participate_tx.tx_data = bytes.fromhex(txn_signed)
        prevout_info = self.getPrevOutInfoFromOffChainTxn(txn_funded, secret_hash)
        bid.participate_tx.txid = bytes.fromhex(prevout_info["outid"])

        return txn_signed

    def createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int,
        sub_fee: bool = False,
        lock_unspents: bool = True,
    ) -> str:
        return self._createRawFundedTransaction(
            addr_to, amount, None, sub_fee, lock_unspents
        )

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self._createRawFundedTransaction(addr_to, amount)
        return self.rpc_wallet("signblsctrawtransaction", [txn_funded])

    def createRedeemTxn(
        self,
        prevout: PrevOutInfoWithSpendingKey,  # amount is in NAV
        output_addr: str,
        output_value: int,  # in Navoshis
        txn_script: bytes | None = None,
    ) -> str:
        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": self.make_int(prevout["amount"]),  # NAV to Navoshis
            "gamma": prevout["gamma"],
            "spending_key": prevout["spending_key"],
            "scriptSig": txn_script.hex(),
        }
        out_params: dict[str, Any] = {
            "amount": output_value,  # amount is in Navoshis
            "address": output_addr,
        }
        params = [[in_params], [out_params]]
        txn = self.rpc("createblsctrawtransaction", params)

        fee = self.make_int(prevout["amount"], r=1) - output_value
        try:
            txn_funded = self.rpc_wallet(
                "fundblsctrawtransaction", [txn, None, False, fee]
            )
        except Exception as e:
            if "Insufficient funds" in str(e):
                raise TemporaryError(str(e))
            raise

        return txn_funded

    def createRefundTxn(
        self,
        prevout: PrevOutInfoWithSpendingKey,  # amount is in NAV
        output_addr: str,
        output_value: int,  # in Navoshis
        locktime: int,
        sequence: int,
        txn_script: bytes | None = None,
    ) -> str:
        del txn_script
        # For ABS lock types, locktime holds the CLTV value; for SEQUENCE types, sequence does.
        nav_locktime = locktime if locktime != 0 else sequence

        in_params: dict[str, Any] = {
            "outid": prevout["outid"],
            "value": self.make_int(prevout["amount"]),  # NAV to Navoshis
            "gamma": prevout["gamma"],
            "spending_key": prevout["spending_key"],
            "scriptSig": "00",  # select else path
            "sequence": nav_locktime,  # CLTV requires nSequence == script locktime
        }
        out_params: dict[str, Any] = {
            "amount": output_value,  # amount is in Navoshis
            "address": output_addr,
        }
        params = [[in_params], [out_params]]
        txn = self.rpc("createblsctrawtransaction", params)

        fee = self.make_int(prevout["amount"], r=1) - output_value
        txn_funded = self.rpc_wallet("fundblsctrawtransaction", [txn, None, False, fee])

        return txn_funded

    def deriveBLSKey(self, evkey, key_path_base) -> bytes:
        BLS_GROUP_ORDER = (
            0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
        )
        parent_path = key_path_base.rpartition("/")[0]
        nonce = 1
        while True:
            key_path = "{}/{}".format(parent_path, nonce)
            extkey = self._sc.callcoinrpc(
                Coins.PART, "extkey", ["info", evkey, key_path]
            )["key_info"]["result"]
            privkey = decodeWif(
                self._sc.callcoinrpc(Coins.PART, "extkey", ["info", extkey])[
                    "key_info"
                ]["privkey"]
            )
            i = b2i(privkey) % BLS_GROUP_ORDER
            if i != 0:
                return i.to_bytes(32, "big")
            nonce += 1
            if nonce > 0x7FFFFFFF:
                raise ValueError("deriveBLSKey failed")

    def deriveBlindingKey(self, privkey: bytes, pubkey: bytes) -> int:
        """Derive a blinding key via ECDH: SHA256(ECDH(privkey, pubkey))."""

        ecdh_secret = PrivateKey(privkey).ecdh(pubkey)
        blinding_key_bytes = sha256(ecdh_secret)
        return int.from_bytes(blinding_key_bytes, "big")

    def deriveSpendingKey(self, blinding_key_hex: str, address: str) -> str:
        """Derive the private spending key for a BLSCT HTLC output.
        Uses rpc_wallet because the address must be owned by this wallet."""
        return self.rpc_wallet("deriveblsctspendingkey", [blinding_key_hex, address])

    def describeTx(self, tx_hex: str):
        # tx_hex is expected to be sigined
        # for txs before signing, use decodeblsctrawtransaction
        return self.rpc("decoderawtransaction", [tx_hex])

    def detectNavItxRefund(self, bid) -> bool:
        # NAV ITX may be refunded while waiting for PTX confirmation.
        # BLSCT outputs have no visible address, so check via isHTLCTxnSpent (listblsctunspent).
        if (
            bid.initiate_tx is not None
            and bid.getITxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED)
            and self.isHTLCTxnSpent(bid.initiate_tx.script)
        ):
            # The ITX HTLC has two spenders: bidder (redeem) and offerer (refund).
            # A spend is only a refund if this node did not redeem it — otherwise our
            # own in-flight redeem races ahead of the ITX state update (redeem tx
            # published but state still TX_CONFIRMED) and gets mislabelled TX_REFUNDED.
            events = self._sc.getEvents(int(Concepts.BID), bid.bid_id)
            if any(
                e.event_type == int(EventLogTypes.ITX_REDEEM_PUBLISHED) for e in events
            ):
                return False
            self._sc.log.info(
                f"NAV ITx spent (refunded) in SWAP_INITIATED for bid {self._sc.log.id(bid.bid_id)}, marking TX_REFUNDED"
            )
            bid.setITxState(TxStates.TX_REFUNDED)
            return True
        return False

    def extractHTLCLockVal(self, script: bytes, is_nav: bool) -> int:
        if is_nav:
            push_size = script[90]
            locktime_bytes = script[91 : 91 + push_size]
        else:
            push_size = script[64]
            locktime_bytes = script[65 : 65 + push_size]
        return int.from_bytes(locktime_bytes, byteorder="little")

    # Workaround: naviod crashes with getblock verbosity=2 (MoneyRange assertion). Remove once naviod fixes.
    def getBlockWithTxns(self, block_hash: str):
        # naviod crashes with getblock with verbosity 2 (MoneyRange bug),
        # so use getblockheader and return an empty tx list b/c NAV will not use txs there
        header = self.rpc("getblockheader", [block_hash])
        return {
            "hash": header["hash"],
            "previousblockhash": header.get("previousblockhash", ""),
            "time": header["time"],
            "height": header["height"],
            "tx": [],
        }

    def get_fee_rate(self, conf_target: int = 2) -> tuple[float, str]:
        del conf_target
        chain_client_settings = self._sc.getChainClientSettings(
            self.coin_type()
        )  # basicswap.json
        override_feerate = chain_client_settings.get("override_feerate", None)
        if override_feerate:
            self._log.debug(
                f"Fee rate override used for {self.coin_name()}: {override_feerate}"
            )
            return override_feerate, "override_feerate"

        navoshi_per_byte = 125
        navoshi_per_kb = navoshi_per_byte * 1000
        nav_per_kb = navoshi_per_kb * 1e-8

        return nav_per_kb, "default_feerate"

    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        del redeem
        # always using the size of a refund transaction since the size
        # difference between redeem and refund transactions are small
        return 1336

    def getLockValue(self, offer, is_initiate: bool) -> int:
        # Absolute CLTV. The participate (PTX) lock is half the initiate (ITX)
        # duration so the PTX matures first, regardless of block rate.
        duration = offer.lock_value if is_initiate else offer.lock_value // 2
        if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
            return self.getChainHeight() + duration
        # Absolute unix-timestamp CLTV (navio enforces time-based locks via
        # locktime >= LOCKTIME_THRESHOLD vs median-time-past).
        return self._sc.getTime() + duration

    def getNavLockTxHeight(
        self,
        txid,
        dest_address,
        bid_amount,
        rescan_from,
    ):
        """BLSCT-specific lock tx lookup.
        dest_address is the secret_hash hex. lock_val is the NAV CLTV lock block
        height extracted from the fake participate script, used to discriminate
        between UTxOs sharing the same secret_hash (e.g. in test environments
        where the Particl HD wallet reuses the same secret)."""
        del bid_amount, rescan_from, txid
        if not dest_address:
            return None

        secret_hash = dest_address.lower()
        try:
            utxos = self._listBlsctUnspent()
            self._log.debug(
                f"getNavLockTxHeight: {len(utxos)} UTxOs from listblsctunspent, seeking secret_hash={secret_hash}"
            )
            for utxo in utxos:
                utxo_spk = utxo.get("scriptPubKey", "").lower()
                if not self._isHTLCScript(utxo_spk):
                    continue
                spk_bytes = bytes.fromhex(utxo_spk)
                spk_secret_hash = atomic_swap_1.extractScriptSecretHash(spk_bytes).hex()
                spk_lock_val = self.extractHTLCLockVal(spk_bytes, is_nav=True)
                self._log.debug(
                    f"getNavLockTxHeight: HTLC UTxO spk_secret_hash={spk_secret_hash} spk_lock_val={spk_lock_val}"
                )
                if spk_secret_hash == secret_hash:
                    confirmations = utxo.get("confirmations", 0)
                    chain_info = self.rpc("getblockchaininfo")
                    chain_height = chain_info["blocks"]
                    block_height = (
                        max(0, chain_height - confirmations + 1)
                        if confirmations > 0
                        else 0
                    )
                    rv = {
                        "depth": confirmations,
                        "height": block_height,
                        "outid": utxo.get("outid", None) or utxo.get("outputHash", ""),
                        "value": int(round(utxo.get("amount", 0) * 100_000_000)),
                        "lock_val": spk_lock_val,
                    }
                    self._log.info(
                        f"getNavLockTxHeight found HTLC via listblsctunspent: {rv}"
                    )
                    return rv
        except Exception as e:
            self._log.error(f"getNavLockTxHeight listblsctunspent search failed: {e}")

        return None

    def getNewAddress(self, use_segwit: bool, label: str = "swap_receive") -> str:
        del use_segwit
        address: str = self.rpc(
            "getnewaddress",
            [
                label,
                "blsct",
            ],
        )
        return address

    def getPrevOutInfoFromChain(self, secret_hash: bytes) -> PrevOutInfo:
        # Find the on-chain HTLC output by secret_hash via listblsctunspent (replacing
        # the off-chain tx_data_funded path). A NAV swap has only one NAV leg, so the
        # secret_hash uniquely identifies its HTLC output in this wallet.
        for utxo in self._listBlsctUnspent():
            spk = utxo.get("scriptPubKey", "").lower()
            if not self._isHTLCScript(spk):
                continue
            spk_bytes = bytes.fromhex(spk)
            if atomic_swap_1.extractScriptSecretHash(spk_bytes) != secret_hash:
                continue
            return {
                "outid": utxo.get("outid") or utxo.get("outputHash", ""),
                "amount": utxo["amount"],
                # gamma is absent for watch-only HTLC outputs; buildNavRedeemPrevout
                # recovers it from the blinding key when needed.
                "gamma": utxo.get("gamma"),
            }
        raise ValueError(f"No on-chain HTLC output for secret_hash={secret_hash.hex()}")

    def getPrevOutInfoFromOffChainTxn(
        self, txn_hex: str, secret_hash: bytes
    ) -> PrevOutInfo:
        txjs = self.rpc_wallet("decodeblsctrawtransaction", [txn_hex])
        self._log.debug(
            f"getPrevOutInfoFromOffChainTxn: secret_hash={secret_hash.hex()}"
        )
        for output in txjs.get("outputs", []):
            spk = output.get("scriptPubKey", "")
            if not self._isHTLCScript(spk):
                continue
            spk_secret_hash = atomic_swap_1.extractScriptSecretHash(bytes.fromhex(spk))
            self._log.debug(
                f"found HTLC script: spk_secret_hash={spk_secret_hash.hex()}"
            )
            if secret_hash == spk_secret_hash:
                return {
                    "outid": output["outputHash"],
                    "amount": output["amount"],
                    "gamma": output["gamma"],
                }
        raise ValueError(f"No HTLC output found for secret_hash={secret_hash.hex()}")

    def getProofOfFunds(self, amount_for, extra_commit_bytes):
        amount_btc = amount_for / 100_000_000
        additional_commitment = extra_commit_bytes.hex()
        result = self.rpc_wallet(
            "createblsctbalanceproof", [amount_btc, additional_commitment]
        )
        proof_hex = result["proof"]
        return ("blsct_balance_proof", proof_hex, [])

    def getSeedHash(self, seed: bytes) -> bytes:
        return seed

    def getTxLocktime(self, tx_data) -> int:
        # tx_data is the initiate (HTLC) tx for NAV; the BLSCT refund tx can't be
        # deserialised by the BTC parser, so read the CLTV value from the HTLC script.
        return self.extractHTLCLockVal(tx_data.script, is_nav=False)

    def getWalletInfo(self):
        rv = super().getWalletInfo()
        # listblsctunspent returns both wallet outputs (address present) and
        # HTLC watch-only imports (no address). The base getwalletinfo balance
        # counts the imported HTLC outputs, inflating the displayed total.
        confirmed = 0.0
        unconfirmed = 0.0
        try:
            outputs = self.rpc_wallet("listblsctunspent", [0])
            for o in outputs:
                if not o.get("address"):
                    continue
                amount = float(o.get("amount", 0))
                if o.get("confirmations", 0) >= 1:
                    confirmed += amount
                else:
                    unconfirmed += amount
            rv["balance"] = round(confirmed, 8)
            rv["unconfirmed_balance"] = round(unconfirmed, 8)
        except Exception as e:
            self._log.warning(f"NAV getWalletInfo listblsctunspent failed: {e}")
        return rv

    def getWalletSeedID(self) -> str:
        """
        The Navio wallet has been initialized using the root key generated by
        `getWalletKeyBLS(c, 1)` as the seed.
        """
        return self.rpc("getblsctseed")

    def handleSwapParticipating(self, bid_id, bid, coin_from, coin_to) -> bool:
        # NAV HTLC outputs have no visible address; isHTLCTxnSpent polls via listblsctunspent.
        # coin_from == NAV (ITX) / coin_to == NAV (PTX): on a spend, distinguish redeem
        # vs refund. BLSCT hides the preimage on-chain, so infer from this node's own
        # recorded action then its role (each HTLC has exactly two spenders).
        save_bid = False
        if (
            coin_from == Coins.NAV
            and bid.initiate_tx is not None
            and bid.getITxState() < TxStates.TX_REDEEMED
        ):
            if self.isHTLCTxnSpent(bid.initiate_tx.script):
                # ITX spenders: bidder (redeem) and offerer (refund, its own ITX).
                events = self._sc.getEvents(int(Concepts.BID), bid_id)
                i_refunded = any(
                    e.event_type == int(EventLogTypes.ITX_REFUND_PUBLISHED)
                    for e in events
                )
                i_redeemed = any(
                    e.event_type == int(EventLogTypes.ITX_REDEEM_PUBLISHED)
                    for e in events
                )
                if i_refunded:
                    itx_state = TxStates.TX_REFUNDED
                elif i_redeemed:
                    itx_state = TxStates.TX_REDEEMED
                elif bid.was_received:
                    itx_state = (
                        TxStates.TX_REDEEMED
                    )  # offerer's ITX, didn't refund -> bidder redeemed
                else:
                    itx_state = (
                        TxStates.TX_REFUNDED
                    )  # bidder side, didn't redeem -> offerer refunded
                bid.setITxState(itx_state)
                save_bid = True
        elif coin_to == Coins.NAV and bid.getPTxState() < TxStates.TX_REDEEMED:
            if self.isHTLCTxnSpent(bid.participate_tx.script):
                # BLSCT hides the redeem preimage on-chain, so redeem vs refund is
                # inferred from this node's own recorded action, then its role: the
                # PTX has exactly two spenders — the offerer (redeem) and the bidder
                # (refund). If I published neither, the spend is the counterparty's.
                events = self._sc.getEvents(int(Concepts.BID), bid_id)
                i_refunded = any(
                    e.event_type == int(EventLogTypes.PTX_REFUND_PUBLISHED)
                    for e in events
                )
                i_redeemed = any(
                    e.event_type == int(EventLogTypes.PTX_REDEEM_PUBLISHED)
                    for e in events
                )
                if i_refunded:
                    ptx_state = TxStates.TX_REFUNDED
                elif i_redeemed:
                    ptx_state = TxStates.TX_REDEEMED
                elif bid.was_received:
                    ptx_state = (
                        TxStates.TX_REFUNDED
                    )  # offerer didn't redeem -> bidder refunded
                else:
                    ptx_state = (
                        TxStates.TX_REDEEMED
                    )  # bidder didn't refund -> offerer redeemed
                bid.setPTxState(ptx_state)
                save_bid = True
        return save_bid

    def initialiseWallet(self, key_bytes, restore_time: int = -1):
        del restore_time
        key_wif = self.encodeKey(key_bytes)
        try:
            self.rpc_wallet("setblsctseed", [key_wif])
        except Exception as e:
            if "Already have this key" in str(e):
                self._log.info(
                    f"{self.coin_name()} wallet already has the correct BLSCT seed."
                )
            else:
                self._log.debug(f"setblsctseed failed: {e}")
                raise

    def _isHTLCScript(self, script: str) -> bool:
        """
        Determines if a script is a Navio HTLC script.

        OP_IF
            OP_SIZE
            32
            OP_EQUALVERIFY
            OP_SHA256
            <32-byte secret hash>
            OP_EQUALVERIFY
            <48-byte address_a>
        OP_ELSE
            <1-4 byte locktime>
            OP_CHECKLOCKTIMEVERIFY
            OP_DROP
            <48-byte address_b>
        OP_ENDIF
        OP_BLSCHECKSIG

        >>> hex = "6382012088a820b812e53d1bd15a928803df44ab86c6a286d9a3d6625a3738f"
        >>> hex += "bed32d89a4c7c178830a7b9a59a0e305eef4f756909e6fa107091fc6d2b2743"
        >>> hex += "3d110d5d3c95ff987a0182bbd2e19897ee71af0466006cc2755467042c688b6"
        >>> hex += "9b17530a7b9a59a0e305eef4f756909e6fa107091fc6d2b27433d110d5d3c95"
        >>> hex += "ff987a0182bbd2e19897ee71af0466006cc2755468b3"
        >>> nav = NAVInterface()
        >>> nav._isHTLCScript(hex)
        True
        >>> hex = "6382012088a8206756e66c48945a6851790e94fed56b86ec9d1e05116d4d289bf"
        >>> hex += "62f858389c3998830a6c43cded614e403d715cd7f28a57736214937dd811bd7e2927eed4cd"
        >>> hex += "904ee8df0066923c7dc021a36e94fa6f8fa21e36703710040b17530a769dfbee940c4f72c1"
        >>> hex += "29b5a315822dabda7932f5f12b8d1c56d2335544995504af3e11446a3b544cb6ec51403377"
        >>> hex += "33468b3"
        >>> nav._isHTLCScript(hex)
        True
        >>> nav._isHTLCScript("76a91488ac")
        False
        """
        script = script.lower()
        pos = 0

        def consume(exp: str) -> bool:
            nonlocal pos
            if pos + len(exp) > len(script):
                return False
            if script[pos : pos + len(exp)] == exp:
                pos += len(exp)
                return True
            else:
                return False

        def skip(n: int) -> bool:
            nonlocal pos
            pos = pos + n * 2
            return pos <= len(script)

        def consume_locktime() -> bool:
            push_size = int(script[pos : pos + 2], 16)
            return skip(push_size + 1)

        def consume_timelock_op() -> bool:
            nonlocal pos
            if pos + 2 > len(script):
                return False
            if script[pos : pos + 2] in ("b1", "b2"):
                pos += 2
                return True
            return False

        def all_consumed() -> bool:
            return pos == len(script)

        return (
            # 63 (OP_IF)
            # 82 (OP_SIZE)
            # 01 20 (32 bytes)
            # 88 (OP_EQUALVERIFY)
            # a8 (OP_SHA256)
            # 20 (Data Length 32)
            consume("6382012088a820")
            # secret hash
            and skip(32)
            # 88 (OP_EQUALVERIFY)
            # 30 (Data Length 48)
            and consume("8830")
            # address_a
            and skip(48)
            # 67 (OP_ELSE)
            and consume("67")
            # 1-4 byte locktime
            and consume_locktime()
            # b1 (OP_CHECKLOCKTIMEVERIFY) or b2 (OP_CHECKSEQUENCEVERIFY)
            # 75 (OP_DROP)
            # 30 (Data Length 48)
            and consume_timelock_op()
            and consume("7530")
            # address_b
            and skip(48)
            # 68 (OP_ENDIF)
            # b3 (OP_BLSCHECKSIG)
            and consume("68b3")
            # should have read everything
            and all_consumed()
        )

    def isHTLCTxnSpent(self, script: bytes) -> bool:
        secret_hash = atomic_swap_1.extractScriptSecretHash(script)
        locktime = self.extractHTLCLockVal(script, is_nav=False)
        self._log.debug(
            f"isHTLCTxnSpent: secret_hash={secret_hash.hex()} {locktime=} script={script.hex()}"
        )
        try:
            utxos = self._listBlsctUnspent()
            for utxo in utxos:
                spk = utxo.get("scriptPubKey", "")
                if not self._isHTLCScript(spk):
                    continue
                spk_bytes = bytes.fromhex(spk)
                spk_secret_hash = atomic_swap_1.extractScriptSecretHash(spk_bytes)
                if secret_hash == spk_secret_hash:
                    # UTxO appears in wallet — verify it's still in the confirmed UTXO set.
                    # listblsctunspent on watchonly wallets does not remove a UTxO when it
                    # is spent by an external wallet. gettxout queries the consensus UTXO
                    # set directly (wallet-independent, mempool-independent) and returns an
                    # empty result once the output is confirmed-spent.
                    outid = utxo.get("outid")
                    if outid:
                        result = self.rpc("gettxout", [outid])
                        if result:
                            # Still in consensus UTXO set → genuinely unspent
                            self._log.debug(
                                f"isHTLCTxnSpent: outid={outid[:16]}... in UTXO set (unspent)"
                            )
                            return False
                        else:
                            # Empty result → confirmed spent
                            self._log.debug(
                                f"isHTLCTxnSpent: outid={outid[:16]}... not in UTXO set (spent)"
                            )
                            return True
                    # No outid available — fall back to listblsctunspent result
                    self._log.debug(
                        f"isHTLCTxnSpent: found matching utxo, not spent yet: {utxo=}"
                    )
                    return False
            self._log.debug(f"isHTLCTxnSpent: {secret_hash.hex()} is spent")
            return True

        except Exception as e:
            self._log.error(f"Failed to check if HTLC txn is spent: {e}")
        return False

    def isInitiateTxnOnChain(self, bid) -> dict:
        # Search by secret hash via listblsctunspent; BLSCT outputs have no visible address
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        return self.getNavLockTxHeight(
            bid.initiate_tx.txid,
            secret_hash.hex(),
            bid.amount,
            bid.chain_a_height_start,
        )

    def isTxNonFinalError(self, err_str: str) -> bool:
        # non-final-input: refund submitted before CLTV locktime expires
        # bad-inputs-unknown: refund input not in UTXO set; PTX still in mempool (BLSCT outputs unspendable until confirmed)
        return (
            "non-final-input" in err_str
            or "bad-input-unknown" in err_str
            or "bad-inputs-unknown" in err_str
            or "'code': 25" in err_str
        )

    def _listBlsctUnspent(self) -> list:
        return self.rpc_wallet("listblsctunspent", [0])

    def processNavHtlcPreimage(self, msg) -> None:
        msg_bytes = self._sc.getSmsgMsgBytes(msg)
        ensure(
            len(msg_bytes) == 60, "Invalid NAV_HTLC_PREIMAGE length"
        )  # bid_id(28) + secret(32)
        bid_id = msg_bytes[:28]
        secret = msg_bytes[28:60]

        self._sc.log.info(
            f"Received NAV HTLC preimage for bid {self._sc.log.id(bid_id)}"
        )
        if bid_id not in self._sc.swaps_in_progress:
            self._sc.log.warning(
                f"processNavHtlcPreimage: bid {self._sc.log.id(bid_id)} not in progress"
            )
            return

        bid = self._sc.swaps_in_progress[bid_id][0]
        if bid.was_received:
            self._sc.log.debug(
                f"processNavHtlcPreimage: offerer ignoring own preimage for bid {self._sc.log.id(bid_id)}"
            )
            return

        bid.recovered_secret = secret
        # Offerer spent the NAV PTx (using this preimage) — mark it redeemed
        if bid.participate_tx:
            bid.setPTxState(TxStates.TX_REDEEMED)
        delay = self._sc.get_short_delay_event_seconds()
        self._sc.log.info(
            f"Redeeming ITX for bid {self._sc.log.id(bid_id)} in {delay} seconds."
        )
        self._sc.createAction(delay, ActionTypes.REDEEM_ITX, bid_id)
        self._sc.saveBid(bid_id, bid)

    def publishPtx(self, bid_id, bid, txn) -> None:
        txid = self.publishTx(bytes.fromhex(txn))
        self._sc.log.debug(
            f"Submitted participate tx {self._sc.logIDT(txid)} to {self.coin_name()} chain for bid {self._sc.log.id(bid_id)}"
        )
        bid.setPTxState(TxStates.TX_SENT)
        self._sc.logEvent(
            Concepts.BID, bid.bid_id, EventLogTypes.PTX_PUBLISHED, "", None
        )

    def publishTx(self, tx: bytes):
        try:
            res = self.rpc("sendrawtransaction", [tx.hex()])
        except Exception as e:
            if self.isTxNonFinalError(str(e)):
                raise TemporaryError(str(e))
            raise
        return res

    def sendNavHtlcPreimage(self, bid_id, bid, offer) -> None:
        # NAV uses BLSCT (private txns) so bidder can't observe the secret from the chain directly.
        # Offerer explicitly sends the secret to bidder so bidder can redeem the ITX (non-NAV side).
        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        secret = self._sc.getContractSecret(bid_date, bid.contract_count)
        payload_hex = (
            str.format("{:02x}", MessageTypes.NAV_HTLC_PREIMAGE)
            + bid_id.hex()
            + secret.hex()
        )
        self._sc.sendMessage(
            offer.addr_from,
            bid.bid_addr,
            payload_hex,
            self._sc.SMSG_SECONDS_IN_HOUR,
            None,
        )

    def signBlsct(self, txn):
        signed_txn = self.rpc("signblsctrawtransaction", [txn])
        return signed_txn

    def tryToGetNavPtxInfoFromChain(self, bid, participate_txid):
        # Offerer detects the bidder's NAV PTX. It has no PTX script, so take the
        # secret_hash from its own ITX and scan listblsctunspent by secret_hash alone:
        # the bidder chose the PTX lock_val, so it's unknown here (lock_val only
        # disambiguates same-hash outputs in test envs; the offerer's NAV wallet holds
        # just this PTX for the hash). Read the lock_val from the matched output and
        # store the fake PTX script so the redeem path can extract it later.
        if bid.initiate_tx is None or bid.initiate_tx.script is None:
            return None
        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        found = self.getNavLockTxHeight(
            participate_txid,
            secret_hash.hex(),
            bid.amount_to,
            bid.chain_b_height_start,
        )
        if found is not None and bid.participate_tx is None:
            bid.participate_tx = SwapTx(
                bid_id=bid.bid_id,
                tx_type=TxTypes.PTX,
                script=self.createFakeNonNavHTLCScript(secret_hash, found["lock_val"]),
            )
        return found

    def updatePtxOutidAndState(self, bid, coin_to, found) -> bool:
        save_bid = False
        if bid.participate_tx.conf != found["depth"]:
            save_bid = True

        # NAV txid changes after aggregation — track by outid instead
        # Offerer: set txid from outid once known (bidder already has it from createParticipateTxn)
        if not bid.was_sent and bid.participate_tx.txid is None:
            outid = found.get("outid", None)
            if outid:
                bid.participate_tx.txid = bytes.fromhex(outid)
                save_bid = True

        if (
            bid.participate_tx.conf is None
            and bid.participate_tx.state != TxStates.TX_SENT
        ):
            bid.participate_tx.chain_height = self._sc.setLastHeightCheckedStart(
                coin_to, found["height"]
            )
            if (
                bid.participate_tx.state is None
                or bid.participate_tx.state < TxStates.TX_SENT
            ):
                bid.setPTxState(TxStates.TX_SENT)
            save_bid = True
        return save_bid

    def verifyProofOfFunds(self, address, signature, utxos, extra_commit_bytes):
        additional_commitment = extra_commit_bytes.hex()
        result = self.rpc("verifyblsctbalanceproof", [signature, additional_commitment])
        if not result.get("valid", False):
            raise ValueError("BLSCT balance proof invalid")
        min_amount_btc = result["min_amount"]
        return int(round(min_amount_btc * 100_000_000))

    def verifyRawTransaction(self, txn, prevouts):
        # BLSCT (Navio) transactions can't be validated through the standard
        # verifyrawtransaction/testmempoolaccept path (confidential inputs and
        # scripts), so treat NAV inputs as valid here; the transaction is still
        # checked by the daemon when broadcast (publishTx / sendrawtransaction).
        del txn, prevouts
        return {
            "inputs_valid": True,
            "validscripts": 1,
        }
