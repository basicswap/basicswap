"""Two-chain value actions for a persisted HNS/BTC seller-first trade.

Network messaging and bid states remain BasicSwap's responsibility. This
controller performs only the value boundary: verify the peer's confirmed lock
before funding, persist a Bitcoin signed intent before broadcast, and use the
HNS wallet bridge's durable settlement operations for the Handshake leg.
"""

import hashlib
import time
from dataclasses import dataclass

from .btc_contract import (
    BtcHtlcContract,
    BtcSpendObservation,
    PreparedBtcTransaction,
)
from .trade_record import (
    MAKER,
    TAKER,
    bind_lock,
    bind_preimage,
    bind_prepared_btc_tx,
)


@dataclass(frozen=True)
class ObservedSwapSpend:
    branch: str
    txid: bytes
    confirmations: int
    preimage: bytes | None
    btc_height: int | None = None
    btc_block_hash: bytes | None = None


class HnsBtcSettlement:
    MINIMUM_MAKER_REDEEM_MARGIN_SECONDS = 30 * 60

    def __init__(
        self,
        record,
        terms,
        btc_interface,
        hns_bridge,
        hns_node,
        hns_network,
        persist_record,
    ):
        if record.role not in (MAKER, TAKER):
            raise ValueError("invalid HNS/BTC trade role")
        if (
            record.offer_id != terms.offer_id
            or record.bid_id != terms.bid_id
            or record.session_nonce != terms.session_nonce
            or record.terms_commitment is None
            or record.session_id != terms.hns_wallet_terms().session_id()
            or record.hns_descriptor != terms.hns_descriptor.encode()
            or record.btc_contract_script != terms.btc_contract_script
            or record.terms_commitment
            != terms.commitment(
                int(time.time()),
                terms.hns_descriptor.network_magic,
                terms.hns_descriptor.genesis,
            )
        ):
            raise ValueError("HNS/BTC settlement terms differ from durable record")
        if not callable(persist_record):
            raise TypeError("HNS/BTC settlement requires a persistence callback")
        self.record = record
        self.terms = terms
        self.btc = BtcHtlcContract(btc_interface, terms)
        self.hns_bridge = hns_bridge
        self.hns_node = hns_node
        self.hns_network = hns_network
        self.persist_record = persist_record

    @property
    def own_coin(self):
        return "hns" if self.terms.hns_first == (self.record.role == MAKER) else "btc"

    @property
    def peer_coin(self):
        return "btc" if self.own_coin == "hns" else "hns"

    def _chain_now(self):
        binding = self.hns_node.bound_snapshot(self.hns_network)
        if not self.hns_node.sync_ready(self.hns_network, binding):
            raise ValueError("HSRD is not synchronized to the wallet chain tip")
        hns_median = binding.tip["median_time_past"]
        btc_info = self.btc.ci.rpc("getblockchaininfo")
        btc_median = btc_info.get("mediantime") if isinstance(btc_info, dict) else None
        if type(hns_median) is not int or type(btc_median) is not int:
            raise ValueError("swap chain median time is unavailable")
        return max(int(time.time()), hns_median, btc_median)

    def _funding_now(self):
        now = self._chain_now()
        self.terms.validate(
            now,
            self.terms.hns_descriptor.network_magic,
            self.terms.hns_descriptor.genesis,
        )
        return now

    def _outpoint(self, coin):
        if coin == "hns":
            txid, vout = self.record.hns_lock_txid, 0
        elif coin == "btc":
            txid, vout = self.record.btc_lock_txid, self.record.btc_lock_vout
        else:
            raise ValueError("invalid HNS/BTC chain")
        if txid is None or vout is None:
            raise ValueError("HNS/BTC lock outpoint is missing")
        return txid, vout

    def verify_lock(self, coin):
        txid, vout = self._outpoint(coin)
        if coin == "hns":
            return self.hns_bridge.verify_lock(
                self.terms.hns_wallet_terms(),
                txid,
                self.terms.minimum_hns_confirmations,
            )
        return (
            self.btc.verify_lock(txid, vout, self.terms.minimum_btc_confirmations)
            is not None
        )

    def _prepared_btc(self, field):
        raw = getattr(self.record, field)
        if raw is None:
            return None
        tx = self.btc.ci.loadTx(raw)
        tx.rehash()
        return PreparedBtcTransaction(
            bytes.fromhex(tx.hash),
            raw,
            self.record.btc_lock_vout if field == "btc_funding_tx" else None,
        )

    def fund_owned_lock(self, maximum_hns_fee):
        """Fund exactly once; the taker first verifies the maker's lock."""
        now = self._funding_now()
        if self.record.role == TAKER and not self.verify_lock(self.peer_coin):
            raise ValueError("first HNS/BTC lock is not sufficiently confirmed")
        if self.own_coin == "hns":
            txid, vout = self.hns_bridge.fund(
                self.terms.hns_wallet_terms(), maximum_hns_fee
            )
            bind_lock(self.record, "hns", txid, vout)
            self.persist_record(self.record)
            return txid, vout

        prepared = self._prepared_btc("btc_funding_tx")
        if prepared is None:
            prepared = self.btc.prepare_funding(
                now,
                self.terms.hns_descriptor.network_magic,
                self.terms.hns_descriptor.genesis,
            )
            bind_prepared_btc_tx(self.record, "btc_funding_tx", prepared)
            self.persist_record(self.record)
        self.btc.broadcast(prepared)
        return prepared.txid, prepared.contract_vout

    def redeem_peer_lock(
        self,
        maximum_hns_fee,
        observed_own_spend=None,
        btc_private_key=None,
        btc_destination=None,
        btc_fee_rate=None,
        maximum_btc_fee=None,
    ):
        """Reveal the persisted secret only after the peer's lock confirms."""
        if self.record.role == MAKER:
            now = self._chain_now()
            _, second_deadline = self.terms.validate(
                now,
                self.terms.hns_descriptor.network_magic,
                self.terms.hns_descriptor.genesis,
                require_funding_window=False,
            )
            if second_deadline <= now + self.MINIMUM_MAKER_REDEEM_MARGIN_SECONDS:
                raise ValueError("second HNS/BTC lock is too close to refund")
        if self.record.role == TAKER:
            minimum = (
                self.terms.minimum_hns_confirmations
                if self.own_coin == "hns"
                else self.terms.minimum_btc_confirmations
            )
            if (
                not isinstance(observed_own_spend, ObservedSwapSpend)
                or observed_own_spend.branch != "redeem"
                or observed_own_spend.preimage != self.record.secret_preimage
                or observed_own_spend.confirmations < minimum
            ):
                raise ValueError("taker has no confirmed preimage reveal")
            if self.own_coin == "btc":
                self.btc.confirm_spend_observation(
                    BtcSpendObservation(
                        observed_own_spend.txid,
                        observed_own_spend.branch,
                        observed_own_spend.preimage,
                        observed_own_spend.btc_height,
                        observed_own_spend.btc_block_hash,
                    ),
                    self.record.btc_lock_txid,
                    self.record.btc_lock_vout,
                    minimum,
                )
            else:
                current = self.hns_bridge.observe_spend(
                    self.terms.hns_wallet_terms(),
                    self.record.hns_lock_txid,
                    minimum,
                )
                if (
                    current is None
                    or current[0] != "redeem"
                    or current[1] != observed_own_spend.txid
                    or current[2] < minimum
                    or current[3] != observed_own_spend.preimage
                ):
                    raise ValueError("HNS preimage reveal is no longer confirmed")
        if self.record.secret_preimage is None:
            raise ValueError("HNS/BTC preimage is not persisted")
        if hashlib.sha256(self.record.secret_preimage).digest() != (
            self.terms.hns_descriptor.hashlock
        ):
            raise ValueError("HNS/BTC persisted preimage is invalid")
        if not self.verify_lock(self.peer_coin):
            raise ValueError("peer HNS/BTC lock is not sufficiently confirmed")
        txid, vout = self._outpoint(self.peer_coin)
        if self.peer_coin == "hns":
            return self.hns_bridge.redeem(
                self.terms.hns_wallet_terms(),
                txid,
                self.terms.minimum_hns_confirmations,
                self.record.secret_preimage,
                maximum_hns_fee,
            )
        prepared = self._prepared_btc("btc_redeem_tx")
        if prepared is None:
            prepared = self.btc.prepare_spend(
                txid,
                vout,
                btc_destination,
                btc_private_key,
                btc_fee_rate,
                maximum_btc_fee,
                preimage=self.record.secret_preimage,
            )
            bind_prepared_btc_tx(self.record, "btc_redeem_tx", prepared)
            self.persist_record(self.record)
        return self.btc.broadcast(prepared)

    def observe_own_lock_spend(self, btc_first_height=None, btc_last_height=None):
        """Recover a taker preimage only from a confirmed contract witness."""
        txid, vout = self._outpoint(self.own_coin)
        if self.own_coin == "hns":
            result = self.hns_bridge.observe_spend(
                self.terms.hns_wallet_terms(),
                txid,
                self.terms.minimum_hns_confirmations,
            )
            if result is None:
                return None
            branch, spend_txid, confirmed, preimage = result
            if confirmed < self.terms.minimum_hns_confirmations:
                return None
            observed = ObservedSwapSpend(branch, spend_txid, confirmed, preimage)
        else:
            if btc_first_height is None or btc_last_height is None:
                raise ValueError("Bitcoin spend scan range is required")
            result = self.btc.scan_confirmed_spend(
                txid,
                vout,
                btc_first_height,
                btc_last_height,
                self.terms.minimum_btc_confirmations,
            )
            if result is None:
                return None
            tip_height = self.btc.ci.rpc("getblockcount")
            observed = ObservedSwapSpend(
                result.branch,
                result.txid,
                tip_height - result.block_height + 1,
                result.preimage,
                result.block_height,
                result.block_hash,
            )
        if observed.branch == "redeem":
            bind_preimage(self.record, observed.preimage)
            self.persist_record(self.record)
        return observed

    def scan_own_btc_lock_spend(self, first_height, max_blocks=100):
        """Advance a durable Bitcoin cursor only across one stable chain span.

        Stop immediately before a discovered spend so the next run can rebuild
        and recheck its confirmed witness after a restart or reorganization.
        """
        if self.own_coin != "btc":
            raise ValueError("the owned HNS/BTC lock is not on Bitcoin")
        if type(first_height) is not int or first_height < 0:
            raise ValueError("invalid Bitcoin spend scan start")
        if type(max_blocks) is not int or not 1 <= max_blocks <= 100:
            raise ValueError("invalid Bitcoin spend scan size")
        txid, vout = self._outpoint("btc")
        height = self.record.btc_scan_height
        anchor = self.record.btc_scan_anchor
        if (height is None) != (anchor is None):
            raise ValueError("incomplete Bitcoin spend scan cursor")
        if height is not None:
            if (
                type(height) is not int
                or height < first_height
                or not isinstance(anchor, bytes)
                or len(anchor) != 32
            ):
                raise ValueError("invalid Bitcoin spend scan cursor")
            try:
                current_anchor = self.btc.ci.rpc("getblockhash", [height])
            except Exception:  # noqa: BLE001
                current_anchor = None
            if current_anchor != anchor.hex():
                self.record.btc_scan_height = None
                self.record.btc_scan_anchor = None
                self.persist_record(self.record)
                height = None
        tip_height = self.btc.ci.rpc("getblockcount")
        if type(tip_height) is not int or tip_height < 0:
            raise ValueError("invalid Bitcoin chain height")
        mature_height = tip_height - self.terms.minimum_btc_confirmations + 1
        scan_first = first_height if height is None else height + 1
        if scan_first > mature_height:
            return None
        scan_last = min(mature_height, scan_first + max_blocks - 1)
        end_hash = self.btc.ci.rpc("getblockhash", [scan_last])
        if not isinstance(end_hash, str) or len(end_hash) != 64:
            raise ValueError("invalid Bitcoin spend scan anchor")
        result = self.btc.scan_confirmed_spend(
            txid,
            vout,
            scan_first,
            scan_last,
            self.terms.minimum_btc_confirmations,
        )
        if self.btc.ci.rpc("getblockhash", [scan_last]) != end_hash:
            raise ValueError("Bitcoin chain changed during spend scan")
        if result is None:
            self.record.btc_scan_height = scan_last
            self.record.btc_scan_anchor = bytes.fromhex(end_hash)
            self.persist_record(self.record)
            return None
        if result.block_height > scan_first:
            prior_height = result.block_height - 1
            prior_hash = self.btc.ci.rpc("getblockhash", [prior_height])
            if self.btc.ci.rpc("getblockhash", [scan_last]) != end_hash:
                raise ValueError("Bitcoin chain changed during spend scan")
            self.record.btc_scan_height = prior_height
            self.record.btc_scan_anchor = bytes.fromhex(prior_hash)
        if result.branch == "redeem":
            bind_preimage(self.record, result.preimage)
        self.persist_record(self.record)
        return ObservedSwapSpend(
            result.branch,
            result.txid,
            tip_height - result.block_height + 1,
            result.preimage,
            result.block_height,
            result.block_hash,
        )

    def refund_owned_lock(
        self,
        maximum_hns_fee,
        btc_private_key=None,
        btc_destination=None,
        btc_fee_rate=None,
        maximum_btc_fee=None,
    ):
        """Refund only the local lock after its chain's native timelock."""
        txid, vout = self._outpoint(self.own_coin)
        if self.own_coin == "hns":
            return self.hns_bridge.refund(
                self.terms.hns_wallet_terms(),
                txid,
                self.terms.minimum_hns_confirmations,
                maximum_hns_fee,
            )
        prepared = self._prepared_btc("btc_refund_tx")
        if prepared is None:
            prepared = self.btc.prepare_spend(
                txid,
                vout,
                btc_destination,
                btc_private_key,
                btc_fee_rate,
                maximum_btc_fee,
            )
            bind_prepared_btc_tx(self.record, "btc_refund_tx", prepared)
            self.persist_record(self.record)
        return self.btc.broadcast(prepared)
