"""Bitcoin P2WSH leg for the private HNS/BTC seller-first protocol.

The Bitcoin Core wallet funds a native witness output. Its contract spend is
signed with a dedicated swap key; the wallet does not need to import the HTLC
or hold the counterparty's key. Callers persist prepared transactions before
broadcast so a restart can rebroadcast the same bytes without double funding.
"""

import hashlib
from dataclasses import dataclass
from decimal import Decimal

from coincurve import PrivateKey

from basicswap.contrib.test_framework import segwit_addr
from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from basicswap.util import b2i
from basicswap.util.crypto import hash160

from .swap_terms import _parse_btc_contract_script


def _hex32(value, name):
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError(f"invalid {name}")
    return value.hex()


def _satoshis(value):
    amount = Decimal(str(value)) * 100_000_000
    if not amount.is_finite() or amount != amount.to_integral_value():
        raise ValueError("invalid Bitcoin output value")
    return int(amount)


def contract_script_pubkey(contract_script):
    _parse_btc_contract_script(contract_script)
    return b"\x00\x20" + hashlib.sha256(contract_script).digest()


@dataclass(frozen=True)
class PreparedBtcTransaction:
    txid: bytes
    raw: bytes
    contract_vout: int | None = None


@dataclass(frozen=True)
class BtcLockObservation:
    confirmations: int
    funding_height: int
    tip_hash: bytes


@dataclass(frozen=True)
class BtcSpendObservation:
    txid: bytes
    branch: str
    preimage: bytes | None
    block_height: int
    block_hash: bytes


class BtcHtlcContract:
    MAX_REPLAY_SCAN_BLOCKS = 1000

    def __init__(self, coin_interface, terms, *, scan_start_height=None):
        if scan_start_height is not None and (
            type(scan_start_height) is not int or scan_start_height < 0
        ):
            raise ValueError("invalid Bitcoin replay scan start")
        self.ci = coin_interface
        self.terms = terms
        self.scan_start_height = scan_start_height
        self.script = terms.btc_contract_script
        self.hashlock, self.receiver_hash, self.refund_time, self.refund_hash = (
            _parse_btc_contract_script(self.script)
        )
        if self.hashlock != terms.hns_descriptor.hashlock:
            raise ValueError("Bitcoin and Handshake hashlocks differ")
        self.script_pubkey = contract_script_pubkey(self.script)

    def address(self):
        result = segwit_addr.encode(
            self.ci.chainparams_network()["hrp"],
            0,
            self.script_pubkey[2:],
        )
        if result is None:
            raise ValueError("invalid Bitcoin contract address")
        return result

    def prepare_funding(self, now_unix, expected_hns_magic, expected_hns_genesis):
        """Prepare a wallet signed lock; persist the result before publishing."""
        chain_info = self.ci.rpc("getblockchaininfo")
        median_time = (
            chain_info.get("mediantime") if isinstance(chain_info, dict) else None
        )
        if type(median_time) is not int:
            raise ValueError("Bitcoin median time is unavailable")
        self.terms.validate(
            max(now_unix, median_time), expected_hns_magic, expected_hns_genesis
        )
        funded = self.ci.createRawFundedTransaction(
            self.address(), self.terms.btc_amount, lock_unspents=True
        )
        signed = self.ci.signTxWithWallet(bytes.fromhex(funded))
        tx = self.ci.loadTx(signed)
        matching = [
            n
            for n, output in enumerate(tx.vout)
            if output.scriptPubKey == self.script_pubkey
            and output.nValue == self.terms.btc_amount
        ]
        if len(matching) != 1:
            raise ValueError("Bitcoin funded lock output mismatch")
        tx.rehash()
        return PreparedBtcTransaction(bytes.fromhex(tx.hash), signed, matching[0])

    def broadcast(self, prepared):
        if not isinstance(prepared, PreparedBtcTransaction):
            raise TypeError("invalid prepared Bitcoin transaction")
        tx = self.ci.loadTx(prepared.raw)
        tx.rehash()
        if bytes.fromhex(tx.hash) != prepared.txid:
            raise ValueError("prepared Bitcoin transaction ID mismatch")
        try:
            returned = self.ci.publishTx(prepared.raw)
        except Exception as broadcast_error:  # noqa: BLE001
            # An indexed node or the mempool can return the exact bytes by
            # txid. A pruned node can do so only with a retained block hash.
            try:
                observed_hex = self.ci.rpc(
                    "getrawtransaction", [prepared.txid.hex(), False]
                )
            except Exception:  # noqa: BLE001
                observed_hex = self._find_confirmed_replay(prepared.txid)
                if observed_hex is None:
                    raise broadcast_error
            if observed_hex != prepared.raw.hex():
                raise ValueError("Bitcoin transaction ID has different witness bytes")
            return prepared.txid
        if returned != prepared.txid.hex():
            raise ValueError("Bitcoin broadcast transaction ID mismatch")
        return prepared.txid

    def _find_confirmed_replay(self, txid):
        """Recover exact mined bytes from retained blocks without txindex."""
        if self.scan_start_height is None:
            return None
        chain = self.ci.rpc("getblockchaininfo")
        if not isinstance(chain, dict):
            raise ValueError("Bitcoin chain status is unavailable")
        tip = chain.get("blocks")
        if type(tip) is not int or tip < 0:
            raise ValueError("invalid Bitcoin chain height")
        first = self.scan_start_height
        if chain.get("pruned") is True:
            prune_height = chain.get("pruneheight", 0)
            if type(prune_height) is not int or prune_height < 0:
                raise ValueError("invalid Bitcoin prune height")
            first = max(first, prune_height)
        if first > tip:
            return None
        if tip - first + 1 > self.MAX_REPLAY_SCAN_BLOCKS:
            raise ValueError("Bitcoin replay exceeds retained scan window")
        txid_hex = txid.hex()
        for height in range(tip, first - 1, -1):
            block_hash = self.ci.rpc("getblockhash", [height])
            block = self.ci.rpc("getblock", [block_hash, 1])
            if (
                not isinstance(block, dict)
                or block.get("hash") != block_hash
                or block.get("height") != height
                or type(block.get("confirmations")) is not int
                or block["confirmations"] < 1
                or not isinstance(block.get("tx"), list)
            ):
                raise ValueError("invalid Bitcoin replay block")
            if txid_hex not in block["tx"]:
                continue
            observed_hex = self.ci.rpc(
                "getrawtransaction", [txid_hex, False, block_hash]
            )
            if self.ci.rpc("getblockhash", [height]) != block_hash:
                raise ValueError("Bitcoin replay block reorganized")
            return observed_hex
        return None

    def validate_prepared_funding(self, prepared, contract_vout):
        """Recheck a stored signed lock before replaying its raw bytes."""
        if not isinstance(prepared, PreparedBtcTransaction):
            raise TypeError("invalid prepared Bitcoin transaction")
        tx = self.ci.loadTx(prepared.raw)
        tx.rehash()
        if (
            bytes.fromhex(tx.hash) != prepared.txid
            or tx.serialize_with_witness() != prepared.raw
        ):
            raise ValueError("stored Bitcoin funding ID mismatch")
        if (
            type(contract_vout) is not int
            or not 0 <= contract_vout < len(tx.vout)
            or tx.vout[contract_vout].scriptPubKey != self.script_pubkey
            or tx.vout[contract_vout].nValue != self.terms.btc_amount
        ):
            raise ValueError("stored Bitcoin funding output mismatch")

    def validate_prepared_spend(
        self, prepared, funding_txid, funding_vout, branch, preimage
    ):
        """Recheck a stored contract spend before replaying its raw bytes."""
        _hex32(funding_txid, "Bitcoin lock transaction ID")
        if branch not in ("redeem", "refund"):
            raise ValueError("invalid Bitcoin spend branch")
        if not isinstance(prepared, PreparedBtcTransaction):
            raise TypeError("invalid prepared Bitcoin transaction")
        tx = self.ci.loadTx(prepared.raw)
        tx.rehash()
        if (
            bytes.fromhex(tx.hash) != prepared.txid
            or tx.serialize_with_witness() != prepared.raw
        ):
            raise ValueError("stored Bitcoin spend ID mismatch")
        if (
            tx.nVersion != 2
            or len(tx.vin) != 1
            or len(tx.vout) != 1
            or len(tx.wit.vtxinwit) != 1
            or tx.vin[0].prevout.hash != b2i(funding_txid)
            or tx.vin[0].prevout.n != funding_vout
            or tx.vin[0].scriptSig != b""
            or tx.vin[0].nSequence != 0xFFFFFFFE
            or not 0 < tx.vout[0].nValue <= self.terms.btc_amount
        ):
            raise ValueError("stored Bitcoin spend transaction mismatch")
        witness = tx.wit.vtxinwit[0].scriptWitness.stack
        if (
            len(witness) != (5 if branch == "redeem" else 4)
            or not witness[0]
            or len(witness[1]) != 33
            or witness[-1] != self.script
        ):
            raise ValueError("stored Bitcoin spend witness mismatch")
        if branch == "redeem":
            if (
                tx.nLockTime != 0
                or witness[3] != b"\x01"
                or witness[2] != preimage
                or not isinstance(preimage, bytes)
                or len(preimage) != 32
                or hashlib.sha256(preimage).digest() != self.hashlock
                or hash160(witness[1]) != self.receiver_hash
            ):
                raise ValueError("stored Bitcoin redeem mismatch")
        elif (
            tx.nLockTime != self.refund_time
            or witness[2] != b""
            or hash160(witness[1]) != self.refund_hash
        ):
            raise ValueError("stored Bitcoin refund mismatch")

    def verify_lock(self, txid, vout, minimum_confirmations):
        """Require the exact confirmed, still unspent output on Bitcoin Core."""
        txid_hex = _hex32(txid, "Bitcoin lock transaction ID")
        if type(vout) is not int or not 0 <= vout <= 0xFFFFFFFF:
            raise ValueError("invalid Bitcoin lock output index")
        if type(minimum_confirmations) is not int or minimum_confirmations < 1:
            raise ValueError("invalid Bitcoin confirmation minimum")
        output = self.ci.rpc("gettxout", [txid_hex, vout, False])
        if output is None:
            return None
        if not isinstance(output, dict):
            raise TypeError("invalid Bitcoin lock observation")
        confirmations = output.get("confirmations")
        script = output.get("scriptPubKey")
        block_hash = output.get("bestblock")
        if (
            type(confirmations) is not int
            or confirmations < 0
            or not isinstance(script, dict)
            or script.get("hex") != self.script_pubkey.hex()
            or _satoshis(output.get("value")) != self.terms.btc_amount
            or not isinstance(block_hash, str)
            or len(block_hash) != 64
        ):
            raise ValueError("Bitcoin lock output mismatch")
        try:
            best_block = bytes.fromhex(block_hash)
        except ValueError as exc:
            raise ValueError("invalid Bitcoin lock block hash") from exc
        if confirmations < minimum_confirmations:
            return None
        header = self.ci.rpc("getblockheader", [block_hash])
        tip_height = header.get("height") if isinstance(header, dict) else None
        if type(tip_height) is not int or tip_height < confirmations - 1:
            raise ValueError("invalid Bitcoin lock chain height")
        return BtcLockObservation(
            confirmations, tip_height - confirmations + 1, best_block
        )

    def prepare_spend(
        self,
        txid,
        vout,
        destination,
        private_key,
        fee_rate,
        maximum_fee,
        *,
        preimage=None,
    ):
        """Sign a redeem or refund using a native SegWit v0 witness."""
        if self.verify_lock(txid, vout, 1) is None:
            raise ValueError("Bitcoin lock is not confirmed and unspent")
        _hex32(txid, "Bitcoin lock transaction ID")
        if type(fee_rate) is not int or fee_rate < 1:
            raise ValueError("invalid Bitcoin fee rate")
        if type(maximum_fee) is not int or maximum_fee < 1:
            raise ValueError("invalid maximum Bitcoin fee")
        if not isinstance(private_key, bytes) or len(private_key) != 32:
            raise ValueError("invalid Bitcoin swap key")
        key = PrivateKey(private_key)
        public_key = key.public_key.format(compressed=True)
        redeem = preimage is not None
        expected_hash = self.receiver_hash if redeem else self.refund_hash
        if hash160(public_key) != expected_hash:
            raise ValueError("Bitcoin swap key does not match contract branch")
        if redeem:
            if not isinstance(preimage, bytes) or len(preimage) != 32:
                raise ValueError("invalid Bitcoin swap preimage")
            if hashlib.sha256(preimage).digest() != self.hashlock:
                raise ValueError("Bitcoin swap preimage hash mismatch")
        else:
            chain_info = self.ci.rpc("getblockchaininfo")
            median_time = chain_info.get("mediantime")
            if type(median_time) is not int or median_time < self.refund_time:
                raise ValueError("Bitcoin refund median time has not passed")

        tx = CTransaction()
        tx.nVersion = 2
        tx.nLockTime = 0 if redeem else self.refund_time
        tx.vin.append(CTxIn(COutPoint(b2i(txid), vout), nSequence=0xFFFFFFFE))
        tx.vout.append(CTxOut(0, self.ci.getDestForAddress(destination)))
        witness = CTxInWitness()
        branch = [preimage, b"\x01"] if redeem else [b""]
        witness.scriptWitness.stack = [bytes(73), public_key, *branch, self.script]
        tx.wit.vtxinwit.append(witness)
        fee = fee_rate * self.ci.getTxVSize(tx)
        if fee > maximum_fee:
            raise ValueError("Bitcoin contract fee exceeds limit")
        output_value = self.terms.btc_amount - fee
        if output_value <= 0 or output_value < self.ci.getdustlimit():
            raise ValueError("Bitcoin contract output would be dust")
        tx.vout[0].nValue = output_value
        signature = self.ci.signTx(
            private_key,
            tx.serialize_without_witness(),
            0,
            self.script,
            self.terms.btc_amount,
        )
        witness.scriptWitness.stack[0] = signature
        tx.rehash()
        return PreparedBtcTransaction(
            bytes.fromhex(tx.hash), tx.serialize_with_witness()
        )

    def inspect_confirmed_spend(self, transaction, txid, vout, height, block_hash):
        """Identify a consensus accepted branch from a decoded mined tx."""
        _hex32(txid, "Bitcoin lock transaction ID")
        if not isinstance(transaction, dict):
            raise TypeError("invalid Bitcoin spend transaction")
        for txin in transaction.get("vin", []):
            if txin.get("txid") != txid.hex() or txin.get("vout") != vout:
                continue
            witness = txin.get("txinwitness")
            if not isinstance(witness, list) or len(witness) not in (4, 5):
                raise ValueError("invalid Bitcoin contract witness")
            try:
                stack = [bytes.fromhex(item) for item in witness]
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid Bitcoin contract witness") from exc
            if stack[-1] != self.script or len(stack[1]) != 33:
                raise ValueError("Bitcoin spend script mismatch")
            if len(stack) == 5:
                if stack[3] != b"\x01" or len(stack[2]) != 32:
                    raise ValueError("invalid Bitcoin redeem witness")
                if hash160(stack[1]) != self.receiver_hash:
                    raise ValueError("Bitcoin redeem key mismatch")
                if hashlib.sha256(stack[2]).digest() != self.hashlock:
                    raise ValueError("Bitcoin revealed preimage mismatch")
                branch, secret = "redeem", stack[2]
            else:
                if stack[2] != b"" or hash160(stack[1]) != self.refund_hash:
                    raise ValueError("invalid Bitcoin refund witness")
                branch, secret = "refund", None
            if not isinstance(transaction.get("txid"), str):
                raise TypeError("invalid Bitcoin spend transaction ID")
            try:
                spend_txid = bytes.fromhex(transaction["txid"])
            except ValueError as exc:
                raise ValueError("invalid Bitcoin spend transaction ID") from exc
            if len(spend_txid) != 32:
                raise ValueError("invalid Bitcoin spend transaction ID")
            return BtcSpendObservation(
                spend_txid,
                branch,
                secret,
                height,
                block_hash,
            )
        return None

    def scan_confirmed_spend(
        self, txid, vout, first_height, last_height, minimum_confirmations=1
    ):
        """Scan a bounded block range; missing pruned blocks fail closed."""
        if (
            type(first_height) is not int
            or type(last_height) is not int
            or first_height < 0
            or last_height < first_height
            or last_height - first_height > 100
            or type(minimum_confirmations) is not int
            or minimum_confirmations < 1
        ):
            raise ValueError("invalid Bitcoin scan range")
        tip_height = self.ci.rpc("getblockcount")
        if (
            type(tip_height) is not int
            or last_height > tip_height - minimum_confirmations + 1
        ):
            raise ValueError("Bitcoin spend scan has insufficient confirmations")
        for height in range(first_height, last_height + 1):
            block_hash_hex = self.ci.rpc("getblockhash", [height])
            block = self.ci.rpc("getblock", [block_hash_hex, 2])
            block_hash = bytes.fromhex(block_hash_hex)
            if block.get("hash") != block_hash_hex or block.get("height") != height:
                raise ValueError("Bitcoin spend scan block mismatch")
            for transaction in block["tx"]:
                observed = self.inspect_confirmed_spend(
                    transaction, txid, vout, height, block_hash
                )
                if observed is not None:
                    self.confirm_spend_observation(
                        observed, txid, vout, minimum_confirmations
                    )
                    return observed
        if self.ci.rpc("getblockhash", [last_height]) != block_hash_hex:
            raise ValueError("Bitcoin chain changed during spend scan")
        return None

    def confirm_spend_observation(
        self, observation, funding_txid, funding_vout, minimum_confirmations=1
    ):
        if not isinstance(observation, BtcSpendObservation):
            raise TypeError("invalid Bitcoin spend observation")
        if type(minimum_confirmations) is not int or minimum_confirmations < 1:
            raise ValueError("invalid Bitcoin confirmation minimum")
        try:
            current_hash = self.ci.rpc("getblockhash", [observation.block_height])
        except Exception as exc:
            raise ValueError(
                "Bitcoin spend observation was reorganized or unavailable"
            ) from exc
        if current_hash != observation.block_hash.hex():
            raise ValueError("Bitcoin spend observation was reorganized")
        tip_height = self.ci.rpc("getblockcount")
        if (
            type(tip_height) is not int
            or tip_height - observation.block_height + 1 < minimum_confirmations
        ):
            raise ValueError("Bitcoin spend observation lost confirmations")
        block = self.ci.rpc("getblock", [current_hash, 2])
        if block.get("hash") != current_hash:
            raise ValueError("Bitcoin spend observation block mismatch")
        for transaction in block["tx"]:
            if transaction.get("txid") != observation.txid.hex():
                continue
            current = self.inspect_confirmed_spend(
                transaction,
                funding_txid,
                funding_vout,
                observation.block_height,
                observation.block_hash,
            )
            if current == observation:
                return
        raise ValueError("Bitcoin spend observation is no longer in its block")
