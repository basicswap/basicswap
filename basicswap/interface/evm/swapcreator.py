# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Wrapper around SwapCreator from the basicswap branch of our fork of
AthanorLabs/atomic-swap (ethereum/contracts/SwapCreator.sol): Athanor's
contract with fixes and a claim window reopening after timeout3.

swapcreator_abi.json and swapcreator_bytecode.hex (creation code, deployed by the
tests) are generated from that build. BasicSwap only uses native coin swaps
(asset 0). SwapContract holds what SwapFactory (swapfactory.py) shares.
"""

import functools
import json
import os

from eth_abi import decode as abi_decode, encode as abi_encode
from coincurve import PublicKey
from eth_utils import (
    collapse_if_tuple,
    event_abi_to_log_topic,
    filter_abi_by_type,
    function_abi_to_4byte_selector,
    get_abi_input_types,
    get_abi_output_types,
    keccak,
    to_checksum_address,
)

from basicswap.interface.evm.keys import commitment
from basicswap.util.ecc import ep

_ABI_DIR = os.path.dirname(__file__)

STAGE = {0: "INVALID", 1: "PENDING", 2: "READY", 3: "COMPLETED"}
LOG_BLOCK_RANGE = 5000
ADDRESS_ZERO = "0x" + "00" * 20


@functools.cache
def load_abi(name: str):
    with open(os.path.join(_ABI_DIR, f"{name}_abi.json"), "r") as fp:
        return json.load(fp)


class SwapContract:
    """What every swap contract design shares: secrets, setReady, claim, refund
    and their events. Each design sets its own Swap struct."""

    ABI: str
    SWAP_TYPE: str
    LOCK_GAS: int
    READY_GAS: int
    CLAIM_GAS: int
    REFUND_GAS: int

    def __init__(self, rpc_client, address: str):
        self.rpc = rpc_client
        self.abi = load_abi(self.ABI)
        self.address = to_checksum_address(address)
        self._functions = {
            e["name"]: e for e in filter_abi_by_type("function", self.abi)
        }
        self._events = {e["name"]: e for e in filter_abi_by_type("event", self.abi)}
        self._error_selectors = {
            function_abi_to_4byte_selector(e): e["name"]
            for e in filter_abi_by_type("error", self.abi)
        }
        self._completion_topics = {
            event_abi_to_log_topic(e): e["name"].upper()
            for e in filter_abi_by_type("event", self.abi)
            if e["name"] in ("Claimed", "Refunded")
        }

    def make_swap(
        self,
        owner,
        claimer,
        claim_commitment: bytes,
        refund_commitment: bytes,
        timeout1: int,
        timeout2: int,
        timeout3: int,
        value: int,
        nonce: int,
    ) -> tuple:
        return (
            to_checksum_address(owner),
            to_checksum_address(claimer),
            bytes(claim_commitment),
            bytes(refund_commitment),
            int(timeout1),
            int(timeout2),
            int(timeout3),
            int(value),
            int(nonce),
        )

    def swap_id(self, swap: tuple) -> bytes:
        return keccak(abi_encode([self.SWAP_TYPE], [swap]))

    def encode_call(self, name: str, *args) -> bytes:
        fn = self._functions[name]
        return function_abi_to_4byte_selector(fn) + abi_encode(
            get_abi_input_types(fn), args
        )

    def call(self, name: str, *args, block="latest"):
        """The return value of a view function; a tuple if it has several."""
        result = abi_decode(
            get_abi_output_types(self._functions[name]),
            self.rpc.eth_call(self.address, self.encode_call(name, *args), block),
        )
        return result[0] if len(result) == 1 else result

    def events(self, receipt, name: str) -> list:
        """Args of this contract's name events in receipt; logs that don't decode are skipped."""
        event = self._events[name]
        topic: bytes = event_abi_to_log_topic(event)
        indexed = [i for i in event["inputs"] if i["indexed"]]
        plain = [i for i in event["inputs"] if not i["indexed"]]
        found = []
        for log in receipt["logs"]:
            if log["address"] != self.address or log["topics"][:1] != [topic]:
                continue
            try:
                values = [
                    abi_decode([collapse_if_tuple(i)], t)[0]
                    for i, t in zip(indexed, log["topics"][1:], strict=True)
                ]
                values += abi_decode([collapse_if_tuple(i) for i in plain], log["data"])
            except Exception:
                continue
            args = {}
            for i, value in zip(indexed + plain, values):
                if "components" in i:
                    value = dict(zip((c["name"] for c in i["components"]), value))
                args[i["name"]] = value
            found.append(args)
        return found

    def decode_error(self, data) -> str:
        try:
            raw = bytes.fromhex(data[2:]) if isinstance(data, str) else bytes(data)
            return self._error_selectors.get(raw[:4])
        except Exception:
            return None

    def _sign(self, data, account, tx_nonce: int, value: int = 0, capped: bool = True):
        """(tx hash, raw tx) for a call with data."""
        return self.rpc.sign_call(
            self.address,
            data,
            account.address,
            account.key,
            value=value,
            error_decoder=self.decode_error,
            nonce=tx_nonce,
            capped=capped,
        )

    def sign_set_ready(self, account, swap: tuple, tx_nonce: int):
        return self._sign(self.encode_call("setReady", swap), account, tx_nonce)

    def sign_claim(self, account, swap: tuple, secret: bytes, tx_nonce: int):
        return self._sign(self.encode_call("claim", swap, secret), account, tx_nonce)

    def sign_refund(
        self,
        account,
        swap: tuple,
        secret: bytes,
        tx_nonce: int,
        capped: bool = True,
    ):
        return self._sign(
            self.encode_call("refund", swap, secret),
            account,
            tx_nonce,
            capped=capped,
        )

    def verifies_secrets(self) -> bool:
        """Known-answer check of mulVerify on this chain, including the fork's range check."""
        secret: int = 2
        c = int.from_bytes(
            commitment(PublicKey.from_secret(secret.to_bytes(32, "big")).format()),
            "big",
        )
        return (
            self.call("mulVerify", secret, c)
            and not self.call("mulVerify", secret + 1, c)
            and not self.call("mulVerify", secret + ep.o, c)
        )

    def find_completion(self, sid: bytes, from_block: int):
        """("CLAIMED" | "REFUNDED", secret) for a completed swap, newest blocks first."""
        end: int = self.rpc.get_block_number()
        while end >= from_block:
            start: int = max(from_block, end - LOG_BLOCK_RANGE + 1)
            logs = self.rpc.get_logs(
                self.address, start, end, [list(self._completion_topics), sid]
            )
            for log in logs:
                kind = self._completion_topics[log["topics"][0]]
                return kind, log["topics"][2]
            end = start - 1
        return None, None


class SwapCreator(SwapContract):
    """The canonical design: one contract holds every swap's coins."""

    ABI = "swapcreator"
    SWAP_TYPE = "(address,address,bytes32,bytes32,uint256,uint256,uint256,address,uint256,uint256)"
    LOCK_GAS = 60000
    READY_GAS = 40000
    CLAIM_GAS = 60000
    REFUND_GAS = 60000

    def make_swap(self, *fields) -> tuple:
        swap = super().make_swap(*fields)
        return swap[:7] + (ADDRESS_ZERO,) + swap[7:]

    def sign_new_swap(
        self,
        account,
        *,
        claim_commitment: bytes,
        refund_commitment: bytes,
        claimer: str,
        duration1: int,
        duration2: int,
        duration3: int,
        value: int,
        nonce: int,
        tx_nonce: int,
    ):
        """newSwap escrowing value; nonce is the swap's, tx_nonce the account's."""
        data = self.encode_call(
            "newSwap",
            claim_commitment,
            refund_commitment,
            to_checksum_address(claimer),
            duration1,
            duration2,
            duration3,
            ADDRESS_ZERO,
            value,
            nonce,
        )
        return self._sign(data, account, tx_nonce, value)

    def stage(self, swap: tuple, block="latest") -> str:
        return STAGE[self.call("swaps", self.swap_id(swap), block=block)]

    def new_swap_event(self, receipt):
        """(swap id, timeout1, timeout2, timeout3) from a newSwap receipt."""
        ours = self.events(receipt, "New")
        if len(ours) != 1:
            raise ValueError(f"Expected one New event, found {len(ours)}")
        swap = ours[0]["swap"]
        return (
            ours[0]["swapID"],
            int(swap["timeout1"]),
            int(swap["timeout2"]),
            int(swap["timeout3"]),
        )

    def lock_swap_id(self, receipt) -> bytes:
        return self.new_swap_event(receipt)[0]

    def escrow_address(self, swap: tuple) -> str:
        return self.address
