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
(asset 0).
"""

import functools
import json
import os

from eth_abi import encode as abi_encode
from coincurve import PublicKey
from eth_utils import (
    event_abi_to_log_topic,
    filter_abi_by_type,
    function_abi_to_4byte_selector,
)
from web3 import Web3
from web3.constants import ADDRESS_ZERO
from web3.logs import DISCARD

from basicswap.interface.evm.keys import commitment
from basicswap.util.ecc import ep

_ABI_PATH = os.path.join(os.path.dirname(__file__), "swapcreator_abi.json")

STAGE = {0: "INVALID", 1: "PENDING", 2: "READY", 3: "COMPLETED"}
SWAP_TYPE = (
    "(address,address,bytes32,bytes32,uint256,uint256,uint256,address,uint256,uint256)"
)
LOG_BLOCK_RANGE = 5000


@functools.cache
def load_abi():
    with open(_ABI_PATH, "r") as fp:
        return json.load(fp)


def make_swap(
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
        Web3.to_checksum_address(owner),
        Web3.to_checksum_address(claimer),
        bytes(claim_commitment),
        bytes(refund_commitment),
        int(timeout1),
        int(timeout2),
        int(timeout3),
        ADDRESS_ZERO,
        int(value),
        int(nonce),
    )


def swap_id(swap: tuple) -> bytes:
    return bytes(Web3.keccak(abi_encode([SWAP_TYPE], [swap])))


class SwapCreator:
    def __init__(self, rpc_client, address: str):
        self.rpc = rpc_client
        self.abi = load_abi()
        self.address = Web3.to_checksum_address(address)
        self.contract = rpc_client.w3.eth.contract(address=self.address, abi=self.abi)
        self._error_selectors = {
            function_abi_to_4byte_selector(e): e["name"]
            for e in filter_abi_by_type("error", self.abi)
        }
        self._completion_topics = {
            event_abi_to_log_topic(e): e["name"].upper()
            for e in filter_abi_by_type("event", self.abi)
            if e["name"] in ("Claimed", "Refunded")
        }

    def decode_error(self, data) -> str:
        try:
            raw = bytes.fromhex(data[2:]) if isinstance(data, str) else bytes(data)
            return self._error_selectors.get(raw[:4])
        except Exception:
            return None

    def _sign(self, fn, account, tx_nonce: int, value: int = 0, capped: bool = True):
        """(tx hash, raw tx) for a call to fn."""
        return self.rpc.sign_function(
            fn,
            account.address,
            account.key,
            value=value,
            error_decoder=self.decode_error,
            nonce=tx_nonce,
            capped=capped,
        )

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
        fn = self.contract.functions.newSwap(
            claim_commitment,
            refund_commitment,
            Web3.to_checksum_address(claimer),
            duration1,
            duration2,
            duration3,
            ADDRESS_ZERO,
            value,
            nonce,
        )
        return self._sign(fn, account, tx_nonce, value)

    def sign_set_ready(self, account, swap: tuple, tx_nonce: int):
        return self._sign(self.contract.functions.setReady(swap), account, tx_nonce)

    def sign_claim(self, account, swap: tuple, secret: bytes, tx_nonce: int):
        return self._sign(
            self.contract.functions.claim(swap, secret), account, tx_nonce
        )

    def sign_refund(
        self,
        account,
        swap: tuple,
        secret: bytes,
        tx_nonce: int,
        capped: bool = True,
    ):
        return self._sign(
            self.contract.functions.refund(swap, secret),
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
        verify = self.contract.functions.mulVerify
        return (
            verify(secret, c).call()
            and not verify(secret + 1, c).call()
            and not verify(secret + ep.o, c).call()
        )

    def code_hash(self) -> str:
        return Web3.keccak(self.rpc.w3.eth.get_code(self.address)).hex()

    def stage(self, swap_id_: bytes, block="latest") -> str:
        return STAGE[
            self.contract.functions.swaps(swap_id_).call(block_identifier=block)
        ]

    def new_swap_event(self, receipt):
        """(swap id, timeout1, timeout2, timeout3) from a newSwap receipt."""
        ours = [
            e
            for e in self.contract.events.New().process_receipt(receipt, errors=DISCARD)
            if e.address == self.address
        ]
        if len(ours) != 1:
            raise ValueError(f"Expected one New event, found {len(ours)}")
        swap = ours[0].args.swap
        return (
            bytes(ours[0].args.swapID),
            int(swap["timeout1"]),
            int(swap["timeout2"]),
            int(swap["timeout3"]),
        )

    def find_completion(self, swap_id_: bytes, from_block: int):
        """("CLAIMED" | "REFUNDED", secret) for a completed swap, newest blocks first."""
        w3 = self.rpc.w3
        end: int = w3.eth.block_number
        while end >= from_block:
            start: int = max(from_block, end - LOG_BLOCK_RANGE + 1)
            logs = w3.eth.get_logs(
                {
                    "address": self.address,
                    "fromBlock": start,
                    "toBlock": end,
                    "topics": [list(self._completion_topics), swap_id_],
                }
            )
            for log in logs:
                kind = self._completion_topics[bytes(log["topics"][0])]
                return kind, bytes(log["topics"][2])
            end = start - 1
        return None, None
