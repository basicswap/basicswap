# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Wrapper around SwapFactory from the per-swap-escrow branch of our fork of
AthanorLabs/atomic-swap (ethereum/contracts/SwapFactory.sol). Each swap's coins
sit at their own CREATE2 address; claim or refund deploys Payout there.

swapfactory_abi.json (with Payout's errors) and swapfactory_bytecode.hex (creation
code, deployed by the tests) are generated from that build.
"""

from eth_utils import keccak, to_canonical_address, to_checksum_address

from basicswap.interface.evm.swapcreator import SwapContract

STAGE = {0: "INVALID", 1: "PENDING", 2: "READY", 3: "COMPLETED"}


class SwapFactory(SwapContract):
    """The per-swap design: lock() forwards the swap's value to swap_address(swap),
    with timeouts fixed before it is signed and a deadline it must be mined by."""

    ABI = "swapfactory"
    SWAP_TYPE = (
        "(address,address,bytes32,bytes32,uint256,uint256,uint256,uint256,uint256)"
    )
    LOCK_GAS = 100000
    READY_GAS = 45000
    CLAIM_GAS = 110000
    REFUND_GAS = 110000

    def __init__(self, rpc_client, address: str):
        super().__init__(rpc_client, address)
        self._payout_init_code_hash: bytes = None

    def swap_address(self, swap: tuple) -> str:
        if self._payout_init_code_hash is None:
            self._payout_init_code_hash = self.call("PAYOUT_INIT_CODE_HASH")
        digest = keccak(
            b"\xff"
            + to_canonical_address(self.address)
            + self.swap_id(swap)
            + self._payout_init_code_hash
        )
        return to_checksum_address(digest[12:])

    def escrow_address(self, swap: tuple) -> str:
        return self.swap_address(swap)

    def sign_lock(self, account, swap: tuple, deadline: int, tx_nonce: int):
        return self._sign(
            self.encode_call("lock", swap, deadline),
            account,
            tx_nonce,
            value=swap[7],
        )

    def lock_swap_id(self, receipt) -> bytes:
        ours = self.events(receipt, "Locked")
        if len(ours) != 1:
            raise ValueError(f"Expected one Locked event, found {len(ours)}")
        return ours[0]["swapID"]

    def stage(self, swap: tuple, block="latest") -> str:
        """The factory's stage; COMPLETED also once the address has a nonce."""
        address: str = self.swap_address(swap)
        if self.rpc.get_transaction_count(address, block) > 0:
            return "COMPLETED"
        return STAGE[self.call("stage", self.swap_id(swap), block=block)]
