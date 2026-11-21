# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
SwapCreator key commitments.

Each side's spend half is valid on both curves (DLEAG). The contract commits
to the keccak hash of its secp256k1 public key and checks a revealed secret
with ecrecover, so the secret is the same 32-byte key the Monero side uses.
"""

from coincurve import PublicKey
from eth_keys import keys
from eth_utils import keccak

from basicswap.util.ecc import ep


def commitment(pk_secp256k1: bytes) -> bytes:
    """keccak256 of the uncompressed x||y; the contract compares its low 160 bits."""
    xy: bytes = PublicKey(bytes(pk_secp256k1)).format(compressed=False)[1:]
    return keccak(xy)


def revealed_key(secret: bytes) -> bytes:
    """A secret from Claimed/Refunded as a key; the contract accepts it unreduced."""
    return (int.from_bytes(secret, "big") % ep.o).to_bytes(32, "big")


class LocalAccount:
    """A private key and its address."""

    def __init__(self, key: bytes):
        self.key = bytes(key)
        self.address: str = keys.PrivateKey(self.key).public_key.to_checksum_address()
