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

from coincurve import PrivateKey, PublicKey

from basicswap.interface.evm.codec import keccak, to_checksum_address

from basicswap.util.ecc import ep


def commitment(pk_secp256k1: bytes) -> bytes:
    """keccak256 of the uncompressed x||y; the contract compares its low 160 bits."""
    xy: bytes = PublicKey(bytes(pk_secp256k1)).format(compressed=False)[1:]
    return keccak(xy)


def revealed_key(secret: bytes) -> bytes:
    """A secret from Claimed/Refunded as a key; the contract accepts it unreduced."""
    return (int.from_bytes(secret, "big") % ep.o).to_bytes(32, "big")


def sign_hash(key: bytes, msg_hash: bytes) -> tuple:
    """(v, r, s), v the recovery id; libsecp256k1 gives the low s Ethereum requires."""
    sig: bytes = PrivateKey(bytes(key)).sign_recoverable(bytes(msg_hash), hasher=None)
    return sig[64], int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big")


class LocalAccount:
    """A private key and its address."""

    def __init__(self, key: bytes):
        self.key = bytes(key)
        xy: bytes = PublicKey.from_secret(self.key).format(compressed=False)[1:]
        self.address: str = to_checksum_address(keccak(xy)[12:])
