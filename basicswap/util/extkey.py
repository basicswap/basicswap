#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024-2025 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from copy import deepcopy
from .crypto import blake256, hash160, hmac_sha512, ripemd160

from coincurve.keys import PrivateKey, PublicKey


def BIP32Hash(chaincode: bytes, child_no: int, key_data_type: int, keydata: bytes):
    return hmac_sha512(
        chaincode,
        key_data_type.to_bytes(1, "big") + keydata + child_no.to_bytes(4, "big"),
    )


def hash160_dcr(data: bytes) -> bytes:
    return ripemd160(blake256(data))


def hardened(i: int) -> int:
    return i | (1 << 31)


class ExtKeyPair:
    __slots__ = (
        "_depth",
        "_fingerprint",
        "_child_no",
        "_chaincode",
        "_key",
        "_pubkey",
        "hash_func",
    )

    def __init__(self, coin_type=1):
        if coin_type == 4:
            self.hash_func = hash160_dcr
        else:
            self.hash_func = hash160

    def set_seed(self, seed: bytes) -> None:
        hashout: bytes = hmac_sha512(b"Bitcoin seed", seed)
        self._key = hashout[:32]
        self._pubkey = None
        self._chaincode = hashout[32:]
        self._depth = 0
        self._child_no = 0
        self._fingerprint = b"\0" * 4

    def has_key(self) -> bool:
        return False if self._key is None else True

    def get_pubkey(self) -> bytes:
        return (
            self._pubkey if self._pubkey else PublicKey.from_secret(self._key).format()
        )

    def neuter(self) -> None:
        if self._key is None:
            raise ValueError("Already neutered")
        self._pubkey = PublicKey.from_secret(self._key).format()
        self._key = None

    def derive(self, child_no: int):
        out = ExtKeyPair()
        out._depth = self._depth + 1
        out._child_no = child_no

        if (child_no >> 31) == 0:
            if self._key:
                K = PublicKey.from_secret(self._key)
                k_encoded = K.format()
            else:
                K = PublicKey(self._pubkey)
                k_encoded = self._pubkey
            out._fingerprint = self.hash_func(k_encoded)[:4]
            new_hash = BIP32Hash(self._chaincode, child_no, k_encoded[0], k_encoded[1:])
            out._chaincode = new_hash[32:]

            if self._key:
                k = PrivateKey(self._key)
                k.add(new_hash[:32], update=True)
                out._key = k.secret
                out._pubkey = None
            else:
                K.add(new_hash[:32], update=True)
                out._key = None
                out._pubkey = K.format()
        else:
            k = PrivateKey(self._key)
            out._fingerprint = self.hash_func(self.get_pubkey())[:4]
            new_hash = BIP32Hash(self._chaincode, child_no, 0, self._key)
            out._chaincode = new_hash[32:]
            k.add(new_hash[:32], update=True)
            out._key = k.secret
            out._pubkey = None

        out.hash_func = self.hash_func
        return out

    def derive_path(self, path: str):
        path_entries = path.split("/")
        rv = deepcopy(self)
        for i, level in enumerate(path_entries):
            level = level.lower()
            if i == 0 and level == "s":
                continue
            should_harden: bool = False
            if len(level) > 1 and level.endswith("h") or level.endswith("'"):
                level = level[:-1]
                should_harden = True
            if level.isdigit():
                child_no: int = int(level)
                if should_harden:
                    child_no = hardened(child_no)
                rv = rv.derive(child_no)
            else:
                raise ValueError("Invalid path node")
        return rv

    def encode_v(self) -> bytes:
        return (
            self._depth.to_bytes(1, "big")
            + self._fingerprint
            + self._child_no.to_bytes(4, "big")
            + self._chaincode
            + b"\x00"
            + self._key
        )

    def encode_p(self) -> bytes:
        return (
            self._depth.to_bytes(1, "big")
            + self._fingerprint
            + self._child_no.to_bytes(4, "big")
            + self._chaincode
            + self.get_pubkey()
        )

    def decode(self, data: bytes) -> None:
        if len(data) != 74:
            raise ValueError("Unexpected extkey length")
        self._depth = data[0]
        self._fingerprint = data[1:5]
        self._child_no = int.from_bytes(data[5:9], "big")
        self._chaincode = data[9:41]

        if data[41] == 0:
            self._key = data[42:]
            self._pubkey = None
        else:
            self._key = None
            self._pubkey = data[41:]
