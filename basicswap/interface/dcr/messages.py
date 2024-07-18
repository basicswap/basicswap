#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import copy
from enum import IntEnum
from basicswap.util.crypto import blake256
from basicswap.util.integer import decode_compactsize, encode_compactsize


class TxSerializeType(IntEnum):
    Full = 0
    NoWitness = 1
    OnlyWitness = 2


class SigHashType(IntEnum):
    SigHashAll = 0x1
    SigHashNone = 0x2
    SigHashSingle = 0x3
    SigHashAnyOneCanPay = 0x80

    SigHashMask = 0x1F


class SignatureType(IntEnum):
    STEcdsaSecp256k1 = 0
    STEd25519 = 1
    STSchnorrSecp256k1 = 2


class COutPoint:
    __slots__ = ("hash", "n", "tree")

    def __init__(self, hash=0, n=0, tree=0):
        self.hash = hash
        self.n = n
        self.tree = tree

    def get_hash(self) -> bytes:
        return self.hash.to_bytes(32, "big")


class CTxIn:
    __slots__ = (
        "prevout",
        "sequence",
        "value_in",
        "block_height",
        "block_index",
        "signature_script",
    )  # Witness

    def __init__(self, prevout=COutPoint(), sequence=0):
        self.prevout = prevout
        self.sequence = sequence
        self.value_in = -1
        self.block_height = 0
        self.block_index = 0xFFFFFFFF
        self.signature_script = bytes()


class CTxOut:
    __slots__ = ("value", "version", "script_pubkey")

    def __init__(self, value=0, script_pubkey=bytes()):
        self.value = value
        self.version = 0
        self.script_pubkey = script_pubkey


class CTransaction:
    __slots__ = ("hash", "version", "vin", "vout", "locktime", "expiry")

    def __init__(self, tx=None):
        if tx is None:
            self.version = 1
            self.vin = []
            self.vout = []
            self.locktime = 0
            self.expiry = 0
        else:
            self.version = tx.version
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.locktime = tx.locktime
            self.expiry = tx.expiry

    def deserialize(self, data: bytes) -> None:

        version = int.from_bytes(data[:4], "little")
        self.version = version & 0xFFFF
        ser_type: int = version >> 16
        o = 4

        if ser_type == TxSerializeType.Full or ser_type == TxSerializeType.NoWitness:
            num_txin, nb = decode_compactsize(data, o)
            o += nb

            for i in range(num_txin):
                txi = CTxIn()
                txi.prevout = COutPoint()
                txi.prevout.hash = int.from_bytes(data[o : o + 32], "little")
                o += 32
                txi.prevout.n = int.from_bytes(data[o : o + 4], "little")
                o += 4
                txi.prevout.tree = data[o]
                o += 1
                txi.sequence = int.from_bytes(data[o : o + 4], "little")
                o += 4
                self.vin.append(txi)

            num_txout, nb = decode_compactsize(data, o)
            o += nb

            for i in range(num_txout):
                txo = CTxOut()
                txo.value = int.from_bytes(data[o : o + 8], "little")
                o += 8
                txo.version = int.from_bytes(data[o : o + 2], "little")
                o += 2
                script_bytes, nb = decode_compactsize(data, o)
                o += nb
                txo.script_pubkey = data[o : o + script_bytes]
                o += script_bytes
                self.vout.append(txo)

            self.locktime = int.from_bytes(data[o : o + 4], "little")
            o += 4
            self.expiry = int.from_bytes(data[o : o + 4], "little")
            o += 4

        if ser_type == TxSerializeType.NoWitness:
            return

        num_wit_scripts, nb = decode_compactsize(data, o)
        o += nb

        if ser_type == TxSerializeType.OnlyWitness:
            self.vin = [CTxIn() for _ in range(num_wit_scripts)]
        else:
            if num_wit_scripts != len(self.vin):
                raise ValueError("non equal witness and prefix txin quantities")

        for i in range(num_wit_scripts):
            txi = self.vin[i]
            txi.value_in = int.from_bytes(data[o : o + 8], "little")
            o += 8
            txi.block_height = int.from_bytes(data[o : o + 4], "little")
            o += 4
            txi.block_index = int.from_bytes(data[o : o + 4], "little")
            o += 4
            script_bytes, nb = decode_compactsize(data, o)
            o += nb
            txi.signature_script = data[o : o + script_bytes]
            o += script_bytes

    def serialize(self, ser_type=TxSerializeType.Full) -> bytes:
        data = bytes()
        version = (self.version & 0xFFFF) | (ser_type << 16)
        data += version.to_bytes(4, "little")

        if ser_type == TxSerializeType.Full or ser_type == TxSerializeType.NoWitness:
            data += encode_compactsize(len(self.vin))
            for txi in self.vin:
                data += txi.prevout.hash.to_bytes(32, "little")
                data += txi.prevout.n.to_bytes(4, "little")
                data += txi.prevout.tree.to_bytes(1, "little")
                data += txi.sequence.to_bytes(4, "little")

            data += encode_compactsize(len(self.vout))
            for txo in self.vout:
                data += txo.value.to_bytes(8, "little")
                data += txo.version.to_bytes(2, "little")
                data += encode_compactsize(len(txo.script_pubkey))
                data += txo.script_pubkey

            data += self.locktime.to_bytes(4, "little")
            data += self.expiry.to_bytes(4, "little")

        if ser_type == TxSerializeType.Full or ser_type == TxSerializeType.OnlyWitness:
            data += encode_compactsize(len(self.vin))
            for txi in self.vin:
                tc_value_in = (
                    txi.value_in & 0xFFFFFFFFFFFFFFFF
                )  # Convert negative values
                data += tc_value_in.to_bytes(8, "little")
                data += txi.block_height.to_bytes(4, "little")
                data += txi.block_index.to_bytes(4, "little")
                data += encode_compactsize(len(txi.signature_script))
                data += txi.signature_script

        return data

    def TxHash(self) -> bytes:
        return blake256(self.serialize(TxSerializeType.NoWitness))[::-1]

    def TxHashWitness(self) -> bytes:
        raise ValueError("todo")

    def TxHashFull(self) -> bytes:
        raise ValueError("todo")


def findOutput(tx, script_pk: bytes):
    for i in range(len(tx.vout)):
        if tx.vout[i].script_pubkey == script_pk:
            return i
    return None
