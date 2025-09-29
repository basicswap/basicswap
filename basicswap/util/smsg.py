#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import hmac
import secrets
import time


from typing import Union, Dict
from coincurve.keys import (
    PublicKey,
    PrivateKey,
)
from Crypto.Cipher import AES

from basicswap.util.crypto import hash160, sha256, ripemd160
from basicswap.util.ecc import getSecretInt
from basicswap.contrib.test_framework.messages import (
    uint256_from_compact,
    uint256_from_str,
)


AES_BLOCK_SIZE = 16


def aes_pad(s: bytes):
    c = AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE
    return s + (bytes((c,)) * c)


def aes_unpad(s: bytes):
    return s[: -(s[len(s) - 1])]


def aes_encrypt(raw: bytes, pass_data: bytes, iv: bytes):
    assert len(pass_data) == 32
    assert len(iv) == 16
    raw = aes_pad(raw)
    cipher = AES.new(pass_data, AES.MODE_CBC, iv)
    return cipher.encrypt(raw)


def aes_decrypt(enc, pass_data: bytes, iv: bytes):
    assert len(pass_data) == 32
    assert len(iv) == 16
    cipher = AES.new(pass_data, AES.MODE_CBC, iv)
    return aes_unpad(cipher.decrypt(enc))


SMSG_MIN_TTL = 60 * 60
SMSG_BUCKET_LEN = 60 * 60
SMSG_HDR_LEN = (
    108  # Length of unencrypted header, 4 + 4 + 2 + 1 + 8 + 4 + 16 + 33 + 32 + 4
)
SMSG_PL_HDR_LEN = 1 + 20 + 65 + 4  # Length of encrypted header in payload


def smsgGetTimestamp(smsg_message: bytes) -> int:
    assert len(smsg_message) > SMSG_HDR_LEN
    return int.from_bytes(smsg_message[11 : 11 + 8], byteorder="little")


def smsgGetTTL(smsg_message: bytes) -> int:
    assert len(smsg_message) > SMSG_HDR_LEN
    return int.from_bytes(smsg_message[19 : 19 + 4], byteorder="little")


def smsgGetPOWHash(smsg_message: bytes) -> bytes:
    assert len(smsg_message) > SMSG_HDR_LEN
    ofs: int = 4
    nonce: bytes = smsg_message[ofs : ofs + 4]
    iv: bytes = nonce * 8

    m = hmac.new(iv, digestmod="SHA256")
    m.update(smsg_message[4:])
    return m.digest()


def smsgGetID(smsg_message: bytes) -> bytes:
    assert len(smsg_message) > SMSG_HDR_LEN
    smsg_timestamp = smsgGetTimestamp(smsg_message)
    return smsg_timestamp.to_bytes(8, byteorder="big") + ripemd160(smsg_message[8:])


def smsgEncrypt(
    privkey_from: bytes,
    pubkey_to: bytes,
    payload: bytes,
    smsg_timestamp: int = None,
    deterministic: bool = False,
    payload_format: int = 2,
    smsg_ttl: int = SMSG_MIN_TTL,
    difficulty_target=0x1EFFFFFF,
) -> bytes:
    # assert len(payload) < 128  # Requires lz4 if payload > 128 bytes
    # TODO: Add lz4 to match core smsg
    if deterministic:
        assert smsg_timestamp is not None
        h = hashlib.sha256(b"smsg")
        h.update(privkey_from)
        h.update(pubkey_to)
        h.update(payload)
        h.update(smsg_timestamp.to_bytes(8, byteorder="big"))
        r = h.digest()
        smsg_iv: bytes = hashlib.sha256(b"smsg_iv" + r).digest()[:16]
    else:
        r = getSecretInt().to_bytes(32, byteorder="big")
        smsg_iv: bytes = secrets.token_bytes(16)
    if smsg_timestamp is None:
        smsg_timestamp = int(time.time())
    R = PublicKey.from_secret(r).format()
    p = PrivateKey(r).ecdh(pubkey_to)
    H = hashlib.sha512(p).digest()
    key_e: bytes = H[:32]
    key_m: bytes = H[32:]

    payload_hash: bytes = sha256(sha256(payload))
    signature: bytes = PrivateKey(privkey_from).sign_recoverable(
        payload_hash, hasher=None
    )

    # Convert format to BTC, add 4 to mark as compressed key
    recid = signature[64]
    signature = bytes((27 + recid + 4,)) + signature[:64]

    pubkey_from: bytes = PublicKey.from_secret(privkey_from).format()
    pkh_from: bytes = hash160(pubkey_from)

    len_payload = len(payload)

    if payload_format == 2:
        address_version = 249  # Marker for format 2
        compressed = 0
        plaintext_data: bytes = bytes((address_version, compressed))
    elif payload_format == 1:
        address_version = 0
        plaintext_data: bytes = bytes((address_version,))
    else:
        raise ValueError("Unknown payload format.")
    plaintext_data += bytes(
        pkh_from + signature + len_payload.to_bytes(4, byteorder="little") + payload
    )

    ciphertext: bytes = aes_encrypt(plaintext_data, key_e, smsg_iv)

    m = hmac.new(key_m, digestmod="SHA256")
    m.update(smsg_timestamp.to_bytes(8, byteorder="little"))
    m.update(smsg_iv)
    m.update(ciphertext)
    mac: bytes = m.digest()

    smsg_hash = bytes((0,)) * 4
    smsg_nonce = bytes((0,)) * 4
    smsg_version = bytes((2, 1))
    smsg_flags = bytes((0,))

    assert len(R) == 33
    assert len(mac) == 32

    smsg_message: bytes = (
        smsg_hash
        + smsg_nonce
        + smsg_version
        + smsg_flags
        + smsg_timestamp.to_bytes(8, byteorder="little")
        + smsg_ttl.to_bytes(4, byteorder="little")
        + smsg_iv
        + R
        + mac
        + len(ciphertext).to_bytes(4, byteorder="little")
        + ciphertext
    )

    target: int = uint256_from_compact(difficulty_target)
    for i in range(1000000):
        pow_hash = smsgGetPOWHash(smsg_message)
        if uint256_from_str(pow_hash) > target:
            smsg_nonce = (int.from_bytes(smsg_nonce, byteorder="little") + 1).to_bytes(
                4, byteorder="little"
            )
            smsg_message = pow_hash[:4] + smsg_nonce + smsg_message[8:]
            continue
        smsg_message = pow_hash[:4] + smsg_message[4:]
        return smsg_message
    raise ValueError("Failed to set POW hash.")


def smsgDecrypt(
    privkey_to: bytes, encrypted_message: bytes, output_dict: bool = False
) -> Union[bytes, Dict]:
    # Without lz4

    assert len(encrypted_message) > SMSG_HDR_LEN
    smsg_timestamp = int.from_bytes(encrypted_message[11 : 11 + 8], byteorder="little")
    ofs: int = 23
    smsg_iv = encrypted_message[ofs : ofs + 16]

    ofs += 16
    R = encrypted_message[ofs : ofs + 33]
    ofs += 33
    mac = encrypted_message[ofs : ofs + 32]
    ofs += 32
    ciphertextlen = int.from_bytes(encrypted_message[ofs : ofs + 4], byteorder="little")
    ofs += 4
    ciphertext = encrypted_message[ofs:]
    assert len(ciphertext) == ciphertextlen

    p = PrivateKey(privkey_to).ecdh(R)
    H = hashlib.sha512(p).digest()
    key_e: bytes = H[:32]
    key_m: bytes = H[32:]

    m = hmac.new(key_m, digestmod="SHA256")
    m.update(smsg_timestamp.to_bytes(8, byteorder="little"))
    m.update(smsg_iv)
    m.update(ciphertext)
    mac_calculated: bytes = m.digest()

    assert mac == mac_calculated

    plaintext = aes_decrypt(ciphertext, key_e, smsg_iv)

    ofs: int = 0
    version = plaintext[0]
    if version == 249:
        compressed = plaintext[1]
        assert compressed == 0
        ofs += 1

    ofs += 1
    pkh_from = plaintext[ofs : ofs + 20]
    ofs += 20
    signature = plaintext[ofs : ofs + 65]
    ofs += 65
    ofs += 4
    payload = plaintext[ofs:]
    payload_hash: bytes = sha256(sha256(payload))

    # Convert format from BTC
    recid = (signature[0] - 27) & 3
    signature = signature[1:] + bytes((recid,))

    pubkey_signer = PublicKey.from_signature_and_message(
        signature, payload_hash, hasher=None
    ).format()

    pkh_from_recovered: bytes = hash160(pubkey_signer)
    assert pkh_from == pkh_from_recovered

    if output_dict:
        return {
            "msgid": smsgGetID(encrypted_message).hex(),
            "sent": smsg_timestamp,
            "hex": payload.hex(),
            "pubkey_from": pubkey_signer.hex(),
        }
    return payload
