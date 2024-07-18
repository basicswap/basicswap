# https://github.com/ipazc/nanoblocks/raw/main/nanoblocks/utils/crypto.py

"""
Cryptographic functions
========================

This is a set of cryptographic functions useful for managing Nano Keys and accounts.
"""

import hashlib
import os

# todo remove? or better performance with numpy?
import numpy as np
import pandas as pd
#import pkg_resources

# https://github.com/ipazc/nanoblocks/raw/main/nanoblocks/protocol/crypto/ed25519.py
#from nanoblocks.protocol.crypto.ed25519 import publickey_unsafe, signature_unsafe
from .xno_crypto_ed25519 import publickey_unsafe, signature_unsafe

# These are the maps used by the 32-base encoding algorithm
pub_key_map = pd.Series(list('13456789abcdefghijkmnopqrstuwxyz'), name="PubKeyMap")
pub_key_map_reverse = pd.Series(np.arange(pub_key_map.shape[0]), index=pub_key_map.to_numpy(), name="PubKeyMapReverse")

"""
# These are the words dictionary for the bip39 mnemonic derivation
words_raw = [l.decode().strip() for l in pkg_resources.resource_stream('nanoblocks', 'protocol/crypto/bip39/bip39.txt')]
words = pd.Series(words_raw, name="Words")
words_reverse = pd.Series(words.index, index=words.to_numpy(), name="ReverseWords")
"""


def chunkize(values_list, chunk_size):
    """
    Make chunks from a given list.

    :param values_list:
        List of values to be chunkized

    :param chunk_size:
        Size of the chunks (except last chunk, which can be smaller in case `chunk_size` is not a divisor of `len(l)`).
    """
    for i in range(0, len(values_list), chunk_size):
        yield values_list[i:i + chunk_size]


def b32encode(hex_values, pad_left=True):
    """
    Base32 encoder algorithm for Nano.

    Transforms the given hex_value into a base-32 representation. The allowed letters are:
            "13456789abcdefghijkmnopqrstuwxyz"

    :param hex_values:
        Hexadecimal values (string) or byte array containing the data to be encoded.

    :param pad_left:
        True if a byte of 0s should be prepended to the input. False otherwise.
        This padding is required when generating a nanoblocks address with this algorithm.
    """
    if type(hex_values) is str:
        data_bytes = int(hex_values, 16).to_bytes(32, "big")
    else:
        data_bytes = hex_values

    data_binary = ("0000" if pad_left else "") + "".join([f'{p:08b}' for p in data_bytes])
    data_encoded = [int(split, 2) for split in chunkize(data_binary, 5)]
    return "".join(pub_key_map.iloc[data_encoded].tolist())


def b32decode(code, remove_pad_left=True):
    """
    Base32 decoder algorithm for Nano.

    :param code:
        Encoded representation to be decoded.

    :param remove_pad_left:
        True if the decoded version contains a left padding byte (which will be removed). False otherwise.
    """
    reverse_codes = pub_key_map_reverse.loc[list(code)].to_numpy()
    reverse_code_binary = "".join([f"{x:05b}" for x in reverse_codes])[4 * int(remove_pad_left):]
    hex_digits_count = len(reverse_code_binary) // 8 * 2
    decoded_key = ('{0:0' + str(hex_digits_count) + 'x}').format(int(reverse_code_binary, 2))
    return decoded_key


def make_seed(entropy_size=64):
    """
    Generates a random seed sampling a random entropy from a cryptographic secure source.

    :param entropy_size:
        Length of the seed to sample.
    """
    entropy_seed = os.urandom(entropy_size)
    seed = hashlib.sha256(entropy_seed).hexdigest().upper()
    return seed


'''
def derive_bip39(seed):
    """
    Derives the bi39 words from the specified seed.

    :param seed:
        Wallet seed from whom to derive the bip39 mnemonic words.
    """
    integer_value = int(seed, 16)
    integer_hash = hashlib.sha256(integer_value.to_bytes(32, "big")).hexdigest().upper()
    entropy_with_checksum = seed + integer_hash[:2]
    word_chunks = [int(c, 2) for c in chunkize(f"{int(entropy_with_checksum,16):0264b}", 11)]
    word_values = words.loc[word_chunks]
    return word_values.tolist()


def derive_seed(bip39list):
    """
    Derives the seed based on the mnemonic words.

    If the mnemonic words are not valid, a KeyError exception is raised.

    :param bip39list:
        List of 24 string words to be used as source for derivation of the seed.
    """
    try:
        entropy_binary_with_checksum = "".join(['{0:011b}'.format(v) for v in words_reverse.loc[bip39list].tolist()])
    except KeyError:
        raise KeyError("Some words are not valid. Please, check them") from None

    entropy_hex_with_checksum = "{0:066x}".format(int(entropy_binary_with_checksum, 2)).upper()

    seed = entropy_hex_with_checksum[:-2]
    bip39_checksum = entropy_hex_with_checksum[-2:]

    integer_value = int(seed, 16)
    seed_checksum = hashlib.sha256(integer_value.to_bytes(32, "big")).hexdigest().upper()[:2]

    if seed_checksum != bip39_checksum:
        raise KeyError("Invalid mnemonic words")

    return seed


def fill_bip39_words(words_list):
    """
    Fills missing words in the given word list.
    If there is any word whose value is None, this method will try to refill it with a random value.

    Note that the last word must be always None since it contains the checksum and must be recomputed for each
    combination.

    :param words_list:
        List of words to refill. Any position with value None will be recomputed with a random value. Last word must be
        always recomputed, so it *MUST* be None.
    """

    if words_list[-1] is not None:
        raise KeyError("The word list cannot be filled due to the last word being previously set to a value."
                       "Try setting the last word to None first.")

    words_list = [w if w is not None else words.sample().iloc[0] for w in words_list[:-1]]
    last_value = np.random.randint(0, 8)

    seed_binary = "".join(['{0:011b}'.format(v) for v in words_reverse.loc[words_list].tolist()]) + '{0:03b}'.format(
        last_value)
    seed_hex = "{0:066x}".format(int(seed_binary, 2)).upper()

    return derive_bip39(seed_hex)
'''


def account_privkey(seed: bytes, account_index: int) -> bytes:
    """
    Returns the private key for the specified account index based on the given seed.

    :param seed:
        Seed to use to derive the account private key.

    :param account_index:
        Index of the account to derive the private key for.
    """
    assert len(seed) == 32
    # these are checked by account_index.to_bytes
    #assert isinstance(account_index, int)
    #assert 0 <= account_index
    #assert account_index <= 2**32-1
    #account_seed = int(seed, 16).to_bytes(32, "big") + account_index.to_bytes(4, "big")
    account_seed = seed + account_index.to_bytes(4, "big")
    account_private_key = hashlib.blake2b(account_seed, digest_size=32).digest()
    # .hexdigest().upper()

    return account_private_key


def account_pubkey(priv_key: bytes):
    """
    Derives the public key for the specified private key.

    For the derivation, it is used the ed25519 public-key signature system with blake2b-512 as the hashing algorithm.
    Note that we are relying in Python's long number management, which may disclose sensitive information due to
    timing and cache side-channel attacks. More information in the `ed25519/ed25519.py` file.

    :param priv_key:
        Key to use to derive the public key from
    """
    #print("basicswap/xno_crypto.py account_pubkey priv_key", repr(priv_key))
    #account_seed_digest = int(priv_key, 16).to_bytes(32, "big")
    account_seed_digest = priv_key
    pub_key_account = publickey_unsafe(account_seed_digest)
    #pub_key_account = "".join([f'{x:02x}' for x in pub_key_account]).upper()
    return pub_key_account


def account_address(pub_key: bytes):
    """
    Derives the nanoblocks address for a given public key.
    E.g. "nano_..."

    The last 8 characters are the checksum of the address.

    :param pub_key:
        public key to derive the account address from.
    """
    encoded_address = b32encode(pub_key)
    #pub_key_digest = int(pub_key, 16).to_bytes(32, "big")
    pub_key_digest = pub_key
    pub_key_checksum_hash = hashlib.blake2b(pub_key_digest, digest_size=5).digest()[::-1]
    encoded_checksum = b32encode(pub_key_checksum_hash, pad_left=False)
    address = f"nano_{encoded_address}{encoded_checksum}"
    return address


def address_pubkey(nano_address):
    """
    Retrieves back the public key from the given nanoblocks address.

    A checksum is checked from the given nanoblocks address, and if it doesnt match a KeyError exception is raised.

    :param nano_address:
        Address of nanoblocks to derive the public key from. Eg "nano_..."
    """
    encoded_address = nano_address[:-8].split("_")[1]

    pub_key = b32decode(encoded_address)
    account_checks = account_address(pub_key) == nano_address

    if not account_checks:
        raise Exception(f"Invalid address {nano_address}: checksum (last 4 bytes) does not match.")

    return pub_key.upper()


def hash_block(block_hex):
    """
    Generates the hash for the given block bytes.
    This hash is required in combination with the signing fields, prior to the signature.

    :param block_hex:
        Hexadecimal string containing the preamble, account, frontier block, representative, balance and link.
    """
    block_hex_bytes = bytes.fromhex(block_hex)
    block_hash = hashlib.blake2b(block_hex_bytes, digest_size=32).hexdigest().upper()
    return block_hash


def sign_block(block_hash, private_key, public_key):
    """
    Signs the given block hash with the given private key and public key.
    Generates a signature ready for attaching to a block.

    :param block_hash:
        Hash string of the block (by a blake2b hashing algorithm with a digest_size of 32 bytes).

    :param private_key:
        Private key used to sign the block.

    :param public_key:
        Public key used for the signature.
    """
    block_bytes = bytes.fromhex(block_hash)
    signature = signature_unsafe(block_bytes, bytes.fromhex(private_key), bytes.fromhex(public_key))
    return signature.hex().upper()
