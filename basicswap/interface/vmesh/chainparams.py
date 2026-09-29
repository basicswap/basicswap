# -*- coding: utf-8 -*-

# VargaMesh integration for BasicSwap
# Initial integration target: VargaMesh Core v0.2.0

from basicswap.util import COIN


params = {
    "name": "vargamesh",
    "display_name": "VargaMesh",
    "ticker": "VMESH",
    "message_magic": 'VargaMesh Signed Message:\n',

    # VMESH target block interval: 120 seconds
    "blocks_target": 60 * 2,

    "decimal_places": 8,

    "mainnet": {
        # VargaMesh Core RPC
        "rpcport": 29667,

        # VargaMesh mainnet Base58 / Bech32 identity
        "pubkey_address": 70,
        "script_address": 50,
        "key_prefix": 190,
        "hrp": "vm",

        # Used by existing VMESH BIP39/BIP84 wallets.
        # Project coin type; currently not registered in SLIP-0044.
        "bip44": 22093,

        "min_amount": 100000,
        "max_amount": 10000000 * COIN,

        "ext_public_key_prefix": 0x024D771C,
        "ext_secret_key_prefix": 0x024D7707,
    },

    "testnet": {
        # VMESH Testnet integration port.
        # BasicSwap will explicitly configure this RPC port.
        "rpcport": 39667,

        # Dedicated VMESH Testnet address identity
        "pubkey_address": 127,
        "script_address": 125,
        "key_prefix": 176,
        "hrp": "tvm",

        # SLIP-0044 reserves coin type 1 for test networks.
        "bip44": 1,

        "min_amount": 100000,
        "max_amount": 10000000 * COIN,

        "name": "testnet3",

        "ext_public_key_prefix": 0x7CC78565,
        "ext_secret_key_prefix": 0x7CC780A6,
    },

    "regtest": {
        "rpcport": 18443,

        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "bcrt",

        "bip44": 1,

        "min_amount": 100000,
        "max_amount": 10000000 * COIN,

        "ext_public_key_prefix": 0x043587CF,
        "ext_secret_key_prefix": 0x04358394,
    },
}
