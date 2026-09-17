# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import COIN

# All values below are pulled directly from Sharecoin's own real mainnet
# chainparams (bitcoin-source/src/kernel/chainparams.cpp in
# github.com/Share-coin/Sharecoin), not guessed or copied from a similar
# coin:
#   - pubkey_address/script_address/key_prefix: base58Prefixes[PUBKEY_ADDRESS]
#     / [SCRIPT_ADDRESS] / [SECRET_KEY] in CMainParams.
#   - hrp: bech32_hrp = "shc" in CMainParams (mainnet); testnet3 uses "tshc",
#     shareNet (this repo's regtest-equivalent dev network) uses "shcrt".
#   - message_magic: MESSAGE_MAGIC in bitcoin-source/src/common/signmessage.cpp.
#   - blocks_target: SHC's own 120s spacing (documented in chainparams.cpp as
#     a deliberate change from Bitcoin's 600s, part of a 2026-07-27 mainnet
#     rebuild - nSubsidyHalvingInterval was adjusted to 2,500,000 blocks to
#     keep the same ~9.5-year halving cadence at the faster block time).
#   - rpcport: default mainnet RPC port from chainparamsbase.cpp (8332,
#     same as Bitcoin's own default - SHC didn't change this).
#
# SHC is a real Bitcoin Core fork (not a from-scratch chain) with Segwit,
# CSV (BIP68/112/113), and CLTV (BIP65) all active from genesis on mainnet
# (BIP34Height/BIP65Height/BIP66Height/CSVHeight = 1, SegwitHeight = 0) -
# confirmed directly in chainparams.cpp, including a comment documenting a
# real bug this fixed (blocks were being rejected as "unexpected-witness"
# before this was corrected from Bitcoin's original historical activation
# heights, which this fresh chain would never reach). This is why SHC
# doesn't need a `coins_without_segwit`/`scriptless_coins` entry in the
# central chainparams.py registry, unlike e.g. DOGE or PIVX.

params = {
    "name": "sharecoin",
    "ticker": "SHC",
    "message_magic": "Sharecoin Signed Message:\n",
    "blocks_target": 120,
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 8332,
        "pubkey_address": 63,
        "script_address": 18,
        "key_prefix": 214,
        "hrp": "shc",
        # NOT YET REGISTERED with SLIP-44 (github.com/satoshilabs/slips) -
        # SHC has no official coin_type index. Using 0x8000_0000 | 9999 as
        # a clearly-out-of-band placeholder (9999 isn't a real registered
        # SLIP-44 index as of this writing) rather than silently reusing
        # another real coin's number - flag this for the BasicSwap
        # maintainers/PR reviewers rather than treat it as decided.
        "bip44": 9999,
        "min_amount": 100000,  # 0.001 SHC, same convention as DOGE/LTC - adjust if too low/high for real fee levels
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 18332,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "tshc",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet3",
    },
    "regtest": {
        # SHC's own dev/regtest-equivalent network is called "shareNet" in
        # its own chainparams.cpp (ChainType-equivalent REGTEST), distinct
        # bech32 hrp "shcrt" - real value, not testnet's "tshc" reused.
        "rpcport": 18443,
        "pubkey_address": 111,
        "script_address": 196,
        "key_prefix": 239,
        "hrp": "shcrt",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
}
