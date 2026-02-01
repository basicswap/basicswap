#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import hashlib
import json
import logging
import mmap
import os
import shutil
import sqlite3
import threading
import traceback

from io import BytesIO
from typing import Dict, List, Optional

from basicswap.basicswap_util import (
    getVoutByAddress,
    getVoutByScriptPubKey,
)
from basicswap.interface.base import Secp256k1Interface
from basicswap.util import (
    b2i,
    ensure,
    i2b,
    i2h,
)
from basicswap.util.extkey import ExtKeyPair
from basicswap.util.script import (
    SerialiseNumCompact,
    decodeScriptNum,
    getCompactSizeLen,
    getWitnessElementLen,
)
from basicswap.util.address import (
    b58decode,
    b58encode,
    decodeAddress,
    decodeWif,
    pubkeyToAddress,
    toWIF,
)
from basicswap.util.crypto import (
    hash160,
    sha256,
)
from coincurve.keys import (
    PrivateKey,
    PublicKey,
)
from coincurve.types import ffi
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key,
)

from basicswap.contrib.test_framework import segwit_addr
from basicswap.contrib.test_framework.descriptors import descsum_create
from basicswap.contrib.test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    CScriptOp,
    OP_0,
    OP_2,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DROP,
    OP_DUP,
    OP_ELSE,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_IF,
    OP_RETURN,
    SIGHASH_ALL,
    SegwitV0SignatureHash,
)
from basicswap.basicswap_util import TxLockTypes

from basicswap.chainparams import Coins
from basicswap.rpc import make_rpc_func, openrpc


SEQUENCE_LOCKTIME_GRANULARITY = 9  # 512 seconds
SEQUENCE_LOCKTIME_TYPE_FLAG = 1 << 22
SEQUENCE_LOCKTIME_MASK = 0x0000FFFF


def ensure_op(v, err_string="Bad opcode"):
    ensure(v, err_string)


def findOutput(tx, script_pk: bytes):
    for i in range(len(tx.vout)):
        if tx.vout[i].scriptPubKey == script_pk:
            return i
    return None


def find_vout_for_address_from_txobj(tx_obj, addr: str) -> int:
    """
    Locate the vout index of the given transaction sending to the
    given address. Raises runtime error exception if not found.
    """
    for i in range(len(tx_obj["vout"])):
        scriptPubKey = tx_obj["vout"][i]["scriptPubKey"]
        if "addresses" in scriptPubKey:
            if any([addr == a for a in scriptPubKey["addresses"]]):
                return i
        elif "address" in scriptPubKey:
            if addr == scriptPubKey["address"]:
                return i
    raise RuntimeError(
        "Vout not found for address: txid={}, addr={}".format(tx_obj["txid"], addr)
    )


def extractScriptLockScriptValues(script_bytes: bytes) -> (bytes, bytes):
    script_len = len(script_bytes)
    ensure(script_len == 71, "Bad script length")
    o = 0
    ensure_op(script_bytes[o] == OP_2)
    ensure_op(script_bytes[o + 1] == 33)
    o += 2
    pk1 = script_bytes[o : o + 33]
    o += 33
    ensure_op(script_bytes[o] == 33)
    o += 1
    pk2 = script_bytes[o : o + 33]
    o += 33
    ensure_op(script_bytes[o] == OP_2)
    ensure_op(script_bytes[o + 1] == OP_CHECKMULTISIG)

    return pk1, pk2


def extractScriptLockRefundScriptValues(script_bytes: bytes):
    script_len = len(script_bytes)
    ensure(script_len > 73, "Bad script length")
    ensure_op(script_bytes[0] == OP_IF)
    ensure_op(script_bytes[1] == OP_2)
    ensure_op(script_bytes[2] == 33)
    pk1 = script_bytes[3 : 3 + 33]
    ensure_op(script_bytes[36] == 33)
    pk2 = script_bytes[37 : 37 + 33]
    ensure_op(script_bytes[70] == OP_2)
    ensure_op(script_bytes[71] == OP_CHECKMULTISIG)
    ensure_op(script_bytes[72] == OP_ELSE)
    o = 73
    csv_val, nb = decodeScriptNum(script_bytes, o)
    o += nb

    ensure(script_len == o + 5 + 33, "Bad script length")  # Fails if script too long
    ensure_op(script_bytes[o] == OP_CHECKSEQUENCEVERIFY)
    o += 1
    ensure_op(script_bytes[o] == OP_DROP)
    o += 1
    ensure_op(script_bytes[o] == 33)
    o += 1
    pk3 = script_bytes[o : o + 33]
    o += 33
    ensure_op(script_bytes[o] == OP_CHECKSIG)
    o += 1
    ensure_op(script_bytes[o] == OP_ENDIF)

    return pk1, pk2, csv_val, pk3


class BTCInterface(Secp256k1Interface):
    _scantxoutset_lock = threading.Lock()

    @staticmethod
    def coin_type():
        return Coins.BTC

    @staticmethod
    def COIN():
        return COIN

    @staticmethod
    def exp() -> int:
        return 8

    @staticmethod
    def nbk() -> int:
        return 32

    @staticmethod
    def nbK() -> int:  # No. of bytes requires to encode a public key
        return 33

    @staticmethod
    def witnessScaleFactor() -> int:
        return 4

    @staticmethod
    def txVersion() -> int:
        return 2

    @staticmethod
    def getTxOutputValue(tx) -> int:
        rv = 0
        for output in tx.vout:
            rv += output.nValue
        return rv

    @staticmethod
    def est_lock_tx_vsize() -> int:
        return 110

    @staticmethod
    def xmr_swap_a_lock_spend_tx_vsize() -> int:
        return 147

    @staticmethod
    def xmr_swap_b_lock_spend_tx_vsize() -> int:
        return 110

    @staticmethod
    def txoType():
        return CTxOut

    @staticmethod
    def outpointType():
        return COutPoint

    @staticmethod
    def txiType():
        return CTxIn

    @staticmethod
    def getExpectedSequence(lockType: int, lockVal: int) -> int:
        ensure(lockVal >= 1, "Bad lockVal")
        if lockType == TxLockTypes.SEQUENCE_LOCK_BLOCKS:
            return lockVal
        if lockType == TxLockTypes.SEQUENCE_LOCK_TIME:
            secondsLocked = lockVal
            # Ensure the locked time is never less than lockVal
            if secondsLocked % (1 << SEQUENCE_LOCKTIME_GRANULARITY) != 0:
                secondsLocked += 1 << SEQUENCE_LOCKTIME_GRANULARITY
            secondsLocked >>= SEQUENCE_LOCKTIME_GRANULARITY
            return secondsLocked | SEQUENCE_LOCKTIME_TYPE_FLAG
        raise ValueError("Unknown lock type")

    @staticmethod
    def decodeSequence(lock_value: int) -> int:
        # Return the raw value
        if lock_value & SEQUENCE_LOCKTIME_TYPE_FLAG:
            return (
                lock_value & SEQUENCE_LOCKTIME_MASK
            ) << SEQUENCE_LOCKTIME_GRANULARITY
        return lock_value & SEQUENCE_LOCKTIME_MASK

    @staticmethod
    def depth_spendable() -> int:
        return 0

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__(network)
        self._rpc_host = coin_settings.get("rpchost", "127.0.0.1")
        self._rpcport = coin_settings["rpcport"]
        self._rpcauth = coin_settings["rpcauth"]
        self.rpc = make_rpc_func(self._rpcport, self._rpcauth, host=self._rpc_host)
        self._rpc_wallet = coin_settings.get("wallet_name", "wallet.dat")
        self._rpc_wallet_watch = coin_settings.get(
            "watch_wallet_name", self._rpc_wallet
        )
        self.rpc_wallet = make_rpc_func(
            self._rpcport, self._rpcauth, host=self._rpc_host, wallet=self._rpc_wallet
        )
        if self._rpc_wallet_watch == self._rpc_wallet:
            self.rpc_wallet_watch = self.rpc_wallet
        else:
            self.rpc_wallet_watch = make_rpc_func(
                self._rpcport,
                self._rpcauth,
                host=self._rpc_host,
                wallet=self._rpc_wallet_watch,
            )
        self.blocks_confirmed = coin_settings["blocks_confirmed"]
        self.setConfTarget(coin_settings["conf_target"])
        self._use_segwit = coin_settings["use_segwit"]
        self._connection_type = coin_settings["connection_type"]
        self._sc = swap_client
        self._log = self._sc.log if self._sc and self._sc.log else logging
        self._expect_seedid_hex = None
        self._altruistic = coin_settings.get("altruistic", True)
        self._use_descriptors = coin_settings.get("use_descriptors", False)
        # Use hardened account indices to match existing wallet keys, only applies when use_descriptors is True
        self._use_legacy_key_paths = coin_settings.get("use_legacy_key_paths", False)
        self._disable_lock_tx_rbf = False
        self._wallet_manager = None
        self._backend = None
        self._pending_utxos_map: Dict[str, list] = {}
        self._pending_utxos_lock = threading.Lock()

    def setBackend(self, backend) -> None:
        self._backend = backend
        self._log.debug(f"{self.coin_name()} using backend: {type(backend).__name__}")

    def getBackend(self):
        return self._backend

    def useBackend(self) -> bool:
        return self._connection_type == "electrum" and self._backend is not None

    def _getTxInputsKey(self, tx) -> str:
        if not tx.vin:
            return ""
        first_in = tx.vin[0]
        return f"{i2h(first_in.prevout.hash)}:{first_in.prevout.n}:{len(tx.vin)}"

    def _getPendingUtxos(self, tx) -> Optional[list]:
        tx_key = self._getTxInputsKey(tx)
        with self._pending_utxos_lock:
            return self._pending_utxos_map.get(tx_key)

    def _clearPendingUtxos(self, tx) -> None:
        tx_key = self._getTxInputsKey(tx)
        with self._pending_utxos_lock:
            self._pending_utxos_map.pop(tx_key, None)

    def getWalletManager(self):
        if self._wallet_manager is not None:
            return self._wallet_manager
        if self._sc and hasattr(self._sc, "getWalletManager"):
            wm = self._sc.getWalletManager()
            if wm and wm.isInitialized(self.coin_type()):
                self._wallet_manager = wm
                return wm
        return None

    def open_rpc(self, wallet=None):
        return openrpc(self._rpcport, self._rpcauth, wallet=wallet, host=self._rpc_host)

    def json_request(self, rpc_conn, method, params):
        try:
            v = rpc_conn.json_request(method, params)
            r = json.loads(v.decode("utf-8"))
        except Exception as ex:
            traceback.print_exc()
            raise ValueError("RPC Server Error " + str(ex))
        if "error" in r and r["error"] is not None:
            raise ValueError("RPC error " + str(r["error"]))
        return r["result"]

    def close_rpc(self, rpc_conn):
        rpc_conn.close()

    def checkWallets(self) -> int:
        if self._connection_type == "electrum":
            wm = self.getWalletManager()
            if wm and wm.isInitialized(self.coin_type()):
                return 1
            return 0

        wallets = self.rpc("listwallets")

        if self._rpc_wallet not in wallets:
            self._log.debug(
                f"Wallet: {self._rpc_wallet} not active, attempting to load."
            )
            try:
                self.rpc(
                    "loadwallet",
                    [
                        self._rpc_wallet,
                    ],
                )
                wallets = self.rpc("listwallets")
            except Exception as e:
                self._log.debug(f'Error loading wallet "{self._rpc_wallet}": {e}.')
                if "does not exist" in str(e) or "Path does not exist" in str(e):
                    self._log.info(
                        f'Creating wallet "{self._rpc_wallet}" for {self.coin_name()}.'
                    )
                    try:
                        self.rpc(
                            "createwallet",
                            [
                                self._rpc_wallet,
                                False,
                                True,
                                "",
                                False,
                                self._use_descriptors,
                            ],
                        )
                        wallets = self.rpc("listwallets")
                        if self.getWalletSeedID() == "Not found":
                            self._log.info(
                                f"Initializing HD seed for {self.coin_name()}."
                            )
                            self._sc.initialiseWallet(self.coin_type())
                    except Exception as create_e:
                        self._log.error(f"Error creating wallet: {create_e}")

        # Wallet name is "" for some LTC and PART installs on older cores
        if self._rpc_wallet not in wallets and len(wallets) > 0:
            self._log.warning(f"Changing {self.ticker()} wallet name.")
            for wallet_name in wallets:
                # Skip over other expected wallets
                if wallet_name in ("mweb",):
                    continue

                change_watchonly_wallet: bool = (
                    self._rpc_wallet_watch == self._rpc_wallet
                )

                self._rpc_wallet = wallet_name
                self._log.info(
                    f"Switched {self.ticker()} wallet name to {self._rpc_wallet}."
                )
                self.rpc_wallet = make_rpc_func(
                    self._rpcport,
                    self._rpcauth,
                    host=self._rpc_host,
                    wallet=self._rpc_wallet,
                )
                if change_watchonly_wallet:
                    self.rpc_wallet_watch = self.rpc_wallet
                break

        return len(wallets)

    def testDaemonRPC(self, with_wallet=True) -> None:
        if self._connection_type == "electrum":
            if self.useBackend():
                self._backend.getBlockHeight()
                return
            raise ValueError(f"No electrum backend available for {self.coin_name()}")
        self.rpc_wallet("getwalletinfo" if with_wallet else "getblockchaininfo")

    def getDaemonVersion(self):
        if self._core_version is None:
            if self.useBackend():
                try:
                    self._core_version = self._backend.getServerVersion()
                except Exception:
                    self._core_version = "electrum"
            else:
                self._core_version = self.rpc("getnetworkinfo")["version"]
        return self._core_version

    def getElectrumServer(self) -> str:
        if self.useBackend() and hasattr(self._backend, "getServerHost"):
            return self._backend.getServerHost()
        return None

    def getBlockchainInfo(self):
        if self.useBackend():
            height = self._backend.getBlockHeight()
            return {"blocks": height, "verificationprogress": 1.0}
        return self.rpc("getblockchaininfo")

    def getChainHeight(self) -> int:
        if self.useBackend():
            self._log.debug("getChainHeight: using backend getBlockHeight")
            height = self._backend.getBlockHeight()
            self._log.debug(f"getChainHeight: got height={height}")
            return height
        return self.rpc("getblockcount")

    def getMempoolTx(self, txid):
        if self._connection_type == "electrum":
            backend = self.getBackend()
            if backend:
                tx_info = backend.getTransaction(txid.hex())
                if tx_info:
                    return tx_info.get("hex") if isinstance(tx_info, dict) else tx_info
                tx_hex = backend.getTransactionRaw(txid.hex())
                if tx_hex:
                    return tx_hex
            return None
        return self.rpc("getrawtransaction", [txid.hex()])

    def getBlockHeaderFromHeight(self, height):
        if self._connection_type == "electrum":
            return self._getBlockHeaderFromHeightElectrum(height)
        block_hash = self.rpc("getblockhash", [height])
        return self.rpc("getblockheader", [block_hash])

    def _getBlockHeaderFromHeightElectrum(self, height):
        backend = self.getBackend()
        if not backend:
            raise ValueError("No electrum backend available")

        import struct

        header_hex = backend._server.call("blockchain.block.header", [height])
        header_bytes = bytes.fromhex(header_hex)
        block_time = struct.unpack("<I", header_bytes[68:72])[0]
        block_hash = sha256(sha256(header_bytes))[::-1].hex()
        return {"height": height, "hash": block_hash, "time": block_time}

    def getBlockHeader(self, block_hash):
        if self._connection_type == "electrum":
            raise NotImplementedError(
                "getBlockHeader by hash not available in electrum mode"
            )
        return self.rpc("getblockheader", [block_hash])

    def getBlockHeaderAt(self, time_target: int, block_after=False):
        blockchaininfo = self.rpc("getblockchaininfo")
        last_block_header = self.rpc(
            "getblockheader", [blockchaininfo["bestblockhash"]]
        )

        max_tries = 5000
        for i in range(max_tries):
            prev_block_header = self.rpc(
                "getblockheader", [last_block_header["previousblockhash"]]
            )
            if prev_block_header["time"] <= time_target:
                return last_block_header if block_after else prev_block_header

            last_block_header = prev_block_header
        raise ValueError(f"Block header not found at time: {time_target}")

    def getWalletAccountPath(self) -> str:
        # Use a bip44 style path, however the seed (derived from the particl mnemonic keychain) can't be turned into a bip39 mnemonic without the matching entropy
        purpose: int = 84  # native segwit
        coin_type: int = self.chainparams_network()["bip44"]
        account: int = 0
        return f"{purpose}h/{coin_type}h/{account}h"

    def initialiseWallet(self, key_bytes: bytes, restore_time: int = -1) -> None:
        assert len(key_bytes) == 32
        self._have_checked_seed = False

        if self._connection_type == "electrum":
            self._log.info(f"Initialising {self.coin_name()} wallet in electrum mode")
            wm = self.getWalletManager()
            if wm:
                wm.initialize(self.coin_type(), key_bytes)
                self._log.info(
                    f"{self.coin_name()} WalletManager initialized successfully"
                )
            else:
                self._log.warning(
                    f"No WalletManager available for {self.coin_name()} electrum mode"
                )
            return

        if self._use_descriptors:
            self._log.info("Importing descriptors")
            ek = ExtKeyPair()
            ek.set_seed(key_bytes)
            ek_encoded: str = self.encode_secret_extkey(ek.encode_v())
            if self._use_legacy_key_paths:
                # Match keys from legacy wallets (created from sethdseed)
                desc_external = descsum_create(f"wpkh({ek_encoded}/0h/0h/*h)")
                desc_internal = descsum_create(f"wpkh({ek_encoded}/0h/1h/*h)")
            else:
                # Use a bip44 path so the seed can be exported as a mnemonic
                path: str = self.getWalletAccountPath()
                desc_external = descsum_create(f"wpkh({ek_encoded}/{path}/0/*)")
                desc_internal = descsum_create(f"wpkh({ek_encoded}/{path}/1/*)")

            rv = self.rpc_wallet(
                "importdescriptors",
                [
                    [
                        {"desc": desc_external, "timestamp": "now", "active": True},
                        {
                            "desc": desc_internal,
                            "timestamp": "now" if restore_time == -1 else restore_time,
                            "active": True,
                            "internal": True,
                        },
                    ],
                ],
            )

            num_successful: int = 0
            for entry in rv:
                if entry.get("success", False) is True:
                    num_successful += 1
            if num_successful != 2:
                self._log.error(f"Failed to import descriptors: {rv}.")
                raise ValueError("Failed to import descriptors.")
        else:
            key_wif = self.encodeKey(key_bytes)
            try:
                self.rpc_wallet("sethdseed", [True, key_wif])
            except Exception as e:
                self._log.debug(f"sethdseed failed: {e}")

                """
                # TODO: Find derived key counts
                if "Already have this key" in str(e):
                    key_id: bytes = self.getSeedHash(key_bytes)
                    self.setActiveKeyChain(key_id)
                else:
                """
                if "Already have this key" not in str(e):
                    raise (e)
                self._log.info(
                    f"{self.coin_name()} wallet already has the correct HD seed."
                )

    def canExportToElectrum(self) -> bool:
        # keychains must be unhardened to export into electrum
        return self._use_descriptors is True and self._use_legacy_key_paths is False

    def getAccountKey(
        self,
        key_bytes: bytes,
        extkey_prefix: Optional[int] = None,
        coin_type_overide: Optional[int] = None,
    ) -> str:
        # For electrum, must start with zprv to get P2WPKH, addresses
        # extkey_prefix: 0x04b2430c
        ek = ExtKeyPair()
        ek.set_seed(key_bytes)
        path: str = self.getWalletAccountPath()
        account_ek = ek.derive_path(path)
        return self.encode_secret_extkey(account_ek.encode_v(), extkey_prefix)

    def getWalletKeyChains(
        self, key_bytes: bytes, extkey_prefix: Optional[int] = None
    ) -> Dict[str, str]:
        ek = ExtKeyPair()
        ek.set_seed(key_bytes)

        # extkey must contain keydata to derive hardened child keys

        if self.canExportToElectrum():
            path: str = self.getWalletAccountPath()
            external_extkey = ek.derive_path(f"{path}/0")
            internal_extkey = ek.derive_path(f"{path}/1")
        else:
            # Match keychain paths of legacy wallets
            external_extkey = ek.derive_path("0h/0h")
            internal_extkey = ek.derive_path("0h/1h")

        def encode_extkey(extkey):
            return self.encode_secret_extkey(extkey.encode_v(), extkey_prefix)

        rv = {
            "external": encode_extkey(external_extkey),
            "internal": encode_extkey(internal_extkey),
        }
        return rv

    def getWalletInfo(self):
        if self.useBackend():
            cached = getattr(self, "_cached_wallet_info", None)
            if cached is not None:
                return cached

            db_balance = 0
            wm = self.getWalletManager()
            if wm:
                try:
                    db_balance = wm.getCachedTotalBalance(self.coin_type())
                except Exception:
                    pass

            return {
                "balance": db_balance / self.COIN() if db_balance else 0,
                "unconfirmed_balance": 0,
                "immature_balance": 0,
                "encrypted": True,
                "locked": False,
                "locked_utxos": 0,
                "syncing": True,
            }

        rv = self.rpc_wallet("getwalletinfo")
        rv["encrypted"] = "unlocked_until" in rv
        rv["locked"] = rv.get("unlocked_until", 1) <= 0
        rv["locked_utxos"] = len(self.rpc_wallet("listlockunspent"))
        return rv

    def _queryElectrumWalletInfo(self, funded_only: bool = False):
        total_confirmed_sats = 0
        total_unconfirmed_sats = 0
        wm = self.getWalletManager()
        if wm:
            addresses = wm.getAllAddresses(self.coin_type(), funded_only=funded_only)

            if addresses:
                try:
                    detailed_balances = self._backend.getDetailedBalance(addresses)
                    for addr, bal_info in detailed_balances.items():
                        confirmed = bal_info.get("confirmed", 0)
                        unconfirmed = bal_info.get("unconfirmed", 0)
                        total_confirmed_sats += confirmed
                        total_unconfirmed_sats += unconfirmed
                except Exception as e:
                    self._log.warning(f"_queryElectrumWalletInfo error: {e}")

        balance_btc = total_confirmed_sats / self.COIN()
        unconfirmed_btc = total_unconfirmed_sats / self.COIN()

        pending_outgoing = 0
        pending_incoming = 0
        pending_count = 0
        if wm:
            pending_txs = wm.getPendingTxs(self.coin_type())
            for ptx in pending_txs:
                pending_count += 1
                if ptx.get("tx_type") == "outgoing":
                    pending_outgoing += ptx.get("amount", 0)
                elif ptx.get("tx_type") == "incoming":
                    pending_incoming += ptx.get("amount", 0)

        result = {
            "balance": balance_btc,
            "unconfirmed_balance": unconfirmed_btc,
            "immature_balance": 0,
            "encrypted": True,
            "locked": False,
            "locked_utxos": 0,
            "pending_outgoing": pending_outgoing / self.COIN(),
            "pending_incoming": pending_incoming / self.COIN(),
            "pending_tx_count": pending_count,
        }

        self._cached_wallet_info = result
        return result

    def refreshElectrumWalletInfo(self, full_scan: bool = False):
        if not self.useBackend():
            return

        do_full_scan = full_scan
        if not do_full_scan:
            scan_counter = getattr(self, "_electrum_scan_counter", 0)
            self._electrum_scan_counter = scan_counter + 1
            do_full_scan = scan_counter % 6 == 0

        try:
            if hasattr(self._backend, "setBackgroundMode"):
                self._backend.setBackgroundMode(True)
            try:
                self._queryElectrumWalletInfo(funded_only=not do_full_scan)

                wm = self.getWalletManager()
                if wm and self._backend:
                    wm.syncBalances(
                        self.coin_type(), self._backend, funded_only=not do_full_scan
                    )
            finally:
                if hasattr(self._backend, "setBackgroundMode"):
                    self._backend.setBackgroundMode(False)
        except Exception as e:
            self._log.debug(f"refreshElectrumWalletInfo error: {e}")

    def getWalletRestoreHeight(self) -> int:
        if self.useBackend():
            height = self.getChainHeight()
            self._log.debug(
                f"getWalletRestoreHeight: electrum mode, using current height {height}"
            )
            return height

        if self._use_descriptors:
            descriptor = self.getActiveDescriptor()
            if descriptor is None:
                start_time = 0
            else:
                start_time = descriptor["timestamp"]
        else:
            start_time = self.rpc_wallet("getwalletinfo")["keypoololdest"]

        blockchaininfo = self.getBlockchainInfo()
        best_block = blockchaininfo["bestblockhash"]

        chain_synced = round(blockchaininfo["verificationprogress"], 1)
        if chain_synced < 1.0:
            raise ValueError(f"{self.coin_name()} chain isn't synced.")

        self._log.debug(f"Finding block at time: {start_time}")

        rpc_conn = self.open_rpc()
        try:
            block_hash = best_block
            while True:
                block_header = self.json_request(
                    rpc_conn, "getblockheader", [block_hash]
                )
                if block_header["time"] < start_time:
                    return block_header["height"]
                if "previousblockhash" not in block_header:  # Genesis block
                    return block_header["height"]
                block_hash = block_header["previousblockhash"]
        finally:
            self.close_rpc(rpc_conn)
        raise ValueError(f"{self.coin_name()} wallet restore height not found.")

    def getActiveDescriptor(self):
        descriptors = self.rpc_wallet("listdescriptors")["descriptors"]
        for descriptor in descriptors:
            if (
                descriptor["desc"].startswith("wpkh")
                and descriptor["active"] is True
                and descriptor["internal"] is False
            ):
                return descriptor
        return None

    def getWalletSeedID(self) -> str:
        if self.useBackend():
            wm = self.getWalletManager()
            if wm:
                seed_id = wm.getSeedID(self.coin_type())
                if seed_id:
                    return seed_id
            return "Not found"

        if self._use_descriptors:
            descriptor = self.getActiveDescriptor()
            if descriptor is None:
                self._log.debug("Could not find active descriptor.")
                return "Not found"
            start = descriptor["desc"].find("]")
            if start < 3:
                return "Could not parse descriptor"
            descriptor = descriptor["desc"][start + 1 :]

            end = descriptor.find("/")
            if end < 10:
                return "Could not parse descriptor"
            extkey = descriptor[:end]

            extkey_data = b58decode(extkey)[4:-4]
            extkey_data_hash: bytes = hash160(extkey_data)
            return extkey_data_hash.hex()

        wi = self.rpc_wallet("getwalletinfo")
        return "Not found" if "hdseedid" not in wi else wi["hdseedid"]

    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        wallet_seed_id = self.getWalletSeedID()
        self._expect_seedid_hex = expect_seedid
        self._have_checked_seed = True
        return expect_seedid == wallet_seed_id

    def getNewAddress(self, use_segwit: bool, label: str = "swap_receive") -> str:
        if self._connection_type == "electrum":
            wm = self.getWalletManager()
            if wm:
                return wm.getNewAddress(self.coin_type(), internal=False, label=label)
            raise ValueError(
                f"{self.coin_name()} wallet not initialized (electrum mode)"
            )

        args = [label]
        if use_segwit:
            args.append("bech32")
        return self.rpc_wallet("getnewaddress", args)

    def isValidAddress(self, address: str) -> bool:
        if self._connection_type == "electrum":
            try:
                self.decodeAddress(address)
                return True
            except Exception:
                return False

        try:
            rv = self.rpc_wallet("validateaddress", [address])
            if rv["isvalid"] is True:
                return True
        except Exception as e:  # noqa: F841
            self._log.debug("validateaddress failed: {}".format(address))
        return False

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        if self._connection_type == "electrum":
            wm = self.getWalletManager()
            if wm:
                info = wm.getAddressInfo(self.coin_type(), address)
                if info:
                    if or_watch_only:
                        return True
                    return True
            return False

        try:
            addr_info = self.rpc_wallet("getaddressinfo", [address])
            if not or_watch_only:
                if addr_info["ismine"]:
                    return True
            else:
                if self._use_descriptors:
                    addr_info = self.rpc_wallet_watch("getaddressinfo", [address])
                if addr_info["ismine"] or addr_info["iswatchonly"]:
                    return True
        except Exception as e:
            self._log.debug(f"isAddressMine RPC check failed: {e}")

        wm = self.getWalletManager()
        if wm:
            info = wm.getAddressInfo(self.coin_type(), address)
            if info:
                if or_watch_only:
                    return True
                return True

        return False

    def checkAddressMine(self, address: str) -> None:
        addr_info = self.rpc_wallet("getaddressinfo", [address])
        ensure(addr_info["ismine"], "ismine is false")
        if self.sc._restrict_unknown_seed_wallets:
            ensure(
                addr_info["hdseedid"] == self._expect_seedid_hex, "unexpected seedid"
            )

    def get_fee_rate(self, conf_target: int = 2) -> (float, str):
        chain_client_settings = self._sc.getChainClientSettings(
            self.coin_type()
        )  # basicswap.json
        override_feerate = chain_client_settings.get("override_feerate", None)
        if override_feerate:
            self._log.debug(
                f"Fee rate override used for {self.coin_name()}: {override_feerate}"
            )
            return override_feerate, "override_feerate"

        min_relay_fee = chain_client_settings.get("min_relay_fee", None)

        def try_get_fee_rate(self, conf_target):

            if self.useBackend():
                try:
                    fee_sat_vb = self._backend.estimateFee(conf_target)
                    if fee_sat_vb and fee_sat_vb > 0:
                        fee_rate = (fee_sat_vb * 1000) / 1e8
                        return fee_rate, "electrum"
                except Exception as e:
                    self._log.debug(f"Electrum estimateFee failed: {e}")
                return 0.00001, "electrum_default"

            try:
                fee_rate: float = self.rpc_wallet("estimatesmartfee", [conf_target])[
                    "feerate"
                ]
                assert fee_rate > 0.0, "Negative feerate"
                return fee_rate, "estimatesmartfee"
            except Exception:
                try:
                    fee_rate: float = self.rpc_wallet("getwalletinfo")["paytxfee"]
                    assert fee_rate > 0.0, "Non positive feerate"
                    return fee_rate, "paytxfee"
                except Exception:
                    fee_rate: float = self.rpc("getnetworkinfo")["relayfee"]
                    return fee_rate, "relayfee"

        fee_rate, rate_src = try_get_fee_rate(self, conf_target)
        if min_relay_fee and min_relay_fee > fee_rate:
            self._log.warning(
                "Feerate {} ({}) is below min relay fee {} for {}".format(
                    self.format_amount(fee_rate, True, 1),
                    rate_src,
                    self.format_amount(min_relay_fee, True, 1),
                    self.coin_name(),
                )
            )
            return min_relay_fee, "min_relay_fee"
        return fee_rate, rate_src

    def isSegwitAddress(self, address: str) -> bool:
        return address.startswith(self.chainparams_network()["hrp"] + "1")

    def decodeAddress(self, address: str) -> bytes:
        bech32_prefix = self.chainparams_network()["hrp"]
        if len(bech32_prefix) > 0 and address.startswith(bech32_prefix + "1"):
            return bytes(segwit_addr.decode(bech32_prefix, address)[1])
        return decodeAddress(address)[1:]

    def pubkey_to_segwit_address(self, pk: bytes) -> str:
        bech32_prefix = self.chainparams_network()["hrp"]
        version = 0
        pkh = hash160(pk)
        return segwit_addr.encode(bech32_prefix, version, pkh)

    def encode_secret_extkey(self, ek_data: bytes, prefix=None) -> str:
        assert len(ek_data) == 74
        if prefix is None:
            prefix = self.chainparams_network()["ext_secret_key_prefix"]
        data: bytes = prefix.to_bytes(4, "big") + ek_data
        checksum = sha256(sha256(data))
        return b58encode(data + checksum[0:4])

    def encode_public_extkey(self, ek_data: bytes) -> str:
        assert len(ek_data) == 74
        prefix = self.chainparams_network()["ext_public_key_prefix"]
        data: bytes = prefix.to_bytes(4, "big") + ek_data
        checksum = sha256(sha256(data))
        return b58encode(data + checksum[0:4])

    def pkh_to_address(self, pkh: bytes) -> str:
        # pkh is ripemd160(sha256(pk))
        assert len(pkh) == 20
        prefix = self.chainparams_network()["pubkey_address"]
        data = bytes((prefix,)) + pkh
        checksum = sha256(sha256(data))
        return b58encode(data + checksum[0:4])

    def sh_to_address(self, sh: bytes) -> str:
        assert len(sh) == 20
        prefix = self.chainparams_network()["script_address"]
        data = bytes((prefix,)) + sh
        checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        return b58encode(data + checksum[0:4])

    def encode_p2wsh(self, script: bytes) -> str:
        bech32_prefix = self.chainparams_network()["hrp"]
        version = 0
        program = script[2:]  # strip version and length
        return segwit_addr.encode(bech32_prefix, version, program)

    def encodeScriptDest(self, script: bytes) -> str:
        return self.encode_p2wsh(script)

    def getDestForAddress(self, address: str) -> bytes:
        bech32_prefix = self.chainparams_network()["hrp"]
        if address.startswith(bech32_prefix + "1"):
            _, witprog = segwit_addr.decode(bech32_prefix, address)
            return CScript([OP_0, bytes(witprog)])

        addr_data = decodeAddress(address)
        prefix_byte = addr_data[0]
        addr_hash = addr_data[1:]

        script_address = self.chainparams_network().get("script_address")
        script_address2 = self.chainparams_network().get("script_address2")

        if prefix_byte == script_address or (
            script_address2 is not None and prefix_byte == script_address2
        ):
            return CScript([OP_HASH160, addr_hash, OP_EQUAL])
        else:
            return CScript([OP_DUP, OP_HASH160, addr_hash, OP_EQUALVERIFY, OP_CHECKSIG])

    def addressToScripthash(self, address: str) -> str:
        script = self.getDestForAddress(address)
        return sha256(script)[::-1].hex()

    def encode_p2sh(self, script: bytes) -> str:
        return pubkeyToAddress(self.chainparams_network()["script_address"], script)

    def pubkey_to_address(self, pk: bytes) -> str:
        assert len(pk) == 33
        return self.pkh_to_address(hash160(pk))

    def getAddressHashFromKey(self, key: bytes) -> bytes:
        pk = self.getPubkey(key)
        return hash160(pk)

    def getSeedHash(self, seed: bytes) -> bytes:
        if self._use_descriptors:
            ek = ExtKeyPair()
            ek.set_seed(seed)
            return hash160(ek.encode_p())

        return self.getAddressHashFromKey(seed)[::-1]

    def encodeKey(self, key_bytes: bytes) -> str:
        wif_prefix = self.chainparams_network()["key_prefix"]
        return toWIF(wif_prefix, key_bytes)

    def encodeSegwitAddress(self, key_hash: bytes) -> str:
        return segwit_addr.encode(self.chainparams_network()["hrp"], 0, key_hash)

    def decodeSegwitAddress(self, addr: str) -> bytes:
        return bytes(segwit_addr.decode(self.chainparams_network()["hrp"], addr)[1])

    def decodeKey(self, k: str) -> bytes:
        return decodeWif(k)

    def getScriptForPubkeyHash(self, pkh: bytes) -> CScript:
        # p2wpkh
        return CScript([OP_0, pkh])

    def loadTx(self, tx_bytes: bytes, allow_witness: bool = True) -> CTransaction:
        # Load tx from bytes to internal representation
        # Transactions with no inputs require allow_witness set to false to decode correctly
        tx = CTransaction()
        tx.deserialize(BytesIO(tx_bytes), allow_witness)
        return tx

    def createSCLockTx(
        self, value: int, script: bytearray, vkbv: bytes = None
    ) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.nLockTime = 0  # TODO: match locktimes by core
        tx.vout.append(self.txoType()(value, self.getScriptDest(script)))
        return tx.serialize()

    def fundSCLockTx(self, tx_bytes, feerate, vkbv=None) -> bytes:
        funded_tx = self.fundTx(tx_bytes, feerate)

        if self._disable_lock_tx_rbf:
            tx = self.loadTx(funded_tx)
            for txi in tx.vin:
                txi.nSequence = 0xFFFFFFFE
            funded_tx = tx.serialize_with_witness()
        return funded_tx

    def genScriptLockRefundTxScript(self, Kal, Kaf, csv_val) -> CScript:
        assert len(Kal) == 33
        assert len(Kaf) == 33

        # fmt: off
        return CScript([
            CScriptOp(OP_IF),
            2, Kal, Kaf, 2, CScriptOp(OP_CHECKMULTISIG),
            CScriptOp(OP_ELSE),
            csv_val, CScriptOp(OP_CHECKSEQUENCEVERIFY), CScriptOp(OP_DROP),
            Kaf, CScriptOp(OP_CHECKSIG),
            CScriptOp(OP_ENDIF)])
        # fmt: on

    def isScriptP2PKH(self, script: bytes) -> bool:
        if len(script) != 25:
            return False
        if script[0] != OP_DUP:
            return False
        if script[1] != OP_HASH160:
            return False
        if script[2] != 20:
            return False
        if script[23] != OP_EQUALVERIFY:
            return False
        if script[24] != OP_CHECKSIG:
            return False
        return True

    def isScriptP2WPKH(self, script: bytes) -> bool:
        if len(script) != 22:
            return False
        if script[0] != OP_0:
            return False
        if script[1] != 20:
            return False
        return True

    def getScriptDummyWitness(self, script: bytes) -> List[bytes]:
        if self.isScriptP2WPKH(script):
            return self.getP2WPKHDummyWitness()
        raise ValueError("Unknown script type")

    def createSCLockRefundTx(
        self,
        tx_lock_bytes,
        script_lock,
        Kal,
        Kaf,
        lock1_value,
        csv_val,
        tx_fee_rate,
        vkbv=None,
    ):
        tx_lock = CTransaction()
        tx_lock = self.loadTx(tx_lock_bytes)

        output_script = self.getScriptDest(script_lock)
        locked_n = findOutput(tx_lock, output_script)
        ensure(locked_n is not None, "Output not found in tx")
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_id_int = tx_lock.sha256

        refund_script = self.genScriptLockRefundTxScript(Kal, Kaf, csv_val)
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(
            CTxIn(
                COutPoint(tx_lock_id_int, locked_n),
                nSequence=lock1_value,
                scriptSig=self.getScriptScriptSig(script_lock),
            )
        )
        tx.vout.append(self.txoType()(locked_coin, self.getScriptDest(refund_script)))

        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        self._log.info(
            "createSCLockRefundTx {}{}.".format(
                self._log.id(i2b(tx.sha256)),
                (
                    ""
                    if self._log.safe_logs
                    else f":\n    fee_rate, vsize, fee: {tx_fee_rate}, {vsize}, {pay_fee}"
                ),
            )
        )

        return tx.serialize(), refund_script, tx.vout[0].nValue

    def createSCLockRefundSpendTx(
        self,
        tx_lock_refund_bytes,
        script_lock_refund,
        pkh_refund_to,
        tx_fee_rate,
        vkbv=None,
    ):
        # Returns the coinA locked coin to the leader
        # The follower will sign the multisig path with a signature encumbered by the leader's coinB spend pubkey
        # If the leader publishes the decrypted signature the leader's coinB spend privatekey will be revealed to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = self.getScriptDest(script_lock_refund)
        locked_n = findOutput(tx_lock_refund, output_script)
        ensure(locked_n is not None, "Output not found in tx")
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(
            CTxIn(
                COutPoint(tx_lock_refund_hash_int, locked_n),
                nSequence=0,
                scriptSig=self.getScriptScriptSig(script_lock_refund),
            )
        )

        tx.vout.append(
            self.txoType()(locked_coin, self.getScriptForPubkeyHash(pkh_refund_to))
        )

        dummy_witness_stack = self.getScriptLockRefundSpendTxDummyWitness(
            script_lock_refund
        )
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        self._log.info(
            "createSCLockRefundSpendTx {}{}.".format(
                self._log.id(i2b(tx.sha256)),
                (
                    ""
                    if self._log.safe_logs
                    else f":\n    fee_rate, vsize, fee: {tx_fee_rate}, {vsize}, {pay_fee}"
                ),
            )
        )

        return tx.serialize()

    def createSCLockRefundSpendToFTx(
        self,
        tx_lock_refund_bytes,
        script_lock_refund,
        pkh_dest,
        tx_fee_rate,
        vkbv=None,
        kbsf=None,
    ):
        # lock refund swipe tx
        # Sends the coinA locked coin to the follower

        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)

        output_script = self.getScriptDest(script_lock_refund)
        locked_n = findOutput(tx_lock_refund, output_script)
        ensure(locked_n is not None, "Output not found in tx")
        locked_coin = tx_lock_refund.vout[locked_n].nValue

        A, B, lock2_value, C = extractScriptLockRefundScriptValues(script_lock_refund)

        tx_lock_refund.rehash()
        tx_lock_refund_hash_int = tx_lock_refund.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(
            CTxIn(
                COutPoint(tx_lock_refund_hash_int, locked_n),
                nSequence=lock2_value,
                scriptSig=self.getScriptScriptSig(script_lock_refund),
            )
        )

        tx.vout.append(
            self.txoType()(locked_coin, self.getScriptForPubkeyHash(pkh_dest))
        )

        if self.altruistic() and kbsf:
            # Add mercy_keyshare
            tx.vout.append(self.txoType()(0, CScript([OP_RETURN, b"XBSW", kbsf])))
        else:
            self._log.debug(
                "Not attaching mercy output, have kbsf {}.".format(
                    "true" if kbsf else "false"
                )
            )

        dummy_witness_stack = self.getScriptLockRefundSwipeTxDummyWitness(
            script_lock_refund
        )
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        tx.rehash()
        self._log.info(
            "createSCLockRefundSpendToFTx {}{}.".format(
                self._log.id(i2b(tx.sha256)),
                (
                    ""
                    if self._log.safe_logs
                    else f":\n    fee_rate, vsize, fee: {tx_fee_rate}, {vsize}, {pay_fee}"
                ),
            )
        )

        return tx.serialize()

    def createSCLockSpendTx(
        self, tx_lock_bytes, script_lock, pkh_dest, tx_fee_rate, vkbv=None, fee_info={}
    ):
        tx_lock = self.loadTx(tx_lock_bytes)
        output_script = self.getScriptDest(script_lock)
        locked_n = findOutput(tx_lock, output_script)
        ensure(locked_n is not None, "Output not found in tx")
        locked_coin = tx_lock.vout[locked_n].nValue

        tx_lock.rehash()
        tx_lock_id_int = tx_lock.sha256

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vin.append(
            CTxIn(
                COutPoint(tx_lock_id_int, locked_n),
                scriptSig=self.getScriptScriptSig(script_lock),
            )
        )

        tx.vout.append(
            self.txoType()(locked_coin, self.getScriptForPubkeyHash(pkh_dest))
        )

        dummy_witness_stack = self.getScriptLockTxDummyWitness(script_lock)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(tx_fee_rate * vsize / 1000)
        tx.vout[0].nValue = locked_coin - pay_fee

        fee_info["fee_paid"] = pay_fee
        fee_info["rate_used"] = tx_fee_rate
        fee_info["witness_bytes"] = witness_bytes
        fee_info["vsize"] = vsize

        tx.rehash()
        self._log.info(
            "createSCLockSpendTx {}{}.".format(
                self._log.id(i2b(tx.sha256)),
                (
                    ""
                    if self._log.safe_logs
                    else f":\n    fee_rate, vsize, fee: {tx_fee_rate}, {vsize}, {pay_fee}"
                ),
            )
        )

        return tx.serialize()

    def verifySCLockTx(
        self,
        tx_bytes,
        script_out,
        swap_value,
        Kal,
        Kaf,
        feerate,
        check_lock_tx_inputs,
        vkbv=None,
    ):
        # Verify:
        #

        # Not necessary to check the lock txn is mineable, as protocol will wait for it to confirm
        # However by checking early we can avoid wasting time processing unmineable txns
        # Check fee is reasonable

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info("Verifying lock tx: {}.".format(self._log.id(txid)))

        ensure(tx.nVersion == self.txVersion(), "Bad version")
        # locktime must be <= chainheight + 2
        # TODO: Locktime is set to 0 to keep compaitibility with older nodes.
        #       Set locktime to current chainheight in createSCLockTx.
        if tx.nLockTime != 0:
            current_height: int = self.getChainHeight()
            if tx.nLockTime > current_height + 2:
                raise ValueError(
                    f"{self.coin_name()} - Bad nLockTime {tx.nLockTime}, current height {current_height}"
                )

        script_pk = self.getScriptDest(script_out)
        locked_n = findOutput(tx, script_pk)
        ensure(locked_n is not None, "Output not found in tx")
        locked_coin = tx.vout[locked_n].nValue

        # Check value
        ensure(locked_coin == swap_value, "Bad locked value")

        # Check script
        A, B = extractScriptLockScriptValues(script_out)
        ensure(A == Kal, "Bad script pubkey")
        ensure(B == Kaf, "Bad script pubkey")

        if check_lock_tx_inputs:
            # TODO: Check that inputs are unspent
            # Verify fee rate
            inputs_value = 0
            add_bytes = 0
            add_witness_bytes = getCompactSizeLen(len(tx.vin))
            for pi in tx.vin:
                ptx = self.rpc("getrawtransaction", [i2h(pi.prevout.hash), True])
                prevout = ptx["vout"][pi.prevout.n]
                inputs_value += self.make_int(prevout["value"])

                prevout_type = prevout["scriptPubKey"]["type"]
                if prevout_type == "witness_v0_keyhash":
                    add_witness_bytes += 107  # sig 72, pk 33 and 2 size bytes
                    add_witness_bytes += getCompactSizeLen(107)
                else:
                    # Assume P2PKH, TODO more types
                    add_bytes += (
                        107  # OP_PUSH72 <ecdsa_signature> OP_PUSH33 <public_key>
                    )

            outputs_value = 0
            for txo in tx.vout:
                outputs_value += txo.nValue
            fee_paid = inputs_value - outputs_value
            assert fee_paid > 0

            vsize = self.getTxVSize(tx, add_bytes, add_witness_bytes)
            fee_rate_paid = fee_paid * 1000 // vsize

            self._log.info(
                "tx amount, vsize, feerate: %ld, %ld, %ld",
                locked_coin,
                vsize,
                fee_rate_paid,
            )

            if not self.compareFeeRates(fee_rate_paid, feerate):
                self._log.warning(
                    "feerate paid doesn't match expected: %ld, %ld",
                    fee_rate_paid,
                    feerate,
                )
                # TODO: Display warning to user

        return txid, locked_n

    def verifySCLockRefundTx(
        self,
        tx_bytes,
        lock_tx_bytes,
        script_out,
        prevout_id,
        prevout_n,
        prevout_seq,
        prevout_script,
        Kal,
        Kaf,
        csv_val_expect,
        swap_value,
        feerate,
        vkbv=None,
    ):
        # Verify:
        #   Must have only one input with correct prevout and sequence
        #   Must have only one output to the p2wsh of the lock refund script
        #   Output value must be locked_coin - lock tx fee

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info("Verifying lock refund tx: {}.".format(self._log.id(txid)))

        ensure(tx.nVersion == self.txVersion(), "Bad version")
        ensure(tx.nLockTime == 0, "nLockTime not 0")
        ensure(len(tx.vin) == 1, "tx doesn't have one input")

        ensure(tx.vin[0].nSequence == prevout_seq, "Bad input nSequence")
        ensure(
            tx.vin[0].scriptSig == self.getScriptScriptSig(prevout_script),
            "Input scriptsig mismatch",
        )
        ensure(
            tx.vin[0].prevout.hash == b2i(prevout_id)
            and tx.vin[0].prevout.n == prevout_n,
            "Input prevout mismatch",
        )

        ensure(len(tx.vout) == 1, "tx doesn't have one output")

        script_pk = self.getScriptDest(script_out)
        locked_n = findOutput(tx, script_pk)
        ensure(locked_n is not None, "Output not found in tx")
        locked_coin = tx.vout[locked_n].nValue

        # Check script and values
        A, B, csv_val, C = extractScriptLockRefundScriptValues(script_out)
        ensure(A == Kal, "Bad script pubkey")
        ensure(B == Kaf, "Bad script pubkey")
        ensure(csv_val == csv_val_expect, "Bad script csv value")
        ensure(C == Kaf, "Bad script pubkey")

        fee_paid = swap_value - locked_coin
        ensure(fee_paid > 0, "negative fee_paid")

        dummy_witness_stack = self.getScriptLockTxDummyWitness(prevout_script)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 // vsize

        self._log.info_s(
            "tx amount, vsize, feerate: %ld, %ld, %ld",
            locked_coin,
            vsize,
            fee_rate_paid,
        )

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError("Bad fee rate, expected: {}".format(feerate))

        return txid, locked_coin, locked_n

    def verifySCLockRefundSpendTx(
        self,
        tx_bytes,
        lock_refund_tx_bytes,
        lock_refund_tx_id,
        prevout_script,
        Kal,
        prevout_n,
        prevout_value,
        feerate,
        vkbv=None,
    ):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output sending lock refund tx value - fee to leader's address, TODO: follower shouldn't need to verify destination addr
        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info("Verifying lock refund spend tx: {}.".format(self._log.id(txid)))

        ensure(tx.nVersion == self.txVersion(), "Bad version")
        ensure(tx.nLockTime == 0, "nLockTime not 0")
        ensure(len(tx.vin) == 1, "tx doesn't have one input")

        ensure(tx.vin[0].nSequence == 0, "Bad input nSequence")
        ensure(
            tx.vin[0].scriptSig == self.getScriptScriptSig(prevout_script),
            "Input scriptsig mismatch",
        )
        ensure(
            tx.vin[0].prevout.hash == b2i(lock_refund_tx_id)
            and tx.vin[0].prevout.n == 0,
            "Input prevout mismatch",
        )

        ensure(len(tx.vout) == 1, "tx doesn't have one output")

        # Destination doesn't matter to the follower
        """
        p2wpkh = CScript([OP_0, hash160(Kal)])
        locked_n = findOutput(tx, p2wpkh)
        ensure(locked_n is not None, 'Output not found in lock refund spend tx')
        """
        tx_value = tx.vout[0].nValue

        fee_paid = prevout_value - tx_value
        ensure(fee_paid > 0, "negative fee_paid")

        dummy_witness_stack = self.getScriptLockRefundSpendTxDummyWitness(
            prevout_script
        )
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 // vsize

        self._log.info_s(
            "tx amount, vsize, feerate: %ld, %ld, %ld", tx_value, vsize, fee_rate_paid
        )

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError("Bad fee rate, expected: {}".format(feerate))

        return True

    def verifySCLockSpendTx(
        self, tx_bytes, lock_tx_bytes, lock_tx_script, a_pkhash_f, feerate, vkbv=None
    ):
        # Verify:
        #   Must have only one input with correct prevout (n is always 0) and sequence
        #   Must have only one output with destination and amount

        tx = self.loadTx(tx_bytes)
        txid = self.getTxid(tx)
        self._log.info("Verifying lock spend tx: {}.".format(self._log.id(txid)))

        ensure(tx.nVersion == self.txVersion(), "Bad version")
        ensure(tx.nLockTime == 0, "nLockTime not 0")
        ensure(len(tx.vin) == 1, "tx doesn't have one input")

        lock_tx = self.loadTx(lock_tx_bytes)
        lock_tx_id = self.getTxid(lock_tx)

        output_script = self.getScriptDest(lock_tx_script)
        locked_n = findOutput(lock_tx, output_script)
        ensure(locked_n is not None, "Output not found in tx")
        locked_coin = lock_tx.vout[locked_n].nValue

        ensure(tx.vin[0].nSequence == 0, "Bad input nSequence")
        ensure(
            tx.vin[0].scriptSig == self.getScriptScriptSig(lock_tx_script),
            "Input scriptsig mismatch",
        )
        ensure(
            tx.vin[0].prevout.hash == b2i(lock_tx_id)
            and tx.vin[0].prevout.n == locked_n,
            "Input prevout mismatch",
        )

        ensure(len(tx.vout) == 1, "tx doesn't have one output")
        p2wpkh = self.getScriptForPubkeyHash(a_pkhash_f)
        ensure(tx.vout[0].scriptPubKey == p2wpkh, "Bad output destination")

        # The value of the lock tx output should already be verified, if the fee is as expected the difference will be the correct amount
        fee_paid = locked_coin - tx.vout[0].nValue
        assert fee_paid > 0

        dummy_witness_stack = self.getScriptLockTxDummyWitness(lock_tx_script)
        witness_bytes = self.getWitnessStackSerialisedLength(dummy_witness_stack)
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        fee_rate_paid = fee_paid * 1000 // vsize

        self._log.info_s(
            "tx amount, vsize, feerate: %ld, %ld, %ld",
            tx.vout[0].nValue,
            vsize,
            fee_rate_paid,
        )

        if not self.compareFeeRates(fee_rate_paid, feerate):
            raise ValueError("Bad fee rate, expected: {}".format(feerate))

        return True

    def signTx(
        self,
        key_bytes: bytes,
        tx_bytes: bytes,
        input_n: int,
        prevout_script: bytes,
        prevout_value: int,
    ) -> bytes:
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(
            prevout_script, tx, input_n, SIGHASH_ALL, prevout_value
        )

        eck = PrivateKey(key_bytes)
        for i in range(10000):
            # Grind for low-R value
            if i == 0:
                nonce = (ffi.NULL, ffi.NULL)
            else:
                extra_entropy = i.to_bytes(4, "little") + (b"\0" * 28)
                nonce = (ffi.NULL, ffi.new("unsigned char [32]", extra_entropy))
            sig = eck.sign(sig_hash, hasher=None, custom_nonce=nonce)
            if len(sig) < 71:
                return sig + bytes((SIGHASH_ALL,))
        raise RuntimeError("sign failed.")

    def signTxOtVES(
        self,
        key_sign: bytes,
        pubkey_encrypt: bytes,
        tx_bytes: bytes,
        input_n: int,
        prevout_script: bytes,
        prevout_value: int,
    ) -> bytes:
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(
            prevout_script, tx, input_n, SIGHASH_ALL, prevout_value
        )

        return ecdsaotves_enc_sign(key_sign, pubkey_encrypt, sig_hash)

    def verifyTxOtVES(
        self,
        tx_bytes: bytes,
        ct: bytes,
        Ks: bytes,
        Ke: bytes,
        input_n: int,
        prevout_script: bytes,
        prevout_value,
    ):
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(
            prevout_script, tx, input_n, SIGHASH_ALL, prevout_value
        )
        return ecdsaotves_enc_verify(Ks, Ke, sig_hash, ct)

    def decryptOtVES(self, k: bytes, esig: bytes) -> bytes:
        return ecdsaotves_dec_sig(k, esig) + bytes((SIGHASH_ALL,))

    def recoverEncKey(self, esig, sig, K):
        return ecdsaotves_rec_enc_key(K, esig, sig[:-1])  # Strip sighash type

    def verifyTxSig(
        self,
        tx_bytes: bytes,
        sig: bytes,
        K: bytes,
        input_n: int,
        prevout_script: bytes,
        prevout_value: int,
    ) -> bool:
        tx = self.loadTx(tx_bytes)
        sig_hash = SegwitV0SignatureHash(
            prevout_script, tx, input_n, SIGHASH_ALL, prevout_value
        )

        pubkey = PublicKey(K)
        return pubkey.verify(sig[:-1], sig_hash, hasher=None)  # Pop the hashtype byte

    def fundTx(self, tx: bytes, feerate) -> bytes:
        if self.useBackend():
            return self._fundTxElectrum(tx, feerate)

        feerate_str = self.format_amount(feerate)
        # TODO: Unlock unspents if bid cancelled
        # TODO: Manually select only segwit prevouts
        options = {
            "lockUnspents": True,
            "feeRate": feerate_str,
        }
        rv = self.rpc_wallet("fundrawtransaction", [tx.hex(), options])
        tx_bytes: bytes = bytes.fromhex(rv["hex"])
        return tx_bytes

    def _fundTxElectrum(self, tx: bytes, feerate) -> bytes:
        wm = self.getWalletManager()
        backend = self.getBackend()
        if not wm or not backend:
            raise ValueError("Electrum backend or WalletManager not available")

        parsed_tx = self.loadTx(tx, allow_witness=False)
        total_output = sum(out.nValue for out in parsed_tx.vout)

        funded_addresses = wm.getFundedAddresses(self.coin_type())
        addr_to_sh = (
            funded_addresses
            if funded_addresses
            else wm.getSignableAddresses(self.coin_type())
        )

        if not addr_to_sh:
            raise ValueError("No addresses available")

        scripthashes = list(addr_to_sh.values())
        sh_to_addr = {sh: addr for addr, sh in addr_to_sh.items()}

        batch_utxos = backend.getBatchUnspent(scripthashes)

        utxos = []
        locked_count = 0
        for sh, sh_utxos in batch_utxos.items():
            addr = sh_to_addr.get(sh, "")
            if not addr:
                self._log.warning(f"_fundTxElectrum: no address for scripthash {sh}")
            for utxo in sh_utxos:
                utxo["address"] = addr
                if addr:
                    computed_sh = self.addressToScripthash(addr)
                    if computed_sh != sh:
                        self._log.error(
                            f"_fundTxElectrum: scripthash mismatch for {addr}: "
                            f"stored={sh}, computed={computed_sh}"
                        )
                if wm.isUTXOLocked(
                    self.coin_type(), utxo.get("txid", ""), utxo.get("vout", 0)
                ):
                    locked_count += 1
                    continue
                utxos.append(utxo)

        if not utxos:
            if locked_count > 0:
                raise ValueError(
                    f"No UTXOs available ({locked_count} locked for pending swaps)"
                )
            raise ValueError("No UTXOs available")

        utxos.sort(key=lambda x: x.get("value", 0), reverse=True)

        input_vsize = 68
        est_vsize = 10 + len(parsed_tx.vout) * 34 + input_vsize
        if isinstance(feerate, int):
            fee_per_vbyte = max(1, feerate // 1000)
        else:
            fee_per_vbyte = max(1, int(feerate * 100000))
        est_fee = est_vsize * fee_per_vbyte

        selected_utxos = []
        total_input = 0
        target = total_output + est_fee

        for utxo in utxos:
            selected_utxos.append(utxo)
            total_input += utxo.get("value", 0)
            est_vsize = (
                10 + len(parsed_tx.vout) * 34 + len(selected_utxos) * input_vsize + 34
            )
            est_fee = est_vsize * fee_per_vbyte
            target = total_output + est_fee
            if total_input >= target:
                break

        if total_input < target:
            raise ValueError(
                f"Insufficient funds: have {total_input}, need {target} sats"
            )

        funded_tx = CTransaction()
        funded_tx.nVersion = self.txVersion()

        dummy_witness_stack = []
        for utxo in selected_utxos:
            txid_bytes = bytes.fromhex(utxo["txid"])[::-1]
            txid_int = int.from_bytes(txid_bytes, "little")
            funded_tx.vin.append(
                CTxIn(COutPoint(txid_int, utxo["vout"]), nSequence=0xFFFFFFFD)
            )
            dummy_witness_stack.append(self.getP2WPKHDummyWitness())

        for out in parsed_tx.vout:
            funded_tx.vout.append(out)

        witness_bytes_len_est: int = self.getWitnessStackSerialisedLength(
            dummy_witness_stack
        )

        feerate_satkb = (
            feerate if isinstance(feerate, int) else int(feerate * 100000000)
        )
        min_relay_fee = 250

        rough_vsize = 10 + (len(funded_tx.vout) + 1) * 34 + len(selected_utxos) * 68
        rough_fee = max(round(feerate_satkb * rough_vsize / 1000), min_relay_fee)
        rough_change = total_input - total_output - rough_fee

        if rough_change > 1000:
            change_addr = wm.getNewInternalAddress(self.coin_type())
            if not change_addr:
                change_addr = wm.getExistingInternalAddress(self.coin_type())
            if not change_addr:
                change_addr = selected_utxos[0].get("address")
            pkh = self.decodeAddress(change_addr)
            change_script = self.getScriptForPubkeyHash(pkh)
            funded_tx.vout.append(self.txoType()(rough_change, change_script))

            final_vsize = self.getTxVSize(
                funded_tx, add_witness_bytes=witness_bytes_len_est
            )
            final_fee = max(round(feerate_satkb * final_vsize / 1000), min_relay_fee)
            change = total_input - total_output - final_fee

            if change > 1000:
                funded_tx.vout[-1].nValue = change
            else:
                funded_tx.vout.pop()
                final_vsize = self.getTxVSize(
                    funded_tx, add_witness_bytes=witness_bytes_len_est
                )
                final_fee = max(
                    round(feerate_satkb * final_vsize / 1000), min_relay_fee
                )
                change = 0
        else:
            final_vsize = self.getTxVSize(
                funded_tx, add_witness_bytes=witness_bytes_len_est
            )
            final_fee = max(round(feerate_satkb * final_vsize / 1000), min_relay_fee)
            change = 0

        for utxo in selected_utxos:
            wm.lockUTXO(
                self.coin_type(),
                utxo.get("txid", ""),
                utxo.get("vout", 0),
                value=utxo.get("value", 0),
                address=utxo.get("address"),
                expires_in=3600,
            )

        tx_serialized = funded_tx.serialize()
        tx_key = self._getTxInputsKey(funded_tx)
        with self._pending_utxos_lock:
            self._pending_utxos_map[tx_key] = selected_utxos

        self._log.debug(
            f"_fundTxElectrum: outputs={len(parsed_tx.vout)}, utxos={len(utxos)}, "
            f"selected={len(selected_utxos)}, input={total_input}, output={total_output}, "
            f"fee={final_fee}, change={change}"
        )
        self._log.info_s(
            "_fundTxElectrum tx amount, vsize, feerate(sat/kB): %ld, %ld, %ld",
            total_output,
            final_vsize,
            feerate_satkb,
        )

        return tx_serialized

    def getNonSegwitOutputs(self):
        unspents = self.rpc_wallet("listunspent", [0, 99999999])
        nonsegwit_unspents = []
        for u in unspents:
            if u.get("spendable", False) is False:
                continue
            if "desc" in u:
                desc = u["desc"]
                if self.use_p2shp2wsh():
                    if not desc.startswith("sh(wpkh"):
                        nonsegwit_unspents.append(
                            {
                                "txid": u["txid"],
                                "vout": u["vout"],
                                "amount": u["amount"],
                            }
                        )
                else:
                    if not desc.startswith("wpkh"):
                        nonsegwit_unspents.append(
                            {
                                "txid": u["txid"],
                                "vout": u["vout"],
                                "amount": u["amount"],
                            }
                        )
        return nonsegwit_unspents

    def lockNonSegwitPrevouts(self) -> None:
        if self.useBackend():
            return

        to_lock = self.getNonSegwitOutputs()

        if len(to_lock) > 0:
            self._log.debug(f"Locking {len(to_lock)} non segwit prevouts")
            self.rpc_wallet("lockunspent", [False, to_lock])

    def listInputs(self, tx_bytes: bytes):
        tx = self.loadTx(tx_bytes)

        if self.useBackend():
            inputs = []
            for pi in tx.vin:
                inputs.append(
                    {
                        "txid": i2h(pi.prevout.hash),
                        "vout": pi.prevout.n,
                        "islocked": False,
                    }
                )
            return inputs

        all_locked = self.rpc_wallet("listlockunspent")
        inputs = []
        for pi in tx.vin:
            txid_hex = i2h(pi.prevout.hash)
            islocked = any(
                [
                    txid_hex == a["txid"] and pi.prevout.n == a["vout"]
                    for a in all_locked
                ]
            )
            inputs.append(
                {"txid": txid_hex, "vout": pi.prevout.n, "islocked": islocked}
            )
        return inputs

    def unlockInputs(self, tx_bytes):
        if self.useBackend():
            return

        tx = self.loadTx(tx_bytes)

        inputs = []
        for pi in tx.vin:
            inputs.append({"txid": i2h(pi.prevout.hash), "vout": pi.prevout.n})
        self.rpc_wallet("lockunspent", [True, inputs])

    def signTxWithWallet(self, tx: bytes) -> bytes:
        if self.useBackend():
            return self._signTxWithWalletElectrum(tx)

        rv = self.rpc_wallet("signrawtransactionwithwallet", [tx.hex()])
        return bytes.fromhex(rv["hex"])

    def _signTxWithWalletElectrum(self, tx: bytes) -> bytes:
        from coincurve import PrivateKey

        wm = self.getWalletManager()
        backend = self.getBackend()
        if not wm or not backend:
            raise ValueError("Electrum backend or WalletManager not available")

        parsed_tx = self.loadTx(tx)

        utxos = self._getPendingUtxos(parsed_tx)
        fetched_from_backend = False
        if not utxos or len(utxos) != len(parsed_tx.vin):
            fetched_from_backend = True
            utxos = []
            txids_to_fetch = [i2h(vin.prevout.hash) for vin in parsed_tx.vin]

            tx_batch = {}
            if hasattr(backend, "getTransactionBatch"):
                tx_batch = backend.getTransactionBatch(txids_to_fetch)

            needs_raw = any(
                tx_batch.get(t) is None or not isinstance(tx_batch.get(t), dict)
                for t in txids_to_fetch
            )

            if needs_raw:
                if hasattr(backend, "getTransactionBatchRaw"):
                    tx_batch_raw = backend.getTransactionBatchRaw(txids_to_fetch)
                else:
                    tx_batch_raw = {
                        t: backend.getTransactionRaw(t) for t in txids_to_fetch
                    }

                for vin in parsed_tx.vin:
                    txid_hex = i2h(vin.prevout.hash)
                    vout_n = vin.prevout.n
                    prev_tx_hex = tx_batch_raw.get(txid_hex)
                    if prev_tx_hex:
                        prev_tx = self.loadTx(bytes.fromhex(prev_tx_hex))
                        if vout_n < len(prev_tx.vout):
                            prev_out = prev_tx.vout[vout_n]
                            addr = self.getAddressFromScriptPubKey(
                                prev_out.scriptPubKey
                            )
                            utxos.append(
                                {
                                    "address": addr,
                                    "value": prev_out.nValue,
                                    "txid": txid_hex,
                                    "vout": vout_n,
                                }
                            )
            else:
                for vin in parsed_tx.vin:
                    txid_hex = i2h(vin.prevout.hash)
                    vout = vin.prevout.n
                    prev_tx = tx_batch.get(txid_hex)
                    if prev_tx and "vout" in prev_tx:
                        vouts = prev_tx["vout"]
                        if vout >= len(vouts):
                            self._log.warning(
                                f"_signTxWithWalletElectrum: vout {vout} out of range for {txid_hex[:16]}..."
                            )
                            continue
                        prev_out = vouts[vout]
                        if "scriptPubKey" in prev_out:
                            addr = prev_out["scriptPubKey"].get(
                                "address",
                                prev_out["scriptPubKey"].get("addresses", [None])[0],
                            )
                            value = int(prev_out.get("value", 0) * 100000000)
                            utxos.append(
                                {
                                    "address": addr,
                                    "value": value,
                                    "txid": txid_hex,
                                    "vout": vout,
                                }
                            )

        for i, (vin, utxo) in enumerate(zip(parsed_tx.vin, utxos)):
            address = utxo.get("address")
            if not address:
                raise ValueError(f"Cannot find address for input {i}")

            priv_key = wm.getPrivateKey(self.coin_type(), address)
            if not priv_key:
                if wm.importAddress(self.coin_type(), address, max_scan_index=2000):
                    priv_key = wm.getPrivateKey(self.coin_type(), address)
            if not priv_key:
                scripthash = self.addressToScripthash(address)
                found_addr = wm.findAddressByScripthash(self.coin_type(), scripthash)
                if found_addr:
                    self._log.debug(
                        f"_signTxWithWalletElectrum: found address by scripthash: "
                        f"{address[:10]}... -> {found_addr[:10]}..."
                    )
                    priv_key = wm.getPrivateKey(self.coin_type(), found_addr)
            if not priv_key:
                addr_info = wm.getAddressInfo(self.coin_type(), address)
                if addr_info and addr_info.get("is_watch_only"):
                    self._log.error(
                        f"_signTxWithWalletElectrum: Address {address} is watch-only without private key. "
                        f"This UTXO cannot be spent. The funds may have been received from an external source "
                        f"or the wallet was not properly initialized when the address was created. "
                        f"label={addr_info.get('label', 'unknown')}"
                    )
                else:
                    self._log.error(
                        f"_signTxWithWalletElectrum: Cannot find private key for address {address}, "
                        f"txid={utxo.get('txid', 'unknown')[:16]}..., vout={utxo.get('vout', -1)}"
                    )
                raise ValueError(f"Cannot find private key for address {address}")

            pk = PrivateKey(priv_key)
            pubkey = pk.public_key.format()

            expected_pkh = self.decodeAddress(address)
            actual_pkh = hash160(pubkey)
            if expected_pkh != actual_pkh:
                self._log.error(
                    f"Private key mismatch for address {address}: "
                    f"expected pkh {expected_pkh.hex()}, got {actual_pkh.hex()}"
                )
                raise ValueError(f"Private key does not match address {address}")

            script_code = CScript(
                [OP_DUP, OP_HASH160, expected_pkh, OP_EQUALVERIFY, OP_CHECKSIG]
            )
            value = utxo.get("value", 0)

            sig = self.signTx(priv_key, tx, i, script_code, value)

            parsed_tx.wit.vtxinwit.append(CTxInWitness())
            parsed_tx.wit.vtxinwit[i].scriptWitness.stack = [sig, pubkey]

        self._log.debug(
            f"_signTxWithWalletElectrum: signed {len(utxos)} inputs "
            f"(fetched={'yes' if fetched_from_backend else 'no'})"
        )

        self._clearPendingUtxos(parsed_tx)

        return parsed_tx.serialize()

    def signTxWithKey(
        self, tx: bytes, key: bytes, prev_amount: Optional[int] = None
    ) -> bytes:
        if self.useBackend():
            return self._signTxWithKeyLocal(tx, key, prev_amount)

        key_wif = self.encodeKey(key)
        rv = self.rpc(
            "signrawtransactionwithkey",
            [
                tx.hex(),
                [
                    key_wif,
                ],
            ],
        )
        return bytes.fromhex(rv["hex"])

    def _signTxWithKeyLocal(
        self, tx: bytes, key: bytes, prev_amount: Optional[int] = None
    ) -> bytes:
        from coincurve import PrivateKey

        if prev_amount is None:
            raise ValueError(
                "_signTxWithKeyLocal requires prev_amount for signature hash"
            )

        pk = PrivateKey(key)
        pubkey = pk.public_key.format()
        pkh = hash160(pubkey)

        script_code = CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

        sig = self.signTx(key, tx, 0, script_code, prev_amount)

        parsed_tx = self.loadTx(tx)
        parsed_tx.wit.vtxinwit.clear()
        parsed_tx.wit.vtxinwit.append(CTxInWitness())
        parsed_tx.wit.vtxinwit[0].scriptWitness.stack = [sig, pubkey]

        self._log.debug(
            f"_signTxWithKeyLocal: signed tx with key, prev_amount={prev_amount}"
        )

        return parsed_tx.serialize()

    def publishTx(self, tx: bytes):
        if self.useBackend():
            txid = self._backend.broadcastTransaction(tx.hex())
            wm = self.getWalletManager()
            if wm and txid:
                parsed_tx = self.loadTx(tx)
                total_out = sum(out.nValue for out in parsed_tx.vout)
                wm.addPendingTx(
                    self.coin_type(),
                    txid,
                    tx_type="outgoing",
                    amount=total_out,
                )
            return txid
        return self.rpc("sendrawtransaction", [tx.hex()])

    def bumpTxFee(self, txid: str, new_feerate: float) -> Optional[str]:
        if not self.useBackend():
            try:
                result = self.rpc_wallet("bumpfee", [txid, {"fee_rate": new_feerate}])
                return result.get("txid")
            except Exception as e:
                self._log.warning(f"bumpfee failed: {e}")
                return None

        backend = self.getBackend()
        wm = self.getWalletManager()
        if not backend or not wm:
            return None

        try:
            tx_info = backend.getTransaction(txid)
            tx_hex = None
            if tx_info and isinstance(tx_info, dict):
                tx_hex = tx_info.get("hex")
            if not tx_hex:
                tx_hex = backend.getTransactionRaw(txid)
            if not tx_hex:
                self._log.warning(f"bumpTxFee: Cannot find tx {txid}")
                return None

            orig_tx = self.loadTx(bytes.fromhex(tx_hex))

            rbf_enabled = any(vin.nSequence < 0xFFFFFFFE for vin in orig_tx.vin)
            if not rbf_enabled:
                self._log.warning(f"bumpTxFee: Transaction {txid} is not RBF-enabled")
                return None

            total_in = 0
            prev_txids = [i2h(vin.prevout.hash) for vin in orig_tx.vin]
            if hasattr(backend, "getTransactionBatchRaw"):
                tx_batch_raw = backend.getTransactionBatchRaw(prev_txids)
            else:
                tx_batch_raw = {t: backend.getTransactionRaw(t) for t in prev_txids}

            for vin in orig_tx.vin:
                prev_txid = i2h(vin.prevout.hash)
                prev_tx_hex = tx_batch_raw.get(prev_txid)
                if prev_tx_hex:
                    prev_tx = self.loadTx(bytes.fromhex(prev_tx_hex))
                    if vin.prevout.n < len(prev_tx.vout):
                        total_in += prev_tx.vout[vin.prevout.n].nValue

            total_out = sum(out.nValue for out in orig_tx.vout)
            current_fee = total_in - total_out

            # Calculate new fee
            tx_vsize = self.getTxVSize(orig_tx)
            new_fee = int(tx_vsize * new_feerate)

            if new_fee <= current_fee:
                self._log.warning(
                    f"bumpTxFee: New fee {new_fee} must be higher than current {current_fee}"
                )
                return None

            fee_increase = new_fee - current_fee

            change_idx = None
            change_value = 0
            for idx, out in enumerate(orig_tx.vout):
                try:
                    addr = self.getAddressFromScriptPubKey(out.scriptPubKey)
                    if wm.hasAddress(self.coin_type(), addr):
                        if out.nValue > change_value:
                            change_idx = idx
                            change_value = out.nValue
                except Exception:
                    continue

            if change_idx is None or change_value < fee_increase:
                self._log.warning("bumpTxFee: No suitable change output to reduce")
                return None

            new_tx = CTransaction()
            new_tx.nVersion = orig_tx.nVersion
            new_tx.vin = orig_tx.vin
            new_tx.vout = []

            for idx, out in enumerate(orig_tx.vout):
                if idx == change_idx:
                    new_out = self.txoType()(
                        out.nValue - fee_increase, out.scriptPubKey
                    )
                    new_tx.vout.append(new_out)
                else:
                    new_tx.vout.append(out)

            signed_tx = self.signTxWithWallet(new_tx.serialize())
            new_txid = self.publishTx(signed_tx)

            self._log.info(
                f"bumpTxFee: Replaced {txid[:16]}... with {new_txid[:16]}... "
                f"(fee: {current_fee} -> {new_fee})"
            )
            return new_txid

        except Exception as e:
            self._log.warning(f"bumpTxFee failed: {e}")
            return None

    def getAddressFromScriptPubKey(self, script) -> Optional[str]:
        """Extract address from scriptPubKey."""
        script_bytes = bytes(script) if hasattr(script, "__bytes__") else script
        if len(script_bytes) == 22 and script_bytes[0] == 0 and script_bytes[1] == 20:
            pkh = script_bytes[2:22]
            return self.encodeSegwitAddress(pkh)
        if len(script_bytes) == 25 and script_bytes[0:3] == b"\x76\xa9\x14":
            pkh = script_bytes[3:23]
            return self.pkh_to_address(pkh)
        return None

    def encodeTx(self, tx) -> bytes:
        return tx.serialize()

    def getTxid(self, tx) -> bytes:
        if isinstance(tx, str):
            tx = bytes.fromhex(tx)
        if isinstance(tx, bytes):
            tx = self.loadTx(tx)
        tx.rehash()
        return i2b(tx.sha256)

    def getTxOutputPos(self, tx, script):
        if isinstance(tx, bytes):
            tx = self.loadTx(tx)
        script_pk = self.getScriptDest(script)
        return findOutput(tx, script_pk)

    def getPubkeyHash(self, K: bytes) -> bytes:
        return hash160(K)

    def getScriptDest(self, script):
        return CScript([OP_0, sha256(script)])

    def getP2WSHScriptDest(self, script):
        return CScript([OP_0, sha256(script)])

    def getScriptScriptSig(self, script: bytes) -> bytes:
        return bytes()

    def getP2SHP2WSHDest(self, script):
        script_hash = sha256(script)
        assert len(script_hash) == 32
        p2wsh_hash = hash160(CScript([OP_0, script_hash]))
        assert len(p2wsh_hash) == 20
        return CScript([OP_HASH160, p2wsh_hash, OP_EQUAL])

    def getP2SHP2WSHScriptSig(self, script):
        script_hash = sha256(script)
        assert len(script_hash) == 32
        return CScript(
            [
                CScript(
                    [
                        OP_0,
                        script_hash,
                    ]
                ),
            ]
        )

    def getPkDest(self, K: bytes) -> bytearray:
        return self.getScriptForPubkeyHash(self.getPubkeyHash(K))

    def scanTxOutset(self, dest):
        if self._connection_type == "electrum":
            return self._scanTxOutsetElectrum(dest)
        return self.rpc("scantxoutset", ["start", ["raw({})".format(dest.hex())]])

    def _scanTxOutsetElectrum(self, dest):
        backend = self.getBackend()
        if not backend:
            return {"success": False, "unspents": [], "total_amount": 0}

        scripthash = self.scriptToScripthash(dest)
        try:
            utxos = backend._server.call(
                "blockchain.scripthash.listunspent", [scripthash]
            )
            chain_height = backend.getBlockHeight()
            total = sum(u.get("value", 0) for u in utxos)
            return {
                "success": True,
                "height": chain_height,
                "unspents": [
                    {
                        "txid": u["tx_hash"],
                        "vout": u["tx_pos"],
                        "amount": u["value"] / self.COIN(),
                        "height": u.get("height", 0),
                    }
                    for u in utxos
                ],
                "total_amount": total / self.COIN(),
            }
        except Exception as e:
            self._log.debug(f"_scanTxOutsetElectrum error: {e}")
            return {"success": False, "unspents": [], "total_amount": 0}

    def getTransaction(self, txid: bytes):
        if self._connection_type == "electrum":
            return self._getTransactionElectrum(txid)
        try:
            return bytes.fromhex(self.rpc("getrawtransaction", [txid.hex()]))
        except Exception as e:  # noqa: F841
            # TODO: filter errors
            return None

    def _getTransactionElectrum(self, txid: bytes):
        backend = self.getBackend()
        if not backend:
            return None
        try:
            tx_info = backend.getTransaction(txid.hex())
            if tx_info:
                tx_hex = tx_info.get("hex") if isinstance(tx_info, dict) else tx_info
                return bytes.fromhex(tx_hex)
            tx_hex = backend.getTransactionRaw(txid.hex())
            if tx_hex:
                return bytes.fromhex(tx_hex)
        except Exception as e:
            self._log.debug(f"_getTransactionElectrum failed for {txid.hex()}: {e}")
        return None

    def getWalletTransaction(self, txid: bytes):
        if self._connection_type == "electrum":
            return self._getTransactionElectrum(txid)
        try:
            return bytes.fromhex(self.rpc_wallet("gettransaction", [txid.hex()])["hex"])
        except Exception as e:  # noqa: F841
            # TODO: filter errors
            return None

    def listWalletTransactions(self, count=100, skip=0, include_watchonly=True):
        if self._connection_type == "electrum":
            return self._listWalletTransactionsElectrum(count, skip)
        try:
            return self.rpc_wallet(
                "listtransactions", ["*", count, skip, include_watchonly]
            )
        except Exception as e:
            self._log.error(f"listWalletTransactions failed: {e}")
            return []

    def _listWalletTransactionsElectrum(self, count=100, skip=0):
        backend = self.getBackend()
        if not backend:
            return []

        transactions = []
        chain_height = backend.getBlockHeight()

        addresses = []
        if hasattr(self, "_wallet_manager") and self._wallet_manager:
            addresses = list(self._wallet_manager._addresses.values())

        for address in addresses:
            try:
                history = backend.getAddressHistory(address)
                for tx in history:
                    tx_hash = tx.get("txid", tx.get("tx_hash", ""))
                    height = tx.get("height", 0)
                    confirmations = (
                        max(0, chain_height - height + 1) if height > 0 else 0
                    )
                    transactions.append(
                        {
                            "txid": tx_hash,
                            "address": address,
                            "confirmations": confirmations,
                            "category": "receive",
                            "amount": 0,
                            "time": 0,
                        }
                    )
            except Exception as e:
                self._log.debug(f"listWalletTransactions electrum error for tx: {e}")

        transactions = transactions[skip : skip + count]
        return transactions

    def setTxSignature(self, tx_bytes: bytes, stack) -> bytes:
        tx = self.loadTx(tx_bytes)
        tx.wit.vtxinwit.clear()
        tx.wit.vtxinwit.append(CTxInWitness())
        tx.wit.vtxinwit[0].scriptWitness.stack = stack
        return tx.serialize()

    def setTxScriptSig(
        self, tx_bytes: bytes, input_no: int, script_sig: bytes
    ) -> bytes:
        tx = self.loadTx(tx_bytes)
        tx.vin[0].scriptSig = script_sig
        return tx.serialize()

    def stripTxSignature(self, tx_bytes) -> bytes:
        tx = self.loadTx(tx_bytes)
        tx.wit.vtxinwit.clear()
        return tx.serialize()

    def extractLeaderSig(self, tx_bytes: bytes) -> bytes:
        tx = self.loadTx(tx_bytes)
        return tx.wit.vtxinwit[0].scriptWitness.stack[1]

    def extractFollowerSig(self, tx_bytes: bytes) -> bytes:
        tx = self.loadTx(tx_bytes)
        return tx.wit.vtxinwit[0].scriptWitness.stack[2]

    def createBLockTx(self, Kbs, output_amount, vkbv=None) -> bytes:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        p2wpkh_script_pk = self.getPkDest(Kbs)
        tx.vout.append(self.txoType()(output_amount, p2wpkh_script_pk))
        return tx.serialize()

    def encodeSharedAddress(self, Kbv, Kbs):
        return self.pubkey_to_segwit_address(Kbs)

    def publishBLockTx(
        self, kbv, Kbs, output_amount, feerate, unlock_time: int = 0
    ) -> bytes:
        b_lock_tx = self.createBLockTx(Kbs, output_amount)

        b_lock_tx = self.fundTx(b_lock_tx, feerate)
        b_lock_tx = self.signTxWithWallet(b_lock_tx)

        return bytes.fromhex(self.publishTx(b_lock_tx))

    def getTxVSize(self, tx, add_bytes: int = 0, add_witness_bytes: int = 0) -> int:
        wsf = self.witnessScaleFactor()
        len_full = len(tx.serialize_with_witness()) + add_bytes + add_witness_bytes
        len_nwit = len(tx.serialize_without_witness()) + add_bytes
        weight = len_nwit * (wsf - 1) + len_full
        return (weight + wsf - 1) // wsf

    def findTxB(
        self,
        kbv,
        Kbs,
        cb_swap_value: int,
        cb_block_confirmed: int,
        restore_height: int,
        bid_sender: bool,
        check_amount: bool = True,
    ):
        dest_address = (
            self.pubkey_to_segwit_address(Kbs)
            if self.using_segwit()
            else self.pubkey_to_address(Kbs)
        )
        return self.getLockTxHeight(None, dest_address, cb_swap_value, restore_height)

        """
        raw_dest = self.getPkDest(Kbs)

        rv = self.scanTxOutset(raw_dest)

        for utxo in rv['unspents']:
            if 'height' in utxo and utxo['height'] > 0 and rv['height'] - utxo['height'] > cb_block_confirmed:
                if self.make_int(utxo['amount']) != cb_swap_value:
                    self._log.warning('Found output to lock tx pubkey of incorrect value: %s', str(utxo['amount']))
                else:
                    return {'txid': utxo['txid'], 'vout': utxo['vout'], 'amount': utxo['amount'], 'height': utxo['height']}
        return None
        """

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        witness_bytes = 109
        vsize = self.getTxVSize(tx, add_witness_bytes=witness_bytes)
        pay_fee = round(fee_rate * vsize / 1000)
        self._log.info_s(
            f"BLockSpendTx fee_rate, vsize, fee: {fee_rate}, {vsize}, {pay_fee}."
        )
        return pay_fee

    def spendBLockTx(
        self,
        chain_b_lock_txid: bytes,
        address_to: str,
        kbv: bytes,
        kbs: bytes,
        cb_swap_value: int,
        b_fee: int,
        restore_height: int,
        spend_actual_balance: bool = False,
        lock_tx_vout=None,
    ) -> bytes:
        self._log.info(
            "spendBLockTx: {} {}\n".format(
                self._log.id(chain_b_lock_txid), lock_tx_vout
            )
        )
        locked_n = lock_tx_vout

        Kbs = self.getPubkey(kbs)
        script_pk = self.getPkDest(Kbs)

        if locked_n is None:
            if self.useBackend():
                backend = self.getBackend()
                tx_hex = backend.getTransactionRaw(chain_b_lock_txid.hex())
                if tx_hex:
                    lock_tx = self.loadTx(bytes.fromhex(tx_hex))
                    locked_n = findOutput(lock_tx, script_pk)
                    if locked_n is None:
                        self._log.error(
                            f"spendBLockTx: Output not found in tx {chain_b_lock_txid.hex()}, "
                            f"script_pk={script_pk.hex()}, num_outputs={len(lock_tx.vout)}"
                        )
                        for i, out in enumerate(lock_tx.vout):
                            self._log.debug(
                                f"  vout[{i}]: value={out.nValue}, scriptPubKey={out.scriptPubKey.hex()}"
                            )
                else:
                    self._log.warning(
                        f"spendBLockTx: Failed to fetch tx {chain_b_lock_txid.hex()} from electrum, "
                        f"defaulting to vout=0 (standard for B lock transactions)"
                    )
                    locked_n = 0
            else:
                wtx = self.rpc_wallet_watch(
                    "gettransaction",
                    [
                        chain_b_lock_txid.hex(),
                    ],
                )
                lock_tx = self.loadTx(bytes.fromhex(wtx["hex"]))
                locked_n = findOutput(lock_tx, script_pk)
        ensure(locked_n is not None, "Output not found in tx")

        pkh_to = self.decodeAddress(address_to)

        tx = CTransaction()
        tx.nVersion = self.txVersion()

        script_lock = self.getScriptForPubkeyHash(Kbs)
        chain_b_lock_txid_int = b2i(chain_b_lock_txid)

        tx.vin.append(
            CTxIn(
                COutPoint(chain_b_lock_txid_int, locked_n),
                nSequence=0,
                scriptSig=self.getScriptScriptSig(script_lock),
            )
        )
        tx.vout.append(
            self.txoType()(cb_swap_value, self.getScriptForPubkeyHash(pkh_to))
        )

        pay_fee = self.getBLockSpendTxFee(tx, b_fee)
        tx.vout[0].nValue = cb_swap_value - pay_fee

        b_lock_spend_tx = tx.serialize()
        b_lock_spend_tx = self.signTxWithKey(
            b_lock_spend_tx, kbs, prev_amount=cb_swap_value
        )

        return bytes.fromhex(self.publishTx(b_lock_spend_tx))

    def importWatchOnlyAddress(self, address: str, label: str) -> None:
        if self._connection_type == "electrum":
            wm = self.getWalletManager()
            if wm:
                wm.importWatchOnlyAddress(
                    self.coin_type(), address, label=label, source="swap"
                )
            return

        if self._use_descriptors:
            desc_watch = descsum_create(f"addr({address})")
            rv = self.rpc_wallet_watch(
                "importdescriptors",
                [
                    [
                        {"desc": desc_watch, "timestamp": "now", "active": False},
                    ],
                ],
            )
            ensure(rv[0]["success"] is True, "importdescriptors failed for watchonly")
            return

        self.rpc_wallet("importaddress", [address, label, False])

    def isWatchOnlyAddress(self, address: str) -> bool:
        addr_info = self.rpc_wallet("getaddressinfo", [address])
        return addr_info["iswatchonly"]

    def getSCLockScriptAddress(self, lock_script: bytes) -> str:
        lock_tx_dest = self.getScriptDest(lock_script)
        return self.encodeScriptDest(lock_tx_dest)

    def getLockTxHeight(
        self,
        txid,
        dest_address,
        bid_amount,
        rescan_from,
        find_index: bool = False,
        vout: int = -1,
    ):
        if self._connection_type == "electrum":
            return self._getLockTxHeightElectrum(
                txid, dest_address, bid_amount, rescan_from, find_index, vout
            )

        # Add watchonly address and rescan if required
        if not self.isAddressMine(dest_address, or_watch_only=True):
            self.importWatchOnlyAddress(dest_address, "bid")
            self._log.info(
                "Imported watch-only addr: {}".format(self._log.addr(dest_address))
            )
            self._log.info(
                "Rescanning {} chain from height: {}".format(
                    self.coin_name(), rescan_from
                )
            )
            self.rpc_wallet("rescanblockchain", [rescan_from])

        return_txid = True if txid is None else False
        if txid is None:
            txns = self.rpc_wallet_watch(
                "listunspent",
                [
                    0,
                    99999999,
                    [
                        dest_address,
                    ],
                ],
            )

            for tx in txns:
                if self.make_int(tx["amount"]) == bid_amount:
                    txid = bytes.fromhex(tx["txid"])
                    break

        if txid is None:
            return None

        try:
            # set `include_watchonly` explicitly to `True` to get transactions for watchonly addresses also in BCH
            tx = self.rpc_wallet_watch("gettransaction", [txid.hex(), True])

            block_height = 0
            if "blockhash" in tx:
                block_header = self.rpc("getblockheader", [tx["blockhash"]])
                block_height = block_header["height"]

            rv = {
                "depth": 0 if "confirmations" not in tx else tx["confirmations"],
                "height": block_height,
            }

            if "mempoolconflicts" in tx and len(tx["mempoolconflicts"]) > 0:
                rv["conflicts"] = tx["mempoolconflicts"]
            elif "walletconflicts" in tx and len(tx["walletconflicts"]) > 0:
                rv["conflicts"] = tx["walletconflicts"]
        except Exception as e:
            self._log.debug(
                "getLockTxHeight gettransaction failed: %s, %s", txid.hex(), str(e)
            )
            return None

        if find_index:
            tx_obj = self.rpc("decoderawtransaction", [tx["hex"]])
            rv["index"] = find_vout_for_address_from_txobj(tx_obj, dest_address)

        if return_txid:
            rv["txid"] = txid.hex()

        return rv

    def _getLockTxHeightElectrum(
        self,
        txid,
        dest_address,
        bid_amount,
        rescan_from,
        find_index: bool = False,
        vout: int = -1,
    ):
        backend = self.getBackend()
        if not backend:
            self._log.error("No electrum backend available for getLockTxHeight")
            return None

        self.importWatchOnlyAddress(dest_address, "bid")

        chain_height = self.getChainHeight()
        return_txid = txid is None

        if txid is None:
            utxos = backend.getUnspentOutputs([dest_address])
            for utxo in utxos:
                if utxo.get("value") == bid_amount:
                    txid = bytes.fromhex(utxo["txid"])
                    break

        if txid is None:
            return None

        wm = self.getWalletManager()
        if wm:
            cached = wm.getCachedTxConfirmations(self.coin_type(), txid.hex())
            if cached is not None:
                confirmations, block_height = cached
                if block_height > 0:
                    confirmations = max(0, chain_height - block_height + 1)
                rv = {"depth": confirmations, "height": block_height}
                if find_index:
                    try:
                        tx_info = backend.getTransaction(txid.hex())
                        tx_hex = None
                        if tx_info and isinstance(tx_info, dict):
                            tx_hex = tx_info.get("hex")
                        if not tx_hex:
                            tx_hex = backend.getTransactionRaw(txid.hex())
                        if tx_hex:
                            tx = self.loadTx(bytes.fromhex(tx_hex))
                            dest_script = self.getDestForAddress(dest_address)
                            for idx, txout in enumerate(tx.vout):
                                if txout.scriptPubKey == dest_script:
                                    rv["index"] = idx
                                    break
                    except Exception:
                        pass
                if return_txid:
                    rv["txid"] = txid.hex()
                return rv

        try:
            tx_info = backend.getTransaction(txid.hex())
            block_height = 0
            confirmations = 0

            if tx_info and isinstance(tx_info, dict):
                if "height" in tx_info:
                    block_height = tx_info.get("height", 0)
                elif "confirmations" in tx_info:
                    confirmations = tx_info.get("confirmations", 0)
                    if confirmations > 0:
                        block_height = chain_height - confirmations + 1

                if block_height > 0:
                    confirmations = max(0, chain_height - block_height + 1)

            if block_height == 0:
                history = backend.getAddressHistory(dest_address)
                for entry in history:
                    if entry.get("txid") == txid.hex():
                        block_height = entry.get("height", 0)
                        if block_height > 0:
                            confirmations = max(0, chain_height - block_height + 1)
                        break

            if wm:
                wm.cacheTxConfirmations(
                    self.coin_type(), txid.hex(), confirmations, block_height
                )

            rv = {
                "depth": confirmations,
                "height": block_height if block_height > 0 else 0,
            }
        except Exception as e:
            self._log.debug(
                "getLockTxHeight electrum failed: %s, %s", txid.hex(), str(e)
            )
            return None

        if find_index:
            try:
                tx_info = backend.getTransaction(txid.hex())
                tx_hex = None
                if tx_info and isinstance(tx_info, dict):
                    tx_hex = tx_info.get("hex")
                if not tx_hex:
                    tx_hex = backend.getTransactionRaw(txid.hex())
                if tx_hex:
                    tx = self.loadTx(bytes.fromhex(tx_hex))
                    dest_script = self.getDestForAddress(dest_address)
                    for idx, txout in enumerate(tx.vout):
                        if txout.scriptPubKey == dest_script:
                            rv["index"] = idx
                            break
            except Exception as e:
                self._log.debug(
                    f"lookupUnspentByAddress electrum index lookup error: {e}"
                )

        if return_txid:
            rv["txid"] = txid.hex()

        return rv

    def scriptToScripthash(self, script: bytes) -> str:
        return sha256(script)[::-1].hex()

    def checkWatchedOutput(self, txid_hex: str, vout: int):
        backend = self.getBackend()
        if not backend:
            return None

        try:
            tx_hex = backend._server.call_background(
                "blockchain.transaction.get", [txid_hex, False]
            )
            if not tx_hex:
                return None

            tx = self.loadTx(bytes.fromhex(tx_hex))
            script_hex = tx.vout[vout].scriptPubKey.hex()
            scripthash = self.scriptToScripthash(bytes.fromhex(script_hex))

            history = backend._server.call_background(
                "blockchain.scripthash.get_history", [scripthash]
            )
            self._log.debug(
                f"checkWatchedOutput {txid_hex}:{vout} - history has {len(history)} entries"
            )

            for tx_entry in history:
                self._log.debug(
                    f"  history entry: {tx_entry.get('tx_hash')[:16]}... height={tx_entry.get('height', 0)}"
                )
                if tx_entry.get("tx_hash") != txid_hex:
                    spend_hex = backend._server.call_background(
                        "blockchain.transaction.get", [tx_entry["tx_hash"], False]
                    )
                    if not spend_hex:
                        continue
                    spend_tx = self.loadTx(bytes.fromhex(spend_hex))
                    for i, inp in enumerate(spend_tx.vin):
                        inp_txid = f"{inp.prevout.hash:064x}"
                        if inp_txid == txid_hex and inp.prevout.n == vout:
                            self._log.debug(f"  Found spend in {tx_entry['tx_hash']}")
                            return {
                                "txid": tx_entry["tx_hash"],
                                "vin": i,
                                "height": tx_entry.get("height", 0),
                            }
        except Exception as e:
            error_msg = str(e).lower()
            if "no such mempool or blockchain transaction" not in error_msg:
                self._log.debug(
                    f"checkWatchedOutput exception for {txid_hex}:{vout}: {e}"
                )
        return None

    def checkWatchedScript(self, script: bytes):
        backend = self.getBackend()
        if not backend:
            return None

        try:
            scripthash = self.scriptToScripthash(script)
            history = backend._server.call_background(
                "blockchain.scripthash.get_history", [scripthash]
            )
            for tx_entry in history:
                tx_hex = backend._server.call_background(
                    "blockchain.transaction.get", [tx_entry["tx_hash"], False]
                )
                if not tx_hex:
                    continue
                tx = self.loadTx(bytes.fromhex(tx_hex))
                for i, out in enumerate(tx.vout):
                    if out.scriptPubKey == script:
                        return {
                            "txid": tx_entry["tx_hash"],
                            "vout": i,
                            "height": tx_entry.get("height", 0),
                        }
        except Exception as e:
            self._log.debug(f"_findOutputSpendingScript electrum error: {e}")
        return None

    def getOutput(self, txid, dest_script, expect_value, xmr_swap=None):
        if self._connection_type == "electrum":
            return self._getOutputElectrum(txid, dest_script, expect_value, xmr_swap)

        # TODO: Use getrawtransaction if txindex is active
        utxos = self.rpc(
            "scantxoutset", ["start", ["raw({})".format(dest_script.hex())]]
        )
        if "height" in utxos:  # chain_height not returned by v18 codebase
            chain_height = utxos["height"]
        else:
            chain_height = self.getChainHeight()
        rv = []
        for utxo in utxos["unspents"]:
            if txid and txid.hex() != utxo["txid"]:
                continue

            if expect_value != self.make_int(utxo["amount"]):
                continue

            rv.append(
                {
                    "depth": (
                        0
                        if "height" not in utxo
                        else (chain_height - utxo["height"]) + 1
                    ),
                    "height": 0 if "height" not in utxo else utxo["height"],
                    "amount": self.make_int(utxo["amount"]),
                    "txid": utxo["txid"],
                    "vout": utxo["vout"],
                }
            )
        return rv, chain_height

    def _getOutputElectrum(self, txid, dest_script, expect_value, xmr_swap=None):
        backend = self.getBackend()
        if not backend:
            return [], 0

        scripthash = self.scriptToScripthash(dest_script)
        chain_height = backend.getBlockHeight()
        rv = []

        try:
            utxos = backend._server.call(
                "blockchain.scripthash.listunspent", [scripthash]
            )
            for utxo in utxos:
                utxo_txid = utxo["tx_hash"]
                if txid and txid.hex() != utxo_txid:
                    continue

                utxo_value = utxo["value"]
                if expect_value != utxo_value:
                    continue

                utxo_height = utxo.get("height", 0)
                rv.append(
                    {
                        "depth": (
                            0 if utxo_height <= 0 else (chain_height - utxo_height) + 1
                        ),
                        "height": utxo_height if utxo_height > 0 else 0,
                        "amount": utxo_value,
                        "txid": utxo_txid,
                        "vout": utxo["tx_pos"],
                    }
                )
        except Exception as e:
            self._log.debug(f"_getOutputElectrum error: {e}")

        return rv, chain_height

    def withdrawCoin(self, value: float, addr_to: str, subfee: bool):
        if self.useBackend():
            return self._withdrawCoinElectrum(value, addr_to, subfee)

        params = [addr_to, value, "", "", subfee, True, self._conf_target]
        return self.rpc_wallet("sendtoaddress", params)

    def _withdrawCoinElectrum(self, value: float, addr_to: str, subfee: bool) -> str:

        amount_sats = self.make_int(value)

        tx_hex = self._createRawFundedTransactionElectrum(addr_to, amount_sats, subfee)

        signed_tx = self.signTxWithWallet(bytes.fromhex(tx_hex))

        txid = self._backend.broadcastTransaction(signed_tx.hex())
        return txid

    def signCompact(self, k, message: str) -> bytes:
        message_hash = sha256(bytes(message, "utf-8"))

        privkey = PrivateKey(k)
        return privkey.sign_recoverable(message_hash, hasher=None)[:64]

    def signRecoverable(self, k, message: str) -> bytes:
        message_hash = sha256(bytes(message, "utf-8"))

        privkey = PrivateKey(k)
        return privkey.sign_recoverable(message_hash, hasher=None)

    def verifyCompactSig(self, K, message: str, sig) -> None:
        message_hash = sha256(bytes(message, "utf-8"))
        pubkey = PublicKey(K)
        rv = pubkey.verify_compact(sig, message_hash, hasher=None)
        assert rv is True

    def verifySigAndRecover(self, sig, message: str) -> bytes:
        message_hash = sha256(bytes(message, "utf-8"))
        pubkey = PublicKey.from_signature_and_message(sig, message_hash, hasher=None)
        return pubkey.format()

    def verifyMessage(
        self, address: str, message: str, signature: str, message_magic: str = None
    ) -> bool:
        if message_magic is None:
            message_magic = self.chainparams()["message_magic"]

        message_bytes = (
            SerialiseNumCompact(len(message_magic))
            + bytes(message_magic, "utf-8")
            + SerialiseNumCompact(len(message))
            + bytes(message, "utf-8")
        )
        message_hash = sha256(sha256(message_bytes))
        signature_bytes = base64.b64decode(signature)
        rec_id = (signature_bytes[0] - 27) & 3
        signature_bytes = signature_bytes[1:] + bytes((rec_id,))
        try:
            pubkey = PublicKey.from_signature_and_message(
                signature_bytes, message_hash, hasher=None
            )
        except Exception as e:
            self._log.info("verifyMessage failed: " + str(e))
            return False

        address_hash = self.decodeAddress(address)
        pubkey_hash = hash160(pubkey.format())

        return True if address_hash == pubkey_hash else False

    def showLockTransfers(self, kbv, Kbs, restore_height):
        raise ValueError("Unimplemented")

    def getWitnessStackSerialisedLength(self, witness_stack):
        length: int = 0
        if len(witness_stack) > 0 and isinstance(witness_stack[0], list):
            for input_stack in witness_stack:
                length += getCompactSizeLen(len(input_stack))
                for e in input_stack:
                    length += getWitnessElementLen(len(e))
        else:
            length += getCompactSizeLen(len(witness_stack))
            for e in witness_stack:
                length += getWitnessElementLen(len(e))

        # See core SerializeTransaction
        length += 1  # vinDummy
        length += 1  # flags
        return length

    def describeTx(self, tx_hex: str):
        if self.useBackend():
            return self._describeTxLocal(tx_hex)
        return self.rpc("decoderawtransaction", [tx_hex])

    def _describeTxLocal(self, tx_hex: str) -> dict:
        tx = self.loadTx(bytes.fromhex(tx_hex))
        tx.rehash()

        bech32_prefix = self.chainparams_network()["hrp"]

        vout = []
        for i, out in enumerate(tx.vout):
            script_hex = out.scriptPubKey.hex()
            scriptPubKey = {"hex": script_hex}

            try:
                if (
                    len(out.scriptPubKey) == 22
                    and out.scriptPubKey[0] == 0
                    and out.scriptPubKey[1] == 20
                ):
                    pkh = bytes(out.scriptPubKey[2:22])
                    addr = segwit_addr.encode(bech32_prefix, 0, pkh)
                    scriptPubKey["address"] = addr
                elif (
                    len(out.scriptPubKey) == 34
                    and out.scriptPubKey[0] == 0
                    and out.scriptPubKey[1] == 32
                ):
                    script_hash = bytes(out.scriptPubKey[2:34])
                    addr = segwit_addr.encode(bech32_prefix, 0, script_hash)
                    scriptPubKey["address"] = addr
            except Exception as e:
                self._log.debug(
                    f"decodeTransaction address decode error for output {i}: {e}"
                )

            vout.append(
                {
                    "n": i,
                    "value": self.format_amount(out.nValue),
                    "scriptPubKey": scriptPubKey,
                }
            )

        vin = []
        for inp in tx.vin:
            vin.append(
                {
                    "txid": i2h(inp.prevout.hash),
                    "vout": inp.prevout.n,
                    "sequence": inp.nSequence,
                }
            )

        txid = (
            tx.hash
            if hasattr(tx, "hash") and tx.hash
            else (i2h(tx.sha256) if tx.sha256 else "")
        )

        return {
            "txid": txid,
            "version": tx.nVersion,
            "locktime": tx.nLockTime,
            "vin": vin,
            "vout": vout,
        }

    def decodeRawTransaction(self, tx_hex: str):
        if self.useBackend():
            return self._describeTxLocal(tx_hex)
        return self.rpc("decoderawtransaction", [tx_hex])

    def getSpendableBalance(self) -> int:
        if self.useBackend():
            cached = getattr(self, "_cached_wallet_info", None)
            if cached is not None:
                return self.make_int(cached.get("balance", 0))
            return 0

        return self.make_int(self.rpc_wallet("getbalances")["mine"]["trusted"])

    def createUTXO(self, value_sats: int):
        # Create a new address and send value_sats to it

        spendable_balance = self.getSpendableBalance()
        if spendable_balance < value_sats:
            raise ValueError("Balance too low")

        address = self.getNewAddress(self._use_segwit, "create_utxo")
        return (
            self.withdrawCoin(self.format_amount(value_sats), address, False),
            address,
        )

    def createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int,
        sub_fee: bool = False,
        lock_unspents: bool = True,
    ) -> str:
        if self.useBackend():
            return self._createRawFundedTransactionElectrum(addr_to, amount, sub_fee)

        txn = self.rpc(
            "createrawtransaction", [[], {addr_to: self.format_amount(amount)}]
        )

        options = {
            "lockUnspents": lock_unspents,
            "conf_target": self._conf_target,
        }
        if sub_fee:
            options["subtractFeeFromOutputs"] = [
                0,
            ]
        return self.rpc_wallet("fundrawtransaction", [txn, options])["hex"]

    def _createRawFundedTransactionElectrum(
        self, addr_to: str, amount: int, sub_fee: bool = False
    ) -> str:
        feerate, _rate_src = self.get_fee_rate()
        if isinstance(feerate, int):
            fee_per_vbyte = max(1, feerate // 1000)
        else:
            fee_per_vbyte = max(1, int(feerate * 100000))

        if sub_fee:
            wm = self.getWalletManager()
            backend = self.getBackend()
            if not wm or not backend:
                raise ValueError("Electrum backend or WalletManager not available")

            funded_addresses = wm.getFundedAddresses(self.coin_type())
            addr_to_sh = (
                funded_addresses
                if funded_addresses
                else wm.getSignableAddresses(self.coin_type())
            )

            scripthashes = list(addr_to_sh.values())
            sh_to_addr = {sh: addr for addr, sh in addr_to_sh.items()}
            batch_utxos = backend.getBatchUnspent(scripthashes)

            all_utxos = []
            for sh, sh_utxos in batch_utxos.items():
                addr = sh_to_addr.get(sh, "")
                for utxo in sh_utxos:
                    utxo["address"] = addr
                    all_utxos.append(utxo)

            if not all_utxos:
                raise ValueError("No UTXOs available")

            total_balance = sum(u.get("value", 0) for u in all_utxos)

            est_vsize = 10 + 31 + len(all_utxos) * 68
            est_fee = est_vsize * fee_per_vbyte

            if total_balance <= est_fee:
                raise ValueError(
                    f"Balance {total_balance} too small to cover fee {est_fee}"
                )

            tx = CTransaction()
            tx.nVersion = self.txVersion()

            for utxo in all_utxos:
                txid_bytes = bytes.fromhex(utxo["txid"])[::-1]
                txid_int = int.from_bytes(txid_bytes, "little")
                txin = CTxIn(COutPoint(txid_int, utxo["vout"]))
                txin.nSequence = 0xFFFFFFFD
                tx.vin.append(txin)

            script = self.getDestForAddress(addr_to)
            tx.vout.append(self.txoType()(total_balance - est_fee, script))

            tx_key = self._getTxInputsKey(tx)
            with self._pending_utxos_lock:
                self._pending_utxos_map[tx_key] = all_utxos

            self._log.debug(
                f"_createRawFundedTransactionElectrum: sub_fee=True, utxos={len(all_utxos)}, "
                f"balance={total_balance}, fee={est_fee}"
            )
            return tx.serialize().hex()

        tx = CTransaction()
        tx.nVersion = self.txVersion()
        script = self.getDestForAddress(addr_to)
        output = self.txoType()(amount, script)
        tx.vout.append(output)

        tx_bytes = tx.serialize()
        funded_tx = self.fundTx(tx_bytes, feerate)

        return funded_tx.hex()

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self.createRawFundedTransaction(addr_to, amount)

        if self.useBackend():
            signed = self.signTxWithWallet(bytes.fromhex(txn_funded))
            return signed.hex()

        return self.rpc_wallet("signrawtransactionwithwallet", [txn_funded])["hex"]

    def getBlockWithTxns(self, block_hash: str):
        if self._connection_type == "electrum":
            raise NotImplementedError("getBlockWithTxns not available in electrum mode")
        return self.rpc("getblock", [block_hash, 2])

    def listUtxos(self):
        if self._connection_type == "electrum":
            return self._listUtxosElectrum()
        return self.rpc_wallet("listunspent")

    def _listUtxosElectrum(self):
        backend = self.getBackend()
        if not backend:
            return []

        utxos = []
        addresses = []
        if hasattr(self, "_wallet_manager") and self._wallet_manager:
            addresses = list(self._wallet_manager._addresses.values())

        chain_height = backend.getBlockHeight()
        for address in addresses:
            try:
                scripthash = self.encodeScriptHash(self.decodeAddress(address))
                addr_utxos = backend._server.call(
                    "blockchain.scripthash.listunspent", [scripthash]
                )
                for u in addr_utxos:
                    height = u.get("height", 0)
                    confirmations = (
                        max(0, chain_height - height + 1) if height > 0 else 0
                    )
                    utxos.append(
                        {
                            "txid": u["tx_hash"],
                            "vout": u["tx_pos"],
                            "address": address,
                            "amount": u["value"] / self.COIN(),
                            "confirmations": confirmations,
                            "spendable": True,
                        }
                    )
            except Exception as e:
                self._log.debug(f"getUnspentOutputs electrum error for address: {e}")
        return utxos

    def getUnspentsByAddr(self):
        unspent_addr = dict()

        if self.useBackend():
            wm = self.getWalletManager()
            if wm:
                addresses = wm.getAllAddresses(self.coin_type())
                if addresses:
                    return self._backend.getBalance(addresses)
            return unspent_addr

        unspent = self.rpc_wallet("listunspent")
        for u in unspent:
            if u.get("spendable", False) is False:
                continue
            if "address" not in u:
                continue
            if "desc" in u:
                desc = u["desc"]
                if self.using_segwit:
                    if self.use_p2shp2wsh():
                        if not desc.startswith("sh(wpkh"):
                            continue
                    else:
                        if not desc.startswith("wpkh"):
                            continue
                else:
                    if not desc.startswith("pkh"):
                        continue
            unspent_addr[u["address"]] = unspent_addr.get(
                u["address"], 0
            ) + self.make_int(u["amount"], r=1)
        return unspent_addr

    def getUTXOBalance(self, address: str):
        if self._connection_type == "electrum":
            return self._getUTXOBalanceElectrum(address)

        sum_unspent = 0

        with BTCInterface._scantxoutset_lock:
            self._log.debug("scantxoutset start")
            ro = self.rpc("scantxoutset", ["start", ["addr({})".format(address)]])
            self._log.debug("scantxoutset end")

            for o in ro["unspents"]:
                sum_unspent += self.make_int(o["amount"])
        return sum_unspent

    def _getUTXOBalanceElectrum(self, address: str):
        backend = self.getBackend()
        if not backend:
            return 0

        try:
            scripthash = self.encodeScriptHash(self.decodeAddress(address))
            utxos = backend._server.call(
                "blockchain.scripthash.listunspent", [scripthash]
            )
            return sum(u.get("value", 0) for u in utxos)
        except Exception as e:
            self._log.debug(f"_getUTXOBalanceElectrum error: {e}")
            return 0

    def signMessage(self, address: str, message: str) -> str:
        if self._connection_type == "electrum":
            return self._signMessageElectrum(address, message)
        return self.rpc_wallet(
            "signmessage",
            [address, message],
        )

    def _signMessageElectrum(self, address: str, message: str) -> str:
        wm = self.getWalletManager()
        if not wm:
            raise ValueError("WalletManager not available")

        privkey = wm.getPrivateKey(self.coin_type(), address)
        if not privkey:
            raise ValueError(f"Private key not found for address: {address}")

        key_wif = self.encodeKey(privkey)
        return self._signMessageWithKeyLocal(key_wif, message)

    def signMessageWithKey(self, key_wif: str, message: str) -> str:
        if self._connection_type == "electrum":
            return self._signMessageWithKeyLocal(key_wif, message)
        return self.rpc("signmessagewithprivkey", [key_wif, message])

    def _signMessageWithKeyLocal(self, key_wif: str, message: str) -> str:
        from coincurve import PrivateKey as CCPrivateKey

        privkey_bytes = decodeWif(key_wif)

        message_magic = self.chainparams()["message_magic"]
        message_bytes = (
            SerialiseNumCompact(len(message_magic))
            + bytes(message_magic, "utf-8")
            + SerialiseNumCompact(len(message))
            + bytes(message, "utf-8")
        )
        message_hash = sha256(sha256(message_bytes))

        pk = CCPrivateKey(privkey_bytes)
        sig = pk.sign_recoverable(message_hash, hasher=None)

        rec_id = sig[64]
        header = 27 + rec_id + 4
        formatted_sig = bytes([header]) + sig[:64]

        return base64.b64encode(formatted_sig).decode("utf-8")

    def getProofOfFunds(self, amount_for, extra_commit_bytes):
        if self.useBackend():
            wm = self.getWalletManager()
            if wm:
                result = wm.findAddressWithCachedBalance(
                    self.coin_type(),
                    amount_for,
                    include_internal=False,
                    max_cache_age=120,
                )

                if result is None and not wm.hasCachedBalances(self.coin_type()):
                    try:
                        addresses = wm.getAllAddresses(
                            self.coin_type(), include_internal=False
                        )
                        if addresses:
                            result = self._backend.findAddressWithBalance(
                                addresses, amount_for
                            )
                    except Exception as e:
                        self._log.warning(
                            f"getProofOfFunds: error querying balance: {e}"
                        )

                ensure(
                    result is not None,
                    "Could not find address with enough funds for proof",
                )
                funds_addr, balance = result
                sign_for_addr = funds_addr

                try:
                    if self.using_segwit():
                        pkh = self.decodeAddress(sign_for_addr)
                        sign_for_addr = self.pkh_to_address(pkh)

                    sign_message = (
                        sign_for_addr + "_swap_proof_" + extra_commit_bytes.hex()
                    )
                    priv_key = wm.getPrivateKey(self.coin_type(), funds_addr)
                    if priv_key:
                        key_wif = self.encodeKey(priv_key)
                        signature = self.signMessageWithKey(key_wif, sign_message)
                        self._log.debug(
                            f"getProofOfFunds electrum: addr={funds_addr[:20]}..., balance={balance}"
                        )
                        return (sign_for_addr, signature, [])
                    else:
                        self._log.error(
                            f"getProofOfFunds electrum: priv_key is None for {funds_addr}"
                        )
                except Exception as e:
                    self._log.error(f"getProofOfFunds electrum: signing failed: {e}")
                    import traceback

                    self._log.error(traceback.format_exc())
                    raise
            raise ValueError("Cannot sign message: address not in WalletManager")

        unspent_addr = self.getUnspentsByAddr()
        sign_for_addr = None
        for addr, value in unspent_addr.items():
            if value >= amount_for:
                sign_for_addr = addr
                break

        ensure(
            sign_for_addr is not None,
            "Could not find address with enough funds for proof",
        )

        self._log.debug(f"sign_for_addr {sign_for_addr}")

        funds_addr: str = sign_for_addr

        if (
            self.using_segwit()
        ):  # TODO: Use isSegwitAddress when scantxoutset can use combo
            # 'Address does not refer to key' for non p2pkh
            pkh = self.decodeAddress(sign_for_addr)
            sign_for_addr = self.pkh_to_address(pkh)
            self._log.debug(f"sign_for_addr converted {sign_for_addr}")

        sign_message: str = sign_for_addr + "_swap_proof_" + extra_commit_bytes.hex()
        if self._use_descriptors:
            # https://github.com/bitcoin/bitcoin/issues/10542
            # https://github.com/bitcoin/bitcoin/issues/26046
            priv_keys = self.rpc_wallet(
                "listdescriptors",
                [
                    True,
                ],
            )
            addr_info = self.rpc_wallet(
                "getaddressinfo",
                [
                    funds_addr,
                ],
            )
            hdkeypath = addr_info["hdkeypath"]
            sign_for_address_key = None
            for descriptor in priv_keys["descriptors"]:
                if descriptor["active"] is False or descriptor["internal"] is True:
                    continue
                desc = descriptor["desc"]
                assert desc.startswith("wpkh(")
                ext_key = desc[5:].split(")")[0].split("/", 1)[0]
                ext_key_data = decodeAddress(ext_key)[4:]
                ci_part = self._sc.ci(Coins.PART)
                ext_key_data_part = ci_part.encode_secret_extkey(ext_key_data)
                rv = ci_part.rpc_wallet(
                    "extkey", ["info", ext_key_data_part, hdkeypath]
                )
                extkey_derived = rv["key_info"]["result"]
                ext_key_data = decodeAddress(extkey_derived)[4:]
                ek = ExtKeyPair()
                ek.decode(ext_key_data)
                sign_for_address_key = self.encodeKey(ek._key)
                break
            assert sign_for_address_key is not None
            signature = self.signMessageWithKey(sign_for_address_key, sign_message)
            del priv_keys
        else:
            signature = self.signMessage(sign_for_addr, sign_message)

        prove_utxos = []  # TODO: Send specific utxos
        return (sign_for_addr, signature, prove_utxos)

    def encodeProofUtxos(self, proof_utxos):
        packed_utxos = bytes()
        for utxo in proof_utxos:
            packed_utxos += utxo[0] + utxo[1].to_bytes(2, "big")
        return packed_utxos

    def decodeProofUtxos(self, msg_utxos):
        proof_utxos = []
        if len(msg_utxos) > 0:
            num_utxos = len(msg_utxos) // 34
            p: int = 0
            for i in range(num_utxos):
                proof_utxos.append(
                    (
                        msg_utxos[p : p + 32],
                        int.from_bytes(msg_utxos[p + 32 : p + 34], "big"),
                    )
                )
                p += 34
        return proof_utxos

    def verifyProofOfFunds(self, address, signature, utxos, extra_commit_bytes):
        passed = self.verifyMessage(
            address, address + "_swap_proof_" + extra_commit_bytes.hex(), signature
        )
        ensure(passed is True, "Proof of funds signature invalid")

        if self.using_segwit():
            address = self.encodeSegwitAddress(decodeAddress(address)[1:])

        if self.useBackend():
            backend = self.getBackend()
            if backend:
                try:
                    unspents = backend.getUnspentOutputs([address])
                    total = sum(u.get("value", 0) for u in unspents)
                    self._log.debug(
                        f"verifyProofOfFunds electrum: {address} has {total} sats"
                    )
                    return total
                except Exception as e:
                    self._log.warning(
                        f"Electrum balance check failed: {e}, skipping balance verification"
                    )
                    return 10**18

        try:
            return self.getUTXOBalance(address)
        except Exception as e:
            self._log.warning(
                f"scantxoutset failed: {e}, skipping balance verification (signature valid)"
            )
            return 10**18

    def isWalletEncrypted(self) -> bool:
        if self._connection_type == "electrum":
            return False
        wallet_info = self.rpc_wallet("getwalletinfo")
        return "unlocked_until" in wallet_info

    def isWalletLocked(self) -> bool:
        if self._connection_type == "electrum":
            return False
        wallet_info = self.rpc_wallet("getwalletinfo")
        if "unlocked_until" in wallet_info and wallet_info["unlocked_until"] <= 0:
            return True
        return False

    def isWalletEncryptedLocked(self) -> (bool, bool):
        if self._connection_type == "electrum":
            return False, False
        wallet_info = self.rpc_wallet("getwalletinfo")
        encrypted = "unlocked_until" in wallet_info
        locked = encrypted and wallet_info["unlocked_until"] <= 0
        return encrypted, locked

    def createWallet(self, wallet_name: str, password: str = "") -> None:
        if self._connection_type == "electrum":
            return
        self.rpc(
            "createwallet",
            [wallet_name, False, True, password, False, self._use_descriptors],
        )

    def setActiveWallet(self, wallet_name: str) -> None:
        if self._connection_type == "electrum":
            return
        # For debugging
        self.rpc_wallet = make_rpc_func(
            self._rpcport, self._rpcauth, host=self._rpc_host, wallet=wallet_name
        )
        self._rpc_wallet = wallet_name

    def newKeypool(self) -> None:
        if self._connection_type == "electrum":
            return
        self._log.debug("Running newkeypool.")
        self.rpc_wallet("newkeypool")

    def encryptWallet(self, password: str, check_seed: bool = True):
        if self._connection_type == "electrum":
            return
        # Watchonly wallets are not encrypted
        # Workaround for https://github.com/bitcoin/bitcoin/issues/26607
        seed_id_before: str = self.getWalletSeedID()
        orig_active_descriptors = []
        orig_hdchain_bytes = None
        walletpath = None
        max_hdchain_key_count: int = 4000000  # Arbitrary

        chain_client_settings = self._sc.getChainClientSettings(
            self.coin_type()
        )  # basicswap.json
        if (
            chain_client_settings.get("manage_daemon", False)
            and check_seed is True
            and seed_id_before != "Not found"
        ):
            # Store active keys
            self.rpc("unloadwallet", [self._rpc_wallet])

            datadir = chain_client_settings["datadir"]
            if self._network != "mainnet":
                datadir = os.path.join(datadir, self._network)
            try_wallet_path = os.path.join(datadir, self._rpc_wallet)
            if os.path.exists(try_wallet_path):
                walletpath = try_wallet_path
            else:
                try_wallet_path = os.path.join(datadir, "wallets", self._rpc_wallet)
                if os.path.exists(try_wallet_path):
                    walletpath = try_wallet_path

            walletfilepath = walletpath
            if os.path.isdir(walletpath):
                walletfilepath = os.path.join(walletpath, "wallet.dat")

            if walletpath is None:
                self._log.warning(f"Unable to find {self.ticker()} wallet path.")
            else:
                if self._use_descriptors:
                    orig_active_descriptors = []
                    with sqlite3.connect(walletfilepath) as conn:
                        c = conn.cursor()
                        rows = c.execute(
                            "SELECT * FROM main WHERE key in (:kext, :kint)",
                            {
                                "kext": bytes.fromhex(
                                    "1161637469766565787465726e616c73706b02"
                                ),
                                "kint": bytes.fromhex(
                                    "11616374697665696e7465726e616c73706b02"
                                ),
                            },
                        )
                        for row in rows:
                            k, v = row
                            orig_active_descriptors.append({"k": k, "v": v})
                else:
                    seedid_bytes: bytes = bytes.fromhex(seed_id_before)[::-1]
                    with open(walletfilepath, "rb") as fp:
                        with mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            pos = mm.find(seedid_bytes)
                            while pos != -1:
                                mm.seek(pos - 8)
                                hdchain_bytes = mm.read(12 + 20)
                                version = int.from_bytes(hdchain_bytes[:4], "little")
                                if version == 2:
                                    external_counter = int.from_bytes(
                                        hdchain_bytes[4:8], "little"
                                    )
                                    internal_counter = int.from_bytes(
                                        hdchain_bytes[-4:], "little"
                                    )
                                    if (
                                        external_counter > 0
                                        and external_counter <= max_hdchain_key_count
                                        and internal_counter > 0
                                        and internal_counter <= max_hdchain_key_count
                                    ):
                                        orig_hdchain_bytes = hdchain_bytes
                                        self._log.debug(
                                            f"Found hdchain for: {seed_id_before} external_counter: {external_counter}, internal_counter: {internal_counter}."
                                        )
                                        break
                                pos = mm.find(seedid_bytes, pos + 1)

            self.rpc("loadwallet", [self._rpc_wallet])

        self.rpc_wallet("encryptwallet", [password])

        if check_seed is False or seed_id_before == "Not found" or walletpath is None:
            return
        seed_id_after: str = self.getWalletSeedID()

        if seed_id_before == seed_id_after:
            return
        self._log.warning(f"{self.ticker()} wallet seed changed after encryption.")
        self._log.debug(
            f"seed_id_before: {seed_id_before} seed_id_after: {seed_id_after}."
        )
        self.setWalletSeedWarning(True)

        if chain_client_settings.get("manage_daemon", False) is False:
            self._log.warning(
                f"{self.ticker()} manage_daemon is false. Can't attempt to fix."
            )
            return
        if self._use_descriptors:
            if len(orig_active_descriptors) < 2:
                self._log.error(
                    "Could not find original active descriptors for wallet."
                )
                return
            self._log.info("Attempting to revert to last descriptors.")
        else:
            if orig_hdchain_bytes is None:
                self._log.error("Could not find hdchain for wallet.")
                return
            self._log.info("Attempting to revert to last hdchain.")
        try:
            # Make a copy of the encrypted wallet before modifying it
            bkp_path = walletpath + ".bkp"
            for i in range(100):
                if not os.path.exists(bkp_path):
                    break
                bkp_path = walletpath + f".bkp{i}"

            if os.path.exists(bkp_path):
                self._log.error("Could not find backup path for wallet.")
                return

            self.rpc("unloadwallet", [self._rpc_wallet])

            if os.path.isfile(walletpath):
                shutil.copy(walletpath, bkp_path)
            else:
                shutil.copytree(walletpath, bkp_path)

            hdchain_replaced: bool = False
            if self._use_descriptors:
                with sqlite3.connect(walletfilepath) as conn:
                    c = conn.cursor()
                    c.executemany(
                        "UPDATE main SET value = :v WHERE key = :k",
                        orig_active_descriptors,
                    )
                    conn.commit()
            else:
                seedid_after_bytes: bytes = bytes.fromhex(seed_id_after)[::-1]
                with open(walletfilepath, "r+b") as fp:
                    with mmap.mmap(fp.fileno(), 0) as mm:
                        pos = mm.find(seedid_after_bytes)
                        while pos != -1:
                            mm.seek(pos - 8)
                            hdchain_bytes = mm.read(12 + 20)
                            version = int.from_bytes(hdchain_bytes[:4], "little")
                            if version == 2:
                                external_counter = int.from_bytes(
                                    hdchain_bytes[4:8], "little"
                                )
                                internal_counter = int.from_bytes(
                                    hdchain_bytes[-4:], "little"
                                )
                                if (
                                    external_counter > 0
                                    and external_counter <= max_hdchain_key_count
                                    and internal_counter > 0
                                    and internal_counter <= max_hdchain_key_count
                                ):
                                    self._log.debug(
                                        f"Replacing hdchain for: {seed_id_after} external_counter: {external_counter}, internal_counter: {internal_counter}."
                                    )
                                    offset: int = pos - 8
                                    mm.seek(offset)
                                    mm.write(orig_hdchain_bytes)
                                    self._log.debug(
                                        f"hdchain replaced at offset: {offset}."
                                    )
                                    hdchain_replaced = True
                                    # Can appear multiple times in file, replace all.
                            pos = mm.find(seedid_after_bytes, pos + 1)

                if hdchain_replaced is False:
                    self._log.error("Could not find new hdchain in wallet.")

            self.rpc("loadwallet", [self._rpc_wallet])

            if hdchain_replaced:
                self.unlockWallet(password, check_seed=False)
                seed_id_after_restore: str = self.getWalletSeedID()
                if seed_id_after_restore == seed_id_before:
                    self.newKeypool()
                else:
                    self._log.warning(
                        f"Expected seed id not found: {seed_id_before}, have {seed_id_after_restore}."
                    )

                self.lockWallet()

        except Exception as e:
            self._log.error(f"{self.ticker()} recreating wallet failed: {e}.")
            if self._sc.debug:
                self._log.error(traceback.format_exc())

    def changeWalletPassword(
        self, old_password: str, new_password: str, check_seed_if_encrypt: bool = True
    ):
        self._log.info("changeWalletPassword - {}".format(self.ticker()))
        if old_password == "":
            if self.isWalletEncrypted():
                raise ValueError("Old password must be set")
            return self.encryptWallet(new_password, check_seed=check_seed_if_encrypt)
        self.rpc_wallet("walletpassphrasechange", [old_password, new_password])

    def unlockWallet(self, password: str, check_seed: bool = True) -> None:
        if password == "":
            return
        self._log.info(f"unlockWallet - {self.ticker()}")

        if self.useBackend():
            return

        if self.coin_type() in (Coins.BTC, Coins.LTC):
            # Recreate wallet if none found
            # Required when encrypting an existing btc/ltc wallet, or switching from electrum to rpc mode. Workaround is to delete the btc/ltc wallet and recreate.
            wallets = self.rpc("listwallets")
            if self._rpc_wallet not in wallets:
                self._log.info(
                    f'Creating wallet "{self._rpc_wallet}" for {self.coin_name()}.'
                )
                # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
                self.rpc(
                    "createwallet",
                    [
                        self._rpc_wallet,
                        False,
                        True,
                        password,
                        False,
                        self._use_descriptors,
                    ],
                )

            try:
                seed_id = self.getWalletSeedID()
                self._log.debug(
                    f"{self.ticker()} unlockWallet getWalletSeedID returned: {seed_id}"
                )
                needs_seed_init = seed_id == "Not found"
            except Exception as e:
                self._log.debug(f"getWalletSeedID failed: {e}, will initialize seed")
                needs_seed_init = True
            if needs_seed_init:
                self._log.info(f"Initializing HD seed for {self.coin_name()}.")
                self._sc.initialiseWallet(self.coin_type())
                if password:
                    self._log.info(f"Encrypting {self.coin_name()} wallet.")
                    try:
                        self.rpc_wallet("encryptwallet", [password])
                    except Exception as e:
                        self._log.debug(f"encryptwallet returned: {e}")
                    import time

                    for i in range(10):
                        time.sleep(1)
                        try:
                            self.rpc("listwallets")
                            break
                        except Exception:
                            self._log.debug(
                                f"Waiting for wallet after encryption... {i + 1}/10"
                            )
                    wallets = self.rpc("listwallets")
                    if self._rpc_wallet not in wallets:
                        self.rpc("loadwallet", [self._rpc_wallet])
                self.setWalletSeedWarning(False)
                check_seed = False

        if self.isWalletEncrypted():
            self.rpc_wallet("walletpassphrase", [password, 100000000])
        if check_seed:
            self._sc.checkWalletSeed(self.coin_type())

    def lockWallet(self):
        self._log.info(f"lockWallet - {self.ticker()}")
        if self.useBackend():
            return
        self.rpc_wallet("walletlock")

    def get_p2sh_script_pubkey(self, script: bytearray) -> bytearray:
        script_hash = hash160(script)
        assert len(script_hash) == 20
        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def get_p2wsh_script_pubkey(self, script: bytearray) -> bytearray:
        return CScript([OP_0, sha256(script)])

    def findTxnByHash(self, txid_hex: str):
        if self._connection_type == "electrum":
            return self._findTxnByHashElectrum(txid_hex)

        # Only works for wallet txns
        try:
            rv = self.rpc_wallet("gettransaction", [txid_hex])
        except Exception as e:  # noqa: F841
            self._log.debug(
                "findTxnByHash getrawtransaction failed: {}".format(txid_hex)
            )
            return None
        if "confirmations" in rv and rv["confirmations"] >= self.blocks_confirmed:
            return {"txid": txid_hex, "amount": 0, "height": rv["blockheight"]}
        return None

    def _findTxnByHashElectrum(self, txid_hex: str):
        backend = self.getBackend()
        if not backend:
            return None

        try:
            tx_info = backend.getTransaction(txid_hex)
            chain_height = backend.getBlockHeight()
            block_height = 0
            confirmations = 0
            tx_hex = None

            if tx_info and isinstance(tx_info, dict):
                if "height" in tx_info:
                    block_height = tx_info.get("height", 0)
                elif "block_height" in tx_info:
                    block_height = tx_info.get("block_height", 0)
                elif "confirmations" in tx_info:
                    confirmations = tx_info.get("confirmations", 0)
                    if confirmations > 0:
                        block_height = chain_height - confirmations + 1
                tx_hex = tx_info.get("hex")

            if block_height == 0 and not tx_hex:
                tx_hex = backend.getTransactionRaw(txid_hex)
                if not tx_hex:
                    return None

            if block_height == 0 and tx_hex:
                try:
                    tx = self.loadTx(bytes.fromhex(tx_hex))
                    for txout in tx.vout:
                        try:
                            addr = self.encodeScriptDest(txout.scriptPubKey)
                            if addr:
                                history = backend.getAddressHistory(addr)
                                for entry in history:
                                    if (
                                        entry.get("tx_hash") == txid_hex
                                        or entry.get("txid") == txid_hex
                                    ):
                                        block_height = entry.get("height", 0)
                                        if block_height > 0:
                                            break
                                if block_height > 0:
                                    break
                        except Exception:
                            continue
                except Exception as e:
                    self._log.debug(
                        f"_findTxnByHashElectrum address fallback failed: {e}"
                    )

            if block_height > 0:
                confirmations = max(0, chain_height - block_height + 1)
                if confirmations >= self.blocks_confirmed:
                    self._log.debug(
                        f"_findTxnByHashElectrum found tx {txid_hex[:16]}... "
                        f"height={block_height}, confirmations={confirmations}"
                    )
                    return {"txid": txid_hex, "amount": 0, "height": block_height}

        except Exception as e:
            self._log.debug(f"_findTxnByHashElectrum failed: {e}")
        return None

    def createRedeemTxn(
        self, prevout, output_addr: str, output_value: int, txn_script: bytes = None
    ) -> str:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        prev_txid = b2i(bytes.fromhex(prevout["txid"]))
        tx.vin.append(CTxIn(COutPoint(prev_txid, prevout["vout"])))
        script = self.getDestForAddress(output_addr)
        tx.vout.append(self.txoType()(output_value, script))
        tx.rehash()
        return tx.serialize().hex()

    def createRefundTxn(
        self,
        prevout,
        output_addr: str,
        output_value: int,
        locktime: int,
        sequence: int,
        txn_script: bytes = None,
    ) -> str:
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.nLockTime = locktime
        prev_txid = b2i(bytes.fromhex(prevout["txid"]))
        tx.vin.append(
            CTxIn(
                COutPoint(prev_txid, prevout["vout"]),
                nSequence=sequence,
            )
        )
        script = self.getDestForAddress(output_addr)
        tx.vout.append(self.txoType()(output_value, script))
        tx.rehash()
        return tx.serialize().hex()

    def ensureFunds(self, amount: int) -> None:
        if self.getSpendableBalance() < amount:
            raise ValueError("Balance too low")

    def getHTLCSpendTxVSize(self, redeem: bool = True) -> int:
        tx_vsize = (
            5  # Add a few bytes, sequence in script takes variable amount of bytes
        )
        if self.using_segwit():
            tx_vsize += 143 if redeem else 134
        else:
            tx_vsize += 323 if redeem else 287
        return tx_vsize

    def find_prevout_info(self, txn_hex: str, txn_script: bytes):
        txjs = self.rpc("decoderawtransaction", [txn_hex])

        if self.using_segwit():
            p2wsh = self.getScriptDest(txn_script)
            n = getVoutByScriptPubKey(txjs, p2wsh.hex())
        else:
            addr_to = self.encode_p2sh(txn_script)
            n = getVoutByAddress(txjs, addr_to)

        return {
            "txid": txjs["txid"],
            "vout": n,
            "scriptPubKey": txjs["vout"][n]["scriptPubKey"]["hex"],
            "redeemScript": txn_script.hex(),
            "amount": txjs["vout"][n]["value"],
        }

    def inspectSwipeTx(self, tx: dict):
        for vout in tx["vout"]:
            script_bytes = bytes.fromhex(vout["scriptPubKey"]["hex"])
            if len(script_bytes) < 39:
                continue
            if script_bytes[0] != OP_RETURN:
                continue
            script_bytes[0]
            return script_bytes[7 : 7 + 32]
        return None

    def isTxExistsError(self, err_str: str) -> bool:
        return "Transaction already in block chain" in err_str

    def isTxNonFinalError(self, err_str: str) -> bool:
        return (
            "non-BIP68-final" in err_str
            or "non-final" in err_str
            or "Missing inputs" in err_str
            or "bad-txns-inputs-missingorspent" in err_str
        )

    def combine_non_segwit_prevouts(self):
        self._log.info("Combining non-segwit prevouts")
        if self._use_segwit is False:
            raise RuntimeError("Not configured to use segwit outputs.")
        prevouts_to_spend = self.getNonSegwitOutputs()
        if len(prevouts_to_spend) < 1:
            raise RuntimeError("No non-segwit outputs found.")

        total_amount: int = 0
        for n, prevout in enumerate(prevouts_to_spend):
            total_amount += self.make_int(prevout["amount"])
        addr_to: str = self.getNewAddress(
            self._use_segwit, "combine_non_segwit_prevouts"
        )

        txn = self.rpc(
            "createrawtransaction",
            [prevouts_to_spend, {addr_to: self.format_amount(total_amount)}],
        )
        fee_rate, rate_src = self.get_fee_rate(self._conf_target)
        fee_rate_str: str = self.format_amount(fee_rate, True, 1)
        self._log.debug(
            f"Using fee rate: {fee_rate_str}, src: {rate_src}, confirms target: {self._conf_target}"
        )
        options = {
            "add_inputs": False,
            "subtractFeeFromOutputs": [
                0,
            ],
            "feeRate": fee_rate_str,
        }
        tx_fee_set = self.rpc_wallet("fundrawtransaction", [txn, options])["hex"]
        tx_signed = self.rpc_wallet("signrawtransactionwithwallet", [tx_fee_set])["hex"]
        tx = self.rpc(
            "decoderawtransaction",
            [
                tx_signed,
            ],
        )
        self._log.info(
            "Submitting tx to combine non-segwit prevouts: {}".format(
                self._log.id(bytes.fromhex(tx["txid"]))
            )
        )
        self.publishTx(tx_signed)

        return tx["txid"]


def testBTCInterface():
    print("TODO: testBTCInterface")


if __name__ == "__main__":
    testBTCInterface()
