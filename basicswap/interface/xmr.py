#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import os

import basicswap.contrib.ed25519_fast as edf
import basicswap.ed25519_fast_util as edu
import basicswap.util_xmr as xmr_util
from coincurve.ed25519 import (
    ed25519_add,
    ed25519_get_pubkey,
    ed25519_scalar_add,
)
from coincurve.keys import PrivateKey
from coincurve.dleag import (
    dleag_prove,
    dleag_verify,
    dleag_proof_len,
    verify_ed25519_point,
)

from basicswap.interface.base import (
    Curves,
)
from basicswap.util import i2b, b2i, b2h, dumpj, ensure, TemporaryError
from basicswap.util.network import is_private_ip_address
from basicswap.rpc_xmr import make_xmr_rpc_func, make_xmr_rpc2_func
from basicswap.chainparams import XMR_COIN, Coins
from basicswap.interface.base import CoinInterface


class XMRInterface(CoinInterface):
    @staticmethod
    def curve_type():
        return Curves.ed25519

    @staticmethod
    def coin_type():
        return Coins.XMR

    @staticmethod
    def ticker_str() -> int:
        return Coins.XMR.name

    @staticmethod
    def COIN():
        return XMR_COIN

    @staticmethod
    def exp() -> int:
        return 12

    @staticmethod
    def nbk() -> int:
        return 32

    @staticmethod
    def nbK() -> int:  # No. of bytes requires to encode a public key
        return 32

    @staticmethod
    def depth_spendable() -> int:
        return 10

    @staticmethod
    def xmr_swap_a_lock_spend_tx_vsize() -> int:
        raise ValueError("Not possible")

    @staticmethod
    def est_lock_tx_vsize() -> int:
        # TODO: Estimate with ringsize
        return 1604

    @staticmethod
    def xmr_swap_b_lock_spend_tx_vsize() -> int:
        # TODO: Estimate with ringsize
        return 1604

    def is_transient_error(self, ex) -> bool:
        str_error: str = str(ex).lower()
        if "failed to get earliest fork height" in str_error:
            return True
        return super().is_transient_error(ex)

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__(network)

        self._addr_prefix = self.chainparams_network()["address_prefix"]

        self.blocks_confirmed = coin_settings["blocks_confirmed"]
        self._restore_height = coin_settings.get("restore_height", 0)
        self.setFeePriority(coin_settings.get("fee_priority", 0))
        self._sc = swap_client
        self._log = self._sc.log if self._sc and self._sc.log else logging
        self._wallet_password = None
        self._have_checked_seed = False
        self._wallet_filename = coin_settings.get("wallet_name", "swap_wallet")

        daemon_login = None
        if coin_settings.get("rpcuser", "") != "":
            daemon_login = (
                coin_settings.get("rpcuser", ""),
                coin_settings.get("rpcpassword", ""),
            )

        rpchost = coin_settings.get("rpchost", "127.0.0.1")
        proxy_host = None
        proxy_port = None
        # Connect to the daemon over a proxy if not running locally
        if swap_client:
            chain_client_settings = swap_client.getChainClientSettings(self.coin_type())
            manage_daemon: bool = chain_client_settings["manage_daemon"]
            if swap_client.use_tor_proxy:
                if manage_daemon is False:
                    log_str: str = ""
                    have_cc_tor_opt = "use_tor" in chain_client_settings
                    if have_cc_tor_opt and chain_client_settings["use_tor"] is False:
                        log_str = (
                            f" bypassing proxy (use_tor false for {self.coin_name()})"
                        )
                    elif have_cc_tor_opt is False and is_private_ip_address(rpchost):
                        log_str = " bypassing proxy (private ip address)"
                    else:
                        proxy_host = swap_client.tor_proxy_host
                        proxy_port = swap_client.tor_proxy_port
                        log_str = f" through proxy at {proxy_host}"
                    self._log.info(
                        f"Connecting to remote {self.coin_name()} daemon at {rpchost}{log_str}."
                    )
                else:
                    self._log.info(
                        f"Not connecting to local {self.coin_name()} daemon through proxy."
                    )
            elif manage_daemon is False:
                self._log.info(
                    f"Connecting to remote {self.coin_name()} daemon at {rpchost}."
                )

        self._rpctimeout = coin_settings.get("rpctimeout", 60)
        self._walletrpctimeout = coin_settings.get("walletrpctimeout", 120)
        # walletrpctimeoutlong likely unneeded
        self._walletrpctimeoutlong = coin_settings.get("walletrpctimeoutlong", 600)

        self.rpc = make_xmr_rpc_func(
            coin_settings["rpcport"],
            daemon_login,
            host=rpchost,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            default_timeout=self._rpctimeout,
            tag="Node(j) ",
        )
        self.rpc2 = make_xmr_rpc2_func(
            coin_settings["rpcport"],
            daemon_login,
            host=rpchost,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            default_timeout=self._rpctimeout,
            tag="Node ",
        )  # non-json endpoint
        self.rpc_wallet = make_xmr_rpc_func(
            coin_settings["walletrpcport"],
            coin_settings["walletrpcauth"],
            host=coin_settings.get("walletrpchost", "127.0.0.1"),
            default_timeout=self._walletrpctimeout,
            tag="Wallet ",
        )

    def setFeePriority(self, new_priority):
        ensure(new_priority >= 0 and new_priority < 4, "Invalid fee_priority value")
        self._fee_priority = new_priority

    def createWallet(self, params):
        if self._wallet_password is not None:
            params["password"] = self._wallet_password
        rv = self.rpc_wallet("generate_from_keys", params)
        if "address" in rv:
            new_address: str = rv["address"]
            is_watch_only: bool = "Watch-only" in rv.get("info", "")
            self._log.info(
                "Generated{} {} wallet: {}".format(
                    " watch-only" if is_watch_only else "",
                    self.coin_name(),
                    self._log.addr(new_address),
                )
            )
        else:
            self._log.debug("generate_from_keys %s", dumpj(rv))
            raise ValueError("generate_from_keys failed")

    def openWallet(self, filename):
        params = {"filename": filename}
        if self._wallet_password is not None:
            params["password"] = self._wallet_password

        try:
            self.rpc_wallet("open_wallet", params)
        except Exception as e:
            if "no connection to daemon" in str(e):
                self._log.debug(f"{self.coin_name()} {e}")
                return  # Bypass refresh error to allow startup with a busy daemon
            if any(
                x in str(e)
                for x in (
                    "invalid signature",
                    "std::bad_alloc",
                    "basic_string::_M_replace_aux",
                )
            ):
                self._log.error(f"{self.coin_name()} wallet is corrupt.")
                chain_client_settings = self._sc.getChainClientSettings(
                    self.coin_type()
                )  # basicswap.json
                if chain_client_settings.get("manage_wallet_daemon", False):
                    self._log.info(f"Renaming {self.coin_name()} wallet cache file.")
                    walletpath = os.path.join(
                        chain_client_settings.get("datadir", "none"),
                        "wallets",
                        filename,
                    )
                    if not os.path.isfile(walletpath):
                        self._log.warning(
                            f"Could not find {self.coin_name()} wallet cache file."
                        )
                        raise
                    bkp_path = walletpath + ".corrupt"
                    for i in range(100):
                        if not os.path.exists(bkp_path):
                            break
                        bkp_path = walletpath + f".corrupt{i}"
                    if os.path.exists(bkp_path):
                        self._log.error(
                            f"Could not find backup path for {self.coin_name()} wallet."
                        )
                        raise
                    os.rename(walletpath, bkp_path)
                    # Drop through to open_wallet
                else:
                    raise
            else:
                try:
                    self.rpc_wallet("close_wallet")
                    self._log.debug(f"Closing {self.coin_name()} wallet")
                except Exception as e:  # noqa: F841
                    pass

            self.rpc_wallet("open_wallet", params)
            self._log.debug(f"Attempting to open {self.coin_name()} wallet")

    def initialiseWallet(
        self, key_view: bytes, key_spend: bytes, restore_height=None
    ) -> None:
        with self._mx_wallet:
            try:
                self.openWallet(self._wallet_filename)
                # TODO: Check address
                return  # Wallet exists
            except Exception as e:  # noqa: F841
                pass

            Kbv = self.getPubkey(key_view)
            Kbs = self.getPubkey(key_spend)
            address_b58 = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)

            params = {
                "filename": self._wallet_filename,
                "address": address_b58,
                "viewkey": b2h(key_view[::-1]),
                "spendkey": b2h(key_spend[::-1]),
                "restore_height": self._restore_height,
            }
            self.createWallet(params)
            self.openWallet(self._wallet_filename)

    def ensureWalletExists(self) -> None:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)

    def testDaemonRPC(self, with_wallet=True) -> None:
        self.rpc_wallet("get_languages")

    def getDaemonVersion(self):
        return self.rpc_wallet("get_version")["version"]

    def getBlockchainInfo(self):
        get_height = self.rpc2("get_height", timeout=self._rpctimeout)
        rv = {
            "blocks": get_height["height"],
            "verificationprogress": 0.0,
        }

        try:
            # get_block_count.block_count is how many blocks are in the longest chain known to the node.
            # get_block_count returns "Internal error" if bootstrap-daemon is active
            if get_height["untrusted"] is True:
                rv["bootstrapping"] = True
                get_info = self.rpc2("get_info", timeout=self._rpctimeout)
                if "height_without_bootstrap" in get_info:
                    rv["blocks"] = get_info["height_without_bootstrap"]

                rv["known_block_count"] = get_info["height"]
                if rv["known_block_count"] > rv["blocks"]:
                    rv["verificationprogress"] = rv["blocks"] / rv["known_block_count"]
            else:
                rv["known_block_count"] = self.rpc(
                    "get_block_count", timeout=self._rpctimeout
                )["count"]
                rv["verificationprogress"] = rv["blocks"] / rv["known_block_count"]
        except Exception as e:
            self._log.warning(f"{self.ticker_str()} get_block_count failed with: {e}")
            rv["verificationprogress"] = 0.0

        return rv

    def getChainHeight(self):
        return self.rpc2("get_height", timeout=self._rpctimeout)["height"]

    def getWalletInfo(self):
        with self._mx_wallet:
            try:
                self.openWallet(self._wallet_filename)
            except Exception as e:
                if "Failed to open wallet" in str(e):
                    rv = {
                        "encrypted": True,
                        "locked": True,
                        "balance": 0,
                        "unconfirmed_balance": 0,
                    }
                    return rv
                raise e

            rv = {}
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")
            balance_info = self.rpc_wallet("get_balance")

            rv["wallet_blocks"] = self.rpc_wallet("get_height")["height"]
            rv["balance"] = self.format_amount(balance_info["unlocked_balance"])
            rv["unconfirmed_balance"] = self.format_amount(
                balance_info["balance"] - balance_info["unlocked_balance"]
            )
            rv["encrypted"] = False if self._wallet_password is None else True
            rv["locked"] = False
            return rv

    def getMainWalletAddress(self) -> str:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            return self.rpc_wallet("get_address")["address"]

    def getNewAddress(self, placeholder) -> str:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            new_address = self.rpc_wallet("create_address", {"account_index": 0})[
                "address"
            ]
            self.rpc_wallet("store")
            return new_address

    def get_fee_rate(self, conf_target: int = 2):
        # fees - array of unsigned int; Represents the base fees at different priorities [slow, normal, fast, fastest].
        fee_est = self.rpc("get_fee_estimate")
        if conf_target <= 1:
            conf_target = 1  # normal
        else:
            conf_target = 0  # slow
        fee_per_k_bytes = fee_est["fees"][conf_target] * 1000

        return float(self.format_amount(fee_per_k_bytes)), "get_fee_estimate"

    def getNewRandomKey(self) -> bytes:
        # Note: Returned bytes are in big endian order
        return i2b(edu.get_secret())

    def pubkey(self, key: bytes) -> bytes:
        return edf.scalarmult_B(key)

    def encodeKey(self, vk: bytes) -> str:
        return vk[::-1].hex()

    def decodeKey(self, k_hex: str) -> bytes:
        return bytes.fromhex(k_hex)[::-1]

    def encodePubkey(self, pk: bytes) -> str:
        return edu.encodepoint(pk)

    def decodePubkey(self, pke):
        return edf.decodepoint(pke)

    def getPubkey(self, privkey):
        return ed25519_get_pubkey(privkey)

    def getAddressFromKeys(self, key_view: bytes, key_spend: bytes) -> str:
        pk_view = self.getPubkey(key_view)
        pk_spend = self.getPubkey(key_spend)
        return xmr_util.encode_address(pk_view, pk_spend, self._addr_prefix)

    def verifyKey(self, k: int) -> bool:
        i = b2i(k)
        return i < edf.l and i > 8

    def verifyPubkey(self, pubkey_bytes):
        # Calls ed25519_decode_check_point() in secp256k1
        # Checks for small order
        return verify_ed25519_point(pubkey_bytes)

    def proveDLEAG(self, key: bytes) -> bytes:
        privkey = PrivateKey(key)
        return dleag_prove(privkey)

    def verifyDLEAG(self, dleag_bytes: bytes) -> bool:
        return dleag_verify(dleag_bytes)

    def lengthDLEAG(self) -> int:
        return dleag_proof_len()

    def sumKeys(self, ka: bytes, kb: bytes) -> bytes:
        return ed25519_scalar_add(ka, kb)

    def sumPubkeys(self, Ka: bytes, Kb: bytes) -> bytes:
        return ed25519_add(Ka, Kb)

    def encodeSharedAddress(self, Kbv: bytes, Kbs: bytes) -> str:
        return xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)

    def publishBLockTx(
        self,
        kbv: bytes,
        Kbs: bytes,
        output_amount: int,
        feerate: int,
        unlock_time: int = 0,
    ) -> bytes:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            Kbv = self.getPubkey(kbv)
            shared_addr = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)

            params = {
                "destinations": [{"amount": output_amount, "address": shared_addr}],
                "unlock_time": unlock_time,
            }
            if self._fee_priority > 0:
                params["priority"] = self._fee_priority
            rv = self.rpc_wallet("transfer", params)
            self._log.info(
                "publishBLockTx {} to address_b58 {}".format(
                    self._log.id(rv["tx_hash"]),
                    self._log.addr(shared_addr),
                )
            )
            tx_hash = bytes.fromhex(rv["tx_hash"])

            return tx_hash

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
        with self._mx_wallet:
            Kbv = self.getPubkey(kbv)
            address_b58 = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)

            kbv_le = kbv[::-1]
            params = {
                "restore_height": restore_height,
                "filename": address_b58,
                "address": address_b58,
                "viewkey": b2h(kbv_le),
            }

            try:
                self.openWallet(address_b58)
            except Exception as e:  # noqa: F841
                self.createWallet(params)
                self.openWallet(address_b58)

            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            """
            # Debug
            try:
                current_height = self.rpc_wallet('get_height')['height']
                self._log.info('findTxB XMR current_height %d\nAddress: %s', current_height, address_b58)
            except Exception as e:
                self._log.info('rpc failed %s', str(e))
                current_height = None  # If the transfer is available it will be deep enough
                #   and (current_height is None or current_height - transfer['block_height'] > cb_block_confirmed):
            """
            params = {"transfer_type": "available"}
            transfers = self.rpc_wallet("incoming_transfers", params)
            rv = None
            if "transfers" in transfers:
                for transfer in transfers["transfers"]:
                    # unlocked <- wallet->is_transfer_unlocked() checks unlock_time and CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
                    if not transfer["unlocked"]:
                        full_tx = self.rpc_wallet(
                            "get_transfer_by_txid", {"txid": transfer["tx_hash"]}
                        )
                        unlock_time = full_tx["transfer"]["unlock_time"]
                        if unlock_time != 0:
                            self._log.warning(
                                "Coin b lock txn is locked: {}, unlock_time {}".format(
                                    transfer["tx_hash"], unlock_time
                                )
                            )
                            rv = -1
                            continue
                    if transfer["amount"] == cb_swap_value or check_amount is False:
                        return {
                            "txid": transfer["tx_hash"],
                            "amount": transfer["amount"],
                            "height": (
                                0
                                if "block_height" not in transfer
                                else transfer["block_height"]
                            ),
                        }
                    else:
                        self._log.warning(
                            "Incorrect amount detected for coin b lock txn: {}".format(
                                transfer["tx_hash"]
                            )
                        )
                        rv = -1
            return rv

    def findTxnByHash(self, txid):
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            try:
                current_height = self.rpc2("get_height", timeout=self._rpctimeout)[
                    "height"
                ]
                self._log.info(
                    f"findTxnByHash {self.ticker_str()} current_height {current_height}\nhash: {txid}"
                )
            except Exception as e:
                self._log.info("rpc failed %s", str(e))
                current_height = (
                    None  # If the transfer is available it will be deep enough
                )

            params = {"transfer_type": "available"}
            rv = self.rpc_wallet("incoming_transfers", params)
            if "transfers" in rv:
                for transfer in rv["transfers"]:
                    if transfer["tx_hash"] == txid and (
                        current_height is None
                        or current_height - transfer["block_height"]
                        > self.blocks_confirmed
                    ):
                        return {
                            "txid": transfer["tx_hash"],
                            "amount": transfer["amount"],
                            "height": transfer["block_height"],
                        }

            return None

    def spendBLockTx(
        self,
        chain_b_lock_txid: bytes,
        address_to: str,
        kbv: bytes,
        kbs: bytes,
        cb_swap_value: int,
        b_fee_rate: int,
        restore_height: int,
        spend_actual_balance: bool = False,
        lock_tx_vout=None,
    ) -> bytes:
        """
        Notes:
        "Error: No unlocked balance in the specified subaddress(es)" can mean not enough funds after tx fee.
        """
        with self._mx_wallet:
            Kbv = self.getPubkey(kbv)
            Kbs = self.getPubkey(kbs)
            address_b58 = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)

            wallet_filename = address_b58 + "_spend"

            params = {
                "filename": wallet_filename,
                "address": address_b58,
                "viewkey": b2h(kbv[::-1]),
                "spendkey": b2h(kbs[::-1]),
                "restore_height": restore_height,
            }

            try:
                self.openWallet(wallet_filename)
            except Exception as e:  # noqa: F841
                self.createWallet(params)
                self.openWallet(wallet_filename)

            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")
            rv = self.rpc_wallet("get_balance")
            if rv["balance"] < cb_swap_value:
                self._log.warning("Balance is too low, checking for existing spend.")
                txns = self.rpc_wallet("get_transfers", {"out": True})
                if "out" in txns:
                    txns = txns["out"]
                    if len(txns) > 0:
                        txid = txns[0]["txid"]
                        self._log.warning(f"spendBLockTx detected spending tx: {txid}.")

                        # Should check for address_to, but only the from address is found in the output
                        if txns[0]["address"] == address_b58:
                            return bytes.fromhex(txid)

                self._log.error(
                    "wallet {} balance {}, expected {}".format(
                        wallet_filename, rv["balance"], cb_swap_value
                    )
                )

                if not spend_actual_balance:
                    raise TemporaryError("Invalid balance")

            if spend_actual_balance and rv["balance"] != cb_swap_value:
                self._log.warning(
                    "Spending actual balance {}, not swap value {}.".format(
                        rv["balance"], cb_swap_value
                    )
                )
                cb_swap_value = rv["balance"]
            if rv["unlocked_balance"] < cb_swap_value:
                self._log.error(
                    "wallet {} balance {}, expected {}, blocks_to_unlock {}".format(
                        wallet_filename,
                        rv["unlocked_balance"],
                        cb_swap_value,
                        rv["blocks_to_unlock"],
                    )
                )
                raise TemporaryError("Invalid unlocked_balance")

            params = {"address": address_to}
            if self._fee_priority > 0:
                params["priority"] = self._fee_priority

            rv = self.rpc_wallet("sweep_all", params)

            return bytes.fromhex(rv["tx_hash_list"][0])

    def withdrawCoin(
        self, value, addr_to: str, sweepall: bool, estimate_fee: bool = False
    ) -> str:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            if sweepall:
                balance = self.rpc_wallet("get_balance")
                if balance["balance"] != balance["unlocked_balance"]:
                    raise ValueError(
                        "Balance must be fully confirmed to use sweep all."
                    )
                self._log.info(
                    "{} {} sweep_all.".format(
                        self.ticker_str(),
                        "estimate fee" if estimate_fee else "withdraw",
                    )
                )
                self._log.debug(
                    "{} balance: {}".format(self.ticker_str(), balance["balance"])
                )
                params = {
                    "address": addr_to,
                    "do_not_relay": estimate_fee,
                    "subaddr_indices_all": True,
                }
                if self._fee_priority > 0:
                    params["priority"] = self._fee_priority
                rv = self.rpc_wallet("sweep_all", params)
                if estimate_fee:
                    return {
                        "num_txns": len(rv["fee_list"]),
                        "sum_amount": sum(rv["amount_list"]),
                        "sum_fee": sum(rv["fee_list"]),
                        "sum_weight": sum(rv["weight_list"]),
                    }
                return rv["tx_hash_list"][0]

            value_sats: int = self.make_int(value)
            params = {
                "destinations": [{"amount": value_sats, "address": addr_to}],
                "do_not_relay": estimate_fee,
            }
            if self._fee_priority > 0:
                params["priority"] = self._fee_priority
            rv = self.rpc_wallet("transfer", params)
            if estimate_fee:
                return {
                    "num_txns": 1,
                    "sum_amount": rv["amount"],
                    "sum_fee": rv["fee"],
                    "sum_weight": rv["weight"],
                }
            return rv["tx_hash"]

    def estimateFee(self, value: int, addr_to: str, sweepall: bool) -> str:
        return self.withdrawCoin(value, addr_to, sweepall, estimate_fee=True)

    def showLockTransfers(self, kbv, Kbs, restore_height):
        with self._mx_wallet:
            try:
                Kbv = self.getPubkey(kbv)
                address_b58 = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)
                wallet_file = address_b58 + "_spend"
                try:
                    self.openWallet(wallet_file)
                except Exception:
                    wallet_file = address_b58
                    try:
                        self.openWallet(wallet_file)
                    except Exception:
                        self._log.info(
                            f"showLockTransfers trying to create wallet for address {address_b58}."
                        )
                        kbv_le = kbv[::-1]
                        params = {
                            "restore_height": restore_height,
                            "filename": address_b58,
                            "address": address_b58,
                            "viewkey": b2h(kbv_le),
                        }
                        self.createWallet(params)
                        self.openWallet(address_b58)

                self.rpc_wallet("refresh")
                self._log.debug(f"Refreshing {self.coin_name()} wallet")

                rv = self.rpc_wallet(
                    "get_transfers",
                    {"in": True, "out": True, "pending": True, "failed": True},
                )
                rv["filename"] = wallet_file
                return rv
            except Exception as e:
                return {"error": str(e)}

    def getSpendableBalance(self) -> int:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            balance_info = self.rpc_wallet("get_balance")
            return balance_info["unlocked_balance"]

    def changeWalletPassword(
        self, old_password, new_password, check_seed_if_encrypt: bool = True
    ):
        self._log.info("changeWalletPassword - {}".format(self.ticker()))
        orig_password = self._wallet_password
        if old_password != "":
            self._wallet_password = old_password
        try:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet(
                "change_wallet_password",
                {"old_password": old_password, "new_password": new_password},
            )
        except Exception as e:
            self._wallet_password = orig_password
            raise e

    def unlockWallet(self, password: str, check_seed: bool = True) -> None:
        self._log.info("unlockWallet - {}".format(self.ticker()))
        self._wallet_password = password

        if check_seed and not self._have_checked_seed:
            self._sc.checkWalletSeed(self.coin_type())

    def lockWallet(self) -> None:
        self._log.info("lockWallet - {}".format(self.ticker()))
        self._wallet_password = None

    def isAddressMine(self, address):
        # TODO
        return True

    def ensureFunds(self, amount: int) -> None:
        if self.getSpendableBalance() < amount:
            raise ValueError("Balance too low")

    def getTransaction(self, txid: bytes):
        return self.rpc2(
            "get_transactions",
            {
                "txs_hashes": [
                    txid.hex(),
                ]
            },
        )
