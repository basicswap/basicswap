# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional


class WalletBackend(ABC):

    @abstractmethod
    def getBalance(self, addresses: List[str]) -> Dict[str, int]:
        pass

    def findAddressWithBalance(
        self, addresses: List[str], min_balance: int
    ) -> Optional[tuple]:
        balances = self.getBalance(addresses)
        for addr, balance in balances.items():
            if balance >= min_balance:
                return (addr, balance)
        return None

    @abstractmethod
    def getUnspentOutputs(
        self, addresses: List[str], min_confirmations: int = 0
    ) -> List[dict]:
        pass

    @abstractmethod
    def broadcastTransaction(self, tx_hex: str) -> str:
        pass

    @abstractmethod
    def getTransaction(self, txid: str) -> Optional[dict]:
        pass

    @abstractmethod
    def getTransactionRaw(self, txid: str) -> Optional[str]:
        pass

    @abstractmethod
    def getBlockHeight(self) -> int:
        pass

    @abstractmethod
    def estimateFee(self, blocks: int = 6) -> int:
        pass

    @abstractmethod
    def isConnected(self) -> bool:
        pass

    @abstractmethod
    def getAddressHistory(self, address: str) -> List[dict]:
        pass


class FullNodeBackend(WalletBackend):

    def __init__(self, rpc_client, coin_type, log):
        self._rpc = rpc_client
        self._coin_type = coin_type
        self._log = log

    def getBalance(self, addresses: List[str]) -> Dict[str, int]:
        result = {}
        for addr in addresses:
            result[addr] = 0

        try:
            utxos = self._rpc("listunspent", [0, 9999999, addresses])
            for utxo in utxos:
                addr = utxo.get("address")
                if addr in result:
                    result[addr] += int(utxo.get("amount", 0) * 1e8)
        except Exception as e:
            self._log.warning(f"FullNodeBackend.getBalance error: {e}")

        return result

    def getUnspentOutputs(
        self, addresses: List[str], min_confirmations: int = 0
    ) -> List[dict]:
        try:
            utxos = self._rpc("listunspent", [min_confirmations, 9999999, addresses])
            result = []
            for utxo in utxos:
                result.append(
                    {
                        "txid": utxo.get("txid"),
                        "vout": utxo.get("vout"),
                        "value": int(utxo.get("amount", 0) * 1e8),
                        "address": utxo.get("address"),
                        "confirmations": utxo.get("confirmations", 0),
                        "scriptPubKey": utxo.get("scriptPubKey"),
                    }
                )
            return result
        except Exception as e:
            self._log.warning(f"FullNodeBackend.getUnspentOutputs error: {e}")
            return []

    def broadcastTransaction(self, tx_hex: str) -> str:
        return self._rpc("sendrawtransaction", [tx_hex])

    def getTransaction(self, txid: str) -> Optional[dict]:
        try:
            return self._rpc("getrawtransaction", [txid, True])
        except Exception:
            return None

    def getTransactionRaw(self, txid: str) -> Optional[str]:
        try:
            return self._rpc("getrawtransaction", [txid, False])
        except Exception:
            return None

    def getBlockHeight(self) -> int:
        return self._rpc("getblockcount")

    def estimateFee(self, blocks: int = 6) -> int:
        try:
            result = self._rpc("estimatesmartfee", [blocks])
            if "feerate" in result:
                return int(result["feerate"] * 1e8 / 1000)
            return 1
        except Exception:
            return 1

    def isConnected(self) -> bool:
        try:
            self._rpc("getblockchaininfo")
            return True
        except Exception:
            return False

    def getAddressHistory(self, address: str) -> List[dict]:
        return []

    def importAddress(self, address: str, label: str = "", rescan: bool = False):
        try:
            self._rpc("importaddress", [address, label, rescan])
        except Exception as e:
            if "already in wallet" not in str(e).lower():
                raise


class ElectrumBackend(WalletBackend):

    def __init__(
        self,
        coin_type,
        log,
        clearnet_servers=None,
        onion_servers=None,
        chain="mainnet",
        proxy_host=None,
        proxy_port=None,
    ):
        from basicswap.interface.electrumx import ElectrumServer
        from basicswap.chainparams import Coins, chainparams

        self._coin_type = coin_type
        self._log = log
        self._subscribed_scripthashes = set()

        coin_params = chainparams.get(coin_type, chainparams.get(Coins.BTC))
        self._network_params = coin_params.get(chain, coin_params.get("mainnet", {}))

        coin_name_map = {
            Coins.BTC: "bitcoin",
            Coins.LTC: "litecoin",
        }
        coin_name = coin_name_map.get(coin_type, "bitcoin")

        self._host = "localhost"
        self._port = 50002
        self._use_ssl = True

        self._server = ElectrumServer(
            coin_name,
            clearnet_servers=clearnet_servers,
            onion_servers=onion_servers,
            log=log,
            proxy_host=proxy_host,
            proxy_port=proxy_port,
        )

        self._realtime_callback = None
        self._address_to_scripthash = {}

        self._cached_height = 0
        self._cached_height_time = 0
        self._height_cache_ttl = 5

        self._cached_fee = {}
        self._cached_fee_time = {}
        self._fee_cache_ttl = 300

        self._max_batch_size = 5
        self._background_mode = False

    def setBackgroundMode(self, enabled: bool):
        self._background_mode = enabled

    def _call(self, method: str, params: list = None, timeout: int = 10):
        if self._background_mode and hasattr(self._server, "call_background"):
            return self._server.call_background(method, params, timeout)
        if hasattr(self._server, "call_user"):
            return self._server.call_user(method, params, timeout)
        return self._server.call(method, params, timeout)

    def _call_batch(self, calls: list, timeout: int = 15):
        if self._background_mode and hasattr(self._server, "call_batch_background"):
            return self._server.call_batch_background(calls, timeout)
        if hasattr(self._server, "call_batch_user"):
            return self._server.call_batch_user(calls, timeout)
        return self._server.call_batch(calls, timeout)

    def _is_server_stopping(self) -> bool:
        return getattr(self._server, "_stopping", False)

    def _split_batch_call(
        self, scripthashes: list, method: str, batch_size: int = None
    ) -> list:
        if batch_size is None:
            batch_size = self._max_batch_size

        all_results = []
        for i in range(0, len(scripthashes), batch_size):
            if self._is_server_stopping():
                self._log.debug("_split_batch_call: server stopping, aborting")
                break
            chunk = scripthashes[i : i + batch_size]
            try:
                calls = [(method, [sh]) for sh in chunk]
                results = self._call_batch(calls)
                all_results.extend(results)
            except Exception:
                if self._is_server_stopping():
                    self._log.debug(
                        "_split_batch_call: server stopping after batch failure, aborting"
                    )
                    break
                for sh in chunk:
                    if self._is_server_stopping():
                        self._log.debug(
                            "_split_batch_call: server stopping during fallback, aborting"
                        )
                        break
                    try:
                        result = self._call(method, [sh])
                        all_results.append(result)
                    except Exception:
                        all_results.append(None)
        return all_results

    def _isUnsupportedAddress(self, address: str) -> bool:
        if address.startswith("ltcmweb1"):
            return True
        return False

    def _addressToScripthash(self, address: str) -> str:
        from basicswap.interface.electrumx import scripthash_from_address

        return scripthash_from_address(address, self._network_params)

    def getBalance(self, addresses: List[str]) -> Dict[str, int]:
        result = {}
        for addr in addresses:
            result[addr] = 0

        if not addresses:
            return result

        addr_list = [addr for addr in addresses if not self._isUnsupportedAddress(addr)]
        if not addr_list:
            return result

        addr_to_scripthash = {}
        for addr in addr_list:
            try:
                addr_to_scripthash[addr] = self._addressToScripthash(addr)
            except Exception as e:
                self._log.debug(f"getBalance: scripthash error for {addr[:10]}...: {e}")

        if not addr_to_scripthash:
            return result

        scripthashes = list(addr_to_scripthash.values())
        scripthash_to_addr = {v: k for k, v in addr_to_scripthash.items()}

        batch_results = self._split_batch_call(
            scripthashes, "blockchain.scripthash.get_balance"
        )

        for i, balance in enumerate(batch_results):
            if balance and isinstance(balance, dict):
                addr = scripthash_to_addr.get(scripthashes[i])
                if addr:
                    confirmed = balance.get("confirmed", 0)
                    unconfirmed = balance.get("unconfirmed", 0)
                    result[addr] = confirmed + unconfirmed

        return result

    def getDetailedBalance(self, addresses: List[str]) -> Dict[str, dict]:
        result = {}
        for addr in addresses:
            result[addr] = {"confirmed": 0, "unconfirmed": 0}

        if not addresses:
            return result

        addr_list = [addr for addr in addresses if not self._isUnsupportedAddress(addr)]
        if not addr_list:
            return result

        batch_size = self._max_batch_size
        for batch_start in range(0, len(addr_list), batch_size):
            if self._is_server_stopping():
                break
            batch = addr_list[batch_start : batch_start + batch_size]

            addr_to_scripthash = {}
            for addr in batch:
                try:
                    addr_to_scripthash[addr] = self._addressToScripthash(addr)
                except Exception as e:
                    self._log.debug(
                        f"getDetailedBalance: scripthash error for {addr[:10]}...: {e}"
                    )

            if not addr_to_scripthash:
                continue

            scripthashes = list(addr_to_scripthash.values())
            scripthash_to_addr = {v: k for k, v in addr_to_scripthash.items()}
            batch_success = False

            for attempt in range(2):
                try:
                    batch_results = self._server.get_balance_batch(scripthashes)
                    for i, balance in enumerate(batch_results):
                        if balance and isinstance(balance, dict):
                            addr = scripthash_to_addr.get(scripthashes[i])
                            if addr:
                                result[addr] = {
                                    "confirmed": balance.get("confirmed", 0),
                                    "unconfirmed": balance.get("unconfirmed", 0),
                                }
                    batch_success = True
                    break
                except Exception as e:
                    if self._is_server_stopping():
                        break
                    if attempt == 0:
                        self._log.debug(
                            f"Batch detailed balance query failed, reconnecting: {e}"
                        )
                        try:
                            self._server.disconnect()
                        except Exception:
                            pass
                        time.sleep(0.5)
                    else:
                        self._log.debug(
                            f"Batch detailed balance query failed after retry, falling back: {e}"
                        )

            if not batch_success:
                for addr, scripthash in addr_to_scripthash.items():
                    if self._is_server_stopping():
                        break
                    try:
                        balance = self._call(
                            "blockchain.scripthash.get_balance", [scripthash]
                        )
                        if balance and isinstance(balance, dict):
                            result[addr] = {
                                "confirmed": balance.get("confirmed", 0),
                                "unconfirmed": balance.get("unconfirmed", 0),
                            }
                    except Exception as e:
                        self._log.debug(
                            f"ElectrumBackend.getDetailedBalance error for {addr[:10]}...: {e}"
                        )

        return result

    def findAddressWithBalance(
        self, addresses: List[str], min_balance: int
    ) -> Optional[tuple]:
        if not addresses:
            return None

        addr_list = [addr for addr in addresses if not self._isUnsupportedAddress(addr)]
        if not addr_list:
            return None

        batch_size = 50
        for batch_start in range(0, len(addr_list), batch_size):
            batch = addr_list[batch_start : batch_start + batch_size]

            addr_to_scripthash = {}
            for addr in batch:
                try:
                    addr_to_scripthash[addr] = self._addressToScripthash(addr)
                except Exception:
                    continue

            if not addr_to_scripthash:
                continue

            try:
                scripthashes = list(addr_to_scripthash.values())
                batch_results = self._server.get_balance_batch(scripthashes)
                scripthash_to_addr = {v: k for k, v in addr_to_scripthash.items()}

                for i, balance in enumerate(batch_results):
                    if balance and isinstance(balance, dict):
                        confirmed = balance.get("confirmed", 0)
                        unconfirmed = balance.get("unconfirmed", 0)
                        total = confirmed + unconfirmed
                        if total >= min_balance:
                            addr = scripthash_to_addr.get(scripthashes[i])
                            if addr:
                                return (addr, total)
            except Exception as e:
                self._log.debug(f"findAddressWithBalance batch error: {e}")

        return None

    def getUnspentOutputs(
        self, addresses: List[str], min_confirmations: int = 0
    ) -> List[dict]:
        result = []
        if not addresses:
            return result

        try:
            current_height = self.getBlockHeight()

            for addr in addresses:
                if self._isUnsupportedAddress(addr):
                    continue
                try:
                    scripthash = self._addressToScripthash(addr)
                    utxos = self._call(
                        "blockchain.scripthash.listunspent", [scripthash]
                    )
                    if utxos:
                        for utxo in utxos:
                            height = utxo.get("height", 0)
                            if height <= 0:
                                confirmations = 0
                            else:
                                confirmations = current_height - height + 1

                            if confirmations >= min_confirmations:
                                result.append(
                                    {
                                        "txid": utxo.get("tx_hash"),
                                        "vout": utxo.get("tx_pos"),
                                        "value": utxo.get("value", 0),
                                        "address": addr,
                                        "confirmations": confirmations,
                                    }
                                )
                except Exception as e:
                    self._log.debug(
                        f"ElectrumBackend.getUnspentOutputs error for {addr[:10]}...: {e}"
                    )
        except Exception as e:
            self._log.warning(f"ElectrumBackend.getUnspentOutputs error: {e}")

        return result

    def broadcastTransaction(self, tx_hex: str) -> str:
        import time

        max_retries = 3
        retry_delay = 0.5

        for attempt in range(max_retries):
            try:
                result = self._server.call("blockchain.transaction.broadcast", [tx_hex])
                if result:
                    return result
            except Exception as e:
                error_msg = str(e).lower()
                if any(
                    pattern in error_msg
                    for pattern in [
                        "missing inputs",
                        "bad-txns",
                        "txn-mempool-conflict",
                        "already in block chain",
                        "transaction already exists",
                        "insufficient fee",
                        "dust",
                        "non-bip68-final",
                        "non-final",
                        "locktime",
                    ]
                ):
                    raise
                if attempt < max_retries - 1:
                    self._log.debug(
                        f"broadcastTransaction retry {attempt + 1}/{max_retries}: {e}"
                    )
                    time.sleep(retry_delay * (2**attempt))  # Exponential backoff
                    continue
                raise
        return None

    def getTransaction(self, txid: str) -> Optional[dict]:
        try:
            return self._call("blockchain.transaction.get", [txid, True])
        except Exception:
            return None

    def getTransactionRaw(self, txid: str) -> Optional[str]:
        try:
            tx_hex = self._call("blockchain.transaction.get", [txid, False])
            return tx_hex
        except Exception as e:
            self._log.warning(f"getTransactionRaw failed for {txid[:16]}...: {e}")
            return None

    def getTransactionBatch(self, txids: List[str]) -> Dict[str, Optional[dict]]:
        result = {}
        if not txids:
            return result

        try:
            calls = [("blockchain.transaction.get", [txid, True]) for txid in txids]
            responses = self._call_batch(calls)
            for txid, tx_info in zip(txids, responses):
                result[txid] = tx_info if tx_info else None
        except Exception as e:
            self._log.debug(f"getTransactionBatch error: {e}")
            for txid in txids:
                result[txid] = self.getTransaction(txid)

        return result

    def getTransactionBatchRaw(self, txids: List[str]) -> Dict[str, Optional[str]]:
        result = {}
        if not txids:
            return result

        try:
            calls = [("blockchain.transaction.get", [txid, False]) for txid in txids]
            responses = self._call_batch(calls)
            for txid, tx_hex in zip(txids, responses):
                result[txid] = tx_hex if tx_hex else None
        except Exception as e:
            self._log.debug(f"getTransactionBatchRaw error: {e}")
            for txid in txids:
                result[txid] = self.getTransactionRaw(txid)

        return result

    def getBlockHeight(self) -> int:
        import time

        if hasattr(self._server, "get_subscribed_height"):
            subscribed_height = self._server.get_subscribed_height()
            if subscribed_height > 0:
                if subscribed_height > self._cached_height:
                    self._cached_height = subscribed_height
                    self._cached_height_time = time.time()
                return subscribed_height

        now = time.time()
        if (
            self._cached_height > 0
            and (now - self._cached_height_time) < self._height_cache_ttl
        ):
            return self._cached_height

        try:
            header = self._call("blockchain.headers.subscribe", [])
            if header:
                height = header.get("height", 0)
                if height > 0:
                    self._cached_height = height
                    self._cached_height_time = now
                return height
            return self._cached_height if self._cached_height > 0 else 0
        except Exception:
            return self._cached_height if self._cached_height > 0 else 0

    def estimateFee(self, blocks: int = 6) -> int:
        now = time.time()
        cache_key = blocks
        if cache_key in self._cached_fee:
            if (now - self._cached_fee_time.get(cache_key, 0)) < self._fee_cache_ttl:
                return self._cached_fee[cache_key]

        try:
            fee = self._call("blockchain.estimatefee", [blocks])
            if fee and fee > 0:
                result = int(fee * 1e8 / 1000)
                self._cached_fee[cache_key] = result
                self._cached_fee_time[cache_key] = now
                return result
            return self._cached_fee.get(cache_key, 1)
        except Exception:
            return self._cached_fee.get(cache_key, 1)

    def isConnected(self) -> bool:
        try:
            self._call("server.ping", [])
            return True
        except Exception:
            return False

    def getServerVersion(self) -> str:
        version = self._server.get_server_version()
        if not version:
            try:
                self._call("server.ping", [])
                version = self._server.get_server_version()
            except Exception:
                pass
        return version or "electrum"

    def getServerHost(self) -> str:
        host, port = self._server.get_current_server()
        if host and port:
            return f"{host}:{port}"
        return f"{self._host}:{self._port}"

    def getConnectionStatus(self) -> dict:
        if hasattr(self._server, "getConnectionStatus"):
            status = self._server.getConnectionStatus()
        else:
            status = {
                "connected": self.isConnected(),
                "failures": 0,
                "last_error": None,
                "all_failed": False,
                "using_defaults": True,
                "server_count": 1,
            }
        status["server"] = self.getServerHost()
        status["version"] = self.getServerVersion()
        return status

    def recentlyReconnected(self, grace_seconds: int = 30) -> bool:
        if hasattr(self._server, "recently_reconnected"):
            return self._server.recently_reconnected(grace_seconds)
        return False

    def getAddressHistory(self, address: str) -> List[dict]:
        if self._isUnsupportedAddress(address):
            return []
        try:
            scripthash = self._addressToScripthash(address)
            history = self._call("blockchain.scripthash.get_history", [scripthash])
            if history:
                return [
                    {"txid": h.get("tx_hash"), "height": h.get("height", 0)}
                    for h in history
                ]
            return []
        except Exception:
            return []

    def getAddressHistoryBackground(self, address: str) -> List[dict]:
        if self._isUnsupportedAddress(address):
            return []
        try:
            scripthash = self._addressToScripthash(address)
            history = self._server.call_background(
                "blockchain.scripthash.get_history", [scripthash]
            )
            if history:
                return [
                    {"txid": h.get("tx_hash"), "height": h.get("height", 0)}
                    for h in history
                ]
            return []
        except Exception:
            return []

    def getBatchBalance(self, scripthashes: List[str]) -> Dict[str, int]:
        result = {}
        for sh in scripthashes:
            result[sh] = 0

        try:
            calls = [("blockchain.scripthash.get_balance", [sh]) for sh in scripthashes]
            responses = self._call_batch(calls)
            for sh, balance in zip(scripthashes, responses):
                if balance:
                    confirmed = balance.get("confirmed", 0)
                    unconfirmed = balance.get("unconfirmed", 0)
                    result[sh] = confirmed + unconfirmed
        except Exception as e:
            self._log.warning(f"ElectrumBackend.getBatchBalance error: {e}")

        return result

    def getBatchUnspent(
        self, scripthashes: List[str], min_confirmations: int = 0
    ) -> Dict[str, List[dict]]:
        result = {}
        for sh in scripthashes:
            result[sh] = []

        try:
            current_height = self.getBlockHeight()

            calls = [("blockchain.scripthash.listunspent", [sh]) for sh in scripthashes]
            responses = self._call_batch(calls)
            for sh, utxos in zip(scripthashes, responses):
                if utxos:
                    for utxo in utxos:
                        height = utxo.get("height", 0)
                        if height <= 0:
                            confirmations = 0
                        else:
                            confirmations = current_height - height + 1

                        if confirmations >= min_confirmations:
                            result[sh].append(
                                {
                                    "txid": utxo.get("tx_hash"),
                                    "vout": utxo.get("tx_pos"),
                                    "value": utxo.get("value", 0),
                                    "confirmations": confirmations,
                                }
                            )
        except Exception as e:
            self._log.warning(f"ElectrumBackend.getBatchUnspent error: {e}")

        return result

    def enableRealtimeNotifications(self, callback) -> None:
        self._realtime_callback = callback
        self._server.enable_realtime_notifications()
        self._log.info(f"Real-time notifications enabled for {self._coin_type}")

    def _create_scripthash_callback(self, scripthash):

        def callback(sh, new_status):
            self._handle_scripthash_notification(sh, new_status)

        return callback

    def _handle_scripthash_notification(self, scripthash, new_status):
        if not self._realtime_callback:
            return

        address = None
        for addr, sh in self._address_to_scripthash.items():
            if sh == scripthash:
                address = addr
                break

        try:
            self._realtime_callback(
                self._coin_type, address, scripthash, "balance_change"
            )
        except Exception as e:
            self._log.debug(f"Error in realtime callback: {e}")

    def subscribeAddressWithCallback(self, address: str) -> str:
        if self._isUnsupportedAddress(address):
            return None

        try:
            scripthash = self._addressToScripthash(address)
            self._address_to_scripthash[address] = scripthash

            if self._realtime_callback:
                status = self._server.subscribe_with_callback(
                    scripthash, self._create_scripthash_callback(scripthash)
                )
            else:
                status = self._call("blockchain.scripthash.subscribe", [scripthash])

            self._subscribed_scripthashes.add(scripthash)
            return status
        except Exception as e:
            self._log.debug(f"Failed to subscribe to {address}: {e}")
            return None

    def getSyncStatus(self) -> dict:
        import time

        height = 0
        height_time = 0
        if hasattr(self._server, "get_subscribed_height"):
            height = self._server.get_subscribed_height()
            height_time = getattr(self._server, "_subscribed_height_time", 0)

        if self._cached_height > 0:
            if self._cached_height > height:
                height = self._cached_height
            if self._cached_height_time > height_time:
                height_time = self._cached_height_time

        now = time.time()
        stale_threshold = 300
        last_activity = getattr(self._server, "_last_activity", 0)
        most_recent = max(height_time, last_activity)
        is_synced = height > 0 and (now - most_recent) < stale_threshold
        return {
            "height": height,
            "synced": is_synced,
            "last_update": height_time,
        }

    def getServer(self):
        return self._server
