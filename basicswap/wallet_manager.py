# -*- coding: utf-8 -*-

# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import threading
import time
from typing import Dict, List, Optional, Tuple

from .chainparams import Coins
from .contrib.test_framework import segwit_addr
from .db_wallet import (
    WalletAddress,
    WalletLockedUTXO,
    WalletPendingTx,
    WalletState,
    WalletTxCache,
    WalletWatchOnly,
)
from .util.crypto import hash160
from .util.extkey import ExtKeyPair


class WalletManager:

    SUPPORTED_COINS = {Coins.BTC, Coins.LTC}

    BIP84_COIN_TYPES = {
        Coins.BTC: 0,
        Coins.LTC: 2,
    }

    HRP = {
        Coins.BTC: {"mainnet": "bc", "testnet": "tb", "regtest": "bcrt"},
        Coins.LTC: {"mainnet": "ltc", "testnet": "tltc", "regtest": "rltc"},
    }

    GAP_LIMIT = 50
    ELECTRUM_GAP_LIMIT = 20

    def __init__(self, swap_client, log):
        self._gap_limits: Dict[Coins, int] = {}
        self._swap_client = swap_client
        self._log = log
        self._seed: bytes = None
        self._master_keys: Dict[Coins, bytes] = {}
        self._external_chains: Dict[Coins, ExtKeyPair] = {}
        self._internal_chains: Dict[Coins, ExtKeyPair] = {}
        self._initialized: set = set()
        self._migration_in_progress: set = set()
        self._balance_sync_lock = threading.Lock()

    def getGapLimit(self, coin_type: Coins) -> int:
        return self._gap_limits.get(coin_type, self.GAP_LIMIT)

    def setGapLimit(self, coin_type: Coins, gap_limit: int) -> None:
        self._gap_limits[coin_type] = gap_limit

    def initialize(self, coin_type: Coins, root_key) -> None:
        if coin_type not in self.SUPPORTED_COINS:
            raise ValueError(f"Coin {coin_type} not supported by WalletManager")

        if isinstance(root_key, ExtKeyPair):
            ek = root_key
            raw_key = ek._key if hasattr(ek, "_key") else None
            self._master_keys[coin_type] = raw_key
            if self._seed is None and raw_key:
                self._seed = raw_key
        elif isinstance(root_key, bytes):
            self._master_keys[coin_type] = root_key
            if self._seed is None:
                self._seed = root_key
            ek = ExtKeyPair()
            ek.set_seed(root_key)
        else:
            raise ValueError(
                f"root_key must be bytes or ExtKeyPair, got {type(root_key)}"
            )

        bip44_coin = self.BIP84_COIN_TYPES.get(coin_type, 0)
        ext_path = f"84h/{bip44_coin}h/0h/0"
        int_path = f"84h/{bip44_coin}h/0h/1"

        self._external_chains[coin_type] = ek.derive_path(ext_path)
        self._internal_chains[coin_type] = ek.derive_path(int_path)
        self._initialized.add(coin_type)

        if self.needsMigration(coin_type):
            self.runMigration(coin_type)

        self._log.debug(f"WalletManager: {Coins(coin_type).name} initialized")

    def getDepositAddress(self, coin_type: Coins) -> Optional[str]:
        return self.getAddress(coin_type, index=0, internal=False)

    def isInitialized(self, coin_type: Coins) -> bool:
        return coin_type in self._initialized

    def _getHRP(self, coin_type: Coins) -> str:
        return self.HRP.get(coin_type, {}).get(self._swap_client.chain, "bc")

    def _deriveKey(self, coin_type: Coins, index: int, internal: bool = False) -> bytes:
        chain = (
            self._internal_chains[coin_type]
            if internal
            else self._external_chains[coin_type]
        )
        return chain.derive(index)._key

    def _deriveAddress(
        self, coin_type: Coins, index: int, internal: bool = False
    ) -> Tuple[str, str, bytes]:
        from coincurve import PublicKey

        key = self._deriveKey(coin_type, index, internal)
        pubkey = PublicKey.from_secret(key).format()
        pkh = hash160(pubkey)
        address = segwit_addr.encode(self._getHRP(coin_type), 0, pkh)
        scripthash = hashlib.sha256(bytes([0x00, 0x14]) + pkh).digest()[::-1].hex()
        return address, scripthash, pubkey

    def _syncStateIndices(self, coin_type: Coins, cursor) -> None:
        query = "SELECT MAX(derivation_index) FROM wallet_addresses WHERE coin_type = ? AND is_internal = ?"
        cursor.execute(query, (int(coin_type), False))
        max_ext = cursor.fetchone()[0]
        cursor.execute(query, (int(coin_type), True))
        max_int = cursor.fetchone()[0]

        cursor.execute(
            "SELECT last_external_index, last_internal_index FROM wallet_state WHERE coin_type = ?",
            (int(coin_type),),
        )
        row = cursor.fetchone()
        if row is None:
            return

        current_ext = row[0] or 0
        current_int = row[1] or 0

        new_ext = max(current_ext, max_ext) if max_ext is not None else current_ext
        new_int = max(current_int, max_int) if max_int is not None else current_int

        if new_ext > current_ext or new_int > current_int:
            now = int(time.time())
            cursor.execute(
                "UPDATE wallet_state SET last_external_index = ?, last_internal_index = ?, updated_at = ? WHERE coin_type = ?",
                (new_ext, new_int, now, int(coin_type)),
            )
            self._swap_client.commitDB()

    def _findReusableAddress(self, coin_type: Coins, internal: bool, cursor):
        query = (
            "SELECT derivation_index, address FROM wallet_addresses"
            " WHERE coin_type = ? AND is_internal = ? AND is_funded = 0"
            " ORDER BY derivation_index ASC LIMIT 1"
        )
        cursor.execute(query, (int(coin_type), internal))
        row = cursor.fetchone()
        if row:
            return row[0], row[1]
        return None, None

    def getNewAddress(
        self, coin_type: Coins, internal: bool = False, label: str = "", cursor=None
    ) -> str:
        if not self.isInitialized(coin_type):
            raise ValueError(f"Wallet not initialized for {Coins(coin_type).name}")

        use_cursor = self._swap_client.openDB(cursor)
        try:
            state = self._swap_client.queryOne(
                WalletState, use_cursor, {"coin_type": int(coin_type)}
            )

            if state is None:
                next_index = 0
                now = int(time.time())
                self._swap_client.add(
                    WalletState(
                        coin_type=int(coin_type),
                        last_external_index=0,
                        last_internal_index=0,
                        derivation_path_type="bip84",
                        migration_complete=False,
                        created_at=now,
                        updated_at=now,
                    ),
                    use_cursor,
                )
            else:
                if internal:
                    next_index = (state.last_internal_index or 0) + 1
                else:
                    next_index = (state.last_external_index or 0) + 1

            if next_index >= self.ELECTRUM_GAP_LIMIT:
                reuse_index, reuse_addr = self._findReusableAddress(
                    coin_type, internal, use_cursor
                )
                if reuse_addr is not None:
                    self._log.debug(
                        f"Reusing unfunded address at index {reuse_index}"
                        f" (next would be {next_index},"
                        f" electrum gap limit {self.ELECTRUM_GAP_LIMIT})"
                    )
                    self._swap_client.commitDB()
                    return reuse_addr

            existing = self._swap_client.queryOne(
                WalletAddress,
                use_cursor,
                {
                    "coin_type": int(coin_type),
                    "derivation_index": next_index,
                    "is_internal": internal,
                },
            )

            if existing:
                address = existing.address
                if state:
                    if internal:
                        state.last_internal_index = next_index
                    else:
                        state.last_external_index = next_index
                    state.updated_at = int(time.time())
                    self._swap_client.updateDB(
                        state, use_cursor, constraints=["coin_type"]
                    )
                self._swap_client.commitDB()
                return address

            address, scripthash, pubkey = self._deriveAddress(
                coin_type, next_index, internal
            )
            bip44_coin = self.BIP84_COIN_TYPES.get(coin_type, 0)
            chain_idx = 1 if internal else 0
            now = int(time.time())
            self._swap_client.add(
                WalletAddress(
                    coin_type=int(coin_type),
                    derivation_index=next_index,
                    is_internal=internal,
                    derivation_path=f"m/84'/{bip44_coin}'/0'/{chain_idx}/{next_index}",
                    address=address,
                    scripthash=scripthash,
                    pubkey=pubkey,
                    is_funded=False,
                    cached_balance=0,
                    created_at=now,
                ),
                use_cursor,
            )

            if state:
                if internal:
                    state.last_internal_index = next_index
                else:
                    state.last_external_index = next_index
                state.updated_at = now
                self._swap_client.updateDB(state, use_cursor, constraints=["coin_type"])

            self._swap_client.commitDB()
            return address

        except Exception as e:
            self._swap_client.rollbackDB()
            raise e
        finally:
            if cursor is None:
                self._swap_client.closeDB(use_cursor, commit=False)

    def getAddress(
        self, coin_type: Coins, index: int, internal: bool = False
    ) -> Optional[str]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            cursor.execute(
                """SELECT address FROM wallet_addresses
                   WHERE coin_type = ? AND derivation_index = ? AND is_internal = ?""",
                (int(coin_type), index, internal),
            )
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else None
        except Exception:
            return None

    def getAddressAtIndex(
        self, coin_type: Coins, index: int, internal: bool = False
    ) -> Optional[str]:
        if not self.isInitialized(coin_type):
            return None

        try:
            address, _, _ = self._deriveAddress(coin_type, index, internal)
            return address
        except Exception:
            return None

    def discoverAddress(
        self, coin_type: Coins, address: str, max_index: int = 1000
    ) -> Optional[Tuple[int, bool]]:
        if not self.isInitialized(coin_type):
            return None

        for internal in [False, True]:
            for i in range(max_index):
                derived_addr, _, _ = self._deriveAddress(coin_type, i, internal)
                if derived_addr == address:
                    return (i, internal)
        return None

    def importAddress(
        self, coin_type: Coins, address: str, max_scan_index: int = 1000
    ) -> bool:
        if not self.isInitialized(coin_type):
            return False

        cursor = self._swap_client.openDB()
        try:
            existing = self._swap_client.queryOne(
                WalletAddress, cursor, {"coin_type": int(coin_type), "address": address}
            )
            if existing:
                return True

            result = self.discoverAddress(coin_type, address, max_scan_index)
            if result is None:
                return False

            index, internal = result
            existing_at_index = self._swap_client.queryOne(
                WalletAddress,
                cursor,
                {
                    "coin_type": int(coin_type),
                    "derivation_index": index,
                    "is_internal": internal,
                },
            )
            if existing_at_index:
                return False

            addr, scripthash, pubkey = self._deriveAddress(coin_type, index, internal)
            bip44_coin = self.BIP84_COIN_TYPES.get(coin_type, 0)
            chain_idx = 1 if internal else 0
            now = int(time.time())
            self._swap_client.add(
                WalletAddress(
                    coin_type=int(coin_type),
                    derivation_index=index,
                    is_internal=internal,
                    derivation_path=f"m/84'/{bip44_coin}'/0'/{chain_idx}/{index}",
                    address=address,
                    scripthash=scripthash,
                    pubkey=pubkey,
                    is_funded=True,
                    cached_balance=0,
                    created_at=now,
                ),
                cursor,
            )

            state = self._swap_client.queryOne(
                WalletState, cursor, {"coin_type": int(coin_type)}
            )
            if state:
                if internal and (state.last_internal_index or 0) < index:
                    state.last_internal_index = index
                    state.updated_at = now
                    self._swap_client.updateDB(state, cursor, constraints=["coin_type"])
                elif not internal and (state.last_external_index or 0) < index:
                    state.last_external_index = index
                    state.updated_at = now
                    self._swap_client.updateDB(state, cursor, constraints=["coin_type"])

            self._swap_client.commitDB()
            return True
        except Exception:
            self._swap_client.rollbackDB()
            return False
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def getAllAddresses(
        self,
        coin_type: Coins,
        include_internal: bool = True,
        include_watch_only: bool = True,
        funded_only: bool = False,
    ) -> List[str]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            query = "SELECT address FROM wallet_addresses WHERE coin_type = ?"
            if not include_internal:
                query += " AND is_internal = 0"
            if funded_only:
                query += " AND (is_funded = 1 OR cached_balance > 0)"
            query += " ORDER BY derivation_index ASC"
            cursor.execute(query, (int(coin_type),))
            addresses = [row[0] for row in cursor.fetchall() if row[0]]
            if include_watch_only:
                watch_query = (
                    "SELECT address FROM wallet_watch_only WHERE coin_type = ?"
                )
                if funded_only:
                    watch_query += " AND (is_funded = 1 OR cached_balance > 0)"
                cursor.execute(watch_query, (int(coin_type),))
                addresses.extend(
                    row[0]
                    for row in cursor.fetchall()
                    if row[0] and row[0] not in addresses
                )
            conn.close()
            return addresses
        except Exception:
            return []

    def getFundedAddresses(self, coin_type: Coins) -> Dict[str, str]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            funded = {}
            cursor.execute(
                "SELECT address, scripthash FROM wallet_addresses WHERE coin_type = ? AND is_funded = 1",
                (int(coin_type),),
            )
            funded.update(
                {row[0]: row[1] for row in cursor.fetchall() if row[0] and row[1]}
            )
            cursor.execute(
                "SELECT address, scripthash FROM wallet_watch_only WHERE coin_type = ? AND is_funded = 1 AND private_key_encrypted IS NOT NULL AND private_key_encrypted != ''",
                (int(coin_type),),
            )
            funded.update(
                {row[0]: row[1] for row in cursor.fetchall() if row[0] and row[1]}
            )
            conn.close()
            return funded
        except Exception:
            return {}

    def getExistingInternalAddress(self, coin_type: Coins) -> Optional[str]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT address FROM wallet_addresses WHERE coin_type = ? AND is_internal = 1 ORDER BY derivation_index DESC LIMIT 1",
                (int(coin_type),),
            )
            row = cursor.fetchone()
            conn.close()
            return row[0] if row and row[0] else None
        except Exception:
            return None

    def getNewInternalAddress(self, coin_type: Coins) -> Optional[str]:
        if coin_type not in self._initialized:
            return None

        cursor = None
        try:
            cursor = self._swap_client.openDB()

            cursor.execute(
                "SELECT MAX(derivation_index) FROM wallet_addresses WHERE coin_type = ? AND is_internal = 1",
                (int(coin_type),),
            )
            row = cursor.fetchone()
            next_index = (row[0] or -1) + 1

            address, scripthash, pubkey = self._deriveAddress(
                coin_type, next_index, internal=True
            )
            path = f"84h/{self.BIP84_COIN_TYPES.get(coin_type, 0)}h/0h/1/{next_index}"

            now = int(time.time())
            self._swap_client.add(
                WalletAddress(
                    coin_type=int(coin_type),
                    derivation_index=next_index,
                    is_internal=True,
                    derivation_path=path,
                    address=address,
                    scripthash=scripthash,
                    pubkey=pubkey,
                    is_funded=False,
                    created_at=now,
                ),
                cursor,
            )
            self._swap_client.commitDB()

            self._log.debug(
                f"Generated new internal address for {coin_type.name}: {address[:16]}..."
            )
            return address
        except Exception as e:
            self._log.warning(f"Failed to generate new internal address: {e}")
            self._swap_client.rollbackDB()
            return None
        finally:
            if cursor:
                self._swap_client.closeDB(cursor, commit=False)

    def getAddressInfo(self, coin_type: Coins, address: str) -> Optional[dict]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT address, scripthash, derivation_index, is_internal, derivation_path, is_funded, cached_balance FROM wallet_addresses WHERE coin_type = ? AND address = ?",
                (int(coin_type), address),
            )
            row = cursor.fetchone()
            if row:
                conn.close()
                return {
                    "address": row[0],
                    "scripthash": row[1],
                    "derivation_index": row[2],
                    "is_internal": bool(row[3]),
                    "derivation_path": row[4],
                    "is_funded": bool(row[5]),
                    "cached_balance": row[6],
                    "is_watch_only": False,
                }
            cursor.execute(
                "SELECT address, scripthash, is_funded, cached_balance, label FROM wallet_watch_only WHERE coin_type = ? AND address = ?",
                (int(coin_type), address),
            )
            row = cursor.fetchone()
            conn.close()
            if row:
                return {
                    "address": row[0],
                    "scripthash": row[1],
                    "is_funded": bool(row[2]),
                    "cached_balance": row[3],
                    "is_watch_only": True,
                    "label": row[4],
                }
            return None
        except Exception:
            return None

    def getCachedTotalBalance(self, coin_type: Coins) -> int:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT COALESCE(SUM(cached_balance), 0) FROM wallet_addresses WHERE coin_type = ?",
                (int(coin_type),),
            )
            total = cursor.fetchone()[0] or 0

            cursor.execute(
                "SELECT COALESCE(SUM(cached_balance), 0) FROM wallet_watch_only WHERE coin_type = ?",
                (int(coin_type),),
            )
            total += cursor.fetchone()[0] or 0

            conn.close()
            return total
        except Exception:
            return 0

    def syncBalances(self, coin_type: Coins, backend, funded_only: bool = False) -> int:

        if not self.isInitialized(coin_type):
            return 0

        if not self._balance_sync_lock.acquire(blocking=False):
            self._log.debug(
                f"syncBalances: skipping, already in progress for {Coins(coin_type).name}"
            )
            return 0

        try:
            addresses = []
            addr_info = {}
            cursor = self._swap_client.openDB()
            try:
                for record in self._swap_client.query(
                    WalletAddress, cursor, {"coin_type": int(coin_type)}
                ):

                    if (
                        funded_only
                        and not record.is_funded
                        and not (record.cached_balance and record.cached_balance > 0)
                    ):
                        continue
                    addresses.append(record.address)
                    addr_info[record.address] = (
                        "wallet",
                        record.is_internal,
                        record.derivation_index,
                    )

                for record in self._swap_client.query(
                    WalletWatchOnly, cursor, {"coin_type": int(coin_type)}
                ):
                    if record.address not in addr_info:
                        if (
                            funded_only
                            and not record.is_funded
                            and not (
                                record.cached_balance and record.cached_balance > 0
                            )
                        ):
                            continue
                        addresses.append(record.address)
                        addr_info[record.address] = ("watch", False, None)
            finally:
                self._swap_client.closeDB(cursor, commit=False)

            if not addresses:
                return 0

            try:
                balances = backend.getBalance(addresses)
            except Exception as e:
                self._log.warning(f"syncBalances network error: {e}")
                return 0

            if not balances:
                return 0

            cursor = self._swap_client.openDB()
            try:
                now = int(time.time())
                updated = 0

                for addr, balance in balances.items():
                    if addr not in addr_info:
                        continue

                    record_type, _, _ = addr_info[addr]
                    if record_type == "wallet":
                        record = self._swap_client.queryOne(
                            WalletAddress,
                            cursor,
                            {"coin_type": int(coin_type), "address": addr},
                        )
                    else:
                        record = self._swap_client.queryOne(
                            WalletWatchOnly,
                            cursor,
                            {"coin_type": int(coin_type), "address": addr},
                        )

                    if record:
                        old_balance = record.cached_balance or 0
                        if balance != old_balance or balance > 0:
                            record.cached_balance = balance
                            record.is_funded = balance > 0
                            if record_type == "wallet":
                                record.cached_balance_time = now
                            self._swap_client.updateDB(
                                record, cursor, constraints=["coin_type", "address"]
                            )
                            updated += 1

                self._swap_client.commitDB()
                return updated
            except Exception as e:
                self._log.warning(f"syncBalances DB error: {e}")
                self._swap_client.rollbackDB()
                return 0
            finally:
                self._swap_client.closeDB(cursor, commit=False)
        finally:
            self._balance_sync_lock.release()

    def findAddressWithCachedBalance(
        self,
        coin_type: Coins,
        min_balance: int,
        include_internal: bool = False,
        max_cache_age: int = 120,
    ) -> Optional[tuple]:
        if not self.isInitialized(coin_type):
            return None

        import sqlite3

        now = int(time.time())
        min_cache_time = now - max_cache_age

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()

            cursor.execute(
                """SELECT address, cached_balance, is_internal, cached_balance_time
                   FROM wallet_addresses
                   WHERE coin_type = ? AND is_funded = 1
                   AND cached_balance_time >= ?
                   ORDER BY cached_balance DESC, derivation_index ASC""",
                (int(coin_type), min_cache_time),
            )
            for row in cursor.fetchall():
                address, cached_balance, is_internal, _ = row
                if not include_internal and is_internal:
                    continue
                if cached_balance and cached_balance >= min_balance:
                    conn.close()
                    return (address, cached_balance)

            cursor.execute(
                """SELECT address, cached_balance, cached_balance_time
                   FROM wallet_watch_only
                   WHERE coin_type = ? AND is_funded = 1
                   AND cached_balance_time >= ?""",
                (int(coin_type), min_cache_time),
            )
            for row in cursor.fetchall():
                address, cached_balance, _ = row
                if cached_balance and cached_balance >= min_balance:
                    conn.close()
                    return (address, cached_balance)

            conn.close()
            return None
        except Exception:
            return None

    def hasCachedBalances(self, coin_type: Coins, max_cache_age: int = 120) -> bool:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM wallet_addresses WHERE coin_type = ? AND cached_balance_time >= ?",
                (int(coin_type), int(time.time()) - max_cache_age),
            )
            count = cursor.fetchone()[0]
            conn.close()
            return count > 0
        except Exception:
            return False

    def getPrivateKey(self, coin_type: Coins, address: str) -> Optional[bytes]:
        if not self.isInitialized(coin_type):
            return None
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT derivation_index, is_internal FROM wallet_addresses WHERE coin_type = ? AND address = ?",
                (int(coin_type), address),
            )
            row = cursor.fetchone()
            if row is not None:
                conn.close()
                return self._deriveKey(coin_type, row[0], bool(row[1]))
            cursor.execute(
                "SELECT private_key_encrypted FROM wallet_watch_only WHERE coin_type = ? AND address = ?",
                (int(coin_type), address),
            )
            row = cursor.fetchone()
            conn.close()
            return (
                self._decryptPrivateKey(row[0], coin_type) if row and row[0] else None
            )
        except Exception:
            return None

    def getSignableAddresses(self, coin_type: Coins) -> Dict[str, str]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT address, scripthash FROM wallet_addresses WHERE coin_type = ?",
                (int(coin_type),),
            )
            result = {row[0]: row[1] for row in cursor.fetchall() if row[0] and row[1]}
            conn.close()
            return result
        except Exception:
            return {}

    def importWatchOnlyAddress(
        self,
        coin_type: Coins,
        address: str,
        scripthash: str = "",
        label: str = "",
        source: str = "import",
        cursor=None,
    ) -> None:
        owns_cursor = cursor is None
        if owns_cursor:
            cursor = self._swap_client.openDB()
        try:
            if self._swap_client.queryOne(
                WalletAddress, cursor, {"coin_type": int(coin_type), "address": address}
            ):
                return
            if self._swap_client.queryOne(
                WalletWatchOnly,
                cursor,
                {"coin_type": int(coin_type), "address": address},
            ):
                return

            if not scripthash:
                scripthash = self._computeScripthash(coin_type, address)

            self._swap_client.add(
                WalletWatchOnly(
                    coin_type=int(coin_type),
                    address=address,
                    scripthash=scripthash,
                    label=label,
                    source=source,
                    is_funded=False,
                    cached_balance=0,
                    created_at=int(time.time()),
                ),
                cursor,
            )
            if owns_cursor:
                self._swap_client.commitDB()
        except Exception as e:
            if owns_cursor:
                self._swap_client.rollbackDB()
            raise e
        finally:
            if owns_cursor:
                self._swap_client.closeDB(cursor, commit=False)

    def importAddressWithKey(
        self,
        coin_type: Coins,
        address: str,
        private_key: bytes,
        label: str = "",
        source: str = "import",
    ) -> bool:
        from coincurve import PublicKey as CCPublicKey

        try:
            pubkey = CCPublicKey.from_secret(private_key).format()
            if (
                segwit_addr.encode(self._getHRP(coin_type), 0, hash160(pubkey))
                != address
            ):
                return False
        except Exception:
            return False

        cursor = self._swap_client.openDB()
        try:
            if self._swap_client.queryOne(
                WalletAddress, cursor, {"coin_type": int(coin_type), "address": address}
            ):
                return False

            existing_watch = self._swap_client.queryOne(
                WalletWatchOnly,
                cursor,
                {"coin_type": int(coin_type), "address": address},
            )
            encrypted_key = self._encryptPrivateKey(private_key, coin_type)

            if existing_watch:
                cursor.execute(
                    """UPDATE wallet_watch_only SET private_key_encrypted = ?, label = ?, source = ?
                       WHERE coin_type = ? AND address = ?""",
                    (
                        encrypted_key,
                        label or existing_watch.label or "",
                        source,
                        int(coin_type),
                        address,
                    ),
                )
            else:
                self._swap_client.add(
                    WalletWatchOnly(
                        coin_type=int(coin_type),
                        address=address,
                        scripthash=self._computeScripthash(coin_type, address),
                        label=label,
                        source=source,
                        is_funded=False,
                        cached_balance=0,
                        private_key_encrypted=encrypted_key,
                        created_at=int(time.time()),
                    ),
                    cursor,
                )

            self._swap_client.commitDB()
            return True
        except Exception:
            self._swap_client.rollbackDB()
            return False
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def importKeysFromRPC(self, coin_type: Coins, rpc_callback) -> int:
        imported = 0
        try:
            funded_addresses = set()

            try:
                for u in rpc_callback("listunspent", [0]):
                    if u.get("address"):
                        funded_addresses.add(u["address"])
            except Exception:
                pass

            try:
                for t in rpc_callback("listtransactions", ["*", 1000]):
                    if t.get("address"):
                        funded_addresses.add(t["address"])
            except Exception:
                pass

            try:
                for r in rpc_callback("listreceivedbyaddress", [0, True]):
                    if r.get("address"):
                        funded_addresses.add(r["address"])
            except Exception:
                pass

            try:
                labels = rpc_callback("listlabels", [])
                for label in labels:
                    try:
                        addrs = rpc_callback("getaddressesbylabel", [label])
                        if isinstance(addrs, dict):
                            for addr in addrs.keys():
                                funded_addresses.add(addr)
                    except Exception:
                        pass
            except Exception:
                pass

            self._log.debug(
                f"importKeysFromRPC: Found {len(funded_addresses)} addresses to check"
            )

            for address in funded_addresses:
                if self.getPrivateKey(coin_type, address):
                    continue
                try:
                    wif = rpc_callback("dumpprivkey", [address])
                    if wif:
                        privkey = self._decodeWIF(wif, coin_type)
                        if privkey and self.importAddressWithKey(
                            coin_type, address, privkey, source="rpc_migration"
                        ):
                            imported += 1
                except Exception:
                    pass

            self._log.info(
                f"importKeysFromRPC: Imported {imported} keys for {coin_type}"
            )
            return imported
        except Exception as e:
            self._log.warning(f"importKeysFromRPC error: {e}")
            return imported

    def _b58decode(self, s: str) -> bytes:
        ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        n = 0
        for c in s:
            n = n * 58 + ALPHABET.index(c)
        result = []
        while n > 0:
            result.append(n & 0xFF)
            n >>= 8
        pad = len(s) - len(s.lstrip("1"))
        return bytes(pad) + bytes(reversed(result))

    def _b58decode_check(self, s: str) -> bytes:
        data = self._b58decode(s)
        payload, checksum = data[:-4], data[-4:]
        expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        if checksum != expected:
            raise ValueError("Invalid base58 checksum")
        return payload

    def _decodeWIF(
        self, wif: str, coin_type: Coins = None
    ) -> Optional[bytes]:  # noqa: ARG002
        try:
            decoded = self._b58decode_check(wif)
            if len(decoded) == 33:
                return decoded[1:]
            elif len(decoded) == 34:
                return decoded[1:33]
            return None
        except Exception:
            return None

    def _getXorKey(self, coin_type: Coins) -> bytes:
        master_key = self._master_keys.get(coin_type)
        if master_key is None:
            raise ValueError(f"Wallet not initialized for {coin_type}")
        return hashlib.sha256(master_key + b"_import_key").digest()

    def _encryptPrivateKey(self, private_key: bytes, coin_type: Coins) -> bytes:
        return bytes(a ^ b for a, b in zip(private_key, self._getXorKey(coin_type)))

    def _decryptPrivateKey(self, encrypted_key: bytes, coin_type: Coins) -> bytes:
        return bytes(a ^ b for a, b in zip(encrypted_key, self._getXorKey(coin_type)))

    def _computeScripthash(self, coin_type: Coins, address: str) -> str:
        _, data = segwit_addr.decode(self._getHRP(coin_type), address)
        if data is None:
            return ""
        return hashlib.sha256(bytes([0x00, 0x14]) + bytes(data)).digest()[::-1].hex()

    def needsMigration(self, coin_type: Coins) -> bool:
        cursor = self._swap_client.openDB()
        try:
            state = self._swap_client.queryOne(
                WalletState, cursor, {"coin_type": int(coin_type)}
            )
            return state is None or not state.migration_complete
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def resetMigration(self, coin_type: Coins) -> None:
        cursor = self._swap_client.openDB()
        try:
            state = self._swap_client.queryOne(
                WalletState, cursor, {"coin_type": int(coin_type)}
            )
            if state:
                state.migration_complete = False
                state.updated_at = int(time.time())
                self._swap_client.updateDB(state, cursor, constraints=["coin_type"])
            self._swap_client.commitDB()
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def runMigration(
        self,
        coin_type: Coins,
        full_node_addresses: Optional[List[str]] = None,
        cached_address: Optional[str] = None,
        num_addresses: int = 20,
    ) -> int:
        if not self.isInitialized(coin_type):
            raise ValueError(f"Wallet not initialized for {Coins(coin_type).name}")
        self._migration_in_progress.add(coin_type)
        try:
            bip44_coin = self.BIP84_COIN_TYPES.get(coin_type, 0)
            derived_addresses = []
            for internal in [False, True]:
                chain_idx = 1 if internal else 0
                for i in range(num_addresses):
                    address, scripthash, pubkey = self._deriveAddress(
                        coin_type, i, internal
                    )
                    derived_addresses.append(
                        {
                            "index": i,
                            "internal": internal,
                            "address": address,
                            "scripthash": scripthash,
                            "pubkey": pubkey,
                            "deriv_path": f"m/84'/{bip44_coin}'/0'/{chain_idx}/{i}",
                        }
                    )

            added = 0
            cursor = self._swap_client.openDB()
            try:
                now = int(time.time())

                state = self._swap_client.queryOne(
                    WalletState, cursor, {"coin_type": int(coin_type)}
                )
                if state is None:
                    self._swap_client.add(
                        WalletState(
                            coin_type=int(coin_type),
                            last_external_index=0,
                            last_internal_index=0,
                            derivation_path_type="bip84",
                            migration_complete=False,
                            created_at=now,
                            updated_at=now,
                        ),
                        cursor,
                    )

                for addr_data in derived_addresses:
                    existing = self._swap_client.queryOne(
                        WalletAddress,
                        cursor,
                        {
                            "coin_type": int(coin_type),
                            "derivation_index": addr_data["index"],
                            "is_internal": addr_data["internal"],
                        },
                    )
                    if existing:
                        continue

                    self._swap_client.add(
                        WalletAddress(
                            coin_type=int(coin_type),
                            derivation_index=addr_data["index"],
                            is_internal=addr_data["internal"],
                            derivation_path=addr_data["deriv_path"],
                            address=addr_data["address"],
                            scripthash=addr_data["scripthash"],
                            pubkey=addr_data["pubkey"],
                            is_funded=False,
                            cached_balance=0,
                            created_at=now,
                        ),
                        cursor,
                    )
                    added += 1

                if full_node_addresses:
                    for addr in full_node_addresses:
                        self.importWatchOnlyAddress(
                            coin_type, addr, source="full_node_migration", cursor=cursor
                        )

                if cached_address:
                    self.importWatchOnlyAddress(
                        coin_type,
                        cached_address,
                        source="cached_deposit",
                        cursor=cursor,
                    )

                state = self._swap_client.queryOne(
                    WalletState, cursor, {"coin_type": int(coin_type)}
                )
                if state:
                    state.migration_complete = True
                    state.last_external_index = num_addresses - 1
                    state.last_internal_index = num_addresses - 1
                    state.updated_at = now
                    self._swap_client.updateDB(state, cursor, constraints=["coin_type"])

                self._swap_client.commitDB()
                return added
            except Exception as e:
                self._swap_client.rollbackDB()
                raise e
            finally:
                self._swap_client.closeDB(cursor, commit=False)
        finally:
            self._migration_in_progress.discard(coin_type)

    def getAddressCount(self, coin_type: Coins) -> int:
        cursor = self._swap_client.openDB()
        try:
            return len(
                list(
                    self._swap_client.query(
                        WalletAddress, cursor, {"coin_type": int(coin_type)}
                    )
                )
            )
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def getSeedID(self, coin_type: Coins) -> Optional[str]:
        from basicswap.contrib.test_framework.script import hash160

        master_key = self._master_keys.get(coin_type)
        if master_key is None:
            return None

        ek = ExtKeyPair()
        ek.set_seed(master_key)
        return hash160(ek.encode_p()).hex()

    def signMessage(self, coin_type: Coins, address: str, message: str) -> bytes:
        from coincurve import PrivateKey

        key = self.getPrivateKey(coin_type, address)
        if key is None:
            raise ValueError(f"Cannot sign: no key for address {address}")
        return PrivateKey(key).sign(message.encode("utf-8"))

    def signHash(self, coin_type: Coins, address: str, msg_hash: bytes) -> bytes:
        from coincurve import PrivateKey

        key = self.getPrivateKey(coin_type, address)
        if key is None:
            raise ValueError(f"Cannot sign: no key for address {address}")
        return PrivateKey(key).sign(msg_hash, hasher=None)

    def getKeyForAddress(
        self, coin_type: Coins, address: str
    ) -> Optional[Tuple[bytes, bytes]]:
        from coincurve import PublicKey

        key = self.getPrivateKey(coin_type, address)
        if key is None:
            return None
        return (key, PublicKey.from_secret(key).format())

    def findAddressByScripthash(
        self, coin_type: Coins, scripthash: str
    ) -> Optional[str]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT address FROM wallet_addresses WHERE coin_type = ? AND scripthash = ?",
                (int(coin_type), scripthash),
            )
            row = cursor.fetchone()
            if row:
                conn.close()
                return row[0]
            cursor.execute(
                "SELECT address FROM wallet_watch_only WHERE coin_type = ? AND scripthash = ?",
                (int(coin_type), scripthash),
            )
            row = cursor.fetchone()
            conn.close()
            return row[0] if row else None
        except Exception:
            return None

    def getAllScripthashes(self, coin_type: Coins) -> List[str]:
        import sqlite3

        try:
            conn = sqlite3.connect(self._swap_client.sqlite_file)
            cursor = conn.cursor()
            scripthashes = []
            for table in ["wallet_addresses", "wallet_watch_only"]:
                cursor.execute(
                    f"SELECT scripthash FROM {table} WHERE coin_type = ? AND scripthash IS NOT NULL",
                    (int(coin_type),),
                )
                scripthashes.extend(row[0] for row in cursor.fetchall() if row[0])
            conn.close()
            return scripthashes
        except Exception:
            return []

    def ensureAddressesExist(self, coin_type: Coins, count: int = 20) -> int:
        if not self.isInitialized(coin_type):
            return 0

        cursor = self._swap_client.openDB()
        try:
            state = self._swap_client.queryOne(
                WalletState, cursor, {"coin_type": int(coin_type)}
            )
            if state is None:
                return 0

            current_external = state.last_external_index or 0
            current_internal = state.last_internal_index or 0
            added = 0
            bip44_coin = self.BIP84_COIN_TYPES.get(coin_type, 0)
            now = int(time.time())

            for internal in [False, True]:
                current = current_internal if internal else current_external
                chain_idx = 1 if internal else 0

                for i in range(current + 1, current + count + 1):
                    existing = self._swap_client.queryOne(
                        WalletAddress,
                        cursor,
                        {
                            "coin_type": int(coin_type),
                            "derivation_index": i,
                            "is_internal": internal,
                        },
                    )
                    if existing:
                        continue

                    address, scripthash, pubkey = self._deriveAddress(
                        coin_type, i, internal
                    )
                    self._swap_client.add(
                        WalletAddress(
                            coin_type=int(coin_type),
                            derivation_index=i,
                            is_internal=internal,
                            derivation_path=f"m/84'/{bip44_coin}'/0'/{chain_idx}/{i}",
                            address=address,
                            scripthash=scripthash,
                            pubkey=pubkey,
                            is_funded=False,
                            cached_balance=0,
                            created_at=now,
                        ),
                        cursor,
                    )
                    added += 1

            if added > 0:
                self._swap_client.commitDB()
            return added
        except Exception as e:
            self._swap_client.rollbackDB()
            raise e
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def syncAddressesToBackend(self, coin_type: Coins, backend) -> int:
        if not hasattr(backend, "importAddress"):
            return 0
        cursor = self._swap_client.openDB()
        try:
            synced = 0
            for record in self._swap_client.query(
                WalletAddress, cursor, {"coin_type": int(coin_type)}
            ):
                try:
                    backend.importAddress(
                        record.address, f"bsx_{record.derivation_index}"
                    )
                    synced += 1
                except Exception:
                    pass
            for record in self._swap_client.query(
                WalletWatchOnly, cursor, {"coin_type": int(coin_type)}
            ):
                try:
                    backend.importAddress(record.address, record.label or "watch_only")
                    synced += 1
                except Exception:
                    pass
            return synced
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def getAddressesForSubscription(self, coin_type: Coins) -> List[Tuple[str, str]]:
        cursor = self._swap_client.openDB()
        try:
            result = [
                (r.address, r.scripthash)
                for r in self._swap_client.query(
                    WalletAddress,
                    cursor,
                    {"coin_type": int(coin_type), "is_funded": True},
                )
            ]
            state = self._swap_client.queryOne(
                WalletState, cursor, {"coin_type": int(coin_type)}
            )
            if state:
                gap_limit = self.getGapLimit(coin_type)
                for internal in [False, True]:
                    last_idx = (
                        state.last_internal_index
                        if internal
                        else state.last_external_index
                    ) or 0
                    for i in range(
                        max(0, last_idx - gap_limit), last_idx + gap_limit + 1
                    ):
                        record = self._swap_client.queryOne(
                            WalletAddress,
                            cursor,
                            {
                                "coin_type": int(coin_type),
                                "derivation_index": i,
                                "is_internal": internal,
                            },
                        )
                        if record and not record.is_funded:
                            result.append((record.address, record.scripthash))
            result.extend(
                (r.address, r.scripthash)
                for r in self._swap_client.query(
                    WalletWatchOnly, cursor, {"coin_type": int(coin_type)}
                )
            )
            return result
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def scanForFundedAddresses(
        self, coin_type: Coins, backend, gap_limit: int = None
    ) -> int:
        if gap_limit is None:
            gap_limit = self.getGapLimit(coin_type)
        if not self.isInitialized(coin_type):
            return 0

        addresses_to_check = []
        cursor = self._swap_client.openDB()
        try:
            bip44_coin = self.BIP84_COIN_TYPES.get(coin_type, 0)
            now = int(time.time())

            for internal in [False, True]:
                chain_idx = 1 if internal else 0
                for index in range(gap_limit):
                    record = self._swap_client.queryOne(
                        WalletAddress,
                        cursor,
                        {
                            "coin_type": int(coin_type),
                            "derivation_index": index,
                            "is_internal": internal,
                        },
                    )
                    if record is None:
                        address, scripthash, pubkey = self._deriveAddress(
                            coin_type, index, internal
                        )
                        record = WalletAddress(
                            coin_type=int(coin_type),
                            derivation_index=index,
                            is_internal=internal,
                            derivation_path=f"m/84'/{bip44_coin}'/0'/{chain_idx}/{index}",
                            address=address,
                            scripthash=scripthash,
                            pubkey=pubkey,
                            is_funded=False,
                            created_at=now,
                        )
                        self._swap_client.add(record, cursor)

                    if not record.is_funded:
                        addresses_to_check.append((record.address, index, internal))

            self._swap_client.commitDB()
        finally:
            self._swap_client.closeDB(cursor, commit=False)

        if not addresses_to_check:
            return 0

        funded_addresses = []
        try:
            addr_list = [a[0] for a in addresses_to_check]
            balances = backend.getBalance(addr_list)
            for addr, balance in balances.items():
                if balance > 0:
                    for check_addr, index, internal in addresses_to_check:
                        if check_addr == addr:
                            funded_addresses.append((addr, index, internal, balance))
                            break
        except Exception:
            return 0

        if not funded_addresses:
            return 0

        cursor = self._swap_client.openDB()
        try:
            found = 0
            max_ext_index = max_int_index = None

            for addr, index, internal, balance in funded_addresses:
                record = self._swap_client.queryOne(
                    WalletAddress,
                    cursor,
                    {"coin_type": int(coin_type), "address": addr},
                )
                if record and not record.is_funded:
                    record.is_funded = True
                    record.cached_balance = balance
                    record.cached_balance_time = int(time.time())
                    self._swap_client.updateDB(
                        record, cursor, constraints=["coin_type", "address"]
                    )
                    found += 1

                    if internal:
                        max_int_index = max(max_int_index or 0, index)
                    else:
                        max_ext_index = max(max_ext_index or 0, index)

            if max_ext_index is not None or max_int_index is not None:
                state = self._swap_client.queryOne(
                    WalletState, cursor, {"coin_type": int(coin_type)}
                )
                if state:
                    if max_ext_index and (
                        state.last_external_index is None
                        or max_ext_index > state.last_external_index
                    ):
                        state.last_external_index = max_ext_index
                    if max_int_index and (
                        state.last_internal_index is None
                        or max_int_index > state.last_internal_index
                    ):
                        state.last_internal_index = max_int_index
                    state.updated_at = int(time.time())
                    self._swap_client.updateDB(state, cursor, constraints=["coin_type"])

            self._swap_client.commitDB()
            return found
        except Exception:
            self._swap_client.rollbackDB()
            return 0
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def updateFundedStatus(
        self, coin_type: Coins, address: str, is_funded: bool
    ) -> bool:
        cursor = self._swap_client.openDB()
        try:
            record = self._swap_client.queryOne(
                WalletAddress, cursor, {"coin_type": int(coin_type), "address": address}
            )
            if record and record.is_funded != is_funded:
                record.is_funded = is_funded
                self._swap_client.updateDB(
                    record, cursor, constraints=["coin_type", "address"]
                )
                self._swap_client.commitDB()
                return True
            return False
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def lockUTXO(
        self,
        coin_type: Coins,
        txid: str,
        vout: int,
        value: int = 0,
        address: str = None,
        bid_id: bytes = None,
        expires_in: int = 3600,
    ) -> bool:
        """Lock a UTXO to prevent double-spending in concurrent swaps."""
        cursor = self._swap_client.openDB()
        try:
            existing = self._swap_client.queryOne(
                WalletLockedUTXO,
                cursor,
                {"coin_type": int(coin_type), "txid": txid, "vout": vout},
            )
            if existing:
                existing.expires_at = int(time.time()) + expires_in if expires_in else 0
                if bid_id:
                    existing.bid_id = bid_id
                self._swap_client.updateDB(
                    existing, cursor, constraints=["coin_type", "txid", "vout"]
                )
                self._swap_client.commitDB()
                return True

            now = int(time.time())
            record = WalletLockedUTXO(
                coin_type=int(coin_type),
                txid=txid,
                vout=vout,
                value=value,
                address=address,
                bid_id=bid_id,
                locked_at=now,
                expires_at=now + expires_in if expires_in else 0,
            )
            self._swap_client.add(record, cursor)
            self._swap_client.commitDB()
            self._log.debug(
                f"Locked UTXO {txid[:16]}...:{vout} for {Coins(coin_type).name}"
            )
            return True
        except Exception as e:
            self._log.warning(f"Failed to lock UTXO {txid[:16]}:{vout}: {e}")
            self._swap_client.rollbackDB()
            return False
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def unlockUTXO(self, coin_type: Coins, txid: str, vout: int) -> bool:
        cursor = self._swap_client.openDB()
        try:
            existing = self._swap_client.queryOne(
                WalletLockedUTXO,
                cursor,
                {"coin_type": int(coin_type), "txid": txid, "vout": vout},
            )
            if existing:
                cursor.execute(
                    "DELETE FROM wallet_locked_utxos WHERE coin_type = ? AND txid = ? AND vout = ?",
                    (int(coin_type), txid, vout),
                )
                self._swap_client.commitDB()
                self._log.debug(
                    f"Unlocked UTXO {txid[:16]}...:{vout} for {Coins(coin_type).name}"
                )
                return True
            return False
        except Exception as e:
            self._log.warning(f"Failed to unlock UTXO {txid[:16]}:{vout}: {e}")
            self._swap_client.rollbackDB()
            return False
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def unlockUTXOsForBid(self, coin_type: Coins, bid_id: bytes) -> int:
        cursor = self._swap_client.openDB()
        try:
            locked = self._swap_client.query(
                WalletLockedUTXO,
                cursor,
                {"coin_type": int(coin_type), "bid_id": bid_id},
            )
            count = 0
            for utxo in locked:
                cursor.execute(
                    "DELETE FROM wallet_locked_utxos WHERE coin_type = ? AND txid = ? AND vout = ?",
                    (int(coin_type), utxo.txid, utxo.vout),
                )
                count += 1
            if count > 0:
                self._swap_client.commitDB()
                self._log.debug(
                    f"Unlocked {count} UTXOs for bid {bid_id.hex()[:16]}..."
                )
            return count
        except Exception as e:
            self._log.warning(f"Failed to unlock UTXOs for bid: {e}")
            self._swap_client.rollbackDB()
            return 0
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def isUTXOLocked(self, coin_type: Coins, txid: str, vout: int) -> bool:
        cursor = self._swap_client.openDB()
        try:
            existing = self._swap_client.queryOne(
                WalletLockedUTXO,
                cursor,
                {"coin_type": int(coin_type), "txid": txid, "vout": vout},
            )
            if not existing:
                return False
            if existing.expires_at and existing.expires_at < int(time.time()):
                cursor.execute(
                    "DELETE FROM wallet_locked_utxos WHERE coin_type = ? AND txid = ? AND vout = ?",
                    (int(coin_type), txid, vout),
                )
                self._swap_client.commitDB()
                return False
            return True
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def getLockedUTXOs(self, coin_type: Coins) -> List[dict]:
        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())
            locked = self._swap_client.query(
                WalletLockedUTXO,
                cursor,
                {"coin_type": int(coin_type)},
            )
            result = []
            expired = []
            for utxo in locked:
                if utxo.expires_at and utxo.expires_at < now:
                    expired.append(utxo)
                else:
                    result.append(
                        {
                            "txid": utxo.txid,
                            "vout": utxo.vout,
                            "value": utxo.value,
                            "address": utxo.address,
                            "bid_id": utxo.bid_id,
                            "locked_at": utxo.locked_at,
                            "expires_at": utxo.expires_at,
                        }
                    )
            for utxo in expired:
                cursor.execute(
                    "DELETE FROM wallet_locked_utxos WHERE coin_type = ? AND txid = ? AND vout = ?",
                    (int(coin_type), utxo.txid, utxo.vout),
                )
            if expired:
                self._swap_client.commitDB()
                self._log.debug(
                    f"Cleaned up {len(expired)} expired UTXO locks for {Coins(coin_type).name}"
                )
            return result
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def extendLocksForBid(
        self, coin_type: Coins, bid_id: bytes, extend_seconds: int = 3600
    ) -> int:
        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())
            locked = self._swap_client.query(
                WalletLockedUTXO,
                cursor,
                {"coin_type": int(coin_type), "bid_id": bid_id},
            )
            count = 0
            for utxo in locked:
                new_expiry = now + extend_seconds
                if utxo.expires_at < new_expiry:
                    utxo.expires_at = new_expiry
                    self._swap_client.updateDB(
                        utxo, cursor, constraints=["coin_type", "txid", "vout"]
                    )
                    count += 1
            if count > 0:
                self._swap_client.commitDB()
                self._log.debug(
                    f"Extended {count} UTXO locks for {Coins(coin_type).name} bid"
                )
            return count
        except Exception as e:
            self._log.warning(f"Failed to extend UTXO locks: {e}")
            self._swap_client.rollbackDB()
            return 0
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def cleanupExpiredLocks(self, coin_type: Coins = None) -> int:
        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())
            if coin_type:
                locked = self._swap_client.query(
                    WalletLockedUTXO,
                    cursor,
                    {"coin_type": int(coin_type)},
                )
            else:
                locked = self._swap_client.query(WalletLockedUTXO, cursor, {})

            count = 0
            for utxo in locked:
                if utxo.expires_at and utxo.expires_at < now:
                    cursor.execute(
                        "DELETE FROM wallet_locked_utxos WHERE coin_type = ? AND txid = ? AND vout = ?",
                        (utxo.coin_type, utxo.txid, utxo.vout),
                    )
                    count += 1
            if count > 0:
                self._swap_client.commitDB()
                self._log.debug(f"Cleaned up {count} expired UTXO locks")
            return count
        except Exception as e:
            self._log.warning(f"Failed to cleanup expired locks: {e}")
            self._swap_client.rollbackDB()
            return 0
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def getCachedTxConfirmations(
        self, coin_type: Coins, txid: str
    ) -> Optional[Tuple[int, int]]:

        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())
            results = self._swap_client.query(
                WalletTxCache,
                cursor,
                {"coin_type": int(coin_type), "txid": txid},
            )
            for cached in results:
                if cached.expires_at and cached.expires_at < now:
                    cursor.execute(
                        "DELETE FROM wallet_tx_cache WHERE coin_type = ? AND txid = ?",
                        (int(coin_type), txid),
                    )
                    self._swap_client.commitDB()
                    return None
                return (cached.confirmations, cached.block_height)
            return None
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def cacheTxConfirmations(
        self,
        coin_type: Coins,
        txid: str,
        confirmations: int,
        block_height: int = 0,
        ttl_seconds: int = 60,
    ) -> None:

        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())

            if confirmations > 0:
                ttl_seconds = max(ttl_seconds, 300)

            existing = self._swap_client.query(
                WalletTxCache,
                cursor,
                {"coin_type": int(coin_type), "txid": txid},
            )
            for cached in existing:
                cached.confirmations = confirmations
                cached.block_height = block_height
                cached.cached_at = now
                cached.expires_at = now + ttl_seconds
                self._swap_client.updateDB(cached, cursor)
                self._swap_client.commitDB()
                return

            new_cache = WalletTxCache()
            new_cache.coin_type = int(coin_type)
            new_cache.txid = txid
            new_cache.confirmations = confirmations
            new_cache.block_height = block_height
            new_cache.cached_at = now
            new_cache.expires_at = now + ttl_seconds
            self._swap_client.add(new_cache, cursor)
            self._swap_client.commitDB()
        except Exception as e:
            self._log.debug(f"Failed to cache tx confirmations: {e}")
            self._swap_client.rollbackDB()
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def cleanupExpiredTxCache(self) -> int:
        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())
            cached = self._swap_client.query(WalletTxCache, cursor, {})
            count = 0
            for entry in cached:
                if entry.expires_at and entry.expires_at < now:
                    cursor.execute(
                        "DELETE FROM wallet_tx_cache WHERE coin_type = ? AND txid = ?",
                        (entry.coin_type, entry.txid),
                    )
                    count += 1
            if count > 0:
                self._swap_client.commitDB()
            return count
        except Exception as e:
            self._log.debug(f"Failed to cleanup tx cache: {e}")
            self._swap_client.rollbackDB()
            return 0
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def addPendingTx(
        self,
        coin_type: Coins,
        txid: str,
        tx_type: str = "outgoing",
        amount: int = 0,
        fee: int = 0,
        addresses: List[str] = None,
        bid_id: bytes = None,
    ) -> bool:
        cursor = self._swap_client.openDB()
        try:
            existing = self._swap_client.query(
                WalletPendingTx,
                cursor,
                {"coin_type": int(coin_type), "txid": txid},
            )
            for _ in existing:
                return False

            import json

            pending = WalletPendingTx()
            pending.coin_type = int(coin_type)
            pending.txid = txid
            pending.tx_type = tx_type
            pending.amount = amount
            pending.fee = fee
            pending.addresses = json.dumps(addresses or [])
            pending.bid_id = bid_id
            pending.first_seen = int(time.time())
            pending.confirmed_at = 0

            self._swap_client.add(pending, cursor)
            self._swap_client.commitDB()
            return True
        except Exception as e:
            self._log.debug(f"Failed to add pending tx: {e}")
            self._swap_client.rollbackDB()
            return False
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def markTxConfirmed(self, coin_type: Coins, txid: str) -> bool:
        cursor = self._swap_client.openDB()
        try:
            results = self._swap_client.query(
                WalletPendingTx,
                cursor,
                {"coin_type": int(coin_type), "txid": txid},
            )
            for pending in results:
                if pending.confirmed_at == 0:
                    pending.confirmed_at = int(time.time())
                    self._swap_client.updateDB(pending, cursor)
                    self._swap_client.commitDB()
                    return True
            return False
        except Exception as e:
            self._log.debug(f"Failed to mark tx confirmed: {e}")
            self._swap_client.rollbackDB()
            return False
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def getPendingTxs(
        self, coin_type: Coins, include_confirmed: bool = False
    ) -> List[dict]:
        cursor = self._swap_client.openDB()
        try:
            import json

            results = self._swap_client.query(
                WalletPendingTx,
                cursor,
                {"coin_type": int(coin_type)},
            )
            pending_list = []
            for pending in results:
                if not include_confirmed and pending.confirmed_at > 0:
                    continue
                pending_list.append(
                    {
                        "txid": pending.txid,
                        "tx_type": pending.tx_type,
                        "amount": pending.amount,
                        "fee": pending.fee,
                        "addresses": json.loads(pending.addresses or "[]"),
                        "bid_id": pending.bid_id,
                        "first_seen": pending.first_seen,
                        "confirmed_at": pending.confirmed_at,
                    }
                )
            return pending_list
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def cleanupConfirmedTxs(self, max_age_seconds: int = 86400) -> int:
        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())
            cutoff = now - max_age_seconds
            results = self._swap_client.query(WalletPendingTx, cursor, {})
            count = 0
            for pending in results:
                if pending.confirmed_at > 0 and pending.confirmed_at < cutoff:
                    cursor.execute(
                        "DELETE FROM wallet_pending_txs WHERE coin_type = ? AND txid = ?",
                        (pending.coin_type, pending.txid),
                    )
                    count += 1
            if count > 0:
                self._swap_client.commitDB()
            return count
        except Exception as e:
            self._log.debug(f"Failed to cleanup confirmed txs: {e}")
            self._swap_client.rollbackDB()
            return 0
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def cleanupOldWatchOnlyAddresses(
        self, coin_type: Coins = None, max_age_days: int = 30
    ) -> int:
        cursor = self._swap_client.openDB()
        try:
            now = int(time.time())
            cutoff = now - (max_age_days * 86400)

            if coin_type:
                results = self._swap_client.query(
                    WalletWatchOnly,
                    cursor,
                    {"coin_type": int(coin_type)},
                )
            else:
                results = self._swap_client.query(WalletWatchOnly, cursor, {})

            count = 0
            for watch in results:
                # Only cleanup swap-related addresses
                if watch.label not in ("bid", "swap", "offer"):
                    continue
                # Only cleanup if old enough
                if watch.created_at and watch.created_at < cutoff:
                    # Only cleanup if not funded (no balance)
                    if not watch.is_funded or watch.cached_balance == 0:
                        cursor.execute(
                            "DELETE FROM wallet_watch_only WHERE coin_type = ? AND address = ?",
                            (watch.coin_type, watch.address),
                        )
                        count += 1

            if count > 0:
                self._swap_client.commitDB()
                self._log.debug(
                    f"Cleaned up {count} old watch-only addresses"
                    + (f" for {Coins(coin_type).name}" if coin_type else "")
                )
            return count
        except Exception as e:
            self._log.debug(f"Failed to cleanup watch-only addresses: {e}")
            self._swap_client.rollbackDB()
            return 0
        finally:
            self._swap_client.closeDB(cursor, commit=False)

    def getWatchOnlyAddressCount(self, coin_type: Coins = None) -> int:
        cursor = self._swap_client.openDB()
        try:
            if coin_type:
                results = self._swap_client.query(
                    WalletWatchOnly,
                    cursor,
                    {"coin_type": int(coin_type)},
                )
            else:
                results = self._swap_client.query(WalletWatchOnly, cursor, {})
            return sum(1 for _ in results)
        finally:
            self._swap_client.closeDB(cursor, commit=False)
