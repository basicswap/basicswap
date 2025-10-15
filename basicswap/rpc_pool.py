# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import queue
import threading
import time
from basicswap.rpc import Jsonrpc


class RPCConnectionPool:
    def __init__(
        self, url, max_connections=5, timeout=10, logger=None, max_idle_time=300
    ):
        self.url = url
        self.max_connections = max_connections
        self.timeout = timeout
        self.logger = logger
        self.max_idle_time = max_idle_time
        self._pool = queue.Queue(maxsize=max_connections)
        self._lock = threading.Lock()
        self._created_connections = 0
        self._connection_timestamps = {}

    def get_connection(self):
        try:
            conn_data = self._pool.get(block=False)
            conn, timestamp = (
                conn_data if isinstance(conn_data, tuple) else (conn_data, time.time())
            )

            if time.time() - timestamp > self.max_idle_time:
                if self.logger:
                    self.logger.debug(
                        f"RPC pool: discarding stale connection (idle for {time.time() - timestamp:.1f}s)"
                    )
                conn.close()
                with self._lock:
                    if self._created_connections > 0:
                        self._created_connections -= 1
                return self._create_new_connection()

            return conn
        except queue.Empty:
            return self._create_new_connection()

    def _create_new_connection(self):
        with self._lock:
            if self._created_connections < self.max_connections:
                self._created_connections += 1
                return Jsonrpc(self.url)

        try:
            conn_data = self._pool.get(block=True, timeout=self.timeout)
            conn, timestamp = (
                conn_data if isinstance(conn_data, tuple) else (conn_data, time.time())
            )

            if time.time() - timestamp > self.max_idle_time:
                if self.logger:
                    self.logger.debug(
                        f"RPC pool: discarding stale connection (idle for {time.time() - timestamp:.1f}s)"
                    )
                conn.close()
                with self._lock:
                    if self._created_connections > 0:
                        self._created_connections -= 1
                return Jsonrpc(self.url)

            return conn
        except queue.Empty:
            if self.logger:
                self.logger.warning(
                    f"RPC pool: timeout waiting for connection, creating temporary connection for {self.url}"
                )
            return Jsonrpc(self.url)

    def return_connection(self, conn):
        try:
            self._pool.put((conn, time.time()), block=False)
        except queue.Full:
            conn.close()
            with self._lock:
                if self._created_connections > 0:
                    self._created_connections -= 1

    def discard_connection(self, conn):
        conn.close()
        with self._lock:
            if self._created_connections > 0:
                self._created_connections -= 1

    def close_all(self):
        while not self._pool.empty():
            try:
                conn_data = self._pool.get(block=False)
                conn = conn_data[0] if isinstance(conn_data, tuple) else conn_data
                conn.close()
            except queue.Empty:
                break
        with self._lock:
            self._created_connections = 0
            self._connection_timestamps.clear()


_rpc_pools = {}
_pool_lock = threading.Lock()
_pool_logger = None


def set_pool_logger(logger):
    global _pool_logger
    _pool_logger = logger


def get_rpc_pool(url, max_connections=5):
    with _pool_lock:
        if url not in _rpc_pools:
            _rpc_pools[url] = RPCConnectionPool(
                url, max_connections, logger=_pool_logger
            )
        return _rpc_pools[url]


def close_all_pools():
    with _pool_lock:
        for pool in _rpc_pools.values():
            pool.close_all()
        _rpc_pools.clear()
