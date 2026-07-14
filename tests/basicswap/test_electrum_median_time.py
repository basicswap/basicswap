# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import struct
import unittest

from basicswap.interface.btc.btc import BTCInterface
from basicswap.basicswap_util import TxLockTypes


def make_header(timestamp: int) -> bytes:
    header = bytearray(80)
    header[68:72] = struct.pack("<I", timestamp)
    return bytes(header)


class StubLog:
    def id(self, v):
        return str(v)

    def error(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


class StubServer:
    def __init__(self, headers=None, raise_on_call=False):
        self._headers = headers or []
        self._raise_on_call = raise_on_call
        self.call_count = 0

    def call(self, method, params):
        self.call_count += 1
        if self._raise_on_call:
            raise RuntimeError("server error")
        if method == "blockchain.block.headers":
            joined = b"".join(self._headers)
            return {"hex": joined.hex(), "count": len(self._headers)}
        raise RuntimeError(f"unexpected call {method}")


class StubBackend:
    def __init__(self, server, height=100, raise_on_height=False):
        self._server = server
        self._height = height
        self._raise_on_height = raise_on_height

    def getBlockHeight(self):
        if self._raise_on_height:
            raise RuntimeError("no connection")
        return self._height


def make_interface(backend):
    ci = BTCInterface.__new__(BTCInterface)
    ci._log = StubLog()
    ci._connection_type = "electrum"
    ci._backend = backend
    ci._median_time_cache = None
    ci._median_time_cache_height = None
    return ci


class TestElectrumMedianTime(unittest.TestCase):
    def test_successful_fetch(self):
        timestamps = list(range(1000, 1011))
        headers = [make_header(t) for t in timestamps]
        backend = StubBackend(StubServer(headers), height=100)
        ci = make_interface(backend)
        self.assertEqual(ci.getChainMedianTime(), 1005)
        self.assertEqual(ci._median_time_cache, 1005)
        self.assertEqual(ci._median_time_cache_height, 100)

    def test_server_error_returns_none_without_cache(self):
        backend = StubBackend(StubServer(raise_on_call=True), height=100)
        ci = make_interface(backend)
        self.assertIsNone(ci.getChainMedianTime())

    def test_server_error_returns_cached_value(self):
        backend = StubBackend(StubServer(raise_on_call=True), height=100)
        ci = make_interface(backend)
        ci._median_time_cache = 1005
        ci._median_time_cache_height = 99
        self.assertEqual(ci.getChainMedianTime(), 1005)

    def test_height_error_returns_cached_value(self):
        backend = StubBackend(StubServer(), height=100, raise_on_height=True)
        ci = make_interface(backend)
        ci._median_time_cache = 1005
        self.assertEqual(ci.getChainMedianTime(), 1005)

    def test_no_backend_returns_none(self):
        ci = make_interface(None)
        # useBackend() is False with no backend, rpc path raises -> fail soft
        ci.rpc = lambda *args: (_ for _ in ()).throw(RuntimeError("no rpc"))
        self.assertIsNone(ci.getChainMedianTime())

    def test_cache_reused_when_height_unchanged(self):
        timestamps = list(range(1000, 1011))
        headers = [make_header(t) for t in timestamps]
        server = StubServer(headers)
        backend = StubBackend(server, height=100)
        ci = make_interface(backend)
        self.assertEqual(ci.getChainMedianTime(), 1005)
        self.assertEqual(ci.getChainMedianTime(), 1005)
        self.assertEqual(server.call_count, 1)

    def test_empty_headers_fails_soft(self):
        backend = StubBackend(StubServer(headers=[]), height=100)
        ci = make_interface(backend)
        self.assertIsNone(ci.getChainMedianTime())

    def test_csv_lock_not_mature_when_mtp_unknown(self):
        backend = StubBackend(StubServer(raise_on_call=True), height=100)
        ci = make_interface(backend)
        encoded_sequence = ci.getExpectedSequence(TxLockTypes.SEQUENCE_LOCK_TIME, 3600)
        self.assertFalse(
            ci.isCsvLockMature(
                TxLockTypes.SEQUENCE_LOCK_TIME,
                encoded_sequence,
                parent_block_height=50,
                parent_block_time=1000,
            )
        )

    def test_abs_lock_not_mature_when_mtp_unknown(self):
        backend = StubBackend(StubServer(raise_on_call=True), height=100)
        ci = make_interface(backend)
        self.assertFalse(ci.isAbsLockTimeMature(500000001))


if __name__ == "__main__":
    unittest.main()
