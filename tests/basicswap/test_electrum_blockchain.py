# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import tempfile
import threading
import unittest
from pathlib import Path

from basicswap.interface.btc.btc import BTCInterface
from basicswap.interface.electrum_blockchain import (
    CHUNK_SIZE,
    Blockchain,
    BlockchainManager,
    ChainConflict,
    HeaderNet,
    HeaderSync,
    InnerNodeOfSpvProofIsValidTx,
    InvalidHeader,
    LeftSiblingDuplicate,
    MerkleRootMismatch,
    MerkleVerificationFailure,
    hash_decode,
    hash_encode,
    hash_header,
    hash_raw_header,
    is_valid_tx,
    serialize_header,
    sha256d,
    verify_tx_is_in_block,
)
from basicswap.interface.electrumx import ElectrumServer

EASY_TARGET = (1 << 255) - 1


class StubLog:
    def id(self, v, **kwargs):
        return str(v)

    def error(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def info(self, *args, **kwargs):
        pass

    def debug(self, *args, **kwargs):
        pass


def mine(prev_hash: str, height: int, timestamp: int, bits: int, tag: int = 0) -> dict:
    target = Blockchain.bits_to_target(bits)
    for nonce in range(1 << 20):
        header = {
            "version": 1,
            "prev_block_hash": prev_hash,
            "merkle_root": f"{tag:064x}",
            "timestamp": timestamp,
            "bits": bits,
            "nonce": nonce,
            "block_height": height,
        }
        if int(hash_header(header), 16) <= target:
            return header
    raise ValueError("No nonce found")


def mine_chain(
    prev: dict | None, start: int, count: int, bits: int, spacing=600, tag=0
):
    headers = []
    prev_hash = hash_header(prev) if prev else "00" * 32
    timestamp = prev["timestamp"] if prev else 1000000
    for height in range(start, start + count):
        timestamp += spacing
        header = mine(prev_hash, height, timestamp, bits, tag)
        headers.append(header)
        prev_hash = hash_header(header)
    return headers


def raw(headers: list) -> bytes:
    return b"".join(serialize_header(h) for h in headers)


EASY_BITS = Blockchain.target_to_bits(EASY_TARGET)


def make_net(genesis: str, checkpoints: list, testnet: bool = False, **kwargs):
    return HeaderNet(
        genesis=genesis,
        checkpoints=checkpoints,
        testnet=testnet,
        max_target=EASY_TARGET,
        first_target=EASY_TARGET,
        target_timespan=CHUNK_SIZE * 600,
        **kwargs,
    )


def make_manager(net):
    headers_dir = tempfile.TemporaryDirectory()
    bc_mgr = BlockchainManager(
        headers_dir=Path(headers_dir.name), net=net, log=StubLog()
    )
    bc_mgr._headers_dir_handle = headers_dir
    return bc_mgr


class ChainServer:
    def __init__(self, headers: list):
        self.headers = headers
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "blockchain.block.header":
            return serialize_header(self.headers[params[0]]).hex()
        if method == "blockchain.block.headers":
            selected = self.headers[params[0] : params[0] + params[1]]
            return {"hex": raw(selected).hex(), "count": len(selected), "max": 2016}
        raise RuntimeError(f"unexpected call {method}")


class Chunk0:
    headers = mine_chain(None, 0, CHUNK_SIZE, EASY_BITS)
    genesis = hash_header(headers[0])
    checkpoint = [hash_header(headers[-1]), EASY_TARGET]


class TestCompactBits(unittest.TestCase):
    def test_round_trips(self):
        for bits in (0x1D00FFFF, 0x17020093, 0x1930F49E, EASY_BITS):
            target = Blockchain.bits_to_target(bits)
            self.assertEqual(Blockchain.target_to_bits(target), bits)

    def test_negative_and_overflow_refused(self):
        with self.assertRaises(InvalidHeader):
            Blockchain.bits_to_target(0x1D80FFFF)
        with self.assertRaises(InvalidHeader):
            Blockchain.bits_to_target(0x23FFFFFF)


class TestVerifyHeader(unittest.TestCase):
    def test_mainnet_checks_link_bits_and_work(self):
        chain = make_manager(make_net(Chunk0.genesis, [])).get_best_chain()
        h1 = Chunk0.headers[1]
        prev = hash_header(Chunk0.headers[0])
        chain.verify_header(h1, prev, EASY_TARGET)
        with self.assertRaises(InvalidHeader):
            chain.verify_header(h1, "11" * 32, EASY_TARGET)
        with self.assertRaises(InvalidHeader):
            chain.verify_header(h1, prev, EASY_TARGET >> 1)
        weak = dict(h1)
        while int(hash_header(weak), 16) <= EASY_TARGET:
            weak["nonce"] += 1
        with self.assertRaises(InvalidHeader):
            chain.verify_header(weak, prev, EASY_TARGET)

    def test_testnet_checks_link_only(self):
        chain = make_manager(
            make_net(Chunk0.genesis, [], testnet=True)
        ).get_best_chain()
        h1 = dict(Chunk0.headers[1], bits=0x1D00FFFF)
        chain.verify_header(h1, hash_header(Chunk0.headers[0]), 0)


class TestCheckpoints(unittest.TestCase):
    def test_chain_starts_at_the_last_checkpoint(self):
        bc_mgr = make_manager(make_net(Chunk0.genesis, [Chunk0.checkpoint]))
        chain = bc_mgr.get_best_chain()
        self.assertEqual(chain.height(), CHUNK_SIZE - 1)
        self.assertEqual(chain.get_hash(CHUNK_SIZE - 1), Chunk0.checkpoint[0])
        self.assertIsNone(chain.read_header(5))
        above = mine_chain(Chunk0.headers[-1], CHUNK_SIZE, 1, EASY_BITS)
        self.assertTrue(chain.can_connect(above[0]))
        stranger = mine(hash_header(Chunk0.headers[-2]), CHUNK_SIZE, 1, EASY_BITS)
        self.assertFalse(chain.can_connect(stranger))
        harder = Blockchain.target_to_bits(EASY_TARGET >> 2)
        wrong_bits = mine_chain(Chunk0.headers[-1], CHUNK_SIZE, 1, harder)
        self.assertFalse(chain.can_connect(wrong_bits[0]))

    def test_chunk_below_checkpoint_fetched_and_verified(self):
        bc_mgr = make_manager(make_net(Chunk0.genesis, [Chunk0.checkpoint]))
        sync = HeaderSync(bc_mgr, ChainServer(Chunk0.headers), StubLog())
        sync.tip = CHUNK_SIZE - 1
        sync.request_chunk_below_max_checkpoint(height=5)
        self.assertEqual(
            hash_header(bc_mgr.get_best_chain().read_header(5)),
            hash_header(Chunk0.headers[5]),
        )

    def test_tampered_chunk_refused(self):
        bc_mgr = make_manager(make_net(Chunk0.genesis, [Chunk0.checkpoint]))
        tampered = list(Chunk0.headers)
        tampered[7] = mine(
            hash_header(tampered[6]), 7, tampered[7]["timestamp"], EASY_BITS, tag=9
        )
        sync = HeaderSync(bc_mgr, ChainServer(tampered), StubLog())
        sync.tip = CHUNK_SIZE - 1
        with self.assertRaises(Exception):
            sync.request_chunk_below_max_checkpoint(height=7)
        self.assertIsNone(bc_mgr.get_best_chain().read_header(7))


class TestHeaderSync(unittest.TestCase):
    def setUp(self):
        self.bc_mgr = make_manager(make_net(Chunk0.genesis, [Chunk0.checkpoint]))
        self.main = Chunk0.headers + mine_chain(
            Chunk0.headers[-1], CHUNK_SIZE, 6, EASY_BITS
        )

    def sync_to(self, server_headers: list):
        sync = HeaderSync(self.bc_mgr, ChainServer(server_headers), StubLog())
        tip = len(server_headers) - 1
        sync.process_header_at_tip(tip, server_headers[tip])
        return sync

    def test_syncs_to_the_served_tip(self):
        self.sync_to(self.main)
        best = self.bc_mgr.get_best_chain()
        self.assertEqual(best.height(), CHUNK_SIZE + 5)
        self.assertEqual(hash_header(best.header_at_tip()), hash_header(self.main[-1]))

    def test_heavier_fork_becomes_best(self):
        self.sync_to(self.main)
        fork = self.main[: CHUNK_SIZE + 3] + mine_chain(
            self.main[CHUNK_SIZE + 2], CHUNK_SIZE + 3, 5, EASY_BITS, tag=7
        )
        self.sync_to(fork)
        best = self.bc_mgr.get_best_chain()
        self.assertEqual(best.height(), CHUNK_SIZE + 7)
        self.assertEqual(
            best.get_hash(CHUNK_SIZE + 3), hash_header(fork[CHUNK_SIZE + 3])
        )
        self.assertEqual(len(self.bc_mgr.blockchains), 2)

    def test_chain_conflicting_with_checkpoint_refused(self):
        other = mine_chain(None, 0, CHUNK_SIZE + 3, EASY_BITS, tag=5)
        with self.assertRaises(ChainConflict):
            self.sync_to(other)


class TestMerkle(unittest.TestCase):
    leaf = "aa" * 32
    sibling = "bb" * 32

    def header_for(self, root: str) -> dict:
        return {"merkle_root": root}

    def test_valid_branch(self):
        root = hash_encode(sha256d(hash_decode(self.leaf) + hash_decode(self.sibling)))
        verify_tx_is_in_block(
            self.leaf, [self.sibling], 0, self.header_for(root), 1, lambda b: False
        )
        with self.assertRaises(MerkleRootMismatch):
            verify_tx_is_in_block(
                self.leaf,
                [self.sibling],
                0,
                self.header_for("00" * 32),
                1,
                lambda b: False,
            )

    def test_inner_node_that_is_a_tx_refused(self):
        root = hash_encode(sha256d(hash_decode(self.leaf) + hash_decode(self.sibling)))
        with self.assertRaises(InnerNodeOfSpvProofIsValidTx):
            verify_tx_is_in_block(
                self.leaf, [self.sibling], 0, self.header_for(root), 1, lambda b: True
            )

    def test_left_sibling_duplicate_refused(self):
        with self.assertRaises(LeftSiblingDuplicate):
            verify_tx_is_in_block(
                self.leaf,
                [self.leaf],
                1,
                self.header_for("00" * 32),
                1,
                lambda b: False,
            )

    def test_branch_shape_checked(self):
        with self.assertRaises(MerkleVerificationFailure):
            verify_tx_is_in_block(
                self.leaf,
                [self.sibling] * 31,
                0,
                self.header_for("00" * 32),
                1,
                lambda b: False,
            )
        with self.assertRaises(MerkleVerificationFailure):
            verify_tx_is_in_block(
                self.leaf,
                [self.sibling],
                2,
                self.header_for("00" * 32),
                1,
                lambda b: False,
            )


class TestInnerNodeTxCheck(unittest.TestCase):
    def test_64_byte_tx_flagged(self):
        tx = (
            (2).to_bytes(4, "little")
            + bytes([1])
            + bytes(range(32))
            + (0).to_bytes(4, "little")
            + bytes([0])
            + (0xFFFFFFFF).to_bytes(4, "little")
            + bytes([1])
            + (1000).to_bytes(8, "little")
            + bytes([4])
            + bytes([0x51, 0x51, 0x51, 0x51])
            + (0).to_bytes(4, "little")
        )
        self.assertEqual(len(tx), 64)
        self.assertTrue(is_valid_tx(tx))
        self.assertTrue(BTCInterface.__new__(BTCInterface)._isValidTxBytes(tx))
        self.assertFalse(is_valid_tx(tx[:-1]))
        self.assertFalse(is_valid_tx(tx + bytes(1)))

    def test_inner_nodes_that_are_not_txs(self):
        ci = BTCInterface.__new__(BTCInterface)
        for node in (bytes(64), b"\xff" * 64, b"\x01" * 64):
            self.assertFalse(ci._isValidTxBytes(node))


class TestLitecoinRetarget(unittest.TestCase):
    def test_target_measured_from_the_checkpoint_timestamp(self):
        last_ts = Chunk0.headers[-1]["timestamp"]
        checkpoint = Chunk0.checkpoint + [last_ts]
        net = make_net(Chunk0.genesis, [checkpoint], timestamp_before_chunk=True)
        bc_mgr = make_manager(net)
        chunk1 = mine_chain(
            Chunk0.headers[-1], CHUNK_SIZE, CHUNK_SIZE, EASY_BITS, spacing=300
        )
        chain = bc_mgr.get_best_chain()
        for header in chunk1:
            chain.save_header(header)
        expected = min(
            EASY_TARGET, EASY_TARGET * (CHUNK_SIZE * 300) // (CHUNK_SIZE * 600)
        )
        expected = Blockchain.bits_to_target(Blockchain.target_to_bits(expected))
        self.assertEqual(chain.get_target(1), expected)
        self.assertEqual(chain.get_timestamp(CHUNK_SIZE - 1), last_ts)
        self.assertEqual(len(chain.get_checkpoints()[0]), 3)


class TimingOutServer(ChainServer):
    def call(self, method, params):
        raise RuntimeError("Request timed out")


class FollowedServers:
    def __init__(self, servers: dict, primary: str):
        self.servers = servers
        self.primary = primary
        self.dropped = []
        self.switched = []
        self.failovers = []

    def get_server_tips(self):
        return {
            k: len(v.headers) - 1 for k, v in self.servers.items() if k != self.primary
        }

    def primary_key(self):
        return self.primary

    def server_caller(self, key):
        return self.servers[key]

    def get_merkle(self, txid, height):
        return {"merkle": ["cc" * 32], "pos": 0, "block_height": height}

    def failover(self, reason):
        self.failovers.append(reason)

    def drop_server(self, key, reason):
        self.dropped.append(key)
        if key != self.primary:
            self.servers.pop(key)

    def switch_primary(self, key):
        self.switched.append(key)
        self.primary = key
        return True


class StubBackend:
    def __init__(self, server):
        self._server = server

    def getBlockHeight(self):
        return len(self._server.servers[self._server.primary].headers) - 1


def make_interface(bc_mgr):
    ci = BTCInterface.__new__(BTCInterface)
    ci._log = StubLog()
    ci._merkle_verified = {}
    ci._merkle_block_hashes = {}
    ci._header_bc_mgr = bc_mgr
    ci._header_syncs = {}
    ci._header_sync_lock = threading.Lock()
    return ci


class TestFollowedServers(unittest.TestCase):
    def setUp(self):
        self.bc_mgr = make_manager(make_net(Chunk0.genesis, [Chunk0.checkpoint]))
        self.main = Chunk0.headers + mine_chain(
            Chunk0.headers[-1], CHUNK_SIZE, 6, EASY_BITS
        )
        self.ci = make_interface(self.bc_mgr)

    def follow(self, primary_headers: list, other_headers: list):
        servers = FollowedServers(
            {"a": ChainServer(primary_headers), "b": ChainServer(other_headers)}, "a"
        )
        self.ci._headerSyncElectrum(StubBackend(servers))
        return servers

    def test_conflicting_server_dropped(self):
        other = mine_chain(None, 0, CHUNK_SIZE + 3, EASY_BITS, tag=5)
        servers = self.follow(self.main, other)
        self.assertEqual(servers.dropped, ["b"])
        self.assertNotIn("b", self.ci._header_syncs)
        self.assertEqual(self.bc_mgr.get_best_chain().height(), CHUNK_SIZE + 5)
        self.assertEqual(servers.switched, [])

    def test_failing_followed_server_dropped(self):
        servers = FollowedServers(
            {"a": ChainServer(self.main), "b": TimingOutServer(self.main)}, "a"
        )
        self.ci._headerSyncElectrum(StubBackend(servers))
        self.assertEqual(servers.dropped, ["b"])
        self.assertNotIn("b", self.ci._header_syncs)
        self.assertEqual(self.bc_mgr.get_best_chain().height(), CHUNK_SIZE + 5)

    def test_failing_primary_kept(self):
        servers = FollowedServers(
            {"a": TimingOutServer(self.main), "b": ChainServer(self.main)}, "a"
        )
        self.ci._headerSyncElectrum(StubBackend(servers))
        self.assertEqual(servers.dropped, [])
        self.assertEqual(self.bc_mgr.get_best_chain().height(), CHUNK_SIZE + 5)

    def test_lagging_primary_switched(self):
        servers = self.follow(self.main[: CHUNK_SIZE + 2], self.main)
        self.assertEqual(self.bc_mgr.get_best_chain().height(), CHUNK_SIZE + 5)
        self.assertEqual(servers.switched, ["b"])

    def test_primary_one_behind_kept(self):
        servers = self.follow(self.main[:-1], self.main)
        self.assertEqual(self.bc_mgr.get_best_chain().height(), CHUNK_SIZE + 5)
        self.assertEqual(servers.switched, [])

    def test_primary_on_lighter_fork_switched(self):
        fork = self.main[: CHUNK_SIZE + 3] + mine_chain(
            self.main[CHUNK_SIZE + 2], CHUNK_SIZE + 3, 2, EASY_BITS, tag=7
        )
        servers = self.follow(fork, self.main)
        best = self.bc_mgr.get_best_chain()
        self.assertEqual(best.height(), CHUNK_SIZE + 5)
        self.assertEqual(
            best.get_hash(CHUNK_SIZE + 3), hash_header(self.main[CHUNK_SIZE + 3])
        )
        self.assertEqual(servers.switched, ["b"])

    def test_bad_proof_fails_over(self):
        bc_mgr = make_manager(make_net(Chunk0.genesis, [], testnet=True))
        chain = bc_mgr.get_best_chain()
        for header in Chunk0.headers[:3]:
            chain.save_header(header)
        ci = make_interface(bc_mgr)
        servers = FollowedServers({"a": ChainServer(Chunk0.headers[:3])}, "a")
        self.assertIs(
            ci._verifyTxMerkleElectrum(StubBackend(servers), "aa" * 32, 2), False
        )
        self.assertEqual(len(servers.failovers), 1)


class FakeConnection:
    def __init__(self):
        self.connected = True
        self.header_callback = None

    def is_connected(self):
        return self.connected

    def disconnect(self):
        self.connected = False

    def register_header_callback(self, callback):
        self.header_callback = callback


class TestServerFailover(unittest.TestCase):
    def make_server(self):
        es = ElectrumServer(
            "bitcoin",
            clearnet_servers=["a.example:50002", "b.example:50002"],
            log=StubLog(),
            max_servers=2,
        )
        es._current_server_host = "a.example"
        es._current_server_port = 50002
        es._current_server_idx = 0
        es._subscribed_height = 900
        return es

    def test_server_failover_blacklists_and_reconnects(self):
        es = self.make_server()
        reconnects = []
        es._reconnect = lambda prefer_current: reconnects.append(prefer_current) or True
        self.assertTrue(es.failover("bad proof"))
        self.assertEqual(reconnects, [False])
        self.assertEqual(es._subscribed_height, 0)
        self.assertEqual([s["host"] for s in es.get_sorted_servers()], ["b.example"])

    def test_failover_prefers_a_followed_server(self):
        es = self.make_server()
        conn_a, conn_b = FakeConnection(), FakeConnection()
        es._connection = conn_a
        es._extra_connections = {"b.example:50002": conn_b}
        es._server_tips = {"a.example:50002": 900, "b.example:50002": 905}
        es._reconnect = lambda prefer_current: self.fail("reconnected")
        self.assertTrue(es.failover("bad proof"))
        self.assertIs(es._connection, conn_b)
        self.assertEqual(es.primary_key(), "b.example:50002")
        self.assertEqual(es._subscribed_height, 905)
        self.assertFalse(conn_a.connected)
        self.assertEqual(es._extra_connections, {})
        self.assertEqual(es.get_server_tips(), {"b.example:50002": 905})

    def test_switch_keeps_the_old_primary(self):
        es = self.make_server()
        conn_a, conn_b = FakeConnection(), FakeConnection()
        es._connection = conn_a
        es._extra_connections = {"b.example:50002": conn_b}
        es._server_tips = {"a.example:50002": 900, "b.example:50002": 905}
        self.assertTrue(es.switch_primary("b.example:50002"))
        self.assertIs(es._connection, conn_b)
        self.assertEqual(es._extra_connections, {"a.example:50002": conn_a})
        self.assertTrue(conn_a.connected)
        conn_a.header_callback(901)
        self.assertEqual(es.get_server_tips()["a.example:50002"], 901)

    def test_dropped_extra_blacklisted(self):
        es = self.make_server()
        conn_a, conn_b = FakeConnection(), FakeConnection()
        es._connection = conn_a
        es._extra_connections = {"b.example:50002": conn_b}
        es._server_tips = {"a.example:50002": 900, "b.example:50002": 905}
        es.drop_server("b.example:50002", "conflicts with checkpoints")
        self.assertFalse(conn_b.connected)
        self.assertEqual(es._extra_connections, {})
        self.assertEqual([s["host"] for s in es.get_sorted_servers()], ["a.example"])
        self.assertIs(es._connection, conn_a)


class TestHashes(unittest.TestCase):
    def test_header_round_trip(self):
        header = Chunk0.headers[3]
        data = serialize_header(header)
        self.assertEqual(hash_raw_header(data), hash_header(header))


if __name__ == "__main__":
    unittest.main()
