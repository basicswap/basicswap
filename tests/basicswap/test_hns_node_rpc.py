"""Contract tests for the read-only hsrd wallet RPC boundary."""

import json
import unittest
from unittest.mock import patch

from basicswap.interface.hns.node_rpc import (
    HnsChainSnapshot,
    HnsNodeError,
    HnsNodeRpc,
    HnsStaleSnapshot,
    script_id_for_address,
)

GENESIS = "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5"
TIP = {
    "hash": "ab" * 32,
    "height": 12,
    "median_time_past": 1_700_000_000,
    "tree_root": "cd" * 32,
}


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body

    def read(self, size):
        return self.body[:size]


class FakeConnection:
    def __init__(self, replies, requests):
        self._replies = replies
        self._requests = requests
        self._request = None
        self.closed = False

    def request(self, verb, path, body=None, headers=None):
        self._request = json.loads(body) if body is not None else None
        self._requests.append((verb, path, self._request, headers))

    def getresponse(self):
        status, result = self._replies.pop(0)
        if self._request is None:
            return FakeResponse(status, json.dumps(result).encode())
        return FakeResponse(
            status,
            json.dumps(
                {
                    "api_version": 1,
                    "request_id": self._request["request_id"],
                    **result,
                }
            ).encode(),
        )

    def close(self):
        self.closed = True


class HnsNodeRpcTest(unittest.TestCase):
    def make_client(self, replies):
        requests = []
        connections = []

        def connect(*args, **kwargs):
            conn = FakeConnection(replies, requests)
            connections.append(conn)
            return conn

        patcher = patch(
            "basicswap.interface.hns.node_rpc.http.client.HTTPConnection", connect
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return HnsNodeRpc(12037, "Bearer secret"), requests, connections

    def test_network_binding_precedes_script_query(self):
        replies = [
            (200, {"result": {"chain_epoch": 7, "tip": TIP}}),
            (
                200,
                {
                    "result": {
                        "chain_epoch": 7,
                        "tip": TIP,
                        "height": 0,
                        "hash": GENESIS,
                    }
                },
            ),
        ]
        client, requests, connections = self.make_client(replies)
        binding = client.bound_snapshot("regtest")
        self.assertEqual(binding.chain_epoch, 7)
        self.assertEqual(
            [item[2]["call"]["method"] for item in requests],
            ["chain_snapshot", "block_hash"],
        )
        self.assertEqual(requests[1][2]["call"]["params"]["expected_chain_epoch"], 7)
        self.assertEqual(requests[0][3]["Authorization"], "Bearer secret")
        self.assertTrue(all(conn.closed for conn in connections))

    def test_sync_readiness_requires_scheduler_and_wallet_tip_agreement(self):
        scheduler_tip = {
            "hash": list(bytes.fromhex(TIP["hash"])),
            "height": TIP["height"],
        }
        synced = {
            "stage": "Synced",
            "active_tip": scheduler_tip,
            "stored_tip": scheduler_tip,
            "best_header": scheduler_tip,
            "target_height": TIP["height"],
            "pending_blocks": 0,
            "inflight_blocks": 0,
            "tracked_blocks": 0,
            "peers": [],
        }
        stale = {
            **synced,
            "best_header": {"hash": list(bytes.fromhex("ef" * 32)), "height": 13},
        }
        client, requests, connections = self.make_client([(200, synced), (200, stale)])
        binding = HnsChainSnapshot(7, TIP)
        self.assertTrue(client.sync_ready("regtest", binding))
        self.assertFalse(client.sync_ready("regtest", binding))
        self.assertEqual(requests[0][:2], ("GET", "/api/v1/sync"))
        self.assertEqual(requests[0][3]["Authorization"], "Bearer secret")
        self.assertTrue(all(conn.closed for conn in connections))

    def test_mainnet_sync_readiness_needs_a_peer(self):
        scheduler_tip = {
            "hash": list(bytes.fromhex(TIP["hash"])),
            "height": TIP["height"],
        }
        status = {
            "stage": "Synced",
            "active_tip": scheduler_tip,
            "stored_tip": scheduler_tip,
            "best_header": scheduler_tip,
            "target_height": TIP["height"],
            "pending_blocks": 0,
            "inflight_blocks": 0,
            "tracked_blocks": 0,
            "peers": [],
        }
        client, _, _ = self.make_client([(200, status)])
        self.assertFalse(client.sync_ready("mainnet", HnsChainSnapshot(7, TIP)))

    def test_sync_readiness_rejects_malformed_scheduler_hash(self):
        status = {
            "stage": "Synced",
            "active_tip": {"hash": [True] * 32, "height": TIP["height"]},
            "stored_tip": {
                "hash": list(bytes.fromhex(TIP["hash"])),
                "height": TIP["height"],
            },
            "best_header": {
                "hash": list(bytes.fromhex(TIP["hash"])),
                "height": TIP["height"],
            },
            "target_height": TIP["height"],
            "pending_blocks": 0,
            "inflight_blocks": 0,
            "tracked_blocks": 0,
            "peers": [],
        }
        client, _, _ = self.make_client([(200, status)])
        with self.assertRaisesRegex(HnsNodeError, "tip hash"):
            client.sync_ready("regtest", HnsChainSnapshot(7, TIP))

    def test_genesis_mismatch_is_rejected(self):
        replies = [
            (200, {"result": {"chain_epoch": 7, "tip": TIP}}),
            (
                200,
                {
                    "result": {
                        "chain_epoch": 7,
                        "tip": TIP,
                        "height": 0,
                        "hash": "00" * 32,
                    }
                },
            ),
        ]
        client, _, _ = self.make_client(replies)
        with self.assertRaisesRegex(HnsNodeError, "genesis mismatch"):
            client.bound_snapshot("regtest")

    def test_confirmed_pages_are_collected_only_under_one_binding(self):
        replies = [
            (
                200,
                {
                    "result": {
                        "chain_epoch": 7,
                        "tip": TIP,
                        "history": [{"script_index": 0, "txid": "11" * 32}],
                        "utxos": [],
                        "continuation": "cursor1",
                    }
                },
            ),
            (
                200,
                {
                    "result": {
                        "chain_epoch": 7,
                        "tip": TIP,
                        "history": [],
                        "utxos": [{"script_index": 0, "coin": {"value": 10}}],
                        "continuation": None,
                    }
                },
            ),
        ]
        client, requests, _ = self.make_client(replies)
        from basicswap.interface.hns.node_rpc import HnsChainSnapshot

        result = client.confirmed_scripts(["11" * 32], HnsChainSnapshot(7, TIP))
        self.assertEqual(len(result.history), 1)
        self.assertEqual(len(result.utxos), 1)
        self.assertEqual(requests[1][2]["call"]["params"]["cursor"], "cursor1")

    def test_reorg_discards_partial_scan(self):
        replies = [
            (
                200,
                {
                    "result": {
                        "chain_epoch": 7,
                        "tip": TIP,
                        "history": [{"script_index": 0}],
                        "utxos": [],
                        "continuation": "cursor1",
                    }
                },
            ),
            (409, {"error": {"code": "stale_snapshot", "retryable": True}}),
        ]
        client, _, _ = self.make_client(replies)
        from basicswap.interface.hns.node_rpc import HnsChainSnapshot

        with self.assertRaises(HnsStaleSnapshot):
            client.confirmed_scripts(["11" * 32], HnsChainSnapshot(7, TIP))

    def test_large_script_set_is_chunked_under_hsrd_request_limit(self):
        replies = [
            (
                200,
                {
                    "result": {
                        "chain_epoch": 7,
                        "tip": TIP,
                        "history": [],
                        "utxos": [],
                        "continuation": None,
                    }
                },
            ),
            (
                200,
                {
                    "result": {
                        "chain_epoch": 7,
                        "tip": TIP,
                        "history": [{"script_index": 0}],
                        "utxos": [],
                        "continuation": None,
                    }
                },
            ),
        ]
        client, requests, _ = self.make_client(replies)
        from basicswap.interface.hns.node_rpc import HnsChainSnapshot

        script_ids = [f"{number:064x}" for number in range(257)]
        result = client.confirmed_scripts(script_ids, HnsChainSnapshot(7, TIP))
        self.assertEqual(result.history[0]["script_index"], 256)
        self.assertEqual(len(requests[0][2]["call"]["params"]["script_ids"]), 256)
        self.assertEqual(len(requests[1][2]["call"]["params"]["script_ids"]), 1)

    def test_mutation_and_non_loopback_are_rejected(self):
        with self.assertRaises(ValueError):
            HnsNodeRpc(12037, "Bearer secret", host="example.com")
        with self.assertRaises(ValueError):
            HnsNodeRpc(12037, "Bearer secret\n")
        client, _, _ = self.make_client([])
        with self.assertRaises(ValueError):
            client.call("broadcast_transaction", {"transaction_hex": "deadbeef"})

    def test_script_identity_uses_hns_address_encoding(self):
        self.assertEqual(
            script_id_for_address(0, bytes(20)),
            "272ae689b02ba3546c5a7714b6558b199dcd1fd4eb765edcd16ec29b002ec7af",
        )
        with self.assertRaises(ValueError):
            script_id_for_address(0, bytes(21))


if __name__ == "__main__":
    unittest.main()
