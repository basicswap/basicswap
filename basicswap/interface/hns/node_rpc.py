"""Bounded, read-only client for hsrd's authenticated wallet RPC v1.

This is an independent node evidence checker. hns-wallet-rs already has the
wallet-side HSRD adapter and native HTLC settlement code; a BasicSwap bridge
should call those Rust APIs for value operations. This client never constructs,
signs, or broadcasts a transaction.
"""

import hashlib
import http.client
import json
import re
import threading
from dataclasses import dataclass

_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")
_GENESIS = {
    "mainnet": "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
    "testnet": "b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901",
    "regtest": "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5",
}


def hns_network_binding(network):
    """Return the wallet descriptor magic and genesis for one HSRD network."""
    if network not in _GENESIS:
        raise ValueError("unsupported HSRD network")
    genesis = bytes.fromhex(_GENESIS[network])
    return int.from_bytes(genesis[:4], "big"), genesis


# hsrd limits the result projection to 8 MiB; allow room for the envelope.
_MAX_RESPONSE = 8 * 1024 * 1024 + 4096
# hsrd defaults to a 65,536-byte request-body limit. A full 10,000-script
# restore set cannot fit in one envelope, so scan fixed-size subsets.
_SCRIPTS_PER_REQUEST = 256
_READ_METHODS = frozenset(
    (
        "capabilities",
        "chain_snapshot",
        "block_hash",
        "confirmed_scripts_page",
        "mempool_scripts_page",
        "transaction_evidence",
        "raw_transaction",
        "spending_transactions",
    )
)


class HnsNodeError(Exception):
    """An RPC, transport, network, or snapshot binding failure."""


class HnsStaleSnapshot(HnsNodeError):
    """A scan crossed a chain or mempool generation; discard partial results."""


@dataclass(frozen=True)
class HnsChainSnapshot:
    chain_epoch: int
    tip: dict


@dataclass(frozen=True)
class HnsConfirmedScan:
    history: list
    utxos: list


def _valid_hash(value):
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _valid_tip(tip):
    return (
        isinstance(tip, dict)
        and set(tip) == {"hash", "height", "median_time_past", "tree_root"}
        and _valid_hash(tip["hash"])
        and _valid_hash(tip["tree_root"])
        and type(tip["height"]) is int
        and tip["height"] >= 0
        and type(tip["median_time_past"]) is int
        and tip["median_time_past"] >= 0
    )


def _sync_tip_hash(value):
    """HSRD's scheduler JSON uses a byte array; wallet v1 uses hex."""
    if (
        not isinstance(value, list)
        or len(value) != 32
        or any(type(byte) is not int or not 0 <= byte <= 255 for byte in value)
    ):
        raise HnsNodeError("invalid hsrd synchronization tip hash")
    return bytes(value).hex()


def script_id_for_address(version: int, program: bytes) -> str:
    """Derive hsrd's ScriptId from a canonical Handshake output address."""
    if type(version) is not int or not 0 <= version <= 31:
        raise ValueError("invalid Handshake address version")
    if not isinstance(program, bytes) or not 2 <= len(program) <= 40:
        raise ValueError("invalid Handshake address program")
    if version == 0 and len(program) not in (20, 32):
        raise ValueError("invalid version zero witness program")
    return hashlib.blake2b(
        bytes((version, len(program))) + program, digest_size=32
    ).hexdigest()


class HnsNodeRpc:
    """Use only the authenticated, indexed hsrd wallet route on loopback.

    The caller owns the authorization secret. The header is never included in
    exception messages, and the HTTP connection is closed for every request.
    """

    def __init__(
        self, port: int, authorization: str, host: str = "127.0.0.1", timeout=10
    ):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("hsrd wallet RPC must be loopback")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("invalid hsrd port")
        if (
            not isinstance(authorization, str)
            or not 1 <= len(authorization) <= 4096
            or authorization[0] in " \t"
            or authorization[-1] in " \t"
            or any(ord(char) < 0x20 or ord(char) > 0x7E for char in authorization)
        ):
            raise ValueError("invalid hsrd authorization header")
        self._host = host
        self._port = port
        self._authorization = authorization
        self._timeout = timeout
        self._next_id = 0
        self._id_lock = threading.Lock()

    def call(self, method: str, params: dict | None = None) -> dict:
        if method not in _READ_METHODS:
            raise ValueError("unsupported read-only hsrd method")
        if params is not None and not isinstance(params, dict):
            raise ValueError("hsrd parameters must be an object")
        with self._id_lock:
            self._next_id += 1
            request_id = str(self._next_id)
        call = {"method": method}
        if params is not None:
            call["params"] = params
        body = json.dumps(
            {"api_version": 1, "request_id": request_id, "call": call},
            separators=(",", ":"),
        ).encode("utf-8")
        connection = http.client.HTTPConnection(
            self._host, self._port, timeout=self._timeout
        )
        try:
            connection.request(
                "POST",
                "/api/v1/wallet",
                body=body,
                headers={
                    "Authorization": self._authorization,
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            status = response.status
            content = response.read(_MAX_RESPONSE + 1)
            if len(content) > _MAX_RESPONSE:
                raise HnsNodeError("hsrd wallet RPC response exceeds limit")
            envelope = json.loads(content)
        except (
            OSError,
            http.client.HTTPException,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise HnsNodeError("hsrd wallet RPC transport or response failure") from exc
        finally:
            connection.close()
        if (
            not isinstance(envelope, dict)
            or envelope.get("api_version") != 1
            or envelope.get("request_id") != request_id
            or ("result" in envelope) == ("error" in envelope)
        ):
            raise HnsNodeError("invalid hsrd wallet RPC envelope")
        if "error" in envelope:
            error = envelope["error"]
            if not isinstance(error, dict):
                raise HnsNodeError("invalid hsrd wallet RPC error")
            if error.get("code") == "stale_snapshot":
                raise HnsStaleSnapshot("hsrd chain or mempool snapshot changed")
            code = error.get("code")
            raise HnsNodeError(
                f"hsrd wallet RPC error: {code}"
                if isinstance(code, str) and len(code) <= 64
                else "hsrd wallet RPC error"
            )
        if status != 200:
            raise HnsNodeError(f"hsrd wallet RPC returned HTTP {status}")
        result = envelope["result"]
        if not isinstance(result, dict):
            raise HnsNodeError("invalid hsrd wallet RPC result")
        return result

    def bound_snapshot(self, network: str) -> HnsChainSnapshot:
        """Check genesis before querying wallet script identities."""
        if network not in _GENESIS:
            raise ValueError("unknown Handshake network")
        snapshot = self.call("chain_snapshot")
        epoch, tip = snapshot.get("chain_epoch"), snapshot.get("tip")
        if type(epoch) is not int or epoch < 0 or not _valid_tip(tip):
            raise HnsNodeError("invalid or uninitialized hsrd chain snapshot")
        genesis = self.call("block_hash", {"height": 0, "expected_chain_epoch": epoch})
        if genesis.get("chain_epoch") != epoch or genesis.get("tip") != tip:
            raise HnsStaleSnapshot("hsrd chain changed during network binding")
        if genesis.get("height") != 0 or not _valid_hash(genesis.get("hash")):
            raise HnsNodeError("invalid hsrd genesis response")
        if genesis["hash"].lower() != _GENESIS[network]:
            raise HnsNodeError("hsrd network genesis mismatch")
        return HnsChainSnapshot(epoch, tip)

    def sync_ready(self, network: str, binding: HnsChainSnapshot) -> bool:
        """Require HSRD's sync scheduler to agree with the wallet chain tip."""
        if network not in _GENESIS or not isinstance(binding, HnsChainSnapshot):
            raise ValueError("invalid hsrd synchronization binding")
        connection = http.client.HTTPConnection(
            self._host, self._port, timeout=self._timeout
        )
        try:
            connection.request(
                "GET",
                "/api/v1/sync",
                headers={"Authorization": self._authorization},
            )
            response = connection.getresponse()
            content = response.read(128 * 1024 + 1)
            if response.status != 200 or len(content) > 128 * 1024:
                raise HnsNodeError("hsrd synchronization status unavailable")
            status = json.loads(content)
        except (
            OSError,
            http.client.HTTPException,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise HnsNodeError("hsrd synchronization status failed") from exc
        finally:
            connection.close()
        if not isinstance(status, dict):
            raise HnsNodeError("invalid hsrd synchronization status")
        if status.get("stage") != "Synced":
            return False
        target = status.get("target_height")
        active = status.get("active_tip")
        stored = status.get("stored_tip")
        best = status.get("best_header")
        if any(not isinstance(tip, dict) for tip in (active, stored, best)):
            raise HnsNodeError("invalid hsrd synchronization tip")
        for tip in (active, stored, best):
            if (
                _sync_tip_hash(tip.get("hash")) != binding.tip["hash"].lower()
                or type(tip.get("height")) is not int
                or tip["height"] != binding.tip["height"]
            ):
                return False
        if target is not None and (
            type(target) is not int or target < 0 or target > binding.tip["height"]
        ):
            return False
        for key in ("pending_blocks", "inflight_blocks", "tracked_blocks"):
            if status.get(key) != 0:
                return False
        peers = status.get("peers")
        if not isinstance(peers, list):
            raise HnsNodeError("invalid hsrd synchronization peers")
        return not (network != "regtest" and not peers)

    def confirmed_scripts(self, script_ids: list[str], binding: HnsChainSnapshot):
        """Return a complete confirmed scan, or no results on a reorg.

        Script IDs are BLAKE2b-256 hashes of canonical HNS output-address
        encodings. The caller must derive and retain their reverse mapping.
        """
        if (
            not isinstance(script_ids, list)
            or not script_ids
            or len(script_ids) > 10_000
            or any(not _valid_hash(item) or item != item.lower() for item in script_ids)
            or script_ids != sorted(set(script_ids))
        ):
            raise ValueError("script IDs must be sorted unique lowercase hashes")
        history = []
        utxos = []
        for first in range(0, len(script_ids), _SCRIPTS_PER_REQUEST):
            batch = script_ids[first : first + _SCRIPTS_PER_REQUEST]
            cursor = None
            seen = set()
            while True:
                page = self.call(
                    "confirmed_scripts_page",
                    {"script_ids": batch, "cursor": cursor, "limit": 256},
                )
                if (
                    page.get("chain_epoch") != binding.chain_epoch
                    or page.get("tip") != binding.tip
                ):
                    raise HnsStaleSnapshot("hsrd chain changed during script scan")
                page_history = page.get("history")
                page_utxos = page.get("utxos")
                if (
                    not isinstance(page_history, list)
                    or not isinstance(page_utxos, list)
                    or len(page_history) + len(page_utxos) > 256
                ):
                    raise HnsNodeError("invalid hsrd confirmed script page")
                for collection, rows in ((history, page_history), (utxos, page_utxos)):
                    for row in rows:
                        if (
                            not isinstance(row, dict)
                            or type(row.get("script_index")) is not int
                            or not 0 <= row["script_index"] < len(batch)
                        ):
                            raise HnsNodeError("invalid hsrd confirmed script row")
                        collection.append(
                            {**row, "script_index": first + row["script_index"]}
                        )
                if len(history) + len(utxos) > 100_000:
                    raise HnsNodeError("hsrd confirmed scan exceeds local result limit")
                cursor = page.get("continuation")
                if cursor is None:
                    break
                if (
                    not isinstance(cursor, str)
                    or not cursor
                    or len(cursor) > 8192
                    or cursor in seen
                ):
                    raise HnsNodeError("invalid hsrd confirmed script cursor")
                seen.add(cursor)
        return HnsConfirmedScan(history, utxos)
