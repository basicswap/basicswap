"""Private framed client for the hns-wallet-rs BasicSwap settlement process.

The child owns HNS keys, coin selection, signing, and persisted settlement
workflows. This client carries exact BasicSwap offer/bid identities and the
canonical HNS HTLC descriptor over a local process pipe. No network peer can
invoke the child directly through this interface.
"""

import hashlib
import json
import os
import queue
import re
import stat
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from .address import decode_v0_address
from .htlc import HnsHtlc

MAX_FRAME_BYTES = 65_536
PROTOCOL_VERSION = 2
SESSION_DOMAIN = b"basicswap/hns-wallet-bridge/session/v2\0"
_DECIMAL_UNITS = re.compile(r"(0|[1-9][0-9]*)\Z")


class HnsWalletBridgeError(RuntimeError):
    """The local wallet process rejected a request or lost its protocol pipe."""


def _hex_bytes(value, size, name):
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"invalid {name}")
    return value.hex()


def _wire_bytes(value, size, name):
    if not isinstance(value, str) or len(value) != size * 2:
        raise HnsWalletBridgeError(f"invalid HNS wallet {name}")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise HnsWalletBridgeError(f"invalid HNS wallet {name}") from exc
    if len(result) != size:
        raise HnsWalletBridgeError(f"invalid HNS wallet {name}")
    return result


def _positive_integer(value, name, maximum):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError(f"invalid {name}")
    return value


@dataclass(frozen=True)
class HnsBridgeTerms:
    offer_id: bytes
    bid_id: bytes
    session_nonce: bytes
    descriptor: HnsHtlc

    def session_id(self):
        _hex_bytes(self.offer_id, 28, "offer ID")
        _hex_bytes(self.bid_id, 28, "bid ID")
        _hex_bytes(self.session_nonce, 32, "session nonce")
        if self.session_nonce == bytes(32):
            raise ValueError("invalid HNS session nonce")
        return hashlib.sha256(
            SESSION_DOMAIN + self.offer_id + self.session_nonce
        ).digest()

    def as_wire(self):
        self.session_id()
        return {
            "offer_id": _hex_bytes(self.offer_id, 28, "offer ID"),
            "bid_id": _hex_bytes(self.bid_id, 28, "bid ID"),
            "session_nonce": _hex_bytes(self.session_nonce, 32, "session nonce"),
            "descriptor": self.descriptor.encode().hex(),
            "descriptor_hash": self.descriptor.descriptor_hash().hex(),
        }


class HnsWalletBridge:
    def __init__(self, executable, database, rpc_endpoint, rpc_authorization_file):
        if Path(rpc_authorization_file).is_symlink():
            raise ValueError("HNS node authorization file must not be a symlink")
        executable = Path(executable).resolve(strict=True)
        database = Path(database).resolve(strict=True)
        rpc_authorization_file = Path(rpc_authorization_file).resolve(strict=True)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("invalid HNS wallet bridge executable")
        if not database.is_file() or not rpc_authorization_file.is_file():
            raise ValueError("invalid HNS wallet bridge configuration")
        if os.name == "posix":
            auth_stat = rpc_authorization_file.stat()
            if (
                not stat.S_ISREG(auth_stat.st_mode)
                or auth_stat.st_uid != os.getuid()
                or auth_stat.st_mode & 0o077
            ):
                raise ValueError("HNS node authorization file must be private")
        self._process = subprocess.Popen(
            [
                str(executable),
                "--database",
                str(database),
                "--rpc-endpoint",
                rpc_endpoint,
                "--rpc-authorization-file",
                str(rpc_authorization_file),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            close_fds=True,
        )
        self._lock = threading.Lock()
        self._responses = queue.Queue(maxsize=1)
        self._sequence = 0
        self._closed = False
        self._reader = threading.Thread(target=self._read_responses, daemon=True)
        self._reader.start()

    def _read_responses(self):
        try:
            while True:
                prefix = self._read_exact(4)
                length = int.from_bytes(prefix, "little")
                if not 0 < length <= MAX_FRAME_BYTES:
                    raise HnsWalletBridgeError("invalid HNS wallet response length")
                frame = self._read_exact(length)
                self._responses.put(frame, timeout=1)
        except (OSError, EOFError, HnsWalletBridgeError, queue.Full) as exc:
            try:
                self._responses.put_nowait(exc)
            except queue.Full:
                pass

    def _read_exact(self, size):
        data = bytearray()
        while len(data) < size:
            chunk = self._process.stdout.read(size - len(data))
            if not chunk:
                raise EOFError("HNS wallet bridge closed its pipe")
            data.extend(chunk)
        return bytes(data)

    def _request(self, operation, timeout=45, **fields):
        with self._lock:
            if self._closed or self._process.poll() is not None:
                raise HnsWalletBridgeError("HNS wallet bridge is stopped")
            sequence = self._sequence + 1
            request = {
                "version": PROTOCOL_VERSION,
                "sequence": sequence,
                "request": {"operation": operation, **fields},
            }
            encoded = json.dumps(
                request, separators=(",", ":"), allow_nan=False
            ).encode()
            if not 0 < len(encoded) <= MAX_FRAME_BYTES:
                raise ValueError("HNS wallet request exceeds frame limit")
            try:
                self._process.stdin.write(len(encoded).to_bytes(4, "little") + encoded)
                self._process.stdin.flush()
            except OSError as exc:
                self.close()
                raise HnsWalletBridgeError(
                    "HNS wallet bridge pipe write failed"
                ) from exc
            self._sequence = sequence
            try:
                frame = self._responses.get(timeout=timeout)
            except queue.Empty as exc:
                self.close()
                raise HnsWalletBridgeError(
                    "HNS wallet bridge response timed out"
                ) from exc
            if isinstance(frame, Exception):
                self.close()
                raise HnsWalletBridgeError(
                    "HNS wallet bridge pipe read failed"
                ) from frame
            try:
                response = json.loads(frame)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self.close()
                raise HnsWalletBridgeError(
                    "invalid HNS wallet bridge response"
                ) from exc
            if (
                not isinstance(response, dict)
                or type(response.get("version")) is not int
                or response["version"] != PROTOCOL_VERSION
                or type(response.get("sequence")) is not int
                or response["sequence"] != sequence
                or type(response.get("ok")) is not bool
                or set(response) != {"version", "sequence", "ok", "result", "error"}
            ):
                self.close()
                raise HnsWalletBridgeError("HNS wallet bridge response mismatch")
            if not response["ok"]:
                if response["result"] is not None or not isinstance(
                    response["error"], str
                ):
                    self.close()
                    raise HnsWalletBridgeError("invalid HNS wallet bridge error")
                raise HnsWalletBridgeError(response["error"])
            if response["error"] is not None or not isinstance(
                response["result"], dict
            ):
                self.close()
                raise HnsWalletBridgeError("invalid HNS wallet bridge result")
            return response["result"]

    def unlock(self, passphrase):
        if not isinstance(passphrase, str) or not passphrase:
            raise ValueError("invalid HNS wallet passphrase")
        result = self._request("unlock", passphrase=passphrase)
        if result != {"unlocked": True}:
            raise HnsWalletBridgeError("invalid HNS unlock result")

    def lock(self):
        result = self._request("lock")
        if result != {"unlocked": False}:
            raise HnsWalletBridgeError("invalid HNS lock result")

    def sync(self):
        result = self._request("sync")
        if result != {"synchronized": True}:
            raise HnsWalletBridgeError("invalid HNS synchronization result")

    @staticmethod
    def _receive_address(network, address):
        try:
            decoded = decode_v0_address(network, address)
        except ValueError as exc:
            raise HnsWalletBridgeError("invalid HNS wallet receive address") from exc
        if len(decoded.program) != 20:
            raise HnsWalletBridgeError("invalid HNS wallet receive program")
        return address

    def receive(self, network):
        result = self._request("receive")
        if set(result) != {"address", "derivation_index"}:
            raise HnsWalletBridgeError("invalid HNS receive result")
        index = result["derivation_index"]
        if type(index) is not int or not 0 <= index <= 0xFFFFFFFF:
            raise HnsWalletBridgeError("invalid HNS receive derivation index")
        return self._receive_address(network, result["address"]), index

    def snapshot(self, network):
        result = self._request("snapshot")
        if set(result) != {"balance", "receive_address"}:
            raise HnsWalletBridgeError("invalid HNS wallet snapshot")
        balance = result["balance"]
        if (
            not isinstance(balance, str)
            or not _DECIMAL_UNITS.fullmatch(balance)
            or int(balance) > 0xFFFFFFFFFFFFFFFF
        ):
            raise HnsWalletBridgeError("invalid HNS wallet balance")
        return int(balance), self._receive_address(network, result["receive_address"])

    def key(self, offer_id, session_nonce, refund):
        if type(refund) is not bool:
            raise ValueError("invalid HNS settlement branch")
        _hex_bytes(session_nonce, 32, "session nonce")
        if session_nonce == bytes(32):
            raise ValueError("invalid HNS session nonce")
        result = self._request(
            "key",
            offer_id=_hex_bytes(offer_id, 28, "offer ID"),
            session_nonce=session_nonce.hex(),
            refund=refund,
        )
        if set(result) != {"public_key"}:
            raise HnsWalletBridgeError("invalid HNS wallet key result")
        return _wire_bytes(result["public_key"], 33, "public key")

    def fund(self, terms, maximum_fee):
        result = self._request(
            "fund",
            terms=terms.as_wire(),
            maximum_fee=_positive_integer(
                maximum_fee, "maximum HNS fee", 0xFFFFFFFFFFFFFFFF
            ),
        )
        if (
            set(result) != {"transaction_id", "output_index", "recovered"}
            or result.get("output_index") != 0
            or type(result.get("recovered")) is not bool
        ):
            raise HnsWalletBridgeError("invalid HNS funding output index")
        return _wire_bytes(result.get("transaction_id"), 32, "funding ID"), 0

    def verify_lock(self, terms, funding_id, confirmations):
        result = self._request(
            "verify_lock",
            terms=terms.as_wire(),
            funding_id=_hex_bytes(funding_id, 32, "funding ID"),
            confirmations=_positive_integer(
                confirmations, "HNS confirmations", 0xFFFFFFFF
            ),
        )
        if set(result) != {"verified"}:
            raise HnsWalletBridgeError("invalid HNS lock verification result")
        verified = result["verified"]
        if type(verified) is not bool:
            raise HnsWalletBridgeError("invalid HNS lock verification result")
        return verified

    def redeem(self, terms, funding_id, confirmations, preimage, maximum_fee):
        result = self._request(
            "redeem",
            terms=terms.as_wire(),
            funding_id=_hex_bytes(funding_id, 32, "funding ID"),
            confirmations=_positive_integer(
                confirmations, "HNS confirmations", 0xFFFFFFFF
            ),
            preimage=_hex_bytes(preimage, 32, "preimage"),
            maximum_fee=_positive_integer(
                maximum_fee, "maximum HNS fee", 0xFFFFFFFFFFFFFFFF
            ),
        )
        if (
            set(result) != {"transaction_id", "recovered"}
            or type(result["recovered"]) is not bool
        ):
            raise HnsWalletBridgeError("invalid HNS redeem result")
        return _wire_bytes(result["transaction_id"], 32, "redeem ID")

    def refund(self, terms, funding_id, confirmations, maximum_fee):
        result = self._request(
            "refund",
            terms=terms.as_wire(),
            funding_id=_hex_bytes(funding_id, 32, "funding ID"),
            confirmations=_positive_integer(
                confirmations, "HNS confirmations", 0xFFFFFFFF
            ),
            maximum_fee=_positive_integer(
                maximum_fee, "maximum HNS fee", 0xFFFFFFFFFFFFFFFF
            ),
        )
        if (
            set(result) != {"transaction_id", "recovered"}
            or type(result["recovered"]) is not bool
        ):
            raise HnsWalletBridgeError("invalid HNS refund result")
        return _wire_bytes(result["transaction_id"], 32, "refund ID")

    def observe_spend(self, terms, funding_id, confirmations):
        result = self._request(
            "observe_spend",
            terms=terms.as_wire(),
            funding_id=_hex_bytes(funding_id, 32, "funding ID"),
            confirmations=_positive_integer(
                confirmations, "HNS confirmations", 0xFFFFFFFF
            ),
        )
        if result.get("observed") is False:
            if set(result) != {"observed"}:
                raise HnsWalletBridgeError("invalid HNS spend observation")
            return None
        if result.get("observed") is not True:
            raise HnsWalletBridgeError("invalid HNS spend observation")
        branch = result.get("branch")
        if branch not in ("redeem", "refund"):
            raise HnsWalletBridgeError("invalid HNS spend branch")
        transaction_id = _wire_bytes(result.get("transaction_id"), 32, "spend ID")
        confirmed = result.get("confirmations")
        if type(confirmed) is not int or confirmed < 0:
            raise HnsWalletBridgeError("invalid HNS spend confirmations")
        if branch == "refund":
            if set(result) != {"observed", "branch", "transaction_id", "confirmations"}:
                raise HnsWalletBridgeError("invalid HNS refund observation")
            return branch, transaction_id, confirmed, None
        if set(result) != {
            "observed",
            "branch",
            "transaction_id",
            "confirmations",
            "preimage",
        }:
            raise HnsWalletBridgeError("invalid HNS redeem observation")
        preimage = _wire_bytes(result["preimage"], 32, "redeem preimage")
        if hashlib.sha256(preimage).digest() != terms.descriptor.hashlock:
            raise HnsWalletBridgeError("HNS redeem preimage mismatch")
        return branch, transaction_id, confirmed, preimage

    def rebroadcast(self):
        result = self._request("rebroadcast")
        if set(result) != {"count"}:
            raise HnsWalletBridgeError("invalid HNS rebroadcast result")
        count = result["count"]
        if type(count) is not int or count < 0:
            raise HnsWalletBridgeError("invalid HNS rebroadcast count")
        return count

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=3)
        self._process.stdin.close()
        self._process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        self.close()
