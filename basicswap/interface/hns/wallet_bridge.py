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
_RECOVERY_WORD = re.compile(r"[a-z]+\Z")


class HnsWalletBridgeError(RuntimeError):
    """The local wallet process rejected a request or lost its protocol pipe."""


def initialize_hns_wallet(
    executable, database, network, restore_height, passphrase, recovery_phrase=None
):
    """Run the short-lived Rust account initializer over a private pipe.

    A newly created recovery phrase is returned exactly once. The caller must
    present it for backup before treating the account as usable.
    """
    executable = Path(executable).resolve(strict=True)
    database = Path(database)
    if database.is_symlink() or database.exists():
        raise ValueError("HNS wallet database already exists")
    if network not in ("mainnet", "testnet", "regtest", "simnet"):
        raise ValueError("invalid HNS wallet network")
    if type(restore_height) is not int or restore_height < 0:
        raise ValueError("invalid HNS wallet restore height")
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("invalid HNS wallet passphrase")
    if recovery_phrase is not None and (
        not isinstance(recovery_phrase, str) or not recovery_phrase
    ):
        raise ValueError("invalid HNS wallet recovery phrase")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("invalid HNS wallet bridge executable")
    request = json.dumps(
        {
            "version": PROTOCOL_VERSION,
            "sequence": 1,
            "passphrase": passphrase,
            "recovery_phrase": recovery_phrase,
        },
        separators=(",", ":"),
    ).encode()
    if not 0 < len(request) <= MAX_FRAME_BYTES:
        raise ValueError("HNS wallet initialization request is too large")
    try:
        process = subprocess.run(
            [
                str(executable),
                "--initialize",
                "--database",
                str(database),
                "--network",
                network,
                "--restore-height",
                str(restore_height),
            ],
            input=len(request).to_bytes(4, "little") + request,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HnsWalletBridgeError("HNS wallet initialization process failed") from exc
    output = process.stdout
    if process.returncode != 0 or len(output) < 4:
        raise HnsWalletBridgeError("HNS wallet initialization failed")
    length = int.from_bytes(output[:4], "little")
    if not 0 < length <= MAX_FRAME_BYTES or len(output) != 4 + length:
        raise HnsWalletBridgeError("invalid HNS wallet initialization response")
    try:
        response = json.loads(output[4:])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HnsWalletBridgeError(
            "invalid HNS wallet initialization response"
        ) from exc
    if (
        not isinstance(response, dict)
        or set(response) != {"version", "sequence", "ok", "result", "error"}
        or type(response["version"]) is not int
        or response["version"] != PROTOCOL_VERSION
        or type(response["sequence"]) is not int
        or response["sequence"] != 1
        or response["ok"] is not True
        or response["error"] is not None
        or not isinstance(response["result"], dict)
    ):
        raise HnsWalletBridgeError("invalid HNS wallet initialization response")
    result = response["result"]
    created = recovery_phrase is None
    expected_keys = (
        {"created", "wallet_id", "seed_fingerprint", "recovery_phrase"}
        if created
        else {"created", "wallet_id", "seed_fingerprint"}
    )
    if set(result) != expected_keys or result["created"] is not created:
        raise HnsWalletBridgeError("invalid HNS wallet initialization result")
    wallet_id = _wire_bytes(result["wallet_id"], 16, "wallet ID")
    seed_fingerprint = _wire_bytes(result["seed_fingerprint"], 32, "seed fingerprint")
    phrase = result.get("recovery_phrase")
    if created and (
        not isinstance(phrase, str)
        or len(phrase.split()) != 24
        or any(_RECOVERY_WORD.fullmatch(word) is None for word in phrase.split())
    ):
        raise HnsWalletBridgeError("invalid HNS wallet recovery phrase")
    if not database.is_file() or database.is_symlink():
        raise HnsWalletBridgeError("HNS wallet database was not created")
    return wallet_id, seed_fingerprint, phrase


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

    def is_running(self):
        """Report child liveness without sending a wallet request."""
        return not self._closed and self._process.poll() is None

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

    def change_passphrase(self, old_passphrase, new_passphrase):
        if not isinstance(old_passphrase, str) or not old_passphrase:
            raise ValueError("invalid old HNS wallet passphrase")
        if not isinstance(new_passphrase, str) or not new_passphrase:
            raise ValueError("invalid new HNS wallet passphrase")
        result = self._request(
            "change_passphrase",
            old_passphrase=old_passphrase,
            new_passphrase=new_passphrase,
        )
        if result != {"changed": True, "unlocked": False}:
            raise HnsWalletBridgeError("invalid HNS passphrase change result")

    def lock(self):
        result = self._request("lock")
        if result != {"unlocked": False}:
            raise HnsWalletBridgeError("invalid HNS lock result")

    def sync(self):
        result = self._request("sync")
        if result != {"synchronized": True}:
            raise HnsWalletBridgeError("invalid HNS synchronization result")

    def identity(self, expected_network):
        if expected_network not in ("mainnet", "testnet", "regtest", "simnet"):
            raise ValueError("invalid HNS wallet network")
        result = self._request("identity")
        if set(result) != {"wallet_id", "seed_fingerprint", "network"}:
            raise HnsWalletBridgeError("invalid HNS wallet identity")
        if result["network"] != expected_network:
            raise HnsWalletBridgeError("HNS wallet network mismatch")
        return (
            _wire_bytes(result["wallet_id"], 16, "wallet ID"),
            _wire_bytes(result["seed_fingerprint"], 32, "seed fingerprint"),
        )

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

    def prepare_send(self, network, recipient, amount, maximum_fee):
        """Hold one Rust approval and return the exact native send summary."""
        try:
            decoded = decode_v0_address(network, recipient)
        except ValueError as exc:
            raise ValueError("invalid HNS send address") from exc
        if len(decoded.program) not in (20, 32):
            raise ValueError("invalid HNS send address")
        result = self._request(
            "prepare_send",
            recipient=recipient,
            amount=_positive_integer(amount, "HNS send amount", 0xFFFFFFFFFFFFFFFF),
            maximum_fee=_positive_integer(
                maximum_fee, "maximum HNS send fee", 0xFFFFFFFFFFFFFFFF
            ),
        )
        if set(result) != {
            "token",
            "recipient",
            "amount",
            "maximum_fee",
            "expires_at_unix",
        }:
            raise HnsWalletBridgeError("invalid HNS send approval")
        token = _wire_bytes(result["token"], 16, "send token")
        if (
            result["recipient"] != recipient
            or result["amount"] != str(amount)
            or result["maximum_fee"] != str(maximum_fee)
            or type(result["expires_at_unix"]) is not int
            or result["expires_at_unix"] <= 0
        ):
            raise HnsWalletBridgeError("HNS send approval differs from request")
        return token.hex(), recipient, amount, maximum_fee, result["expires_at_unix"]

    def approve_send(self, token):
        result = self._request("approve_send", token=_hex_bytes(token, 16, "send token"))
        if set(result) != {"transaction_id"}:
            raise HnsWalletBridgeError("invalid HNS send receipt")
        return _wire_bytes(result["transaction_id"], 32, "send transaction ID").hex()

    def reject_send(self, token):
        result = self._request("reject_send", token=_hex_bytes(token, 16, "send token"))
        if result != {"rejected": True}:
            raise HnsWalletBridgeError("invalid HNS send rejection")

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

    @staticmethod
    def _submitted_transaction(result):
        if set(result) != {"transaction_id"}:
            raise HnsWalletBridgeError("invalid HNS submitted transaction result")
        transaction_id = result["transaction_id"]
        if transaction_id is None:
            return None
        return _wire_bytes(transaction_id, 32, "submitted transaction ID")

    def submitted_funding(self, terms):
        """Recover a submitted lock without authorizing a new funding action."""
        return self._submitted_transaction(
            self._request("submitted_funding", terms=terms.as_wire())
        )

    def submitted_spend(self, terms, funding_id, refund):
        """Recover a submitted spend without authorizing a new redeem/refund."""
        if type(refund) is not bool:
            raise ValueError("invalid HNS spend branch")
        return self._submitted_transaction(
            self._request(
                "submitted_spend",
                terms=terms.as_wire(),
                funding_id=_hex_bytes(funding_id, 32, "funding ID"),
                refund=refund,
            )
        )

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
