# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
JSON-RPC client for the EVM interface.

Wraps one or more HTTP endpoints and provides read helpers plus EIP-1559
transaction signing with a locally held private key.  Hardware-wallet
signing (Ledger/Trezor) is out of scope for the initial integration.
"""

import gzip
import json
import time
import urllib.error
import urllib.request

import rlp
import socks

from eth_keys import keys
from eth_utils import keccak, to_canonical_address, to_checksum_address
from sockshandler import SocksiPyHandler

from basicswap.util import TemporaryError

TX_TYPE_EIP1559 = b"\x02"
TX_FIELDS = (
    "chainId",
    "nonce",
    "maxPriorityFeePerGas",
    "maxFeePerGas",
    "gas",
    "to",
    "value",
    "data",
    "accessList",
)


class EthRpcError(Exception):
    pass


class RpcError(Exception):
    """An error response from the node."""

    def __init__(self, error: dict):
        super().__init__(error.get("message", str(error)))
        self.data = error.get("data")


class RevertError(RpcError):
    pass


class ReceiptTimeout(Exception):
    pass


def _endpointDown(e: Exception) -> bool:
    if isinstance(e, urllib.error.HTTPError):
        return e.code >= 500 or e.code == 429
    return isinstance(e, OSError)


def _hex(value) -> str:
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    return value


def _bytes(value: str) -> bytes:
    return bytes.fromhex(value[2:])


def _receipt(r: dict) -> dict:
    return {
        "transactionHash": _bytes(r["transactionHash"]),
        "blockNumber": int(r["blockNumber"], 16),
        "status": int(r["status"], 16),
        "gasUsed": int(r["gasUsed"], 16),
        "effectiveGasPrice": int(r["effectiveGasPrice"], 16),
        "contractAddress": r.get("contractAddress"),
        "logs": [
            {
                "address": to_checksum_address(log["address"]),
                "topics": [_bytes(t) for t in log["topics"]],
                "data": _bytes(log["data"]),
            }
            for log in r["logs"]
        ],
    }


def sign_tx(tx: dict, private_key: bytes):
    """EIP-1559 tx from TX_FIELDS; returns (tx hash, raw tx)."""
    to = tx.get("to")
    fields = [
        tx["chainId"],
        tx["nonce"],
        tx["maxPriorityFeePerGas"],
        tx["maxFeePerGas"],
        tx["gas"],
        to_canonical_address(to) if to else b"",
        tx["value"],
        bytes(tx.get("data", b"")),
        tx.get("accessList", []),
    ]
    unsigned: bytes = TX_TYPE_EIP1559 + rlp.encode(fields)
    sig = keys.PrivateKey(bytes(private_key)).sign_msg_hash(keccak(unsigned))
    raw: bytes = TX_TYPE_EIP1559 + rlp.encode(fields + [sig.v, sig.r, sig.s])
    return keccak(raw), raw


def decode_tx(raw: bytes) -> dict:
    """The TX_FIELDS of a raw EIP-1559 tx."""
    items = rlp.decode(bytes(raw)[1:])
    tx = dict(zip(TX_FIELDS, items))
    for name in ("chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gas"):
        tx[name] = int.from_bytes(tx[name], "big")
    tx["value"] = int.from_bytes(tx["value"], "big")
    return tx


class WrongChainError(Exception):
    pass


class HttpEndpoint:
    def __init__(self, url: str, proxy=None, timeout: int = 30):
        """proxy: (host, port) of a SOCKS5 proxy that resolves the host itself."""
        self.endpoint_uri = url
        self._timeout = timeout
        handlers = []
        if proxy is not None:
            handlers.append(SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, *proxy))
        self._opener = urllib.request.build_opener(*handlers)
        self._request_id = 0

    def make_request(self, method: str, params) -> dict:
        self._request_id += 1
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self._request_id,
                "method": method,
                "params": params,
            }
        ).encode()
        request = urllib.request.Request(
            self.endpoint_uri,
            body,
            {"Content-Type": "application/json", "User-Agent": "jsonrpc"},
        )
        with self._opener.open(request, timeout=self._timeout) as response:
            data: bytes = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
            return json.loads(data)

    def is_connected(self) -> bool:
        try:
            return "result" in self.make_request("web3_clientVersion", [])
        except Exception:
            return False


class FailoverProvider:
    """Sends each request to the current endpoint, moving on while it is down.

    With chain_id set, an endpoint is used only once it reports that chain.
    """

    def __init__(self, providers, on_switch=None, chain_id=None, on_reject=None):
        self.providers = providers
        self.current = 0
        self._on_switch = on_switch
        self._chain_id = chain_id
        self._on_reject = on_reject
        self._chain_ok = set()
        self._wrong_chain = {}

    def _checkChain(self, i: int) -> None:
        if self._chain_id is None or i in self._chain_ok:
            return
        if i not in self._wrong_chain:
            result = self.providers[i].make_request("eth_chainId", []).get("result")
            node_chain = None if result is None else int(result, 16)
            if node_chain == self._chain_id:
                self._chain_ok.add(i)
                return
            self._wrong_chain[i] = WrongChainError(
                f"{self.providers[i].endpoint_uri} is on chain {node_chain}, "
                f"not {self._chain_id}"
            )
            if self._on_reject:
                self._on_reject(self._wrong_chain[i])
        raise self._wrong_chain[i]

    def make_request(self, method, params):
        error = None
        for n in range(len(self.providers)):
            i = (self.current + n) % len(self.providers)
            try:
                self._checkChain(i)
                response = self.providers[i].make_request(method, params)
            except WrongChainError as e:
                error = e
                continue
            except Exception as e:
                if not _endpointDown(e):
                    raise
                error = e
                continue
            if i != self.current:
                self.current = i
                if self._on_switch:
                    self._on_switch(self.providers[i].endpoint_uri, error)
            return response
        raise error

    def is_connected(self) -> bool:
        return any(p.is_connected() for p in self.providers)


class EthRpcClient:
    def __init__(
        self,
        endpoints,
        timeout: int = 30,
        max_fee_per_gas: int = None,
        priority_fee: int = None,
        on_switch=None,
        chain_id: int = None,
        on_reject=None,
    ):
        """endpoints: (url, proxy or None) pairs, tried in order."""
        self.max_fee_per_gas = max_fee_per_gas
        self.priority_fee = priority_fee
        self.chain_id = chain_id
        self.provider = FailoverProvider(
            [HttpEndpoint(url, proxy, timeout) for url, proxy in endpoints],
            on_switch,
            chain_id,
            on_reject,
        )

    def request(self, method: str, params=()):
        """The result of method; raises RpcError (RevertError for a revert)."""
        response = self.provider.make_request(method, list(params))
        error = response.get("error")
        if error is not None:
            if "revert" in str(error.get("message", "")).lower():
                raise RevertError(error)
            raise RpcError(error)
        return response.get("result")

    # --- connection / chain ---

    def is_connected(self) -> bool:
        try:
            return self.provider.is_connected()
        except Exception:
            return False

    def get_block_number(self) -> int:
        return int(self.request("eth_blockNumber"), 16)

    def get_block(self, block="latest") -> dict:
        b = self.request("eth_getBlockByNumber", [_hex(block), False])
        return {"number": int(b["number"], 16), "timestamp": int(b["timestamp"], 16)}

    def get_block_time(self) -> int:
        return self.get_block()["timestamp"]

    def client_version(self) -> str:
        return self.request("web3_clientVersion").splitlines()[0]

    def get_balance(self, address: str) -> int:
        return int(self.request("eth_getBalance", [address, "latest"]), 16)

    def get_transaction_count(self, address: str, block="latest") -> int:
        return int(self.request("eth_getTransactionCount", [address, _hex(block)]), 16)

    def get_code(self, address: str) -> bytes:
        return _bytes(self.request("eth_getCode", [address, "latest"]))

    def eth_call(self, to: str, data: bytes, block="latest") -> bytes:
        return _bytes(
            self.request("eth_call", [{"to": to, "data": _hex(data)}, _hex(block)])
        )

    def get_logs(self, address: str, from_block: int, to_block: int, topics) -> list:
        """topics: bytes, or a list of bytes for any of them, per position."""
        logs = self.request(
            "eth_getLogs",
            [
                {
                    "address": address,
                    "fromBlock": _hex(from_block),
                    "toBlock": _hex(to_block),
                    "topics": [
                        (
                            [_hex(t) for t in topic]
                            if isinstance(topic, list)
                            else _hex(topic)
                        )
                        for topic in topics
                    ],
                }
            ],
        )
        return [{"topics": [_bytes(t) for t in log["topics"]]} for log in logs]

    def gas_price(self) -> int:
        return int(self.request("eth_gasPrice"), 16)

    def _baseAndTip(self, capped: bool = True) -> tuple:
        """Raises TemporaryError while the fee needed now is above max_fee_per_gas."""
        tip: int = (
            int(self.request("eth_maxPriorityFeePerGas"), 16)
            if self.priority_fee is None
            else self.priority_fee
        )
        history = self.request("eth_feeHistory", ["0x1", "latest", []])
        base: int = int(history["baseFeePerGas"][-1], 16)
        if (
            capped
            and self.max_fee_per_gas is not None
            and base + tip > self.max_fee_per_gas
        ):
            raise TemporaryError(
                f"Network fee {base + tip} wei/gas above the cap {self.max_fee_per_gas}"
            )
        return base, tip

    def _capFee(self, fee: int) -> int:
        return fee if self.max_fee_per_gas is None else min(fee, self.max_fee_per_gas)

    def fee_params(self, capped: bool = True) -> dict:
        """EIP-1559 fees with room for the base fee to double; only base fee plus tip is paid."""
        base, tip = self._baseAndTip(capped)
        return {
            "maxFeePerGas": self._capFee(2 * base + tip) if capped else 2 * base + tip,
            "maxPriorityFeePerGas": tip,
        }

    def sweep_fee_params(self) -> dict:
        """Fees paid in full, so a transfer of balance minus gas * fee empties the
        account: a tip equal to the cap means no refund. Covers one block of base
        fee rise."""
        base, tip = self._baseAndTip()
        fee: int = self._capFee(base * 9 // 8 + tip)
        return {"maxFeePerGas": fee, "maxPriorityFeePerGas": fee}

    def replacement_fees(self, raw: bytes):
        """Fees to re-sign raw with, uncapped: the price now and at least 1/8 above
        its own on both; None while it still pays the price now."""
        tx = decode_tx(raw)
        base, tip = self._baseAndTip(capped=False)
        if tx["maxFeePerGas"] >= base + tip and tx["maxPriorityFeePerGas"] >= tip:
            return None
        return {
            "maxFeePerGas": max(2 * base + tip, tx["maxFeePerGas"] * 9 // 8 + 1),
            "maxPriorityFeePerGas": max(tip, tx["maxPriorityFeePerGas"] * 9 // 8 + 1),
        }

    def resign(self, raw: bytes, private_key, fees: dict):
        """raw at the same nonce with new fees; returns (tx hash, raw tx, wei it needs)."""
        tx = decode_tx(raw)
        tx.update(fees)
        return (
            *sign_tx(tx, private_key),
            tx["gas"] * tx["maxFeePerGas"] + tx["value"],
        )

    # --- transactions ---

    def estimate_gas(self, txn: dict) -> int:
        return int(
            self.request(
                "eth_estimateGas",
                [
                    {
                        k: _hex(txn[k])
                        for k in ("from", "to", "value", "data")
                        if k in txn
                    }
                ],
            ),
            16,
        )

    def sign_call(
        self,
        to: str,
        data: bytes,
        from_address: str,
        private_key,
        nonce: int,
        value: int = 0,
        gas_limit: int = None,
        error_decoder=None,
        capped: bool = True,
    ):
        """Build and sign a contract call with the local key; returns (tx hash, raw tx).

        Raises EthRpcError with a decoded revert reason if gas estimation fails.
        """
        if gas_limit is None:
            try:
                estimated = self.estimate_gas(
                    {"from": from_address, "to": to, "value": value, "data": data}
                )
            except Exception as e:
                raise EthRpcError(self._describe_error(e, error_decoder))
            # estimate_gas can underestimate calls that transfer value (e.g. claim)
            gas_limit = (estimated * 5) // 4

        txn = {
            "chainId": self.chain_id,
            "nonce": nonce,
            "to": to,
            "value": value,
            "data": data,
            "gas": gas_limit,
            **self.fee_params(capped),
        }
        return sign_tx(txn, private_key)

    def _transfer(
        self, from_address: str, to: str, value: int, fees: dict, nonce: int
    ) -> dict:
        txn = {
            "chainId": self.chain_id,
            "nonce": nonce,
            "to": to,
            "value": value,
            **fees,
        }
        try:
            txn["gas"] = self.estimate_gas({"from": from_address, **txn})
        except Exception as e:
            raise EthRpcError(self._describe_error(e))
        return txn

    def sign_transfer(
        self, from_address: str, private_key, to: str, value: int, nonce: int
    ):
        """Sign a plain native-coin transfer; returns (tx hash, raw tx)."""
        return sign_tx(
            self._transfer(from_address, to, value, self.fee_params(), nonce),
            private_key,
        )

    def sign_sweep(self, from_address: str, private_key, to: str, nonce: int):
        """Sign a transfer of the whole balance less its fee; returns (tx hash, raw tx, value)."""
        txn = self._transfer(from_address, to, 0, self.sweep_fee_params(), nonce)
        txn["value"] = self.get_balance(from_address) - txn["gas"] * txn["maxFeePerGas"]
        if txn["value"] <= 0:
            raise ValueError("Balance too small to pay the fee")
        return (*sign_tx(txn, private_key), txn["value"])

    def broadcast(self, tx_hash: bytes, raw: bytes, error_decoder=None) -> None:
        """Raises EthRpcError if the node neither accepts the tx nor has seen it."""
        try:
            self.request("eth_sendRawTransaction", [_hex(raw)])
        except Exception as e:
            if self.get_transaction(tx_hash) is None:
                raise EthRpcError(self._describe_error(e, error_decoder))

    def wait_receipt(
        self,
        tx_hash: bytes,
        poll_latency: float = 0.1,
        timeout: int = 120,
        error_decoder=None,
    ):
        """Raises EthRpcError if the tx reverted, and ReceiptTimeout if it
        isn't mined within timeout."""
        deadline: float = time.monotonic() + timeout
        receipt = self.get_receipt(tx_hash)
        while receipt is None:
            if time.monotonic() >= deadline:
                raise ReceiptTimeout(f"Tx {bytes(tx_hash).hex()} not mined")
            time.sleep(poll_latency)
            receipt = self.get_receipt(tx_hash)
        if receipt["status"] == 0:
            reason = self._replay_revert(
                self.get_transaction(tx_hash), receipt, error_decoder
            )
            raise EthRpcError(f"Transaction reverted ({reason})")
        return receipt

    def get_receipt(self, tx_hash: bytes):
        r = self.request("eth_getTransactionReceipt", [_hex(tx_hash)])
        return None if r is None else _receipt(r)

    def get_transaction(self, tx_hash: bytes):
        """from, to, input and value of a tx the node knows, or None."""
        tx = self.request("eth_getTransactionByHash", [_hex(tx_hash)])
        if tx is None:
            return None
        return {
            "from": tx["from"],
            "to": tx["to"],
            "input": tx["input"],
            "value": int(tx["value"], 16),
        }

    def _replay_revert(self, tx, receipt, error_decoder) -> str:
        # Re-execute the tx at its block to recover the revert reason.
        try:
            call_tx = {
                "from": tx["from"],
                "to": tx["to"],
                "data": tx["input"],
                "value": _hex(tx["value"]),
            }
            self.request("eth_call", [call_tx, _hex(receipt["blockNumber"] - 1)])
            return "unknown"
        except Exception as e:
            return self._describe_error(e, error_decoder)

    def _describe_error(self, e, error_decoder=None) -> str:
        # Decode a contract custom-error revert if possible.
        if error_decoder is not None:
            data = self._error_data(e)
            if data:
                name = error_decoder(data)
                if name:
                    return f"reverted: {name}"
        return str(e)

    @staticmethod
    def _error_data(e):
        data = getattr(e, "data", None)
        return data if isinstance(data, (bytes, str)) and data != "0x" else None
