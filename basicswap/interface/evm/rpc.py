# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Thin web3 JSON-RPC client for the EVM interface.

Wraps one or more HTTP endpoints and provides read helpers plus EIP-1559
contract-transaction signing with a locally held private key.  Hardware-wallet
signing (Ledger/Trezor) is out of scope for the initial integration.
"""

import logging

import requests

from eth_account.typed_transactions import TypedTransaction
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import TransactionNotFound
from web3.providers import JSONBaseProvider

from basicswap.util import TemporaryError

for _name in ("web3", "urllib3"):
    logging.getLogger(_name).setLevel(logging.WARNING)


class EthRpcError(Exception):
    pass


def _endpointDown(e: Exception) -> bool:
    if isinstance(e, (requests.ConnectionError, requests.Timeout)):
        return True
    if isinstance(e, requests.HTTPError) and e.response is not None:
        return e.response.status_code >= 500 or e.response.status_code == 429
    return False


class WrongChainError(Exception):
    pass


class FailoverProvider(JSONBaseProvider):
    """Sends each request to the current endpoint, moving on while it is down.

    With chain_id set, an endpoint is used only once it reports that chain.
    """

    def __init__(self, providers, on_switch=None, chain_id=None, on_reject=None):
        super().__init__()
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

    def is_connected(self, show_traceback: bool = False) -> bool:
        return any(p.is_connected(show_traceback) for p in self.providers)


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
        providers = []
        for url, proxy in endpoints:
            request_kwargs = {"timeout": timeout}
            if proxy:
                request_kwargs["proxies"] = {"http": proxy, "https": proxy}
            providers.append(Web3.HTTPProvider(url, request_kwargs=request_kwargs))
        self.w3 = Web3(FailoverProvider(providers, on_switch, chain_id, on_reject))

    # --- connection / chain ---

    def is_connected(self) -> bool:
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    def get_block_number(self) -> int:
        return self.w3.eth.block_number

    def get_block_time(self) -> int:
        return self.w3.eth.get_block("latest")["timestamp"]

    def client_version(self) -> str:
        return self.w3.client_version.splitlines()[0]

    def get_balance(self, address: str) -> int:
        return self.w3.eth.get_balance(Web3.to_checksum_address(address))

    def get_transaction_count(self, address: str, block="latest") -> int:
        return self.w3.eth.get_transaction_count(
            Web3.to_checksum_address(address), block
        )

    def gas_price(self) -> int:
        return self.w3.eth.gas_price

    def _baseAndTip(self, capped: bool = True) -> tuple:
        """Raises TemporaryError while the fee needed now is above max_fee_per_gas."""
        tip: int = (
            self.w3.eth.max_priority_fee
            if self.priority_fee is None
            else self.priority_fee
        )
        base: int = self.w3.eth.fee_history(1, "latest")["baseFeePerGas"][-1]
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
        tx = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
        base, tip = self._baseAndTip(capped=False)
        if tx["maxFeePerGas"] >= base + tip and tx["maxPriorityFeePerGas"] >= tip:
            return None
        return {
            "maxFeePerGas": max(2 * base + tip, tx["maxFeePerGas"] * 9 // 8 + 1),
            "maxPriorityFeePerGas": max(tip, tx["maxPriorityFeePerGas"] * 9 // 8 + 1),
        }

    def resign(self, raw: bytes, private_key, fees: dict):
        """raw at the same nonce with new fees; returns (tx hash, raw tx, wei it needs)."""
        tx = TypedTransaction.from_bytes(HexBytes(raw)).as_dict()
        for field in ("type", "v", "r", "s"):
            tx.pop(field, None)
        tx.update(fees)
        return (
            *self._sign(tx, private_key),
            tx["gas"] * tx["maxFeePerGas"] + tx["value"],
        )

    # --- transactions ---

    def sign_function(
        self,
        fn,
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
        from_address = Web3.to_checksum_address(from_address)
        w3 = self.w3

        if gas_limit is None:
            try:
                estimated = fn.estimate_gas({"from": from_address, "value": value})
            except Exception as e:
                raise EthRpcError(self._describe_error(e, error_decoder))
            # estimate_gas can underestimate calls that transfer value (e.g. claim)
            gas_limit = (estimated * 5) // 4

        tx_params = {
            "chainId": self.chain_id,
            "nonce": nonce,
            "from": from_address,
            "value": value,
            "gas": gas_limit,
            **self.fee_params(capped),
        }
        txn = fn.build_transaction(tx_params)
        signed = w3.eth.account.sign_transaction(txn, private_key=private_key)
        return bytes(signed.hash), bytes(signed.raw_transaction)

    def _transfer(
        self, from_address: str, to: str, value: int, fees: dict, nonce: int
    ) -> dict:
        w3 = self.w3
        txn = {
            "chainId": self.chain_id,
            "nonce": nonce,
            "from": from_address,
            "to": Web3.to_checksum_address(to),
            "value": value,
            **fees,
        }
        try:
            txn["gas"] = w3.eth.estimate_gas(txn)
        except Exception as e:
            raise EthRpcError(self._describe_error(e))
        return txn

    def _sign(self, txn: dict, private_key):
        signed = self.w3.eth.account.sign_transaction(txn, private_key=private_key)
        return bytes(signed.hash), bytes(signed.raw_transaction)

    def sign_transfer(
        self, from_address: str, private_key, to: str, value: int, nonce: int
    ):
        """Sign a plain native-coin transfer; returns (tx hash, raw tx)."""
        from_address = Web3.to_checksum_address(from_address)
        return self._sign(
            self._transfer(from_address, to, value, self.fee_params(), nonce),
            private_key,
        )

    def sign_sweep(self, from_address: str, private_key, to: str, nonce: int):
        """Sign a transfer of the whole balance less its fee; returns (tx hash, raw tx, value)."""
        from_address = Web3.to_checksum_address(from_address)
        txn = self._transfer(from_address, to, 0, self.sweep_fee_params(), nonce)
        txn["value"] = self.get_balance(from_address) - txn["gas"] * txn["maxFeePerGas"]
        if txn["value"] <= 0:
            raise ValueError("Balance too small to pay the fee")
        return (*self._sign(txn, private_key), txn["value"])

    def broadcast(self, tx_hash: bytes, raw: bytes, error_decoder=None) -> None:
        """Raises EthRpcError if the node neither accepts the tx nor has seen it."""
        try:
            self.w3.eth.send_raw_transaction(raw)
        except Exception as e:
            if self._find_transaction(tx_hash) is None:
                raise EthRpcError(self._describe_error(e, error_decoder))

    def wait_receipt(
        self,
        tx_hash: bytes,
        poll_latency: float = 0.1,
        timeout: int = 120,
        error_decoder=None,
    ):
        """Raises EthRpcError if the tx reverted, and web3's TimeExhausted if it
        isn't mined within timeout."""
        w3 = self.w3
        receipt = w3.eth.wait_for_transaction_receipt(
            tx_hash, timeout=timeout, poll_latency=poll_latency
        )
        if receipt.get("status", 1) == 0:
            reason = self._replay_revert(
                w3.eth.get_transaction(tx_hash), receipt, error_decoder
            )
            raise EthRpcError(f"Transaction reverted ({reason})")
        return receipt

    def get_receipt(self, tx_hash: bytes):
        try:
            return self.w3.eth.get_transaction_receipt(tx_hash)
        except TransactionNotFound:
            return None

    def _find_transaction(self, tx_hash: bytes):
        try:
            return self.w3.eth.get_transaction(tx_hash)
        except TransactionNotFound:
            return None

    def _replay_revert(self, tx, receipt, error_decoder) -> str:
        # Re-execute the tx at its block to recover the revert reason.
        try:
            call_tx = {
                "from": tx["from"],
                "to": tx["to"],
                "data": tx["input"],
                "value": tx["value"],
            }
            self.w3.eth.call(call_tx, receipt["blockNumber"] - 1)
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
