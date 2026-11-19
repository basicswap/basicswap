# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Base interface for EVM-native-currency coins in basicswap.

An EVM coin is account-based (like XMR) and is the "script/escrow coin" of an
EVM_XMR_SWAP: swap funds are escrowed in the SwapCreator contract rather than a
UTXO script.  This base manages an EVM account (HD-derived from the basicswap
seed), connects to an external JSON-RPC node via web3, and wraps the contract.

Concrete coins (ETH, and further EVM chains) subclass EVMInterface and provide
only their identity: coin_type(), ticker_str(), COIN() and per-network
chainparams.  Everything else here is chain-agnostic.
"""

import logging
import time

from enum import IntEnum
from urllib.parse import urlparse

import requests

from eth_abi import decode as abi_decode, encode as abi_encode
from eth_account import Account
from eth_utils import function_signature_to_4byte_selector
from eth_account.signers.local import LocalAccount
from web3 import Web3
from web3.exceptions import ProviderConnectionError, Web3RPCError

from basicswap.db import EvmSignedTx, EvmWalletTx
from basicswap.interface.base import CoinInterface, Curves
from basicswap.interface.evm.rpc import EthRpcClient, EthRpcError
from basicswap.interface.evm.swapcreator import SwapCreator
from basicswap.util import TemporaryError
from basicswap.util.network import is_private_ip_address


class EvmTxStates(IntEnum):
    PENDING = 0
    MINED = 1
    DROPPED = 2  # reverted, or its nonce went to none of its versions


def normaliseNodes(entries) -> list:
    """{url, failover} dicts from settings; a bare url string fails over."""
    nodes = []
    seen = set()
    for entry in entries or []:
        if isinstance(entry, str):
            url, failover = entry.strip(), True
        elif isinstance(entry, dict):
            url, failover = str(entry.get("url", "")).strip(), entry.get(
                "failover", True
            )
        else:
            continue
        if url and url not in seen:
            seen.add(url)
            nodes.append({"url": url, "failover": bool(failover)})
    return nodes


def nodesWithSelected(entries, rpc_url: str) -> list:
    """The node list, with the node in use added if it's missing."""
    nodes = normaliseNodes(entries)
    if rpc_url and rpc_url not in (n["url"] for n in nodes):
        nodes.insert(0, {"url": rpc_url, "failover": True})
    return nodes


def validateRpcUrl(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"RPC URL needs a scheme and host, e.g. https://{url.strip()}")
    if parsed.scheme == "http" and not is_private_ip_address(parsed.hostname):
        raise ValueError(f"Use https for a public RPC node: {url.strip()}")
    return url.strip()


class EVMInterface(CoinInterface):
    @staticmethod
    def curve_type():
        # EVM accounts use secp256k1; swap keys come from the XMR side's
        # DLEAG, so this derives from the generic CoinInterface rather than
        # Secp256k1Interface.
        return Curves.secp256k1

    # Amounts in BasicSwap are 8-decimal so they fit SQLite and message ints
    WEI_PER_UNIT = 10**10

    @staticmethod
    def exp() -> int:
        return 8

    @staticmethod
    def nbk() -> int:
        return 32

    @staticmethod
    def nbK() -> int:
        return 32

    def __init__(self, coin_settings, network, swap_client=None, **kwargs):
        super().__init__(network, **kwargs)
        self._swap_client = swap_client
        self._log = swap_client.log if swap_client and swap_client.log else logging

        self.blocks_confirmed = coin_settings.get("blocks_confirmed", 4)
        self.setConfTarget(coin_settings.get("conf_target", 2))
        self._connection_type = coin_settings.get("connection_type", "web3")
        self._use_segwit = coin_settings.get("use_segwit", False)
        self._chain_id = coin_settings.get(
            "chain_id", self.chainparams_network().get("chain_id")
        )
        self._deployment = self.chainparams()["deployments"].get(self._chain_id, {})
        self._blocklist = self.chainparams().get("blocklist", {}).get(self._chain_id)
        self._blocklist_function = self.chainparams().get("blocklist_function")
        self._contract_address = coin_settings.get(
            "contract_address", self._deployment.get("address")
        )

        rpchost = coin_settings.get("rpchost", "127.0.0.1")
        rpcport = coin_settings.get("rpcport", self.chainparams_network()["rpcport"])
        self._rpc_url = coin_settings.get("rpc_url") or f"http://{rpchost}:{rpcport}"
        self._nodes = normaliseNodes(coin_settings.get("remote_daemon_urls", []))
        self._auto_select: bool = coin_settings.get("automatically_select_daemon", True)
        self._rpctimeout = coin_settings.get("rpctimeout", 30)
        self._max_fee_per_gas = coin_settings.get(
            "max_fee_per_gas", self.MAX_FEE_PER_GAS
        )

        self._rpc = None
        self._account = None
        self._account_index: int = coin_settings.get("account", 0)
        self._contract = None

    # --- connection ---

    @property
    def rpc(self) -> EthRpcClient:
        if self._rpc is None:
            self._rpc = EthRpcClient(
                [(url, self._rpcProxy(url)) for url in self.rpcUrls()],
                timeout=self._rpctimeout,
                max_fee_per_gas=self._max_fee_per_gas,
                priority_fee=self.PRIORITY_FEE,
                on_switch=self._onNodeSwitch,
                chain_id=self._chain_id,
                on_reject=self._onNodeRejected,
            )
        return self._rpc

    def is_transient_error(self, ex) -> bool:
        """Node trouble: rate limits, a lagging node, an unreachable one."""
        if isinstance(
            ex, (requests.RequestException, ProviderConnectionError, Web3RPCError)
        ):
            return True
        return super().is_transient_error(ex)

    def _onNodeRejected(self, error) -> None:
        self._log.error(f"{self.coin_name()} node not used: {error}")

    def rpcUrls(self) -> list:
        """The selected node first, then the failover nodes if auto-select is on."""
        urls = [self._rpc_url]
        if self._auto_select:
            urls += [
                n["url"]
                for n in self._nodes
                if n["failover"] and n["url"] != self._rpc_url
            ]
        return urls

    def _onNodeSwitch(self, url: str, error) -> None:
        self._log.warning(
            f"{self.coin_name()} node unreachable ({error}), using {urlparse(url).hostname}."
        )

    def testNode(self, url: str) -> int:
        """Block height at url, through the same proxy the coin would use."""
        url = validateRpcUrl(url)
        proxy = self._rpcProxy(url, log=False)
        rpc = EthRpcClient([(url, proxy)], timeout=10, chain_id=self._chain_id)
        return rpc.get_block_number()

    def _rpcProxy(self, url: str, log: bool = True):
        sc = self._swap_client
        if sc is None or not sc.use_tor_proxy:
            return None
        host = urlparse(url).hostname or ""
        cc_use_tor = sc.getChainClientSettings(self.coin_type()).get("use_tor")
        if cc_use_tor is False:
            reason = f"bypassing proxy (use_tor false for {self.coin_name()})"
            proxy = None
        elif cc_use_tor is None and is_private_ip_address(host):
            reason = "bypassing proxy (private ip address)"
            proxy = None
        else:
            # socks5h so the node's hostname is resolved through tor too
            proxy = f"socks5h://{sc.tor_proxy_host}:{sc.tor_proxy_port}"
            reason = f"through proxy at {sc.tor_proxy_host}"
        if log:
            self._log.info(f"Connecting to {self.coin_name()} node at {host} {reason}.")
        return proxy

    def getContractAddress(self) -> str:
        if self._contract_address is None:
            raise ValueError("No swap contract address configured")
        return self._contract_address

    def usesContract(self, address: str) -> bool:
        return (
            self._contract_address is not None
            and address.lower() == self._contract_address.lower()
        )

    def getContract(self, address=None) -> SwapCreator:
        address = address or self.getContractAddress()
        if (
            self._contract is None
            or self._contract.address.lower() != str(address).lower()
        ):
            contract = SwapCreator(self.rpc, address)
            code_hashes = self._deployment.get("code_hashes")
            if code_hashes is not None and contract.code_hash() not in code_hashes:
                raise ValueError(f"No SwapCreator at {contract.address}")
            if not contract.verifies_secrets():
                raise ValueError(
                    f"SwapCreator at {contract.address} fails its secret check"
                )
            self._contract = contract
        return self._contract

    def isBlocked(self, address: str) -> bool:
        """On the chain's issuer blocklist; False on chains without one."""
        if self._blocklist is None:
            return False
        data = function_signature_to_4byte_selector(
            self._blocklist_function
        ) + abi_encode(["address"], [address])
        result = self.rpc.w3.eth.call({"to": self._blocklist, "data": data})
        return abi_decode(["bool"], result)[0]

    def getMaxFeePerGas(self):
        return self._max_fee_per_gas

    def setMaxFeePerGas(self, max_fee_per_gas) -> None:
        """None restores the chain's default cap."""
        self._max_fee_per_gas = (
            self.MAX_FEE_PER_GAS if max_fee_per_gas is None else max_fee_per_gas
        )
        if self._rpc is not None:
            self._rpc.max_fee_per_gas = self._max_fee_per_gas

    def setRpcUrl(self, rpc_url: str) -> None:
        # The cached contract holds the old client too
        self._rpc_url = rpc_url
        self._rpc = None
        self._contract = None

    def setNodes(self, nodes, auto_select: bool) -> None:
        self._nodes = normaliseNodes(nodes)
        self._auto_select = auto_select
        self._rpc = None
        self._contract = None

    # --- wallet / account ---

    def initialiseWallet(self, key_bytes: bytes, restore_time: int = -1) -> None:
        # key_bytes is the seed root, which identifies the seed but is never an account
        self._deriveAccount()

    def setActiveAccount(self, private_key) -> None:
        """Import a raw private key (e.g. an anvil test account)."""
        self._account = Account.from_key(private_key)

    def getAccountIndex(self) -> int:
        return self._account_index

    def setAccountIndex(self, index: int) -> None:
        self._account_index = index
        self._account = None

    def onMainnetChain(self) -> bool:
        # By chain id, as a mainnet instance can be pointed at a test chain
        return self._chain_id == self.chainparams()["mainnet"]["chain_id"]

    def accountKey(self, index: int) -> bytes:
        sc = self._swap_client
        coin: int = int(self.coin_type())
        # Hardened, so no other account's key follows from this one
        if self.onMainnetChain():
            return sc.getWalletKeyAtPath(f"44445555h/1h/{coin}h/{index}h")
        # Test chains never share a key with mainnet or each other
        return sc.getWalletKeyAtPath(f"44445555h/2h/{coin}h/{self._chain_id}h/{index}h")

    def _deriveAccount(self) -> LocalAccount:
        # The EVM wallet has no separate keystore: the signing key is derived on
        # demand from the basicswap (Particl) seed, which requires the Particl
        # wallet to be unlocked.
        if self._swap_client is None:
            raise ValueError("EVM wallet account not initialised")
        self._account = Account.from_key(self.accountKey(self._account_index)[:32])
        self.setWalletSeedWarning(False)
        return self._account

    @property
    def account(self) -> LocalAccount:
        if self._account is None:
            return self._deriveAccount()
        return self._account

    # --- wallet lock / password ---
    #
    # An EVM coin holds no independent encrypted keystore; the key is derived
    # from the Particl seed, so lock/unlock/password state tracks the Particl
    # wallet.

    def unlockWallet(
        self,
        password: str,
        check_seed: bool = True,
        encrypt_if_unencrypted: bool = False,
    ) -> None:
        # Deriving the account requires the Particl wallet to be unlocked, which
        # unlockWallets() guarantees before this is reached.
        try:
            self._deriveAccount()
        except Exception as e:
            self._log.debug(f"EVM unlockWallet deferred account derivation: {e}")

    def lockWallet(self) -> None:
        self._account = None

    def changeWalletPassword(
        self, old_password, new_password, check_seed_if_encrypt: bool = True
    ) -> None:
        # No separate EVM keystore password to change.
        return

    def isWalletEncryptedLocked(self):
        # Mirror the Particl wallet state; an EVM coin has no independent lock.
        if self._swap_client is not None:
            try:
                return self._swap_client.getLockedState()
            except Exception:
                pass
        return False, False

    def getSeedHash(self, seed: bytes, length: int = 20) -> bytes:
        # Seed id for the wallet is its derived account address bytes.

        acct = Account.from_key(seed[:32])
        return bytes(Web3.to_bytes(hexstr=acct.address))

    def getWalletSeedID(self) -> str:
        return self.getSeedHash(
            self._swap_client.getWalletKey(self.coin_type(), 1)
        ).hex()

    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        try:
            return expect_seedid == self.getWalletSeedID()
        except Exception:
            return False

    def getNewAddress(self, placeholder=None) -> str:
        # An EVM coin reuses a single account address.
        return self.account.address

    def withdrawCoin(self, value, addr_to: str, subfee: bool) -> str:
        """Send value (whole coins) to addr_to; returns the txid without waiting for it to be mined."""
        if not self.isValidAddress(addr_to):
            raise ValueError(f"Invalid address: {addr_to}")
        value_wei: int = self.toWei(self.make_int(value))
        sent = {}

        if subfee and self.make_int(value) >= self.getSpendableBalance():

            def sign(nonce):
                tx_hash, raw, sent["wei"] = self.rpc.sign_sweep(
                    self.account.address, self.account.key, addr_to, nonce
                )
                return tx_hash, raw

        else:
            if subfee:
                value_wei -= self.withdrawFeeWei()
                if value_wei <= 0:
                    raise ValueError("Amount too small to pay the fee")
            sent["wei"] = value_wei

            def sign(nonce):
                return self.rpc.sign_transfer(
                    self.account.address, self.account.key, addr_to, value_wei, nonce
                )

        handle = self.sendTx(sign, "withdraw", wait=False)
        self.recordTx(handle, "withdraw", -self.fromWei(sent["wei"]), to_addr=addr_to)
        return handle.hex()

    def isValidAddress(self, address: str) -> bool:
        try:

            return Web3.is_address(address)
        except Exception:
            return False

    def isAddressMine(self, address: str, *args, **kwargs) -> bool:
        return (
            self._account is not None
            and address.lower() == self.account.address.lower()
        )

    # --- chain / balance ---

    def getChainHeight(self) -> int:
        return self.rpc.get_block_number()

    def testDaemonRPC(self, with_wallet: bool = True) -> None:
        self.rpc.get_block_number()

    def getDaemonVersion(self):
        return self.rpc.client_version()

    def checkWallets(self) -> int:
        return 1

    def getBlockchainInfo(self):
        blocks = self.rpc.get_block_number()
        return {
            "chain": self._network,
            "blocks": blocks,
            # An EVM node has no notion of local sync progress from a single
            # JSON-RPC query here; treat a reachable node as fully synced.
            "verificationprogress": 1.0,
        }

    def getWalletInfo(self):
        encrypted, locked = self.isWalletEncryptedLocked()
        # Resolve the account address first; it only needs the (unlocked)
        # Particl seed, not the JSON-RPC node.
        try:
            address = self.account.address
        except Exception as e:
            self._log.debug(f"EVM account not available: {e}")
            address = ""

        balance = self.fromWei(self.rpc.get_balance(address)) if address else 0

        return {
            "address": address,
            "balance": self.format_amount(balance),
            "unconfirmed_balance": self.format_amount(0),
            "encrypted": encrypted,
            "locked": locked,
        }

    # Seconds sendTx waits for a receipt; swap actions call it holding the DB
    # lock, and a later call picks the receipt up
    RECEIPT_WAIT = 1
    # Gas used by a plain value transfer (the withdraw path).
    WITHDRAW_GAS = 21000
    # Gas swap txs are sent with; chains that bill L1 data in gas need more
    CLAIM_GAS = 60000
    LOCK_GAS = 60000
    READY_GAS = 40000
    # The gas drip covers a claim at this multiple of the gas price
    DRIP_GAS_PRICE_MULTIPLE = 2
    # Kept per open swap so its refund can be sent and bumped through a spike,
    # priced at the higher of this multiple of the gas price and the fee cap
    REFUND_GAS = 60000
    REFUND_RESERVE_PRICE_MULTIPLE = 4
    # Highest maxFeePerGas to sign, in wei; None for no cap
    MAX_FEE_PER_GAS = None
    # Tip per gas, in wei; None takes the node's suggestion
    PRIORITY_FEE = None

    def get_fee_rate(self, conf_target: int = 2):
        """Return (fee_rate, source).

        fee_rate is the gas price expressed in coin per gas unit, so a withdraw
        estimate is simply fee_rate * gas_used (see estimateWithdrawFee).
        """
        chain_client_settings = (
            self._swap_client.getChainClientSettings(self.coin_type())
            if self._swap_client
            else {}
        )
        override_feerate = chain_client_settings.get("override_feerate", None)
        if override_feerate:
            self._log.debug(
                f"Fee rate override used for {self.coin_name()}: {override_feerate}"
            )
            return override_feerate, "override_feerate"

        try:
            gas_price_wei = self.rpc.gas_price()
        except Exception as e:
            self._log.debug(f"EVM gas_price unavailable: {e}")
            gas_price_wei = 0
        return gas_price_wei / (self.COIN() * self.WEI_PER_UNIT), "gas_price"

    def withdrawFeeWei(self) -> int:
        """Most a plain transfer can cost at the capped fee."""
        return self.WITHDRAW_GAS * self.rpc.fee_params()["maxFeePerGas"]

    def dripGasCost(self, gas_price: int = None) -> int:
        """Wei the gas drip sends for one claim."""
        if gas_price is None:
            gas_price = self.rpc.gas_price()
        return self.CLAIM_GAS * gas_price * self.DRIP_GAS_PRICE_MULTIPLE

    def refundReserve(self, gas_price: int = None) -> int:
        """Coin units kept back per open swap where we're the EVM side."""
        if gas_price is None:
            gas_price = self.rpc.gas_price()
        price: int = max(
            gas_price * self.REFUND_RESERVE_PRICE_MULTIPLE,
            self.MAX_FEE_PER_GAS or 0,
        )
        return self.fromWei(self.REFUND_GAS * price, round_up=True)

    def estClaimFee(self) -> int:
        """Fee to claim a swap's escrow, in coin units."""
        return self.fromWei(self.CLAIM_GAS * self.rpc.gas_price(), round_up=True)

    def estSwapFee(
        self,
        lock: bool = True,
        ready: bool = True,
        drip: bool = True,
        gas_price: int = None,
    ) -> int:
        """Fee the EVM side pays on a completed swap: newSwap, setReady and the gas
        drip; each flag set False leaves out a part already paid."""
        if gas_price is None:
            gas_price = self.rpc.gas_price()
        gas: int = (self.LOCK_GAS if lock else 0) + (self.READY_GAS if ready else 0)
        wei: int = gas * gas_price
        if drip:
            wei += self.WITHDRAW_GAS * gas_price + self.dripGasCost(gas_price)
        return self.fromWei(wei, round_up=True)

    def toWei(self, amount: int) -> int:
        return amount * self.WEI_PER_UNIT

    def fromWei(self, wei: int, round_up: bool = False) -> int:
        return -(-wei // self.WEI_PER_UNIT) if round_up else wei // self.WEI_PER_UNIT

    def _receiptFee(self, receipt) -> int:
        return self.fromWei(
            receipt["gasUsed"] * receipt["effectiveGasPrice"], round_up=True
        )

    # --- signed txs ---

    def _signedTxs(self, cursor, **constraints) -> list:
        return list(
            self._swap_client.query(
                EvmSignedTx,
                cursor,
                {
                    "coin_type": int(self.coin_type()),
                    "address": self.account.address,
                    **constraints,
                },
                order_by={"record_id": "asc"},
            )
        )

    def _setTxState(self, handle: bytes, state: int, cursor) -> None:
        cursor.execute(
            "UPDATE evm_signed_txs SET state = :state WHERE handle = :handle",
            {"state": int(state), "handle": handle},
        )

    def _minedReceipt(self, handle: bytes, cursor):
        """Receipt of whichever version of handle was mined, or None; settles its state."""
        for row in self._signedTxs(cursor, handle=handle):
            receipt = self.rpc.get_receipt(row.txid)
            if receipt is not None:
                state = (
                    EvmTxStates.MINED if receipt["status"] == 1 else EvmTxStates.DROPPED
                )
                self._setTxState(handle, state, cursor)
                return receipt
        return None

    def _nonceTaken(self, nonce: int) -> bool:
        return self.rpc.get_transaction_count(self.account.address) > nonce

    def _signedTxRow(self, nonce, handle, txid, raw, kind, bid_id, bump_at):
        return EvmSignedTx(
            coin_type=int(self.coin_type()),
            address=self.account.address,
            nonce=nonce,
            handle=handle,
            txid=txid,
            raw=raw,
            kind=kind,
            bid_id=bid_id,
            bump_at=bump_at,
            state=EvmTxStates.PENDING,
            created_at=int(time.time()),
        )

    def _nextNonce(self, cursor) -> int:
        """Past every unmined tx we signed, as a node may have dropped one."""
        nonce: int = self.rpc.get_transaction_count(self.account.address, "pending")
        for row in self._signedTxs(cursor, state=EvmTxStates.PENDING):
            nonce = max(nonce, row.nonce + 1)
        return nonce

    def receiptFor(self, handle: bytes):
        """Receipt of whichever version of the tx handle names was mined, or None."""
        sc = self._swap_client
        cursor = sc.openDB()
        try:
            return self._minedReceipt(handle, cursor) or self.rpc.get_receipt(handle)
        finally:
            sc.closeDB(cursor)

    def sendTx(
        self,
        sign,
        kind: str,
        bid_id: bytes = None,
        bump_at: int = None,
        wait: bool = True,
        error_decoder=None,
    ):
        """Broadcast the tx for bid_id and kind, signing it only if none was sent or
        the last was dropped; returns its receipt, or its handle without wait.

        sign(nonce) returns (tx hash, raw tx). bump_at is the chain time from which
        bumpTxs re-signs it. Raises TimeExhausted while unmined, TemporaryError while
        its nonce is used but no version has a receipt, and EthRpcError if it
        reverted or the node refused it; a later call then signs it again.
        """
        sc = self._swap_client
        cursor = sc.openDB()
        try:
            rows = (
                self._signedTxs(cursor, bid_id=bid_id, kind=kind)
                if bid_id is not None
                else []
            )
            row = rows[-1] if rows and rows[-1].state != EvmTxStates.DROPPED else None
            if row is not None:
                # Nonce first: a tx mined between the two reads must not look dropped
                taken: bool = self._nonceTaken(row.nonce)
                receipt = self._minedReceipt(row.handle, cursor)
                if receipt is not None and receipt["status"] == 1:
                    return receipt if wait else row.handle
                if receipt is not None:
                    row = None
                elif taken:
                    # bumpTxs settles it on a later pass, so one lagging answer
                    # can't re-sign a mined tx
                    raise TemporaryError(
                        f"{self.coin_name()} {kind} nonce {row.nonce} used, no receipt yet"
                    )
                elif bump_at is not None and bump_at != row.bump_at:
                    cursor.execute(
                        "UPDATE evm_signed_txs SET bump_at = :bump_at WHERE handle = :handle",
                        {"bump_at": bump_at, "handle": row.handle},
                    )
            fresh: bool = row is None
            if fresh:
                nonce: int = self._nextNonce(cursor)
                txid, raw = sign(nonce)
                row = self._signedTxRow(nonce, txid, txid, raw, kind, bid_id, bump_at)
                sc.add(row, cursor)
        finally:
            sc.closeDB(cursor)

        try:
            self.rpc.broadcast(row.txid, row.raw, error_decoder)
        except EthRpcError:
            if fresh:
                cursor = sc.openDB()
                try:
                    self._setTxState(row.handle, EvmTxStates.DROPPED, cursor)
                finally:
                    sc.closeDB(cursor)
            raise
        if not wait:
            return row.handle
        return self.rpc.wait_receipt(
            row.txid, timeout=self.RECEIPT_WAIT, error_decoder=error_decoder
        )

    def bumpTxs(self) -> None:
        """Once an unmined tx is past its bump time, re-sign it and every unmined
        tx below it at the price now; rebroadcast the rest."""
        sc = self._swap_client
        cursor = sc.openDB()
        try:
            rows = self._signedTxs(cursor, state=EvmTxStates.PENDING)
            if not rows:
                return
            taken: int = self.rpc.get_transaction_count(self.account.address)
            newest = {}
            settled = set()
            for row in rows:
                if row.nonce >= taken:
                    newest[row.nonce] = row
                elif row.handle not in settled:
                    settled.add(row.handle)
                    if self._minedReceipt(row.handle, cursor) is None:
                        self._setTxState(row.handle, EvmTxStates.DROPPED, cursor)

            now: int = self.rpc.get_block_time()
            top: int = max(
                (
                    n
                    for n, r in newest.items()
                    if r.bump_at is not None and now >= r.bump_at
                ),
                default=-1,
            )
            balance = None
            expect: int = taken
            for nonce in sorted(newest):
                row = newest[nonce]
                if nonce <= top and nonce != expect:
                    self._log.warning(
                        f"{self.coin_name()} nonce {expect} is not ours, can't bump past it."
                    )
                    top = -1
                expect = nonce + 1
                fees = self.rpc.replacement_fees(row.raw) if nonce <= top else None
                if fees is not None:
                    txid, raw, cost = self.rpc.resign(row.raw, self.account.key, fees)
                    if balance is None:
                        balance = self.rpc.get_balance(self.account.address)
                    if cost > balance:
                        self._log.warning(
                            f"{self.coin_name()} balance too low to bump {row.kind} "
                            f"{row.handle.hex()} (needs {cost} wei)."
                        )
                        top = -1
                    else:
                        row = self._signedTxRow(
                            row.nonce,
                            row.handle,
                            txid,
                            raw,
                            row.kind,
                            row.bid_id,
                            row.bump_at,
                        )
                        sc.add(row, cursor)
                        sc.commitDB()
                        self._log.info(
                            f"{self.coin_name()} bumped {row.kind} {row.handle.hex()} "
                            f"at nonce {nonce} to {fees['maxFeePerGas']} wei/gas."
                        )
                try:
                    self.rpc.broadcast(row.txid, row.raw)
                except EthRpcError as e:
                    self._log.debug(
                        f"{self.coin_name()} rebroadcast {row.txid.hex()}: {e}"
                    )
        finally:
            sc.closeDB(cursor)

    def recordTx(
        self,
        txid: bytes,
        kind: str,
        amount: int,
        receipt=None,
        to_addr: str = None,
        bid_id: bytes = None,
        cursor=None,
    ) -> None:
        sc = self._swap_client
        txid = bytes(txid)
        use_cursor = sc.openDB(cursor)
        try:
            if sc.queryOne(
                EvmWalletTx,
                use_cursor,
                {"coin_type": int(self.coin_type()), "txid": txid},
            ):
                return
            row = EvmWalletTx(
                coin_type=int(self.coin_type()),
                txid=txid,
                kind=kind,
                amount=amount,
                address=self.account.address,
                to_addr=to_addr,
                bid_id=bid_id,
                created_at=int(time.time()),
            )
            if receipt is not None:
                row.block_height = receipt["blockNumber"]
                row.fee = self._receiptFee(receipt)
            sc.add(row, use_cursor)
        finally:
            if cursor is None:
                sc.closeDB(use_cursor)

    def listWalletTransactions(self, count=100, skip=0, include_watchonly=True):
        sc = self._swap_client
        cursor = sc.openDB()
        try:
            rows = list(
                sc.query(
                    EvmWalletTx,
                    cursor,
                    {
                        "coin_type": int(self.coin_type()),
                        "address": self.account.address,
                    },
                    order_by={"record_id": "desc"},
                    query_suffix=" LIMIT :count OFFSET :skip",
                    extra_query_data={"count": count, "skip": skip},
                )
            )[::-1]
        finally:
            sc.closeDB(cursor, commit=False)

        height = None
        mined = []
        try:
            height = self.getChainHeight()
            for row in rows:
                if row.block_height is None:
                    receipt = self.receiptFor(row.txid)
                    if receipt is not None:
                        row.block_height = receipt["blockNumber"]
                        row.fee = self._receiptFee(receipt)
                        mined.append(row)
        except Exception as e:
            self._log.debug(f"{self.coin_name()} tx confirmations unavailable: {e}")
        if mined:
            cursor = sc.openDB()
            try:
                for row in mined:
                    sc.updateDB(row, cursor, ["record_id"])
            finally:
                sc.closeDB(cursor)

        rv = [
            {
                "txid": row.txid.hex(),
                "category": "receive" if row.amount > 0 else "send",
                "amount": row.amount / self.COIN(),
                "fee": (row.fee or 0) / self.COIN(),
                "confirmations": (
                    0
                    if height is None or row.block_height is None
                    else height - row.block_height + 1
                ),
                "time": row.created_at,
                "address": row.to_addr or "",
                "kind": row.kind,
            }
            for row in rows
        ]
        return rv

    def getBalances(self) -> tuple[int, int]:
        balance: int = self.getSpendableBalance()
        return balance, balance

    def getSpendableBalance(self) -> int:
        return self.fromWei(self.rpc.get_balance(self.account.address))

    def ensureFunds(self, amount: int) -> None:
        if self.getSpendableBalance() < amount:
            raise ValueError("Balance too low")
