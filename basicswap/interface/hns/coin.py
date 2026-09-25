"""Handshake chain and wallet boundary for BasicSwap's native HNS protocol.

HSRD supplies authenticated, read-only chain evidence. A separate encrypted
hns-wallet-rs process owns HNS keys and value operations. The Bitcoin-style
CoinInterface value methods are deliberately absent; HNS trades must use the
HNS/BTC protocol and settlement controller.
"""

import logging
import os
import stat
from pathlib import Path

from basicswap.chainparams import Coins
from basicswap.interface.base import CoinInterface

from . import HNS_COIN, HNS_MAX_MONEY
from .address import decode_v0_address
from .node_rpc import HnsNodeRpc
from .wallet_bridge import HnsWalletBridge


def read_private_hsrd_authorization(path):
    if not isinstance(path, (str, os.PathLike)) or Path(path).is_symlink():
        raise ValueError("invalid HSRD authorization file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("invalid HSRD authorization file")
        if os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077):
            raise ValueError("HSRD authorization file must be private")
        contents = os.read(descriptor, 4098)
    finally:
        os.close(descriptor)
    if len(contents) > 4097:
        raise ValueError("HSRD authorization header exceeds limit")
    authorization = contents.decode("ascii").removesuffix("\n")
    # HnsNodeRpc validates the exact header before it can be sent to HSRD.
    return authorization


class HNSInterface(CoinInterface):
    @staticmethod
    def coin_type():
        return Coins.HNS

    @staticmethod
    def COIN():
        return HNS_COIN

    @staticmethod
    def exp():
        return 6

    def max_money(self):
        return HNS_MAX_MONEY

    def __init__(
        self, coin_settings, network, swap_client=None, *, node=None, bridge=None
    ):
        super().__init__(network, coin_settings=coin_settings, swap_client=swap_client)
        self._log = swap_client.log if swap_client is not None else logging
        if network not in ("mainnet", "testnet", "regtest"):
            raise ValueError("unsupported HNS network")
        if coin_settings.get("connection_type") != "rpc":
            raise ValueError("HNS requires the native HSRD RPC backend")
        host = coin_settings.get("rpchost", "127.0.0.1")
        port = coin_settings.get("rpcport")
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError("HSRD wallet RPC must be loopback")
        fingerprint = coin_settings.get("wallet_seed_fingerprint")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise ValueError("HNS wallet seed fingerprint must be configured")
        try:
            self._expected_fingerprint = bytes.fromhex(fingerprint)
        except ValueError as exc:
            raise ValueError("invalid HNS wallet seed fingerprint") from exc
        self._connection_type = "rpc"
        self._maximum_send_fee = coin_settings.get("maximum_send_fee", 100_000)
        if (
            type(self._maximum_send_fee) is not int
            or not 0 < self._maximum_send_fee <= 10_000_000
        ):
            raise ValueError("invalid maximum HNS send fee")
        self._use_segwit = True
        self.setConfTarget(coin_settings.get("conf_target", 2))
        self._node = node
        self._bridge = bridge
        self._bridge_config = None
        self._unlocked = False
        if self._node is None:
            authorization_file = coin_settings.get("rpc_authorization_file")
            authorization = read_private_hsrd_authorization(authorization_file)
            self._node = HnsNodeRpc(port, authorization, host)
        if self._bridge is None:
            self._bridge_config = (
                coin_settings["bridge_executable"],
                coin_settings["wallet_database"],
                f"{host}:{port}",
                coin_settings["rpc_authorization_file"],
            )
            self._bridge = HnsWalletBridge(*self._bridge_config)

    @property
    def node(self):
        return self._node

    @property
    def bridge(self):
        return self._bridge

    def testDaemonRPC(self, with_wallet=True):
        self._node.bound_snapshot(self._network)
        if with_wallet and self.checkWallets() != 1:
            raise ValueError("HNS wallet bridge is unavailable")

    def checkWallets(self):
        return 1 if self._bridge is not None and self._bridge.is_running() else 0

    def getDaemonVersion(self):
        self.testDaemonRPC(with_wallet=False)
        return "HSRD wallet RPC v1"

    def getBlockchainInfo(self):
        binding = self._node.bound_snapshot(self._network)
        ready = self._node.sync_ready(self._network, binding)
        return {
            "blocks": binding.tip["height"],
            "bestblockhash": binding.tip["hash"],
            "mediantime": binding.tip["median_time_past"],
            "verificationprogress": 1.0 if ready else 0.0,
        }

    def getChainHeight(self):
        return self.getBlockchainInfo()["blocks"]

    def getChainMedianTime(self):
        return self.getBlockchainInfo()["mediantime"]

    def isValidAddress(self, address):
        try:
            return len(decode_v0_address(self._network, address).program) in (20, 32)
        except ValueError:
            return False

    def unlockWallet(self, passphrase):
        if not self._bridge.is_running():
            self._unlocked = False
            self.setWalletSeedWarning(True)
            if self._bridge_config is None:
                raise ValueError("HNS wallet bridge is unavailable")
            self._bridge.close()
            self._bridge = HnsWalletBridge(*self._bridge_config)
        self._bridge.unlock(passphrase)
        try:
            _, fingerprint = self._bridge.identity(self._network)
            if fingerprint != self._expected_fingerprint:
                raise ValueError(
                    "HNS wallet recovery seed differs from configured wallet"
                )
        except Exception:
            if self._bridge.is_running():
                self._bridge.lock()
            raise
        self._unlocked = True
        self.setWalletSeedWarning(False)

    def changeWalletPassword(self, old_password, new_password):
        if not self.walletIdentityReady():
            raise ValueError("HNS wallet must be unlocked before changing its password")
        try:
            self._bridge.change_passphrase(old_password, new_password)
        finally:
            # The bridge discards its runtime after a rekey attempt. Recheck
            # identity and rebuild its wallet service under the new key.
            self._unlocked = False
            self.setWalletSeedWarning(True)
        self.unlockWallet(new_password)

    def lockWallet(self):
        self._bridge.lock()
        self._unlocked = False
        self.setWalletSeedWarning(True)

    def walletIdentityReady(self):
        return self._unlocked and self.knownWalletSeed() and self.checkWallets() == 1

    def getSpendableBalance(self):
        if not self.walletIdentityReady():
            raise ValueError("HNS wallet is locked or seed identity is unknown")
        return self._bridge.snapshot(self._network)[0]

    def getMainWalletAddress(self):
        if not self.walletIdentityReady():
            raise ValueError("HNS wallet is locked or seed identity is unknown")
        return self._bridge.snapshot(self._network)[1]

    def getNewAddress(self, use_segwit=True, label="swap_receive"):
        if use_segwit is not True:
            raise ValueError("HNS only supports native witness addresses")
        if not self.walletIdentityReady():
            raise ValueError("HNS wallet is locked or seed identity is unknown")
        return self._bridge.receive(self._network)[0]

    def prepareWithdrawal(self, value, address):
        if not self.walletIdentityReady():
            raise ValueError("HNS wallet is locked or seed identity is unknown")
        if not self.isValidAddress(address):
            raise ValueError("invalid HNS withdrawal address")
        amount = self.make_int(value)
        if amount <= 0:
            raise ValueError("HNS withdrawal amount must be positive")
        return self._bridge.prepare_send(
            self._network, address, amount, self._maximum_send_fee
        )

    def approveWithdrawal(self, token):
        if not self.walletIdentityReady():
            raise ValueError("HNS wallet is locked or seed identity is unknown")
        return self._bridge.approve_send(token)

    def rejectWithdrawal(self, token):
        if not self.walletIdentityReady():
            raise ValueError("HNS wallet is locked or seed identity is unknown")
        self._bridge.reject_send(token)

    def withdrawCoin(self, value, addr_to, subfee=False):
        raise ValueError("HNS sends require review on the HNS wallet page")

    def isWalletEncryptedLocked(self):
        return True, not self.walletIdentityReady()

    def getWalletInfo(self):
        # The encrypted sidecar cannot disclose balance while it is locked.
        balance = self.getSpendableBalance() if self.walletIdentityReady() else 0
        return {
            "balance": self.format_amount(balance),
            "unconfirmed_balance": "0",
            "encrypted": True,
            "locked": not self.walletIdentityReady(),
        }

    def close(self):
        self._bridge.close()
