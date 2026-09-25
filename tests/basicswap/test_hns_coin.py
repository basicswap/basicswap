"""Guarded HSRD/sidecar coin interface and wallet seed binding."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import SwapTypes, TxLockTypes
from basicswap.chainparams import Coins, chainparams
from basicswap.interface.hns.coin import (
    HNSInterface,
    read_private_hsrd_authorization,
)

ADDRESS = "rs1qqyqszqgpqyqszqgpqyqszqgpqyqszqgpprmh8u"
FINGERPRINT = bytes.fromhex("55" * 32)


class FakeNode:
    ready = True

    def bound_snapshot(self, network):
        assert network == "regtest"
        return SimpleNamespace(
            tip={"height": 17, "hash": "ab" * 32, "median_time_past": 1_760_000_000}
        )

    def sync_ready(self, network, binding):
        return self.ready


class FakeBridge:
    def __init__(self):
        self.fingerprint = FINGERPRINT
        self.locked = True
        self.closed = False

    def unlock(self, passphrase):
        assert passphrase == "test passphrase"
        self.locked = False

    def identity(self, network):
        assert network == "regtest"
        return bytes.fromhex("44" * 16), self.fingerprint

    def lock(self):
        self.locked = True

    def snapshot(self, network):
        assert not self.locked
        return 1_250_000, ADDRESS

    def receive(self, network):
        assert not self.locked
        return ADDRESS, 1

    def close(self):
        self.closed = True

    def is_running(self):
        return not self.closed


class HnsCoinInterfaceTest(unittest.TestCase):
    def interface(self, bridge=None, node=None):
        return HNSInterface(
            {
                "connection_type": "rpc",
                "rpchost": "127.0.0.1",
                "rpcport": 14037,
                "wallet_seed_fingerprint": FINGERPRINT.hex(),
            },
            "regtest",
            node=node or FakeNode(),
            bridge=bridge or FakeBridge(),
        )

    def test_coin_parameters_and_locked_wallet(self):
        coin = self.interface()
        self.assertEqual(coin.coin_type(), Coins.HNS)
        self.assertEqual(coin.COIN(), 1_000_000)
        self.assertEqual(coin.exp(), 6)
        self.assertEqual(coin.max_money(), 2_040_000_000_000_000)
        self.assertEqual(chainparams[Coins.HNS]["ticker"], "HNS")
        self.assertEqual(coin.getChainHeight(), 17)
        self.assertEqual(coin.getBlockchainInfo()["verificationprogress"], 1.0)
        self.assertEqual(coin.getWalletInfo()["locked"], True)
        self.assertFalse(coin.knownWalletSeed())
        with self.assertRaisesRegex(ValueError, "locked"):
            coin.getSpendableBalance()
        coin.unlockWallet("test passphrase")
        self.assertTrue(coin.knownWalletSeed())
        self.assertEqual(coin.getSpendableBalance(), 1_250_000)
        self.assertEqual(coin.getWalletInfo()["balance"], "1.250000")
        self.assertEqual(coin.getNewAddress(), ADDRESS)
        self.assertTrue(coin.isValidAddress(ADDRESS))
        with self.assertRaisesRegex(ValueError, "native witness"):
            coin.getNewAddress(use_segwit=False)
        coin.lockWallet()
        self.assertFalse(coin.knownWalletSeed())
        coin.close()
        self.assertTrue(coin.bridge.closed)
        self.assertEqual(coin.checkWallets(), 0)
        self.assertEqual(coin.isWalletEncryptedLocked(), (True, True))

    def test_generic_swap_types_cannot_fund_hns(self):
        for swap_type in SwapTypes:
            with (
                self.subTest(swap_type=swap_type),
                self.assertRaisesRegex(ValueError, "not enabled"),
            ):
                BasicSwap.validateSwapType(None, Coins.HNS, Coins.BTC, swap_type)
        with self.assertRaisesRegex(ValueError, "HNS/BTC pair"):
            BasicSwap.validateSwapType(
                None, Coins.BTC, Coins.LTC, SwapTypes.HNS_BTC_SWAP
            )
        BasicSwap.validateOfferLockValue(
            None,
            SwapTypes.HNS_BTC_SWAP,
            Coins.HNS,
            Coins.BTC,
            TxLockTypes.ABS_LOCK_TIME,
            48 * 60 * 60,
        )
        with self.assertRaisesRegex(ValueError, "absolute-time lock"):
            BasicSwap.validateOfferLockValue(
                None,
                SwapTypes.HNS_BTC_SWAP,
                Coins.HNS,
                Coins.BTC,
                TxLockTypes.SEQUENCE_LOCK_TIME,
                48 * 60 * 60,
            )

    def test_changed_seed_locks_bridge(self):
        bridge = FakeBridge()
        bridge.fingerprint = bytes.fromhex("66" * 32)
        coin = self.interface(bridge=bridge)
        with self.assertRaisesRegex(ValueError, "recovery seed differs"):
            coin.unlockWallet("test passphrase")
        self.assertTrue(bridge.locked)
        self.assertFalse(coin.knownWalletSeed())

    def test_dead_bridge_is_not_reported_as_unlocked(self):
        bridge = FakeBridge()
        coin = self.interface(bridge=bridge)
        coin.unlockWallet("test passphrase")
        bridge.closed = True
        self.assertEqual(coin.checkWallets(), 0)
        self.assertEqual(coin.isWalletEncryptedLocked(), (True, True))
        self.assertTrue(coin.getWalletInfo()["locked"])
        with self.assertRaisesRegex(ValueError, "locked"):
            coin.getSpendableBalance()
        with self.assertRaisesRegex(ValueError, "bridge is unavailable"):
            coin.unlockWallet("test passphrase")

    def test_unlock_reopens_a_stopped_owned_bridge(self):
        settings = {
            "connection_type": "rpc",
            "rpchost": "127.0.0.1",
            "rpcport": 14037,
            "wallet_seed_fingerprint": FINGERPRINT.hex(),
            "bridge_executable": "/trusted/hns-wallet-basicswap-bridge",
            "wallet_database": "/private/hns-wallet.db",
            "rpc_authorization_file": "/private/hsrd-auth",
        }
        with patch(
            "basicswap.interface.hns.coin.HnsWalletBridge",
            side_effect=lambda *args: FakeBridge(),
        ) as constructor:
            coin = HNSInterface(settings, "regtest", node=FakeNode())
            first = coin.bridge
            coin.unlockWallet("test passphrase")
            first.close()
            self.assertTrue(coin.getWalletInfo()["locked"])
            coin.unlockWallet("test passphrase")
            self.assertIsNot(coin.bridge, first)
            self.assertEqual(coin.getSpendableBalance(), 1_250_000)
            self.assertEqual(constructor.call_count, 2)

    def test_stale_hsrd_scheduler_is_not_reported_synced(self):
        node = FakeNode()
        node.ready = False
        coin = self.interface(node=node)
        self.assertEqual(coin.getBlockchainInfo()["verificationprogress"], 0.0)

    def test_authorization_file_must_be_private_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            authorization = Path(directory) / "authorization"
            authorization.write_text("Bearer isolated-regtest\n", encoding="ascii")
            authorization.chmod(0o600)
            self.assertEqual(
                read_private_hsrd_authorization(authorization),
                "Bearer isolated-regtest",
            )
            alias = Path(directory) / "alias"
            alias.symlink_to(authorization)
            with self.assertRaisesRegex(ValueError, "authorization file"):
                read_private_hsrd_authorization(alias)
            authorization.write_text("a" * 4098, encoding="ascii")
            with self.assertRaisesRegex(ValueError, "exceeds limit"):
                read_private_hsrd_authorization(authorization)
            authorization.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "must be private"):
                read_private_hsrd_authorization(authorization)


if __name__ == "__main__":
    unittest.main()
