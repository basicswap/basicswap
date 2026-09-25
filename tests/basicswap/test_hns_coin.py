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
from basicswap.ui.page_wallet import page_wallet

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

    def prepare_send(self, network, recipient, amount, maximum_fee):
        assert network == "regtest" and recipient == ADDRESS
        assert amount == 250_000 and maximum_fee == 100_000
        return "ab" * 16, recipient, amount, maximum_fee, 1_900_000_000

    def approve_send(self, token):
        assert token == bytes.fromhex("ab" * 16)
        return "cd" * 32

    def reject_send(self, token):
        assert token == bytes.fromhex("ab" * 16)

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
        app = SimpleNamespace(coin_clients={Coins.BTC: {"connection_type": "rpc"}})
        for swap_type in SwapTypes:
            if swap_type == SwapTypes.HNS_BTC_SWAP:
                BasicSwap.validateSwapType(app, Coins.HNS, Coins.BTC, swap_type)
                BasicSwap.validateSwapType(app, Coins.BTC, Coins.HNS, swap_type)
                continue
            with (
                self.subTest(swap_type=swap_type),
                self.assertRaisesRegex(ValueError, "native HNS/BTC"),
            ):
                BasicSwap.validateSwapType(app, Coins.HNS, Coins.BTC, swap_type)
        with self.assertRaisesRegex(ValueError, "native HNS/BTC"):
            BasicSwap.validateSwapType(
                app, Coins.BTC, Coins.LTC, SwapTypes.HNS_BTC_SWAP
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

    def test_hns_withdrawal_requires_wallet_and_exact_native_approval(self):
        coin = self.interface()
        with self.assertRaisesRegex(ValueError, "locked"):
            coin.prepareWithdrawal("0.250000", ADDRESS)
        with self.assertRaisesRegex(ValueError, "wallet page"):
            coin.withdrawCoin("0.250000", ADDRESS)
        coin.unlockWallet("test passphrase")
        with self.assertRaisesRegex(ValueError, "invalid HNS withdrawal address"):
            coin.prepareWithdrawal("0.250000", "bc1qwrong")
        with self.assertRaisesRegex(ValueError, "must be positive"):
            coin.prepareWithdrawal("0", ADDRESS)
        preview = coin.prepareWithdrawal("0.250000", ADDRESS)
        self.assertEqual(
            preview,
            ("ab" * 16, ADDRESS, 250_000, 100_000, 1_900_000_000),
        )
        token = bytes.fromhex(preview[0])
        self.assertEqual(coin.approveWithdrawal(token), "cd" * 32)
        coin.rejectWithdrawal(token)

    def test_hns_wallet_page_reviews_the_native_send_without_core_fee_rpc(self):
        coin = self.interface()
        coin.unlockWallet("test passphrase")
        app = SimpleNamespace(
            checkSystemStatus=lambda: None,
            getSummary=dict,
            updateWalletsInfo=lambda *_args, **_kwargs: None,
            ci=lambda selected: coin,
            coin_clients={Coins.HNS: {"connection_type": "rpc"}},
            getCachedWalletsInfo=lambda _filter: {
                Coins.HNS: {
                    "name": "Handshake",
                    "balance": "1.250000",
                    "deposit_address": ADDRESS,
                }
            },
            xmr_based_coins=(),
            _restrict_unknown_seed_wallets=False,
            debug_ui=False,
            debug=False,
            use_tor_proxy=False,
            log=SimpleNamespace(warning=lambda *_args: None),
            getFeeRateForCoin=lambda _coin: self.fail(
                "HNS wallet page must not request a Core fee rate"
            ),
        )
        form = {
            b"withdraw_19": [b"Withdraw"],
            b"amt_19": [b"0.250000"],
            b"to_19": [ADDRESS.encode()],
        }
        page = SimpleNamespace(
            server=SimpleNamespace(
                swap_client=app,
                env=SimpleNamespace(get_template=lambda _name: "wallet-template"),
            ),
            checkForm=lambda *_args: form,
            render_template=lambda _template, context: context,
        )
        result = page_wallet(page, ["", "wallet", "hns"], b"")
        self.assertEqual(result["err_messages"], [])
        self.assertEqual(result["w"]["hns_send"]["recipient"], ADDRESS)
        self.assertEqual(result["w"]["hns_send"]["amount"], "0.250000")
        self.assertEqual(result["w"]["hns_send"]["maximum_fee"], "0.100000")
        page.checkForm = lambda *_args: {
            b"approve_hns_send": [b"1"],
            b"hns_send_token": [result["w"]["hns_send"]["token"].encode()],
        }
        def offline_cache(*_args, **_kwargs):
            raise RuntimeError("cache offline")

        app.updateWalletsInfo = offline_cache
        approved = page_wallet(page, ["", "wallet", "hns"], b"")
        self.assertEqual(approved["err_messages"], [])
        self.assertIn("cd" * 32, approved["messages"][0])
        self.assertNotIn("hns_send", approved["w"])

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
