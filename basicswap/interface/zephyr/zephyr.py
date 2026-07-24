#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

# Zephyr Protocol coin module for BasicSwap.
# Zephyr is a Monero fork (base v2.3.0) with a Djed-style stablecoin overlay, so almost
# everything is inherited unchanged from XMRInterface (key-share split, DLEq, address
# encoding, lock-tx publishing). The only adaptations are the stablecoin multi-asset model
# leaking into the *wallet* RPC - see zephyr-testnet/RQ2-RPC-DIFF.md:
#   - get_balance: Zephyr returns {"balances":[{"asset_type":"ZPH", balance, ...}], ...}
#     vs Monero's flat {balance, unlocked_balance}. We flatten the ZPH entry to top level.
#   - transfer / transfer_split: Zephyr requires source_asset/destination_asset; a swap
#     moves base ZEPH so both are "ZPH" (conversions are out of the swap path).
# Both are handled by wrapping self.rpc_wallet, so all inherited XMRInterface methods work
# unchanged.

from basicswap.chainparams import Coins
from basicswap.interface.zephyr.chainparams import ZEPH_COIN
from basicswap.interface.xmr.xmr import XMRInterface


class ZEPHInterface(XMRInterface):

    @staticmethod
    def coin_type():
        return Coins.ZEPH

    @staticmethod
    def ticker_str() -> int:
        return Coins.ZEPH.name

    @staticmethod
    def COIN():
        return ZEPH_COIN

    @staticmethod
    def exp() -> int:
        return 12

    @staticmethod
    def depth_spendable() -> int:
        # Per-fork confirmation-depth audit (the Wownero PR #110 lesson: do not blindly inherit
        # Monero's value - retune it for THIS fork's block time). Zephyr is a direct Monero v2.3.0
        # fork, so it keeps Monero's 120s (2 min) block target; at that block time 10 confirmations
        # is ~20 min, the same wall-clock maturity as Monero - so 10 is appropriate here (unlike
        # Wownero's 5 min blocks, where inheriting 10 meant 50 min and had to be cut to ~3). Zephyr's
        # smaller hashrate also argues for staying conservative. The swap chain-B lock confirmation is
        # a separate knob (`blocks_confirmed`, default 6 / 2 in tests); a production ZEPH coin-settings
        # entry should set it explicitly for the same block time.
        return 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rpc_wallet = self._wrap_rpc_wallet(self.rpc_wallet)

    @staticmethod
    def _wrap_rpc_wallet(inner):
        def rpc_wallet(method, params=None, **kwargs):
            if method in ("transfer", "transfer_split"):
                params = dict(params or {})
                params.setdefault("source_asset", "ZPH")
                params.setdefault("destination_asset", "ZPH")
            rv = inner(method, params, **kwargs)
            if method == "get_balance" and isinstance(rv, dict):
                zb = None
                for b in rv.get("balances", []) or []:
                    if b.get("asset_type") == "ZPH":
                        zb = b
                        break
                if zb is not None:
                    rv["balance"] = zb.get("balance", 0)
                    rv["unlocked_balance"] = zb.get("unlocked_balance", 0)
                    rv["blocks_to_unlock"] = zb.get("blocks_to_unlock", 0)
                    rv["multisig_import_needed"] = zb.get(
                        "multisig_import_needed", False
                    )
                # Guarantee Monero-shaped keys even for empty/sparse responses (a fresh
                # Zephyr wallet's get_balance omits them), so inherited XMRInterface code works.
                rv.setdefault("balance", rv.get("unlocked_balance", 0))
                rv.setdefault("unlocked_balance", 0)
                rv.setdefault("blocks_to_unlock", 0)
                rv.setdefault("multisig_import_needed", False)
            return rv

        return rpc_wallet

    # Defensive wallet-open override (same shape as the Wownero module).
    def openWallet(self, filename):
        params = {"filename": filename}
        if self._wallet_password is not None:
            params["password"] = self._wallet_password
        try:
            self.rpc_wallet("open_wallet", params)
        except Exception as e:
            if "no connection to daemon" in str(e):
                self._log.debug(f"{self.coin_name()} {e}")
                return  # allow startup with a busy daemon
            try:
                self.rpc_wallet("store")
                self.rpc_wallet("close_wallet")
            except Exception:
                pass
            self.rpc_wallet("open_wallet", params)
