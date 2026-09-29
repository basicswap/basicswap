# -*- coding: utf-8 -*-

# VargaMesh integration for BasicSwap

from basicswap.interface.btc.btc import BTCInterface
from basicswap.chainparams import Coins


class VMESHInterface(BTCInterface):

    @staticmethod
    def coin_type():
        return Coins.VMESH

    def getWalletInfo(self):
        """
        Normalise modern VargaMesh / Bitcoin Core wallet RPC output.

        Modern descriptor-wallet RPCs no longer expose balance,
        unconfirmed_balance and immature_balance through getwalletinfo.
        BasicSwap 0.18.9 still expects those compatibility fields.
        """
        rv = super().getWalletInfo()

        required = (
            "balance",
            "unconfirmed_balance",
            "immature_balance",
        )

        if any(k not in rv for k in required):
            balances = self.rpc_wallet("getbalances")
            mine = balances.get("mine", {})

            rv.setdefault(
                "balance",
                mine.get("trusted", 0),
            )
            rv.setdefault(
                "unconfirmed_balance",
                mine.get("untrusted_pending", 0),
            )
            rv.setdefault(
                "immature_balance",
                mine.get("immature", 0),
            )

        return rv

    def max_money(self) -> int:
        # VMESH:
        # 25 VMESH initial subsidy
        # halving every 1,051,200 blocks
        # geometric upper bound = 52,560,000 VMESH
        return 52_560_000 * self.COIN()
