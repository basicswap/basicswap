#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins


class NMCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.NMC

    def lockNonSegwitPrevouts(self) -> None:
        # For tests
        # NMC Seems to ignore utxo locks
        unspent = self.rpc_wallet("listunspent")

        to_lock = []
        for u in unspent:
            if u.get("spendable", False) is False:
                continue
            if "desc" in u:
                desc = u["desc"]
                if self.use_p2shp2wsh():
                    if not desc.startswith("sh(wpkh"):
                        to_lock.append(
                            {
                                "txid": u["txid"],
                                "vout": u["vout"],
                                "amount": u["amount"],
                            }
                        )
                else:
                    if not desc.startswith("wpkh"):
                        to_lock.append(
                            {
                                "txid": u["txid"],
                                "vout": u["vout"],
                                "amount": u["amount"],
                            }
                        )

        if len(to_lock) > 0:
            self._log.debug(f"Spending {len(to_lock)} non segwit prevouts")
            addr_out = self.rpc_wallet(
                "getnewaddress", ["convert non segwit", "bech32"]
            )
            prevouts = []
            sum_amount: int = 0
            for utxo in to_lock:
                prevouts.append(
                    {
                        "txid": utxo["txid"],
                        "vout": utxo["vout"],
                    }
                )
                sum_amount += self.make_int(utxo["amount"])

            fee = 100000 * len(prevouts)
            funded_tx = self.rpc(
                "createrawtransaction",
                [prevouts, {addr_out: self.format_amount(sum_amount - fee)}],
            )
            signed_tx = self.rpc_wallet("signrawtransactionwithwallet", [funded_tx])
            self.rpc("sendrawtransaction", [signed_tx["hex"]])
