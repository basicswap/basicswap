# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.chainparams import Coins
from basicswap.contrib.test_framework.messages import CTransaction
from basicswap.interface.btc.btc import BTCInterface
from basicswap.util import ensure

# Rincoin Core v1.1.0, CTransaction::RIN_FORK_TX_VERSION ("RIN3", RIP-0009).
# From block 840,000 a block is valid only if every transaction other than the
# coinbase carries this version.  v1.1.0 accepts it as standard at any height.
RIN_FORK_TX_VERSION = 0x52494E33

# The getnetworkinfo version of Rincoin Core v1.1.0.  Earlier versions refuse
# transactions with the RIN3 version as non-standard.
RIN_MIN_CORE_VERSION = 1010000


class RINInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.RIN

    @staticmethod
    def txVersion() -> int:
        return RIN_FORK_TX_VERSION

    def max_money(self) -> int:
        return 168000000 * self.COIN()

    def supportsTaproot(self) -> bool:
        # Taproot is not active on Rincoin mainnet (RIP-0011), an output to a
        # version 1 program would be spendable by anyone.
        return False

    def getDaemonVersion(self):
        version = super().getDaemonVersion()
        ensure(
            version >= RIN_MIN_CORE_VERSION,
            "Rincoin Core v1.1.0 or later is required",
        )
        return version

    def createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int,
        sub_fee: bool = False,
        lock_unspents: bool = True,
        feerate: int = None,
        change_addr: str = None,
    ) -> str:
        # createrawtransaction always builds version 2.  Set the version first,
        # fundrawtransaction keeps a version other than 2.
        tx = CTransaction()
        tx.nVersion = self.txVersion()
        tx.vout.append(self.txoType()(amount, self.getDestForAddress(addr_to)))

        if feerate:
            fee_rate = self.format_amount(feerate)
            fee_src = "specified"
        else:
            fee_rate, fee_src = self.get_fee_rate(self._conf_target)
            self._ensureFeeRateWithinMax(fee_rate, fee_src)
        self._log.debug(
            f"Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}"
        )

        options = {
            "lockUnspents": lock_unspents,
            "feeRate": fee_rate,
        }
        if change_addr:
            options["changeAddress"] = change_addr
        if sub_fee:
            options["subtractFeeFromOutputs"] = [
                0,
            ]
        funded_hex: str = self.rpc_wallet(
            "fundrawtransaction", [tx.serialize().hex(), options]
        )["hex"]
        funded_tx = self.loadTx(bytes.fromhex(funded_hex))
        ensure(
            funded_tx.nVersion == self.txVersion(),
            f"Funded tx has version {funded_tx.nVersion}, expected {self.txVersion()}",
        )
        return funded_hex
