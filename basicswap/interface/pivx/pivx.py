# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from io import BytesIO

from basicswap.interface.btc.btc import BTCInterface
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins
from basicswap.util.address import decodeAddress
from basicswap.interface.contrib.pivx_test_framework.messages import CTransaction
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_DUP,
    OP_HASH160,
    OP_CHECKSIG,
    OP_EQUALVERIFY,
)


class PIVXInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.PIVX

    def __init__(self, coin_settings, network, swap_client=None, **kwargs):
        super().__init__(
            coin_settings=coin_settings,
            network=network,
            swap_client=swap_client,
            **kwargs,
        )
        # No multiwallet support
        self.rpc_wallet = make_rpc_func(
            self._rpcport, self._rpcauth, host=self._rpc_host
        )
        self.rpc_wallet_watch = self.rpc_wallet

    def encryptWallet(self, password: str, check_seed: bool = True):
        # Watchonly wallets are not encrypted

        seed_id_before: str = self.getWalletSeedID()

        self.rpc_wallet("encryptwallet", [password], timeout=120)

        if check_seed is False or seed_id_before == "Not found":
            return
        seed_id_after: str = self.getWalletSeedID()

        if seed_id_before == seed_id_after:
            return
        self._log.warning(f"{self.ticker()} wallet seed changed after encryption.")
        self._log.debug(
            f"seed_id_before: {seed_id_before} seed_id_after: {seed_id_after}."
        )
        self.setWalletSeedWarning(True)
        # Workaround for https://github.com/bitcoin/bitcoin/issues/26607
        chain_client_settings = self._sc.getChainClientSettings(
            self.coin_type()
        )  # basicswap.json

        if chain_client_settings.get("manage_daemon", False) is False:
            self._log.warning(
                f"{self.ticker()} manage_daemon is false. Can't attempt to fix."
            )
            return

    def signTxWithWallet(self, tx):
        rv = self.rpc("signrawtransaction", [tx.hex()])
        return bytes.fromhex(rv["hex"])

    def createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int,
        sub_fee: bool = False,
        lock_unspents: bool = True,
        feerate: int = None,
    ) -> str:
        txn = self.rpc(
            "createrawtransaction", [[], {addr_to: self.format_amount(amount)}]
        )
        if feerate:
            fee_rate = self.format_amount(feerate)
            fee_src = "specified"
        else:
            fee_rate, fee_src = self.get_fee_rate(self._conf_target)
        self._log.debug(
            f"Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}"
        )
        options = {
            "lockUnspents": lock_unspents,
            "feeRate": fee_rate,
        }
        if sub_fee:
            options["subtractFeeFromOutputs"] = [
                0,
            ]
        return self.rpc("fundrawtransaction", [txn, options])["hex"]

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self.createRawFundedTransaction(addr_to, amount)
        return self.rpc("signrawtransaction", [txn_funded])["hex"]

    def decodeAddress(self, address):
        return decodeAddress(address)[1:]

    def getBlockWithTxns(self, block_hash):
        block = self.rpc("getblock", [block_hash, True])
        tx_rv = []
        for txid_str in block["tx"]:
            tx_dec = self.rpc("getrawtransaction", [txid_str, True])
            tx_rv.append(tx_dec)
        block["tx"] = tx_rv
        return block

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, "", "", subfee]
        return self.rpc("sendtoaddress", params)

    def getSpendableBalance(self) -> int:
        return self.make_int(self.rpc("getwalletinfo")["balance"])

    def loadTx(self, tx_bytes):
        # Load tx from bytes to internal representation
        tx = CTransaction()
        tx.deserialize(BytesIO(tx_bytes))
        return tx

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        add_bytes = 107
        size = len(tx.serialize_with_witness()) + add_bytes
        pay_fee = round(fee_rate * size / 1000)
        self._log.info(
            f"BLockSpendTx fee_rate, size, fee: {fee_rate}, {size}, {pay_fee}."
        )
        return pay_fee

    def signTxWithKey(self, tx: bytes, key: bytes, prev_amount=None) -> bytes:
        key_wif = self.encodeKey(key)
        rv = self.rpc(
            "signrawtransaction",
            [
                tx.hex(),
                [],
                [
                    key_wif,
                ],
            ],
        )
        return bytes.fromhex(rv["hex"])

    def findTxnByHash(self, txid_hex: str):
        # Only works for wallet txns
        try:
            rv = self.rpc("gettransaction", [txid_hex])
        except Exception as e:  # noqa: F841
            self._log.debug(
                "findTxnByHash getrawtransaction failed: {}".format(txid_hex)
            )
            return None
        if "confirmations" in rv and rv["confirmations"] >= self.blocks_confirmed:
            block_height = self.getBlockHeader(rv["blockhash"])["height"]
            return {"txid": txid_hex, "amount": 0, "height": block_height}
        return None

    def getChainMedianTime(self) -> int:
        bestblockhash = self.rpc("getbestblockhash")
        bestblockheader = self.rpc(
            "getblockheader",
            [
                bestblockhash,
            ],
        )
        return bestblockheader["mediantime"]
