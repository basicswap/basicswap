#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.chainparams import Coins
from basicswap.util.address import decodeAddress
from basicswap.contrib.mnemonic import Mnemonic
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_DUP,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
)


class DASHInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.DASH

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__(coin_settings, network, swap_client)
        self._wallet_passphrase = ""
        self._have_checked_seed = False

        self._wallet_v20_compatible = (
            False
            if not swap_client
            else swap_client.getChainClientSettings(self.coin_type()).get(
                "wallet_v20_compatible", False
            )
        )

    def decodeAddress(self, address: str) -> bytes:
        return decodeAddress(address)[1:]

    def getWalletSeedID(self) -> str:
        hdseed: str = self.rpc_wallet("dumphdinfo")["hdseed"]
        return self.getSeedHash(bytes.fromhex(hdseed)).hex()

    def entropyToMnemonic(self, key: bytes) -> None:
        return Mnemonic("english").to_mnemonic(key)

    def initialiseWallet(self, key_bytes: bytes) -> None:
        self._have_checked_seed = False
        if self._wallet_v20_compatible:
            self._log.warning("Generating wallet compatible with v20 seed.")
            words = self.entropyToMnemonic(key_bytes)
            mnemonic_passphrase = ""
            self.rpc_wallet(
                "upgradetohd", [words, mnemonic_passphrase, self._wallet_passphrase]
            )
            self._have_checked_seed = False
            if self._wallet_passphrase != "":
                self.unlockWallet(self._wallet_passphrase)
            return

        key_wif = self.encodeKey(key_bytes)
        self.rpc_wallet("sethdseed", [True, key_wif])

    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        self._expect_seedid_hex = expect_seedid
        rv = self.rpc_wallet("dumphdinfo")
        if rv["mnemonic"] != "":
            entropy = Mnemonic("english").to_entropy(rv["mnemonic"].split(" "))
            entropy_hash = self.getAddressHashFromKey(entropy)[::-1].hex()
            have_expected_seed: bool = expect_seedid == entropy_hash
        else:
            have_expected_seed: bool = expect_seedid == self.getWalletSeedID()
        self._have_checked_seed = True
        return have_expected_seed

    def withdrawCoin(self, value, addr_to, subfee):
        params = [addr_to, value, "", "", subfee, False, False, self._conf_target]
        return self.rpc_wallet("sendtoaddress", params)

    def getSpendableBalance(self) -> int:
        return self.make_int(self.rpc_wallet("getwalletinfo")["balance"])

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

    def findTxnByHash(self, txid_hex: str):
        # Only works for wallet txns
        try:
            rv = self.rpc_wallet("gettransaction", [txid_hex])
        except Exception as e:  # noqa: F841
            self._log.debug(
                "findTxnByHash getrawtransaction failed: {}".format(txid_hex)
            )
            return None
        if "confirmations" in rv and rv["confirmations"] >= self.blocks_confirmed:
            block_height = self.getBlockHeader(rv["blockhash"])["height"]
            return {"txid": txid_hex, "amount": 0, "height": block_height}

        return None

    def unlockWallet(self, password: str):
        super().unlockWallet(password)
        if self._wallet_v20_compatible:
            # Store password for initialiseWallet
            self._wallet_passphrase = password
        if not self._have_checked_seed:
            try:
                self._sc.checkWalletSeed(self.coin_type())
            except Exception as ex:
                # dumphdinfo can fail if the wallet is not initialised
                self._log.debug(f"DASH checkWalletSeed failed: {ex}.")

    def lockWallet(self):
        super().lockWallet()
        self._wallet_passphrase = ""
