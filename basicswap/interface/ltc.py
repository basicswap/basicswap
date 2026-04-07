#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .btc import BTCInterface
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins, chainparams


class LTCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.LTC

    def __init__(self, coin_settings, network, swap_client=None):
        super(LTCInterface, self).__init__(coin_settings, network, swap_client)
        self._rpc_wallet_mweb = coin_settings.get("mweb_wallet_name", "mweb")
        self.rpc_wallet_mweb = make_rpc_func(
            self._rpcport,
            self._rpcauth,
            host=self._rpc_host,
            wallet=self._rpc_wallet_mweb,
        )

    def checkWallets(self) -> int:
        if self._connection_type == "electrum":
            wm = self.getWalletManager()
            if wm and wm.isInitialized(self.coin_type()):
                return 1
            return 0

        wallets = self.rpc("listwallets")

        if self._rpc_wallet not in wallets:
            self._log.debug(
                f"Wallet: {self._rpc_wallet} not active, attempting to load."
            )
            try:
                self.rpc(
                    "loadwallet",
                    [
                        self._rpc_wallet,
                    ],
                )
                wallets = self.rpc("listwallets")
            except Exception as e:
                self._log.debug(f'Error loading wallet "{self._rpc_wallet}": {e}.')
                if "does not exist" in str(e) or "Path does not exist" in str(e):
                    try:
                        wallet_dirs = self.rpc("listwalletdir")
                        existing = [w["name"] for w in wallet_dirs.get("wallets", [])]
                    except Exception:
                        existing = []
                    if existing:
                        raise ValueError(
                            f'{self.coin_name()} wallet "{self._rpc_wallet}" does not exist.'
                            f" Other wallets found on disk: {existing}."
                            f' Set "wallet_name" in your {self.coin_name()} config to the correct wallet name,'
                            f" or use restorewallet to set the wallet name."
                        )
                    self._log.info(
                        f'Creating wallet "{self._rpc_wallet}" for {self.coin_name()}.'
                    )
                    try:
                        self.rpc(
                            "createwallet",
                            [
                                self._rpc_wallet,
                                False,
                                True,
                                "",
                                False,
                                self._use_descriptors,
                            ],
                        )
                        wallets = self.rpc("listwallets")
                        if self.getWalletSeedID() == "Not found":
                            self._log.info(
                                f"Initializing HD seed for {self.coin_name()}."
                            )
                            self._sc.initialiseWallet(self.coin_type())
                    except Exception as create_e:
                        self._log.error(f"Error creating wallet: {create_e}")

        if self._rpc_wallet not in wallets and len(wallets) > 0:
            self._log.warning(f"Changing {self.ticker()} wallet name.")
            for wallet_name in wallets:
                if wallet_name in ("mweb",):
                    continue

                change_watchonly_wallet: bool = (
                    self._rpc_wallet_watch == self._rpc_wallet
                )

                self._rpc_wallet = wallet_name
                self._log.info(
                    f"Switched {self.ticker()} wallet name to {self._rpc_wallet}."
                )
                self.rpc_wallet = make_rpc_func(
                    self._rpcport,
                    self._rpcauth,
                    host=self._rpc_host,
                    wallet=self._rpc_wallet,
                )
                if change_watchonly_wallet:
                    self.rpc_wallet_watch = self.rpc_wallet
                break

        return len(wallets)

    def getNewMwebAddress(self, use_segwit=False, label="swap_receive") -> str:
        if self.useBackend():
            raise ValueError("MWEB addresses not supported in electrum mode")
        return self.rpc_wallet_mweb("getnewaddress", [label, "mweb"])

    def getNewStealthAddress(self, label=""):
        if self.useBackend():
            raise ValueError("MWEB addresses not supported in electrum mode")
        return self.getNewMwebAddress(False, label)

    def withdrawCoin(self, value, type_from: str, addr_to: str, subfee: bool) -> str:
        if self.useBackend():
            if type_from == "mweb":
                raise ValueError("MWEB withdrawals not supported in electrum mode")
            return self._withdrawCoinElectrum(value, addr_to, subfee)

        params = [addr_to, value, "", "", subfee, True, self._conf_target]
        if type_from == "mweb":
            return self.rpc_wallet_mweb("sendtoaddress", params)
        return self.rpc_wallet("sendtoaddress", params)

    def createUTXO(self, value_sats: int):
        # Create a new address and send value_sats to it

        spendable_balance = self.getSpendableBalance()
        if spendable_balance < value_sats:
            raise ValueError("Balance too low")

        address = self.getNewAddress(self._use_segwit, "create_utxo")
        return (
            self.withdrawCoin(self.format_amount(value_sats), "plain", address, False),
            address,
        )

    def getWalletInfo(self):
        rv = super(LTCInterface, self).getWalletInfo()
        if not self.useBackend():
            try:
                mweb_info = self.rpc_wallet_mweb("getwalletinfo")
                rv["mweb_balance"] = mweb_info["balance"]
                rv["mweb_unconfirmed"] = mweb_info["unconfirmed_balance"]
                rv["mweb_immature"] = mweb_info["immature_balance"]
            except Exception:
                pass
        return rv

    def getUnspentsByAddr(self):
        unspent_addr = dict()

        if self.useBackend():
            wm = self.getWalletManager()
            if wm:
                addresses = wm.getAllAddresses(self.coin_type())
                if addresses:
                    return self._backend.getBalance(addresses)
            return unspent_addr

        unspent = self.rpc_wallet("listunspent")
        for u in unspent:
            if u.get("spendable", False) is False:
                continue
            if u.get("solvable", False) is False:  # Filter out mweb outputs
                continue
            if "address" not in u:
                continue
            if "desc" in u:
                desc = u["desc"]
                if self.using_segwit:
                    if self.use_p2shp2wsh():
                        if not desc.startswith("sh(wpkh"):
                            continue
                    else:
                        if not desc.startswith("wpkh"):
                            continue
                else:
                    if not desc.startswith("pkh"):
                        continue
            unspent_addr[u["address"]] = unspent_addr.get(
                u["address"], 0
            ) + self.make_int(u["amount"], r=1)
        return unspent_addr

    def unlockWallet(self, password: str, check_seed: bool = True) -> None:
        if password == "":
            return
        self._log.info("unlockWallet - {}".format(self.ticker()))

        if self.useBackend():
            return

        wallets = self.rpc("listwallets")
        if self._rpc_wallet not in wallets:
            try:
                self.rpc("loadwallet", [self._rpc_wallet])
            except Exception as e:
                if "does not exist" in str(e) or "Path does not exist" in str(e):
                    try:
                        wallet_dirs = self.rpc("listwalletdir")
                        existing = [w["name"] for w in wallet_dirs.get("wallets", [])]
                    except Exception:
                        existing = []
                    if existing:
                        raise ValueError(
                            f'{self.coin_name()} wallet "{self._rpc_wallet}" does not exist.'
                            f" Other wallets found on disk: {existing}."
                            f' Set "wallet_name" in your {self.coin_name()} config to the correct wallet name,'
                            f" or use restorewallet to set the wallet name."
                        )
                    self._log.info(
                        f'Creating wallet "{self._rpc_wallet}" for {self.coin_name()}.'
                    )
                    self.rpc(
                        "createwallet",
                        [
                            self._rpc_wallet,
                            False,
                            True,
                            password,
                            False,
                            self._use_descriptors,
                        ],
                    )
                else:
                    raise

        try:
            seed_id = self.getWalletSeedID()
            needs_seed_init = seed_id == "Not found"
        except Exception as e:
            self._log.debug(f"getWalletSeedID failed: {e}")
            needs_seed_init = True
        if needs_seed_init:
            self._log.info(f"Initializing HD seed for {self.coin_name()}.")
            self._sc.initialiseWallet(self.coin_type())
            if password:
                self._log.info(f"Encrypting {self.coin_name()} wallet.")
                try:
                    self.rpc_wallet("encryptwallet", [password], timeout=120)
                except Exception as e:
                    self._log.debug(f"encryptwallet returned: {e}")
                import time

                for i in range(10):
                    time.sleep(1)
                    try:
                        self.rpc("listwallets")
                        break
                    except Exception:
                        self._log.debug(
                            f"Waiting for wallet after encryption... {i + 1}/10"
                        )
                wallets = self.rpc("listwallets")
                if self._rpc_wallet not in wallets:
                    self.rpc("loadwallet", [self._rpc_wallet])
            self.setWalletSeedWarning(False)
            check_seed = False

        if self.isWalletEncrypted():
            self.rpc_wallet("walletpassphrase", [password, 100000000], timeout=120)

        if check_seed:
            self._sc.checkWalletSeed(self.coin_type())


class LTCInterfaceMWEB(LTCInterface):

    def interface_type(self) -> int:
        return Coins.LTC_MWEB

    def __init__(self, coin_settings, network, swap_client=None):
        super(LTCInterfaceMWEB, self).__init__(coin_settings, network, swap_client)
        self._rpc_wallet = coin_settings.get("mweb_wallet_name", "mweb")
        self.rpc_wallet = make_rpc_func(
            self._rpcport, self._rpcauth, host=self._rpc_host, wallet=self._rpc_wallet
        )
        self.rpc_wallet_watch = self.rpc_wallet

    def chainparams(self):
        return chainparams[Coins.LTC]

    def chainparams_network(self):
        return chainparams[Coins.LTC][self._network]

    def coin_name(self) -> str:
        coin_chainparams = chainparams[Coins.LTC]
        return coin_chainparams["name"].capitalize() + " MWEB"

    def ticker(self) -> str:
        ticker = chainparams[Coins.LTC]["ticker"]
        if self._network == "testnet":
            ticker = "t" + ticker
        elif self._network == "regtest":
            ticker = "rt" + ticker
        return ticker + "_MWEB"

    def getNewAddress(self, use_segwit=False, label="swap_receive") -> str:
        return self.getNewMwebAddress()

    def has_mweb_wallet(self) -> bool:
        return "mweb" in self.rpc("listwallets")

    def init_wallet(self, password=None):
        # If system is encrypted mweb wallet will be created at first unlock

        self._log.info("init_wallet - {}".format(self.ticker()))

        wallets = self.rpc("listwallets")
        if self._rpc_wallet not in wallets:
            try:
                self.rpc("loadwallet", [self._rpc_wallet])
                self._log.debug(f'Loaded existing wallet "{self._rpc_wallet}".')
            except Exception as e:
                if "does not exist" in str(e) or "Path does not exist" in str(e):
                    self._log.info(
                        f'Creating wallet "{self._rpc_wallet}" for {self.coin_name()}.'
                    )
                    self.rpc(
                        "createwallet",
                        [
                            self._rpc_wallet,
                            False,
                            True,
                            password,
                            False,
                            self._use_descriptors,
                        ],
                    )
                else:
                    raise

        wallets = self.rpc("listwallets")
        if "mweb" not in wallets:
            try:
                self.rpc("loadwallet", ["mweb"])
                self._log.debug("Loaded existing MWEB wallet.")
            except Exception as e:
                if "does not exist" in str(e) or "Path does not exist" in str(e):
                    self._log.info(f"Creating MWEB wallet for {self.coin_name()}.")
                    # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup
                    self.rpc(
                        "createwallet",
                        ["mweb", False, True, password, False, False, True],
                    )
                else:
                    raise

        if password is not None:
            # Max timeout value, ~3 years
            self.rpc_wallet("walletpassphrase", [password, 100000000], timeout=120)

        if self.getWalletSeedID() == "Not found":
            self._sc.initialiseWallet(self.interface_type())

            # Workaround to trigger mweb_spk_man->LoadMWEBKeychain()
            self.rpc("unloadwallet", ["mweb"])
            self.rpc("loadwallet", ["mweb"])
            if password is not None:
                self.rpc_wallet("walletpassphrase", [password, 100000000], timeout=120)
            self.rpc_wallet("keypoolrefill")

    def unlockWallet(self, password: str, check_seed: bool = True) -> None:
        if password == "":
            return
        self._log.info("unlockWallet - {}".format(self.ticker()))

        if self.useBackend():
            return

        if not self.has_mweb_wallet():
            self.init_wallet(password)
        else:
            self.rpc_wallet("walletpassphrase", [password, 100000000], timeout=120)
            try:
                seed_id = self.getWalletSeedID()
                needs_seed_init = seed_id == "Not found"
            except Exception as e:
                self._log.debug(f"getWalletSeedID failed: {e}")
                needs_seed_init = True
            if needs_seed_init:
                self._log.info(f"Initializing HD seed for {self.coin_name()}.")
                self._sc.initialiseWallet(self.interface_type())

        if check_seed:
            self._sc.checkWalletSeed(self.interface_type())
