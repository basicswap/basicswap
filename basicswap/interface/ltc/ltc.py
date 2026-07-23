# -*- coding: utf-8 -*-

# Copyright (c) 2020-2023 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.interface.btc.btc import BTCInterface
from basicswap.rpc import make_rpc_func
from basicswap.chainparams import Coins, chainparams
from basicswap.interface.ltc.util import check_header_pow_scrypt


class LTCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.LTC

    def __init__(self, coin_settings, network, swap_client=None, **kwargs):
        super().__init__(
            coin_settings=coin_settings,
            network=network,
            swap_client=swap_client,
            **kwargs,
        )
        self._rpc_wallet_mweb = coin_settings.get("mweb_wallet_name", "mweb")
        self.rpc_wallet_mweb = make_rpc_func(
            self._rpcport,
            self._rpcauth,
            host=self._rpc_host,
            wallet=self._rpc_wallet_mweb,
        )

    @staticmethod
    def _checkHeaderPoW(header_bytes: bytes) -> bool:
        return check_header_pow_scrypt(header_bytes)

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

    def _annotateWalletTransactions(self, transactions, count, skip, include_watchonly):
        try:
            mweb_txns = self.rpc_wallet_mweb(
                "listtransactions", ["*", count, skip, include_watchonly]
            )
        except Exception as e:
            self._log.error(f"listWalletTransactions mweb failed: {e}")
            return transactions

        seen = {
            (tx.get("txid"), tx.get("category"), tx.get("address"), tx.get("vout"))
            for tx in transactions
        }
        for tx in mweb_txns:
            key = (
                tx.get("txid"),
                tx.get("category"),
                tx.get("address"),
                tx.get("vout"),
            )
            if key in seen:
                continue
            tx["tx_class"] = "mweb"
            transactions.append(tx)
            seen.add(key)

        transactions.sort(key=lambda t: t.get("time", t.get("timereceived", 0)) or 0)
        return transactions

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
            utxo_address: str = u["address"]
            if any(
                utxo_address.startswith(prefix) for prefix in ("ltcmweb1", "tmweb1")
            ):
                continue
            if "desc" in u:
                desc = u["desc"]
                if self.using_segwit():
                    if self.use_p2shp2wsh():
                        if not desc.startswith("sh(wpkh"):
                            continue
                    else:
                        if not desc.startswith("wpkh"):
                            continue
                else:
                    if not desc.startswith("pkh"):
                        continue
            unspent_addr[utxo_address] = unspent_addr.get(
                utxo_address, 0
            ) + self.make_int(u["amount"], r=1)
        return unspent_addr

    def getMWEBBalance(self) -> int:
        if self.useBackend():
            raise ValueError("MWEB not supported in electrum mode")

        value: int = 0
        unspent = self.rpc_wallet(
            "listunspent",
            [
                0,
            ],
        )
        for u in unspent:
            if "address" not in u:
                continue
            utxo_address: str = u["address"]
            if any(
                utxo_address.startswith(prefix) for prefix in ("ltcmweb1", "tmweb1")
            ):
                value += self.make_int(u["amount"], r=1)
        return value

    def convertMWEBBalance(self):
        if self.useBackend():
            raise ValueError("MWEB not supported in electrum mode")

        self._log.info(f"convertMWEBBalance - {self.ticker()}")
        locked_before = self.rpc_wallet("listlockunspent")
        lock_utxos = []
        try:
            # Hack: mark all the other utxos as unspendable, alternative is to use a mweb_transfer wallet
            utxos = self.rpc_wallet("listunspent")
            mweb_amount: int = 0
            for utxo in utxos:
                utxo_address: str = utxo.get("address", "")
                if any(
                    utxo_address.startswith(prefix) for prefix in ("ltcmweb1", "tmweb1")
                ):
                    mweb_amount += self.make_int(utxo["amount"], r=1)
                    continue
                utxo_op = {"txid": utxo["txid"], "vout": utxo["vout"]}
                if utxo_op in locked_before:
                    continue
                lock_utxos.append(utxo_op)

            if mweb_amount == 0:
                raise ValueError("No MWEB outputs to convert")
            self.rpc_wallet("lockunspent", [False, lock_utxos])
            subfee_to_mweb: bool = True
            convert_value = self.format_amount(mweb_amount)
            plain_addr: str = self.rpc_wallet("getnewaddress", ["transfer", "bech32"])

            # Double check generated address is owned by this wallet
            if not self.isAddressMine(plain_addr):
                raise ValueError("Generated address not owned by wallet!")
            params = [
                plain_addr,
                convert_value,
                "",
                "",
                subfee_to_mweb,
                True,
                self._conf_target,
            ]
            txid = self.rpc_wallet("sendtoaddress", params)

            self._log.info(f"MWEB in plain converted in txid: {self._log.id(txid)}")
            return txid
        finally:
            self.rpc_wallet("lockunspent", [True, lock_utxos])

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
                    if len(existing) == 0:
                        self._log.info(
                            f'Creating wallet "{self._rpc_wallet}" for {self.coin_name()}.'
                        )
                        # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
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

    def __init__(self, coin_settings, network, swap_client=None, **kwargs):
        super().__init__(
            coin_settings=coin_settings,
            network=network,
            swap_client=swap_client,
            **kwargs,
        )
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

        wallet_name: str = self._rpc_wallet
        self._log.info(f"init_wallet - {self.ticker()}")

        wallets = self.rpc("listwallets")
        if wallet_name not in wallets:
            try:
                self.rpc("loadwallet", [wallet_name])
                self._log.debug(f'Loaded existing wallet "{wallet_name}".')
            except Exception as e:
                if "does not exist" in str(e) or "Path does not exist" in str(e):
                    self._log.info(
                        f'Creating wallet "{wallet_name}" for {self.coin_name()}.'
                    )
                    # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
                    self.rpc(
                        "createwallet",
                        [
                            wallet_name,
                            False,
                            True,
                            password,
                            False,
                            self._use_descriptors,
                        ],
                    )
                else:
                    raise

        if password is not None:
            # Max timeout value, ~3 years
            self.rpc_wallet("walletpassphrase", [password, 100000000], timeout=120)

        if self.getWalletSeedID() == "Not found":
            self._sc.initialiseWallet(self.interface_type())

            # Workaround to trigger mweb_spk_man->LoadMWEBKeychain()
            self.rpc("unloadwallet", [wallet_name])
            self.rpc("loadwallet", [wallet_name])
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
