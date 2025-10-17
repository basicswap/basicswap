#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import basicswap.util_xmr as xmr_util
from basicswap.chainparams import SAL_COIN, Coins
from basicswap.util import b2h, TemporaryError
from .xmr import XMRInterface


class SALInterface(XMRInterface):

    @staticmethod
    def coin_type():
        return Coins.SAL

    @staticmethod
    def ticker_str() -> int:
        return Coins.SAL.name

    @staticmethod
    def COIN():
        return SAL_COIN

    @staticmethod
    def exp() -> int:
        return 8

    @staticmethod
    def depth_spendable() -> int:
        return 20
    
    def getMainAddress(self) -> str:
        """Override to specify SAL1 asset type"""
        return self.rpc_wallet('get_address', {'account_index': 0, 'asset_type': 'SAL1'})['address']
    
    def createTx(self, addr_to, amount, priority=2, subaddr_indices=None):
        """Override to specify SAL1 asset type for transactions"""
        params = {
            'destinations': [{'amount': amount, 'address': addr_to}],
            'priority': priority,
            'asset_type': 'SAL1'
        }
        if subaddr_indices:
            params['subaddr_indices'] = subaddr_indices
        return self.rpc_wallet('transfer', params)
    
    def getUnspentOutputs(self, subaddr_indices=None):
        """Override to specify SAL1 asset type"""
        params = {'asset_type': 'SAL1'}
        if subaddr_indices:
            params['subaddr_indices'] = subaddr_indices
        return self.rpc_wallet('incoming_transfers', params)

    def getCachedMainWalletAddress(self, session=None):
        """Return Carrot address for seed verification"""
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            result = self.rpc_wallet('get_address', {'account_index': 0})
            # Top-level 'address' is legacy - must use addresses[0].address_carrot
            if 'addresses' in result and len(result['addresses']) > 0:
                return result['addresses'][0]['address_carrot']
            return result.get('address', '')  # Fallback

    def getBalance(self, subaddress_indices=None):
        """Override to specify SAL1 asset type for balance queries"""
        params = {'asset_type': 'SAL1'}
        if subaddress_indices:
            params['address_indices'] = subaddress_indices
        return self.rpc_wallet('get_balance', params)  # Make sure this returns a dict

    def getWalletInfo(self):
        with self._mx_wallet:
            try:
                self.openWallet(self._wallet_filename)
            except Exception as e:
                if "Failed to open wallet" in str(e):
                    return {
                        "encrypted": True,
                        "locked": True,
                        "balance": 0,
                        "unconfirmed_balance": 0,
                    }
                raise e

            rv = {}
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            # Salvium wallets need to receive SAL1 before they can query balance
            try:
                balance_info = self.rpc_wallet("get_balance", {"asset_type": "SAL1"})

                # Handle response format - could be array or single balance
                if 'balances' in balance_info:
                    sal_balance = next((b for b in balance_info['balances'] if b.get('asset_type') == 'SAL1'), None)
                    if sal_balance:
                        unlocked = sal_balance.get('unlocked_balance', 0)
                        total = sal_balance.get('balance', 0)
                    else:
                        unlocked = total = 0
                else:
                    unlocked = balance_info.get('unlocked_balance', 0)
                    total = balance_info.get('balance', 0)

            except Exception as e:
                if "not found in wallet" in str(e):
                    self._log.info(f"{self.coin_name()} wallet has no SAL1 yet - needs to receive funds first")
                    unlocked = total = 0
                else:
                    raise

            rv["wallet_blocks"] = self.rpc_wallet("get_height")["height"]
            rv["balance"] = self.format_amount(unlocked)
            rv["unconfirmed_balance"] = self.format_amount(total - unlocked)
            rv["encrypted"] = False if self._wallet_password is None else True
            rv["locked"] = False
            return rv

    def getMainWalletAddress(self) -> str:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            return self.rpc_wallet("get_address", {"asset_type": "SAL1"})["address"]

    def getNewAddress(self, placeholder) -> str:
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            new_address = self.rpc_wallet("create_address", {
                "account_index": 0,
                "asset_type": "SAL1"
            })["address"]
            self.rpc_wallet("store")
            return new_address

    def threadPollSALChainState(swap_client, coin_type):
        swap_client.log.info('threadPollSALChainState starting')
        while not swap_client.delay_event.is_set():
            try:
                swap_client.ci(coin_type).checkWallets()
            except Exception as e:
                swap_client.log.error(f'threadPollSALChainState error: {e}')
            swap_client.delay_event.wait(swap_client._check_wallet_seconds)

    def encodeSharedAddress(self, Kbv: bytes, Kbs: bytes) -> str:
        """Override to use Carrot addressing for shared/swap addresses"""
        return xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)

    def publishBLockTx(
        self,
        kbv: bytes,
        Kbs: bytes,
        output_amount: int,
        feerate: int,
        unlock_time: int = 0,
    ) -> bytes:
        """Override to add SAL1 asset_type"""
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")
    
            Kbv = self.getPubkey(kbv)
            shared_addr = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)
    
            params = {
                "destinations": [{"amount": output_amount, "address": shared_addr, "asset_type": "SAL1"}],
                "source_asset": "SAL1",
                "dest_asset": "SAL1",
                "tx_type": 3,  # TRANSFER
                "unlock_time": unlock_time,
            }
            if self._fee_priority > 0:
                params["priority"] = self._fee_priority
            rv = self.rpc_wallet("transfer", params)
            self._log.info(
                "publishBLockTx {} to address_b58 {}".format(
                    self._log.id(rv["tx_hash"]),
                    self._log.addr(shared_addr),
                )
            )
            tx_hash = bytes.fromhex(rv["tx_hash"])
            return tx_hash

    def withdrawCoin(
        self, value, addr_to: str, sweepall: bool, estimate_fee: bool = False
    ) -> str:
        """Override to add SAL1 asset_type"""
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            if sweepall:
                balance = self.rpc_wallet("get_balance", {"asset_type": "SAL1"})
                # Handle balances array format
                bal_info = balance
                if 'balances' in balance:
                    sal_bal = next((b for b in balance['balances'] if b.get('asset_type') == 'SAL1'), None)
                    if sal_bal:
                        bal_info = sal_bal
                    else:
                        raise ValueError("No SAL1 balance found")

                if bal_info["balance"] != bal_info["unlocked_balance"]:
                    raise ValueError("Balance must be fully confirmed to use sweep all.")

                self._log.info(
                    "{} {} sweep_all.".format(
                        self.ticker_str(),
                        "estimate fee" if estimate_fee else "withdraw",
                    )
                )
                self._log.debug("{} balance: {}".format(self.ticker_str(), bal_info["balance"]))

                params = {
                    "address": addr_to,
                    "asset_type": "SAL1",
                    "do_not_relay": estimate_fee,
                    "subaddr_indices_all": True,
                }
                if self._fee_priority > 0:
                    params["priority"] = self._fee_priority
                rv = self.rpc_wallet("sweep_all", params)
                if estimate_fee:
                    return {
                        "num_txns": len(rv["fee_list"]),
                        "sum_amount": sum(rv["amount_list"]),
                        "sum_fee": sum(rv["fee_list"]),
                        "sum_weight": sum(rv["weight_list"]),
                    }
                return rv["tx_hash_list"][0]

            value_sats: int = self.make_int(value)
            params = {
                "destinations": [{"amount": value_sats, "address": addr_to, "asset_type": "SAL1"}],
                "source_asset": "SAL1",
                "dest_asset": "SAL1",
                "tx_type": 3,  # TRANSFER
                "do_not_relay": estimate_fee,
            }
            if self._fee_priority > 0:
                params["priority"] = self._fee_priority
            rv = self.rpc_wallet("transfer", params)
            if estimate_fee:
                return {
                    "num_txns": 1,
                    "sum_amount": rv["amount"],
                    "sum_fee": rv["fee"],
                    "sum_weight": rv["weight"],
                }
            return rv["tx_hash"]

    def findTxB(
        self,
        kbv,
        Kbs,
        cb_swap_value: int,
        cb_block_confirmed: int,
        restore_height: int,
        bid_sender: bool,
        check_amount: bool = True,
    ):
        """Override to handle SAL1 asset type"""
        with self._mx_wallet:
            Kbv = self.getPubkey(kbv)
            address_b58 = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)

            kbv_le = kbv[::-1]
            params = {
                "restore_height": restore_height,
                "filename": address_b58,
                "address": address_b58,
                "viewkey": b2h(kbv_le),
            }

            try:
                self.openWallet(address_b58)
            except Exception:
                self.createWallet(params)
                self.openWallet(address_b58)

            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            # SAL requires asset_type parameter
            params = {"transfer_type": "available", "asset_type": "SAL1"}
            transfers = self.rpc_wallet("incoming_transfers", params)
            rv = None
            if "transfers" in transfers:
                for transfer in transfers["transfers"]:
                    if not transfer["unlocked"]:
                        full_tx = self.rpc_wallet(
                            "get_transfer_by_txid", {"txid": transfer["tx_hash"]}
                        )
                        unlock_time = full_tx["transfer"]["unlock_time"]
                        if unlock_time != 0:
                            self._log.warning(
                                "Coin b lock txn is locked: {}, unlock_time {}".format(
                                    transfer["tx_hash"], unlock_time
                                )
                            )
                            rv = -1
                            continue
                    if transfer["amount"] == cb_swap_value or check_amount is False:
                        return {
                            "txid": transfer["tx_hash"],
                            "amount": transfer["amount"],
                            "height": (
                                0
                                if "block_height" not in transfer
                                else transfer["block_height"]
                            ),
                        }
                    else:
                        self._log.warning(
                            "Incorrect amount detected for coin b lock txn: {}".format(
                                transfer["tx_hash"]
                            )
                        )
                        rv = -1
            return rv

    def spendBLockTx(
        self,
        chain_b_lock_txid: bytes,
        address_to: str,
        kbv: bytes,
        kbs: bytes,
        cb_swap_value: int,
        b_fee_rate: int,
        restore_height: int,
        spend_actual_balance: bool = False,
        lock_tx_vout=None,
    ) -> bytes:
        """Override to handle SAL1 asset type"""
        with self._mx_wallet:
            Kbv = self.getPubkey(kbv)
            Kbs = self.getPubkey(kbs)
            address_b58 = xmr_util.encode_address(Kbv, Kbs, self._addr_prefix)
    
            wallet_filename = address_b58 + "_spend"
    
            params = {
                "filename": wallet_filename,
                "address": address_b58,
                "viewkey": b2h(kbv[::-1]),
                "spendkey": b2h(kbs[::-1]),
                "restore_height": restore_height,
            }

            try:
                self.openWallet(wallet_filename)
            except Exception:
                self.createWallet(params)
                self.openWallet(wallet_filename)

            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            # Get SAL1 balance
            rv = self.rpc_wallet("get_balance", {"asset_type": "SAL1"})
            bal_info = rv
            if 'balances' in rv:
                sal_bal = next((b for b in rv['balances'] if b.get('asset_type') == 'SAL1'), None)
                if sal_bal:
                    bal_info = sal_bal

            if bal_info["balance"] < cb_swap_value:
                self._log.warning("Balance is too low, checking for existing spend.")
                txns = self.rpc_wallet("get_transfers", {"out": True})
                if "out" in txns:
                    txns = txns["out"]
                    if len(txns) > 0:
                        txid = txns[0]["txid"]
                        self._log.warning(f"spendBLockTx detected spending tx: {txid}.")

                        if txns[0]["address"] == address_b58:
                            return bytes.fromhex(txid)

                self._log.error(
                    "wallet {} balance {}, expected {}".format(
                        wallet_filename, bal_info["balance"], cb_swap_value
                    )
                )

                if not spend_actual_balance:
                    raise TemporaryError("Invalid balance")

            if spend_actual_balance and bal_info["balance"] != cb_swap_value:
                self._log.warning(
                    "Spending actual balance {}, not swap value {}.".format(
                        bal_info["balance"], cb_swap_value
                    )
                )
                cb_swap_value = bal_info["balance"]
            if bal_info["unlocked_balance"] < cb_swap_value:
                self._log.error(
                    "wallet {} balance {}, expected {}, blocks_to_unlock {}".format(
                        wallet_filename,
                        bal_info["unlocked_balance"],
                        cb_swap_value,
                        bal_info.get("blocks_to_unlock", 0),
                    )
                )
                raise TemporaryError("Invalid unlocked_balance")

            params = {"address": address_to, "asset_type": "SAL1"}
            if self._fee_priority > 0:
                params["priority"] = self._fee_priority

            rv = self.rpc_wallet("sweep_all", params)
    
            return bytes.fromhex(rv["tx_hash_list"][0])

    def findTxnByHash(self, txid):
        """Override to handle SAL1 asset type"""
        with self._mx_wallet:
            self.openWallet(self._wallet_filename)
            self.rpc_wallet("refresh")
            self._log.debug(f"Refreshing {self.coin_name()} wallet")

            try:
                current_height = self.rpc2("get_height", timeout=self._rpctimeout)["height"]
                self._log.info(
                    f"findTxnByHash {self.ticker_str()} current_height {current_height}\nhash: {txid}"
                )
            except Exception as e:
                self._log.info("rpc failed %s", str(e))
                current_height = None

            # SAL requires asset_type parameter
            params = {"transfer_type": "available", "asset_type": "SAL1"}
            rv = self.rpc_wallet("incoming_transfers", params)
            if "transfers" in rv:
                for transfer in rv["transfers"]:
                    if transfer["tx_hash"] == txid and (
                        current_height is None
                        or current_height - transfer["block_height"] > self.blocks_confirmed
                    ):
                        return {
                            "txid": transfer["tx_hash"],
                            "amount": transfer["amount"],
                            "height": transfer["block_height"],
                        }

            return None

    def initialiseWallet(self, key_view: bytes, key_spend: bytes, restore_height=None) -> None:
        import os
        self._log.info(f"=== SAL initialiseWallet called ===")

        wallet_path = os.path.join(self._sc.getChainClientSettings(self.coin_type())['datadir'], 'wallets', self._wallet_filename)
        self._log.info(f"Checking: {wallet_path}.keys")
        self._log.info(f"File exists: {os.path.exists(wallet_path + '.keys')}")

        # If wallet file exists, don't recreate
        if os.path.exists(wallet_path + '.keys'):
            self._log.info(f"Salvium wallet file EXISTS - NOT recreating")
            return

        self._log.info(f"Salvium wallet doesn't exist - CREATING")
        # Wallet doesn't exist, create it
        super().initialiseWallet(key_view, key_spend, restore_height)
        self._log.info(f"=== SAL initialiseWallet complete ===")

    def getAddressFromKeys(self, key_view: bytes, key_spend: bytes) -> str:
        """Salvium Carrot addresses cannot be derived - must query wallet RPC"""
        with self._mx_wallet:
            try:
                # The wallet should already exist - just open and query it
                self.openWallet(self._wallet_filename)
                result = self.rpc_wallet('get_address', {'account_index': 0})
            
                if 'addresses' in result and len(result['addresses']) > 0:
                    addr = result['addresses'][0]['address_carrot']
                    self._log.info(f"getAddressFromKeys returning: {addr}")
                    return addr
            except Exception as e:
                self._log.error(f"Failed to get Salvium address from wallet: {e}")
                raise ValueError("Salvium Carrot addresses require wallet RPC - cannot derive from keys alone") from e
        
            raise ValueError("Salvium wallet returned no addresses")

    def getSpendableBalance(self) -> int:
        """Override to handle SAL's balance array structure"""
        balance_info = self.getBalance()
        # SAL returns: {"balances": [{"asset_type": "SAL1", "unlocked_balance": X}]}
        if 'balances' in balance_info and len(balance_info['balances']) > 0:
            for bal in balance_info['balances']:
                if bal.get('asset_type') == 'SAL1':
                    return bal.get('unlocked_balance', 0)
        return 0

