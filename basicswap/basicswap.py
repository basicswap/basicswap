# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import collections
import concurrent.futures
import copy
import datetime as dt
import json
import logging
import os
import random
import secrets
import shutil
import sqlite3
import string
import struct
import sys
import threading
import time
import traceback
import zmq

from typing import Optional

from . import __version__
from .base import BaseApp
from .basicswap_util import (
    ActionTypes,
    AddressTypes,
    AutomationOverrideOptions,
    BidStates,
    canAcceptBidState,
    ConnectionRequestTypes,
    DebugTypes,
    describeEventEntry,
    EventLogTypes,
    fiatTicker,
    get_api_key_setting,
    getLastBidState,
    getVoutByAddress,
    getVoutByScriptPubKey,
    inactive_states,
    isActiveBidState,
    KeyTypes,
    MessageNetworks,
    MessageNetworkLinkTypes,
    MessageTypes,
    NotificationTypes as NT,
    OfferStates,
    strBidState,
    SwapTypes,
    TxLockTypes,
    TxStates,
    TxTypes,
    VisibilityOverrideOptions,
    XmrSplitMsgTypes,
)
from .chainparams import (
    Coins,
    chainparams,
    Fiat,
    ticker_map,
)
from .db_upgrades import upgradeDatabase, upgradeDatabaseData
from .db_util import remove_expired_data
from .rpc import escape_rpcauth
from .rpc_xmr import make_xmr_rpc2_func
from .ui.util import getCoinName
from .ui.app import UIApp
from .util import (
    AutomationConstraint,
    AutomationConstraintTemporary,
    LockedCoinError,
    TemporaryError,
    InactiveCoin,
    b2h,
    b2i,
    format_timestamp,
    DeserialiseNum,
    h2b,
    i2b,
    zeroIfNone,
    make_int,
    ensure,
)
from .util.address import (
    toWIF,
    decodeWif,
    decodeAddress,
    pubkeyToAddress,
)
from .util.crypto import sha256
from .util.logging import LogCategories as LC
from .util.network import is_private_ip_address
from .util.smsg import smsgGetID
from .interface.base import Curves
from .interface.part import PARTInterface, PARTInterfaceAnon, PARTInterfaceBlind
from .explorers import (
    default_chart_api_key,
    default_coingecko_api_key,
)
from .script import OpCodes
from .messages_npb import (
    ADSBidIntentAcceptMessage,
    ADSBidIntentMessage,
    BidAcceptMessage,
    BidMessage,
    ConnectReqMessage,
    OfferMessage,
    OfferRevokeMessage,
    XmrBidAcceptMessage,
    XmrBidLockReleaseMessage,
    XmrBidLockSpendTxMessage,
    XmrBidLockTxSigsMessage,
    XmrBidMessage,
    XmrSplitMessage,
)
from .db import (
    Action,
    AutomationLink,
    AutomationStrategy,
    Bid,
    Concepts,
    create_db,
    CURRENT_DB_VERSION,
    DirectMessageRoute,
    DirectMessageRouteLink,
    EventLog,
    getOrderByStr,
    KnownIdentity,
    MessageLink,
    Notification,
    Offer,
    pack_state,
    PooledAddress,
    PrefundedTx,
    SentOffer,
    SmsgAddress,
    SwapTx,
    Wallets,
    XmrOffer,
    XmrSplitData,
    XmrSwap,
)
from .explorers import (
    ExplorerInsight,
    ExplorerBitAps,
    ExplorerChainz,
)
from .network.simplex import (
    encryptMsg,
    getJoinedSimplexLink,
    getResponseData,
)
from .network.bsx_network import BSXNetwork, networkTypeToID
from .network.util import getMsgPubkey
import basicswap.config as cfg
import basicswap.network.network as bsn
import basicswap.protocols.atomic_swap_1 as atomic_swap_1
import basicswap.protocols.xmr_swap_1 as xmr_swap_1


PROTOCOL_VERSION_SECRET_HASH = 5
MINPROTO_VERSION_SECRET_HASH = 4

PROTOCOL_VERSION_ADAPTOR_SIG = 4
MINPROTO_VERSION_ADAPTOR_SIG = 4

MINPROTO_VERSION = min(MINPROTO_VERSION_SECRET_HASH, MINPROTO_VERSION_ADAPTOR_SIG)
MAXPROTO_VERSION = 10


def validOfferStateToReceiveBid(offer_state):
    if offer_state == OfferStates.OFFER_RECEIVED:
        return True
    if offer_state == OfferStates.OFFER_SENT:
        return True
    return False


def checkAndNotifyBalanceChange(
    swap_client, coin_type, ci, cc, new_height, trigger_source="block"
):
    if not swap_client.ws_server:
        return

    try:
        blockchain_info = ci.getBlockchainInfo()
        verification_progress = blockchain_info.get("verificationprogress", 1.0)
        if verification_progress < 0.99:
            return
    except Exception:
        return

    try:
        current_balance = ci.getSpendableBalance()
        current_total_balance = swap_client.getTotalBalance(coin_type)
        cached_balance = cc.get("cached_balance", None)
        cached_total_balance = cc.get("cached_total_balance", None)

        current_unconfirmed = current_total_balance - current_balance
        cached_unconfirmed = cc.get("cached_unconfirmed", None)

        if (
            cached_balance is None
            or current_balance != cached_balance
            or cached_total_balance is None
            or current_total_balance != cached_total_balance
            or cached_unconfirmed is None
            or current_unconfirmed != cached_unconfirmed
        ):
            cc["cached_balance"] = current_balance
            cc["cached_total_balance"] = current_total_balance
            cc["cached_unconfirmed"] = current_unconfirmed
            balance_event = {
                "event": "coin_balance_updated",
                "coin": ci.ticker(),
                "height": new_height,
                "trigger": trigger_source,
            }
            swap_client.ws_server.send_message_to_all(json.dumps(balance_event))
    except Exception:
        cc["cached_balance"] = None
        cc["cached_total_balance"] = None
        cc["cached_unconfirmed"] = None


def threadPollXMRChainState(swap_client, coin_type):
    ci = swap_client.ci(coin_type)
    cc = swap_client.coin_clients[coin_type]
    while not swap_client.chainstate_delay_event.is_set():
        try:
            new_height = ci.getChainHeight()
            if new_height != cc["chain_height"]:
                swap_client.log.debug(
                    f"New {ci.ticker()} block at height: {new_height}"
                )
                with swap_client.mxDB:
                    cc["chain_height"] = new_height

                checkAndNotifyBalanceChange(
                    swap_client, coin_type, ci, cc, new_height, "block"
                )

        except Exception as e:
            swap_client.log.warning(
                f"threadPollXMRChainState {ci.ticker()}, error: {e}"
            )
        swap_client.chainstate_delay_event.wait(
            random.randrange(20, 30)
        )  # Random to stagger updates


def threadPollChainState(swap_client, coin_type):
    ci = swap_client.ci(coin_type)
    cc = swap_client.coin_clients[coin_type]

    if coin_type == Coins.PART and swap_client._zmq_queue_enabled:
        poll_delay_range = (40, 60)
    else:
        poll_delay_range = (20, 30)

    while not swap_client.chainstate_delay_event.is_set():
        try:
            chain_state = ci.getBlockchainInfo()
            new_height: int = chain_state["blocks"]
            if chain_state["bestblockhash"] != cc["chain_best_block"]:
                swap_client.log.debug(
                    f"New {ci.ticker()} block at height: {new_height}"
                )
                with swap_client.mxDB:
                    cc["chain_height"] = new_height
                    cc["chain_best_block"] = chain_state["bestblockhash"]
                    if "mediantime" in chain_state:
                        cc["chain_median_time"] = chain_state["mediantime"]

                checkAndNotifyBalanceChange(
                    swap_client, coin_type, ci, cc, new_height, "block"
                )

        except Exception as e:
            swap_client.log.warning(f"threadPollChainState {ci.ticker()}, error: {e}")
        swap_client.chainstate_delay_event.wait(random.randrange(*poll_delay_range))


class WatchedOutput:  # Watch for spends
    __slots__ = ("bid_id", "txid_hex", "vout", "tx_type", "swap_type")

    def __init__(self, bid_id: bytes, txid_hex: str, vout, tx_type, swap_type):
        self.bid_id = bid_id
        self.txid_hex = txid_hex
        self.vout = vout
        self.tx_type = tx_type
        self.swap_type = swap_type


class WatchedScript:  # Watch for txns containing outputs
    __slots__ = ("bid_id", "script", "tx_type", "swap_type")

    def __init__(self, bid_id: bytes, script: bytes, tx_type, swap_type):
        self.bid_id = bid_id
        self.script = script
        self.tx_type = tx_type
        self.swap_type = swap_type


class WatchedTransaction:
    # TODO
    # Watch for presence in mempool (getrawtransaction)
    def __init__(self, bid_id: bytes, txid_hex: str, tx_type, swap_type):
        self.bid_id = bid_id
        self.txid_hex = txid_hex
        self.tx_type = tx_type
        self.swap_type = swap_type


class BasicSwap(BaseApp, BSXNetwork, UIApp):
    ws_server = None
    protocolInterfaces = {
        SwapTypes.SELLER_FIRST: atomic_swap_1.AtomicSwapInterface(),
        SwapTypes.XMR_SWAP: xmr_swap_1.XmrSwapInterface(),
    }

    def __init__(
        self,
        data_dir,
        settings,
        chain,
        log_name="BasicSwap",
        transient_instance=False,
        extra_opts={},
    ):
        super().__init__(data_dir, settings, chain, log_name)

        v = __version__.split(".")
        self._version = struct.pack(">HHH", int(v[0]), int(v[1]), int(v[2]))

        self._transient_instance = transient_instance
        self.check_actions_seconds = self.get_int_setting(
            "check_actions_seconds", 10, 1, 10 * 60
        )
        self.check_expired_seconds = self.get_int_setting(
            "check_expired_seconds", 5 * 60, 1, 10 * 60
        )  # Expire DB records and smsg messages
        self.check_expiring_bids_offers_seconds = self.get_int_setting(
            "check_expiring_bids_offers_seconds", 60, 1, 10 * 60
        )  # Set offer and bid states to expired
        self.check_progress_seconds = self.get_int_setting(
            "check_progress_seconds", 60, 1, 10 * 60
        )
        self.check_watched_seconds = self.get_int_setting(
            "check_watched_seconds", 60, 1, 10 * 60
        )
        self.check_split_messages_seconds = self.get_int_setting(
            "check_split_messages_seconds", 20, 1, 10 * 60
        )
        # Retry auto accept for bids at BID_AACCEPT_DELAY, also updates when bids complete
        self.check_delayed_auto_accept_seconds = self.get_int_setting(
            "check_delayed_auto_accept_seconds", 60, 1, 20 * 60
        )
        self.startup_tries = self.get_int_setting(
            "startup_tries", 21, 1, 100
        )  # Seconds waited for will be (x(1 + x+1) / 2
        self.debug_ui = self.settings.get("debug_ui", False)
        self._debug_cases = []
        self._last_checked_actions = 0
        self._last_checked_expired = 0
        self._last_checked_expiring_bids_offers = 0
        self._last_checked_progress = 0
        self._last_checked_watched = 0
        self._last_checked_split_messages = 0
        self._last_checked_delayed_auto_accept = 0
        self._possibly_revoked_offers = collections.deque(
            [], maxlen=48
        )  # TODO: improve
        self._expiring_bids = []  # List of bids expiring soon
        self._expiring_offers = []  # List of offers expiring soon
        self._updating_wallets_info = {}
        self._last_updated_wallets_info = 0

        self.check_updates_seconds = self.get_int_setting(
            "check_updates_seconds", 24 * 60 * 60, 60 * 60, 7 * 24 * 60 * 60
        )
        self._last_checked_updates = 0
        self._latest_version = None
        self._update_available = False
        self._notifications_enabled = self.settings.get("notifications_enabled", True)
        self._disabled_notification_types = self.settings.get(
            "disabled_notification_types", []
        )
        self._keep_notifications = self.settings.get("keep_notifications", 50)
        self._show_notifications = self.settings.get("show_notifications", 10)
        self._expire_db_records = self.settings.get("expire_db_records", False)
        self._expire_db_records_after = self.get_int_setting(
            "expire_db_records_after", 7 * 86400, 0, 31 * 86400
        )  # Seconds
        self._sc_lock_tx_timeout = self.get_int_setting(
            "sc_lock_tx_timeout", 48 * 3600, 3600, 6 * 3600
        )  # Seconds
        self._sc_lock_tx_mempool_timeout = self.get_int_setting(
            "sc_lock_tx_mempool_timeout", 48 * 3600, 3600, 12 * 3600
        )  # Seconds

        self._max_logfile_bytes = self.settings.get(
            "max_logfile_size", 100
        )  # In MB. Set to 0 to disable truncation
        if self._max_logfile_bytes > 0:
            self._max_logfile_bytes *= 1024 * 1024
        self._max_logfiles = self.get_int_setting("max_logfiles", 10, 1, 100)

        self._notifications_cache = {}
        self._is_encrypted = None
        self._is_locked = None

        self._max_transient_errors = self.settings.get(
            "max_transient_errors", 100
        )  # Number of retries before a bid will stop when encountering transient errors.

        # Keep sensitive info out of the log file (WIP)
        self.log.safe_logs = self.settings.get("safe_logs", False)
        if self.log.safe_logs and self.debug:
            raise ValueError("Safe logs mode is incompatible with debug mode")

        if self.log.safe_logs:
            self.log.warning("Safe log enabled.")
            if "safe_logs_prefix" in self.settings:
                self.log.safe_logs_prefix = self.settings["safe_logs_prefix"].encode(
                    encoding="UTF-8"
                )
            else:
                self.log.warning('Using random "safe_logs_prefix".')
                self.log.safe_logs_prefix = random.randbytes(8)

        # TODO: Set dynamically
        self.balance_only_coins = (Coins.LTC_MWEB,)
        self.scriptless_coins = (
            Coins.XMR,
            Coins.WOW,
            Coins.PART_ANON,
            Coins.FIRO,
            Coins.DOGE,
        )
        self.adaptor_swap_only_coins = self.scriptless_coins + (
            Coins.PART_BLIND,
            Coins.BCH,
        )
        self.coins_without_segwit = (Coins.PIVX, Coins.DASH)

        # TODO: Adjust ranges
        self.min_delay_event = self.get_int_setting("min_delay_event", 10, 0, 20 * 60)
        self.max_delay_event = self.get_int_setting(
            "max_delay_event", 60, self.min_delay_event, 20 * 60
        )
        self.min_delay_event_short = self.get_int_setting(
            "min_delay_event_short", 2, 0, 10 * 60
        )
        self.max_delay_event_short = self.get_int_setting(
            "max_delay_event_short", 30, self.min_delay_event_short, 10 * 60
        )

        self.min_delay_retry = self.get_int_setting("min_delay_retry", 60, 0, 20 * 60)
        self.max_delay_retry = self.get_int_setting(
            "max_delay_retry", 5 * 60, self.min_delay_retry, 20 * 60
        )

        self.min_sequence_lock_seconds = self.settings.get(
            "min_sequence_lock_seconds", 60 if self.debug else (1 * 60 * 60)
        )
        self.max_sequence_lock_seconds = self.settings.get(
            "max_sequence_lock_seconds", 96 * 60 * 60
        )

        self._wallet_update_timeout = self.settings.get("wallet_update_timeout", 10)

        self._restrict_unknown_seed_wallets = self.settings.get(
            "restrict_unknown_seed_wallets", True
        )
        self._max_check_loop_blocks = self.settings.get("max_check_loop_blocks", 100000)
        self._force_db_upgrade = self.settings.get("force_db_upgrade", False)
        self._bid_expired_leeway = 5

        self.swaps_in_progress = dict()

        self.threads = []
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="bsp"
        )

        # Encode key to match network
        wif_prefix = chainparams[Coins.PART][self.chain]["key_prefix"]
        self.network_key = toWIF(wif_prefix, decodeWif(self.settings["network_key"]))

        self.network_pubkey = self.settings["network_pubkey"]
        self.network_addr = pubkeyToAddress(
            chainparams[Coins.PART][self.chain]["pubkey_address"],
            bytes.fromhex(self.network_pubkey),
        )

        self.sqlite_file: str = os.path.join(
            self.data_dir,
            "db{}.sqlite".format("" if self.chain == "mainnet" else ("_" + self.chain)),
        )
        db_exists: bool = os.path.exists(self.sqlite_file)

        if not db_exists:
            self.log.info("First run")
            create_db(self.sqlite_file, self.log)

        cursor = self.openDB()
        try:
            self.db_version = self.getIntKV("db_version", cursor, CURRENT_DB_VERSION)
            self.db_data_version = self.getIntKV("db_data_version", cursor, 0)
            self._contract_count = self.getIntKV("contract_count", cursor, 0)
            self.commitDB()
        finally:
            self.closeDB(cursor)

        self.with_coins_override = extra_opts.get("with_coins", set())
        self.without_coins_override = extra_opts.get("without_coins", set())

        for c in Coins:
            if c in chainparams:
                self.setCoinConnectParams(c)

        if self.chain == "mainnet":
            self.coin_clients[Coins.PART]["explorers"].append(
                ExplorerInsight(
                    self, Coins.PART, "https://explorer.particl.io/particl-insight-api"
                )
            )
            self.coin_clients[Coins.LTC]["explorers"].append(
                ExplorerBitAps(
                    self, Coins.LTC, "https://api.bitaps.com/ltc/v1/blockchain"
                )
            )
            self.coin_clients[Coins.LTC]["explorers"].append(
                ExplorerChainz(
                    self, Coins.LTC, "http://chainz.cryptoid.info/ltc/api.dws"
                )
            )
        elif self.chain == "testnet":
            self.coin_clients[Coins.PART]["explorers"].append(
                ExplorerInsight(
                    self,
                    Coins.PART,
                    "https://explorer-testnet.particl.io/particl-insight-api",
                )
            )
            self.coin_clients[Coins.LTC]["explorers"].append(
                ExplorerBitAps(
                    self, Coins.LTC, "https://api.bitaps.com/ltc/testnet/v1/blockchain"
                )
            )

            # non-segwit
            # https://testnet.litecore.io/insight-api

        random.seed(secrets.randbits(128))

    def finalise(self):
        self.log.info("Finalising")

        try:
            from basicswap.ui.page_amm import stop_amm_process, get_amm_status

            amm_status = get_amm_status()
            if amm_status == "running":
                self.log.info("Stopping AMM process...")
                success, msg = stop_amm_process(self)
                if success:
                    self.log.info(f"AMM shutdown: {msg}")
                else:
                    self.log.warning(f"AMM shutdown warning: {msg}")
        except Exception as e:
            self.log.error(f"Error stopping AMM during shutdown: {e}")

        self.delay_event.set()
        self.chainstate_delay_event.set()

        if self._network:
            self._network.stopNetwork()
            self._network = None

        for t in self.threads:
            if hasattr(t, "stop") and callable(t.stop):
                t.stop()
            t.join()

        if sys.version_info[1] >= 9:
            self.thread_pool.shutdown(cancel_futures=True)
        else:
            self.thread_pool.shutdown()

        self.swaps_in_progress.clear()
        super().finalise()

    def logIDB(self, concept_id: bytes) -> str:
        return self.log.id(concept_id, prefix="B_")

    def logIDO(self, concept_id: bytes) -> str:
        return self.log.id(concept_id, prefix="O_")

    def logIDM(self, concept_id: bytes) -> str:
        return self.log.id(concept_id, prefix="M_")

    def logIDT(self, concept_id: bytes) -> str:
        return self.log.id(concept_id, prefix="T_")

    def handleSessionErrors(self, e, cursor, tag):
        if self.debug:
            self.log.error(traceback.format_exc())

        self.log.error(f"Error: {tag} - {e}")
        self.rollbackDB()

    def setCoinConnectParams(self, coin):
        # Set anything that does not require the daemon to be running
        chain_client_settings = self.getChainClientSettings(coin)

        coin_chainparams = chainparams[coin]
        coin_name: str = coin_chainparams["name"]

        bindir = os.path.expanduser(chain_client_settings.get("bindir", ""))
        datadir = os.path.expanduser(
            chain_client_settings.get(
                "datadir", os.path.join(cfg.TEST_DATADIRS, coin_name)
            )
        )

        connection_type = chain_client_settings.get("connection_type", "none")
        if (
            len(self.with_coins_override) > 0
            and coin_name not in self.with_coins_override
        ) or coin_name in self.without_coins_override:
            connection_type = "none"
        rpcauth = None
        if connection_type == "rpc":
            if "rpcauth" in chain_client_settings:
                rpcauth = chain_client_settings["rpcauth"]
                self.log.debug(
                    f"Read {Coins(coin).name} rpc credentials from json settings"
                )
            elif "rpcpassword" in chain_client_settings:
                rpcauth = (
                    chain_client_settings["rpcuser"]
                    + ":"
                    + chain_client_settings["rpcpassword"]
                )
                self.log.debug(
                    f"Read {Coins(coin).name} rpc credentials from json settings"
                )

        try:
            cursor = self.openDB()
            last_height_checked = self.getIntKV(
                "last_height_checked_" + coin_name, cursor, 0
            )
            try:
                block_check_min_time = self.getIntKV(
                    "block_check_min_time_" + coin_name, cursor
                )
            except Exception as e:  # noqa: F841
                block_check_min_time = 0xFFFFFFFFFFFFFFFF
        finally:
            self.closeDB(cursor)

        default_segwit = coin_chainparams.get("has_segwit", False)
        default_csv = coin_chainparams.get("has_csv", True)
        self.coin_clients[coin] = {
            "coin": coin,
            "name": coin_name,
            "connection_type": connection_type,
            "bindir": bindir,
            "datadir": datadir,
            "rpchost": chain_client_settings.get("rpchost", "127.0.0.1"),
            "rpcport": chain_client_settings.get(
                "rpcport", coin_chainparams[self.chain]["rpcport"]
            ),
            "rpcauth": rpcauth,
            "blocks_confirmed": chain_client_settings.get("blocks_confirmed", 6),
            "conf_target": chain_client_settings.get("conf_target", 2),
            "watched_outputs": [],
            "watched_scripts": [],
            "last_height_checked": last_height_checked,
            "block_check_min_time": block_check_min_time,
            "use_segwit": chain_client_settings.get("use_segwit", default_segwit),
            "use_csv": chain_client_settings.get("use_csv", default_csv),
            "core_version_group": chain_client_settings.get("core_version_group", 0),
            "pid": None,
            "core_version": None,
            "explorers": [],
            "chain_lookups": chain_client_settings.get("chain_lookups", "local"),
            "restore_height": chain_client_settings.get("restore_height", 0),
            "fee_priority": chain_client_settings.get("fee_priority", 0),
            # Chain state
            "chain_height": None,
            "chain_best_block": None,
            "chain_median_time": None,
        }

        # Passthrough settings
        for setting_name in (
            "use_descriptors",
            "wallet_name",
            "watch_wallet_name",
            "mweb_wallet_name",
        ):
            if setting_name in chain_client_settings:
                self.coin_clients[coin][setting_name] = chain_client_settings[
                    setting_name
                ]

        if coin in (Coins.FIRO, Coins.LTC):
            if not chain_client_settings.get("min_relay_fee"):
                chain_client_settings["min_relay_fee"] = 0.00001

        if coin == Coins.PART:
            self.coin_clients[coin]["anon_tx_ring_size"] = chain_client_settings.get(
                "anon_tx_ring_size", 12
            )
            self.coin_clients[Coins.PART_ANON] = self.coin_clients[coin]
            self.coin_clients[Coins.PART_BLIND] = self.coin_clients[coin]

        if coin == Coins.LTC:
            self.coin_clients[Coins.LTC_MWEB] = self.coin_clients[coin]

        if self.coin_clients[coin]["connection_type"] == "rpc":
            if coin == Coins.DCR:
                self.coin_clients[coin]["walletrpcport"] = chain_client_settings[
                    "walletrpcport"
                ]
            elif coin in (Coins.XMR, Coins.WOW):
                self.coin_clients[coin]["rpctimeout"] = chain_client_settings.get(
                    "rpctimeout", 60
                )
                self.coin_clients[coin]["walletrpctimeout"] = chain_client_settings.get(
                    "walletrpctimeout", 120
                )
                self.coin_clients[coin]["walletrpctimeoutlong"] = (
                    chain_client_settings.get("walletrpctimeoutlong", 600)
                )

                if not self._transient_instance and chain_client_settings.get(
                    "automatically_select_daemon", False
                ):
                    self.selectXMRRemoteDaemon(coin)

                self.coin_clients[coin]["walletrpchost"] = chain_client_settings.get(
                    "walletrpchost", "127.0.0.1"
                )
                self.coin_clients[coin]["walletrpcport"] = chain_client_settings.get(
                    "walletrpcport", chainparams[coin][self.chain]["walletrpcport"]
                )
                if "walletrpcpassword" in chain_client_settings:
                    self.coin_clients[coin]["walletrpcauth"] = (
                        chain_client_settings["walletrpcuser"],
                        chain_client_settings["walletrpcpassword"],
                    )
                else:
                    raise ValueError("Missing XMR wallet rpc credentials.")

                self.coin_clients[coin]["rpcuser"] = chain_client_settings.get(
                    "rpcuser", ""
                )
                self.coin_clients[coin]["rpcpassword"] = chain_client_settings.get(
                    "rpcpassword", ""
                )

    def getXMRTrustedDaemon(self, coin, node_host: str) -> bool:
        coin = Coins(coin)  # Errors for invalid coin value
        chain_client_settings = self.getChainClientSettings(coin)
        trusted_daemon_setting = chain_client_settings.get("trusted_daemon", True)
        self.log.debug(
            f"'trusted_daemon' setting for {getCoinName(coin)}: {trusted_daemon_setting}."
        )
        if isinstance(trusted_daemon_setting, bool):
            return trusted_daemon_setting
        if trusted_daemon_setting == "auto":
            return is_private_ip_address(node_host)
        self.log.warning(
            f"Unknown 'trusted_daemon' setting for {getCoinName(coin)}: {trusted_daemon_setting}."
        )
        return False

    def getXMRWalletProxy(self, coin, node_host: str) -> (Optional[str], Optional[int]):
        coin = Coins(coin)  # Errors for invalid coin value
        chain_client_settings = self.getChainClientSettings(coin)
        proxy_host = None
        proxy_port = None
        if self.use_tor_proxy:
            have_cc_tor_opt = "use_tor" in chain_client_settings
            if have_cc_tor_opt and chain_client_settings["use_tor"] is False:
                self.log.warning(
                    f"use_tor is true for system but false for {coin.name}."
                )
            elif have_cc_tor_opt is False and is_private_ip_address(node_host):
                self.log.warning(
                    f"Not using proxy for {coin.name} node at private ip address {node_host}."
                )
            else:
                proxy_host = self.tor_proxy_host
                proxy_port = self.tor_proxy_port
        return proxy_host, proxy_port

    def selectXMRRemoteDaemon(self, coin):
        self.log.info("Selecting remote XMR daemon.")
        chain_client_settings = self.getChainClientSettings(coin)
        remote_daemon_urls = chain_client_settings.get("remote_daemon_urls", [])

        coin_settings = self.coin_clients[coin]
        rpchost: str = coin_settings["rpchost"]
        rpcport: int = coin_settings["rpcport"]
        timeout: int = coin_settings["rpctimeout"]

        def get_rpc_func(rpcport, daemon_login, rpchost):

            proxy_host, proxy_port = self.getXMRWalletProxy(coin, rpchost)
            if proxy_host:
                self.log.info(f"Connecting through proxy at {proxy_host}.")

            if coin in (Coins.XMR, Coins.WOW):
                return make_xmr_rpc2_func(
                    rpcport,
                    daemon_login,
                    rpchost,
                    proxy_host=proxy_host,
                    proxy_port=proxy_port,
                )

        daemon_login = None
        if coin_settings.get("rpcuser", "") != "":
            daemon_login = (
                coin_settings.get("rpcuser", ""),
                coin_settings.get("rpcpassword", ""),
            )
        current_daemon_url = f"{rpchost}:{rpcport}"
        if current_daemon_url in remote_daemon_urls:
            self.log.info(f"Trying last used url {rpchost}:{rpcport}.")
            try:
                rpc2 = get_rpc_func(rpcport, daemon_login, rpchost)
                _ = rpc2("get_height", timeout=timeout)["height"]
                return True
            except Exception as e:
                self.log.warning(
                    f"Failed to set XMR remote daemon to {rpchost}:{rpcport}, {e}"
                )
        random.shuffle(remote_daemon_urls)
        for url in remote_daemon_urls:
            self.log.info(f"Trying url {url}.")
            try:
                rpchost, rpcport = url.rsplit(":", 1)
                rpc2 = get_rpc_func(rpcport, daemon_login, rpchost)
                _ = rpc2("get_height", timeout=timeout)["height"]
                coin_settings["rpchost"] = rpchost
                coin_settings["rpcport"] = rpcport
                data = {
                    "rpchost": rpchost,
                    "rpcport": rpcport,
                }
                self.editSettings(self.coin_clients[coin]["name"], data)
                return True
            except Exception as e:
                self.log.warning(f"Failed to set XMR remote daemon to {url}, {e}")

        raise ValueError("Failed to select a working XMR daemon url.")

    def isCoinActive(self, coin):
        use_coinid = coin
        interface_ind = "interface"
        if coin == Coins.PART_ANON:
            use_coinid = Coins.PART
            interface_ind = "interface_anon"
        if coin == Coins.PART_BLIND:
            use_coinid = Coins.PART
            interface_ind = "interface_blind"
        if coin == Coins.LTC_MWEB:
            use_coinid = Coins.LTC
            interface_ind = "interface_mweb"

        if use_coinid not in self.coin_clients:
            raise ValueError("Unknown coinid {}".format(int(coin)))
        return interface_ind in self.coin_clients[use_coinid]

    def ci(self, coin):  # Coin interface
        use_coinid = coin
        interface_ind = "interface"
        if coin == Coins.PART_ANON:
            use_coinid = Coins.PART
            interface_ind = "interface_anon"
        if coin == Coins.PART_BLIND:
            use_coinid = Coins.PART
            interface_ind = "interface_blind"
        if coin == Coins.LTC_MWEB:
            use_coinid = Coins.LTC
            interface_ind = "interface_mweb"

        if use_coinid not in self.coin_clients:
            raise ValueError("Unknown coinid {}".format(int(coin)))
        if interface_ind not in self.coin_clients[use_coinid]:
            raise InactiveCoin(int(coin))

        return self.coin_clients[use_coinid][interface_ind]

    def isBchXmrSwap(self, offer: Offer) -> bool:
        if offer.swap_type != SwapTypes.XMR_SWAP:
            return False
        if self.is_reverse_ads_bid(offer.coin_from, offer.coin_to):
            return offer.coin_to == Coins.BCH
        return offer.coin_from == Coins.BCH

    def pi(self, protocol_ind):
        if protocol_ind not in self.protocolInterfaces:
            raise ValueError(f"Unknown protocol_ind {protocol_ind}")
        return self.protocolInterfaces[protocol_ind]

    def createInterface(self, coin):
        if coin == Coins.PART:
            interface = PARTInterface(self.coin_clients[coin], self.chain, self)
            self.coin_clients[coin]["interface_anon"] = PARTInterfaceAnon(
                self.coin_clients[coin], self.chain, self
            )
            self.coin_clients[coin]["interface_blind"] = PARTInterfaceBlind(
                self.coin_clients[coin], self.chain, self
            )
            return interface
        elif coin == Coins.BTC:
            from .interface.btc import BTCInterface

            return BTCInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.BCH:
            from .interface.bch import BCHInterface

            return BCHInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.LTC:
            from .interface.ltc import LTCInterface, LTCInterfaceMWEB

            interface = LTCInterface(self.coin_clients[coin], self.chain, self)
            self.coin_clients[coin]["interface_mweb"] = LTCInterfaceMWEB(
                self.coin_clients[coin], self.chain, self
            )
            return interface
        elif coin == Coins.DOGE:
            from .interface.doge import DOGEInterface

            return DOGEInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.DCR:
            from .interface.dcr import DCRInterface

            return DCRInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.NMC:
            from .interface.nmc import NMCInterface

            return NMCInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.XMR:
            from .interface.xmr import XMRInterface

            return XMRInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.WOW:
            from .interface.wow import WOWInterface

            return WOWInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.PIVX:
            from .interface.pivx import PIVXInterface

            return PIVXInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.DASH:
            from .interface.dash import DASHInterface

            return DASHInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.FIRO:
            from .interface.firo import FIROInterface

            return FIROInterface(self.coin_clients[coin], self.chain, self)
        elif coin == Coins.NAV:
            from .interface.nav import NAVInterface

            return NAVInterface(self.coin_clients[coin], self.chain, self)
        else:
            raise ValueError("Unknown coin type")

    def createPassthroughInterface(self, coin):
        if coin == Coins.BTC:
            from .interface.passthrough_btc import PassthroughBTCInterface

            return PassthroughBTCInterface(self.coin_clients[coin], self.chain)
        else:
            raise ValueError("Unknown coin type")

    def setCoinRunParams(self, coin):
        cc = self.coin_clients[coin]
        if coin in (Coins.XMR, Coins.WOW):
            return
        if cc["connection_type"] == "rpc" and cc["rpcauth"] is None:
            authcookiepath = os.path.join(self.getChainDatadirPath(coin), ".cookie")

            pidfilename = cc["name"]
            if cc["name"] in (
                "bitcoin",
                "litecoin",
                "dogecoin",
                "namecoin",
                "dash",
                "firo",
                "bitcoincash",
            ):
                pidfilename += "d"

            pidfilepath = os.path.join(
                self.getChainDatadirPath(coin), pidfilename + ".pid"
            )
            self.log.debug(
                f"Reading {Coins(coin).name} rpc credentials from auth cookie {authcookiepath}",
            )
            # Wait for daemon to start
            # Test pids to ensure authcookie is read for the correct process
            datadir_pid = -1
            for i in range(20):
                try:
                    if os.name == "nt" and cc["core_version_group"] <= 17:
                        # Older core versions don't write a pid file on windows
                        pass
                    else:
                        with open(pidfilepath, "rb") as fp:
                            datadir_pid = int(fp.read().decode("UTF-8"))
                        assert datadir_pid == cc["pid"], "Mismatched pid"
                    assert os.path.exists(authcookiepath)
                    break
                except Exception as e:
                    if self.debug:
                        self.log.warning(f"Error, iteration {i}: {e}")
                    self.delay_event.wait(0.5)
            try:
                if (
                    os.name != "nt" or cc["core_version_group"] > 17
                ):  # Litecoin on windows doesn't write a pid file
                    assert datadir_pid == cc["pid"], "Mismatched pid"
                with open(authcookiepath, "rb") as fp:
                    cc["rpcauth"] = escape_rpcauth(fp.read().decode("UTF-8"))
            except Exception as e:
                self.log.error(
                    "Unable to read authcookie for %s, %s, datadir pid %d, daemon pid %s. Error: %s",
                    Coins(coin).name,
                    authcookiepath,
                    datadir_pid,
                    cc["pid"],
                    str(e),
                )
                raise ValueError("Error, terminating")

    def createCoinInterface(self, coin):
        if self.coin_clients[coin]["connection_type"] == "rpc":
            self.coin_clients[coin]["interface"] = self.createInterface(coin)
        elif self.coin_clients[coin]["connection_type"] == "passthrough":
            self.coin_clients[coin]["interface"] = self.createPassthroughInterface(coin)

    def start(self):
        import platform

        self.log.info(
            f"Starting BasicSwap {__version__}, database v{self.db_version}\n\n"
        )
        self.log.info(f"Python version: {platform.python_version()}")
        self.log.info(f"SQLite version: {sqlite3.sqlite_version}")
        self.log.debug(f"Timezone offset: {time.timezone} ({time.tzname[0]})")
        gil_status: bool = True
        if sys.version_info >= (3, 13):
            gil_status = sys._is_gil_enabled()
        self.log.debug(f"GIL enabled: {gil_status}")

        MIN_SQLITE_VERSION = (3, 35, 0)  # Upsert
        if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
            raise RuntimeError(
                "SQLite {} or higher required.".format(".".join(MIN_SQLITE_VERSION))
            )

        upgradeDatabase(self, self.db_version)
        upgradeDatabaseData(self, self.db_data_version)

        for c in Coins:
            if c not in chainparams:
                continue
            self.setCoinRunParams(c)
            self.createCoinInterface(c)

            if self.coin_clients[c]["connection_type"] == "rpc":
                ci = self.ci(c)
                self.waitForDaemonRPC(c)

                core_version = ci.getDaemonVersion()
                self.log.info(f"{ci.coin_name()} Core version {core_version}")
                self.coin_clients[c]["core_version"] = core_version

                thread_func = {
                    Coins.XMR: threadPollXMRChainState,
                    Coins.WOW: threadPollXMRChainState,
                }.get(
                    c, threadPollChainState
                )  # default case

                t = threading.Thread(target=thread_func, args=(self, c))
                self.threads.append(t)
                t.start()

                if c == Coins.PART:
                    self.coin_clients[c]["have_spent_index"] = ci.haveSpentIndex()

                    try:
                        # Sanity checks
                        rv = self.callcoinrpc(c, "extkey")
                        if "result" in rv and "No keys to list." in rv["result"]:
                            raise ValueError("No keys loaded.")

                        if (
                            self.callcoinrpc(c, "getstakinginfo")["enabled"]
                            is not False
                        ):
                            self.log.warning(
                                f"{ci.coin_name()} staking is not disabled."
                            )
                    except Exception as e:
                        self.log.error(f"Sanity checks failed: {e}")

                elif c in (Coins.XMR, Coins.WOW):
                    try:
                        ci.ensureWalletExists()
                    except Exception as e:
                        if "invalid signature" in str(e):  # wallet is corrupt
                            raise
                        self.log.warning(
                            f"Can't open {ci.coin_name()} wallet, could be locked."
                        )
                        continue
                elif c == Coins.LTC:
                    ci_mweb = self.ci(Coins.LTC_MWEB)
                    is_encrypted, _ = self.getLockedState()
                    if not is_encrypted and not ci_mweb.has_mweb_wallet():
                        ci_mweb.init_wallet()

                self.checkWalletSeed(c)

        if "p2p_host" in self.settings:
            network_key = self.getNetworkKey(1)
            self._network = bsn.Network(
                self.settings["p2p_host"], self.settings["p2p_port"], network_key, self
            )
            self._network.startNetwork()

        self.log.debug(
            f"network_key {self.network_key}\nnetwork_pubkey {self.network_pubkey}\nnetwork_addr {self.network_addr}"
        )

        self.startNetworks()

        # Initialise locked state
        _, _ = self.getLockedState()

        # Re-load in-progress bids
        self.loadFromDB()

        # Scan inbox
        # TODO: Redundant? small window for zmq messages to go unnoticed during startup?
        options = {"encoding": "hex"}
        if self._can_use_smsg_payload2:
            options["pubkey_from"] = True
        ro = self.callrpc("smsginbox", ["unread", "", options])
        nm = 0
        for msg in ro["messages"]:
            self.processMsg(msg)
            nm += 1
        self.log.info(f"Scanned {nm} unread messages.")

        autostart_setting = self.settings.get("amm_autostart", False)
        self.log.info(f"Checking AMM autostart setting: {autostart_setting}")

        if autostart_setting:
            self.log.info("AMM autostart is enabled, starting AMM process...")
            try:
                from basicswap.ui.page_amm import (
                    start_amm_process,
                    start_amm_process_force,
                    check_existing_amm_processes,
                )

                self.log.info("Waiting 2 seconds for BasicSwap to fully initialize...")
                time.sleep(2)

                amm_host = self.settings.get("htmlhost", "127.0.0.1")
                amm_port = self.settings.get("htmlport", 12700)
                amm_debug = False

                self.log.info(
                    f"Starting AMM with host={amm_host}, port={amm_port}, debug={amm_debug}"
                )

                existing_pids = check_existing_amm_processes()
                if existing_pids:
                    self.log.warning(
                        f"Found existing AMM processes: {existing_pids}. Using force start to clean up..."
                    )
                    success, msg = start_amm_process_force(
                        self, amm_host, amm_port, debug=amm_debug
                    )
                    if success:
                        self.log.info(f"AMM autostart force successful: {msg}")
                    else:
                        self.log.warning(f"AMM autostart force failed: {msg}")
                else:
                    success, msg = start_amm_process(
                        self, amm_host, amm_port, debug=amm_debug
                    )
                    if success:
                        self.log.info(f"AMM autostart successful: {msg}")
                    else:
                        self.log.warning(f"AMM autostart failed: {msg}")
            except Exception as e:
                self.log.error(f"AMM autostart error: {str(e)}")
                import traceback

                self.log.error(traceback.format_exc())
        else:
            self.log.info("AMM autostart is disabled")

    def stopDaemon(self, coin) -> None:
        if coin in (Coins.XMR, Coins.DCR, Coins.WOW):
            return
        num_tries = 10
        authcookiepath = os.path.join(self.getChainDatadirPath(coin), ".cookie")
        stopping = False
        try:
            for i in range(num_tries):
                self.callcoincli(coin, "stop", timeout=10)
                self.log.debug(f"Trying to stop {Coins(coin).name}")
                stopping = True
                # self.delay_event will be set here
                time.sleep(i + 1)
        except Exception as ex:
            str_ex = str(ex)
            if (
                "Could not connect" in str_ex
                or "Could not locate RPC credentials" in str_ex
                or "couldn't connect to server" in str_ex
            ):
                if stopping:
                    for i in range(30):
                        # The lock file doesn't get deleted
                        # Using .cookie is a temporary workaround, will only work if rpc password is unset.
                        # TODO: Query lock on .lock properly
                        if os.path.exists(authcookiepath):
                            self.log.debug(
                                f"Waiting on .cookie file {Coins(coin).name}"
                            )
                            time.sleep(i + 1)
                    time.sleep(4)  # Extra time to settle
                return
            self.log.error(f"stopDaemon {ex}")
            self.log.error(traceback.format_exc())
        raise ValueError(f"Could not stop {Coins(coin).name}")

    def stopDaemons(self) -> None:
        for c in self.activeCoins():
            chain_client_settings = self.getChainClientSettings(c)
            if chain_client_settings["manage_daemon"] is True:
                self.stopDaemon(c)

    def waitForDaemonRPC(self, coin_type, with_wallet: bool = True) -> None:
        if with_wallet:
            self.waitForDaemonRPC(coin_type, with_wallet=False)
            if coin_type in (Coins.XMR, Coins.WOW):
                return

            check_coin_types = [
                coin_type,
            ]
            if coin_type == Coins.PART:
                check_coin_types += [Coins.PART_ANON, Coins.PART_BLIND]
            for check_coin_type in check_coin_types:
                ci = self.ci(check_coin_type)
                # checkWallets can adjust the wallet name.
                if ci.checkWallets() < 1:
                    self.log.error(f"No wallets found for coin {ci.coin_name()}.")
                    # systemd will try to restart the process if fail_code != 0
                    self.stopRunning(1)

        startup_tries = self.startup_tries
        chain_client_settings = self.getChainClientSettings(coin_type)
        if "startup_tries" in chain_client_settings:
            startup_tries = chain_client_settings["startup_tries"]
        if startup_tries < 1:
            self.log.warning('"startup_tries" can\'t be less than 1.')
            startup_tries = 1
        for i in range(startup_tries):
            if self.delay_event.is_set():
                return
            try:
                self.coin_clients[coin_type]["interface"].testDaemonRPC(with_wallet)
                return
            except Exception as ex:
                self.log.warning(
                    f"Can't connect to {Coins(coin_type).name} RPC: {ex}.  Trying again in {1 + i} second/s, {1 + i}/{startup_tries}."
                )
                self.delay_event.wait(1 + i)
        self.log.error(f"Can't connect to {Coins(coin_type).name} RPC, exiting.")
        self.stopRunning(1)  # systemd will try to restart the process if fail_code != 0

    def checkCoinsReady(self, coin_from, coin_to) -> None:
        check_coins = (coin_from, coin_to)
        for c in check_coins:
            ci = self.ci(c)
            if self._restrict_unknown_seed_wallets and not ci.knownWalletSeed():
                raise ValueError(
                    '{} has an unexpected wallet seed and "restrict_unknown_seed_wallets" is enabled.'.format(
                        ci.coin_name()
                    )
                )
            if self.coin_clients[c]["connection_type"] != "rpc":
                continue
            if c in (Coins.XMR, Coins.WOW):
                continue  # TODO
            synced = round(ci.getBlockchainInfo()["verificationprogress"], 3)
            if synced < 1.0:
                raise ValueError(
                    "{} chain is still syncing, currently at {}.".format(
                        ci.coin_name(), synced
                    )
                )

    def isSystemUnlocked(self) -> bool:
        # TODO - Check all active coins
        ci = self.ci(Coins.PART)
        return not ci.isWalletLocked()

    def checkSystemStatus(self) -> None:
        ci = self.ci(Coins.PART)
        if ci.isWalletLocked():
            raise LockedCoinError(Coins.PART)

    def checkForUpdates(self) -> None:
        if not self.settings.get("check_updates", True):
            return

        now = time.time()
        if now - self._last_checked_updates < self.check_updates_seconds:
            return

        self._last_checked_updates = now
        self.log.info("Checking for BasicSwap updates...")

        try:
            url = "https://api.github.com/repos/basicswap/basicswap/tags"
            response_data = self.readURL(url, timeout=30)
            tags_data = json.loads(response_data.decode("utf-8"))

            if not tags_data or not isinstance(tags_data, list) or len(tags_data) == 0:
                self.log.warning("Could not determine latest version from GitHub tags")
                return

            latest_tag = tags_data[0].get("name", "").lstrip("v")
            if not latest_tag:
                self.log.warning("Could not determine latest version from GitHub tags")
                return

            self._latest_version = latest_tag
            current_version = __version__

            def version_tuple(v):
                return tuple(map(int, v.split(".")))

            try:
                if version_tuple(latest_tag) > version_tuple(current_version):
                    if not self._update_available:
                        self._update_available = True
                        self.log.info(
                            f"Update available: v{latest_tag} (current: v{current_version})"
                        )

                        self.notify(
                            NT.UPDATE_AVAILABLE,
                            {
                                "current_version": current_version,
                                "latest_version": latest_tag,
                                "release_url": f"https://github.com/basicswap/basicswap/releases/tag/v{latest_tag}",
                                "release_notes": f"New version v{latest_tag} is available. Click to view details on GitHub.",
                            },
                        )
                    else:
                        self.log.info(f"Update v{latest_tag} already notified")
                else:
                    self._update_available = False
                    self.log.info(f"BasicSwap is up to date (v{current_version})")
            except ValueError as e:
                self.log.warning(f"Error comparing versions: {e}")

        except Exception as e:
            self.log.warning(f"Failed to check for updates: {e}")

    def isBaseCoinActive(self, c) -> bool:
        if c not in chainparams:
            return False
        if self.coin_clients[c]["connection_type"] == "rpc":
            return True
        return False

    def activeCoins(self):
        for c in Coins:
            if self.isBaseCoinActive(c):
                yield c

    def getListOfWalletCoins(self):
        # Always unlock Particl first
        coins_list = [
            Coins.PART,
        ] + [c for c in self.activeCoins() if c != Coins.PART]
        if Coins.LTC in coins_list:
            coins_list.append(Coins.LTC_MWEB)
        return coins_list

    def changeWalletPasswords(
        self, old_password: str, new_password: str, coin=None
    ) -> None:
        # Only the main wallet password is changed for monero, avoid issues by preventing until active swaps are complete
        if len(self.swaps_in_progress) > 0:
            raise ValueError("Can't change passwords while swaps are in progress")

        if old_password == new_password:
            raise ValueError("Passwords must differ")

        if len(new_password) < 4:
            raise ValueError("New password is too short")

        coins_list = self.getListOfWalletCoins()

        # Unlock wallets to ensure they all have the same password.
        for c in coins_list:
            if coin and c != coin:
                continue
            ci = self.ci(c)
            try:
                ci.unlockWallet(old_password)
            except Exception as e:  # noqa: F841
                raise ValueError("Failed to unlock {}".format(ci.coin_name()))

        for c in coins_list:
            if coin and c != coin:
                continue
            self.ci(c).changeWalletPassword(old_password, new_password)

        # Update cached state
        if coin is None or coin == Coins.PART:
            self._is_encrypted, self._is_locked = self.ci(
                Coins.PART
            ).isWalletEncryptedLocked()

    def unlockWallets(self, password: str, coin=None) -> None:
        try:
            self._read_zmq_queue = False
            for c in self.getListOfWalletCoins():
                if coin and c != coin:
                    continue
                try:
                    self.ci(c).unlockWallet(password)
                except Exception as e:
                    self.log.warning(f"Failed to unlock wallet {getCoinName(c)}")
                    if coin is not None or c == Coins.PART:
                        raise e
                if c == Coins.PART:
                    self._is_locked = False

            self.loadFromDB()
        finally:
            self._read_zmq_queue = True

    def lockWallets(self, coin=None) -> None:
        try:
            self._read_zmq_queue = False
            self.swaps_in_progress.clear()

            for c in self.getListOfWalletCoins():
                if coin and c != coin:
                    continue
                self.ci(c).lockWallet()
                if c == Coins.PART:
                    self._is_locked = True
        finally:
            self._read_zmq_queue = True

    def storeSeedIDForCoin(self, root_key, coin_type, cursor=None) -> None:
        ci = self.ci(coin_type)
        db_key_coin_name = ci.coin_name().lower()
        seed_id = ci.getSeedHash(root_key)

        key_str = "main_wallet_seedid_" + db_key_coin_name
        self.setStringKV(key_str, seed_id.hex(), cursor)

        if coin_type == Coins.DCR:
            # TODO: How to force getmasterpubkey to always return the new slip44 (42) key
            key_str = "main_wallet_seedid_alt_" + db_key_coin_name
            legacy_root_hash = ci.getSeedHash(root_key, 20)
            self.setStringKV(key_str, legacy_root_hash.hex(), cursor)

    def initialiseWallet(
        self, interface_type, raise_errors: bool = False, restore_time: int = -1
    ) -> None:
        if interface_type == Coins.PART:
            return
        ci = self.ci(interface_type)
        db_key_coin_name = ci.coin_name().lower()
        self.log.info(f"Initialising {ci.coin_name()} wallet.")

        if interface_type in (Coins.XMR, Coins.WOW):
            key_view = self.getWalletKey(interface_type, 1, for_ed25519=True)
            key_spend = self.getWalletKey(interface_type, 2, for_ed25519=True)
            ci.initialiseWallet(key_view, key_spend)
            root_address = ci.getAddressFromKeys(key_view, key_spend)

            key_str = "main_wallet_addr_" + db_key_coin_name
            self.setStringKV(key_str, root_address)
            return

        root_key = self.getWalletKey(interface_type, 1)
        try:
            ci.initialiseWallet(root_key, restore_time)
        except Exception as e:
            # <  0.21: sethdseed cannot set a new HD seed while still in Initial Block Download.
            self.log.error(f"initialiseWallet failed: {e}")
            if raise_errors:
                raise e
            if self.debug:
                self.log.error(traceback.format_exc())
            return

        try:
            cursor = self.openDB()
            self.storeSeedIDForCoin(root_key, interface_type, cursor)

            # Clear any saved addresses
            self.clearStringKV("receive_addr_" + db_key_coin_name, cursor)
            self.clearStringKV("stealth_addr_" + db_key_coin_name, cursor)

            coin_id = int(interface_type)
            info_type = 1  # wallet
            query_str = "DELETE FROM wallets WHERE coin_id = ? AND balance_type = ?"
            cursor.execute(query_str, (coin_id, info_type))
        finally:
            self.closeDB(cursor)

    def updateIdentityBidState(self, cursor, address: str, bid) -> None:
        offer = self.getOffer(bid.offer_id, cursor)
        addresses_to_update = [offer.addr_from, bid.bid_addr]
        for addr in addresses_to_update:
            identity_stats = self.queryOne(KnownIdentity, cursor, {"address": addr})
            if not identity_stats:
                identity_stats = KnownIdentity(
                    active_ind=1, address=addr, created_at=self.getTime()
                )
            is_offer_creator = addr == offer.addr_from
            if bid.state == BidStates.SWAP_COMPLETED:
                if is_offer_creator:
                    old_value = zeroIfNone(identity_stats.num_recv_bids_successful)
                    identity_stats.num_recv_bids_successful = old_value + 1
                else:
                    old_value = zeroIfNone(identity_stats.num_sent_bids_successful)
                    identity_stats.num_sent_bids_successful = old_value + 1
            elif bid.state in (
                BidStates.BID_ERROR,
                BidStates.XMR_SWAP_FAILED_REFUNDED,
                BidStates.XMR_SWAP_FAILED_SWIPED,
                BidStates.XMR_SWAP_FAILED,
                BidStates.SWAP_TIMEDOUT,
            ):
                if is_offer_creator:
                    old_value = zeroIfNone(identity_stats.num_recv_bids_failed)
                    identity_stats.num_recv_bids_failed = old_value + 1
                else:
                    old_value = zeroIfNone(identity_stats.num_sent_bids_failed)
                    identity_stats.num_sent_bids_failed = old_value + 1
            elif bid.state == BidStates.BID_REJECTED:
                if is_offer_creator:
                    old_value = zeroIfNone(identity_stats.num_recv_bids_rejected)
                    identity_stats.num_recv_bids_rejected = old_value + 1
                else:
                    old_value = zeroIfNone(identity_stats.num_sent_bids_rejected)
                    identity_stats.num_sent_bids_rejected = old_value + 1
            self.add(identity_stats, cursor, upsert=True)

    def getPreFundedTx(
        self, linked_type: int, linked_id: bytes, tx_type: int, cursor=None
    ) -> Optional[bytes]:
        try:
            use_cursor = self.openDB(cursor)
            tx = self.queryOne(
                PrefundedTx,
                use_cursor,
                {
                    "linked_type": linked_type,
                    "linked_id": linked_id,
                    "tx_type": tx_type,
                    "used_by": None,
                },
            )
            if tx is None:
                return None
            tx.used_by = linked_id
            self.add(tx, use_cursor, upsert=True)
            return tx.tx_data
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def activateBid(self, cursor, bid) -> None:
        if bid.bid_id in self.swaps_in_progress:
            self.log.debug(f"Bid {self.log.id(bid.bid_id)} is already in progress")

        self.log.debug(f"Loading active bid {self.log.id(bid.bid_id)}")

        offer = self.getOffer(bid.offer_id, cursor=cursor)
        if not offer:
            raise ValueError("Offer not found")

        self.loadBidTxns(bid, cursor)

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)

        if offer.swap_type == SwapTypes.XMR_SWAP:
            xmr_swap = self.queryOne(XmrSwap, cursor, {"bid_id": bid.bid_id})
            self.watchXmrSwap(bid, offer, xmr_swap, cursor)
            if (
                ci_to.watch_blocks_for_scripts()
                and bid.xmr_a_lock_tx
                and bid.xmr_a_lock_tx.chain_height
            ):
                if not bid.xmr_b_lock_tx or not bid.xmr_b_lock_tx.txid:
                    chain_a_block_header = ci_from.getBlockHeaderFromHeight(
                        bid.xmr_a_lock_tx.chain_height
                    )
                    chain_b_block_header = ci_to.getBlockHeaderAt(
                        chain_a_block_header["time"]
                    )
                    dest_script = ci_to.getPkDest(xmr_swap.pkbs)
                    self.setLastHeightCheckedStart(
                        ci_to.coin_type(), chain_b_block_header["height"], cursor
                    )
                    self.addWatchedScript(
                        ci_to.coin_type(),
                        bid.bid_id,
                        dest_script,
                        TxTypes.XMR_SWAP_B_LOCK,
                    )
        else:
            self.swaps_in_progress[bid.bid_id] = (bid, offer)

            if bid.initiate_tx and bid.initiate_tx.txid:
                self.addWatchedOutput(
                    coin_from,
                    bid.bid_id,
                    bid.initiate_tx.txid.hex(),
                    bid.initiate_tx.vout,
                    BidStates.SWAP_INITIATED,
                )
            if bid.participate_tx and bid.participate_tx.txid:
                self.addWatchedOutput(
                    coin_to,
                    bid.bid_id,
                    bid.participate_tx.txid.hex(),
                    bid.participate_tx.vout,
                    BidStates.SWAP_PARTICIPATING,
                )

            if (
                ci_to.watch_blocks_for_scripts()
                and bid.participate_tx
                and bid.participate_tx.txid is None
            ):
                if bid.initiate_tx and bid.initiate_tx.chain_height:
                    chain_a_block_header = ci_from.getBlockHeaderFromHeight(
                        bid.initiate_tx.chain_height
                    )
                    chain_b_block_header = ci_to.getBlockHeaderAt(
                        chain_a_block_header["time"]
                    )
                    self.setLastHeightCheckedStart(
                        coin_to, chain_b_block_header["height"], cursor
                    )
                self.addWatchedScript(
                    coin_to,
                    bid.bid_id,
                    ci_to.getScriptDest(bid.participate_tx.script),
                    TxTypes.PTX,
                )

            if self.coin_clients[coin_from]["last_height_checked"] < 1:
                if bid.initiate_tx and bid.initiate_tx.chain_height:
                    self.setLastHeightCheckedStart(
                        coin_from, bid.initiate_tx.chain_height, cursor
                    )
            if self.coin_clients[coin_to]["last_height_checked"] < 1:
                if bid.participate_tx and bid.participate_tx.chain_height:
                    self.setLastHeightCheckedStart(
                        coin_to, bid.participate_tx.chain_height, cursor
                    )

        # TODO process addresspool if bid has previously been abandoned

    def deactivateBid(self, cursor, offer, bid) -> None:
        # Remove from in progress
        self.log.debug(f"Removing bid from in-progress: {self.log.id(bid.bid_id)}")
        self.swaps_in_progress.pop(bid.bid_id, None)

        bid.in_progress = 0
        if cursor is None:
            self.saveBid(bid.bid_id, bid)

        # Remove any watched outputs
        self.removeWatchedOutput(Coins(offer.coin_from), bid.bid_id, None)
        self.removeWatchedOutput(Coins(offer.coin_to), bid.bid_id, None)

        self.removeWatchedScript(Coins(offer.coin_from), bid.bid_id, None)
        self.removeWatchedScript(Coins(offer.coin_to), bid.bid_id, None)

        if bid.state in (BidStates.BID_ABANDONED, BidStates.SWAP_COMPLETED):
            # Return unused addrs to pool
            itx_state = bid.getITxState()
            ptx_state = bid.getPTxState()
            if itx_state is not None and itx_state != TxStates.TX_REDEEMED:
                self.returnAddressToPool(bid.bid_id, TxTypes.ITX_REDEEM)
            if itx_state is not None and itx_state != TxStates.TX_REFUNDED:
                self.returnAddressToPool(bid.bid_id, TxTypes.ITX_REFUND)
            if ptx_state is not None and ptx_state != TxStates.TX_REDEEMED:
                self.returnAddressToPool(bid.bid_id, TxTypes.PTX_REDEEM)
            if ptx_state is not None and ptx_state != TxStates.TX_REFUNDED:
                self.returnAddressToPool(bid.bid_id, TxTypes.PTX_REFUND)

        try:
            use_cursor = self.openDB(cursor)

            # Remove any delayed events
            query: str = "DELETE FROM actions WHERE linked_id = :bid_id "
            if self.debug:
                query = "UPDATE actions SET active_ind = 2 WHERE linked_id = :bid_id "
            use_cursor.execute(query, {"bid_id": bid.bid_id})

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
            # Unlock locked inputs (TODO)
            if offer.swap_type == SwapTypes.XMR_SWAP:
                ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
                rows = use_cursor.execute(
                    "SELECT a_lock_tx FROM xmr_swaps WHERE bid_id = :bid_id",
                    {"bid_id": bid.bid_id},
                ).fetchall()
                if len(rows) > 0:
                    xmr_swap_a_lock_tx = rows[0][0]
                    try:
                        ci_from.unlockInputs(xmr_swap_a_lock_tx)
                    except Exception as e:
                        self.log.debug(f"unlockInputs failed {e}")
                        pass  # Invalid parameter, unknown transaction
            elif SwapTypes.SELLER_FIRST:
                pass  # No prevouts are locked

            # Update identity stats
            if bid.state in (
                BidStates.BID_ERROR,
                BidStates.XMR_SWAP_FAILED_REFUNDED,
                BidStates.XMR_SWAP_FAILED_SWIPED,
                BidStates.XMR_SWAP_FAILED,
                BidStates.SWAP_COMPLETED,
                BidStates.SWAP_TIMEDOUT,
            ):
                was_sent: bool = bid.was_received if reverse_bid else bid.was_sent
                peer_address = offer.addr_from if was_sent else bid.bid_addr
                self.updateIdentityBidState(use_cursor, peer_address, bid)

        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def loadFromDB(self) -> None:
        if self.isSystemUnlocked() is False:
            self.log.info("Not loading from db.  System is locked.")
            return
        self.log.info("Loading data from db")
        self.swaps_in_progress.clear()
        bid_cursor = None
        try:
            cursor = self.openDB()
            bid_cursor = self.getNewDBCursor()
            for bid in self.query(Bid, bid_cursor):
                if bid.in_progress == 1 or (
                    bid.state
                    and bid.state > BidStates.BID_RECEIVED
                    and bid.state < BidStates.SWAP_COMPLETED
                ):
                    try:
                        self.activateBid(cursor, bid)
                    except Exception as ex:
                        self.logException(f"Failed to activate bid! Error: {ex}")
                        try:
                            bid.setState(BidStates.BID_ERROR, "Failed to activate")

                            offer = self.queryOne(
                                Offer, cursor, {"offer_id": bid.offer_id}
                            )
                            self.deactivateBid(cursor, offer, bid)
                        except Exception as ex:
                            self.logException(f"Further error deactivating: {ex}")
            self.buildNotificationsCache(cursor)
        finally:
            self.closeDBCursor(bid_cursor)
            self.closeDB(cursor)

    def getActiveBidMsgValidTime(self) -> int:
        return self.SMSG_SECONDS_IN_HOUR * 48

    def getAcceptBidMsgValidTime(self, bid) -> int:
        now: int = self.getTime()
        smsg_max_valid = self.SMSG_SECONDS_IN_HOUR * 48
        smsg_min_valid = self.SMSG_SECONDS_IN_HOUR * 1
        bid_valid = (bid.expire_at - now) + 10 * 60  # Add 10 minute buffer
        return max(smsg_min_valid, min(smsg_max_valid, bid_valid))

    def is_reverse_ads_bid(self, coin_from, coin_to) -> bool:
        return coin_from in self.scriptless_coins + self.coins_without_segwit

    def validateSwapType(self, coin_from, coin_to, swap_type):

        for coin in (coin_from, coin_to):
            if coin in self.balance_only_coins:
                raise ValueError(f"Invalid coin: {coin.name}")

        if swap_type == SwapTypes.XMR_SWAP:
            reverse_bid: bool = self.is_reverse_ads_bid(coin_from, coin_to)
            itx_coin = coin_to if reverse_bid else coin_from
            ptx_coin = coin_from if reverse_bid else coin_to
            if itx_coin in self.coins_without_segwit + self.scriptless_coins:
                if ptx_coin in self.coins_without_segwit + self.scriptless_coins:
                    raise ValueError(
                        f"{coin_from.name} -> {coin_to.name} is not currently supported"
                    )
                raise ValueError(
                    f"Invalid swap type for: {coin_from.name} -> {coin_to.name}"
                )
        else:
            if (
                coin_from in self.adaptor_swap_only_coins
                or coin_to in self.adaptor_swap_only_coins
            ):
                raise ValueError(
                    f"Invalid swap type for: {coin_from.name} -> {coin_to.name}"
                )

    def _process_notification_safe(self, event_type, event_data) -> None:
        try:
            show_event = event_type not in self._disabled_notification_types
            if event_type == NT.OFFER_RECEIVED:
                offer_id: bytes = bytes.fromhex(event_data["offer_id"])
                self.log.debug(f"Received new offer {self.log.id(offer_id)}")
                if self.ws_server and show_event:
                    event_data["event"] = "new_offer"
                    self.ws_server.send_message_to_all(json.dumps(event_data))
            elif event_type == NT.BID_RECEIVED:
                offer_id: bytes = bytes.fromhex(event_data["offer_id"])
                offer_type: str = event_data["type"]
                bid_id: bytes = bytes.fromhex(event_data["bid_id"])
                self.log.info(
                    f"Received valid bid {self.log.id(bid_id)} for {offer_type} offer {self.log.id(offer_id)}"
                )
                if self.ws_server and show_event:
                    event_data["event"] = "new_bid"
                    self.ws_server.send_message_to_all(json.dumps(event_data))
            elif event_type == NT.BID_ACCEPTED:
                bid_id: bytes = bytes.fromhex(event_data["bid_id"])
                self.log.info(f"Received valid bid accept for {self.log.id(bid_id)}")
                if self.ws_server and show_event:
                    event_data["event"] = "bid_accepted"
                    self.ws_server.send_message_to_all(json.dumps(event_data))
            elif event_type == NT.SWAP_COMPLETED:
                bid_id: bytes = bytes.fromhex(event_data["bid_id"])
                self.log.info(f"Swap completed for bid {self.log.id(bid_id)}")
                event_data["event"] = "swap_completed"

                if self.ws_server and show_event:
                    self.ws_server.send_message_to_all(json.dumps(event_data))
            else:
                self.log.warning(f"Unknown notification {event_type}")

            now: int = self.getTime()
            use_cursor = self.openDB(None)
            try:
                self.add(
                    Notification(
                        active_ind=1,
                        created_at=now,
                        event_type=int(event_type),
                        event_data=bytes(json.dumps(event_data), "UTF-8"),
                    ),
                    use_cursor,
                )

                use_cursor.execute(
                    "DELETE FROM notifications WHERE record_id NOT IN (SELECT record_id FROM notifications WHERE active_ind=1 ORDER BY created_at ASC LIMIT ?)",
                    (self._keep_notifications,),
                )

                if show_event:
                    self._notifications_cache[now] = (event_type, event_data)
                while len(self._notifications_cache) > self._show_notifications:
                    # dicts preserve insertion order in Python 3.7+
                    self._notifications_cache.pop(next(iter(self._notifications_cache)))

            finally:
                self.closeDB(use_cursor)

        except Exception as ex:
            self.log.error(
                f"Notification processing failed for event_type {event_type}: {ex}"
            )

    def notify(self, event_type, event_data, cursor=None) -> None:
        """Submit notification for processing in isolated thread."""
        try:
            self.thread_pool.submit(
                self._process_notification_safe, event_type, event_data
            )
        except Exception as ex:
            self.log.error(f"Failed to submit notification to thread pool: {ex}")
            try:
                self._process_notification_safe(event_type, event_data)
            except Exception as ex2:
                self.log.error(f"Notification fallback also failed: {ex2}")

    def buildNotificationsCache(self, cursor):
        self._notifications_cache.clear()
        q = cursor.execute(
            "SELECT created_at, event_type, event_data FROM notifications WHERE active_ind = 1 ORDER BY created_at ASC LIMIT ?",
            (self._keep_notifications,),
        )
        for entry in q:
            self._notifications_cache[entry[0]] = (
                entry[1],
                json.loads(entry[2].decode("UTF-8")),
            )

    def getNotifications(self):
        rv = []
        for k, v in self._notifications_cache.items():
            rv.append(
                (time.strftime("%d-%m-%y %H:%M:%S", time.localtime(k)), int(v[0]), v[1])
            )
        return rv

    def setIdentityData(self, filters, data):
        address = filters["address"]
        ci = self.ci(Coins.PART)
        ensure(ci.isValidAddress(address), "Invalid identity address")

        try:
            now: int = self.getTime()
            cursor = self.openDB()
            q = cursor.execute(
                "SELECT COUNT(*) FROM knownidentities WHERE address = :address",
                {"address": address},
            ).fetchone()
            if q[0] < 1:
                cursor.execute(
                    "INSERT INTO knownidentities (active_ind, address, created_at) VALUES (1, :address, :now)",
                    {"address": address, "now": now},
                )

            if "label" in data:
                cursor.execute(
                    "UPDATE knownidentities SET label = :label WHERE address = :address",
                    {"address": address, "label": data["label"]},
                )

            if "automation_override" in data:
                new_value: int = 0
                data_value = data["automation_override"]
                if isinstance(data_value, int):
                    new_value = data_value
                elif isinstance(data_value, str):
                    if data_value.isdigit():
                        new_value = int(data_value)
                    elif data_value == "default":
                        new_value = 0
                    elif data_value == "always_accept":
                        new_value = int(AutomationOverrideOptions.ALWAYS_ACCEPT)
                    elif data_value == "never_accept":
                        new_value = int(AutomationOverrideOptions.NEVER_ACCEPT)
                    else:
                        raise ValueError("Unknown automation_override value")
                else:
                    raise ValueError("Unknown automation_override type")

                cursor.execute(
                    "UPDATE knownidentities SET automation_override = :new_value WHERE address = :address",
                    {"address": address, "new_value": new_value},
                )

            if "visibility_override" in data:
                new_value: int = 0
                data_value = data["visibility_override"]
                if isinstance(data_value, int):
                    new_value = data_value
                elif isinstance(data_value, str):
                    if data_value.isdigit():
                        new_value = int(data_value)
                    elif data_value == "default":
                        new_value = 0
                    elif data_value == "hide":
                        new_value = int(VisibilityOverrideOptions.HIDE)
                    elif data_value == "block":
                        new_value = int(VisibilityOverrideOptions.BLOCK)
                    else:
                        raise ValueError("Unknown visibility_override value")
                else:
                    raise ValueError("Unknown visibility_override type")

                cursor.execute(
                    "UPDATE knownidentities SET visibility_override = :new_value WHERE address = :address",
                    {"address": address, "new_value": new_value},
                )

            if "note" in data:
                cursor.execute(
                    "UPDATE knownidentities SET note = :note WHERE address = :address",
                    {"address": address, "note": data["note"]},
                )

        finally:
            self.closeDB(cursor)

    def listIdentities(self, filters={}):
        try:
            cursor = self.openDB()

            query_str: str = (
                "SELECT address, label, num_sent_bids_successful, num_recv_bids_successful, "
                + "       num_sent_bids_rejected, num_recv_bids_rejected, num_sent_bids_failed, num_recv_bids_failed, "
                + "       automation_override, visibility_override, note "
                + " FROM knownidentities "
                + " WHERE active_ind = 1 "
            )
            query_data: dict = {}

            address: str = filters.get("address", None)
            if address is not None:
                query_str += " AND address = :address "
                query_data["address"] = address

            query_str += getOrderByStr(filters)

            limit = filters.get("limit", None)
            if limit is not None:
                query_str += " LIMIT :limit"
                query_data["limit"] = limit
            offset = filters.get("offset", None)
            if offset is not None:
                query_str += " OFFSET :offset"
                query_data["offset"] = offset

            q = cursor.execute(query_str, query_data)
            rv = []
            for row in q:
                identity = {
                    "address": row[0] if row[0] is not None else "",
                    "label": row[1] if row[1] is not None else "",
                    "num_sent_bids_successful": zeroIfNone(row[2]),
                    "num_recv_bids_successful": zeroIfNone(row[3]),
                    "num_sent_bids_rejected": zeroIfNone(row[4]),
                    "num_recv_bids_rejected": zeroIfNone(row[5]),
                    "num_sent_bids_failed": zeroIfNone(row[6]),
                    "num_recv_bids_failed": zeroIfNone(row[7]),
                    "automation_override": zeroIfNone(row[8]),
                    "visibility_override": zeroIfNone(row[9]),
                    "note": row[10],
                }
                rv.append(identity)
            return rv
        finally:
            self.closeDB(cursor, commit=False)

    def vacuumDB(self):
        try:
            cursor = self.openDB()
            return cursor.execute("VACUUM")
        finally:
            self.closeDB(cursor)

    def validateOfferAmounts(
        self, coin_from, coin_to, amount: int, amount_to: int, min_bid_amount: int
    ) -> None:
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        ensure(amount >= min_bid_amount, "amount < min_bid_amount")
        ensure(amount > ci_from.min_amount(), "From amount below min value for chain")
        ensure(amount < ci_from.max_amount(), "From amount above max value for chain")

        ensure(amount_to > ci_to.min_amount(), "To amount below min value for chain")
        ensure(amount_to < ci_to.max_amount(), "To amount above max value for chain")

    def validateOfferLockValue(
        self, swap_type, coin_from, coin_to, lock_type, lock_value: int
    ) -> None:
        coin_from_has_csv = self.coin_clients[coin_from]["use_csv"]
        coin_to_has_csv = self.coin_clients[coin_to]["use_csv"]

        if lock_type == TxLockTypes.SEQUENCE_LOCK_TIME:
            ensure(
                lock_value >= self.min_sequence_lock_seconds
                and lock_value <= self.max_sequence_lock_seconds,
                "Invalid lock_value time",
            )
            if swap_type == SwapTypes.XMR_SWAP:
                reverse_bid: bool = self.is_reverse_ads_bid(coin_from, coin_to)
                itx_coin_has_csv = coin_to_has_csv if reverse_bid else coin_from_has_csv
                ensure(itx_coin_has_csv, "ITX coin needs CSV activated.")
            else:
                ensure(
                    coin_from_has_csv and coin_to_has_csv,
                    "Both coins need CSV activated.",
                )
        elif lock_type == TxLockTypes.SEQUENCE_LOCK_BLOCKS:
            ensure(lock_value >= 5 and lock_value <= 1000, "Invalid lock_value blocks")
            if swap_type == SwapTypes.XMR_SWAP:
                reverse_bid: bool = self.is_reverse_ads_bid(coin_from, coin_to)
                itx_coin_has_csv = coin_to_has_csv if reverse_bid else coin_from_has_csv
                ensure(itx_coin_has_csv, "ITX coin needs CSV activated.")
            else:
                ensure(
                    coin_from_has_csv and coin_to_has_csv,
                    "Both coins need CSV activated.",
                )
        elif lock_type == TxLockTypes.ABS_LOCK_TIME:
            # TODO: range?
            ensure(not coin_from_has_csv or not coin_to_has_csv, "Should use CSV.")
            ensure(
                lock_value >= 4 * 60 * 60 and lock_value <= 96 * 60 * 60,
                "Invalid lock_value time",
            )
        elif lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
            # TODO: range?
            ensure(not coin_from_has_csv or not coin_to_has_csv, "Should use CSV.")
            ensure(lock_value >= 10 and lock_value <= 1000, "Invalid lock_value blocks")
        else:
            raise ValueError("Unknown locktype")

    def validateOfferValidTime(
        self, offer_type, coin_from, coin_to, valid_for_seconds: int
    ) -> None:
        # TODO: adjust
        if valid_for_seconds < 10 * 60:
            raise ValueError("Offer TTL too low")
        if valid_for_seconds > 48 * 60 * 60:
            raise ValueError("Offer TTL too high")

    def validateBidValidTime(
        self, offer_type, coin_from, coin_to, valid_for_seconds: int
    ) -> None:
        # TODO: adjust
        if valid_for_seconds < 10 * 60:
            raise ValueError("Bid TTL too low")
        if valid_for_seconds > 24 * 60 * 60:
            raise ValueError("Bid TTL too high")

    def calculateRateTolerance(self, offer_rate: int) -> int:
        return max(1, offer_rate // 10000)

    def ratesMatch(self, rate1: int, rate2: int, offer_rate: int) -> bool:
        tolerance = self.calculateRateTolerance(offer_rate)
        return abs(rate1 - rate2) <= tolerance

    def validateBidAmount(self, offer, bid_amount: int, bid_rate: int) -> None:
        ensure(bid_amount >= offer.min_bid_amount, "Bid amount below minimum")
        ensure(bid_amount <= offer.amount_from, "Bid amount above offer amount")
        if not offer.amount_negotiable:
            ensure(
                offer.amount_from == bid_amount, "Bid amount must match offer amount."
            )
        if not offer.rate_negotiable:
            ensure(
                self.ratesMatch(bid_rate, offer.rate, offer.rate),
                "Rate mismatch.",
            )

    def validateMessageNets(self, message_nets: str) -> None:
        try:
            self.expandMessageNets(message_nets)
        except Exception as e:
            raise ValueError(f"Invalid message networks: {e}")

    def ensureWalletCanSend(
        self, ci, swap_type, ensure_balance: int, estimated_fee: int, for_offer=True
    ) -> None:
        balance_msg: str = (
            f"{ci.format_amount(ensure_balance)} {ci.coin_name()} with estimated fee {ci.format_amount(estimated_fee)}"
        )
        self.log.debug(f"Ensuring wallet can send {balance_msg}.")
        try:
            if ci.interface_type() in self.scriptless_coins:
                ci.ensureFunds(ensure_balance + estimated_fee)
            else:
                pi = self.pi(swap_type)
                _ = pi.getFundedInitiateTxTemplate(ci, ensure_balance, False)
                # TODO: Save the prefunded tx so the fee can't change, complicates multiple offers at the same time.
        except Exception as e:
            type_str = "offer" if for_offer else "bid"
            err_msg = f"Insufficient funds for {type_str} of {balance_msg}."
            if self.debug:
                self.log.error(f"ensureWalletCanSend failed {e}")
                current_balance: int = ci.getSpendableBalance()
                err_msg += (
                    f" Debug: Spendable balance: {ci.format_amount(current_balance)}."
                )
            self.log.error(err_msg)
            raise ValueError(err_msg)

    def getOfferAddressTo(self, extra_options) -> str:
        if "addr_send_to" in extra_options:
            return extra_options["addr_send_to"]
        return self.network_addr

    def postOffer(
        self,
        coin_from,
        coin_to,
        amount: int,
        rate: int,
        min_bid_amount: int,
        swap_type,
        lock_type=TxLockTypes.SEQUENCE_LOCK_TIME,
        lock_value: int = 48 * 60 * 60,
        auto_accept_bids: bool = False,
        addr_send_from: str = None,
        extra_options={},
    ) -> bytes:
        # Offer to send offer.amount_from of coin_from in exchange for offer.amount_from * offer.rate of coin_to

        ensure(coin_from != coin_to, "coin_from == coin_to")
        try:
            coin_from_t = Coins(coin_from)
            ci_from = self.ci(coin_from_t)
        except Exception:
            raise ValueError("Unknown coin from type")
        try:
            coin_to_t = Coins(coin_to)
            ci_to = self.ci(coin_to_t)
        except Exception:
            raise ValueError("Unknown coin to type")

        self.validateSwapType(coin_from_t, coin_to_t, swap_type)
        self.validateOfferLockValue(
            swap_type, coin_from_t, coin_to_t, lock_type, lock_value
        )

        valid_for_seconds: int = extra_options.get("valid_for_seconds", 60 * 60)
        self.validateOfferValidTime(
            swap_type, coin_from_t, coin_to_t, valid_for_seconds
        )

        amount_to: int = extra_options.get(
            "amount_to", int((amount * rate) // ci_from.COIN())
        )
        self.validateOfferAmounts(
            coin_from_t, coin_to_t, amount, amount_to, min_bid_amount
        )
        # Recalculate the rate so it will match the bid rate
        rate: int = ci_from.make_int(amount_to / amount, r=1)

        offer_addr_to = self.getOfferAddressTo(extra_options)

        reverse_bid: bool = self.is_reverse_ads_bid(coin_from, coin_to)

        try:
            cursor = self.openDB()
            self.checkCoinsReady(coin_from_t, coin_to_t)
            offer_addr: str = self.prepareSMSGAddress(
                addr_send_from, AddressTypes.OFFER, cursor
            )

            offer_created_at = self.getTime()

            msg_buf = OfferMessage()

            msg_buf.protocol_version = (
                PROTOCOL_VERSION_ADAPTOR_SIG
                if swap_type == SwapTypes.XMR_SWAP
                else PROTOCOL_VERSION_SECRET_HASH
            )
            msg_buf.coin_from = int(coin_from)
            msg_buf.coin_to = int(coin_to)
            msg_buf.amount_from = int(amount)
            msg_buf.amount_to = int(amount_to)
            msg_buf.min_bid_amount = int(min_bid_amount)

            msg_buf.time_valid = valid_for_seconds
            msg_buf.lock_type = lock_type
            msg_buf.lock_value = lock_value
            msg_buf.swap_type = swap_type
            msg_buf.amount_negotiable = extra_options.get("amount_negotiable", False)
            msg_buf.rate_negotiable = extra_options.get("rate_negotiable", False)

            msg_buf.message_nets = self.getMessageNetsString()

            if msg_buf.amount_negotiable or msg_buf.rate_negotiable:
                ensure(
                    auto_accept_bids is False,
                    "Auto-accept unavailable when amount or rate are variable",
                )

            if "from_fee_override" in extra_options:
                msg_buf.fee_rate_from = ci_from.make_int(
                    extra_options["from_fee_override"]
                )
            else:
                # TODO: conf_target = ci_from.settings.get('conf_target', 2)
                conf_target = 2
                if "from_fee_conf_target" in extra_options:
                    conf_target = extra_options["from_fee_conf_target"]
                fee_rate, fee_src = self.getFeeRateForCoin(coin_from, conf_target)
                if "from_fee_multiplier_percent" in extra_options:
                    fee_rate *= extra_options["fee_multiplier"] / 100.0
                msg_buf.fee_rate_from = ci_from.make_int(fee_rate)

            if "to_fee_override" in extra_options:
                msg_buf.fee_rate_to = ci_to.make_int(extra_options["to_fee_override"])
            else:
                # TODO: conf_target = ci_to.settings.get('conf_target', 2)
                conf_target = 2
                if "to_fee_conf_target" in extra_options:
                    conf_target = extra_options["to_fee_conf_target"]
                fee_rate, fee_src = self.getFeeRateForCoin(coin_to, conf_target)
                if "to_fee_multiplier_percent" in extra_options:
                    fee_rate *= extra_options["fee_multiplier"] / 100.0
                msg_buf.fee_rate_to = ci_to.make_int(fee_rate)

            if swap_type == SwapTypes.XMR_SWAP:
                xmr_offer = XmrOffer()

                chain_a_ci = ci_to if reverse_bid else ci_from
                lock_value_2 = (
                    lock_value + 1000
                    if (None, DebugTypes.OFFER_LOCK_2_VALUE_INC) in self._debug_cases
                    else lock_value
                )
                # Delay before the chain a lock refund tx can be mined
                xmr_offer.lock_time_1 = chain_a_ci.getExpectedSequence(
                    lock_type, lock_value
                )
                # Delay before the follower can spend from the chain a lock refund tx
                xmr_offer.lock_time_2 = chain_a_ci.getExpectedSequence(
                    lock_type, lock_value_2
                )

                xmr_offer.a_fee_rate = msg_buf.fee_rate_from
                xmr_offer.b_fee_rate = (
                    msg_buf.fee_rate_to
                )  # Unused: TODO - Set priority?

            # Set auto-accept type
            automation_id = extra_options.get("automation_id", -1)
            if automation_id == -1 and auto_accept_bids:
                automation_id = 1  # Default strategy

            if automation_id != -1:
                strategy = self.queryOne(
                    AutomationStrategy,
                    cursor,
                    {"active_ind": 1, "record_id": automation_id},
                )
                if strategy:
                    msg_buf.auto_accept_type = (
                        2 if strategy.only_known_identities else 1
                    )
            else:
                msg_buf.auto_accept_type = 0

            # If a prefunded txn is not used, check that the wallet balance can cover the tx fee.
            if "prefunded_itx" not in extra_options:
                # TODO: Better tx size estimate, xmr_swap_b_lock_tx_vsize could be larger than xmr_swap_b_lock_spend_tx_vsize
                estimated_fee: int = (
                    msg_buf.fee_rate_from * ci_from.est_lock_tx_vsize() // 1000
                )
                self.ensureWalletCanSend(ci_from, swap_type, int(amount), estimated_fee)

            # TODO: Send proof of funds with offer
            # proof_of_funds_hash = getOfferProofOfFundsHash(msg_buf, offer_addr)
            # proof_addr, proof_sig, proof_utxos = self.getProofOfFunds(
            #     coin_from_t, ensure_balance, proof_of_funds_hash
            # )

            offer_bytes: bytes = msg_buf.to_bytes()
            payload_hex: str = (
                str.format("{:02x}", MessageTypes.OFFER) + offer_bytes.hex()
            )
            msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
            # Send offers to active and bridged networks
            offer_id: bytes = self.sendMessage(
                offer_addr, offer_addr_to, payload_hex, msg_valid, cursor
            )

            security_token = extra_options.get("security_token", None)
            if security_token is not None and len(security_token) != 20:
                raise ValueError("Security token must be 20 bytes long.")

            bid_reversed: bool = (
                msg_buf.swap_type == SwapTypes.XMR_SWAP
                and self.is_reverse_ads_bid(msg_buf.coin_from, msg_buf.coin_to)
            )
            offer = Offer(
                offer_id=offer_id,
                active_ind=1,
                protocol_version=msg_buf.protocol_version,
                coin_from=msg_buf.coin_from,
                coin_to=msg_buf.coin_to,
                amount_from=msg_buf.amount_from,
                amount_to=msg_buf.amount_to,
                rate=rate,
                min_bid_amount=msg_buf.min_bid_amount,
                time_valid=msg_buf.time_valid,
                lock_type=int(msg_buf.lock_type),
                lock_value=msg_buf.lock_value,
                swap_type=msg_buf.swap_type,
                amount_negotiable=msg_buf.amount_negotiable,
                rate_negotiable=msg_buf.rate_negotiable,
                addr_to=offer_addr_to,
                addr_from=offer_addr,
                created_at=offer_created_at,
                expire_at=offer_created_at + msg_buf.time_valid,
                was_sent=True,
                bid_reversed=bid_reversed,
                security_token=security_token,
                from_feerate=msg_buf.fee_rate_from,
                to_feerate=msg_buf.fee_rate_to,
                pk_from=self.getPubkeyForAddress(cursor, offer_addr),
                auto_accept_type=msg_buf.auto_accept_type,
                message_nets=msg_buf.message_nets,
            )
            offer.setState(OfferStates.OFFER_SENT)

            if swap_type == SwapTypes.XMR_SWAP:
                xmr_offer.offer_id = offer_id
                self.add(xmr_offer, cursor)

            automation_id = extra_options.get("automation_id", -1)
            if automation_id == -1 and auto_accept_bids:
                # Use default strategy
                automation_id = 1
            if automation_id != -1:
                auto_link = AutomationLink(
                    active_ind=1,
                    linked_type=Concepts.OFFER,
                    linked_id=offer_id,
                    strategy_id=automation_id,
                    created_at=offer_created_at,
                    repeat_limit=1,
                    repeat_count=0,
                )
                self.add(auto_link, cursor)

            if "prefunded_itx" in extra_options:
                prefunded_tx = PrefundedTx(
                    active_ind=1,
                    created_at=offer_created_at,
                    linked_type=Concepts.OFFER,
                    linked_id=offer_id,
                    tx_type=TxTypes.ITX_PRE_FUNDED,
                    tx_data=extra_options["prefunded_itx"],
                )
                self.add(prefunded_tx, cursor)

            self.add(offer, cursor)
            self.add(SentOffer(offer_id=offer_id), cursor)
        finally:
            self.closeDB(cursor)
        self.log.info(f"Sent OFFER {self.log.id(offer_id)}")

        if self.ws_server:
            self.ws_server.send_message_to_all('{"event": "offer_created"}')

        return offer_id

    def revokeOffer(self, offer_id, security_token=None) -> None:
        self.log.info(f"Revoking offer {self.log.id(offer_id)}")

        cursor = self.openDB()
        try:
            offer = self.queryOne(Offer, cursor, {"offer_id": offer_id})

            if (
                offer.security_token is not None
                and offer.security_token != security_token
            ):
                raise ValueError("Mismatched security token")

            msg_buf = OfferRevokeMessage()
            msg_buf.offer_msg_id = offer_id

            signature_enc = self.ci(Coins.PART).signMessage(
                offer.addr_from, offer_id.hex() + "_revoke"
            )

            msg_buf.signature = base64.b64decode(signature_enc)

            msg_bytes = msg_buf.to_bytes()
            payload_hex = (
                str.format("{:02x}", MessageTypes.OFFER_REVOKE) + msg_bytes.hex()
            )

            msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, offer.time_valid)
            msg_id = self.sendMessage(
                offer.addr_from,
                self.network_addr,
                payload_hex,
                msg_valid,
                cursor,
                payload_version=offer.smsg_payload_version,
            )
            self.log.debug(
                f"Revoked offer {self.log.id(offer_id)} in msg {self.log.id(msg_id)}"
            )
        finally:
            self.closeDB(cursor, commit=False)

    def archiveOffer(self, offer_id) -> None:
        self.log.info(f"Archiving offer {self.log.id(offer_id)}")
        cursor = self.openDB()
        try:
            offer = self.queryOne(Offer, cursor, {"offer_id": offer_id})

            if offer.active_ind != 1:
                raise ValueError("Offer is not active")

            offer.active_ind = 3
            self.updateDB(
                Offer,
                cursor,
                [
                    "offer_id",
                ],
            )
        finally:
            self.closeDB(cursor)

    def editOffer(self, offer_id, data) -> None:
        self.log.info(f"Editing offer {self.log.id(offer_id)}")
        cursor = self.openDB()
        try:
            offer = self.queryOne(Offer, cursor, {"offer_id": offer_id})
            ensure(offer, f"Offer not found: {self.log.id(offer_id)}.")
            if "automation_strat_id" in data:
                new_automation_strat_id = data["automation_strat_id"]
                link = self.queryOne(
                    Offer,
                    cursor,
                    {
                        "linked_type": int(Concepts.OFFER),
                        "linked_id": offer.offer_id,
                    },
                )
                if not link:
                    if new_automation_strat_id > 0:
                        link = AutomationLink(
                            active_ind=1,
                            linked_type=Concepts.OFFER,
                            linked_id=offer_id,
                            strategy_id=new_automation_strat_id,
                            created_at=self.getTime(),
                        )
                else:
                    if new_automation_strat_id < 1:
                        link.active_ind = 0
                    else:
                        link.strategy_id = new_automation_strat_id
                        link.active_ind = 1
                self.add(link, cursor, upsert=True)
        finally:
            self.closeDB(cursor)

    def grindForEd25519Key(self, coin_type, evkey, key_path_base) -> bytes:
        ci = self.ci(coin_type)
        nonce = 1
        while True:
            key_path = key_path_base + "/{}".format(nonce)
            extkey = self.callcoinrpc(Coins.PART, "extkey", ["info", evkey, key_path])[
                "key_info"
            ]["result"]
            privkey = decodeWif(
                self.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"][
                    "privkey"
                ]
            )

            if ci.verifyKey(privkey):
                return privkey
            nonce += 1
            if nonce > 1000:
                raise ValueError("grindForEd25519Key failed")

    def getWalletKey(self, coin_type, key_num, for_ed25519=False) -> bytes:
        evkey = self.callcoinrpc(Coins.PART, "extkey", ["account", "default", "true"])[
            "evkey"
        ]

        key_path_base = "44445555h/1h/{}/{}".format(int(coin_type), key_num)

        if not for_ed25519:
            extkey = self.callcoinrpc(
                Coins.PART, "extkey", ["info", evkey, key_path_base]
            )["key_info"]["result"]
            return decodeWif(
                self.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"][
                    "privkey"
                ]
            )

        return self.grindForEd25519Key(coin_type, evkey, key_path_base)

    def getPathKey(
        self,
        coin_from,
        coin_to,
        bid_created_at: int,
        contract_count: int,
        key_no: int,
        for_ed25519: bool = False,
    ) -> bytes:
        evkey = self.callcoinrpc(Coins.PART, "extkey", ["account", "default", "true"])[
            "evkey"
        ]

        days = bid_created_at // 86400
        secs = bid_created_at - days * 86400
        key_path_base = "44445555h/999999/{}/{}/{}/{}/{}/{}".format(
            int(coin_from), int(coin_to), days, secs, contract_count, key_no
        )

        if not for_ed25519:
            extkey = self.callcoinrpc(
                Coins.PART, "extkey", ["info", evkey, key_path_base]
            )["key_info"]["result"]
            return decodeWif(
                self.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"][
                    "privkey"
                ]
            )

        return self.grindForEd25519Key(coin_to, evkey, key_path_base)

    def getNetworkKey(self, key_num):
        evkey = self.callcoinrpc(Coins.PART, "extkey", ["account", "default", "true"])[
            "evkey"
        ]

        key_path = "44445556h/1h/{}".format(int(key_num))

        extkey = self.callcoinrpc(Coins.PART, "extkey", ["info", evkey, key_path])[
            "key_info"
        ]["result"]
        return decodeWif(
            self.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"][
                "privkey"
            ]
        )

    def getContractPubkey(self, date, contract_count):

        # Derive an address to use for a contract
        evkey = self.callcoinrpc(Coins.PART, "extkey", ["account", "default", "true"])[
            "evkey"
        ]

        # Should the coin path be included?
        path = "44445555h"
        path += "/" + str(date.year) + "/" + str(date.month) + "/" + str(date.day)
        path += "/" + str(contract_count)

        extkey = self.callcoinrpc(Coins.PART, "extkey", ["info", evkey, path])[
            "key_info"
        ]["result"]
        pubkey = self.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"][
            "pubkey"
        ]
        return bytes.fromhex(pubkey)

    def getContractPrivkey(self, date: dt.datetime, contract_count: int) -> bytes:
        # Derive an address to use for a contract
        evkey = self.callcoinrpc(Coins.PART, "extkey", ["account", "default", "true"])[
            "evkey"
        ]

        path = "44445555h"
        path += "/" + str(date.year) + "/" + str(date.month) + "/" + str(date.day)
        path += "/" + str(contract_count)

        extkey = self.callcoinrpc(Coins.PART, "extkey", ["info", evkey, path])[
            "key_info"
        ]["result"]
        privkey = self.callcoinrpc(Coins.PART, "extkey", ["info", extkey])["key_info"][
            "privkey"
        ]
        raw = decodeAddress(privkey)[1:]
        if len(raw) > 32:
            raw = raw[:32]
        return raw

    def getContractSecret(self, date: dt.datetime, contract_count: int) -> bytes:
        # Derive a key to use for a contract secret
        evkey = self.callcoinrpc(Coins.PART, "extkey", ["account", "default", "true"])[
            "evkey"
        ]

        path = "44445555h/99999"
        path += "/" + str(date.year) + "/" + str(date.month) + "/" + str(date.day)
        path += "/" + str(contract_count)

        return sha256(
            bytes(
                self.callcoinrpc(Coins.PART, "extkey", ["info", evkey, path])[
                    "key_info"
                ]["result"],
                "UTF-8",
            )
        )

    def getReceiveAddressFromPool(self, coin_type, bid_id: bytes, tx_type, cursor=None):
        self.log.debug(
            f"Get address from pool bid_id {self.log.id(bid_id)}, type {tx_type}, coin {coin_type}"
        )
        try:
            use_cursor = self.openDB(cursor)

            record = self.queryOne(
                PooledAddress,
                use_cursor,
                {"coin_type": int(coin_type), "bid_id": None},
            )
            if not record:
                address = self.getReceiveAddressForCoin(coin_type)
                record = PooledAddress(addr=address, coin_type=int(coin_type))
            record.bid_id = bid_id
            record.tx_type = tx_type
            addr = record.addr
            ensure(
                self.ci(coin_type).isAddressMine(addr),
                "Pool address not owned by wallet!",
            )
            self.add(record, use_cursor, upsert=True)
            self.commitDB()
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)
        return addr

    def returnAddressToPool(self, bid_id: bytes, tx_type):
        self.log.debug(
            f"Return address to pool bid_id {self.log.id(bid_id)}, type {tx_type}"
        )
        try:
            cursor = self.openDB()
            try:
                record = self.queryOne(
                    PooledAddress,
                    cursor,
                    {"tx_type": int(tx_type), "bid_id": bid_id},
                )
                self.log.debug(f"Returning address to pool addr {record.addr}")

                # unset PooledAddress.bid_id
                query = "UPDATE addresspool SET bid_id = NULL WHERE bid_id = :bid_id AND tx_type = :tx_type"
                cursor.execute(query, {"bid_id": bid_id, "tx_type": tx_type})

                self.commitDB()
            except Exception as e:  # noqa: F841
                pass
        finally:
            self.closeDB(cursor, commit=False)

    def getReceiveAddressForCoin(self, coin_type):
        new_addr = self.ci(coin_type).getNewAddress(
            self.coin_clients[coin_type]["use_segwit"]
        )
        self.log.debug(
            f"Generated new receive address {self.log.addr(new_addr)} for {Coins(coin_type).name}"
        )
        return new_addr

    def getFeeRateForCoin(self, coin_type, conf_target: int = 2):
        return self.ci(coin_type).get_fee_rate(conf_target)

    def estimateWithdrawFee(self, coin_type, fee_rate):
        if coin_type in (Coins.XMR, Coins.WOW):
            # Fee estimate must be manually initiated
            return None
        tx_vsize = self.ci(coin_type).getHTLCSpendTxVSize()
        est_fee = (fee_rate * tx_vsize) / 1000
        return est_fee

    def withdrawCoin(self, coin_type, value, addr_to, subfee: bool) -> str:
        ci = self.ci(coin_type)
        info_str: str = ""
        if self.log.safe_logs is False:
            if subfee and coin_type in (Coins.XMR, Coins.WOW):
                info_str = f" sweep all to {addr_to}"
            else:
                info_str = " {} to {}{}".format(
                    value, addr_to, " subfee" if subfee else ""
                )
        self.log.info(f"withdrawCoin {ci.ticker()}{info_str}")

        txid = ci.withdrawCoin(value, addr_to, subfee)
        self.log.info_s(f"In txn: {txid}")
        return txid

    def withdrawLTC(self, type_from, value, addr_to, subfee: bool) -> str:
        ci = self.ci(Coins.LTC)
        self.log.info(
            "withdrawLTC{}".format(
                ""
                if self.log.safe_logs
                else " {} {} to {} {}".format(
                    value, type_from, addr_to, " subfee" if subfee else ""
                )
            )
        )
        txid = ci.withdrawCoin(value, type_from, addr_to, subfee)
        self.log.info_s(f"In txn: {txid}")
        return txid

    def withdrawParticl(
        self, type_from: str, type_to: str, value, addr_to: str, subfee: bool
    ) -> str:
        self.log.info(
            "withdrawParticl{}".format(
                ""
                if self.log.safe_logs
                else " {} {} to {} {} {}".format(
                    value, type_from, type_to, addr_to, " subfee" if subfee else ""
                )
            )
        )

        if type_from == "plain":
            type_from = "part"
        if type_to == "plain":
            type_to = "part"

        ci = self.ci(Coins.PART)
        txid = ci.sendTypeTo(type_from, type_to, value, addr_to, subfee)
        self.log.info_s(f"In txn: {txid}")
        return txid

    def cacheNewAddressForCoin(self, coin_type, cursor=None):
        self.log.debug(f"cacheNewAddressForCoin {Coins(coin_type).name}")
        key_str = "receive_addr_" + self.ci(coin_type).coin_name().lower()
        addr = self.getReceiveAddressForCoin(coin_type)
        self.setStringKV(key_str, addr, cursor)
        return addr

    def getCachedMainWalletAddress(self, ci, cursor=None):
        db_key = "main_wallet_addr_" + ci.coin_name().lower()
        cached_addr = self.getStringKV(db_key, cursor)
        if cached_addr is not None:
            return cached_addr
        self.log.warning(f"Setting {db_key}")
        main_address = ci.getMainWalletAddress()
        self.setStringKV(db_key, main_address, cursor)
        return main_address

    def checkWalletSeed(self, c) -> bool:
        ci = self.ci(c)
        if c == Coins.PART:
            ci.setWalletSeedWarning(
                False
            )  # All keys should be be derived from the Particl mnemonic
            return True  # TODO
        if c in (Coins.XMR, Coins.WOW):
            expect_address = self.getCachedMainWalletAddress(ci)
            if expect_address is None:
                self.log.warning(
                    f"Can't find expected main wallet address for coin {ci.coin_name()}"
                )
                return False
            ci._have_checked_seed = True
            wallet_address: str = ci.getMainWalletAddress()
            if expect_address == wallet_address:
                ci.setWalletSeedWarning(False)
                return True
            msg: str = f"Wallet for coin {ci.coin_name()} not derived from swap seed."
            if not self.log.safe_logs:
                msg += f"\n  Expected {expect_address}\n  Have     {wallet_address}"
            self.log.warning(msg)
            return False

        seed_key: str = "main_wallet_seedid_" + ci.coin_name().lower()
        expect_seedid: str = self.getStringKV(seed_key)
        if expect_seedid is None:
            self.log.warning(
                f"Can't find expected wallet seed id for coin {ci.coin_name()}."
            )
            _, is_locked = self.getLockedState()
            if is_locked is False:
                self.log.warning(
                    f"Setting seed ID for coin {ci.coin_name()} from master key."
                )
                root_key = self.getWalletKey(c, 1)
                self.storeSeedIDForCoin(root_key, c)
                expect_seedid: str = self.getStringKV(seed_key)
            else:
                self.log.warning("Node is locked.")
                return False

        if c == Coins.BTC and len(ci.rpc("listwallets")) < 1:
            self.log.warning(f"Missing wallet for coin {ci.coin_name()}")
            return False
        if ci.checkExpectedSeed(expect_seedid):
            ci.setWalletSeedWarning(False)
            return True
        if c == Coins.DCR:
            # Try the legacy extkey
            expect_seedid = self.getStringKV(
                "main_wallet_seedid_alt_" + ci.coin_name().lower()
            )
            if ci.checkExpectedSeed(expect_seedid):
                ci.setWalletSeedWarning(False)
                self.log.warning(f"{ci.coin_name()} is using the legacy extkey.")
                return True
        self.log.warning(
            f"Wallet for coin {ci.coin_name()} not derived from swap seed."
        )
        return False

    def reseedWallet(self, coin_type):
        ci = self.ci(coin_type)
        self.log.info(f"reseedWallet {ci.coin_name()}")
        if ci.knownWalletSeed():
            raise ValueError(
                f"{ci.coin_name()} wallet seed is already derived from the particl mnemonic"
            )

        self.initialiseWallet(coin_type, raise_errors=True)

        # TODO: How to scan pruned blocks?

        if not self.checkWalletSeed(coin_type):
            if coin_type in (Coins.XMR, Coins.WOW):
                raise ValueError("TODO: How to reseed XMR wallet?")
            else:
                raise ValueError("Wallet seed doesn't match expected.")

    def getCachedAddressForCoin(self, coin_type, cursor=None):
        self.log.debug(f"getCachedAddressForCoin {Coins(coin_type).name}")
        # TODO: auto refresh after used

        ci = self.ci(coin_type)
        key_str = "receive_addr_" + ci.coin_name().lower()
        use_cursor = self.openDB(cursor)
        try:
            addr = self.getStringKV(key_str, use_cursor)
            if addr is None:
                addr = self.getReceiveAddressForCoin(coin_type)
                self.setStringKV(key_str, addr, use_cursor)
        finally:
            if cursor is None:
                self.closeDB(use_cursor)
        return addr

    def cacheNewStealthAddressForCoin(self, coin_type):
        self.log.debug(f"cacheNewStealthAddressForCoin {Coins(coin_type).name}")

        if coin_type == Coins.LTC_MWEB:
            coin_type = Coins.LTC
        ci = self.ci(coin_type)
        key_str = "stealth_addr_" + ci.coin_name().lower()
        addr = ci.getNewStealthAddress()
        self.setStringKV(key_str, addr)
        return addr

    def getCachedStealthAddressForCoin(self, coin_type, cursor=None):
        self.log.debug(f"getCachedStealthAddressForCoin {Coins(coin_type).name}")

        if coin_type == Coins.LTC_MWEB:
            coin_type = Coins.LTC
        ci = self.ci(coin_type)
        key_str = "stealth_addr_" + ci.coin_name().lower()
        use_cursor = self.openDB(cursor)
        try:
            addr = self.getStringKV(key_str, use_cursor)
            if addr is None:
                addr = ci.getNewStealthAddress()
                self.log.info(f"Generated new stealth address for {ci.coin_name()}")
                self.setStringKV(key_str, addr, use_cursor)
        finally:
            if cursor is None:
                self.closeDB(use_cursor)
        return addr

    def getCachedWalletRestoreHeight(self, ci, cursor=None):
        self.log.debug(f"getCachedWalletRestoreHeight {ci.coin_name()}")

        key_str = "restore_height_" + ci.coin_name().lower()
        use_cursor = self.openDB(cursor)
        try:
            try:
                wrh = self.getIntKV(key_str, use_cursor)
            except Exception:
                wrh = ci.getWalletRestoreHeight()
                self.log.info(f"Found restore height for {ci.coin_name()}, block {wrh}")
                self.setIntKV(key_str, wrh, use_cursor)
        finally:
            if cursor is None:
                self.closeDB(use_cursor)
        return wrh

    def getWalletRestoreHeight(self, ci, cursor=None):
        wrh = ci._restore_height
        if wrh is not None:
            return wrh
        found_height = self.getCachedWalletRestoreHeight(ci, cursor=cursor)
        ci.setWalletRestoreHeight(found_height)
        return found_height

    def getNewContractId(self, cursor):
        self._contract_count += 1
        cursor.execute(
            'UPDATE kv_int SET value = :value WHERE KEY="contract_count"',
            {"value": self._contract_count},
        )
        return self._contract_count

    def getProofOfFunds(self, coin_type, amount_for: int, extra_commit_bytes):
        ci = self.ci(coin_type)
        self.log.debug(
            f"getProofOfFunds {ci.coin_name()} {ci.format_amount(amount_for)}"
        )

        if self.coin_clients[coin_type]["connection_type"] != "rpc":
            return (None, None, None)

        return ci.getProofOfFunds(amount_for, extra_commit_bytes)

    def saveBidInSession(
        self, bid_id: bytes, bid, cursor, xmr_swap=None, save_in_progress=None
    ) -> None:
        self.add(bid, cursor, upsert=True)
        if bid.initiate_tx:
            self.add(bid.initiate_tx, cursor, upsert=True)
        if bid.participate_tx:
            self.add(bid.participate_tx, cursor, upsert=True)
        if bid.xmr_a_lock_tx:
            self.add(bid.xmr_a_lock_tx, cursor, upsert=True)
        if bid.xmr_a_lock_spend_tx:
            self.add(bid.xmr_a_lock_spend_tx, cursor, upsert=True)
        if bid.xmr_b_lock_tx:
            self.add(bid.xmr_b_lock_tx, cursor, upsert=True)
        for tx_type, tx in bid.txns.items():
            self.add(tx, cursor, upsert=True)
        if xmr_swap is not None:
            self.add(xmr_swap, cursor, upsert=True)

        if save_in_progress is not None:
            if not isinstance(save_in_progress, Offer):
                raise ValueError("Must specify offer for save_in_progress")
            self.swaps_in_progress[bid_id] = (bid, save_in_progress)  # (bid, offer)

    def saveBid(self, bid_id: bytes, bid, xmr_swap=None) -> None:
        cursor = self.openDB()
        try:
            self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
        finally:
            self.closeDB(cursor)

    def createActionInSession(
        self, delay: int, action_type: int, linked_id: bytes, cursor
    ) -> None:
        self.log.debug(f"createAction {action_type} {self.log.id(linked_id)}")
        now: int = self.getTime()
        action = Action(
            active_ind=1,
            created_at=now,
            trigger_at=now + delay,
            action_type=action_type,
            linked_id=linked_id,
        )
        self.add(action, cursor)
        for debug_case in self._debug_cases:
            bid_id, debug_ind = debug_case
            if bid_id == linked_id and debug_ind == DebugTypes.DUPLICATE_ACTIONS:
                action = Action(
                    active_ind=1,
                    created_at=now,
                    trigger_at=now + delay + 3,
                    action_type=action_type,
                    linked_id=linked_id,
                )
                self.add(action, cursor)

    def createAction(self, delay: int, action_type: int, linked_id: bytes) -> None:
        cursor = self.openDB()
        try:
            self.createActionInSession(delay, action_type, linked_id, cursor)
        finally:
            self.closeDB(cursor)

    def logEvent(
        self,
        linked_type: int,
        linked_id: bytes,
        event_type: int,
        event_msg: str,
        cursor,
    ) -> None:
        entry = EventLog(
            active_ind=1,
            created_at=self.getTime(),
            linked_type=linked_type,
            linked_id=linked_id,
            event_type=int(event_type),
            event_msg=event_msg,
        )

        use_cursor = self.openDB(cursor)
        try:
            self.add(entry, use_cursor)
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def logBidEvent(
        self, bid_id: bytes, event_type: int, event_msg: str, cursor
    ) -> None:
        self.log.debug(f"logBidEvent {self.log.id(bid_id)} {event_type}")
        self.logEvent(Concepts.BID, bid_id, event_type, event_msg, cursor)

    def countBidEvents(self, bid, event_type, cursor):
        q = cursor.execute(
            "SELECT COUNT(*) FROM eventlog WHERE linked_type = :linked_type AND linked_id = :linked_id AND event_type = :event_type",
            {
                "linked_type": int(Concepts.BID),
                "linked_id": bid.bid_id,
                "event_type": int(event_type),
            },
        ).fetchone()
        return q[0]

    def getEvents(self, linked_type: int, linked_id: bytes):
        events = []
        cursor = self.openDB()
        try:
            for entry in self.query(
                EventLog, cursor, {"linked_type": linked_type, "linked_id": linked_id}
            ):
                events.append(entry)
            return events
        finally:
            self.closeDB(cursor, commit=False)

    def addMessageLink(
        self,
        linked_type: int,
        linked_id: int,
        msg_type: int,
        msg_id: bytes,
        msg_sequence: int = 0,
        cursor=None,
    ) -> None:
        entry = MessageLink(
            active_ind=1,
            created_at=self.getTime(),
            linked_type=linked_type,
            linked_id=linked_id,
            msg_type=int(msg_type),
            msg_sequence=msg_sequence,
            msg_id=msg_id,
        )

        use_cursor = self.openDB(cursor)
        try:
            self.add(entry, use_cursor)
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def getLinkedMessageId(
        self,
        linked_type: int,
        linked_id: int,
        msg_type: int,
        msg_sequence: int = 0,
        cursor=None,
    ) -> bytes:
        try:
            use_cursor = self.openDB(cursor)
            q = use_cursor.execute(
                "SELECT msg_id FROM message_links WHERE linked_type = :linked_type AND linked_id = :linked_id AND msg_type = :msg_type AND msg_sequence = :msg_sequence",
                {
                    "linked_type": linked_type,
                    "linked_id": linked_id,
                    "msg_type": msg_type,
                    "msg_sequence": msg_sequence,
                },
            ).fetchone()
            return q[0]
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def countMessageLinks(
        self,
        linked_type: int,
        linked_id: int,
        msg_type: int,
        msg_sequence: int = 0,
        cursor=None,
    ) -> int:
        try:
            use_cursor = self.openDB(cursor)
            q = use_cursor.execute(
                "SELECT COUNT(*) FROM message_links WHERE linked_type = :linked_type AND linked_id = :linked_id AND msg_type = :msg_type AND msg_sequence = :msg_sequence",
                {
                    "linked_type": linked_type,
                    "linked_id": linked_id,
                    "msg_type": msg_type,
                    "msg_sequence": msg_sequence,
                },
            ).fetchone()
            return q[0]
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def setBidAmounts(
        self, amount: int, offer, extra_options, ci_from
    ) -> (int, int, int):
        if "amount_to" in extra_options:
            amount_to: int = extra_options["amount_to"]
        elif "bid_rate" in extra_options:
            bid_rate = extra_options["bid_rate"]
            amount_to: int = int((amount * bid_rate) // ci_from.COIN())
            if not offer.rate_negotiable:
                self.log.warning(
                    "Fixed-rate offer bids should set amount to instead of bid rate."
                )
        else:
            amount_to: int = offer.amount_to
        bid_rate: int = ci_from.make_int(amount_to / amount, r=1)

        if offer.amount_negotiable and not offer.rate_negotiable:

            if extra_options.get("adjust_amount_for_rate", True):
                self.log.debug(
                    "Attempting to reduce amount to match offer rate within tolerance."
                )

                adjust_tries: int = 10000 if ci_from.exp() > 8 else 1000
                best_amount = amount
                best_amount_to = amount_to
                best_bid_rate = bid_rate
                best_diff = abs(bid_rate - offer.rate)

                for i in range(adjust_tries):
                    test_amount = amount - i
                    test_amount_to: int = int(
                        (test_amount * offer.rate) // ci_from.COIN()
                    )
                    test_bid_rate: int = ci_from.make_int(
                        test_amount_to / test_amount, r=1
                    )
                    test_diff = abs(test_bid_rate - offer.rate)

                    if test_diff < best_diff and self.ratesMatch(
                        test_bid_rate, offer.rate, offer.rate
                    ):
                        best_amount = test_amount
                        best_amount_to = test_amount_to
                        best_bid_rate = test_bid_rate
                        best_diff = test_diff

                        if test_diff == 0:
                            break

                    if not self.ratesMatch(test_bid_rate, offer.rate, offer.rate):
                        test_amount_to -= 1
                        test_bid_rate: int = ci_from.make_int(
                            test_amount_to / test_amount, r=1
                        )
                        test_diff = abs(test_bid_rate - offer.rate)

                        if test_diff < best_diff and self.ratesMatch(
                            test_bid_rate, offer.rate, offer.rate
                        ):
                            best_amount = test_amount
                            best_amount_to = test_amount_to
                            best_bid_rate = test_bid_rate
                            best_diff = test_diff

                            if test_diff == 0:
                                break

                        if amount == test_amount and amount_to == test_amount_to:
                            break

                        if best_diff == abs(bid_rate - offer.rate):
                            best_amount = test_amount
                            best_amount_to = test_amount_to
                            best_bid_rate = test_bid_rate
                        break
                if best_amount != amount or best_amount_to != amount_to:
                    if amount != best_amount:
                        msg: str = "Reducing bid amount-from"
                        if not self.log.safe_logs:
                            msg += f" from {amount} to {best_amount} to match offer rate (diff: {best_diff})."
                        self.log.info(msg)
                    elif amount_to != best_amount_to:
                        msg: str = "Reducing bid amount-to"
                        if not self.log.safe_logs:
                            msg += f" from {amount_to} to {best_amount_to} to match offer rate (diff: {best_diff})."
                        self.log.info(msg)
                    amount = best_amount
                    amount_to = best_amount_to
                    bid_rate = best_bid_rate
        return amount, amount_to, bid_rate

    def postBid(
        self, offer_id: bytes, amount: int, addr_send_from: str = None, extra_options={}
    ) -> bytes:
        # Bid to send bid.amount * bid.rate of coin_to in exchange for bid.amount of coin_from
        self.log.debug(f"postBid for offer: {self.log.id(offer_id)}")

        offer = self.getOffer(offer_id)
        ensure(offer, f"Offer not found: {self.log.id(offer_id)}.")
        ensure(offer.expire_at > self.getTime(), "Offer has expired")

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.postXmrBid(offer_id, amount, addr_send_from, extra_options)

        ensure(
            offer.protocol_version >= MINPROTO_VERSION_SECRET_HASH,
            "Incompatible offer protocol version",
        )
        valid_for_seconds = extra_options.get("valid_for_seconds", 60 * 10)
        self.validateBidValidTime(
            offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds
        )

        if not isinstance(amount, int):
            amount = int(amount)
            self.log.warning("postBid amount should be an integer type.")

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        amount, amount_to, bid_rate = self.setBidAmounts(
            amount, offer, extra_options, ci_from
        )
        self.validateBidAmount(offer, amount, bid_rate)

        try:
            cursor = self.openDB()
            self.checkCoinsReady(coin_from, coin_to)

            now: int = self.getTime()
            encoded_proof_utxos = None
            if offer.swap_type == SwapTypes.SELLER_FIRST:
                proof_addr, proof_sig, proof_utxos = self.getProofOfFunds(
                    coin_to, amount_to, offer_id
                )
                if len(proof_utxos) > 0:
                    encoded_proof_utxos = ci_to.encodeProofUtxos(proof_utxos)
            else:
                raise ValueError("TODO")

            bid_addr: str = self.prepareSMSGAddress(
                addr_send_from, AddressTypes.BID, cursor
            )
            request_data = {
                "offer_id": offer_id.hex(),
                "amount_from": amount,
                "amount_to": amount_to,
            }
            bid_message_nets = self.selectMessageNetStringForConcept(
                Concepts.OFFER, offer_id, offer.message_nets, cursor
            )
            route_id, route_established = self.prepareMessageRoute(
                bid_message_nets,
                request_data,
                bid_addr,
                offer.addr_from,
                cursor,
                valid_for_seconds,
            )

            contract_count = self.getNewContractId(cursor)
            contract_pubkey = self.getContractPubkey(
                dt.datetime.fromtimestamp(now).date(), contract_count
            )

            bid = Bid(
                protocol_version=PROTOCOL_VERSION_SECRET_HASH,
                active_ind=1,
                offer_id=offer_id,
                amount=amount,  # amount of coin_from
                amount_to=amount_to,
                rate=bid_rate,
                pkhash_buyer=ci_from.pkh(contract_pubkey),
                proof_address=proof_addr,
                proof_signature=proof_sig,
                proof_utxos=encoded_proof_utxos,
                created_at=now,
                contract_count=contract_count,
                expire_at=now + valid_for_seconds,
                bid_addr=bid_addr,
                was_sent=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
                message_nets=bid_message_nets,
            )

            pkhash_buyer_to = ci_to.pkh(contract_pubkey)
            if pkhash_buyer_to != bid.pkhash_buyer:
                # Different pubkey hash
                bid.pkhash_buyer_to = pkhash_buyer_to

            if route_id and route_established is False:
                msg_buf = self.getBidMessage(bid, offer)
                msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
                encrypted_msg = encryptMsg(
                    self,
                    bid.bid_addr,
                    offer.addr_from,
                    bytes((MessageTypes.BID,)) + msg_buf.to_bytes(),
                    msg_valid,
                    cursor,
                    timestamp=bid.created_at,
                    deterministic=True,
                )
                bid_id = smsgGetID(encrypted_msg)
                bid.setState(BidStates.CONNECT_REQ_SENT)
            else:
                bid_id = self.sendBidMessage(bid, offer, cursor)
                bid.setState(BidStates.BID_SENT)
            if route_id:
                message_route_link = DirectMessageRouteLink(
                    active_ind=2 if route_established else 1,
                    direct_message_route_id=route_id,
                    linked_type=Concepts.BID,
                    linked_id=bid_id,
                    created_at=bid.created_at,
                )
                self.add(message_route_link, cursor)

            bid.bid_id = bid_id

            self.saveBidInSession(bid_id, bid, cursor)

            self.log.info(f"Sent BID {self.log.id(bid_id)}")
            return bid_id
        finally:
            self.closeDB(cursor)

    def getOffer(self, offer_id: bytes, cursor=None):
        try:
            use_cursor = self.openDB(cursor)
            return self.queryOne(Offer, use_cursor, {"offer_id": offer_id})
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def setTxBlockInfoFromHeight(self, ci, tx, height: int) -> None:
        try:
            tx.block_height = height
            block_header = ci.getBlockHeaderFromHeight(height)
            tx.block_hash = bytes.fromhex(block_header["hash"])
            tx.block_time = block_header["time"]  # Or median_time?
        except Exception as e:
            self.log.warning(f"setTxBlockInfoFromHeight failed {e}")

    def loadBidTxns(self, bid, cursor) -> None:
        bid.txns = {}
        for stx in self.query(SwapTx, cursor, {"bid_id": bid.bid_id}):
            if stx.tx_type == TxTypes.ITX:
                bid.initiate_tx = stx
            elif stx.tx_type == TxTypes.PTX:
                bid.participate_tx = stx
            elif stx.tx_type == TxTypes.XMR_SWAP_A_LOCK:
                bid.xmr_a_lock_tx = stx
            elif stx.tx_type == TxTypes.XMR_SWAP_A_LOCK_SPEND:
                bid.xmr_a_lock_spend_tx = stx
            elif stx.tx_type == TxTypes.XMR_SWAP_B_LOCK:
                bid.xmr_b_lock_tx = stx
            else:
                bid.txns[stx.tx_type] = stx

    def getXmrBidFromSession(self, cursor, bid_id: bytes):
        bid = self.queryOne(Bid, cursor, {"bid_id": bid_id})
        xmr_swap = None
        if bid:
            xmr_swap = self.queryOne(XmrSwap, cursor, {"bid_id": bid_id})
            self.loadBidTxns(bid, cursor)
        return bid, xmr_swap

    def getXmrBid(self, bid_id: bytes):
        try:
            cursor = self.openDB()
            return self.getXmrBidFromSession(cursor, bid_id)
        finally:
            self.closeDB(cursor, commit=False)

    def getXmrOfferFromSession(self, cursor, offer_id: bytes):
        offer = self.queryOne(Offer, cursor, {"offer_id": offer_id})
        xmr_offer = None
        if offer:
            xmr_offer = self.queryOne(XmrOffer, cursor, {"offer_id": offer_id})
        return offer, xmr_offer

    def getXmrOffer(self, offer_id: bytes, cursor=None):
        try:
            use_cursor = self.openDB(cursor)
            return self.getXmrOfferFromSession(use_cursor, offer_id)
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def getBid(self, bid_id: bytes, cursor=None, with_txns=True):
        try:
            use_cursor = self.openDB(cursor)
            bid = self.queryOne(Bid, use_cursor, {"bid_id": bid_id})
            if bid and with_txns:
                self.loadBidTxns(bid, use_cursor)
            return bid
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def getBidAndOffer(self, bid_id: bytes, cursor=None, with_txns=True):
        try:
            use_cursor = self.openDB(cursor)
            bid = self.queryOne(Bid, use_cursor, {"bid_id": bid_id})
            offer = None
            if bid:
                offer = self.queryOne(Offer, use_cursor, {"offer_id": bid.offer_id})
                if with_txns:
                    self.loadBidTxns(bid, use_cursor)
            return bid, offer
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def getXmrBidAndOffer(self, bid_id: bytes, list_events=True):
        try:
            cursor = self.openDB()
            xmr_swap = None
            offer = None
            xmr_offer = None
            events = []

            bid = self.queryOne(Bid, cursor, {"bid_id": bid_id})
            if bid:
                offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
                if offer and offer.swap_type == SwapTypes.XMR_SWAP:
                    xmr_swap = self.queryOne(XmrSwap, cursor, {"bid_id": bid.bid_id})
                    xmr_offer = self.queryOne(
                        XmrOffer, cursor, {"offer_id": bid.offer_id}
                    )
                self.loadBidTxns(bid, cursor)
                if list_events:
                    events = self.list_bid_events(bid.bid_id, cursor)

            return bid, xmr_swap, offer, xmr_offer, events
        finally:
            self.closeDB(cursor, commit=False)

    def getIdentity(self, address: str):
        try:
            cursor = self.openDB()
            identity = self.queryOne(KnownIdentity, cursor, {"address": address})
            return identity
        finally:
            self.closeDB(cursor, commit=False)

    def list_bid_events(self, bid_id: bytes, cursor):
        query_str = (
            "SELECT created_at, event_type, event_msg FROM eventlog "
            + "WHERE active_ind = 1 AND linked_type = :linked_type AND linked_id = :linked_id "
        )
        q = cursor.execute(
            query_str, {"linked_type": int(Concepts.BID), "linked_id": bid_id}
        )
        events = []
        for row in q:
            events.append({"at": row[0], "desc": describeEventEntry(row[1], row[2])})

        query_str = (
            "SELECT created_at, trigger_at FROM actions "
            + "WHERE active_ind = 1 AND linked_id = :linked_id "
        )
        q = cursor.execute(query_str, {"linked_id": bid_id})
        for row in q:
            events.append(
                {
                    "at": row[0],
                    "desc": "Delaying until: {}".format(
                        format_timestamp(row[1], with_seconds=True)
                    ),
                }
            )

        return events

    def acceptBid(self, bid_id: bytes, cursor=None) -> None:
        self.log.info(f"Accepting bid {self.log.id(bid_id)}")

        try:
            use_cursor = self.openDB(cursor)

            bid, offer = self.getBidAndOffer(bid_id, use_cursor)
            ensure(bid, "Bid not found")
            ensure(offer, "Offer not found")

            # Ensure bid is still valid
            now: int = self.getTime()
            ensure(bid.expire_at > now, "Bid expired")
            ensure(
                canAcceptBidState(bid.state),
                "Wrong bid state: {}".format(BidStates(bid.state).name),
            )

            if offer.swap_type == SwapTypes.XMR_SWAP:
                ensure(
                    bid.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG,
                    "Incompatible bid protocol version",
                )
                reverse_bid: bool = self.is_reverse_ads_bid(
                    offer.coin_from, offer.coin_to
                )
                if reverse_bid:
                    return self.acceptADSReverseBid(bid_id, use_cursor)
                return self.acceptXmrBid(bid_id, use_cursor)

            ensure(
                bid.protocol_version >= MINPROTO_VERSION_SECRET_HASH,
                "Incompatible bid protocol version",
            )
            if bid.contract_count is None:
                bid.contract_count = self.getNewContractId(use_cursor)

            coin_from = Coins(offer.coin_from)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(offer.coin_to)
            bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

            secret = self.getContractSecret(bid_date, bid.contract_count)
            secret_hash = sha256(secret)

            pubkey_refund = self.getContractPubkey(bid_date, bid.contract_count)
            pkhash_refund = ci_from.pkh(pubkey_refund)

            if coin_from in (Coins.DCR,):
                op_hash = OpCodes.OP_SHA256_DECRED
            else:
                op_hash = OpCodes.OP_SHA256

            if bid.initiate_tx is not None:
                txid = bid.initiate_tx.txid
                script = bid.initiate_tx.script
                self.log.warning(
                    f"Initiate txn {self.log.id(txid)} already exists for bid {self.log.id(bid_id)}"
                )
            else:
                if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
                    sequence = ci_from.getExpectedSequence(
                        offer.lock_type, offer.lock_value
                    )
                    script = atomic_swap_1.buildContractScript(
                        sequence,
                        secret_hash,
                        bid.pkhash_buyer,
                        pkhash_refund,
                        op_hash=op_hash,
                    )
                else:
                    if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                        lock_value = ci_from.getChainHeight() + offer.lock_value
                    else:
                        lock_value = self.getTime() + offer.lock_value
                    self.log.debug(
                        f"Initiate {ci_from.coin_name()} lock_value {offer.lock_value} {lock_value}",
                    )
                    script = atomic_swap_1.buildContractScript(
                        lock_value,
                        secret_hash,
                        bid.pkhash_buyer,
                        pkhash_refund,
                        OpCodes.OP_CHECKLOCKTIMEVERIFY,
                        op_hash=op_hash,
                    )

                bid.pkhash_seller = ci_to.pkh(pubkey_refund)

                prefunded_tx = self.getPreFundedTx(
                    Concepts.OFFER,
                    offer.offer_id,
                    TxTypes.ITX_PRE_FUNDED,
                    cursor=use_cursor,
                )
                txn, lock_tx_vout = self.createInitiateTxn(
                    coin_from, bid_id, bid, script, prefunded_tx
                )

                # Store the signed refund txn in case wallet is locked when refund is possible
                refund_txn = self.createRefundTxn(
                    coin_from, txn, offer, bid, script, cursor=use_cursor
                )
                bid.initiate_txn_refund = bytes.fromhex(refund_txn)

                txid = ci_from.publishTx(bytes.fromhex(txn))
                self.log.debug(
                    f"Submitted initiate txn {txid} to {ci_from.coin_name()} chain for bid {self.log.id(bid_id)}",
                )
                bid.initiate_tx = SwapTx(
                    bid_id=bid_id,
                    tx_type=TxTypes.ITX,
                    txid=bytes.fromhex(txid),
                    vout=lock_tx_vout,
                    tx_data=bytes.fromhex(txn),
                    script=script,
                )
                bid.setITxState(TxStates.TX_SENT)
                self.logEvent(
                    Concepts.BID,
                    bid.bid_id,
                    EventLogTypes.ITX_PUBLISHED,
                    "",
                    use_cursor,
                )

                # Check non-bip68 final
                try:
                    txid = ci_from.publishTx(bid.initiate_txn_refund)
                    self.log.error(
                        f"Submit refund_txn unexpectedly worked {self.logIDT(bytes.fromhex(txid))}"
                    )
                except Exception as ex:
                    if ci_from.isTxNonFinalError(str(ex)) is False:
                        self.log.error(f"Submit refund_txn unexpected error: {ex}")
                        raise ex

            if txid is not None:
                msg_buf = BidAcceptMessage()
                msg_buf.bid_msg_id = bid_id
                msg_buf.initiate_txid = bytes.fromhex(txid)
                msg_buf.contract_script = bytes(script)

                # pkh sent in script is hashed with sha256, Decred expects blake256
                if bid.pkhash_seller != pkhash_refund:
                    msg_buf.pkhash_seller = bid.pkhash_seller

                bid_bytes = msg_buf.to_bytes()
                payload_hex = (
                    str.format("{:02x}", MessageTypes.BID_ACCEPT) + bid_bytes.hex()
                )

                msg_valid: int = self.getAcceptBidMsgValidTime(bid)
                accept_msg_id = self.sendMessage(
                    offer.addr_from,
                    bid.bid_addr,
                    payload_hex,
                    msg_valid,
                    use_cursor,
                    message_nets=bid.message_nets,
                    payload_version=offer.smsg_payload_version,
                )

                self.addMessageLink(
                    Concepts.BID,
                    bid_id,
                    MessageTypes.BID_ACCEPT,
                    accept_msg_id,
                    cursor=use_cursor,
                )
                self.log.info(f"Sent BID_ACCEPT {self.logIDM(accept_msg_id)}")

                bid.setState(BidStates.BID_ACCEPTED)

                self.saveBidInSession(bid_id, bid, use_cursor)
                self.swaps_in_progress[bid_id] = (bid, offer)

        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def sendXmrSplitMessages(
        self,
        msg_type,
        addr_from: str,
        addr_to: str,
        xmr_swap,
        dleag: bytes,
        msg_valid: int,
        bid_msg_ids,
        cursor,
        message_nets,
        payload_version,
    ) -> None:

        dleag_split_size_init, dleag_split_size = xmr_swap.getMsgSplitInfo()
        sent_bytes = dleag_split_size_init

        num_sent = 1
        while sent_bytes < len(dleag):
            size_to_send: int = min(dleag_split_size, len(dleag) - sent_bytes)
            msg_buf = XmrSplitMessage(
                msg_id=xmr_swap.bid_id,
                msg_type=msg_type,
                sequence=num_sent,
                dleag=dleag[sent_bytes : sent_bytes + size_to_send],
            )
            msg_bytes = msg_buf.to_bytes()
            payload_hex = (
                str.format("{:02x}", MessageTypes.XMR_BID_SPLIT) + msg_bytes.hex()
            )
            bid_msg_ids[num_sent] = self.sendMessage(
                addr_from,
                addr_to,
                payload_hex,
                msg_valid,
                cursor,
                message_nets=message_nets,
                payload_version=payload_version,
            )
            num_sent += 1
            sent_bytes += size_to_send

    def getADSBidIntentMessage(self, bid, offer) -> bytes:
        valid_for_seconds: int = bid.expire_at - bid.created_at
        msg_buf = ADSBidIntentMessage()
        msg_buf.protocol_version = bid.protocol_version
        msg_buf.offer_msg_id = bid.offer_id
        msg_buf.time_valid = valid_for_seconds
        msg_buf.amount_from = bid.amount_to
        msg_buf.amount_to = bid.amount

        # Set msg_buf.message_nets to let the remote node know what networks to respond on.
        # bid.message_nets is a local field denoting the network/s to send to
        if offer.smsg_payload_version > 1:
            msg_buf.message_nets = self.getMessageNetsString()

        return msg_buf

    def sendADSBidIntentMessage(self, bid, offer, cursor) -> bytes:
        valid_for_seconds: int = bid.expire_at - bid.created_at
        msg_buf = self.getADSBidIntentMessage(bid, offer)
        msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
        payload_hex = (
            str.format("{:02x}", MessageTypes.ADS_BID_LF) + msg_buf.to_bytes().hex()
        )

        self.logD(
            LC.NET,
            f"sendADSBidIntentMessage offer.message_nets {offer.message_nets}, bid.message_nets {bid.message_nets}, msg_buf.message_nets {msg_buf.message_nets}",
        )
        return self.sendMessage(
            bid.bid_addr,
            offer.addr_from,
            payload_hex,
            msg_valid,
            cursor,
            timestamp=bid.created_at,
            deterministic=(False if bid.bid_id is None else True),
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )

    def getXmrBidMessage(self, bid, xmr_swap, offer) -> XmrBidMessage:
        valid_for_seconds: int = bid.expire_at - bid.created_at
        msg_buf = XmrBidMessage()
        msg_buf.protocol_version = PROTOCOL_VERSION_ADAPTOR_SIG
        msg_buf.offer_msg_id = bid.offer_id
        msg_buf.time_valid = valid_for_seconds
        msg_buf.amount = bid.amount
        msg_buf.amount_to = bid.amount_to

        msg_buf.dest_af = xmr_swap.dest_af
        msg_buf.pkaf = xmr_swap.pkaf
        msg_buf.kbvf = xmr_swap.vkbvf

        dleag_split_size_init, _ = xmr_swap.getMsgSplitInfo()
        if len(xmr_swap.kbsf_dleag) > dleag_split_size_init:
            msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag[:dleag_split_size_init]
        else:
            msg_buf.kbsf_dleag = xmr_swap.kbsf_dleag

        # Set msg_buf.message_nets to let the remote node know what networks to respond on.
        # bid.message_nets is a local field denoting the network/s to send to
        if offer.smsg_payload_version > 1:
            msg_buf.message_nets = self.getMessageNetsString()

        return msg_buf

    def sendXmrBidMessage(self, bid, xmr_swap, offer, cursor) -> bytes:
        valid_for_seconds: int = bid.expire_at - bid.created_at

        ci_to = self.ci(offer.coin_to)

        msg_buf = self.getXmrBidMessage(bid, xmr_swap, offer)

        payload_hex = (
            str.format("{:02x}", MessageTypes.XMR_BID_FL) + msg_buf.to_bytes().hex()
        )
        msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)

        self.logD(
            LC.NET,
            f"sendXmrBidMessage offer.message_nets {offer.message_nets}, bid.message_nets {bid.message_nets}, msg_buf.message_nets {msg_buf.message_nets}",
        )
        bid_msg_id = self.sendMessage(
            bid.bid_addr,
            offer.addr_from,
            payload_hex,
            msg_valid,
            cursor,
            timestamp=bid.created_at,
            deterministic=(False if bid.bid_id is None else True),
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )
        bid_id = bid_msg_id
        if bid.bid_id and bid_msg_id != bid.bid_id:
            self.log.warning(
                f"sendXmrBidMessage: Mismatched bid ids: {bid.bid_id.hex()}, {bid_msg_id.hex()}."
            )

        bid_msg_ids = {}
        if xmr_swap.bid_id is None:
            xmr_swap.bid_id = bid_id
        if ci_to.curve_type() == Curves.ed25519:
            self.sendXmrSplitMessages(
                XmrSplitMsgTypes.BID,
                bid.bid_addr,
                offer.addr_from,
                xmr_swap,
                xmr_swap.kbsf_dleag,
                msg_valid,
                bid_msg_ids,
                cursor,
                message_nets=bid.message_nets,
                payload_version=offer.smsg_payload_version,
            )
        for k, msg_id in bid_msg_ids.items():
            self.addMessageLink(
                Concepts.BID,
                bid_id,
                MessageTypes.BID,
                msg_id,
                msg_sequence=k,
                cursor=cursor,
            )

        return bid_msg_id

    def getBidMessage(self, bid, offer) -> BidMessage:
        valid_for_seconds: int = bid.expire_at - bid.created_at
        msg_buf = BidMessage()
        msg_buf.protocol_version = bid.protocol_version
        msg_buf.offer_msg_id = bid.offer_id
        msg_buf.time_valid = valid_for_seconds
        msg_buf.amount = bid.amount
        msg_buf.amount_to = bid.amount_to

        msg_buf.pkhash_buyer = bid.pkhash_buyer
        if bid.pkhash_buyer_to:
            msg_buf.pkhash_buyer_to = bid.pkhash_buyer_to

        msg_buf.proof_address = bid.proof_address
        msg_buf.proof_signature = bid.proof_signature

        if bid.proof_utxos:
            msg_buf.proof_utxos = bid.proof_utxos

        # Set msg_buf.message_nets to let the remote node know what networks to respond on.
        # bid.message_nets is a local field denoting the network/s to send to
        if offer.smsg_payload_version > 1:
            msg_buf.message_nets = self.getMessageNetsString()

        return msg_buf

    def sendBidMessage(self, bid, offer, cursor) -> bytes:
        valid_for_seconds: int = bid.expire_at - bid.created_at

        msg_buf = self.getBidMessage(bid, offer)

        payload_hex = str.format("{:02x}", MessageTypes.BID) + msg_buf.to_bytes().hex()
        msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)

        self.logD(
            LC.NET,
            f"sendBidMessage offer.message_nets {offer.message_nets}, bid.message_nets {bid.message_nets}, msg_buf.message_nets {msg_buf.message_nets}",
        )
        bid_msg_id = self.sendMessage(
            bid.bid_addr,
            offer.addr_from,
            payload_hex,
            msg_valid,
            cursor,
            timestamp=bid.created_at,
            deterministic=(False if bid.bid_id is None else True),
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )
        if bid.bid_id and bid_msg_id != bid.bid_id:
            self.log.warning(
                f"sendBidMessage: Mismatched bid ids: {bid.bid_id.hex()}, {bid_msg_id.hex()}."
            )
        return bid_msg_id

    def prepareMessageRoute(
        self,
        message_nets,
        req_data,
        addr_from: str,
        addr_to: str,
        cursor,
        valid_for_seconds,
    ) -> (int, bool):
        if self._use_direct_message_routes is False:
            return None, False

        # message_nets contains the network selected to use:
        # TODO: allow multiple networks
        self.logD(LC.NET, f"prepareMessageRoute message_nets {message_nets}")

        if message_nets.startswith("b."):
            # TODO: get direct messages working through portals
            self.logD(LC.NET, "Not using route - bridged networks.")
            return None, False
        if len(message_nets) == 0:
            if len(self.active_networks) == 1:
                network_id: int = networkTypeToID(
                    self.active_networks[0].get("type", "smsg")
                )
            else:
                self.logD(LC.NET, "Not using route - Multiple networks.")
                return None, False
                # raise RuntimeError(
                #     "Network must be specified if multiple networks are active."
                # )
        else:
            network_id: int = networkTypeToID(message_nets)
        if network_id not in (MessageNetworks.SIMPLEX,):
            return None, False
        try:
            net_i = self.getActiveNetworkInterface(network_id)
        except Exception as e:  # noqa: F841
            self.logD(
                LC.NET,
                f"Not using route - network interface not found for {network_id}.",
            )
            return None, False

        # Look for active route
        message_route = self.getMessageRoute(1, addr_from, addr_to, cursor=cursor)
        self.log.debug(f"Using active message route: {message_route}")
        if message_route:
            return message_route.record_id, True

        # Look for route being established
        message_route = self.getMessageRoute(2, addr_from, addr_to, cursor=cursor)
        self.log.debug(f"Waiting for message route: {message_route}")
        if message_route:
            return message_route.record_id, False

        cmd_id = net_i.send_command("/connect")
        response = net_i.wait_for_command_response(cmd_id)
        connReqInvitation = getJoinedSimplexLink(response)
        pccConnId = getResponseData(response, "connection")["pccConnId"]
        req_data["bsx_address"] = addr_from
        req_data["connection_req"] = connReqInvitation

        msg_buf = ConnectReqMessage()
        msg_buf.network_type = MessageNetworks.SIMPLEX
        msg_buf.network_data = b"bsx"
        msg_buf.request_type = ConnectionRequestTypes.BID
        msg_buf.request_data = json.dumps(req_data).encode("UTF-8")

        bid_bytes = msg_buf.to_bytes()
        payload_hex = str.format("{:02x}", MessageTypes.CONNECT_REQ) + bid_bytes.hex()

        msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
        connect_req_msgid = self.sendMessage(
            addr_from,
            addr_to,
            payload_hex,
            msg_valid,
            cursor,
            message_nets=message_nets,
        )

        now: int = self.getTime()
        message_route = DirectMessageRoute(
            active_ind=2,
            network_id=network_id,
            linked_type=Concepts.OFFER,
            smsg_addr_local=addr_from,
            smsg_addr_remote=addr_to,
            route_data=json.dumps(
                {
                    "connection_req": connReqInvitation,
                    "connect_req_msgid": connect_req_msgid.hex(),
                    "pccConnId": pccConnId,
                }
            ).encode("UTF-8"),
            created_at=now,
        )
        message_route_id = self.add(message_route, cursor)

        self.log.info(f"Sent CONNECT_REQ {self.logIDB(connect_req_msgid)}")
        return message_route_id, False

    def postXmrBid(
        self, offer_id: bytes, amount: int, addr_send_from: str = None, extra_options={}
    ) -> bytes:
        # Bid to send bid.amount * bid.rate of coin_to in exchange for bid.amount of coin_from
        # Send MSG1L F -> L or MSG0F L -> F
        self.log.debug(f"postXmrBid {self.logIDO(offer_id)}")

        try:
            cursor = self.openDB()
            offer, xmr_offer = self.getXmrOffer(offer_id, cursor=cursor)

            ensure(offer, f"Offer not found: {self.log.id(offer_id)}.")
            ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(offer_id)}.")
            ensure(
                offer.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG,
                "Incompatible offer protocol version",
            )
            ensure(offer.expire_at > self.getTime(), "Offer has expired")

            coin_from = Coins(offer.coin_from)
            coin_to = Coins(offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            valid_for_seconds: int = extra_options.get("valid_for_seconds", 60 * 10)

            amount, amount_to, bid_rate = self.setBidAmounts(
                amount, offer, extra_options, ci_from
            )

            bid_created_at: int = self.getTime()
            if offer.swap_type != SwapTypes.XMR_SWAP:
                raise ValueError(f"TODO: Unknown swap type {offer.swap_type.name}")

            if not (self.debug and extra_options.get("debug_skip_validation", False)):
                self.validateBidValidTime(
                    offer.swap_type, coin_from, coin_to, valid_for_seconds
                )
                self.validateBidAmount(offer, amount, bid_rate)

            self.checkCoinsReady(coin_from, coin_to)

            # TODO: Better tx size estimate
            fee_rate, fee_src = self.getFeeRateForCoin(coin_to, conf_target=2)
            fee_rate_to = ci_to.make_int(fee_rate)
            estimated_fee: int = fee_rate_to * ci_to.est_lock_tx_vsize() // 1000
            self.ensureWalletCanSend(
                ci_to, offer.swap_type, int(amount_to), estimated_fee, for_offer=False
            )

            bid_addr: str = self.prepareSMSGAddress(
                addr_send_from, AddressTypes.BID, cursor
            )

            # return id of route waiting to be established
            request_data = {
                "offer_id": offer_id.hex(),
                "amount_from": amount,
                "amount_to": amount_to,
            }
            bid_message_nets = self.selectMessageNetStringForConcept(
                Concepts.OFFER, offer.offer_id, offer.message_nets, cursor
            )
            route_id, route_established = self.prepareMessageRoute(
                bid_message_nets,
                request_data,
                bid_addr,
                offer.addr_from,
                cursor,
                valid_for_seconds,
            )

            reverse_bid: bool = self.is_reverse_ads_bid(coin_from, coin_to)
            if reverse_bid:
                reversed_rate: int = ci_to.make_int(amount / amount_to, r=1)

                xmr_swap = XmrSwap()
                xmr_swap.contract_count = self.getNewContractId(cursor)
                self.setMsgSplitInfo(xmr_swap)

                bid = Bid(
                    protocol_version=PROTOCOL_VERSION_ADAPTOR_SIG,
                    active_ind=1,
                    offer_id=offer_id,
                    amount=amount_to,
                    amount_to=amount,
                    rate=reversed_rate,
                    created_at=bid_created_at,
                    contract_count=xmr_swap.contract_count,
                    expire_at=bid_created_at + valid_for_seconds,
                    bid_addr=bid_addr,
                    was_sent=True,
                    was_received=False,
                    message_nets=bid_message_nets,
                )

                if route_id and route_established is False:
                    msg_buf = self.getADSBidIntentMessage(bid, offer)
                    msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
                    encrypted_msg = encryptMsg(
                        self,
                        bid.bid_addr,
                        offer.addr_from,
                        bytes((MessageTypes.ADS_BID_LF,)) + msg_buf.to_bytes(),
                        msg_valid,
                        cursor,
                        timestamp=bid.created_at,
                        deterministic=True,
                    )
                    bid_id = smsgGetID(encrypted_msg)
                    bid.setState(BidStates.CONNECT_REQ_SENT)
                else:
                    bid_id = self.sendADSBidIntentMessage(bid, offer, cursor)
                    bid.setState(BidStates.BID_REQUEST_SENT)
                if route_id:
                    message_route_link = DirectMessageRouteLink(
                        active_ind=2 if route_established else 1,
                        direct_message_route_id=route_id,
                        linked_type=Concepts.BID,
                        linked_id=bid_id,
                        created_at=bid_created_at,
                    )
                    self.add(message_route_link, cursor)
                bid.bid_id = bid_id
                xmr_swap.bid_id = bid.bid_id

                self.saveBidInSession(xmr_swap.bid_id, bid, cursor, xmr_swap)
                self.commitDB()

                self.log.info(f"Sent ADS_BID_LF {self.logIDB(xmr_swap.bid_id)}")
                return xmr_swap.bid_id

            xmr_swap = XmrSwap()
            xmr_swap.contract_count = self.getNewContractId(cursor)
            self.setMsgSplitInfo(xmr_swap)

            address_out = self.getReceiveAddressFromPool(
                coin_from, offer_id, TxTypes.XMR_SWAP_A_LOCK, cursor=cursor
            )
            if coin_from in (Coins.PART_BLIND,):
                addrinfo = ci_from.rpc("getaddressinfo", [address_out])
                xmr_swap.dest_af = bytes.fromhex(addrinfo["pubkey"])
            else:
                xmr_swap.dest_af = ci_from.decodeAddress(address_out)

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbvf = self.getPathKey(
                coin_from,
                coin_to,
                bid_created_at,
                xmr_swap.contract_count,
                KeyTypes.KBVF,
                for_ed25519,
            )
            kbsf = self.getPathKey(
                coin_from,
                coin_to,
                bid_created_at,
                xmr_swap.contract_count,
                KeyTypes.KBSF,
                for_ed25519,
            )

            kaf = self.getPathKey(
                coin_from,
                coin_to,
                bid_created_at,
                xmr_swap.contract_count,
                KeyTypes.KAF,
            )

            xmr_swap.vkbvf = kbvf
            xmr_swap.pkbvf = ci_to.getPubkey(kbvf)
            xmr_swap.pkbsf = ci_to.getPubkey(kbsf)

            xmr_swap.pkaf = ci_from.getPubkey(kaf)

            if ci_to.curve_type() == Curves.ed25519:
                xmr_swap.kbsf_dleag = ci_to.proveDLEAG(kbsf)
                xmr_swap.pkasf = xmr_swap.kbsf_dleag[0:33]
            elif ci_to.curve_type() == Curves.secp256k1:
                for i in range(10):
                    xmr_swap.kbsf_dleag = ci_to.signRecoverable(
                        kbsf, "proof kbsf owned for swap"
                    )
                    pk_recovered = ci_to.verifySigAndRecover(
                        xmr_swap.kbsf_dleag, "proof kbsf owned for swap"
                    )
                    if pk_recovered == xmr_swap.pkbsf:
                        break
                    self.log.debug("kbsl recovered pubkey mismatch, retrying.")
                assert pk_recovered == xmr_swap.pkbsf
                xmr_swap.pkasf = xmr_swap.pkbsf
            else:
                raise ValueError("Unknown curve")
            assert xmr_swap.pkasf == ci_from.getPubkey(kbsf)

            bid = Bid(
                protocol_version=PROTOCOL_VERSION_ADAPTOR_SIG,
                active_ind=1,
                offer_id=offer_id,
                amount=amount,
                amount_to=amount_to,
                rate=bid_rate,
                created_at=bid_created_at,
                contract_count=xmr_swap.contract_count,
                expire_at=bid_created_at + valid_for_seconds,
                bid_addr=bid_addr,
                was_sent=True,
                message_nets=bid_message_nets,
            )

            if route_id and route_established is False:
                msg_buf = self.getXmrBidMessage(bid, xmr_swap, offer)
                msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
                encrypted_msg = encryptMsg(
                    self,
                    bid.bid_addr,
                    offer.addr_from,
                    bytes((MessageTypes.XMR_BID_FL,)) + msg_buf.to_bytes(),
                    msg_valid,
                    cursor,
                    timestamp=bid.created_at,
                    deterministic=True,
                )
                bid_id = smsgGetID(encrypted_msg)
                bid.setState(BidStates.CONNECT_REQ_SENT)
            else:
                bid_id = self.sendXmrBidMessage(bid, xmr_swap, offer, cursor)
                bid.setState(BidStates.BID_SENT)
            if route_id:
                message_route_link = DirectMessageRouteLink(
                    active_ind=2 if route_established else 1,
                    direct_message_route_id=route_id,
                    linked_type=Concepts.BID,
                    linked_id=bid_id,
                    created_at=bid_created_at,
                )
                self.add(message_route_link, cursor)
            bid.bid_id = bid_id
            xmr_swap.bid_id = bid.bid_id

            bid.chain_a_height_start = ci_from.getChainHeight()
            bid.chain_b_height_start = ci_to.getChainHeight()

            wallet_restore_height = self.getWalletRestoreHeight(ci_to, cursor)
            if bid.chain_b_height_start < wallet_restore_height:
                bid.chain_b_height_start = wallet_restore_height
                self.log.warning(
                    f"Adaptor-sig swap restore height clamped to {wallet_restore_height}"
                )

            self.saveBidInSession(bid.bid_id, bid, cursor, xmr_swap)
            self.log.info(f"Sent XMR_BID_FL {self.logIDB(xmr_swap.bid_id)}")
            return xmr_swap.bid_id
        finally:
            self.closeDB(cursor)

    def acceptXmrBid(self, bid_id: bytes, cursor=None) -> None:
        # MSG1F and MSG2F L -> F
        self.log.info(f"Accepting adaptor-sig bid {self.log.id(bid_id)}")

        now: int = self.getTime()
        try:
            use_cursor = self.openDB(cursor)
            bid, xmr_swap = self.getXmrBidFromSession(use_cursor, bid_id)
            ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
            ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")
            ensure(bid.expire_at > now, "Bid expired")

            last_bid_state = bid.state
            if last_bid_state == BidStates.SWAP_DELAYING:
                last_bid_state = getLastBidState(bid.states)

            ensure(
                canAcceptBidState(last_bid_state),
                "Wrong bid state: {}".format(str(BidStates(last_bid_state))),
            )

            offer, xmr_offer = self.getXmrOffer(bid.offer_id, cursor=use_cursor)
            ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
            ensure(
                xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}."
            )
            ensure(offer.expire_at > now, "Offer has expired")

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
            coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
            coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            a_fee_rate: int = (
                xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate
            )

            if xmr_swap.contract_count is None:
                xmr_swap.contract_count = self.getNewContractId(use_cursor)

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbvl = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KBVL,
                for_ed25519,
            )
            kbsl = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KBSL,
                for_ed25519,
            )

            kal = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KAL,
            )

            xmr_swap.vkbvl = kbvl
            xmr_swap.pkbvl = ci_to.getPubkey(kbvl)
            xmr_swap.pkbsl = ci_to.getPubkey(kbsl)

            xmr_swap.vkbv = ci_to.sumKeys(kbvl, xmr_swap.vkbvf)
            ensure(ci_to.verifyKey(xmr_swap.vkbv), "Invalid key, vkbv")
            xmr_swap.pkbv = ci_to.sumPubkeys(xmr_swap.pkbvl, xmr_swap.pkbvf)
            xmr_swap.pkbs = ci_to.sumPubkeys(xmr_swap.pkbsl, xmr_swap.pkbsf)

            xmr_swap.pkal = ci_from.getPubkey(kal)

            # MSG2F
            pi = self.pi(SwapTypes.XMR_SWAP)

            refundExtraArgs = dict()
            lockExtraArgs = dict()
            if self.isBchXmrSwap(offer):
                pkh_refund_to = ci_from.decodeAddress(
                    self.getCachedAddressForCoin(coin_from, use_cursor)
                )
                pkh_dest = xmr_swap.dest_af
                # refund script
                refundExtraArgs["mining_fee"] = 1000
                refundExtraArgs["out_1"] = ci_from.getScriptForPubkeyHash(pkh_refund_to)
                refundExtraArgs["out_2"] = ci_from.getScriptForPubkeyHash(pkh_dest)
                refundExtraArgs["public_key"] = xmr_swap.pkaf
                refundExtraArgs["timelock"] = xmr_offer.lock_time_2
                refund_lock_tx_script = ci_from.genScriptLockTxScript(
                    ci_from, xmr_swap.pkal, xmr_swap.pkaf, **refundExtraArgs
                )
                # will make use of this in `createSCLockRefundTx`
                refundExtraArgs["refund_lock_tx_script"] = refund_lock_tx_script

                # lock script
                lockExtraArgs["mining_fee"] = 1000
                lockExtraArgs["out_1"] = ci_from.getScriptForPubkeyHash(pkh_dest)
                lockExtraArgs["out_2"] = ci_from.scriptToP2SH32LockingBytecode(
                    refund_lock_tx_script
                )
                lockExtraArgs["public_key"] = xmr_swap.pkal
                lockExtraArgs["timelock"] = xmr_offer.lock_time_1

            xmr_swap.a_lock_tx_script = pi.genScriptLockTxScript(
                ci_from, xmr_swap.pkal, xmr_swap.pkaf, **lockExtraArgs
            )
            prefunded_tx = self.getPreFundedTx(
                Concepts.OFFER,
                bid.offer_id,
                TxTypes.ITX_PRE_FUNDED,
                cursor=use_cursor,
            )
            if prefunded_tx:
                xmr_swap.a_lock_tx = pi.promoteMockTx(
                    ci_from, prefunded_tx, xmr_swap.a_lock_tx_script
                )
            else:
                xmr_swap.a_lock_tx = ci_from.createSCLockTx(
                    bid.amount, xmr_swap.a_lock_tx_script, xmr_swap.vkbv
                )
                xmr_swap.a_lock_tx = ci_from.fundSCLockTx(
                    xmr_swap.a_lock_tx, a_fee_rate, xmr_swap.vkbv
                )

            xmr_swap.a_lock_tx_id = ci_from.getTxid(xmr_swap.a_lock_tx)
            (
                xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_script,
                xmr_swap.a_swap_refund_value,
            ) = ci_from.createSCLockRefundTx(
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_tx_script,
                xmr_swap.pkal,
                xmr_swap.pkaf,
                xmr_offer.lock_time_1,
                xmr_offer.lock_time_2,
                a_fee_rate,
                xmr_swap.vkbv,
                **refundExtraArgs,
            )
            xmr_swap.a_lock_refund_tx_id = ci_from.getTxid(xmr_swap.a_lock_refund_tx)
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.al_lock_refund_tx_sig = ci_from.signTx(
                kal,
                xmr_swap.a_lock_refund_tx,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )
            v = ci_from.verifyTxSig(
                xmr_swap.a_lock_refund_tx,
                xmr_swap.al_lock_refund_tx_sig,
                xmr_swap.pkal,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )
            ensure(v, "Invalid coin A lock refund tx leader sig")
            pkh_refund_to = ci_from.decodeAddress(
                self.getCachedAddressForCoin(coin_from, use_cursor)
            )
            xmr_swap.a_lock_refund_spend_tx = ci_from.createSCLockRefundSpendTx(
                xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_script,
                pkh_refund_to,
                a_fee_rate,
                xmr_swap.vkbv,
                **refundExtraArgs,
            )
            xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxid(
                xmr_swap.a_lock_refund_spend_tx
            )

            # Double check txns before sending
            self.log.debug(
                f"Bid: {self.log.id(bid_id)} - Double checking chain A lock txns are valid before sending bid accept."
            )
            check_lock_tx_inputs = False  # TODO: check_lock_tx_inputs without txindex
            _, xmr_swap.a_lock_tx_vout = ci_from.verifySCLockTx(
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_tx_script,
                bid.amount,
                xmr_swap.pkal,
                xmr_swap.pkaf,
                a_fee_rate,
                check_lock_tx_inputs,
                xmr_swap.vkbv,
                **lockExtraArgs,
            )

            _, _, lock_refund_vout = ci_from.verifySCLockRefundTx(
                xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_refund_tx_script,
                xmr_swap.a_lock_tx_id,
                xmr_swap.a_lock_tx_vout,
                xmr_offer.lock_time_1,
                xmr_swap.a_lock_tx_script,
                xmr_swap.pkal,
                xmr_swap.pkaf,
                xmr_offer.lock_time_2,
                bid.amount,
                a_fee_rate,
                xmr_swap.vkbv,
                **refundExtraArgs,
            )

            ci_from.verifySCLockRefundSpendTx(
                xmr_swap.a_lock_refund_spend_tx,
                xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_id,
                xmr_swap.a_lock_refund_tx_script,
                xmr_swap.pkal,
                lock_refund_vout,
                xmr_swap.a_swap_refund_value,
                a_fee_rate,
                xmr_swap.vkbv,
                **refundExtraArgs,
            )

            msg_buf = XmrBidAcceptMessage()
            msg_buf.bid_msg_id = bid_id
            msg_buf.pkal = xmr_swap.pkal
            msg_buf.kbvl = kbvl

            dleag_split_size_init, _ = xmr_swap.getMsgSplitInfo()
            if ci_to.curve_type() == Curves.ed25519:
                xmr_swap.kbsl_dleag = ci_to.proveDLEAG(kbsl)
                msg_buf.kbsl_dleag = xmr_swap.kbsl_dleag[:dleag_split_size_init]
            elif ci_to.curve_type() == Curves.secp256k1:
                for i in range(10):
                    xmr_swap.kbsl_dleag = ci_to.signRecoverable(
                        kbsl, "proof kbsl owned for swap"
                    )
                    pk_recovered = ci_to.verifySigAndRecover(
                        xmr_swap.kbsl_dleag, "proof kbsl owned for swap"
                    )
                    if pk_recovered == xmr_swap.pkbsl:
                        break
                    self.log.debug("kbsl recovered pubkey mismatch, retrying.")
                assert pk_recovered == xmr_swap.pkbsl
                msg_buf.kbsl_dleag = xmr_swap.kbsl_dleag
            else:
                raise ValueError("Unknown curve")

            # MSG2F
            msg_buf.a_lock_tx = xmr_swap.a_lock_tx
            msg_buf.a_lock_tx_script = xmr_swap.a_lock_tx_script
            msg_buf.a_lock_refund_tx = xmr_swap.a_lock_refund_tx
            msg_buf.a_lock_refund_tx_script = bytes(xmr_swap.a_lock_refund_tx_script)
            msg_buf.a_lock_refund_spend_tx = xmr_swap.a_lock_refund_spend_tx
            msg_buf.al_lock_refund_tx_sig = xmr_swap.al_lock_refund_tx_sig

            msg_bytes = msg_buf.to_bytes()
            payload_hex = (
                str.format("{:02x}", MessageTypes.XMR_BID_ACCEPT_LF) + msg_bytes.hex()
            )

            addr_from: str = bid.bid_addr if reverse_bid else offer.addr_from
            addr_to: str = offer.addr_from if reverse_bid else bid.bid_addr

            msg_valid: int = self.getAcceptBidMsgValidTime(bid)
            bid_msg_ids = {}
            bid_msg_ids[0] = self.sendMessage(
                addr_from,
                addr_to,
                payload_hex,
                msg_valid,
                use_cursor,
                message_nets=bid.message_nets,
                payload_version=offer.smsg_payload_version,
            )

            if ci_to.curve_type() == Curves.ed25519:
                self.sendXmrSplitMessages(
                    XmrSplitMsgTypes.BID_ACCEPT,
                    addr_from,
                    addr_to,
                    xmr_swap,
                    xmr_swap.kbsl_dleag,
                    msg_valid,
                    bid_msg_ids,
                    use_cursor,
                    bid.message_nets,
                    payload_version=offer.smsg_payload_version,
                )

            bid.setState(BidStates.BID_ACCEPTED)  # ADS

            self.saveBidInSession(bid_id, bid, use_cursor, xmr_swap=xmr_swap)
            for k, msg_id in bid_msg_ids.items():
                self.addMessageLink(
                    Concepts.BID,
                    bid_id,
                    MessageTypes.BID_ACCEPT,
                    msg_id,
                    msg_sequence=k,
                    cursor=use_cursor,
                )

            # Add to swaps_in_progress only when waiting on txns
            self.log.info(f"Sent XMR_BID_ACCEPT_LF {self.log.id(bid_id)}")
            return bid_id
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def acceptADSReverseBid(self, bid_id: bytes, cursor=None) -> None:
        self.log.info(f"Accepting reverse adaptor-sig bid {self.log.id(bid_id)}")

        now: int = self.getTime()
        try:
            use_cursor = self.openDB(cursor)
            bid, xmr_swap = self.getXmrBidFromSession(use_cursor, bid_id)
            ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
            ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")
            ensure(bid.expire_at > now, "Bid expired")

            last_bid_state = bid.state
            if last_bid_state == BidStates.SWAP_DELAYING:
                last_bid_state = getLastBidState(bid.states)

            ensure(
                canAcceptBidState(last_bid_state),
                "Wrong bid state: {}".format(str(BidStates(last_bid_state))),
            )

            offer, xmr_offer = self.getXmrOffer(bid.offer_id, cursor=use_cursor)
            ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
            ensure(
                xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}."
            )
            ensure(offer.expire_at > now, "Offer has expired")

            # Bid is reversed
            coin_from = Coins(offer.coin_to)
            coin_to = Coins(offer.coin_from)
            ci_from = self.ci(coin_from)
            ci_to = self.ci(coin_to)

            # TODO: Better tx size estimate
            fee_rate, fee_src = self.getFeeRateForCoin(coin_to, conf_target=2)
            fee_rate_from = ci_to.make_int(fee_rate)
            estimated_fee: int = fee_rate_from * ci_to.est_lock_tx_vsize() // 1000
            self.ensureWalletCanSend(
                ci_to,
                offer.swap_type,
                offer.amount_from,
                estimated_fee,
                for_offer=False,
            )

            if xmr_swap.contract_count is None:
                xmr_swap.contract_count = self.getNewContractId(use_cursor)

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbvf = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KBVF,
                for_ed25519,
            )
            kbsf = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KBSF,
                for_ed25519,
            )

            kaf = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KAF,
            )

            address_out = self.getReceiveAddressFromPool(
                coin_from, bid.offer_id, TxTypes.XMR_SWAP_A_LOCK, cursor=use_cursor
            )
            if coin_from == Coins.PART_BLIND:
                addrinfo = ci_from.rpc("getaddressinfo", [address_out])
                xmr_swap.dest_af = bytes.fromhex(addrinfo["pubkey"])
            else:
                xmr_swap.dest_af = ci_from.decodeAddress(address_out)

            xmr_swap.vkbvf = kbvf
            xmr_swap.pkbvf = ci_to.getPubkey(kbvf)
            xmr_swap.pkbsf = ci_to.getPubkey(kbsf)

            xmr_swap.pkaf = ci_from.getPubkey(kaf)

            xmr_swap_1.setDLEAG(xmr_swap, ci_to, kbsf)
            assert xmr_swap.pkasf == ci_from.getPubkey(kbsf)

            dleag_split_size_init, _ = xmr_swap.getMsgSplitInfo()
            msg_buf = ADSBidIntentAcceptMessage()
            msg_buf.bid_msg_id = bid_id
            msg_buf.dest_af = xmr_swap.dest_af
            msg_buf.pkaf = xmr_swap.pkaf
            msg_buf.kbvf = kbvf
            msg_buf.kbsf_dleag = (
                xmr_swap.kbsf_dleag
                if len(xmr_swap.kbsf_dleag) < dleag_split_size_init
                else xmr_swap.kbsf_dleag[:dleag_split_size_init]
            )

            bid_bytes = msg_buf.to_bytes()
            payload_hex = (
                str.format("{:02x}", MessageTypes.ADS_BID_ACCEPT_FL) + bid_bytes.hex()
            )

            addr_from: str = offer.addr_from
            addr_to: str = bid.bid_addr
            msg_valid: int = self.getAcceptBidMsgValidTime(bid)
            bid_msg_ids = {}
            bid_msg_ids[0] = self.sendMessage(
                addr_from,
                addr_to,
                payload_hex,
                msg_valid,
                use_cursor,
                message_nets=bid.message_nets,
                payload_version=offer.smsg_payload_version,
            )

            if ci_to.curve_type() == Curves.ed25519:
                self.sendXmrSplitMessages(
                    XmrSplitMsgTypes.BID,
                    addr_from,
                    addr_to,
                    xmr_swap,
                    xmr_swap.kbsf_dleag,
                    msg_valid,
                    bid_msg_ids,
                    use_cursor,
                    message_nets=bid.message_nets,
                    payload_version=offer.smsg_payload_version,
                )

            bid.setState(BidStates.BID_REQUEST_ACCEPTED)

            for k, msg_id in bid_msg_ids.items():
                self.addMessageLink(
                    Concepts.BID,
                    bid_id,
                    MessageTypes.ADS_BID_ACCEPT_FL,
                    msg_id,
                    msg_sequence=k,
                    cursor=use_cursor,
                )
            self.log.info(f"Sent ADS_BID_ACCEPT_FL {self.logIDM(bid_msg_ids[0])}")
            self.saveBidInSession(bid_id, bid, use_cursor, xmr_swap=xmr_swap)
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def deactivateBidForReason(self, bid_id: bytes, new_state, cursor=None) -> None:
        try:
            use_cursor = self.openDB(cursor)
            bid, offer = self.getBidAndOffer(bid_id, use_cursor, with_txns=False)
            ensure(bid, "Bid not found")
            ensure(offer, "Offer not found")

            bid.setState(new_state)
            self.deactivateBid(use_cursor, offer, bid)
            self.updateDB(
                bid,
                use_cursor,
                [
                    "bid_id",
                ],
            )
            self.commitDB()
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def abandonBid(self, bid_id: bytes) -> None:
        if not self.debug:
            self.log.error(
                f"Can't abandon bid {self.log.id(bid_id)} when not in debug mode."
            )
            return

        self.log.info(f"Abandoning Bid {self.log.id(bid_id)}")
        self.deactivateBidForReason(bid_id, BidStates.BID_ABANDONED)

    def timeoutBid(self, bid_id: bytes, cursor=None) -> None:
        self.log.info(f"Bid {self.log.id(bid_id)} timed-out")
        self.deactivateBidForReason(bid_id, BidStates.SWAP_TIMEDOUT, cursor=cursor)

    def setBidError(
        self, bid_id: bytes, bid, error_str: str, save_bid: bool = True, xmr_swap=None
    ) -> None:
        self.log.error(f"Bid {self.log.id(bid_id)} - Error: {error_str}")
        bid.setState(BidStates.BID_ERROR)
        bid.state_note = "error msg: " + error_str
        if save_bid:
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

    def createInitiateTxn(
        self, coin_type, bid_id: bytes, bid, initiate_script, prefunded_tx=None
    ) -> (Optional[str], Optional[int]):
        if self.coin_clients[coin_type]["connection_type"] != "rpc":
            return None, None
        ci = self.ci(coin_type)

        if ci.using_segwit():
            p2wsh = ci.getScriptDest(initiate_script)
            addr_to = ci.encodeScriptDest(p2wsh)
        else:
            addr_to = ci.encode_p2sh(initiate_script)
        self.log.debug(
            f"Create initiate txn for coin {ci.coin_name()} to {addr_to} for bid {self.log.id(bid_id)}"
        )

        if prefunded_tx:
            pi = self.pi(SwapTypes.SELLER_FIRST)
            txn_signed = pi.promoteMockTx(ci, prefunded_tx, initiate_script).hex()
        else:
            txn_signed = ci.createRawSignedTransaction(addr_to, bid.amount)

        txjs = ci.describeTx(txn_signed)
        vout = getVoutByAddress(txjs, addr_to)
        assert vout is not None

        return txn_signed, vout

    def deriveParticipateScript(self, bid_id: bytes, bid, offer) -> bytearray:
        self.log.debug(f"deriveParticipateScript for bid {self.log.id(bid_id)}")

        coin_to = Coins(offer.coin_to)
        ci_to = self.ci(coin_to)

        secret_hash = atomic_swap_1.extractScriptSecretHash(bid.initiate_tx.script)
        pkhash_seller = bid.pkhash_seller

        if bid.pkhash_buyer_to and len(bid.pkhash_buyer_to) > 0:
            pkhash_buyer_refund = bid.pkhash_buyer_to
        else:
            pkhash_buyer_refund = bid.pkhash_buyer

        if coin_to in (Coins.DCR,):
            op_hash = OpCodes.OP_SHA256_DECRED
        else:
            op_hash = OpCodes.OP_SHA256

        # Participate txn is locked for half the time of the initiate txn
        lock_value = offer.lock_value // 2
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = ci_to.getExpectedSequence(offer.lock_type, lock_value)
            participate_script = atomic_swap_1.buildContractScript(
                sequence,
                secret_hash,
                pkhash_seller,
                pkhash_buyer_refund,
                op_hash=op_hash,
            )
        else:
            # Lock from the height or time of the block containing the initiate txn
            ci_from = self.ci(offer.coin_from)
            block_header = ci_from.getBlockHeaderFromHeight(
                bid.initiate_tx.chain_height
            )
            initiate_tx_block_hash = block_header["hash"]
            initiate_tx_block_time = block_header["time"]
            if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                # Walk the coin_to chain back until block time matches
                block_header_at = ci_to.getBlockHeaderAt(
                    initiate_tx_block_time, block_after=True
                )
                cblock_hash = block_header_at["hash"]
                cblock_height = block_header_at["height"]

                self.log.debug(
                    f"Setting lock value from height of block {ci_to.coin_name()} {cblock_hash}"
                )
                contract_lock_value = cblock_height + lock_value
            else:
                self.log.debug(
                    f"Setting lock value from time of block {ci_from.coin_name()} {initiate_tx_block_hash}"
                )
                contract_lock_value = initiate_tx_block_time + lock_value
            self.log.debug(
                f"participate {ci_to.coin_name()} lock_value {lock_value} {contract_lock_value}"
            )
            participate_script = atomic_swap_1.buildContractScript(
                contract_lock_value,
                secret_hash,
                pkhash_seller,
                pkhash_buyer_refund,
                OpCodes.OP_CHECKLOCKTIMEVERIFY,
                op_hash=op_hash,
            )
        return participate_script

    def createParticipateTxn(
        self, bid_id: bytes, bid, offer, participate_script: bytearray
    ):
        self.log.debug("createParticipateTxn")

        coin_to = Coins(offer.coin_to)

        if self.coin_clients[coin_to]["connection_type"] != "rpc":
            return None
        ci = self.ci(coin_to)

        amount_to: int = bid.amount_to

        if bid.debug_ind == DebugTypes.MAKE_INVALID_PTX:
            amount_to -= 1
            self.log.debug(
                f"bid {self.log.id(bid_id)}: Make invalid PTx for testing: {bid.debug_ind}."
            )
            self.logBidEvent(
                bid.bid_id,
                EventLogTypes.DEBUG_TWEAK_APPLIED,
                "ind {}".format(bid.debug_ind),
                None,
            )

        if ci.using_segwit():
            p2wsh = ci.getScriptDest(participate_script)
            addr_to = ci.encodeScriptDest(p2wsh)
        else:
            addr_to = ci.encode_p2sh(participate_script)

        txn_signed = ci.createRawSignedTransaction(addr_to, amount_to)

        refund_txn = self.createRefundTxn(
            coin_to,
            txn_signed,
            offer,
            bid,
            participate_script,
            tx_type=TxTypes.PTX_REFUND,
        )
        bid.participate_txn_refund = bytes.fromhex(refund_txn)

        chain_height = ci.getChainHeight()
        txjs = self.callcoinrpc(coin_to, "decoderawtransaction", [txn_signed])
        txid = txjs["txid"]

        if ci.using_segwit():
            vout = getVoutByScriptPubKey(txjs, p2wsh.hex())
        else:
            vout = getVoutByAddress(txjs, addr_to)
        self.addParticipateTxn(bid_id, bid, coin_to, txid, vout, chain_height)
        bid.participate_tx.script = participate_script
        bid.participate_tx.tx_data = bytes.fromhex(txn_signed)

        return txn_signed

    def createRedeemTxn(
        self,
        coin_type,
        bid,
        for_txn_type="participate",
        addr_redeem_out=None,
        fee_rate=None,
        cursor=None,
    ):
        self.log.debug(f"createRedeemTxn for coin {Coins(coin_type).name}")
        ci = self.ci(coin_type)

        if for_txn_type == "participate":
            prev_txnid = bid.participate_tx.txid.hex()
            prev_n = bid.participate_tx.vout
            txn_script = bid.participate_tx.script
            prev_amount = bid.amount_to
        else:
            prev_txnid = bid.initiate_tx.txid.hex()
            prev_n = bid.initiate_tx.vout
            txn_script = bid.initiate_tx.script
            prev_amount = bid.amount

        if ci.using_segwit():
            prev_p2wsh = ci.getScriptDest(txn_script)
            script_pub_key = prev_p2wsh.hex()
        else:
            script_pub_key = ci.get_p2sh_script_pubkey(txn_script).hex()

        prevout = {
            "txid": prev_txnid,
            "vout": prev_n,
            "scriptPubKey": script_pub_key,
            "redeemScript": txn_script.hex(),
            "amount": ci.format_amount(prev_amount),
        }

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()
        privkey = self.getContractPrivkey(bid_date, bid.contract_count)
        pubkey = ci.getPubkey(privkey)

        secret = bid.recovered_secret
        if secret is None:
            secret = self.getContractSecret(bid_date, bid.contract_count)
        ensure(len(secret) == 32, "Bad secret length")

        if self.coin_clients[coin_type]["connection_type"] != "rpc":
            return None

        if fee_rate is None:
            fee_rate, fee_src = self.getFeeRateForCoin(coin_type)

        tx_vsize = ci.getHTLCSpendTxVSize()
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug(
            f"Redeem tx fee {ci.format_amount(tx_fee, conv_int=True, r=1)}, rate {fee_rate}"
        )

        amount_out = prev_amount - ci.make_int(tx_fee, r=1)
        ensure(amount_out > 0, "Amount out <= 0")

        if addr_redeem_out is None:
            addr_redeem_out = self.getReceiveAddressFromPool(
                coin_type,
                bid.bid_id,
                (
                    TxTypes.PTX_REDEEM
                    if for_txn_type == "participate"
                    else TxTypes.ITX_REDEEM
                ),
                cursor,
            )
        assert addr_redeem_out is not None

        self.log.debug(f"addr_redeem_out {addr_redeem_out}")

        redeem_txn = ci.createRedeemTxn(
            prevout, addr_redeem_out, amount_out, txn_script
        )
        options = {}
        if ci.using_segwit():
            options["force_segwit"] = True

        if coin_type in (Coins.NAV, Coins.DCR):
            privkey_wif = self.ci(coin_type).encodeKey(privkey)
            redeem_sig = ci.getTxSignature(redeem_txn, prevout, privkey_wif)
        else:
            privkey_wif = self.ci(Coins.PART).encodeKey(privkey)
            redeem_sig = self.callcoinrpc(
                Coins.PART,
                "createsignaturewithkey",
                [redeem_txn, prevout, privkey_wif, "ALL", options],
            )

        if coin_type == Coins.PART or ci.using_segwit():
            witness_stack = [
                bytes.fromhex(redeem_sig),
                pubkey,
                secret,
                bytes((1,)),  # Converted to OP_1 in Decred push_script_data
                txn_script,
            ]
            redeem_txn = ci.setTxSignature(
                bytes.fromhex(redeem_txn), witness_stack
            ).hex()
        else:
            script = (len(redeem_sig) // 2).to_bytes(1, "big") + bytes.fromhex(
                redeem_sig
            )
            script += (33).to_bytes(1, "big") + pubkey
            script += (32).to_bytes(1, "big") + secret
            script += (OpCodes.OP_1).to_bytes(1, "big")
            script += (
                (OpCodes.OP_PUSHDATA1).to_bytes(1, "big")
                + (len(txn_script)).to_bytes(1, "big")
                + txn_script
            )
            redeem_txn = ci.setTxScriptSig(bytes.fromhex(redeem_txn), 0, script).hex()

        if coin_type in (Coins.NAV, Coins.DCR):
            # Only checks signature
            ro = ci.verifyRawTransaction(redeem_txn, [prevout])
        else:
            ro = self.callcoinrpc(
                Coins.PART, "verifyrawtransaction", [redeem_txn, [prevout]]
            )

        ensure(ro["inputs_valid"] is True, "inputs_valid is false")
        # outputs_valid will be false if not a Particl txn
        # ensure(ro['complete'] is True, 'complete is false')
        ensure(ro["validscripts"] == 1, "validscripts != 1")

        if self.debug:
            # Check fee
            if ci.get_connection_type() == "rpc":
                redeem_txjs = self.callcoinrpc(
                    coin_type, "decoderawtransaction", [redeem_txn]
                )
                if coin_type in (Coins.DCR,):
                    txsize = len(redeem_txn) // 2
                    self.log.debug(f"size paid, actual size {tx_vsize} {txsize}")
                    ensure(tx_vsize >= txsize, "underpaid fee")
                elif ci.use_tx_vsize():
                    self.log.debug(
                        "vsize paid, actual vsize %d %d", tx_vsize, redeem_txjs["vsize"]
                    )
                    ensure(tx_vsize >= redeem_txjs["vsize"], "underpaid fee")
                else:
                    self.log.debug(
                        "size paid, actual size %d %d", tx_vsize, redeem_txjs["size"]
                    )
                    ensure(tx_vsize >= redeem_txjs["size"], "underpaid fee")

            redeem_txid = ci.getTxid(bytes.fromhex(redeem_txn))
            self.log.debug(
                f"Have valid redeem tx {self.log.id(redeem_txid)} for contract {for_txn_type} tx {self.log.id(prev_txnid)}"
            )
        return redeem_txn

    def createRefundTxn(
        self,
        coin_type,
        txn,
        offer,
        bid,
        txn_script: bytearray,
        addr_refund_out=None,
        tx_type=TxTypes.ITX_REFUND,
        cursor=None,
    ):
        self.log.debug(f"createRefundTxn for coin {Coins(coin_type).name}")
        if self.coin_clients[coin_type]["connection_type"] != "rpc":
            return None

        ci = self.ci(coin_type)
        if coin_type in (Coins.NAV, Coins.DCR):
            prevout = ci.find_prevout_info(txn, txn_script)
        else:
            # TODO: Sign in bsx for all coins
            txjs = self.callcoinrpc(Coins.PART, "decoderawtransaction", [txn])
            if ci.using_segwit():
                p2wsh = ci.getScriptDest(txn_script)
                vout = getVoutByScriptPubKey(txjs, p2wsh.hex())
            else:
                addr_to = self.ci(Coins.PART).encode_p2sh(txn_script)
                vout = getVoutByAddress(txjs, addr_to)

            prevout = {
                "txid": txjs["txid"],
                "vout": vout,
                "scriptPubKey": txjs["vout"][vout]["scriptPubKey"]["hex"],
                "redeemScript": txn_script.hex(),
                "amount": txjs["vout"][vout]["value"],
            }

        bid_date = dt.datetime.fromtimestamp(bid.created_at).date()

        privkey = self.getContractPrivkey(bid_date, bid.contract_count)
        pubkey = ci.getPubkey(privkey)

        lock_value = DeserialiseNum(txn_script, 64)
        sequence: int = 1
        if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS:
            sequence = lock_value

        fee_rate, fee_src = self.getFeeRateForCoin(coin_type)

        tx_vsize = ci.getHTLCSpendTxVSize(False)
        tx_fee = (fee_rate * tx_vsize) / 1000

        self.log.debug(
            f"Refund tx fee {ci.format_amount(tx_fee, conv_int=True, r=1)}, rate {fee_rate}"
        )

        amount_out = ci.make_int(prevout["amount"], r=1) - ci.make_int(tx_fee, r=1)
        if amount_out <= 0:
            raise ValueError("Refund amount out <= 0")

        if addr_refund_out is None:
            addr_refund_out = self.getReceiveAddressFromPool(
                coin_type, bid.bid_id, tx_type, cursor
            )
        ensure(addr_refund_out is not None, "addr_refund_out is null")
        self.log.debug(f"addr_refund_out {addr_refund_out}")

        locktime: int = 0
        if (
            offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS
            or offer.lock_type == TxLockTypes.ABS_LOCK_TIME
        ):
            locktime = lock_value

        refund_txn = ci.createRefundTxn(
            prevout, addr_refund_out, amount_out, locktime, sequence, txn_script
        )

        options = {}
        if self.coin_clients[coin_type]["use_segwit"]:
            options["force_segwit"] = True
        if coin_type in (Coins.NAV, Coins.DCR):
            privkey_wif = ci.encodeKey(privkey)
            refund_sig = ci.getTxSignature(refund_txn, prevout, privkey_wif)
        else:
            privkey_wif = self.ci(Coins.PART).encodeKey(privkey)
            refund_sig = self.callcoinrpc(
                Coins.PART,
                "createsignaturewithkey",
                [refund_txn, prevout, privkey_wif, "ALL", options],
            )
        if (
            coin_type in (Coins.PART, Coins.DCR)
            or self.coin_clients[coin_type]["use_segwit"]
        ):
            witness_stack = [bytes.fromhex(refund_sig), pubkey, b"", txn_script]
            refund_txn = ci.setTxSignature(
                bytes.fromhex(refund_txn), witness_stack
            ).hex()
        else:
            script = (len(refund_sig) // 2).to_bytes(1, "big") + bytes.fromhex(
                refund_sig
            )
            script += (33).to_bytes(1, "big") + pubkey
            script += (OpCodes.OP_0).to_bytes(1, "big")
            script += (
                (OpCodes.OP_PUSHDATA1).to_bytes(1, "big")
                + (len(txn_script)).to_bytes(1, "big")
                + txn_script
            )
            refund_txn = ci.setTxScriptSig(bytes.fromhex(refund_txn), 0, script).hex()

        if coin_type in (Coins.NAV, Coins.DCR):
            # Only checks signature
            ro = ci.verifyRawTransaction(refund_txn, [prevout])
        else:
            ro = self.callcoinrpc(
                Coins.PART, "verifyrawtransaction", [refund_txn, [prevout]]
            )

        ensure(ro["inputs_valid"] is True, "inputs_valid is false")
        # outputs_valid will be false if not a Particl txn
        # ensure(ro['complete'] is True, 'complete is false')
        ensure(ro["validscripts"] == 1, "validscripts != 1")

        if self.debug:
            # Check fee
            if ci.get_connection_type() == "rpc":
                refund_txjs = self.callcoinrpc(
                    coin_type,
                    "decoderawtransaction",
                    [
                        refund_txn,
                    ],
                )
                if coin_type in (Coins.DCR,):
                    txsize = len(refund_txn) // 2
                    self.log.debug(f"size paid, actual size {tx_vsize} {txsize}")
                    ensure(tx_vsize >= txsize, "underpaid fee")
                elif ci.use_tx_vsize():
                    self.log.debug(
                        "vsize paid, actual vsize %d %d", tx_vsize, refund_txjs["vsize"]
                    )
                    ensure(tx_vsize >= refund_txjs["vsize"], "underpaid fee")
                else:
                    self.log.debug(
                        "size paid, actual size %d %d", tx_vsize, refund_txjs["size"]
                    )
                    ensure(tx_vsize >= refund_txjs["size"], "underpaid fee")

            refund_txid = ci.getTxid(bytes.fromhex(refund_txn))
            prev_txid = ci.getTxid(bytes.fromhex(txn))
            self.log.debug(
                f"Have valid refund tx {self.log.id(refund_txid)} for contract tx {self.log.id(prev_txid)}",
            )

        return refund_txn

    def initiateTxnConfirmed(self, bid_id: bytes, bid, offer) -> None:
        self.log.debug(f"initiateTxnConfirmed for bid {self.log.id(bid_id)}")
        bid.setState(BidStates.SWAP_INITIATED)
        bid.setITxState(TxStates.TX_CONFIRMED)

        if bid.debug_ind == DebugTypes.BUYER_STOP_AFTER_ITX:
            self.log.debug(
                f"{self.logIDB(bid_id)}: Abandoning for testing: {bid.debug_ind}, {DebugTypes(bid.debug_ind).name}."
            )
            bid.setState(BidStates.BID_ABANDONED)
            self.logBidEvent(
                bid.bid_id,
                EventLogTypes.DEBUG_TWEAK_APPLIED,
                f"ind {bid.debug_ind}",
                None,
            )
            return  # Bid saved in checkBidState

        # Seller first mode, buyer participates
        participate_script = self.deriveParticipateScript(bid_id, bid, offer)
        if bid.was_sent:
            if bid.participate_tx is not None:
                self.log.warning(
                    f"Participate tx {self.log.id(bid.participate_tx.txid)} already exists for bid {self.log.id(bid_id)}"
                )
            else:
                self.log.debug(
                    f"Preparing participate txn for bid {self.log.id(bid_id)}"
                )

                ci_to = self.ci(offer.coin_to)
                txn = self.createParticipateTxn(bid_id, bid, offer, participate_script)
                txid = ci_to.publishTx(bytes.fromhex(txn))
                self.log.debug(
                    f"Submitted participate tx {self.log.id(txid)} to {ci_to.coin_name()} chain for bid {self.log.id(bid_id)}"
                )
                bid.setPTxState(TxStates.TX_SENT)
                self.logEvent(
                    Concepts.BID, bid.bid_id, EventLogTypes.PTX_PUBLISHED, "", None
                )
        else:
            bid.participate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.PTX,
                script=participate_script,
            )
            ci = self.ci(offer.coin_to)
            if ci.watch_blocks_for_scripts() is True:
                chain_a_block_header = self.ci(
                    offer.coin_from
                ).getBlockHeaderFromHeight(bid.initiate_tx.chain_height)
                chain_b_block_header = self.ci(offer.coin_to).getBlockHeaderAt(
                    chain_a_block_header["time"]
                )
                self.setLastHeightCheckedStart(
                    offer.coin_to, chain_b_block_header["height"]
                )
                self.addWatchedScript(
                    offer.coin_to,
                    bid_id,
                    ci.getScriptDest(participate_script),
                    TxTypes.PTX,
                )

        # Bid saved in checkBidState

    def setLastHeightCheckedStart(self, coin_type, tx_height: int, cursor=None) -> int:
        ci = self.ci(coin_type)
        coin_name = ci.coin_name()
        if tx_height < 1:
            tx_height = self.lookupChainHeight(coin_type)

        block_header = ci.getBlockHeaderFromHeight(tx_height)
        block_time = block_header["time"]
        cc = self.coin_clients[coin_type]
        if len(cc["watched_outputs"]) == 0 and len(cc["watched_scripts"]) == 0:
            cc["last_height_checked"] = tx_height
            cc["block_check_min_time"] = block_time
            self.setIntKV("block_check_min_time_" + coin_name, block_time, cursor)
            self.log.debug(f"Start checking {coin_name} chain at height {tx_height}")
        elif cc["last_height_checked"] > tx_height:
            cc["last_height_checked"] = tx_height
            cc["block_check_min_time"] = block_time
            self.setIntKV("block_check_min_time_" + coin_name, block_time, cursor)
            self.log.debug(
                f"Rewind {coin_name} chain last height checked to {tx_height}"
            )
        else:
            self.log.debug(
                "Not setting %s chain last height checked to %d, leaving on %d",
                coin_name,
                tx_height,
                cc["last_height_checked"],
            )

        return tx_height

    def addParticipateTxn(
        self, bid_id: bytes, bid, coin_type, txid_hex: str, vout, tx_height
    ) -> None:

        # TODO: Check connection type
        participate_txn_height = self.setLastHeightCheckedStart(coin_type, tx_height)

        if bid.participate_tx is None:
            bid.participate_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.PTX,
            )
        bid.participate_tx.txid = bytes.fromhex(txid_hex)
        bid.participate_tx.vout = vout
        bid.participate_tx.chain_height = participate_txn_height

        # Start checking for spends of participate_txn before fully confirmed
        ci = self.ci(coin_type)
        self.log.debug(
            f"Watching {ci.coin_name()} chain for spend of output {self.logIDT(bid.participate_tx.txid)} {vout}"
        )
        self.addWatchedOutput(
            coin_type, bid_id, txid_hex, vout, BidStates.SWAP_PARTICIPATING
        )

    def participateTxnConfirmed(self, bid_id: bytes, bid, offer) -> None:
        self.log.debug(f"participateTxnConfirmed for bid {self.log.id(bid_id)}")

        if bid.debug_ind == DebugTypes.DONT_CONFIRM_PTX:
            self.log.debug(f"Not confirming PTX for debugging {self.log.id(bid_id)}")
            return

        bid.setState(BidStates.SWAP_PARTICIPATING)
        bid.setPTxState(TxStates.TX_CONFIRMED)

        # Seller redeems from participate txn
        if bid.was_received:
            ci_to = self.ci(offer.coin_to)
            txn = self.createRedeemTxn(ci_to.coin_type(), bid)
            txid = ci_to.publishTx(bytes.fromhex(txn))
            self.log.debug(
                f"Submitted participate redeem tx {self.log.id(txid)} to {ci_to.coin_name()} chain for bid {self.log.id(bid_id)}."
            )
            self.logEvent(
                Concepts.BID, bid.bid_id, EventLogTypes.PTX_REDEEM_PUBLISHED, "", None
            )
            # TX_REDEEMED will be set when spend is detected
            # TODO: Wait for depth?

        # bid saved in checkBidState

    def getTotalBalance(self, coin_type) -> int:
        try:
            ci = self.ci(coin_type)
            if hasattr(ci, "rpc_wallet"):
                if coin_type in (Coins.XMR, Coins.WOW):
                    balance_info = ci.rpc_wallet("get_balance")
                    return balance_info["balance"]
                elif coin_type == Coins.PART:
                    balances = ci.rpc_wallet("getbalances")
                    return ci.make_int(
                        balances["mine"]["trusted"]
                        + balances["mine"]["untrusted_pending"]
                    )
                else:
                    try:
                        balances = ci.rpc_wallet("getbalances")
                        return ci.make_int(
                            balances["mine"]["trusted"]
                            + balances["mine"]["untrusted_pending"]
                        )
                    except Exception:
                        wallet_info = ci.rpc_wallet("getwalletinfo")
                        total = wallet_info.get("balance", 0)
                        if "unconfirmed_balance" in wallet_info:
                            total += wallet_info["unconfirmed_balance"]
                        if "immature_balance" in wallet_info:
                            total += wallet_info["immature_balance"]
                        return ci.make_int(total)
            else:
                return ci.getSpendableBalance()
        except Exception:
            return ci.getSpendableBalance()

    def getAddressBalance(self, coin_type, address: str) -> int:
        if self.coin_clients[coin_type]["chain_lookups"] == "explorer":
            explorers = self.coin_clients[coin_type]["explorers"]

            # TODO: random offset into explorers, try blocks
            for exp in explorers:
                return exp.getBalance(address)
        return self.lookupUnspentByAddress(coin_type, address, sum_output=True)

    def lookupChainHeight(self, coin_type) -> int:
        return self.callcoinrpc(coin_type, "getblockcount")

    def lookupUnspentByAddress(
        self,
        coin_type,
        address: str,
        sum_output: bool = False,
        assert_amount=None,
        assert_txid=None,
    ) -> int:

        ci = self.ci(coin_type)
        if self.coin_clients[coin_type]["chain_lookups"] == "explorer":
            explorers = self.coin_clients[coin_type]["explorers"]

            # TODO: random offset into explorers, try blocks
            for exp in explorers:
                # TODO: ExplorerBitAps use only gettransaction if assert_txid is set
                rv = exp.lookupUnspentByAddress(address)

                if assert_amount is not None:
                    ensure(
                        rv["value"] == int(assert_amount),
                        "Incorrect output amount in txn {}: {} != {}.".format(
                            assert_txid, rv["value"], int(assert_amount)
                        ),
                    )
                if assert_txid is not None:
                    ensure(rv["txid)"] == assert_txid, "Incorrect txid")

                return rv

            raise ValueError(
                "No explorer for lookupUnspentByAddress {}".format(
                    Coins(coin_type).name
                )
            )

        if self.coin_clients[coin_type]["connection_type"] != "rpc":
            raise ValueError(
                "No RPC connection for lookupUnspentByAddress {}".format(
                    Coins(coin_type).name
                )
            )

        if assert_txid is not None:
            try:
                ro = self.callcoinrpc(coin_type, "getmempoolentry", [assert_txid])
                fee = ro["fee"]
                self.log.debug(
                    f"Tx {self.log.id(assert_txid)} found in mempool, fee {fee}"
                )
                # TODO: Save info
                return None
            except Exception:
                pass

        num_blocks = self.callcoinrpc(coin_type, "getblockcount")

        sum_unspent = 0
        self.log.debug("[rm] scantxoutset start")  # scantxoutset is slow
        ro = self.callcoinrpc(
            coin_type, "scantxoutset", ["start", ["addr({})".format(address)]]
        )  # TODO: Use combo(address) where possible
        self.log.debug("[rm] scantxoutset end")
        for o in ro["unspents"]:
            if assert_txid and o["txid"] != assert_txid:
                continue
            # Verify amount
            if assert_amount:
                ensure(
                    make_int(o["amount"]) == int(assert_amount),
                    "Incorrect output amount in txn {}: {} != {}.".format(
                        assert_txid, make_int(o["amount"]), int(assert_amount)
                    ),
                )

            if not sum_output:
                if o["height"] > 0:
                    n_conf = num_blocks - o["height"]
                else:
                    n_conf = -1
                return {
                    "txid": o["txid"],
                    "index": o["vout"],
                    "height": o["height"],
                    "n_conf": n_conf,
                    "value": ci.make_int(o["amount"]),
                }
            else:
                sum_unspent += ci.make_int(o["amount"])
        if sum_output:
            return sum_unspent
        return None

    def findTxB(self, ci_to, xmr_swap, bid, cursor, bid_sender: bool) -> bool:
        bid_changed = False

        found_tx = None
        if ci_to.watch_blocks_for_scripts():
            if bid.xmr_b_lock_tx is None or bid.xmr_b_lock_tx.txid is None:
                # Watching chain for dest_address with WatchedScript
                pass
            else:
                dest_address = ci_to.pkh_to_address(ci_to.pkh(xmr_swap.pkbs))
                found_tx = ci_to.getLockTxHeight(
                    bid.xmr_b_lock_tx.txid,
                    dest_address,
                    bid.amount_to,
                    bid.chain_b_height_start,
                    vout=bid.xmr_b_lock_tx.vout,
                )
        else:
            # Have to use findTxB instead of relying on the first seen height to detect chain reorgs
            found_tx = ci_to.findTxB(
                xmr_swap.vkbv,
                xmr_swap.pkbs,
                bid.amount_to,
                ci_to.blocks_confirmed,
                bid.chain_b_height_start,
                bid_sender,
                check_amount=(
                    False if bid.debug_ind == DebugTypes.B_LOCK_TX_MISSED_SEND else True
                ),
            )

        if isinstance(found_tx, int) and found_tx == -1:
            if self.countBidEvents(bid, EventLogTypes.LOCK_TX_B_INVALID, cursor) < 1:
                self.logBidEvent(
                    bid.bid_id,
                    EventLogTypes.LOCK_TX_B_INVALID,
                    "Detected invalid lock tx B",
                    cursor,
                )
                bid_changed = True
        elif found_tx is not None:
            if found_tx["height"] != 0 and (
                bid.xmr_b_lock_tx is None or not bid.xmr_b_lock_tx.chain_height
            ):
                self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_SEEN, "", cursor)

            found_txid = bytes.fromhex(found_tx["txid"])
            if (
                bid.xmr_b_lock_tx is None
                or bid.xmr_b_lock_tx.chain_height is None
                or xmr_swap.b_lock_tx_id != found_txid
            ):
                self.log.debug(f"Found lock tx B in {ci_to.coin_name()} chain")
                xmr_swap.b_lock_tx_id = found_txid
            if bid.xmr_b_lock_tx is None:
                bid.xmr_b_lock_tx = SwapTx(
                    bid_id=bid.bid_id,
                    tx_type=TxTypes.XMR_SWAP_B_LOCK,
                    txid=xmr_swap.b_lock_tx_id,
                )
            if bid.xmr_b_lock_tx.txid != found_txid:
                self.log.debug(
                    f"Updating {ci_to.coin_name()} lock txid: {self.log.id(found_txid)}"
                )
                bid.xmr_b_lock_tx.txid = found_txid

            bid.xmr_b_lock_tx.chain_height = found_tx["height"]
            bid_changed = True
        return bid_changed

    def checkXmrBidState(self, bid_id: bytes, bid, offer):
        rv = False

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)

        was_sent: bool = bid.was_received if reverse_bid else bid.was_sent
        was_received: bool = bid.was_sent if reverse_bid else bid.was_received

        cursor = None
        try:
            cursor = self.openDB()

            xmr_offer = self.queryOne(XmrOffer, cursor, {"offer_id": offer.offer_id})
            ensure(
                xmr_offer,
                f"Adaptor-sig offer not found: {self.log.id(offer.offer_id)}.",
            )
            xmr_swap = self.queryOne(XmrSwap, cursor, {"bid_id": bid.bid_id})
            ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid.bid_id)}.")

            if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                refund_tx = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND]
                if was_received:
                    if bid.debug_ind == DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND:
                        self.log.debug(
                            f"Adaptor-sig bid {self.log.id(bid_id)}: Stalling bid for testing: {bid.debug_ind}."
                        )
                        bid.setState(BidStates.BID_STALLED_FOR_TEST)
                        rv = True
                        self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                        self.logBidEvent(
                            bid.bid_id,
                            EventLogTypes.DEBUG_TWEAK_APPLIED,
                            "ind {}".format(bid.debug_ind),
                            cursor,
                        )
                        self.commitDB()
                        return rv

                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND not in bid.txns:
                        try:
                            if self.haveDebugInd(
                                bid.bid_id,
                                DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND2,
                            ):
                                raise TemporaryError(
                                    "Debug: BID_DONT_SPEND_COIN_A_LOCK_REFUND2"
                                )
                            if bid.xmr_b_lock_tx is None and self.haveDebugInd(
                                bid.bid_id,
                                DebugTypes.WAIT_FOR_COIN_B_LOCK_BEFORE_REFUND,
                            ):
                                raise TemporaryError(
                                    "Debug: Waiting for Coin B Lock Tx"
                                )
                            txid_str = ci_from.publishTx(
                                xmr_swap.a_lock_refund_spend_tx
                            )
                            self.logBidEvent(
                                bid.bid_id,
                                EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_PUBLISHED,
                                "",
                                cursor,
                            )

                            self.log.info(
                                f"Submitted coin a lock refund spend tx for bid {self.log.id(bid_id)}, txid {self.log.id(txid_str)}"
                            )
                            bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND] = SwapTx(
                                bid_id=bid_id,
                                tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND,
                                txid=bytes.fromhex(txid_str),
                            )
                            self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                            self.commitDB()
                        except Exception as ex:
                            self.log.debug(
                                f"Trying to publish coin a lock refund spend tx: {ex}"
                            )

                if was_sent:
                    if xmr_swap.a_lock_refund_swipe_tx is None:
                        self.createCoinALockRefundSwipeTx(
                            ci_from, bid, offer, xmr_swap, xmr_offer
                        )
                        self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                        self.commitDB()

                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE not in bid.txns:
                        try:
                            if self.haveDebugInd(
                                bid.bid_id,
                                DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND2,
                            ):
                                raise TemporaryError(
                                    "Debug: BID_DONT_SPEND_COIN_A_LOCK_REFUND2"
                                )
                            txid = ci_from.publishTx(xmr_swap.a_lock_refund_swipe_tx)
                            self.logBidEvent(
                                bid.bid_id,
                                EventLogTypes.LOCK_TX_A_REFUND_SWIPE_TX_PUBLISHED,
                                "",
                                cursor,
                            )
                            self.log.info(
                                f"Submitted coin a lock refund swipe tx for bid {self.log.id(bid_id)}"
                            )
                            bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE] = SwapTx(
                                bid_id=bid_id,
                                tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE,
                                txid=bytes.fromhex(txid),
                            )
                            if self.isBchXmrSwap(offer):
                                if ci_from.altruistic():
                                    for_ed25519: bool = (
                                        True
                                        if ci_to.curve_type() == Curves.ed25519
                                        else False
                                    )
                                    kbsf = self.getPathKey(
                                        ci_from.coin_type(),
                                        ci_to.coin_type(),
                                        bid.created_at,
                                        xmr_swap.contract_count,
                                        KeyTypes.KBSF,
                                        for_ed25519,
                                    )

                                    mercy_tx = ci_from.createMercyTx(
                                        xmr_swap.a_lock_refund_swipe_tx,
                                        h2b(txid),
                                        xmr_swap.a_lock_refund_tx_script,
                                        kbsf,
                                    )
                                    txid_hex: str = ci_from.publishTx(mercy_tx)
                                    bid.txns[TxTypes.BCH_MERCY] = SwapTx(
                                        bid_id=bid_id,
                                        tx_type=TxTypes.BCH_MERCY,
                                        txid=bytes.fromhex(txid_hex),
                                    )
                                    self.log.info(
                                        f"Submitted mercy tx for bid {self.log.id(bid_id)}, txid {self.log.id(txid_hex)}"
                                    )
                                    self.logBidEvent(
                                        bid_id,
                                        EventLogTypes.BCH_MERCY_TX_PUBLISHED,
                                        "",
                                        cursor,
                                    )
                                else:
                                    self.log.info(
                                        f"Not sending mercy tx for bid {self.log.id(bid_id)}"
                                    )

                            self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                            self.commitDB()
                        except Exception as ex:
                            self.log.debug(
                                f"Trying to publish coin a lock refund swipe tx: {ex}"
                            )

                if BidStates(bid.state) == BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED:
                    txid_hex = bid.xmr_b_lock_tx.spend_txid.hex()

                    found_tx = ci_to.findTxnByHash(txid_hex)
                    if found_tx is not None:
                        self.log.info(
                            f"Found coin b lock recover tx bid {self.log.id(bid_id)}"
                        )
                        rv = True  # Remove from swaps_in_progress
                        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)
                        self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                        self.commitDB()
                    return rv
            else:  # not XMR_SWAP_A_LOCK_REFUND in bid.txns
                if (
                    len(xmr_swap.al_lock_refund_tx_sig) > 0
                    and len(xmr_swap.af_lock_refund_tx_sig) > 0
                ):
                    try:
                        txid = ci_from.publishTx(xmr_swap.a_lock_refund_tx)

                        # BCH txids change
                        if self.isBchXmrSwap(offer):
                            self.log.debug(
                                "Recomputing refund spend transaction and txid after submitting lock tx spend."
                            )

                            tx = ci_from.loadTx(xmr_swap.a_lock_refund_spend_tx)
                            tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_refund_tx_id)
                            xmr_swap.a_lock_refund_spend_tx = (
                                tx.serialize_without_witness()
                            )
                            xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxid(
                                xmr_swap.a_lock_refund_spend_tx
                            )

                        self.log.info(
                            f"Submitted coin a lock refund tx for bid {self.log.id(bid_id)}"
                        )
                        self.logBidEvent(
                            bid.bid_id,
                            EventLogTypes.LOCK_TX_A_REFUND_TX_PUBLISHED,
                            "",
                            cursor,
                        )
                        bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND] = SwapTx(
                            bid_id=bid_id,
                            tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND,
                            txid=bytes.fromhex(txid),
                        )
                        self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                        self.commitDB()
                        return rv
                    except Exception as ex:
                        if ci_from.isTxExistsError(str(ex)):
                            self.log.info(
                                f"Found coin a lock refund tx for bid {self.log.id(bid_id)}"
                            )
                            txid = ci_from.getTxid(xmr_swap.a_lock_refund_tx)
                            if TxTypes.XMR_SWAP_A_LOCK_REFUND not in bid.txns:
                                bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND] = SwapTx(
                                    bid_id=bid_id,
                                    tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND,
                                    txid=txid,
                                )
                            self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                            self.commitDB()
                            return rv

            state = BidStates(bid.state)
            if state == BidStates.SWAP_COMPLETED:
                rv = True  # Remove from swaps_in_progress
            elif state == BidStates.XMR_SWAP_FAILED_REFUNDED:
                rv = True  # Remove from swaps_in_progress
            elif state == BidStates.XMR_SWAP_FAILED_SWIPED:
                rv = True  # Remove from swaps_in_progress
            elif state == BidStates.XMR_SWAP_FAILED:
                if was_sent and bid.xmr_b_lock_tx:
                    if (
                        self.countQueuedActions(
                            cursor, bid_id, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B
                        )
                        < 1
                    ):
                        delay = self.get_delay_event_seconds()
                        self.log.info(
                            f"Recovering adaptor-sig swap chain B lock tx for bid {self.log.id(bid_id)} in {delay} seconds"
                        )
                        self.createActionInSession(
                            delay,
                            ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B,
                            bid_id,
                            cursor,
                        )
                        self.commitDB()
            elif state == BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX:
                if bid.xmr_a_lock_tx is None or bid.xmr_a_lock_tx.txid is None:
                    return rv

                # TODO: Timeout waiting for transactions
                bid_changed: bool = False
                a_lock_tx_addr = ci_from.getSCLockScriptAddress(
                    xmr_swap.a_lock_tx_script
                )
                lock_tx_chain_info = ci_from.getLockTxHeight(
                    bid.xmr_a_lock_tx.txid,
                    a_lock_tx_addr,
                    bid.amount,
                    bid.chain_a_height_start,
                    vout=bid.xmr_a_lock_tx.vout,
                )

                if lock_tx_chain_info is None:
                    return rv

                if "txid" in lock_tx_chain_info and (
                    xmr_swap.a_lock_tx_id is None
                    or lock_tx_chain_info["txid"] != b2h(xmr_swap.a_lock_tx_id)
                ):
                    # BCH: If we find that txid was changed (by funding or otherwise), we need to update it to track correctly
                    xmr_swap.a_lock_tx_id = h2b(lock_tx_chain_info["txid"])

                    tx = ci_from.loadTx(xmr_swap.a_lock_refund_tx)
                    tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_tx_id)
                    xmr_swap.a_lock_refund_tx = tx.serialize_without_witness()
                    xmr_swap.a_lock_refund_tx_id = ci_from.getTxid(
                        xmr_swap.a_lock_refund_tx
                    )

                    tx = ci_from.loadTx(xmr_swap.a_lock_spend_tx)
                    tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_tx_id)
                    xmr_swap.a_lock_spend_tx = tx.serialize_without_witness()
                    xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(
                        xmr_swap.a_lock_spend_tx
                    )

                    if bid.xmr_a_lock_tx:
                        bid.xmr_a_lock_tx.txid = xmr_swap.a_lock_tx_id
                        bid.xmr_a_lock_tx.tx_data = xmr_swap.a_lock_tx
                        bid.xmr_a_lock_tx.spend_txid = xmr_swap.a_lock_spend_tx_id

                    # Update watcher
                    self.removeWatchedOutput(ci_from.coin_type(), bid.bid_id, None)
                    self.removeWatchedOutput(ci_to.coin_type(), bid.bid_id, None)
                    self.watchXmrSwap(bid, offer, xmr_swap, cursor)
                    bid_changed = True

                if (
                    bid.xmr_a_lock_tx.state == TxStates.TX_NONE
                    and lock_tx_chain_info["height"] == 0
                ):
                    bid.xmr_a_lock_tx.setState(TxStates.TX_IN_MEMPOOL)
                    self.logBidEvent(
                        bid.bid_id, EventLogTypes.LOCK_TX_A_IN_MEMPOOL, "", cursor
                    )

                if "conflicts" in lock_tx_chain_info:
                    if (
                        self.countBidEvents(
                            bid, EventLogTypes.LOCK_TX_A_CONFLICTS, cursor
                        )
                        < 1
                    ):
                        self.logBidEvent(
                            bid.bid_id, EventLogTypes.LOCK_TX_A_CONFLICTS, "", cursor
                        )

                if (
                    not bid.xmr_a_lock_tx.chain_height
                    and lock_tx_chain_info["height"] != 0
                ):
                    self.logBidEvent(
                        bid.bid_id, EventLogTypes.LOCK_TX_A_SEEN, "", cursor
                    )
                    self.setTxBlockInfoFromHeight(
                        ci_from, bid.xmr_a_lock_tx, lock_tx_chain_info["height"]
                    )
                    bid.xmr_a_lock_tx.setState(TxStates.TX_IN_CHAIN)

                    bid_changed = True
                if (
                    bid.xmr_a_lock_tx.chain_height != lock_tx_chain_info["height"]
                    and lock_tx_chain_info["height"] != 0
                ):
                    bid.xmr_a_lock_tx.chain_height = lock_tx_chain_info["height"]
                    bid_changed = True

                if lock_tx_chain_info["depth"] >= ci_from.blocks_confirmed:
                    self.logBidEvent(
                        bid.bid_id, EventLogTypes.LOCK_TX_A_CONFIRMED, "", cursor
                    )
                    bid.xmr_a_lock_tx.setState(TxStates.TX_CONFIRMED)

                    bid.setState(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
                    bid_changed = True

                    if was_sent:
                        delay = self.get_delay_event_seconds()
                        self.log.info(
                            f"Sending adaptor-sig swap chain B lock tx for bid {self.log.id(bid_id)} in {delay} seconds",
                        )
                        self.createActionInSession(
                            delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, bid_id, cursor
                        )
                        # bid.setState(BidStates.SWAP_DELAYING)
                    elif ci_to.watch_blocks_for_scripts():
                        chain_a_block_header = ci_from.getBlockHeaderFromHeight(
                            bid.xmr_a_lock_tx.chain_height
                        )
                        block_time = chain_a_block_header["time"]
                        chain_b_block_header = ci_to.getBlockHeaderAt(block_time)
                        self.log.debug(
                            "chain a block_time {}, chain b block height {}".format(
                                block_time, chain_b_block_header["height"]
                            )
                        )
                        dest_script = ci_to.getPkDest(xmr_swap.pkbs)
                        self.setLastHeightCheckedStart(
                            ci_to.coin_type(), chain_b_block_header["height"], cursor
                        )
                        self.addWatchedScript(
                            ci_to.coin_type(),
                            bid.bid_id,
                            dest_script,
                            TxTypes.XMR_SWAP_B_LOCK,
                        )

                if bid_changed:
                    self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                    self.commitDB()

            elif state in (
                BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED,
                BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND,
            ):
                bid_changed = self.findTxB(ci_to, xmr_swap, bid, cursor, was_sent)

                if (
                    bid.xmr_b_lock_tx
                    and bid.xmr_b_lock_tx.chain_height is not None
                    and bid.xmr_b_lock_tx.chain_height > 0
                ):
                    chain_height = ci_to.getChainHeight()

                    if bid.debug_ind == DebugTypes.BID_STOP_AFTER_COIN_B_LOCK:
                        self.log.debug(
                            f"Adaptor-sig bid {self.log.id(bid_id)}: Stalling bid for testing: {bid.debug_ind}."
                        )
                        bid.setState(BidStates.BID_STALLED_FOR_TEST)
                        self.logBidEvent(
                            bid.bid_id,
                            EventLogTypes.DEBUG_TWEAK_APPLIED,
                            f"ind {bid.debug_ind}",
                            cursor,
                        )
                    elif (
                        bid.xmr_b_lock_tx.state != TxStates.TX_CONFIRMED
                        and chain_height - bid.xmr_b_lock_tx.chain_height
                        >= ci_to.blocks_confirmed
                    ):
                        self.logBidEvent(
                            bid.bid_id, EventLogTypes.LOCK_TX_B_CONFIRMED, "", cursor
                        )
                        bid.xmr_b_lock_tx.setState(TxStates.TX_CONFIRMED)
                        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)

                        if was_received:
                            if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                                self.log.warning(
                                    f"Not releasing ads script coin lock tx for bid {self.log.id(bid_id)}: Chain A lock refund tx already exists."
                                )
                            else:
                                delay = self.get_delay_event_seconds()
                                self.log.info(
                                    f"Releasing ads script coin lock tx for bid {self.log.id(bid_id)} in {delay} seconds."
                                )
                                self.createActionInSession(
                                    delay,
                                    ActionTypes.SEND_XMR_LOCK_RELEASE,
                                    bid_id,
                                    cursor,
                                )

                if bid_changed:
                    self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                    self.commitDB()
            elif state == BidStates.XMR_SWAP_LOCK_RELEASED:
                # Wait for script spend tx to confirm
                # TODO: Use explorer to get tx / block hash for getrawtransaction

                if was_received:
                    try:
                        txn_hex = ci_from.getMempoolTx(xmr_swap.a_lock_spend_tx_id)
                        self.log.info(
                            f"Found lock spend txn in {ci_from.coin_name()} mempool, {self.logIDT(xmr_swap.a_lock_spend_tx_id)}"
                        )
                        self.process_XMR_SWAP_A_LOCK_tx_spend(
                            bid_id, xmr_swap.a_lock_spend_tx_id.hex(), txn_hex, cursor
                        )
                    except Exception as e:
                        self.log.debug(f"getrawtransaction lock spend tx failed: {e}")
            elif state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
                if (
                    was_received
                    and self.countQueuedActions(
                        cursor, bid_id, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B
                    )
                    < 1
                ):
                    if self.haveDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_B_LOCK):
                        self.log.debug(
                            f"Adaptor-sig bid {self.log.id(bid_id)}: Stalling bid for testing: {bid.debug_ind}."
                        )
                        # If BID_STALLED_FOR_TEST is set process_XMR_SWAP_A_LOCK_tx_spend would fail
                        self.logBidEvent(
                            bid.bid_id,
                            EventLogTypes.DEBUG_TWEAK_APPLIED,
                            f"ind {bid.debug_ind}",
                            cursor,
                        )
                    else:
                        bid.setState(BidStates.SWAP_DELAYING)
                        delay = self.get_delay_event_seconds()
                        self.log.info(
                            f"Redeeming coin b lock tx for bid {self.log.id(bid_id)} in {delay} seconds."
                        )
                        self.createActionInSession(
                            delay,
                            ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B,
                            bid_id,
                            cursor,
                        )
                    self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                    self.commitDB()
            elif state == BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED:
                txid_hex = bid.xmr_b_lock_tx.spend_txid.hex()

                found_tx = ci_to.findTxnByHash(txid_hex)
                if found_tx is not None:
                    self.log.info(
                        f"Found coin b lock spend tx bid {self.log.id(bid_id)}"
                    )
                    rv = True  # Remove from swaps_in_progress
                    bid.setState(BidStates.SWAP_COMPLETED)
                    self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                    self.commitDB()
                    self.notify(NT.SWAP_COMPLETED, {"bid_id": bid_id.hex()})
            elif state == BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND:
                if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                    refund_tx = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND]
                    if refund_tx.block_time is None:
                        refund_tx_addr = ci_from.getSCLockScriptAddress(
                            xmr_swap.a_lock_refund_tx_script
                        )
                        lock_refund_tx_chain_info = ci_from.getLockTxHeight(
                            refund_tx.txid,
                            refund_tx_addr,
                            0,
                            bid.chain_a_height_start,
                            vout=refund_tx.vout,
                        )

                        if (
                            lock_refund_tx_chain_info is not None
                            and lock_refund_tx_chain_info.get("height", 0) > 0
                        ):
                            self.setTxBlockInfoFromHeight(
                                ci_from, refund_tx, lock_refund_tx_chain_info["height"]
                            )

                            self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
                            self.commitDB()

        except Exception as ex:
            raise ex
        finally:
            self.closeDB(cursor)

        return rv

    def checkBidState(self, bid_id: bytes, bid, offer):
        # assert (self.mxDB.locked())
        # Return True to remove bid from in-progress list

        state = BidStates(bid.state)
        self.log.debug(f"checkBidState {self.log.id(bid_id)} {state}")

        if offer.swap_type == SwapTypes.XMR_SWAP:
            return self.checkXmrBidState(bid_id, bid, offer)

        save_bid = False
        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        # TODO: Batch calls to scantxoutset
        # TODO: timeouts
        if state == BidStates.BID_ABANDONED:
            self.log.info(f"Deactivating abandoned bid: {self.log.id(bid_id)}")
            return True  # Mark bid for archiving
        if state == BidStates.BID_ACCEPTED:
            # Waiting for initiate txn to be confirmed in 'from' chain
            index = None
            tx_height = None
            initiate_txnid_hex = bid.initiate_tx.txid.hex()
            last_initiate_txn_conf = bid.initiate_tx.conf
            ci_from = self.ci(coin_from)
            if coin_from == Coins.PART:  # Has txindex
                try:
                    p2sh = ci_from.encode_p2sh(bid.initiate_tx.script)
                    initiate_txn = self.callcoinrpc(
                        coin_from, "getrawtransaction", [initiate_txnid_hex, True]
                    )
                    # Verify amount
                    vout = getVoutByAddress(initiate_txn, p2sh)

                    out_value = make_int(initiate_txn["vout"][vout]["value"])
                    ensure(
                        out_value == int(bid.amount),
                        "Incorrect output amount in initiate txn {}: {} != {}.".format(
                            initiate_txnid_hex, out_value, int(bid.amount)
                        ),
                    )

                    bid.initiate_tx.conf = initiate_txn["confirmations"]
                    try:
                        tx_height = initiate_txn["height"]
                    except Exception:
                        tx_height = -1
                    index = vout
                except Exception:
                    pass
            else:
                if ci_from.using_segwit():
                    dest_script = ci_from.getScriptDest(bid.initiate_tx.script)
                    addr = ci_from.encodeScriptDest(dest_script)
                else:
                    addr = ci_from.encode_p2sh(bid.initiate_tx.script)

                found = ci_from.getLockTxHeight(
                    bid.initiate_tx.txid,
                    addr,
                    bid.amount,
                    bid.chain_a_height_start,
                    find_index=True,
                    vout=bid.initiate_tx.vout,
                )
                index = None
                if found:
                    bid.initiate_tx.conf = found["depth"]
                    if "index" in found:
                        index = found["index"]
                    tx_height = found["height"]

            if bid.initiate_tx.conf != last_initiate_txn_conf:
                save_bid = True

            if bid.initiate_tx.vout is None and index is not None:
                bid.initiate_tx.vout = index
                save_bid = True

            if bid.initiate_tx.conf is not None:
                self.log.debug(
                    f"initiate_txnid {self.log.id(initiate_txnid_hex)} confirms {bid.initiate_tx.conf}"
                )

                if (
                    last_initiate_txn_conf is None or last_initiate_txn_conf < 1
                ) and tx_height > 0:
                    # Start checking for spends of initiate_txn before fully confirmed
                    bid.initiate_tx.chain_height = self.setLastHeightCheckedStart(
                        coin_from, tx_height
                    )
                    self.setTxBlockInfoFromHeight(ci_from, bid.initiate_tx, tx_height)

                    self.addWatchedOutput(
                        coin_from,
                        bid_id,
                        initiate_txnid_hex,
                        bid.initiate_tx.vout,
                        BidStates.SWAP_INITIATED,
                    )
                    if (
                        bid.getITxState() is None
                        or bid.getITxState() < TxStates.TX_SENT
                    ):
                        bid.setITxState(TxStates.TX_SENT)
                    save_bid = True

                if (
                    bid.initiate_tx.conf
                    >= self.coin_clients[coin_from]["blocks_confirmed"]
                ):
                    self.initiateTxnConfirmed(bid_id, bid, offer)
                    save_bid = True

            # Bid times out if buyer doesn't see tx in chain within INITIATE_TX_TIMEOUT seconds
            if (
                bid.initiate_tx is None
                and bid.state_time + atomic_swap_1.INITIATE_TX_TIMEOUT < self.getTime()
            ):
                self.log.info(
                    f"Swap timed out waiting for initiate tx for bid {self.log.id(bid_id)}"
                )
                bid.setState(
                    BidStates.SWAP_TIMEDOUT, "Timed out waiting for initiate tx"
                )
                self.saveBid(bid_id, bid)
                return True  # Mark bid for archiving
        elif state == BidStates.SWAP_INITIATED:
            # Waiting for participate txn to be confirmed in 'to' chain
            if ci_to.using_segwit():
                p2wsh = ci_to.getScriptDest(bid.participate_tx.script)
                addr = ci_to.encodeScriptDest(p2wsh)
            else:
                addr = ci_to.encode_p2sh(bid.participate_tx.script)

            ci_to = self.ci(coin_to)
            participate_txid = (
                None
                if bid.participate_tx is None or bid.participate_tx.txid is None
                else bid.participate_tx.txid
            )
            participate_txvout = (
                None
                if bid.participate_tx is None or bid.participate_tx.vout is None
                else bid.participate_tx.vout
            )
            found = ci_to.getLockTxHeight(
                participate_txid,
                addr,
                bid.amount_to,
                bid.chain_b_height_start,
                find_index=True,
                vout=participate_txvout,
            )
            if found:
                index = found.get("index", participate_txvout)
                if bid.participate_tx.conf != found["depth"]:
                    save_bid = True
                if (
                    bid.participate_tx.conf is None
                    and bid.participate_tx.state != TxStates.TX_SENT
                ):
                    txid = found.get(
                        "txid",
                        None if participate_txid is None else participate_txid.hex(),
                    )
                    self.log.debug(
                        f"Found bid {self.log.id(bid_id)} participate txn {self.log.id(txid)} in chain {ci_to.coin_name()}."
                    )
                    self.addParticipateTxn(
                        bid_id, bid, coin_to, txid, index, found["height"]
                    )

                    # Only update tx state if tx hasn't already been seen
                    if (
                        bid.participate_tx.state is None
                        or bid.participate_tx.state < TxStates.TX_SENT
                    ):
                        bid.setPTxState(TxStates.TX_SENT)

                bid.participate_tx.conf = found["depth"]
                if found["height"] > 0 and bid.participate_tx.block_height is None:
                    self.setTxBlockInfoFromHeight(
                        ci_to, bid.participate_tx, found["height"]
                    )

            if bid.participate_tx.conf is not None:
                self.log.debug(
                    f"participate txid {self.log.id(bid.participate_tx.txid)} confirms {bid.participate_tx.conf}."
                )
                if (
                    bid.participate_tx.conf
                    >= self.coin_clients[coin_to]["blocks_confirmed"]
                ):
                    self.participateTxnConfirmed(bid_id, bid, offer)
                    save_bid = True
        elif state == BidStates.SWAP_PARTICIPATING:
            # Waiting for initiate txn spend
            pass
        elif state == BidStates.BID_ERROR:
            # Wait for user input
            pass
        else:
            self.log.warning(f"checkBidState unknown state {state}")

        if state > BidStates.BID_ACCEPTED:
            # Wait for spend of all known swap txns
            itx_state = bid.getITxState()
            ptx_state = bid.getPTxState()
            if (itx_state is None or itx_state >= TxStates.TX_REDEEMED) and (
                ptx_state is None or ptx_state >= TxStates.TX_REDEEMED
            ):
                self.log.info(f"Swap completed for bid {self.log.id(bid_id)}")

                self.returnAddressToPool(
                    bid_id,
                    (
                        TxTypes.ITX_REFUND
                        if itx_state == TxStates.TX_REDEEMED
                        else TxTypes.PTX_REDEEM
                    ),
                )
                self.returnAddressToPool(
                    bid_id,
                    (
                        TxTypes.ITX_REFUND
                        if ptx_state == TxStates.TX_REDEEMED
                        else TxTypes.PTX_REDEEM
                    ),
                )

                bid.setState(BidStates.SWAP_COMPLETED)
                self.saveBid(bid_id, bid)
                try:
                    self.notify(
                        NT.SWAP_COMPLETED,
                        {
                            "bid_id": bid_id.hex(),
                        },
                    )
                except Exception as ex:
                    self.log.warning(
                        f"Failed to send swap completion notification: {ex}"
                    )

                return True  # Mark bid for archiving

        if save_bid:
            self.saveBid(bid_id, bid)

        if bid.debug_ind == DebugTypes.SKIP_LOCK_TX_REFUND:
            return False  # Bid is still active

        # Try refund, keep trying until sent tx is spent
        if (
            bid.getITxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED)
            and bid.initiate_txn_refund is not None
        ):
            try:
                txid = ci_from.publishTx(bid.initiate_txn_refund)
                self.log.debug(
                    f"Submitted initiate refund txn {self.log.id(txid)} to {ci_from.coin_name()} chain for bid {self.log.id(bid_id)}."
                )
                self.logEvent(
                    Concepts.BID,
                    bid.bid_id,
                    EventLogTypes.ITX_REFUND_PUBLISHED,
                    "",
                    None,
                )
                # State will update when spend is detected
            except Exception as ex:
                if ci_from.isTxNonFinalError(str(ex)) is False:
                    self.log.warning(
                        f"Error trying to submit initiate refund txn: {ex}"
                    )

        if (
            bid.getPTxState() in (TxStates.TX_SENT, TxStates.TX_CONFIRMED)
            and bid.participate_txn_refund is not None
        ):
            try:
                txid = ci_to.publishTx(bid.participate_txn_refund)
                self.log.debug(
                    f"Submitted participate refund txn {self.log.id(txid)} to {ci_to.coin_name()} chain for bid {self.log.id(bid_id)}."
                )
                self.logEvent(
                    Concepts.BID,
                    bid.bid_id,
                    EventLogTypes.PTX_REFUND_PUBLISHED,
                    "",
                    None,
                )
                # State will update when spend is detected
            except Exception as ex:
                if ci_to.isTxNonFinalError(str(ex)):
                    self.log.warning(
                        f"Error trying to submit participate refund txn: {ex}"
                    )
        return False  # Bid is still active

    def extractSecret(self, coin_type, bid, spend_in):
        try:
            if coin_type in (Coins.DCR,):
                script_sig = spend_in["scriptSig"]["asm"].split(" ")
                ensure(len(script_sig) == 5, "Bad witness size")
                return bytes.fromhex(script_sig[2])
            elif (
                coin_type in (Coins.PART,) or self.coin_clients[coin_type]["use_segwit"]
            ):
                ensure(len(spend_in["txinwitness"]) == 5, "Bad witness size")
                return bytes.fromhex(spend_in["txinwitness"][2])
            else:
                script_sig = spend_in["scriptSig"]["asm"].split(" ")
                ensure(len(script_sig) == 5, "Bad witness size")
                return bytes.fromhex(script_sig[2])
        except Exception:
            return None

    def addWatchedOutput(
        self, coin_type, bid_id, txid_hex, vout, tx_type, swap_type=None
    ):
        self.log.debug(
            f"Adding watched output {Coins(coin_type).name} bid {self.log.id(bid_id)} tx {self.log.id(txid_hex)} type {tx_type}"
        )

        watched = self.coin_clients[coin_type]["watched_outputs"]

        for wo in watched:
            if wo.bid_id == bid_id and wo.txid_hex == txid_hex and wo.vout == vout:
                self.log.debug("Output already being watched.")
                return

        watched.append(WatchedOutput(bid_id, txid_hex, vout, tx_type, swap_type))

    def removeWatchedOutput(self, coin_type, bid_id: bytes, txid_hex: str) -> None:
        # Remove all for bid if txid is None
        self.log.debug(
            f"removeWatchedOutput {Coins(coin_type).name} {self.log.id(bid_id)} {self.log.id(txid_hex)}"
        )
        old_len = len(self.coin_clients[coin_type]["watched_outputs"])
        for i in range(old_len - 1, -1, -1):
            wo = self.coin_clients[coin_type]["watched_outputs"][i]
            if wo.bid_id == bid_id and (txid_hex is None or wo.txid_hex == txid_hex):
                del self.coin_clients[coin_type]["watched_outputs"][i]
                self.log.debug(
                    f"Removed watched output {Coins(coin_type).name} {self.log.id(bid_id)} {self.log.id(wo.txid_hex)}"
                )

    def addWatchedScript(
        self, coin_type, bid_id, script: bytes, tx_type, swap_type=None
    ):
        self.log.debug(
            f"Adding watched script {Coins(coin_type).name} bid {self.log.id(bid_id)} type {tx_type}."
        )

        watched = self.coin_clients[coin_type]["watched_scripts"]

        for ws in watched:
            if ws.bid_id == bid_id and ws.tx_type == tx_type and ws.script == script:
                self.log.debug("Script already being watched.")
                return

        watched.append(WatchedScript(bid_id, script, tx_type, swap_type))

    def removeWatchedScript(
        self, coin_type, bid_id: bytes, script: bytes, tx_type: TxTypes = None
    ) -> None:
        # Remove all for bid if script and type_ind is None
        self.log.debug(
            "removeWatchedScript {} {}{}".format(
                Coins(coin_type).name,
                {self.log.id(bid_id)},
                (" type " + str(tx_type)) if tx_type is not None else "",
            )
        )
        old_len = len(self.coin_clients[coin_type]["watched_scripts"])
        for i in range(old_len - 1, -1, -1):
            ws = self.coin_clients[coin_type]["watched_scripts"][i]
            if (
                ws.bid_id == bid_id
                and (script is None or ws.script == script)
                and (tx_type is None or ws.tx_type == tx_type)
            ):
                del self.coin_clients[coin_type]["watched_scripts"][i]
                self.log.debug(
                    f"Removed watched script {Coins(coin_type).name} {self.log.id(bid_id)}"
                )

    def initiateTxnSpent(
        self, bid_id: bytes, spend_txid: str, spend_n: int, spend_txn
    ) -> None:
        self.log.debug(
            f"Bid {self.log.id(bid_id)} initiate txn spent by {self.logIDT(spend_txid)} {spend_n}."
        )

        if bid_id in self.swaps_in_progress:
            bid = self.swaps_in_progress[bid_id][0]
            offer = self.swaps_in_progress[bid_id][1]

            bid.initiate_tx.spend_txid = bytes.fromhex(spend_txid)
            bid.initiate_tx.spend_n = spend_n
            spend_in = spend_txn["vin"][spend_n]

            coin_from = Coins(offer.coin_from)

            secret = self.extractSecret(coin_from, bid, spend_in)
            if secret is None:
                self.log.info(
                    f"Bid {self.log.id(bid_id)} initiate txn refunded by {self.logIDT(spend_txid)} {spend_n}."
                )
                # TODO: Wait for depth?
                bid.setITxState(TxStates.TX_REFUNDED)
            else:
                self.log.info(
                    f"Bid {self.log.id(bid_id)} initiate txn redeemed by {self.logIDT(spend_txid)} {spend_n}."
                )
                # TODO: Wait for depth?
                bid.setITxState(TxStates.TX_REDEEMED)

            self.removeWatchedOutput(coin_from, bid_id, bid.initiate_tx.txid.hex())
            self.saveBid(bid_id, bid)

    def participateTxnSpent(
        self, bid_id: bytes, spend_txid: str, spend_n: int, spend_txn
    ) -> None:
        self.log.debug(
            f"Bid {self.log.id(bid_id)} participate txn spent by {self.logIDT(spend_txid)} {spend_n}."
        )

        # TODO: More SwapTypes
        if bid_id in self.swaps_in_progress:
            bid = self.swaps_in_progress[bid_id][0]
            offer = self.swaps_in_progress[bid_id][1]

            bid.participate_tx.spend_txid = bytes.fromhex(spend_txid)
            bid.participate_tx.spend_n = spend_n
            spend_in = spend_txn["vin"][spend_n]

            coin_to = Coins(offer.coin_to)

            secret = self.extractSecret(coin_to, bid, spend_in)
            if secret is None:
                self.log.info(
                    f"Bid {self.log.id(bid_id)} participate txn refunded by {self.logIDT(spend_txid)} {spend_n}."
                )
                # TODO: Wait for depth?
                bid.setPTxState(TxStates.TX_REFUNDED)
            else:
                self.log.debug(
                    f"Secret {secret.hex()} extracted from participate spend {self.logIDT(spend_txid)} {spend_n}"
                )
                bid.recovered_secret = secret
                # TODO: Wait for depth?
                bid.setPTxState(TxStates.TX_REDEEMED)

                if bid.was_sent:
                    if bid.debug_ind == DebugTypes.DONT_SPEND_ITX:
                        self.log.debug(
                            f"{self.logIDB(bid_id)}: Abandoning for testing: {bid.debug_ind}, {DebugTypes(bid.debug_ind).name}."
                        )
                        bid.setState(BidStates.BID_ABANDONED)
                        self.logBidEvent(
                            bid.bid_id,
                            EventLogTypes.DEBUG_TWEAK_APPLIED,
                            f"ind {bid.debug_ind}",
                            None,
                        )
                    else:
                        delay = self.get_short_delay_event_seconds()
                        self.log.info(
                            f"Redeeming ITX for bid {self.log.id(bid_id)} in {delay} seconds."
                        )
                        self.createAction(delay, ActionTypes.REDEEM_ITX, bid_id)
                # TODO: Wait for depth? new state SWAP_TXI_REDEEM_SENT?

            self.removeWatchedOutput(coin_to, bid_id, bid.participate_tx.txid.hex())
            self.saveBid(bid_id, bid)

    def process_XMR_SWAP_A_LOCK_tx_spend(
        self, bid_id: bytes, spend_txid_hex, spend_txn_hex, cursor=None
    ) -> None:
        self.log.debug(
            f"Detected spend of Adaptor-sig swap coin a lock tx for bid {self.log.id(bid_id)}"
        )
        try:
            use_cursor = self.openDB(cursor)
            bid, xmr_swap = self.getXmrBidFromSession(use_cursor, bid_id)
            ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
            ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

            if BidStates(bid.state) == BidStates.BID_STALLED_FOR_TEST:
                self.log.debug(f"Bid stalled{self.log.id(bid_id)}")
                return

            offer, xmr_offer = self.getXmrOfferFromSession(use_cursor, bid.offer_id)
            ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
            ensure(
                xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}."
            )

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
            was_received: bool = bid.was_sent if reverse_bid else bid.was_received
            coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)

            state = BidStates(bid.state)
            spending_txid = bytes.fromhex(spend_txid_hex)

            ci_from = self.ci(coin_from)
            spend_tx = ci_from.loadTx(h2b(spend_txn_hex))

            bid.xmr_a_lock_tx.spend_txid = spending_txid

            is_spending_lock_tx = False
            if self.isBchXmrSwap(offer):
                is_spending_lock_tx = self.ci(coin_from).isSpendingLockTx(spend_tx)

            if spending_txid == xmr_swap.a_lock_spend_tx_id or (
                i2b(spend_tx.vin[0].prevout.hash) == xmr_swap.a_lock_tx_id
                and is_spending_lock_tx
            ):
                # bch txids change
                if self.isBchXmrSwap(offer):
                    xmr_swap.a_lock_spend_tx_id = spending_txid
                    xmr_swap.a_lock_spend_tx = bytes.fromhex(spend_txn_hex)

                if state == BidStates.XMR_SWAP_LOCK_RELEASED:
                    xmr_swap.a_lock_spend_tx = bytes.fromhex(spend_txn_hex)
                    bid.setState(
                        BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED
                    )  # TODO: Wait for confirmation?

                    if bid.xmr_a_lock_tx:
                        bid.xmr_a_lock_tx.setState(TxStates.TX_REDEEMED)

                    if not was_received:
                        bid.setState(BidStates.SWAP_COMPLETED)
                        try:
                            self.notify(
                                NT.SWAP_COMPLETED,
                                {
                                    "bid_id": bid_id.hex(),
                                },
                            )
                        except Exception as ex:
                            self.log.warning(
                                f"Failed to send swap completion notification: {ex}"
                            )
                else:
                    # Could already be processed if spend was detected in the mempool
                    self.log.warning(
                        f"Coin a lock tx spend ignored due to bid state for bid {self.log.id(bid_id)}."
                    )

            elif spending_txid == xmr_swap.a_lock_refund_tx_id or (
                i2b(spend_tx.vin[0].prevout.hash) == xmr_swap.a_lock_tx_id
                and not is_spending_lock_tx
            ):
                self.log.debug("Coin a lock tx spent by lock refund tx.")
                # bch txids change
                if self.isBchXmrSwap(offer):
                    self.log.debug(
                        "Recomputing refund spend transaction and txid after lock tx spent."
                    )

                    xmr_swap.a_lock_refund_tx_id = spending_txid
                    xmr_swap.a_lock_refund_tx = bytes.fromhex(spend_txn_hex)

                    tx = ci_from.loadTx(xmr_swap.a_lock_refund_spend_tx)
                    tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_refund_tx_id)
                    xmr_swap.a_lock_refund_spend_tx = tx.serialize_without_witness()
                    xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxid(
                        xmr_swap.a_lock_refund_spend_tx
                    )

                    if was_received:
                        refund_to_script = ci_from.getRefundOutputScript(xmr_swap)
                        self.addWatchedScript(
                            ci_from.coin_type(),
                            bid_id,
                            refund_to_script,
                            TxTypes.BCH_MERCY,
                        )

                bid.setState(BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND)
                self.logBidEvent(
                    bid.bid_id, EventLogTypes.LOCK_TX_A_REFUND_TX_SEEN, "", use_cursor
                )

                if TxTypes.XMR_SWAP_A_LOCK_REFUND not in bid.txns:
                    bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND] = SwapTx(
                        bid_id=bid.bid_id,
                        tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND,
                        txid=xmr_swap.a_lock_refund_tx_id,
                    )
            else:
                self.setBidError(
                    bid.bid_id,
                    bid,
                    "Unexpected txn spent coin a lock tx: {}".format(spend_txid_hex),
                    save_bid=False,
                )

            self.saveBidInSession(
                bid_id, bid, use_cursor, xmr_swap, save_in_progress=offer
            )
        except Exception as ex:
            self.logException(f"process_XMR_SWAP_A_LOCK_tx_spend {ex}")
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def process_XMR_SWAP_A_LOCK_REFUND_tx_spend(
        self, bid_id: bytes, spend_txid_hex: str, spend_txn
    ) -> None:
        self.log.debug(
            f"Detected spend of Adaptor-sig swap coin a lock refund tx for bid {self.log.id(bid_id)}."
        )
        try:
            cursor = self.openDB()
            bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
            ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
            ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

            offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
            ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
            ensure(
                xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}."
            )

            reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
            coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
            coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
            was_sent: bool = bid.was_received if reverse_bid else bid.was_sent
            was_received: bool = bid.was_sent if reverse_bid else bid.was_received

            ci_from = self.ci(coin_from)

            spending_txid = bytes.fromhex(spend_txid_hex)

            spend_txn_hex = spend_txn["hex"]
            spend_tx = ci_from.loadTx(h2b(spend_txn_hex))

            is_spending_lock_refund_tx = False
            if self.isBchXmrSwap(offer):
                is_spending_lock_refund_tx = ci_from.isSpendingLockRefundTx(spend_tx)

            if spending_txid == xmr_swap.a_lock_refund_spend_tx_id or (
                i2b(spend_tx.vin[0].prevout.hash) == xmr_swap.a_lock_refund_tx_id
                and is_spending_lock_refund_tx
            ):
                self.log.info(
                    f"Found coin a lock refund spend tx, bid {self.log.id(bid_id)}."
                )

                # bch txids change
                if self.isBchXmrSwap(offer):
                    xmr_swap.a_lock_refund_spend_tx_id = spending_txid
                    xmr_swap.a_lock_refund_spend_tx = bytes.fromhex(spend_txn_hex)

                    if was_received:
                        self.removeWatchedScript(
                            coin_from, bid_id, None, TxTypes.BCH_MERCY
                        )

                self.logBidEvent(
                    bid.bid_id,
                    EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_SEEN,
                    "",
                    cursor,
                )

                if bid.xmr_a_lock_tx:
                    bid.xmr_a_lock_tx.setState(TxStates.TX_REFUNDED)

                if was_sent:
                    xmr_swap.a_lock_refund_spend_tx = bytes.fromhex(
                        spend_txn_hex
                    )  # Replace with fully signed tx
                    if TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND not in bid.txns:
                        bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND] = SwapTx(
                            bid_id=bid_id,
                            tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND,
                            txid=xmr_swap.a_lock_refund_spend_tx_id,
                        )
                    if bid.xmr_b_lock_tx is not None:
                        delay = self.get_delay_event_seconds()
                        self.log.info(
                            f"Recovering adaptor-sig swap chain B lock tx for bid {self.log.id(bid_id)} in {delay} seconds."
                        )
                        self.createActionInSession(
                            delay,
                            ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B,
                            bid_id,
                            cursor,
                        )
                    else:
                        # Other side refunded before swap lock tx was sent
                        bid.setState(BidStates.XMR_SWAP_FAILED)

                if was_received:
                    if not was_sent:  # Self bids
                        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)

            else:
                self.log.info(
                    f"Coin a lock refund spent by unknown tx, bid {self.log.id(bid_id)}."
                )

                mercy_keyshare = None
                if was_received:
                    if self.isBchXmrSwap(offer):
                        # Mercy tx is sent separately
                        pass
                    else:
                        # Look for a mercy output
                        try:
                            mercy_keyshare = ci_from.inspectSwipeTx(spend_txn)
                            if mercy_keyshare is None:
                                raise ValueError("Not found")
                            ensure(
                                self.ci(coin_to).verifyKey(mercy_keyshare),
                                "Invalid keyshare",
                            )
                        except Exception as e:
                            self.log.warning(
                                f"Could not extract mercy output from swipe tx: {self.log.id(spend_txid_hex)}, {e}."
                            )

                        if mercy_keyshare is None:
                            bid.setState(BidStates.XMR_SWAP_FAILED_SWIPED)
                        else:
                            delay = self.get_delay_event_seconds()
                            self.log.info(
                                f"Redeeming coin b lock tx for bid {self.log.id(bid_id)} in {delay} seconds."
                            )
                            self.createActionInSession(
                                delay,
                                ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B,
                                bid_id,
                                cursor,
                            )
                else:
                    bid.setState(BidStates.XMR_SWAP_FAILED_SWIPED)

                if TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE not in bid.txns:
                    bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE] = SwapTx(
                        bid_id=bid_id,
                        tx_type=TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE,
                        txid=spending_txid,
                    )
                    if mercy_keyshare:
                        bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE].tx_data = (
                            mercy_keyshare
                        )

            self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)
        except Exception as ex:
            self.logException(f"process_XMR_SWAP_A_LOCK_REFUND_tx_spend {ex}")
        finally:
            self.closeDB(cursor)

    def processSpentOutput(
        self, coin_type, watched_output, spend_txid_hex, spend_n, spend_txn
    ) -> None:
        if watched_output.swap_type == SwapTypes.XMR_SWAP:
            if watched_output.tx_type == TxTypes.XMR_SWAP_A_LOCK:
                self.process_XMR_SWAP_A_LOCK_tx_spend(
                    watched_output.bid_id, spend_txid_hex, spend_txn["hex"]
                )
            elif watched_output.tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND:
                self.process_XMR_SWAP_A_LOCK_REFUND_tx_spend(
                    watched_output.bid_id, spend_txid_hex, spend_txn
                )

            self.removeWatchedOutput(
                coin_type, watched_output.bid_id, watched_output.txid_hex
            )
            return

        if watched_output.tx_type == BidStates.SWAP_PARTICIPATING:
            self.participateTxnSpent(
                watched_output.bid_id, spend_txid_hex, spend_n, spend_txn
            )
        else:
            self.initiateTxnSpent(
                watched_output.bid_id, spend_txid_hex, spend_n, spend_txn
            )

    def processFoundScript(
        self, coin_type, watched_script, txid: bytes, vout: int
    ) -> None:
        if watched_script.tx_type == TxTypes.PTX:
            if watched_script.bid_id in self.swaps_in_progress:
                bid = self.swaps_in_progress[watched_script.bid_id][0]

                bid.participate_tx.txid = txid
                bid.participate_tx.vout = vout
                bid.setPTxState(TxStates.TX_IN_CHAIN)

                self.saveBid(watched_script.bid_id, bid)
            else:
                self.log.warning(
                    f"Could not find active bid for found watched script: {self.logIDB(watched_script.bid_id)}."
                )
        elif watched_script.tx_type == TxTypes.XMR_SWAP_A_LOCK:
            self.log.info(
                f"Found chain A lock txid {self.log.id(txid)} for bid: {self.log.id(watched_script.bid_id)}."
            )
            bid = self.swaps_in_progress[watched_script.bid_id][0]
            if bid.xmr_a_lock_tx.txid != txid:
                self.log.debug(
                    f"Updating xmr_a_lock_tx from {self.log.id(bid.xmr_a_lock_tx.txid)} to {txid}."
                )
                bid.xmr_a_lock_tx.txid = txid
                bid.xmr_a_lock_tx.vout = vout
            self.saveBid(watched_script.bid_id, bid)
        elif watched_script.tx_type == TxTypes.XMR_SWAP_B_LOCK:
            self.log.info(
                f"Found chain B lock txid {self.log.id(txid)} for bid: {self.log.id(watched_script.bid_id)}."
            )
            bid = self.swaps_in_progress[watched_script.bid_id][0]
            bid.xmr_b_lock_tx = SwapTx(
                bid_id=watched_script.bid_id,
                tx_type=TxTypes.XMR_SWAP_B_LOCK,
                txid=txid,
                vout=vout,
            )
            if bid.xmr_b_lock_tx.txid != txid:
                self.log.debug(
                    f"Updating xmr_b_lock_tx from {self.log.id(bid.xmr_b_lock_tx.txid)} to {self.log.id(txid)}."
                )
                bid.xmr_b_lock_tx.txid = txid
                bid.xmr_b_lock_tx.vout = vout
            bid.xmr_b_lock_tx.setState(TxStates.TX_IN_CHAIN)
            self.saveBid(watched_script.bid_id, bid)
        else:
            self.log.warning(
                f"Unknown found watched script tx type for bid {self.log.id(watched_script.bid_id)}."
            )

        self.removeWatchedScript(
            coin_type, watched_script.bid_id, watched_script.script
        )

    def processMercyTx(
        self, coin_type, watched_script, txid: bytes, vout: int, tx
    ) -> None:
        bid_id = watched_script.bid_id
        ci = self.ci(coin_type)
        if (
            len(tx["vout"]) < 2 or ci.make_int(tx["vout"][vout]["value"]) != 546
        ):  # Dust limit

            self.log.info(f"Found tx is not a mercy tx for bid: {self.log.id(bid_id)}.")
            self.removeWatchedScript(coin_type, bid_id, watched_script.script)
            return

        self.log.info(f"Found mercy tx for bid: {self.log.id(bid_id)}.")

        self.logBidEvent(
            bid_id, EventLogTypes.BCH_MERCY_TX_FOUND, txid.hex(), cursor=None
        )

        if bid_id not in self.swaps_in_progress:
            self.log.warning(
                f"Could not find active bid for found mercy tx: {self.logIDB(bid_id)}."
            )
        else:
            mercy_keyshare = bytes.fromhex(
                tx["vout"][0]["scriptPubKey"]["asm"].split(" ")[2]
            )
            ensure(ci.verifyKey(mercy_keyshare), "Invalid keyshare")

            bid = self.swaps_in_progress[bid_id][0]
            bid.txns[TxTypes.BCH_MERCY] = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.BCH_MERCY,
                txid=txid,
                tx_data=mercy_keyshare,
            )
            self.saveBid(bid_id, bid)

            delay = self.get_delay_event_seconds()
            self.log.info(
                f"Redeeming coin b lock tx for bid {self.logIDB(bid_id)} in {delay} seconds."
            )
            self.createAction(delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B, bid_id)

        self.removeWatchedScript(coin_type, bid_id, watched_script.script)

    def haveCheckedPrevBlock(self, ci, c, block, cursor=None) -> bool:
        previousblockhash = bytes.fromhex(block["previousblockhash"])
        try:
            use_cursor = self.openDB(cursor)

            q = use_cursor.execute(
                "SELECT COUNT(*) FROM checkedblocks WHERE block_hash = :block_hash",
                {"block_hash": previousblockhash},
            ).fetchone()
            if q[0] > 0:
                return True

        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

        return False

    def updateCheckedBlock(self, ci, cc, block, cursor=None) -> None:
        now: int = self.getTime()
        try:
            use_cursor = self.openDB(cursor)

            block_height = int(block["height"])
            if cc["last_height_checked"] != block_height:
                cc["last_height_checked"] = block_height
                self.setIntKV(
                    "last_height_checked_" + ci.coin_name().lower(),
                    block_height,
                    cursor=use_cursor,
                )

            query = """INSERT INTO checkedblocks (created_at, coin_type, block_height, block_hash, block_time)
                       VALUES (:now, :coin_type, :block_height, :block_hash, :block_time)"""
            use_cursor.execute(
                query,
                {
                    "now": now,
                    "coin_type": int(ci.coin_type()),
                    "block_height": block_height,
                    "block_hash": bytes.fromhex(block["hash"]),
                    "block_time": int(block["time"]),
                },
            )

        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def checkForSpends(self, coin_type, c):
        # assert (self.mxDB.locked())
        self.log.debug(f"checkForSpends {Coins(coin_type).name}.")

        # TODO: Check for spends on watchonly txns where possible
        if self.coin_clients[coin_type].get("have_spent_index", False):
            # TODO: batch getspentinfo
            for o in c["watched_outputs"]:
                found_spend = None
                try:
                    found_spend = self.callcoinrpc(
                        Coins.PART,
                        "getspentinfo",
                        [{"txid": o.txid_hex, "index": o.vout}],
                    )
                except Exception as ex:
                    if "Unable to get spent info" not in str(ex):
                        self.log.warning(f"getspentinfo {ex}")
                if found_spend is not None:
                    spend_txid = found_spend["txid"]
                    spend_n = found_spend["index"]
                    self.log.debug(
                        f"Found spend in spentindex {self.logIDT(o.txid_hex)} {o.vout} in {self.logIDT(spend_txid)} {spend_n}"
                    )
                    spend_txn = self.callcoinrpc(
                        Coins.PART, "getrawtransaction", [spend_txid, True]
                    )
                    self.processSpentOutput(
                        coin_type, o, spend_txid, spend_n, spend_txn
                    )
            return

        ci = self.ci(coin_type)
        chain_blocks = ci.getChainHeight()
        last_height_checked: int = c["last_height_checked"]
        block_check_min_time: int = c["block_check_min_time"]
        self.log.debug(
            f"{ci.ticker()} chain_blocks, last_height_checked {chain_blocks} {last_height_checked}."
        )

        blocks_checked: int = 0
        while last_height_checked < chain_blocks:
            if self.delay_event.is_set():
                break
            blocks_checked += 1
            if blocks_checked % 10000 == 0:
                self.log.debug(
                    f"{ci.ticker()} chain_blocks, last_height_checked, blocks_checked {chain_blocks} {last_height_checked} {blocks_checked}."
                )
            if blocks_checked > self._max_check_loop_blocks:
                self.log.debug(
                    f"Hit max_check_loop_blocks for {ci.ticker()} chain_blocks, last_height_checked {chain_blocks} {last_height_checked}"
                )
                break

            block_hash = ci.rpc("getblockhash", [last_height_checked + 1])
            try:
                block = ci.getBlockWithTxns(block_hash)
            except Exception as e:
                if "Block not available (pruned data)" in str(e):
                    # TODO: Better solution?
                    bci = ci.getBlockchainInfo()
                    pruneheight = bci["pruneheight"]
                    self.log.error(
                        f"Coin {ci.coin_name()} last_height_checked {last_height_checked} set to pruneheight {pruneheight}."
                    )
                    last_height_checked = pruneheight
                    continue
                else:
                    self.logException(f"getblock error {e}")
                    break

            if block_check_min_time > block["time"] or last_height_checked < 1:
                pass
            elif not self.haveCheckedPrevBlock(ci, c, block):
                last_height_checked -= 1
                self.log.debug(
                    "Have not seen previousblockhash {} for block {}".format(
                        block["previousblockhash"], block["hash"]
                    )
                )
                continue

            for tx in block["tx"]:
                for s in c["watched_scripts"]:
                    for i, txo in enumerate(tx["vout"]):
                        if "scriptPubKey" in txo and "hex" in txo["scriptPubKey"]:
                            # TODO: Optimise by loading rawtx in CTransaction
                            if bytes.fromhex(txo["scriptPubKey"]["hex"]) == s.script:
                                txid_bytes = bytes.fromhex(tx["txid"])
                                self.log.debug(
                                    f"Found script from search for bid {self.log.id(s.bid_id)}: {self.logIDT(txid_bytes)} {i}."
                                )
                                if s.tx_type == TxTypes.BCH_MERCY:
                                    self.processMercyTx(coin_type, s, txid_bytes, i, tx)
                                else:
                                    self.processFoundScript(coin_type, s, txid_bytes, i)

                for o in c["watched_outputs"]:
                    for i, inp in enumerate(tx["vin"]):
                        inp_txid = inp.get("txid", None)
                        if inp_txid is None:  # Coinbase
                            continue
                        if inp_txid == o.txid_hex and inp["vout"] == o.vout:
                            txid = tx["txid"]
                            self.log.debug(
                                f"Found spend from search {self.logIDT(o.txid_hex)} {o.vout} in {self.logIDT(txid)} {i}."
                            )
                            self.processSpentOutput(coin_type, o, txid, i, tx)

            last_height_checked += 1
            self.updateCheckedBlock(ci, c, block)

    def expireMessageRoutes(self) -> None:
        if self._is_locked is True:
            self.log.debug("Not expiring message routes while system is locked")
            return

        num_removed: int = 0
        now: int = self.getTime()
        cursor = self.openDB()
        try:
            query_str = (
                "SELECT record_id, network_id, created_at, active_ind, route_data FROM direct_message_routes "
                + "WHERE 1 = 1 "
            )
            rows = cursor.execute(query_str).fetchall()
            for row in rows:
                record_id, network_id, created_at, active_ind, route_data = row

                route_data = json.loads(route_data.decode("UTF-8"))

                if now - created_at < self._expire_message_routes_after:
                    continue

                # unestablished routes
                if active_ind == 2:
                    pass
                else:
                    query_str = (
                        "SELECT MAX(created_at) FROM direct_message_route_links "
                        + "WHERE direct_message_route_id = :message_route_id "
                    )
                    max_link_created_at = cursor.execute(
                        query_str, {"message_route_id": record_id}
                    ).fetchone()[0]

                    if now - max_link_created_at < self._expire_message_routes_after:
                        continue

                    query_str = (
                        "SELECT COUNT(*) FROM direct_message_route_links rl "
                        + "INNER JOIN bids b ON b.bid_id = rl.linked_id "
                        + "INNER JOIN bidstates s ON s.state_id = b.state "
                        + "WHERE rl.direct_message_route_id = :message_route_id AND rl.linked_type = :link_type_bid "
                        + "AND (b.in_progress OR s.in_progress OR (s.swap_ended = 0 AND b.expire_at > :now))"
                    )
                    num_active_bids = cursor.execute(
                        query_str,
                        {
                            "message_route_id": record_id,
                            "link_type_bid": Concepts.BID,
                            "now": now,
                        },
                    ).fetchone()[0]
                    if num_active_bids > 0:
                        self.log.warning(
                            f"Not expiring message route {record_id} with {num_active_bids} active bids."
                        )
                        continue

                self.closeMessageRoute(record_id, network_id, route_data, cursor)
                num_removed += 1
        finally:
            self.closeDB(cursor)

        if num_removed > 0:
            self.log.info(
                "Expired {} message route{}.".format(
                    num_removed,
                    "s" if num_removed != 1 else "",
                )
            )

    def expireMessages(self) -> None:
        if self._is_locked is True:
            self.log.debug("Not expiring messages while system is locked")
            return

        self.mxDB.acquire()
        rpc_conn = None
        try:
            ci_part = self.ci(Coins.PART)
            rpc_conn = ci_part.open_rpc()
            num_messages: int = 0
            num_removed: int = 0

            def remove_if_expired(msg):
                nonlocal num_messages, num_removed
                try:
                    num_messages += 1
                    if "sent" not in msg:
                        # TODO: Always show time sent and ttl from core
                        options = {"encoding": "none", "export": True}
                        msg_data = ci_part.json_request(
                            rpc_conn, "smsg", [msg["msgid"], options]
                        )
                        msg_time: int = msg_data["sent"]
                        msg_ttl: int = msg_data["ttl"]
                    else:
                        msg_time: int = msg["sent"]
                        msg_ttl: int = msg["ttl"]
                    expire_at: int = msg_time + msg_ttl
                    if expire_at < now:
                        options = {"encoding": "none", "delete": True}
                        ci_part.json_request(rpc_conn, "smsg", [msg["msgid"], options])
                        num_removed += 1
                except Exception as e:  # noqa: F841
                    if self.debug:
                        self.log.error(traceback.format_exc())
                        self.log.error(f"Failed to process message {msg}")

            now: int = self.getTime()
            options = {"encoding": "none", "setread": False}
            inbox_messages = ci_part.json_request(
                rpc_conn, "smsginbox", ["all", "", options]
            )["messages"]
            for msg in inbox_messages:
                remove_if_expired(msg)
            outbox_messages = ci_part.json_request(
                rpc_conn, "smsgoutbox", ["all", "", options]
            )["messages"]
            for msg in outbox_messages:
                remove_if_expired(msg)

            if num_messages + num_removed > 0:
                self.log.info(f"Expired {num_removed} / {num_messages} messages.")

        finally:
            if rpc_conn:
                ci_part.close_rpc(rpc_conn)
            self.mxDB.release()

    def expireDBRecords(self) -> None:
        if self._is_locked is True:
            self.log.debug("Not expiring database records while system locked.")
            return
        if not self._expire_db_records:
            return
        remove_expired_data(self, self._expire_db_records_after)

    def checkAcceptedBids(self) -> None:
        # Check for bids stuck as accepted (not yet in-progress)
        if self._is_locked is True:
            self.log.debug("Not checking accepted bids while system locked.")
            return

        now: int = self.getTime()
        cursor = self.openDB()

        respond_grace_period: int = 60 * 60
        # Time for transaction to be mined into the chain
        # Only timeout waiting for the tx to be mined if not the sending the tx.
        tx_grace_period: int = self._sc_lock_tx_timeout
        tx_mempool_grace_period: int = self._sc_lock_tx_mempool_timeout

        try:
            query_str = (
                "SELECT b.bid_id FROM bids AS b, bidstates AS s "
                + "WHERE b.active_ind = 1 AND s.state_id = b.state "
                + " AND ((b.state = :accepted_state AND b.expire_at + :respond_grace_period <= :now) "
                + "  OR (s.can_timeout AND b.expire_at + (CASE WHEN EXISTS(SELECT event_id FROM eventlog WHERE linked_type = :event_linked_type AND linked_id = b.bid_id AND event_type = :tx_mempool_event_type) THEN :tx_mempool_grace_period ELSE :tx_grace_period END) <= :now)) "
                + " AND NOT EXISTS(SELECT event_id FROM eventlog WHERE linked_type = :event_linked_type AND linked_id = b.bid_id AND event_type = :tx_sent_event_type)"
            )
            q = cursor.execute(
                query_str,
                {
                    "accepted_state": int(BidStates.BID_ACCEPTED),
                    "now": now,
                    "respond_grace_period": respond_grace_period,
                    "tx_grace_period": tx_grace_period,
                    "tx_mempool_grace_period": tx_mempool_grace_period,
                    "event_linked_type": int(Concepts.BID),
                    "tx_mempool_event_type": EventLogTypes.LOCK_TX_A_IN_MEMPOOL,
                    "tx_sent_event_type": EventLogTypes.LOCK_TX_A_PUBLISHED,
                },
            )
            for row in q:
                bid_id = row[0]
                self.log.info(f"Timing out bid {self.log.id(bid_id)}.")
                self.timeoutBid(bid_id, cursor)

        finally:
            self.closeDB(cursor)

    def countQueuedActions(self, cursor, bid_id: bytes, action_type) -> int:
        query = "SELECT COUNT(*) FROM actions WHERE active_ind = 1 AND linked_id = :linked_id "
        if action_type is not None:
            query += "AND action_type = :action_type"

        q = cursor.execute(
            query, {"linked_id": bid_id, "action_type": action_type}
        ).fetchone()
        return q[0]

    def checkQueuedActions(self) -> None:
        now: int = self.getTime()
        reload_in_progress: bool = False
        try:
            cursor = self.openDB()

            query = "SELECT action_type, linked_id FROM actions WHERE active_ind = 1 AND trigger_at <= :now"
            rows = cursor.execute(query, {"now": now}).fetchall()

            for row in rows:
                action_type, linked_id = row
                accepting_bid: bool = False
                try:
                    if action_type == ActionTypes.ACCEPT_BID:
                        accepting_bid = True
                        self.acceptBid(linked_id, cursor)
                    elif action_type == ActionTypes.ACCEPT_XMR_BID:
                        accepting_bid = True
                        self.acceptXmrBid(linked_id, cursor)
                    elif action_type == ActionTypes.SIGN_XMR_SWAP_LOCK_TX_A:
                        self.sendXmrBidTxnSigsFtoL(linked_id, cursor)
                    elif action_type == ActionTypes.SEND_XMR_SWAP_LOCK_TX_A:
                        self.sendXmrBidCoinALockTx(linked_id, cursor)
                    elif action_type == ActionTypes.SEND_XMR_SWAP_LOCK_TX_B:
                        self.sendXmrBidCoinBLockTx(linked_id, cursor)
                    elif action_type == ActionTypes.SEND_XMR_LOCK_RELEASE:
                        self.sendXmrBidLockRelease(linked_id, cursor)
                    elif action_type == ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_A:
                        self.redeemXmrBidCoinALockTx(linked_id, cursor)
                    elif action_type == ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B:
                        self.redeemXmrBidCoinBLockTx(linked_id, cursor)
                    elif action_type == ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B:
                        self.recoverXmrBidCoinBLockTx(linked_id, cursor)
                    elif action_type == ActionTypes.SEND_XMR_SWAP_LOCK_SPEND_MSG:
                        self.sendXmrBidCoinALockSpendTxMsg(linked_id, cursor)
                    elif action_type == ActionTypes.REDEEM_ITX:
                        atomic_swap_1.redeemITx(self, linked_id, cursor)
                    elif action_type == ActionTypes.ACCEPT_AS_REV_BID:
                        accepting_bid = True
                        self.acceptADSReverseBid(linked_id, cursor)
                    else:
                        self.log.warning(f"Unknown event type: {action_type}")
                except Exception as ex:
                    err_msg = f"checkQueuedActions failed: {ex}"
                    self.logException(err_msg)

                    bid_id = linked_id
                    # Failing to accept a bid should not set an error state as the bid has not begun yet
                    if accepting_bid:
                        self.logEvent(
                            Concepts.BID, bid_id, EventLogTypes.ERROR, err_msg, cursor
                        )

                        # If delaying with no (further) queued actions reset state
                        if self.countQueuedActions(cursor, bid_id, None) < 2:
                            bid, offer = self.getBidAndOffer(bid_id, cursor)
                            last_state = getLastBidState(bid.states)
                            if (
                                bid
                                and bid.state == BidStates.SWAP_DELAYING
                                and canAcceptBidState(last_state)
                            ):
                                new_state = (
                                    BidStates.BID_ERROR
                                    if offer.bid_reversed
                                    else last_state
                                )
                                bid.setState(new_state)
                                self.saveBidInSession(bid_id, bid, cursor)
                    else:
                        bid = self.getBid(bid_id, cursor)
                        if bid:
                            bid.setState(BidStates.BID_ERROR, err_msg)
                            self.saveBidInSession(bid_id, bid, cursor)

            query: str = "DELETE FROM actions WHERE trigger_at <= :now"
            if self.debug:
                query = "UPDATE actions SET active_ind = 2 WHERE trigger_at <= :now"
            cursor.execute(query, {"now": now})

        except Exception as ex:
            self.handleSessionErrors(ex, cursor, "checkQueuedActions")
            reload_in_progress = True
        finally:
            self.closeDB(cursor)

        if reload_in_progress:
            self.loadFromDB()

    def checkSplitMessages(self) -> None:
        # Combines split data messages
        now: int = self.getTime()
        ttl_xmr_split_messages = 60 * 60
        bid_cursor = None
        dleag_proof_len: int = 48893  # coincurve.dleag.dleag_proof_len()
        try:
            cursor = self.openDB()
            bid_cursor = self.getNewDBCursor()
            q_bids = self.query(
                Bid,
                bid_cursor,
                {
                    "state": (
                        int(BidStates.BID_RECEIVING),
                        int(BidStates.BID_RECEIVING_ACC),
                    )
                },
            )
            for bid in q_bids:
                q = cursor.execute(
                    "SELECT LENGTH(kbsl_dleag), LENGTH(kbsf_dleag) FROM xmr_swaps WHERE bid_id = :bid_id",
                    {
                        "bid_id": bid.bid_id,
                    },
                ).fetchone()
                kbsl_dleag_len: int = q[0]
                kbsf_dleag_len: int = q[1]

                if bid.state == int(BidStates.BID_RECEIVING_ACC):
                    bid_type: str = "bid accept"
                    msg_type: int = int(XmrSplitMsgTypes.BID_ACCEPT)
                    total_dleag_size: int = kbsl_dleag_len
                else:
                    bid_type: str = "bid"
                    msg_type: int = int(XmrSplitMsgTypes.BID)
                    total_dleag_size: int = kbsf_dleag_len

                q = cursor.execute(
                    "SELECT COUNT(*), SUM(LENGTH(dleag)) AS total_dleag_size FROM xmr_split_data WHERE bid_id = :bid_id AND msg_type = :msg_type",
                    {"bid_id": bid.bid_id, "msg_type": msg_type},
                ).fetchone()
                total_dleag_size += 0 if q[1] is None else q[1]

                if total_dleag_size >= dleag_proof_len:
                    try:
                        if bid.state == int(BidStates.BID_RECEIVING):
                            self.receiveXmrBid(bid, cursor)
                        elif bid.state == int(BidStates.BID_RECEIVING_ACC):
                            self.receiveXmrBidAccept(bid, cursor)
                        else:
                            raise ValueError("Unexpected bid state")
                    except Exception as ex:
                        self.log.info(
                            f"Verify adaptor-sig {bid_type} {self.log.id(bid.bid_id)} failed: {ex}"
                        )
                        if self.debug:
                            self.log.error(traceback.format_exc())
                        bid.setState(
                            BidStates.BID_ERROR, f"Failed {bid_type} validation: {ex}"
                        )
                        self.updateDB(
                            bid,
                            cursor,
                            [
                                "bid_id",
                            ],
                        )
                        self.updateBidInProgress(bid)
                    continue
                if bid.created_at + ttl_xmr_split_messages < now:
                    self.log.debug(
                        f"Expiring partially received {bid_type}: {self.log.id(bid.bid_id)}."
                    )
                    bid.setState(BidStates.BID_ERROR, "Timed out")
                    self.updateDB(
                        bid,
                        cursor,
                        [
                            "bid_id",
                        ],
                    )
            # Expire old records
            cursor.execute(
                "DELETE FROM xmr_split_data WHERE created_at + :ttl < :now",
                {"ttl": ttl_xmr_split_messages, "now": now},
            )
        finally:
            self.closeDBCursor(bid_cursor)
            self.closeDB(cursor)

    def checkDelayedAutoAccept(self) -> None:
        bids_cursor = None
        try:
            cursor = self.openDB()
            bids_cursor = self.getNewDBCursor()
            for bid in self.query(
                Bid, bids_cursor, {"state": int(BidStates.BID_AACCEPT_DELAY)}
            ):
                offer = self.getOffer(bid.offer_id, cursor=cursor)
                if self.shouldAutoAcceptBid(offer, bid, cursor=cursor):
                    delay = self.get_delay_event_seconds()
                    self.log.info(
                        f"Auto accepting bid {self.log.id(bid.bid_id)} in {delay} seconds."
                    )
                    self.createActionInSession(
                        delay, ActionTypes.ACCEPT_BID, bid.bid_id, cursor
                    )
        finally:
            self.closeDBCursor(bids_cursor)
            self.closeDB(cursor)

    def processOffer(self, msg) -> None:
        offer_bytes = self.getSmsgMsgBytes(msg)

        msg_payload_version = self.getSmsgMsgPayloadVersion(msg)
        offer_data = OfferMessage(init_all=False)
        try:
            offer_data.from_bytes(offer_bytes[:2], init_all=False)
            ensure(
                offer_data.protocol_version >= MINPROTO_VERSION
                and offer_data.protocol_version <= MAXPROTO_VERSION,
                "protocol_version out of range",
            )
        except Exception as e:  # noqa: F841
            self.log.warning(
                "Incoming offer invalid protocol version: {}.".format(
                    getattr(offer_data, "protocol_version", -1)
                )
            )
            return
        try:
            offer_data.from_bytes(offer_bytes)
        except Exception as e:
            self.log.warning(
                "Failed to decode offer, protocol version: {}, {}.".format(
                    getattr(offer_data, "protocol_version", -1), str(e)
                )
            )
            return

        # Validate offer data
        now: int = self.getTime()
        coin_from = Coins(offer_data.coin_from)
        ci_from = self.ci(coin_from)
        coin_to = Coins(offer_data.coin_to)
        ci_to = self.ci(coin_to)
        ensure(offer_data.coin_from != offer_data.coin_to, "coin_from == coin_to")

        self.validateSwapType(coin_from, coin_to, offer_data.swap_type)
        self.validateOfferAmounts(
            coin_from,
            coin_to,
            offer_data.amount_from,
            offer_data.amount_to,
            offer_data.min_bid_amount,
        )
        self.validateOfferLockValue(
            offer_data.swap_type,
            coin_from,
            coin_to,
            offer_data.lock_type,
            offer_data.lock_value,
        )
        self.validateOfferValidTime(
            offer_data.swap_type, coin_from, coin_to, offer_data.time_valid
        )

        if msg["sent"] + offer_data.time_valid < now:
            self.log.debug("Ignoring expired offer.")
            return

        self.validateMessageNets(offer_data.message_nets)

        offer_rate: int = ci_from.make_int(
            offer_data.amount_to / offer_data.amount_from, r=1
        )
        reverse_bid: bool = self.is_reverse_ads_bid(coin_from, coin_to)

        if offer_data.swap_type == SwapTypes.SELLER_FIRST:
            ensure(
                offer_data.protocol_version >= MINPROTO_VERSION_SECRET_HASH,
                "Invalid protocol version",
            )
            ensure(len(offer_data.proof_address) == 0, "Unexpected data")
            ensure(len(offer_data.proof_signature) == 0, "Unexpected data")
            ensure(len(offer_data.pkhash_seller) == 0, "Unexpected data")
            ensure(len(offer_data.secret_hash) == 0, "Unexpected data")
        elif offer_data.swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError("TODO")
        elif offer_data.swap_type == SwapTypes.XMR_SWAP:
            ensure(
                offer_data.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG,
                "Invalid protocol version",
            )
            if reverse_bid:
                ensure(
                    ci_to.has_segwit(),
                    "Coin-to must support segwit for reverse bid offers",
                )
            else:
                ensure(ci_from.has_segwit(), "Coin-from must support segwit")
            ensure(len(offer_data.proof_address) == 0, "Unexpected data")
            ensure(len(offer_data.proof_signature) == 0, "Unexpected data")
            ensure(len(offer_data.pkhash_seller) == 0, "Unexpected data")
            ensure(len(offer_data.secret_hash) == 0, "Unexpected data")
        else:
            raise ValueError("Unknown swap type {}.".format(offer_data.swap_type))

        offer_id = bytes.fromhex(msg["msgid"])

        if self.isOfferRevoked(offer_id, msg["from"]):
            raise ValueError("Offer has been revoked {}.".format(offer_id.hex()))

        pk_from: bytes = getMsgPubkey(self, msg)
        try:
            cursor = self.openDB()
            # Offers must be received on the public network_addr or manually created addresses
            if msg["to"] != self.network_addr:
                # Double check active_ind, shouldn't be possible to receive message if not active
                query_str = "SELECT COUNT(addr_id) FROM smsgaddresses WHERE addr = :addr AND use_type = :use_type AND active_ind = 1"
                rv = cursor.execute(
                    query_str,
                    {"addr": msg["to"], "use_type": int(AddressTypes.RECV_OFFER)},
                ).fetchone()
                if rv[0] < 1:
                    raise ValueError("Offer received on incorrect address")

            # Check for sent
            existing_offer = self.getOffer(offer_id, cursor=cursor)
            if existing_offer is None:
                bid_reversed: bool = (
                    offer_data.swap_type == SwapTypes.XMR_SWAP
                    and self.is_reverse_ads_bid(
                        offer_data.coin_from, offer_data.coin_to
                    )
                )
                offer = Offer(
                    offer_id=offer_id,
                    active_ind=1,
                    protocol_version=offer_data.protocol_version,
                    coin_from=offer_data.coin_from,
                    coin_to=offer_data.coin_to,
                    amount_from=offer_data.amount_from,
                    amount_to=offer_data.amount_to,
                    rate=offer_rate,
                    min_bid_amount=offer_data.min_bid_amount,
                    time_valid=offer_data.time_valid,
                    lock_type=int(offer_data.lock_type),
                    lock_value=offer_data.lock_value,
                    swap_type=offer_data.swap_type,
                    amount_negotiable=offer_data.amount_negotiable,
                    rate_negotiable=offer_data.rate_negotiable,
                    addr_to=msg["to"],
                    addr_from=msg["from"],
                    pk_from=pk_from,
                    created_at=msg["sent"],
                    expire_at=msg["sent"] + offer_data.time_valid,
                    was_sent=False,
                    bid_reversed=bid_reversed,
                    auto_accept_type=(
                        offer_data.auto_accept_type
                        if b"\xa0\x01" in offer_bytes
                        else None
                    ),
                    message_nets=offer_data.message_nets,
                    smsg_payload_version=msg_payload_version,
                )
                offer.setState(OfferStates.OFFER_RECEIVED)
                self.add(offer, cursor)

                if offer.swap_type == SwapTypes.XMR_SWAP:
                    xmr_offer = XmrOffer()

                    xmr_offer.offer_id = offer_id

                    chain_a_ci = ci_to if reverse_bid else ci_from
                    lock_value_2 = offer_data.lock_value
                    if (None, DebugTypes.OFFER_LOCK_2_VALUE_INC) in self._debug_cases:
                        lock_value_2 += 1000
                    xmr_offer.lock_time_1 = chain_a_ci.getExpectedSequence(
                        offer_data.lock_type, offer_data.lock_value
                    )
                    xmr_offer.lock_time_2 = chain_a_ci.getExpectedSequence(
                        offer_data.lock_type, lock_value_2
                    )

                    xmr_offer.a_fee_rate = offer_data.fee_rate_from
                    xmr_offer.b_fee_rate = offer_data.fee_rate_to

                    self.add(xmr_offer, cursor)

                    self.notify(NT.OFFER_RECEIVED, {"offer_id": offer_id.hex()}, cursor)
            else:
                existing_offer.setState(OfferStates.OFFER_RECEIVED)
                existing_offer.pk_from = pk_from
                self.add(existing_offer, cursor, upsert=True)
            received_on_net: str = networkTypeToID(msg.get("type", "smsg"))
            self.addMessageNetworkLink(
                Concepts.OFFER,
                offer_id,
                MessageNetworkLinkTypes.RECEIVED_ON,
                received_on_net,
                cursor,
            )
        finally:
            self.closeDB(cursor)

    def processOfferRevoke(self, msg) -> None:
        ensure(msg["to"] == self.network_addr, "Message received on wrong address")

        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = OfferRevokeMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        now: int = self.getTime()
        try:
            cursor = self.openDB()

            if len(msg_data.offer_msg_id) != 28:
                raise ValueError("Invalid msg_id length")
            if len(msg_data.signature) != 65:
                raise ValueError("Invalid signature length")

            offer = self.getOffer(msg_data.offer_msg_id, cursor=cursor)
            if offer is None:
                self.storeOfferRevoke(msg_data.offer_msg_id, msg_data.signature)

                # Offer may not have been received yet, or involved an inactive coin on this node.
                self.log.debug(
                    f"Offer not found to revoke: {self.log.id(msg_data.offer_msg_id)}."
                )
                return

            if offer.expire_at <= now:
                self.log.debug(
                    f"Offer is already expired, no need to revoke: {self.log.id(msg_data.offer_msg_id)}."
                )
                return

            signature_enc = base64.b64encode(msg_data.signature).decode("UTF-8")

            passed = self.ci(Coins.PART).verifyMessage(
                offer.addr_from, msg_data.offer_msg_id.hex() + "_revoke", signature_enc
            )
            ensure(passed is True, "Signature invalid")

            offer.active_ind = 2
            # TODO: Remove message, or wait for expire

            self.updateDB(
                offer,
                cursor,
                [
                    "offer_id",
                ],
            )
        finally:
            self.closeDB(cursor)

    def getCompletedAndActiveBidsValue(self, offer, cursor):
        bids = []
        total_value: int = 0

        q = cursor.execute(
            """SELECT bid_id, amount, state FROM bids
               JOIN bidstates ON bidstates.state_id = bids.state AND (bidstates.state_id = :state_id OR bidstates.in_progress > 0)
               WHERE bids.active_ind = 1 AND bids.offer_id = :offer_id
               UNION
               SELECT bid_id, amount, state FROM bids
               JOIN actions ON actions.linked_id = bids.bid_id AND actions.active_ind = 1 AND (actions.action_type = :action_type_acc_bid OR actions.action_type = :action_type_acc_adp_bid)
               WHERE bids.active_ind = 1 AND bids.offer_id = :offer_id
            """,
            {
                "state_id": int(BidStates.SWAP_COMPLETED),
                "offer_id": offer.offer_id,
                "action_type_acc_bid": int(ActionTypes.ACCEPT_BID),
                "action_type_acc_adp_bid": int(ActionTypes.ACCEPT_XMR_BID),
            },
        )
        for row in q:
            bid_id, amount, state = row
            bids.append((bid_id, amount, state))
            total_value += amount
        return bids, total_value

    def evaluateKnownIdentityForAutoAccept(self, strategy, identity_stats) -> bool:
        if identity_stats:
            if (
                identity_stats.automation_override
                == AutomationOverrideOptions.NEVER_ACCEPT
            ):
                raise AutomationConstraint("From address is marked never accept")
            if (
                identity_stats.automation_override
                == AutomationOverrideOptions.ALWAYS_ACCEPT
            ):
                return True

        if strategy.only_known_identities:
            if not identity_stats:
                raise AutomationConstraint("Unknown bidder")

            # TODO: More options
            if identity_stats.num_recv_bids_successful < 1:
                raise AutomationConstraint("Bidder has too few successful swaps")
            if (
                identity_stats.num_recv_bids_successful
                <= identity_stats.num_recv_bids_failed
            ):
                raise AutomationConstraint("Bidder has too many failed swaps")
        return True

    def shouldAutoAcceptBid(self, offer, bid, cursor=None, options={}) -> bool:
        try:
            use_cursor = self.openDB(cursor)

            if self.countQueuedActions(use_cursor, bid.bid_id, ActionTypes.ACCEPT_BID):
                # Bid is already queued to be accepted
                return False

            link = self.queryOne(
                AutomationLink,
                use_cursor,
                {
                    "active_ind": 1,
                    "linked_type": int(Concepts.OFFER),
                    "linked_id": offer.offer_id,
                },
            )
            if link is None:
                return False

            strategy = self.queryOne(
                AutomationStrategy,
                use_cursor,
                {"active_ind": 1, "record_id": link.strategy_id},
            )
            opts = json.loads(strategy.data.decode("UTF-8"))

            bid_amount: int = bid.amount
            bid_rate: int = bid.rate

            if options.get("reverse_bid", False):
                bid_amount = bid.amount_to
                bid_rate = options.get("bid_rate")

            self.log.debug(f"Evaluating against strategy {strategy.record_id}.")

            now: int = self.getTime()
            if bid.expire_at < now:
                raise AutomationConstraint(
                    "Bid expired"
                )  # State will be set to expired in expireBidsAndOffers

            if not offer.amount_negotiable:
                if bid_amount != offer.amount_from:
                    raise AutomationConstraint("Need exact amount match")

            if bid_amount < offer.min_bid_amount:
                raise AutomationConstraint("Bid amount below offer minimum")

            if opts.get("exact_rate_only", False) is True:
                if not self.ratesMatch(bid_rate, offer.rate, offer.rate):
                    raise AutomationConstraint("Rate outside acceptable tolerance")

            active_bids, total_bids_value = self.getCompletedAndActiveBidsValue(
                offer, use_cursor
            )

            total_bids_value_multiplier = opts.get("total_bids_value_multiplier", 1.0)
            if total_bids_value_multiplier > 0.0:
                if (
                    total_bids_value + bid_amount
                    > offer.amount_from * total_bids_value_multiplier
                ):
                    raise AutomationConstraint(
                        "Over remaining offer value {}".format(
                            offer.amount_from * total_bids_value_multiplier
                            - total_bids_value
                        )
                    )

            num_not_completed = 0
            for active_bid in active_bids:
                if active_bid[2] != BidStates.SWAP_COMPLETED:
                    num_not_completed += 1
            max_concurrent_bids = opts.get("max_concurrent_bids", 1)
            self.log.debug(
                f"active_bids {num_not_completed}, max_concurrent_bids {max_concurrent_bids}."
            )
            if num_not_completed >= max_concurrent_bids:
                raise AutomationConstraintTemporary(
                    f"Already have {num_not_completed} bids to complete"
                )

            identity_stats = self.queryOne(
                KnownIdentity, use_cursor, {"address": bid.bid_addr}
            )
            self.evaluateKnownIdentityForAutoAccept(strategy, identity_stats)

            # Ensure the coin from wallet has sufficient balance for multiple bids
            bids_active_if_accepted: int = num_not_completed + 1

            ci_from = self.ci(offer.coin_from)
            try:
                ci_from.ensureFunds(bids_active_if_accepted * bid_amount)
            except Exception as e:  # noqa: F841
                raise AutomationConstraintTemporary("Balance too low")

            self.logEvent(
                Concepts.BID,
                bid.bid_id,
                EventLogTypes.AUTOMATION_ACCEPTING_BID,
                "",
                use_cursor,
            )

            return True
        except (AutomationConstraint, AutomationConstraintTemporary) as e:
            self.log.info(f"Not auto accepting bid {self.log.id(bid.bid_id)}, {e}.")
            if self.debug:
                self.logEvent(
                    Concepts.BID,
                    bid.bid_id,
                    EventLogTypes.AUTOMATION_CONSTRAINT,
                    str(e),
                    use_cursor,
                )

            if isinstance(e, AutomationConstraintTemporary):
                bid.setState(BidStates.BID_AACCEPT_DELAY)
            else:
                bid.setState(BidStates.BID_AACCEPT_FAIL)
            self.updateDB(
                bid,
                use_cursor,
                [
                    "bid_id",
                ],
            )

            return False
        except Exception as e:
            self.logException(f"shouldAutoAcceptBid {e}")
            return False
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def addRecvBidNetworkLink(self, msg, bid_id, cursor=None):
        if "chat_type" not in msg or msg["chat_type"] != "direct":
            return
        conn_id = msg["conn_id"]
        query_str = (
            "SELECT record_id, network_id, route_data FROM direct_message_routes"
        )
        try:
            use_cursor = self.openDB(cursor)
            rows = use_cursor.execute(query_str).fetchall()

            for row in rows:
                record_id, network_id, route_data = row
                route_data = json.loads(route_data.decode("UTF-8"))

                if conn_id == route_data["pccConnId"]:
                    message_route_link = DirectMessageRouteLink(
                        active_ind=2,
                        direct_message_route_id=record_id,
                        linked_type=Concepts.BID,
                        linked_id=bid_id,
                        created_at=self.getTime(),
                    )
                    self.add(message_route_link, use_cursor)
                    break
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def processBid(self, msg) -> None:
        self.log.debug("Processing bid msg {}.".format(self.log.id(msg["msgid"])))
        now: int = self.getTime()
        bid_bytes = self.getSmsgMsgBytes(msg)
        bid_data = BidMessage(init_all=False)
        bid_data.from_bytes(bid_bytes)

        # Validate bid data
        ensure(
            bid_data.protocol_version >= MINPROTO_VERSION_SECRET_HASH,
            "Invalid protocol version",
        )
        ensure(len(bid_data.offer_msg_id) == 28, "Bad offer_id length")

        offer_id = bid_data.offer_msg_id
        offer = self.getOffer(offer_id)
        ensure(offer and offer.was_sent, "Unknown offer")

        ensure(offer.state == OfferStates.OFFER_RECEIVED, "Bad offer state")
        ensure(msg["to"] == offer.addr_from, "Received on incorrect address")
        ensure(now <= offer.expire_at, "Offer expired")
        self.validateBidValidTime(
            offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid
        )
        ensure(now <= msg["sent"] + bid_data.time_valid, "Bid expired")

        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(coin_to)
        bid_rate: int = ci_from.make_int(bid_data.amount_to / bid_data.amount, r=1)
        self.validateBidAmount(offer, bid_data.amount, bid_rate)

        self.validateMessageNets(bid_data.message_nets)

        network_type: str = msg.get("msg_net", "smsg")
        network_type_received_on_id: int = networkTypeToID(network_type)
        bid_message_nets: str = self.selectMessageNetString(
            [
                network_type_received_on_id,
            ],
            bid_data.message_nets,
        )
        self.logD(
            LC.NET,
            f"processBid offer.message_nets {offer.message_nets}, bid.message_nets {bid_message_nets}, bid_data.message_nets {bid_data.message_nets}",
        )
        # TODO: Allow higher bids
        # assert (bid_data.rate != offer['data'].rate), 'Bid rate mismatch'

        swap_type = offer.swap_type
        if swap_type == SwapTypes.SELLER_FIRST:
            ensure(len(bid_data.pkhash_buyer) == 20, "Bad pkhash_buyer length")

            proof_utxos = ci_to.decodeProofUtxos(bid_data.proof_utxos)
            sum_unspent = ci_to.verifyProofOfFunds(
                bid_data.proof_address, bid_data.proof_signature, proof_utxos, offer_id
            )
            self.log.debug(
                "Proof of funds {} {}.".format(
                    bid_data.proof_address, self.ci(coin_to).format_amount(sum_unspent)
                )
            )
            ensure(sum_unspent >= bid_data.amount_to, "Proof of funds failed")

        elif swap_type == SwapTypes.BUYER_FIRST:
            raise ValueError("TODO")
        else:
            raise ValueError("Unknown swap type {}.".format(swap_type))

        bid_id = bytes.fromhex(msg["msgid"])

        bid = self.getBid(bid_id)
        pk_from: bytes = getMsgPubkey(self, msg)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                protocol_version=bid_data.protocol_version,
                amount=bid_data.amount,
                amount_to=bid_data.amount_to,
                rate=bid_rate,
                pkhash_buyer=bid_data.pkhash_buyer,
                proof_address=bid_data.proof_address,
                proof_utxos=bid_data.proof_utxos,
                created_at=msg["sent"],
                expire_at=msg["sent"] + bid_data.time_valid,
                bid_addr=msg["from"],
                pk_bid_addr=pk_from,
                was_received=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
                message_nets=bid_message_nets,
            )

            if len(bid_data.pkhash_buyer_to) > 0:
                bid.pkhash_buyer_to = bid_data.pkhash_buyer_to
        else:
            ensure(
                bid.state == BidStates.BID_SENT,
                "Wrong bid state: {}".format(BidStates(bid.state).name),
            )
            bid.created_at = msg["sent"]
            bid.expire_at = msg["sent"] + bid_data.time_valid
            bid.pk_bid_addr = pk_from
            bid.was_received = True
        if len(bid_data.proof_address) > 0:
            bid.proof_address = bid_data.proof_address

        bid.setState(BidStates.BID_RECEIVED)
        try:
            cursor = self.openDB()
            self.addRecvBidNetworkLink(msg, bid_id, cursor)
            self.saveBidInSession(bid_id, bid, cursor)
            received_on_net: str = networkTypeToID(msg.get("type", "smsg"))
            self.addMessageNetworkLink(
                Concepts.BID,
                offer_id,
                MessageNetworkLinkTypes.RECEIVED_ON,
                received_on_net,
                cursor,
            )
        finally:
            self.closeDB(cursor)

        self.notify(
            NT.BID_RECEIVED,
            {
                "type": "secrethash",
                "bid_id": bid_id.hex(),
                "offer_id": bid_data.offer_msg_id.hex(),
            },
        )

        if self.shouldAutoAcceptBid(offer, bid):
            delay = self.get_delay_event_seconds()
            self.log.info(
                f"Auto accepting bid {self.log.id(bid_id)} in {delay} seconds."
            )
            self.createAction(delay, ActionTypes.ACCEPT_BID, bid_id)

    def processBidAccept(self, msg) -> None:
        self.log.debug(
            "Processing bid accepted msg {}".format(self.log.id(msg["msgid"]))
        )
        now: int = self.getTime()
        bid_accept_bytes = self.getSmsgMsgBytes(msg)
        bid_accept_data = BidAcceptMessage(init_all=False)
        bid_accept_data.from_bytes(bid_accept_bytes)

        ensure(len(bid_accept_data.bid_msg_id) == 28, "Bad bid_msg_id length")
        ensure(len(bid_accept_data.initiate_txid) == 32, "Bad initiate_txid length")
        ensure(len(bid_accept_data.contract_script) < 100, "Bad contract_script length")

        self.log.debug(f"for bid {self.log.id(bid_accept_data.bid_msg_id)}.")

        bid_id: bytes = bid_accept_data.bid_msg_id
        bid, offer = self.getBidAndOffer(bid_id)
        ensure(bid is not None and bid.was_sent is True, "Unknown bid_id")
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")

        ensure(bid.expire_at > now + self._bid_expired_leeway, "Bid expired")
        ensure(msg["to"] == bid.bid_addr, "Received on incorrect address")
        ensure(msg["from"] == offer.addr_from, "Sent from incorrect address")

        coin_from = Coins(offer.coin_from)
        ci_from = self.ci(coin_from)

        if bid.state >= BidStates.BID_ACCEPTED:
            if bid.was_received:  # Sent to self
                accept_msg_id: bytes = self.getLinkedMessageId(
                    Concepts.BID, bid_id, MessageTypes.BID_ACCEPT
                )

                self.log.info(
                    f"Received valid bid accept {self.logIDM(accept_msg_id)} for bid {self.log.id(bid_id)} sent to self."
                )
                return
            raise ValueError("Wrong bid state: {}".format(BidStates(bid.state).name))

        use_csv = True if offer.lock_type < TxLockTypes.ABS_LOCK_BLOCKS else False

        if coin_from in (Coins.DCR,):
            op_hash = OpCodes.OP_SHA256_DECRED
        else:
            op_hash = OpCodes.OP_SHA256
        op_lock = (
            OpCodes.OP_CHECKSEQUENCEVERIFY
            if use_csv
            else OpCodes.OP_CHECKLOCKTIMEVERIFY
        )
        script_valid, script_hash, script_pkhash1, script_lock_val, script_pkhash2 = (
            atomic_swap_1.verifyContractScript(
                bid_accept_data.contract_script, op_lock=op_lock, op_hash=op_hash
            )
        )
        if not script_valid:
            raise ValueError("Bad script")

        ensure(script_pkhash1 == bid.pkhash_buyer, "pkhash_buyer mismatch")

        if use_csv:
            expect_sequence = ci_from.getExpectedSequence(
                offer.lock_type, offer.lock_value
            )
            ensure(script_lock_val == expect_sequence, "sequence mismatch")
        else:
            if offer.lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
                block_header_from = ci_from.getBlockHeaderAt(now)
                chain_height_at_bid_creation = block_header_from["height"]
                ensure(
                    script_lock_val
                    <= chain_height_at_bid_creation
                    + offer.lock_value
                    + atomic_swap_1.ABS_LOCK_BLOCKS_LEEWAY,
                    "script lock height too high",
                )
                ensure(
                    script_lock_val
                    >= chain_height_at_bid_creation
                    + offer.lock_value
                    - atomic_swap_1.ABS_LOCK_BLOCKS_LEEWAY,
                    "script lock height too low",
                )
            else:
                ensure(
                    script_lock_val
                    <= now + offer.lock_value + atomic_swap_1.INITIATE_TX_TIMEOUT,
                    "script lock time too high",
                )
                ensure(
                    script_lock_val
                    >= now + offer.lock_value - atomic_swap_1.ABS_LOCK_TIME_LEEWAY,
                    "script lock time too low",
                )

        ensure(
            self.countMessageLinks(Concepts.BID, bid_id, MessageTypes.BID_ACCEPT) == 0,
            "Bid already accepted",
        )

        bid_accept_msg_id = bytes.fromhex(msg["msgid"])
        self.addMessageLink(
            Concepts.BID, bid_id, MessageTypes.BID_ACCEPT, bid_accept_msg_id
        )

        bid.initiate_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.ITX,
            txid=bid_accept_data.initiate_txid,
            script=bid_accept_data.contract_script,
        )

        if len(bid_accept_data.pkhash_seller) == 20:
            bid.pkhash_seller = bid_accept_data.pkhash_seller
        else:
            bid.pkhash_seller = script_pkhash2

        bid.setState(BidStates.BID_ACCEPTED)
        bid.setITxState(TxStates.TX_NONE)

        bid.offer_id.hex()

        self.saveBid(bid_id, bid)
        self.swaps_in_progress[bid_id] = (bid, offer)
        self.notify(NT.BID_ACCEPTED, {"bid_id": bid_id.hex()})

    def receiveXmrBid(self, bid, cursor) -> None:
        self.log.debug(f"Receiving adaptor-sig bid {self.log.id(bid.bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")

        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")
        xmr_swap = self.queryOne(XmrSwap, cursor, {"bid_id": bid.bid_id})
        ensure(xmr_swap, "Adaptor-sig swap not found: {}.".format(bid.bid_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        addr_expect_from: str = ""
        if reverse_bid:
            ci_from = self.ci(Coins(offer.coin_to))
            ci_to = self.ci(Coins(offer.coin_from))
            addr_expect_from = bid.bid_addr
            addr_expect_to = offer.addr_from
        else:
            ensure(offer.was_sent, "Offer not sent: {}.".format(bid.offer_id.hex()))
            ci_from = self.ci(Coins(offer.coin_from))
            ci_to = self.ci(Coins(offer.coin_to))
            addr_expect_from = offer.addr_from
            addr_expect_to = bid.bid_addr

        if ci_to.curve_type() == Curves.ed25519:
            if len(xmr_swap.kbsf_dleag) < ci_to.lengthDLEAG():
                q = self.query(
                    XmrSplitData,
                    cursor,
                    {"bid_id": bid.bid_id, "msg_type": int(XmrSplitMsgTypes.BID)},
                    {"msg_sequence": "asc"},
                )
                for row in q:
                    ensure(
                        row.addr_to == addr_expect_from,
                        "Received on incorrect address, segment_id {}".format(
                            row.record_id
                        ),
                    )
                    ensure(
                        row.addr_from == addr_expect_to,
                        "Sent from incorrect address, segment_id {}".format(
                            row.record_id
                        ),
                    )
                    xmr_swap.kbsf_dleag += row.dleag

            if not ci_to.verifyDLEAG(xmr_swap.kbsf_dleag):
                raise ValueError("Invalid DLEAG proof.")

            # Extract pubkeys from MSG1L DLEAG
            xmr_swap.pkasf = xmr_swap.kbsf_dleag[0:33]
            if not ci_from.verifyPubkey(xmr_swap.pkasf):
                raise ValueError("Invalid coin a pubkey.")
            xmr_swap.pkbsf = xmr_swap.kbsf_dleag[33 : 33 + 32]
            if not ci_to.verifyPubkey(xmr_swap.pkbsf):
                raise ValueError("Invalid coin b pubkey.")
        elif ci_to.curve_type() == Curves.secp256k1:
            xmr_swap.pkasf = ci_to.verifySigAndRecover(
                xmr_swap.kbsf_dleag, "proof kbsf owned for swap"
            )
            if not ci_from.verifyPubkey(xmr_swap.pkasf):
                raise ValueError("Invalid coin a pubkey.")
            xmr_swap.pkbsf = xmr_swap.pkasf
        else:
            raise ValueError("Unknown curve")

        ensure(ci_to.verifyKey(xmr_swap.vkbvf), "Invalid key, vkbvf")
        ensure(ci_from.verifyPubkey(xmr_swap.pkaf), "Invalid pubkey, pkaf")

        if not reverse_bid:  # notify already ran in processADSBidReversed
            self.notify(
                NT.BID_RECEIVED,
                {
                    "type": "ads",
                    "bid_id": bid.bid_id.hex(),
                    "offer_id": bid.offer_id.hex(),
                },
                cursor,
            )

        bid.setState(BidStates.BID_RECEIVED)

        if reverse_bid or self.shouldAutoAcceptBid(offer, bid, cursor):
            delay = self.get_delay_event_seconds()
            self.log.info(
                "Auto accepting {}adaptor-sig bid {} in {} seconds.".format(
                    "reverse " if reverse_bid else "", self.log.id(bid.bid_id), delay
                )
            )
            self.createActionInSession(
                delay, ActionTypes.ACCEPT_XMR_BID, bid.bid_id, cursor
            )
            bid.setState(BidStates.SWAP_DELAYING)

        self.saveBidInSession(bid.bid_id, bid, cursor, xmr_swap)

    def receiveXmrBidAccept(self, bid, cursor) -> None:
        # Follower receiving MSG1F and MSG2F
        self.log.debug(f"Receiving adaptor-sig bid accept {self.log.id(bid.bid_id)}.")

        offer, xmr_offer = self.getXmrOffer(bid.offer_id, cursor=cursor)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")
        xmr_swap = self.queryOne(XmrSwap, cursor, {"bid_id": bid.bid_id})
        ensure(xmr_swap, "Adaptor-sig swap not found: {}.".format(bid.bid_id.hex()))

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)
        addr_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_to: str = offer.addr_from if reverse_bid else bid.bid_addr

        if ci_to.curve_type() == Curves.ed25519:
            if len(xmr_swap.kbsl_dleag) < ci_to.lengthDLEAG():
                q = self.query(
                    XmrSplitData,
                    cursor,
                    {
                        "bid_id": bid.bid_id,
                        "msg_type": int(XmrSplitMsgTypes.BID_ACCEPT),
                    },
                    order_by={"msg_sequence": "asc"},
                )
                for row in q:
                    ensure(
                        row.addr_to == addr_to,
                        "Received on incorrect address, segment_id {}".format(
                            row.record_id
                        ),
                    )
                    ensure(
                        row.addr_from == addr_from,
                        "Sent from incorrect address, segment_id {}".format(
                            row.record_id
                        ),
                    )
                    xmr_swap.kbsl_dleag += row.dleag
            if not ci_to.verifyDLEAG(xmr_swap.kbsl_dleag):
                raise ValueError("Invalid DLEAG proof.")

            # Extract pubkeys from MSG1F DLEAG
            xmr_swap.pkasl = xmr_swap.kbsl_dleag[0:33]
            if not ci_from.verifyPubkey(xmr_swap.pkasl):
                raise ValueError("Invalid coin a pubkey.")
            xmr_swap.pkbsl = xmr_swap.kbsl_dleag[33 : 33 + 32]
            if not ci_to.verifyPubkey(xmr_swap.pkbsl):
                raise ValueError("Invalid coin b pubkey.")
        elif ci_to.curve_type() == Curves.secp256k1:
            xmr_swap.pkasl = ci_to.verifySigAndRecover(
                xmr_swap.kbsl_dleag, "proof kbsl owned for swap"
            )
            if not ci_from.verifyPubkey(xmr_swap.pkasl):
                raise ValueError("Invalid coin a pubkey.")
            xmr_swap.pkbsl = xmr_swap.pkasl
        else:
            raise ValueError("Unknown curve")

        # vkbv and vkbvl are verified in processXmrBidAccept
        xmr_swap.pkbv = ci_to.sumPubkeys(xmr_swap.pkbvl, xmr_swap.pkbvf)
        xmr_swap.pkbs = ci_to.sumPubkeys(xmr_swap.pkbsl, xmr_swap.pkbsf)

        if not ci_from.verifyPubkey(xmr_swap.pkal):
            raise ValueError("Invalid pubkey.")

        if xmr_swap.pkbvl == xmr_swap.pkbvf:
            raise ValueError("Duplicate scriptless view pubkey.")
        if xmr_swap.pkbsl == xmr_swap.pkbsf:
            raise ValueError("Duplicate scriptless spend pubkey.")
        if xmr_swap.pkal == xmr_swap.pkaf:
            raise ValueError("Duplicate script spend pubkey.")

        bid.setState(BidStates.BID_ACCEPTED)  # ADS
        self.saveBidInSession(bid.bid_id, bid, cursor, xmr_swap)

        if reverse_bid is False:
            self.notify(NT.BID_ACCEPTED, {"bid_id": bid.bid_id.hex()}, cursor)

        delay = self.get_delay_event_seconds()
        self.log.info(
            f"Responding to adaptor-sig bid accept {self.log.id(bid.bid_id)} in {delay} seconds."
        )
        self.createActionInSession(
            delay, ActionTypes.SIGN_XMR_SWAP_LOCK_TX_A, bid.bid_id, cursor
        )

    def processXmrBid(self, msg) -> None:
        # MSG1L
        self.log.debug(
            "Processing adaptor-sig bid msg {}".format(self.log.id(msg["msgid"]))
        )
        now: int = self.getTime()
        bid_bytes = self.getSmsgMsgBytes(msg)
        bid_data = XmrBidMessage(init_all=False)
        bid_data.from_bytes(bid_bytes)

        # Validate data
        ensure(
            bid_data.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG,
            "Invalid protocol version",
        )
        ensure(len(bid_data.offer_msg_id) == 28, "Bad offer_id length")

        offer_id = bid_data.offer_msg_id
        offer, xmr_offer = self.getXmrOffer(offer_id)
        ensure(offer and offer.was_sent, f"Offer not found: {self.log.id(offer_id)}.")
        ensure(offer.swap_type == SwapTypes.XMR_SWAP, "Bid/offer swap type mismatch")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(offer_id)}.")

        ci_from = self.ci(offer.coin_from)
        ci_to = self.ci(offer.coin_to)

        if not validOfferStateToReceiveBid(offer.state):
            raise ValueError("Bad offer state")
        ensure(msg["to"] == offer.addr_from, "Received on incorrect address")
        ensure(now <= offer.expire_at, "Offer expired")
        self.validateBidValidTime(
            offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid
        )
        ensure(now <= msg["sent"] + bid_data.time_valid, "Bid expired")

        bid_rate: int = ci_from.make_int(bid_data.amount_to / bid_data.amount, r=1)
        self.validateBidAmount(offer, bid_data.amount, bid_rate)

        ensure(ci_to.verifyKey(bid_data.kbvf), "Invalid chain B follower view key")
        ensure(
            ci_from.verifyPubkey(bid_data.pkaf), "Invalid chain A follower public key"
        )
        ensure(
            ci_from.isValidAddressHash(bid_data.dest_af)
            or ci_from.isValidPubkey(bid_data.dest_af),
            "Invalid destination address",
        )

        if ci_to.curve_type() == Curves.ed25519:
            ensure(len(bid_data.kbsf_dleag) <= 16000, "Invalid kbsf_dleag size")

        self.validateMessageNets(bid_data.message_nets)

        bid_id = bytes.fromhex(msg["msgid"])

        network_type: str = msg.get("msg_net", "smsg")
        network_type_received_on_id: int = networkTypeToID(network_type)
        bid_message_nets: str = self.selectMessageNetString(
            [
                network_type_received_on_id,
            ],
            bid_data.message_nets,
        )
        self.logD(
            LC.NET,
            f"processXmrBid offer.message_nets {offer.message_nets}, bid.message_nets {bid_message_nets}, bid_data.message_nets {bid_data.message_nets}",
        )

        bid, xmr_swap = self.getXmrBid(bid_id)
        pk_from: bytes = getMsgPubkey(self, msg)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                protocol_version=bid_data.protocol_version,
                amount=bid_data.amount,
                amount_to=bid_data.amount_to,
                rate=bid_rate,
                created_at=msg["sent"],
                expire_at=msg["sent"] + bid_data.time_valid,
                bid_addr=msg["from"],
                pk_bid_addr=pk_from,
                was_received=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
                message_nets=bid_message_nets,
            )

            xmr_swap = XmrSwap(
                bid_id=bid_id,
                dest_af=bid_data.dest_af,
                pkaf=bid_data.pkaf,
                vkbvf=bid_data.kbvf,
                pkbvf=ci_to.getPubkey(bid_data.kbvf),
                kbsf_dleag=bid_data.kbsf_dleag,
            )
            self.setMsgSplitInfo(xmr_swap)
            wallet_restore_height = self.getWalletRestoreHeight(ci_to)
            if bid.chain_b_height_start < wallet_restore_height:
                bid.chain_b_height_start = wallet_restore_height
                self.log.warning(
                    f"Adaptor-sig swap restore height clamped to {wallet_restore_height}."
                )
        else:
            ensure(
                bid.state == BidStates.BID_SENT,
                "Wrong bid state: {}".format(BidStates(bid.state).name),
            )
            # Don't update bid.created_at, it's been used to derive kaf
            bid.expire_at = msg["sent"] + bid_data.time_valid
            bid.pk_bid_addr = pk_from
            bid.was_received = True

        bid.setState(BidStates.BID_RECEIVING)

        self.log.info(
            f"Receiving adaptor-sig bid {self.log.id(bid_id)} for offer {self.log.id(bid_data.offer_msg_id)}."
        )
        try:
            cursor = self.openDB()
            self.addRecvBidNetworkLink(msg, bid_id, cursor)
            self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
            received_on_net: str = networkTypeToID(msg.get("type", "smsg"))
            self.addMessageNetworkLink(
                Concepts.BID,
                offer_id,
                MessageNetworkLinkTypes.RECEIVED_ON,
                received_on_net,
                cursor,
            )
            if ci_to.curve_type() != Curves.ed25519:
                self.receiveXmrBid(bid, cursor)
        finally:
            self.closeDB(cursor)

    def processXmrBidAccept(self, msg) -> None:
        # F receiving MSG1F and MSG2F
        self.log.debug(
            "Processing adaptor-sig bid accept msg {}.".format(
                self.log.id(msg["msgid"])
            )
        )

        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = XmrBidAcceptMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, "Bad bid_msg_id length")

        self.log.debug(f"for bid {self.log.id(msg_data.bid_msg_id)}.")
        bid, xmr_swap = self.getXmrBid(msg_data.bid_msg_id)
        ensure(bid, f"Bid not found: {self.log.id(msg_data.bid_msg_id)}.")
        ensure(
            xmr_swap,
            f"Adaptor-sig swap not found: {self.log.id(msg_data.bid_msg_id)}.",
        )

        offer, xmr_offer = self.getXmrOffer(bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)
        addr_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_to: str = offer.addr_from if reverse_bid else bid.bid_addr
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate

        ensure(msg["to"] == addr_to, "Received on incorrect address")
        ensure(msg["from"] == addr_from, "Sent from incorrect address")

        try:
            xmr_swap.pkal = msg_data.pkal
            xmr_swap.vkbvl = msg_data.kbvl
            ensure(ci_to.verifyKey(xmr_swap.vkbvl), "Invalid key, vkbvl")
            xmr_swap.vkbv = ci_to.sumKeys(xmr_swap.vkbvl, xmr_swap.vkbvf)
            ensure(ci_to.verifyKey(xmr_swap.vkbv), "Invalid key, vkbv")

            xmr_swap.pkbvl = ci_to.getPubkey(msg_data.kbvl)
            xmr_swap.kbsl_dleag = msg_data.kbsl_dleag

            xmr_swap.a_lock_tx = msg_data.a_lock_tx
            xmr_swap.a_lock_tx_script = msg_data.a_lock_tx_script
            xmr_swap.a_lock_refund_tx = msg_data.a_lock_refund_tx
            xmr_swap.a_lock_refund_tx_script = msg_data.a_lock_refund_tx_script
            xmr_swap.a_lock_refund_spend_tx = msg_data.a_lock_refund_spend_tx
            xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxid(
                xmr_swap.a_lock_refund_spend_tx
            )
            xmr_swap.al_lock_refund_tx_sig = msg_data.al_lock_refund_tx_sig

            refundExtraArgs = dict()
            lockExtraArgs = dict()
            if self.isBchXmrSwap(offer):
                # perform check that both lock and refund transactions have their outs pointing to correct follower address
                # and prepare extra args for validation

                bch_ci = self.ci(Coins.BCH)

                mining_fee, out_1, out_2, public_key, timelock = (
                    bch_ci.extractScriptLockScriptValues(xmr_swap.a_lock_tx_script)
                )
                ensure(
                    out_1 == bch_ci.getScriptForPubkeyHash(xmr_swap.dest_af),
                    "Invalid BCH lock tx script out_1",
                )
                ensure(
                    out_2
                    == bch_ci.scriptToP2SH32LockingBytecode(
                        xmr_swap.a_lock_refund_tx_script
                    ),
                    "Invalid BCH lock tx script out_2",
                )

                lockExtraArgs["mining_fee"] = mining_fee
                lockExtraArgs["out_1"] = out_1
                lockExtraArgs["out_2"] = out_2
                lockExtraArgs["public_key"] = public_key
                lockExtraArgs["timelock"] = timelock

                mining_fee, out_1, out_2, public_key, timelock = (
                    bch_ci.extractScriptLockScriptValues(
                        xmr_swap.a_lock_refund_tx_script
                    )
                )
                ensure(
                    out_2 == bch_ci.getScriptForPubkeyHash(xmr_swap.dest_af),
                    "Invalid BCH refund tx script out_2",
                )

                refundExtraArgs["mining_fee"] = mining_fee
                refundExtraArgs["out_1"] = out_1
                refundExtraArgs["out_2"] = out_2
                refundExtraArgs["public_key"] = public_key
                refundExtraArgs["timelock"] = timelock

            # TODO: check_lock_tx_inputs without txindex
            check_a_lock_tx_inputs = False
            xmr_swap.a_lock_tx_id, xmr_swap.a_lock_tx_vout = ci_from.verifySCLockTx(
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_tx_script,
                bid.amount,
                xmr_swap.pkal,
                xmr_swap.pkaf,
                a_fee_rate,
                check_a_lock_tx_inputs,
                xmr_swap.vkbv,
                **lockExtraArgs,
            )

            (
                xmr_swap.a_lock_refund_tx_id,
                xmr_swap.a_swap_refund_value,
                lock_refund_vout,
            ) = ci_from.verifySCLockRefundTx(
                xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_refund_tx_script,
                xmr_swap.a_lock_tx_id,
                xmr_swap.a_lock_tx_vout,
                xmr_offer.lock_time_1,
                xmr_swap.a_lock_tx_script,
                xmr_swap.pkal,
                xmr_swap.pkaf,
                xmr_offer.lock_time_2,
                bid.amount,
                a_fee_rate,
                xmr_swap.vkbv,
                **refundExtraArgs,
            )

            ci_from.verifySCLockRefundSpendTx(
                xmr_swap.a_lock_refund_spend_tx,
                xmr_swap.a_lock_refund_tx,
                xmr_swap.a_lock_refund_tx_id,
                xmr_swap.a_lock_refund_tx_script,
                xmr_swap.pkal,
                lock_refund_vout,
                xmr_swap.a_swap_refund_value,
                a_fee_rate,
                xmr_swap.vkbv,
                **refundExtraArgs,
            )

            self.log.info("Checking leader's lock refund tx signature.")
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            v = ci_from.verifyTxSig(
                xmr_swap.a_lock_refund_tx,
                xmr_swap.al_lock_refund_tx_sig,
                xmr_swap.pkal,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )
            ensure(v, "Invalid coin A lock refund tx leader sig")

            allowed_states = [
                BidStates.BID_SENT,
                BidStates.BID_RECEIVED,
                BidStates.BID_REQUEST_ACCEPTED,
            ]
            if bid.was_sent and offer.was_sent:
                allowed_states.append(
                    BidStates.BID_ACCEPTED
                )  # TODO: Split BID_ACCEPTED into received and sent
            ensure(
                bid.state in allowed_states,
                f"Invalid state for bid {bid.state}",
            )
            bid.setState(BidStates.BID_RECEIVING_ACC)
            self.saveBid(bid.bid_id, bid, xmr_swap=xmr_swap)

            if ci_to.curve_type() != Curves.ed25519:
                try:
                    cursor = self.openDB()
                    self.receiveXmrBidAccept(bid, cursor)
                finally:
                    self.closeDB(cursor)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid.bid_id, bid, str(ex), xmr_swap=xmr_swap)

    def watchXmrSwap(self, bid, offer, xmr_swap, cursor=None) -> None:
        self.log.debug(f"Adaptor-sig swap in progress, bid {self.log.id(bid.bid_id)}.")
        self.swaps_in_progress[bid.bid_id] = (bid, offer)

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        self.setLastHeightCheckedStart(coin_from, bid.chain_a_height_start, cursor)

        if bid.xmr_a_lock_tx and bid.xmr_a_lock_tx.txid:
            self.addWatchedOutput(
                coin_from,
                bid.bid_id,
                bid.xmr_a_lock_tx.txid.hex(),
                bid.xmr_a_lock_tx.vout,
                TxTypes.XMR_SWAP_A_LOCK,
                SwapTypes.XMR_SWAP,
            )

        if xmr_swap.a_lock_refund_tx_id:
            lock_refund_vout = self.ci(coin_from).getLockRefundTxSwapOutput(xmr_swap)
            self.addWatchedOutput(
                coin_from,
                bid.bid_id,
                xmr_swap.a_lock_refund_tx_id.hex(),
                lock_refund_vout,
                TxTypes.XMR_SWAP_A_LOCK_REFUND,
                SwapTypes.XMR_SWAP,
            )
        bid.in_progress = 1

        # Watch outputs for chain A lock tx if txid is unknown (BCH)
        if bid.xmr_a_lock_tx and bid.xmr_a_lock_tx.txid is None:
            find_script: bytes = self.ci(coin_from).getScriptDest(
                xmr_swap.a_lock_tx_script
            )
            self.addWatchedScript(
                coin_from, bid.bid_id, find_script, TxTypes.XMR_SWAP_A_LOCK
            )

    def sendXmrBidTxnSigsFtoL(self, bid_id, cursor) -> None:
        # F -> L: Sending MSG3L
        self.log.debug(f"Signing adaptor-sig bid lock txns {self.logIDB(bid_id)}.")

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)

        try:
            kaf = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KAF,
            )

            prevout_amount = ci_from.getLockRefundTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.af_lock_refund_spend_tx_esig = ci_from.signTxOtVES(
                kaf,
                xmr_swap.pkasl,
                xmr_swap.a_lock_refund_spend_tx,
                0,
                xmr_swap.a_lock_refund_tx_script,
                prevout_amount,
            )
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            xmr_swap.af_lock_refund_tx_sig = ci_from.signTx(
                kaf,
                xmr_swap.a_lock_refund_tx,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )

            xmr_swap_1.addLockRefundSigs(self, xmr_swap, ci_from)

            msg_buf = XmrBidLockTxSigsMessage(
                bid_msg_id=bid_id,
                af_lock_refund_spend_tx_esig=xmr_swap.af_lock_refund_spend_tx_esig,
                af_lock_refund_tx_sig=xmr_swap.af_lock_refund_tx_sig,
            )

            msg_bytes = msg_buf.to_bytes()
            payload_hex = (
                str.format("{:02x}", MessageTypes.XMR_BID_TXN_SIGS_FL) + msg_bytes.hex()
            )

            msg_valid: int = self.getActiveBidMsgValidTime()
            addr_send_from: str = offer.addr_from if reverse_bid else bid.bid_addr
            addr_send_to: str = bid.bid_addr if reverse_bid else offer.addr_from
            coin_a_lock_tx_sigs_l_msg_id = self.sendMessage(
                addr_send_from,
                addr_send_to,
                payload_hex,
                msg_valid,
                cursor,
                message_nets=bid.message_nets,
                payload_version=offer.smsg_payload_version,
            )
            self.addMessageLink(
                Concepts.BID,
                bid_id,
                MessageTypes.XMR_BID_TXN_SIGS_FL,
                coin_a_lock_tx_sigs_l_msg_id,
                cursor=cursor,
            )
            self.log.info(
                f"Sent XMR_BID_TXN_SIGS_FL {self.logIDM(coin_a_lock_tx_sigs_l_msg_id)} for bid {self.log.id(bid_id)}."
            )

            if ci_from.watch_blocks_for_scripts() and self.isBchXmrSwap(offer):
                # BCH doesn't have segwit
                # Lock txid will change when signed.
                # TODO: BCH Watchonly: Remove when BCH watchonly works.
                a_lock_tx_id = None
            else:
                a_lock_tx_id = ci_from.getTxid(xmr_swap.a_lock_tx)
            a_lock_tx_vout = ci_from.getTxOutputPos(
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script
            )

            if a_lock_tx_id:
                self.log.debug(
                    f"Waiting for lock tx A {self.log.id(a_lock_tx_id)} to {ci_from.coin_name()} chain for bid {self.log.id(bid_id)}."
                )
            else:
                find_script: bytes = ci_from.getScriptDest(xmr_swap.a_lock_tx_script)
                self.log.debug(
                    "Waiting for lock tx A with script {} to {} chain for bid {}".format(
                        find_script.hex(), ci_from.coin_name(), self.log.id(bid_id)
                    )
                )

            if bid.xmr_a_lock_tx is None:
                bid.xmr_a_lock_tx = SwapTx(
                    bid_id=bid_id,
                    tx_type=TxTypes.XMR_SWAP_A_LOCK,
                    txid=a_lock_tx_id,
                    vout=a_lock_tx_vout,
                )
            bid.xmr_a_lock_tx.setState(TxStates.TX_NONE)

            bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            self.watchXmrSwap(bid, offer, xmr_swap, cursor)
            self.saveBidInSession(bid_id, bid, cursor, xmr_swap)
        except Exception as e:  # noqa: F841
            if self.debug:
                self.log.error(traceback.format_exc())

    def sendXmrBidCoinALockTx(self, bid_id: bytes, cursor) -> None:
        # Offerer/Leader. Send coin A lock tx
        self.log.debug(
            f"Sending coin A lock tx for adaptor-sig bid {self.log.id(bid_id)}."
        )

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate

        kal = self.getPathKey(
            coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAL
        )

        # Prove leader can sign for kal, sent in MSG4F
        xmr_swap.kal_sig = ci_from.signCompact(kal, "proof key owned for swap")

        # Create Script lock spend tx
        xmr_swap.a_lock_spend_tx = ci_from.createSCLockSpendTx(
            xmr_swap.a_lock_tx,
            xmr_swap.a_lock_tx_script,
            xmr_swap.dest_af,
            a_fee_rate,
            xmr_swap.vkbv,
        )

        xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)
        if bid.xmr_a_lock_tx:
            bid.xmr_a_lock_tx.spend_txid = xmr_swap.a_lock_spend_tx_id
        prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
        xmr_swap.al_lock_spend_tx_esig = ci_from.signTxOtVES(
            kal,
            xmr_swap.pkasf,
            xmr_swap.a_lock_spend_tx,
            0,
            xmr_swap.a_lock_tx_script,
            prevout_amount,
        )
        """
        # Double check a_lock_spend_tx is valid
        # Fails for part_blind
        ci_from.verifySCLockSpendTx(
            xmr_swap.a_lock_spend_tx,
            xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script,
            xmr_swap.dest_af, a_fee_rate, xmr_swap.vkbv)
        """

        lock_tx_sent: bool = False
        # publishalocktx
        if bid.xmr_a_lock_tx and bid.xmr_a_lock_tx.state:
            if bid.xmr_a_lock_tx.state >= TxStates.TX_SENT:
                self.log.warning(
                    f"Lock tx has already been sent {self.logIDT(bid.xmr_a_lock_tx.txid)}."
                )
                lock_tx_sent = True

        if lock_tx_sent is False:
            lock_tx_signed = ci_from.signTxWithWallet(xmr_swap.a_lock_tx)
            if not self.isBchXmrSwap(offer):
                # Double check txid hasn't changed, can happen if the prevouts are not segwit
                if ci_from.getTxid(lock_tx_signed) != xmr_swap.a_lock_tx_id:
                    self.log.debug(f"Before tx {xmr_swap.a_lock_tx.hex()}")
                    self.log.debug(f"After tx {lock_tx_signed.hex()}")
                    raise ValueError("Coin A lock tx txid changed after signing!")

            txid_hex = ci_from.publishTx(lock_tx_signed)

            if txid_hex != b2h(xmr_swap.a_lock_tx_id):
                self.log.info(
                    "Recomputing refund transactions and txids after lock tx publish."
                )
                xmr_swap.a_lock_tx = lock_tx_signed
                xmr_swap.a_lock_tx_id = bytes.fromhex(txid_hex)

                tx = ci_from.loadTx(xmr_swap.a_lock_refund_tx)
                tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_tx_id)
                xmr_swap.a_lock_refund_tx = tx.serialize_without_witness()
                xmr_swap.a_lock_refund_tx_id = ci_from.getTxid(
                    xmr_swap.a_lock_refund_tx
                )

                tx = ci_from.loadTx(xmr_swap.a_lock_spend_tx)
                tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_tx_id)
                xmr_swap.a_lock_spend_tx = tx.serialize_without_witness()
                xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)

                vout_pos = ci_from.getTxOutputPos(
                    xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script
                )
                if not bid.xmr_a_lock_tx:
                    bid.xmr_a_lock_tx = SwapTx(
                        bid_id=bid_id,
                        tx_type=TxTypes.XMR_SWAP_A_LOCK,
                        txid=xmr_swap.a_lock_tx_id,
                        vout=vout_pos,
                    )

                bid.xmr_a_lock_tx.txid = xmr_swap.a_lock_tx_id
                bid.xmr_a_lock_tx.tx_data = lock_tx_signed
                bid.xmr_a_lock_tx.spend_txid = xmr_swap.a_lock_spend_tx_id

            vout_pos = ci_from.getTxOutputPos(
                xmr_swap.a_lock_tx, xmr_swap.a_lock_tx_script
            )
            self.log.debug(
                f"Submitted lock tx {self.log.id(txid_hex)} to {ci_from.coin_name()} chain for bid {self.log.id(bid_id)}.",
            )

            if bid.xmr_a_lock_tx is None:
                bid.xmr_a_lock_tx = SwapTx(
                    bid_id=bid_id,
                    tx_type=TxTypes.XMR_SWAP_A_LOCK,
                    txid=bytes.fromhex(txid_hex),
                    vout=vout_pos,
                )
            bid.xmr_a_lock_tx.setState(TxStates.TX_SENT)
            self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_A_PUBLISHED, "", cursor)

        bid.setState(BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX)
        self.watchXmrSwap(bid, offer, xmr_swap, cursor)

        delay = self.get_short_delay_event_seconds()
        self.log.info(
            f"Sending lock spend tx message for bid {self.log.id(bid_id)} in {delay} seconds."
        )
        self.createActionInSession(
            delay, ActionTypes.SEND_XMR_SWAP_LOCK_SPEND_MSG, bid_id, cursor
        )

        self.saveBidInSession(bid_id, bid, cursor, xmr_swap)

    def sendXmrBidCoinBLockTx(self, bid_id: bytes, cursor) -> None:
        # Follower sending coin B lock tx
        self.log.debug(
            f"Sending coin B lock tx for adaptor-sig bid {self.log.id(bid_id)}."
        )

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        ci_to = self.ci(offer.coin_from if reverse_bid else offer.coin_to)
        b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate
        was_sent: bool = bid.was_received if reverse_bid else bid.was_sent

        if self.findTxB(ci_to, xmr_swap, bid, cursor, was_sent) is True:
            self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)
            return

        if bid.xmr_b_lock_tx:
            self.log.warning(
                f"Coin B lock tx {self.log.id(bid.xmr_b_lock_tx.b_lock_tx_id)} exists for adaptor-sig bid {self.log.id(bid_id)}."
            )
            return

        if bid.debug_ind == DebugTypes.BID_STOP_AFTER_COIN_A_LOCK:
            self.log.debug(
                f"Adaptor-sig bid {self.log.id(bid_id)}: Stalling bid for testing: {bid.debug_ind}."
            )
            bid.setState(BidStates.BID_STALLED_FOR_TEST)
            self.logBidEvent(
                bid.bid_id,
                EventLogTypes.DEBUG_TWEAK_APPLIED,
                f"ind {bid.debug_ind}",
                cursor,
            )
            self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)
            return

        unlock_time = 0
        if bid.debug_ind in (
            DebugTypes.CREATE_INVALID_COIN_B_LOCK,
            DebugTypes.B_LOCK_TX_MISSED_SEND,
        ):
            bid.amount_to -= int(bid.amount_to * 0.1)
            self.log.debug(
                f"Adaptor-sig bid {self.log.id(bid_id)}: Debug {bid.debug_ind} - Reducing lock b txn amount by 10% to {ci_to.format_amount(bid.amount_to)}.",
            )
            self.logBidEvent(
                bid.bid_id,
                EventLogTypes.DEBUG_TWEAK_APPLIED,
                f"ind {bid.debug_ind}",
                cursor,
            )
        if bid.debug_ind == DebugTypes.SEND_LOCKED_XMR:
            unlock_time = 10000
            self.log.debug(
                f"Adaptor-sig bid {self.log.id(bid_id)}: Debug {bid.debug_ind} - Sending locked XMR."
            )
            self.logBidEvent(
                bid.bid_id,
                EventLogTypes.DEBUG_TWEAK_APPLIED,
                f"ind {bid.debug_ind}",
                cursor,
            )

        try:
            b_lock_tx_id = ci_to.publishBLockTx(
                xmr_swap.vkbv,
                xmr_swap.pkbs,
                bid.amount_to,
                b_fee_rate,
                unlock_time=unlock_time,
            )
            if bid.debug_ind == DebugTypes.B_LOCK_TX_MISSED_SEND:
                self.log.debug(
                    f"Adaptor-sig bid {self.log.id(bid_id)}: Debug {bid.debug_ind} - Losing XMR lock tx {self.log.id(b_lock_tx_id)}."
                )
                self.logBidEvent(
                    bid.bid_id,
                    EventLogTypes.DEBUG_TWEAK_APPLIED,
                    f"ind {bid.debug_ind}",
                    cursor,
                )
                raise TemporaryError("Fail for debug event")
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            error_msg = (
                f"publishBLockTx failed for bid {self.log.id(bid_id)} with error {ex}"
            )
            num_retries = self.countBidEvents(
                bid, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, cursor
            )
            if num_retries > 0:
                error_msg += f", retry no. {num_retries} / {self._max_transient_errors}"
            self.log.error(error_msg)

            if num_retries < self._max_transient_errors and (
                ci_to.is_transient_error(ex) or self.is_transient_error(ex)
            ):
                delay = self.get_delay_retry_seconds()
                self.log.info(
                    f"Retrying sending adaptor-sig swap chain B lock tx for bid {self.log.id(bid_id)} in {delay} seconds."
                )
                self.createActionInSession(
                    delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_B, bid_id, cursor
                )
            else:
                self.setBidError(
                    bid_id, bid, "publishBLockTx failed: " + str(ex), save_bid=False
                )
                self.saveBidInSession(
                    bid_id, bid, cursor, xmr_swap, save_in_progress=offer
                )

            self.logBidEvent(
                bid.bid_id, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, str(ex), cursor
            )
            return

        self.log.debug(
            f"Submitted lock txn {self.log.id(bid_id)} to {ci_to.coin_name()} chain for bid {self.log.id(bid_id)}."
        )
        bid.xmr_b_lock_tx = SwapTx(
            bid_id=bid_id,
            tx_type=TxTypes.XMR_SWAP_B_LOCK,
            txid=b_lock_tx_id,
        )
        xmr_swap.b_lock_tx_id = b_lock_tx_id
        bid.xmr_b_lock_tx.setState(TxStates.TX_SENT)
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_PUBLISHED, "", cursor)
        if bid.debug_ind == DebugTypes.BID_STOP_AFTER_COIN_B_LOCK:
            self.log.debug(
                "Adaptor-sig bid {self.log.id(bid_id)}: Stalling bid for testing: {bid.debug_ind}."
            )
            bid.setState(BidStates.BID_STALLED_FOR_TEST)
            self.logBidEvent(
                bid.bid_id,
                EventLogTypes.DEBUG_TWEAK_APPLIED,
                f"ind {bid.debug_ind}",
                cursor,
            )
        self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)

    def sendXmrBidLockRelease(self, bid_id: bytes, cursor) -> None:
        # Leader sending lock tx a release secret (MSG5F)
        self.log.debug(f"Sending bid secret for adaptor-sig bid {self.log.id(bid_id)}.")

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)

        msg_buf = XmrBidLockReleaseMessage(
            bid_msg_id=bid_id, al_lock_spend_tx_esig=xmr_swap.al_lock_spend_tx_esig
        )

        msg_bytes = msg_buf.to_bytes()
        payload_hex = (
            str.format("{:02x}", MessageTypes.XMR_BID_LOCK_RELEASE_LF) + msg_bytes.hex()
        )

        addr_send_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_send_to: str = offer.addr_from if reverse_bid else bid.bid_addr
        msg_valid: int = self.getActiveBidMsgValidTime()
        coin_a_lock_release_msg_id = self.sendMessage(
            addr_send_from,
            addr_send_to,
            payload_hex,
            msg_valid,
            cursor,
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )
        self.addMessageLink(
            Concepts.BID,
            bid_id,
            MessageTypes.XMR_BID_LOCK_RELEASE_LF,
            coin_a_lock_release_msg_id,
            cursor=cursor,
        )

        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)

    def redeemXmrBidCoinALockTx(self, bid_id: bytes, cursor) -> None:
        # Follower redeeming A lock tx
        self.log.debug(
            f"Redeeming coin A lock tx for adaptor-sig bid {self.log.id(bid_id)}."
        )

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
            self.log.warning(
                f"Not redeeming coin A lock tx for bid {self.log.id(bid_id)}: Chain A lock refund tx already exists."
            )
            return

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
        kbsf = self.getPathKey(
            coin_from,
            coin_to,
            bid.created_at,
            xmr_swap.contract_count,
            KeyTypes.KBSF,
            for_ed25519,
        )
        kaf = self.getPathKey(
            coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF
        )

        if not self.isBchXmrSwap(offer):
            # segwit coins sign the transaction
            al_lock_spend_sig = ci_from.decryptOtVES(
                kbsf, xmr_swap.al_lock_spend_tx_esig
            )
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            v = ci_from.verifyTxSig(
                xmr_swap.a_lock_spend_tx,
                al_lock_spend_sig,
                xmr_swap.pkal,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )
            ensure(v, "Invalid coin A lock tx spend tx leader sig")

            af_lock_spend_sig = ci_from.signTx(
                kaf,
                xmr_swap.a_lock_spend_tx,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )
            v = ci_from.verifyTxSig(
                xmr_swap.a_lock_spend_tx,
                af_lock_spend_sig,
                xmr_swap.pkaf,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )
            ensure(v, "Invalid coin A lock tx spend tx follower sig")

            witness_stack = []
            if coin_from not in (Coins.DCR,):
                witness_stack += [
                    b"",
                ]
            witness_stack += [
                al_lock_spend_sig,
                af_lock_spend_sig,
                xmr_swap.a_lock_tx_script,
            ]

            xmr_swap.a_lock_spend_tx = ci_from.setTxSignature(
                xmr_swap.a_lock_spend_tx, witness_stack
            )
        else:
            # bch signs the output pkh
            tx = ci_from.loadTx(xmr_swap.a_lock_spend_tx)
            out1 = tx.vout[0].scriptPubKey
            out1_sig = ci_from.decryptOtVES(kbsf, xmr_swap.al_lock_spend_tx_esig)
            v = ci_from.verifyDataSig(out1, out1_sig, xmr_swap.pkal)
            ensure(v, "Invalid signature for lock spend txn")

            # update prevout after tx was signed
            tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_tx_id)
            tx.vin[0].scriptSig = ci_from.getScriptScriptSig(
                xmr_swap.a_lock_tx_script, out1_sig
            )
            xmr_swap.a_lock_spend_tx = tx.serialize_without_witness()
            xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)

        txid = bytes.fromhex(ci_from.publishTx(xmr_swap.a_lock_spend_tx))
        self.log.debug(
            f"Submitted lock spend txn {self.log.id(txid)} to {ci_from.coin_name()} chain for bid {self.log.id(bid_id)}."
        )
        self.logBidEvent(
            bid.bid_id, EventLogTypes.LOCK_TX_A_SPEND_TX_PUBLISHED, "", cursor
        )
        if bid.xmr_a_lock_spend_tx is None:
            bid.xmr_a_lock_spend_tx = SwapTx(
                bid_id=bid_id,
                tx_type=TxTypes.XMR_SWAP_A_LOCK_SPEND,
                txid=txid,
            )
            bid.xmr_a_lock_spend_tx.setState(TxStates.TX_NONE)
        else:
            self.log.warning(
                f"Chain A lock TX {self.log.id(bid.xmr_a_lock_spend_tx.txid)} already exists for bid {self.log.id(bid_id)}."
            )

        self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)

    def redeemXmrBidCoinBLockTx(self, bid_id: bytes, cursor) -> None:
        # Leader redeeming B lock tx
        self.log.debug(
            f"Redeeming coin B lock tx for adaptor-sig bid {self.log.id(bid_id)}."
        )

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate

        try:
            if bid.xmr_b_lock_tx is None:
                raise TemporaryError("Chain B lock tx not found.")
            chain_height: int = ci_to.getChainHeight()
            lock_tx_depth: int = chain_height - bid.xmr_b_lock_tx.chain_height
            if lock_tx_depth < ci_to.depth_spendable():
                raise TemporaryError(
                    f"Chain B lock tx still confirming {lock_tx_depth} / {ci_to.depth_spendable()}."
                )

            if TxTypes.BCH_MERCY in bid.txns:
                self.log.info("Using keyshare from mercy tx.")
                kbsf = bid.txns[TxTypes.BCH_MERCY].tx_data
                pkbsf = ci_to.getPubkey(kbsf)
                ensure(
                    pkbsf == xmr_swap.pkbsf,
                    "Keyshare from mercy tx does not match expected pubkey",
                )
            elif TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE in bid.txns:
                self.log.info("Using keyshare from swipe tx.")
                kbsf = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE].tx_data
                pkbsf = ci_to.getPubkey(kbsf)
                ensure(
                    pkbsf == xmr_swap.pkbsf,
                    "Keyshare from swipe tx does not match expected pubkey",
                )
            else:
                # Extract the leader's decrypted signature and use it to recover the follower's privatekey
                xmr_swap.al_lock_spend_tx_sig = ci_from.extractLeaderSig(
                    xmr_swap.a_lock_spend_tx
                )
                kbsf = ci_from.recoverEncKey(
                    xmr_swap.al_lock_spend_tx_esig,
                    xmr_swap.al_lock_spend_tx_sig,
                    xmr_swap.pkasf,
                )
            assert kbsf is not None

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbsl = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KBSL,
                for_ed25519,
            )
            vkbs = ci_to.sumKeys(kbsl, kbsf)

            if coin_to == (Coins.XMR, Coins.WOW):
                address_to = self.getCachedMainWalletAddress(ci_to, cursor)
            elif coin_to in (Coins.PART_BLIND, Coins.PART_ANON):
                address_to = self.getCachedStealthAddressForCoin(coin_to, cursor)
            else:
                address_to = self.getReceiveAddressFromPool(
                    coin_to, bid_id, TxTypes.XMR_SWAP_B_LOCK_SPEND, cursor
                )

            lock_tx_vout = bid.getLockTXBVout()
            txid = ci_to.spendBLockTx(
                xmr_swap.b_lock_tx_id,
                address_to,
                xmr_swap.vkbv,
                vkbs,
                bid.amount_to,
                b_fee_rate,
                bid.chain_b_height_start,
                lock_tx_vout=lock_tx_vout,
            )
            self.log.debug(
                f"Submitted lock B spend txn {self.log.id(txid)} to {ci_to.coin_name()} chain for bid {self.log.id(bid_id)}."
            )
            self.logBidEvent(
                bid.bid_id, EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED, "", cursor
            )
        except Exception as ex:
            error_msg = (
                f"spendBLockTx failed for bid {self.log.id(bid_id)} with error {ex}"
            )
            num_retries = self.countBidEvents(
                bid, EventLogTypes.FAILED_TX_B_SPEND, cursor
            )
            if num_retries > 0:
                error_msg += f", retry no. {num_retries} / {self._max_transient_errors}"
            self.log.error(error_msg)

            if num_retries < self._max_transient_errors and (
                ci_to.is_transient_error(ex) or self.is_transient_error(ex)
            ):
                delay = self.get_delay_retry_seconds()
                self.log.info(
                    f"Retrying sending adaptor-sig swap chain B spend tx for bid {self.log.id(bid_id)} in {delay} seconds."
                )
                self.createActionInSession(
                    delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_B, bid_id, cursor
                )
            else:
                self.setBidError(
                    bid_id, bid, "spendBLockTx failed: " + str(ex), save_bid=False
                )
                self.saveBidInSession(
                    bid_id, bid, cursor, xmr_swap, save_in_progress=offer
                )

            self.logBidEvent(
                bid.bid_id, EventLogTypes.FAILED_TX_B_SPEND, str(ex), cursor
            )
            return

        bid.xmr_b_lock_tx.spend_txid = txid
        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
        if bid.xmr_b_lock_tx:
            bid.xmr_b_lock_tx.setState(TxStates.TX_REDEEMED)

        # TODO: Why does using bid.txns error here?
        self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)

    def recoverXmrBidCoinBLockTx(self, bid_id: bytes, cursor) -> None:
        # Follower recovering B lock tx
        self.log.debug(
            f"Recovering coin B lock tx for adaptor-sig bid {self.log.id(bid_id)}"
        )

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)
        b_fee_rate: int = xmr_offer.a_fee_rate if reverse_bid else xmr_offer.b_fee_rate

        # Extract the follower's decrypted signature and use it to recover the leader's privatekey
        af_lock_refund_spend_tx_sig = ci_from.extractFollowerSig(
            xmr_swap.a_lock_refund_spend_tx
        )
        kbsl = ci_from.recoverEncKey(
            xmr_swap.af_lock_refund_spend_tx_esig,
            af_lock_refund_spend_tx_sig,
            xmr_swap.pkasl,
        )
        assert kbsl is not None

        for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
        kbsf = self.getPathKey(
            coin_from,
            coin_to,
            bid.created_at,
            xmr_swap.contract_count,
            KeyTypes.KBSF,
            for_ed25519,
        )
        vkbs = ci_to.sumKeys(kbsl, kbsf)

        try:
            if offer.coin_to in (Coins.XMR, Coins.WOW):
                address_to = self.getCachedMainWalletAddress(ci_to, cursor)
            elif coin_to in (Coins.PART_BLIND, Coins.PART_ANON):
                address_to = self.getCachedStealthAddressForCoin(coin_to, cursor)
            else:
                address_to = self.getReceiveAddressFromPool(
                    coin_to, bid_id, TxTypes.XMR_SWAP_B_LOCK_REFUND, cursor
                )

            lock_tx_vout = bid.getLockTXBVout()
            txid = ci_to.spendBLockTx(
                xmr_swap.b_lock_tx_id,
                address_to,
                xmr_swap.vkbv,
                vkbs,
                bid.amount_to,
                b_fee_rate,
                bid.chain_b_height_start,
                lock_tx_vout=lock_tx_vout,
                spend_actual_balance=(
                    True if bid.debug_ind == DebugTypes.B_LOCK_TX_MISSED_SEND else False
                ),
            )
            self.log.debug(
                f"Submitted lock B refund txn {self.log.id(txid)} to {ci_to.coin_name()} chain for bid {self.log.id(bid_id)}."
            )
            self.logBidEvent(
                bid.bid_id, EventLogTypes.LOCK_TX_B_REFUND_TX_PUBLISHED, "", cursor
            )
        except Exception as ex:
            # TODO: Make min-conf 10?
            error_msg = f"spendBLockTx refund failed for bid {self.log.id(bid_id)} with error {ex}"
            num_retries = self.countBidEvents(
                bid, EventLogTypes.FAILED_TX_B_REFUND, cursor
            )
            if num_retries > 0:
                error_msg += f", retry no. {num_retries} / {self._max_transient_errors}"
            self.log.error(error_msg)

            str_error = str(ex)
            if num_retries < self._max_transient_errors and (
                ci_to.is_transient_error(ex) or self.is_transient_error(ex)
            ):
                delay = self.get_delay_retry_seconds()
                self.log.info(
                    f"Retrying sending adaptor-sig swap chain B refund tx for bid {self.log.id(bid_id)} in {delay} seconds."
                )
                self.createActionInSession(
                    delay, ActionTypes.RECOVER_XMR_SWAP_LOCK_TX_B, bid_id, cursor
                )
            else:
                self.setBidError(
                    bid_id,
                    bid,
                    "spendBLockTx for refund failed: " + str(ex),
                    save_bid=False,
                )
                self.saveBidInSession(
                    bid_id, bid, cursor, xmr_swap, save_in_progress=offer
                )

            self.logBidEvent(
                bid.bid_id, EventLogTypes.FAILED_TX_B_REFUND, str_error, cursor
            )
            return

        bid.xmr_b_lock_tx.spend_txid = txid

        bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED)
        if bid.xmr_b_lock_tx:
            bid.xmr_b_lock_tx.setState(TxStates.TX_REFUNDED)
        self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)

    def sendXmrBidCoinALockSpendTxMsg(self, bid_id: bytes, cursor) -> None:
        # Send MSG4F L -> F
        self.log.debug(
            f"Sending coin A lock spend tx msg for adaptor-sig bid {self.log.id(bid_id)}."
        )

        bid, xmr_swap = self.getXmrBidFromSession(cursor, bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOfferFromSession(cursor, bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        addr_send_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_send_to: str = offer.addr_from if reverse_bid else bid.bid_addr

        msg_buf = XmrBidLockSpendTxMessage(
            bid_msg_id=bid_id,
            a_lock_spend_tx=xmr_swap.a_lock_spend_tx,
            kal_sig=xmr_swap.kal_sig,
        )

        msg_bytes = msg_buf.to_bytes()
        payload_hex = (
            str.format("{:02x}", MessageTypes.XMR_BID_LOCK_SPEND_TX_LF)
            + msg_bytes.hex()
        )

        msg_valid: int = self.getActiveBidMsgValidTime()
        xmr_swap.coin_a_lock_refund_spend_tx_msg_id = self.sendMessage(
            addr_send_from,
            addr_send_to,
            payload_hex,
            msg_valid,
            cursor,
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )

        bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX)
        self.saveBidInSession(bid_id, bid, cursor, xmr_swap, save_in_progress=offer)

    def processXmrBidCoinALockSigs(self, msg) -> None:
        # Leader processing MSG3L
        self.log.debug(
            "Processing xmr coin a follower lock sigs msg {}.".format(
                self.log.id(msg["msgid"])
            )
        )

        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = XmrBidLockTxSigsMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, "Bad bid_msg_id length")
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOffer(bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)
        addr_sent_from: str = offer.addr_from if reverse_bid else bid.bid_addr
        addr_sent_to: str = bid.bid_addr if reverse_bid else offer.addr_from
        ci_from = self.ci(coin_from)
        ci_to = self.ci(coin_to)

        ensure(msg["to"] == addr_sent_to, "Received on incorrect address")
        ensure(msg["from"] == addr_sent_from, "Sent from incorrect address")

        try:
            allowed_states = [
                BidStates.BID_ACCEPTED,
            ]
            if bid.was_sent and offer.was_sent:
                allowed_states.append(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            ensure(
                bid.state in allowed_states,
                "Invalid state for bid {}".format(bid.state),
            )
            xmr_swap.af_lock_refund_spend_tx_esig = (
                msg_data.af_lock_refund_spend_tx_esig
            )
            xmr_swap.af_lock_refund_tx_sig = msg_data.af_lock_refund_tx_sig

            for_ed25519: bool = True if ci_to.curve_type() == Curves.ed25519 else False
            kbsl = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KBSL,
                for_ed25519,
            )
            kal = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KAL,
            )

            if not self.isBchXmrSwap(offer):
                # segwit coins sign the transaction
                xmr_swap.af_lock_refund_spend_tx_sig = ci_from.decryptOtVES(
                    kbsl, xmr_swap.af_lock_refund_spend_tx_esig
                )
                prevout_amount = ci_from.getLockRefundTxSwapOutputValue(bid, xmr_swap)
                al_lock_refund_spend_tx_sig = ci_from.signTx(
                    kal,
                    xmr_swap.a_lock_refund_spend_tx,
                    0,
                    xmr_swap.a_lock_refund_tx_script,
                    prevout_amount,
                )

                self.log.debug("Setting lock refund spend tx sigs.")
                witness_stack = []
                if coin_from not in (Coins.DCR,):
                    witness_stack += [
                        b"",
                    ]
                witness_stack += [
                    al_lock_refund_spend_tx_sig,
                    xmr_swap.af_lock_refund_spend_tx_sig,
                    bytes((1,)),
                    xmr_swap.a_lock_refund_tx_script,
                ]
                signed_tx = ci_from.setTxSignature(
                    xmr_swap.a_lock_refund_spend_tx, witness_stack
                )
                ensure(signed_tx, "setTxSignature failed")
                xmr_swap.a_lock_refund_spend_tx = signed_tx

                v = ci_from.verifyTxSig(
                    xmr_swap.a_lock_refund_spend_tx,
                    xmr_swap.af_lock_refund_spend_tx_sig,
                    xmr_swap.pkaf,
                    0,
                    xmr_swap.a_lock_refund_tx_script,
                    prevout_amount,
                )
                ensure(v, "Invalid signature for lock refund spend txn")
                xmr_swap_1.addLockRefundSigs(self, xmr_swap, ci_from)
            else:
                # BCH signs the output pkh

                tx = ci_from.loadTx(xmr_swap.a_lock_refund_spend_tx)
                out1 = tx.vout[0].scriptPubKey
                out1_sig = ci_from.decryptOtVES(
                    kbsl, xmr_swap.af_lock_refund_spend_tx_esig
                )
                v = ci_from.verifyDataSig(out1, out1_sig, xmr_swap.pkaf)
                ensure(v, "Invalid signature for lock refund spend txn")

                tx.vin[0].scriptSig = ci_from.getScriptScriptSig(
                    xmr_swap.a_lock_refund_tx_script, out1_sig
                )
                tx.vin[0].prevout.hash = b2i(xmr_swap.a_lock_tx_id)
                xmr_swap.a_lock_refund_spend_tx = tx.serialize_without_witness()
                xmr_swap.a_lock_refund_spend_tx_id = ci_from.getTxid(
                    xmr_swap.a_lock_refund_spend_tx
                )

            delay = self.get_delay_event_seconds()
            self.log.info(
                f"Sending coin A lock tx for adaptor-sig bid {self.log.id(bid_id)} in {delay} seconds."
            )
            self.createAction(delay, ActionTypes.SEND_XMR_SWAP_LOCK_TX_A, bid_id)

            bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS)
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))

    def processXmrBidLockSpendTx(self, msg) -> None:
        # Follower receiving MSG4F
        self.log.debug(
            "Processing adaptor-sig bid lock spend tx msg {}.".format(
                self.log.id(msg["msgid"])
            )
        )

        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = XmrBidLockSpendTxMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        ensure(len(msg_data.bid_msg_id) == 28, "Bad bid_msg_id length")
        bid_id = msg_data.bid_msg_id

        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOffer(bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        addr_sent_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_sent_to: str = offer.addr_from if reverse_bid else bid.bid_addr
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate

        ensure(msg["to"] == addr_sent_to, "Received on incorrect address")
        ensure(msg["from"] == addr_sent_from, "Sent from incorrect address")

        try:
            xmr_swap.a_lock_spend_tx = msg_data.a_lock_spend_tx
            xmr_swap.a_lock_spend_tx_id = ci_from.getTxid(xmr_swap.a_lock_spend_tx)
            if bid.xmr_a_lock_tx:
                bid.xmr_a_lock_tx.spend_txid = xmr_swap.a_lock_spend_tx_id
            xmr_swap.kal_sig = msg_data.kal_sig

            ci_from.verifySCLockSpendTx(
                xmr_swap.a_lock_spend_tx,
                xmr_swap.a_lock_tx,
                xmr_swap.a_lock_tx_script,
                xmr_swap.dest_af,
                a_fee_rate,
                xmr_swap.vkbv,
            )

            ci_from.verifyCompactSig(
                xmr_swap.pkal, "proof key owned for swap", xmr_swap.kal_sig
            )

            if bid.state == BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS:
                bid.setState(BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX)
                bid.setState(BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX)
            else:
                self.log.warning(
                    f"processXmrBidLockSpendTx bid {self.log.id(bid_id)} unexpected state {bid.state}."
                )
            self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))

        # Update copy of bid in swaps_in_progress
        self.swaps_in_progress[bid_id] = (bid, offer)

    def processXmrSplitMessage(self, msg) -> None:
        self.log.debug("Processing xmr split msg {}".format(self.log.id(msg["msgid"])))
        now: int = self.getTime()
        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = XmrSplitMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        # Validate data
        ensure(len(msg_data.msg_id) == 28, "Bad msg_id length")
        self.log.debug(f"for bid {self.log.id(msg_data.msg_id)}.")

        # TODO: Wait for bid msg to arrive first

        if (
            msg_data.msg_type == XmrSplitMsgTypes.BID
            or msg_data.msg_type == XmrSplitMsgTypes.BID_ACCEPT
        ):
            cursor = self.openDB()
            try:
                q = cursor.execute(
                    "SELECT COUNT(*) FROM xmr_split_data WHERE bid_id = :bid_id AND msg_type = :msg_type AND msg_sequence = :msg_sequence",
                    {
                        "bid_id": msg_data.msg_id,
                        "msg_type": msg_data.msg_type,
                        "msg_sequence": msg_data.sequence,
                    },
                ).fetchone()
                num_exists = q[0]
                if num_exists > 0:
                    self.log.warning(
                        f"Ignoring duplicate xmr_split_data entry: ({self.logIDM(msg_data.msg_id)}, {msg_data.msg_type}, {msg_data.sequence})."
                    )
                    return

                dbr = XmrSplitData()
                dbr.addr_from = msg["from"]
                dbr.addr_to = msg["to"]
                dbr.bid_id = msg_data.msg_id
                dbr.msg_type = msg_data.msg_type
                dbr.msg_sequence = msg_data.sequence
                dbr.dleag = msg_data.dleag
                dbr.created_at = now
                self.add(dbr, cursor, upsert=True)
            finally:
                self.closeDB(cursor)

    def processXmrLockReleaseMessage(self, msg) -> None:
        self.log.debug(
            "Processing adaptor-sig swap lock release msg {}.".format(
                self.log.id(msg["msgid"])
            )
        )

        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = XmrBidLockReleaseMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        # Validate data
        ensure(len(msg_data.bid_msg_id) == 28, "Bad msg_id length")

        bid_id = msg_data.bid_msg_id
        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        if BidStates(bid.state) in (BidStates.BID_STALLED_FOR_TEST,):
            self.log.debug(f"Bid stalled {self.log.id(bid_id)}.")
            return

        offer, xmr_offer = self.getXmrOffer(bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        ci_from = self.ci(offer.coin_to if reverse_bid else offer.coin_from)
        addr_sent_from: str = bid.bid_addr if reverse_bid else offer.addr_from
        addr_sent_to: str = offer.addr_from if reverse_bid else bid.bid_addr

        ensure(msg["to"] == addr_sent_to, "Received on incorrect address")
        ensure(msg["from"] == addr_sent_from, "Sent from incorrect address")

        xmr_swap.al_lock_spend_tx_esig = msg_data.al_lock_spend_tx_esig
        try:
            prevout_amount = ci_from.getLockTxSwapOutputValue(bid, xmr_swap)
            v = ci_from.verifyTxOtVES(
                xmr_swap.a_lock_spend_tx,
                xmr_swap.al_lock_spend_tx_esig,
                xmr_swap.pkal,
                xmr_swap.pkasf,
                0,
                xmr_swap.a_lock_tx_script,
                prevout_amount,
            )
            ensure(v, "verifyTxOtVES failed for chain a lock tx leader esig")
        except Exception as ex:
            if self.debug:
                self.log.error(traceback.format_exc())
            self.setBidError(bid_id, bid, str(ex))
            self.swaps_in_progress[bid_id] = (bid, offer)
            return

        if self.haveDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK):
            self.logBidEvent(
                bid_id,
                EventLogTypes.DEBUG_TWEAK_APPLIED,
                "ind {}".format(DebugTypes.BID_DONT_SPEND_COIN_A_LOCK),
                None,
            )
        else:
            delay = self.get_delay_event_seconds()
            self.log.info(
                f"Redeeming coin A lock tx for adaptor-sig bid {self.log.id(bid_id)} in {delay} seconds."
            )
            self.createAction(delay, ActionTypes.REDEEM_XMR_SWAP_LOCK_TX_A, bid_id)

        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)
        self.swaps_in_progress[bid_id] = (bid, offer)

    def processADSBidReversed(self, msg) -> None:
        self.log.debug(
            "Processing adaptor-sig reverse bid msg {}.".format(
                self.log.id(msg["msgid"])
            )
        )

        now: int = self.getTime()
        bid_bytes = self.getSmsgMsgBytes(msg)
        bid_data = ADSBidIntentMessage(init_all=False)
        bid_data.from_bytes(bid_bytes)

        # Validate data
        ensure(
            bid_data.protocol_version >= MINPROTO_VERSION_ADAPTOR_SIG,
            "Invalid protocol version",
        )
        ensure(len(bid_data.offer_msg_id) == 28, "Bad offer_id length")

        offer_id = bid_data.offer_msg_id
        offer, xmr_offer = self.getXmrOffer(offer_id)
        ensure(offer and offer.was_sent, f"Offer not found: {self.log.id(offer_id)}.")
        ensure(offer.swap_type == SwapTypes.XMR_SWAP, "Bid/offer swap type mismatch")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(offer_id)}.")

        self.validateMessageNets(bid_data.message_nets)

        ci_from = self.ci(offer.coin_to)
        ci_to = self.ci(offer.coin_from)

        if not validOfferStateToReceiveBid(offer.state):
            raise ValueError("Bad offer state")
        ensure(msg["to"] == offer.addr_from, "Received on incorrect address")
        ensure(now <= offer.expire_at, "Offer expired")
        self.validateBidValidTime(
            offer.swap_type, offer.coin_from, offer.coin_to, bid_data.time_valid
        )
        ensure(now <= msg["sent"] + bid_data.time_valid, "Bid expired")

        # ci_from/to are reversed
        bid_rate: int = ci_to.make_int(bid_data.amount_to / bid_data.amount_from, r=1)
        reversed_rate: int = ci_from.make_int(
            bid_data.amount_from / bid_data.amount_to, r=1
        )
        self.validateBidAmount(offer, bid_data.amount_from, bid_rate)

        _, _ = self.expandMessageNets(bid_data.message_nets)

        bid_id = bytes.fromhex(msg["msgid"])

        bid, xmr_swap = self.getXmrBid(bid_id)
        pk_from: bytes = getMsgPubkey(self, msg)
        if bid is None:
            bid = Bid(
                active_ind=1,
                bid_id=bid_id,
                offer_id=offer_id,
                protocol_version=bid_data.protocol_version,
                amount=bid_data.amount_to,
                amount_to=bid_data.amount_from,
                rate=reversed_rate,
                created_at=msg["sent"],
                expire_at=msg["sent"] + bid_data.time_valid,
                bid_addr=msg["from"],
                pk_bid_addr=pk_from,
                was_sent=False,
                was_received=True,
                chain_a_height_start=ci_from.getChainHeight(),
                chain_b_height_start=ci_to.getChainHeight(),
                message_nets=bid_data.message_nets,
            )

            xmr_swap = XmrSwap(
                bid_id=bid_id,
            )
            self.setMsgSplitInfo(xmr_swap)
            wallet_restore_height = self.getWalletRestoreHeight(ci_to)
            if bid.chain_b_height_start < wallet_restore_height:
                bid.chain_b_height_start = wallet_restore_height
                self.log.warning(
                    f"Adaptor-sig swap restore height clamped to {wallet_restore_height}."
                )
        else:
            ensure(
                bid.state == BidStates.BID_REQUEST_SENT,
                "Wrong bid state: {}".format(BidStates(bid.state).name),
            )
            # Don't update bid.created_at, it's been used to derive kaf
            bid.expire_at = msg["sent"] + bid_data.time_valid
            bid.pk_bid_addr = pk_from
            bid.was_received = True

        bid.setState(BidStates.BID_RECEIVED)  # BID_REQUEST_RECEIVED
        self.addRecvBidNetworkLink(msg, bid_id)

        self.log.info(
            f"Received reverse adaptor-sig bid {self.log.id(bid_id)} for offer {self.log.id(bid_data.offer_msg_id)}."
        )
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

        try:
            cursor = self.openDB()
            self.notify(
                NT.BID_RECEIVED,
                {
                    "type": "ads_reversed",
                    "bid_id": bid.bid_id.hex(),
                    "offer_id": bid.offer_id.hex(),
                },
                cursor,
            )

            options = {"reverse_bid": True, "bid_rate": bid_rate}
            if self.shouldAutoAcceptBid(offer, bid, cursor, options=options):
                delay = self.get_delay_event_seconds()
                self.log.info(
                    f"Auto accepting reverse adaptor-sig bid {self.log.id(bid.bid_id)} in {delay} seconds."
                )
                self.createActionInSession(
                    delay, ActionTypes.ACCEPT_AS_REV_BID, bid.bid_id, cursor
                )
                bid.setState(BidStates.SWAP_DELAYING)
        finally:
            self.closeDB(cursor)

    def processADSBidReversedAccept(self, msg) -> None:
        self.log.debug(
            "Processing adaptor-sig reverse bid accept msg {}.".format(
                self.log.id(msg["msgid"])
            )
        )

        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = ADSBidIntentAcceptMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        bid_id = msg_data.bid_msg_id
        bid, xmr_swap = self.getXmrBid(bid_id)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(xmr_swap, f"Adaptor-sig swap not found: {self.log.id(bid_id)}.")

        offer, xmr_offer = self.getXmrOffer(bid.offer_id)
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(xmr_offer, f"Adaptor-sig offer not found: {self.log.id(bid.offer_id)}.")

        ensure(msg["to"] == bid.bid_addr, "Received on incorrect address")
        ensure(msg["from"] == offer.addr_from, "Sent from incorrect address")

        allowed_states = [
            BidStates.BID_REQUEST_SENT,
        ]
        if bid.was_sent and offer.was_sent:
            allowed_states.append(BidStates.BID_REQUEST_ACCEPTED)
        ensure(
            bid.state in allowed_states,
            "Invalid state for bid {}".format(bid.state),
        )

        ci_from = self.ci(offer.coin_to)
        ci_to = self.ci(offer.coin_from)

        ensure(ci_to.verifyKey(msg_data.kbvf), "Invalid chain B follower view key")
        ensure(
            ci_from.verifyPubkey(msg_data.pkaf), "Invalid chain A follower public key"
        )
        ensure(
            ci_from.isValidAddressHash(msg_data.dest_af)
            or ci_from.isValidPubkey(msg_data.dest_af),
            "Invalid destination address",
        )
        if ci_to.curve_type() == Curves.ed25519:
            ensure(len(msg_data.kbsf_dleag) <= 16000, "Invalid kbsf_dleag size")

        xmr_swap.dest_af = msg_data.dest_af
        xmr_swap.pkaf = msg_data.pkaf
        xmr_swap.vkbvf = msg_data.kbvf
        xmr_swap.pkbvf = ci_to.getPubkey(msg_data.kbvf)
        xmr_swap.kbsf_dleag = msg_data.kbsf_dleag

        bid.chain_a_height_start: int = ci_from.getChainHeight()
        bid.chain_b_height_start: int = ci_to.getChainHeight()

        wallet_restore_height: int = self.getWalletRestoreHeight(ci_to)
        if bid.chain_b_height_start < wallet_restore_height:
            bid.chain_b_height_start = wallet_restore_height
            self.log.warning(
                f"Reverse adaptor-sig swap restore height clamped to {wallet_restore_height}"
            )

        bid.setState(BidStates.BID_RECEIVING)

        self.log.info(
            f"Receiving reverse adaptor-sig bid {self.log.id(bid_id)} for offer {self.log.id(bid.offer_id)}."
        )
        self.saveBid(bid_id, bid, xmr_swap=xmr_swap)

        try:
            cursor = self.openDB()
            self.notify(NT.BID_ACCEPTED, {"bid_id": bid_id.hex()}, cursor)
            if ci_to.curve_type() != Curves.ed25519:
                self.receiveXmrBid(bid, cursor)
        finally:
            self.closeDB(cursor)

    def processConnectRequest(self, msg) -> None:
        self.log.debug(
            "Processing connection request msg {}.".format(self.log.id(msg["msgid"]))
        )
        msg_bytes = self.getSmsgMsgBytes(msg)
        msg_data = ConnectReqMessage(init_all=False)
        msg_data.from_bytes(msg_bytes)

        req_data = json.loads(msg_data.request_data)

        offer_id = bytes.fromhex(req_data["offer_id"])
        bidder_addr = req_data["bsx_address"]

        net_i = self.getActiveNetworkInterface(MessageNetworks.SIMPLEX)
        try:
            cursor = self.openDB()
            offer = self.getOffer(offer_id, cursor)
            ensure(offer, f"Offer not found: {self.log.id(offer_id)}.")
            ensure(offer.expire_at > self.getTime(), "Offer has expired")
            ensure(msg["from"] == bidder_addr, "Mismatched from address")
            ensure(msg["to"] == offer.addr_from, "Mismatched to address")

            self.log.debug(
                f"Opening direct message route from {offer.addr_from} to {bidder_addr}"
            )
            message_route = self.getMessageRoute(
                2, bidder_addr, offer.addr_from, cursor=cursor
            )
            if message_route:
                raise ValueError("Direct message route already exists")

            connReqInvitation = req_data["connection_req"]
            cmd_id = net_i.send_command(f"/connect {connReqInvitation}")
            response = net_i.wait_for_command_response(cmd_id)
            pccConnId = getResponseData(response, "connection")["pccConnId"]

            now: int = self.getTime()
            message_route = DirectMessageRoute(
                active_ind=2,
                network_id=2,
                linked_type=Concepts.OFFER,
                smsg_addr_local=offer.addr_from,
                smsg_addr_remote=bidder_addr,
                route_data=json.dumps(
                    {"connection_req": connReqInvitation, "pccConnId": pccConnId}
                ).encode("UTF-8"),
                created_at=now,
            )
            message_route_id = self.add(message_route, cursor)

            message_route_link = DirectMessageRouteLink(
                active_ind=1,
                direct_message_route_id=message_route_id,
                linked_type=Concepts.OFFER,
                linked_id=offer_id,
                created_at=now,
            )
            self.add(message_route_link, cursor)

        finally:
            self.closeDB(cursor)

    def processContactConnected(self, event_data) -> None:
        contact_data = getResponseData(event_data, "contact")
        connId = contact_data["activeConn"]["connId"]
        localDisplayName = contact_data["localDisplayName"]
        self.log.debug(
            f"Processing Contact Connected event, ID: {connId}, contact name: {localDisplayName}."
        )

        try:
            cursor = self.openDB()

            query_str = (
                "SELECT record_id, network_id, smsg_addr_local, smsg_addr_remote, route_data FROM direct_message_routes "
                + "WHERE active_ind = 2"
            )
            rows = cursor.execute(query_str).fetchall()

            found_direct_message_route = None
            for row in rows:
                record_id, network_id, smsg_addr_local, smsg_addr_remote, route_data = (
                    row
                )
                route_data = json.loads(route_data.decode("UTF-8"))

                if connId == route_data["pccConnId"]:
                    self.log.debug(
                        f"Direct message route established local: {smsg_addr_local}, remote: {smsg_addr_remote}."
                    )
                    # route_data["localDisplayName"] = localDisplayName

                    cursor.execute(query_str)
                    # query = "UPDATE direct_message_routes SET active_ind = 1, route_data = :route_data WHERE record_id = :record_id "
                    query = "UPDATE direct_message_routes SET active_ind = 1 WHERE record_id = :record_id "
                    cursor.execute(query, {"record_id": record_id})
                    found_direct_message_route = record_id
                    break

            if found_direct_message_route:
                query_str = (
                    "SELECT record_id, linked_type, linked_id FROM direct_message_route_links "
                    + "WHERE active_ind = 1"
                )
                rows = cursor.execute(query_str).fetchall()
                for row in rows:
                    record_id, linked_type, linked_id = row

                    if linked_type == Concepts.BID:
                        self.routeEstablishedForBid(linked_id, cursor)
                        query = "UPDATE direct_message_route_links SET active_ind = 2 WHERE record_id = :record_id "
                        cursor.execute(query, {"record_id": record_id})
                    elif linked_type == Concepts.OFFER:
                        pass
                    else:
                        self.log.warning(
                            f"Unknown direct_message_route_link type: {linked_type}, {self.log.id(linked_id)}."
                        )
            else:
                self.log.warning(
                    f"Unknown direct message route connected, connId: {connId}"
                )
        finally:
            self.closeDB(cursor)

    def routeEstablishedForBid(self, bid_id: bytes, cursor):
        self.log.info(f"Route established for bid {self.log.id(bid_id)}")

        bid, offer = self.getBidAndOffer(bid_id, cursor)
        ensure(bid, "Bid not found")
        ensure(offer, "Offer not found")

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)

        if offer.swap_type == SwapTypes.XMR_SWAP:
            xmr_swap = self.queryOne(XmrSwap, cursor, {"bid_id": bid.bid_id})

            reverse_bid: bool = self.is_reverse_ads_bid(coin_from, coin_to)
            if reverse_bid:
                bid_id = self.sendADSBidIntentMessage(bid, offer, cursor)
                bid.setState(BidStates.BID_REQUEST_SENT)
                self.log.info(f"Sent ADS_BID_LF {self.logIDB(xmr_swap.bid_id)}")
            else:
                bid_id = self.sendXmrBidMessage(bid, xmr_swap, offer, cursor)
                bid.setState(BidStates.BID_SENT)
                self.log.info(f"Sent XMR_BID_FL {self.logIDB(xmr_swap.bid_id)}")
            self.saveBidInSession(bid.bid_id, bid, cursor, xmr_swap)
        else:
            bid_id = self.sendBidMessage(bid, offer, cursor)
            bid.setState(BidStates.BID_SENT)
            self.log.info(f"Sent BID {self.log.id(bid_id)}")
            self.saveBidInSession(bid_id, bid, cursor)

    def processMsg(self, msg) -> None:
        try:
            if "hex" not in msg:
                if self.debug:
                    if "error" in msg:
                        self.log.debug(
                            "Message error {}: {}.".format(msg["msgid"], msg["error"])
                        )
                    raise ValueError("Invalid msg received {}.".format(msg["msgid"]))
                return

            network_type = msg.get("msg_net", "smsg")
            if network_type == "smsg":
                self.num_smsg_messages_received += 1
            elif network_type == "simplex":
                pass  # Counted earlier, split between group and direct
            else:
                self.log.warning(f"processMsg unknown network: {network_type}")
            msg_type = int(msg["hex"][:2], 16)

            if msg_type == MessageTypes.OFFER:
                self.processOffer(msg)
            elif msg_type == MessageTypes.OFFER_REVOKE:
                self.processOfferRevoke(msg)
            # TODO: When changing from wallet keys (encrypted/locked) handle swap messages while locked
            elif msg_type == MessageTypes.BID:
                self.processBid(msg)
            elif msg_type == MessageTypes.BID_ACCEPT:
                self.processBidAccept(msg)
            elif msg_type == MessageTypes.XMR_BID_FL:
                self.processXmrBid(msg)
            elif msg_type == MessageTypes.XMR_BID_ACCEPT_LF:
                self.processXmrBidAccept(msg)
            elif msg_type == MessageTypes.XMR_BID_TXN_SIGS_FL:
                self.processXmrBidCoinALockSigs(msg)
            elif msg_type == MessageTypes.XMR_BID_LOCK_SPEND_TX_LF:
                self.processXmrBidLockSpendTx(msg)
            elif msg_type == MessageTypes.XMR_BID_SPLIT:
                self.processXmrSplitMessage(msg)
            elif msg_type == MessageTypes.XMR_BID_LOCK_RELEASE_LF:
                self.processXmrLockReleaseMessage(msg)
            elif msg_type == MessageTypes.ADS_BID_LF:
                self.processADSBidReversed(msg)
            elif msg_type == MessageTypes.ADS_BID_ACCEPT_FL:
                self.processADSBidReversedAccept(msg)
            elif msg_type == MessageTypes.CONNECT_REQ:
                self.processConnectRequest(msg)
            elif msg_type == MessageTypes.PORTAL_OFFER:
                self.processPortalOffer(msg)
            elif msg_type == MessageTypes.PORTAL_SEND:
                self.processPortalMessage(msg)

        except InactiveCoin as ex:
            self.log.debug(
                f"Ignoring message involving inactive coin {Coins(ex.coinid).name}, type {MessageTypes(msg_type).name}."
            )
        except Exception as ex:
            self.log.error(f"processMsg {ex}")
            if self.debug:
                self.log.error(traceback.format_exc())
                self.logEvent(
                    Concepts.NETWORK_MESSAGE,
                    bytes.fromhex(msg["msgid"]),
                    EventLogTypes.ERROR,
                    str(ex),
                    None,
                )

    def processZmqHashwtx(self, message) -> None:
        try:
            if Coins.PART not in self.coin_clients:
                return

            self.thread_pool.submit(self._processZmqHashwtxAsync)

        except Exception as e:
            self.log.warning(f"Error processing PART wallet transaction: {e}")
            if self.debug:
                self.log.error(traceback.format_exc())

    def _processZmqHashwtxAsync(self) -> None:
        try:
            ci = self.ci(Coins.PART)
            cc = self.coin_clients[Coins.PART]
            current_height = cc.get("chain_height", 0)

            checkAndNotifyBalanceChange(self, Coins.PART, ci, cc, current_height, "zmq")

        except Exception as e:
            self.log.warning(f"Error processing PART wallet transaction: {e}")
            if self.debug:
                self.log.error(traceback.format_exc())

    def expireBidsAndOffers(self, now) -> None:
        bids_to_expire = set()
        offers_to_expire = set()
        check_records: bool = False

        for i, (bid_id, expired_at) in enumerate(self._expiring_bids):
            if expired_at <= now:
                bids_to_expire.add(bid_id)
                self._expiring_bids.pop(i)
        for i, (offer_id, expired_at) in enumerate(self._expiring_offers):
            if expired_at <= now:
                offers_to_expire.add(offer_id)
                self._expiring_offers.pop(i)

        if (
            now - self._last_checked_expiring_bids_offers
            >= self.check_expiring_bids_offers_seconds
        ):
            check_records = True
            self._last_checked_expiring_bids = now

        if (
            len(bids_to_expire) == 0
            and len(offers_to_expire) == 0
            and check_records is False
        ):
            return

        bids_expired: int = 0
        offers_expired: int = 0
        try:
            cursor = self.openDB()

            if check_records:
                query = """SELECT 1, b.bid_id, b.expire_at FROM bids AS b, bidstates AS s WHERE b.active_ind = 1 AND b.expire_at <= :check_time AND s.state_id = b.state AND s.can_expire
                           UNION ALL
                           SELECT 2, offer_id, expire_at FROM offers WHERE active_ind = 1 AND state IN (:offer_received, :offer_sent) AND expire_at <= :check_time
                """
                q = cursor.execute(
                    query,
                    {
                        "offer_received": int(OfferStates.OFFER_RECEIVED),
                        "offer_sent": int(OfferStates.OFFER_SENT),
                        "check_time": now + self.check_expiring_bids_offers_seconds,
                    },
                )
                for entry in q:
                    record_id = entry[1]
                    expire_at = entry[2]
                    if entry[0] == 1:
                        if expire_at > now:
                            self._expiring_bids.append((record_id, expire_at))
                        else:
                            bids_to_expire.add(record_id)
                    elif entry[0] == 2:
                        if expire_at > now:
                            self._expiring_offers.append((record_id, expire_at))
                        else:
                            offers_to_expire.add(record_id)

            for bid_id in bids_to_expire:
                query = "SELECT b.states FROM bids AS b, bidstates AS s WHERE b.bid_id = :bid_id AND b.active_ind = 1 AND s.state_id = b.state AND s.can_expire"
                rows = cursor.execute(
                    query,
                    {
                        "bid_id": bid_id,
                    },
                ).fetchall()
                if len(rows) > 0:
                    new_state: int = int(BidStates.BID_EXPIRED)
                    states = (
                        bytes() if rows[0][0] is None else rows[0][0]
                    ) + pack_state(new_state, now)
                    query = "UPDATE bids SET state = :new_state, states = :states WHERE bid_id = :bid_id"
                    cursor.execute(
                        query,
                        {"bid_id": bid_id, "new_state": new_state, "states": states},
                    )
                    bids_expired += 1
            for offer_id in offers_to_expire:
                query = "SELECT states FROM offers WHERE offer_id = :offer_id AND active_ind = 1 AND state IN (:offer_received, :offer_sent)"
                rows = cursor.execute(
                    query,
                    {
                        "offer_id": offer_id,
                        "offer_received": int(OfferStates.OFFER_RECEIVED),
                        "offer_sent": int(OfferStates.OFFER_SENT),
                    },
                ).fetchall()
                if len(rows) > 0:
                    new_state: int = int(OfferStates.OFFER_EXPIRED)
                    states = (
                        bytes() if rows[0][0] is None else rows[0][0]
                    ) + pack_state(new_state, now)
                    query = "UPDATE offers SET state = :new_state, states = :states WHERE offer_id = :offer_id"
                    cursor.execute(
                        query,
                        {
                            "offer_id": offer_id,
                            "new_state": new_state,
                            "states": states,
                        },
                    )
                    offers_expired += 1
        finally:
            self.closeDB(cursor)

        if bids_expired + offers_expired > 0:
            mb = "" if bids_expired == 1 else "s"
            mo = "" if offers_expired == 1 else "s"
            self.log.debug(
                f"Expired {bids_expired} bid{mb} and {offers_expired} offer{mo}"
            )

    def update(self) -> None:
        if self._zmq_queue_enabled and self.zmqSubscriber:
            try:
                if self._read_zmq_queue:
                    topic, message, seq = self.zmqSubscriber.recv_multipart(
                        flags=zmq.NOBLOCK
                    )
                    if topic == b"smsg":
                        self.processZmqSmsg(message)
                    elif topic == b"hashwtx":
                        self.processZmqHashwtx(message)
            except zmq.Again as e:  # noqa: F841
                pass
            except Exception as e:
                self.logException(f"smsg zmq {e}")

        self.updateNetwork()

        try:
            # TODO: Wait for blocks / txns, would need to check multiple coins
            now: int = self.getTime()
            self.expireBidsAndOffers(now)

            to_remove = []
            if now - self._last_checked_progress >= self.check_progress_seconds:
                for bid_id, v in self.swaps_in_progress.items():
                    try:
                        if self.checkBidState(bid_id, v[0], v[1]) is True:
                            to_remove.append((bid_id, v[0], v[1]))
                    except Exception as ex:
                        if self.debug:
                            self.log.error("checkBidState %s", traceback.format_exc())
                        if self.is_transient_error(ex):
                            self.log.warning(
                                f"checkBidState {self.log.id(bid_id)} {ex}."
                            )
                            self.logBidEvent(
                                bid_id,
                                EventLogTypes.SYSTEM_WARNING,
                                "No connection to daemon",
                                cursor=None,
                            )
                        else:
                            self.log.error(f"checkBidState {self.log.id(bid_id)} {ex}.")
                            self.setBidError(bid_id, v[0], str(ex))

                for bid_id, bid, offer in to_remove:
                    self.deactivateBid(None, offer, bid)
                self._last_checked_progress = now

            if now - self._last_checked_watched >= self.check_watched_seconds:
                for k, c in self.coin_clients.items():
                    if (
                        k == Coins.PART_ANON
                        or k == Coins.PART_BLIND
                        or k == Coins.LTC_MWEB
                    ):
                        continue
                    if len(c["watched_outputs"]) > 0 or len(c["watched_scripts"]):
                        self.checkForSpends(k, c)
                self._last_checked_watched = now

            if now - self._last_checked_expired >= self.check_expired_seconds:
                self.expireMessages()
                self.expireMessageRoutes()
                self.expireDBRecords()
                self.checkAcceptedBids()
                self._last_checked_expired = now

                if self._max_logfile_bytes > 0:
                    logfile_size: int = self.fp.tell()
                    self.log.debug(f"Log file bytes: {logfile_size}.")
                    if logfile_size > self._max_logfile_bytes:
                        for i, log_handler in enumerate(self.log.handlers):
                            stream_name = getattr(log_handler.stream, "name", "")
                            if stream_name.endswith(".log"):
                                del self.log.handlers[i]
                                break

                        self.fp.close()
                        log_path = os.path.join(self.data_dir, "basicswap.log")
                        if self._max_logfiles == 1:
                            os.remove(log_path)
                        else:
                            last_log = os.path.join(
                                self.data_dir,
                                f"basicswap_{self._max_logfiles - 1:0>2}.log",
                            )
                            if os.path.exists(last_log):
                                os.remove(last_log)

                            for i in range(self._max_logfiles - 2, 0, -1):
                                path_from = os.path.join(
                                    self.data_dir, f"basicswap_{i:0>2}.log"
                                )
                                path_to = os.path.join(
                                    self.data_dir, f"basicswap_{i + 1:0>2}.log"
                                )
                                if os.path.exists(path_from):
                                    os.rename(path_from, path_to)

                            log_path = os.path.join(self.data_dir, "basicswap.log")
                            os.rename(
                                log_path,
                                os.path.join(self.data_dir, "basicswap_01.log"),
                            )

                        self.openLogFile()

                        stream_fp = logging.StreamHandler(self.fp)
                        stream_fp.setFormatter(self.log_formatter)
                        self.log.addHandler(stream_fp)
                        self.log.info("Log file rotated.")

            if now - self._last_checked_actions >= self.check_actions_seconds:
                self.checkQueuedActions()
                self._last_checked_actions = now

            if (
                now - self._last_checked_split_messages
                >= self.check_split_messages_seconds
            ):
                self.checkSplitMessages()
                self._last_checked_split_messages = now

            if (
                len(to_remove) > 0
                or now - self._last_checked_delayed_auto_accept
                >= self.check_delayed_auto_accept_seconds
            ):
                self.checkDelayedAutoAccept()
                self._last_checked_delayed_auto_accept = now

            if now - self._last_checked_updates >= self.check_updates_seconds:
                self.checkForUpdates()

        except Exception as ex:
            self.logException(f"update {ex}")

    def manualBidUpdate(self, bid_id: bytes, data) -> None:
        self.log.info(f"Manually updating bid {self.log.id(bid_id)}.")

        add_bid_action = -1
        try:
            cursor = self.openDB()
            bid, offer = self.getBidAndOffer(bid_id, cursor)
            ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
            ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")

            has_changed = False
            if bid.state != data["bid_state"]:
                bid.setState(data["bid_state"])
                self.log.warning(f"Set state to {strBidState(bid.state)}.")
                has_changed = True

            if data.get("bid_action", -1) != -1:
                self.log.warning(
                    "Adding action {}.".format(ActionTypes(data["bid_action"]).name)
                )
                add_bid_action = ActionTypes(data["bid_action"])
                has_changed = True

            if "debug_ind" in data:
                if bid.debug_ind != data["debug_ind"]:
                    if bid.debug_ind is None and data["debug_ind"] == -1:
                        pass  # Already unset
                    else:
                        bid.debug_ind = data["debug_ind"]
                        self.log.debug(
                            f"Bid {self.log.id(bid_id)} Setting debug flag: {bid.debug_ind}"
                        )
                        has_changed = True

            if data.get("kbs_other", None) is not None:
                return xmr_swap_1.recoverNoScriptTxnWithKey(
                    self, bid_id, data["kbs_other"], cursor
                )

            if has_changed:
                activate_bid = False
                if bid.state and isActiveBidState(bid.state):
                    activate_bid = True

                if add_bid_action > -1:
                    delay = self.get_delay_event_seconds()
                    self.createActionInSession(delay, add_bid_action, bid_id, cursor)

                if activate_bid:
                    self.activateBid(cursor, bid)
                else:
                    self.deactivateBid(cursor, offer, bid)

                self.saveBidInSession(bid_id, bid, cursor)
                self.commitDB()
            else:
                raise ValueError("No changes")
        finally:
            self.closeDB(cursor, commit=False)

    def editGeneralSettings(self, data):
        self.log.info("Updating general settings.")
        settings_changed = False
        suggest_reboot = False
        settings_copy = copy.deepcopy(self.settings)
        with self.mxDB:
            if "debug" in data:
                new_value = data["debug"]
                ensure(isinstance(new_value, bool), "New debug value not boolean")
                if settings_copy.get("debug", False) != new_value:
                    self.debug = new_value
                    settings_copy["debug"] = new_value
                    settings_changed = True

            if "debug_ui" in data:
                new_value = data["debug_ui"]
                ensure(isinstance(new_value, bool), "New debug_ui value not boolean")
                if settings_copy.get("debug_ui", False) != new_value:
                    self.debug_ui = new_value
                    settings_copy["debug_ui"] = new_value
                    settings_changed = True

            if "expire_db_records" in data:
                new_value = data["expire_db_records"]
                ensure(
                    isinstance(new_value, bool),
                    "New expire_db_records value not boolean",
                )
                if settings_copy.get("expire_db_records", False) != new_value:
                    self._expire_db_records = new_value
                    settings_copy["expire_db_records"] = new_value
                    settings_changed = True

            if "show_chart" in data:
                new_value = data["show_chart"]
                ensure(isinstance(new_value, bool), "New show_chart value not boolean")
                if settings_copy.get("show_chart", True) != new_value:
                    settings_copy["show_chart"] = new_value
                    settings_changed = True

            if "chart_api_key" in data:
                new_value = data["chart_api_key"]
                ensure(
                    isinstance(new_value, str), "New chart_api_key value not a string"
                )
                ensure(len(new_value) <= 128, "New chart_api_key value too long")
                if all(c in string.hexdigits for c in new_value):
                    if settings_copy.get("chart_api_key", "") != new_value:
                        settings_copy["chart_api_key"] = new_value
                        if "chart_api_key_enc" in settings_copy:
                            settings_copy.pop("chart_api_key_enc")
                        settings_changed = True
                else:
                    # Encode value as hex to avoid escaping
                    new_value = new_value.encode("UTF-8").hex()
                    if settings_copy.get("chart_api_key_enc", "") != new_value:
                        settings_copy["chart_api_key_enc"] = new_value
                        if "chart_api_key" in settings_copy:
                            settings_copy.pop("chart_api_key")
                        settings_changed = True

            if "coingecko_api_key" in data:
                new_value = data["coingecko_api_key"]
                ensure(
                    isinstance(new_value, str),
                    "New coingecko_api_key value not a string",
                )
                ensure(len(new_value) <= 128, "New coingecko_api_keyvalue too long")
                if all(c in string.hexdigits for c in new_value):
                    if settings_copy.get("coingecko_api_key", "") != new_value:
                        settings_copy["coingecko_api_key"] = new_value
                        if "coingecko_api_key_enc" in settings_copy:
                            settings_copy.pop("coingecko_api_key_enc")
                        settings_changed = True
                else:
                    # Encode value as hex to avoid escaping
                    new_value = new_value.encode("UTF-8").hex()
                    if settings_copy.get("coingecko_api_key_enc", "") != new_value:
                        settings_copy["coingecko_api_key_enc"] = new_value
                        if "coingecko_api_key" in settings_copy:
                            settings_copy.pop("coingecko_api_key")
                        settings_changed = True

            if "enabled_chart_coins" in data:
                new_value = data["enabled_chart_coins"].strip()
                ensure(
                    isinstance(new_value, str),
                    "New enabled_chart_coins value not a string",
                )
                if new_value.lower() == "all" or new_value == "":
                    pass
                else:
                    tickers = new_value.split(",")
                    seen_tickers = []
                    for ticker in tickers:
                        upcased_ticker = ticker.strip().upper()
                        if upcased_ticker.lower() not in ticker_map:
                            raise ValueError(f"Unknown coin: {ticker}")
                        if upcased_ticker in seen_tickers:
                            raise ValueError(f"Duplicate coin: {ticker}")
                        seen_tickers.append(upcased_ticker)
                if settings_copy.get("enabled_chart_coins", "") != new_value:
                    settings_copy["enabled_chart_coins"] = new_value
                    settings_changed = True

            if "notifications_new_offers" in data:
                new_value = data["notifications_new_offers"]
                ensure(
                    isinstance(new_value, bool),
                    "New notifications_new_offers value not boolean",
                )
                if settings_copy.get("notifications_new_offers", False) != new_value:
                    settings_copy["notifications_new_offers"] = new_value
                    settings_changed = True

            if "notifications_new_bids" in data:
                new_value = data["notifications_new_bids"]
                ensure(
                    isinstance(new_value, bool),
                    "New notifications_new_bids value not boolean",
                )
                if settings_copy.get("notifications_new_bids", True) != new_value:
                    settings_copy["notifications_new_bids"] = new_value
                    settings_changed = True

            if "notifications_bid_accepted" in data:
                new_value = data["notifications_bid_accepted"]
                ensure(
                    isinstance(new_value, bool),
                    "New notifications_bid_accepted value not boolean",
                )
                if settings_copy.get("notifications_bid_accepted", True) != new_value:
                    settings_copy["notifications_bid_accepted"] = new_value
                    settings_changed = True

            if "notifications_balance_changes" in data:
                new_value = data["notifications_balance_changes"]
                ensure(
                    isinstance(new_value, bool),
                    "New notifications_balance_changes value not boolean",
                )
                if (
                    settings_copy.get("notifications_balance_changes", True)
                    != new_value
                ):
                    settings_copy["notifications_balance_changes"] = new_value
                    settings_changed = True

            if "notifications_outgoing_transactions" in data:
                new_value = data["notifications_outgoing_transactions"]
                ensure(
                    isinstance(new_value, bool),
                    "New notifications_outgoing_transactions value not boolean",
                )
                if (
                    settings_copy.get("notifications_outgoing_transactions", True)
                    != new_value
                ):
                    settings_copy["notifications_outgoing_transactions"] = new_value
                    settings_changed = True

            if "notifications_duration" in data:
                new_value = data["notifications_duration"]
                ensure(
                    isinstance(new_value, int),
                    "New notifications_duration value not integer",
                )
                ensure(
                    5 <= new_value <= 60,
                    "notifications_duration must be between 5 and 60 seconds",
                )
                if settings_copy.get("notifications_duration", 20) != new_value:
                    settings_copy["notifications_duration"] = new_value
                    settings_changed = True

            if settings_changed:
                settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
                settings_path_new = settings_path + ".new"
                shutil.copyfile(settings_path, settings_path + ".last")
                with open(settings_path_new, "w") as fp:
                    json.dump(settings_copy, fp, indent=4)
                shutil.move(settings_path_new, settings_path)
                self.settings = settings_copy
        return settings_changed, suggest_reboot

    def editSettings(self, coin_name: str, data):
        self.log.info(f"Updating settings {coin_name}.")
        settings_changed = False
        suggest_reboot = False
        settings_copy = copy.deepcopy(self.settings)
        with self.mxDB:
            settings_cc = settings_copy["chainclients"][coin_name]
            if "lookups" in data:
                if settings_cc.get("chain_lookups", "local") != data["lookups"]:
                    settings_changed = True
                    settings_cc["chain_lookups"] = data["lookups"]
                    for coin, cc in self.coin_clients.items():
                        if cc["name"] == coin_name:
                            cc["chain_lookups"] = data["lookups"]
                            break

            for setting in (
                "manage_daemon",
                "rpchost",
                "rpcport",
                "automatically_select_daemon",
            ):
                if setting not in data:
                    continue
                if settings_cc.get(setting) != data[setting]:
                    settings_changed = True
                    suggest_reboot = True
                    settings_cc[setting] = data[setting]

            if "remotedaemonurls" in data:
                remotedaemonurls_in = data["remotedaemonurls"].split("\n")
                remotedaemonurls = set()
                for url in remotedaemonurls_in:
                    if url.count(":") > 0:
                        remotedaemonurls.add(url.strip())

                if set(settings_cc.get("remote_daemon_urls", [])) != remotedaemonurls:
                    settings_cc["remote_daemon_urls"] = list(remotedaemonurls)
                    settings_changed = True
                    suggest_reboot = True

            # Ensure remote_daemon_urls appears in settings if automatically_select_daemon is present
            if (
                "automatically_select_daemon" in settings_cc
                and "remote_daemon_urls" not in settings_cc
            ):
                settings_cc["remote_daemon_urls"] = []
                settings_changed = True

            if "fee_priority" in data:
                new_fee_priority = data["fee_priority"]
                ensure(
                    new_fee_priority >= 0 and new_fee_priority < 4, "Invalid priority"
                )

                if settings_cc.get("fee_priority", 0) != new_fee_priority:
                    settings_changed = True
                    settings_cc["fee_priority"] = new_fee_priority
                    for coin, cc in self.coin_clients.items():
                        if cc["name"] == coin_name:
                            cc["fee_priority"] = new_fee_priority
                            if self.isCoinActive(coin):
                                self.ci(coin).setFeePriority(new_fee_priority)
                            break

            if "conf_target" in data:
                new_conf_target = data["conf_target"]
                ensure(
                    new_conf_target >= 1 and new_conf_target < 33, "Invalid conf_target"
                )

                if settings_cc.get("conf_target", 2) != new_conf_target:
                    settings_changed = True
                    settings_cc["conf_target"] = new_conf_target
                    for coin, cc in self.coin_clients.items():
                        if cc["name"] == coin_name:
                            cc["conf_target"] = new_conf_target
                            if self.isCoinActive(coin):
                                self.ci(coin).setConfTarget(new_conf_target)
                            break

            if "anon_tx_ring_size" in data:
                new_anon_tx_ring_size = data["anon_tx_ring_size"]
                ensure(
                    new_anon_tx_ring_size >= 3 and new_anon_tx_ring_size < 33,
                    "Invalid anon_tx_ring_size",
                )

                if settings_cc.get("anon_tx_ring_size", 12) != new_anon_tx_ring_size:
                    settings_changed = True
                    settings_cc["anon_tx_ring_size"] = new_anon_tx_ring_size
                    for coin, cc in self.coin_clients.items():
                        if cc["name"] == coin_name:
                            cc["anon_tx_ring_size"] = new_anon_tx_ring_size
                            if self.isCoinActive(coin):
                                self.ci(coin).setAnonTxRingSize(new_anon_tx_ring_size)
                            break

            if "wallet_pwd" in data:
                new_wallet_pwd = data["wallet_pwd"]
                if settings_cc.get("wallet_pwd", "") != new_wallet_pwd:
                    settings_changed = True
                    settings_cc["wallet_pwd"] = new_wallet_pwd

            if settings_changed:
                settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
                settings_path_new = settings_path + ".new"
                shutil.copyfile(settings_path, settings_path + ".last")
                with open(settings_path_new, "w") as fp:
                    json.dump(settings_copy, fp, indent=4)
                shutil.move(settings_path_new, settings_path)
                self.settings = settings_copy
        return settings_changed, suggest_reboot

    def enableCoin(self, coin_name: str) -> None:
        self.log.info(f"Enabling coin {coin_name}.")

        coin_id = self.getCoinIdFromName(coin_name)
        if coin_id in (Coins.PART, Coins.PART_BLIND, Coins.PART_ANON):
            raise ValueError("Invalid coin")

        settings_cc = self.settings["chainclients"][coin_name]
        if "connection_type_prev" not in settings_cc:
            raise ValueError("Can't find previous value.")
        settings_cc["connection_type"] = settings_cc["connection_type_prev"]
        del settings_cc["connection_type_prev"]
        if "manage_daemon_prev" in settings_cc:
            settings_cc["manage_daemon"] = settings_cc["manage_daemon_prev"]
            del settings_cc["manage_daemon_prev"]
        if "manage_wallet_daemon_prev" in settings_cc:
            settings_cc["manage_wallet_daemon"] = settings_cc[
                "manage_wallet_daemon_prev"
            ]
            del settings_cc["manage_wallet_daemon_prev"]

        settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
        shutil.copyfile(settings_path, settings_path + ".last")
        with open(settings_path, "w") as fp:
            json.dump(self.settings, fp, indent=4)
        # Client must be restarted

    def disableCoin(self, coin_name: str) -> None:
        self.log.info(f"Disabling coin {coin_name}.")

        coin_id = self.getCoinIdFromName(coin_name)
        if coin_id in (Coins.PART, Coins.PART_BLIND, Coins.PART_ANON):
            raise ValueError("Invalid coin")

        settings_cc = self.settings["chainclients"][coin_name]

        if settings_cc["connection_type"] != "rpc":
            raise ValueError("Already disabled.")

        settings_cc["manage_daemon_prev"] = settings_cc["manage_daemon"]
        settings_cc["manage_daemon"] = False
        settings_cc["connection_type_prev"] = settings_cc["connection_type"]
        settings_cc["connection_type"] = "none"

        if "manage_wallet_daemon" in settings_cc:
            settings_cc["manage_wallet_daemon_prev"] = settings_cc[
                "manage_wallet_daemon"
            ]
            settings_cc["manage_wallet_daemon"] = False

        settings_path = os.path.join(self.data_dir, cfg.CONFIG_FILENAME)
        shutil.copyfile(settings_path, settings_path + ".last")
        with open(settings_path, "w") as fp:
            json.dump(self.settings, fp, indent=4)
        # Client must be restarted

    def getSummary(self, opts=None):
        num_watched_outputs = 0
        for c, v in self.coin_clients.items():
            if c in (Coins.PART_ANON, Coins.PART_BLIND):
                continue
            num_watched_outputs += len(v["watched_outputs"])

        now: int = self.getTime()
        q_bids_str: str = (
            """SELECT
               COUNT(CASE WHEN b.was_sent THEN 1 ELSE NULL END) AS count_sent,
               COUNT(CASE WHEN b.was_sent AND (s.in_progress OR (s.swap_ended = 0 AND b.expire_at > :now AND o.expire_at > :now)) THEN 1 ELSE NULL END) AS count_sent_active,
               COUNT(CASE WHEN b.was_received THEN 1 ELSE NULL END) AS count_received,
               COUNT(CASE WHEN b.was_received AND s.can_accept AND b.expire_at > :now AND o.expire_at > :now THEN 1 ELSE NULL END) AS count_available,
               COUNT(CASE WHEN b.was_received AND (s.in_progress OR (s.swap_ended = 0 AND b.expire_at > :now AND o.expire_at > :now)) THEN 1 ELSE NULL END) AS count_recv_active
               FROM bids b
               JOIN offers o ON b.offer_id = o.offer_id
               JOIN bidstates s ON b.state = s.state_id
               WHERE b.active_ind = 1"""
        )

        q_offers_str: str = (
            """SELECT
               COUNT(CASE WHEN expire_at > :now THEN 1 ELSE NULL END) AS count_active,
               COUNT(CASE WHEN was_sent THEN 1 ELSE NULL END) AS count_sent,
               COUNT(CASE WHEN was_sent AND expire_at > :now THEN 1 ELSE NULL END) AS count_sent_active
               FROM offers WHERE active_ind = 1"""
        )

        try:
            cursor = self.openDB()
            q = cursor.execute(q_bids_str, {"now": now}).fetchone()
            bids_sent = q[0]
            bids_sent_active = q[1]
            bids_received = q[2]
            bids_available = q[3]
            bids_recv_active = q[4]

            q = cursor.execute(q_offers_str, {"now": now}).fetchone()
            num_offers = q[0]
            num_sent_offers = q[1]
            num_sent_active_offers = q[2]
        finally:
            self.closeDB(cursor, commit=False)

        rv = {
            "network": self.chain,
            "num_swapping": len(self.swaps_in_progress),
            "num_network_offers": num_offers,
            "num_sent_offers": num_sent_offers,
            "num_sent_active_offers": num_sent_active_offers,
            "num_recv_bids": bids_received,
            "num_sent_bids": bids_sent,
            "num_sent_active_bids": bids_sent_active,
            "num_recv_active_bids": bids_recv_active,
            "num_available_bids": bids_available,
            "num_watched_outputs": num_watched_outputs,
        }
        return rv

    def getBlockchainInfo(self, coin):
        ci = self.ci(coin)

        try:
            blockchaininfo = ci.getBlockchainInfo()

            rv = {
                "version": self.coin_clients[coin]["core_version"],
                "name": ci.coin_name(),
                "blocks": blockchaininfo["blocks"],
                "synced": "{:.2f}".format(
                    round(100 * blockchaininfo["verificationprogress"], 2)
                ),
            }

            if "known_block_count" in blockchaininfo:
                rv["known_block_count"] = blockchaininfo["known_block_count"]
            if "bootstrapping" in blockchaininfo:
                rv["bootstrapping"] = blockchaininfo["bootstrapping"]

            return rv
        except Exception as e:
            self.log.warning(f"getWalletInfo failed with: {e}.")

    def getWalletInfo(self, coin):
        ci = self.ci(coin)

        try:
            walletinfo = ci.getWalletInfo()
            rv = {
                "deposit_address": self.getCachedAddressForCoin(coin),
                "balance": ci.format_amount(walletinfo["balance"], conv_int=True),
                "unconfirmed": ci.format_amount(
                    walletinfo["unconfirmed_balance"], conv_int=True
                ),
                "expected_seed": ci.knownWalletSeed(),
                "encrypted": walletinfo["encrypted"],
                "locked": walletinfo["locked"],
            }

            if "wallet_blocks" in walletinfo:
                rv["wallet_blocks"] = walletinfo["wallet_blocks"]

            if "immature_balance" in walletinfo:
                rv["immature"] = ci.format_amount(
                    walletinfo["immature_balance"], conv_int=True
                )

            if "locked_utxos" in walletinfo:
                rv["locked_utxos"] = walletinfo["locked_utxos"]

            if coin == Coins.PART:
                rv["stealth_address"] = self.getCachedStealthAddressForCoin(Coins.PART)
                rv["anon_balance"] = walletinfo["anon_balance"]
                rv["anon_pending"] = (
                    walletinfo["unconfirmed_anon"] + walletinfo["immature_anon_balance"]
                )
                rv["blind_balance"] = walletinfo["blind_balance"]
                rv["blind_unconfirmed"] = walletinfo["unconfirmed_blind"]
            elif coin in (Coins.XMR, Coins.WOW):
                rv["main_address"] = self.getCachedMainWalletAddress(ci)
            elif coin == Coins.NAV:
                rv["immature"] = walletinfo["immature_balance"]
            elif coin == Coins.LTC:
                try:
                    rv["mweb_address"] = self.getCachedStealthAddressForCoin(
                        Coins.LTC_MWEB
                    )
                except Exception as e:
                    self.log.warning(
                        f"getCachedStealthAddressForCoin for {ci.coin_name()} failed with: {e}."
                    )
                rv["mweb_balance"] = walletinfo["mweb_balance"]
                rv["mweb_pending"] = (
                    walletinfo["mweb_unconfirmed"] + walletinfo["mweb_immature"]
                )

            return rv
        except Exception as e:
            self.log.warning(f"getWalletInfo for {ci.coin_name()} failed with: {e}.")

    def addWalletInfoRecord(self, coin, info_type, wi) -> None:
        coin_id = int(coin)
        cursor = self.openDB()
        try:
            now: int = self.getTime()
            self.add(
                Wallets(
                    coin_id=coin,
                    balance_type=info_type,
                    wallet_data=json.dumps(wi),
                    created_at=now,
                ),
                cursor,
            )
            query_str = "DELETE FROM wallets WHERE (coin_id = :coin_id AND balance_type = :info_type) AND record_id NOT IN (SELECT record_id FROM wallets WHERE coin_id = :coin_id AND balance_type = :info_type ORDER BY created_at DESC LIMIT 3 )"
            cursor.execute(query_str, {"coin_id": coin_id, "info_type": info_type})
            self.commitDB()
        except Exception as e:
            self.log.error(f"addWalletInfoRecord {e}.")
        finally:
            self.closeDB(cursor, commit=False)

    def updateWalletInfo(self, coin) -> None:
        # Store wallet info to db so it's available after startup
        try:
            bi = self.getBlockchainInfo(coin)
            if bi:
                self.addWalletInfoRecord(coin, 0, bi)

            # monero-wallet-rpc is slow/unresponsive while syncing
            wi = self.getWalletInfo(coin)
            if wi:
                self.addWalletInfoRecord(coin, 1, wi)
        except Exception as e:
            self.log.error(f"updateWalletInfo {e}.")
        finally:
            self._updating_wallets_info[int(coin)] = False

    def updateWalletsInfo(
        self,
        force_update: bool = False,
        only_coin: bool = None,
        wait_for_complete: bool = False,
    ) -> None:
        now: int = self.getTime()
        if not force_update and now - self._last_updated_wallets_info < 30:
            return
        for c in Coins:
            if only_coin is not None and c != only_coin:
                continue
            if c not in chainparams:
                continue
            cc = self.coin_clients[c]
            if cc["connection_type"] == "rpc":
                if (
                    not force_update
                    and now - cc.get("last_updated_wallet_info", 0) < 30
                ):
                    return
                cc["last_updated_wallet_info"] = self.getTime()
                self._updating_wallets_info[int(c)] = True
                handle = self.thread_pool.submit(self.updateWalletInfo, c)
                if wait_for_complete:
                    try:
                        handle.result(timeout=self._wallet_update_timeout)
                    except Exception as e:
                        self.log.error(f"updateWalletInfo {e}.")

    def getWalletsInfo(self, opts=None):
        rv = {}
        for c in self.activeCoins():
            key = chainparams[c]["ticker"] if opts.get("ticker_key", False) else c
            try:
                rv[key] = self.getWalletInfo(c)
                rv[key].update(self.getBlockchainInfo(c))
            except Exception as ex:
                rv[key] = {"name": getCoinName(c), "error": str(ex)}
        return rv

    def getCachedWalletsInfo(self, opts=None):
        rv = {}
        try:
            cursor = self.openDB()
            query_data: dict = {}
            where_str = ""
            if opts is not None and "coin_id" in opts:
                where_str = "WHERE coin_id = :coin_id"
                query_data["coin_id"] = opts["coin_id"]
            inner_str = f"SELECT coin_id, balance_type, MAX(created_at) as max_created_at FROM wallets {where_str} GROUP BY coin_id, balance_type"
            query_str = f"SELECT a.coin_id, a.balance_type, wallet_data, created_at FROM wallets a, ({inner_str}) b WHERE a.coin_id = b.coin_id AND a.balance_type = b.balance_type AND a.created_at = b.max_created_at"

            q = cursor.execute(query_str, query_data)
            for row in q:
                coin_id = row[0]

                if self.isCoinActive(coin_id) is False:
                    # Skip cached info if coin was disabled
                    continue

                wallet_data = json.loads(row[2])
                if row[1] == 1:
                    wallet_data["lastupdated"] = row[3]
                    wallet_data["updating"] = self._updating_wallets_info.get(
                        coin_id, False
                    )

                    # Ensure the latest addresses are displayed
                    coin_name: str = chainparams[coin_id]["name"]
                    c2 = self.getNewDBCursor()
                    q2 = c2.execute(
                        "SELECT key, value FROM kv_string WHERE key = ? OR key = ?",
                        (f"receive_addr_{coin_name}", f"stealth_addr_{coin_name}"),
                    )
                    for row2 in q2:
                        if row2[0].startswith("stealth"):
                            if coin_id == Coins.LTC:
                                wallet_data["mweb_address"] = row2[1]
                            else:
                                wallet_data["stealth_address"] = row2[1]
                        else:
                            wallet_data["deposit_address"] = row2[1]
                    c2.close()

                if coin_id in rv:
                    rv[coin_id].update(wallet_data)
                else:
                    rv[coin_id] = wallet_data
        finally:
            self.closeDB(cursor)

        if opts is not None and "coin_id" in opts:
            return rv

        for c in self.activeCoins():
            coin_id = int(c)
            if coin_id not in rv:
                rv[coin_id] = {
                    "name": getCoinName(c),
                    "no_data": True,
                    "updating": self._updating_wallets_info.get(coin_id, False),
                }

        return rv

    def countAcceptedBids(self, offer_id: bytes = None) -> int:
        cursor = self.openDB()
        try:
            query: str = "SELECT COUNT(*) FROM bids WHERE state >= :state_ind"
            query_data: dict = {"state_ind": int(BidStates.BID_ACCEPTED)}
            if offer_id:
                query += " AND offer_id = :offer_id"
                query_data["offer_id":offer_id]

            q = cursor.execute(query, query_data).fetchone()
            return q[0]
        finally:
            self.closeDB(cursor, commit=False)

    def listOffers(self, sent: bool = False, filters={}):
        cursor = self.openDB()
        try:
            rv = []
            now: int = self.getTime()

            query_suffix: str = ""
            query_data: dict = {"now": now}

            if sent:
                query_suffix += " AND was_sent = 1"

                active_state = filters.get("active", "any")
                if active_state == "active":
                    query_suffix += " AND (expire_at > :now AND active_ind = 1)"
                elif active_state == "expired":
                    query_suffix += " AND expire_at <= :now"
                elif active_state == "revoked":
                    query_suffix += " AND active_ind != 1"
            else:
                query_suffix += " AND (expire_at > :now AND active_ind = 1)"

            filter_offer_id = filters.get("offer_id", None)
            if filter_offer_id is not None:
                query_suffix += " AND offer_id = :filter_offer_id"
                query_data["filter_offer_id"] = filter_offer_id
            filter_coin_from = filters.get("coin_from", None)
            if filter_coin_from and filter_coin_from > -1:
                query_suffix += " AND coin_from = :filter_coin_from"
                query_data["filter_coin_from"] = int(filter_coin_from)
            filter_coin_to = filters.get("coin_to", None)
            if filter_coin_to and filter_coin_to > -1:
                query_suffix += " AND coin_to = :filter_coin_to"
                query_data["filter_coin_to"] = int(filter_coin_to)

            filter_include_sent = filters.get("include_sent", None)
            if filter_include_sent is not None and filter_include_sent is not True:
                query_suffix += " AND was_sent = 0"

            filter_auto_accept_type = filters.get("auto_accept_type", None)
            if filter_auto_accept_type and filter_auto_accept_type != "any":
                query_suffix += " AND auto_accept_type = :filter_auto_accept_type"
                query_data["filter_auto_accept_type"] = int(filter_auto_accept_type)

            query_suffix += getOrderByStr(filters)

            limit = filters.get("limit", None)
            if limit is not None:
                query_suffix += " LIMIT :limit"
                query_data["limit"] = limit
            offset = filters.get("offset", None)
            if offset is not None:
                query_suffix += " OFFSET :offset"
                query_data["offset"] = offset

            q = self.query(
                Offer, cursor, query_suffix=query_suffix, extra_query_data=query_data
            )
            for row in q:
                offer = row
                # Show offers for enabled coins only
                try:
                    _ = self.ci(offer.coin_from)
                    _ = self.ci(offer.coin_to)
                except Exception as e:  # noqa: F841
                    continue
                rv.append(offer)
            return rv
        finally:
            self.closeDB(cursor, commit=False)

    def activeBidsQueryStr(
        self, offer_table: str = "offers", bids_table: str = "bids"
    ) -> str:
        offers_inset: str = ""
        if offer_table != "":
            offers_inset = f" AND {offer_table}.expire_at > :now"

        inactive_states_str = ", ".join([str(int(s)) for s in inactive_states])
        return f" ({bids_table}.state NOT IN ({inactive_states_str}) AND ({bids_table}.state > {BidStates.BID_RECEIVED} OR ({bids_table}.expire_at > :now{offers_inset}))) "

    def listBids(
        self,
        sent: bool = False,
        offer_id: bytes = None,
        for_html: bool = False,
        filters={},
    ):
        cursor = self.openDB()
        try:
            rv = []
            now: int = self.getTime()

            query_data: dict = {
                "now": now,
                "ads_swap": SwapTypes.XMR_SWAP,
                "itx_type": TxTypes.ITX,
                "ptx_type": TxTypes.PTX,
                "al_type": TxTypes.XMR_SWAP_A_LOCK,
                "bl_type": TxTypes.XMR_SWAP_B_LOCK,
            }
            query_str: str = (
                "SELECT "
                + "bids.created_at, bids.expire_at, bids.bid_id, bids.offer_id, bids.amount, bids.state, bids.was_received, "
                + "tx1.state, tx2.state, offers.coin_from, bids.rate, bids.bid_addr, offers.bid_reversed, bids.amount_to, offers.coin_to "
                + "FROM bids "
                + "LEFT JOIN offers ON offers.offer_id = bids.offer_id "
                + "LEFT JOIN transactions AS tx1 ON tx1.bid_id = bids.bid_id AND tx1.tx_type = CASE WHEN offers.swap_type = :ads_swap THEN :al_type ELSE :itx_type END "
                + "LEFT JOIN transactions AS tx2 ON tx2.bid_id = bids.bid_id AND tx2.tx_type = CASE WHEN offers.swap_type = :ads_swap THEN :bl_type ELSE :ptx_type END "
            )

            query_str += "WHERE bids.active_ind = 1 "
            filter_bid_id = filters.get("bid_id", None)
            if filter_bid_id is not None:
                query_str += "AND bids.bid_id = :filter_bid_id "
                query_data["filter_bid_id"] = filter_bid_id

            if offer_id is not None:
                query_str += "AND bids.offer_id = :filter_offer_id "
                query_data["filter_offer_id"] = offer_id
            elif sent is None:
                pass  # Return both sent and received
            elif sent:
                query_str += "AND bids.was_sent = 1 "
            else:
                query_str += "AND bids.was_received = 1 "

            bid_state_ind = filters.get("bid_state_ind", -1)
            if bid_state_ind != -1:
                query_str += "AND bids.state = :bid_state_ind "
                query_data["bid_state_ind"] = bid_state_ind

            with_available_or_active = filters.get("with_available_or_active", False)
            with_expired = filters.get("with_expired", True)
            if with_available_or_active:
                query_str += " AND " + self.activeBidsQueryStr()
            else:
                if with_expired is not True:
                    query_str += (
                        "AND bids.expire_at > :now AND offers.expire_at > :now "
                    )

            query_str += getOrderByStr(filters, table_name="bids")

            limit = filters.get("limit", None)
            if limit is not None:
                query_str += " LIMIT :limit"
                query_data["limit"] = limit
            offset = filters.get("offset", None)
            if offset is not None:
                query_str += " OFFSET :offset"
                query_data["offset"] = offset

            q = cursor.execute(query_str, query_data)
            for row in q:
                result = [x for x in row]
                coin_from = result[9]
                coin_to = result[14]
                # Show bids for enabled coins only
                try:
                    ci_from = self.ci(coin_from)
                    _ = self.ci(coin_to)
                except Exception as e:  # noqa: F841
                    continue
                if result[12]:  # Reversed
                    amount_from = result[13]
                    amount_to = result[4]
                    result[4] = amount_from
                    result[13] = amount_to
                    result[10] = ci_from.make_int(amount_to / amount_from, r=1)

                rv.append(result)
            return rv
        finally:
            self.closeDB(cursor, commit=False)

    def listSwapsInProgress(self, for_html=False):
        self.mxDB.acquire()
        try:
            rv = []
            for k, v in self.swaps_in_progress.items():
                bid, offer = v
                itx_state = None
                ptx_state = None

                if offer.swap_type == SwapTypes.XMR_SWAP:
                    itx_state = bid.xmr_a_lock_tx.state if bid.xmr_a_lock_tx else None
                    ptx_state = bid.xmr_b_lock_tx.state if bid.xmr_b_lock_tx else None
                else:
                    itx_state = bid.getITxState()
                    ptx_state = bid.getPTxState()

                rv.append((k, bid.offer_id.hex(), bid.state, itx_state, ptx_state))
            return rv
        finally:
            self.mxDB.release()

    def listWatchedOutputs(self):
        self.mxDB.acquire()
        try:
            rv = []
            rv_heights = []
            for c, v in self.coin_clients.items():
                if c in (Coins.PART_ANON, Coins.PART_BLIND):  # exclude duplicates
                    continue
                if self.coin_clients[c]["connection_type"] == "rpc":
                    rv_heights.append((c, v["last_height_checked"]))
                for o in v["watched_outputs"]:
                    rv.append((c, o.bid_id, o.txid_hex, o.vout, o.tx_type))
            return (rv, rv_heights)
        finally:
            self.mxDB.release()

    def listAllSMSGAddresses(self, filters={}, cursor=None):
        query_str: str = (
            "SELECT addr_id, addr, use_type, active_ind, created_at, note, pubkey FROM smsgaddresses WHERE 1=1 "
        )
        query_data: dict = {}

        if filters.get("exclude_inactive", True) is True:
            query_str += " AND active_ind = :active_ind "
            query_data["active_ind"] = 1
        if "addr_id" in filters:
            query_str += " AND addr_id = :addr_id "
            query_data["addr_id"] = filters["addr_id"]
        if "addressnote" in filters:
            query_str += " AND note LIKE :note "
            query_data["note"] = "%" + filters["addressnote"] + "%"
        if "addr_type" in filters and filters["addr_type"] > -1:
            query_str += " AND use_type = :addr_type "
            query_data["addr_type"] = filters["addr_type"]

        query_str += getOrderByStr(filters)
        limit = filters.get("limit", None)
        if limit is not None:
            query_str += " LIMIT :limit"
            query_data["limit"] = limit
        offset = filters.get("offset", None)
        if offset is not None:
            query_str += " OFFSET :offset"
            query_data["offset"] = offset

        try:
            use_cursor = self.openDB(cursor)
            rv = []
            q = use_cursor.execute(query_str, query_data)
            for row in q:
                rv.append(
                    {
                        "id": row[0],
                        "addr": row[1],
                        "type": row[2],
                        "active_ind": row[3],
                        "created_at": row[4],
                        "note": row[5],
                        "pubkey": row[6],
                    }
                )
            return rv
        finally:
            if cursor is None:
                self.closeDB(use_cursor, commit=False)

    def listSMSGAddresses(self, use_type_str: str):
        if use_type_str == "offer_send_from":
            use_type = AddressTypes.OFFER
        elif use_type_str == "offer_send_to":
            use_type = AddressTypes.SEND_OFFER
        elif use_type_str == "bid":
            use_type = AddressTypes.BID
        else:
            raise ValueError("Unknown address type")

        try:
            cursor = self.openDB()
            rv = []
            q = cursor.execute(
                "SELECT sa.addr, ki.label FROM smsgaddresses AS sa LEFT JOIN knownidentities AS ki ON sa.addr = ki.address WHERE sa.use_type = ? AND sa.active_ind = 1 ORDER BY sa.addr_id DESC",
                (use_type,),
            )
            for row in q:
                rv.append((row[0], row[1]))
            return rv
        finally:
            self.closeDB(cursor, commit=False)

    def listAutomationStrategies(self, filters={}):
        try:
            cursor = self.openDB()
            rv = []

            query_str: str = (
                "SELECT strats.record_id, strats.label, strats.type_ind FROM automationstrategies AS strats"
            )
            query_str += " WHERE strats.active_ind = 1 "
            query_data: dict = {}

            type_ind = filters.get("type_ind", None)
            if type_ind is not None:
                query_str += " AND strats.type_ind = :type_ind "
                query_data["type_ind"] = type_ind

            query_str += getOrderByStr(filters, table_name="strats")

            limit = filters.get("limit", None)
            if limit is not None:
                query_str += " LIMIT :limit"
                query_data["limit"] = limit
            offset = filters.get("offset", None)
            if offset is not None:
                query_str += " OFFSET :offset"
                query_data["offset"] = offset

            q = cursor.execute(query_str, query_data)
            for row in q:
                rv.append(row)
            return rv
        finally:
            self.closeDB(cursor, commit=False)

    def getAutomationStrategy(self, strategy_id: int):
        try:
            cursor = self.openDB()
            return self.queryOne(AutomationStrategy, cursor, {"record_id": strategy_id})
        finally:
            self.closeDB(cursor, commit=False)

    def updateAutomationStrategy(self, strategy_id: int, data: dict) -> None:
        self.log.debug(f"updateAutomationStrategy {strategy_id}.")
        try:
            cursor = self.openDB()
            strategy = self.queryOne(
                AutomationStrategy, cursor, {"record_id": strategy_id}
            )
            if "data" in data:
                strategy.data = json.dumps(data["data"]).encode("UTF-8")
                self.log.debug("data {}".format(data["data"]))
            if "note" in data:
                strategy.note = data["note"]
            if "label" in data:
                strategy.label = data["label"]
            if "only_known_identities" in data:
                strategy.only_known_identities = int(data["only_known_identities"])

            if "set_max_concurrent_bids" in data:
                new_max_concurrent_bids = data["set_max_concurrent_bids"]
                ensure(
                    isinstance(new_max_concurrent_bids, int),
                    "set_max_concurrent_bids must be an integer",
                )
                strategy_data = (
                    {}
                    if strategy.data is None
                    else json.loads(strategy.data.decode("UTF-8"))
                )
                strategy_data["max_concurrent_bids"] = new_max_concurrent_bids
                strategy.data = json.dumps(strategy_data).encode("UTF-8")

            self.updateDB(strategy, cursor, ["record_id"])
        finally:
            self.closeDB(cursor)

    def getLinkedStrategy(self, linked_type: int, linked_id):
        try:
            cursor = self.openDB()
            query_str = (
                "SELECT links.strategy_id, strats.label FROM automationlinks links"
                + " LEFT JOIN automationstrategies strats ON strats.record_id = links.strategy_id"
                + " WHERE links.linked_type = :linked_type AND links.linked_id = :linked_id AND links.active_ind = 1"
            )
            query_data: dict = {"linked_type": int(linked_type), "linked_id": linked_id}
            q = cursor.execute(query_str, query_data).fetchone()
            return q
        finally:
            self.closeDB(cursor, commit=False)

    def newSMSGAddress(
        self, use_type=AddressTypes.RECV_OFFER, addressnote=None, cursor=None
    ):
        now: int = self.getTime()
        try:
            use_cursor = self.openDB(cursor)

            smsg_chain_id = self.getStringKV("smsg_chain_id", use_cursor)
            if not smsg_chain_id:
                smsg_account = self.callrpc(
                    "extkey", ["deriveAccount", "smsg keys", "78900"]
                )
                smsg_account_id = smsg_account["account"]
                self.log.info(
                    f"Creating smsg keys account {self.log.addr(smsg_account_id)}."
                )
                extkey = self.callrpc("extkey")

                # Disable receiving on all chains
                extkey = self.callrpc("extkey", ["account", smsg_account_id])
                for c in extkey["chains"]:
                    self.callrpc("extkey", ["options", c["id"], "receive_on", "false"])
                    if c["function"] == "active_external":
                        smsg_chain_id = c["id"]

                if not smsg_chain_id:
                    raise ValueError("External chain not found.")

                self.setStringKV("smsg_chain_id", smsg_chain_id, use_cursor)

            smsg_chain = self.callrpc("extkey", ["key", smsg_chain_id])
            num_derives = int(smsg_chain["num_derives"])

            new_addr = self.callrpc(
                "deriverangekeys",
                [num_derives, num_derives, smsg_chain_id, False, True],
            )[0]
            num_derives += 1
            # Update num_derives
            self.callrpc(
                "extkey", ["options", smsg_chain_id, "num_derives", str(num_derives)]
            )

            addr_info = self.callrpc("getaddressinfo", [new_addr])
            self.callrpc("smsgaddlocaladdress", [new_addr])  # Enable receiving smsgs
            self.callrpc("smsglocalkeys", ["anon", "-", new_addr])

            addr_obj = SmsgAddress(
                addr=new_addr,
                use_type=use_type,
                active_ind=1,
                created_at=now,
                pubkey=addr_info["pubkey"],
            )
            if addressnote is not None:
                addr_obj.note = addressnote

            self.add(addr_obj, use_cursor)
            return new_addr, addr_info["pubkey"]
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def addSMSGAddress(self, pubkey_hex: str, addressnote: str = None) -> None:
        cursor = self.openDB()
        try:
            now: int = self.getTime()
            ci = self.ci(Coins.PART)
            add_addr = ci.pubkey_to_address(bytes.fromhex(pubkey_hex))
            self.callrpc("smsgaddaddress", [add_addr, pubkey_hex])
            self.callrpc("smsglocalkeys", ["anon", "-", add_addr])

            self.add(
                SmsgAddress(
                    addr=add_addr,
                    use_type=AddressTypes.SEND_OFFER,
                    active_ind=1,
                    created_at=now,
                    note=addressnote,
                    pubkey=pubkey_hex,
                ),
                cursor,
            )
            return add_addr
        finally:
            self.closeDB(cursor)

    def editSMSGAddress(
        self,
        address: str,
        active_ind: int,
        addressnote: str = None,
        use_type=None,
        cursor=None,
    ) -> None:
        use_cursor = self.openDB(cursor)
        try:
            mode = "-" if active_ind == 0 else "+"
            rv = self.callrpc("smsglocalkeys", ["recv", mode, address])
            if "not found" in rv["result"]:
                self.callrpc(
                    "smsgaddlocaladdress",
                    [
                        address,
                    ],
                )
                self.callrpc("smsglocalkeys", ["anon", "-", address])
            values = {"active_ind": active_ind, "addr": address, "use_type": use_type}
            query_str: str = "UPDATE smsgaddresses SET active_ind = :active_ind"
            if addressnote is not None:
                values["note"] = addressnote
                query_str += ", note = :note"
            query_str += " WHERE addr = :addr"

            rv = use_cursor.execute(query_str, values)
            if rv.rowcount < 1:
                query_str: str = (
                    "INSERT INTO smsgaddresses (addr, active_ind, use_type) VALUES (:addr, :active_ind, :use_type)"
                )
                use_cursor.execute(query_str, values)
        finally:
            if cursor is None:
                self.closeDB(use_cursor)

    def disableAllSMSGAddresses(self):
        filters = {
            "exclude_inactive": True,
        }
        cursor = self.openDB()
        rv = {}
        num_disabled = 0
        try:
            active_addresses = self.listAllSMSGAddresses(filters, cursor=cursor)
            for active_address in active_addresses:
                if active_address["addr"] == self.network_addr:
                    continue
                self.editSMSGAddress(
                    active_address["addr"], active_ind=0, cursor=cursor
                )
            num_disabled += 1
        finally:
            self.closeDB(cursor)

        rv["num_disabled"] = num_disabled

        num_core_disabled = 0
        # Check localkeys
        smsg_localkeys = self.callrpc("smsglocalkeys")
        all_keys = smsg_localkeys["wallet_keys"] + smsg_localkeys["smsg_keys"]
        for smsg_addr in all_keys:
            if smsg_addr["address"] == self.network_addr:
                continue
            if smsg_addr["receive"] != 0:
                self.log.warning(
                    "Disabling smsg key found in core and not bsx: {}.".format(
                        self.log.addr(smsg_addr["address"])
                    )
                )
                self.callrpc("smsglocalkeys", ["recv", "-", smsg_addr["address"]])
                num_core_disabled += 1

        if num_core_disabled > 0:
            rv["num_core_disabled"] = num_core_disabled
        return rv

    def prepareSMSGAddress(self, addr_send_from, use_type, cursor):
        if addr_send_from is None:
            return self.newSMSGAddress(use_type=use_type, cursor=cursor)[0]
        use_addr = addr_send_from
        self.editSMSGAddress(
            use_addr, 1, use_type=use_type, cursor=cursor
        )  # Ensure receive is active
        return use_addr

    def createCoinALockRefundSwipeTx(self, ci, bid, offer, xmr_swap, xmr_offer):
        self.log.debug(f"Creating {ci.coin_name()} lock refund swipe tx.")

        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
        a_fee_rate: int = xmr_offer.b_fee_rate if reverse_bid else xmr_offer.a_fee_rate
        coin_from = Coins(offer.coin_to if reverse_bid else offer.coin_from)
        coin_to = Coins(offer.coin_from if reverse_bid else offer.coin_to)

        # TODO: Ensure a chain B lock tx to the expected/summed address exists before sending mercy output.
        kbsf = None
        if self.isBchXmrSwap(offer):
            pass
            # BCH sends a separate mercy tx
        else:
            for_ed25519: bool = (
                True if self.ci(coin_to).curve_type() == Curves.ed25519 else False
            )
            kbsf = self.getPathKey(
                coin_from,
                coin_to,
                bid.created_at,
                xmr_swap.contract_count,
                KeyTypes.KBSF,
                for_ed25519,
            )

        pkh_dest = ci.decodeAddress(self.getReceiveAddressForCoin(ci.coin_type()))
        spend_tx = ci.createSCLockRefundSpendToFTx(
            xmr_swap.a_lock_refund_tx,
            xmr_swap.a_lock_refund_tx_script,
            pkh_dest,
            a_fee_rate,
            xmr_swap.vkbv,
            kbsf,
        )

        vkaf = self.getPathKey(
            coin_from, coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KAF
        )
        prevout_amount = ci.getLockRefundTxSwapOutputValue(bid, xmr_swap)
        sig = ci.signTx(
            vkaf, spend_tx, 0, xmr_swap.a_lock_refund_tx_script, prevout_amount
        )

        witness_stack = [
            sig,
            b"",
            xmr_swap.a_lock_refund_tx_script,
        ]

        xmr_swap.a_lock_refund_swipe_tx = ci.setTxSignature(spend_tx, witness_stack)

    def setBidDebugInd(self, bid_id: bytes, debug_ind, add_to_bid: bool = True) -> None:
        self.log.debug(f"Bid {self.log.id(bid_id)} Setting debug flag: {debug_ind}.")

        self._debug_cases.append((bid_id, debug_ind))
        if add_to_bid is False:
            return

        bid = self.getBid(bid_id)
        if bid is None:
            raise ValueError("Bid not found.")

        bid.debug_ind = debug_ind

        # Update in memory copy.  TODO: Improve
        bid_in_progress = self.swaps_in_progress.get(bid_id, None)
        if bid_in_progress:
            bid_in_progress[0].debug_ind = debug_ind

        self.saveBid(bid_id, bid)

    def haveDebugInd(self, bid_id: bytes, debug_ind) -> None:
        for entry in self._debug_cases:
            if entry[0] == bid_id and entry[1] == debug_ind:
                return True
        return False

    def storeOfferRevoke(self, offer_id: bytes, sig) -> bool:
        self.log.debug(f"Storing revoke request for offer: {self.log.id(offer_id)}.")
        for pair in self._possibly_revoked_offers:
            if offer_id == pair[0]:
                return False
        self._possibly_revoked_offers.appendleft((offer_id, sig))
        return True

    def isOfferRevoked(self, offer_id: bytes, offer_addr_from) -> bool:
        for pair in self._possibly_revoked_offers:
            if offer_id == pair[0]:
                signature_enc = base64.b64encode(pair[1]).decode("UTF-8")
                passed = self.ci(Coins.PART).verifyMessage(
                    offer_addr_from, offer_id.hex() + "_revoke", signature_enc
                )
                return (
                    True if passed is True else False
                )  # _possibly_revoked_offers should not contain duplicates
        return False

    def updateBidInProgress(self, bid):
        swap_in_progress = self.swaps_in_progress.get(bid.bid_id, None)
        if swap_in_progress is None:
            return
        self.swaps_in_progress[bid.bid_id] = (bid, swap_in_progress[1])

    def getAddressLabel(self, addresses):
        cursor = self.openDB()
        try:
            rv = []
            for a in addresses:
                v = self.queryOne(KnownIdentity, cursor, {"address": a})
                rv.append("" if (not v or not v.label) else v.label)
            return rv
        finally:
            self.closeDB(cursor, commit=False)

    def getLockedState(self):
        if self._is_encrypted is None or self._is_locked is None:
            self._is_encrypted, self._is_locked = self.ci(
                Coins.PART
            ).isWalletEncryptedLocked()
        return self._is_encrypted, self._is_locked

    def getExchangeName(self, coin_id: int, exchange_name: str) -> str:
        if coin_id == Coins.BCH:
            return "bitcoin-cash"
        if coin_id == Coins.FIRO:
            return "zcoin"

        # Handle coin variants that use base coin chainparams
        use_coinid = coin_id
        if coin_id == Coins.PART_ANON or coin_id == Coins.PART_BLIND:
            use_coinid = Coins.PART
        elif coin_id == Coins.LTC_MWEB:
            use_coinid = Coins.LTC

        return chainparams[use_coinid]["name"]

    def lookupFiatRates(
        self,
        coins_list,
        currency_to: int = Fiat.USD,
        rate_source: str = "coingecko.com",
        saved_ttl: int = 300,
    ):
        if self.debug:
            coins_list_display = ", ".join([Coins(c).name for c in coins_list])
            self.log.debug(f"lookupFiatRates {coins_list_display}.")
        ensure(len(coins_list) > 0, "Must specify coin/s")
        ensure(saved_ttl >= 0, "Invalid saved time")

        now: int = int(time.time())
        oldest_time_valid: int = now - saved_ttl
        return_rates = {}

        headers = {"User-Agent": "Mozilla/5.0", "Connection": "close"}

        cursor = self.openDB()
        try:
            parameters = {
                "rate_source": rate_source,
                "oldest_time_valid": oldest_time_valid,
                "currency_to": currency_to,
            }
            coins_list_query = ""
            for i, coin_id in enumerate(coins_list):
                try:
                    _ = Coins(coin_id)
                except Exception:
                    raise ValueError(f"Unknown coin type {coin_id}")

                param_name = f"coin_{i}"
                if i > 0:
                    coins_list_query += ","
                coins_list_query += f":{param_name}"
                parameters[param_name] = coin_id

            query = f"SELECT currency_from, rate FROM coinrates WHERE currency_from IN ({coins_list_query}) AND currency_to = :currency_to AND source = :rate_source AND last_updated >= :oldest_time_valid"
            rows = cursor.execute(query, parameters)

            for row in rows:
                return_rates[int(row[0])] = float(row[1])

            need_coins = []
            new_values = {}
            exchange_name_map = {}
            for coin_id in coins_list:
                if coin_id not in return_rates:
                    need_coins.append(coin_id)

            if len(need_coins) < 1:
                return return_rates

            if rate_source == "coingecko.com":
                ticker_to: str = fiatTicker(currency_to).lower()
                # Update all requested coins
                coin_ids: str = ""
                for coin_id in coins_list:
                    if len(coin_ids) > 0:
                        coin_ids += ","
                    exchange_name: str = self.getExchangeName(coin_id, rate_source)
                    coin_ids += exchange_name
                    exchange_name_map[exchange_name] = coin_id

                api_key: str = get_api_key_setting(
                    self.settings,
                    "coingecko_api_key",
                    default_coingecko_api_key,
                    escape=True,
                )
                url: str = (
                    f"https://api.coingecko.com/api/v3/simple/price?ids={coin_ids}&vs_currencies={ticker_to}"
                )
                if api_key != "":
                    url += f"&api_key={api_key}"

                self.log.debug(f"lookupFiatRates: {url}")
                js = json.loads(self.readURL(url, timeout=10, headers=headers))

                for k, v in js.items():
                    return_rates[int(exchange_name_map[k])] = v[ticker_to]
                    new_values[exchange_name_map[k]] = v[ticker_to]
            elif rate_source == "cryptocompare.com":
                ticker_to: str = fiatTicker(currency_to).upper()
                api_key: str = get_api_key_setting(
                    self.settings,
                    "chart_api_key",
                    default_chart_api_key,
                    escape=True,
                )
                if len(need_coins) == 1:
                    coin_ticker: str = chainparams[coin_id]["ticker"]
                    url: str = (
                        f"https://min-api.cryptocompare.com/data/price?fsym={coin_ticker}&tsyms={ticker_to}"
                    )
                    self.log.debug(f"lookupFiatRates: {url}")
                    js = json.loads(self.readURL(url, timeout=10, headers=headers))
                    return_rates[int(coin_id)] = js[ticker_to]
                    new_values[coin_id] = js[ticker_to]
                else:
                    coin_ids: str = ""
                    for coin_id in coins_list:
                        if len(coin_ids) > 0:
                            coin_ids += ","
                        coin_ticker: str = chainparams[coin_id]["ticker"]
                        coin_ids += coin_ticker
                        exchange_name_map[coin_ticker] = coin_id
                    url: str = (
                        f"https://min-api.cryptocompare.com/data/pricemulti?fsyms={coin_ids}&tsyms={ticker_to}"
                    )
                    self.log.debug(f"lookupFiatRates: {url}")
                    js = json.loads(self.readURL(url, timeout=10, headers=headers))
                    for k, v in js.items():
                        return_rates[int(exchange_name_map[k])] = v[ticker_to]
                        new_values[exchange_name_map[k]] = v[ticker_to]
            else:
                raise ValueError(f"Unknown rate source {rate_source}")

            if len(new_values) < 1:
                return return_rates

            # ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE constraint
            update_query = """
                UPDATE coinrates SET
                    rate=:rate,
                    last_updated=:last_updated
                WHERE currency_from = :currency_from AND currency_to = :currency_to AND source = :rate_source
                """

            insert_query = """INSERT INTO coinrates(currency_from, currency_to, rate, source, last_updated)
                    VALUES(:currency_from, :currency_to, :rate, :rate_source, :last_updated)"""

            for k, v in new_values.items():
                cursor.execute(
                    update_query,
                    {
                        "currency_from": k,
                        "currency_to": currency_to,
                        "rate": v,
                        "rate_source": rate_source,
                        "last_updated": now,
                    },
                )
                if cursor.rowcount < 1:
                    cursor.execute(
                        insert_query,
                        {
                            "currency_from": k,
                            "currency_to": currency_to,
                            "rate": v,
                            "rate_source": rate_source,
                            "last_updated": now,
                        },
                    )

            self.commitDB()
            return return_rates
        finally:
            self.closeDB(cursor, commit=False)

    def lookupRates(self, coin_from, coin_to, output_array=False):
        self.log.debug(
            "lookupRates {}, {}.".format(
                Coins(int(coin_from)).name, Coins(int(coin_to)).name
            )
        )

        rate_sources = self.settings.get("rate_sources", {})
        ci_from = self.ci(int(coin_from))
        ci_to = self.ci(int(coin_to))
        name_from = ci_from.chainparams()["name"]
        name_to = ci_to.chainparams()["name"]
        ticker_from = ci_from.chainparams()["ticker"]
        ticker_to = ci_to.chainparams()["ticker"]
        rv = {}

        if rate_sources.get("coingecko.com", True):
            try:
                js = self.lookupFiatRates([int(coin_from), int(coin_to)])
                rate = float(js[int(coin_from)]) / float(js[int(coin_to)])
                js["rate_inferred"] = ci_to.format_amount(rate, conv_int=True, r=1)

                js[name_from] = {"usd": js[int(coin_from)]}
                js.pop(int(coin_from))
                js[name_to] = {"usd": js[int(coin_to)]}
                js.pop(int(coin_to))

                rv["coingecko"] = js
            except Exception as e:
                rv["coingecko_error"] = str(e)
                if self.debug:
                    self.log.error(traceback.format_exc())

        if output_array:

            def format_float(f):
                return "{:.12f}".format(f).rstrip("0").rstrip(".")

            rv_array = []
            if "coingecko_error" in rv:
                rv_array.append(("coingecko.com", "error", rv["coingecko_error"]))
            elif "coingecko" in rv:
                js = rv["coingecko"]
                rv_array.append(
                    (
                        "coingecko.com",
                        ticker_from,
                        ticker_to,
                        format_float(float(js[name_from]["usd"])),
                        format_float(float(js[name_to]["usd"])),
                        format_float(float(js["rate_inferred"])),
                    )
                )
            return rv_array

        return rv
