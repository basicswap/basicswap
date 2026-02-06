# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import html

from .util import (
    getCoinName,
    get_data_entry,
    have_data_entry,
    get_data_entry_or,
)
from basicswap.util import (
    toBool,
    InactiveCoin,
)
from basicswap.basicswap_util import (
    get_api_key_setting,
)
from basicswap.chainparams import (
    Coins,
)


def page_settings(self, url_split, post_string):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()

    messages = []
    err_messages = []
    active_tab = "default"
    form_data = self.checkForm(post_string, "settings", err_messages)
    if form_data:
        try:
            if have_data_entry(form_data, "apply_general"):
                active_tab = "general"
                data = {
                    "debug": toBool(get_data_entry(form_data, "debugmode")),
                    "debug_ui": toBool(get_data_entry(form_data, "debugui")),
                    "expire_db_records": toBool(
                        get_data_entry(form_data, "expire_db_records")
                    ),
                }
                swap_client.editGeneralSettings(data)
            elif have_data_entry(form_data, "apply_chart"):
                active_tab = "general"
                data = {
                    "show_chart": toBool(get_data_entry(form_data, "showchart")),
                    "coingecko_api_key": html.unescape(
                        get_data_entry_or(form_data, "coingeckoapikey", "")
                    ),
                    "enabled_chart_coins": get_data_entry_or(
                        form_data, "enabledchartcoins", ""
                    ),
                }
                swap_client.editGeneralSettings(data)
            elif have_data_entry(form_data, "apply_notifications"):
                active_tab = "notifications"
                data = {
                    "notifications_new_offers": toBool(
                        get_data_entry_or(
                            form_data, "notifications_new_offers", "false"
                        )
                    ),
                    "notifications_new_bids": toBool(
                        get_data_entry_or(form_data, "notifications_new_bids", "false")
                    ),
                    "notifications_bid_accepted": toBool(
                        get_data_entry_or(
                            form_data, "notifications_bid_accepted", "false"
                        )
                    ),
                    "notifications_balance_changes": toBool(
                        get_data_entry_or(
                            form_data, "notifications_balance_changes", "false"
                        )
                    ),
                    "notifications_outgoing_transactions": toBool(
                        get_data_entry_or(
                            form_data, "notifications_outgoing_transactions", "false"
                        )
                    ),
                    "notifications_swap_completed": toBool(
                        get_data_entry_or(
                            form_data, "notifications_swap_completed", "false"
                        )
                    ),
                    "notifications_duration": int(
                        get_data_entry_or(form_data, "notifications_duration", "20")
                    ),
                    "check_updates": toBool(
                        get_data_entry_or(form_data, "check_updates", "false")
                    ),
                }
                swap_client.editGeneralSettings(data)
                messages.append("Notification settings applied.")
            elif have_data_entry(form_data, "apply_tor"):
                active_tab = "tor"
                # TODO: Detect if running in docker
                raise ValueError(
                    "TODO: If running in docker see doc/tor.md to enable/disable tor."
                )

            electrum_supported_coins = (
                "bitcoin",
                "litecoin",
            )
            for name, c in swap_client.settings["chainclients"].items():
                if have_data_entry(form_data, "apply_" + name):
                    data = {"lookups": get_data_entry(form_data, "lookups_" + name)}
                    if name in ("monero", "wownero"):
                        data["fee_priority"] = int(
                            get_data_entry(form_data, "fee_priority_" + name)
                        )
                        data["manage_daemon"] = (
                            True
                            if get_data_entry(form_data, "managedaemon_" + name)
                            == "true"
                            else False
                        )
                        data["rpchost"] = get_data_entry(form_data, "rpchost_" + name)
                        data["rpcport"] = int(
                            get_data_entry(form_data, "rpcport_" + name)
                        )
                        data["remotedaemonurls"] = get_data_entry_or(
                            form_data, "remotedaemonurls_" + name, ""
                        )
                        data["automatically_select_daemon"] = (
                            True
                            if get_data_entry(form_data, "autosetdaemon_" + name)
                            == "true"
                            else False
                        )
                    else:
                        data["conf_target"] = int(
                            get_data_entry(form_data, "conf_target_" + name)
                        )
                        if name == "particl":
                            data["anon_tx_ring_size"] = int(
                                get_data_entry(form_data, "rct_ring_size_" + name)
                            )
                        if name in electrum_supported_coins:
                            new_connection_type = get_data_entry_or(
                                form_data, "connection_type_" + name, None
                            )
                            if new_connection_type and new_connection_type != c.get(
                                "connection_type"
                            ):
                                coin_id = swap_client.getCoinIdFromName(name)
                                has_active_swaps = False
                                for bid_id, (bid, offer) in list(
                                    swap_client.swaps_in_progress.items()
                                ):
                                    if (
                                        offer.coin_from == coin_id
                                        or offer.coin_to == coin_id
                                    ):
                                        has_active_swaps = True
                                        break
                                if has_active_swaps:
                                    display_name = getCoinName(coin_id)
                                    err_messages.append(
                                        f"Cannot change {display_name} connection mode while swaps are in progress. "
                                        f"Please wait for all {display_name} swaps to complete."
                                    )
                                else:
                                    data["connection_type"] = new_connection_type
                                    if new_connection_type == "electrum":
                                        data["manage_daemon"] = False
                                    elif new_connection_type == "rpc":
                                        data["manage_daemon"] = True
                            clearnet_servers = get_data_entry_or(
                                form_data, "electrum_clearnet_" + name, ""
                            ).strip()
                            data["electrum_clearnet_servers"] = clearnet_servers
                            onion_servers = get_data_entry_or(
                                form_data, "electrum_onion_" + name, ""
                            ).strip()
                            data["electrum_onion_servers"] = onion_servers
                            auto_transfer_now = have_data_entry(
                                form_data, "auto_transfer_now_" + name
                            )
                            if auto_transfer_now:
                                transfer_value = get_data_entry_or(
                                    form_data, "auto_transfer_now_" + name, "false"
                                )
                                data["auto_transfer_now"] = transfer_value == "true"
                            gap_limit_str = get_data_entry_or(
                                form_data, "gap_limit_" + name, "20"
                            ).strip()
                            try:
                                gap_limit = int(gap_limit_str)
                                if gap_limit < 5:
                                    gap_limit = 5
                                elif gap_limit > 100:
                                    gap_limit = 100
                                data["address_gap_limit"] = gap_limit
                            except ValueError:
                                pass

                    settings_changed, suggest_reboot, migration_message = (
                        swap_client.editSettings(name, data)
                    )
                    if migration_message:
                        messages.append(migration_message)
                    if settings_changed is True:
                        messages.append("Settings applied.")
                    if suggest_reboot is True:
                        messages.append("Please restart BasicSwap.")
                elif have_data_entry(form_data, "enable_" + name):
                    swap_client.enableCoin(name)
                    display_name = getCoinName(swap_client.getCoinIdFromName(name))
                    messages.append(display_name + " enabled, shutting down.")
                    swap_client.stopRunning()
                elif have_data_entry(form_data, "disable_" + name):
                    swap_client.disableCoin(name)
                    display_name = getCoinName(swap_client.getCoinIdFromName(name))
                    messages.append(display_name + " disabled, shutting down.")
                    swap_client.stopRunning()
                elif have_data_entry(form_data, "force_sweep_" + name):
                    coin_id = swap_client.getCoinIdFromName(name)
                    display_name = getCoinName(coin_id)
                    try:
                        result = swap_client.sweepLiteWalletFunds(coin_id)
                        if result.get("success"):
                            amount = result.get("amount", 0)
                            fee = result.get("fee", 0)
                            txid = result.get("txid", "")
                            messages.append(
                                f"Successfully swept {amount:.8f} {display_name} to RPC wallet. "
                                f"Fee: {fee:.8f}. TXID: {txid} (1 confirmation required)"
                            )
                        elif result.get("skipped"):
                            messages.append(
                                f"{display_name}: {result.get('reason', 'Sweep skipped')}"
                            )
                        else:
                            err_messages.append(
                                f"{display_name}: Sweep failed - {result.get('error', 'Unknown error')}"
                            )
                    except Exception as e:
                        err_messages.append(f"{display_name}: Sweep failed - {str(e)}")
        except InactiveCoin as ex:
            err_messages.append("InactiveCoin {}".format(Coins(ex.coinid).name))
        except Exception as e:
            err_messages.append(str(e))
    chains_formatted = []
    electrum_supported_coins = (
        "bitcoin",
        "litecoin",
    )

    sorted_names = sorted(swap_client.settings["chainclients"].keys())
    from basicswap.interface.electrumx import (
        DEFAULT_ELECTRUM_SERVERS,
        DEFAULT_ONION_SERVERS,
    )

    for name in sorted_names:
        c = swap_client.settings["chainclients"][name]
        try:
            display_name = getCoinName(swap_client.getCoinIdFromName(name))
        except Exception:
            display_name = name

        clearnet_servers = c.get("electrum_clearnet_servers", None)
        onion_servers = c.get("electrum_onion_servers", None)

        if not clearnet_servers:
            default_clearnet = DEFAULT_ELECTRUM_SERVERS.get(name, [])
            clearnet_servers = [
                f"{s['host']}:{s['port']}:{str(s.get('ssl', True)).lower()}"
                for s in default_clearnet
            ]
        if not onion_servers:
            default_onion = DEFAULT_ONION_SERVERS.get(name, [])
            onion_servers = [
                f"{s['host']}:{s['port']}:{str(s.get('ssl', False)).lower()}"
                for s in default_onion
            ]

        clearnet_text = "\n".join(clearnet_servers) if clearnet_servers else ""
        onion_text = "\n".join(onion_servers) if onion_servers else ""

        chains_formatted.append(
            {
                "name": name,
                "display_name": display_name,
                "lookups": c.get("chain_lookups", "local"),
                "manage_daemon": c.get("manage_daemon", "Unknown"),
                "connection_type": c.get("connection_type", "Unknown"),
                "supports_electrum": name in electrum_supported_coins,
                "clearnet_servers_text": clearnet_text,
                "onion_servers_text": onion_text,
                "address_gap_limit": c.get("address_gap_limit", 20),
            }
        )
        if name in ("monero", "wownero"):
            chains_formatted[-1]["fee_priority"] = c.get("fee_priority", 0)
            chains_formatted[-1]["manage_wallet_daemon"] = c.get(
                "manage_wallet_daemon", "Unknown"
            )
            chains_formatted[-1]["rpchost"] = c.get("rpchost", "localhost")
            chains_formatted[-1]["rpcport"] = int(c.get("rpcport", 18081))
            chains_formatted[-1]["remotedaemonurls"] = "\n".join(
                c.get("remote_daemon_urls", [])
            )
            chains_formatted[-1]["autosetdaemon"] = c.get(
                "automatically_select_daemon", False
            )
        else:
            chains_formatted[-1]["conf_target"] = c.get("conf_target", 2)

        if name == "particl":
            chains_formatted[-1]["anon_tx_ring_size"] = c.get("anon_tx_ring_size", 12)
        else:
            if c.get("connection_type", "Unknown") == "none":
                if "connection_type_prev" in c:
                    chains_formatted[-1]["can_reenable"] = True
            else:
                chains_formatted[-1]["can_disable"] = True

        try:
            coin_id = swap_client.getCoinIdFromName(name)
            lite_balance_info = swap_client.getLiteWalletBalanceInfo(coin_id)
            if lite_balance_info:
                chains_formatted[-1]["lite_wallet_balance"] = lite_balance_info
        except Exception:
            pass

    general_settings = {
        "debug": swap_client.debug,
        "debug_ui": swap_client.debug_ui,
        "expire_db_records": swap_client._expire_db_records,
        "check_updates": swap_client.settings.get("check_updates", True),
    }

    coingecko_api_key = get_api_key_setting(
        swap_client.settings, "coingecko_api_key", default_value="", escape=True
    )

    chart_settings = {
        "show_chart": swap_client.settings.get("show_chart", True),
        "coingecko_api_key": coingecko_api_key,
        "enabled_chart_coins": swap_client.settings.get("enabled_chart_coins", ""),
    }

    notification_settings = {
        "notifications_new_offers": swap_client.settings.get(
            "notifications_new_offers", False
        ),
        "notifications_new_bids": swap_client.settings.get(
            "notifications_new_bids", True
        ),
        "notifications_bid_accepted": swap_client.settings.get(
            "notifications_bid_accepted", True
        ),
        "notifications_balance_changes": swap_client.settings.get(
            "notifications_balance_changes", True
        ),
        "notifications_outgoing_transactions": swap_client.settings.get(
            "notifications_outgoing_transactions", True
        ),
        "notifications_swap_completed": swap_client.settings.get(
            "notifications_swap_completed", True
        ),
        "notifications_duration": swap_client.settings.get(
            "notifications_duration", 20
        ),
        "check_updates": swap_client.settings.get("check_updates", True),
    }

    tor_control_password = (
        ""
        if swap_client.tor_control_password is None
        else swap_client.tor_control_password
    )
    tor_settings = {
        "use_tor": swap_client.use_tor_proxy,
        "proxy_host": swap_client.tor_proxy_host,
        "proxy_port": swap_client.tor_proxy_port,
        "control_password": html.escape(tor_control_password),
        "control_port": swap_client.tor_control_port,
    }

    template = server.env.get_template("settings.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
            "summary": swap_client.getSummary(),
            "chains": chains_formatted,
            "general_settings": general_settings,
            "chart_settings": chart_settings,
            "notification_settings": notification_settings,
            "tor_settings": tor_settings,
            "active_tab": active_tab,
        },
    )
