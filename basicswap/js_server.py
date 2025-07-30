# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import random
import urllib.parse

from .util import (
    ensure,
    toBool,
)
from .basicswap_util import (
    fiatFromTicker,
    strBidState,
    strTxState,
    SwapTypes,
    NotificationTypes as NT,
)
from .chainparams import (
    Coins,
    chainparams,
    Fiat,
    getCoinIdFromTicker,
    getCoinIdFromName,
)
from .ui.util import (
    PAGE_LIMIT,
    getCoinName,
    getCoinType,
    inputAmount,
    describeBid,
    setCoinFilter,
    get_data_entry,
    get_data_entry_or,
    have_data_entry,
    listOldBidStates,
    checkAddressesOwned,
)
from .ui.page_offers import postNewOffer
from .protocols.xmr_swap_1 import recoverNoScriptTxnWithKey, getChainBSplitKey
from .db import Concepts


def getFormData(post_string: str, is_json: bool):
    if post_string == "":
        raise ValueError("No post data")
    if is_json:
        form_data = json.loads(post_string)
        form_data["is_json"] = True
    else:
        form_data = urllib.parse.parse_qs(post_string)
    return form_data


def withdraw_coin(swap_client, coin_type, post_string, is_json):
    post_data = getFormData(post_string, is_json)
    address = get_data_entry(post_data, "address")

    if coin_type in (Coins.XMR, Coins.WOW):
        value = None
        sweepall = get_data_entry(post_data, "sweepall")
        if not isinstance(sweepall, bool):
            sweepall = toBool(sweepall)
        if not sweepall:
            value = get_data_entry(post_data, "value")
    else:
        value = get_data_entry(post_data, "value")
        subfee = get_data_entry(post_data, "subfee")
        if not isinstance(subfee, bool):
            subfee = toBool(subfee)

    if coin_type == Coins.PART:
        type_from = get_data_entry_or(post_data, "type_from", "plain")
        type_to = get_data_entry_or(post_data, "type_to", "plain")
        txid_hex = swap_client.withdrawParticl(
            type_from, type_to, value, address, subfee
        )
    elif coin_type == Coins.LTC:
        type_from = get_data_entry_or(post_data, "type_from", "plain")
        txid_hex = swap_client.withdrawLTC(type_from, value, address, subfee)
    elif coin_type in (Coins.XMR, Coins.WOW):
        txid_hex = swap_client.withdrawCoin(coin_type, value, address, sweepall)
    else:
        txid_hex = swap_client.withdrawCoin(coin_type, value, address, subfee)

    return {"txid": txid_hex}


def js_error(self, error_str) -> bytes:
    error_str_json = json.dumps({"error": error_str})
    return bytes(error_str_json, "UTF-8")


def js_coins(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client

    coins = []
    for coin in Coins:
        cc = swap_client.coin_clients[coin]
        coin_chainparams = chainparams[cc["coin"]]
        coin_active: bool = False if cc["connection_type"] == "none" else True
        if coin == Coins.LTC_MWEB:
            coin_active = False
        entry = {
            "id": int(coin),
            "ticker": coin_chainparams["ticker"],
            "name": getCoinName(coin),
            "active": coin_active,
            "decimal_places": coin_chainparams["decimal_places"],
        }
        if coin == Coins.PART_ANON:
            entry["variant"] = "Anon"
        elif coin == Coins.PART_BLIND:
            entry["variant"] = "Blind"
        elif coin == Coins.LTC_MWEB:
            entry["variant"] = "MWEB"
        coins.append(entry)

    return bytes(json.dumps(coins), "UTF-8")


def js_walletbalances(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client

    try:

        swap_client.updateWalletsInfo()
        wallets = swap_client.getCachedWalletsInfo()
        coins_with_balances = []

        for k, v in swap_client.coin_clients.items():
            if k not in chainparams:
                continue
            if v["connection_type"] == "rpc":

                balance = "0.0"
                if k in wallets:
                    w = wallets[k]
                    if "balance" in w and "error" not in w and "no_data" not in w:
                        raw_balance = w["balance"]
                        if isinstance(raw_balance, float):
                            balance = f"{raw_balance:.8f}".rstrip("0").rstrip(".")
                        elif isinstance(raw_balance, int):
                            balance = str(raw_balance)
                        else:
                            balance = raw_balance

                pending = "0.0"
                if k in wallets:
                    w = wallets[k]
                    if "error" not in w and "no_data" not in w:
                        ci = swap_client.ci(k)
                        pending_amount = 0
                        if "unconfirmed" in w and float(w["unconfirmed"]) > 0.0:
                            pending_amount += ci.make_int(w["unconfirmed"])
                        if "immature" in w and float(w["immature"]) > 0.0:
                            pending_amount += ci.make_int(w["immature"])
                        if pending_amount > 0:
                            pending = ci.format_amount(pending_amount)

                coin_entry = {
                    "id": int(k),
                    "name": getCoinName(k),
                    "balance": balance,
                    "pending": pending,
                    "ticker": chainparams[k]["ticker"],
                }

                coins_with_balances.append(coin_entry)

                if k == Coins.PART:
                    variants = [
                        {
                            "coin": Coins.PART_ANON,
                            "balance_field": "anon_balance",
                            "pending_field": "anon_pending",
                        },
                        {
                            "coin": Coins.PART_BLIND,
                            "balance_field": "blind_balance",
                            "pending_field": "blind_unconfirmed",
                        },
                    ]

                    for variant_info in variants:
                        variant_balance = "0.0"
                        variant_pending = "0.0"

                        if k in wallets:
                            w = wallets[k]
                            if "error" not in w and "no_data" not in w:
                                if variant_info["balance_field"] in w:
                                    raw_balance = w[variant_info["balance_field"]]
                                    if isinstance(raw_balance, float):
                                        variant_balance = f"{raw_balance:.8f}".rstrip(
                                            "0"
                                        ).rstrip(".")
                                    elif isinstance(raw_balance, int):
                                        variant_balance = str(raw_balance)
                                    else:
                                        variant_balance = raw_balance

                                if (
                                    variant_info["pending_field"] in w
                                    and float(w[variant_info["pending_field"]]) > 0.0
                                ):
                                    variant_pending = str(
                                        w[variant_info["pending_field"]]
                                    )

                        variant_entry = {
                            "id": int(variant_info["coin"]),
                            "name": getCoinName(variant_info["coin"]),
                            "balance": variant_balance,
                            "pending": variant_pending,
                            "ticker": chainparams[Coins.PART]["ticker"],
                        }

                        coins_with_balances.append(variant_entry)

                elif k == Coins.LTC:
                    variant_balance = "0.0"
                    variant_pending = "0.0"

                    if k in wallets:
                        w = wallets[k]
                        if "error" not in w and "no_data" not in w:
                            if "mweb_balance" in w:
                                variant_balance = w["mweb_balance"]

                            pending_amount = 0
                            if (
                                "mweb_unconfirmed" in w
                                and float(w["mweb_unconfirmed"]) > 0.0
                            ):
                                pending_amount += float(w["mweb_unconfirmed"])
                            if "mweb_immature" in w and float(w["mweb_immature"]) > 0.0:
                                pending_amount += float(w["mweb_immature"])
                            if pending_amount > 0:
                                variant_pending = f"{pending_amount:.8f}".rstrip(
                                    "0"
                                ).rstrip(".")

                    variant_entry = {
                        "id": int(Coins.LTC_MWEB),
                        "name": getCoinName(Coins.LTC_MWEB),
                        "balance": variant_balance,
                        "pending": variant_pending,
                        "ticker": chainparams[Coins.LTC]["ticker"],
                    }

                    coins_with_balances.append(variant_entry)

        return bytes(json.dumps(coins_with_balances), "UTF-8")

    except Exception as e:
        error_data = {"error": str(e)}
        return bytes(json.dumps(error_data), "UTF-8")


def js_wallets(self, url_split, post_string, is_json):
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    if len(url_split) > 3:
        ticker_str = url_split[3]
        coin_type = getCoinIdFromTicker(ticker_str)

        if len(url_split) > 4:
            cmd = url_split[4]
            if cmd == "withdraw":
                return bytes(
                    json.dumps(
                        withdraw_coin(swap_client, coin_type, post_string, is_json)
                    ),
                    "UTF-8",
                )
            elif cmd == "nextdepositaddr":
                return bytes(
                    json.dumps(swap_client.cacheNewAddressForCoin(coin_type)), "UTF-8"
                )
            elif cmd == "createutxo":
                post_data = getFormData(post_string, is_json)
                ci = swap_client.ci(coin_type)
                value = ci.make_int(get_data_entry(post_data, "value"))
                txid_hex, new_addr = ci.createUTXO(value)
                return bytes(
                    json.dumps({"txid": txid_hex, "address": new_addr}), "UTF-8"
                )
            elif cmd == "reseed":
                swap_client.reseedWallet(coin_type)
                return bytes(json.dumps({"reseeded": True}), "UTF-8")
            elif cmd == "newstealthaddress":
                if coin_type != Coins.PART:
                    raise ValueError("Invalid coin for command")
                return bytes(
                    json.dumps(swap_client.ci(coin_type).getNewStealthAddress()),
                    "UTF-8",
                )
            elif cmd == "newmwebaddress":
                if coin_type not in (Coins.LTC, Coins.LTC_MWEB):
                    raise ValueError("Invalid coin for command")
                return bytes(
                    json.dumps(swap_client.ci(coin_type).getNewMwebAddress()), "UTF-8"
                )
            raise ValueError("Unknown command")

        if coin_type == Coins.LTC_MWEB:
            coin_type = Coins.LTC
        rv = swap_client.getWalletInfo(coin_type)
        if not rv:
            raise ValueError(f"getWalletInfo failed for coin: {coin_type}")
        rv.update(swap_client.getBlockchainInfo(coin_type))
        ci = swap_client.ci(coin_type)
        checkAddressesOwned(swap_client, ci, rv)
        return bytes(json.dumps(rv), "UTF-8")

    return bytes(json.dumps(swap_client.getWalletsInfo({"ticker_key": True})), "UTF-8")


def js_offers(self, url_split, post_string, is_json, sent=False) -> bytes:
    swap_client = self.server.swap_client

    try:
        swap_client.checkSystemStatus()
    except Exception as e:
        from basicswap.util import LockedCoinError
        from basicswap.ui.util import getCoinName

        if isinstance(e, LockedCoinError):
            error_msg = f"Wallet must be unlocked to view offers. Please unlock your {getCoinName(e.coinid)} wallet."
            return bytes(json.dumps({"error": error_msg, "locked": True}), "UTF-8")
        else:
            return bytes(json.dumps({"error": str(e)}), "UTF-8")

    offer_id = None
    if len(url_split) > 3:
        if url_split[3] == "new":
            form_data = getFormData(post_string, is_json)
            offer_id = postNewOffer(swap_client, form_data)
            rv = {"offer_id": offer_id.hex()}
            return bytes(json.dumps(rv), "UTF-8")
        offer_id = bytes.fromhex(url_split[3])

    with_extra_info = False
    filters = {
        "coin_from": -1,
        "coin_to": -1,
        "page_no": 1,
        "limit": PAGE_LIMIT,
        "sort_by": "created_at",
        "sort_dir": "desc",
    }

    if offer_id:
        filters["offer_id"] = offer_id

    parsed_url = urllib.parse.urlparse(self.path)
    query_params = urllib.parse.parse_qs(parsed_url.query) if parsed_url.query else {}

    if "with_extra_info" in query_params:
        with_extra_info = toBool(query_params["with_extra_info"][0])

    if post_string != "":
        post_data = getFormData(post_string, is_json)
        filters["coin_from"] = setCoinFilter(post_data, "coin_from")
        filters["coin_to"] = setCoinFilter(post_data, "coin_to")

        if have_data_entry(post_data, "sort_by"):
            sort_by = get_data_entry(post_data, "sort_by")
            ensure(sort_by in ["created_at", "rate"], "Invalid sort by")
            filters["sort_by"] = sort_by
        if have_data_entry(post_data, "sort_dir"):
            sort_dir = get_data_entry(post_data, "sort_dir")
            ensure(sort_dir in ["asc", "desc"], "Invalid sort dir")
            filters["sort_dir"] = sort_dir

        if have_data_entry(post_data, "offset"):
            filters["offset"] = int(get_data_entry(post_data, "offset"))
        if have_data_entry(post_data, "limit"):
            filters["limit"] = int(get_data_entry(post_data, "limit"))
            ensure(filters["limit"] > 0, "Invalid limit")
        if have_data_entry(post_data, "active"):
            filters["active"] = get_data_entry(post_data, "active")
        if have_data_entry(post_data, "include_sent"):
            filters["include_sent"] = toBool(get_data_entry(post_data, "include_sent"))

        if have_data_entry(post_data, "with_extra_info"):
            with_extra_info = toBool(get_data_entry(post_data, "with_extra_info"))

    offers = swap_client.listOffers(sent, filters)
    rv = []
    for o in offers:
        ci_from = swap_client.ci(o.coin_from)
        ci_to = swap_client.ci(o.coin_to)
        offer_data = {
            "swap_type": o.swap_type,
            "addr_from": o.addr_from,
            "addr_to": o.addr_to,
            "offer_id": o.offer_id.hex(),
            "created_at": o.created_at,
            "expire_at": o.expire_at,
            "coin_from": ci_from.coin_name(),
            "coin_to": ci_to.coin_name(),
            "amount_from": ci_from.format_amount(o.amount_from),
            "amount_to": ci_to.format_amount(
                (o.amount_from * o.rate) // ci_from.COIN()
            ),
            "rate": ci_to.format_amount(o.rate),
            "min_bid_amount": ci_from.format_amount(o.min_bid_amount),
            "is_expired": o.expire_at <= swap_client.getTime(),
            "is_own_offer": o.was_sent,
            "is_revoked": True if o.active_ind == 2 else False,
            "is_public": o.addr_to == swap_client.network_addr
            or o.addr_to.strip() == "",
        }
        offer_data["auto_accept_type"] = getattr(o, "auto_accept_type", 0)
        if with_extra_info:
            offer_data["amount_negotiable"] = o.amount_negotiable
            offer_data["rate_negotiable"] = o.rate_negotiable
            if o.swap_type == SwapTypes.XMR_SWAP:
                _, xmr_offer = swap_client.getXmrOffer(o.offer_id)
                offer_data["lock_time_1"] = xmr_offer.lock_time_1
                offer_data["lock_time_2"] = xmr_offer.lock_time_2

                offer_data["feerate_from"] = xmr_offer.a_fee_rate
                offer_data["feerate_to"] = xmr_offer.b_fee_rate
            else:
                offer_data["feerate_from"] = o.from_feerate
                offer_data["feerate_to"] = o.to_feerate

            offer_data["automation_strat_id"] = getattr(o, "auto_accept_type", 0)
            offer_data["auto_accept_type"] = getattr(o, "auto_accept_type", 0)

            if o.was_sent:
                try:
                    strategy = swap_client.getLinkedStrategy(Concepts.OFFER, o.offer_id)
                    if strategy:
                        offer_data["local_automation_strat_id"] = strategy[0]
                        swap_client.log.debug(
                            f"Found local automation strategy for own offer {o.offer_id.hex()}: {strategy[0]}"
                        )
                    else:
                        offer_data["local_automation_strat_id"] = 0
                except Exception as e:
                    swap_client.log.debug(
                        f"Error getting local automation strategy for offer {o.offer_id.hex()}: {e}"
                    )
                    offer_data["local_automation_strat_id"] = 0

        rv.append(offer_data)
    return bytes(json.dumps(rv), "UTF-8")


def js_sentoffers(self, url_split, post_string, is_json) -> bytes:
    return js_offers(self, url_split, post_string, is_json, True)


def parseBidFilters(post_data):
    offer_id = None
    filters = {}

    if have_data_entry(post_data, "offer_id"):
        offer_id = bytes.fromhex(get_data_entry(post_data, "offer_id"))
        assert len(offer_id) == 28

    if have_data_entry(post_data, "sort_by"):
        sort_by = get_data_entry(post_data, "sort_by")
        assert sort_by in [
            "created_at",
        ], "Invalid sort by"
        filters["sort_by"] = sort_by
    if have_data_entry(post_data, "sort_dir"):
        sort_dir = get_data_entry(post_data, "sort_dir")
        assert sort_dir in ["asc", "desc"], "Invalid sort dir"
        filters["sort_dir"] = sort_dir

    if have_data_entry(post_data, "offset"):
        filters["offset"] = int(get_data_entry(post_data, "offset"))
    if have_data_entry(post_data, "limit"):
        filters["limit"] = int(get_data_entry(post_data, "limit"))
        assert filters["limit"] > 0 and filters["limit"] <= PAGE_LIMIT, "Invalid limit"

    if have_data_entry(post_data, "with_available_or_active"):
        filters["with_available_or_active"] = toBool(
            get_data_entry(post_data, "with_available_or_active")
        )
    elif have_data_entry(post_data, "with_expired"):
        filters["with_expired"] = toBool(get_data_entry(post_data, "with_expired"))

    if have_data_entry(post_data, "with_extra_info"):
        filters["with_extra_info"] = toBool(
            get_data_entry(post_data, "with_extra_info")
        )

    return offer_id, filters


def formatBids(swap_client, bids, filters) -> bytes:
    with_extra_info = filters.get("with_extra_info", False)
    rv = []
    for b in bids:
        ci_from = swap_client.ci(b[9])
        offer = swap_client.getOffer(b[3])
        ci_to = swap_client.ci(offer.coin_to) if offer else None

        bid_rate: int = 0 if b[10] is None else b[10]
        amount_to = None
        if ci_to:
            amount_to_int = (b[4] * bid_rate + ci_from.COIN() - 1) // ci_from.COIN()
            amount_to = ci_to.format_amount(amount_to_int)

        bid_data = {
            "bid_id": b[2].hex(),
            "offer_id": b[3].hex(),
            "created_at": b[0],
            "expire_at": b[1],
            "coin_from": ci_from.coin_name(),
            "coin_to": ci_to.coin_name() if ci_to else "Unknown",
            "amount_from": ci_from.format_amount(b[4]),
            "amount_to": amount_to,
            "bid_rate": swap_client.ci(b[14]).format_amount(bid_rate),
            "bid_state": strBidState(b[5]),
            "addr_from": b[11],
            "addr_to": offer.addr_to if offer else None,
        }

        if with_extra_info:
            bid_data.update(
                {"tx_state_a": strTxState(b[7]), "tx_state_b": strTxState(b[8])}
            )
        rv.append(bid_data)
    return bytes(json.dumps(rv), "UTF-8")


def js_bids(self, url_split, post_string: str, is_json: bool) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    if len(url_split) > 3:
        if url_split[3] == "new":
            post_data = getFormData(post_string, is_json)

            offer_id = bytes.fromhex(get_data_entry(post_data, "offer_id"))
            assert len(offer_id) == 28

            offer = swap_client.getOffer(offer_id)
            assert offer, "Offer not found."

            ci_from = swap_client.ci(offer.coin_from)
            ci_to = swap_client.ci(offer.coin_to)
            amount_from = inputAmount(get_data_entry(post_data, "amount_from"), ci_from)

            addr_from = None
            if have_data_entry(post_data, "addr_from"):
                addr_from = get_data_entry(post_data, "addr_from")
                if addr_from == "-1":
                    addr_from = None

            if have_data_entry(post_data, "validmins"):
                valid_for_seconds = int(get_data_entry(post_data, "validmins")) * 60
            elif have_data_entry(post_data, "valid_for_seconds"):
                valid_for_seconds = int(get_data_entry(post_data, "valid_for_seconds"))
            else:
                valid_for_seconds = 10 * 60

            extra_options = {
                "valid_for_seconds": valid_for_seconds,
            }

            if have_data_entry(post_data, "amount_to"):
                extra_options["amount_to"] = inputAmount(
                    get_data_entry(post_data, "amount_to"), ci_to
                )
            elif have_data_entry(post_data, "bid_rate"):
                extra_options["bid_rate"] = ci_to.make_int(
                    get_data_entry(post_data, "bid_rate"), r=1
                )
            if have_data_entry(post_data, "bid_amount"):
                amount_from = inputAmount(
                    get_data_entry(post_data, "bid_amount"), ci_from
                )

            if offer.swap_type == SwapTypes.XMR_SWAP:
                bid_id = swap_client.postXmrBid(
                    offer_id,
                    amount_from,
                    addr_send_from=addr_from,
                    extra_options=extra_options,
                )
            else:
                bid_id = swap_client.postBid(
                    offer_id,
                    amount_from,
                    addr_send_from=addr_from,
                    extra_options=extra_options,
                )

            if have_data_entry(post_data, "debugind"):
                swap_client.setBidDebugInd(
                    bid_id, int(get_data_entry(post_data, "debugind"))
                )

            rv = {"bid_id": bid_id.hex()}
            return bytes(json.dumps(rv), "UTF-8")

        bid_id = bytes.fromhex(url_split[3])
        assert len(bid_id) == 28

        show_txns: bool = False
        with_events: bool = False
        if post_string != "":
            post_data = getFormData(post_string, is_json)
            if have_data_entry(post_data, "accept"):
                swap_client.acceptBid(bid_id)
            elif have_data_entry(post_data, "abandon"):
                swap_client.abandonBid(bid_id)
            elif have_data_entry(post_data, "debugind"):
                swap_client.setBidDebugInd(
                    bid_id, int(get_data_entry(post_data, "debugind"))
                )

            if have_data_entry(post_data, "show_extra"):
                show_txns = True
            if have_data_entry(post_data, "with_events"):
                with_events = True

        bid, xmr_swap, offer, xmr_offer, events = swap_client.getXmrBidAndOffer(bid_id)
        assert bid, "Unknown bid ID"

        if post_string != "":
            if have_data_entry(post_data, "chainbkeysplit"):
                return bytes(
                    json.dumps(
                        {
                            "splitkey": getChainBSplitKey(
                                swap_client, bid, xmr_swap, offer
                            )
                        }
                    ),
                    "UTF-8",
                )
            elif have_data_entry(post_data, "spendchainblocktx"):
                remote_key = get_data_entry(post_data, "remote_key")
                return bytes(
                    json.dumps(
                        {
                            "txid": recoverNoScriptTxnWithKey(
                                swap_client, bid_id, remote_key
                            ).hex()
                        }
                    ),
                    "UTF-8",
                )

        if len(url_split) > 4 and url_split[4] == "states":
            old_states = listOldBidStates(bid)

            if with_events:
                new_list = []
                for entry in old_states:
                    entry_list = list(entry)
                    entry_list.insert(1, "state")
                    new_list.append(entry_list)
                for event in events:
                    new_list.append([event["at"], "event", event["desc"]])
                old_states = sorted(new_list, key=lambda x: x[0])

            return bytes(json.dumps(old_states), "UTF-8")

        edit_bid = False
        data = describeBid(
            swap_client,
            bid,
            xmr_swap,
            offer,
            xmr_offer,
            events,
            edit_bid,
            show_txns,
            for_api=True,
        )
        return bytes(json.dumps(data), "UTF-8")

    post_data = {} if post_string == "" else getFormData(post_string, is_json)
    offer_id, filters = parseBidFilters(post_data)

    bids = swap_client.listBids(offer_id=offer_id, filters=filters)
    return formatBids(swap_client, bids, filters)


def js_sentbids(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client

    try:
        swap_client.checkSystemStatus()
    except Exception as e:
        from basicswap.util import LockedCoinError
        from basicswap.ui.util import getCoinName

        if isinstance(e, LockedCoinError):
            error_msg = f"Wallet must be unlocked to view bids. Please unlock your {getCoinName(e.coinid)} wallet."
            return bytes(json.dumps({"error": error_msg, "locked": True}), "UTF-8")
        else:
            return bytes(json.dumps({"error": str(e)}), "UTF-8")

    post_data = getFormData(post_string, is_json)
    offer_id, filters = parseBidFilters(post_data)

    bids = swap_client.listBids(sent=True, offer_id=offer_id, filters=filters)
    return formatBids(swap_client, bids, filters)


def js_network(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    return bytes(json.dumps(swap_client.get_network_info()), "UTF-8")


def js_revokeoffer(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    offer_id = bytes.fromhex(url_split[3])
    assert len(offer_id) == 28
    swap_client.revokeOffer(offer_id)
    return bytes(json.dumps({"revoked_offer": offer_id.hex()}), "UTF-8")


def js_smsgaddresses(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    post_data = {} if post_string == "" else getFormData(post_string, is_json)

    if len(url_split) > 3:
        mode: str = url_split[3]
        if mode == "new":
            addressnote = get_data_entry_or(post_data, "addressnote", "")
            new_addr, pubkey = swap_client.newSMSGAddress(addressnote=addressnote)
            return bytes(
                json.dumps({"new_address": new_addr, "pubkey": pubkey}), "UTF-8"
            )
        if mode == "add":
            addressnote = get_data_entry_or(post_data, "addressnote", "")
            pubkey_hex = get_data_entry(post_data, "addresspubkey")
            added_address = swap_client.addSMSGAddress(pubkey_hex, addressnote)
            return bytes(
                json.dumps({"added_address": added_address, "pubkey": pubkey_hex}),
                "UTF-8",
            )
        elif mode == "edit":
            address = get_data_entry(post_data, "address")
            activeind = int(get_data_entry(post_data, "active_ind"))
            addressnote = get_data_entry_or(post_data, "addressnote", "")
            new_addr = swap_client.editSMSGAddress(address, activeind, addressnote)
            return bytes(json.dumps({"edited_address": address}), "UTF-8")
        elif mode == "disableall":
            rv = swap_client.disableAllSMSGAddresses()
            return bytes(json.dumps(rv), "UTF-8")

    filters = {
        "exclude_inactive": post_data.get("exclude_inactive", True),
    }
    return bytes(json.dumps(swap_client.listAllSMSGAddresses(filters)), "UTF-8")


def js_rates(self, url_split, post_string, is_json) -> bytes:
    post_data = getFormData(post_string, is_json)

    sc = self.server.swap_client
    coin_from = get_data_entry(post_data, "coin_from")
    coin_to = get_data_entry(post_data, "coin_to")
    return bytes(json.dumps(sc.lookupRates(coin_from, coin_to)), "UTF-8")


def js_rates_list(self, url_split, query_string, is_json) -> bytes:
    get_data = urllib.parse.parse_qs(query_string)

    sc = self.server.swap_client
    coin_from = getCoinType(get_data["from"][0])
    coin_to = getCoinType(get_data["to"][0])
    return bytes(json.dumps(sc.lookupRates(coin_from, coin_to, True)), "UTF-8")


def js_rate(self, url_split, post_string, is_json) -> bytes:
    post_data = getFormData(post_string, is_json)

    sc = self.server.swap_client
    coin_from = getCoinType(get_data_entry(post_data, "coin_from"))
    ci_from = sc.ci(coin_from)
    coin_to = getCoinType(get_data_entry(post_data, "coin_to"))
    ci_to = sc.ci(coin_to)

    # Set amount to if rate is provided
    rate = get_data_entry_or(post_data, "rate", None)
    if rate is not None:
        amt_from_str = get_data_entry_or(post_data, "amt_from", None)
        amt_to_str = get_data_entry_or(post_data, "amt_to", None)

        if amt_from_str is not None:
            rate = ci_to.make_int(rate, r=1)
            amt_from = inputAmount(amt_from_str, ci_from)
            amount_to_int = (amt_from * rate + ci_from.COIN() - 1) // ci_from.COIN()
            amount_to = ci_to.format_amount(amount_to_int)
            return bytes(json.dumps({"amount_to": amount_to}), "UTF-8")
        if amt_to_str is not None:
            rate = ci_from.make_int(1.0 / float(rate), r=1)
            amt_to = inputAmount(amt_to_str, ci_to)
            amount_from_int = (amt_to * rate + ci_to.COIN() - 1) // ci_to.COIN()
            amount_from = ci_from.format_amount(amount_from_int)
            return bytes(json.dumps({"amount_from": amount_from}), "UTF-8")

    amt_from: int = inputAmount(get_data_entry(post_data, "amt_from"), ci_from)
    amt_to: int = inputAmount(get_data_entry(post_data, "amt_to"), ci_to)

    rate: int = ci_to.format_amount(ci_from.make_int(amt_to / amt_from, r=1))
    return bytes(json.dumps({"rate": rate}), "UTF-8")


def js_index(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client

    try:
        swap_client.checkSystemStatus()
    except Exception as e:
        from basicswap.util import LockedCoinError
        from basicswap.ui.util import getCoinName

        if isinstance(e, LockedCoinError):
            error_msg = f"Wallet must be unlocked to view summary. Please unlock your {getCoinName(e.coinid)} wallet."
            return bytes(json.dumps({"error": error_msg, "locked": True}), "UTF-8")
        else:
            return bytes(json.dumps({"error": str(e)}), "UTF-8")

    return bytes(json.dumps(swap_client.getSummary()), "UTF-8")


def js_generatenotification(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client

    if not swap_client.debug:
        raise ValueError("Debug mode not active.")

    r = random.randint(0, 3)
    if r == 0:
        swap_client.notify(NT.OFFER_RECEIVED, {"offer_id": random.randbytes(28).hex()})
    elif r == 1:
        swap_client.notify(
            NT.BID_RECEIVED,
            {
                "type": "atomic",
                "bid_id": random.randbytes(28).hex(),
                "offer_id": random.randbytes(28).hex(),
            },
        )
    elif r == 2:
        swap_client.notify(NT.BID_ACCEPTED, {"bid_id": random.randbytes(28).hex()})
    elif r == 3:
        swap_client.notify(
            NT.BID_RECEIVED,
            {
                "type": "ads",
                "bid_id": random.randbytes(28).hex(),
                "offer_id": random.randbytes(28).hex(),
            },
        )

    return bytes(json.dumps({"type": r}), "UTF-8")


def js_notifications(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()

    return bytes(json.dumps(swap_client.getNotifications()), "UTF-8")


def js_identities(self, url_split, post_string: str, is_json: bool) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()

    filters = {
        "page_no": 1,
        "limit": PAGE_LIMIT,
        "sort_by": "created_at",
        "sort_dir": "desc",
    }

    if len(url_split) > 3:
        address = url_split[3]
        filters["address"] = address

    if post_string != "":
        post_data = getFormData(post_string, is_json)

        if have_data_entry(post_data, "sort_by"):
            sort_by = get_data_entry(post_data, "sort_by")
            assert sort_by in ["created_at", "rate"], "Invalid sort by"
            filters["sort_by"] = sort_by
        if have_data_entry(post_data, "sort_dir"):
            sort_dir = get_data_entry(post_data, "sort_dir")
            assert sort_dir in ["asc", "desc"], "Invalid sort dir"
            filters["sort_dir"] = sort_dir

        if have_data_entry(post_data, "offset"):
            filters["offset"] = int(get_data_entry(post_data, "offset"))
        if have_data_entry(post_data, "limit"):
            filters["limit"] = int(get_data_entry(post_data, "limit"))
            assert (
                filters["limit"] > 0 and filters["limit"] <= PAGE_LIMIT
            ), "Invalid limit"

        set_data = {}
        if have_data_entry(post_data, "set_label"):
            set_data["label"] = get_data_entry(post_data, "set_label")
        if have_data_entry(post_data, "set_automation_override"):
            set_data["automation_override"] = get_data_entry(
                post_data, "set_automation_override"
            )
        if have_data_entry(post_data, "set_visibility_override"):
            set_data["visibility_override"] = get_data_entry(
                post_data, "set_visibility_override"
            )
        if have_data_entry(post_data, "set_note"):
            set_data["note"] = get_data_entry(post_data, "set_note")

        if set_data:
            ensure("address" in filters, "Must provide an address to modify data")
            swap_client.setIdentityData(filters, set_data)

    rv = swap_client.listIdentities(filters)
    if "address" in filters:
        rv = {} if len(rv) < 1 else rv[0]
    return bytes(json.dumps(rv), "UTF-8")


def js_automationstrategies(self, url_split, post_string: str, is_json: bool) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()

    filters = {
        "page_no": 1,
        "limit": PAGE_LIMIT,
        "sort_by": "created_at",
        "sort_dir": "desc",
    }

    strat_id = int(url_split[3]) if len(url_split) > 3 else None

    if post_string != "":
        post_data = getFormData(post_string, is_json)

        if have_data_entry(post_data, "sort_by"):
            sort_by = get_data_entry(post_data, "sort_by")
            assert sort_by in ["created_at", "rate"], "Invalid sort by"
            filters["sort_by"] = sort_by
        if have_data_entry(post_data, "sort_dir"):
            sort_dir = get_data_entry(post_data, "sort_dir")
            assert sort_dir in ["asc", "desc"], "Invalid sort dir"
            filters["sort_dir"] = sort_dir

        if have_data_entry(post_data, "offset"):
            filters["offset"] = int(get_data_entry(post_data, "offset"))
        if have_data_entry(post_data, "limit"):
            filters["limit"] = int(get_data_entry(post_data, "limit"))
            assert (
                filters["limit"] > 0 and filters["limit"] <= PAGE_LIMIT
            ), "Invalid limit"

        set_data = {}
        if have_data_entry(post_data, "set_label"):
            set_data["label"] = get_data_entry(post_data, "set_label")
        if have_data_entry(post_data, "set_data"):
            set_data["data"] = json.loads(get_data_entry(post_data, "set_data"))
        if have_data_entry(post_data, "set_note"):
            set_data["note"] = get_data_entry(post_data, "set_note")
        if have_data_entry(post_data, "set_only_known_identities"):
            set_data["only_known_identities"] = get_data_entry(
                post_data, "set_only_known_identities"
            )

        if have_data_entry(post_data, "set_max_concurrent_bids"):
            if "data" in set_data:
                raise ValueError("set_max_concurrent_bids can't be used with set_data")
            set_data["set_max_concurrent_bids"] = int(
                get_data_entry(post_data, "set_max_concurrent_bids")
            )

        if set_data:
            ensure(strat_id is not None, "Must specify a strategy to modify")
            swap_client.updateAutomationStrategy(strat_id, set_data)

    if strat_id is not None:
        strat_data = swap_client.getAutomationStrategy(strat_id)
        rv = {
            "record_id": strat_data.record_id,
            "label": strat_data.label,
            "type_ind": strat_data.type_ind,
            "only_known_identities": strat_data.only_known_identities,
            "data": json.loads(strat_data.data.decode("UTF-8")),
            "note": "" if strat_data.note is None else strat_data.note,
        }
        return bytes(json.dumps(rv), "UTF-8")

    rv = []
    strats = swap_client.listAutomationStrategies(filters)
    for row in strats:
        rv.append((row[0], row[1], row[2]))
    return bytes(json.dumps(rv), "UTF-8")


def js_validateamount(self, url_split, post_string: str, is_json: bool) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()

    post_data = getFormData(post_string, is_json)

    ticker_str = post_data["coin"]
    amount = post_data["amount"]
    round_method = post_data.get("method", "none")

    valid_round_methods = ("roundoff", "rounddown", "none")
    if round_method not in valid_round_methods:
        raise ValueError(
            f"Unknown rounding method, must be one of {valid_round_methods}"
        )

    coin_type = getCoinIdFromTicker(ticker_str)
    ci = swap_client.ci(coin_type)

    r = 0
    if round_method == "roundoff":
        r = 1
    elif round_method == "rounddown":
        r = -1

    output_amount = ci.format_amount(amount, conv_int=True, r=r)
    return bytes(json.dumps(output_amount), "UTF-8")


def js_vacuumdb(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    swap_client.vacuumDB()

    return bytes(json.dumps({"completed": True}), "UTF-8")


def js_getcoinseed(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    post_data = getFormData(post_string, is_json)

    coin_in = get_data_entry(post_data, "coin")
    extkey_prefix = get_data_entry_or(
        post_data, "extkey_prefix", 0x04B2430C
    )  # default, zprv for P2WPKH in electrum
    if isinstance(extkey_prefix, str):
        if extkey_prefix.isdigit():
            extkey_prefix = int(extkey_prefix)
        else:
            extkey_prefix = int(extkey_prefix, 16)  # Try hex

    try:
        coin = getCoinIdFromName(coin_in)
    except Exception:
        coin = getCoinType(coin_in)

    if coin in (Coins.PART, Coins.PART_ANON, Coins.PART_BLIND):
        raise ValueError("Particl wallet seed is set from the Basicswap mnemonic.")

    ci = swap_client.ci(coin)
    rv = {"coin": ci.ticker()}
    if coin in (Coins.XMR, Coins.WOW):
        key_view = swap_client.getWalletKey(coin, 1, for_ed25519=True)
        key_spend = swap_client.getWalletKey(coin, 2, for_ed25519=True)
        address = ci.getAddressFromKeys(key_view, key_spend)

        expect_address = swap_client.getCachedMainWalletAddress(ci)
        rv.update(
            {
                "key_view": ci.encodeKey(key_view),
                "key_spend": ci.encodeKey(key_spend),
                "address": address,
                "expected_address": (
                    "Unset" if expect_address is None else expect_address
                ),
            }
        )
    else:
        seed_key = swap_client.getWalletKey(coin, 1)
        seed_id = ci.getSeedHash(seed_key)
        expect_seedid = swap_client.getStringKV(
            "main_wallet_seedid_" + ci.coin_name().lower()
        )
        try:
            wallet_seed_id = ci.getWalletSeedID()
        except Exception as e:
            wallet_seed_id = f"Error: {e}"
        rv.update(
            {
                "seed": seed_key.hex(),
                "seed_id": seed_id.hex(),
                "expected_seed_id": "Unset" if expect_seedid is None else expect_seedid,
                "current_seed_id": wallet_seed_id,
            }
        )
        if hasattr(ci, "canExportToElectrum") and ci.canExportToElectrum():
            rv.update(
                {"account_key": ci.getAccountKey(seed_key, extkey_prefix)}
            )  # Master key can be imported into electrum (Must set prefix for P2WPKH)

    return bytes(
        json.dumps(rv),
        "UTF-8",
    )


def js_setpassword(self, url_split, post_string, is_json) -> bytes:
    # Set or change wallet passwords
    # Only works with currently enabled coins
    # Will fail if any coin does not unlock on the old password
    swap_client = self.server.swap_client
    post_data = getFormData(post_string, is_json)

    old_password = get_data_entry(post_data, "oldpassword")
    new_password = get_data_entry(post_data, "newpassword")

    if have_data_entry(post_data, "coin"):
        # Set password for one coin
        coin = getCoinType(get_data_entry(post_data, "coin"))
        if coin in (Coins.PART_ANON, Coins.PART_BLIND, Coins.LTC_MWEB):
            raise ValueError("Invalid coin.")
        swap_client.changeWalletPasswords(old_password, new_password, coin)
        return bytes(json.dumps({"success": True}), "UTF-8")

    # Set password for all coins
    swap_client.changeWalletPasswords(old_password, new_password)
    return bytes(json.dumps({"success": True}), "UTF-8")


def js_unlock(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    post_data = getFormData(post_string, is_json)

    password: str = get_data_entry(post_data, "password")

    if have_data_entry(post_data, "coin"):
        coin = getCoinType(str(get_data_entry(post_data, "coin")))
        if coin in (Coins.PART_ANON, Coins.PART_BLIND):
            raise ValueError("Invalid coin.")
        swap_client.unlockWallets(password, coin)
        return bytes(json.dumps({"success": True}), "UTF-8")

    swap_client.unlockWallets(password)
    return bytes(json.dumps({"success": True}), "UTF-8")


def js_lock(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    post_data = {} if post_string == "" else getFormData(post_string, is_json)

    if have_data_entry(post_data, "coin"):
        coin = getCoinType(get_data_entry(post_data, "coin"))
        if coin in (Coins.PART_ANON, Coins.PART_BLIND):
            raise ValueError("Invalid coin.")
        swap_client.lockWallets(coin)
        return bytes(json.dumps({"success": True}), "UTF-8")

    swap_client.lockWallets()
    return bytes(json.dumps({"success": True}), "UTF-8")


def js_404(self, url_split, post_string, is_json) -> bytes:
    return bytes(json.dumps({"Error": "path unknown"}), "UTF-8")


def js_help(self, url_split, post_string, is_json) -> bytes:
    # TODO: Add details and examples
    commands = []
    for k in endpoints:
        commands.append(k)
    return bytes(json.dumps({"commands": commands}), "UTF-8")


def js_readurl(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    post_data = {} if post_string == "" else getFormData(post_string, is_json)
    if not have_data_entry(post_data, "url"):
        raise ValueError("Requires URL.")
    url = get_data_entry(post_data, "url")
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    response = swap_client.readURL(url, headers=default_headers)
    try:
        error = json.loads(response.decode())
        if "Error" in error:
            return json.dumps({"Error": error["Error"]}).encode()
    except json.JSONDecodeError:
        pass
    return response


def js_active(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    swap_client.checkSystemStatus()
    all_bids = []
    try:
        for bid_id, (bid, offer) in list(swap_client.swaps_in_progress.items()):
            try:
                ci_from = swap_client.ci(offer.coin_from)
                ci_to = swap_client.ci(offer.coin_to)
                if offer.bid_reversed:
                    amount_from: int = bid.amount_to
                    amount_to: int = bid.amount
                    bid_rate: int = ci_from.make_int(amount_to / amount_from, r=1)
                else:
                    amount_from: int = bid.amount
                    amount_to: int = bid.amount_to
                    bid_rate: int = bid.rate
                swap_data = {
                    "bid_id": bid_id.hex(),
                    "offer_id": offer.offer_id.hex(),
                    "created_at": bid.created_at,
                    "expire_at": bid.expire_at,
                    "bid_state": strBidState(bid.state),
                    "tx_state_a": None,
                    "tx_state_b": None,
                    "coin_from": ci_from.coin_name(),
                    "coin_to": ci_to.coin_name(),
                    "amount_from": ci_from.format_amount(amount_from),
                    "amount_to": ci_to.format_amount(amount_to),
                    "rate": bid_rate,
                    "addr_from": bid.bid_addr if bid.was_received else offer.addr_from,
                    "was_sent": bid.was_sent,
                }

                if offer.swap_type == SwapTypes.XMR_SWAP:
                    swap_data["tx_state_a"] = (
                        strTxState(bid.xmr_a_lock_tx.state)
                        if bid.xmr_a_lock_tx
                        else None
                    )
                    swap_data["tx_state_b"] = (
                        strTxState(bid.xmr_b_lock_tx.state)
                        if bid.xmr_b_lock_tx
                        else None
                    )
                else:
                    swap_data["tx_state_a"] = bid.getITxState()
                    swap_data["tx_state_b"] = bid.getPTxState()

                all_bids.append(swap_data)

            except Exception:
                pass
    except Exception:
        return bytes(json.dumps([]), "UTF-8")
    return bytes(json.dumps(all_bids), "UTF-8")


def js_coinprices(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    post_data = {} if post_string == "" else getFormData(post_string, is_json)
    if not have_data_entry(post_data, "coins"):
        raise ValueError("Requires coins list.")

    currency_to = Fiat.USD
    if have_data_entry(post_data, "currency_to"):
        currency_to = fiatFromTicker(get_data_entry(post_data, "currency_to"))

    rate_source: str = "coingecko.com"
    if have_data_entry(post_data, "source"):
        rate_source = get_data_entry(post_data, "source")

    match_input_key: bool = toBool(
        get_data_entry_or(post_data, "match_input_key", "true")
    )
    ttl: int = int(get_data_entry_or(post_data, "ttl", 300))

    coins = get_data_entry(post_data, "coins")
    coins_list = coins.split(",")
    coin_ids = []
    input_id_map = {}
    for coin in coins_list:
        if coin.isdigit():
            try:
                coin_id = Coins(int(coin))
            except Exception:
                raise ValueError(f"Unknown coin type {coin}")
        else:
            try:
                coin_id = getCoinIdFromTicker(coin)
            except Exception:
                try:
                    coin_id = getCoinIdFromName(coin)
                except Exception:
                    raise ValueError(f"Unknown coin type {coin}")
        coin_ids.append(coin_id)
        input_id_map[coin_id] = coin

    coinprices = swap_client.lookupFiatRates(
        coin_ids, currency_to=currency_to, rate_source=rate_source, saved_ttl=ttl
    )

    rv = {}
    for k, v in coinprices.items():
        if match_input_key:
            rv[input_id_map[k]] = v
        else:
            rv[int(k)] = v
    return bytes(
        json.dumps({"currency": currency_to.name, "source": rate_source, "rates": rv}),
        "UTF-8",
    )


def js_messageroutes(self, url_split, post_string, is_json) -> bytes:
    swap_client = self.server.swap_client
    post_data = {} if post_string == "" else getFormData(post_string, is_json)

    filters = {
        "page_no": 1,
        "limit": PAGE_LIMIT,
        "sort_by": "created_at",
        "sort_dir": "desc",
    }

    if have_data_entry(post_data, "sort_by"):
        sort_by = get_data_entry(post_data, "sort_by")
        ensure(
            sort_by
            in [
                "created_at",
            ],
            "Invalid sort by",
        )
        filters["sort_by"] = sort_by
    if have_data_entry(post_data, "sort_dir"):
        sort_dir = get_data_entry(post_data, "sort_dir")
        ensure(sort_dir in ["asc", "desc"], "Invalid sort dir")
        filters["sort_dir"] = sort_dir

    if have_data_entry(post_data, "offset"):
        filters["offset"] = int(get_data_entry(post_data, "offset"))
    if have_data_entry(post_data, "limit"):
        filters["limit"] = int(get_data_entry(post_data, "limit"))
        ensure(filters["limit"] > 0, "Invalid limit")

    if have_data_entry(post_data, "address_from"):
        filters["address_from"] = get_data_entry(post_data, "address_from")
    if have_data_entry(post_data, "address_to"):
        filters["address_to"] = get_data_entry(post_data, "address_to")

    action = get_data_entry_or(post_data, "action", None)

    message_routes = swap_client.listMessageRoutes(filters, action)
    return bytes(json.dumps(message_routes), "UTF-8")


endpoints = {
    "coins": js_coins,
    "walletbalances": js_walletbalances,
    "wallets": js_wallets,
    "offers": js_offers,
    "sentoffers": js_sentoffers,
    "bids": js_bids,
    "sentbids": js_sentbids,
    "network": js_network,
    "revokeoffer": js_revokeoffer,
    "smsgaddresses": js_smsgaddresses,
    "rate": js_rate,
    "rates": js_rates,
    "rateslist": js_rates_list,
    "generatenotification": js_generatenotification,
    "notifications": js_notifications,
    "identities": js_identities,
    "automationstrategies": js_automationstrategies,
    "validateamount": js_validateamount,
    "vacuumdb": js_vacuumdb,
    "getcoinseed": js_getcoinseed,
    "setpassword": js_setpassword,
    "unlock": js_unlock,
    "lock": js_lock,
    "help": js_help,
    "readurl": js_readurl,
    "active": js_active,
    "coinprices": js_coinprices,
    "messageroutes": js_messageroutes,
}


def js_url_to_function(url_split):
    if len(url_split) > 2:
        return endpoints.get(url_split[2], js_404)
    return js_index
