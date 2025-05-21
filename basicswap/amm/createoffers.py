#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2023-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Create offers

{
    "min_seconds_between_offers": Add a random delay between creating offers between min and max, default 60.
    "max_seconds_between_offers": ^, default "min_seconds_between_offers" * 4
    "min_seconds_between_bids": Add a random delay between creating bids between min and max, default 60.
    "max_seconds_between_bids": ^, default "min_seconds_between_bids" * 4
    "wallet_port_override": Used for testing.
    "prune_state_delay": Seconds between pruning old state data, set to 0 to disable pruning.
    "main_loop_delay": Seconds between main loop iterations.
    "prune_state_after_seconds": Seconds to keep old state data for.
    "auth": Basicswap API auth string, e.g., "admin:password". Ignored if client auth is not enabled.
    "offers": [
        {
            "name": Offer template name, eg "Offer 0", will be automatically renamed if not unique.
            "coin_from": Coin you send.
            "coin_to": Coin you receive.
            "amount": Amount to create the offer for.
            "minrate": Rate below which the offer won't drop.
            "ratetweakpercent": modify the offer rate from the fetched value, can be negative.
            "amount_variable": bool, bidder can set a different amount
            "address": Address offer is sent from, default will generate a new address per offer.
            "min_coin_from_amt": Won't generate offers if the wallet would drop below min_coin_from_amt.
            "offer_valid_seconds": Seconds that the generated offers will be valid for.

            # Optional
            "enabled": Set to false to ignore offer template.
            "swap_type": Type of swap, defaults to "adaptor_sig"
            "min_swap_amount": Sets "amt_bid_min" on the offer, minimum purchase quantity when offer amount is variable.
            "amount_step": If set offers will be created for amount values between "amount" and "min_coin_from_amt" in decrements of "amount_step".
        },
        ...
    ],
    "bids": [
        {
            "name": Bid template name, must be unique, eg "Bid 0", will be automatically renamed if not unique.
            "coin_from": Coin you receive.
            "coin_to": Coin you send.
            "amount": amount to bid.
            "max_rate": Maximum rate for bids.
            "min_coin_to_balance": Won't send bids if wallet amount of "coin_to" would drop below.

            # Optional
            "enabled": Set to false to ignore bid template.
            "max_concurrent": Maximum number of bids to have active at once, default 1.
            "amount_variable": Can send bids below the set "amount" where possible if true.
            "max_coin_from_balance": Won't send bids if wallet amount of "coin_from" would be above.
            "address": Address offer is sent from, default will generate a new address per bid.
        },
        ...
    ]
}

"""

__version__ = "0.3"

import argparse
import json
import os
import random
import shutil
import signal
import sys
import threading
import time
import traceback
import urllib
import urllib.error
import base64
from urllib.request import urlopen

delay_event = threading.Event()
shutdown_in_progress = False
coins_map = {}
read_json_api = None
read_json_api_wallet = None

DEFAULT_CONFIG_FILE: str = "createoffers.json"
DEFAULT_STATE_FILE: str = "createoffers_state.json"


def post_req(url: str, json_data=None, auth_header_val=None):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    if auth_header_val:
        req.add_header("Authorization", auth_header_val)
    if json_data:
        req.add_header("Content-Type", "application/json; charset=utf-8")
        post_bytes = json.dumps(json_data).encode("utf-8")
        req.add_header("Content-Length", len(post_bytes))
    else:
        post_bytes = None
    return urlopen(req, data=post_bytes, timeout=300)


def make_json_api_func(host: str, port: int, auth_string: str = None):
    host = host
    port = port
    _auth_header_val = None
    _auth_required_confirmed = False
    if auth_string:
        try:
            if auth_string and ":" in auth_string:
                try:
                    auth_bytes = auth_string.encode("utf-8")
                    _auth_header_val = "Basic " + base64.b64encode(auth_bytes).decode(
                        "ascii"
                    )
                except Exception as e:
                    print(
                        f"Warning: Could not process auth string '{auth_string}': {e}"
                    )
                    _auth_header_val = None
            elif auth_string:
                print(
                    "Warning: Auth string is not in 'username:password' format. Ignoring."
                )
        except Exception as e:
            print(f"Error processing authentication: {e}")

    def api_func(path=None, json_data=None, timeout=300):
        nonlocal _auth_required_confirmed
        url = f"http://{host}:{port}/json"
        if path is not None:
            url += "/" + path

        current_auth_header = _auth_header_val if _auth_required_confirmed else None

        try:
            if json_data is not None:
                response_obj = post_req(
                    url, json_data, auth_header_val=current_auth_header
                )
            else:
                headers = {"User-Agent": "Mozilla/5.0"}
                if current_auth_header:
                    headers["Authorization"] = current_auth_header
                req = urllib.request.Request(url, headers=headers)
                response_obj = urlopen(req, timeout=timeout)

            response_bytes = response_obj.read()
            return json.loads(response_bytes)

        except urllib.error.HTTPError as e:
            if e.code == 401 and not _auth_required_confirmed:
                if _auth_header_val:
                    print(
                        "Server requires authentication, retrying with credentials..."
                    )
                    _auth_required_confirmed = True
                    try:
                        if json_data is not None:
                            response_obj = post_req(
                                url, json_data, auth_header_val=_auth_header_val
                            )
                        else:
                            headers = {
                                "User-Agent": "Mozilla/5.0",
                                "Authorization": _auth_header_val,
                            }
                            req = urllib.request.Request(url, headers=headers)
                            response_obj = urlopen(req, timeout=timeout)
                        response_bytes = response_obj.read()
                        return json.loads(response_bytes)
                    except urllib.error.HTTPError as retry_e:
                        if retry_e.code == 401:
                            raise ValueError(
                                "Authentication failed: Invalid credentials provided in 'auth' key."
                            )
                        else:
                            print(f"Error during authenticated API request: {retry_e}")
                            raise retry_e
                    except Exception as retry_e:
                        print(f"Error during authenticated API request: {retry_e}")
                        raise retry_e
                else:
                    raise ValueError(
                        "Server requires authentication (401), but no 'auth' key found or properly formatted in config file."
                    )
            else:
                if e.code == 401 and _auth_required_confirmed:
                    raise ValueError(
                        "Authentication failed: Invalid credentials provided in 'auth' key."
                    )
                else:
                    raise e
        except Exception as e:
            print(f"Error during API connection: {e}")
            raise e

    return api_func


def signal_handler(sig, _) -> None:
    global shutdown_in_progress
    os.write(sys.stdout.fileno(), f"Signal {sig} detected, ending program.\n".encode("utf-8"))
    shutdown_in_progress = True
    delay_event.set()


def findCoin(coin: str, known_coins) -> str:
    for known_coin in known_coins:
        if (
            known_coin["name"].lower() == coin.lower()
            or known_coin["ticker"].lower() == coin.lower()
        ):
            if known_coin["active"] is False:
                raise ValueError(f"Inactive coin {coin}")
            return known_coin["name"]
    raise ValueError(f"Unknown coin {coin}")


def readConfig(args, known_coins):
    config_path: str = args.configfile
    num_changes: int = 0
    with open(config_path) as fs:
        config = json.load(fs)

    if "offers" not in config:
        config["offers"] = []
    if "bids" not in config:
        config["bids"] = []

    if "min_seconds_between_offers" not in config:
        config["min_seconds_between_offers"] = 60
        print("Set min_seconds_between_offers", config["min_seconds_between_offers"])
        num_changes += 1
    if "max_seconds_between_offers" not in config:
        config["max_seconds_between_offers"] = config["min_seconds_between_offers"] * 4
        print("Set max_seconds_between_offers", config["max_seconds_between_offers"])
        num_changes += 1

    if "min_seconds_between_bids" not in config:
        config["min_seconds_between_bids"] = 60
        print("Set min_seconds_between_bids", config["min_seconds_between_bids"])
        num_changes += 1
    if "max_seconds_between_bids" not in config:
        config["max_seconds_between_bids"] = config["min_seconds_between_bids"] * 4
        print("Set max_seconds_between_bids", config["max_seconds_between_bids"])
        num_changes += 1

    offer_templates = config["offers"]
    offer_templates_map = {}
    num_enabled = 0
    for i, offer_template in enumerate(offer_templates):
        num_enabled += 1 if offer_template.get("enabled", True) else 0
        if "name" not in offer_template:
            print("Naming offer template", i)
            offer_template["name"] = f"Offer {i}"
            num_changes += 1
        if offer_template["name"] in offer_templates_map:
            print("Renaming offer template", offer_template["name"])
            original_name = offer_template["name"]
            offset = 2
            while f"{original_name}_{offset}" in offer_templates_map:
                offset += 1
            offer_template["name"] = f"{original_name}_{offset}"
            num_changes += 1
        offer_templates_map[offer_template["name"]] = offer_template

        if "amount_step" not in offer_template:
            if offer_template.get("min_coin_from_amt", 0) < offer_template["amount"]:
                print("Setting min_coin_from_amt for", offer_template["name"])
                offer_template["min_coin_from_amt"] = offer_template["amount"]
                num_changes += 1
        else:
            if "min_coin_from_amt" not in offer_template:
                print("Setting min_coin_from_amt for", offer_template["name"])
                offer_template["min_coin_from_amt"] = 0
                num_changes += 1

        if "address" not in offer_template:
            print("Setting address to auto for offer", offer_template["name"])
            offer_template["address"] = "auto"
            num_changes += 1
        if "ratetweakpercent" not in offer_template:
            print("Setting ratetweakpercent to 0 for offer", offer_template["name"])
            offer_template["ratetweakpercent"] = 0
            num_changes += 1
        if "amount_variable" not in offer_template:
            print("Setting amount_variable to True for offer", offer_template["name"])
            offer_template["amount_variable"] = True
            num_changes += 1

        if offer_template.get("enabled", True) is False:
            continue
        offer_template["coin_from"] = findCoin(offer_template["coin_from"], known_coins)
        offer_template["coin_to"] = findCoin(offer_template["coin_to"], known_coins)
    config["num_enabled_offers"] = num_enabled

    bid_templates = config["bids"]
    bid_templates_map = {}
    num_enabled = 0
    for i, bid_template in enumerate(bid_templates):
        num_enabled += 1 if bid_template.get("enabled", True) else 0
        if "name" not in bid_template:
            print("Naming bid template", i)
            bid_template["name"] = f"Bid {i}"
            num_changes += 1
        if bid_template["name"] in bid_templates_map:
            print("Renaming bid template", bid_template["name"])
            original_name = bid_template["name"]
            offset = 2
            while f"{original_name}_{offset}" in bid_templates_map:
                offset += 1
            bid_template["name"] = f"{original_name}_{offset}"
            num_changes += 1
        bid_templates_map[bid_template["name"]] = bid_template

        if bid_template.get("min_swap_amount", 0.0) < 0.001:
            print("Setting min_swap_amount for bid template", bid_template["name"])
            bid_template["min_swap_amount"] = 0.001

        if "address" not in bid_template:
            print("Setting address to auto for bid", bid_template["name"])
            bid_template["address"] = "auto"
            num_changes += 1

        if bid_template.get("enabled", True) is False:
            continue
        bid_template["coin_from"] = findCoin(bid_template["coin_from"], known_coins)
        bid_template["coin_to"] = findCoin(bid_template["coin_to"], known_coins)
    config["num_enabled_bids"] = num_enabled

    config["main_loop_delay"] = config.get("main_loop_delay", 60)
    if config["main_loop_delay"] < 10:
        print("Setting main_loop_delay to 10")
        config["main_loop_delay"] = 10
        num_changes += 1
    if config["main_loop_delay"] > 1000:
        print("Setting main_loop_delay to 1000")
        config["main_loop_delay"] = 1000
        num_changes += 1
    config["prune_state_delay"] = config.get("prune_state_delay", 120)

    # Add market-based rate adjustment option (default: enabled)
    # When enabled, the script will analyze existing offers in the market
    # and adjust rates to be competitive (slightly better than the best existing offer)
    # This helps ensure your offers are more likely to be taken
    if "adjust_rates_based_on_market" not in config:
        config["adjust_rates_based_on_market"] = True
        print("Setting adjust_rates_based_on_market to True")
        num_changes += 1

    seconds_in_day: int = 86400
    config["prune_state_after_seconds"] = config.get(
        "prune_state_after_seconds", seconds_in_day * 7
    )
    if config["prune_state_after_seconds"] < seconds_in_day:
        print(f"Setting prune_state_after_seconds to {seconds_in_day}")
        config["prune_state_after_seconds"] = seconds_in_day
        num_changes += 1

    if num_changes > 0:
        shutil.copyfile(config_path, config_path + ".last")
        with open(config_path, "w") as fp:
            json.dump(config, fp, indent=4)

    return config


def write_state(statefile, script_state):
    if os.path.exists(statefile):
        shutil.copyfile(statefile, statefile + ".last")
    with open(statefile, "w") as fp:
        json.dump(script_state, fp, indent=4)


def process_offers(args, config, script_state) -> None:
    global shutdown_in_progress
    if shutdown_in_progress:
        return

    offer_templates = config["offers"]
    if len(offer_templates) < 1:
        return
    if args.debug:
        print(
            "Processing {} offer template{}".format(
                config["num_enabled_offers"],
                "s" if config["num_enabled_offers"] != 1 else "",
            )
        )

    random.shuffle(offer_templates)
    sent_offers = read_json_api("sentoffers", {"active": "active"})
    for offer_template in offer_templates:
        if offer_template.get("enabled", True) is False:
            continue
        offers_found = 0

        coin_from_data = coins_map[offer_template["coin_from"]]
        coin_to_data = coins_map[offer_template["coin_to"]]

        wallet_from = read_json_api_wallet(
            "wallets/{}".format(coin_from_data["ticker"])
        )
        coin_ticker = coin_from_data["ticker"]
        if coin_ticker == "PART" and "variant" in coin_from_data:
            coin_variant = coin_from_data["variant"]
            if coin_variant == "Anon":
                coin_from_data_name = "PART_ANON"
                wallet_balance: float = float(wallet_from["anon_balance"])
            elif coin_variant == "Blind":
                coin_from_data_name = "PART_BLIND"
                wallet_balance: float = float(wallet_from["blind_balance"])
            else:
                raise ValueError(f"{coin_ticker} variant {coin_variant} not handled")
        else:
            coin_from_data_name = coin_ticker
            wallet_balance: float = float(wallet_from["balance"])

        for offer in sent_offers:
            created_offers = script_state.get("offers", {})
            prev_template_offers = created_offers.get(offer_template["name"], {})

            if next(
                (x for x in prev_template_offers if x["offer_id"] == offer["offer_id"]),
                None,
            ):
                offers_found += 1
                if wallet_balance <= float(offer_template["min_coin_from_amt"]):
                    offer_id = offer["offer_id"]
                    print(
                        "Revoking offer {}, wallet from balance below minimum".format(
                            offer_id
                        )
                    )
                    result = read_json_api(f"revokeoffer/{offer_id}")
                    print("revokeoffer", result)

        if offers_found > 0:
            continue

        max_offer_amount: float = offer_template["amount"]
        min_offer_amount: float = offer_template.get("amount_step", max_offer_amount)

        min_wallet_from_amount: float = float(offer_template["min_coin_from_amt"])
        if wallet_balance - min_offer_amount <= min_wallet_from_amount:
            print(
                "Skipping template {}, wallet from balance below minimum".format(
                    offer_template["name"]
                )
            )
            continue

        offer_amount: float = max_offer_amount
        if wallet_balance - max_offer_amount <= min_wallet_from_amount:
            available_balance: float = wallet_balance - min_wallet_from_amount
            min_steps: int = available_balance // min_offer_amount
            assert min_steps > 0  # Should not be possible, checked above
            offer_amount = min_offer_amount * min_steps

        delay_next_offer_before = script_state.get("delay_next_offer_before", 0)
        if delay_next_offer_before > int(time.time()):
            print("Delaying offers until {}".format(delay_next_offer_before))
            break

        # Get market rates from CoinGecko
        rates = read_json_api(
            "rates",
            {"coin_from": coin_from_data["id"], "coin_to": coin_to_data["id"]},
        )
        print("CoinGecko Rates:", rates)
        coingecko_rate = float(rates["coingecko"]["rate_inferred"])
        use_rate = coingecko_rate

        # Get existing offers to adjust our rate based on market conditions
        # Only if the feature is enabled in config
        if config.get("adjust_rates_based_on_market", True):
            received_offers = read_json_api('offers', {
                'active': 'active',
                'include_sent': False,
                'coin_from': coin_from_data['id'],
                'coin_to': coin_to_data['id']
            })

            if args.debug:
                print(f"Found {len(received_offers)} existing offers for {coin_from_data['ticker']} to {coin_to_data['ticker']}")

            # Adjust rates based on existing offers
            if received_offers:
                # Calculate average market rate from existing offers
                market_rates = [float(offer['rate']) for offer in received_offers]
                if market_rates:
                    avg_market_rate = sum(market_rates) / len(market_rates)
                    min_market_rate = min(market_rates)
                    max_market_rate = max(market_rates)

                    # Adjust our rate to be competitive
                    # Strategy: Position our rate between CoinGecko and the best market rate
                    # If our minrate is higher than market rates, respect that limit
                    if min_market_rate < use_rate:
                        # Calculate a competitive rate that's slightly better than average market rate
                        competitive_rate = min_market_rate * 0.99  # 1% better than best offer

                        # Don't go below our minimum rate
                        if competitive_rate >= offer_template["minrate"]:
                            use_rate = competitive_rate
                            print(f"Adjusting rate to be competitive: {use_rate} (1% better than best market rate {min_market_rate})")
                        else:
                            print(f"Market rate {min_market_rate} is below our minimum rate {offer_template['minrate']}")
                    else:
                        print(f"Our CoinGecko rate {use_rate} is already better than best market rate {min_market_rate}")

                    # Log market statistics
                    print(f"Market statistics - Avg: {avg_market_rate}, Min: {min_market_rate}, Max: {max_market_rate}")
                else:
                    print("No valid market rates found in existing offers")
        else:
            if args.debug:
                print("Market-based rate adjustment is disabled in config")

        if offer_template["ratetweakpercent"] != 0:
            print(
                "Adjusting rate {} by {}%.".format(
                    use_rate, offer_template["ratetweakpercent"]
                )
            )
            tweak = offer_template["ratetweakpercent"] / 100.0
            use_rate += use_rate * tweak

        if use_rate < offer_template["minrate"]:
            print("Warning: Clamping rate to minimum.")
            use_rate = offer_template["minrate"]

        print("Creating offer for: {} at rate: {}".format(offer_template, use_rate))
        template_from_addr = offer_template["address"]
        offer_data = {
            "addr_from": (-1 if template_from_addr == "auto" else template_from_addr),
            "coin_from": coin_from_data_name,
            "coin_to": coin_to_data["ticker"],
            "amt_from": offer_amount,
            "amt_var": offer_template["amount_variable"],
            "valid_for_seconds": offer_template.get(
                "offer_valid_seconds", config.get("offer_valid_seconds", 3600)
            ),
            "rate": use_rate,
            "swap_type": offer_template.get("swap_type", "adaptor_sig"),
            "lockhrs": "24",
            "automation_strat_id": 1,
        }
        if "min_swap_amount" in offer_template:
            offer_data["amt_bid_min"] = offer_template["min_swap_amount"]
        if args.debug:
            print("offer data {}".format(offer_data))
        new_offer = read_json_api("offers/new", offer_data)
        if "error" in new_offer:
            raise ValueError(
                "Server failed to create offer: {}".format(new_offer["error"])
            )
        print("New offer: {}".format(new_offer["offer_id"]))
        if "offers" not in script_state:
            script_state["offers"] = {}
        template_name = offer_template["name"]
        if template_name not in script_state["offers"]:
            script_state["offers"][template_name] = []
        script_state["offers"][template_name].append(
            {"offer_id": new_offer["offer_id"], "time": int(time.time())}
        )
        max_seconds_between_offers = config["max_seconds_between_offers"]
        min_seconds_between_offers = config["min_seconds_between_offers"]
        time_between_offers = min_seconds_between_offers
        if max_seconds_between_offers > min_seconds_between_offers:
            time_between_offers = random.randint(
                min_seconds_between_offers, max_seconds_between_offers
            )

        script_state["delay_next_offer_before"] = int(time.time()) + time_between_offers
        write_state(args.statefile, script_state)


def process_bids(args, config, script_state) -> None:
    global shutdown_in_progress
    if shutdown_in_progress:
        return

    bid_templates = config["bids"]
    if len(bid_templates) < 1:
        return
    random.shuffle(bid_templates)

    if args.debug:
        print(
            "Processing {} bid template{}".format(
                config["num_enabled_bids"],
                "s" if config["num_enabled_bids"] != 1 else "",
            )
        )
    for bid_template in bid_templates:
        if bid_template.get("enabled", True) is False:
            continue
        delay_next_bid_before = script_state.get("delay_next_bid_before", 0)
        if delay_next_bid_before > int(time.time()):
            print("Delaying bids until {}".format(delay_next_bid_before))
            break

        # Check bids in progress
        max_concurrent = bid_template.get("max_concurrent", 1)
        if "bids" not in script_state:
            script_state["bids"] = {}
        template_name = bid_template["name"]
        if template_name not in script_state["bids"]:
            script_state["bids"][template_name] = []
        previous_bids = script_state["bids"][template_name]

        bids_in_progress: int = 0
        for previous_bid in previous_bids:
            if not previous_bid["active"]:
                continue
            previous_bid_id = previous_bid["bid_id"]
            previous_bid_info = read_json_api(f"bids/{previous_bid_id}")
            bid_state = previous_bid_info["bid_state"]
            if bid_state in (
                "Completed",
                "Timed-out",
                "Abandoned",
                "Error",
                "Rejected",
            ):
                print(f"Marking bid inactive {previous_bid_id}, state {bid_state}")
                previous_bid["active"] = False
                write_state(args.statefile, script_state)
                continue
            if bid_state in ("Sent", "Received") and previous_bid_info[
                "expired_at"
            ] < int(time.time()):
                print(f"Marking bid inactive {previous_bid_id}, expired")
                previous_bid["active"] = False
                write_state(args.statefile, script_state)
                continue
            bids_in_progress += 1

        if bids_in_progress >= max_concurrent:
            print("Max concurrent bids reached for template")
            continue

        # Bidder sends coin_to and receives coin_from
        coin_from_data = coins_map[bid_template["coin_from"]]
        coin_to_data = coins_map[bid_template["coin_to"]]

        page_limit: int = 25
        offers_options = {
            "active": "active",
            "include_sent": False,
            "coin_from": coin_from_data["id"],
            "coin_to": coin_to_data["id"],
            "with_extra_info": True,
            "sort_by": "rate",
            "sort_dir": "asc",
            "offset": 0,
            "limit": page_limit,
        }

        received_offers = []
        for i in range(1000000):  # for i in itertools.count()
            page_offers = read_json_api("offers", offers_options)
            if len(page_offers) < 1:
                break
            received_offers += page_offers
            offers_options["offset"] = offers_options["offset"] + page_limit
            if i > 100:
                print(f"Warning: Broke offers loop at: {i}")
                break

        if args.debug:
            print("Received Offers", received_offers)

        for offer in received_offers:
            offer_id = offer["offer_id"]
            offer_amount = float(offer["amount_from"])
            offer_rate = float(offer["rate"])
            bid_amount = bid_template["amount"]

            min_swap_amount = bid_template.get(
                "min_swap_amount", 0.01
            )  # TODO: Make default vary per coin
            can_adjust_offer_amount: bool = offer["amount_negotiable"]
            can_adjust_bid_amount: bool = bid_template.get("amount_variable", True)
            can_adjust_amount: bool = can_adjust_offer_amount and can_adjust_bid_amount

            if offer_amount < min_swap_amount:
                if args.debug:
                    print(f"Offer amount below min swap amount bid {offer_id}")
                continue

            if can_adjust_offer_amount is False and offer_amount > bid_amount:
                if args.debug:
                    print(f"Bid amount too low for offer {offer_id}")
                continue

            if bid_amount > offer_amount:
                if can_adjust_bid_amount:
                    bid_amount = offer_amount
                else:
                    if args.debug:
                        print(f"Bid amount too high for offer {offer_id}")
                    continue

            if offer_rate > bid_template["maxrate"]:
                if args.debug:
                    print(f"Bid rate too low for offer {offer_id}")
                continue

            sent_bids = read_json_api(
                "sentbids",
                {
                    "offer_id": offer["offer_id"],
                    "with_available_or_active": True,
                },
            )
            if len(sent_bids) > 0:
                if args.debug:
                    print(f"Already bidding on offer {offer_id}")
                continue

            offer_identity = read_json_api("identities/{}".format(offer["addr_from"]))
            if "address" in offer_identity:
                id_offer_from = offer_identity
                automation_override = id_offer_from["automation_override"]
                if automation_override == 2:
                    if args.debug:
                        print(
                            f"Not bidding on offer {offer_id}, automation_override ({automation_override})."
                        )
                    continue
                if automation_override == 1:
                    if args.debug:
                        print(
                            "Offer address from {}, set to always accept.".format(
                                offer["addr_from"]
                            )
                        )
                else:
                    successful_sent_bids = id_offer_from["num_sent_bids_successful"]
                    failed_sent_bids = id_offer_from["num_sent_bids_failed"]
                    if failed_sent_bids > 3 and failed_sent_bids > successful_sent_bids:
                        if args.debug:
                            print(
                                f"Not bidding on offer {offer_id}, too many failed bids ({failed_sent_bids})."
                            )
                        continue

            validateamount: bool = False
            max_coin_from_balance = bid_template.get("max_coin_from_balance", -1)
            if max_coin_from_balance > 0:
                wallet_from = read_json_api_wallet(
                    "wallets/{}".format(coin_from_data["ticker"])
                )
                total_balance_from = float(wallet_from["balance"]) + float(
                    wallet_from["unconfirmed"]
                )
                if args.debug:
                    print(f"Total coin from balance {total_balance_from}")
                if total_balance_from + bid_amount > max_coin_from_balance:
                    if (
                        can_adjust_amount
                        and max_coin_from_balance - total_balance_from > min_swap_amount
                    ):
                        bid_amount = max_coin_from_balance - total_balance_from
                        validateamount = True
                        print(f"Reduced bid amount to {bid_amount}")
                    else:
                        if args.debug:
                            print(
                                f"Bid amount would exceed maximum wallet total for offer {offer_id}"
                            )
                        continue

            min_coin_to_balance = bid_template["min_coin_to_balance"]
            if min_coin_to_balance > 0:
                wallet_to = read_json_api_wallet(
                    "wallets/{}".format(coin_to_data["ticker"])
                )

                total_balance_to = float(wallet_to["balance"]) + float(
                    wallet_to["unconfirmed"]
                )
                if args.debug:
                    print(f"Total coin to balance {total_balance_to}")

                swap_amount_to = bid_amount * offer_rate
                if total_balance_to - swap_amount_to < min_coin_to_balance:
                    if can_adjust_amount:
                        adjusted_swap_amount_to = total_balance_to - min_coin_to_balance
                        adjusted_bid_amount = adjusted_swap_amount_to / offer_rate

                        if adjusted_bid_amount > min_swap_amount:
                            bid_amount = adjusted_bid_amount
                            validateamount = True
                            print(f"Reduced bid amount to {bid_amount}")
                            swap_amount_to = adjusted_bid_amount * offer_rate

                if total_balance_to - swap_amount_to < min_coin_to_balance:
                    if args.debug:
                        print(
                            f"Bid amount would exceed minimum coin to wallet total for offer {offer_id}"
                        )
                    continue

            if validateamount:
                bid_amount = read_json_api(
                    "validateamount",
                    {
                        "coin": coin_from_data["ticker"],
                        "amount": bid_amount,
                        "method": "rounddown",
                    },
                )
            bid_data = {
                "offer_id": offer["offer_id"],
                "amount_from": bid_amount,
            }

            if "address" in bid_template:
                addr_from = bid_template["address"]
                if addr_from != -1 and addr_from != "auto":
                    bid_data["addr_from"] = addr_from

            if config.get("test_mode", False):
                print("Would create bid: {}".format(bid_data))
                bid_id = "simulated"
            else:
                if args.debug:
                    print("Creating bid: {}".format(bid_data))
                new_bid = read_json_api("bids/new", bid_data)
                if "error" in new_bid:
                    raise ValueError(
                        "Server failed to create bid: {}".format(new_bid["error"])
                    )
                print(
                    "New bid: {} on offer {}".format(
                        new_bid["bid_id"], offer["offer_id"]
                    )
                )
                bid_id = new_bid["bid_id"]

            script_state["bids"][template_name].append(
                {"bid_id": bid_id, "time": int(time.time()), "active": True}
            )

            max_seconds_between_bids = config["max_seconds_between_bids"]
            min_seconds_between_bids = config["min_seconds_between_bids"]
            if max_seconds_between_bids > min_seconds_between_bids:
                time_between_bids = random.randint(
                    min_seconds_between_bids, max_seconds_between_bids
                )
            else:
                time_between_bids = min_seconds_between_bids
            script_state["delay_next_bid_before"] = int(time.time()) + time_between_bids
            write_state(args.statefile, script_state)
            break  # Create max one bid per iteration


def prune_script_state(now, args, config, script_state):
    global shutdown_in_progress
    if shutdown_in_progress:
        return

    if args.debug:
        print("Pruning script state.")

    removed_offers: int = 0
    removed_bids: int = 0

    max_ttl: int = config["prune_state_after_seconds"]
    if "offers" in script_state:
        for template_name, template_group in script_state["offers"].items():
            offers_to_remove = []
            for offer in template_group:
                if now - offer["time"] > max_ttl:
                    offers_to_remove.append(offer["offer_id"])

            for offer_id in offers_to_remove:
                for i, offer in enumerate(template_group):
                    if offer_id == offer["offer_id"]:
                        del template_group[i]
                        removed_offers += 1
                        break

    if "bids" in script_state:
        for template_name, template_group in script_state["bids"].items():
            bids_to_remove = []
            for bid in template_group:
                if now - bid["time"] > max_ttl:
                    bids_to_remove.append(bid["bid_id"])

            for bid_id in bids_to_remove:
                for i, bid in enumerate(template_group):
                    if bid_id == bid["bid_id"]:
                        del template_group[i]
                        removed_bids += 1
                        break

    if removed_offers > 0 or removed_bids > 0:
        print(
            "Pruned {} offer{} and {} bid{} from script state.".format(
                removed_offers,
                "s" if removed_offers != 1 else "",
                removed_bids,
                "s" if removed_bids != 1 else "",
            )
        )
    script_state["time_last_pruned_state"] = now
    write_state(args.statefile, script_state)


def main():
    global read_json_api, read_json_api_wallet
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="%(prog)s {version}".format(version=__version__),
    )
    parser.add_argument(
        "--host",
        dest="host",
        help="RPC host (default=127.0.0.1)",
        type=str,
        default="127.0.0.1",
        required=False,
    )
    parser.add_argument(
        "--port",
        dest="port",
        help="RPC port (default=12700)",
        type=int,
        default=12700,
        required=False,
    )
    parser.add_argument(
        "--oneshot",
        dest="oneshot",
        help="Exit after one iteration (default=false)",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        help="Print extra debug messages (default=false)",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--configfile",
        dest="configfile",
        help=f"config file path (default={DEFAULT_CONFIG_FILE})",
        type=str,
        default=DEFAULT_CONFIG_FILE,
        required=False,
    )
    parser.add_argument(
        "--statefile",
        dest="statefile",
        help=f"state file path (default={DEFAULT_STATE_FILE})",
        type=str,
        default=DEFAULT_STATE_FILE,
        required=False,
    )
    args = parser.parse_args()

    if not os.path.exists(args.configfile):
        print(f'Error: Config file "{args.configfile}" not found.')
        return 1

    try:
        with open(args.configfile) as fs:
            initial_config = json.load(fs)
    except Exception as e:
        print(f"Error reading config file {args.configfile}: {e}")
        return 1

    auth_info = initial_config.get("auth")

    read_json_api = make_json_api_func(args.host, args.port, auth_info)
    wallet_api_port_override = initial_config.get("wallet_port_override")
    if wallet_api_port_override:
        read_json_api_wallet_auth = make_json_api_func(
            args.host, int(wallet_api_port_override), auth_info
        )
    else:
        read_json_api_wallet_auth = read_json_api_wallet

    try:
        print("Checking API connection...")
        known_coins = read_json_api("coins")
        for known_coin in known_coins:
            coins_map[known_coin["name"]] = known_coin
        print("API connection successful.")
    except ValueError as e:
        print(f"\nError: {e}")
        print(
            'Please ensure the \'auth\' key in your config file is correct (e.g., "auth": "username:password")'
        )
        return 1
    except urllib.error.URLError as e:
        print(
            f"\nError: Could not connect to Basicswap API at http://{args.host}:{args.port}"
        )
        print(f"Reason: {e.reason}")
        print("Please ensure Basicswap is running and accessible.")
        return 1
    except Exception as e:
        print(f"\nError during initial API connection: {e}")
        if args.debug:
            traceback.print_exc()
        return 1

    script_state = {}
    if os.path.exists(args.statefile):
        try:
            with open(args.statefile) as fs:
                script_state = json.load(fs)
        except Exception as e:
            print(f"Error reading state file {args.statefile}: {e}")
            print("Starting with empty state.")
            script_state = {}

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        while not delay_event.is_set():
            # Read config each iteration so it can be modified without restarting
            config = readConfig(args, known_coins)

            # override wallet api calls for testing
            if "wallet_port_override" in config:
                wallet_api_port = int(config["wallet_port_override"])
                print(f"Overriding wallet api port: {wallet_api_port}")
                read_json_api_wallet = read_json_api_wallet_auth
            else:
                read_json_api_wallet = read_json_api

            # Skip processing if shutdown is in progress
            if not shutdown_in_progress:
                try:
                    process_offers(args, config, script_state)

                    process_bids(args, config, script_state)

                    now = int(time.time())
                    prune_state_delay = config["prune_state_delay"]
                    if prune_state_delay > 0:
                        if (
                            now - script_state.get("time_last_pruned_state", 0)
                            > prune_state_delay
                        ):
                            prune_script_state(now, args, config, script_state)

                except Exception as e:
                    print(f"Error: {e}.")
                    if args.debug:
                        traceback.print_exc()

            if args.oneshot or shutdown_in_progress:
                break

            if not shutdown_in_progress:
                print("Looping indefinitely, ctrl+c to exit.")

            delay_event.wait(config["main_loop_delay"])

        print("Done.")
        return 0
    except KeyboardInterrupt:
        print("\nExiting due to keyboard interrupt.")
        return 0
    except Exception as e:
        print(f"Fatal error: {e}")
        if args.debug:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    main()
