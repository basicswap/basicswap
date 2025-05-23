# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import json
import time
import subprocess
import threading
import traceback
import sys
from urllib import parse
from urllib.request import Request, urlopen
from .util import listAvailableCoins

DEFAULT_AMM_CONFIG_FILE = "createoffers.json"
DEFAULT_AMM_STATE_FILE = "createoffers_state.json"

amm_process = None
amm_log_buffer = []
amm_log_lock = threading.Lock()
amm_status = "stopped"
amm_config_file = DEFAULT_AMM_CONFIG_FILE
amm_state_file = DEFAULT_AMM_STATE_FILE
amm_host = "127.0.0.1"
amm_port = 12700
amm_debug = False


def ensure_amm_dir(swap_client):
    """Ensure the AMM directory exists in the datadir"""
    amm_dir = os.path.join(swap_client.data_dir, "AMM")
    os.makedirs(amm_dir, exist_ok=True)
    return amm_dir


def get_amm_config_path(swap_client, config_file=None):
    """Get the full path to the AMM config file"""
    if config_file is None:
        config_file = amm_config_file
    return os.path.join(ensure_amm_dir(swap_client), config_file)


def get_amm_state_path(swap_client, state_file=None):
    """Get the full path to the AMM state file"""
    if state_file is None:
        state_file = amm_state_file
    return os.path.join(ensure_amm_dir(swap_client), state_file)


def get_amm_module_path():
    """Get the path to the AMM module"""
    return "basicswap.amm.createoffers"


def log_capture_thread(process, swap_client):
    """Thread to capture and store logs from the AMM process"""
    global amm_status

    while process.poll() is None:
        try:
            line = process.stdout.readline()
            if not line:
                break

            line_str = line.decode("utf-8", errors="replace").rstrip()

            with amm_log_lock:
                amm_log_buffer.append(line_str)
                if len(amm_log_buffer) > 1000:
                    amm_log_buffer.pop(0)

            debug_enabled = globals().get('amm_debug', False)
            if debug_enabled or any(important in line_str for important in [
                "Error:", "Failed to", "New offer created", "New bid created", "Revoking offer",
                "AMM process", "Offer revoked", "Server failed"
            ]):
                swap_client.log.info(f"AMM: {line_str}")
        except Exception as e:
            swap_client.log.error(f"Error capturing AMM log: {str(e)}")

    with amm_log_lock:
        amm_status = "stopped"
        amm_log_buffer.append("AMM process has stopped.")
        swap_client.log.info("AMM process has stopped.")


def start_amm_process(
    swap_client, host, port, config_file=None, state_file=None, debug=False
):
    """Start the AMM process"""
    global amm_process, amm_log_buffer, amm_status, amm_config_file, amm_state_file, amm_debug

    amm_debug = debug

    if amm_process is not None and amm_process.poll() is None:
        return False, "AMM process is already running"

    if config_file:
        amm_config_file = config_file
    if state_file:
        amm_state_file = state_file

    config_path = get_amm_config_path(swap_client)
    state_path = get_amm_state_path(swap_client)

    if not os.path.exists(config_path):
        default_config = {
            "min_seconds_between_offers": 60,
            "max_seconds_between_offers": 240,
            "main_loop_delay": 60,
            "offers": [],
            "bids": [],
        }

        if swap_client.debug:
            default_config["prune_state_delay"] = 120
            default_config["prune_state_after_seconds"] = 604800
            default_config["min_seconds_between_bids"] = 60
            default_config["max_seconds_between_bids"] = 240

        with open(config_path, "w") as f:
            json.dump(default_config, f, indent=4)

    module_path = get_amm_module_path()
    cmd = [
        sys.executable,
        "-m",
        module_path,
        "--host",
        host,
        "--port",
        str(port),
        "--configfile",
        config_path,
        "--statefile",
        state_path,
    ]

    cmd_str = " ".join(cmd)
    swap_client.log.info(f"Starting AMM process with command: {cmd_str}")

    if debug:
        cmd.append("--debug")

    try:
        amm_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=False,
            bufsize=-1,
        )

        with amm_log_lock:
            amm_log_buffer = []
            amm_status = "running"
            amm_log_buffer.append(f"AMM process started with PID {amm_process.pid}")
            amm_log_buffer.append(f"Using config file: {config_path}")
            amm_log_buffer.append(f"Using state file: {state_path}")

        log_thread = threading.Thread(
            target=log_capture_thread, args=(amm_process, swap_client), daemon=True
        )
        log_thread.start()

        return True, f"AMM process started with PID {amm_process.pid}"
    except Exception as e:
        return False, f"Failed to start AMM process: {str(e)}"


def stop_amm_process():
    """Stop the AMM process"""
    global amm_status

    if amm_process is None or amm_process.poll() is not None:
        return False, "AMM process is not running"

    try:
        amm_process.terminate()

        for _ in range(10):
            if amm_process.poll() is not None:
                break
            time.sleep(0.1)

        if amm_process.poll() is None:
            amm_process.kill()
            amm_process.wait(timeout=5)

        with amm_log_lock:
            amm_status = "stopped"
            amm_log_buffer.append("AMM process stopped.")

        return True, "AMM process stopped"
    except Exception as e:
        return False, f"Failed to stop AMM process: {str(e)}"


def get_amm_status():
    """Get the current status of the AMM process"""
    if amm_process is not None:
        if amm_process.poll() is None:
            return "running"
        else:
            return f"exited with code {amm_process.returncode}"

    return amm_status


def get_amm_logs():
    """Get the AMM logs"""
    with amm_log_lock:
        return amm_log_buffer.copy()


def get_amm_active_count(swap_client, debug_override=False):
    """Get the count of active AMM offers and bids"""
    amm_count = 0

    debug_enabled = swap_client.debug and debug_override

    status = get_amm_status()
    if status != "running":
        return 0

    state_path = get_amm_state_path(swap_client)
    if not os.path.exists(state_path):
        if debug_enabled:
            swap_client.log.info(
                f"AMM state file not found at {state_path}, returning count 0"
            )
        return 0

    state_data = {}
    active_network_offers = {}

    try:
        with open(state_path, "r") as f:
            state_data = json.load(f)

        if debug_enabled:
            swap_client.log.info(f"AMM state data: {json.dumps(state_data, indent=2)}")

        try:
            network_offers = swap_client.listOffers()

            if debug_enabled:
                swap_client.log.info(f"Network offers type: {type(network_offers)}")
                if network_offers and len(network_offers) > 0:
                    swap_client.log.info(f"First offer type: {type(network_offers[0])}")

            for offer in network_offers:
                try:
                    if hasattr(offer, "offer_id"):
                        offer_id = (
                            offer.offer_id.hex()
                            if hasattr(offer.offer_id, "hex")
                            else str(offer.offer_id)
                        )
                    elif hasattr(offer, "id"):
                        offer_id = (
                            offer.id.hex()
                            if hasattr(offer.id, "hex")
                            else str(offer.id)
                        )
                    elif isinstance(offer, (list, tuple)) and len(offer) > 0:
                        offer_id = (
                            offer[0].hex()
                            if hasattr(offer[0], "hex")
                            else str(offer[0])
                        )
                    elif isinstance(offer, dict) and "offer_id" in offer:
                        offer_id = (
                            offer["offer_id"].hex()
                            if hasattr(offer["offer_id"], "hex")
                            else str(offer["offer_id"])
                        )
                    else:
                        offer_str = str(offer)
                        if debug_enabled:
                            swap_client.log.info(
                                f"Offer string representation: {offer_str}"
                            )
                        continue

                    active_network_offers[offer_id] = True

                except Exception as e:
                    if debug_enabled:
                        swap_client.log.error(f"Error processing offer: {str(e)}")
                        swap_client.log.error(f"Offer: {offer}")
                        swap_client.log.error(traceback.format_exc())
                    continue

            if debug_enabled:
                swap_client.log.info(
                    f"Found {len(active_network_offers)} active offers in the network"
                )
                if len(active_network_offers) > 0:
                    swap_client.log.info(
                        f"Active offer IDs: {list(active_network_offers.keys())}"
                    )
        except Exception as e:
            if debug_enabled:
                swap_client.log.error(f"Error getting network offers: {str(e)}")
                swap_client.log.error(traceback.format_exc())

        if len(active_network_offers) == 0:
            if debug_enabled:
                swap_client.log.info(
                    "No active network offers found, trying direct API call"
                )

            try:
                global amm_host, amm_port
                if "amm_host" not in globals() or "amm_port" not in globals():
                    amm_host = "127.0.0.1"
                    amm_port = 12700
                    if debug_enabled:
                        swap_client.log.info(
                            f"Using default host {amm_host} and port {amm_port} for API call"
                        )

                api_url = f"http://{amm_host}:{amm_port}/api/v1/offers"

                req = Request(api_url)
                response = urlopen(req)
                data = json.loads(response.read().decode("utf-8"))

                if "offers" in data:
                    for offer in data["offers"]:
                        if "id" in offer:
                            offer_id = offer["id"]
                            active_network_offers[offer_id] = True

                if debug_enabled:
                    swap_client.log.info(
                        f"Found {len(active_network_offers)} active offers via API"
                    )
                    if len(active_network_offers) > 0:
                        swap_client.log.info(
                            f"Active offer IDs via API: {list(active_network_offers.keys())}"
                        )
            except Exception as e:
                if debug_enabled:
                    swap_client.log.error(f"Error getting offers via API: {str(e)}")
                    swap_client.log.error(traceback.format_exc())

        if "offers" in state_data:
            for template_name, offers in state_data["offers"].items():
                active_offer_count = 0
                for offer in offers:
                    if (
                        "offer_id" in offer
                        and offer["offer_id"] in active_network_offers
                    ):
                        active_offer_count += 1

                amm_count += active_offer_count
                if debug_enabled:
                    total_offers = len(offers)
                    swap_client.log.info(
                        f"Template '{template_name}': {active_offer_count} active out of {total_offers} total offers"
                    )

        if "bids" in state_data:
            for template_name, bids in state_data["bids"].items():
                active_bid_count = 0
                for bid in bids:
                    if "bid_id" in bid and bid.get("active", False):
                        active_bid_count += 1

                amm_count += active_bid_count
                if debug_enabled:
                    total_bids = len(bids)
                    swap_client.log.info(
                        f"Template '{template_name}': {active_bid_count} active out of {total_bids} total bids"
                    )

        if debug_enabled:
            swap_client.log.info(f"Total active AMM count: {amm_count}")

        if (
            amm_count == 0
            and len(active_network_offers) == 0
            and "offers" in state_data
        ):
            if debug_enabled:
                swap_client.log.info(
                    "No active network offers found, using most recent offer from state file"
                )

            most_recent_time = 0
            most_recent_offer = None

            for template_name, offers in state_data["offers"].items():
                for offer in offers:
                    if "time" in offer and offer["time"] > most_recent_time:
                        most_recent_time = offer["time"]
                        most_recent_offer = offer

            if most_recent_offer and "time" in most_recent_offer:
                current_time = int(time.time())
                offer_age = current_time - most_recent_offer["time"]

                if offer_age < 3600:
                    amm_count = 1
                    if debug_enabled:
                        swap_client.log.info(
                            f"Using most recent offer as active (age: {offer_age} seconds)"
                        )
                        if "offer_id" in most_recent_offer:
                            swap_client.log.info(
                                f"Most recent offer ID: {most_recent_offer['offer_id']}"
                            )

        if amm_count == 0 and "delay_next_offer_before" in state_data:
            if debug_enabled:
                swap_client.log.info(
                    "Found delay_next_offer_before in state, AMM is running but waiting to create next offer"
                )

            config_path = get_amm_config_path(swap_client)
            if os.path.exists(config_path):
                try:
                    with open(config_path, "r") as f:
                        config_data = json.load(f)

                    for offer in config_data.get("offers", []):
                        if offer.get("enabled", False):
                            if debug_enabled:
                                swap_client.log.info(
                                    f"Found enabled offer '{offer.get('name')}', but no active offers in network"
                                )
                            break
                except Exception as e:
                    if debug_enabled:
                        swap_client.log.error(f"Error reading config file: {str(e)}")

        if (
            amm_count == 0
            and status == "running"
            and "offers" in state_data
            and len(state_data["offers"]) > 0
        ):
            if debug_enabled:
                swap_client.log.info(
                    "AMM is running with offers in state file, but none are active. Setting count to 1."
                )
            amm_count = 1
    except Exception as e:
        if debug_enabled:
            swap_client.log.error(f"Error getting AMM count: {str(e)}")
            swap_client.log.error(traceback.format_exc())
        return 0

    if debug_enabled:
        swap_client.log.info(f"Final AMM active count: {amm_count}")

    return amm_count


def page_amm(self, _, post_string):
    """Render the AMM page"""
    global amm_host, amm_port, amm_debug

    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    messages = []
    err_messages = []

    basicswap_host = swap_client.settings.get("htmlhost", "127.0.0.1")
    basicswap_port = swap_client.settings.get("htmlport", 12700)

    if amm_host == "127.0.0.1" and amm_port == 12700:
        amm_host = basicswap_host
        amm_port = basicswap_port

    amm_dir = ensure_amm_dir(swap_client)
    config_path = get_amm_config_path(swap_client)
    state_path = get_amm_state_path(swap_client)

    config_exists = os.path.exists(config_path)
    state_exists = os.path.exists(state_path)

    script_exists = True
    script_path = get_amm_module_path()

    config_content = ""
    config_data = {}
    if config_exists:
        try:
            with open(config_path, "r") as f:
                config_content = f.read()
                config_data = json.loads(config_content)
        except Exception as e:
            err_messages.append(f"Failed to read config file: {str(e)}")
    else:
        default_config = {
            "min_seconds_between_offers": 60,
            "max_seconds_between_offers": 240,
            "main_loop_delay": 60,
            "offers": [
                {
                    "id": "offer1234",
                    "name": "Example Offer",
                    "enabled": False,
                    "coin_from": "PART",
                    "coin_to": "BTC",
                    "amount": 10.0,
                    "minrate": 0.0001,
                    "ratetweakpercent": 0,
                    "adjust_rates_based_on_market": True,
                    "amount_variable": True,
                    "address": "auto",
                    "min_coin_from_amt": 10.0,
                    "offer_valid_seconds": 3600,
                }
            ],
            "bids": [],
        }

        # Add debug-only settings if in debug mode
        if swap_client.debug:
            default_config["prune_state_delay"] = 120
            default_config["prune_state_after_seconds"] = 604800
            default_config["min_seconds_between_bids"] = 60
            default_config["max_seconds_between_bids"] = 240

            # Add example bid in debug mode
            default_config["bids"] = [
                {
                    "id": "bid5678",
                    "name": "Example Bid",
                    "enabled": False,
                    "coin_from": "BTC",
                    "coin_to": "PART",
                    "amount": 0.01,
                    "max_rate": 10000.0,
                    "min_coin_to_balance": 1.0,
                    "max_concurrent": 1,
                    "amount_variable": True,
                    "address": "auto",
                }
            ]

        try:
            with open(config_path, "w") as f:
                json.dump(default_config, f, indent=4)
            config_exists = True
            config_content = json.dumps(default_config, indent=4)
            config_data = default_config
            messages.append("Created default configuration file")
        except Exception as e:
            err_messages.append(f"Failed to create default config file: {str(e)}")

    if post_string:
        try:
            form_data = parse.parse_qs(
                post_string.decode("utf-8")
                if isinstance(post_string, bytes)
                else post_string
            )

            if "start" in form_data:
                amm_host = form_data.get("host", ["127.0.0.1"])[0]
                amm_port = int(form_data.get("port", ["12700"])[0])
                amm_debug = "debug" in form_data

                success, msg = start_amm_process(
                    swap_client, amm_host, amm_port, debug=amm_debug
                )
                if success:
                    messages.append(msg)
                else:
                    err_messages.append(msg)

            elif "stop" in form_data:
                # Stop AMM process
                success, msg = stop_amm_process()
                if success:
                    messages.append(msg)
                else:
                    err_messages.append(msg)

            elif "restart" in form_data:
                # Restart AMM process
                stop_amm_process()
                time.sleep(1)

                amm_host = form_data.get("host", ["127.0.0.1"])[0]
                amm_port = int(form_data.get("port", ["12700"])[0])
                amm_debug = "debug" in form_data

                success, msg = start_amm_process(
                    swap_client, amm_host, amm_port, debug=amm_debug
                )
                if success:
                    messages.append("AMM process restarted: " + msg)
                else:
                    err_messages.append("Failed to restart AMM process: " + msg)

            elif "save_config" in form_data:
                config_content = form_data.get("config_content", [""])[0]

                try:
                    json.loads(config_content)

                    with open(config_path, "w") as f:
                        f.write(config_content)

                    try:
                        config_data = json.loads(config_content)
                    except Exception:
                        pass

                    messages.append("Config file saved successfully")
                except json.JSONDecodeError as e:
                    err_messages.append(f"Invalid JSON: {str(e)}")
                except Exception as e:
                    err_messages.append(f"Failed to save config file: {str(e)}")

            elif "add_offer" in form_data:
                try:
                    with open(config_path, "r") as f:
                        current_config = json.load(f)

                    import uuid

                    offer_id = str(uuid.uuid4())[:8]

                    if (
                        not form_data.get("offer_name", [""])[0]
                        or not form_data.get("offer_coin_from", [""])[0]
                        or not form_data.get("offer_coin_to", [""])[0]
                    ):
                        err_messages.append(
                            "Missing required fields for offer: Name, Coin From, and Coin To are required"
                        )
                        raise ValueError("Missing required fields")

                    new_offer = {
                        "id": offer_id,
                        "name": form_data.get("offer_name", ["New Offer"])[0],
                        "enabled": "offer_enabled" in form_data,
                        "coin_from": form_data.get("offer_coin_from", [""])[0],
                        "coin_to": form_data.get("offer_coin_to", [""])[0],
                        "amount": float(form_data.get("offer_amount", ["0"])[0] or "0"),
                        "minrate": float(
                            form_data.get("offer_minrate", ["0"])[0] or "0"
                        ),
                        "ratetweakpercent": float(
                            form_data.get("offer_ratetweakpercent", ["0"])[0] or "0"
                        ),
                        "amount_variable": "offer_amount_variable" in form_data,
                        "address": form_data.get("offer_address", ["auto"])[0]
                        or "auto",
                    }

                    if form_data.get("offer_min_coin_from_amt", [""])[0]:
                        try:
                            new_offer["min_coin_from_amt"] = float(
                                form_data.get("offer_min_coin_from_amt", ["0"])[0]
                                or "0"
                            )
                        except ValueError:
                            pass

                    if form_data.get("offer_valid_seconds", [""])[0]:
                        try:
                            new_offer["offer_valid_seconds"] = int(
                                form_data.get("offer_valid_seconds", ["3600"])[0]
                                or "3600"
                            )
                        except ValueError:
                            pass

                    if "offers" not in current_config:
                        current_config["offers"] = []

                    current_config["offers"].append(new_offer)

                    with open(config_path, "w") as f:
                        json.dump(current_config, f, indent=4)

                    config_content = json.dumps(current_config, indent=4)
                    config_data = current_config

                    messages.append(
                        f"New offer '{new_offer['name']}' added successfully"
                    )
                except Exception as e:
                    err_messages.append(f"Failed to add offer: {str(e)}")

            elif "add_bid" in form_data:
                try:
                    with open(config_path, "r") as f:
                        current_config = json.load(f)

                    import uuid

                    bid_id = str(uuid.uuid4())[:8]

                    if (
                        not form_data.get("bid_name", [""])[0]
                        or not form_data.get("bid_coin_from", [""])[0]
                        or not form_data.get("bid_coin_to", [""])[0]
                    ):
                        err_messages.append(
                            "Missing required fields for bid: Name, Coin From, and Coin To are required"
                        )
                        raise ValueError("Missing required fields")

                    new_bid = {
                        "id": bid_id,
                        "name": form_data.get("bid_name", ["New Bid"])[0],
                        "enabled": "bid_enabled" in form_data,
                        "coin_from": form_data.get("bid_coin_from", [""])[0],
                        "coin_to": form_data.get("bid_coin_to", [""])[0],
                        "amount": float(form_data.get("bid_amount", ["0"])[0] or "0"),
                        "max_rate": float(
                            form_data.get("bid_max_rate", ["0"])[0] or "0"
                        ),
                        "amount_variable": "bid_amount_variable" in form_data,
                        "address": form_data.get("bid_address", ["auto"])[0] or "auto",
                    }

                    if form_data.get("bid_min_coin_to_balance", [""])[0]:
                        try:
                            new_bid["min_coin_to_balance"] = float(
                                form_data.get("bid_min_coin_to_balance", ["0"])[0]
                                or "0"
                            )
                        except ValueError:
                            pass

                    if form_data.get("bid_max_concurrent", [""])[0]:
                        try:
                            new_bid["max_concurrent"] = int(
                                form_data.get("bid_max_concurrent", ["1"])[0] or "1"
                            )
                        except ValueError:
                            pass

                    if form_data.get("bid_min_swap_amount", [""])[0]:
                        try:
                            new_bid["min_swap_amount"] = float(
                                form_data.get("bid_min_swap_amount", ["0"])[0] or "0"
                            )
                        except ValueError:
                            pass

                    if "bids" not in current_config:
                        current_config["bids"] = []

                    current_config["bids"].append(new_bid)

                    with open(config_path, "w") as f:
                        json.dump(current_config, f, indent=4)

                    config_content = json.dumps(current_config, indent=4)
                    config_data = current_config

                    messages.append(f"New bid '{new_bid['name']}' added successfully")
                except Exception as e:
                    err_messages.append(f"Failed to add bid: {str(e)}")

            elif "prune_state" in form_data:
                if swap_client.debug_ui:
                    try:
                        if os.path.exists(state_path):
                            with open(state_path, "w") as f:
                                f.write("{}")
                            messages.append("AMM state file cleared successfully")
                            state_content = "{}"
                            state_data = {}
                        else:
                            messages.append("AMM state file does not exist")
                    except Exception as e:
                        err_messages.append(f"Failed to clear AMM state file: {str(e)}")
                else:
                    err_messages.append("Debug UI mode must be enabled to clear the AMM state file")

            elif "create_default" in form_data:
                # Create default config with all available options
                include_bids = "include_bids" in form_data and swap_client.debug

                default_config = {
                    # General settings
                    "min_seconds_between_offers": 60,  # Minimum delay between creating offers
                    "max_seconds_between_offers": 240,  # Maximum delay between creating offers
                    "main_loop_delay": 60,  # Seconds between main loop iterations (10-1000)
                    # Optional settings
                    "auth": "",  # BasicSwap API auth string, e.g., "admin:password" (if auth is enabled)
                    # "wallet_port_override": 12345,  # Override wallet API port (for testing only) - uncomment and set if needed
                    # Offer templates
                    "offers": [
                        {
                            # Required settings
                            "id": "offer1234",  # Unique identifier for this offer
                            "name": "Example Offer",  # Template name, must be unique
                            "enabled": False,  # Set to true to enable this offer
                            "coin_from": "Particl",  # Coin you send
                            "coin_to": "Monero",  # Coin you receive
                            "amount": 10.0,  # Amount to create the offer for
                            "minrate": 0.0001,  # Rate below which the offer won't drop
                            "ratetweakpercent": 0,  # Modify the offer rate from the fetched value (can be negative)
                            "adjust_rates_based_on_market": True,  # Whether to adjust rates based on existing market offers
                            "amount_variable": True,  # Whether bidder can set a different amount
                            "address": "auto",  # Address offer is sent from (auto = generate new address per offer)
                            "min_coin_from_amt": 10.0,  # Won't generate offers if wallet balance would drop below this
                            "offer_valid_seconds": 3600,  # How long generated offers will be valid for
                            # Optional settings
                            "swap_type": "adaptor_sig",  # Type of swap, defaults to "adaptor_sig"
                            "min_swap_amount": 0.001,  # Minimum purchase quantity when offer amount is variable
                            # "amount_step": 1.0  # If set, offers will be created between "amount" and "min_coin_from_amt" in decrements
                        }
                    ],
                    "bids": [],  # Empty by default
                }

                if swap_client.debug:
                    default_config["prune_state_delay"] = 120  # Seconds between pruning old state data (0 to disable)
                    default_config["prune_state_after_seconds"] = 604800  # How long to keep old state data (7 days)
                    default_config["min_seconds_between_bids"] = 60  # Minimum delay between creating bids
                    default_config["max_seconds_between_bids"] = 240  # Maximum delay between creating bids

                if include_bids:
                    default_config["bids"] = [
                        {
                            # Required settings
                            "id": "bid5678",  # Unique identifier for this bid
                            "name": "Example Bid",  # Template name, must be unique
                            "enabled": False,  # Set to true to enable this bid
                            "coin_from": "Monero",  # Coin you receive
                            "coin_to": "Particl",  # Coin you send
                            "amount": 0.01,  # Amount to bid
                            "max_rate": 10000.0,  # Maximum rate for bids
                            "min_coin_to_balance": 1.0,  # Won't send bids if wallet amount would drop below this
                            # Optional settings
                            "max_concurrent": 1,  # Maximum number of bids to have active at once
                            "amount_variable": True,  # Can send bids below the set amount where possible
                            # "max_coin_from_balance": 100.0,  # Won't send bids if wallet amount would be above this
                            "address": "auto",  # Address bid is sent from (auto = generate new address per bid)
                            "min_swap_amount": 0.001,  # Minimum swap amount
                        }
                    ]

                try:
                    with open(config_path, "w") as f:
                        json.dump(default_config, f, indent=4)
                    config_content = json.dumps(default_config, indent=4)
                    messages.append("Created default configuration file")
                except Exception as e:
                    err_messages.append(
                        f"Failed to create default config file: {str(e)}"
                    )

        except Exception as e:
            if swap_client.debug:
                swap_client.log.error(traceback.format_exc())
            err_messages.append(str(e))

    current_status = get_amm_status()
    logs = get_amm_logs()

    amm_count = get_amm_active_count(swap_client, amm_debug)
    if swap_client.debug and amm_debug:
        swap_client.log.info(f"AMM active count: {amm_count}")
        logs.append(
            f"AMM active count: {amm_count} (only counting offers that are currently active in the network)"
        )

    state_content = ""
    state_data = {}
    if state_exists:
        try:
            with open(state_path, "r") as f:
                state_content = f.read()
                state_data = json.loads(state_content)
        except Exception as e:
            err_messages.append(f"Failed to read state file: {str(e)}")

    coins = listAvailableCoins(swap_client)

    template = server.env.get_template("amm.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "err_messages": err_messages,
            "summary": summary,
            "amm_dir": amm_dir,
            "config_path": config_path,
            "state_path": state_path,
            "script_path": script_path,
            "config_exists": config_exists,
            "state_exists": state_exists,
            "script_exists": script_exists,
            "config_content": config_content,
            "config_data": config_data,
            "state_content": state_content,
            "state_data": state_data,
            "current_status": current_status,
            "logs": logs,
            "current_page": "amm",
            "amm_host": amm_host,
            "amm_port": amm_port,
            "amm_debug": amm_debug,
            "debug_ui_mode": swap_client.debug_ui,
            "coins": coins,
        },
    )


def amm_status_api(swap_client, _, params=None):
    """API endpoint to get AMM status"""
    status = get_amm_status()

    debug_enabled = False
    if params and "debug" in params:
        debug_enabled = params["debug"].lower() == "true"

    amm_count = get_amm_active_count(swap_client, debug_enabled)

    return {"status": status, "amm_active_count": amm_count}
