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
from .util import listAvailableCoinsWithBalances

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
amm_ui_debug = False


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


def get_amm_script_path(swap_client):
    """Get the path to the AMM script"""
    return os.path.join(swap_client.data_dir, "basicswap", "scripts", "createoffers.py")


def log_capture_thread(process, swap_client):
    """Thread to capture and store logs from the AMM process"""
    global amm_status

    while process.poll() is None:
        try:
            line = process.stdout.readline()
            if not line:
                break

            line_str = (
                line.rstrip()
                if isinstance(line, str)
                else line.decode("utf-8", errors="replace").rstrip()
            )

            with amm_log_lock:
                amm_log_buffer.append(line_str)
                if len(amm_log_buffer) > 1000:
                    amm_log_buffer.pop(0)

            debug_enabled = globals().get("amm_debug", False) or globals().get(
                "amm_ui_debug", False
            )

            always_show = any(
                important in line_str
                for important in [
                    "Error:",
                    "Failed to",
                    "New offer created",
                    "New bid created",
                    "Revoking offer",
                    "AMM process",
                    "Offer revoked",
                    "Server failed",
                    "Created default configuration",
                    "API connection successful",
                    "Done.",
                ]
            )

            debug_messages = debug_enabled and not any(
                spam in line_str.lower()
                for spam in [
                    "processing 0 offer template",
                    "processing 0 bid template",
                    "looping indefinitely",
                ]
            )

            if always_show or debug_messages:
                if debug_enabled and any(
                    spam in line_str.lower()
                    for spam in [
                        "processing 0 offer template",
                        "processing 0 bid template",
                    ]
                ):
                    pass
                else:
                    swap_client.log.info(f"AMM: {line_str}")
        except Exception as e:
            swap_client.log.error(f"Error capturing AMM log: {str(e)}")

    with amm_log_lock:
        amm_status = "stopped"
        amm_log_buffer.append("AMM process has stopped.")
        swap_client.log.info("AMM process has stopped.")


def check_existing_amm_processes():
    """Check for existing AMM processes and return their PIDs"""
    import subprocess

    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=10
        )

        existing_pids = []
        for line in result.stdout.split("\n"):
            if (
                (
                    "basicswap.amm.createoffers" in line
                    or "scripts/createoffers.py" in line
                    or "createoffers.py" in line
                )
                and "grep" not in line
                and "python" in line
            ):
                parts = line.split()
                if len(parts) > 1:
                    try:
                        pid = int(parts[1])
                        existing_pids.append(pid)
                    except (ValueError, IndexError):
                        continue

        return existing_pids
    except Exception as e:
        print(f"Error checking for existing AMM processes: {e}")
        return []


def kill_existing_amm_processes(swap_client):
    """Kill any existing AMM processes"""
    existing_pids = check_existing_amm_processes()

    if not existing_pids:
        return True, "No existing AMM processes found"

    killed_pids = []
    failed_pids = []

    for pid in existing_pids:
        try:
            import os
            import signal

            os.kill(pid, signal.SIGTERM)

            import time

            time.sleep(1)

            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
                swap_client.log.warning(f"Force killed AMM process {pid}")
            except ProcessLookupError:
                pass

            killed_pids.append(pid)
            swap_client.log.info(f"Terminated existing AMM process {pid}")

        except ProcessLookupError:
            killed_pids.append(pid)
        except PermissionError:
            failed_pids.append(pid)
            swap_client.log.error(f"Permission denied killing AMM process {pid}")
        except Exception as e:
            failed_pids.append(pid)
            swap_client.log.error(f"Failed to kill AMM process {pid}: {e}")

    if failed_pids:
        return (
            False,
            f"Failed to kill processes: {failed_pids}. You may need to kill them manually with: sudo kill -9 {' '.join(map(str, failed_pids))}",
        )

    if killed_pids:
        return (
            True,
            f"Terminated {len(killed_pids)} existing AMM process(es): {killed_pids}",
        )

    return True, "No AMM processes needed termination"


def start_amm_process(
    swap_client, host, port, config_file=None, state_file=None, debug=False
):
    """Start the AMM process with proper duplicate prevention"""
    global amm_process, amm_log_buffer, amm_status, amm_config_file, amm_state_file, amm_debug

    amm_debug = debug

    existing_pids = check_existing_amm_processes()
    if existing_pids:
        return (
            False,
            f"AMM processes already running with PIDs: {existing_pids}. Please stop them first or use the 'Force Start' option.",
        )

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
            "min_seconds_between_offers": 15,
            "max_seconds_between_offers": 60,
            "main_loop_delay": 60,
            "offers": [],
            "bids": [],
        }

        if swap_client.debug:
            default_config["prune_state_delay"] = 120
            default_config["prune_state_after_seconds"] = 604800
            default_config["min_seconds_between_bids"] = 15
            default_config["max_seconds_between_bids"] = 60

        with open(config_path, "w") as f:
            json.dump(default_config, f, indent=4)

    script_path = get_amm_script_path(swap_client)
    cmd = [
        sys.executable,
        script_path,
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
            universal_newlines=True,
            bufsize=1,
            env=dict(os.environ, PYTHONUNBUFFERED="1"),
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


def start_amm_process_force(
    swap_client, host, port, config_file=None, state_file=None, debug=False
):
    """Force start AMM process by killing existing ones first"""
    kill_success, kill_msg = kill_existing_amm_processes(swap_client)

    if not kill_success:
        return False, f"Failed to kill existing processes: {kill_msg}"

    import time

    time.sleep(2)

    return start_amm_process(swap_client, host, port, config_file, state_file, debug)


def stop_amm_process(swap_client=None):
    """Stop the AMM process and any orphaned processes"""
    global amm_status, amm_process

    stopped_processes = []
    errors = []

    if amm_process is not None and amm_process.poll() is None:
        try:
            amm_process.terminate()

            for _ in range(30):
                if amm_process.poll() is not None:
                    break
                time.sleep(0.1)

            if amm_process.poll() is None:
                amm_process.kill()
                amm_process.wait(timeout=5)

            stopped_processes.append(f"Main AMM process (PID: {amm_process.pid})")

        except Exception as e:
            errors.append(f"Failed to stop main AMM process: {str(e)}")

    if swap_client:
        try:
            kill_success, kill_msg = kill_existing_amm_processes(swap_client)
            if kill_success and "Terminated" in kill_msg:
                stopped_processes.append("Orphaned AMM processes")
            elif not kill_success:
                errors.append(kill_msg)
        except Exception as e:
            errors.append(f"Failed to check for orphaned processes: {str(e)}")

    with amm_log_lock:
        amm_status = "stopped"
        if stopped_processes:
            amm_log_buffer.append(f"Stopped: {', '.join(stopped_processes)}")
        if errors:
            amm_log_buffer.append(f"Errors: {', '.join(errors)}")

    amm_process = None

    if errors:
        return False, f"Stopped with errors: {'; '.join(errors)}"
    elif stopped_processes:
        return True, f"Successfully stopped: {', '.join(stopped_processes)}"
    else:
        return True, "No AMM processes were running"


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

    debug_enabled = debug_override and (
        swap_client.debug
        or globals().get("amm_ui_debug", False)
        or globals().get("amm_debug", False)
    )

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

    config_path = get_amm_config_path(swap_client)
    enabled_offers = set()
    enabled_bids = set()

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                config_data = json.load(f)

            for offer in config_data.get("offers", []):
                if offer.get("enabled", False):
                    enabled_offers.add(offer.get("name", ""))

            for bid in config_data.get("bids", []):
                if bid.get("enabled", False):
                    enabled_bids.add(bid.get("name", ""))

            if debug_enabled:
                swap_client.log.info(
                    f"Enabled templates: {len(enabled_offers)} offers, {len(enabled_bids)} bids"
                )

        except Exception as e:
            if debug_enabled:
                swap_client.log.error(f"Error reading config file: {str(e)}")
            enabled_offers = None
            enabled_bids = None

    state_data = {}
    active_network_offers = {}

    try:
        with open(state_path, "r") as f:
            state_data = json.load(f)

        if debug_enabled:
            swap_client.log.debug(
                f"AMM state data loaded with {len(state_data.get('offers', {}))} offer templates"
            )

        try:
            network_offers = swap_client.listOffers()

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
                swap_client.log.debug(
                    f"Found {len(active_network_offers)} active offers in the network"
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

            except Exception as e:
                if debug_enabled:
                    swap_client.log.error(f"Error getting offers via API: {str(e)}")
                    swap_client.log.error(traceback.format_exc())

        if "offers" in state_data:
            for template_name, offers in state_data["offers"].items():
                if enabled_offers is None or template_name in enabled_offers:
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
                        enabled_status = (
                            "enabled"
                            if enabled_offers is None or template_name in enabled_offers
                            else "disabled"
                        )
                        if debug_enabled:
                            swap_client.log.debug(
                                f"Template '{template_name}' ({enabled_status}): {active_offer_count} active out of {total_offers} total offers"
                            )
                elif debug_enabled:
                    swap_client.log.debug(
                        f"Template '{template_name}' is disabled, skipping {len(offers)} offers"
                    )

        if "bids" in state_data:
            for template_name, bids in state_data["bids"].items():
                if enabled_bids is None or template_name in enabled_bids:
                    active_bid_count = 0
                    for bid in bids:
                        if "bid_id" in bid and bid.get("active", False):
                            active_bid_count += 1

                    amm_count += active_bid_count
                    if debug_enabled:
                        total_bids = len(bids)
                        enabled_status = (
                            "enabled"
                            if enabled_bids is None or template_name in enabled_bids
                            else "disabled"
                        )

                        if debug_enabled:
                            swap_client.log.debug(
                                f"Template '{template_name}' ({enabled_status}): {active_bid_count} active out of {total_bids} total bids"
                            )
                elif debug_enabled:
                    swap_client.log.debug(
                        f"Template '{template_name}' is disabled, skipping {len(bids)} bids"
                    )

        if debug_enabled:
            swap_client.log.debug(f"Total active AMM count: {amm_count}")

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
        swap_client.log.debug(f"Final AMM active count: {amm_count}")

    return amm_count


def page_amm(self, _, post_string):
    """Render the AMM page"""
    global amm_host, amm_port, amm_debug, amm_ui_debug

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

    script_path = get_amm_script_path(swap_client)
    script_exists = os.path.exists(script_path)

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
            "min_seconds_between_offers": 15,
            "max_seconds_between_offers": 60,
            "main_loop_delay": 60,
            "offers": [
                {
                    "id": "offer1234",
                    "name": "Example Offer",
                    "enabled": False,
                    "coin_from": "PART",
                    "coin_to": "BTC",
                    "amount": 1.0,
                    "minrate": 0.0001,
                    "ratetweakpercent": 0,
                    "adjust_rates_based_on_market": True,
                    "amount_variable": True,
                    "amount_step": 0.001,
                    "address": "auto",
                    "min_coin_from_amt": 0,
                    "offer_valid_seconds": 3600,
                }
            ],
            "bids": [],
        }

        if swap_client.debug:
            default_config["prune_state_delay"] = 120
            default_config["prune_state_after_seconds"] = 604800
            default_config["min_seconds_between_bids"] = 15
            default_config["max_seconds_between_bids"] = 60

            default_config["bids"] = [
                {
                    "id": "bid5678",
                    "name": "Example Bid",
                    "enabled": False,
                    "coin_from": "BTC",
                    "coin_to": "PART",
                    "amount": 0.001,
                    "max_rate": 10000.0,
                    "min_coin_to_balance": 1.0,
                    "max_concurrent": 1,
                    "amount_variable": True,
                    "address": "auto",
                    "offers_to_bid_on": "auto_accept_only",
                    "min_swap_amount": 0.001,
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
                amm_ui_debug = "debug" in form_data
                amm_debug = amm_ui_debug

                success, msg = start_amm_process(
                    swap_client, amm_host, amm_port, debug=amm_debug
                )
                if success:
                    messages.append(msg)
                else:
                    err_messages.append(msg)

            elif "force_start" in form_data:
                amm_host = form_data.get("host", ["127.0.0.1"])[0]
                amm_port = int(form_data.get("port", ["12700"])[0])
                amm_ui_debug = "debug" in form_data
                amm_debug = amm_ui_debug

                success, msg = start_amm_process_force(
                    swap_client, amm_host, amm_port, debug=amm_debug
                )
                if success:
                    messages.append(f"Force started: {msg}")
                else:
                    err_messages.append(f"Force start failed: {msg}")

            elif "stop" in form_data:
                success, msg = stop_amm_process(swap_client)
                if success:
                    messages.append(msg)
                else:
                    err_messages.append(msg)

            elif "check_processes" in form_data:
                existing_pids = check_existing_amm_processes()
                if existing_pids:
                    messages.append(f"Found existing AMM processes: {existing_pids}")
                else:
                    messages.append("No existing AMM processes found")

            elif "kill_orphans" in form_data:
                success, msg = kill_existing_amm_processes(swap_client)
                if success:
                    messages.append(msg)
                else:
                    err_messages.append(msg)

            is_control_action = (
                "save_global_settings" not in form_data
                and "add_offer" not in form_data
                and "add_bid" not in form_data
                and "save_config" not in form_data
                and "create_default" not in form_data
                and "prune_state" not in form_data
            )

            if is_control_action:
                if "autostart" in form_data:
                    swap_client.settings["amm_autostart"] = True
                    swap_client.log.info("AMM autostart enabled")
                    messages.append("AMM autostart enabled")
                    try:
                        import shutil
                        from basicswap import config as cfg

                        settings_path = os.path.join(
                            swap_client.data_dir, cfg.CONFIG_FILENAME
                        )
                        settings_path_new = settings_path + ".new"
                        shutil.copyfile(settings_path, settings_path + ".last")
                        with open(settings_path_new, "w") as fp:
                            json.dump(swap_client.settings, fp, indent=4)
                        shutil.move(settings_path_new, settings_path)
                        swap_client.log.info(
                            "AMM autostart setting saved to basicswap.json"
                        )
                    except Exception as e:
                        swap_client.log.error(
                            f"Failed to save autostart setting: {str(e)}"
                        )
                        err_messages.append(
                            f"Failed to save autostart setting: {str(e)}"
                        )
                else:
                    if "amm_autostart" in swap_client.settings:
                        del swap_client.settings["amm_autostart"]
                        swap_client.log.info("AMM autostart disabled")
                        messages.append("AMM autostart disabled")
                        try:
                            import shutil
                            from basicswap import config as cfg

                            settings_path = os.path.join(
                                swap_client.data_dir, cfg.CONFIG_FILENAME
                            )
                            settings_path_new = settings_path + ".new"
                            shutil.copyfile(settings_path, settings_path + ".last")
                            with open(settings_path_new, "w") as fp:
                                json.dump(swap_client.settings, fp, indent=4)
                            shutil.move(settings_path_new, settings_path)
                            swap_client.log.info(
                                "AMM autostart setting removed from basicswap.json"
                            )
                        except Exception as e:
                            swap_client.log.error(
                                f"Failed to save autostart setting: {str(e)}"
                            )
                            err_messages.append(
                                f"Failed to save autostart setting: {str(e)}"
                            )

            if "save_global_settings" in form_data:
                try:
                    with open(config_path, "r") as f:
                        current_config = json.load(f)

                    if "min_seconds_between_offers" in form_data:
                        try:
                            current_config["min_seconds_between_offers"] = int(
                                form_data.get("min_seconds_between_offers", ["15"])[0]
                                or "15"
                            )
                        except ValueError:
                            pass

                    if "max_seconds_between_offers" in form_data:
                        try:
                            current_config["max_seconds_between_offers"] = int(
                                form_data.get("max_seconds_between_offers", ["60"])[0]
                                or "60"
                            )
                        except ValueError:
                            pass

                    if "main_loop_delay" in form_data:
                        try:
                            current_config["main_loop_delay"] = int(
                                form_data.get("main_loop_delay", ["60"])[0] or "60"
                            )
                        except ValueError:
                            pass

                    if "auth" in form_data:
                        current_config["auth"] = form_data.get("auth", [""])[0]

                    if swap_client.debug_ui:
                        if "min_seconds_between_bids" in form_data:
                            try:
                                current_config["min_seconds_between_bids"] = int(
                                    form_data.get("min_seconds_between_bids", ["15"])[0]
                                    or "15"
                                )
                            except ValueError:
                                pass

                        if "max_seconds_between_bids" in form_data:
                            try:
                                current_config["max_seconds_between_bids"] = int(
                                    form_data.get("max_seconds_between_bids", ["60"])[0]
                                    or "60"
                                )
                            except ValueError:
                                pass

                        if "prune_state_delay" in form_data:
                            try:
                                current_config["prune_state_delay"] = int(
                                    form_data.get("prune_state_delay", ["120"])[0]
                                    or "120"
                                )
                            except ValueError:
                                pass

                        if "prune_state_after_seconds" in form_data:
                            try:
                                current_config["prune_state_after_seconds"] = int(
                                    form_data.get(
                                        "prune_state_after_seconds", ["604800"]
                                    )[0]
                                    or "604800"
                                )
                            except ValueError:
                                pass

                    with open(config_path, "w") as f:
                        json.dump(current_config, f, indent=4)

                    config_content = json.dumps(current_config, indent=4)
                    config_data = current_config

                    messages.append("Global settings saved successfully")
                except Exception as e:
                    err_messages.append(f"Failed to save global settings: {str(e)}")

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

                    if form_data.get("bid_use_balance_bidding", [""])[0]:
                        new_bid["use_balance_bidding"] = True

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
                    err_messages.append(
                        "Debug UI mode must be enabled to clear the AMM state file"
                    )

            elif "create_default" in form_data:
                # Create default config with all available options
                include_bids = "include_bids" in form_data and swap_client.debug

                default_config = {
                    # General settings
                    "min_seconds_between_offers": 15,  # Minimum delay between creating offers
                    "max_seconds_between_offers": 60,  # Maximum delay between creating offers
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
                            "amount": 1.0,  # Amount to create the offer for
                            "minrate": 0.0001,  # Rate below which the offer won't drop
                            "ratetweakpercent": 0,  # Modify the offer rate from the fetched value (can be negative)
                            "adjust_rates_based_on_market": False,  # Whether to adjust rates based on existing market offers
                            "amount_variable": True,  # Whether bidder can set a different amount
                            "amount_step": 0.001,  # Offer size increment (privacy/offer management feature)
                            "address": "auto",  # Address offer is sent from (auto = generate new address per offer)
                            "min_coin_from_amt": 0,  # Won't generate offers if wallet balance would drop below this
                            "offer_valid_seconds": 3600,  # How long generated offers will be valid for
                            "automation_strategy": "accept_all",  # Auto accept bids: "accept_all", "accept_known", or "none"
                            # Optional settings
                            "swap_type": "adaptor_sig",  # Type of swap, defaults to "adaptor_sig"
                            "min_swap_amount": 0.001,  # Minimum purchase quantity when offer amount is variable
                        }
                    ],
                    "bids": [],  # Empty by default
                }

                if swap_client.debug:
                    default_config["prune_state_delay"] = (
                        120  # Seconds between pruning old state data (0 to disable)
                    )
                    default_config["prune_state_after_seconds"] = (
                        604800  # How long to keep old state data (7 days)
                    )
                    default_config["min_seconds_between_bids"] = (
                        15  # Minimum delay between creating bids
                    )
                    default_config["max_seconds_between_bids"] = (
                        60  # Maximum delay between creating bids
                    )

                if include_bids:
                    default_config["bids"] = [
                        {
                            # Required settings
                            "id": "bid5678",  # Unique identifier for this bid
                            "name": "Example Bid",  # Template name, must be unique
                            "enabled": False,  # Set to true to enable this bid
                            "coin_from": "Monero",  # Coin you receive
                            "coin_to": "Particl",  # Coin you send
                            "amount": 0.001,  # Amount to bid
                            "max_rate": 10000.0,  # Maximum rate for bids
                            "min_coin_to_balance": 1.0,  # Won't send bids if wallet amount would drop below this
                            "offers_to_bid_on": "auto_accept_only",  # Which offers to bid on: "all", "auto_accept_only", or "known_only"
                            # Optional settings
                            "max_concurrent": 1,  # Maximum number of bids to have active at once
                            "amount_variable": True,  # Can send bids below the set amount where possible
                            # "max_coin_from_balance": 100.0,  # Won't send bids if wallet amount would be above this
                            "address": "auto",  # Address bid is sent from (auto = generate new address per bid)
                            "min_swap_amount": 0.001,  # Minimum swap amount
                            # "use_balance_bidding": False,  # Calculate bid amount as (wallet_balance - offer_min_amount) instead of using template amount
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

    amm_count = get_amm_active_count(swap_client, amm_ui_debug)

    if amm_ui_debug and post_string:
        swap_client.log.debug(f"AMM active count: {amm_count}")
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

    coins = listAvailableCoinsWithBalances(swap_client)

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
            "amm_debug": amm_ui_debug,
            "amm_autostart": swap_client.settings.get("amm_autostart", False),
            "debug_ui_mode": swap_client.debug_ui,
            "coins": coins,
        },
    )


def amm_autostart_api(swap_client, post_string, params=None):
    """API endpoint to save AMM autostart setting"""
    try:
        if post_string:
            if isinstance(post_string, bytes):
                post_string_decoded = post_string.decode("utf-8")
            else:
                post_string_decoded = post_string

            post_data = parse.parse_qs(post_string_decoded)
            autostart_value = post_data.get("autostart", ["false"])[0]
            autostart = autostart_value.lower() == "true"
        else:
            autostart_value = params.get("autostart", "false") if params else "false"
            autostart = autostart_value.lower() == "true"

        if autostart:
            swap_client.settings["amm_autostart"] = True
            swap_client.log.info("AMM autostart enabled via API")
        else:
            if "amm_autostart" in swap_client.settings:
                del swap_client.settings["amm_autostart"]
            swap_client.log.info("AMM autostart disabled via API")

        try:
            import shutil
            from basicswap import config as cfg

            settings_path = os.path.join(swap_client.data_dir, cfg.CONFIG_FILENAME)
            settings_path_new = settings_path + ".new"
            shutil.copyfile(settings_path, settings_path + ".last")
            with open(settings_path_new, "w") as fp:
                json.dump(swap_client.settings, fp, indent=4)
            shutil.move(settings_path_new, settings_path)

            return {
                "success": True,
                "autostart": autostart,
                "message": f"Autostart {'enabled' if autostart else 'disabled'}",
            }
        except Exception as e:
            swap_client.log.error(f"Failed to save autostart setting via API: {str(e)}")
            return {"success": False, "error": f"Failed to save setting: {str(e)}"}

    except Exception as e:
        swap_client.log.error(f"AMM autostart API error: {str(e)}")
        return {"success": False, "error": str(e)}


def amm_debug_api(swap_client, post_string, params=None):
    """API endpoint to save AMM debug setting"""
    try:
        if post_string:
            post_data = parse.parse_qs(post_string)
            debug_enabled = post_data.get("debug", ["false"])[0].lower() == "true"
        else:
            debug_enabled = (
                params.get("debug", "false").lower() == "true" if params else False
            )

        global amm_ui_debug
        amm_ui_debug = debug_enabled
        swap_client.log.info(
            f"AMM UI debug {'enabled' if debug_enabled else 'disabled'} via API"
        )

        return {
            "success": True,
            "debug": debug_enabled,
            "message": f"Debug {'enabled' if debug_enabled else 'disabled'}",
        }

    except Exception as e:
        swap_client.log.error(f"AMM debug API error: {str(e)}")
        return {"success": False, "error": str(e)}


def amm_status_api(swap_client, _, params=None):
    """API endpoint to get AMM status"""
    status = get_amm_status()

    debug_enabled = False
    if params and "debug" in params:
        debug_enabled = params["debug"].lower() == "true"

    amm_count = get_amm_active_count(swap_client, debug_enabled)

    return {"status": status, "amm_active_count": amm_count}
