#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import traceback

import basicswap.config as cfg
from basicswap import __version__
from basicswap.basicswap import BasicSwap
from basicswap.chainparams import chainparams, Coins, isKnownCoinName
from basicswap.network.simplex_chat import startSimplexClient
from basicswap.ui.util import getCoinName
from basicswap.util.daemon import Daemon

initial_logger = logging.getLogger()
initial_logger.level = logging.DEBUG
if not len(initial_logger.handlers):
    initial_logger.addHandler(initial_logger.StreamHandler(sys.stdout))
logger = initial_logger

swap_client = None


def signal_handler(sig, frame):
    os.write(
        sys.stdout.fileno(), f"Signal {sig} detected, ending program.\n".encode("utf-8")
    )
    if swap_client is not None and not swap_client.chainstate_delay_event.is_set():
        try:
            from basicswap.ui.page_amm import stop_amm_process, get_amm_status

            amm_status = get_amm_status()
            if amm_status == "running":
                logger.info("Signal handler stopping AMM process...")
                success, msg = stop_amm_process(swap_client)
                if success:
                    logger.info(f"AMM signal shutdown: {msg}")
                else:
                    logger.warning(f"AMM signal shutdown warning: {msg}")
        except Exception as e:
            logger.error(f"Error stopping AMM in signal handler: {e}")

        swap_client.stopRunning()


def checkPARTZmqConfigBeforeStart(part_settings, swap_settings):
    try:
        datadir = part_settings.get("datadir")
        if not datadir:
            return

        config_path = os.path.join(datadir, "particl.conf")
        if not os.path.exists(config_path):
            return

        with open(config_path, "r") as f:
            config_content = f.read()

        zmq_host = swap_settings.get("zmqhost", "tcp://127.0.0.1")
        zmq_port = swap_settings.get("zmqport", 14792)
        expected_line = f"zmqpubhashwtx={zmq_host}:{zmq_port}"

        if "zmqpubhashwtx=" not in config_content:
            with open(config_path, "a") as f:
                f.write(f"{expected_line}\n")
        elif expected_line not in config_content:
            lines = config_content.split("\n")
            updated_lines = []
            for line in lines:
                if line.startswith("zmqpubhashwtx="):
                    updated_lines.append(expected_line)
                else:
                    updated_lines.append(line)

            with open(config_path, "w") as f:
                f.write("\n".join(updated_lines))

    except Exception as e:
        logger.debug(f"Error checking PART ZMQ config: {e}")


def startDaemon(node_dir, bin_dir, daemon_bin, opts=[], extra_config={}):
    daemon_bin = os.path.expanduser(os.path.join(bin_dir, daemon_bin))
    datadir_path = os.path.expanduser(node_dir)
    coin_name = extra_config.get("coin_name", "")

    # Rewrite litecoin.conf
    # TODO: Remove
    ltc_conf_path = os.path.join(datadir_path, "litecoin.conf")
    if os.path.exists(ltc_conf_path):
        needs_rewrite: bool = False
        add_changetype: bool = True
        with open(ltc_conf_path) as fp:
            for line in fp:
                line = line.strip()
                if line.startswith("changetype="):
                    add_changetype = False
                    break
                if line.endswith("=onion"):
                    needs_rewrite = True
                    break
        if needs_rewrite:
            logger.info("Rewriting litecoin.conf")
            shutil.copyfile(ltc_conf_path, ltc_conf_path + ".last")
            with (
                open(ltc_conf_path + ".last") as fp_from,
                open(ltc_conf_path, "w") as fp_to,
            ):
                for line in fp_from:
                    if line.strip().endswith("=onion"):
                        fp_to.write(line.strip()[:-6] + "\n")
                    else:
                        fp_to.write(line)
                if add_changetype:
                    fp_to.write("changetype=bech32\n")
                    add_changetype = False
        if add_changetype:
            logger.info("Adding changetype to litecoin.conf")
            with open(ltc_conf_path, "a") as fp:
                fp.write("changetype=bech32\n")

    # Rewrite bitcoin.conf
    # TODO: Remove
    btc_conf_path = os.path.join(datadir_path, "bitcoin.conf")
    if coin_name == "bitcoin" and os.path.exists(btc_conf_path):
        add_changetype: bool = True
        with open(btc_conf_path) as fp:
            for line in fp:
                line = line.strip()
                if line.startswith("changetype="):
                    add_changetype = False
                    break
        if add_changetype:
            logger.info("Adding changetype to bitcoin.conf")
            with open(btc_conf_path, "a") as fp:
                fp.write("changetype=bech32\n")

    args = [
        daemon_bin,
    ]
    add_datadir: bool = extra_config.get("add_datadir", True)
    if add_datadir:
        args.append("-datadir=" + datadir_path)
    args += opts
    logger.info(f"Starting node {daemon_bin}")
    logger.debug("Arguments {}".format(" ".join(args)))

    opened_files = []
    if extra_config.get("stdout_to_file", False):
        stdout_dest = open(
            os.path.join(
                datadir_path, extra_config.get("stdout_filename", "core_stdout.log")
            ),
            "w",
        )
        opened_files.append(stdout_dest)
        stderr_dest = stdout_dest
    else:
        stdout_dest = subprocess.PIPE
        stderr_dest = subprocess.PIPE

    shell: bool = False
    if extra_config.get("use_shell", False):
        args = " ".join(args)
        shell = True
    return Daemon(
        subprocess.Popen(
            args,
            shell=shell,
            stdin=subprocess.PIPE,
            stdout=stdout_dest,
            stderr=stderr_dest,
            cwd=datadir_path,
        ),
        opened_files,
        os.path.basename(daemon_bin),
    )


def startXmrDaemon(node_dir, bin_dir, daemon_bin, opts=[]):
    daemon_path = os.path.expanduser(os.path.join(bin_dir, daemon_bin))

    datadir_path = os.path.expanduser(node_dir)
    if daemon_bin.startswith("wow"):
        config_filename = "wownerod.conf"
    elif daemon_bin.startswith("sal"):
        config_filename = "salviumd.conf"
    else:
        config_filename = "monerod.conf"

    args = [
        daemon_path,
        "--non-interactive",
        "--config-file=" + os.path.join(datadir_path, config_filename),
    ] + opts
    logger.info(f"Starting node {daemon_bin}")
    logger.debug("Arguments {}".format(" ".join(args)))

    # return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    file_stdout = open(os.path.join(datadir_path, "core_stdout.log"), "w")
    file_stderr = open(os.path.join(datadir_path, "core_stderr.log"), "w")
    return Daemon(
        subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=file_stdout,
            stderr=file_stderr,
            cwd=datadir_path,
        ),
        [file_stdout, file_stderr],
        os.path.basename(daemon_bin),
    )


def startXmrWalletDaemon(node_dir, bin_dir, wallet_bin, opts=[]):
    daemon_path = os.path.expanduser(os.path.join(bin_dir, wallet_bin))
    args = [daemon_path, "--non-interactive"]

    needs_rewrite: bool = False
    config_to_remove = [
        "daemon-address=",
        "untrusted-daemon=",
        "trusted-daemon=",
        "proxy=",
    ]

    data_dir = os.path.expanduser(node_dir)

    if wallet_bin.startswith("wow"):
        wallet_config_filename = "wownero-wallet-rpc.conf"
    elif wallet_bin.startswith("sal"):
        wallet_config_filename = "salvium_wallet.conf"
    else:
        wallet_config_filename = "monero_wallet.conf"

    config_path = os.path.join(data_dir, wallet_config_filename)
    if os.path.exists(config_path):
        args += ["--config-file=" + config_path]
        with open(config_path) as fp:
            for line in fp:
                if any(
                    line.startswith(config_line) for config_line in config_to_remove
                ):
                    logger.warning(
                        "Found old config in monero_wallet.conf: {}".format(
                            line.strip()
                        )
                    )
                    needs_rewrite = True
    args += opts

    if needs_rewrite:
        logger.info("Rewriting wallet config")
        shutil.copyfile(config_path, config_path + ".last")
        with open(config_path + ".last") as fp_from, open(config_path, "w") as fp_to:
            for line in fp_from:
                if not any(
                    line.startswith(config_line) for config_line in config_to_remove
                ):
                    fp_to.write(line)

    logger.info(f"Starting wallet daemon {wallet_bin}")
    logger.debug("Arguments {}".format(" ".join(args)))

    # TODO: return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=data_dir)
    wallet_stdout = open(os.path.join(data_dir, "wallet_stdout.log"), "w")
    wallet_stderr = open(os.path.join(data_dir, "wallet_stderr.log"), "w")
    return Daemon(
        subprocess.Popen(
            args,
            stdin=subprocess.PIPE,
            stdout=wallet_stdout,
            stderr=wallet_stderr,
            cwd=data_dir,
        ),
        [wallet_stdout, wallet_stderr],
        os.path.basename(wallet_bin),
    )


def getCoreBinName(coin_id: int, coin_settings, default_name: str) -> str:
    return coin_settings.get(
        "core_binname", chainparams[coin_id].get("core_binname", default_name)
    ) + (".exe" if os.name == "nt" else "")


def getWalletBinName(coin_id: int, coin_settings, default_name: str) -> str:
    return coin_settings.get(
        "wallet_binname", chainparams[coin_id].get("wallet_binname", default_name)
    ) + (".exe" if os.name == "nt" else "")


def getCoreBinArgs(coin_id: int, coin_settings, prepare=False, use_tor_proxy=False):
    extra_args = []
    if "config_filename" in coin_settings:
        extra_args.append("--conf=" + coin_settings["config_filename"])
    if "port" in coin_settings and coin_id != Coins.BTC:
        if prepare is False and use_tor_proxy:
            if coin_id == Coins.BCH:
                # Without this BCH (27.1) will bind to the default BTC port, even with proxy set
                extra_args.append("--bind=127.0.0.1:" + str(int(coin_settings["port"])))
        else:
            extra_args.append("--port=" + str(int(coin_settings["port"])))

    # BTC versions from v28 fail to start if the onionport is in use.
    # As BCH may use port 8334, disable it here.
    # When tor is enabled a bind option for the onionport will be added to bitcoin.conf.
    # https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-28.0.md?plain=1#L84
    if (
        prepare is False
        and use_tor_proxy is False
        and coin_id in (Coins.BTC, Coins.NMC)
    ):
        port: int = coin_settings.get("port", 8333)
        extra_args.append(f"--bind=0.0.0.0:{port}")
    return extra_args


def mainLoop(daemons, update: bool = True):
    while not swap_client.delay_event.wait(0.5):
        if update:
            swap_client.update()
        else:
            pass

        for daemon in daemons:
            if daemon.running is False:
                continue
            poll = daemon.handle.poll()
            if poll is None:
                pass  # Process is running
            else:
                daemon.running = False
                swap_client.log.error(
                    f"Process {daemon.handle.pid} for {daemon.name} terminated unexpectedly returning {poll}."
                )


def runClient(
    data_dir: str,
    chain: str,
    start_only_coins: bool,
    log_prefix: str = "BasicSwap",
    extra_opts=dict(),
) -> int:
    global swap_client, logger
    daemons = []
    pids = []
    settings_path = os.path.join(data_dir, cfg.CONFIG_FILENAME)
    pids_path = os.path.join(data_dir, ".pids")

    if os.getenv("WALLET_ENCRYPTION_PWD", "") != "":
        if "decred" in start_only_coins:
            # Workaround for dcrwallet requiring password for initial startup
            logger.warning(
                "Allowing set WALLET_ENCRYPTION_PWD var with --startonlycoin=decred."
            )
        else:
            raise ValueError(
                "Please unset the WALLET_ENCRYPTION_PWD environment variable."
            )

    if not os.path.exists(settings_path):
        raise ValueError("Settings file not found: " + str(settings_path))

    with open(settings_path) as fs:
        settings = json.load(fs)

    swap_client = BasicSwap(
        data_dir, settings, chain, log_name=log_prefix, extra_opts=extra_opts
    )
    logger = swap_client.log

    if os.path.exists(pids_path):
        with open(pids_path) as fd:
            for ln in fd:
                # TODO: try close
                logger.warning("Found pid for daemon {}".format(ln.strip()))

    # Ensure daemons are stopped
    swap_client.stopDaemons()

    # Settings may have been modified
    settings = swap_client.settings

    try:
        # Try start daemons
        for network in settings.get("networks", []):
            if network.get("enabled", True) is False:
                continue
            network_type: str = network.get("type", "unknown")
            if network_type == "simplex":
                simplex_dir = os.path.join(data_dir, "simplex")

                log_level = "debug" if swap_client.debug else "info"

                socks_proxy = None
                if "socks_proxy_override" in network:
                    socks_proxy = network["socks_proxy_override"]
                elif swap_client.use_tor_proxy:
                    socks_proxy = (
                        f"{swap_client.tor_proxy_host}:{swap_client.tor_proxy_port}"
                    )

                daemons.append(
                    startSimplexClient(
                        network["client_path"],
                        simplex_dir,
                        network["server_address"],
                        network["ws_port"],
                        logger,
                        swap_client.delay_event,
                        socks_proxy=socks_proxy,
                        log_level=log_level,
                    )
                )
                pid = daemons[-1].handle.pid
                swap_client.log.info(f"Started Simplex client {pid}")

        for c, v in settings["chainclients"].items():
            if len(start_only_coins) > 0 and c not in start_only_coins:
                continue
            if (
                len(swap_client.with_coins_override) > 0
                and c not in swap_client.with_coins_override
            ) or c in swap_client.without_coins_override:
                if v.get("manage_daemon", False) or v.get(
                    "manage_wallet_daemon", False
                ):
                    logger.warning(
                        f"Not starting coin {c.capitalize()}, disabled by arguments."
                    )
                continue
            try:
                coin_id = swap_client.getCoinIdFromName(c)
                display_name = getCoinName(coin_id)
            except Exception as e:  # noqa: F841
                logger.warning(f"Not starting unknown coin: {c}")
                continue
            if c in ("monero", "salvium", "wownero"):
                if v["manage_daemon"] is True:
                    swap_client.log.info(f"Starting {display_name} daemon")
                    filename: str = getCoreBinName(coin_id, v, c + "d")

                    daemons.append(startXmrDaemon(v["datadir"], v["bindir"], filename))
                    pid = daemons[-1].handle.pid
                    swap_client.log.info(f"Started {filename} {pid}")

                if v["manage_wallet_daemon"] is True:
                    swap_client.log.info(f"Starting {display_name} wallet daemon")
                    daemon_addr = "{}:{}".format(v["rpchost"], v["rpcport"])
                    trusted_daemon: bool = swap_client.getXMRTrustedDaemon(
                        coin_id, v["rpchost"]
                    )
                    opts = [
                        "--daemon-address",
                        daemon_addr,
                    ]

                    proxy_log_str = ""
                    proxy_host, proxy_port = swap_client.getXMRWalletProxy(
                        coin_id, v["rpchost"]
                    )
                    if proxy_host:
                        proxy_log_str = " through proxy"
                        opts += [
                            "--proxy",
                            f"{proxy_host}:{proxy_port}",
                            "--daemon-ssl-allow-any-cert",
                        ]

                    swap_client.log.info(
                        "daemon-address: {} ({}){}".format(
                            daemon_addr,
                            "trusted" if trusted_daemon else "untrusted",
                            proxy_log_str,
                        )
                    )

                    daemon_rpcuser = v.get("rpcuser", "")
                    daemon_rpcpass = v.get("rpcpassword", "")
                    if daemon_rpcuser != "":
                        opts.append("--daemon-login")
                        opts.append(daemon_rpcuser + ":" + daemon_rpcpass)

                    opts.append(
                        "--trusted-daemon" if trusted_daemon else "--untrusted-daemon"
                    )
                    filename: str = getWalletBinName(coin_id, v, c + "-wallet-rpc")

                    daemons.append(
                        startXmrWalletDaemon(v["datadir"], v["bindir"], filename, opts)
                    )
                    pid = daemons[-1].handle.pid
                    swap_client.log.info(f"Started {filename} {pid}")

                continue  # /monero

            if c == "decred":
                appdata = v["datadir"]
                extra_opts = [
                    f'--appdata="{appdata}"',
                ]
                use_shell: bool = True if os.name == "nt" else False
                if v["manage_daemon"] is True:
                    swap_client.log.info(f"Starting {display_name} daemon")
                    filename: str = getCoreBinName(coin_id, v, "dcrd")

                    extra_config = {
                        "add_datadir": False,
                        "stdout_to_file": True,
                        "stdout_filename": "dcrd_stdout.log",
                        "use_shell": use_shell,
                        "coin_name": "decred",
                    }
                    daemons.append(
                        startDaemon(
                            appdata,
                            v["bindir"],
                            filename,
                            opts=extra_opts,
                            extra_config=extra_config,
                        )
                    )
                    pid = daemons[-1].handle.pid
                    swap_client.log.info(f"Started {filename} {pid}")

                if v["manage_wallet_daemon"] is True:
                    swap_client.log.info(f"Starting {display_name} wallet daemon")
                    filename: str = getWalletBinName(coin_id, v, "dcrwallet")

                    wallet_pwd = v["wallet_pwd"]
                    if wallet_pwd == "":
                        # Only set when in startonlycoin mode
                        wallet_pwd = os.getenv("WALLET_ENCRYPTION_PWD", "")
                    if wallet_pwd != "":
                        extra_opts.append(f'--pass="{wallet_pwd}"')
                    extra_config = {
                        "add_datadir": False,
                        "stdout_to_file": True,
                        "stdout_filename": "dcrwallet_stdout.log",
                        "use_shell": use_shell,
                        "coin_name": "decred",
                    }
                    daemons.append(
                        startDaemon(
                            appdata,
                            v["bindir"],
                            filename,
                            opts=extra_opts,
                            extra_config=extra_config,
                        )
                    )
                    pid = daemons[-1].handle.pid
                    swap_client.log.info(f"Started {filename} {pid}")

                continue  # /decred

            if v["manage_daemon"] is True:
                if c == "particl" and swap_client._zmq_queue_enabled:
                    checkPARTZmqConfigBeforeStart(v, swap_client.settings)

                swap_client.log.info(f"Starting {display_name} daemon")

                filename: str = getCoreBinName(coin_id, v, c + "d")
                extra_opts = getCoreBinArgs(
                    coin_id, v, use_tor_proxy=swap_client.use_tor_proxy
                )
                extra_config = {"coin_name": c}
                daemons.append(
                    startDaemon(
                        v["datadir"],
                        v["bindir"],
                        filename,
                        opts=extra_opts,
                        extra_config=extra_config,
                    )
                )
                pid = daemons[-1].handle.pid
                pids.append((c, pid))
                swap_client.setDaemonPID(c, pid)
                swap_client.log.info(f"Started {filename} {pid}")
        if len(pids) > 0:
            with open(pids_path, "w") as fd:
                for p in pids:
                    fd.write("{}:{}\n".format(*p))

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGHUP, signal_handler)

        if len(start_only_coins) > 0:
            logger.info(
                f"Only running {start_only_coins}. Manually exit with Ctrl + c when ready."
            )
            mainLoop(daemons, update=False)
        else:
            swap_client.start()

            logger.info("Exit with Ctrl + c.")
            mainLoop(daemons)

    except Exception as e:  # noqa: F841
        traceback.print_exc()

    if swap_client.ws_server:
        try:
            swap_client.log.info("Stopping websocket server.")
            swap_client.ws_server.shutdown_gracefully()
        except Exception as e:  # noqa: F841
            traceback.print_exc()

    swap_client.finalise()

    closed_pids = []
    for d in daemons:
        swap_client.log.info(f"Interrupting {d.name} {d.handle.pid}")
        try:
            d.handle.send_signal(
                signal.CTRL_C_EVENT if os.name == "nt" else signal.SIGINT
            )
        except Exception as e:
            swap_client.log.info(f"Interrupting {d.name} {d.handle.pid}, error {e}")
    for d in daemons:
        try:
            d.handle.wait(timeout=120)
            for fp in [d.handle.stdout, d.handle.stderr, d.handle.stdin] + d.files:
                if fp:
                    fp.close()
            closed_pids.append(d.handle.pid)
        except Exception as e:
            swap_client.log.error(f"Error: {e}")

    fail_code: int = swap_client.fail_code
    del swap_client

    if os.path.exists(pids_path):
        with open(pids_path) as fd:
            lines = fd.read().split("\n")
        still_running = ""
        for ln in lines:
            try:
                if int(ln.split(":")[1]) not in closed_pids:
                    still_running += ln + "\n"
            except Exception:
                pass
        with open(pids_path, "w") as fd:
            fd.write(still_running)

    return fail_code


def printVersion():
    logger.info(
        f"Basicswap version: {__version__}",
    )


def ensure_coin_valid(coin: str) -> bool:
    if isKnownCoinName(coin) is False:
        raise ValueError(f"Unknown coin: {coin}")


def printHelp():
    print("Usage: basicswap-run ")
    print("\n--help, -h               Print help.")
    print("--version, -v            Print version.")
    print(
        f"--datadir=PATH           Path to basicswap data directory, default:{cfg.BASICSWAP_DATADIR}."
    )
    print("--mainnet                Run in mainnet mode.")
    print("--testnet                Run in testnet mode.")
    print("--regtest                Run in regtest mode.")
    print("--withcoin=              Run only with coin/s.")
    print("--withoutcoin=           Run without coin/s.")
    print(
        "--startonlycoin          Only start the provides coin daemon/s, use this if a chain requires extra processing."
    )
    print("--logprefix              Specify log prefix.")
    print(
        "--forcedbupgrade         Recheck database against schema regardless of version."
    )


def main():
    data_dir = None
    chain = "mainnet"
    start_only_coins = set()
    log_prefix: str = "BasicSwap"
    options = dict()
    with_coins = set()
    without_coins = set()

    for v in sys.argv[1:]:
        if len(v) < 2 or v[0] != "-":
            logger.warning(f"Unknown argument {v}")
            continue

        s = v.split("=")
        name = s[0].strip()

        for i in range(2):
            if name[0] == "-":
                name = name[1:]

        if name == "v" or name == "version":
            printVersion()
            return 0
        if name == "h" or name == "help":
            printHelp()
            return 0

        if name in ("mainnet", "testnet", "regtest"):
            chain = name
            continue
        if name in ("withcoin", "withcoins"):
            for coin in [s.strip().lower() for s in s[1].split(",")]:
                ensure_coin_valid(coin)
                with_coins.add(coin)
            continue
        if name in ("withoutcoin", "withoutcoins"):
            for coin in [s.strip().lower() for s in s[1].split(",")]:
                if coin == "particl":
                    raise ValueError("Particl is required.")
                ensure_coin_valid(coin)
                without_coins.add(coin)
            continue
        if name == "forcedbupgrade":
            options["force_db_upgrade"] = True
            continue
        if len(s) == 2:
            if name == "datadir":
                data_dir = os.path.abspath(os.path.expanduser(s[1]))
                continue
            if name == "logprefix":
                log_prefix = s[1]
                continue
        if name == "startonlycoin":
            for coin in [s.lower() for s in s[1].split(",")]:
                ensure_coin_valid(coin)
                start_only_coins.add(coin)
            continue

        logger.warning(f"Unknown argument {v}")

    if os.name == "nt":
        logger.warning(
            "Running on windows is discouraged and windows support may be discontinued in the future.  Please consider using the WSL docker setup instead."
        )

    if data_dir is None:
        data_dir = os.path.join(os.path.expanduser(cfg.BASICSWAP_DATADIR))
    logger.info(f"Using datadir: {data_dir}")
    logger.info(f"Chain: {chain}")

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    if len(with_coins) > 0:
        with_coins.add("particl")
        options["with_coins"] = with_coins
    if len(without_coins) > 0:
        options["without_coins"] = without_coins

    logger.info(os.path.basename(sys.argv[0]) + ", version: " + __version__ + "\n\n")
    fail_code = runClient(data_dir, chain, start_only_coins, log_prefix, options)

    print("Done.")
    return fail_code


if __name__ == "__main__":
    main()
