#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import select
import sqlite3
import subprocess
import time

from basicswap.util.daemon import Daemon


def serverExistsInDatabase(simplex_db_path: str, server_address: str, logger) -> bool:
    try:
        # Extract hostname from SMP URL format: smp://fingerprint@hostname
        if server_address.startswith("smp://") and "@" in server_address:
            host = server_address.split("@")[-1]
        elif ":" in server_address:
            host = server_address.split(":", 1)[0]
        else:
            host = server_address

        with sqlite3.connect(simplex_db_path) as con:
            c = con.cursor()

            # Check for any server entry with this hostname
            query = (
                "SELECT COUNT(*) FROM protocol_servers WHERE host LIKE ? OR host = ?"
            )
            host_pattern = f"%{host}%"
            count = c.execute(query, (host_pattern, host)).fetchone()[0]

            if count > 0:
                logger.debug(
                    f"Server {host} already exists in database ({count} entries)"
                )
                return True
            else:
                logger.debug(f"Server {host} not found in database")
                return False

    except Exception as e:
        logger.error(f"Database check failed: {e}")
        return False


def initSimplexClient(args, logger, delay_event):
    # Need to set initial profile through CLI
    # TODO: Must be a better way?
    logger.info("Initialising Simplex client")

    (pipe_r, pipe_w) = os.pipe()  # subprocess.PIPE is buffered, blocks when read

    if os.name == "nt":
        str_args = " ".join(args)
        p = subprocess.Popen(
            str_args, shell=True, stdin=subprocess.PIPE, stdout=pipe_w, stderr=pipe_w
        )
    else:
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=pipe_w, stderr=pipe_w)

    def readOutput():
        buf = os.read(pipe_r, 1024).decode("utf-8")
        response = None
        # logger.debug(f"simplex-chat output: {buf}")
        if "display name:" in buf:
            logger.debug("Setting display name")
            response = b"user\n"
        else:
            logger.debug(f"Unexpected output: {buf}")
            return
        if response is not None:
            p.stdin.write(response)
            p.stdin.flush()

    try:
        start_time: int = time.time()
        max_wait_seconds: int = 60
        while p.poll() is None:
            if time.time() > start_time + max_wait_seconds:
                raise RuntimeError("Timed out")
            if os.name == "nt":
                readOutput()
                delay_event.wait(0.1)
                continue
            while len(select.select([pipe_r], [], [], 0)[0]) == 1:
                readOutput()
                delay_event.wait(0.1)
    except Exception as e:
        logger.error(f"initSimplexClient: {e}")
    finally:
        if p.poll() is None:
            p.terminate()
        os.close(pipe_r)
        os.close(pipe_w)
        p.stdin.close()


def startSimplexClient(
    bin_path: str,
    data_path: str,
    server_address: str,
    websocket_port: int,
    logger,
    delay_event,
    socks_proxy=None,
    log_level: str = "debug",
) -> Daemon:
    logger.info("Starting Simplex client")
    if not os.path.exists(data_path):
        os.makedirs(data_path)

    simplex_data_prefix = os.path.join(data_path, "simplex_client_data")
    simplex_db_path = simplex_data_prefix + "_chat.db"
    args = [bin_path, "-d", simplex_data_prefix, "-p", str(websocket_port)]

    if socks_proxy:
        args += ["--socks-proxy", socks_proxy]

    if not os.path.exists(simplex_db_path):
        # Database doesn't exist - safe to add server during initialization
        logger.info("Database not found, initializing Simplex client")
        init_args = args + ["-e", "/help"]  # Run command to exit client
        init_args += ["-s", server_address]
        initSimplexClient(init_args, logger, delay_event)
    else:
        # Database exists - only add server if it's not already there
        if not serverExistsInDatabase(simplex_db_path, server_address, logger):
            logger.debug(f"Adding server to Simplex CLI args: {server_address}")
            args += ["-s", server_address]
        else:
            logger.debug("Server already exists, not adding to CLI args")

    args += ["-l", log_level]

    opened_files = []
    stdout_dest = open(
        os.path.join(data_path, "simplex_stdout.log"),
        "w",
    )
    opened_files.append(stdout_dest)
    stderr_dest = stdout_dest
    return Daemon(
        subprocess.Popen(
            args,
            shell=False,
            stdin=subprocess.PIPE,
            stdout=stdout_dest,
            stderr=stderr_dest,
            cwd=data_path,
        ),
        opened_files,
        "simplex-chat",
    )
