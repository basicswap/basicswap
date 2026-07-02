# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Copyright (c) 2024-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import json
import logging
import os
import subprocess
import sys
import threading
import urllib
from urllib.request import urlopen
from basicswap.util import toBool as make_boolean  # noqa: F401


def _tee_stream(src, dst, buf):
    # Drain a subprocess pipe, echoing each line to dst and accumulating it.
    for line in src:
        dst.write(line)
        dst.flush()
        buf.append(line)


def run_prepare_subprocess(args, env=None, expect_code: int = 0, timeout: int = 600):
    # Run basicswap-prepare in a subprocess so its import-time env reads are
    # always fresh, regardless of what has imported the module in-process.
    # args: without the program name (argv[1:] equivalent).
    # stdout/stderr are streamed to the caller's console (tee) while also being
    # captured, so the returned CompletedProcess keeps them as separate strings.
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "basicswap.bin.prepare"] + args,
        env=os.environ.copy() if env is None else env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out_buf, err_buf = [], []
    t_out = threading.Thread(
        target=_tee_stream, args=(proc.stdout, sys.stdout, out_buf)
    )
    t_err = threading.Thread(
        target=_tee_stream, args=(proc.stderr, sys.stderr, err_buf)
    )
    t_out.start()
    t_err.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise
    finally:
        t_out.join()
        t_err.join()
        proc.stdout.close()
        proc.stderr.close()

    result = subprocess.CompletedProcess(
        proc.args, proc.returncode, "".join(out_buf), "".join(err_buf)
    )
    if result.returncode != expect_code:
        raise RuntimeError(
            f"basicswap-prepare exited {result.returncode}, expected {expect_code}:\n"
            + result.stderr
        )
    return result


PORT_OFS = int(os.getenv("PORT_OFS", 1))
UI_PORT = 12700 + PORT_OFS

REQUIRED_SETTINGS = {
    "blocks_confirmed": 1,
    "conf_target": 1,
    "use_segwit": True,
    "connection_type": "rpc",
}


def post_json_req(url, json_data):
    req = urllib.request.Request(url)
    req.add_header("Content-Type", "application/json; charset=utf-8")
    post_bytes = json.dumps(json_data).encode("utf-8")
    req.add_header("Content-Length", len(post_bytes))
    return urlopen(req, post_bytes, timeout=300).read()


def read_text_api(port, path=None):
    url = f"http://127.0.0.1:{port}/json"
    if path is not None:
        url += "/" + path
    return urlopen(url, timeout=300).read().decode("utf-8")


def read_json_api(port, path=None, json_data=None):
    url = f"http://127.0.0.1:{port}/json"
    if path is not None:
        url += "/" + path

    if json_data is not None:
        return json.loads(post_json_req(url, json_data))
    return json.loads(urlopen(url, timeout=300).read())


def post_json_api(port, path, json_data):
    url = f"http://127.0.0.1:{port}/json"
    if path is not None:
        url += "/" + path
    return json.loads(post_json_req(url, json_data))


def waitForServer(delay_event, port, wait_for=40):
    for i in range(wait_for):
        if delay_event.is_set():
            raise ValueError("Test stopped.")
        try:
            delay_event.wait(1.0)
            _ = read_json_api(port)
            return
        except Exception as e:
            logging.error(f"waitForServer: {e}")
    raise ValueError("waitForServer failed")


def wait_for_offers(delay_event, node_id, num_offers, offer_id=None) -> None:
    logging.info(f"Waiting for {num_offers} offers on node {node_id}")
    for i in range(20):
        delay_event.wait(1)
        offers = read_json_api(
            UI_PORT + node_id, "offers" if offer_id is None else f"offers/{offer_id}"
        )
        if len(offers) >= num_offers:
            return
    raise ValueError("wait_for_offers failed")
