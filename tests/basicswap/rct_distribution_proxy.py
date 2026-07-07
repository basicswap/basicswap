#!/usr/bin/env python3
"""On-the-wire RingCT-distribution fix for the ZEPH regtest tests.

A stock zephyr-wallet-rpc hardcodes the RingCT output-distribution query to start at the mainnet
AUDIT_FORK_HEIGHT (block 481500), with no per-network variant, so on a short regtest chain that
height is past the tip, the daemon returns "failed to get output distribution", and no RingCT tx
can build. This tiny localhost proxy sits between the wallet and zephyrd and rewrites the
get_output_distribution request's from_height to 0 on the wire - a strict mainnet no-op, needed
ONLY by the regtest test (mainnet users never hit it). Same effect as clamping from_height inside
the wallet, but against the stock upstream binary, so the coin-add can depend on Zephyr's official
release. See README-ZEPH.md.

Usage (test): start_rct_distribution_proxy(listen_port, zephyrd_rpc_port); point the wallet's
--daemon-address at listen_port; call .shutdown() in tearDown.
"""

import logging
import struct
import threading
import http.server
import socketserver
import http.client

_TARGET = "/get_output_distribution.bin"
# epee stores a field as: name-length byte, ASCII name, type tag, value.
# "from_height" is 11 chars (0x0B); the uint64 type tag is 0x05; the value is 8 bytes little-endian.
_MARKER = bytes([0x0B]) + b"from_height" + bytes([0x05])


def _rewrite_from_height(body: bytes) -> bytes:
    i = body.find(_MARKER)
    if i < 0:
        return body
    off = i + len(_MARKER)
    if off + 8 > len(body):
        return body
    old = struct.unpack_from("<Q", body, off)[0]
    if old == 0:
        return body
    buf = bytearray(body)
    struct.pack_into("<Q", buf, off, 0)  # same length, so no Content-Length change
    logging.debug("rct-distribution-proxy: rewrote from_height %d -> 0", old)
    return bytes(buf)


def _make_handler(upstream_port: int):
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _proxy(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n) if n else b""
            if self.path == _TARGET:
                body = _rewrite_from_height(body)
            up = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=180)
            try:
                fwd = {
                    k: v
                    for k, v in self.headers.items()
                    if k.lower()
                    not in ("host", "connection", "content-length", "transfer-encoding")
                }
                up.request(self.command, self.path, body=body, headers=fwd)
                r = up.getresponse()
                data = r.read()
            except Exception as e:
                self.send_error(502, str(e))
                up.close()
                return
            self.send_response(r.status)
            for k, v in r.getheaders():
                if k.lower() not in (
                    "connection",
                    "transfer-encoding",
                    "content-length",
                ):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            up.close()

        do_POST = _proxy
        do_GET = _proxy

        def log_message(self, *args):
            pass

    return _Handler


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_rct_distribution_proxy(listen_port: int, upstream_port: int) -> _Server:
    """Start the proxy in a background daemon thread; return the server (.shutdown() to stop).

    The wallet points --daemon-address at listen_port; the proxy forwards to zephyrd at
    upstream_port, rewriting only the get_output_distribution request's from_height to 0.
    """
    server = _Server(("127.0.0.1", listen_port), _make_handler(upstream_port))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    logging.info(
        "rct-distribution-proxy: 127.0.0.1:%d -> 127.0.0.1:%d",
        listen_port,
        upstream_port,
    )
    return server


if __name__ == "__main__":
    import sys

    _srv = start_rct_distribution_proxy(int(sys.argv[1]), int(sys.argv[2]))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        _srv.shutdown()
