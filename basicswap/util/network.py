# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import contextlib
import ipaddress
import os
import socket
import time
import urllib.parse

from urllib.error import ContentTooShortError
from urllib.parse import _splittype
from urllib.request import Request, urlopen


def is_private_ip_address(addr: str):
    if addr == "localhost":
        return True
    if addr.endswith(".local"):
        return True
    try:
        return ipaddress.ip_address(addr).is_private
    except Exception:
        return False


def is_loopback_address(addr: str) -> bool:
    if addr == "localhost":
        return True
    if addr.startswith("::ffff:"):  # IPv4-mapped IPv6, e.g. ::ffff:127.0.0.1
        addr = addr[len("::ffff:") :]
    try:
        return ipaddress.ip_address(addr).is_loopback  # 127.0.0.0/8, ::1
    except ValueError:
        return False


def is_url_scheme_allowed(url: str) -> bool:
    # Only http(s) may be fetched; blocks file://, ftp://, gopher:// etc.
    return urllib.parse.urlparse(url).scheme in ("http", "https")


def is_public_url(url: str) -> bool:
    # True only when url is http(s) and its host resolves exclusively to public
    # addresses. Used to keep the /json/readurl proxy from reaching internal
    # services (loopback, LAN, cloud-metadata). is_private covers 127.0.0.0/8
    # and 169.254.0.0/16.
    parsed = urllib.parse.urlparse(url)
    if not is_url_scheme_allowed(url):
        return False
    host = parsed.hostname
    if host is None or is_private_ip_address(host):
        return False
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addrinfo = socket.getaddrinfo(host, port)
    except Exception:
        return False
    for *_, sockaddr in addrinfo:
        if is_private_ip_address(sockaddr[0]):
            return False
    return True


def _normalize_origin(value):
    # value is a full URL with scheme (a browser Origin/Referer).
    # Returns (scheme, host, port) or None.
    p = urllib.parse.urlsplit(value)
    host = (p.hostname or "").lower()
    scheme = (p.scheme or "").lower()
    if not host or not scheme:
        return None
    try:
        port = p.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return (scheme, host, port)


def allowed_entry_hostname(entry):
    # Extract the bare hostname from an allowed_hosts entry, which may be a bare
    # host ("host"), a host:port, or a full origin ("scheme://host[:port]").
    # Used by the Host-header check so scheme-form entries (added for reverse
    # proxies) still match the schemeless Host header.
    e = str(entry).strip()
    if not e:
        return None
    if "://" not in e:
        e = "//" + e
    host = urllib.parse.urlsplit(e).hostname
    return host.lower() if host else None


def is_origin_allowed(origin, html_host, html_port, allowed_hosts) -> bool:
    # Validate a browser Origin/Referer for CSRF / cross-site WebSocket hijacking.
    # Shared by the HTTP same-origin check and the WebSocket handshake so the two
    # cannot drift. The comparison is against the HTML server's origin (the page
    # origin), which is what both a same-origin POST and a page-opened WebSocket
    # carry. "*" in allowed_hosts is a Host-header-check opt-out only and is
    # ignored here — the origin check is always enforced.
    norm = _normalize_origin(origin)
    if norm is None:
        return False  # opaque ("null") / malformed -> reject
    scheme, host, port = norm

    # 1. Strict default origins: http on the HTML port, loopback + concrete bind
    #    host. A page on another port (e.g. http://127.0.0.1:8080) does NOT match.
    if html_port is not None:
        default_hosts = {"localhost", "127.0.0.1", "::1"}
        if html_host and str(html_host) not in ("0.0.0.0", "::"):
            default_hosts.add(str(html_host).lower())
        if scheme == "http" and port == int(html_port) and host in default_hosts:
            return True

    # 2. Configured entries. An entry with a scheme is an exact origin; a bare
    #    host matches that host on any scheme/port (the operator vouched for it).
    for entry in allowed_hosts or []:
        if entry == "*":
            continue
        e = str(entry).strip().lower()
        if "://" in e:
            t = _normalize_origin(e)
            if t is not None and (scheme, host, port) == t:
                return True
        elif host == e.strip("[]"):
            return True
    return False


def make_reporthook(read_start: int, logger):
    read = read_start  # Number of bytes read so far
    last_percent_str = ""
    time_last = time.time()
    read_last = read_start
    display_last = time_last
    abo = 7
    average_buffer = [-1] * 8

    if read_start > 0:
        logger.info(f"Attempting to resume from byte {read_start}")

    def reporthook(blocknum, blocksize, totalsize):
        nonlocal read, last_percent_str, time_last, read_last, display_last, abo
        read += blocksize

        # totalsize excludes read_start
        use_size = totalsize + read_start
        dl_complete: bool = totalsize > 0 and read >= use_size
        time_now = time.time()
        time_delta = time_now - time_last
        if time_delta < 4.0 and not dl_complete:
            return

        # Avoid division by zero by picking a value
        if time_delta <= 0.0:
            time_delta = 0.01

        bytes_delta = read - read_last
        time_last = time_now
        read_last = read
        bits_per_second = (bytes_delta * 8) / time_delta

        abo = 0 if abo >= 7 else abo + 1
        average_buffer[abo] = bits_per_second

        samples = 0
        average_bits_per_second = 0
        for sample in average_buffer:
            if sample < 0:
                continue
            average_bits_per_second += sample
            samples += 1
        average_bits_per_second /= samples

        speed_str: str
        if average_bits_per_second > 1000**3:
            speed_str = "{:.2f} Gbps".format(average_bits_per_second / (1000**3))
        elif average_bits_per_second > 1000**2:
            speed_str = "{:.2f} Mbps".format(average_bits_per_second / (1000**2))
        else:
            speed_str = "{:.2f} kbps".format(average_bits_per_second / 1000)

        if totalsize > 0:
            percent_str = "%5.0f%%" % (read * 1e2 / use_size)
            if percent_str != last_percent_str or time_now - display_last > 10:
                logger.info(percent_str + "  " + speed_str)
                last_percent_str = percent_str
                display_last = time_now
        else:
            logger.info(f"Read {read}, {speed_str}")

    return reporthook


def urlretrieve(url, filename, reporthook=None, data=None, resume_from=0):
    """urlretrieve with resume"""
    url_type, path = _splittype(url)

    req = Request(url)
    if resume_from > 0:
        req.add_header("Range", f"bytes={resume_from}-")
    with contextlib.closing(urlopen(req)) as fp:
        headers = fp.info()

        # Just return the local path and the "headers" for file://
        # URLs. No sense in performing a copy unless requested.
        if url_type == "file" and not filename:
            return os.path.normpath(path), headers

        with open(filename, "ab" if resume_from > 0 else "wb") as tfp:
            result = filename, headers
            bs = 1024 * 8
            size = -1
            read = resume_from
            blocknum = 0
            range_from = 0
            if "content-length" in headers:
                size = int(headers["Content-Length"])
            if "Content-Range" in headers:
                range_str = headers["Content-Range"]
                offset = range_str.find("-")
                range_from = int(range_str[6:offset])
            if resume_from != range_from:
                raise ValueError("Download is not resuming from the expected byte")

            if reporthook:
                reporthook(blocknum, bs, size)

            while True:
                block = fp.read(bs)
                if not block:
                    break
                read += len(block)
                tfp.write(block)
                blocknum += 1
                if reporthook:
                    reporthook(blocknum, bs, size)

    if size >= 0 and read < size:
        raise ContentTooShortError(
            "retrieval incomplete: got only %i out of %i bytes" % (read, size), result
        )

    return result
