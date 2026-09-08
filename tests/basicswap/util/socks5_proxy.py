#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""Minimal in-process SOCKS5 proxy (no auth, CONNECT only) for tests."""

import socket
import struct
import threading


class MiniSocks5Proxy:
    def __init__(self, host: str = "127.0.0.1"):
        self.host: str = host
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, 0))
        self.listener.listen(8)
        self.port: int = self.listener.getsockname()[1]
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.targets = []
        self.lock = threading.Lock()

    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        try:
            self.listener.close()
        except Exception:
            pass
        self.thread.join(timeout=5.0)

    def serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                break
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    @staticmethod
    def recvExact(conn, num_bytes: int) -> bytes:
        data = b""
        while len(data) < num_bytes:
            chunk = conn.recv(num_bytes - len(data))
            if not chunk:
                raise ConnectionError("Closed")
            data += chunk
        return data

    def handle(self, conn) -> None:
        upstream = None
        try:
            ver, num_methods = struct.unpack("!BB", self.recvExact(conn, 2))
            assert ver == 5
            self.recvExact(conn, num_methods)
            conn.sendall(b"\x05\x00")  # No authentication

            ver, cmd, _, atyp = struct.unpack("!BBBB", self.recvExact(conn, 4))
            assert ver == 5 and cmd == 1  # CONNECT
            if atyp == 1:
                host = socket.inet_ntoa(self.recvExact(conn, 4))
            elif atyp == 3:
                host_len = self.recvExact(conn, 1)[0]
                host = self.recvExact(conn, host_len).decode("ascii")
            else:
                raise ValueError(f"Unsupported ATYP {atyp}")
            port = struct.unpack("!H", self.recvExact(conn, 2))[0]

            with self.lock:
                self.targets.append((host, port))

            upstream = socket.create_connection((host, port), timeout=10.0)
            upstream.settimeout(None)
            conn.sendall(
                b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
            )

            def pump(src, dst):
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        dst.sendall(data)
                except OSError:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            t = threading.Thread(target=pump, args=(upstream, conn), daemon=True)
            t.start()
            pump(conn, upstream)
            t.join(timeout=5.0)
        except Exception:
            pass
        finally:
            for s in (conn, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
