#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Minimal in-process Nostr relay for tests.

Implements just enough of the websocket protocol (RFC 6455, text frames)
and NIP-01 (EVENT/REQ/CLOSE, filters: kinds, #t, #p, since, ids, authors)
to test the BSX Nostr transport without external infrastructure.
"""

import base64
import hashlib
import json
import socket
import struct
import threading

WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def recvExact(conn, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return data


def readFrame(conn):
    """Returns (opcode, payload) for a complete (possibly fragmented) message."""
    payload = b""
    opcode = None
    while True:
        header = recvExact(conn, 2)
        fin = header[0] & 0x80
        frame_opcode = header[0] & 0x0F
        masked = header[1] & 0x80
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", recvExact(conn, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", recvExact(conn, 8))[0]
        mask = recvExact(conn, 4) if masked else None
        frame_payload = recvExact(conn, length) if length else b""
        if mask:
            frame_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(frame_payload))
        if frame_opcode != 0:  # First frame of message
            opcode = frame_opcode
        payload += frame_payload
        if fin:
            return opcode, payload


def writeFrame(conn, payload: bytes, opcode: int = 0x1) -> None:
    header = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header += bytes([length])
    elif length < 0x10000:
        header += bytes([126]) + struct.pack(">H", length)
    else:
        header += bytes([127]) + struct.pack(">Q", length)
    conn.sendall(header + payload)


def eventMatchesFilter(event: dict, sub_filter: dict) -> bool:
    if "ids" in sub_filter and event["id"] not in sub_filter["ids"]:
        return False
    if "authors" in sub_filter and event["pubkey"] not in sub_filter["authors"]:
        return False
    if "kinds" in sub_filter and event["kind"] not in sub_filter["kinds"]:
        return False
    if "since" in sub_filter and event["created_at"] < sub_filter["since"]:
        return False
    if "until" in sub_filter and event["created_at"] > sub_filter["until"]:
        return False
    for key, values in sub_filter.items():
        if not key.startswith("#"):
            continue
        tag_name = key[1:]
        tag_values = [
            tag[1]
            for tag in event.get("tags", [])
            if len(tag) >= 2 and tag[0] == tag_name
        ]
        if not any(v in tag_values for v in values):
            return False
    return True


class ClientConnection:
    def __init__(self, conn):
        self.conn = conn
        self.send_mutex = threading.Lock()
        self.subscriptions = {}  # sub_id -> list of filters

    def send(self, message: str) -> None:
        with self.send_mutex:
            writeFrame(self.conn, message.encode("utf-8"))


class MiniNostrRelay:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.events = []  # Stored events in receive order
        self.mutex = threading.Lock()
        self.clients = []
        self.running = False
        self.socket = None
        self.accept_thread = None
        self.num_events_stored: int = 0

    def start(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.port = self.socket.getsockname()[1]
        self.socket.listen(8)
        self.running = True
        self.accept_thread = threading.Thread(target=self.acceptLoop, daemon=True)
        self.accept_thread.start()

    def stop(self) -> None:
        self.running = False
        try:
            self.socket.close()
        except Exception:
            pass
        with self.mutex:
            for client in self.clients:
                try:
                    client.conn.close()
                except Exception:
                    pass
            self.clients.clear()
        if self.accept_thread:
            self.accept_thread.join(timeout=2)

    def url(self) -> str:
        return f"ws://{self.host}:{self.port}"

    def acceptLoop(self) -> None:
        while self.running:
            try:
                conn, _ = self.socket.accept()
            except OSError:
                break
            threading.Thread(target=self.clientLoop, args=(conn,), daemon=True).start()

    def handshake(self, conn) -> bool:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(4096)
            if not chunk:
                return False
            request += chunk
        key = None
        for line in request.decode("utf-8", errors="replace").split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
        if key is None:
            return False
        accept = base64.b64encode(
            hashlib.sha1((key + WS_MAGIC).encode("utf-8")).digest()
        ).decode("utf-8")
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        conn.sendall(response.encode("utf-8"))
        return True

    def clientLoop(self, conn) -> None:
        try:
            if not self.handshake(conn):
                conn.close()
                return
            client = ClientConnection(conn)
            with self.mutex:
                self.clients.append(client)
            while self.running:
                opcode, payload = readFrame(conn)
                if opcode == 0x8:  # Close
                    break
                if opcode == 0x9:  # Ping
                    with client.send_mutex:
                        writeFrame(conn, payload, opcode=0xA)
                    continue
                if opcode != 0x1:
                    continue
                self.processMessage(client, payload.decode("utf-8"))
        except (ConnectionError, OSError):
            pass
        finally:
            with self.mutex:
                if "client" in locals() and client in self.clients:
                    self.clients.remove(client)
            try:
                conn.close()
            except Exception:
                pass

    def processMessage(self, client, message: str) -> None:
        data = json.loads(message)
        msg_type = data[0]
        if msg_type == "EVENT":
            event = data[1]
            with self.mutex:
                known = any(e["id"] == event["id"] for e in self.events)
                if not known:
                    self.events.append(event)
                    self.num_events_stored += 1
                clients = list(self.clients)
            client.send(json.dumps(["OK", event["id"], True, ""]))
            if known:
                return
            for other in clients:
                for sub_id, filters in other.subscriptions.items():
                    if any(eventMatchesFilter(event, f) for f in filters):
                        try:
                            other.send(json.dumps(["EVENT", sub_id, event]))
                        except Exception:
                            pass
                        break
        elif msg_type == "REQ":
            sub_id = data[1]
            filters = data[2:]
            client.subscriptions[sub_id] = filters
            with self.mutex:
                stored = list(self.events)
            for event in stored:
                if any(eventMatchesFilter(event, f) for f in filters):
                    client.send(json.dumps(["EVENT", sub_id, event]))
            client.send(json.dumps(["EOSE", sub_id]))
        elif msg_type == "CLOSE":
            client.subscriptions.pop(data[1], None)
