#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
    Message 2 bytes msg_class, 4 bytes length, [ 2 bytes msg_type, payload ]

    Handshake procedure:
        node0 connecting to node1
        node0 send_handshake
        node1 process_handshake
        node1 send_ping  - With a version field
        node0 recv_ping
            Both nodes are initialised

    XChaCha20_Poly1305 mac is 16bytes
"""

import time
import queue
import random
import select
import socket
import hashlib
import logging
import secrets
import threading
import traceback

from enum import IntEnum, auto
from collections import OrderedDict
from Crypto.Cipher import ChaCha20_Poly1305  # TODO: Add to libsecp256k1/coincurve fork
from coincurve.keys import PrivateKey, PublicKey
from basicswap.contrib.rfc6979 import (
    rfc6979_hmac_sha256_initialize,
    rfc6979_hmac_sha256_generate,
)


START_TOKEN = 0xABCD
MSG_START_TOKEN = START_TOKEN.to_bytes(2, "big")

MSG_MAX_SIZE = 0x200000  # 2MB

MSG_HEADER_LEN = 8


MAX_SEEN_EPHEM_KEYS = 1000
TIMESTAMP_LEEWAY = 8


class NetMessageTypes(IntEnum):
    HANDSHAKE = auto()
    PING = auto()
    PONG = auto()
    DATA = auto()
    ONION_PACKET = auto()

    @classmethod
    def has_value(cls, value):
        return value in cls._value2member_map_


"""
class NetMessage:
    def __init__(self):
        self._msg_class = None  # 2 bytes
        self._len = None # 4 bytes
        self._msg_type = None  # 2 bytes
"""


# Ensure handshake keys are not reused by including the time in the msg, mac and key hash
# Verify timestamp is not too old
# Add keys to db to catch concurrent attempts, records can be cleared periodically, the timestamp should catch older replay attempts
class MsgHandshake:
    __slots__ = ("_timestamp", "_ephem_pk", "_ct", "_mac")

    def __init__(self):
        pass

    def encode_aad(self):  # Additional Authenticated Data
        return (
            int(NetMessageTypes.HANDSHAKE).to_bytes(2, "big")
            + self._timestamp.to_bytes(8, "big")
            + self._ephem_pk
        )

    def encode(self):
        return self.encode_aad() + self._ct + self._mac

    def decode(self, msg_mv):
        o = 2
        self._timestamp = int.from_bytes(msg_mv[o : o + 8], "big")
        o += 8
        self._ephem_pk = bytes(msg_mv[o : o + 33])
        o += 33
        self._ct = bytes(msg_mv[o:-16])
        self._mac = bytes(msg_mv[-16:])


class Peer:
    __slots__ = (
        "_mx",
        "_pubkey",
        "_address",
        "_socket",
        "_version",
        "_ready",
        "_incoming",
        "_connected_at",
        "_last_received_at",
        "_bytes_sent",
        "_bytes_received",
        "_receiving_length",
        "_receiving_buffer",
        "_recv_messages",
        "_misbehaving_score",
        "_ke",
        "_km",
        "_dir",
        "_sent_nonce",
        "_recv_nonce",
        "_last_handshake_at",
        "_ping_nonce",
        "_last_ping_at",
        "_last_ping_rtt",
    )

    def __init__(self, address, socket, pubkey):
        self._mx = threading.Lock()
        self._pubkey = pubkey
        self._address = address
        self._socket = socket
        self._version = None
        self._ready = False  # True when handshake is complete
        self._incoming = False
        self._connected_at = time.time()
        self._last_received_at = 0
        self._last_handshake_at = 0

        self._bytes_sent = 0
        self._bytes_received = 0

        self._receiving_length = 0
        self._receiving_buffer = None
        self._recv_messages = queue.Queue()  # Built in mutex
        self._misbehaving_score = 0  # TODO: Must be persistent - save to db

        self._ping_nonce = 0
        self._last_ping_at = 0  # ms
        self._last_ping_rtt = 0  # ms

    def close(self):
        self._socket.close()


def listen_thread(cls):
    timeout = 1.0

    max_bytes = 0x10000
    while cls._running:
        # logging.info('[rm] network loop %d', cls._running)
        readable, writable, errored = select.select(
            cls._read_sockets, cls._write_sockets, cls._error_sockets, timeout
        )
        cls._mx.acquire()
        try:
            disconnected_peers = []
            for s in readable:
                if s == cls._socket:
                    peer_socket, address = cls._socket.accept()
                    logging.info("Connection from %s", address)
                    new_peer = Peer(address, peer_socket, None)
                    new_peer._incoming = True
                    cls._peers.append(new_peer)
                    cls._error_sockets.append(peer_socket)
                    cls._read_sockets.append(peer_socket)
                else:
                    for peer in cls._peers:
                        if peer._socket == s:
                            try:
                                bytes_recv = s.recv(max_bytes, socket.MSG_DONTWAIT)
                            except socket.error as se:
                                if se.args[0] not in (socket.EWOULDBLOCK,):
                                    logging.error("Receive error %s", str(se))
                                    disconnected_peers.append(peer)
                                    continue
                            except Exception as e:
                                logging.error("Receive error %s", str(e))
                                disconnected_peers.append(peer)
                                continue

                            if len(bytes_recv) < 1:
                                disconnected_peers.append(peer)
                                continue
                            cls.receive_bytes(peer, bytes_recv)

            for s in errored:
                logging.warning("Socket error")

            for peer in disconnected_peers:
                cls.disconnect(peer)
        finally:
            cls._mx.release()


def msg_thread(cls):
    timeout = 0.1
    while cls._running:
        processed = False

        with cls._mx:
            for peer in cls._peers:
                try:
                    now_us = time.time_ns() // 1000
                    if peer._ready is True:
                        if (
                            now_us - peer._last_ping_at >= 5000000
                        ):  # 5 seconds  TODO: Make variable
                            cls.send_ping(peer)
                    msg = peer._recv_messages.get(False)
                    cls.process_message(peer, msg)
                    processed = True
                except queue.Empty:
                    pass
                except Exception as e:
                    logging.warning("process message error %s", str(e))
                    if cls._sc.debug:
                        logging.error(traceback.format_exc())

        if processed is False:
            time.sleep(timeout)


class Network:
    __slots__ = (
        "_p2p_host",
        "_p2p_port",
        "_network_key",
        "_network_pubkey",
        "_sc",
        "_peers",
        "_max_connections",
        "_running",
        "_network_thread",
        "_msg_thread",
        "_mx",
        "_socket",
        "_read_sockets",
        "_write_sockets",
        "_error_sockets",
        "_csprng",
        "_seen_ephem_keys",
    )

    def __init__(self, p2p_host, p2p_port, network_key, swap_client):
        self._p2p_host = p2p_host
        self._p2p_port = p2p_port
        self._network_key = network_key
        self._network_pubkey = PublicKey.from_secret(network_key).format()
        self._sc = swap_client
        self._peers = []

        self._max_connections = 10
        self._running = False

        self._network_thread = None
        self._msg_thread = None
        self._mx = threading.Lock()
        self._socket = None
        self._read_sockets = []
        self._write_sockets = []
        self._error_sockets = []  # Check for error events
        self._seen_ephem_keys = OrderedDict()

    def startNetwork(self):
        self._mx.acquire()
        try:
            self._csprng = rfc6979_hmac_sha256_initialize(secrets.token_bytes(32))

            self._running = True
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self._p2p_host, self._p2p_port))
            self._socket.listen(self._max_connections)
            self._read_sockets.append(self._socket)

            self._network_thread = threading.Thread(target=listen_thread, args=(self,))
            self._network_thread.start()

            self._msg_thread = threading.Thread(target=msg_thread, args=(self,))
            self._msg_thread.start()
        finally:
            self._mx.release()

    def stopNetwork(self):
        self._mx.acquire()
        try:
            self._running = False
        finally:
            self._mx.release()

        if self._network_thread:
            self._network_thread.join()
        if self._msg_thread:
            self._msg_thread.join()

        self._mx.acquire()
        try:
            if self._socket:
                self._socket.close()

            for peer in self._peers:
                peer.close()
        finally:
            self._mx.release()

    def add_connection(self, host, port, peer_pubkey):
        self._sc.log.info(
            "Connecting from %s to %s at %s %d",
            self._network_pubkey.hex(),
            peer_pubkey.hex(),
            host,
            port,
        )
        self._mx.acquire()
        try:
            address = (host, port)
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect(address)
            peer = Peer(address, peer_socket, peer_pubkey)
            self._peers.append(peer)
            self._error_sockets.append(peer_socket)
            self._read_sockets.append(peer_socket)
        finally:
            self._mx.release()

        self.send_handshake(peer)

    def disconnect(self, peer):
        self._sc.log.info("Closing peer socket %s", peer._address)
        self._read_sockets.pop(self._read_sockets.index(peer._socket))
        self._error_sockets.pop(self._error_sockets.index(peer._socket))
        peer.close()
        self._peers.pop(self._peers.index(peer))

    def check_handshake_ephem_key(self, peer, timestamp, ephem_pk, direction=1):
        # assert ._mx.acquire() ?

        used = self._seen_ephem_keys.get(ephem_pk)
        if used:
            raise ValueError(
                "Handshake ephem_pk reused %s peer %s",
                "for" if direction == 1 else "by",
                used[0],
            )

        self._seen_ephem_keys[ephem_pk] = (peer._address, timestamp)

        while len(self._seen_ephem_keys) > MAX_SEEN_EPHEM_KEYS:
            self._seen_ephem_keys.popitem(last=False)

    def send_handshake(self, peer):
        self._sc.log.debug("send_handshake %s", peer._address)
        peer._mx.acquire()
        try:
            # TODO: Drain peer._recv_messages
            if not peer._recv_messages.empty():
                self._sc.log.warning(
                    "send_handshake %s - Receive queue dumped.", peer._address
                )
                while not peer._recv_messages.empty():
                    peer._recv_messages.get(False)

            msg = MsgHandshake()

            msg._timestamp = int(time.time())
            key_r = rfc6979_hmac_sha256_generate(self._csprng, 32)
            k = PrivateKey(key_r)
            msg._ephem_pk = PublicKey.from_secret(key_r).format()
            self.check_handshake_ephem_key(peer, msg._timestamp, msg._ephem_pk)

            ss = k.ecdh(peer._pubkey)

            hashed = hashlib.sha512(ss + msg._timestamp.to_bytes(8, "big")).digest()
            peer._ke = hashed[:32]
            peer._km = hashed[32:]

            nonce = peer._km[24:]

            payload = self._sc._version

            nk = PrivateKey(self._network_key)
            sig = nk.sign_recoverable(peer._km)
            payload += sig

            aad = msg.encode_aad()
            aad += nonce
            cipher = ChaCha20_Poly1305.new(key=peer._ke, nonce=nonce)
            cipher.update(aad)
            msg._ct, msg._mac = cipher.encrypt_and_digest(payload)

            peer._sent_nonce = hashlib.sha256(nonce + msg._mac).digest()
            peer._recv_nonce = hashlib.sha256(peer._km).digest()  # Init nonce

            peer._last_handshake_at = msg._timestamp
            peer._ready = False  # Wait for peer to complete handshake

            self.send_msg(peer, msg)
        finally:
            peer._mx.release()

    def process_handshake(self, peer, msg_mv):
        self._sc.log.debug("process_handshake %s", peer._address)

        # TODO: Drain peer._recv_messages
        if not peer._recv_messages.empty():
            self._sc.log.warning(
                "process_handshake %s - Receive queue dumped.", peer._address
            )
            while not peer._recv_messages.empty():
                peer._recv_messages.get(False)

        msg = MsgHandshake()
        msg.decode(msg_mv)

        try:
            now = int(time.time())
            if now - peer._last_handshake_at < 30:
                raise ValueError("Too many handshakes from peer %s", peer._address)

            if abs(msg._timestamp - now) > TIMESTAMP_LEEWAY:
                raise ValueError("Bad handshake timestamp from peer %s", peer._address)

            self.check_handshake_ephem_key(
                peer, msg._timestamp, msg._ephem_pk, direction=2
            )

            nk = PrivateKey(self._network_key)
            ss = nk.ecdh(msg._ephem_pk)

            hashed = hashlib.sha512(ss + msg._timestamp.to_bytes(8, "big")).digest()
            peer._ke = hashed[:32]
            peer._km = hashed[32:]

            nonce = peer._km[24:]

            aad = msg.encode_aad()
            aad += nonce
            cipher = ChaCha20_Poly1305.new(key=peer._ke, nonce=nonce)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(
                msg._ct, msg._mac
            )  # Will raise error if mac doesn't match

            peer._version = plaintext[:6]
            sig = plaintext[6:]

            pk_peer = PublicKey.from_signature_and_message(sig, peer._km)
            # TODO: Should pk_peer be linked to public data?

            peer._pubkey = pk_peer.format()
            peer._recv_nonce = hashlib.sha256(nonce + msg._mac).digest()
            peer._sent_nonce = hashlib.sha256(peer._km).digest()  # Init nonce

            peer._last_handshake_at = msg._timestamp
            peer._ready = True
            # Schedule a ping to complete the handshake, TODO: Send here?
            peer._last_ping_at = 0

        except Exception as e:
            # TODO: misbehaving
            self._sc.log.debug("[rm] process_handshake %s", str(e))

    def process_ping(self, peer, msg_mv):
        nonce = peer._recv_nonce[:24]

        cipher = ChaCha20_Poly1305.new(key=peer._ke, nonce=nonce)
        cipher.update(msg_mv[0:2])
        cipher.update(nonce)

        mac = msg_mv[-16:]
        plaintext = cipher.decrypt_and_verify(msg_mv[2:-16], mac)

        ping_nonce = int.from_bytes(plaintext[:4], "big")
        # Version is added to a ping following a handshake message
        if len(plaintext) >= 10:
            peer._ready = True
            version = plaintext[4:10]
            if peer._version is None:
                peer._version = version
                self._sc.log.debug(
                    "Set version from ping %s, %s",
                    peer._pubkey.hex(),
                    peer._version.hex(),
                )

        peer._recv_nonce = hashlib.sha256(nonce + mac).digest()

        self.send_pong(peer, ping_nonce)

    def process_pong(self, peer, msg_mv):
        nonce = peer._recv_nonce[:24]

        cipher = ChaCha20_Poly1305.new(key=peer._ke, nonce=nonce)
        cipher.update(msg_mv[0:2])
        cipher.update(nonce)

        mac = msg_mv[-16:]
        plaintext = cipher.decrypt_and_verify(msg_mv[2:-16], mac)

        pong_nonce = int.from_bytes(plaintext[:4], "big")

        if pong_nonce == peer._ping_nonce:
            peer._last_ping_rtt = (time.time_ns() // 1000) - peer._last_ping_at
        else:
            self._sc.log.debug("Pong received out of order %s", peer._address)

        peer._recv_nonce = hashlib.sha256(nonce + mac).digest()

    def send_ping(self, peer):
        ping_nonce = random.getrandbits(32)

        msg_bytes = int(NetMessageTypes.PING).to_bytes(2, "big")
        nonce = peer._sent_nonce[:24]

        cipher = ChaCha20_Poly1305.new(key=peer._ke, nonce=nonce)
        cipher.update(msg_bytes)
        cipher.update(nonce)

        payload = ping_nonce.to_bytes(4, "big")
        if peer._last_ping_at == 0:
            payload += self._sc._version
        ct, mac = cipher.encrypt_and_digest(payload)

        msg_bytes += ct + mac

        peer._sent_nonce = hashlib.sha256(nonce + mac).digest()

        peer._last_ping_at = time.time_ns() // 1000
        peer._ping_nonce = ping_nonce

        self.send_msg(peer, msg_bytes)

    def send_pong(self, peer, ping_nonce):
        msg_bytes = int(NetMessageTypes.PONG).to_bytes(2, "big")
        nonce = peer._sent_nonce[:24]

        cipher = ChaCha20_Poly1305.new(key=peer._ke, nonce=nonce)
        cipher.update(msg_bytes)
        cipher.update(nonce)

        payload = ping_nonce.to_bytes(4, "big")
        ct, mac = cipher.encrypt_and_digest(payload)
        msg_bytes += ct + mac

        peer._sent_nonce = hashlib.sha256(nonce + mac).digest()

        self.send_msg(peer, msg_bytes)

    def send_msg(self, peer, msg):
        msg_encoded = msg if isinstance(msg, bytes) else msg.encode()
        len_encoded = len(msg_encoded)

        msg_packed = (
            bytearray(MSG_START_TOKEN) + len_encoded.to_bytes(4, "big") + msg_encoded
        )
        peer._socket.sendall(msg_packed)

        peer._bytes_sent += len_encoded

    def process_message(self, peer, msg_bytes):
        logging.info("[rm] process_message %s len %d", peer._address, len(msg_bytes))

        peer._mx.acquire()
        try:
            mv = memoryview(msg_bytes)
            o = 0
            msg_type = int.from_bytes(mv[o : o + 2], "big")
            if msg_type == NetMessageTypes.HANDSHAKE:
                self.process_handshake(peer, mv)
            elif msg_type == NetMessageTypes.PING:
                self.process_ping(peer, mv)
            elif msg_type == NetMessageTypes.PONG:
                self.process_pong(peer, mv)
            else:
                self._sc.log.debug("Unknown message type %d", msg_type)
        finally:
            peer._mx.release()

    def receive_bytes(self, peer, bytes_recv):
        # logging.info('[rm] receive_bytes %s %s', peer._address, bytes_recv)

        len_received = len(bytes_recv)
        peer._last_received_at = time.time()
        peer._bytes_received += len_received

        invalid_msg = False
        mv = memoryview(bytes_recv)

        o = 0
        try:
            while o < len_received:
                if peer._receiving_length == 0:
                    if len(bytes_recv) < MSG_HEADER_LEN:
                        raise ValueError("Msg too short")

                    if mv[o : o + 2] != MSG_START_TOKEN:
                        raise ValueError("Invalid start token")
                    o += 2

                    msg_len = int.from_bytes(mv[o : o + 4], "big")
                    o += 4
                    if msg_len < 2 or msg_len > MSG_MAX_SIZE:
                        raise ValueError("Invalid data length")

                    # Precheck msg_type
                    msg_type = int.from_bytes(mv[o : o + 2], "big")
                    # o += 2  # Don't inc offset, msg includes type
                    if not NetMessageTypes.has_value(msg_type):
                        raise ValueError("Invalid msg type")

                    peer._receiving_length = msg_len
                    len_pkt = len_received - o
                    nc = msg_len if len_pkt > msg_len else len_pkt

                    peer._receiving_buffer = mv[o : o + nc]
                    o += nc
                else:
                    len_to_go = peer._receiving_length - len(peer._receiving_buffer)
                    len_pkt = len_received - o
                    nc = len_to_go if len_pkt > len_to_go else len_pkt
                    peer._receiving_buffer = mv[o : o + nc]
                    o += nc
                if len(peer._receiving_buffer) == peer._receiving_length:
                    peer._recv_messages.put(peer._receiving_buffer)
                    peer._receiving_length = 0

        except Exception as e:
            if self._sc.debug:
                self._sc.log.error(
                    "Invalid message received from %s %s", peer._address, str(e)
                )
            # TODO: misbehaving

    def test_onion(self, path):
        self._sc.log.debug("test_onion packet")

    def get_info(self):
        rv = {}

        peers = []
        with self._mx:
            for peer in self._peers:
                peer_info = {
                    "pubkey": "Unknown" if not peer._pubkey else peer._pubkey.hex(),
                    "address": "{}:{}".format(peer._address[0], peer._address[1]),
                    "bytessent": peer._bytes_sent,
                    "bytesrecv": peer._bytes_received,
                    "ready": peer._ready,
                    "incoming": peer._incoming,
                }
                peers.append(peer_info)

        rv["peers"] = peers
        return rv
