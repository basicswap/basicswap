#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import random
import string

from basicswap.chainparams import Coins
from basicswap.util.smsg import (
    smsgEncrypt,
    smsgDecrypt,
    smsgGetID,
    smsgGetTimestamp,
    SMSG_BUCKET_LEN,
)
from basicswap.contrib.test_framework.messages import (
    NODE_SMSG,
    msg_smsgPong,
    msg_smsgMsg,
)
from basicswap.contrib.test_framework.p2p import (
    P2PInterface,
    P2P_SERVICES,
    NetworkThread,
)
from basicswap.contrib.test_framework.util import (
    PortSeed,
)

from tests.basicswap.common import BASE_PORT
from tests.basicswap.test_xmr import BaseTest, test_delay_event


class P2PInterfaceSMSG(P2PInterface):
    def __init__(self):
        super().__init__()
        self.is_part = True

    def on_smsgPing(self, msg):
        logging.info("on_smsgPing")
        self.send_message(msg_smsgPong(1))

    def on_smsgPong(self, msg):
        logging.info("on_smsgPong", msg)

    def on_smsgInv(self, msg):
        logging.info("on_smsgInv")


def wait_for_smsg(ci, msg_id: str, wait_for=20) -> None:
    for i in range(wait_for):
        if test_delay_event.is_set():
            raise ValueError("Test stopped.")
        try:
            ci.rpc_wallet("smsg", [msg_id])
            return
        except Exception as e:
            logging.info(e)
            test_delay_event.wait(1)

    raise ValueError("wait_for_smsg timed out.")


class Test(BaseTest):
    __test__ = True
    start_ltc_nodes = False
    start_xmr_nodes = False

    @classmethod
    def setUpClass(cls):
        super(Test, cls).setUpClass()
        PortSeed.n = 1

        logging.info("Setting up network thread")
        cls.network_thread = NetworkThread()
        cls.network_thread.network_event_loop.set_debug(True)
        cls.network_thread.start()

    @classmethod
    def run_loop_ended(cls):
        logging.info("run_loop_ended")
        logging.info("Closing down network thread")
        cls.network_thread.close()

    @classmethod
    def tearDownClass(cls):
        logging.info("Finalising Test")
        super(Test, cls).tearDownClass()

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()

    def test_01_p2p(self):
        swap_clients = self.swap_clients

        kwargs = {}
        kwargs["dstport"] = BASE_PORT
        kwargs["dstaddr"] = "127.0.0.1"
        services = P2P_SERVICES | NODE_SMSG
        p2p_conn = P2PInterfaceSMSG()
        p2p_conn.p2p_connected_to_node = True
        p2p_conn.peer_connect(
            **kwargs,
            services=services,
            send_version=True,
            net="regtest",
            timeout_factor=99999,
            supports_v2_p2p=False,
        )()

        p2p_conn.wait_for_connect()
        p2p_conn.wait_for_verack()
        p2p_conn.sync_with_ping()

        ci0_part = swap_clients[0].ci(Coins.PART)
        test_key_recv: bytes = ci0_part.getNewRandomKey()
        test_key_recv_wif: str = ci0_part.encodeKey(test_key_recv)
        test_key_recv_pk: bytes = ci0_part.getPubkey(test_key_recv)
        ci0_part.rpc("smsgimportprivkey", [test_key_recv_wif, "test key"])

        message_test: str = "Test message"
        test_key_send: bytes = ci0_part.getNewRandomKey()
        encrypted_message: bytes = smsgEncrypt(
            test_key_send, test_key_recv_pk, message_test.encode("utf-8")
        )

        decrypted_message: bytes = smsgDecrypt(test_key_recv, encrypted_message)
        assert decrypted_message.decode("utf-8") == message_test

        msg_id: bytes = smsgGetID(encrypted_message)
        smsg_timestamp: int = smsgGetTimestamp(encrypted_message)
        smsg_bucket: int = smsg_timestamp - (smsg_timestamp % SMSG_BUCKET_LEN)

        smsgMsg = msg_smsgMsg(1, smsg_bucket, encrypted_message)
        p2p_conn.send_message(smsgMsg)

        wait_for_smsg(ci0_part, msg_id.hex())
        rv = ci0_part.rpc_wallet("smsg", [msg_id.hex()])
        assert rv["text"] == message_test

        ci1_part = swap_clients[1].ci(Coins.PART)
        rv = ci1_part.rpc("smsgimport", [encrypted_message.hex(), {"submitmsg": True}])
        assert rv["msgid"] == msg_id.hex()

    def test_02_payload_v2(self):
        # Test SMSG plaintext version 2

        ci0_part = self.swap_clients[0].ci(Coins.PART)

        len_smsgaddresses_start = len(ci0_part.rpc("smsgaddresses"))

        message_test: str = "Test message"
        for i in range(2048):
            message_test += random.choice(string.ascii_letters + string.digits)
        message_test += "end."

        test_key_recv: bytes = ci0_part.getNewRandomKey()
        test_key_recv_wif: str = ci0_part.encodeKey(test_key_recv)
        test_key_recv_pk: bytes = ci0_part.getPubkey(test_key_recv)
        ci0_part.rpc("smsgimportprivkey", [test_key_recv_wif, "test key"])
        ro = ci0_part.rpc("smsgoptions", ["set", "addReceivedPubkeys", False])
        assert "addReceivedPubkeys = false" in str(ro)

        test_addr_core = ci0_part.pubkey_to_address(ci0_part.getPubkey(test_key_recv))
        test_key_send: bytes = ci0_part.getNewRandomKey()
        test_pk_bsx = ci0_part.getPubkey(test_key_send)

        logging.info("Test core to BSX")
        options = {
            "submitmsg": False,
            "ttl_is_seconds": True,
            "payload_format_version": 2,
            "compression": 0,
            "add_to_outbox": False,
        }
        ro = ci0_part.rpc(
            "smsgsend",
            [
                test_addr_core,
                test_pk_bsx.hex(),
                message_test,
                False,
                self.swap_clients[0].SMSG_SECONDS_IN_HOUR,
                False,
                options,
            ],
        )
        encrypted_message = bytes.fromhex(ro["msg"])
        decrypted_message: bytes = smsgDecrypt(test_key_send, encrypted_message)
        assert decrypted_message.decode("utf-8") == message_test

        logging.info("Test BSX to core")
        encrypted_message: bytes = smsgEncrypt(
            test_key_send, test_key_recv_pk, message_test.encode("utf-8")
        )
        msg_id: bytes = smsgGetID(encrypted_message)

        rv = ci0_part.rpc("smsgimport", [encrypted_message.hex(), {"submitmsg": True}])
        assert rv["msgid"] == msg_id.hex()

        options = {"pubkey_from": True}
        rv = ci0_part.rpc("smsg", [msg_id.hex(), options])
        assert rv["text"].endswith("end.")
        assert rv["msgid"] == msg_id.hex()
        assert "pubkey_from" in rv

        smsgaddresses = ci0_part.rpc("smsgaddresses")
        assert len(smsgaddresses) == len_smsgaddresses_start
