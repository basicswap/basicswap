"""Opt-in Particl SMSG v2 delivery of a native HNS/BTC offer.

PARTICLD_BIN and PARTICL_CLI_BIN must point to locally verified Particl Core
executables. This test creates only disposable regtest wallets and nodes.
"""

import json
import os
import sqlite3
import subprocess
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import MessageTypes, SwapTypes, TxLockTypes
from basicswap.chainparams import Coins
from basicswap.db import Bid, HnsBtcOutbox, HnsBtcSwap, Offer
from basicswap.interface.hns.app_protocol import receive_hns_btc_bid
from basicswap.messages_npb import OfferMessage
from basicswap.network.bsx_network import BSXNetwork
from basicswap.util.address import b58decode, decodeWif
from basicswap.util.smsg import smsgEncrypt, smsgGetID
from tests.basicswap.run_hns_bridge_regtest import free_port
from tests.basicswap.test_hns_app_protocol import FakeApp
from tests.basicswap.test_hns_two_chain_regtest import wait_for


class ParticlNode:
    def __init__(self, root, executable, cli_executable, connect=None):
        self.root = root
        self.root.mkdir()
        self.rpc_port = free_port()
        self.p2p_port = free_port()
        command = [
            str(executable),
            "-regtest",
            f"-datadir={root}",
            f"-rpcport={self.rpc_port}",
            f"-port={self.p2p_port}",
            "-server=1",
            "-rpcuser=isolated",
            "-rpcpassword=isolated",
            "-discover=0",
            "-dnsseed=0",
            "-listenonion=0",
            "-smsg=1",
            "-smsgsregtestadjust=0",
            "-deprecatedrpc=create_bdb",
            "-printtoconsole=0",
        ]
        if connect is not None:
            command.append(f"-connect=127.0.0.1:{connect}")
        self.cli_executable = cli_executable
        self.process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        try:
            wait_for(lambda: self.rpc("getblockchaininfo"), "Particl RPC startup", 30)
            self.rpc("createwallet", "test")
            seed = self.rpc("mnemonic", "new")["master"]
            self.rpc("extkeyimportmaster", seed)
        except Exception:
            self.close()
            raise

    def rpc(self, *args):
        result = subprocess.run(
            [
                str(self.cli_executable),
                "-regtest",
                f"-datadir={self.root}",
                f"-rpcport={self.rpc_port}",
                "-rpcuser=isolated",
                "-rpcpassword=isolated",
                *(str(value) for value in args),
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        output = result.stdout.strip()
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    def close(self):
        try:
            self.rpc("stop")
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            self.process.terminate()
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)


@unittest.skipUnless(
    os.getenv("PARTICLD_BIN") and os.getenv("PARTICL_CLI_BIN"),
    "set verified Particl Core binary paths for the isolated SMSG regtest",
)
class HnsParticlSmsgRegtest(unittest.TestCase):
    def test_hns_offer_and_trade_envelopes_cross_real_particl_smsg_v2(self):
        with tempfile.TemporaryDirectory(prefix="basicswap-hns-smsg-") as directory:
            root = Path(directory)
            sender = ParticlNode(
                root / "sender",
                os.environ["PARTICLD_BIN"],
                os.environ["PARTICL_CLI_BIN"],
            )
            try:
                receiver = ParticlNode(
                    root / "receiver",
                    os.environ["PARTICLD_BIN"],
                    os.environ["PARTICL_CLI_BIN"],
                    sender.p2p_port,
                )
                try:
                    wait_for(
                        lambda: (
                            sender.rpc("getconnectioncount") > 0
                            and receiver.rpc("getconnectioncount") > 0
                        ),
                        "Particl peers",
                        30,
                    )
                    from_address = sender.rpc("getnewaddress")
                    to_address = receiver.rpc("getnewaddress")
                    sender.rpc("smsgaddlocaladdress", from_address)
                    receiver.rpc("smsgaddlocaladdress", to_address)
                    receiver_pubkey = b58decode(
                        receiver.rpc("smsggetpubkey", to_address)["publickey"]
                    )
                    sender_pubkey = b58decode(
                        sender.rpc("smsggetpubkey", from_address)["publickey"]
                    )
                    self.assertEqual(len(receiver_pubkey), 33)
                    self.assertEqual(len(sender_pubkey), 33)
                    offer = OfferMessage()
                    offer.protocol_version = 5
                    offer.coin_from = int(Coins.HNS)
                    offer.coin_to = int(Coins.BTC)
                    offer.amount_from = 2_000_000
                    offer.amount_to = 100_000
                    offer.min_bid_amount = offer.amount_from
                    offer.time_valid = 3600
                    offer.lock_type = int(TxLockTypes.ABS_LOCK_TIME)
                    offer.lock_value = 24 * 3600
                    offer.swap_type = int(SwapTypes.HNS_BTC_SWAP)
                    offer.fee_rate_to = 1000
                    offer.message_nets = "smsg"
                    payload = bytes((MessageTypes.OFFER,)) + offer.to_bytes()
                    options = {
                        "decodehex": True,
                        "ttl_is_seconds": True,
                        "payload_format_version": 2,
                        "compression": 0,
                        "returnmsg": True,
                    }
                    sent = sender.rpc(
                        "smsgsend",
                        from_address,
                        receiver_pubkey.hex(),
                        payload.hex(),
                        "false",
                        3600,
                        "false",
                        json.dumps(options),
                    )
                    message_id = sent["msgid"]

                    def received():
                        inbox = receiver.rpc(
                            "smsginbox",
                            "all",
                            "",
                            json.dumps({"encoding": "hex", "pubkey_from": True}),
                        )
                        return next(
                            (
                                message
                                for message in inbox.get("messages", [])
                                if message.get("msgid") == message_id
                            ),
                            None,
                        )

                    try:
                        message = wait_for(received, "HNS offer over Particl SMSG", 45)
                    except AssertionError as exc:
                        inbox = receiver.rpc(
                            "smsginbox",
                            "all",
                            "",
                            json.dumps({"encoding": "hex", "pubkey_from": True}),
                        )
                        self.fail(
                            f"{exc}; sent={sent}; inbox={inbox}; "
                            f"local_keys={receiver.rpc('smsglocalkeys')}"
                        )
                    self.assertEqual(message.get("payloadversion"), 2)
                    self.assertEqual(bytes.fromhex(message["hex"]), payload)
                    self.assertEqual(message["to"], to_address)
                    self.assertEqual(message["from"], from_address)
                    self.assertEqual(
                        bytes.fromhex(message["pubkey_from"]), sender_pubkey
                    )

                    app = FakeApp(root / "received-offer.sqlite")
                    app.now = int(time.time())
                    app.network_addr = to_address
                    app._debug_cases = []
                    app.getSmsgMsgBytes = lambda msg: BSXNetwork.getSmsgMsgBytes(
                        app, msg
                    )
                    app.getSmsgMsgPayloadVersion = lambda msg: (
                        BSXNetwork.getSmsgMsgPayloadVersion(app, msg)
                    )
                    app.getOffer = lambda offer_id, cursor=None: app.queryOne(
                        Offer, cursor, {"offer_id": offer_id}
                    )
                    app.isOfferRevoked = lambda *_args: False
                    app.notify = lambda *_args: None
                    app.addMessageNetworkLink = lambda *_args: None
                    app.is_reverse_ads_bid = lambda *_args: False
                    app.validateSwapType = lambda *args: BasicSwap.validateSwapType(
                        app, *args
                    )
                    app.validateOfferAmounts = lambda *_args: None
                    app.validateOfferLockValue = lambda *args: (
                        BasicSwap.validateOfferLockValue(app, *args)
                    )
                    app.validateOfferValidTime = lambda *args: (
                        BasicSwap.validateOfferValidTime(app, *args)
                    )
                    app.validateMessageNets = lambda *args: (
                        BasicSwap.validateMessageNets(app, *args)
                    )
                    app.coin.validateFeeRate = lambda *_args: None
                    app.coin.make_int = lambda value, r=0: round(value * 1_000_000)
                    BasicSwap.processOffer(app, dict(message, type="smsg"))
                    with closing(sqlite3.connect(app.path)) as connection:
                        stored = app.queryOne(
                            Offer,
                            connection.cursor(),
                            {"offer_id": bytes.fromhex(message_id)},
                        )
                    self.assertEqual(stored.swap_type, SwapTypes.HNS_BTC_SWAP)
                    self.assertEqual(stored.pk_from, sender_pubkey)

                    app.offer = stored
                    app.getOffer = lambda offer_id, cursor=None: (
                        app.offer if offer_id == app.offer.offer_id else None
                    )
                    app.prepareSMSGAddress = lambda *_args: to_address
                    taker_key = decodeWif(receiver.rpc("dumpprivkey", to_address))

                    def encrypt_bid(
                        _app,
                        addr_from,
                        addr_to,
                        payload,
                        ttl,
                        _cursor,
                        timestamp,
                        deterministic,
                    ):
                        self.assertEqual(
                            (addr_from, addr_to), (to_address, from_address)
                        )
                        return smsgEncrypt(
                            taker_key,
                            sender_pubkey,
                            payload,
                            smsg_timestamp=timestamp,
                            deterministic=deterministic,
                            smsg_ttl=ttl,
                        )

                    def import_bid(method, params):
                        self.assertEqual(method, "smsgimport")
                        return receiver.rpc(method, params[0], json.dumps(params[1]))

                    app.callrpc = import_bid
                    with patch(
                        "basicswap.interface.hns.app_protocol.encryptMsg", encrypt_bid
                    ):
                        bid_id = BasicSwap.postBid(
                            app, stored.offer_id, stored.amount_from, None, {}
                        )
                    with closing(sqlite3.connect(app.path)) as connection:
                        sent_bid = app.queryOne(
                            Bid, connection.cursor(), {"bid_id": bid_id}
                        )
                        outbox = app.queryOne(
                            HnsBtcOutbox,
                            connection.cursor(),
                            {"message_id": bid_id},
                        )
                    self.assertIsNotNone(outbox.delivered_at)
                    self.assertEqual(sent_bid.bid_addr, to_address)

                    def maker_received_bid():
                        inbox = sender.rpc(
                            "smsginbox",
                            "all",
                            "",
                            json.dumps({"encoding": "hex", "pubkey_from": True}),
                        )
                        return next(
                            (
                                candidate
                                for candidate in inbox.get("messages", [])
                                if candidate.get("msgid") == bid_id.hex()
                            ),
                            None,
                        )

                    inbound_bid = wait_for(
                        maker_received_bid, "BasicSwap bid over Particl SMSG", 45
                    )
                    maker_app = FakeApp(root / "maker-app.sqlite", maker=True)
                    maker_app.now = int(time.time())
                    maker_app.offer = Offer(**vars(stored))
                    maker_app.offer.was_sent = True
                    maker_app.getSmsgMsgBytes = lambda msg: BSXNetwork.getSmsgMsgBytes(
                        maker_app, msg
                    )
                    maker_app.getSmsgMsgPayloadVersion = lambda msg: (
                        BSXNetwork.getSmsgMsgPayloadVersion(maker_app, msg)
                    )
                    cursor = maker_app.openDB()
                    try:
                        maker_app.add(maker_app.offer, cursor)
                    finally:
                        maker_app.closeDB(cursor)
                    self.assertEqual(
                        receive_hns_btc_bid(maker_app, dict(inbound_bid, type="smsg")),
                        bid_id,
                    )
                    with closing(sqlite3.connect(maker_app.path)) as connection:
                        received_bid = maker_app.queryOne(
                            HnsBtcSwap,
                            connection.cursor(),
                            {"bid_id": bid_id},
                        )
                    self.assertIsNotNone(received_bid)

                    routes = (
                        (
                            receiver,
                            sender,
                            to_address,
                            sender_pubkey,
                            MessageTypes.HNS_BTC_BID,
                        ),
                        (
                            sender,
                            receiver,
                            from_address,
                            receiver_pubkey,
                            MessageTypes.HNS_BTC_BID_ACCEPT,
                        ),
                        (
                            receiver,
                            sender,
                            to_address,
                            sender_pubkey,
                            MessageTypes.HNS_BTC_SECOND_LOCK,
                        ),
                    )
                    for source, destination, source_address, public_key, kind in routes:
                        with self.subTest(message_type=kind):
                            sender_key = source.rpc("dumpprivkey", source_address)
                            self.assertIsInstance(sender_key, str)
                            payload = bytes((kind,)) + b"outbox delivery"
                            encrypted = smsgEncrypt(
                                decodeWif(sender_key),
                                public_key,
                                payload,
                                smsg_timestamp=int(time.time()),
                                deterministic=True,
                                smsg_ttl=3600,
                            )
                            exact_id = smsgGetID(encrypted).hex()
                            imported = source.rpc(
                                "smsgimport",
                                encrypted.hex(),
                                json.dumps({"submitmsg": True, "rehashmsg": False}),
                            )
                            self.assertEqual(imported["msgid"], exact_id)

                            def received_exact(node=destination, expected_id=exact_id):
                                inbox = node.rpc(
                                    "smsginbox",
                                    "all",
                                    "",
                                    json.dumps(
                                        {"encoding": "hex", "pubkey_from": True}
                                    ),
                                )
                                return next(
                                    (
                                        candidate
                                        for candidate in inbox.get("messages", [])
                                        if candidate.get("msgid") == expected_id
                                    ),
                                    None,
                                )

                            exact = wait_for(
                                received_exact, "exact HNS outbox SMSG", 45
                            )
                            self.assertEqual(bytes.fromhex(exact["hex"]), payload)
                finally:
                    receiver.close()
            finally:
                sender.close()


if __name__ == "__main__":
    unittest.main()
