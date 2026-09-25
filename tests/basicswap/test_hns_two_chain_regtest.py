"""Opt-in funded HNS/BTC settlement on isolated HSD, HSRD, and Bitcoin Core.

Run through run_hns_bridge_regtest.py --two-chain. This exercises the value
protocol in both directions; BasicSwap message routing is tested separately.
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
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import URLError

from coincurve import PrivateKey

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import BidStates, MessageTypes, SwapTypes, TxLockTypes
from basicswap.chainparams import Coins
from basicswap.db import (
    Bid,
    DBMethods,
    HnsBtcOutbox,
    HnsBtcSwap,
    Offer,
    create_table,
    extract_schema,
)
from basicswap.interface.hns.app_protocol import (
    receive_hns_btc_accept,
    receive_hns_btc_bid,
    receive_hns_btc_second_lock,
)
from basicswap.interface.hns.app_settlement import progress_hns_btc_trades
from basicswap.interface.hns.node_rpc import HnsNodeRpc, hns_network_binding
from basicswap.interface.hns.settlement import HnsBtcSettlement
from basicswap.interface.hns.trade_protocol import (
    bind_sent_bid,
    make_accept_message,
    make_second_lock_message,
    prepare_maker_terms,
    prepare_taker_bid,
    receive_accept_message,
    receive_maker_bid,
    receive_second_lock_message,
)
from basicswap.interface.hns.trade_record import restore_trade
from basicswap.interface.hns.wallet_bridge import (
    HnsWalletBridge,
    initialize_hns_wallet,
)
from basicswap.util.address import b58decode, decodeWif
from basicswap.util.smsg import smsgEncrypt
from tests.basicswap.run_hns_bridge_regtest import free_port
from tests.basicswap.test_hns_app_protocol import FakeApp
from tests.basicswap.test_hns_btc_contract_regtest import (
    CoreContractInterface,
    CoreRegtest,
)


def hsd_call(variable, port_variable, *command):
    return subprocess.run(
        [
            os.environ[variable],
            "--network=regtest",
            f"--prefix={os.environ['BASICSWAP_HSD_REGTEST_PREFIX']}",
            f"--http-port={os.environ[port_variable]}",
            *command,
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=True,
    ).stdout.strip()


def mine_hns(count):
    hsd_call(
        "BASICSWAP_HSD_CLI",
        "BASICSWAP_HSD_REGTEST_RPC_PORT",
        "rpc",
        "generatetoaddress",
        str(count),
        os.environ["BASICSWAP_HSD_MINER_ADDRESS"],
    )


def wait_for(action, description, seconds=90):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = action()
            if result:
                return result
        except Exception as exc:  # noqa: BLE001
            last_error = exc
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for {description}: {last_error}")


class TradeJournal:
    """Commit every side effect to a separate peer database."""

    def __init__(self, path):
        self.path = path
        self.methods = DBMethods()
        self.writes = 0
        with closing(sqlite3.connect(self.path)) as connection, connection:
            create_table(
                connection.cursor(),
                "hns_btc_swaps",
                extract_schema()["hns_btc_swaps"],
            )

    def save(self, record):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.methods.add(record, connection.cursor(), upsert=True)
        self.writes += 1

    def load(self, session_id):
        with closing(sqlite3.connect(self.path)) as connection:
            record = self.methods.queryOne(
                HnsBtcSwap, connection.cursor(), {"session_id": session_id}
            )
        if record is None:
            raise AssertionError("HNS/BTC trade journal is missing")
        return record


class AppCoreInterface(CoreContractInterface):
    def getChainHeight(self):
        return self.rpc("getblockcount")

    def get_fee_rate(self, _target=2):
        return 0.00002, "regtest"

    def getNewAddress(self, _segwit=True, _label="hns_btc_swap"):
        return self.core.call("getnewaddress", [], "swap")


@unittest.skipUnless(
    all(
        os.getenv(name)
        for name in (
            "HNS_BRIDGE_BIN",
            "BITCOIND_BIN",
            "BASICSWAP_HSRD_REGTEST_RPC",
            "BASICSWAP_HSD_CLI",
        )
    ),
    "run the isolated two-chain regtest harness",
)
class HnsTwoChainRegtest(unittest.TestCase):
    def test_funded_trade_both_directions(self):
        with tempfile.TemporaryDirectory(prefix="basicswap-hns-two-chain-") as temp:
            root = Path(temp)
            btc_rpc, btc_p2p = free_port(), free_port()
            bitcoind = subprocess.Popen(
                [
                    os.environ["BITCOIND_BIN"],
                    "-regtest",
                    f"-datadir={root}",
                    f"-rpcport={btc_rpc}",
                    f"-port={btc_p2p}",
                    "-server=1",
                    "-txindex=1",
                    "-fallbackfee=0.0001",
                    "-printtoconsole=0",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            core = CoreRegtest(btc_rpc, root / "regtest" / ".cookie")
            try:
                wait_for(
                    lambda: core.call("getblockchaininfo"),
                    "Bitcoin Core startup",
                    30,
                )
                core.call("createwallet", ["swap"])
                miner = core.call("getnewaddress", [], "swap")
                core.call("generatetoaddress", [105, miner])
                btc = AppCoreInterface(core)
                host, port = os.environ["BASICSWAP_HSRD_REGTEST_RPC"].split(":")
                self.assertEqual(host, "127.0.0.1")
                auth_file = Path(os.environ["BASICSWAP_HSRD_REGTEST_AUTH_FILE"])
                node = HnsNodeRpc(int(port), auth_file.read_text(encoding="ascii"))
                magic, genesis = hns_network_binding("regtest")
                bridges = []
                for label in ("maker", "taker"):
                    database = root / f"{label}.db"
                    initialize_hns_wallet(
                        os.environ["HNS_BRIDGE_BIN"],
                        database,
                        "regtest",
                        0,
                        "test passphrase",
                    )
                    bridge = HnsWalletBridge(
                        os.environ["HNS_BRIDGE_BIN"],
                        database,
                        f"127.0.0.1:{port}",
                        auth_file,
                    )
                    bridges.append(bridge)
                    bridge.unlock("test passphrase")
                    address, _ = bridge.receive("regtest")
                    hsd_call(
                        "BASICSWAP_HSW_CLI",
                        "BASICSWAP_HSW_REGTEST_RPC_PORT",
                        "send",
                        address,
                        "10",
                    )
                try:
                    mine_hns(2)
                    for bridge in bridges:
                        wait_for(
                            lambda b=bridge: b.snapshot("regtest")[0] > 2_100_000,
                            "HNS wallet funding",
                        )
                    smsg = None
                    if bool(os.getenv("PARTICLD_BIN")) != bool(
                        os.getenv("PARTICL_CLI_BIN")
                    ):
                        raise ValueError(
                            "set both PARTICLD_BIN and PARTICL_CLI_BIN for live SMSG"
                        )
                    if os.getenv("PARTICLD_BIN") and os.getenv("PARTICL_CLI_BIN"):
                        from tests.basicswap.test_hns_particl_smsg_regtest import (
                            ParticlNode,
                        )

                        maker_smsg = ParticlNode(
                            root / "particl-maker",
                            os.environ["PARTICLD_BIN"],
                            os.environ["PARTICL_CLI_BIN"],
                        )
                        try:
                            taker_smsg = ParticlNode(
                                root / "particl-taker",
                                os.environ["PARTICLD_BIN"],
                                os.environ["PARTICL_CLI_BIN"],
                                maker_smsg.p2p_port,
                            )
                        except Exception:
                            maker_smsg.close()
                            raise
                        try:
                            wait_for(
                                lambda: (
                                    maker_smsg.rpc("getconnectioncount") > 0
                                    and taker_smsg.rpc("getconnectioncount") > 0
                                ),
                                "Particl SMSG peers",
                                30,
                            )
                            maker_address = maker_smsg.rpc("getnewaddress")
                            taker_address = taker_smsg.rpc("getnewaddress")
                            maker_smsg.rpc("smsgaddlocaladdress", maker_address)
                            taker_smsg.rpc("smsgaddlocaladdress", taker_address)
                            smsg = {
                                "maker": maker_smsg,
                                "taker": taker_smsg,
                                "maker_address": maker_address,
                                "taker_address": taker_address,
                                "keys": {
                                    maker_address: decodeWif(
                                        maker_smsg.rpc("dumpprivkey", maker_address)
                                    ),
                                    taker_address: decodeWif(
                                        taker_smsg.rpc("dumpprivkey", taker_address)
                                    ),
                                },
                                "public_keys": {
                                    maker_address: b58decode(
                                        maker_smsg.rpc("smsggetpubkey", maker_address)[
                                            "publickey"
                                        ]
                                    ),
                                    taker_address: b58decode(
                                        taker_smsg.rpc("smsggetpubkey", taker_address)[
                                            "publickey"
                                        ]
                                    ),
                                },
                            }
                        except Exception:
                            taker_smsg.close()
                            maker_smsg.close()
                            raise
                    try:
                        for hns_first in (True, False):
                            with self.subTest(hns_first=hns_first):
                                self.run_trade(
                                    hns_first,
                                    bridges[0],
                                    bridges[1],
                                    node,
                                    btc,
                                    core,
                                    miner,
                                    magic,
                                    genesis,
                                    root,
                                )
                                self.run_app_trade(
                                    hns_first,
                                    bridges[0],
                                    bridges[1],
                                    node,
                                    btc,
                                    core,
                                    miner,
                                    root,
                                    smsg,
                                )
                    finally:
                        if smsg is not None:
                            smsg["taker"].close()
                            smsg["maker"].close()
                finally:
                    for bridge in bridges:
                        bridge.close()
            finally:
                try:
                    core.call("stop")
                except (OSError, URLError, FileNotFoundError):
                    pass
                try:
                    bitcoind.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    bitcoind.terminate()
                    bitcoind.wait(timeout=5)

    def run_trade(
        self,
        hns_first,
        maker_bridge,
        taker_bridge,
        node,
        btc,
        core,
        miner,
        magic,
        genesis,
        root,
    ):
        now = int(time.time())
        marker = b"\x01" if hns_first else b"\x02"
        offer_id, bid_id = marker * 28, (marker[0] + 2).to_bytes(1, "big") * 28
        nonce, secret = marker * 32, (marker[0] + 4).to_bytes(1, "big") * 32
        maker_btc_key, taker_btc_key = b"\x11" * 32, b"\x22" * 32
        hns_amount, btc_amount = 2_000_000, 100_000
        taker, bid_raw = prepare_taker_bid(
            offer_id,
            hns_first,
            hns_amount,
            btc_amount,
            taker_btc_key,
            taker_bridge,
            now,
            session_nonce=nonce,
            hns_network="regtest",
        )
        maker_journal = TradeJournal(root / f"maker-{marker.hex()}.sqlite")
        taker_journal = TradeJournal(root / f"taker-{marker.hex()}.sqlite")
        taker_journal.save(taker)
        bind_sent_bid(taker, bid_id)
        taker_journal.save(taker)
        maker = receive_maker_bid(offer_id, bid_id, bid_raw, now, now)
        maker_journal.save(maker)
        terms = prepare_maker_terms(
            maker,
            hns_first,
            hns_amount,
            btc_amount,
            maker_btc_key,
            maker_bridge,
            secret,
            now + 24 * 3600,
            now + 12 * 3600,
            now,
            magic,
            genesis,
            "regtest",
        )
        maker_journal.save(maker)
        self.assertEqual(maker.secret_preimage, secret)
        maker_value = HnsBtcSettlement(
            maker,
            terms,
            btc,
            maker_bridge,
            node,
            "regtest",
            maker_journal.save,
        )
        maker_value.fund_owned_lock(100_000)
        if hns_first:
            mine_hns(2)
        else:
            core.call("generatetoaddress", [2, miner])
        wait_for(
            lambda: maker_value.verify_lock(maker_value.own_coin),
            "confirmed first lock",
        )
        accept_raw = make_accept_message(maker, terms, now, magic, genesis)
        maker_journal.save(maker)
        received = receive_accept_message(
            taker,
            accept_raw,
            hns_first,
            hns_amount,
            btc_amount,
            int(time.time()),
            magic,
            genesis,
        )
        taker_journal.save(taker)
        self.assertEqual(received, terms)
        taker_value = HnsBtcSettlement(
            taker,
            received,
            btc,
            taker_bridge,
            node,
            "regtest",
            taker_journal.save,
        )
        taker_value.fund_owned_lock(100_000)
        if hns_first:
            core.call("generatetoaddress", [2, miner])
        else:
            mine_hns(2)
        wait_for(
            lambda: taker_value.verify_lock(taker_value.own_coin),
            "confirmed second lock",
        )
        second_raw = make_second_lock_message(
            taker, terms, int(time.time()), magic, genesis
        )
        taker_journal.save(taker)
        receive_second_lock_message(
            maker, terms, second_raw, int(time.time()), magic, genesis
        )
        maker_journal.save(maker)
        maker = maker_journal.load(maker.session_id)
        taker = taker_journal.load(taker.session_id)
        for record in (maker, taker):
            recovered, _ = restore_trade(
                record,
                hns_first,
                hns_amount,
                btc_amount,
                int(time.time()),
                magic,
                genesis,
            )
            self.assertEqual(recovered, terms)
        maker_value = HnsBtcSettlement(
            maker, terms, btc, maker_bridge, node, "regtest", maker_journal.save
        )
        taker_value = HnsBtcSettlement(
            taker, terms, btc, taker_bridge, node, "regtest", taker_journal.save
        )
        btc_scan_start = core.call("getblockcount") - 1
        maker_value.redeem_peer_lock(
            100_000,
            btc_private_key=maker_btc_key,
            btc_destination=core.call("getnewaddress", [], "swap"),
            btc_fee_rate=2,
            maximum_btc_fee=10_000,
        )
        if hns_first:
            core.call("generatetoaddress", [2, miner])
            observed = taker_value.observe_own_lock_spend(
                btc_scan_start, core.call("getblockcount") - 1
            )
        else:
            mine_hns(2)
            observed = wait_for(
                taker_value.observe_own_lock_spend,
                "confirmed HNS preimage reveal",
            )
        self.assertEqual(observed.branch, "redeem")
        self.assertEqual(observed.preimage, secret)
        taker_value.redeem_peer_lock(
            100_000,
            observed_own_spend=observed,
            btc_private_key=taker_btc_key,
            btc_destination=core.call("getnewaddress", [], "swap"),
            btc_fee_rate=2,
            maximum_btc_fee=10_000,
        )
        if hns_first:
            mine_hns(2)
            maker_observed = wait_for(
                maker_value.observe_own_lock_spend,
                "confirmed HNS taker redemption",
            )
        else:
            core.call("generatetoaddress", [2, miner])
            maker_observed = maker_value.observe_own_lock_spend(
                btc_scan_start, core.call("getblockcount") - 1
            )
        self.assertEqual(maker_observed.branch, "redeem")
        self.assertEqual(maker_observed.preimage, secret)
        self.assertGreater(maker_journal.writes, 4)
        self.assertGreater(taker_journal.writes, 4)

    def run_app_trade(
        self,
        hns_first,
        maker_bridge,
        taker_bridge,
        node,
        btc,
        core,
        miner,
        root,
        smsg=None,
    ):
        """Drive the BasicSwap bid, message, and worker route with live chains."""
        now = int(time.time())
        marker = b"\x41" if hns_first else b"\x42"
        offer_id = marker * 28
        hns_amount, btc_amount = 2_000_000, 100_000
        coin_from = Coins.HNS if hns_first else Coins.BTC
        coin_to = Coins.BTC if hns_first else Coins.HNS
        maker = FakeApp(root / f"app-maker-{marker.hex()}.sqlite", maker=True)
        taker = FakeApp(root / f"app-taker-{marker.hex()}.sqlite")
        def configure(app, bridge):
            app.now = now
            hns_ci = SimpleNamespace(
                bridge=bridge,
                node=node,
                walletIdentityReady=lambda: True,
                getChainHeight=lambda: node.bound_snapshot("regtest").tip["height"],
            )
            app.coin = hns_ci
            app.ci = lambda coin, hns=hns_ci: hns if coin == Coins.HNS else btc
            app.fail_first_send = False
            if smsg is not None:
                role = "maker" if app.maker else "taker"
                address = smsg[f"{role}_address"]
                app.prepareSMSGAddress = lambda *_args, addr=address: addr
                particl_peer = smsg[role]
                app.callrpc = lambda method, params, peer=particl_peer: peer.rpc(
                    method, params[0], json.dumps(params[1])
                )

        for app, bridge, was_sent in (
            (maker, maker_bridge, True),
            (taker, taker_bridge, False),
        ):
            configure(app, bridge)
            app.offer = Offer(
                offer_id=offer_id,
                swap_type=SwapTypes.HNS_BTC_SWAP,
                coin_from=coin_from,
                coin_to=coin_to,
                amount_from=hns_amount if hns_first else btc_amount,
                amount_to=btc_amount if hns_first else hns_amount,
                rate=50_000 if hns_first else 2_000_000_000,
                min_bid_amount=hns_amount if hns_first else btc_amount,
                amount_negotiable=False,
                rate_negotiable=False,
                message_nets="smsg",
                created_at=now,
                expire_at=now + 3600,
                addr_from=smsg["maker_address"] if smsg is not None else "maker",
                protocol_version=5,
                active_ind=1,
                was_sent=was_sent,
                lock_type=TxLockTypes.ABS_LOCK_TIME,
                lock_value=24 * 3600,
            )
            cursor = app.openDB()
            try:
                app.add(app.offer, cursor)
            finally:
                app.closeDB(cursor)

        def restart(app, bridge):
            restored = FakeApp(app.path, maker=app.maker, create_schema=False)
            configure(restored, bridge)
            restored.offer = app.offer
            return restored

        def easy_encrypt(
            _app,
            sender,
            receiver,
            payload,
            ttl,
            _cursor,
            timestamp,
            deterministic,
        ):
            if smsg is not None:
                return smsgEncrypt(
                    smsg["keys"][sender],
                    smsg["public_keys"][receiver],
                    payload,
                    smsg_timestamp=timestamp,
                    deterministic=deterministic,
                    smsg_ttl=ttl,
                )
            return smsgEncrypt(
                b"\x07" * 32,
                PrivateKey(b"\x08" * 32).public_key.format(),
                payload,
                smsg_timestamp=timestamp,
                deterministic=deterministic,
                smsg_ttl=ttl,
                difficulty_target=0x207FFFFF,
            )

        def read(app, model, constraints):
            cursor = app.openDB()
            try:
                return app.queryOne(model, cursor, constraints)
            finally:
                app.closeDB(cursor, commit=False)

        def envelope(raw, message_id, sender, receiver):
            if smsg is not None:
                peer = (
                    smsg["maker"]
                    if receiver == smsg["maker_address"]
                    else smsg["taker"]
                )

                def delivered():
                    inbox = peer.rpc(
                        "smsginbox",
                        "all",
                        "",
                        json.dumps({"encoding": "hex", "pubkey_from": True}),
                    )
                    return next(
                        (
                            item
                            for item in inbox.get("messages", [])
                            if item.get("msgid") == message_id.hex()
                        ),
                        None,
                    )

                item = wait_for(delivered, "HNS trade packet over Particl SMSG", 45)
                self.assertEqual(item.get("payloadversion"), 2)
                plaintext = bytes.fromhex(item["hex"])
                self.assertEqual(plaintext[1:], raw)
                self.assertIn(
                    plaintext[0],
                    (
                        int(MessageTypes.HNS_BTC_BID),
                        int(MessageTypes.HNS_BTC_BID_ACCEPT),
                        int(MessageTypes.HNS_BTC_SECOND_LOCK),
                    ),
                )
                self.assertEqual(item["from"], sender)
                self.assertEqual(item["to"], receiver)
                return dict(item, raw=raw, type="smsg")
            return {
                "raw": raw,
                "msgid": message_id.hex(),
                "sent": now,
                "from": sender,
                "to": receiver,
                "type": "smsg",
            }

        with patch("basicswap.interface.hns.app_protocol.encryptMsg", easy_encrypt):
            bid_id = BasicSwap.postBid(
                taker, offer_id, taker.offer.amount_from, None, {}
            )
        taker_record = read(taker, HnsBtcSwap, {"bid_id": bid_id})
        with patch(
            "basicswap.interface.hns.app_protocol.getMsgPubkey",
            return_value=(
                smsg["public_keys"][smsg["taker_address"]]
                if smsg is not None
                else PrivateKey(b"\x07" * 32).public_key.format()
            ),
        ):
            receive_hns_btc_bid(
                maker,
                envelope(
                    taker_record.bid_message,
                    bid_id,
                    smsg["taker_address"] if smsg is not None else "sender",
                    smsg["maker_address"] if smsg is not None else "maker",
                ),
            )
        with (
            patch(
                "basicswap.interface.hns.app_protocol.make_accept_message",
                side_effect=RuntimeError("simulated interruption after first funding"),
            ),
            self.assertRaisesRegex(RuntimeError, "simulated interruption"),
        ):
            BasicSwap.acceptBid(maker, bid_id)
        pending = read(maker, HnsBtcSwap, {"bid_id": bid_id})
        self.assertEqual(pending.phase, 1)
        self.assertIsNone(pending.accept_message)
        maker = restart(maker, maker_bridge)
        with patch("basicswap.interface.hns.app_protocol.encryptMsg", easy_encrypt):
            wait_for(
                lambda: (
                    progress_hns_btc_trades(maker),
                    read(maker, HnsBtcSwap, {"bid_id": bid_id}).accept_message,
                )[1],
                "maker acceptance after restart",
            )
        maker_record = read(maker, HnsBtcSwap, {"bid_id": bid_id})
        accept_id = read(
            maker,
            HnsBtcOutbox,
            {
                "session_id": maker_record.session_id,
                "message_type": int(MessageTypes.HNS_BTC_BID_ACCEPT),
            },
        ).message_id
        accept_row = read(maker, HnsBtcOutbox, {"message_id": accept_id})
        self.assertIsNotNone(accept_row.delivered_at)
        receive_hns_btc_accept(
            taker,
            envelope(
                maker_record.accept_message,
                accept_id,
                smsg["maker_address"] if smsg is not None else "maker",
                smsg["taker_address"] if smsg is not None else "sender",
            ),
        )
        if hns_first:
            mine_hns(2)
        else:
            core.call("generatetoaddress", [2, miner])

        second_coin = "btc" if hns_first else "hns"

        def second_funded():
            progress_hns_btc_trades(taker)
            record = read(taker, HnsBtcSwap, {"bid_id": bid_id})
            return record.btc_lock_txid if hns_first else record.hns_lock_txid

        wait_for(second_funded, "app taker funding")
        taker = restart(taker, taker_bridge)
        second_confirmation = None
        if hns_first:
            second_confirmation = core.call("generatetoaddress", [2, miner])
        else:
            mine_hns(2)
        with patch("basicswap.interface.hns.app_settlement.encryptMsg", easy_encrypt):
            wait_for(
                lambda: progress_hns_btc_trades(taker),
                "app confirmed second lock announcement",
            )
        taker_record = read(taker, HnsBtcSwap, {"bid_id": bid_id})
        second_row = read(
            taker,
            HnsBtcOutbox,
            {
                "session_id": taker_record.session_id,
                "message_type": int(MessageTypes.HNS_BTC_SECOND_LOCK),
            },
        )
        self.assertIsNotNone(second_row.delivered_at)
        receive_hns_btc_second_lock(
            maker,
            envelope(
                taker_record.second_lock_message,
                second_row.message_id,
                smsg["taker_address"] if smsg is not None else "sender",
                smsg["maker_address"] if smsg is not None else "maker",
            ),
        )
        if hns_first:
            core.call("invalidateblock", [second_confirmation[0]])
            progress_hns_btc_trades(maker)
            unsettled = read(maker, HnsBtcSwap, {"bid_id": bid_id})
            self.assertIsNone(unsettled.btc_redeem_tx)
            core.call("reconsiderblock", [second_confirmation[0]])

        def maker_redeemed():
            progress_hns_btc_trades(maker)
            return read(maker, Bid, {"bid_id": bid_id}).state in (
                BidStates.SWAP_PARTICIPATING,
                BidStates.SWAP_COMPLETED,
            )

        wait_for(maker_redeemed, f"app maker redeeming {second_coin}")
        maker = restart(maker, maker_bridge)
        if hns_first:
            core.call("generatetoaddress", [2, miner])
        else:
            mine_hns(2)

        def taker_redeemed():
            progress_hns_btc_trades(taker)
            return read(taker, Bid, {"bid_id": bid_id}).state in (
                BidStates.SWAP_PARTICIPATING,
                BidStates.SWAP_COMPLETED,
            )

        wait_for(taker_redeemed, "app taker recovering preimage and redeeming")
        if hns_first:
            mine_hns(2)
        else:
            core.call("generatetoaddress", [2, miner])

        def both_completed():
            progress_hns_btc_trades(maker)
            progress_hns_btc_trades(taker)
            return all(
                read(app, Bid, {"bid_id": bid_id}).state == BidStates.SWAP_COMPLETED
                for app in (maker, taker)
            )

        wait_for(both_completed, "both app bids completing")


if __name__ == "__main__":
    unittest.main()
