"""Fund and refund an HNS lock with HSD, HSRD, and the Rust wallet.

Run only through run_hns_bridge_regtest.py --hns-refund-clock. Every daemon is
isolated and advances on the same test-only realtime clock.
"""

import os
import sqlite3
import struct
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from coincurve import PrivateKey

from basicswap.basicswap import BasicSwap
from basicswap.basicswap_util import BidStates, SwapTypes, TxLockTypes
from basicswap.chainparams import Coins
from basicswap.db import Bid, HnsBtcSwap, Offer
from basicswap.interface.hns.app_protocol import receive_hns_btc_bid
from basicswap.interface.hns.app_settlement import progress_hns_btc_trades
from basicswap.interface.hns.htlc import HnsHtlc
from basicswap.interface.hns.node_rpc import HnsNodeRpc, hns_network_binding
from basicswap.interface.hns.wallet_bridge import (
    HnsBridgeTerms,
    HnsWalletBridge,
    initialize_hns_wallet,
)
from basicswap.util.smsg import smsgEncrypt
from tests.basicswap.test_hns_app_protocol import FakeApp
from tests.basicswap.test_hns_two_chain_regtest import hsd_call, mine_hns, wait_for


@unittest.skipUnless(
    all(
        os.getenv(name)
        for name in (
            "HNS_BRIDGE_BIN",
            "BASICSWAP_HNS_REGTEST_CLOCK_FILE",
            "BASICSWAP_HSRD_REGTEST_RPC",
            "BASICSWAP_HSD_CLI",
        )
    ),
    "run the isolated HNS timeout refund clock harness",
)
class HnsTimeoutRefundRegtest(unittest.TestCase):
    def test_maker_hns_lock_refunds_after_native_deadline(self):
        with tempfile.TemporaryDirectory(prefix="basicswap-hns-refund-") as directory:
            root = Path(directory)
            now = int(time.time())
            host, port = os.environ["BASICSWAP_HSRD_REGTEST_RPC"].split(":")
            self.assertEqual(host, "127.0.0.1")
            auth_file = Path(os.environ["BASICSWAP_HSRD_REGTEST_AUTH_FILE"])
            node = HnsNodeRpc(int(port), auth_file.read_text(encoding="ascii"))
            wallet_db = root / "maker.db"
            initialize_hns_wallet(
                os.environ["HNS_BRIDGE_BIN"],
                wallet_db,
                "regtest",
                0,
                "test passphrase",
            )
            bridge = HnsWalletBridge(
                os.environ["HNS_BRIDGE_BIN"],
                wallet_db,
                f"127.0.0.1:{port}",
                auth_file,
            )
            try:
                bridge.unlock("test passphrase")
                address, _ = bridge.receive("regtest")
                hsd_call(
                    "BASICSWAP_HSW_CLI",
                    "BASICSWAP_HSW_REGTEST_RPC_PORT",
                    "send",
                    address,
                    "10",
                )
                mine_hns(2)
                wait_for(
                    lambda: bridge.snapshot("regtest")[0] > 2_100_000,
                    "maker HNS wallet funding",
                )
                maker = FakeApp(root / "maker.sqlite", maker=True)
                taker = FakeApp(root / "taker.sqlite")
                btc = SimpleNamespace(
                    getChainHeight=lambda: 110,
                    rpc=lambda method, _params=None: (
                        {"mediantime": int(time.time())}
                        if method == "getblockchaininfo"
                        else None
                    ),
                )
                hns = SimpleNamespace(
                    bridge=bridge,
                    node=node,
                    walletIdentityReady=lambda: True,
                    getChainHeight=lambda: node.bound_snapshot("regtest").tip["height"],
                )
                maker.coin = hns
                maker.ci = lambda coin: hns if coin == Coins.HNS else btc
                for app, was_sent in ((maker, True), (taker, False)):
                    app.now = now
                    app.fail_first_send = False
                    app.offer = Offer(
                        offer_id=b"\x61" * 28,
                        swap_type=SwapTypes.HNS_BTC_SWAP,
                        coin_from=Coins.HNS,
                        coin_to=Coins.BTC,
                        amount_from=2_000_000,
                        amount_to=100_000,
                        rate=50_000,
                        min_bid_amount=2_000_000,
                        amount_negotiable=False,
                        rate_negotiable=False,
                        message_nets="smsg",
                        created_at=now,
                        expire_at=now + 3600,
                        addr_from="maker",
                        protocol_version=5,
                        active_ind=1,
                        was_sent=was_sent,
                        lock_type=TxLockTypes.ABS_LOCK_TIME,
                        lock_value=6 * 3600,
                    )
                    cursor = app.openDB()
                    try:
                        app.add(app.offer, cursor)
                    finally:
                        app.closeDB(cursor)

                def easy_encrypt(
                    _app, _sender, _receiver, payload, ttl, _cursor, timestamp,
                    deterministic,
                ):
                    return smsgEncrypt(
                        b"\x07" * 32,
                        PrivateKey(b"\x08" * 32).public_key.format(),
                        payload,
                        smsg_timestamp=timestamp,
                        deterministic=deterministic,
                        smsg_ttl=ttl,
                        difficulty_target=0x207FFFFF,
                    )

                with patch(
                    "basicswap.interface.hns.app_protocol.encryptMsg", easy_encrypt
                ):
                    bid_id = BasicSwap.postBid(
                        taker, maker.offer.offer_id, maker.offer.amount_from, None, {}
                    )
                with closing(sqlite3.connect(taker.path)) as connection:
                    taker_record = taker.queryOne(
                        HnsBtcSwap, connection.cursor(), {"bid_id": bid_id}
                    )
                with patch(
                    "basicswap.interface.hns.app_protocol.getMsgPubkey",
                    return_value=PrivateKey(b"\x07" * 32).public_key.format(),
                ):
                    receive_hns_btc_bid(
                        maker,
                        {
                            "raw": taker_record.bid_message,
                            "msgid": bid_id.hex(),
                            "sent": now,
                            "from": "sender",
                            "to": "maker",
                            "type": "smsg",
                        },
                    )
                with patch(
                    "basicswap.interface.hns.app_protocol.encryptMsg", easy_encrypt
                ):
                    BasicSwap.acceptBid(maker, bid_id)
                with closing(sqlite3.connect(maker.path)) as connection:
                    maker_record = maker.queryOne(
                        HnsBtcSwap, connection.cursor(), {"bid_id": bid_id}
                    )
                self.assertIsNotNone(maker_record.hns_lock_txid)
                mine_hns(2)
                magic, genesis = hns_network_binding("regtest")
                wallet_terms = HnsBridgeTerms(
                    maker_record.offer_id,
                    maker_record.bid_id,
                    maker_record.session_nonce,
                    HnsHtlc.decode(maker_record.hns_descriptor, magic, genesis),
                )
                wait_for(
                    lambda: bridge.verify_lock(
                        wallet_terms, maker_record.hns_lock_txid, 2
                    ),
                    "confirmed maker HNS lock",
                )

                clock_file = Path(os.environ["BASICSWAP_HNS_REGTEST_CLOCK_FILE"])
                with clock_file.open("r+b") as clock:
                    clock.write(struct.pack("=q", 8 * 3600))
                    clock.flush()
                maker.now = now + 8 * 3600
                before_future = node.bound_snapshot("regtest").tip["height"]
                mine_hns(12)
                wait_for(
                    lambda: node.bound_snapshot("regtest").tip["height"]
                    >= before_future + 12,
                    "HSRD future regtest blocks",
                )

                def refund_submitted():
                    progress_hns_btc_trades(maker)
                    return bridge.submitted_spend(
                        wallet_terms, maker_record.hns_lock_txid, refund=True
                    )

                wait_for(refund_submitted, "HNS timeout refund submission")
                mine_hns(2)

                def refunded():
                    progress_hns_btc_trades(maker)
                    with closing(sqlite3.connect(maker.path)) as connection:
                        bid = maker.queryOne(Bid, connection.cursor(), {"bid_id": bid_id})
                    return bid.state == BidStates.SWAP_TIMEDOUT

                wait_for(refunded, "confirmed HNS timeout refund", seconds=90)
            finally:
                bridge.close()


if __name__ == "__main__":
    unittest.main()
