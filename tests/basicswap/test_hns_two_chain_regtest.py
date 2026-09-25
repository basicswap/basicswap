"""Opt-in funded HNS/BTC settlement on isolated HSD, HSRD, and Bitcoin Core.

Run through run_hns_bridge_regtest.py --two-chain. This exercises the value
protocol in both directions; BasicSwap message routing is tested separately.
"""

import os
import sqlite3
import subprocess
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from urllib.error import URLError

from basicswap.db import DBMethods, HnsBtcSwap, create_table, extract_schema
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
from tests.basicswap.run_hns_bridge_regtest import free_port
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
                btc = CoreContractInterface(core)
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


if __name__ == "__main__":
    unittest.main()
