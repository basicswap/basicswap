"""Restartable BasicSwap scheduling for the native HNS/BTC value path.

Every chain action is driven from the persisted bid and swap record. The
settlement controller checks the peer's confirmed lock and stores signed
Bitcoin bytes before broadcast; the Handshake bridge owns its own journal.
"""

from basicswap.basicswap_util import BidStates, MessageTypes, SwapTypes
from basicswap.chainparams import Coins
from basicswap.db import Bid, HnsBtcSwap, Offer
from basicswap.network.simplex import encryptMsg

from .app_protocol import (
    _hns_btc_offer_pair,
    _persist_trade,
    deliver_hns_app_message,
)
from .node_rpc import hns_network_binding
from .outbox import prepare_hns_outbox_message
from .settlement import HnsBtcSettlement
from .trade_protocol import make_second_lock_message
from .trade_record import TAKER, restore_trade


def _load_trade(app, bid_id):
    cursor = app.openDB()
    try:
        bid = app.queryOne(Bid, cursor, {"bid_id": bid_id})
        record = app.queryOne(HnsBtcSwap, cursor, {"bid_id": bid_id})
        offer = (
            app.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
            if bid is not None
            else None
        )
    finally:
        app.closeDB(cursor, commit=False)
    if bid is None or record is None or offer is None:
        raise ValueError("incomplete HNS/BTC trade")
    hns_first = _hns_btc_offer_pair(offer)
    hns_amount = bid.amount if hns_first else bid.amount_to
    btc_amount = bid.amount_to if hns_first else bid.amount
    magic, genesis = hns_network_binding(app.chain)
    terms, _ = restore_trade(
        record, hns_first, hns_amount, btc_amount, app.getTime(), magic, genesis
    )
    return bid, offer, record, terms, magic, genesis


def _settlement(app, record, terms):
    hns_ci, btc_ci = app.ci(Coins.HNS), app.ci(Coins.BTC)
    if not hns_ci.walletIdentityReady():
        raise ValueError("HNS wallet is locked or has an unknown seed")
    if app.coin_clients[Coins.BTC]["connection_type"] != "rpc":
        raise ValueError("HNS/BTC requires Bitcoin Core RPC")
    return HnsBtcSettlement(
        record,
        terms,
        btc_ci,
        hns_ci.bridge,
        hns_ci.node,
        app.chain,
        lambda changed: _persist_trade(app, changed),
    )


def _maximum_hns_fee(app):
    value = app.coin_clients[Coins.HNS].get("maximum_htlc_fee", 100_000)
    if type(value) is not int or not 0 < value <= 10_000_000:
        raise ValueError("invalid maximum HNS HTLC fee")
    return value


def progress_hns_btc_taker(app, bid_id):
    """Verify the first lock, fund once, then announce the confirmed second."""
    bid, offer, record, terms, magic, genesis = _load_trade(app, bid_id)
    if record.role != TAKER or not bid.was_sent or record.accept_message is None:
        raise ValueError("incomplete taker HNS/BTC trade")
    if record.second_lock_message is not None:
        return False
    settlement = _settlement(app, record, terms)
    if not settlement.verify_lock(settlement.peer_coin):
        return False
    own_txid = (
        record.hns_lock_txid if settlement.own_coin == "hns" else record.btc_lock_txid
    )
    if own_txid is None and record.btc_funding_tx is None:
        now = settlement._chain_now()
        terms.validate(now, magic, genesis)
    settlement.fund_owned_lock(_maximum_hns_fee(app))
    if not settlement.verify_lock(settlement.own_coin):
        return False

    _, second_deadline = terms.validate(app.getTime(), magic, genesis, False)
    now = app.getTime()
    if second_deadline <= now + HnsBtcSettlement.MINIMUM_MAKER_REDEEM_MARGIN_SECONDS:
        raise ValueError("second HNS/BTC lock is too close to refund to announce")
    cursor = app.openDB()
    try:
        current = app.queryOne(HnsBtcSwap, cursor, {"session_id": record.session_id})
        if current is None or current.accept_message != record.accept_message:
            raise ValueError("HNS/BTC terms changed during second-lock funding")
        if current.second_lock_message is not None:
            app.closeDB(cursor, commit=False)
            return False
        raw = make_second_lock_message(current, terms, now, magic, genesis)
        encrypted = encryptMsg(
            app,
            bid.bid_addr,
            offer.addr_from,
            bytes((MessageTypes.HNS_BTC_SECOND_LOCK,)) + raw,
            min(48 * 3600, max(app.SMSG_SECONDS_IN_HOUR, second_deadline - now)),
            cursor,
            timestamp=now,
            deterministic=True,
        )
        outbox = prepare_hns_outbox_message(
            current.session_id,
            MessageTypes.HNS_BTC_SECOND_LOCK,
            encrypted,
            now,
            second_deadline,
        )
        app.updateDB(current, cursor, ["session_id"])
        bid.setState(BidStates.SWAP_INITIATED)
        app.updateDB(bid, cursor, ["bid_id"])
        app.add(outbox, cursor)
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)
    try:
        deliver_hns_app_message(app, outbox, app.getTime())
    except Exception as exc:  # noqa: BLE001
        app.log.warning("HNS/BTC second lock %s queued: %s", bid_id.hex(), exc)
    return True


def progress_hns_btc_trades(app, limit=100):
    """Step active trades without holding a database lock across chain calls."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("invalid HNS/BTC progress batch size")
    cursor = app.openDB()
    try:
        bid_ids = [
            row[0]
            for row in cursor.execute(
                "SELECT b.bid_id FROM bids b "
                "JOIN offers o ON o.offer_id = b.offer_id "
                "JOIN hns_btc_swaps s ON s.bid_id = b.bid_id "
                "WHERE o.swap_type = :swap_type AND s.role = :role "
                "AND s.accept_message IS NOT NULL "
                "AND s.second_lock_message IS NULL "
                "ORDER BY b.created_at LIMIT :limit",
                {
                    "swap_type": int(SwapTypes.HNS_BTC_SWAP),
                    "role": TAKER,
                    "limit": limit,
                },
            )
        ]
    finally:
        app.closeDB(cursor, commit=False)
    progressed = 0
    for bid_id in bid_ids:
        try:
            progressed += bool(progress_hns_btc_taker(app, bid_id))
        except Exception as exc:  # noqa: BLE001
            app.log.warning("HNS/BTC bid %s pending: %s", bid_id.hex(), exc)
    return progressed
