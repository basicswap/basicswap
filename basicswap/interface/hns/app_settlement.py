"""Restartable BasicSwap scheduling for the native HNS/BTC value path.

Every chain action is driven from the persisted bid and swap record. The
settlement controller checks the peer's confirmed lock and stores signed
Bitcoin bytes before broadcast; the Handshake bridge owns its own journal.
"""

from decimal import ROUND_CEILING, Decimal

from basicswap.basicswap_util import BidStates, KeyTypes, MessageTypes, SwapTypes
from basicswap.chainparams import Coins
from basicswap.db import Bid, HnsBtcSwap, Offer
from basicswap.network.simplex import encryptMsg

from .app_protocol import (
    _hns_btc_offer_pair,
    _persist_trade,
    accept_hns_btc_bid,
    deliver_hns_app_message,
)
from .node_rpc import hns_network_binding
from .outbox import prepare_hns_outbox_message
from .settlement import HnsBtcSettlement
from .trade_protocol import make_second_lock_message, restore_maker_terms
from .trade_record import MAKER, TAKER, restore_trade


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
    if record.role == MAKER and record.accept_message is None and record.phase >= 1:
        terms = restore_maker_terms(
            record, hns_first, hns_amount, btc_amount, app.getTime(), magic, genesis
        )
    else:
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


def _btc_spend_args(app, bid, offer, record, field):
    """Bound a Core fee estimate and use the durable per-bid Bitcoin key."""
    if getattr(record, field) is not None:
        return {
            "btc_private_key": None,
            "btc_destination": None,
            "btc_fee_rate": None,
            "maximum_btc_fee": None,
        }
    ci = app.ci(Coins.BTC)
    fee_rate, _source = ci.get_fee_rate(2)
    sat_vbyte = Decimal(str(fee_rate)) * 100_000
    if not sat_vbyte.is_finite() or sat_vbyte <= 0:
        raise ValueError("invalid Bitcoin HTLC fee estimate")
    sat_vbyte = int(sat_vbyte.to_integral_value(rounding=ROUND_CEILING))
    maximum_rate = app.coin_clients[Coins.BTC].get("maximum_htlc_fee_rate", 100)
    maximum_fee = app.coin_clients[Coins.BTC].get("maximum_htlc_fee", 100_000)
    if (
        type(maximum_rate) is not int
        or not 1 <= maximum_rate <= 10_000
        or type(maximum_fee) is not int
        or not 0 < maximum_fee <= 10_000_000
    ):
        raise ValueError("invalid Bitcoin HTLC fee limit")
    if sat_vbyte > maximum_rate:
        raise ValueError("Bitcoin HTLC fee estimate exceeds configured limit")
    key = app.getPathKey(
        Coins(offer.coin_from),
        Coins(offer.coin_to),
        bid.created_at,
        bid.contract_count,
        KeyTypes.HNS_BTC,
    )
    return {
        "btc_private_key": key,
        "btc_destination": ci.getNewAddress(True, "hns_btc_swap"),
        "btc_fee_rate": sat_vbyte,
        "maximum_btc_fee": maximum_fee,
    }


def _spend_scan_start(bid, offer):
    height = (
        bid.chain_a_height_start
        if offer.coin_from == Coins.BTC
        else bid.chain_b_height_start
    )
    if type(height) is not int or height < 0:
        raise ValueError("missing Bitcoin swap scan start height")
    return max(0, height - 2)


def _observe_spend(settlement, bid, offer, owned):
    coin = settlement.own_coin if owned else settlement.peer_coin
    if coin == "hns":
        if owned:
            return settlement.observe_own_lock_spend()
        result = settlement.hns_bridge.observe_spend(
            settlement.terms.hns_wallet_terms(),
            settlement.record.hns_lock_txid,
            settlement.terms.minimum_hns_confirmations,
        )
        if result is None:
            return None
        branch, txid, confirmations, preimage = result
        if confirmations < settlement.terms.minimum_hns_confirmations:
            return None
        from .settlement import ObservedSwapSpend

        return ObservedSwapSpend(branch, txid, confirmations, preimage)
    start = _spend_scan_start(bid, offer)
    if owned:
        return settlement.scan_own_btc_lock_spend(start)
    return settlement.scan_peer_btc_lock_spend(start)


def _set_bid_state(app, bid, state):
    if bid.state == state:
        return
    cursor = app.openDB()
    try:
        current = app.queryOne(Bid, cursor, {"bid_id": bid.bid_id})
        if current is None:
            raise ValueError("HNS/BTC bid disappeared")
        if current.state != state:
            current.setState(state)
            app.updateDB(current, cursor, ["bid_id"])
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)


def _refund_submitted(settlement):
    record = settlement.record
    if settlement.own_coin == "btc":
        return record.btc_refund_tx is not None
    return (
        settlement.hns_bridge.submitted_spend(
            settlement.terms.hns_wallet_terms(), record.hns_lock_txid, refund=True
        )
        is not None
    )


def _maybe_refund(app, bid, offer, record, terms, settlement, magic, genesis):
    own_txid = (
        record.hns_lock_txid if settlement.own_coin == "hns" else record.btc_lock_txid
    )
    if own_txid is None:
        return False
    first, second = terms.validate(app.getTime(), magic, genesis, False)
    own_deadline = first if record.role == MAKER else second
    if not _refund_submitted(settlement) and settlement._chain_now() < own_deadline:
        return False
    kwargs = (
        _btc_spend_args(app, bid, offer, record, "btc_refund_tx")
        if settlement.own_coin == "btc"
        else {}
    )
    settlement.refund_owned_lock(_maximum_hns_fee(app), **kwargs)
    return True


def _peer_redeem_confirmed(settlement, bid, offer):
    spend = _observe_spend(settlement, bid, offer, owned=False)
    if spend is None:
        return False
    if spend.branch != "redeem" or spend.preimage != settlement.record.secret_preimage:
        raise ValueError("peer HNS/BTC lock was not redeemed with trade preimage")
    submitted = _peer_redeem_submitted(settlement)
    if submitted != spend.txid:
        raise ValueError("peer HNS/BTC redemption differs from submitted spend")
    return True


def _peer_redeem_submitted(settlement):
    if settlement.peer_coin == "btc":
        prepared = settlement._prepared_btc("btc_redeem_tx")
        return prepared.txid if prepared is not None else None
    return settlement.hns_bridge.submitted_spend(
        settlement.terms.hns_wallet_terms(),
        settlement.record.hns_lock_txid,
        refund=False,
    )


def _progress_after_second(app, bid, offer, record, terms, settlement, magic, genesis):
    owned = _observe_spend(settlement, bid, offer, owned=True)
    if owned is not None and owned.branch == "refund":
        _set_bid_state(app, bid, BidStates.SWAP_TIMEDOUT)
        return True
    if owned is not None and owned.branch != "redeem":
        raise ValueError("unknown HNS/BTC owned lock spend")
    if owned is not None and _peer_redeem_confirmed(settlement, bid, offer):
        _set_bid_state(app, bid, BidStates.SWAP_COMPLETED)
        return True
    if record.role == MAKER:
        if not _refund_submitted(settlement):
            submitted = _peer_redeem_submitted(settlement)
            if submitted is None and not settlement.verify_lock(settlement.peer_coin):
                if owned is None:
                    return _maybe_refund(
                        app, bid, offer, record, terms, settlement, magic, genesis
                    )
                return False
            kwargs = (
                _btc_spend_args(app, bid, offer, record, "btc_redeem_tx")
                if settlement.peer_coin == "btc" and submitted is None
                else {}
            )
            settlement.redeem_peer_lock(_maximum_hns_fee(app), **kwargs)
            _set_bid_state(app, bid, BidStates.SWAP_PARTICIPATING)
    else:
        if owned is None:
            return _maybe_refund(
                app, bid, offer, record, terms, settlement, magic, genesis
            )
        kwargs = (
            _btc_spend_args(app, bid, offer, record, "btc_redeem_tx")
            if settlement.peer_coin == "btc"
            else {}
        )
        settlement.redeem_peer_lock(
            _maximum_hns_fee(app), observed_own_spend=owned, **kwargs
        )
        _set_bid_state(app, bid, BidStates.SWAP_PARTICIPATING)
    if owned is not None and _peer_redeem_confirmed(settlement, bid, offer):
        _set_bid_state(app, bid, BidStates.SWAP_COMPLETED)
        return True
    return False


def progress_hns_btc_taker(app, bid_id):
    """Verify, fund, announce, observe preimage, redeem, or refund."""
    bid, offer, record, terms, magic, genesis = _load_trade(app, bid_id)
    if record.role != TAKER or not bid.was_sent or record.accept_message is None:
        raise ValueError("incomplete taker HNS/BTC trade")
    settlement = _settlement(app, record, terms)
    if record.second_lock_message is not None:
        return _progress_after_second(
            app, bid, offer, record, terms, settlement, magic, genesis
        )
    if record.hns_lock_txid is not None and record.btc_lock_txid is not None:
        owned = _observe_spend(settlement, bid, offer, owned=True)
        if owned is not None and owned.branch == "refund":
            _set_bid_state(app, bid, BidStates.SWAP_TIMEDOUT)
            return True
    if not settlement.verify_lock(settlement.peer_coin):
        return _maybe_refund(app, bid, offer, record, terms, settlement, magic, genesis)
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
        return _maybe_refund(app, bid, offer, record, terms, settlement, magic, genesis)
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


def progress_hns_btc_maker(app, bid_id):
    """Redeem only a confirmed second lock and observe both final spends."""
    bid, offer, record, terms, magic, genesis = _load_trade(app, bid_id)
    if (
        record.role != MAKER
        or not bid.was_received
        or (record.accept_message is None and record.phase < 1)
    ):
        raise ValueError("incomplete maker HNS/BTC trade")
    settlement = _settlement(app, record, terms)
    own_txid = (
        record.hns_lock_txid if settlement.own_coin == "hns" else record.btc_lock_txid
    )
    if own_txid is None and record.accept_message is None:
        return False
    if record.second_lock_message is not None:
        return _progress_after_second(
            app, bid, offer, record, terms, settlement, magic, genesis
        )
    owned = _observe_spend(settlement, bid, offer, owned=True)
    if owned is not None:
        if owned.branch == "refund":
            _set_bid_state(app, bid, BidStates.SWAP_TIMEDOUT)
            return True
        if owned.branch != "redeem":
            raise ValueError("unknown HNS/BTC owned lock spend")
    return _maybe_refund(app, bid, offer, record, terms, settlement, magic, genesis)


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
                "WHERE o.swap_type = :swap_type "
                "AND ((s.accept_message IS NOT NULL "
                "AND b.state IN (:accepted, :initiated, :participating)) "
                "OR (s.role = :maker AND s.phase >= 1 "
                "AND s.accept_message IS NULL "
                "AND b.state NOT IN (:completed, :timedout))) "
                "ORDER BY b.created_at LIMIT :limit",
                {
                    "swap_type": int(SwapTypes.HNS_BTC_SWAP),
                    "accepted": int(BidStates.BID_ACCEPTED),
                    "initiated": int(BidStates.SWAP_INITIATED),
                    "participating": int(BidStates.SWAP_PARTICIPATING),
                    "maker": MAKER,
                    "completed": int(BidStates.SWAP_COMPLETED),
                    "timedout": int(BidStates.SWAP_TIMEDOUT),
                    "limit": limit,
                },
            )
        ]
    finally:
        app.closeDB(cursor, commit=False)
    progressed = 0
    for bid_id in bid_ids:
        try:
            cursor = app.openDB()
            try:
                row = cursor.execute(
                    "SELECT role, phase, accept_message FROM hns_btc_swaps "
                    "WHERE bid_id = :bid_id",
                    {"bid_id": bid_id},
                ).fetchone()
            finally:
                app.closeDB(cursor, commit=False)
            if row is None:
                raise ValueError("HNS/BTC trade disappeared")
            if row[0] == MAKER and row[1] >= 1 and row[2] is None:
                try:
                    accept_hns_btc_bid(app, bid_id)
                except Exception as exc:  # noqa: BLE001
                    app.log.warning(
                        "HNS/BTC maker acceptance %s pending: %s", bid_id.hex(), exc
                    )
            if row[0] == TAKER:
                progressed += bool(progress_hns_btc_taker(app, bid_id))
            elif row[0] == MAKER:
                progressed += bool(progress_hns_btc_maker(app, bid_id))
            else:
                raise ValueError("invalid HNS/BTC role")
        except Exception as exc:  # noqa: BLE001
            app.log.warning("HNS/BTC bid %s pending: %s", bid_id.hex(), exc)
    return progressed
