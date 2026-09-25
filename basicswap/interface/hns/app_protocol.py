"""BasicSwap database and SMSG boundary for the native HNS/BTC bid.

The bid ID is computed from encrypted bytes before the row is committed.
Network submission happens only after the bid, HNS session, and exact bytes
are durable. Later trade messages use the same outbox boundary.
"""

import datetime as dt

from basicswap.basicswap_util import (
    AddressTypes,
    BidStates,
    KeyTypes,
    MessageNetworks,
    MessageTypes,
    SwapTypes,
    TxLockTypes,
)
from basicswap.chainparams import Coins
from basicswap.db import Bid, HnsBtcOutbox, HnsBtcSwap, Offer
from basicswap.messages_npb import (
    HnsBtcBidAcceptMessage,
    HnsBtcBidMessage,
    HnsBtcSecondLockMessage,
)
from basicswap.network.simplex import encryptMsg
from basicswap.network.util import getMsgPubkey

from .node_rpc import hns_network_binding
from .outbox import deliver_hns_outbox_message, prepare_hns_outbox_message
from .settlement import HnsBtcSettlement
from .trade_protocol import (
    bind_sent_bid,
    make_accept_message,
    prepare_maker_terms,
    prepare_taker_bid,
    receive_accept_message,
    receive_maker_bid,
    receive_second_lock_message,
)
from .trade_record import MAKER, TAKER, restore_trade


def _hns_btc_offer_pair(offer):
    if offer.swap_type != SwapTypes.HNS_BTC_SWAP or frozenset(
        (offer.coin_from, offer.coin_to)
    ) != frozenset((Coins.HNS, Coins.BTC)):
        raise ValueError("offer is not a native HNS/BTC trade")
    return offer.coin_from == Coins.HNS


def _submit_exact_smsg(app, row):
    response = app.callrpc(
        "smsgimport",
        [row.message_bytes.hex(), {"submitmsg": True, "rehashmsg": False}],
    )
    if not isinstance(response, dict) or response.get("msgid") != row.message_id.hex():
        raise ValueError("HNS/BTC SMSG submission ID changed")


def _persist_trade(app, record):
    cursor = app.openDB()
    try:
        app.updateDB(record, cursor, ["session_id"])
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)


def deliver_hns_app_message(app, row, now):
    def persist(changed):
        cursor = app.openDB()
        try:
            app.updateDB(changed, cursor, ["message_id"])
        except Exception:
            app.closeDB(cursor, commit=False)
            raise
        else:
            app.closeDB(cursor)

    return deliver_hns_outbox_message(
        row, now, lambda _bytes: _submit_exact_smsg(app, row), persist
    )


def flush_hns_app_outbox(app, now, limit=100):
    """Retry committed messages after a send failure or process restart."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("invalid HNS/BTC outbox batch size")
    cursor = app.openDB()
    try:
        ids = [
            row[0]
            for row in cursor.execute(
                "SELECT message_id FROM hns_btc_outbox "
                "WHERE delivered_at IS NULL AND expire_at > :now "
                "ORDER BY created_at, message_id LIMIT :limit",
                {"now": now, "limit": limit},
            )
        ]
    finally:
        app.closeDB(cursor, commit=False)
    delivered = 0
    for message_id in ids:
        cursor = app.openDB()
        try:
            row = app.queryOne(HnsBtcOutbox, cursor, {"message_id": message_id})
        finally:
            app.closeDB(cursor, commit=False)
        if row is None or row.delivered_at is not None:
            continue
        try:
            deliver_hns_app_message(app, row, now)
            delivered += 1
        except Exception as exc:  # noqa: BLE001
            app.log.warning("HNS/BTC outbox %s pending: %s", message_id.hex(), exc)
    return delivered


def post_hns_btc_bid(app, offer, amount, addr_send_from, extra_options):
    """Persist a fixed-size taker bid and exact encrypted ID before SMSG send."""
    hns_first = _hns_btc_offer_pair(offer)
    if offer.amount_negotiable or offer.rate_negotiable or amount != offer.amount_from:
        raise ValueError("HNS/BTC currently requires a fixed full-size offer")
    active, _bridged = app.expandMessageNets(offer.message_nets)
    if MessageNetworks.SMSG not in active or app._smsg_payload_version < 2:
        raise ValueError("HNS/BTC requires active SMSG payload version 2")
    valid_for_seconds = extra_options.get("valid_for_seconds", 600)
    app.validateBidValidTime(
        offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds
    )
    coin_from, coin_to = Coins(offer.coin_from), Coins(offer.coin_to)
    ci_from, ci_to = app.ci(coin_from), app.ci(coin_to)
    amount, amount_to, rate = app.setBidAmounts(amount, offer, extra_options, ci_from)
    app.validateBidAmount(offer, amount, rate)
    if amount_to != offer.amount_to:
        raise ValueError("HNS/BTC fixed offer amount changed")
    hns_amount = amount if hns_first else amount_to
    btc_amount = amount_to if hns_first else amount
    hns_ci = app.ci(Coins.HNS)
    if not hns_ci.walletIdentityReady():
        raise ValueError("HNS wallet is locked or has an unknown seed")

    cursor = app.openDB()
    try:
        app.checkCoinsReady(coin_from, coin_to)
        now = app.getTime()
        if offer.expire_at <= now + valid_for_seconds:
            raise ValueError("HNS/BTC offer expires before the bid")
        contract_count = app.getNewContractId(cursor)
        btc_private_key = app.getPathKey(
            coin_from,
            coin_to,
            now,
            contract_count,
            KeyTypes.HNS_BTC,
        )
        record, raw_bid = prepare_taker_bid(
            offer.offer_id,
            hns_first,
            hns_amount,
            btc_amount,
            btc_private_key,
            hns_ci.bridge,
            now,
            valid_for_seconds=valid_for_seconds,
            message_nets="smsg",
            hns_network=app.chain,
        )
        bid_addr = app.prepareSMSGAddress(addr_send_from, AddressTypes.BID, cursor)
        encrypted = encryptMsg(
            app,
            bid_addr,
            offer.addr_from,
            bytes((MessageTypes.HNS_BTC_BID,)) + raw_bid,
            max(app.SMSG_SECONDS_IN_HOUR, valid_for_seconds),
            cursor,
            timestamp=now,
            deterministic=True,
        )
        outbox = prepare_hns_outbox_message(
            record.session_id,
            MessageTypes.HNS_BTC_BID,
            encrypted,
            now,
            now + valid_for_seconds,
        )
        bind_sent_bid(record, outbox.message_id)
        bid = Bid(
            bid_id=outbox.message_id,
            protocol_version=offer.protocol_version,
            active_ind=1,
            offer_id=offer.offer_id,
            amount=amount,
            amount_to=amount_to,
            rate=rate,
            created_at=now,
            contract_count=contract_count,
            expire_at=now + valid_for_seconds,
            bid_addr=bid_addr,
            was_sent=True,
            chain_a_height_start=ci_from.getChainHeight(),
            chain_b_height_start=ci_to.getChainHeight(),
            message_nets="smsg",
        )
        bid.setState(BidStates.BID_SENT)
        app.add(record, cursor)
        app.add(outbox, cursor)
        app.saveBidInSession(outbox.message_id, bid, cursor)
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)
    try:
        deliver_hns_app_message(app, outbox, app.getTime())
    except Exception as exc:  # noqa: BLE001
        app.log.warning(
            "HNS/BTC bid %s queued for retry: %s", outbox.message_id.hex(), exc
        )
    return outbox.message_id


def receive_hns_btc_bid(app, msg):
    """Bind a received SMSG bid to a sent fixed HNS/BTC offer atomically."""
    if msg.get("type", "smsg") != "smsg":
        raise ValueError("HNS/BTC bid must arrive over SMSG")
    try:
        bid_id = bytes.fromhex(msg["msgid"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid HNS/BTC bid message ID") from exc
    if len(bid_id) != 28:
        raise ValueError("invalid HNS/BTC bid message ID")
    raw = app.getSmsgMsgBytes(msg)
    wire = HnsBtcBidMessage()
    try:
        wire.from_bytes(raw)
        if wire.to_bytes() != raw:
            raise ValueError("noncanonical HNS/BTC bid")
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid HNS/BTC bid message") from exc
    offer = app.getOffer(wire.offer_msg_id)
    if offer is None or not offer.was_sent or offer.active_ind != 1:
        raise ValueError("unknown HNS/BTC offer")
    _hns_btc_offer_pair(offer)
    now = app.getTime()
    if (
        offer.expire_at <= now
        or offer.amount_negotiable
        or offer.rate_negotiable
        or msg.get("to") != offer.addr_from
        or wire.amount_from != offer.amount_from
        or wire.amount_to != offer.amount_to
        or wire.message_nets != "smsg"
    ):
        raise ValueError("HNS/BTC bid differs from fixed offer or destination")
    record = receive_maker_bid(offer.offer_id, bid_id, raw, msg["sent"], now)
    coin_from, coin_to = Coins(offer.coin_from), Coins(offer.coin_to)
    cursor = app.openDB()
    duplicate = False
    try:
        existing = app.queryOne(Bid, cursor, {"bid_id": bid_id})
        if existing is not None:
            existing_record = app.queryOne(
                type(record), cursor, {"session_id": record.session_id}
            )
            if (
                existing_record is None
                or existing_record.bid_message != raw
                or existing.offer_id != offer.offer_id
                or existing.bid_addr != msg["from"]
            ):
                raise ValueError("HNS/BTC bid replay changed")
            duplicate = True
        else:
            bid = Bid(
                bid_id=bid_id,
                active_ind=1,
                offer_id=offer.offer_id,
                protocol_version=offer.protocol_version,
                amount=offer.amount_from,
                amount_to=offer.amount_to,
                rate=offer.rate,
                created_at=msg["sent"],
                expire_at=msg["sent"] + wire.time_valid,
                bid_addr=msg["from"],
                pk_bid_addr=getMsgPubkey(app, msg),
                was_received=True,
                chain_a_height_start=app.ci(coin_from).getChainHeight(),
                chain_b_height_start=app.ci(coin_to).getChainHeight(),
                message_nets="smsg",
            )
            bid.setState(BidStates.BID_RECEIVED)
            app.add(record, cursor)
            app.saveBidInSession(bid_id, bid, cursor)
            app.addRecvBidNetworkLink(msg, bid_id, cursor)
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor, commit=not duplicate)
    return bid_id


def accept_hns_btc_bid(app, bid_id):
    """Fund the maker's first lock and queue its exact acceptance SMSG."""
    cursor = app.openDB()
    existing_accept = None
    try:
        bid = app.queryOne(Bid, cursor, {"bid_id": bid_id})
        record = app.queryOne(HnsBtcSwap, cursor, {"bid_id": bid_id})
        offer = (
            app.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
            if bid is not None
            else None
        )
        if bid is None or record is None or offer is None:
            raise ValueError("incomplete maker HNS/BTC bid")
        hns_first = _hns_btc_offer_pair(offer)
        if (
            record.role != MAKER
            or not bid.was_received
            or not offer.was_sent
            or (offer.active_ind != 1 and record.terms_commitment is None)
            or offer.amount_negotiable
            or offer.rate_negotiable
            or offer.lock_type != TxLockTypes.ABS_LOCK_TIME
            or type(offer.lock_value) is not int
            or not 6 * 3600 <= offer.lock_value <= 96 * 3600
        ):
            raise ValueError("HNS/BTC bid was not received by this maker")
        now = app.getTime()
        if record.terms_commitment is None and (
            bid.expire_at <= now or offer.expire_at <= now
        ):
            raise ValueError("HNS/BTC bid or offer expired")
        if bid.contract_count is None:
            bid.contract_count = app.getNewContractId(cursor)
            app.updateDB(bid, cursor, ["bid_id"])
        existing_row = cursor.execute(
            "SELECT message_id FROM hns_btc_outbox "
            "WHERE session_id = :session_id AND message_type = :message_type",
            {
                "session_id": record.session_id,
                "message_type": int(MessageTypes.HNS_BTC_BID_ACCEPT),
            },
        ).fetchone()
        if existing_row is not None:
            if record.accept_message is None:
                raise ValueError("HNS/BTC acceptance outbox has no persisted terms")
            existing_accept = app.queryOne(
                HnsBtcOutbox, cursor, {"message_id": existing_row[0]}
            )
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)

    if existing_accept is not None:
        if existing_accept.delivered_at is None:
            try:
                deliver_hns_app_message(app, existing_accept, app.getTime())
            except Exception as exc:  # noqa: BLE001
                app.log.warning("HNS/BTC accept %s queued for retry: %s", bid_id.hex(), exc)
        return existing_accept.message_id

    hns_ci, btc_ci = app.ci(Coins.HNS), app.ci(Coins.BTC)
    if not hns_ci.walletIdentityReady():
        raise ValueError("HNS wallet is locked or has an unknown seed")
    if app.coin_clients[Coins.BTC]["connection_type"] != "rpc":
        raise ValueError("HNS/BTC requires Bitcoin Core RPC")
    btc_key = app.getPathKey(
        Coins(offer.coin_from),
        Coins(offer.coin_to),
        bid.created_at,
        bid.contract_count,
        KeyTypes.HNS_BTC,
    )
    secret = app.getContractSecret(
        dt.datetime.fromtimestamp(bid.created_at, dt.UTC).date(),
        bid.contract_count,
    )
    hns_amount = bid.amount if hns_first else bid.amount_to
    btc_amount = bid.amount_to if hns_first else bid.amount
    magic, genesis = hns_network_binding(app.chain)
    first_refund = now + offer.lock_value
    second_refund = now + offer.lock_value // 2
    terms = prepare_maker_terms(
        record,
        hns_first,
        hns_amount,
        btc_amount,
        btc_key,
        hns_ci.bridge,
        secret,
        first_refund,
        second_refund,
        now,
        magic,
        genesis,
        app.chain,
    )
    # The partial unique index makes accepting one bid per offer atomic even
    # when two UI requests race. No value action occurs before this commit.
    record.phase = 1
    _persist_trade(app, record)
    settlement = HnsBtcSettlement(
        record,
        terms,
        btc_ci,
        hns_ci.bridge,
        hns_ci.node,
        app.chain,
        lambda changed: _persist_trade(app, changed),
    )
    maximum_hns_fee = app.coin_clients[Coins.HNS].get("maximum_htlc_fee", 100_000)
    if type(maximum_hns_fee) is not int or not 0 < maximum_hns_fee <= 10_000_000:
        raise ValueError("invalid maximum HNS HTLC fee")
    settlement.fund_owned_lock(maximum_hns_fee)

    cursor = app.openDB()
    queued = None
    try:
        existing_id = cursor.execute(
            "SELECT message_id FROM hns_btc_outbox "
            "WHERE session_id = :session_id AND message_type = :message_type",
            {
                "session_id": record.session_id,
                "message_type": int(MessageTypes.HNS_BTC_BID_ACCEPT),
            },
        ).fetchone()
        if existing_id is not None:
            if record.accept_message is None:
                raise ValueError("HNS/BTC acceptance outbox has no persisted terms")
            queued = app.queryOne(HnsBtcOutbox, cursor, {"message_id": existing_id[0]})
            if queued is None:
                raise ValueError("HNS/BTC acceptance outbox row is missing")
        else:
            now = app.getTime()
            _, second_deadline = terms.validate(now, magic, genesis, False)
            if second_deadline <= now + HnsBtcSettlement.MINIMUM_MAKER_REDEEM_MARGIN_SECONDS:
                raise ValueError("HNS/BTC second lock refund is too close")
            raw = make_accept_message(record, terms, now, magic, genesis)
            encrypted = encryptMsg(
                app,
                offer.addr_from,
                bid.bid_addr,
                bytes((MessageTypes.HNS_BTC_BID_ACCEPT,)) + raw,
                min(
                    48 * 3600,
                    max(app.SMSG_SECONDS_IN_HOUR, second_deadline - now),
                ),
                cursor,
                timestamp=now,
                deterministic=True,
            )
            queued = prepare_hns_outbox_message(
                record.session_id,
                MessageTypes.HNS_BTC_BID_ACCEPT,
                encrypted,
                now,
                second_deadline,
            )
            app.updateDB(record, cursor, ["session_id"])
            bid.setState(BidStates.BID_ACCEPTED)
            app.updateDB(bid, cursor, ["bid_id"])
            app.add(queued, cursor)
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)
    try:
        deliver_hns_app_message(app, queued, app.getTime())
    except Exception as exc:  # noqa: BLE001
        app.log.warning("HNS/BTC accept %s queued for retry: %s", bid_id.hex(), exc)
    return queued.message_id


def receive_hns_btc_accept(app, msg):
    """Durably bind a maker's contracts before considering second-leg funding."""
    if msg.get("type", "smsg") != "smsg":
        raise ValueError("HNS/BTC acceptance must arrive over SMSG")
    raw = app.getSmsgMsgBytes(msg)
    wire = HnsBtcBidAcceptMessage()
    try:
        wire.from_bytes(raw)
        if wire.to_bytes() != raw or len(wire.bid_msg_id) != 28:
            raise ValueError("noncanonical HNS/BTC acceptance")
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid HNS/BTC acceptance") from exc
    bid_id = wire.bid_msg_id
    cursor = app.openDB()
    try:
        bid = app.queryOne(Bid, cursor, {"bid_id": bid_id})
        record = app.queryOne(HnsBtcSwap, cursor, {"bid_id": bid_id})
        offer = (
            app.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
            if bid is not None
            else None
        )
        if bid is None or record is None or offer is None:
            raise ValueError("unknown taker HNS/BTC bid")
        hns_first = _hns_btc_offer_pair(offer)
        if (
            record.role != TAKER
            or not bid.was_sent
            or msg.get("from") != offer.addr_from
            or msg.get("to") != bid.bid_addr
            or bid.offer_id != record.offer_id
        ):
            raise ValueError("HNS/BTC acceptance sender or bid mismatch")
        hns_amount = bid.amount if hns_first else bid.amount_to
        btc_amount = bid.amount_to if hns_first else bid.amount
        magic, genesis = hns_network_binding(app.chain)
        receive_accept_message(
            record,
            raw,
            hns_first,
            hns_amount,
            btc_amount,
            app.getTime(),
            magic,
            genesis,
        )
        app.updateDB(record, cursor, ["session_id"])
        if bid.state in (BidStates.BID_SENT, BidStates.BID_RECEIVING_ACC):
            bid.setState(BidStates.BID_ACCEPTED)
            app.updateDB(bid, cursor, ["bid_id"])
        app.addRecvBidNetworkLink(msg, bid_id, cursor)
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)
    return bid_id


def receive_hns_btc_second_lock(app, msg):
    """Record the taker's outpoint; a worker must verify it on chain."""
    if msg.get("type", "smsg") != "smsg":
        raise ValueError("HNS/BTC second lock must arrive over SMSG")
    raw = app.getSmsgMsgBytes(msg)
    wire = HnsBtcSecondLockMessage()
    try:
        wire.from_bytes(raw)
        if wire.to_bytes() != raw or len(wire.bid_msg_id) != 28:
            raise ValueError("noncanonical HNS/BTC second lock")
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid HNS/BTC second lock") from exc
    bid_id = wire.bid_msg_id
    cursor = app.openDB()
    try:
        bid = app.queryOne(Bid, cursor, {"bid_id": bid_id})
        record = app.queryOne(HnsBtcSwap, cursor, {"bid_id": bid_id})
        offer = (
            app.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
            if bid is not None
            else None
        )
        if bid is None or record is None or offer is None:
            raise ValueError("unknown maker HNS/BTC bid")
        hns_first = _hns_btc_offer_pair(offer)
        if (
            record.role != MAKER
            or not bid.was_received
            or msg.get("from") != bid.bid_addr
            or msg.get("to") != offer.addr_from
            or bid.offer_id != record.offer_id
        ):
            raise ValueError("HNS/BTC second lock sender or bid mismatch")
        hns_amount = bid.amount if hns_first else bid.amount_to
        btc_amount = bid.amount_to if hns_first else bid.amount
        now = app.getTime()
        magic, genesis = hns_network_binding(app.chain)
        terms, _ = restore_trade(
            record, hns_first, hns_amount, btc_amount, now, magic, genesis
        )
        receive_second_lock_message(record, terms, raw, now, magic, genesis)
        app.updateDB(record, cursor, ["session_id"])
        app.addRecvBidNetworkLink(msg, bid_id, cursor)
    except Exception:
        app.closeDB(cursor, commit=False)
        raise
    else:
        app.closeDB(cursor)
    return bid_id
