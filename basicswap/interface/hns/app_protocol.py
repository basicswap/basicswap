"""BasicSwap database and SMSG boundary for the native HNS/BTC bid.

The bid ID is computed from encrypted bytes before the row is committed.
Network submission happens only after the bid, HNS session, and exact bytes
are durable. Later trade messages use the same outbox boundary.
"""

from basicswap.basicswap_util import (
    AddressTypes,
    BidStates,
    KeyTypes,
    MessageNetworks,
    MessageTypes,
    SwapTypes,
)
from basicswap.chainparams import Coins
from basicswap.db import Bid, HnsBtcOutbox
from basicswap.network.simplex import encryptMsg

from .outbox import deliver_hns_outbox_message, prepare_hns_outbox_message
from .trade_protocol import bind_sent_bid, prepare_taker_bid


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
