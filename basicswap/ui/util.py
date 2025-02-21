# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import struct
from basicswap.util import (
    hex_or_none,
    make_int,
    format_timestamp,
)
from basicswap.chainparams import (
    Coins,
    chainparams,
)
from basicswap.basicswap_util import (
    ActionTypes,
    BidStates,
    DebugTypes,
    canAcceptBidState,
    getLastBidState,
    strBidState,
    strTxState,
    strTxType,
    SwapTypes,
    TxLockTypes,
    TxStates,
    TxTypes,
)

from basicswap.protocols.xmr_swap_1 import getChainBSplitKey, getChainBRemoteSplitKey

PAGE_LIMIT = 1000
invalid_coins_from = []
known_chart_coins = [
    "BTC",
    "PART",
    "XMR",
    "LTC",
    "FIRO",
    "DASH",
    "PIVX",
    "DOGE",
    "ETH",
    "DCR",
    "ZANO",
    "WOW",
    "BCH",
]


def tickerToCoinId(ticker):
    search_str = ticker.upper()
    for c in Coins:
        if c.name == search_str:
            return c.value
    raise ValueError("Unknown coin")


def getCoinType(coin_type_ind):
    # coin_type_ind can be int id or str ticker
    try:
        return int(coin_type_ind)
    except Exception:
        return tickerToCoinId(coin_type_ind)


def validateAmountString(amount, ci):
    if not isinstance(amount, str):
        return
    ar = amount.split(".")
    if len(ar) > 1 and len(ar[1]) > ci.exp():
        raise ValueError("Too many decimal places in amount {}".format(amount))


def inputAmount(amount_str, ci):
    validateAmountString(amount_str, ci)
    return make_int(amount_str, ci.exp())


def get_data_entry_or(post_data, name, default):
    if "is_json" in post_data:
        return post_data.get(name, default)
    key_bytes = name.encode("utf-8")
    if key_bytes in post_data:
        return post_data[key_bytes][0].decode("utf-8")
    return default


def get_data_entry(post_data, name):
    if "is_json" in post_data:
        return post_data[name]
    return post_data[name.encode("utf-8")][0].decode("utf-8")


def have_data_entry(post_data, name):
    if "is_json" in post_data:
        return name in post_data
    return name.encode("utf-8") in post_data


def setCoinFilter(form_data, field_name):
    try:
        coin_type = getCoinType(get_data_entry(form_data, field_name))
    except Exception:
        return -1
    if coin_type == -1:
        return -1
    try:
        return Coins(coin_type)
    except Exception:
        raise ValueError("Unknown Coin Type {}".format(str(field_name)))


def set_pagination_filters(form_data, filters):
    if form_data and have_data_entry(form_data, "pageback"):
        filters["page_no"] = int(form_data[b"pageno"][0]) - 1
        if filters["page_no"] < 1:
            filters["page_no"] = 1
    elif form_data and have_data_entry(form_data, "pageforwards"):
        filters["page_no"] = int(form_data[b"pageno"][0]) + 1

    no_limit = False
    if form_data:
        if "is_json" in form_data:
            no_limit = form_data.get("no_limit", False)
        else:
            no_limit = b"no_limit" in form_data

    if no_limit:
        filters["offset"] = 0
        filters["limit"] = None
    else:
        if filters["page_no"] > 1:
            filters["offset"] = (filters["page_no"] - 1) * PAGE_LIMIT
        filters["limit"] = PAGE_LIMIT


def get_data_with_pagination(data, filters):
    if filters.get("limit") is None:
        return data
    
    offset = filters.get("offset", 0)
    limit = filters.get("limit", PAGE_LIMIT)
    return data[offset:offset + limit]


def getTxIdHex(bid, tx_type, suffix):
    if tx_type == TxTypes.ITX:
        obj = bid.initiate_tx
    elif tx_type == TxTypes.PTX:
        obj = bid.participate_tx
    else:
        return "Unknown Type"

    if not obj:
        return "None"
    if not obj.txid:
        return "None"
    return obj.txid.hex() + suffix


def getTxSpendHex(bid, tx_type):
    if tx_type == TxTypes.ITX:
        obj = bid.initiate_tx
    elif tx_type == TxTypes.PTX:
        obj = bid.participate_tx
    else:
        return "Unknown Type"

    if not obj:
        return "None"
    if not obj.spend_txid:
        return "None"
    return obj.spend_txid.hex() + " {}".format(obj.spend_n)


def listBidStates():
    rv = []
    for s in BidStates:
        rv.append((int(s), strBidState(s)))
    return rv


def listBidActions():
    rv = []
    for a in ActionTypes:
        rv.append((int(a), a.name))
    return rv


def describeBid(
    swap_client,
    bid,
    xmr_swap,
    offer,
    xmr_offer,
    bid_events,
    edit_bid,
    show_txns,
    view_tx_ind=None,
    for_api=False,
    show_lock_transfers=False,
):
    ci_from = swap_client.ci(Coins(offer.coin_from))
    ci_to = swap_client.ci(Coins(offer.coin_to))

    reverse_bid: bool = swap_client.is_reverse_ads_bid(offer.coin_from, offer.coin_to)
    ci_leader = ci_to if reverse_bid else ci_from
    ci_follower = ci_from if reverse_bid else ci_to

    bid_amount: int = bid.amount
    bid_amount_to: int = bid.amount_to
    bid_rate: int = offer.rate if bid.rate is None else bid.rate

    initiator_role: str = "offerer"  # Leader
    participant_role: str = "bidder"  # Follower
    if reverse_bid:
        bid_amount = bid.amount_to
        bid_amount_to = bid.amount
        bid_rate = ci_from.make_int(bid.amount / bid.amount_to, r=1)
        initiator_role = "bidder"
        participant_role = "offerer"

    state_description = ""
    if offer.swap_type == SwapTypes.SELLER_FIRST:
        if bid.state == BidStates.BID_SENT:
            state_description = "Waiting for seller to accept."
        elif bid.state == BidStates.BID_RECEIVED:
            state_description = "Waiting for seller to accept."
        elif bid.state == BidStates.BID_ACCEPTED:
            if not bid.initiate_tx:
                state_description = "Waiting for seller to send initiate tx."
            else:
                state_description = "Waiting for initiate tx to confirm."
        elif bid.state == BidStates.SWAP_INITIATED:
            state_description = (
                "Waiting for participate txn to be confirmed in {} chain".format(
                    ci_follower.ticker()
                )
            )
        elif bid.state == BidStates.SWAP_PARTICIPATING:
            if bid.was_sent:
                state_description = (
                    "Waiting for participate txn to be spent in {} chain".format(
                        ci_follower.ticker()
                    )
                )
            else:
                state_description = (
                    "Waiting for initiate txn to be spent in {} chain".format(
                        ci_leader.ticker()
                    )
                )
        elif bid.state == BidStates.SWAP_COMPLETED:
            state_description = "Swap completed"
            if (
                bid.getITxState() == TxStates.TX_REDEEMED
                and bid.getPTxState() == TxStates.TX_REDEEMED
            ):
                state_description += " successfully"
            else:
                state_description += (
                    ", ITX "
                    + strTxState(bid.getITxState())
                    + ", PTX "
                    + strTxState(bid.getPTxState())
                )
        elif bid.state == BidStates.SWAP_TIMEDOUT:
            state_description = "Timed out waiting for initiate txn"
        elif bid.state == BidStates.BID_ABANDONED:
            state_description = "Bid abandoned"
        elif bid.state == BidStates.BID_ERROR:
            state_description = bid.state_note
    elif offer.swap_type == SwapTypes.XMR_SWAP:
        if bid.state == BidStates.BID_SENT:
            state_description = "Waiting for offerer to accept"
        if bid.state == BidStates.BID_RECEIVING:
            # Offerer receiving bid from bidder
            state_description = "Waiting for bid to be fully received"
        elif canAcceptBidState(bid.state):
            # Offerer received bid from bidder
            # TODO: Manual vs automatic
            state_description = "Bid must be accepted"
        elif bid.state == BidStates.BID_RECEIVING_ACC:
            state_description = "Receiving accepted bid message"
        elif bid.state == BidStates.BID_ACCEPTED:
            state_description = (
                "Offerer has accepted bid, waiting for bidder to respond"
            )
        elif bid.state == BidStates.SWAP_DELAYING:
            last_state = getLastBidState(bid.states)
            if canAcceptBidState(last_state):
                state_description = "Delaying before accepting bid"
            elif last_state == BidStates.BID_RECEIVING_ACC:
                state_description = "Delaying before responding to accepted bid"
            elif last_state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
                state_description = (
                    f"Delaying before spending from {ci_follower.ticker()} lock tx"
                )
            elif last_state == BidStates.BID_ACCEPTED:
                state_description = (
                    f"Delaying before sending {ci_leader.ticker()} lock tx"
                )
            else:
                state_description = "Delaying before automated action"
        elif bid.state == BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX:
            state_description = f"Waiting for {ci_leader.ticker()} lock tx to confirm in chain ({ci_leader.blocks_confirmed} blocks)"
        elif bid.state == BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED:
            if xmr_swap.b_lock_tx_id is None:
                state_description = f"Waiting for {ci_follower.ticker()} lock tx"
            else:
                state_description = f"Waiting for {ci_follower.ticker()} lock tx to confirm in chain ({ci_follower.blocks_confirmed} blocks)"
        elif bid.state == BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED:
            state_description = (
                f"Waiting for {initiator_role} to unlock {ci_leader.ticker()} lock tx"
            )
        elif bid.state == BidStates.XMR_SWAP_LOCK_RELEASED:
            state_description = f"Waiting for {participant_role} to spend from {ci_leader.ticker()} lock tx"
        elif bid.state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
            state_description = f"Waiting for {initiator_role} to spend from {ci_follower.ticker()} lock tx"
        elif bid.state == BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED:
            state_description = f"Waiting for {ci_follower.ticker()} lock tx spend tx to confirm in chain"
        elif bid.state == BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND:
            if bid.was_sent:
                state_description = (
                    f"Waiting for {initiator_role} to redeem or locktime to expire"
                )
            else:
                state_description = "Redeeming output"

    addr_label = swap_client.getAddressLabel(
        [
            bid.bid_addr,
        ]
    )[0]

    can_abandon: bool = False
    if swap_client.debug and bid.state not in (
        BidStates.BID_ABANDONED,
        BidStates.SWAP_COMPLETED,
    ):
        can_abandon = True

    data = {
        "coin_from": ci_from.coin_name(),
        "coin_to": ci_to.coin_name(),
        "amt_from": ci_from.format_amount(bid_amount),
        "amt_to": ci_to.format_amount(bid_amount_to),
        "bid_rate": ci_to.format_amount(bid_rate),
        "ticker_from": ci_from.ticker(),
        "ticker_to": ci_to.ticker(),
        "bid_state": strBidState(bid.state),
        "state_description": state_description,
        "itx_state": strTxState(bid.getITxState()),
        "ptx_state": strTxState(bid.getPTxState()),
        "offer_id": bid.offer_id.hex(),
        "addr_from": bid.bid_addr,
        "addr_from_label": addr_label,
        "addr_fund_proof": bid.proof_address,
        "created_at": (
            bid.created_at
            if for_api
            else format_timestamp(bid.created_at, with_seconds=True)
        ),
        "expired_at": (
            bid.expire_at
            if for_api
            else format_timestamp(bid.expire_at, with_seconds=True)
        ),
        "was_sent": "True" if bid.was_sent else "False",
        "was_received": "True" if bid.was_received else "False",
        "initiate_tx": getTxIdHex(bid, TxTypes.ITX, " " + ci_leader.ticker()),
        "initiate_conf": (
            "None"
            if (not bid.initiate_tx or not bid.initiate_tx.conf)
            else bid.initiate_tx.conf
        ),
        "participate_tx": getTxIdHex(bid, TxTypes.PTX, " " + ci_follower.ticker()),
        "participate_conf": (
            "None"
            if (not bid.participate_tx or not bid.participate_tx.conf)
            else bid.participate_tx.conf
        ),
        "show_txns": show_txns,
        "can_abandon": can_abandon,
        "events": bid_events,
        "debug_ui": swap_client.debug_ui,
        "reverse_bid": reverse_bid,
    }

    if edit_bid:
        data["bid_state_ind"] = int(bid.state)
        data["bid_states"] = listBidStates()

        if swap_client.debug_ui:
            data["debug_ind"] = bid.debug_ind
            data["debug_options"] = [(int(t), t.name) for t in DebugTypes]

    if show_txns:
        if offer.swap_type == SwapTypes.XMR_SWAP:
            txns = []
            if bid.xmr_a_lock_tx:
                confirms = None
                if (
                    swap_client.coin_clients[ci_leader.coin_type()]["chain_height"]
                    and bid.xmr_a_lock_tx.chain_height
                ):
                    confirms = (
                        swap_client.coin_clients[ci_leader.coin_type()]["chain_height"]
                        - bid.xmr_a_lock_tx.chain_height
                    ) + 1
                txns.append(
                    {
                        "type": "Chain A Lock",
                        "txid": hex_or_none(bid.xmr_a_lock_tx.txid),
                        "confirms": confirms,
                    }
                )
            if bid.xmr_a_lock_spend_tx:
                txns.append(
                    {
                        "type": "Chain A Lock Spend",
                        "txid": bid.xmr_a_lock_spend_tx.txid.hex(),
                    }
                )
            if bid.xmr_b_lock_tx:
                confirms = None
                if (
                    swap_client.coin_clients[ci_follower.coin_type()]["chain_height"]
                    and bid.xmr_b_lock_tx.chain_height
                ):
                    confirms = (
                        swap_client.coin_clients[ci_follower.coin_type()][
                            "chain_height"
                        ]
                        - bid.xmr_b_lock_tx.chain_height
                    ) + 1
                txns.append(
                    {
                        "type": "Chain B Lock",
                        "txid": bid.xmr_b_lock_tx.txid.hex(),
                        "confirms": confirms,
                    }
                )
            if bid.xmr_b_lock_tx and bid.xmr_b_lock_tx.spend_txid:
                txns.append(
                    {
                        "type": "Chain B Lock Spend",
                        "txid": bid.xmr_b_lock_tx.spend_txid.hex(),
                    }
                )
            if xmr_swap.a_lock_refund_tx:
                txns.append(
                    {
                        "type": strTxType(TxTypes.XMR_SWAP_A_LOCK_REFUND),
                        "txid": xmr_swap.a_lock_refund_tx_id.hex(),
                    }
                )
            if xmr_swap.a_lock_refund_spend_tx:
                txns.append(
                    {
                        "type": strTxType(TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND),
                        "txid": xmr_swap.a_lock_refund_spend_tx_id.hex(),
                    }
                )
            for tx_type, tx in bid.txns.items():
                if tx_type in (
                    TxTypes.XMR_SWAP_A_LOCK_REFUND,
                    TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND,
                ):
                    continue
                txns.append({"type": strTxType(tx_type), "txid": tx.txid.hex()})
            data["txns"] = txns

            data["xmr_b_shared_address"] = (
                ci_to.encodeSharedAddress(xmr_swap.pkbv, xmr_swap.pkbs)
                if xmr_swap.pkbs
                else None
            )
            data["xmr_b_shared_viewkey"] = (
                ci_to.encodeKey(xmr_swap.vkbv) if xmr_swap.vkbv else None
            )

            if swap_client.debug_ui:
                try:
                    data["xmr_b_half_privatekey"] = getChainBSplitKey(
                        swap_client, bid, xmr_swap, offer
                    )
                except Exception as e:  # noqa: F841
                    swap_client.log.debug(
                        "Unable to get xmr_b_half_privatekey for bid: {}".format(
                            bid.bid_id.hex()
                        )
                    )
                try:
                    remote_split_key = getChainBRemoteSplitKey(
                        swap_client, bid, xmr_swap, offer
                    )
                    if remote_split_key:
                        data["xmr_b_half_privatekey_remote"] = remote_split_key
                except Exception as e:  # noqa: F841
                    swap_client.log.debug(
                        "Unable to get xmr_b_half_privatekey_remote for bid: {}".format(
                            bid.bid_id.hex()
                        )
                    )

            if show_lock_transfers:
                if xmr_swap.pkbs:
                    data["lock_transfers"] = json.dumps(
                        ci_to.showLockTransfers(
                            xmr_swap.vkbv, xmr_swap.pkbs, bid.chain_b_height_start
                        ),
                        indent=4,
                    )
                else:
                    data["lock_transfers"] = "Shared address not yet known."
        else:
            data["initiate_tx_refund"] = (
                "None" if not bid.initiate_txn_refund else bid.initiate_txn_refund.hex()
            )
            data["participate_tx_refund"] = (
                "None"
                if not bid.participate_txn_refund
                else bid.participate_txn_refund.hex()
            )
            data["initiate_tx_spend"] = getTxSpendHex(bid, TxTypes.ITX)
            data["participate_tx_spend"] = getTxSpendHex(bid, TxTypes.PTX)

            if bid.initiate_tx and bid.initiate_tx.tx_data is not None:
                data["initiate_tx_inputs"] = ci_from.listInputs(bid.initiate_tx.tx_data)
            if bid.participate_tx and bid.participate_tx.tx_data is not None:
                data["initiate_tx_inputs"] = ci_from.listInputs(
                    bid.participate_tx.tx_data
                )

    if offer.swap_type == SwapTypes.XMR_SWAP:
        data["coin_a_lock_refund_tx_est_final"] = "None"
        data["coin_a_lock_refund_swipe_tx_est_final"] = "None"

        if offer.lock_type == TxLockTypes.SEQUENCE_LOCK_TIME:
            if bid.xmr_a_lock_tx and bid.xmr_a_lock_tx.block_time:
                raw_sequence = ci_leader.getExpectedSequence(
                    offer.lock_type, offer.lock_value
                )
                seconds_locked = ci_leader.decodeSequence(raw_sequence)
                data["coin_a_lock_refund_tx_est_final"] = (
                    bid.xmr_a_lock_tx.block_time + seconds_locked
                )
                data["coin_a_last_median_time"] = swap_client.coin_clients[
                    offer.coin_from
                ]["chain_median_time"]

            if TxTypes.XMR_SWAP_A_LOCK_REFUND in bid.txns:
                refund_tx = bid.txns[TxTypes.XMR_SWAP_A_LOCK_REFUND]
                if refund_tx.block_time is not None:
                    raw_sequence = ci_leader.getExpectedSequence(
                        offer.lock_type, offer.lock_value
                    )
                    seconds_locked = ci_leader.decodeSequence(raw_sequence)
                    data["coin_a_lock_refund_swipe_tx_est_final"] = (
                        refund_tx.block_time + seconds_locked
                    )

        if view_tx_ind:
            data["view_tx_ind"] = view_tx_ind
            view_tx_id = bytes.fromhex(view_tx_ind)

            if xmr_swap:
                if view_tx_id == xmr_swap.a_lock_tx_id and xmr_swap.a_lock_tx:
                    data["view_tx_hex"] = xmr_swap.a_lock_tx.hex()
                    data["chain_a_lock_tx_inputs"] = ci_leader.listInputs(
                        xmr_swap.a_lock_tx
                    )
                if (
                    view_tx_id == xmr_swap.a_lock_refund_tx_id
                    and xmr_swap.a_lock_refund_tx
                ):
                    data["view_tx_hex"] = xmr_swap.a_lock_refund_tx.hex()
                if (
                    view_tx_id == xmr_swap.a_lock_refund_spend_tx_id
                    and xmr_swap.a_lock_refund_spend_tx
                ):
                    data["view_tx_hex"] = xmr_swap.a_lock_refund_spend_tx.hex()
                if (
                    view_tx_id == xmr_swap.a_lock_spend_tx_id
                    and xmr_swap.a_lock_spend_tx
                ):
                    data["view_tx_hex"] = xmr_swap.a_lock_spend_tx.hex()

                if "view_tx_hex" in data:
                    data["view_tx_desc"] = json.dumps(
                        ci_leader.describeTx(data["view_tx_hex"]), indent=4
                    )
    else:
        if offer.lock_type == TxLockTypes.SEQUENCE_LOCK_TIME:
            if bid.initiate_tx and bid.initiate_tx.block_time is not None:
                raw_sequence = ci_leader.getExpectedSequence(
                    offer.lock_type, offer.lock_value
                )
                seconds_locked = ci_leader.decodeSequence(raw_sequence)
                data["itx_refund_tx_est_final"] = (
                    bid.initiate_tx.block_time + seconds_locked
                )
            if bid.participate_tx and bid.participate_tx.block_time is not None:
                raw_sequence = ci_follower.getExpectedSequence(
                    offer.lock_type, offer.lock_value // 2
                )
                seconds_locked = ci_follower.decodeSequence(raw_sequence)
                data["ptx_refund_tx_est_final"] = (
                    bid.participate_tx.block_time + seconds_locked
                )

    return data


def listOldBidStates(bid):
    old_states = []
    num_states = len(bid.states) // 12
    for i in range(num_states):
        up = struct.unpack_from("<iq", bid.states[i * 12 : (i + 1) * 12])
        old_states.append((up[1], "Bid " + strBidState(up[0])))
    if bid.initiate_tx and bid.initiate_tx.states is not None:
        num_states = len(bid.initiate_tx.states) // 12
        for i in range(num_states):
            up = struct.unpack_from(
                "<iq", bid.initiate_tx.states[i * 12 : (i + 1) * 12]
            )
            if up[0] != TxStates.TX_NONE:
                old_states.append((up[1], "ITX " + strTxState(up[0])))
    if bid.participate_tx and bid.participate_tx.states is not None:
        num_states = len(bid.participate_tx.states) // 12
        for i in range(num_states):
            up = struct.unpack_from(
                "<iq", bid.participate_tx.states[i * 12 : (i + 1) * 12]
            )
            if up[0] != TxStates.TX_NONE:
                old_states.append((up[1], "PTX " + strTxState(up[0])))
    if len(old_states) > 0:
        old_states.sort(key=lambda x: x[0])
    return old_states


def getCoinName(c):
    if c == Coins.PART_ANON:
        return chainparams[Coins.PART]["name"].capitalize() + " Anon"
    if c == Coins.PART_BLIND:
        return chainparams[Coins.PART]["name"].capitalize() + " Blind"
    if c == Coins.LTC_MWEB:
        return chainparams[Coins.LTC]["name"].capitalize() + " MWEB"

    coin_chainparams = chainparams[c]
    if "display_name" in coin_chainparams:
        return coin_chainparams["display_name"]
    return coin_chainparams["name"].capitalize()


def listAvailableCoins(swap_client, with_variants=True, split_from=False):
    coins_from = []
    coins = []
    for k, v in swap_client.coin_clients.items():
        if k not in chainparams:
            continue
        if v["connection_type"] == "rpc":
            coins.append((int(k), getCoinName(k)))
            if split_from and k not in invalid_coins_from:
                coins_from.append(coins[-1])
            if with_variants and k == Coins.PART:
                for v in (Coins.PART_ANON, Coins.PART_BLIND):
                    coins.append((int(v), getCoinName(v)))
                    if split_from and v not in invalid_coins_from:
                        coins_from.append(coins[-1])
            if with_variants and k == Coins.LTC:
                for v in (Coins.LTC_MWEB,):
                    pass  # Add when swappable
    if split_from:
        return coins_from, coins
    return coins


def checkAddressesOwned(swap_client, ci, wallet_info):
    if "stealth_address" in wallet_info:

        if wallet_info["stealth_address"] != "?":
            if not ci.isAddressMine(wallet_info["stealth_address"]):
                ci._log.error(
                    "Unowned stealth address: {}".format(wallet_info["stealth_address"])
                )
                wallet_info["stealth_address"] = "Error: unowned address"
            elif (
                swap_client._restrict_unknown_seed_wallets and not ci.knownWalletSeed()
            ):
                wallet_info["stealth_address"] = "WARNING: Unknown wallet seed"

    if "deposit_address" in wallet_info:
        if wallet_info["deposit_address"] != "Refresh necessary":
            if not ci.isAddressMine(wallet_info["deposit_address"]):
                ci._log.error(
                    "Unowned deposit address: {}".format(wallet_info["deposit_address"])
                )
                wallet_info["deposit_address"] = "Error: unowned address"
            elif (
                swap_client._restrict_unknown_seed_wallets and not ci.knownWalletSeed()
            ):
                wallet_info["deposit_address"] = "WARNING: Unknown wallet seed"


def validateTextInput(text, name, messages, max_length=None):
    if max_length is not None and len(text) > max_length:
        messages.append(f"Error: {name} is too long")
        return False
    if len(text) > 0 and all(c.isalnum() or c.isspace() for c in text) is False:
        messages.append(f"Error: {name} must consist of only letters and digits")
        return False
    return True
