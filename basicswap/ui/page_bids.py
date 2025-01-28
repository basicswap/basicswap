# -*- coding: utf-8 -*-

# Copyright (c) 2022-2024 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .util import (
    PAGE_LIMIT,
    describeBid,
    get_data_entry,
    have_data_entry,
    get_data_entry_or,
    listBidActions,
    listBidStates,
    listOldBidStates,
    set_pagination_filters,
)
from basicswap.util import (
    ensure,
    toBool,
    format_timestamp,
)
from basicswap.basicswap_util import (
    BidStates,
    SwapTypes,
    DebugTypes,
    canAcceptBidState,
    strTxState,
    strBidState,
)


def page_bid(self, url_split, post_string):
    ensure(len(url_split) > 2, "Bid ID not specified")
    try:
        bid_id = bytes.fromhex(url_split[2])
        assert len(bid_id) == 28
    except Exception:
        raise ValueError("Bad bid ID")
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()

    messages = []
    err_messages = []
    show_txns = False
    show_offerer_seq_diagram = False
    show_bidder_seq_diagram = False
    show_lock_transfers = False
    edit_bid = False
    view_tx_ind = None
    form_data = self.checkForm(post_string, "bid", err_messages)
    if form_data:
        if b"abandon_bid" in form_data:
            try:
                swap_client.abandonBid(bid_id)
                messages.append("Bid abandoned")
            except Exception as ex:
                err_messages.append("Abandon failed " + str(ex))
        elif b"accept_bid" in form_data:
            try:
                swap_client.acceptBid(bid_id)
                messages.append("Bid accepted")
            except Exception as ex:
                err_messages.append("Accept failed " + str(ex))
        elif b"show_txns" in form_data:
            show_txns = True
        elif b"show_offerer_seq_diagram" in form_data:
            show_offerer_seq_diagram = True
        elif b"show_bidder_seq_diagram" in form_data:
            show_bidder_seq_diagram = True
        elif b"edit_bid" in form_data:
            edit_bid = True
        elif b"edit_bid_submit" in form_data:
            data = {
                "bid_state": int(form_data[b"new_state"][0]),
                "bid_action": int(get_data_entry_or(form_data, "new_action", -1)),
                "debug_ind": int(get_data_entry_or(form_data, "debugind", -1)),
                "kbs_other": get_data_entry_or(form_data, "kbs_other", None),
            }
            try:
                swap_client.manualBidUpdate(bid_id, data)
                messages.append("Bid edited")
            except Exception as ex:
                err_messages.append("Edit failed " + str(ex))
        elif b"view_tx_submit" in form_data:
            show_txns = True
            view_tx_ind = form_data[b"view_tx"][0].decode("utf-8")
            if len(view_tx_ind) != 64:
                err_messages.append("Invalid transaction selected.")
                view_tx_ind = None
        elif b"view_lock_transfers" in form_data:
            show_txns = True
            show_lock_transfers = True

    bid, xmr_swap, offer, xmr_offer, events = swap_client.getXmrBidAndOffer(bid_id)
    ensure(bid, "Unknown bid ID")

    data = describeBid(
        swap_client,
        bid,
        xmr_swap,
        offer,
        xmr_offer,
        events,
        edit_bid,
        show_txns,
        view_tx_ind,
        show_lock_transfers=show_lock_transfers,
    )

    if bid.debug_ind is not None and bid.debug_ind > 0:
        messages.append(
            "Debug flag set: {}, {}".format(
                bid.debug_ind, DebugTypes(bid.debug_ind).name
            )
        )

    data["show_bidder_seq_diagram"] = show_bidder_seq_diagram
    data["show_offerer_seq_diagram"] = show_offerer_seq_diagram

    old_states = listOldBidStates(bid)

    if len(data["addr_from_label"]) > 0:
        data["addr_from_label"] = "(" + data["addr_from_label"] + ")"
    data["can_accept_bid"] = True if canAcceptBidState(bid.state) else False

    if swap_client.debug_ui:
        data["bid_actions"] = [
            (-1, "None"),
        ] + listBidActions()

    template = server.env.get_template(
        "bid_xmr.html" if offer.swap_type == SwapTypes.XMR_SWAP else "bid.html"
    )
    return self.render_template(
        template,
        {
            "bid_id": bid_id.hex(),
            "messages": messages,
            "err_messages": err_messages,
            "data": data,
            "edit_bid": edit_bid,
            "old_states": old_states,
            "summary": summary,
        },
    )


def page_bids(self, url_split, post_string, sent=False, available=False, received=False):
    server = self.server
    swap_client = server.swap_client
    swap_client.checkSystemStatus()
    summary = swap_client.getSummary()
    filter_key = "page_available_bids" if available else "page_bids"

    filters = {
        "page_no": 1,
        "bid_state_ind": -1,
        "with_expired": True,
        "limit": PAGE_LIMIT,
        "sort_by": "created_at",
        "sort_dir": "desc",
    }
    if available:
        filters["bid_state_ind"] = BidStates.BID_RECEIVED
        filters["with_expired"] = False

    messages = []
    form_data = self.checkForm(post_string, "bids", messages)
    if form_data:
        if have_data_entry(form_data, "clearfilters"):
            swap_client.clearFilters(filter_key)
        else:
            if have_data_entry(form_data, "sort_by"):
                sort_by = get_data_entry(form_data, "sort_by")
                ensure(sort_by in ["created_at"], "Invalid sort by")
                filters["sort_by"] = sort_by
            if have_data_entry(form_data, "sort_dir"):
                sort_dir = get_data_entry(form_data, "sort_dir")
                ensure(sort_dir in ["asc", "desc"], "Invalid sort dir")
                filters["sort_dir"] = sort_dir
            if have_data_entry(form_data, "state"):
                state_ind = int(get_data_entry(form_data, "state"))
                if state_ind != -1:
                    try:
                        _ = BidStates(state_ind)
                    except Exception:
                        raise ValueError("Invalid state")
                filters["bid_state_ind"] = state_ind
            if have_data_entry(form_data, "with_expired"):
                with_expired = toBool(get_data_entry(form_data, "with_expired"))
                filters["with_expired"] = with_expired

            set_pagination_filters(form_data, filters)
        if have_data_entry(form_data, "applyfilters"):
            swap_client.setFilters(filter_key, filters)
    else:
        saved_filters = swap_client.getFilters(filter_key)
        if saved_filters:
            filters.update(saved_filters)

    page_data = {
        "bid_states": listBidStates(),
    }

    if available:
        bids = swap_client.listBids(sent=False, filters=filters)
        template = server.env.get_template("bids_available.html")
        return self.render_template(
            template,
            {
                "page_type_available": "Bids Available",
                "page_type_available_description": "Bids available for you to accept.",
                "messages": messages,
                "filters": filters,
                "data": page_data,
                "summary": summary,
                "filter_key": filter_key,
                "bids": [
                    (format_timestamp(b[0]), b[2].hex(), b[3].hex(),
                     strBidState(b[5]), strTxState(b[7]),
                     strTxState(b[8]), b[11])
                    for b in bids
                ],
                "bids_count": len(bids),
            }
        )

    sent_bids = swap_client.listBids(sent=True, filters=filters)
    received_bids = swap_client.listBids(sent=False, filters=filters)

    template = server.env.get_template("bids.html")
    return self.render_template(
        template,
        {
            "messages": messages,
            "filters": filters,
            "data": page_data,
            "summary": summary,
            "filter_key": filter_key,
            "sent_bids": [
                (
                    format_timestamp(b[0]),
                    b[2].hex(),
                    b[3].hex(),
                    strBidState(b[5]),
                    strTxState(b[7]),
                    strTxState(b[8]),
                    b[11],
                )
                for b in sent_bids
            ],
            "received_bids": [
                (
                    format_timestamp(b[0]),
                    b[2].hex(), 
                    b[3].hex(),
                    strBidState(b[5]),
                    strTxState(b[7]),
                    strTxState(b[8]),
                    b[11],
                )
                for b in received_bids
            ],
            "sent_bids_count": len(sent_bids),
            "received_bids_count": len(received_bids),
            "bids_count": len(sent_bids) + len(received_bids),
        },
    )
