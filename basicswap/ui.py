# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .util import (
    make_int,
    format_timestamp,
)
from .chainparams import (
    Coins,
)
from .basicswap import (
    SwapTypes,
    BidStates,
    TxStates,
    TxTypes,
    strTxType,
    strBidState,
    strTxState,
)

PAGE_LIMIT = 50


def validateAmountString(amount, ci):
    if type(amount) != str:
        return
    ar = amount.split('.')
    if len(ar) > 1 and len(ar[1]) > ci.exp():
        raise ValueError('Too many decimal places in amount {}'.format(amount))


def inputAmount(amount_str, ci):
    validateAmountString(amount_str, ci)
    return make_int(amount_str, ci.exp())


def setCoinFilter(form_data, field_name):
    if field_name not in form_data:
        return -1
    coin_type = int(form_data[field_name][0])
    if coin_type == -1:
        return -1
    try:
        return Coins(coin_type)
    except Exception:
        raise ValueError('Unknown Coin Type {}'.format(str(field_name)))


def getTxIdHex(bid, tx_type, suffix):
    if tx_type == TxTypes.ITX:
        obj = bid.initiate_tx
    elif tx_type == TxTypes.PTX:
        obj = bid.participate_tx
    else:
        return 'Unknown Type'

    if not obj:
        return 'None'
    if not obj.txid:
        return 'None'
    return obj.txid.hex() + suffix


def getTxSpendHex(bid, tx_type):
    if tx_type == TxTypes.ITX:
        obj = bid.initiate_tx
    elif tx_type == TxTypes.PTX:
        obj = bid.participate_tx
    else:
        return 'Unknown Type'

    if not obj:
        return 'None'
    if not obj.spend_txid:
        return 'None'
    return obj.spend_txid.hex() + ' {}'.format(obj.spend_n)


def listBidStates():
    rv = []
    for s in BidStates:
        rv.append((int(s), strBidState(s)))
    return rv


def describeBid(swap_client, bid, xmr_swap, offer, xmr_offer, bid_events, edit_bid, show_txns, view_tx_ind=None):
    ci_from = swap_client.ci(Coins(offer.coin_from))
    ci_to = swap_client.ci(Coins(offer.coin_to))
    ticker_from = ci_from.ticker()
    ticker_to = ci_to.ticker()

    state_description = ''
    if offer.swap_type == SwapTypes.SELLER_FIRST:
        if bid.state == BidStates.BID_SENT:
            state_description = 'Waiting for seller to accept.'
        elif bid.state == BidStates.BID_RECEIVED:
            state_description = 'Waiting for seller to accept.'
        elif bid.state == BidStates.BID_ACCEPTED:
            if not bid.initiate_tx:
                state_description = 'Waiting for seller to send initiate tx.'
            else:
                state_description = 'Waiting for initiate tx to confirm.'
        elif bid.state == BidStates.SWAP_INITIATED:
            state_description = 'Waiting for participate txn to be confirmed in {} chain'.format(ticker_to)
        elif bid.state == BidStates.SWAP_PARTICIPATING:
            if bid.was_sent:
                state_description = 'Waiting for participate txn to be spent in {} chain'.format(ticker_to)
            else:
                state_description = 'Waiting for initiate txn to be spent in {} chain'.format(ticker_from)
        elif bid.state == BidStates.SWAP_COMPLETED:
            state_description = 'Swap completed'
            if bid.getITxState() == TxStates.TX_REDEEMED and bid.getPTxState() == TxStates.TX_REDEEMED:
                state_description += ' successfully'
            else:
                state_description += ', ITX ' + strTxState(bid.getITxState()) + ', PTX ' + strTxState(bid.getPTxState())
        elif bid.state == BidStates.SWAP_TIMEDOUT:
            state_description = 'Timed out waiting for initiate txn'
        elif bid.state == BidStates.BID_ABANDONED:
            state_description = 'Bid abandoned'
        elif bid.state == BidStates.BID_ERROR:
            state_description = bid.state_note

    data = {
        'amt_from': ci_from.format_amount(bid.amount),
        'amt_to': ci_to.format_amount((bid.amount * offer.rate) // ci_from.COIN()),
        'ticker_from': ticker_from,
        'ticker_to': ticker_to,
        'bid_state': strBidState(bid.state),
        'state_description': state_description,
        'itx_state': strTxState(bid.getITxState()),
        'ptx_state': strTxState(bid.getPTxState()),
        'offer_id': bid.offer_id.hex(),
        'addr_from': bid.bid_addr,
        'addr_fund_proof': bid.proof_address,
        'created_at': format_timestamp(bid.created_at, with_seconds=True),
        'expired_at': format_timestamp(bid.expire_at, with_seconds=True),
        'was_sent': 'True' if bid.was_sent else 'False',
        'was_received': 'True' if bid.was_received else 'False',
        'initiate_tx': getTxIdHex(bid, TxTypes.ITX, ' ' + ticker_from),
        'initiate_conf': 'None' if (not bid.initiate_tx or not bid.initiate_tx.conf) else bid.initiate_tx.conf,
        'participate_tx': getTxIdHex(bid, TxTypes.PTX, ' ' + ticker_to),
        'participate_conf': 'None' if (not bid.participate_tx or not bid.participate_tx.conf) else bid.participate_tx.conf,
        'show_txns': show_txns,
        'can_abandon': True if bid.state not in (BidStates.BID_ABANDONED, BidStates.SWAP_COMPLETED) else False,
    }

    if edit_bid:
        data['bid_state_ind'] = int(bid.state)
        data['bid_states'] = listBidStates()

    if show_txns:
        if offer.swap_type == SwapTypes.XMR_SWAP:
            txns = []
            if bid.xmr_a_lock_tx:
                confirms = None
                if swap_client.coin_clients[ci_from.coin_type()]['last_height'] and bid.xmr_a_lock_tx.chain_height:
                    confirms = (swap_client.coin_clients[ci_from.coin_type()]['last_height'] - bid.xmr_a_lock_tx.chain_height) + 1
                txns.append({'type': 'Chain A Lock', 'txid': bid.xmr_a_lock_tx.txid.hex(), 'confirms': confirms})
            if bid.xmr_a_lock_spend_tx:
                txns.append({'type': 'Chain A Lock Spend', 'txid': bid.xmr_a_lock_spend_tx.txid.hex()})
            if bid.xmr_b_lock_tx:
                confirms = None
                if swap_client.coin_clients[ci_to.coin_type()]['last_height'] and bid.xmr_b_lock_tx.chain_height:
                    confirms = (swap_client.coin_clients[ci_to.coin_type()]['last_height'] - bid.xmr_b_lock_tx.chain_height) + 1
                txns.append({'type': 'Chain B Lock', 'txid': bid.xmr_b_lock_tx.txid.hex(), 'confirms': confirms})
            if bid.xmr_b_lock_tx and bid.xmr_b_lock_tx.spend_txid:
                txns.append({'type': 'Chain B Lock Spend', 'txid': bid.xmr_b_lock_tx.spend_txid.hex()})
            if xmr_swap.a_lock_refund_tx:
                txns.append({'type': strTxType(TxTypes.XMR_SWAP_A_LOCK_REFUND), 'txid': xmr_swap.a_lock_refund_tx_id.hex()})
            if xmr_swap.a_lock_refund_spend_tx:
                txns.append({'type': strTxType(TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND), 'txid': xmr_swap.a_lock_refund_spend_tx_id.hex()})
            for tx_type, tx in bid.txns.items():
                if tx_type in (TxTypes.XMR_SWAP_A_LOCK_REFUND, TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND):
                    continue
                txns.append({'type': strTxType(tx_type), 'txid': tx.txid.hex()})
            data['txns'] = txns
        else:
            data['initiate_tx_refund'] = 'None' if not bid.initiate_txn_refund else bid.initiate_txn_refund.hex()
            data['participate_tx_refund'] = 'None' if not bid.participate_txn_refund else bid.participate_txn_refund.hex()
            data['initiate_tx_spend'] = getTxSpendHex(bid, TxTypes.ITX)
            data['participate_tx_spend'] = getTxSpendHex(bid, TxTypes.PTX)

    if offer.swap_type == SwapTypes.XMR_SWAP:
        if view_tx_ind:
            data['view_tx_ind'] = view_tx_ind
            view_tx_id = bytes.fromhex(view_tx_ind)

            if xmr_swap:
                if view_tx_id == xmr_swap.a_lock_tx_id and xmr_swap.a_lock_tx:
                    data['view_tx_hex'] = xmr_swap.a_lock_tx.hex()
                if view_tx_id == xmr_swap.a_lock_refund_tx_id and xmr_swap.a_lock_refund_tx:
                    data['view_tx_hex'] = xmr_swap.a_lock_refund_tx.hex()
                if view_tx_id == xmr_swap.a_lock_refund_spend_tx_id and xmr_swap.a_lock_refund_spend_tx:
                    data['view_tx_hex'] = xmr_swap.a_lock_refund_spend_tx.hex()

        data['events'] = bid_events

    return data
