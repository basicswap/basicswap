# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time

from .util import (
    make_int,
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


def validateAmountString(amount):
    if type(amount) != str:
        return
    ar = amount.split('.')
    if len(ar) > 1 and len(ar[1]) > 8:
        raise ValueError('Too many decimal places in amount {}'.format(amount))


def inputAmount(amount_str):
    validateAmountString(amount_str)
    return make_int(amount_str)


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


def describeBid(swap_client, bid, offer, edit_bid, show_txns):
    ci_from = swap_client.ci(Coins(offer.coin_from))
    ci_to = swap_client.ci(Coins(offer.coin_to))
    ticker_from = ci_from.ticker()
    ticker_to = ci_to.ticker()

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
    else:
        state_description = ''

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
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.created_at)),
        'expired_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(bid.expire_at)),
        'was_sent': 'True' if bid.was_sent else 'False',
        'was_received': 'True' if bid.was_received else 'False',
        'initiate_tx': getTxIdHex(bid, TxTypes.ITX, ' ' + ticker_from),
        'initiate_conf': 'None' if (not bid.initiate_tx or not bid.initiate_tx.conf) else bid.initiate_tx.conf,
        'participate_tx': getTxIdHex(bid, TxTypes.PTX, ' ' + ticker_to),
        'participate_conf': 'None' if (not bid.participate_tx or not bid.participate_tx.conf) else bid.participate_tx.conf,
        'show_txns': show_txns,
    }

    if edit_bid:
        data['bid_state_ind'] = int(bid.state)
        data['bid_states'] = listBidStates()

    if show_txns:
        if offer.swap_type == SwapTypes.XMR_SWAP:
            txns = []
            if bid.xmr_a_lock_tx:
                txns.append({'type': 'Chain A Lock', 'txid': bid.xmr_a_lock_tx.txid.hex()})
            if bid.xmr_a_lock_spend_tx:
                txns.append({'type': 'Chain A Lock Spend', 'txid': bid.xmr_a_lock_spend_tx.txid.hex()})
            if bid.xmr_b_lock_tx:
                txns.append({'type': 'Chain B Lock', 'txid': bid.xmr_b_lock_tx.txid.hex()})
            if bid.xmr_b_lock_tx and bid.xmr_b_lock_tx.spend_txid:
                txns.append({'type': 'Chain B Lock Spend', 'txid': bid.xmr_b_lock_tx.spend_txid.hex()})

            for tx_type, tx in bid.txns.items():
                txns.append({'type': strTxType(tx_type), 'txid': tx.txid.hex()})
            data['txns'] = txns
        else:
            data['initiate_tx_refund'] = 'None' if not bid.initiate_txn_refund else bid.initiate_txn_refund.hex()
            data['participate_tx_refund'] = 'None' if not bid.participate_txn_refund else bid.participate_txn_refund.hex()
            data['initiate_tx_spend'] = getTxSpendHex(bid, TxTypes.ITX)
            data['participate_tx_spend'] = getTxSpendHex(bid, TxTypes.PTX)

    return data
