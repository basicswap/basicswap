# -*- coding: utf-8 -*-

# Copyright (c) 2021-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.


import struct
import hashlib
from enum import IntEnum, auto
from .util.address import (
    encodeAddress,
    decodeAddress,
)
from .chainparams import (
    chainparams,
)


class TxLockTypes(IntEnum):
    SEQUENCE_LOCK_BLOCKS = 1
    SEQUENCE_LOCK_TIME = 2
    ABS_LOCK_BLOCKS = 3
    ABS_LOCK_TIME = 4


class KeyTypes(IntEnum):
    KBVL = 1
    KBSL = 2
    KAL = 3
    KBVF = 4
    KBSF = 5
    KAF = 6


class MessageTypes(IntEnum):
    OFFER = auto()
    BID = auto()
    BID_ACCEPT = auto()

    XMR_OFFER = auto()
    XMR_BID_FL = auto()
    XMR_BID_SPLIT = auto()
    XMR_BID_ACCEPT_LF = auto()
    XMR_BID_TXN_SIGS_FL = auto()
    XMR_BID_LOCK_SPEND_TX_LF = auto()
    XMR_BID_LOCK_RELEASE_LF = auto()
    OFFER_REVOKE = auto()

    ADS_BID_LF = auto()
    ADS_BID_ACCEPT_FL = auto()


class AddressTypes(IntEnum):
    OFFER = auto()
    BID = auto()
    RECV_OFFER = auto()
    SEND_OFFER = auto()


class SwapTypes(IntEnum):
    SELLER_FIRST = auto()
    BUYER_FIRST = auto()
    SELLER_FIRST_2MSG = auto()
    BUYER_FIRST_2MSG = auto()
    XMR_SWAP = auto()
    XMR_BCH_SWAP = auto()


class OfferStates(IntEnum):
    OFFER_SENT = 1
    OFFER_RECEIVED = 2
    OFFER_ABANDONED = 3
    OFFER_EXPIRED = 4


class BidStates(IntEnum):
    BID_SENT = 1
    BID_RECEIVING = 2               # Partially received
    BID_RECEIVED = 3
    BID_RECEIVING_ACC = 4           # Partially received accept message
    BID_ACCEPTED = 5                # BidAcceptMessage received/sent
    SWAP_INITIATED = 6              # Initiate txn validated
    SWAP_PARTICIPATING = 7          # Participate txn validated
    SWAP_COMPLETED = 8              # All swap txns spent
    XMR_SWAP_SCRIPT_COIN_LOCKED = 9
    XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX = 10
    XMR_SWAP_NOSCRIPT_COIN_LOCKED = 11
    XMR_SWAP_LOCK_RELEASED = 12
    XMR_SWAP_SCRIPT_TX_REDEEMED = 13
    XMR_SWAP_SCRIPT_TX_PREREFUND = 14  # script txo moved into pre-refund tx
    XMR_SWAP_NOSCRIPT_TX_REDEEMED = 15
    XMR_SWAP_NOSCRIPT_TX_RECOVERED = 16
    XMR_SWAP_FAILED_REFUNDED = 17
    XMR_SWAP_FAILED_SWIPED = 18
    XMR_SWAP_FAILED = 19
    SWAP_DELAYING = 20
    SWAP_TIMEDOUT = 21
    BID_ABANDONED = 22          # Bid will no longer be processed
    BID_ERROR = 23              # An error occurred
    BID_STALLED_FOR_TEST = 24
    BID_REJECTED = 25
    BID_STATE_UNKNOWN = 26
    XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS = 27      # XmrBidLockTxSigsMessage
    XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX = 28     # XmrBidLockSpendTxMessage
    BID_REQUEST_SENT = 29
    BID_REQUEST_ACCEPTED = 30
    BID_EXPIRED = 31


class TxStates(IntEnum):
    TX_NONE = auto()
    TX_SENT = auto()
    TX_CONFIRMED = auto()
    TX_REDEEMED = auto()
    TX_REFUNDED = auto()
    TX_IN_MEMPOOL = auto()
    TX_IN_CHAIN = auto()


class TxTypes(IntEnum):
    ITX = auto()
    PTX = auto()
    ITX_REDEEM = auto()
    ITX_REFUND = auto()
    PTX_REDEEM = auto()
    PTX_REFUND = auto()

    XMR_SWAP_A_LOCK = auto()
    XMR_SWAP_A_LOCK_SPEND = auto()
    XMR_SWAP_A_LOCK_REFUND = auto()
    XMR_SWAP_A_LOCK_REFUND_SPEND = auto()
    XMR_SWAP_A_LOCK_REFUND_SWIPE = auto()
    XMR_SWAP_B_LOCK = auto()
    XMR_SWAP_B_LOCK_SPEND = auto()
    XMR_SWAP_B_LOCK_REFUND = auto()

    ITX_PRE_FUNDED = auto()


class ActionTypes(IntEnum):
    ACCEPT_BID = auto()
    ACCEPT_XMR_BID = auto()
    SIGN_XMR_SWAP_LOCK_TX_A = auto()
    SEND_XMR_SWAP_LOCK_TX_A = auto()
    SEND_XMR_SWAP_LOCK_TX_B = auto()
    SEND_XMR_LOCK_RELEASE = auto()
    REDEEM_XMR_SWAP_LOCK_TX_A = auto()  # Follower
    REDEEM_XMR_SWAP_LOCK_TX_B = auto()  # Leader
    RECOVER_XMR_SWAP_LOCK_TX_B = auto()
    SEND_XMR_SWAP_LOCK_SPEND_MSG = auto()
    REDEEM_ITX = auto()
    ACCEPT_AS_REV_BID = auto()


class EventLogTypes(IntEnum):
    FAILED_TX_B_LOCK_PUBLISH = auto()
    LOCK_TX_A_PUBLISHED = auto()
    LOCK_TX_B_PUBLISHED = auto()
    FAILED_TX_B_SPEND = auto()
    LOCK_TX_A_SEEN = auto()
    LOCK_TX_A_CONFIRMED = auto()
    LOCK_TX_B_SEEN = auto()
    LOCK_TX_B_CONFIRMED = auto()
    DEBUG_TWEAK_APPLIED = auto()
    FAILED_TX_B_REFUND = auto()
    LOCK_TX_B_INVALID = auto()
    LOCK_TX_A_REFUND_TX_PUBLISHED = auto()
    LOCK_TX_A_REFUND_SPEND_TX_PUBLISHED = auto()
    LOCK_TX_A_REFUND_SWIPE_TX_PUBLISHED = auto()
    LOCK_TX_B_REFUND_TX_PUBLISHED = auto()
    SYSTEM_WARNING = auto()
    LOCK_TX_A_SPEND_TX_PUBLISHED = auto()
    LOCK_TX_B_SPEND_TX_PUBLISHED = auto()
    LOCK_TX_A_REFUND_TX_SEEN = auto()
    LOCK_TX_A_REFUND_SPEND_TX_SEEN = auto()
    ERROR = auto()
    AUTOMATION_CONSTRAINT = auto()
    AUTOMATION_ACCEPTING_BID = auto()
    ITX_PUBLISHED = auto()
    ITX_REDEEM_PUBLISHED = auto()
    ITX_REFUND_PUBLISHED = auto()
    PTX_PUBLISHED = auto()
    PTX_REDEEM_PUBLISHED = auto()
    PTX_REFUND_PUBLISHED = auto()
    LOCK_TX_B_IN_MEMPOOL = auto()


class XmrSplitMsgTypes(IntEnum):
    BID = auto()
    BID_ACCEPT = auto()


class DebugTypes(IntEnum):
    NONE = 0
    BID_STOP_AFTER_COIN_A_LOCK = auto()
    BID_DONT_SPEND_COIN_A_LOCK_REFUND = auto()
    CREATE_INVALID_COIN_B_LOCK = auto()
    BUYER_STOP_AFTER_ITX = auto()
    MAKE_INVALID_PTX = auto()
    DONT_SPEND_ITX = auto()
    SKIP_LOCK_TX_REFUND = auto()
    SEND_LOCKED_XMR = auto()
    B_LOCK_TX_MISSED_SEND = auto()
    DUPLICATE_ACTIONS = auto()
    DONT_CONFIRM_PTX = auto()
    OFFER_LOCK_2_VALUE_INC = auto()


class NotificationTypes(IntEnum):
    NONE = 0
    OFFER_RECEIVED = auto()
    BID_RECEIVED = auto()
    BID_ACCEPTED = auto()


class AutomationOverrideOptions(IntEnum):
    DEFAULT = 0
    ALWAYS_ACCEPT = 1
    NEVER_ACCEPT = auto()


def strAutomationOverrideOption(option):
    if option == AutomationOverrideOptions.DEFAULT:
        return 'Default'
    if option == AutomationOverrideOptions.ALWAYS_ACCEPT:
        return 'Always Accept'
    if option == AutomationOverrideOptions.NEVER_ACCEPT:
        return 'Never Accept'
    return 'Unknown'


class VisibilityOverrideOptions(IntEnum):
    DEFAULT = 0
    HIDE = 1
    BLOCK = auto()


def strVisibilityOverrideOption(option):
    if option == VisibilityOverrideOptions.DEFAULT:
        return 'Default'
    if option == VisibilityOverrideOptions.HIDE:
        return 'Hide'
    if option == VisibilityOverrideOptions.BLOCK:
        return 'Block'
    return 'Unknown'


def strOfferState(state):
    if state == OfferStates.OFFER_SENT:
        return 'Sent'
    if state == OfferStates.OFFER_RECEIVED:
        return 'Received'
    if state == OfferStates.OFFER_ABANDONED:
        return 'Abandoned'
    if state == OfferStates.OFFER_EXPIRED:
        return 'Expired'
    return 'Unknown'


def strBidState(state):
    if state == BidStates.BID_SENT:
        return 'Sent'
    if state == BidStates.BID_RECEIVING:
        return 'Receiving'
    if state == BidStates.BID_RECEIVING_ACC:
        return 'Receiving accept'
    if state == BidStates.BID_RECEIVED:
        return 'Received'
    if state == BidStates.BID_ACCEPTED:
        return 'Accepted'
    if state == BidStates.SWAP_INITIATED:
        return 'Initiated'
    if state == BidStates.SWAP_PARTICIPATING:
        return 'Participating'
    if state == BidStates.SWAP_COMPLETED:
        return 'Completed'
    if state == BidStates.SWAP_TIMEDOUT:
        return 'Timed-out'
    if state == BidStates.BID_ABANDONED:
        return 'Abandoned'
    if state == BidStates.BID_STALLED_FOR_TEST:
        return 'Stalled (debug)'
    if state == BidStates.BID_ERROR:
        return 'Error'
    if state == BidStates.BID_REJECTED:
        return 'Rejected'
    if state == BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED:
        return 'Script coin locked'
    if state == BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX:
        return 'Script coin spend tx valid'
    if state == BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED:
        return 'Scriptless coin locked'
    if state == BidStates.XMR_SWAP_LOCK_RELEASED:
        return 'Script coin lock released'
    if state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
        return 'Script tx redeemed'
    if state == BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND:
        return 'Script pre-refund tx in chain'
    if state == BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED:
        return 'Scriptless tx redeemed'
    if state == BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED:
        return 'Scriptless tx recovered'
    if state == BidStates.XMR_SWAP_FAILED_REFUNDED:
        return 'Failed, refunded'
    if state == BidStates.XMR_SWAP_FAILED_SWIPED:
        return 'Failed, swiped'
    if state == BidStates.XMR_SWAP_FAILED:
        return 'Failed'
    if state == BidStates.SWAP_DELAYING:
        return 'Delaying'
    if state == BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS:
        return 'Exchanged script lock tx sigs msg'
    if state == BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX:
        return 'Exchanged script lock spend tx msg'
    if state == BidStates.BID_REQUEST_SENT:
        return 'Request sent'
    if state == BidStates.BID_REQUEST_ACCEPTED:
        return 'Request accepted'
    if state == BidStates.BID_STATE_UNKNOWN:
        return 'Unknown bid state'
    if state == BidStates.BID_EXPIRED:
        return 'Expired'
    return 'Unknown' + ' ' + str(state)


def strTxState(state):
    if state == TxStates.TX_NONE:
        return 'None'
    if state == TxStates.TX_SENT:
        return 'Sent'
    if state == TxStates.TX_CONFIRMED:
        return 'Confirmed'
    if state == TxStates.TX_REDEEMED:
        return 'Redeemed'
    if state == TxStates.TX_REFUNDED:
        return 'Refunded'
    if state == TxStates.TX_IN_MEMPOOL:
        return 'In Mempool'
    if state == TxStates.TX_IN_CHAIN:
        return 'In Chain'
    return 'Unknown'


def strTxType(tx_type):
    if tx_type == TxTypes.XMR_SWAP_A_LOCK:
        return 'Chain A Lock Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_SPEND:
        return 'Chain A Lock Spend Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND:
        return 'Chain A Lock Refund Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND_SPEND:
        return 'Chain A Lock Refund Spend Tx'
    if tx_type == TxTypes.XMR_SWAP_A_LOCK_REFUND_SWIPE:
        return 'Chain A Lock Refund Swipe Tx'
    if tx_type == TxTypes.XMR_SWAP_B_LOCK:
        return 'Chain B Lock Tx'
    if tx_type == TxTypes.ITX_PRE_FUNDED:
        return 'Funded mock initiate tx'
    return 'Unknown'


def strAddressType(addr_type):
    if addr_type == AddressTypes.OFFER:
        return 'Offer'
    if addr_type == AddressTypes.BID:
        return 'Bid'
    if addr_type == AddressTypes.RECV_OFFER:
        return 'Offer recv'
    if addr_type == AddressTypes.SEND_OFFER:
        return 'Offer send'
    return 'Unknown'


def getLockName(lock_type):
    if lock_type == TxLockTypes.SEQUENCE_LOCK_BLOCKS:
        return 'Sequence lock, blocks'
    if lock_type == TxLockTypes.SEQUENCE_LOCK_TIME:
        return 'Sequence lock, time'
    if lock_type == TxLockTypes.ABS_LOCK_BLOCKS:
        return 'blocks'
    if lock_type == TxLockTypes.ABS_LOCK_TIME:
        return 'time'


def describeEventEntry(event_type, event_msg):
    if event_type == EventLogTypes.FAILED_TX_B_LOCK_PUBLISH:
        return 'Failed to publish lock tx B'
    if event_type == EventLogTypes.LOCK_TX_A_PUBLISHED:
        return 'Lock tx A published'
    if event_type == EventLogTypes.LOCK_TX_B_PUBLISHED:
        return 'Lock tx B published'
    if event_type == EventLogTypes.FAILED_TX_B_SPEND:
        return 'Failed to publish lock tx B spend: ' + event_msg
    if event_type == EventLogTypes.LOCK_TX_A_SEEN:
        return 'Lock tx A seen in chain'
    if event_type == EventLogTypes.LOCK_TX_A_CONFIRMED:
        return 'Lock tx A confirmed in chain'
    if event_type == EventLogTypes.LOCK_TX_B_SEEN:
        return 'Lock tx B seen in chain'
    if event_type == EventLogTypes.LOCK_TX_B_CONFIRMED:
        return 'Lock tx B confirmed in chain'
    if event_type == EventLogTypes.LOCK_TX_B_IN_MEMPOOL:
        return 'Lock tx B seen in mempool'
    if event_type == EventLogTypes.DEBUG_TWEAK_APPLIED:
        return 'Debug tweak applied ' + event_msg
    if event_type == EventLogTypes.FAILED_TX_B_REFUND:
        return 'Failed to publish lock tx B refund'
    if event_type == EventLogTypes.LOCK_TX_B_INVALID:
        return 'Detected invalid lock Tx B'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_TX_PUBLISHED:
        return 'Lock tx A refund tx published'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_PUBLISHED:
        return 'Lock tx A refund spend tx published'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_SWIPE_TX_PUBLISHED:
        return 'Lock tx A refund swipe tx published'
    if event_type == EventLogTypes.LOCK_TX_B_REFUND_TX_PUBLISHED:
        return 'Lock tx B refund tx published'
    if event_type == EventLogTypes.LOCK_TX_A_SPEND_TX_PUBLISHED:
        return 'Lock tx A spend tx published'
    if event_type == EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED:
        return 'Lock tx B spend tx published'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_TX_SEEN:
        return 'Lock tx A refund tx seen in chain'
    if event_type == EventLogTypes.LOCK_TX_A_REFUND_SPEND_TX_SEEN:
        return 'Lock tx A refund spend tx seen in chain'
    if event_type == EventLogTypes.SYSTEM_WARNING:
        return 'Warning: ' + event_msg
    if event_type == EventLogTypes.ERROR:
        return 'Error: ' + event_msg
    if event_type == EventLogTypes.AUTOMATION_CONSTRAINT:
        return 'Failed auto accepting'
    if event_type == EventLogTypes.AUTOMATION_ACCEPTING_BID:
        return 'Auto accepting'
    if event_type == EventLogTypes.ITX_PUBLISHED:
        return 'Initiate tx published'
    if event_type == EventLogTypes.ITX_REDEEM_PUBLISHED:
        return 'Initiate tx redeem tx published'
    if event_type == EventLogTypes.ITX_REFUND_PUBLISHED:
        return 'Initiate tx refund tx published'
    if event_type == EventLogTypes.PTX_PUBLISHED:
        return 'Participate tx published'
    if event_type == EventLogTypes.PTX_REDEEM_PUBLISHED:
        return 'Participate tx redeem tx published'
    if event_type == EventLogTypes.PTX_REFUND_PUBLISHED:
        return 'Participate tx refund tx published'


def getVoutByAddress(txjs, p2sh):
    for o in txjs['vout']:
        try:
            if 'address' in o['scriptPubKey'] and o['scriptPubKey']['address'] == p2sh:
                return o['n']
            if p2sh in o['scriptPubKey']['addresses']:
                return o['n']
        except Exception:
            pass
    raise ValueError('Address output not found in txn')


def getVoutByScriptPubKey(txjs, scriptPubKey_hex: str) -> int:
    for o in txjs['vout']:
        try:
            if scriptPubKey_hex == o['scriptPubKey']['hex']:
                return o['n']
        except Exception:
            pass
    raise ValueError('scriptPubKey output not found in txn')


def replaceAddrPrefix(addr, coin_type, chain_name, addr_type='pubkey_address'):
    return encodeAddress(bytes((chainparams[coin_type][chain_name][addr_type],)) + decodeAddress(addr)[1:])


def getOfferProofOfFundsHash(offer_msg, offer_addr):
    # TODO: Hash must not include proof_of_funds sig if it exists in offer_msg
    h = hashlib.sha256()
    h.update(offer_addr.encode('utf-8'))
    offer_bytes = offer_msg.to_bytes()
    h.update(offer_bytes)
    return h.digest()


def getLastBidState(packed_states):
    num_states = len(packed_states) // 12
    if num_states < 2:
        return BidStates.BID_STATE_UNKNOWN
    return struct.unpack_from('<i', packed_states[(num_states - 2) * 12:])[0]
    try:
        num_states = len(packed_states) // 12
        if num_states < 2:
            return BidStates.BID_STATE_UNKNOWN
        return struct.unpack_from('<i', packed_states[(num_states - 2) * 12:])[0]
    except Exception:
        return BidStates.BID_STATE_UNKNOWN


def strSwapType(swap_type):
    if swap_type == SwapTypes.SELLER_FIRST:
        return 'seller_first'
    if swap_type == SwapTypes.XMR_SWAP:
        return 'xmr_swap'
    return None


def strSwapDesc(swap_type):
    if swap_type == SwapTypes.SELLER_FIRST:
        return 'Secret Hash'
    if swap_type == SwapTypes.XMR_SWAP:
        return 'Adaptor Sig'
    return None


inactive_states = [BidStates.SWAP_COMPLETED, BidStates.BID_ERROR, BidStates.BID_REJECTED, BidStates.SWAP_TIMEDOUT, BidStates.BID_ABANDONED, BidStates.BID_EXPIRED]


def isActiveBidState(state):
    if state >= BidStates.BID_ACCEPTED and state < BidStates.SWAP_COMPLETED:
        return True
    return state in (
        BidStates.SWAP_DELAYING,
        BidStates.XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX,
        BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED,
        BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED,
        BidStates.XMR_SWAP_LOCK_RELEASED,
        BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED,
        BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED,
        BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND,
        BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS,
        BidStates.XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX,
        BidStates.XMR_SWAP_FAILED,
        BidStates.BID_REQUEST_ACCEPTED,
    )


def isErrorBidState(state):
    return state in (
        BidStates.BID_STALLED_FOR_TEST,
        BidStates.BID_ERROR,
    )


def isFailingBidState(state):
    return state in (
        BidStates.BID_STALLED_FOR_TEST,
        BidStates.BID_ERROR,
        BidStates.XMR_SWAP_SCRIPT_TX_PREREFUND,
        BidStates.XMR_SWAP_NOSCRIPT_TX_RECOVERED,
        BidStates.XMR_SWAP_FAILED_REFUNDED,
        BidStates.XMR_SWAP_FAILED_SWIPED,
        BidStates.XMR_SWAP_FAILED,
    )


def isFinalBidState(state):
    return state in inactive_states
