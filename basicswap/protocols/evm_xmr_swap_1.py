# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Protocol interface and bid-state driver for EVM<->XMR swaps through the
SwapCreator contract, from the basicswap branch of our atomic-swap fork.

The EVM side (leader) escrows with newSwap, committing to both sides'
secp256k1 keys, and the XMR side (follower) locks XMR to the joint address.
Each side's spend half is valid on both curves, proven by the DLEAG sent with
the bid and the accept, so the secret claim() or refund() reveals is that
side's Monero spend half. View halves go over SMSG.

Windows: the EVM side refunds before timeout1 (unless ready) or from timeout2
to timeout3; the XMR side claims once ready or from timeout1 until timeout2,
and again from timeout3, which pays it and lets a stalled EVM side still take
the XMR, as adaptor-sig's mercy does. Refund and claim never overlap, but a tx
mined outside its window reverts and still reveals its key, so BasicSwap
sends each one well inside it: a window's start must be past in a confirmed
block, and its end a margin away.
"""

from web3.exceptions import TimeExhausted

from basicswap.util import ensure, TemporaryError
from basicswap.chainparams import Coins
from basicswap.basicswap_util import (
    ActionTypes,
    AddressTypes,
    BidStates,
    canAcceptBidState,
    EventLogTypes,
    getLastBidState,
    KeyTypes,
    MessageNetworkLinkTypes,
    MessageTypes,
    NotificationTypes as NT,
    SwapTypes,
    TxTypes,
    XmrSplitMsgTypes,
)
from basicswap.db import (
    Bid,
    Concepts,
    EvmXmrSwap,
    Offer,
)
from basicswap.messages_npb import (
    EvmXmrBidMessage,
    EvmXmrBidAcceptMessage,
    EvmXmrLockMessage,
)
from basicswap.interface.evm import keys as evmkeys
from basicswap.interface.evm.swapcreator import make_swap, swap_id
from basicswap.interface.evm.rpc import EthRpcError
from basicswap import multibid
from basicswap.network.bsx_network import networkTypeToID
from basicswap.network.util import getMsgPubkey
from . import ProtocolInterface

PROTOCOL_VERSION_EVM_XMR = 1
MINPROTO_VERSION_EVM_XMR = 1
MIN_LOCK_SECONDS = 4 * 60 * 60


class EvmXmrSwapInterface(ProtocolInterface):
    swap_type = SwapTypes.EVM_XMR_SWAP


def weAreEvmSide(self, offer, bid) -> bool:
    """The maker sends coin_from, the bidder coin_to; the EVM-coin sender is the EVM side."""
    evm_is_from: bool = Coins(offer.coin_from) in self.evm_contract_coins
    return evm_is_from if bid.was_received else (not evm_is_from)


def evmAmountsForBid(self, offer, bid):
    """(EVM amount, XMR amount) for a bid, either direction, in each coin's units."""
    if Coins(offer.coin_from) in self.evm_contract_coins:
        return int(bid.amount), int(bid.amount_to)
    return int(bid.amount_to), int(bid.amount)


def evmCoin(self, coin_from, coin_to):
    return coin_from if Coins(coin_from) in self.evm_contract_coins else coin_to


def _contract(self, evm_swap):
    return self.ci(evm_swap.evm_coin).getContract(address=evm_swap.contract_address)


def _chainTime(self, evm_swap) -> int:
    return self.ci(evm_swap.evm_coin).rpc.get_block_time()


_EVM_XMR_TERMINAL_STATES = (
    BidStates.SWAP_COMPLETED,
    BidStates.XMR_SWAP_FAILED_REFUNDED,
    BidStates.XMR_SWAP_FAILED_NOTHING_TO_RECOVER,
    BidStates.BID_ERROR,
    BidStates.BID_ABANDONED,
    BidStates.BID_REJECTED,
    BidStates.BID_EXPIRED,
    # Nothing is locked: the EVM side can't time out once its lock is sent
    BidStates.SWAP_TIMEDOUT,
)


def evmAddressInOpenSwaps(self, evm_coin, address: str, cursor) -> bool:
    """True while an unfinished bid's escrow is tied to address."""
    terminal: str = ", ".join(str(int(s)) for s in _EVM_XMR_TERMINAL_STATES)
    return (
        cursor.execute(
            "SELECT 1 FROM evm_xmr_swaps s JOIN bids b ON b.bid_id = s.bid_id "
            "WHERE s.evm_coin = :evm_coin "
            "AND (LOWER(s.evm_addr) = :addr OR LOWER(s.xmr_side_addr) = :addr) "
            f"AND b.state NOT IN ({terminal}) LIMIT 1",
            {"evm_coin": int(evm_coin), "addr": address.lower()},
        ).fetchone()
        is not None
    )


# --- keys --------------------------------------------------------------------


def _sides(we_are_evm: bool):
    return ("evm", "xmr") if we_are_evm else ("xmr", "evm")


def _setOwnKeys(self, evm_swap, created_at: int, we_are_evm: bool, cursor) -> bytes:
    """Derive our halves from the seed; returns the spend half's DLEAG."""
    ci_xmr = self.ci(Coins.XMR)
    evm_swap.contract_count = self.getNewContractId(cursor)
    view_type, spend_type = (
        (KeyTypes.KBVL, KeyTypes.KBSL) if we_are_evm else (KeyTypes.KBVF, KeyTypes.KBSF)
    )

    def pathKey(key_type) -> bytes:
        return self.getPathKey(
            evm_swap.evm_coin,
            Coins.XMR,
            created_at,
            evm_swap.contract_count,
            key_type,
            for_ed25519=True,
        )

    kbv: bytes = pathKey(view_type)
    kbs: bytes = pathKey(spend_type)
    dleag: bytes = ci_xmr.proveDLEAG(kbs)
    ours, _ = _sides(we_are_evm)
    setattr(evm_swap, f"{ours}_kbv", kbv)
    setattr(evm_swap, f"{ours}_kbs", kbs)
    setattr(evm_swap, f"{ours}_pkbs", ci_xmr.getPubkey(kbs))
    setattr(evm_swap, f"{ours}_pkas", dleag[0:33])
    return dleag


def _storePeerMessage(self, evm_swap, msg_data, peer_is_evm: bool) -> None:
    """The peer's view half and first DLEAG part; checked once the DLEAG is complete."""
    peer, _ = _sides(peer_is_evm)
    setattr(evm_swap, f"{peer}_kbv", bytes(msg_data.kbv))
    evm_swap.peer_dleag = bytes(msg_data.kbs_dleag)
    if not peer_is_evm:
        ci_evm = self.ci(evm_swap.evm_coin)
        ensure(ci_evm.isValidAddress(msg_data.claimer_addr), "Invalid claimer address")
        evm_swap.xmr_side_addr = msg_data.claimer_addr
        evm_swap.gas_request = msg_data.gas_request


def _swapsInProgress(self, evm_coin, evm_side: bool):
    for bid_id, (bid, offer) in self.swaps_in_progress.items():
        if (
            offer.swap_type == SwapTypes.EVM_XMR_SWAP
            and Coins(evmCoin(self, offer.coin_from, offer.coin_to)) == Coins(evm_coin)
            and weAreEvmSide(self, offer, bid) == evm_side
        ):
            yield bid_id, bid, offer


def _gasRequest(self, evm_coin) -> int:
    """XMR side: wei to ask for so this claim and those in progress are covered."""
    ci_evm = self.ci(evm_coin)
    in_progress: int = sum(1 for _ in _swapsInProgress(self, evm_coin, False))
    needed: int = ci_evm.dripGasCost() * (in_progress + 1)
    return max(0, needed - ci_evm.rpc.get_balance(ci_evm.account.address))


def _assemblePeerDleag(
    self, cursor, bid, evm_swap, msg_type, addr_from, addr_to
) -> None:
    if len(evm_swap.peer_dleag) < self.ci(Coins.XMR).lengthDLEAG():
        evm_swap.peer_dleag += self.splitDleag(
            cursor, bid.bid_id, msg_type, addr_from, addr_to, evm_swap
        )


def _checkPeerKeys(self, evm_swap, peer_is_evm: bool) -> None:
    ci_xmr = self.ci(Coins.XMR)
    peer, _ = _sides(peer_is_evm)
    ensure(ci_xmr.verifyKey(getattr(evm_swap, f"{peer}_kbv")), "Invalid peer view key")
    dleag: bytes = evm_swap.peer_dleag
    ensure(ci_xmr.verifyDLEAG(dleag), "Invalid DLEAG proof")
    pkas: bytes = dleag[0:33]
    pkbs: bytes = dleag[33 : 33 + 32]
    evmkeys.commitment(pkas)
    ensure(ci_xmr.verifyPubkey(pkbs), "Invalid peer spend pubkey")
    setattr(evm_swap, f"{peer}_pkas", pkas)
    setattr(evm_swap, f"{peer}_pkbs", pkbs)


def _checkDistinctKeys(self, evm_swap) -> None:
    ci_xmr = self.ci(Coins.XMR)
    ensure(evm_swap.evm_pkbs != evm_swap.xmr_pkbs, "Duplicate spend pubkey")
    ensure(
        ci_xmr.getPubkey(evm_swap.evm_kbv) != ci_xmr.getPubkey(evm_swap.xmr_kbv),
        "Duplicate view pubkey",
    )


def sharedKeys(self, evm_swap):
    """(joint private view key, joint public spend key)"""
    ci_xmr = self.ci(Coins.XMR)
    return (
        ci_xmr.sumKeys(evm_swap.evm_kbv, evm_swap.xmr_kbv),
        ci_xmr.sumPubkeys(evm_swap.evm_pkbs, evm_swap.xmr_pkbs),
    )


def _revealedKey(self, revealed: bytes, expect_pkbs: bytes) -> bytes:
    ci_xmr = self.ci(Coins.XMR)
    ensure(ci_xmr.getPubkey(revealed) == expect_pkbs, "Revealed key mismatch")
    return revealed


# --- the on-chain swap -------------------------------------------------------


def _nonce(bid_id: bytes) -> int:
    return int.from_bytes(bid_id, "big")


def _swap(self, offer, bid, evm_swap) -> tuple:
    evm_amount, _ = evmAmountsForBid(self, offer, bid)
    return make_swap(
        evm_swap.evm_addr,
        evm_swap.xmr_side_addr,
        evmkeys.commitment(evm_swap.xmr_pkas),
        evmkeys.commitment(evm_swap.evm_pkas),
        evm_swap.timeout1,
        evm_swap.timeout2,
        evm_swap.timeout3,
        self.ci(evm_swap.evm_coin).toWei(evm_amount),
        _nonce(bid.bid_id),
    )


def _lockReceipt(self, evm_swap):
    w3 = self.ci(evm_swap.evm_coin).rpc.w3
    return w3.eth.get_transaction_receipt(evm_swap.evm_lock_tx_id)


def _evmLock(self, offer, bid, evm_swap):
    """(swap, state, revealed key); state is INVALID, PENDING, READY, CLAIMED or REFUNDED."""
    swap = _swap(self, offer, bid, evm_swap)
    contract = _contract(self, evm_swap)
    sid: bytes = swap_id(swap)
    stage: str = contract.stage(sid)
    if stage != "COMPLETED":
        return swap, stage, None
    kind, secret = contract.find_completion(
        sid, _lockReceipt(self, evm_swap)["blockNumber"]
    )
    ensure(kind is not None, "Completed swap has no Claimed or Refunded event")
    return swap, kind, evmkeys.revealed_key(secret)


def evmSwapNeeds(ci_evm) -> int:
    """Coin units an EVM-side swap needs beyond its escrow: its fees and refund reserve."""
    gas_price: int = ci_evm.rpc.gas_price()
    return ci_evm.estSwapFee(gas_price=gas_price) + ci_evm.refundReserve(gas_price)


def evmFree(self, evm_coin, exclude_bid: bytes = None) -> int:
    """Balance less what open EVM-side swaps may still spend: the escrow and lock
    gas until the lock is sent, setReady until it is, the drip until it's sent,
    and a refund reserve."""
    ci_evm = self.ci(evm_coin)
    free: int = ci_evm.getSpendableBalance()
    gas_price = None
    cursor = None
    try:
        for bid_id, bid, offer in _swapsInProgress(self, evm_coin, True):
            if bid_id == exclude_bid:
                continue
            if gas_price is None:
                gas_price = ci_evm.rpc.gas_price()
            free -= ci_evm.refundReserve(gas_price)
            if bid.state == BidStates.BID_ACCEPTED:
                free -= evmAmountsForBid(self, offer, bid)[0] + ci_evm.estSwapFee(
                    gas_price=gas_price
                )
                continue
            if cursor is None:
                cursor = self.openDB()
            evm_swap = self.queryOne(EvmXmrSwap, cursor, {"bid_id": bid_id})
            free -= ci_evm.estSwapFee(
                lock=False,
                ready=bid.state
                in (
                    BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED,
                    BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED,
                ),
                drip=evm_swap is not None and _dripDue(evm_swap),
                gas_price=gas_price,
            )
    finally:
        if cursor is not None:
            self.closeDB(cursor, commit=False)
    return free


def evmSpendable(self, evm_coin, exclude_bid: bytes = None) -> int:
    """Balance a new EVM-side swap can escrow, after open swaps and its own needs."""
    return evmFree(self, evm_coin, exclude_bid) - evmSwapNeeds(self.ci(evm_coin))


def ensureEvmFunds(self, evm_coin, amount: int, exclude_bid: bytes = None) -> None:
    ci_evm = self.ci(evm_coin)
    spendable: int = evmSpendable(self, evm_coin, exclude_bid)
    ensure(
        amount <= spendable,
        f"{ci_evm.coin_name()} balance too low: {ci_evm.format_amount(amount)} needed, "
        f"{ci_evm.format_amount(max(0, spendable))} free after fees, refund reserves "
        "and open swaps",
    )


def xmrLockMinMargin(self) -> int:
    """Least time left before timeout1 to send the XMR lock with: the EVM side
    refunds once two release margins are left without a confirmed lock."""
    return self.getBLockMinMargin(self.ci(Coins.XMR)) + self._sc_lock_release_min_margin


def _confirmedHeight(self, evm_swap) -> int:
    ci_evm = self.ci(evm_swap.evm_coin)
    return max(0, ci_evm.rpc.get_block_number() - ci_evm.blocks_confirmed + 1)


def _confirmedChainTime(self, evm_swap) -> int:
    """Time of the block at blocks_confirmed depth; a timeout past it stays past."""
    w3 = self.ci(evm_swap.evm_coin).rpc.w3
    return w3.eth.get_block(_confirmedHeight(self, evm_swap))["timestamp"]


def _evmClaimable(evm_swap, state_name, now, confirmed_now, margin: int) -> bool:
    if state_name not in ("PENDING", "READY"):
        return False
    if confirmed_now >= evm_swap.timeout3:
        return True
    if now >= evm_swap.timeout2 - margin:
        return False
    return state_name == "READY" or confirmed_now >= evm_swap.timeout1


def _evmRefundable(evm_swap, state_name, now, confirmed_now, margin: int) -> bool:
    if state_name not in ("PENDING", "READY"):
        return False
    if state_name == "PENDING" and now < evm_swap.timeout1 - margin:
        return True
    return confirmed_now >= evm_swap.timeout2 and now < evm_swap.timeout3 - margin


def _validateEvmLock(self, offer, evm_swap, swap, now: int) -> bool:
    """XMR side: False while the lock is too shallow; raises if it isn't the agreed swap."""
    ci_evm = self.ci(evm_swap.evm_coin)
    receipt = _lockReceipt(self, evm_swap)
    ensure(receipt["status"] == 1, "EVM lock tx failed")
    contract = _contract(self, evm_swap)
    sid = contract.new_swap_event(receipt)[0]
    ensure(sid == swap_id(swap), "EVM lock tx created another swap")
    duration: int = int(offer.lock_value)
    ensure(
        evm_swap.timeout2 - evm_swap.timeout1 == duration
        and evm_swap.timeout3 - evm_swap.timeout2 == duration
        and evm_swap.timeout1 <= now + duration,
        "EVM lock timeouts differ from the offer",
    )
    depth: int = ci_evm.rpc.get_block_number() - receipt["blockNumber"] + 1
    if depth < ci_evm.blocks_confirmed:
        return False
    return not _anyBlocked(self, ci_evm, (contract.address, evm_swap.xmr_side_addr))


def ensureContractUnblocked(ci_evm, address: str) -> None:
    """A blocklisted swap contract can't take new locks."""
    ensure(
        not ci_evm.isBlocked(address),
        f"{ci_evm.coin_name()} swap contract {address} is blocklisted",
    )


def _anyBlocked(self, ci_evm, addresses) -> bool:
    """Blocked addresses can't pay out, so the swap could only end in a revert."""
    for address in addresses:
        if ci_evm.isBlocked(address):
            self.log.warning(f"{address} is on the {ci_evm.coin_name()} blocklist.")
            return True
    return False


def _xmrRestoreHeight(self, cursor=None) -> int:
    """The joint watch wallet scans from here: the XMR lock comes after the bid."""
    ci_xmr = self.ci(Coins.XMR)
    return max(ci_xmr.getChainHeight(), self.getWalletRestoreHeight(ci_xmr, cursor))


# --- bid handshake -----------------------------------------------------------


def postEvmXmrBid(
    self, offer_id: bytes, amount: int, addr_send_from: str = None, extra_options={}
) -> bytes:
    """Bidder: send an EvmXmrBidMessage for an EVM<->XMR offer."""
    self.log.debug(f"postEvmXmrBid {self.log.id(offer_id)}")
    try:
        cursor = self.openDB()
        offer = self.getOffer(offer_id, cursor=cursor)
        ensure(offer, f"Offer not found: {self.log.id(offer_id)}.")
        ensure(offer.swap_type == SwapTypes.EVM_XMR_SWAP, "Not an EVM<->XMR offer")
        ensure(
            offer.protocol_version >= MINPROTO_VERSION_EVM_XMR,
            "Incompatible offer protocol version",
        )
        ensure(offer.expire_at > self.getTime(), "Offer has expired")
        ensure(offer.active_ind == 1, "Offer not active")
        # One bid row can't play both sides of an EVM swap
        ensure(not offer.was_sent, "Can't bid on your own EVM<->XMR offer")

        coin_from = Coins(offer.coin_from)
        coin_to = Coins(offer.coin_to)
        ci_from = self.ci(coin_from)
        self.checkCoinsReady(coin_from, coin_to)

        bid_created_at: int = self.getTime()
        valid_for_seconds: int = extra_options.get("valid_for_seconds", 60 * 10)
        self.validateBidValidTime(
            offer.swap_type, offer.coin_from, offer.coin_to, valid_for_seconds
        )

        amount, amount_to, bid_rate = self.setBidAmounts(
            amount, offer, extra_options, ci_from
        )
        self.validateBidAmount(offer, amount, bid_rate)

        bid_addr: str = self.prepareSMSGAddress(
            addr_send_from, AddressTypes.BID, cursor
        )
        bid_message_nets = self.selectMessageNetStringForConcept(
            Concepts.OFFER, offer.offer_id, offer.message_nets, cursor
        )

        bid = Bid(
            protocol_version=PROTOCOL_VERSION_EVM_XMR,
            active_ind=1,
            offer_id=offer_id,
            amount=amount,
            amount_to=amount_to,
            rate=bid_rate,
            created_at=bid_created_at,
            expire_at=bid_created_at + valid_for_seconds,
            bid_addr=bid_addr,
            was_sent=True,
            was_received=False,
            message_nets=bid_message_nets,
        )

        evm_coin = evmCoin(self, coin_from, coin_to)
        we_are_evm: bool = weAreEvmSide(self, offer, bid)
        ci_evm = self.ci(evm_coin)
        if we_are_evm:
            ensureEvmFunds(self, evm_coin, amount_to)
        evm_swap = EvmXmrSwap(
            evm_coin=int(evm_coin),
            contract_address=ci_evm.getContractAddress(),
        )
        ensureContractUnblocked(ci_evm, evm_swap.contract_address)
        self.setMsgSplitInfo(evm_swap)
        bid.chain_b_height_start = _xmrRestoreHeight(self, cursor)
        dleag: bytes = _setOwnKeys(self, evm_swap, bid_created_at, we_are_evm, cursor)
        my_addr: str = ci_evm.getNewAddress()
        if we_are_evm:
            evm_swap.evm_addr = my_addr
        else:
            evm_swap.xmr_side_addr = my_addr

        split_size_init, _ = evm_swap.getMsgSplitInfo()
        msg_buf = EvmXmrBidMessage()
        msg_buf.protocol_version = PROTOCOL_VERSION_EVM_XMR
        msg_buf.offer_msg_id = offer_id
        msg_buf.time_valid = valid_for_seconds
        msg_buf.amount = amount
        msg_buf.amount_to = amount_to
        msg_buf.claimer_addr = "" if we_are_evm else my_addr
        msg_buf.kbv = evm_swap.evm_kbv if we_are_evm else evm_swap.xmr_kbv
        msg_buf.kbs_dleag = dleag[:split_size_init]
        msg_buf.gas_request = 0 if we_are_evm else _gasRequest(self, evm_coin)
        if offer.smsg_payload_version and offer.smsg_payload_version > 1:
            msg_buf.message_nets = self.getMessageNetsString()

        payload_hex = (
            str.format("{:02x}", MessageTypes.EVM_XMR_BID_FL) + msg_buf.to_bytes().hex()
        )
        msg_valid: int = max(self.SMSG_SECONDS_IN_HOUR, valid_for_seconds)
        bid_id = self.sendMessage(
            bid_addr,
            offer.addr_from,
            payload_hex,
            msg_valid,
            cursor,
            timestamp=bid_created_at,
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )
        bid.bid_id = bid_id
        evm_swap.bid_id = bid_id
        self.sendXmrSplitMessages(
            XmrSplitMsgTypes.BID,
            bid_addr,
            offer.addr_from,
            evm_swap,
            dleag,
            msg_valid,
            {},
            cursor,
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
            parent_msg_id=bid_id,
        )
        bid.setState(BidStates.BID_SENT)
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        self.commitDB()
        self.log.info(f"Sent EVM_XMR_BID_FL {self.log.id(bid_id)}")
        return bid_id
    finally:
        self.closeDB(cursor)


def processEvmXmrBid(self, msg) -> None:
    """Maker: receive an EvmXmrBidMessage; the bid is checked once its DLEAG is complete."""
    self.log.debug(f"Processing EVM<->XMR bid msg {self.log.id(msg['msgid'])}")
    now: int = self.getTime()
    bid_bytes = self.getSmsgMsgBytes(msg)
    bid_data = EvmXmrBidMessage(init_all=False)
    bid_data.from_bytes(bid_bytes)

    ensure(len(bid_data.offer_msg_id) == 28, "Bad offer_id length")
    offer_id = bid_data.offer_msg_id
    offer = self.getOffer(offer_id)
    ensure(offer and offer.was_sent, f"Offer not found: {self.log.id(offer_id)}")
    ensure(offer.swap_type == SwapTypes.EVM_XMR_SWAP, "Bid/offer swap type mismatch")
    bid_rate: int = self.validateIncomingBid(msg, offer, bid_data, now)
    ensure(
        bid_data.protocol_version >= MINPROTO_VERSION_EVM_XMR,
        "Unsupported protocol version",
    )
    ensure(len(bid_data.kbs_dleag) <= 16000, "Invalid kbs_dleag size")
    self.validateMessageNets(bid_data.message_nets)

    bid_id = bytes.fromhex(msg["msgid"])
    evm_coin = evmCoin(self, offer.coin_from, offer.coin_to)

    ensure(
        self.getBid(bid_id, with_txns=False) is None,
        f"Duplicate bid: {self.log.id(bid_id)}",
    )
    bid = Bid(
        active_ind=1,
        bid_id=bid_id,
        offer_id=offer_id,
        protocol_version=bid_data.protocol_version,
        amount=bid_data.amount,
        amount_to=bid_data.amount_to,
        rate=bid_rate,
        created_at=msg["sent"],
        expire_at=msg["sent"] + bid_data.time_valid,
        bid_addr=msg["from"],
        pk_bid_addr=getMsgPubkey(self, msg),
        was_received=True,
        message_nets=self.selectMessageNetString(
            [networkTypeToID(msg.get("msg_net", "smsg"))], bid_data.message_nets
        ),
    )
    evm_swap = EvmXmrSwap(
        bid_id=bid_id,
        split_parent_msg_id=bid_id,
        evm_coin=int(evm_coin),
        contract_address=self.ci(evm_coin).getContractAddress(),
    )
    self.setMsgSplitInfo(evm_swap)
    bid.chain_b_height_start = _xmrRestoreHeight(self)
    _storePeerMessage(self, evm_swap, bid_data, not weAreEvmSide(self, offer, bid))

    bid.setState(BidStates.BID_RECEIVING)
    self.log.info(
        f"Receiving EVM<->XMR bid {self.log.id(bid_id)} for offer {self.log.id(offer_id)}."
    )
    try:
        cursor = self.openDB()
        self.addRecvBidNetworkLink(msg, bid_id, cursor)
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        self.addMessageNetworkLink(
            Concepts.BID,
            offer_id,
            MessageNetworkLinkTypes.RECEIVED_ON,
            networkTypeToID(msg.get("type", "smsg")),
            cursor,
        )
    finally:
        self.closeDB(cursor)


def receiveEvmXmrBid(self, bid, cursor) -> None:
    """Maker: the bid's DLEAG is complete; check it and queue auto-accept."""
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
    ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
    evm_swap = self.queryOne(EvmXmrSwap, cursor, {"bid_id": bid.bid_id})
    ensure(evm_swap, f"EVM<->XMR swap not found: {self.log.id(bid.bid_id)}.")
    peer_is_evm: bool = not weAreEvmSide(self, offer, bid)

    _assemblePeerDleag(
        self, cursor, bid, evm_swap, XmrSplitMsgTypes.BID, bid.bid_addr, offer.addr_from
    )
    _checkPeerKeys(self, evm_swap, peer_is_evm)

    bid.setState(BidStates.BID_RECEIVED)
    self.log.info(f"Received EVM<->XMR bid {self.log.id(bid.bid_id)}.")
    self.notify(
        NT.BID_RECEIVED,
        {"type": "evm_xmr", "bid_id": bid.bid_id.hex(), "offer_id": bid.offer_id.hex()},
        cursor,
    )
    if self.shouldAutoAcceptBid(offer, bid, cursor):
        delay = self.get_delay_event_seconds()
        self.log.info(
            f"Auto accepting EVM<->XMR bid {self.log.id(bid.bid_id)} in {delay} seconds."
        )
        self.createActionInSession(
            delay, ActionTypes.ACCEPT_EVM_XMR_BID, bid.bid_id, cursor
        )
        bid.setState(BidStates.SWAP_DELAYING)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)


def acceptEvmXmrBid(self, bid_id: bytes, cursor=None) -> None:
    """Maker: send the EvmXmrBidAcceptMessage and set BID_ACCEPTED."""
    self.log.info(f"Accepting EVM<->XMR bid {self.log.id(bid_id)}")
    now: int = self.getTime()
    try:
        use_cursor = self.openDB(cursor)
        bid, evm_swap = self.getXmrBidFromSession(use_cursor, bid_id, EvmXmrSwap)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(evm_swap, f"EVM<->XMR swap not found: {self.log.id(bid_id)}.")
        ensure(bid.expire_at > now + self._bid_accept_leeway, "Bid expired")
        last_bid_state = bid.state
        if last_bid_state == BidStates.SWAP_DELAYING:
            last_bid_state = getLastBidState(bid.states)
        ensure(
            canAcceptBidState(last_bid_state),
            f"Wrong bid state: {BidStates(last_bid_state).name}",
        )

        offer = self.queryOne(Offer, use_cursor, {"offer_id": bid.offer_id})
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(offer.expire_at > now, "Offer has expired")
        ensure(offer.active_ind == 1, "Offer not active")
        self.checkCoinsReady(offer.coin_from, offer.coin_to)
        ensureContractUnblocked(self.ci(evm_swap.evm_coin), evm_swap.contract_address)

        we_are_evm: bool = weAreEvmSide(self, offer, bid)
        if we_are_evm:
            # Adaptor-sig funds its lock tx here; the escrow is sent after the accept
            ensureEvmFunds(
                self, evm_swap.evm_coin, evmAmountsForBid(self, offer, bid)[0], bid_id
            )
        dleag: bytes = _setOwnKeys(
            self, evm_swap, bid.created_at, we_are_evm, use_cursor
        )
        _checkDistinctKeys(self, evm_swap)
        my_addr: str = self.ci(evm_swap.evm_coin).getNewAddress()
        if we_are_evm:
            evm_swap.evm_addr = my_addr
        else:
            evm_swap.xmr_side_addr = my_addr

        split_size_init, _ = evm_swap.getMsgSplitInfo()
        msg_buf = EvmXmrBidAcceptMessage()
        msg_buf.bid_msg_id = bid_id
        msg_buf.claimer_addr = "" if we_are_evm else my_addr
        msg_buf.kbv = evm_swap.evm_kbv if we_are_evm else evm_swap.xmr_kbv
        msg_buf.kbs_dleag = dleag[:split_size_init]
        msg_buf.contract_address = evm_swap.contract_address
        msg_buf.gas_request = 0 if we_are_evm else _gasRequest(self, evm_swap.evm_coin)

        payload_hex = (
            str.format("{:02x}", MessageTypes.EVM_XMR_BID_ACCEPT_LF)
            + msg_buf.to_bytes().hex()
        )
        msg_valid: int = self.getAcceptBidMsgValidTime(bid)
        accept_msg_id = self.sendMessage(
            offer.addr_from,
            bid.bid_addr,
            payload_hex,
            msg_valid,
            use_cursor,
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
        )
        self.addMessageLink(
            Concepts.BID,
            bid_id,
            MessageTypes.BID_ACCEPT,
            accept_msg_id,
            cursor=use_cursor,
        )
        self.sendXmrSplitMessages(
            XmrSplitMsgTypes.BID_ACCEPT,
            offer.addr_from,
            bid.bid_addr,
            evm_swap,
            dleag,
            msg_valid,
            {},
            use_cursor,
            message_nets=bid.message_nets,
            payload_version=offer.smsg_payload_version,
            parent_msg_id=accept_msg_id,
        )

        bid.setState(BidStates.BID_ACCEPTED)
        bid.in_progress = 1
        self.saveBidInSession(bid_id, bid, use_cursor, evm_swap, save_in_progress=offer)
        self.log.info(f"Sent EVM_XMR_BID_ACCEPT_LF {self.log.id(bid_id)}")
    finally:
        if cursor is None:
            self.closeDB(use_cursor)


def processEvmXmrBidAccept(self, msg) -> None:
    """Bidder: receive the accept; it is checked once its DLEAG is complete."""
    self.log.debug(f"Processing EVM<->XMR bid accept {self.log.id(msg['msgid'])}")
    msg_bytes = self.getSmsgMsgBytes(msg)
    msg_data = EvmXmrBidAcceptMessage(init_all=False)
    msg_data.from_bytes(msg_bytes)

    ensure(len(msg_data.bid_msg_id) == 28, "Bad bid_msg_id length")
    bid_id = msg_data.bid_msg_id
    try:
        cursor = self.openDB()
        bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(evm_swap, f"EVM<->XMR swap not found: {self.log.id(bid_id)}.")
        ensure(bid.state == BidStates.BID_SENT, f"Unexpected bid state {bid.state}")
        offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(msg["to"] == bid.bid_addr, "Received on incorrect address")
        ensure(msg["from"] == offer.addr_from, "Sent from incorrect address")
        ensure(len(msg_data.kbs_dleag) <= 16000, "Invalid kbs_dleag size")
        ensure(
            msg_data.contract_address.lower() == evm_swap.contract_address.lower(),
            "Accept names another swap contract",
        )

        _storePeerMessage(self, evm_swap, msg_data, not weAreEvmSide(self, offer, bid))
        evm_swap.split_parent_msg_id = bytes.fromhex(msg["msgid"])

        bid.setState(BidStates.BID_RECEIVING_ACC)
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        self.log.info(f"Receiving EVM_XMR_BID_ACCEPT_LF {self.log.id(bid_id)}")
    finally:
        self.closeDB(cursor)


def receiveEvmXmrBidAccept(self, bid, cursor) -> None:
    """Bidder: the accept's DLEAG is complete; check it and start the swap."""
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
    ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
    evm_swap = self.queryOne(EvmXmrSwap, cursor, {"bid_id": bid.bid_id})
    ensure(evm_swap, f"EVM<->XMR swap not found: {self.log.id(bid.bid_id)}.")
    peer_is_evm: bool = not weAreEvmSide(self, offer, bid)

    _assemblePeerDleag(
        self,
        cursor,
        bid,
        evm_swap,
        XmrSplitMsgTypes.BID_ACCEPT,
        offer.addr_from,
        bid.bid_addr,
    )
    _checkPeerKeys(self, evm_swap, peer_is_evm)
    _checkDistinctKeys(self, evm_swap)

    if evm_swap.evm_lock_tx_id is None:
        bid.setState(BidStates.BID_ACCEPTED)
    else:
        _setEvmLockSeen(self, bid, cursor)
    bid.in_progress = 1
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap, save_in_progress=offer)
    self.log.info(f"Received EVM<->XMR bid accept {self.log.id(bid.bid_id)}")


def _setEvmLockSeen(self, bid, cursor) -> None:
    bid.setState(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
    self.logBidEvent(bid.bid_id, EventLogTypes.EVM_LOCK_TX_SEEN, "", cursor)


def processEvmXmrLock(self, msg) -> None:
    """XMR side: receive the Swap fields; kept until the accept completes if it is still arriving."""
    self.log.debug(f"Processing EVM<->XMR lock msg {self.log.id(msg['msgid'])}")
    msg_bytes = self.getSmsgMsgBytes(msg)
    msg_data = EvmXmrLockMessage(init_all=False)
    msg_data.from_bytes(msg_bytes)
    ensure(len(msg_data.bid_msg_id) == 28, "Bad bid_msg_id length")
    bid_id = msg_data.bid_msg_id
    try:
        cursor = self.openDB()
        bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
        ensure(bid, f"Bid not found: {self.log.id(bid_id)}.")
        ensure(evm_swap, f"EVM<->XMR swap not found: {self.log.id(bid_id)}.")
        offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
        ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
        ensure(weAreEvmSide(self, offer, bid) is False, "Lock msg for EVM side")
        addr_from: str = offer.addr_from if bid.was_sent else bid.bid_addr
        addr_to: str = bid.bid_addr if bid.was_sent else offer.addr_from
        ensure(msg["to"] == addr_to, "Received on incorrect address")
        ensure(msg["from"] == addr_from, "Sent from incorrect address")
        # The EVM side escrows once it has sent its accept, which may still be arriving
        ensure(
            bid.state in (BidStates.BID_ACCEPTED, BidStates.BID_RECEIVING_ACC),
            f"Unexpected bid state {bid.state}",
        )
        ensure(evm_swap.evm_lock_tx_id is None, "EVM lock already received")
        ci_evm = self.ci(evm_swap.evm_coin)
        ensure(ci_evm.isValidAddress(msg_data.owner), "Invalid swap owner address")

        evm_swap.evm_addr = msg_data.owner
        evm_swap.timeout1 = msg_data.timeout1
        evm_swap.timeout2 = msg_data.timeout2
        evm_swap.timeout3 = msg_data.timeout3
        evm_swap.xmr_lock_deadline = msg_data.xmr_lock_deadline
        evm_swap.evm_lock_tx_id = bytes(msg_data.lock_tx_id)
        if bid.state == BidStates.BID_ACCEPTED:
            _setEvmLockSeen(self, bid, cursor)
            self.swaps_in_progress[bid_id] = (bid, offer)
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        self.log.info(f"Received EVM_XMR_LOCK {self.log.id(bid_id)}")
    finally:
        self.closeDB(cursor)


# --- queued action helpers ---------------------------------------------------


def sendEvmLock(self, bid_id: bytes, cursor) -> None:
    """EVM side: escrow the EVM coin with newSwap and tell the XMR side the struct."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
    ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")

    ci_evm = self.ci(evm_swap.evm_coin)
    contract = _contract(self, evm_swap)
    evm_amount, _ = evmAmountsForBid(self, offer, bid)
    duration: int = int(offer.lock_value)

    def sign(tx_nonce):
        return contract.sign_new_swap(
            ci_evm.account,
            claim_commitment=evmkeys.commitment(evm_swap.xmr_pkas),
            refund_commitment=evmkeys.commitment(evm_swap.evm_pkas),
            claimer=evm_swap.xmr_side_addr,
            duration1=duration,
            duration2=duration,
            duration3=duration,
            value=ci_evm.toWei(evm_amount),
            nonce=_nonce(bid_id),
            tx_nonce=tx_nonce,
        )

    sent: bool = self.countBidEvents(bid, EventLogTypes.EVM_LOCK_TX_SENT, cursor) > 0
    if not sent:
        if _anyBlocked(self, ci_evm, (contract.address, evm_swap.evm_addr)):
            raise TemporaryError("EVM lock not sent, an address is blocked")
        # Its reserve was checked on accept; a gas price rise since mustn't fail the swap
        free: int = evmFree(self, evm_swap.evm_coin, bid_id)
        if evm_amount + ci_evm.estSwapFee(ready=False, drip=False) > free:
            raise TemporaryError(
                f"EVM lock not sent: {ci_evm.format_amount(max(0, free))} "
                f"{ci_evm.coin_name()} free after open swaps"
            )
    try:
        # Signed once: a retry rebroadcasts it, and its nonce stops a second escrow
        ci_evm.sendTx(
            sign, "lock", bid_id, wait=False, error_decoder=contract.decode_error
        )
        # Once sent the bid can't time out, or nothing would refund the escrow
        if not sent:
            self.logBidEvent(bid_id, EventLogTypes.EVM_LOCK_TX_SENT, "", cursor)
            self.commitDB()
        receipt = ci_evm.sendTx(
            sign, "lock", bid_id, error_decoder=contract.decode_error
        )
    except TimeExhausted:
        raise TemporaryError("EVM lock tx not mined yet")
    except EthRpcError as e:
        raise TemporaryError(f"EVM lock tx failed: {e}")
    # newSwap's timeouts come from its block; a reorg can move it
    if (
        ci_evm.rpc.get_block_number() - receipt["blockNumber"] + 1
        < ci_evm.blocks_confirmed
    ):
        raise TemporaryError("EVM lock tx not confirmed yet")
    evm_swap.evm_lock_tx_id = bytes(receipt["transactionHash"])
    sid, evm_swap.timeout1, evm_swap.timeout2, evm_swap.timeout3 = (
        contract.new_swap_event(receipt)
    )
    # newSwap sets timeout1 to its block time plus the first duration
    evm_swap.xmr_lock_deadline = evm_swap.timeout1 - duration + self._evm_xmr_lock_wait
    ensure(sid == swap_id(_swap(self, offer, bid, evm_swap)), "Swap id mismatch")
    ci_evm.recordTx(
        receipt["transactionHash"],
        "lock",
        -evm_amount,
        receipt,
        to_addr=contract.address,
        bid_id=bid_id,
        cursor=cursor,
    )
    self.logBidEvent(bid_id, EventLogTypes.EVM_LOCK_TX_PUBLISHED, "", cursor)

    msg_buf = EvmXmrLockMessage()
    msg_buf.bid_msg_id = bid_id
    msg_buf.owner = evm_swap.evm_addr
    msg_buf.timeout1 = evm_swap.timeout1
    msg_buf.timeout2 = evm_swap.timeout2
    msg_buf.timeout3 = evm_swap.timeout3
    msg_buf.lock_tx_id = evm_swap.evm_lock_tx_id
    msg_buf.xmr_lock_deadline = evm_swap.xmr_lock_deadline
    payload_hex = (
        str.format("{:02x}", MessageTypes.EVM_XMR_LOCK) + msg_buf.to_bytes().hex()
    )
    addr_from = offer.addr_from if bid.was_received else bid.bid_addr
    addr_to = bid.bid_addr if bid.was_received else offer.addr_from
    msg_valid: int = self.getAcceptBidMsgValidTime(bid)
    self.sendMessage(
        addr_from,
        addr_to,
        payload_hex,
        msg_valid,
        cursor,
        message_nets=bid.message_nets,
        payload_version=offer.smsg_payload_version,
    )

    bid.setState(BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap, save_in_progress=offer)
    self.log.info(
        f"Sent EVM lock for bid {self.log.id(bid_id)} tx {evm_swap.evm_lock_tx_id.hex()}"
    )


def _findXmrLock(self, offer, bid, evm_swap, cursor) -> bool:
    """Record the XMR lock at the joint address; False if there is none."""
    ci_xmr = self.ci(Coins.XMR)
    kbv, Kbs = sharedKeys(self, evm_swap)
    _, xmr_pico = evmAmountsForBid(self, offer, bid)
    found = ci_xmr.findTxB(
        kbv,
        Kbs,
        xmr_pico,
        ci_xmr.blocks_confirmed,
        bid.chain_b_height_start or 0,
        bid_sender=False,
    )
    changed, valid = self.recordTxB(
        ci_xmr, evm_swap, bid, found, xmr_pico, True, cursor
    )
    if changed:
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
    return valid


def _xmrSideLockEnded(self, bid_id, bid, offer, evm_swap, cursor) -> None:
    """XMR side, no XMR lock recorded: the EVM side refunded."""
    # A lock sent just before a restart may not have been recorded
    if _findXmrLock(self, offer, bid, evm_swap, cursor):
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        _queueAction(
            self,
            bid_id,
            ActionTypes.RECOVER_XMR_FROM_EVM_REFUND,
            "Recovering unrecorded XMR lock after EVM refund",
            cursor,
        )
        return
    self.log.info(
        f"EVM lock refunded before XMR lock for bid {self.log.id(bid_id)}; abandoning."
    )
    bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
    self.commitDB()


def xmrLockRemaining(self, evm_swap):
    """Seconds left to send the XMR lock before the EVM side's lock deadline."""
    if not evm_swap.xmr_lock_deadline:
        return None
    return (
        evm_swap.xmr_lock_deadline
        - self.getConfirmAllowance(self.ci(Coins.XMR))
        - _chainTime(self, evm_swap)
    )


def _xmrLockBatch(self, bid, evm_swap, now: int, cursor):
    """Plan siblings to lock with bid in one XMR tx, or None to hold the lock."""
    ready_timeout: int = self.getPlanReadyTimeout(bid.plan_id, cursor)
    plan = multibid.plan_batch_decision(
        self.getPlanLegs(bid.plan_id, cursor),
        bid.bid_id,
        cap=self.ci(Coins.XMR).max_batched_lock_outputs(),
        now=now,
        ready_timeout=ready_timeout,
        confirm_timeout=self.getPlanConfirmTimeout(
            self.ci(evm_swap.evm_coin), ready_timeout
        ),
    )
    for leg in plan.drop:
        self.log.info(
            f"Abandoning plan leg {self.log.id(leg.bid_id)}, no EVM lock while a ready leg waited {ready_timeout} seconds."
        )
        self.deactivateBidForReason(leg.bid_id, BidStates.BID_ABANDONED, cursor=cursor)
    if plan.wait:
        self.log.info(
            f"Holding the XMR lock for bid {self.log.id(bid.bid_id)}, the rest of its plan is not locked yet."
        )
        self.createActionInSession(
            self.get_delay_event_seconds(),
            ActionTypes.SEND_XMR_LOCK_FOR_EVM,
            bid.bid_id,
            cursor,
        )
        return None
    batch = []
    for leg in plan.batch:
        try:
            swap, state_name, _ = _evmLock(self, leg.offer, leg, leg.evm_swap)
            valid: bool = state_name == "PENDING" and _validateEvmLock(
                self, leg.offer, leg.evm_swap, swap, now
            )
        except Exception as e:
            if leg.bid_id == bid.bid_id:
                raise
            # One counterparty's bad or unseen lock mustn't stop the others
            self.log.warning(
                f"Leaving plan leg {self.log.id(leg.bid_id)} out of the XMR lock: {e}"
            )
            continue
        if not valid:
            continue
        if leg.evm_swap.timeout1 - now < xmrLockMinMargin(self) or (
            leg.lock_remaining_seconds is not None and leg.lock_remaining_seconds < 0
        ):
            continue
        # A leg whose lock is already on chain must not be paid a second time
        if _findXmrLock(self, leg.offer, leg, leg.evm_swap, cursor):
            self.saveBidInSession(
                leg.bid_id,
                leg,
                cursor,
                leg.evm_swap,
                save_in_progress=leg.offer,
            )
            continue
        batch.append(leg)
    return batch


def _setXmrLockSent(self, bid, offer, evm_swap, b_lock_txid: bytes, cursor) -> None:
    self.setBidBLockTx(bid, evm_swap, b_lock_txid, cursor)
    # The in-progress copy must be replaced or the leg re-queues its lock
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap, save_in_progress=offer)
    self.log.info(f"Published XMR lock for EVM bid {self.log.id(bid.bid_id)}")


def sendXmrLockForEvm(self, bid_id: bytes, cursor) -> None:
    """XMR side: check the EVM lock, publish Monero to the joint address."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    if evm_swap.b_lock_tx_id is not None:
        # Locked in a plan sibling's tx
        return
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
    ensure(offer, f"Offer not found: {self.log.id(bid.offer_id)}.")
    ci_xmr = self.ci(Coins.XMR)

    swap, state_name, _ = _evmLock(self, offer, bid, evm_swap)
    if state_name == "REFUNDED":
        _xmrSideLockEnded(self, bid_id, bid, offer, evm_swap, cursor)
        return
    # READY when the EVM side saw a lock sent before a restart
    ensure(state_name in ("PENDING", "READY"), f"EVM lock {state_name}")
    now: int = _chainTime(self, evm_swap)
    if not _validateEvmLock(self, offer, evm_swap, swap, now):
        self.log.debug(f"EVM lock for bid {self.log.id(bid_id)} not yet confirmed.")
        return

    lock_margin: int = xmrLockMinMargin(self)
    lock_remaining: int = evm_swap.timeout1 - now
    send_by: int = evm_swap.xmr_lock_deadline - self.getConfirmAllowance(ci_xmr)
    b_lock_txid = None
    if lock_remaining < lock_margin or now > send_by:
        # Too late to send it, it only counts if it was sent in time
        if _findXmrLock(self, offer, bid, evm_swap, cursor):
            b_lock_txid = evm_swap.b_lock_tx_id
        else:
            self.log.error(
                f"Not sending XMR lock for EVM bid {self.log.id(bid_id)}, too late: "
                f"{lock_remaining}s to timeout1 (needs {lock_margin}), "
                f"{send_by - now}s to the EVM side's lock deadline."
            )
            self.logBidEvent(
                bid_id, EventLogTypes.LOCK_TX_B_ABANDONED_LOCK_CLOSE, "", cursor
            )
            self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
            return

    batch = []
    covered = [0]
    if b_lock_txid is None:
        if bid.plan_id:
            batch = _xmrLockBatch(self, bid, evm_swap, now, cursor)
            if batch is None:
                return
        _, xmr_pico = evmAmountsForBid(self, offer, bid)
        kbv, Kbs = sharedKeys(self, evm_swap)
        try:
            if batch:
                locks = [(kbv, Kbs, xmr_pico)]
                for leg in batch:
                    leg_kbv, leg_Kbs = sharedKeys(self, leg.evm_swap)
                    locks.append(
                        (
                            leg_kbv,
                            leg_Kbs,
                            evmAmountsForBid(self, leg.offer, leg)[1],
                        )
                    )
                b_lock_txid, covered = ci_xmr.publishBLockTxs(locks, 0)
            else:
                b_lock_txid = ci_xmr.publishBLockTx(kbv, Kbs, xmr_pico, 0)
        except Exception as ex:
            self.logBidEvent(
                bid_id, EventLogTypes.FAILED_TX_B_LOCK_PUBLISH, str(ex), cursor
            )
            if ci_xmr.is_transient_error(ex) or self.is_transient_error(ex):
                delay = self.get_delay_retry_seconds()
                self.log.info(
                    f"Retrying XMR lock for bid {self.log.id(bid_id)} in {delay} seconds: {ex}"
                )
                self.createActionInSession(
                    delay, ActionTypes.SEND_XMR_LOCK_FOR_EVM, bid_id, cursor
                )
                self.commitDB()
                return
            raise
    for n, leg in enumerate(batch, start=1):
        if n in covered:
            _setXmrLockSent(self, leg, leg.offer, leg.evm_swap, b_lock_txid, cursor)
    if 0 not in covered:
        delay = self.get_delay_retry_seconds()
        self.log.info(
            f"Retrying the XMR lock for bid {self.log.id(bid_id)} in {delay} seconds, tx {self.log.id(b_lock_txid)} does not pay it."
        )
        self.createActionInSession(
            delay, ActionTypes.SEND_XMR_LOCK_FOR_EVM, bid_id, cursor
        )
        return
    _setXmrLockSent(self, bid, offer, evm_swap, b_lock_txid, cursor)


def _dripDue(evm_swap) -> bool:
    return bool(evm_swap.gas_request) and evm_swap.gas_drip_txid is None


def sendGasDrip(self, bid_id: bytes, cursor) -> None:
    """EVM side: send the XMR side its claim gas once the XMR lock is confirmed."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    if not _dripDue(evm_swap):
        return
    ci_evm = self.ci(evm_swap.evm_coin)
    rpc = ci_evm.rpc
    try:
        # Signed once, so a retry can't pay twice
        receipt = ci_evm.sendTx(
            lambda tx_nonce: rpc.sign_transfer(
                ci_evm.account.address,
                ci_evm.account.key,
                evm_swap.xmr_side_addr,
                min(evm_swap.gas_request, ci_evm.dripGasCost()),
                tx_nonce,
            ),
            "gas_drip",
            bid_id,
        )
    except TimeExhausted:
        raise TemporaryError("EVM gas drip not mined yet")
    except EthRpcError as e:
        raise TemporaryError(f"EVM gas drip failed: {e}")
    evm_swap.gas_drip_txid = bytes(receipt["transactionHash"])
    ci_evm.recordTx(
        evm_swap.gas_drip_txid,
        "gas_drip",
        -ci_evm.fromWei(rpc.w3.eth.get_transaction(evm_swap.gas_drip_txid)["value"]),
        receipt,
        to_addr=evm_swap.xmr_side_addr,
        bid_id=bid_id,
        cursor=cursor,
    )
    self.logBidEvent(bid_id, EventLogTypes.EVM_GAS_DRIP_TX_PUBLISHED, "", cursor)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
    self.log.info(f"Sent EVM claim gas for bid {self.log.id(bid_id)}")


def markEvmReady(self, bid_id: bytes, cursor) -> None:
    """EVM side: call setReady() once the Monero lock is confirmed."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
    swap, state_name, _ = _evmLock(self, offer, bid, evm_swap)
    if state_name == "PENDING":
        lock_remaining: int = evm_swap.timeout1 - _chainTime(self, evm_swap)
        if lock_remaining > self._sc_lock_release_min_margin:
            ci_evm = self.ci(evm_swap.evm_coin)
            contract = _contract(self, evm_swap)
            try:
                receipt = ci_evm.sendTx(
                    lambda tx_nonce: contract.sign_set_ready(
                        ci_evm.account, swap, tx_nonce
                    ),
                    "ready",
                    bid_id,
                    error_decoder=contract.decode_error,
                )
            except TimeExhausted:
                self.log.info(
                    f"EVM setReady for bid {self.log.id(bid_id)} not mined yet."
                )
                return
            except Exception as e:
                self.log.error(
                    f"Marking EVM lock ready for bid {self.log.id(bid_id)} failed: {e}"
                )
                return
            ci_evm.recordTx(
                receipt["transactionHash"],
                "ready",
                0,
                receipt,
                bid_id=bid_id,
                cursor=cursor,
            )
            self.logBidEvent(bid_id, EventLogTypes.EVM_LOCK_TX_READY, "", cursor)
            self.log.info(f"Marked EVM lock ready for bid {self.log.id(bid_id)}")
        else:
            # The XMR side can claim once timeout1 passes
            self.log.warning(
                f"Not marking EVM lock ready for bid {self.log.id(bid_id)}, "
                f"timeout1 too close: {lock_remaining} <= {self._sc_lock_release_min_margin}."
            )
    bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap, save_in_progress=offer)


def claimEvmLock(self, bid_id: bytes, cursor) -> None:
    """XMR side: claim() the escrowed EVM coin, revealing its spend half."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
    swap, state_name, _ = _evmLock(self, offer, bid, evm_swap)
    now: int = _chainTime(self, evm_swap)
    if not _evmClaimable(
        evm_swap,
        state_name,
        now,
        _confirmedChainTime(self, evm_swap),
        self._sc_lock_release_min_margin,
    ):
        self.log.warning(
            f"EVM lock for bid {self.log.id(bid_id)} is not claimable ({state_name})."
        )
        return
    ci_evm = self.ci(evm_swap.evm_coin)
    contract = _contract(self, evm_swap)
    # The late claim from timeout3 has no deadline
    bump_at = None
    if now < evm_swap.timeout3:
        bump_at = evm_swap.timeout2 - self._sc_lock_release_min_margin
    try:
        receipt = ci_evm.sendTx(
            lambda tx_nonce: contract.sign_claim(
                ci_evm.account, swap, evm_swap.xmr_kbs, tx_nonce
            ),
            "claim",
            bid_id,
            bump_at=bump_at,
            error_decoder=contract.decode_error,
        )
    except TimeExhausted:
        self.log.info(f"EVM claim for bid {self.log.id(bid_id)} not mined yet.")
        return
    except Exception as e:
        self.log.error(f"Claiming EVM lock for bid {self.log.id(bid_id)} failed: {e}")
        return
    evm_swap.evm_spend_tx_id = bytes(receipt["transactionHash"])
    ci_evm.recordTx(
        evm_swap.evm_spend_tx_id,
        "claim",
        evmAmountsForBid(self, offer, bid)[0],
        receipt,
        bid_id=bid_id,
        cursor=cursor,
    )
    self.logBidEvent(bid_id, EventLogTypes.EVM_LOCK_SPEND_TX_PUBLISHED, "", cursor)
    bid.setState(BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap, save_in_progress=offer)
    self.log.info(f"Claimed EVM lock for bid {self.log.id(bid_id)}")


def _xmrLockSpendable(self, offer, bid, evm_swap, action_type, cursor) -> bool:
    """Requeue action_type until the XMR lock has unlocked, as adaptor-sig does."""
    ci_xmr = self.ci(Coins.XMR)
    if (
        _findXmrLock(self, offer, bid, evm_swap, cursor)
        and bid.xmr_b_lock_tx.chain_height
    ):
        depth: int = ci_xmr.getChainHeight() - bid.xmr_b_lock_tx.chain_height
        if depth >= ci_xmr.depth_spendable():
            return True
        status = f"still confirming {depth} / {ci_xmr.depth_spendable()}"
    else:
        status = "height not known"
    delay = self.get_delay_retry_seconds()
    self.log.info(
        f"XMR lock for bid {self.log.id(bid.bid_id)} {status}, sweeping in {delay} seconds."
    )
    self.logBidEvent(
        bid.bid_id,
        EventLogTypes.FAILED_TX_B_SPEND,
        f"Chain B lock tx {status}.",
        cursor,
    )
    self.createActionInSession(delay, action_type, bid.bid_id, cursor)
    return False


def _sweepJointAddress(self, bid, evm_swap, xmr_pico: int, tx_type, cursor) -> bytes:
    """Spend the XMR lock to our wallet once both spend halves are known."""
    ci_xmr = self.ci(Coins.XMR)
    kbv, _ = sharedKeys(self, evm_swap)
    txid, published = self.sendBLockSpendTx(
        ci_xmr,
        bid,
        tx_type,
        cursor,
        evm_swap.b_lock_tx_id,
        self.getCachedMainWalletAddress(ci_xmr, cursor),
        kbv,
        ci_xmr.sumKeys(evm_swap.evm_kbs, evm_swap.xmr_kbs),
        xmr_pico,
        0,
        bid.chain_b_height_start or 0,
    )
    if published:
        self.logBidEvent(
            bid.bid_id, EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED, "", cursor
        )
    return txid


def redeemXmrForEvm(self, bid_id: bytes, cursor) -> None:
    """EVM side: rebuild the joint spend key from the claim, sweep the joint address."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})

    _, state_name, revealed = _evmLock(self, offer, bid, evm_swap)
    ensure(state_name == "CLAIMED", f"EVM lock {state_name}, not claimed")
    evm_swap.xmr_kbs = _revealedKey(self, revealed, evm_swap.xmr_pkbs)

    _, xmr_pico = evmAmountsForBid(self, offer, bid)
    if evm_swap.b_lock_tx_id is None:
        # Claimed past timeout1 before we saw the lock
        ensure(_findXmrLock(self, offer, bid, evm_swap, cursor), "XMR lock not found")
    if not _xmrLockSpendable(
        self, offer, bid, evm_swap, ActionTypes.REDEEM_XMR_FOR_EVM, cursor
    ):
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        return
    spend_txid = _sweepJointAddress(
        self, bid, evm_swap, xmr_pico, TxTypes.XMR_SWAP_B_LOCK_SPEND, cursor
    )
    bid.setState(BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap, save_in_progress=offer)
    self.log.info(f"Swept XMR for EVM bid {self.log.id(bid_id)} tx {spend_txid.hex()}")


def refundEvmLock(self, bid_id: bytes, cursor) -> None:
    """EVM side: refund() the escrow, revealing the EVM side's spend half."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})
    swap, state_name, _ = _evmLock(self, offer, bid, evm_swap)
    now: int = _chainTime(self, evm_swap)
    if not _evmRefundable(
        evm_swap,
        state_name,
        now,
        _confirmedChainTime(self, evm_swap),
        self._sc_lock_release_min_margin,
    ):
        self.log.warning(
            f"EVM lock for bid {self.log.id(bid_id)} is not refundable ({state_name})."
        )
        return
    ci_evm = self.ci(evm_swap.evm_coin)
    contract = _contract(self, evm_swap)
    early: bool = now < evm_swap.timeout1
    deadline: int = evm_swap.timeout1 if early else evm_swap.timeout3
    try:
        # Unsent by timeout1, the XMR side can claim without having locked
        receipt = ci_evm.sendTx(
            lambda tx_nonce: contract.sign_refund(
                ci_evm.account, swap, evm_swap.evm_kbs, tx_nonce, capped=not early
            ),
            "refund",
            bid_id,
            bump_at=deadline - self._sc_lock_release_min_margin,
            error_decoder=contract.decode_error,
        )
    except TimeExhausted:
        self.log.info(f"EVM refund for bid {self.log.id(bid_id)} not mined yet.")
        return
    except Exception as e:
        self.log.error(f"Refunding EVM lock for bid {self.log.id(bid_id)} failed: {e}")
        return
    evm_swap.evm_refund_tx_id = bytes(receipt["transactionHash"])
    ci_evm.recordTx(
        evm_swap.evm_refund_tx_id,
        "refund",
        evmAmountsForBid(self, offer, bid)[0],
        receipt,
        bid_id=bid_id,
        cursor=cursor,
    )
    self.logBidEvent(bid_id, EventLogTypes.EVM_LOCK_REFUND_TX_PUBLISHED, "", cursor)
    bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
    self.log.info(f"Refunded EVM lock for bid {self.log.id(bid_id)}")


def recoverXmrFromEvmRefund(self, bid_id: bytes, cursor) -> None:
    """XMR side: rebuild the joint spend key from the refund, sweep our XMR back."""
    bid, evm_swap = self.getXmrBidFromSession(cursor, bid_id, EvmXmrSwap)
    ensure(bid and evm_swap, f"Bid not found: {self.log.id(bid_id)}.")
    ensure(evm_swap.b_lock_tx_id is not None, "No Monero lock to recover")
    offer = self.queryOne(Offer, cursor, {"offer_id": bid.offer_id})

    _, state_name, revealed = _evmLock(self, offer, bid, evm_swap)
    ensure(state_name == "REFUNDED", f"EVM lock {state_name}, not refunded")
    evm_swap.evm_kbs = _revealedKey(self, revealed, evm_swap.evm_pkbs)

    if not _xmrLockSpendable(
        self, offer, bid, evm_swap, ActionTypes.RECOVER_XMR_FROM_EVM_REFUND, cursor
    ):
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        return
    _, xmr_pico = evmAmountsForBid(self, offer, bid)
    spend_txid = _sweepJointAddress(
        self, bid, evm_swap, xmr_pico, TxTypes.XMR_SWAP_B_LOCK_REFUND, cursor
    )
    bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap, save_in_progress=offer)
    self.log.info(
        f"Recovered XMR after EVM refund for bid {self.log.id(bid_id)} tx {spend_txid.hex()}"
    )


# --- bid-state driver --------------------------------------------------------


def checkEvmXmrBidState(self, bid_id: bytes, bid, offer):
    """Poll and advance an in-progress EVM<->XMR bid; True removes it from swaps_in_progress."""
    rv = False
    cursor = None
    try:
        cursor = self.openDB()
        evm_swap = self.queryOne(EvmXmrSwap, cursor, {"bid_id": bid.bid_id})
        ensure(evm_swap, f"EVM<->XMR swap not found: {self.log.id(bid.bid_id)}.")

        we_are_evm: bool = weAreEvmSide(self, offer, bid)
        state = BidStates(bid.state)

        if state in _EVM_XMR_TERMINAL_STATES:
            return True

        elif state == BidStates.BID_ACCEPTED:
            if we_are_evm:
                _queueAction(
                    self, bid_id, ActionTypes.SEND_EVM_LOCK, "Sending EVM lock", cursor
                )

        elif state == BidStates.XMR_SWAP_SCRIPT_COIN_LOCKED:
            if we_are_evm:
                _evmCheckMoneroLock(self, bid_id, bid, offer, evm_swap, cursor)
            else:
                _xmrCheckEvmLock(self, bid_id, bid, offer, evm_swap, cursor)

        elif state == BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED:
            if we_are_evm:
                _queueDrip(self, bid_id, evm_swap, cursor)
                _queueAction(
                    self,
                    bid_id,
                    ActionTypes.SEND_EVM_LOCK_READY,
                    "Marking EVM lock ready",
                    cursor,
                )

        elif state == BidStates.XMR_SWAP_LOCK_RELEASED:
            _, state_name, _ = _evmLock(self, offer, bid, evm_swap)
            now: int = _chainTime(self, evm_swap)
            if _lockEnded(self, bid_id, bid, evm_swap, state_name, we_are_evm, cursor):
                pass
            elif we_are_evm:
                _queueDrip(self, bid_id, evm_swap, cursor)
                confirmed_now: int = _confirmedChainTime(self, evm_swap)
                if confirmed_now >= evm_swap.timeout2 and _evmRefundable(
                    evm_swap,
                    state_name,
                    now,
                    confirmed_now,
                    self._sc_lock_release_min_margin,
                ):
                    _queueAction(
                        self,
                        bid_id,
                        ActionTypes.REFUND_EVM_LOCK,
                        "Refunding EVM lock",
                        cursor,
                    )
            else:
                if _evmClaimable(
                    evm_swap,
                    state_name,
                    now,
                    _confirmedChainTime(self, evm_swap),
                    self._sc_lock_release_min_margin,
                ):
                    _queueAction(
                        self,
                        bid_id,
                        ActionTypes.CLAIM_EVM_LOCK,
                        "Claiming EVM lock",
                        cursor,
                    )

        elif state == BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED:
            if we_are_evm:
                _queueAction(
                    self,
                    bid_id,
                    ActionTypes.REDEEM_XMR_FOR_EVM,
                    "Redeeming XMR",
                    cursor,
                )
            else:
                bid.setState(BidStates.SWAP_COMPLETED)
                self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
                self.commitDB()
                self.notify(NT.SWAP_COMPLETED, {"bid_id": bid_id.hex()})
                rv = True

        elif state == BidStates.XMR_SWAP_NOSCRIPT_TX_REDEEMED:
            bid.setState(BidStates.SWAP_COMPLETED)
            self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
            self.commitDB()
            self.notify(NT.SWAP_COMPLETED, {"bid_id": bid_id.hex()})
            rv = True

    finally:
        self.closeDB(cursor)
    return rv


def _lockEnded(self, bid_id, bid, evm_swap, state_name, we_are_evm, cursor) -> bool:
    """Move on from a completed EVM lock; False while it is still open."""
    if state_name == "CLAIMED":
        if we_are_evm:
            self.logBidEvent(
                bid_id, EventLogTypes.EVM_LOCK_SPEND_TX_PUBLISHED, "", cursor
            )
        bid.setState(BidStates.XMR_SWAP_SCRIPT_TX_REDEEMED)
    elif state_name == "REFUNDED":
        if not we_are_evm:
            _queueAction(
                self,
                bid_id,
                ActionTypes.RECOVER_XMR_FROM_EVM_REFUND,
                "Recovering XMR after EVM refund",
                cursor,
            )
            return True
        bid.setState(BidStates.XMR_SWAP_FAILED_REFUNDED)
    else:
        return False
    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
    self.commitDB()
    return True


def _xmrCheckEvmLock(self, bid_id, bid, offer, evm_swap, cursor) -> None:
    """XMR side: lock XMR, then wait for setReady or timeout1."""
    swap, state_name, _ = _evmLock(self, offer, bid, evm_swap)
    if evm_swap.b_lock_tx_id is None:
        if state_name == "REFUNDED":
            _xmrSideLockEnded(self, bid_id, bid, offer, evm_swap, cursor)
        elif (
            self.countBidEvents(
                bid, EventLogTypes.LOCK_TX_B_ABANDONED_LOCK_CLOSE, cursor
            )
            < 1
        ):
            _queueAction(
                self,
                bid_id,
                ActionTypes.SEND_XMR_LOCK_FOR_EVM,
                "Sending XMR lock",
                cursor,
            )
        elif state_name in ("PENDING", "READY"):
            # Too late to send one, but one sent before a restart may still be mined
            if not _findXmrLock(self, offer, bid, evm_swap, cursor):
                if _chainTime(self, evm_swap) >= evm_swap.timeout1:
                    bid.setState(BidStates.XMR_SWAP_FAILED_NOTHING_TO_RECOVER)
                    self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
                    self.commitDB()
                return
            self.logBidEvent(bid_id, EventLogTypes.LOCK_TX_B_PUBLISHED, "", cursor)
            self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
            self.commitDB()
        return
    if _lockEnded(self, bid_id, bid, evm_swap, state_name, False, cursor):
        return
    if state_name == "READY":
        # A reorg could swap setReady for a refund, reverting our claim and leaking its secret
        state_name = _contract(self, evm_swap).stage(
            swap_id(swap), _confirmedHeight(self, evm_swap)
        )
    if state_name == "READY" or (
        state_name == "PENDING"
        and _confirmedChainTime(self, evm_swap) >= evm_swap.timeout1
    ):
        if state_name == "READY":
            self.logBidEvent(bid_id, EventLogTypes.EVM_LOCK_TX_READY, "", cursor)
        bid.setState(BidStates.XMR_SWAP_LOCK_RELEASED)
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        self.commitDB()


def _evmCheckMoneroLock(self, bid_id, bid, offer, evm_swap, cursor) -> None:
    """EVM side: wait for the XMR lock, refund before timeout1 if it doesn't confirm."""
    _, state_name, _ = _evmLock(self, offer, bid, evm_swap)
    if _lockEnded(self, bid_id, bid, evm_swap, state_name, True, cursor):
        return
    if state_name != "PENDING":
        return

    ci_xmr = self.ci(Coins.XMR)
    found: bool = _findXmrLock(self, offer, bid, evm_swap, cursor)
    if found:
        lock_height = bid.xmr_b_lock_tx.chain_height
        confirmed = lock_height > 0 and (
            ci_xmr.getChainHeight() - lock_height >= ci_xmr.blocks_confirmed
        )
        if confirmed:
            self.logBidEvent(bid_id, EventLogTypes.LOCK_TX_B_CONFIRMED, "", cursor)
            bid.setState(BidStates.XMR_SWAP_NOSCRIPT_COIN_LOCKED)
        self.saveBidInSession(bid.bid_id, bid, cursor, evm_swap)
        self.commitDB()
        if confirmed:
            return

    # With no XMR lock mined, refund soon after the EVM lock, while it can't be
    # late; timeout1 - 2 margins is the fallback if this node was down
    margin: int = self._sc_lock_release_min_margin
    now: int = _chainTime(self, evm_swap)
    confirmed_now: int = _confirmedChainTime(self, evm_swap)
    if _evmRefundable(evm_swap, state_name, now, confirmed_now, margin) and (
        (not found and now >= evm_swap.xmr_lock_deadline)
        or now >= evm_swap.timeout1 - 2 * margin
        or confirmed_now >= evm_swap.timeout2
    ):
        _queueAction(
            self, bid_id, ActionTypes.REFUND_EVM_LOCK, "Refunding EVM lock", cursor
        )


def _queueDrip(self, bid_id, evm_swap, cursor) -> None:
    if _dripDue(evm_swap):
        _queueAction(
            self, bid_id, ActionTypes.SEND_EVM_GAS_DRIP, "Sending claim gas", cursor
        )


def _queueAction(self, bid_id, action_type, what: str, cursor) -> None:
    if self.countQueuedActions(cursor, bid_id, action_type) < 1:
        delay = self.get_delay_event_seconds()
        self.log.info(f"{what} for bid {self.log.id(bid_id)} in {delay} seconds.")
        self.createActionInSession(delay, action_type, bid_id, cursor)
        self.commitDB()
