# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from sqlalchemy.orm import scoped_session

from basicswap.util import (
    ensure,
)
from basicswap.chainparams import (
    Coins,
)
from basicswap.basicswap_util import (
    KeyTypes,
    EventLogTypes,
)


def addLockRefundSigs(self, xmr_swap, ci):
    self.log.debug('Setting lock refund tx sigs')
    witness_stack = [
        b'',
        xmr_swap.al_lock_refund_tx_sig,
        xmr_swap.af_lock_refund_tx_sig,
        xmr_swap.a_lock_tx_script,
    ]

    signed_tx = ci.setTxSignature(xmr_swap.a_lock_refund_tx, witness_stack)
    ensure(signed_tx, 'setTxSignature failed')
    xmr_swap.a_lock_refund_tx = signed_tx


def recoverNoScriptTxnWithKey(self, bid_id, encoded_key):
    # Manually recover txn if  other key is known
    session = scoped_session(self.session_factory)
    try:
        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'XMR swap not found: {}.'.format(bid_id.hex()))
        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'XMR offer not found: {}.'.format(bid.offer_id.hex()))
        ci_to = self.ci(offer.coin_to)

        for_ed25519 = True if Coins(offer.coin_to) == Coins.XMR else False
        if bid.was_sent:
            kbsl = ci_to.decodeKey(encoded_key)
            kbsf = self.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)
        else:
            kbsl = self.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSL, for_ed25519)
            kbsf = ci_to.decodeKey(encoded_key)
        ensure(ci_to.verifyKey(kbsl), 'Invalid kbsl')
        ensure(ci_to.verifyKey(kbsf), 'Invalid kbsf')
        vkbs = ci_to.sumKeys(kbsl, kbsf)

        address_to = self.getCachedMainWalletAddress(ci_to)
        txid = ci_to.spendBLockTx(xmr_swap.b_lock_tx_id, address_to, xmr_swap.vkbv, vkbs, bid.amount_to, xmr_offer.b_fee_rate, bid.chain_b_height_start)
        self.log.debug('Submitted lock B spend txn %s to %s chain for bid %s', txid.hex(), ci_to.coin_name(), bid_id.hex())
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED, txid.hex(), session)
        session.commit()

        return txid
    finally:
        session.close()
        session.remove()


def getChainBSplitKey(swap_client, bid, xmr_swap, offer):
    ci_to = swap_client.ci(offer.coin_to)

    key_type = KeyTypes.KBSF if bid.was_sent else KeyTypes.KBSL
    return ci_to.encodeKey(swap_client.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, key_type, True if offer.coin_to == Coins.XMR else False))
