# -*- coding: utf-8 -*-

# Copyright (c) 2020-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from sqlalchemy.orm import scoped_session

from basicswap.util import (
    ensure,
)
from basicswap.interface import Curves
from basicswap.chainparams import (
    Coins,
)
from basicswap.basicswap_util import (
    KeyTypes,
    SwapTypes,
    EventLogTypes,
)
from . import ProtocolInterface
from basicswap.contrib.test_framework.script import (
    CScript, CScriptOp,
    OP_CHECKMULTISIG)


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


def recoverNoScriptTxnWithKey(self, bid_id: bytes, encoded_key):
    self.log.info('Manually recovering %s', bid_id.hex())
    # Manually recover txn if other key is known
    session = scoped_session(self.session_factory)
    try:
        bid, xmr_swap = self.getXmrBidFromSession(session, bid_id)
        ensure(bid, 'Bid not found: {}.'.format(bid_id.hex()))
        ensure(xmr_swap, 'Adaptor-sig swap not found: {}.'.format(bid_id.hex()))
        offer, xmr_offer = self.getXmrOfferFromSession(session, bid.offer_id, sent=False)
        ensure(offer, 'Offer not found: {}.'.format(bid.offer_id.hex()))
        ensure(xmr_offer, 'Adaptor-sig offer not found: {}.'.format(bid.offer_id.hex()))
        ci_to = self.ci(offer.coin_to)

        for_ed25519 = True if Coins(offer.coin_to) == Coins.XMR else False

        try:
            decoded_key_half = ci_to.decodeKey(encoded_key)
        except Exception as e:
            raise ValueError('Failed to decode provided key-half: ', str(e))

        if bid.was_sent:
            kbsl = decoded_key_half
            kbsf = self.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSF, for_ed25519)
        else:
            kbsl = self.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, KeyTypes.KBSL, for_ed25519)
            kbsf = decoded_key_half
        ensure(ci_to.verifyKey(kbsl), 'Invalid kbsl')
        ensure(ci_to.verifyKey(kbsf), 'Invalid kbsf')
        vkbs = ci_to.sumKeys(kbsl, kbsf)

        if offer.coin_to == Coins.XMR:
            address_to = self.getCachedMainWalletAddress(ci_to)
        else:
            address_to = self.getCachedStealthAddressForCoin(offer.coin_to)

        amount = bid.amount_to
        txid = ci_to.spendBLockTx(xmr_swap.b_lock_tx_id, address_to, xmr_swap.vkbv, vkbs, bid.amount_to, xmr_offer.b_fee_rate, bid.chain_b_height_start, spend_actual_balance=True)
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


def getChainBRemoteSplitKey(swap_client, bid, xmr_swap, offer):
    ci_from = swap_client.ci(offer.coin_from)
    ci_to = swap_client.ci(offer.coin_to)

    if bid.was_sent:
        if xmr_swap.a_lock_refund_spend_tx:
            af_lock_refund_spend_tx_sig = ci_from.extractFollowerSig(xmr_swap.a_lock_refund_spend_tx)
            kbsl = ci_from.recoverEncKey(xmr_swap.af_lock_refund_spend_tx_esig, af_lock_refund_spend_tx_sig, xmr_swap.pkasl)
            return ci_to.encodeKey(kbsl)
    else:
        if xmr_swap.a_lock_spend_tx:
            al_lock_spend_tx_sig = ci_from.extractLeaderSig(xmr_swap.a_lock_spend_tx)
            kbsf = ci_from.recoverEncKey(xmr_swap.al_lock_spend_tx_esig, al_lock_spend_tx_sig, xmr_swap.pkasf)
            return ci_to.encodeKey(kbsf)

    return None


def reverseBidAmountAndRate(swap_client, offer, bid_amount: int, bid_rate: int) -> (int, int):
    ci_from = swap_client.ci(offer.coin_to)
    ci_to = swap_client.ci(offer.coin_from)
    use_rate: int = offer.rate if bid_rate is None else bid_rate
    amount_from: int = bid_amount
    amount_to: int = int((int(amount_from) * use_rate) // ci_from.COIN())
    reversed_rate: int = ci_to.make_int(amount_from / amount_to, r=1)

    return amount_to, reversed_rate


def setDLEAG(xmr_swap, ci_to, kbsf: bytes) -> None:
    if ci_to.curve_type() == Curves.ed25519:
        xmr_swap.kbsf_dleag = ci_to.proveDLEAG(kbsf)
        xmr_swap.pkasf = xmr_swap.kbsf_dleag[0: 33]
    elif ci_to.curve_type() == Curves.secp256k1:
        for i in range(10):
            xmr_swap.kbsf_dleag = ci_to.signRecoverable(kbsf, 'proof kbsf owned for swap')
            pk_recovered: bytes = ci_to.verifySigAndRecover(xmr_swap.kbsf_dleag, 'proof kbsf owned for swap')
            if pk_recovered == xmr_swap.pkbsf:
                break
            # self.log.debug('kbsl recovered pubkey mismatch, retrying.')
        assert (pk_recovered == xmr_swap.pkbsf)
        xmr_swap.pkasf = xmr_swap.pkbsf
    else:
        raise ValueError('Unknown curve')


class XmrSwapInterface(ProtocolInterface):
    swap_type = SwapTypes.XMR_SWAP

    def genScriptLockTxScript(self, ci, Kal: bytes, Kaf: bytes) -> CScript:
        Kal_enc = Kal if len(Kal) == 33 else ci.encodePubkey(Kal)
        Kaf_enc = Kaf if len(Kaf) == 33 else ci.encodePubkey(Kaf)

        return CScript([2, Kal_enc, Kaf_enc, 2, CScriptOp(OP_CHECKMULTISIG)])

    def getFundedInitiateTxTemplate(self, ci, amount: int, sub_fee: bool) -> bytes:
        addr_to = self.getMockAddrTo(ci)
        funded_tx = ci.createRawFundedTransaction(addr_to, amount, sub_fee, lock_unspents=False)

        return bytes.fromhex(funded_tx)

    def promoteMockTx(self, ci, mock_tx: bytes, script: bytearray) -> bytearray:
        mock_txo_script = self.getMockScriptScriptPubkey(ci)
        real_txo_script = ci.getScriptDest(script)

        found: int = 0
        ctx = ci.loadTx(mock_tx)
        for txo in ctx.vout:
            if txo.scriptPubKey == mock_txo_script:
                txo.scriptPubKey = real_txo_script
                found += 1

        if found < 1:
            raise ValueError('Mocked output not found')
        if found > 1:
            raise ValueError('Too many mocked outputs found')
        ctx.nLockTime = 0

        return ctx.serialize()
