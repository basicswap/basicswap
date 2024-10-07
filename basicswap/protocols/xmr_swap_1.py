# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import unittest
from basicswap.interface.contrib.bch_test_framework.script import (
    OP_TXINPUTCOUNT,
    OP_1,
    OP_NUMEQUALVERIFY,
    OP_TXOUTPUTCOUNT,
    OP_0,
    OP_UTXOVALUE,
    OP_OUTPUTVALUE,
    OP_SUB,
    OP_UTXOTOKENCATEGORY,
    OP_OUTPUTTOKENCATEGORY,
    OP_EQUALVERIFY,
    OP_UTXOTOKENCOMMITMENT,
    OP_OUTPUTTOKENCOMMITMENT,
    OP_UTXOTOKENAMOUNT,
    OP_OUTPUTTOKENAMOUNT,
    OP_INPUTSEQUENCENUMBER,
    OP_NOTIF,
    OP_OUTPUTBYTECODE,
    OP_OVER,
    OP_CHECKDATASIG,
    OP_ELSE,
    OP_CHECKSEQUENCEVERIFY,
    OP_DROP,
    OP_EQUAL,
    OP_ENDIF,
)
from basicswap.util import (
    ensure,
)
from basicswap.interface.base import Curves
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
    OP_CHECKMULTISIG
)


def addLockRefundSigs(self, xmr_swap, ci):
    self.log.debug('Setting lock refund tx sigs')

    witness_stack = []
    if ci.coin_type() not in (Coins.DCR, ):
        witness_stack += [b'', ]
    witness_stack += [
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
    session = self.openSession()
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
        lock_tx_vout = bid.getLockTXBVout()
        txid = ci_to.spendBLockTx(xmr_swap.b_lock_tx_id, address_to, xmr_swap.vkbv, vkbs, amount, xmr_offer.b_fee_rate, bid.chain_b_height_start, spend_actual_balance=True, lock_tx_vout=lock_tx_vout)
        self.log.debug('Submitted lock B spend txn %s to %s chain for bid %s', txid.hex(), ci_to.coin_name(), bid_id.hex())
        self.logBidEvent(bid.bid_id, EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED, txid.hex(), session)
        session.commit()

        return txid
    finally:
        self.closeSession(session, commit=False)


def getChainBSplitKey(swap_client, bid, xmr_swap, offer):
    reverse_bid: bool = offer.bid_reversed
    ci_follower = swap_client.ci(offer.coin_from if reverse_bid else offer.coin_to)

    key_type = KeyTypes.KBSF if bid.was_sent else KeyTypes.KBSL
    return ci_follower.encodeKey(swap_client.getPathKey(offer.coin_from, offer.coin_to, bid.created_at, xmr_swap.contract_count, key_type, True if ci_follower.coin_type() == Coins.XMR else False))


def getChainBRemoteSplitKey(swap_client, bid, xmr_swap, offer):
    reverse_bid: bool = offer.bid_reversed
    ci_leader = swap_client.ci(offer.coin_to if reverse_bid else offer.coin_from)
    ci_follower = swap_client.ci(offer.coin_from if reverse_bid else offer.coin_to)

    if bid.was_sent:
        if xmr_swap.a_lock_refund_spend_tx:
            af_lock_refund_spend_tx_sig = ci_leader.extractFollowerSig(xmr_swap.a_lock_refund_spend_tx)
            kbsl = ci_leader.recoverEncKey(xmr_swap.af_lock_refund_spend_tx_esig, af_lock_refund_spend_tx_sig, xmr_swap.pkasl)
            return ci_follower.encodeKey(kbsl)
    else:
        if xmr_swap.a_lock_spend_tx:
            al_lock_spend_tx_sig = ci_leader.extractLeaderSig(xmr_swap.a_lock_spend_tx)
            kbsf = ci_leader.recoverEncKey(xmr_swap.al_lock_spend_tx_esig, al_lock_spend_tx_sig, xmr_swap.pkasf)
            return ci_follower.encodeKey(kbsf)
    return None


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

class XmrBchSwapInterface(ProtocolInterface):
    swap_type = SwapTypes.XMR_BCH_SWAP

    def genScriptLockTxScript(self, mining_fee: int, out_1: bytes, out_2: bytes, public_key: bytes, timelock: int) -> CScript:
        return CScript([
            # // v4.1.0-CashTokens-Optimized
            # // Based on swaplock.cash v4.1.0-CashTokens
            # 
            # // Alice has XMR, wants BCH and/or CashTokens.
            # // Bob has BCH and/or CashTokens, wants XMR.
            # 
            # // Verify 1-in-1-out TX form
            CScriptOp(OP_TXINPUTCOUNT),
            CScriptOp(OP_1), CScriptOp(OP_NUMEQUALVERIFY),
            CScriptOp(OP_TXOUTPUTCOUNT),
            CScriptOp(OP_1), CScriptOp(OP_NUMEQUALVERIFY),

            # // int miningFee
            mining_fee,
            # // Verify pre-agreed mining fee and that the rest of BCH is forwarded
            # // to the output.
            CScriptOp(OP_0), CScriptOp(OP_UTXOVALUE),
            CScriptOp(OP_0), CScriptOp(OP_OUTPUTVALUE),
            CScriptOp(OP_SUB), CScriptOp(OP_NUMEQUALVERIFY),

            # # // Verify that any CashTokens are forwarded to the output.
            CScriptOp(OP_0), CScriptOp(OP_UTXOTOKENCATEGORY),
            CScriptOp(OP_0), CScriptOp(OP_OUTPUTTOKENCATEGORY),
            CScriptOp(OP_EQUALVERIFY),
            CScriptOp(OP_0), CScriptOp(OP_UTXOTOKENCOMMITMENT),
            CScriptOp(OP_0), CScriptOp(OP_OUTPUTTOKENCOMMITMENT),
            CScriptOp(OP_EQUALVERIFY),
            CScriptOp(OP_0), CScriptOp(OP_UTXOTOKENAMOUNT),
            CScriptOp(OP_0), CScriptOp(OP_OUTPUTTOKENAMOUNT),
            CScriptOp(OP_NUMEQUALVERIFY),

            # // If sequence is not used then it is a regular swap TX.
            CScriptOp(OP_0), CScriptOp(OP_INPUTSEQUENCENUMBER),
            CScriptOp(OP_NOTIF),
                # // bytes aliceOutput
                out_1,
                # // Verify that the BCH and/or CashTokens are forwarded to Alice's
                # // output.
                CScriptOp(OP_0), CScriptOp(OP_OUTPUTBYTECODE),
                CScriptOp(OP_OVER), CScriptOp(OP_EQUALVERIFY),

                # // pubkey bobPubkeyVES
                public_key,
                # // Require Alice to decrypt and publish Bob's VES signature.
                # // The "message" signed is simply a sha256 hash of Alice's output
                # // locking bytecode.
                # // By decrypting Bob's VES and publishing it, Alice reveals her
                # // XMR key share to Bob.
                CScriptOp(OP_CHECKDATASIG),

                # // If a TX using this path is mined then Alice gets her BCH.
                # // Bob uses the revealed XMR key share to collect his XMR.

            # // Refund will become available when timelock expires, and it would
            # // expire because Alice didn't collect on time, either of her own accord
            # // or because Bob bailed out and witheld the encrypted signature.
            CScriptOp(OP_ELSE),
                # // int timelock_0
                timelock,
                # // Verify refund timelock.
                CScriptOp(OP_CHECKSEQUENCEVERIFY), CScriptOp(OP_DROP),

                # // bytes refundLockingBytecode
                out_2,

                # // Verify that the BCH and/or CashTokens are forwarded to Refund
                # // contract.
                CScriptOp(OP_0), CScriptOp(OP_OUTPUTBYTECODE),
                CScriptOp(OP_EQUAL),

                # // BCH and/or CashTokens are simply forwarded to Refund contract.
            CScriptOp(OP_ENDIF)
        ])
