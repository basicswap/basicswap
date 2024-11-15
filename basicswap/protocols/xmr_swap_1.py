# -*- coding: utf-8 -*-

# Copyright (c) 2020-2024 tecnovert
# Copyright (c) 2024 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import traceback

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
from basicswap.contrib.test_framework.script import CScript, CScriptOp, OP_CHECKMULTISIG


def addLockRefundSigs(self, xmr_swap, ci):
    self.log.debug("Setting lock refund tx sigs")

    witness_stack = []
    if ci.coin_type() not in (Coins.DCR,):
        witness_stack += [
            b"",
        ]
    witness_stack += [
        xmr_swap.al_lock_refund_tx_sig,
        xmr_swap.af_lock_refund_tx_sig,
        xmr_swap.a_lock_tx_script,
    ]

    signed_tx = ci.setTxSignature(xmr_swap.a_lock_refund_tx, witness_stack)
    ensure(signed_tx, "setTxSignature failed")
    xmr_swap.a_lock_refund_tx = signed_tx


def recoverNoScriptTxnWithKey(self, bid_id: bytes, encoded_key, session=None):
    self.log.info(f"Manually recovering {bid_id.hex()}")
    # Manually recover txn if other key is known
    try:
        use_session = self.openSession(session)
        bid, xmr_swap = self.getXmrBidFromSession(use_session, bid_id)
        ensure(bid, "Bid not found: {}.".format(bid_id.hex()))
        ensure(xmr_swap, "Adaptor-sig swap not found: {}.".format(bid_id.hex()))
        offer, xmr_offer = self.getXmrOfferFromSession(
            use_session, bid.offer_id, sent=False
        )
        ensure(offer, "Offer not found: {}.".format(bid.offer_id.hex()))
        ensure(xmr_offer, "Adaptor-sig offer not found: {}.".format(bid.offer_id.hex()))

        # The no-script coin is always the follower
        reverse_bid: bool = self.is_reverse_ads_bid(offer.coin_from)
        ci_from = self.ci(Coins(offer.coin_from))
        ci_to = self.ci(Coins(offer.coin_to))
        ci_follower = ci_from if reverse_bid else ci_to

        try:
            decoded_key_half = ci_follower.decodeKey(encoded_key)
        except Exception as e:
            raise ValueError("Failed to decode provided key-half: ", str(e))

        was_sent: bool = bid.was_received if reverse_bid else bid.was_sent

        localkeyhalf = ci_follower.decodeKey(
            getChainBSplitKey(self, bid, xmr_swap, offer)
        )
        if was_sent:
            kbsl = decoded_key_half
            kbsf = localkeyhalf
        else:
            kbsl = localkeyhalf
            kbsf = decoded_key_half

        ensure(ci_follower.verifyKey(kbsl), "Invalid kbsl")
        ensure(ci_follower.verifyKey(kbsf), "Invalid kbsf")
        if kbsl == kbsf:
            raise ValueError("Provided key matches local key")
        vkbs = ci_follower.sumKeys(kbsl, kbsf)

        ensure(ci_follower.verifyPubkey(xmr_swap.pkbs), "Invalid pkbs")  # Sanity check

        # Ensure summed key matches the expected pubkey
        summed_pkbs = ci_follower.getPubkey(vkbs)
        if summed_pkbs != xmr_swap.pkbs:
            err_msg: str = "Summed key does not match expected wallet spend pubkey"
            have_pk = summed_pkbs.hex()
            expect_pk = xmr_swap.pkbs.hex()
            self.log.error(f"{err_msg}. Got: {have_pk}, Expect: {expect_pk}")
            raise ValueError(err_msg)

        if ci_follower.coin_type() in (Coins.XMR, Coins.WOW):
            address_to = self.getCachedMainWalletAddress(ci_follower, use_session)
        else:
            address_to = self.getCachedStealthAddressForCoin(
                ci_follower.coin_type(), use_session
            )
        amount = bid.amount_to
        lock_tx_vout = bid.getLockTXBVout()
        txid = ci_follower.spendBLockTx(
            xmr_swap.b_lock_tx_id,
            address_to,
            xmr_swap.vkbv,
            vkbs,
            amount,
            xmr_offer.b_fee_rate,
            bid.chain_b_height_start,
            spend_actual_balance=True,
            lock_tx_vout=lock_tx_vout,
        )
        self.log.debug(
            "Submitted lock B spend txn %s to %s chain for bid %s",
            txid.hex(),
            ci_follower.coin_name(),
            bid_id.hex(),
        )
        self.logBidEvent(
            bid.bid_id,
            EventLogTypes.LOCK_TX_B_SPEND_TX_PUBLISHED,
            txid.hex(),
            use_session,
        )
        use_session.commit()

        return txid
    except Exception as e:
        self.log.error(traceback.format_exc())
        raise (e)
    finally:
        if session is None:
            self.closeSession(use_session, commit=False)


def getChainBSplitKey(swap_client, bid, xmr_swap, offer):
    reverse_bid: bool = offer.bid_reversed
    ci_leader = swap_client.ci(offer.coin_to if reverse_bid else offer.coin_from)
    ci_follower = swap_client.ci(offer.coin_from if reverse_bid else offer.coin_to)

    for_ed25519: bool = True if ci_follower.curve_type() == Curves.ed25519 else False
    was_sent: bool = bid.was_received if reverse_bid else bid.was_sent

    key_type = KeyTypes.KBSF if was_sent else KeyTypes.KBSL
    return ci_follower.encodeKey(
        swap_client.getPathKey(
            ci_leader.coin_type(),
            ci_follower.coin_type(),
            bid.created_at,
            xmr_swap.contract_count,
            key_type,
            for_ed25519,
        )
    )


def getChainBRemoteSplitKey(swap_client, bid, xmr_swap, offer):
    reverse_bid: bool = offer.bid_reversed
    ci_leader = swap_client.ci(offer.coin_to if reverse_bid else offer.coin_from)
    ci_follower = swap_client.ci(offer.coin_from if reverse_bid else offer.coin_to)

    if bid.was_sent:
        if xmr_swap.a_lock_refund_spend_tx:
            af_lock_refund_spend_tx_sig = ci_leader.extractFollowerSig(
                xmr_swap.a_lock_refund_spend_tx
            )
            kbsl = ci_leader.recoverEncKey(
                xmr_swap.af_lock_refund_spend_tx_esig,
                af_lock_refund_spend_tx_sig,
                xmr_swap.pkasl,
            )
            return ci_follower.encodeKey(kbsl)
    else:
        if xmr_swap.a_lock_spend_tx:
            al_lock_spend_tx_sig = ci_leader.extractLeaderSig(xmr_swap.a_lock_spend_tx)
            kbsf = ci_leader.recoverEncKey(
                xmr_swap.al_lock_spend_tx_esig, al_lock_spend_tx_sig, xmr_swap.pkasf
            )
            return ci_follower.encodeKey(kbsf)
    return None


def setDLEAG(xmr_swap, ci_to, kbsf: bytes) -> None:
    if ci_to.curve_type() == Curves.ed25519:
        xmr_swap.kbsf_dleag = ci_to.proveDLEAG(kbsf)
        xmr_swap.pkasf = xmr_swap.kbsf_dleag[0:33]
    elif ci_to.curve_type() == Curves.secp256k1:
        for i in range(10):
            xmr_swap.kbsf_dleag = ci_to.signRecoverable(
                kbsf, "proof kbsf owned for swap"
            )
            pk_recovered: bytes = ci_to.verifySigAndRecover(
                xmr_swap.kbsf_dleag, "proof kbsf owned for swap"
            )
            if pk_recovered == xmr_swap.pkbsf:
                break
            # self.log.debug('kbsl recovered pubkey mismatch, retrying.')
        assert pk_recovered == xmr_swap.pkbsf
        xmr_swap.pkasf = xmr_swap.pkbsf
    else:
        raise ValueError("Unknown curve")


class XmrSwapInterface(ProtocolInterface):
    swap_type = SwapTypes.XMR_SWAP

    def genScriptLockTxScript(self, ci, Kal: bytes, Kaf: bytes, **kwargs) -> CScript:
        # fallthrough to ci if genScriptLockTxScript is implemented there
        if hasattr(ci, "genScriptLockTxScript") and callable(ci.genScriptLockTxScript):
            return ci.genScriptLockTxScript(ci, Kal, Kaf, **kwargs)

        Kal_enc = Kal if len(Kal) == 33 else ci.encodePubkey(Kal)
        Kaf_enc = Kaf if len(Kaf) == 33 else ci.encodePubkey(Kaf)

        return CScript([2, Kal_enc, Kaf_enc, 2, CScriptOp(OP_CHECKMULTISIG)])

    def getFundedInitiateTxTemplate(self, ci, amount: int, sub_fee: bool) -> bytes:
        addr_to = self.getMockAddrTo(ci)
        funded_tx = ci.createRawFundedTransaction(
            addr_to, amount, sub_fee, lock_unspents=False
        )

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
            raise ValueError("Mocked output not found")
        if found > 1:
            raise ValueError("Too many mocked outputs found")
        ctx.nLockTime = 0

        return ctx.serialize()
