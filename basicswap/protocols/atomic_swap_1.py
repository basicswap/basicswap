# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.db import (
    Concepts,
)
from basicswap.util import (
    SerialiseNum,
)
from basicswap.script import (
    OpCodes,
)
from basicswap.basicswap_util import (
    SwapTypes,
    EventLogTypes,
)
from . import ProtocolInterface

INITIATE_TX_TIMEOUT = 40 * 60  # TODO: make variable per coin
ABS_LOCK_TIME_LEEWAY = 10 * 60


def buildContractScript(lock_val, secret_hash, pkh_redeem, pkh_refund, op_lock=OpCodes.OP_CHECKSEQUENCEVERIFY):
    script = bytearray([
        OpCodes.OP_IF,
        OpCodes.OP_SIZE,
        0x01, 0x20,  # 32
        OpCodes.OP_EQUALVERIFY,
        OpCodes.OP_SHA256,
        0x20]) \
        + secret_hash \
        + bytearray([
            OpCodes.OP_EQUALVERIFY,
            OpCodes.OP_DUP,
            OpCodes.OP_HASH160,
            0x14]) \
        + pkh_redeem \
        + bytearray([OpCodes.OP_ELSE, ]) \
        + SerialiseNum(lock_val) \
        + bytearray([
            op_lock,
            OpCodes.OP_DROP,
            OpCodes.OP_DUP,
            OpCodes.OP_HASH160,
            0x14]) \
        + pkh_refund \
        + bytearray([
            OpCodes.OP_ENDIF,
            OpCodes.OP_EQUALVERIFY,
            OpCodes.OP_CHECKSIG])
    return script


def extractScriptSecretHash(script):
    return script[7:39]


def redeemITx(self, bid_id, session):
    bid, offer = self.getBidAndOffer(bid_id, session)
    ci_from = self.ci(offer.coin_from)

    txn = self.createRedeemTxn(ci_from.coin_type(), bid, for_txn_type='initiate')
    txid = ci_from.publishTx(bytes.fromhex(txn))

    bid.initiate_tx.spend_txid = bytes.fromhex(txid)
    self.log.debug('Submitted initiate redeem txn %s to %s chain for bid %s', txid, ci_from.coin_name(), bid_id.hex())
    self.logEvent(Concepts.BID, bid_id, EventLogTypes.ITX_REDEEM_PUBLISHED, '', session)


class AtomicSwapInterface(ProtocolInterface):
    swap_type = SwapTypes.SELLER_FIRST

    def getFundedInitiateTxTemplate(self, ci, amount: int, sub_fee: bool) -> bytes:
        addr_to = self.getMockAddrTo(ci)
        funded_tx = ci.createRawFundedTransaction(addr_to, amount, sub_fee, lock_unspents=False)

        return bytes.fromhex(funded_tx)

    def promoteMockTx(self, ci, mock_tx: bytes, script: bytearray) -> bytearray:
        mock_txo_script = self.getMockScriptScriptPubkey(ci)
        real_txo_script = ci.get_p2wsh_script_pubkey(script) if ci._use_segwit else ci.get_p2sh_script_pubkey(script)

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

        funded_tx = ctx.serialize()
        return ci.signTxWithWallet(funded_tx)
