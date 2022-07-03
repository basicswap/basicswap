# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.util import (
    SerialiseNum,
)
from basicswap.script import (
    OpCodes,
)

INITIATE_TX_TIMEOUT = 40 * 60  # TODO: make variable per coin


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
    txid = self.submitTxn(ci_from.coin_type(), txn)

    bid.initiate_tx.spend_txid = bytes.fromhex(txid)
    self.log.debug('Submitted initiate redeem txn %s to %s chain for bid %s', txid, ci_from.coin_name(), bid_id.hex())
