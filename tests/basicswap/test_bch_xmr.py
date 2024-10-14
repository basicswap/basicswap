#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import logging
import unittest

from basicswap.chainparams import XMR_COIN
from basicswap.db import (
    Concepts,
)
from basicswap.basicswap import (
    BidStates,
    Coins,
    DebugTypes,
    SwapTypes,
)
from basicswap.basicswap_util import (
    TxLockTypes,
    EventLogTypes,
)
from basicswap.util import (
    COIN,
    make_int,
    format_amount,
)
from basicswap.interface.base import Curves
from basicswap.util.crypto import sha256
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    abandon_all_swaps,
    wait_for_bid,
    wait_for_event,
    wait_for_offer,
    wait_for_balance,
    wait_for_unspent,
    wait_for_none_active,
    BTC_BASE_RPC_PORT,
)
from basicswap.contrib.test_framework.messages import (
    ToHex,
    FromHex,
    CTxIn,
    COutPoint,
    CTransaction,
    CTxInWitness,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_EQUAL,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
)
from .test_xmr import BaseTest, test_delay_event, callnoderpc

from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key
)

logger = logging.getLogger()


class TestFunctions(BaseTest):
    __test__ = True
    start_bch_nodes = True
    base_rpc_port = None
    extra_wait_time = 0

    def callnoderpc(self, method, params=[], wallet=None, node_id=0):
        return callnoderpc(node_id, method, params, wallet, self.base_rpc_port)

    def mineBlock(self, num_blocks=1):
        self.callnoderpc('generatetoaddress', [num_blocks, self.btc_addr])

    def check_softfork_active(self, feature_name):
        deploymentinfo = self.callnoderpc('getdeploymentinfo')
        assert (deploymentinfo['deployments'][feature_name]['active'] is True)

    def test_010_bch_txn_size(self):
        logging.info('---------- Test {} txn_size'.format(Coins.BCH))

        swap_clients = self.swap_clients
        ci = swap_clients[0].ci(Coins.BCH)
        pi = swap_clients[0].pi(SwapTypes.XMR_BCH_SWAP)

        amount: int = ci.make_int(random.uniform(0.1, 2.0), r=1)

        # Record unspents before createSCLockTx as the used ones will be locked
        unspents = ci.rpc('listunspent')

        # fee_rate is in sats/B
        fee_rate: int = 1

        a = ci.getNewSecretKey()
        b = ci.getNewSecretKey()

        A = ci.getPubkey(a)
        B = ci.getPubkey(b)

        mining_fee = 1000
        timelock = 2
        a_receive = ci.getNewAddress()
        b_refund = ci.getNewAddress()
        refund_lock_tx_script = pi.genScriptLockTxScript(mining_fee=mining_fee, out_1=ci.addressToLockingBytecode(b_refund), out_2=ci.addressToLockingBytecode(a_receive), public_key=A, timelock=timelock)
        addr_out = ci.getNewAddress()

        lock_tx_script = pi.genScriptLockTxScript(mining_fee=mining_fee, out_1=ci.addressToLockingBytecode(a_receive), out_2=ci.scriptToP2SH32LockingBytecode(refund_lock_tx_script), public_key=B, timelock=timelock)

        lock_tx = ci.createSCLockTx(amount, lock_tx_script)
        lock_tx = ci.fundSCLockTx(lock_tx, fee_rate)
        lock_tx = ci.signTxWithWallet(lock_tx)
        print(lock_tx.hex())

        unspents_after = ci.rpc('listunspent')
        assert (len(unspents) > len(unspents_after))

        tx_decoded = ci.rpc('decoderawtransaction', [lock_tx.hex()])
        txid = tx_decoded['txid']

        vsize = tx_decoded['size']
        expect_fee_int = round(fee_rate * vsize)
        expect_fee = ci.format_amount(expect_fee_int)

        out_value: int = 0
        for txo in tx_decoded['vout']:
            if 'value' in txo:
                out_value += ci.make_int(txo['value'])
        in_value: int = 0
        for txi in tx_decoded['vin']:
            for utxo in unspents:
                if 'vout' not in utxo:
                    continue
                if utxo['txid'] == txi['txid'] and utxo['vout'] == txi['vout']:
                    in_value += ci.make_int(utxo['amount'])
                    break
        fee_value = in_value - out_value

        ci.rpc('sendrawtransaction', [lock_tx.hex()])
        rv = ci.rpc('gettransaction', [txid])
        wallet_tx_fee = -ci.make_int(rv['fee'])

        assert (wallet_tx_fee == fee_value)
        assert (wallet_tx_fee == expect_fee_int)

        pkh_out = ci.decodeAddress(a_receive)

        msg = sha256(ci.addressToLockingBytecode(a_receive))

        # bob creates an adaptor signature for alice and transmits it to her
        bAdaptorSig = ecdsaotves_enc_sign(b, A, msg)

        # alice verifies the adaptor signature
        assert (ecdsaotves_enc_verify(B, A, msg, bAdaptorSig))

        # alice decrypts the adaptor signature
        bAdaptorSig_dec = ecdsaotves_dec_sig(a, bAdaptorSig)

        fee_info = {}
        lock_spend_tx = ci.createSCLockSpendTx(lock_tx, lock_tx_script, pkh_out, mining_fee, ves=bAdaptorSig_dec, fee_info=fee_info)
        vsize_estimated: int = fee_info['vsize']

        tx_decoded = ci.rpc('decoderawtransaction', [lock_spend_tx.hex()])
        print(tx_decoded)
        txid = tx_decoded['txid']

        tx_decoded = ci.rpc('decoderawtransaction', [lock_spend_tx.hex()])
        vsize_actual: int = tx_decoded['size']

        assert (vsize_actual <= vsize_estimated and vsize_estimated - vsize_actual < 4)
        assert (ci.rpc('sendrawtransaction', [lock_spend_tx.hex()]) == txid)

        expect_size: int = ci.xmr_swap_a_lock_spend_tx_vsize()
        assert (expect_size >= vsize_actual)
        assert (expect_size - vsize_actual < 10)

        # Test chain b (no-script) lock tx size
        v = ci.getNewSecretKey()
        s = ci.getNewSecretKey()
        S = ci.getPubkey(s)
        lock_tx_b_txid = ci.publishBLockTx(v, S, amount, fee_rate)

        addr_out = ci.getNewAddress(True)
        lock_tx_b_spend_txid = ci.spendBLockTx(lock_tx_b_txid, addr_out, v, s, amount, fee_rate, 0)
        lock_tx_b_spend = ci.getTransaction(lock_tx_b_spend_txid)
        if lock_tx_b_spend is None:
            lock_tx_b_spend = ci.getWalletTransaction(lock_tx_b_spend_txid)
        lock_tx_b_spend_decoded = ci.rpc('decoderawtransaction', [lock_tx_b_spend.hex()])

        expect_size: int = ci.xmr_swap_b_lock_spend_tx_vsize()
        assert (expect_size >= lock_tx_b_spend_decoded['size'])
        assert (expect_size - lock_tx_b_spend_decoded['size'] < 10)

    def test_05_bch_xmr(self):
        logging.info('---------- Test BCH to XMR')
        swap_clients = self.swap_clients
        offer_id = swap_clients[0].postOffer(Coins.BCH, Coins.XMR, 10 * COIN, 100 * XMR_COIN, 10 * COIN, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offers = swap_clients[1].listOffers(filters={'offer_id': offer_id})
        offer = offers[0]

        swap_clients[1].ci(Coins.XMR).setFeePriority(3)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        assert (xmr_swap)

        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        swap_clients[1].ci(Coins.XMR).setFeePriority(0)
