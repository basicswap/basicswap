#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2023 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import logging
import unittest

from basicswap.basicswap import (
    Coins,
    SwapTypes,
    BidStates,
    DebugTypes,
)
from basicswap.basicswap_util import (
    TxLockTypes,
)
from basicswap.util import (
    make_int,
    format_amount,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    wait_for_bid,
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
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
)
from .test_xmr import BaseTest, test_delay_event, callnoderpc

logger = logging.getLogger()


class BasicSwapTest(BaseTest):
    base_rpc_port = None

    def getBalance(self, js_wallets, coin):
        return float(js_wallets[coin.name]['balance']) + float(js_wallets[coin.name]['unconfirmed'])

    def callnoderpc(self, method, params=[], wallet=None, node_id=0):
        return callnoderpc(node_id, method, params, wallet, self.base_rpc_port)

    def mineBlock(self, num_blocks=1):
        self.callnoderpc('generatetoaddress', [num_blocks, self.btc_addr])

    def prepare_balance(self, coin_ticker: str, amount: float, port_target_node: int, port_take_from_node: int) -> None:
        js_w = read_json_api(port_target_node, 'wallets')
        if float(js_w[coin_ticker]['balance']) < amount:
            post_json = {
                'value': amount,
                'address': js_w[coin_ticker]['deposit_address'],
                'subfee': False,
            }
            json_rv = read_json_api(port_take_from_node, 'wallets/{}/withdraw'.format(coin_ticker.lower()), post_json)
            assert (len(json_rv['txid']) == 64)
            wait_for_balance(test_delay_event, 'http://127.0.0.1:{}/json/wallets/{}'.format(port_target_node, coin_ticker.lower()), 'balance', amount)

    def test_001_nested_segwit(self):
        logging.info('---------- Test {} p2sh nested segwit'.format(self.test_coin_from.name))

        addr_p2sh_segwit = self.callnoderpc('getnewaddress', ['segwit test', 'p2sh-segwit'])
        addr_info = self.callnoderpc('getaddressinfo', [addr_p2sh_segwit, ])
        assert addr_info['script'] == 'witness_v0_keyhash'

        txid = self.callnoderpc('sendtoaddress', [addr_p2sh_segwit, 1.0])
        assert len(txid) == 64

        self.mineBlock()
        ro = self.callnoderpc('scantxoutset', ['start', ['addr({})'.format(addr_p2sh_segwit)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

        tx_wallet = self.callnoderpc('gettransaction', [txid, ])['hex']
        tx = self.callnoderpc('decoderawtransaction', [tx_wallet, ])

        prevout_n = -1
        for txo in tx['vout']:
            if addr_p2sh_segwit == txo['scriptPubKey']['address']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        tx_funded = self.callnoderpc('createrawtransaction', [[{'txid': txid, 'vout': prevout_n}], {addr_p2sh_segwit: 0.99}])
        tx_signed = self.callnoderpc('signrawtransactionwithwallet', [tx_funded, ])['hex']
        tx_funded_decoded = self.callnoderpc('decoderawtransaction', [tx_funded, ])
        tx_signed_decoded = self.callnoderpc('decoderawtransaction', [tx_signed, ])
        assert tx_funded_decoded['txid'] != tx_signed_decoded['txid']

        # Add scriptsig for txids to match
        addr_p2sh_segwit_info = self.callnoderpc('getaddressinfo', [addr_p2sh_segwit, ])
        decoded_tx = FromHex(CTransaction(), tx_funded)
        decoded_tx.vin[0].scriptSig = bytes.fromhex('16' + addr_p2sh_segwit_info['hex'])
        txid_with_scriptsig = decoded_tx.rehash()
        assert txid_with_scriptsig == tx_signed_decoded['txid']

    def test_002_native_segwit(self):
        logging.info('---------- Test {} p2sh native segwit'.format(self.test_coin_from.name))

        addr_segwit = self.callnoderpc('getnewaddress', ['segwit test', 'bech32'])
        addr_info = self.callnoderpc('getaddressinfo', [addr_segwit, ])
        assert addr_info['iswitness'] is True

        txid = self.callnoderpc('sendtoaddress', [addr_segwit, 1.0])
        assert len(txid) == 64
        tx_wallet = self.callnoderpc('gettransaction', [txid, ])['hex']
        tx = self.callnoderpc('decoderawtransaction', [tx_wallet, ])

        self.mineBlock()
        ro = self.callnoderpc('scantxoutset', ['start', ['addr({})'.format(addr_segwit)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

        prevout_n = -1
        for txo in tx['vout']:
            if addr_segwit == txo['scriptPubKey']['address']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        tx_funded = self.callnoderpc('createrawtransaction', [[{'txid': txid, 'vout': prevout_n}], {addr_segwit: 0.99}])
        tx_signed = self.callnoderpc('signrawtransactionwithwallet', [tx_funded, ])['hex']
        tx_funded_decoded = self.callnoderpc('decoderawtransaction', [tx_funded, ])
        tx_signed_decoded = self.callnoderpc('decoderawtransaction', [tx_signed, ])
        assert tx_funded_decoded['txid'] == tx_signed_decoded['txid']

    def test_003_cltv(self):
        logging.info('---------- Test {} cltv'.format(self.test_coin_from.name))
        ci = self.swap_clients[0].ci(self.test_coin_from)

        chain_height = self.callnoderpc('getblockcount')
        script = CScript([chain_height + 3, OP_CHECKLOCKTIMEVERIFY, ])

        script_dest = ci.getScriptDest(script)
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = self.callnoderpc('fundrawtransaction', [tx_hex])
        utxo_pos = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = self.callnoderpc('signrawtransactionwithwallet', [tx_funded['hex'], ])['hex']
        txid = self.callnoderpc('sendrawtransaction', [tx_signed, ])

        addr_out = self.callnoderpc('getnewaddress', ['csv test', 'bech32'])
        pkh = ci.decodeSegwitAddress(addr_out)
        script_out = ci.getScriptForPubkeyHash(pkh)

        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()
        tx_spend.nLockTime = chain_height + 3
        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), utxo_pos)))
        tx_spend.vout.append(ci.txoType()(ci.make_int(1.0999), script_out))
        tx_spend.wit.vtxinwit.append(CTxInWitness())
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [script, ]
        tx_spend_hex = ToHex(tx_spend)
        try:
            txid = self.callnoderpc('sendrawtransaction', [tx_spend_hex, ])
            assert False, 'Should fail'
        except Exception as e:
            assert ('non-final' in str(e))

        self.mineBlock(5)
        txid = self.callnoderpc('sendrawtransaction', [tx_spend_hex, ])
        self.mineBlock()
        ro = self.callnoderpc('listreceivedbyaddress', [0, ])
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr_out:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

    def test_004_csv(self):
        logging.info('---------- Test {} csv'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients
        ci = self.swap_clients[0].ci(self.test_coin_from)

        script = CScript([3, OP_CHECKSEQUENCEVERIFY, ])

        script_dest = ci.getScriptDest(script)
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = self.callnoderpc('fundrawtransaction', [tx_hex])
        utxo_pos = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = self.callnoderpc('signrawtransactionwithwallet', [tx_funded['hex'], ])['hex']
        txid = self.callnoderpc('sendrawtransaction', [tx_signed, ])

        addr_out = self.callnoderpc('getnewaddress', ['csv test', 'bech32'])
        pkh = ci.decodeSegwitAddress(addr_out)
        script_out = ci.getScriptForPubkeyHash(pkh)

        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()
        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), utxo_pos),
                            nSequence=3))
        tx_spend.vout.append(ci.txoType()(ci.make_int(1.0999), script_out))
        tx_spend.wit.vtxinwit.append(CTxInWitness())
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [script, ]
        tx_spend_hex = ToHex(tx_spend)
        try:
            txid = self.callnoderpc('sendrawtransaction', [tx_spend_hex, ])
            assert False, 'Should fail'
        except Exception as e:
            assert ('non-BIP68-final' in str(e))

        self.mineBlock(3)
        txid = self.callnoderpc('sendrawtransaction', [tx_spend_hex, ])
        self.mineBlock(1)
        ro = self.callnoderpc('listreceivedbyaddress', [0, ])
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr_out:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

    def test_005_watchonly(self):
        logging.info('---------- Test {} watchonly'.format(self.test_coin_from.name))

        addr = self.callnoderpc('getnewaddress', ['watchonly test', 'bech32'])
        ro = self.callnoderpc('importaddress', [addr, '', False], node_id=1)
        txid = self.callnoderpc('sendtoaddress', [addr, 1.0])
        tx_hex = self.callnoderpc('getrawtransaction', [txid, ])
        self.callnoderpc('sendrawtransaction', [tx_hex, ], node_id=1)
        ro = self.callnoderpc('gettransaction', [txid, ], node_id=1)
        assert (ro['txid'] == txid)
        balances = self.callnoderpc('getbalances', node_id=1)
        assert (balances['watchonly']['trusted'] + balances['watchonly']['untrusted_pending'] >= 1.0)

    def test_006_getblock_verbosity(self):
        logging.info('---------- Test {} getblock verbosity'.format(self.test_coin_from.name))

        best_hash = self.callnoderpc('getbestblockhash')
        block = self.callnoderpc('getblock', [best_hash, 2])
        assert ('vin' in block['tx'][0])

    def test_007_hdwallet(self):
        logging.info('---------- Test {} hdwallet'.format(self.test_coin_from.name))

        test_seed = '8e54a313e6df8918df6d758fafdbf127a115175fdd2238d0e908dd8093c9ac3b'
        test_wif = self.swap_clients[0].ci(self.test_coin_from).encodeKey(bytes.fromhex(test_seed))
        new_wallet_name = random.randbytes(10).hex()
        # wallet_name, wallet_name, blank, passphrase, avoid_reuse, descriptors
        self.callnoderpc('createwallet', [new_wallet_name, False, True, '', False, False])
        self.callnoderpc('sethdseed', [True, test_wif], wallet=new_wallet_name)
        addr = self.callnoderpc('getnewaddress', wallet=new_wallet_name)
        self.callnoderpc('unloadwallet', [new_wallet_name])
        assert (addr == 'bcrt1qps7hnjd866e9ynxadgseprkc2l56m00dvwargr')

        self.swap_clients[0].initialiseWallet(Coins.BTC, raise_errors=True)
        assert self.swap_clients[0].checkWalletSeed(Coins.BTC) is True
        for i in range(1500):
            self.callnoderpc('getnewaddress')
        assert self.swap_clients[0].checkWalletSeed(Coins.BTC) is True

        rv = read_json_api(1800, 'getcoinseed', {'coin': 'XMR'})
        assert (rv['address'] == '47H7UDLzYEsR28BWttxp59SP1UVSxs4VKDJYSfmz7Wd4Fue5VWuoV9x9eejunwzVSmHWN37gBkaAPNf9VD4bTvwQKsBVWyK')

    def do_test_01_full_swap(self, coin_from: Coins, coin_to: Coins) -> None:
        logging.info('---------- Test {} to {}'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[0].scriptless_coins
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)
        ci_part0 = swap_clients[0].ci(Coins.PART)
        ci_part1 = swap_clients[1].ci(Coins.PART)

        # Offerer sends the offer
        # Bidder sends the bid
        id_offerer: int = 0
        id_bidder: int = 1

        # Leader sends the initial (chain a) lock tx.
        # Follower sends the participate (chain b) lock tx.
        id_leader: int = 1 if reverse_bid else 0
        id_follower: int = 0 if reverse_bid else 1
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_0 = read_json_api(1800, 'wallets')
        node0_from_before = self.getBalance(js_0, coin_from)

        js_1 = read_json_api(1801, 'wallets')
        node1_from_before = self.getBalance(js_1, coin_from)

        js_0_to = read_json_api(1800, 'wallets/{}'.format(coin_to.name.lower()))
        js_1_to = read_json_api(1801, 'wallets/{}'.format(coin_to.name.lower()))

        node0_sent_messages_before: int = ci_part0.rpc_callback('smsgoutbox', ['count',])['num_messages']
        node1_sent_messages_before: int = ci_part1.rpc_callback('smsgoutbox', ['count',])['num_messages']

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].listOffers(filters={'offer_id': offer_id})[0]
        assert (offer.offer_id == offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)
        swap_clients[id_offerer].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[id_bidder], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        amount_from = float(ci_from.format_amount(amt_swap))
        js_1 = read_json_api(1801, 'wallets')
        node1_from_after = self.getBalance(js_1, coin_from)
        if coin_from is not Coins.PART:  # TODO: staking
            assert (node1_from_after > node1_from_before + (amount_from - 0.05))

        js_0 = read_json_api(1800, 'wallets')
        node0_from_after = self.getBalance(js_0, coin_from)
        # TODO: Discard block rewards
        # assert (node0_from_after < node0_from_before - amount_from)

        js_0_to_after = read_json_api(1800, 'wallets/{}'.format(coin_to.name.lower()))
        js_1_to_after = read_json_api(1801, 'wallets/{}'.format(coin_to.name.lower()))

        scale_from = 8
        amount_to = int((amt_swap * rate_swap) // (10 ** scale_from))
        amount_to_float = float(ci_to.format_amount(amount_to))
        node1_to_after = float(js_1_to_after['unconfirmed']) + float(js_1_to_after['balance'])
        node1_to_before = float(js_1_to['unconfirmed']) + float(js_1_to['balance'])
        if False:  # TODO: set stakeaddress and xmr rewards to non wallet addresses
            assert (node1_to_after < node1_to_before - amount_to_float)

        node0_sent_messages_after: int = ci_part0.rpc_callback('smsgoutbox', ['count',])['num_messages']
        node1_sent_messages_after: int = ci_part1.rpc_callback('smsgoutbox', ['count',])['num_messages']
        node0_sent_messages: int = node0_sent_messages_after - node0_sent_messages_before
        node1_sent_messages: int = node1_sent_messages_after - node1_sent_messages_before
        assert (node0_sent_messages == (5 if reverse_bid else 6))
        assert (node1_sent_messages == (6 if reverse_bid else 4))

    def test_01_a_full_swap(self):
        if not self.has_segwit:
            return
        self.do_test_01_full_swap(self.test_coin_from, Coins.XMR)

    def test_01_b_full_swap_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR.name, 100.0, 1800, 1801)
        self.do_test_01_full_swap(Coins.XMR, self.test_coin_from)

    def test_01_c_full_swap_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_01_full_swap(self.test_coin_from, Coins.PART)

    def test_01_d_full_swap_from_part(self):
        self.do_test_01_full_swap(Coins.PART, self.test_coin_from)

    def do_test_02_leader_recover_a_lock_tx(self, coin_from: Coins, coin_to: Coins) -> None:
        logging.info('---------- Test {} to {} leader recovers coin a lock tx'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[0].scriptless_coins
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)

        id_offerer: int = 0
        id_bidder: int = 1
        id_leader: int = 1 if reverse_bid else 0
        id_follower: int = 0 if reverse_bid else 1
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_wl_before = read_json_api(1800 + id_leader, 'wallets')
        wl_from_before = self.getBalance(js_wl_before, coin_from)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=32)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].getOffer(offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)

        swap_clients[id_follower].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[id_offerer].acceptBid(bid_id)

        leader_sent_bid: bool = True if reverse_bid else False
        wait_for_bid(test_delay_event, swap_clients[id_leader], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=leader_sent_bid, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[id_follower], bid_id, [BidStates.BID_STALLED_FOR_TEST, BidStates.XMR_SWAP_FAILED], sent=(not leader_sent_bid))

        js_wl_after = read_json_api(1800 + id_leader, 'wallets')
        wl_from_after = self.getBalance(js_wl_after, coin_from)

        # TODO: Discard block rewards
        # assert (node0_from_before - node0_from_after < 0.02)

    def test_02_a_leader_recover_a_lock_tx(self):
        if not self.has_segwit:
            return
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_from, Coins.XMR)

    def test_02_b_leader_recover_a_lock_tx_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR.name, 100.0, 1800, 1801)
        self.do_test_02_leader_recover_a_lock_tx(Coins.XMR, self.test_coin_from)

    def test_02_c_leader_recover_a_lock_tx_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_from, Coins.PART)

    def test_02_leader_recover_a_lock_tx_from_part(self):
        self.do_test_02_leader_recover_a_lock_tx(Coins.PART, self.test_coin_from)

    def do_test_03_follower_recover_a_lock_tx(self, coin_from, coin_to):
        logging.info('---------- Test {} to {} follower recovers coin a lock tx'.format(coin_from.name, coin_to.name))

        # Leader is too slow to recover the coin a lock tx and follower swipes it
        # coin b lock tx remains unspent

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[0].scriptless_coins
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)

        id_offerer: int = 0
        id_bidder: int = 1
        id_leader: int = 1 if reverse_bid else 0
        id_follower: int = 0 if reverse_bid else 1
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=32)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[id_bidder].getOffer(offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)

        swap_clients[id_follower].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[id_leader].setBidDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND)

        swap_clients[id_offerer].acceptBid(bid_id)

        leader_sent_bid: bool = True if reverse_bid else False
        wait_for_bid(test_delay_event, swap_clients[id_leader], bid_id, BidStates.BID_STALLED_FOR_TEST, wait_for=180, sent=leader_sent_bid)
        wait_for_bid(test_delay_event, swap_clients[id_follower], bid_id, BidStates.XMR_SWAP_FAILED_SWIPED, wait_for=80, sent=(not leader_sent_bid))

        js_w1_after = read_json_api(1801, 'wallets')

        node1_from_before = self.getBalance(js_w1_before, coin_from)
        node1_from_after = self.getBalance(js_w1_after, coin_from)
        amount_from = float(format_amount(amt_swap, 8))
        # TODO: Discard block rewards
        # assert (node1_from_after - node1_from_before > (amount_from - 0.02))

        swap_clients[0].abandonBid(bid_id)

        wait_for_none_active(test_delay_event, 1800)
        wait_for_none_active(test_delay_event, 1801)

    def test_03_a_follower_recover_a_lock_tx(self):
        if not self.has_segwit:
            return
        self.do_test_03_follower_recover_a_lock_tx(self.test_coin_from, Coins.XMR)

    def test_03_b_follower_recover_a_lock_tx_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR.name, 100.0, 1800, 1801)
        self.do_test_03_follower_recover_a_lock_tx(Coins.XMR, self.test_coin_from)

    def test_03_c_follower_recover_a_lock_tx_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_03_follower_recover_a_lock_tx(self.test_coin_from, Coins.PART)

    def test_03_d_follower_recover_a_lock_tx_from_part(self):
        self.do_test_03_follower_recover_a_lock_tx(Coins.PART, self.test_coin_from)

    def do_test_04_follower_recover_b_lock_tx(self, coin_from, coin_to):
        logging.info('---------- Test {} to {} follower recovers coin b lock tx'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[0].scriptless_coins
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[0].ci(coin_to)

        id_offerer: int = 0
        id_bidder: int = 1
        id_leader: int = 1 if reverse_bid else 0
        id_follower: int = 0 if reverse_bid else 1
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_w0_before = read_json_api(1800, 'wallets')
        js_w1_before = read_json_api(1801, 'wallets')

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=32)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].getOffer(offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)

        swap_clients[id_follower].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[id_offerer].acceptBid(bid_id)

        leader_sent_bid: bool = True if reverse_bid else False
        wait_for_bid(test_delay_event, swap_clients[id_leader], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=200, sent=leader_sent_bid)
        wait_for_bid(test_delay_event, swap_clients[id_follower], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=(not leader_sent_bid))

        js_w0_after = read_json_api(1800, 'wallets')
        js_w1_after = read_json_api(1801, 'wallets')

        node0_from_before = self.getBalance(js_w0_before, coin_from)
        node0_from_after = self.getBalance(js_w0_after, coin_from)
        logging.info('node0 end coin_from balance {}, diff {}'.format(node0_from_after, node0_from_after - node0_from_before))
        node0_to_before = self.getBalance(js_w0_before, coin_to)
        node0_to_after = self.getBalance(js_w0_after, coin_to)
        logging.info('node0 end coin_to balance {}, diff {}'.format(node0_to_after, node0_to_after - node0_to_before))
        if coin_from != Coins.PART:  # TODO: Discard block rewards
            assert (node0_from_before - node0_from_after < 0.02)

        node1_from_before = self.getBalance(js_w1_before, coin_from)
        node1_from_after = self.getBalance(js_w1_after, coin_from)
        logging.info('node1 end coin_from balance {}, diff {}'.format(node1_from_after, node1_from_after - node1_from_before))
        node1_to_before = self.getBalance(js_w1_before, coin_to)
        node1_to_after = self.getBalance(js_w1_after, coin_to)
        logging.info('node1 end coin_to balance {}, diff {}'.format(node1_to_after, node1_to_after - node1_to_before))
        assert (node1_to_before - node1_to_after < 0.02)

    def test_04_a_follower_recover_b_lock_tx(self):
        if not self.has_segwit:
            return
        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_from, Coins.XMR)

    def test_04_b_follower_recover_b_lock_tx_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR.name, 100.0, 1800, 1801)
        self.do_test_04_follower_recover_b_lock_tx(Coins.XMR, self.test_coin_from)

    def test_04_c_follower_recover_b_lock_tx_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_from, Coins.PART)

    def test_04_d_follower_recover_b_lock_tx_from_part(self):
        self.do_test_04_follower_recover_b_lock_tx(Coins.PART, self.test_coin_from)

    def do_test_05_self_bid(self, coin_from, coin_to):
        logging.info('---------- Test {} to {} same client'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        ci_to = swap_clients[0].ci(coin_to)

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)

        offer_id = swap_clients[1].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        bid_id = swap_clients[1].postXmrBid(offer_id, amt_swap)

        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)

    def test_05_self_bid(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(self.test_coin_from, Coins.XMR)

    def test_05_self_bid_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(self.test_coin_from, Coins.PART)

    def test_05_self_bid_from_part(self):
        self.do_test_05_self_bid(Coins.PART, self.test_coin_from)

    def test_06_preselect_inputs(self):
        tla_from = self.test_coin_from.name
        logging.info('---------- Test {} Preselected inputs'.format(tla_from))
        swap_clients = self.swap_clients

        self.prepare_balance(tla_from, 100.0, 1802, 1800)

        js_w2 = read_json_api(1802, 'wallets')
        assert (float(js_w2[tla_from]['balance']) >= 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        post_json = {
            'value': float(js_w2[tla_from]['balance']),
            'address': read_json_api(1802, 'wallets/{}/nextdepositaddr'.format(tla_from.lower())),
            'subfee': True,
        }
        json_rv = read_json_api(1802, 'wallets/{}/withdraw'.format(tla_from.lower()), post_json)
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1802/json/wallets/{}'.format(tla_from.lower()), 'balance', 10.0)
        assert (len(json_rv['txid']) == 64)

        # Create prefunded ITX
        ci = swap_clients[2].ci(self.test_coin_from)
        ci_to = swap_clients[2].ci(Coins.XMR)
        pi = swap_clients[2].pi(SwapTypes.XMR_SWAP)
        js_w2 = read_json_api(1802, 'wallets')
        swap_value = ci.make_int(js_w2[tla_from]['balance'])
        assert (swap_value > ci.make_int(95))

        itx = pi.getFundedInitiateTxTemplate(ci, swap_value, True)
        itx_decoded = ci.describeTx(itx.hex())
        n = pi.findMockVout(ci, itx_decoded)
        value_after_subfee = ci.make_int(itx_decoded['vout'][n]['value'])
        assert (value_after_subfee < swap_value)
        swap_value = value_after_subfee
        wait_for_unspent(test_delay_event, ci, swap_value)

        extra_options = {'prefunded_itx': itx}
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[2].postOffer(self.test_coin_from, Coins.XMR, swap_value, rate_swap, swap_value, SwapTypes.XMR_SWAP, extra_options=extra_options)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.BID_RECEIVED)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

        # Verify expected inputs were used
        bid, _, _, _, _ = swap_clients[2].getXmrBidAndOffer(bid_id)
        assert (bid.xmr_a_lock_tx)
        wtx = ci.rpc_callback('gettransaction', [bid.xmr_a_lock_tx.txid.hex(),])
        itx_after = ci.describeTx(wtx['hex'])
        assert (len(itx_after['vin']) == len(itx_decoded['vin']))
        for i, txin in enumerate(itx_decoded['vin']):
            txin_after = itx_after['vin'][i]
            assert (txin['txid'] == txin_after['txid'])
            assert (txin['vout'] == txin_after['vout'])

    def test_07_expire_stuck_accepted(self):
        coin_from, coin_to = (self.test_coin_from, Coins.XMR)
        logging.info('---------- Test {} to {} expires bid stuck on accepted'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        ci_to = swap_clients[0].ci(coin_to)

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)

        offer_id = swap_clients[0].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        bid_id = swap_clients[1].postXmrBid(offer_id, amt_swap)
        swap_clients[1].abandonBid(bid_id)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_ACCEPTED)

        try:
            swap_clients[0].setMockTimeOffset(7200)
            old_check_expired_seconds = swap_clients[0].check_expired_seconds
            swap_clients[0].check_expired_seconds = 1

            wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_TIMEDOUT, wait_for=180)
        finally:
            swap_clients[0].check_expired_seconds = old_check_expired_seconds
            swap_clients[0].setMockTimeOffset(0)


class TestBTC(BasicSwapTest):
    __test__ = True
    test_coin_from = Coins.BTC
    start_ltc_nodes = False
    base_rpc_port = BTC_BASE_RPC_PORT

    def test_009_wallet_encryption(self):

        for coin in ('btc', 'part', 'xmr'):
            jsw = read_json_api(1800, f'wallets/{coin}')
            assert (jsw['encrypted'] is False)
            assert (jsw['locked'] is False)

        read_json_api(1800, 'setpassword', {'oldpassword': '', 'newpassword': 'notapassword123'})

        # Entire system is locked with Particl wallet
        jsw = read_json_api(1800, 'wallets/btc')
        assert ('Coin must be unlocked' in jsw['error'])

        read_json_api(1800, 'unlock', {'coin': 'part', 'password': 'notapassword123'})

        for coin in ('btc', 'xmr'):
            jsw = read_json_api(1800, f'wallets/{coin}')
            assert (jsw['encrypted'] is True)
            assert (jsw['locked'] is True)

        read_json_api(1800, 'lock', {'coin': 'part'})
        jsw = read_json_api(1800, 'wallets/part')
        assert ('Coin must be unlocked' in jsw['error'])

        read_json_api(1800, 'setpassword', {'oldpassword': 'notapassword123', 'newpassword': 'notapassword456'})
        read_json_api(1800, 'unlock', {'password': 'notapassword456'})

        for coin in ('part', 'btc', 'xmr'):
            jsw = read_json_api(1800, f'wallets/{coin}')
            assert (jsw['encrypted'] is True)
            assert (jsw['locked'] is False)

    def test_01_full_swap(self):
        js_0 = read_json_api(1800, 'wallets')
        if not js_0['PART']['encrypted']:
            read_json_api(1800, 'setpassword', {'oldpassword': '', 'newpassword': 'notapassword123'})
            read_json_api(1800, 'unlock', {'password': 'notapassword123'})
        js_0 = read_json_api(1800, 'wallets')
        assert (js_0['PART']['encrypted'] is True)
        assert (js_0['PART']['locked'] is False)

        super().test_01_full_swap()


if __name__ == '__main__':
    unittest.main()
