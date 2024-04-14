#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2021-2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import random
import logging
import unittest

from basicswap.db import (
    Concepts,
)
from basicswap.basicswap import (
    Coins,
    SwapTypes,
    BidStates,
    DebugTypes,
)
from basicswap.basicswap_util import (
    TxLockTypes,
    EventLogTypes,
)
from basicswap.util import (
    make_int,
    format_amount,
)
from basicswap.interface import Curves
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

logger = logging.getLogger()


class TestFunctions(BaseTest):
    base_rpc_port = None
    extra_wait_time = 0

    node_a_id = 0
    node_b_id = 1
    node_c_id = 2

    def callnoderpc(self, method, params=[], wallet=None, node_id=0):
        return callnoderpc(node_id, method, params, wallet, self.base_rpc_port)

    def mineBlock(self, num_blocks=1):
        self.callnoderpc('generatetoaddress', [num_blocks, self.btc_addr])

    def check_softfork_active(self, feature_name):
        deploymentinfo = self.callnoderpc('getdeploymentinfo')
        assert (deploymentinfo['deployments'][feature_name]['active'] is True)

    def getBalance(self, js_wallets, coin) -> float:
        if coin == Coins.PART_BLIND:
            coin_ticker: str = 'PART'
            balance_type: str = 'blind_balance'
            unconfirmed_name: str = 'blind_unconfirmed'
        elif coin == Coins.PART_ANON:
            coin_ticker: str = 'PART'
            balance_type: str = 'anon_balance'
            unconfirmed_name: str = 'anon_pending'
        elif coin == Coins.NAV:
            coin_wallet = js_wallets[coin.name]
            return float(coin_wallet['balance']) + float(coin_wallet['unconfirmed']) + float(coin_wallet['immature'])
        else:
            coin_ticker: str = coin.name
            balance_type: str = 'balance'
            unconfirmed_name: str = 'unconfirmed'

        return float(js_wallets[coin_ticker][balance_type]) + float(js_wallets[coin_ticker][unconfirmed_name])

    def prepare_balance(self, coin, amount: float, port_target_node: int, port_take_from_node: int, test_balance: bool = True) -> None:
        delay_iterations = 100 if coin == Coins.NAV else 20
        delay_time = 5 if coin == Coins.NAV else 3
        if coin == Coins.PART_BLIND:
            coin_ticker: str = 'PART'
            balance_type: str = 'blind_balance'
            address_type: str = 'stealth_address'
            type_to: str = 'blind'
        elif coin == Coins.PART_ANON:
            coin_ticker: str = 'PART'
            balance_type: str = 'anon_balance'
            address_type: str = 'stealth_address'
            type_to: str = 'anon'
        else:
            coin_ticker: str = coin.name
            balance_type: str = 'balance'
            address_type: str = 'deposit_address'
        js_w = read_json_api(port_target_node, 'wallets')
        current_balance: float = float(js_w[coin_ticker][balance_type])
        if test_balance and current_balance >= amount:
            return
        post_json = {
            'value': amount,
            'address': js_w[coin_ticker][address_type],
            'subfee': False,
        }
        if coin in (Coins.XMR, ):
            post_json['sweepall'] = False
        if coin in (Coins.PART_BLIND, Coins.PART_ANON):
            post_json['type_to'] = type_to
        json_rv = read_json_api(port_take_from_node, 'wallets/{}/withdraw'.format(coin_ticker.lower()), post_json)
        assert (len(json_rv['txid']) == 64)
        wait_for_amount: float = amount
        if not test_balance:
            wait_for_amount += current_balance
        wait_for_balance(test_delay_event, 'http://127.0.0.1:{}/json/wallets/{}'.format(port_target_node, coin_ticker.lower()), balance_type, wait_for_amount, iterations=delay_iterations, delay_time=delay_time)

    def do_test_01_full_swap(self, coin_from: Coins, coin_to: Coins) -> None:
        logging.info('---------- Test {} to {}'.format(coin_from.name, coin_to.name))

        # Offerer sends the offer
        # Bidder sends the bid
        id_offerer: int = self.node_a_id
        id_bidder: int = self.node_b_id

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[id_offerer].scriptless_coins
        ci_from = swap_clients[id_offerer].ci(coin_from)
        ci_to = swap_clients[id_bidder].ci(coin_to)
        ci_part0 = swap_clients[id_offerer].ci(Coins.PART)
        ci_part1 = swap_clients[id_bidder].ci(Coins.PART)

        self.prepare_balance(coin_from, 100.0, 1800 + id_offerer, 1801 if reverse_bid else 1800)

        # Leader sends the initial (chain a) lock tx.
        # Follower sends the participate (chain b) lock tx.
        id_leader: int = id_bidder if reverse_bid else id_offerer
        id_follower: int = id_offerer if reverse_bid else id_bidder
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_0 = read_json_api(1800 + id_offerer, 'wallets')
        node0_from_before: float = self.getBalance(js_0, coin_from)

        js_1 = read_json_api(1800 + id_bidder, 'wallets')
        node1_from_before: float = self.getBalance(js_1, coin_from)

        node0_sent_messages_before: int = ci_part0.rpc('smsgoutbox', ['count',])['num_messages']
        node1_sent_messages_before: int = ci_part1.rpc('smsgoutbox', ['count',])['num_messages']

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].listOffers(filters={'offer_id': offer_id})[0]
        assert (offer.offer_id == offer_id)

        post_json = {'with_extra_info': True}
        offer0 = read_json_api(1800 + id_offerer, f'offers/{offer_id.hex()}', post_json)[0]
        offer1 = read_json_api(1800 + id_offerer, f'offers/{offer_id.hex()}', post_json)[0]
        assert ('lock_time_1' in offer0)
        assert ('lock_time_1' in offer1)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)

        bid0 = read_json_api(1800 + id_offerer, f'bids/{bid_id.hex()}')
        bid1 = read_json_api(1800 + id_bidder, f'bids/{bid_id.hex()}')

        tolerance = 1
        assert (bid0['ticker_from'] == ci_from.ticker())
        assert (bid1['ticker_from'] == ci_from.ticker())
        assert (bid0['ticker_to'] == ci_to.ticker())
        assert (bid1['ticker_to'] == ci_to.ticker())
        assert (abs(ci_from.make_int(bid0['amt_from']) - amt_swap) <= tolerance)
        assert (abs(ci_from.make_int(bid1['amt_from']) - amt_swap) <= tolerance)
        assert (abs(ci_to.make_int(bid0['bid_rate']) - rate_swap) <= tolerance)
        assert (abs(ci_to.make_int(bid1['bid_rate']) - rate_swap) <= tolerance)
        assert (bid0['reverse_bid'] == reverse_bid)
        assert (bid1['reverse_bid'] == reverse_bid)

        found: bool = False
        bids0 = read_json_api(1800 + id_offerer, 'bids')
        for bid in bids0:
            if bid['bid_id'] != bid_id.hex():
                continue
            assert (bid['amount_from'] == bid1['amt_from'])
            assert (bid['bid_rate'] == bid1['bid_rate'])
            found = True
            break
        assert (found)

        swap_clients[id_offerer].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.SWAP_COMPLETED, wait_for=(self.extra_wait_time + 180))
        wait_for_bid(test_delay_event, swap_clients[id_bidder], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=(self.extra_wait_time + 30))

        amount_from = float(ci_from.format_amount(amt_swap))
        js_1_after = read_json_api(1800 + id_bidder, 'wallets')
        node1_from_after = self.getBalance(js_1_after, coin_from)
        if coin_from is not Coins.PART:  # TODO: staking
            assert (node1_from_after > node1_from_before + (amount_from - 0.05))

        js_0_after = read_json_api(1800 + id_offerer, 'wallets')
        node0_from_after: float = self.getBalance(js_0_after, coin_from)
        # TODO: Discard block rewards
        # assert (node0_from_after < node0_from_before - amount_from)

        scale_from = ci_from.exp()
        amount_to = int((amt_swap * rate_swap) // (10 ** scale_from))
        amount_to_float = float(ci_to.format_amount(amount_to))
        node1_to_after: float = self.getBalance(js_1_after, coin_to)
        node1_to_before: float = self.getBalance(js_1, coin_to)
        if False:  # TODO: set stakeaddress and xmr rewards to non wallet addresses
            assert (node1_to_after < node1_to_before - amount_to_float)

        node0_sent_messages_after: int = ci_part0.rpc('smsgoutbox', ['count',])['num_messages']
        node1_sent_messages_after: int = ci_part1.rpc('smsgoutbox', ['count',])['num_messages']
        node0_sent_messages: int = node0_sent_messages_after - node0_sent_messages_before
        node1_sent_messages: int = node1_sent_messages_after - node1_sent_messages_before
        split_msgs: int = 2 if (ci_from.curve_type() != Curves.secp256k1 or ci_to.curve_type() != Curves.secp256k1) else 0
        assert (node0_sent_messages == (3 + split_msgs if reverse_bid else 4 + split_msgs))
        assert (node1_sent_messages == (4 + split_msgs if reverse_bid else 2 + split_msgs))

        post_json = {'show_extra': True}
        bid0 = read_json_api(1800 + id_offerer, f'bids/{bid_id.hex()}', post_json)
        bid1 = read_json_api(1800 + id_bidder, f'bids/{bid_id.hex()}', post_json)

        chain_a_lock_txid = None
        chain_b_lock_txid = None
        for tx in bid0['txns']:
            if tx['type'] == 'Chain A Lock Spend':
                chain_a_lock_txid = tx['txid']
            elif tx['type'] == 'Chain B Lock Spend':
                chain_b_lock_txid = tx['txid']
        for tx in bid1['txns']:
            if not chain_a_lock_txid and tx['type'] == 'Chain A Lock Spend':
                chain_a_lock_txid = tx['txid']
            elif not chain_b_lock_txid and tx['type'] == 'Chain B Lock Spend':
                chain_b_lock_txid = tx['txid']
        assert (chain_a_lock_txid is not None)
        assert (chain_b_lock_txid is not None)

    def do_test_02_leader_recover_a_lock_tx(self, coin_from: Coins, coin_to: Coins, lock_value: int = 32) -> None:
        logging.info('---------- Test {} to {} leader recovers coin a lock tx'.format(coin_from.name, coin_to.name))

        id_offerer: int = self.node_a_id
        id_bidder: int = self.node_b_id

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[id_offerer].scriptless_coins
        ci_from = swap_clients[id_offerer].ci(coin_from)
        ci_to = swap_clients[id_offerer].ci(coin_to)

        id_leader: int = id_bidder if reverse_bid else id_offerer
        id_follower: int = id_offerer if reverse_bid else id_bidder
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_wl_before = read_json_api(1800 + id_leader, 'wallets')
        wl_from_before = self.getBalance(js_wl_before, coin_from)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=lock_value)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].getOffer(offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)

        swap_clients[id_follower].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[id_offerer].acceptBid(bid_id)

        leader_sent_bid: bool = True if reverse_bid else False
        wait_for_bid(test_delay_event, swap_clients[id_leader], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=leader_sent_bid, wait_for=(self.extra_wait_time + 180))
        wait_for_bid(test_delay_event, swap_clients[id_follower], bid_id, [BidStates.BID_STALLED_FOR_TEST, BidStates.XMR_SWAP_FAILED], sent=(not leader_sent_bid), wait_for=(self.extra_wait_time + 30))

        js_wl_after = read_json_api(1800 + id_leader, 'wallets')
        wl_from_after = self.getBalance(js_wl_after, coin_from)

        # TODO: Discard block rewards
        # assert (node0_from_before - node0_from_after < 0.02)

    def do_test_03_follower_recover_a_lock_tx(self, coin_from, coin_to, lock_value: int = 32):
        logging.info('---------- Test {} to {} follower recovers coin a lock tx'.format(coin_from.name, coin_to.name))

        # Leader is too slow to recover the coin a lock tx and follower swipes it
        # coin b lock tx remains unspent

        id_offerer: int = self.node_a_id
        id_bidder: int = self.node_b_id

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[id_offerer].scriptless_coins
        ci_from = swap_clients[id_offerer].ci(coin_from)
        ci_to = swap_clients[id_offerer].ci(coin_to)

        id_leader: int = id_bidder if reverse_bid else id_offerer
        id_follower: int = id_offerer if reverse_bid else id_bidder
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_w0_before = read_json_api(1800 + id_offerer, 'wallets')
        js_w1_before = read_json_api(1800 + id_bidder, 'wallets')

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=lock_value)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].getOffer(offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)

        swap_clients[id_follower].setBidDebugInd(bid_id, DebugTypes.BID_STOP_AFTER_COIN_A_LOCK)
        swap_clients[id_leader].setBidDebugInd(bid_id, DebugTypes.BID_DONT_SPEND_COIN_A_LOCK_REFUND)

        swap_clients[id_offerer].acceptBid(bid_id)

        leader_sent_bid: bool = True if reverse_bid else False
        wait_for_bid(test_delay_event, swap_clients[id_leader], bid_id, BidStates.BID_STALLED_FOR_TEST, wait_for=(self.extra_wait_time + 180), sent=leader_sent_bid)
        wait_for_bid(test_delay_event, swap_clients[id_follower], bid_id, BidStates.XMR_SWAP_FAILED_SWIPED, wait_for=(self.extra_wait_time + 80), sent=(not leader_sent_bid))

        js_w1_after = read_json_api(1800 + id_bidder, 'wallets')

        node1_from_before = self.getBalance(js_w1_before, coin_from)
        node1_from_after = self.getBalance(js_w1_after, coin_from)
        amount_from = float(format_amount(amt_swap, 8))
        # TODO: Discard block rewards
        # assert (node1_from_after - node1_from_before > (amount_from - 0.02))

        swap_clients[id_offerer].abandonBid(bid_id)

        wait_for_none_active(test_delay_event, 1800 + id_offerer)
        wait_for_none_active(test_delay_event, 1800 + id_bidder)

    def do_test_04_follower_recover_b_lock_tx(self, coin_from, coin_to, lock_value: int = 32):
        logging.info('---------- Test {} to {} follower recovers coin b lock tx'.format(coin_from.name, coin_to.name))

        id_offerer: int = self.node_a_id
        id_bidder: int = self.node_b_id

        swap_clients = self.swap_clients
        reverse_bid: bool = coin_from in swap_clients[id_offerer].scriptless_coins
        ci_from = swap_clients[id_offerer].ci(coin_from)
        ci_to = swap_clients[id_offerer].ci(coin_to)

        id_offerer: int = id_offerer
        id_bidder: int = id_bidder
        id_leader: int = id_bidder if reverse_bid else id_offerer
        id_follower: int = id_offerer if reverse_bid else id_bidder
        logging.info(f'Offerer, bidder, leader, follower: {id_offerer}, {id_bidder}, {id_leader}, {id_follower}')

        js_w0_before = read_json_api(1800 + id_offerer, 'wallets')
        js_w1_before = read_json_api(1800 + id_bidder, 'wallets')

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[id_offerer].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=lock_value)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)
        offer = swap_clients[id_bidder].getOffer(offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED)

        swap_clients[id_follower].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[id_offerer].acceptBid(bid_id)

        leader_sent_bid: bool = True if reverse_bid else False
        wait_for_bid(test_delay_event, swap_clients[id_leader], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=(self.extra_wait_time + 200), sent=leader_sent_bid)
        wait_for_bid(test_delay_event, swap_clients[id_follower], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=(not leader_sent_bid), wait_for=(self.extra_wait_time + 30))

        js_w0_after = read_json_api(1800 + id_offerer, 'wallets')
        js_w1_after = read_json_api(1800 + id_bidder, 'wallets')

        node0_from_before = self.getBalance(js_w0_before, coin_from)
        node0_from_after = self.getBalance(js_w0_after, coin_from)
        logging.info('node0 end coin_from balance {}, diff {}'.format(node0_from_after, node0_from_after - node0_from_before))
        node0_to_before = self.getBalance(js_w0_before, coin_to)
        node0_to_after = self.getBalance(js_w0_after, coin_to)
        logging.info('node0 end coin_to balance {}, diff {}'.format(node0_to_after, node0_to_after - node0_to_before))
        max_fee_from: float = 0.1 if coin_from == Coins.PART_ANON else 0.02
        if coin_from != Coins.PART:  # TODO: Discard block rewards
            assert (node0_from_before - node0_from_after < max_fee_from)

        node1_from_before = self.getBalance(js_w1_before, coin_from)
        node1_from_after = self.getBalance(js_w1_after, coin_from)
        logging.info('node1 end coin_from balance {}, diff {}'.format(node1_from_after, node1_from_after - node1_from_before))
        node1_to_before = self.getBalance(js_w1_before, coin_to)
        node1_to_after = self.getBalance(js_w1_after, coin_to)
        logging.info('node1 end coin_to balance {}, diff {}'.format(node1_to_after, node1_to_after - node1_to_before))

        max_fee_to: float = 0.1 if coin_to == Coins.PART_ANON else 0.02
        assert (node1_to_before - node1_to_after < max_fee_to)

    def do_test_05_self_bid(self, coin_from, coin_to):
        logging.info('---------- Test {} to {} same client'.format(coin_from.name, coin_to.name))

        id_both: int = self.node_b_id

        swap_clients = self.swap_clients
        ci_from = swap_clients[id_both].ci(coin_from)
        ci_to = swap_clients[id_both].ci(coin_to)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)

        offer_id = swap_clients[id_both].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        bid_id = swap_clients[id_both].postXmrBid(offer_id, amt_swap)

        wait_for_bid(test_delay_event, swap_clients[id_both], bid_id, BidStates.SWAP_COMPLETED, wait_for=(self.extra_wait_time + 180))


class BasicSwapTest(TestFunctions):

    def test_001_nested_segwit(self):
        # p2sh-p2wpkh
        logging.info('---------- Test {} p2sh nested segwit'.format(self.test_coin_from.name))
        ci = self.swap_clients[0].ci(self.test_coin_from)

        addr_p2sh_segwit = ci.rpc_wallet('getnewaddress', ['segwit test', 'p2sh-segwit'])
        addr_info = ci.rpc_wallet('getaddressinfo', [addr_p2sh_segwit, ])
        assert addr_info['script'] == 'witness_v0_keyhash'

        txid = ci.rpc_wallet('sendtoaddress', [addr_p2sh_segwit, 1.0])
        assert len(txid) == 64

        self.mineBlock()
        ro = ci.rpc('scantxoutset', ['start', ['addr({})'.format(addr_p2sh_segwit)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

        tx_wallet = ci.rpc_wallet('gettransaction', [txid, ])['hex']
        tx = ci.rpc('decoderawtransaction', [tx_wallet, ])

        prevout_n = -1
        for txo in tx['vout']:
            if addr_p2sh_segwit == txo['scriptPubKey']['address']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        tx_funded = ci.rpc('createrawtransaction', [[{'txid': txid, 'vout': prevout_n}], {addr_p2sh_segwit: 0.99}])
        tx_signed = ci.rpc_wallet('signrawtransactionwithwallet', [tx_funded, ])['hex']
        tx_funded_decoded = ci.rpc('decoderawtransaction', [tx_funded, ])
        tx_signed_decoded = ci.rpc('decoderawtransaction', [tx_signed, ])
        assert tx_funded_decoded['txid'] != tx_signed_decoded['txid']

        # Add scriptsig for txids to match
        addr_p2sh_segwit_info = ci.rpc_wallet('getaddressinfo', [addr_p2sh_segwit, ])
        decoded_tx = FromHex(CTransaction(), tx_funded)
        decoded_tx.vin[0].scriptSig = bytes.fromhex('16' + addr_p2sh_segwit_info['hex'])
        txid_with_scriptsig = decoded_tx.rehash()
        assert txid_with_scriptsig == tx_signed_decoded['txid']

    def test_002_native_segwit(self):
        # p2wpkh
        logging.info('---------- Test {} p2sh native segwit'.format(self.test_coin_from.name))
        ci = self.swap_clients[0].ci(self.test_coin_from)

        addr_segwit = ci.rpc_wallet('getnewaddress', ['segwit test', 'bech32'])
        addr_info = ci.rpc_wallet('getaddressinfo', [addr_segwit, ])
        assert addr_info['iswitness'] is True

        txid = ci.rpc_wallet('sendtoaddress', [addr_segwit, 1.0])
        assert len(txid) == 64
        tx_wallet = ci.rpc_wallet('gettransaction', [txid, ])['hex']
        tx = ci.rpc('decoderawtransaction', [tx_wallet, ])

        self.mineBlock()
        ro = ci.rpc('scantxoutset', ['start', ['addr({})'.format(addr_segwit)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

        prevout_n = -1
        for txo in tx['vout']:
            if addr_segwit == txo['scriptPubKey']['address']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        tx_funded = ci.rpc('createrawtransaction', [[{'txid': txid, 'vout': prevout_n}], {addr_segwit: 0.99}])
        tx_signed = ci.rpc_wallet('signrawtransactionwithwallet', [tx_funded, ])['hex']
        tx_funded_decoded = ci.rpc('decoderawtransaction', [tx_funded, ])
        tx_signed_decoded = ci.rpc('decoderawtransaction', [tx_signed, ])
        assert tx_funded_decoded['txid'] == tx_signed_decoded['txid']

    def test_003_cltv(self):
        logging.info('---------- Test {} cltv'.format(self.test_coin_from.name))
        ci = self.swap_clients[0].ci(self.test_coin_from)

        self.check_softfork_active('bip65')

        chain_height = self.callnoderpc('getblockcount')
        script = CScript([chain_height + 3, OP_CHECKLOCKTIMEVERIFY, ])

        script_dest = ci.getScriptDest(script)
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = ci.rpc_wallet('fundrawtransaction', [tx_hex])
        utxo_pos = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = ci.rpc_wallet('signrawtransactionwithwallet', [tx_funded['hex'], ])['hex']
        txid = ci.rpc('sendrawtransaction', [tx_signed, ])

        addr_out = ci.rpc_wallet('getnewaddress', ['cltv test', 'bech32'])
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

        tx_spend.nLockTime = chain_height + 2
        tx_spend_invalid_hex = ToHex(tx_spend)

        for tx_hex in [tx_spend_invalid_hex, tx_spend_hex]:
            try:
                txid = self.callnoderpc('sendrawtransaction', [tx_hex, ])
            except Exception as e:
                assert ('non-final' in str(e))
            else:
                assert False, 'Should fail'

        self.mineBlock(5)
        try:
            txid = ci.rpc('sendrawtransaction', [tx_spend_invalid_hex, ])
        except Exception as e:
            assert ('Locktime requirement not satisfied' in str(e))
        else:
            assert False, 'Should fail'

        txid = ci.rpc('sendrawtransaction', [tx_spend_hex, ])
        self.mineBlock()
        ro = ci.rpc_wallet('listreceivedbyaddress', [0, ])
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr_out:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

        # Ensure tx was mined
        tx_wallet = ci.rpc_wallet('gettransaction', [txid, ])
        assert (len(tx_wallet['blockhash']) == 64)

    def test_004_csv(self):
        logging.info('---------- Test {} csv'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients
        ci = self.swap_clients[0].ci(self.test_coin_from)

        self.check_softfork_active('csv')

        script = CScript([3, OP_CHECKSEQUENCEVERIFY, ])

        script_dest = ci.getScriptDest(script)
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = ci.rpc_wallet('fundrawtransaction', [tx_hex])
        utxo_pos = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = ci.rpc_wallet('signrawtransactionwithwallet', [tx_funded['hex'], ])['hex']
        txid = ci.rpc('sendrawtransaction', [tx_signed, ])

        addr_out = ci.rpc_wallet('getnewaddress', ['csv test', 'bech32'])
        pkh = ci.decodeSegwitAddress(addr_out)
        script_out = ci.getScriptForPubkeyHash(pkh)

        # Double check output type
        prev_tx = ci.rpc('decoderawtransaction', [tx_signed, ])
        assert (prev_tx['vout'][utxo_pos]['scriptPubKey']['type'] == 'witness_v0_scripthash')

        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()
        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), utxo_pos),
                            nSequence=3))
        tx_spend.vout.append(ci.txoType()(ci.make_int(1.0999), script_out))
        tx_spend.wit.vtxinwit.append(CTxInWitness())
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [script, ]
        tx_spend_hex = ToHex(tx_spend)
        try:
            txid = ci.rpc('sendrawtransaction', [tx_spend_hex, ])
        except Exception as e:
            assert ('non-BIP68-final' in str(e))
        else:
            assert False, 'Should fail'

        self.mineBlock(3)
        txid = ci.rpc('sendrawtransaction', [tx_spend_hex, ])
        self.mineBlock(1)
        ro = ci.rpc_wallet('listreceivedbyaddress', [0, ])
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr_out:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

        # Ensure tx was mined
        tx_wallet = ci.rpc_wallet('gettransaction', [txid, ])
        assert (len(tx_wallet['blockhash']) == 64)

    def test_005_watchonly(self):
        logging.info('---------- Test {} watchonly'.format(self.test_coin_from.name))
        ci = self.swap_clients[0].ci(self.test_coin_from)
        ci1 = self.swap_clients[1].ci(self.test_coin_from)

        addr = ci.rpc_wallet('getnewaddress', ['watchonly test', 'bech32'])
        ro = ci1.rpc_wallet('importaddress', [addr, '', False])
        txid = ci.rpc_wallet('sendtoaddress', [addr, 1.0])
        tx_hex = ci.rpc('getrawtransaction', [txid, ])
        ci1.rpc_wallet('sendrawtransaction', [tx_hex, ])
        ro = ci1.rpc_wallet('gettransaction', [txid, ])
        assert (ro['txid'] == txid)
        balances = ci1.rpc_wallet('getbalances')
        assert (balances['watchonly']['trusted'] + balances['watchonly']['untrusted_pending'] >= 1.0)

    def test_006_getblock_verbosity(self):
        logging.info('---------- Test {} getblock verbosity'.format(self.test_coin_from.name))

        best_hash = self.callnoderpc('getbestblockhash')
        block = self.callnoderpc('getblock', [best_hash, 2])
        assert ('vin' in block['tx'][0])

    def test_007_hdwallet(self):
        logging.info('---------- Test {} hdwallet'.format(self.test_coin_from.name))
        ci = self.swap_clients[0].ci(self.test_coin_from)

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
            ci.rpc_wallet('getnewaddress')
        assert self.swap_clients[0].checkWalletSeed(Coins.BTC) is True

        rv = read_json_api(1800, 'getcoinseed', {'coin': 'XMR'})
        assert (rv['address'] == '47H7UDLzYEsR28BWttxp59SP1UVSxs4VKDJYSfmz7Wd4Fue5VWuoV9x9eejunwzVSmHWN37gBkaAPNf9VD4bTvwQKsBVWyK')

    def test_008_gettxout(self):
        logging.info('---------- Test {} gettxout'.format(self.test_coin_from.name))

        swap_client = self.swap_clients[0]
        ci = swap_client.ci(self.test_coin_from)

        addr_1 = ci.rpc_wallet('getnewaddress', ['gettxout test 1',])
        txid = ci.rpc_wallet('sendtoaddress', [addr_1, 1.0])
        assert len(txid) == 64

        self.mineBlock()

        unspents = ci.rpc_wallet('listunspent', [0, 999999999, [addr_1,]])
        assert (len(unspents) == 1)

        utxo = unspents[0]
        txout = ci.rpc('gettxout', [utxo['txid'], utxo['vout']])
        if 'address' in txout['scriptPubKey']:
            assert (addr_1 == txout['scriptPubKey']['address'])
        else:
            assert (addr_1 in txout['scriptPubKey']['addresses'])
        # Spend
        addr_2 = ci.rpc_wallet('getnewaddress', ['gettxout test 2',])
        tx_funded = ci.rpc('createrawtransaction', [[{'txid': utxo['txid'], 'vout': utxo['vout']}], {addr_2: 0.99}])
        tx_signed = ci.rpc_wallet('signrawtransactionwithwallet', [tx_funded,])['hex']
        ci.rpc('sendrawtransaction', [tx_signed,])

        # utxo should be unavailable when spent in the mempool
        txout = ci.rpc('gettxout', [utxo['txid'], utxo['vout']])
        assert (txout is None)

    def test_009_scantxoutset(self):
        logging.info('---------- Test {} scantxoutset'.format(self.test_coin_from.name))
        ci = self.swap_clients[0].ci(self.test_coin_from)

        addr_1 = ci.rpc_wallet('getnewaddress', ['scantxoutset test', ])
        txid = ci.rpc_wallet('sendtoaddress', [addr_1, 1.0])
        assert len(txid) == 64

        self.mineBlock()

        ro = ci.rpc('scantxoutset', ['start', ['addr({})'.format(addr_1)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

    def test_010_txn_size(self):
        logging.info('---------- Test {} txn_size'.format(self.test_coin_from.name))

        swap_clients = self.swap_clients
        ci = swap_clients[0].ci(self.test_coin_from)
        pi = swap_clients[0].pi(SwapTypes.XMR_SWAP)

        amount: int = ci.make_int(random.uniform(0.1, 2.0), r=1)

        # Record unspents before createSCLockTx as the used ones will be locked
        unspents = ci.rpc_wallet('listunspent')

        # fee_rate is in sats/kvB
        fee_rate: int = 1000

        a = ci.getNewSecretKey()
        b = ci.getNewSecretKey()

        A = ci.getPubkey(a)
        B = ci.getPubkey(b)
        lock_tx_script = pi.genScriptLockTxScript(ci, A, B)

        lock_tx = ci.createSCLockTx(amount, lock_tx_script)
        lock_tx = ci.fundSCLockTx(lock_tx, fee_rate)
        lock_tx = ci.signTxWithWallet(lock_tx)

        unspents_after = ci.rpc_wallet('listunspent')
        assert (len(unspents) > len(unspents_after))

        tx_decoded = ci.rpc('decoderawtransaction', [lock_tx.hex()])
        txid = tx_decoded['txid']

        vsize = tx_decoded['vsize']
        expect_fee_int = round(fee_rate * vsize / 1000)
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
        rv = ci.rpc_wallet('gettransaction', [txid])
        wallet_tx_fee = -ci.make_int(rv['fee'])

        assert (wallet_tx_fee == fee_value)
        assert (wallet_tx_fee == expect_fee_int)

        addr_out = ci.getNewAddress(True)
        pkh_out = ci.decodeAddress(addr_out)
        fee_info = {}
        lock_spend_tx = ci.createSCLockSpendTx(lock_tx, lock_tx_script, pkh_out, fee_rate, fee_info=fee_info)
        vsize_estimated: int = fee_info['vsize']

        tx_decoded = ci.rpc('decoderawtransaction', [lock_spend_tx.hex()])
        txid = tx_decoded['txid']

        witness_stack = [
            b'',
            ci.signTx(a, lock_spend_tx, 0, lock_tx_script, amount),
            ci.signTx(b, lock_spend_tx, 0, lock_tx_script, amount),
            lock_tx_script,
        ]
        lock_spend_tx = ci.setTxSignature(lock_spend_tx, witness_stack)
        tx_decoded = ci.rpc('decoderawtransaction', [lock_spend_tx.hex()])
        vsize_actual: int = tx_decoded['vsize']

        assert (vsize_actual <= vsize_estimated and vsize_estimated - vsize_actual < 4)
        assert (ci.rpc('sendrawtransaction', [lock_spend_tx.hex()]) == txid)

        expect_vsize: int = ci.xmr_swap_a_lock_spend_tx_vsize()
        assert (expect_vsize >= vsize_actual)
        assert (expect_vsize - vsize_actual < 10)

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

        expect_vsize: int = ci.xmr_swap_b_lock_spend_tx_vsize()
        assert (expect_vsize >= lock_tx_b_spend_decoded['vsize'])
        assert (expect_vsize - lock_tx_b_spend_decoded['vsize'] < 10)

    def test_011_p2sh(self):
        # Not used in bsx for native-segwit coins
        logging.info('---------- Test {} p2sh'.format(self.test_coin_from.name))

        swap_clients = self.swap_clients
        ci = self.swap_clients[0].ci(self.test_coin_from)

        script = CScript([2, 2, OP_EQUAL, ])

        script_dest = ci.get_p2sh_script_pubkey(script)
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = ci.rpc_wallet('fundrawtransaction', [tx_hex])
        utxo_pos = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = ci.rpc_wallet('signrawtransactionwithwallet', [tx_funded['hex'], ])['hex']
        txid = ci.rpc('sendrawtransaction', [tx_signed, ])

        addr_out = ci.rpc_wallet('getnewaddress', ['csv test', 'bech32'])
        pkh = ci.decodeSegwitAddress(addr_out)
        script_out = ci.getScriptForPubkeyHash(pkh)

        # Double check output type
        prev_tx = ci.rpc('decoderawtransaction', [tx_signed, ])
        assert (prev_tx['vout'][utxo_pos]['scriptPubKey']['type'] == 'scripthash')

        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()
        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), utxo_pos),
                            scriptSig=CScript([script,])))
        tx_spend.vout.append(ci.txoType()(ci.make_int(1.0999), script_out))
        tx_spend_hex = ToHex(tx_spend)

        txid = ci.rpc('sendrawtransaction', [tx_spend_hex, ])
        self.mineBlock(1)
        ro = ci.rpc_wallet('listreceivedbyaddress', [0, ])
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr_out:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

        # Ensure tx was mined
        tx_wallet = ci.rpc_wallet('gettransaction', [txid, ])
        assert (len(tx_wallet['blockhash']) == 64)

    def test_012_p2sh_p2wsh(self):
        # Not used in bsx for native-segwit coins
        logging.info('---------- Test {} p2sh-p2wsh'.format(self.test_coin_from.name))

        swap_clients = self.swap_clients
        ci = self.swap_clients[0].ci(self.test_coin_from)

        script = CScript([2, 2, OP_EQUAL, ])

        script_dest = ci.getP2SHP2WSHDest(script)
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = ci.rpc_wallet('fundrawtransaction', [tx_hex])
        utxo_pos = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = ci.rpc_wallet('signrawtransactionwithwallet', [tx_funded['hex'], ])['hex']
        txid = ci.rpc('sendrawtransaction', [tx_signed, ])

        addr_out = ci.rpc_wallet('getnewaddress', ['csv test', 'bech32'])
        pkh = ci.decodeSegwitAddress(addr_out)
        script_out = ci.getScriptForPubkeyHash(pkh)

        # Double check output type
        prev_tx = ci.rpc('decoderawtransaction', [tx_signed, ])
        assert (prev_tx['vout'][utxo_pos]['scriptPubKey']['type'] == 'scripthash')

        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()
        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), utxo_pos),
                            scriptSig=ci.getP2SHP2WSHScriptSig(script)))
        tx_spend.vout.append(ci.txoType()(ci.make_int(1.0999), script_out))
        tx_spend.wit.vtxinwit.append(CTxInWitness())
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [script, ]
        tx_spend_hex = ToHex(tx_spend)

        txid = ci.rpc('sendrawtransaction', [tx_spend_hex, ])
        self.mineBlock(1)
        ro = ci.rpc_wallet('listreceivedbyaddress', [0, ])
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr_out:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

        # Ensure tx was mined
        tx_wallet = ci.rpc_wallet('gettransaction', [txid, ])
        assert (len(tx_wallet['blockhash']) == 64)

    def test_01_a_full_swap(self):
        if not self.has_segwit:
            return
        self.do_test_01_full_swap(self.test_coin_from, Coins.XMR)

    def test_01_b_full_swap_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_01_full_swap(Coins.XMR, self.test_coin_from)

    def test_01_c_full_swap_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_01_full_swap(self.test_coin_from, Coins.PART)

    def test_01_d_full_swap_from_part(self):
        self.do_test_01_full_swap(Coins.PART, self.test_coin_from)

    def test_02_a_leader_recover_a_lock_tx(self):
        if not self.has_segwit:
            return
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_from, Coins.XMR)

    def test_02_b_leader_recover_a_lock_tx_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_02_leader_recover_a_lock_tx(Coins.XMR, self.test_coin_from)

    def test_02_c_leader_recover_a_lock_tx_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_from, Coins.PART)

    def test_02_leader_recover_a_lock_tx_from_part(self):
        self.do_test_02_leader_recover_a_lock_tx(Coins.PART, self.test_coin_from)

    def test_03_a_follower_recover_a_lock_tx(self):
        if not self.has_segwit:
            return
        self.do_test_03_follower_recover_a_lock_tx(self.test_coin_from, Coins.XMR)

    def test_03_b_follower_recover_a_lock_tx_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_03_follower_recover_a_lock_tx(Coins.XMR, self.test_coin_from)

    def test_03_c_follower_recover_a_lock_tx_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_03_follower_recover_a_lock_tx(self.test_coin_from, Coins.PART)

    def test_03_d_follower_recover_a_lock_tx_from_part(self):
        self.do_test_03_follower_recover_a_lock_tx(Coins.PART, self.test_coin_from)

    def test_04_a_follower_recover_b_lock_tx(self):
        if not self.has_segwit:
            return
        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_from, Coins.XMR)

    def test_04_b_follower_recover_b_lock_tx_reverse(self):
        if not self.has_segwit:
            return
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_04_follower_recover_b_lock_tx(Coins.XMR, self.test_coin_from)

    def test_04_c_follower_recover_b_lock_tx_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_from, Coins.PART)

    def test_04_d_follower_recover_b_lock_tx_from_part(self):
        self.do_test_04_follower_recover_b_lock_tx(Coins.PART, self.test_coin_from)

    def test_05_self_bid(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(self.test_coin_from, Coins.XMR)

    def test_05_self_bid_to_part(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(self.test_coin_from, Coins.PART)

    def test_05_self_bid_from_part(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(Coins.PART, self.test_coin_from)

    def test_05_self_bid_rev(self):
        if not self.has_segwit:
            return
        self.do_test_05_self_bid(Coins.XMR, self.test_coin_from)

    def test_06_preselect_inputs(self):
        tla_from = self.test_coin_from.name
        logging.info('---------- Test {} Preselected inputs'.format(tla_from))
        swap_clients = self.swap_clients

        self.prepare_balance(self.test_coin_from, 100.0, 1802, 1800)

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
        wtx = ci.rpc_wallet('gettransaction', [bid.xmr_a_lock_tx.txid.hex(),])
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

    def test_08_insufficient_funds(self):
        tla_from = self.test_coin_from.name
        logging.info('---------- Test {} Insufficient Funds'.format(tla_from))
        swap_clients = self.swap_clients
        coin_from = self.test_coin_from
        coin_to = Coins.XMR

        self.prepare_balance(coin_from, 10.0, 1802, 1800)

        id_offerer: int = self.node_c_id
        id_bidder: int = self.node_b_id

        swap_clients = self.swap_clients
        ci_from = swap_clients[id_offerer].ci(coin_from)
        ci_to = swap_clients[id_bidder].ci(coin_to)

        jsw = read_json_api(1800 + id_offerer, 'wallets')
        balance_from_before: float = self.getBalance(jsw, coin_from)

        amt_swap: int = ci_from.make_int(balance_from_before, r=1)
        rate_swap: int = ci_to.make_int(2.0, r=1)
        offer_id = swap_clients[id_offerer].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, amt_swap)

        event = wait_for_event(test_delay_event, swap_clients[id_offerer], Concepts.BID, bid_id, event_type=EventLogTypes.ERROR, wait_for=60)
        assert ('Insufficient funds' in event.event_msg)

        wait_for_bid(test_delay_event, swap_clients[id_offerer], bid_id, BidStates.BID_RECEIVED, wait_for=20)

    def test_08_insufficient_funds_rev(self):
        tla_from = self.test_coin_from.name
        logging.info('---------- Test {} Insufficient Funds (reverse)'.format(tla_from))
        swap_clients = self.swap_clients
        coin_from = Coins.XMR
        coin_to = self.test_coin_from

        self.prepare_balance(coin_to, 10.0, 1802, 1800)

        id_offerer: int = self.node_b_id
        id_bidder: int = self.node_c_id

        swap_clients = self.swap_clients
        ci_from = swap_clients[id_offerer].ci(coin_from)
        ci_to = swap_clients[id_bidder].ci(coin_to)

        jsw = read_json_api(1800 + id_bidder, 'wallets')
        balance_to_before: float = self.getBalance(jsw, coin_to)

        amt_swap: int = ci_from.make_int(balance_to_before, r=1)
        rate_swap: int = ci_to.make_int(1.0, r=1)

        amt_swap -= 1
        offer_id = swap_clients[id_offerer].postOffer(coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP, auto_accept_bids=True)
        wait_for_offer(test_delay_event, swap_clients[id_bidder], offer_id)

        bid_id = swap_clients[id_bidder].postXmrBid(offer_id, amt_swap)

        event = wait_for_event(test_delay_event, swap_clients[id_bidder], Concepts.BID, bid_id, event_type=EventLogTypes.ERROR, wait_for=60)
        assert ('Insufficient funds' in event.event_msg)

        wait_for_bid(test_delay_event, swap_clients[id_bidder], bid_id, BidStates.BID_ERROR, sent=True, wait_for=20)


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
        abandon_all_swaps(test_delay_event, self.swap_clients[0])
        wait_for_none_active(test_delay_event, 1800)
        js_0 = read_json_api(1800, 'wallets')
        if not js_0['PART']['encrypted']:
            read_json_api(1800, 'setpassword', {'oldpassword': '', 'newpassword': 'notapassword123'})
            read_json_api(1800, 'unlock', {'password': 'notapassword123'})
        js_0 = read_json_api(1800, 'wallets')
        assert (js_0['PART']['encrypted'] is True)
        assert (js_0['PART']['locked'] is False)

        super().test_01_a_full_swap()


class TestBTC_PARTB(TestFunctions):
    __test__ = True
    test_coin_from = Coins.BTC
    test_coin_to = Coins.PART_BLIND
    start_ltc_nodes = False
    base_rpc_port = BTC_BASE_RPC_PORT

    def test_01_a_full_swap(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1801, 1800)
        self.do_test_01_full_swap(self.test_coin_from, self.test_coin_to)

    def test_01_b_full_swap_reverse(self):
        self.extra_wait_time = 60
        try:
            self.prepare_balance(self.test_coin_to, 100.0, 1800, 1800)
            self.do_test_01_full_swap(self.test_coin_to, self.test_coin_from)
        finally:
            self.extra_wait_time = 0

    def test_02_a_leader_recover_a_lock_tx(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1801, 1800)
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_from, self.test_coin_to)

    def test_02_b_leader_recover_a_lock_tx_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1800)
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_to, self.test_coin_from)

    def test_03_a_follower_recover_a_lock_tx(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1801, 1800)
        self.do_test_03_follower_recover_a_lock_tx(self.test_coin_from, self.test_coin_to)

    def test_03_b_follower_recover_a_lock_tx_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1800)
        self.do_test_03_follower_recover_a_lock_tx(self.test_coin_to, self.test_coin_from, lock_value=12)

    def test_04_a_follower_recover_b_lock_tx(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1801, 1800)
        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_from, self.test_coin_to)

    def test_04_b_follower_recover_b_lock_tx_reverse(self):
        self.prepare_balance(self.test_coin_to, 100.0, 1800, 1800)
        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_to, self.test_coin_from)


class TestBTC_PARTA(TestBTC_PARTB):
    __test__ = True
    test_coin_to = Coins.PART_ANON


if __name__ == '__main__':
    unittest.main()
