#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import random
import logging
import unittest

import basicswap.config as cfg
from basicswap.basicswap import (
    Coins,
    TxStates,
    SwapTypes,
    BidStates,
)
from basicswap.basicswap_util import (
    TxLockTypes,
)
from basicswap.util import (
    COIN,
    make_int,
    format_amount,
)
from basicswap.rpc import (
    callrpc_cli,
    waitForRPC,
)
from tests.basicswap.util import (
    read_json_api,
)
from tests.basicswap.common import (
    stopDaemons,
    wait_for_bid,
    make_rpc_func,
    TEST_HTTP_PORT,
    wait_for_offer,
    wait_for_in_progress,
    wait_for_bid_tx_state,
)
from basicswap.contrib.test_framework.messages import (
    FromHex,
    CTransaction,
)
from bin.basicswap_run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from tests.basicswap.test_xmr import BaseTest, test_delay_event, callnoderpc

logger = logging.getLogger()

FIRO_BASE_PORT = 34832
FIRO_BASE_RPC_PORT = 35832
FIRO_BASE_ZMQ_PORT = 36832


def firoCli(cmd, node_id=0):
    return callrpc_cli(cfg.FIRO_BINDIR, os.path.join(cfg.TEST_DATADIRS, 'firo_' + str(node_id)), 'regtest', cmd, cfg.FIRO_CLI)


def prepareDataDir(datadir, node_id, conf_file, dir_prefix, base_p2p_port, base_rpc_port, num_nodes=3):
    node_dir = os.path.join(datadir, dir_prefix + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        fp.write('regtest=1\n')
        fp.write('port=' + str(base_p2p_port + node_id) + '\n')
        fp.write('rpcport=' + str(base_rpc_port + node_id) + '\n')

        salt = generate_salt(16)
        fp.write('rpcauth={}:{}${}\n'.format('test' + str(node_id), salt, password_to_hmac(salt, 'test_pass' + str(node_id))))

        fp.write('daemon=0\n')
        fp.write('dandelion=0\n')
        fp.write('printtoconsole=0\n')
        fp.write('server=1\n')
        fp.write('discover=0\n')
        fp.write('listenonion=0\n')
        fp.write('bind=127.0.0.1\n')
        fp.write('findpeers=0\n')
        fp.write('debug=1\n')
        fp.write('debugexclude=libevent\n')

        fp.write('fallbackfee=0.01\n')
        fp.write('acceptnonstdtxn=0\n')

        # qa/rpc-tests/segwit.py
        fp.write('prematurewitness=1\n')
        fp.write('walletprematurewitness=1\n')
        fp.write('blockversion=4\n')
        fp.write('promiscuousmempoolflags=517\n')

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            fp.write('addnode=127.0.0.1:{}\n'.format(base_p2p_port + i))

    return node_dir


class Test(BaseTest):
    __test__ = True
    test_coin_from = Coins.FIRO
    firo_daemons = []
    firo_addr = None
    start_ltc_nodes = False
    start_xmr_nodes = False

    test_atomic = True
    test_xmr = False

    # Particl node mnemonics are set in test/basicswap/mnemonics.py
    firo_seeds = [
        'd90b7ed1be614e1c172653aee1f3b6230f43b7fa99cf07fa984a17966ad81de7',
        '6c81d6d74ba33a0db9e41518c2b6789fbe938e98018a4597dac661cfc5f2dfc1',
        'c5de2be44834e7e47ad7dc8e35c6b77c79f17c6bb40d5509a00fc3dff384a865',
    ]

    @classmethod
    def prepareExtraDataDir(cls, i):
        if not cls.restore_instance:
            seed_hex = cls.firo_seeds[i]
            extra_opts = [f'-hdseed={seed_hex}', ]
            data_dir = prepareDataDir(cfg.TEST_DATADIRS, i, 'firo.conf', 'firo_', base_p2p_port=FIRO_BASE_PORT, base_rpc_port=FIRO_BASE_RPC_PORT)
            if os.path.exists(os.path.join(cfg.FIRO_BINDIR, 'firo-wallet')):
                callrpc_cli(cfg.FIRO_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'firo-wallet')

        cls.firo_daemons.append(startDaemon(os.path.join(cfg.TEST_DATADIRS, 'firo_' + str(i)), cfg.FIRO_BINDIR, cfg.FIROD, opts=extra_opts))
        logging.info('Started %s %d', cfg.FIROD, cls.firo_daemons[-1].pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=FIRO_BASE_RPC_PORT))

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.FIRO, cls.firo_daemons[i].pid)

    @classmethod
    def prepareExtraCoins(cls):
        if cls.restore_instance:
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.firo_addr = cls.swap_clients[0].ci(Coins.FIRO).pubkey_to_address(void_block_rewards_pubkey)
        else:
            num_blocks = 400
            cls.firo_addr = callnoderpc(0, 'getnewaddress', ['mining_addr'], base_rpc_port=FIRO_BASE_RPC_PORT)
            # cls.firo_addr = callnoderpc(0, 'addwitnessaddress', [cls.firo_addr], base_rpc_port=FIRO_BASE_RPC_PORT)
            logging.info('Mining %d Firo blocks to %s', num_blocks, cls.firo_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.firo_addr], base_rpc_port=FIRO_BASE_RPC_PORT)

            firo_addr1 = callnoderpc(1, 'getnewaddress', ['initial addr'], base_rpc_port=FIRO_BASE_RPC_PORT)
            # firo_addr1 = callnoderpc(1, 'addwitnessaddress', [firo_addr1], base_rpc_port=FIRO_BASE_RPC_PORT)
            for i in range(5):
                callnoderpc(0, 'sendtoaddress', [firo_addr1, 1000], base_rpc_port=FIRO_BASE_RPC_PORT)

            # Set future block rewards to nowhere (a random address), so wallet amounts stay constant
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.firo_addr = cls.swap_clients[0].ci(Coins.FIRO).pubkey_to_address(void_block_rewards_pubkey)
            num_blocks = 100
            logging.info('Mining %d Firo blocks to %s', num_blocks, cls.firo_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.firo_addr], base_rpc_port=FIRO_BASE_RPC_PORT)

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising FIRO Test')
        super(Test, cls).tearDownClass()

        stopDaemons(cls.firo_daemons)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings['chainclients']['firo'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': FIRO_BASE_RPC_PORT + node_id,
            'rpcuser': 'test' + str(node_id),
            'rpcpassword': 'test_pass' + str(node_id),
            'datadir': os.path.join(datadir, 'firo_' + str(node_id)),
            'bindir': cfg.FIRO_BINDIR,
            'use_csv': True,
            'use_segwit': False,
        }

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()
        callnoderpc(0, 'generatetoaddress', [1, cls.firo_addr], base_rpc_port=FIRO_BASE_RPC_PORT)

    def getBalance(self, js_wallets):
        return float(js_wallets[self.test_coin_from.name]['balance']) + float(js_wallets[self.test_coin_from.name]['unconfirmed'])

    def getXmrBalance(self, js_wallets):
        return float(js_wallets[Coins.XMR.name]['unconfirmed']) + float(js_wallets[Coins.XMR.name]['balance'])

    def callnoderpc(self, method, params=[], wallet=None, node_id=0):
        return callnoderpc(node_id, method, params, wallet, base_rpc_port=FIRO_BASE_RPC_PORT)

    def test_001_firo(self):
        logging.info('---------- Test {} segwit'.format(self.test_coin_from.name))

        '''
        Segwit is not currently enabled:
        https://github.com/firoorg/firo/blob/master/src/validation.cpp#L4425

        Txns spending segwit utxos don't get mined.
        '''

        swap_clients = self.swap_clients

        addr_plain = firoCli('getnewaddress \"segwit test\"')
        addr_witness = firoCli(f'addwitnessaddress {addr_plain}')
        addr_witness_info = firoCli(f'validateaddress {addr_witness}')
        txid = firoCli(f'sendtoaddress {addr_witness} 1.0')
        assert len(txid) == 64

        self.callnoderpc('generatetoaddress', [1, self.firo_addr])
        '''
        TODO: Add back when segwit is active
        ro = self.callnoderpc('scantxoutset', ['start', ['addr({})'.format(addr_witness)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)
        '''

        tx_wallet = firoCli(f'gettransaction {txid}')
        tx_hex = tx_wallet['hex']
        tx = firoCli(f'decoderawtransaction {tx_hex}')

        prevout_n = -1
        for txo in tx['vout']:
            if addr_witness in txo['scriptPubKey']['addresses']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        tx_funded = firoCli(f'createrawtransaction [{{\\"txid\\":\\"{txid}\\",\\"vout\\":{prevout_n}}}] {{\\"{addr_plain}\\":0.99}}')
        tx_signed = firoCli(f'signrawtransaction {tx_funded}')['hex']

        # Add scriptsig for txids to match
        decoded_tx = CTransaction()
        decoded_tx = FromHex(decoded_tx, tx_funded)
        decoded_tx.vin[0].scriptSig = bytes.fromhex('16' + addr_witness_info['hex'])
        txid_with_scriptsig = decoded_tx.rehash()

        tx_funded_decoded = firoCli(f'decoderawtransaction {tx_funded}')
        tx_signed_decoded = firoCli(f'decoderawtransaction {tx_signed}')
        assert tx_funded_decoded['txid'] != tx_signed_decoded['txid']
        assert txid_with_scriptsig == tx_signed_decoded['txid']

    def test_007_hdwallet(self):
        logging.info('---------- Test {} hdwallet'.format(self.test_coin_from.name))

        swap_client = self.swap_clients[0]
        # Run initialiseWallet to set 'main_wallet_seedid_'
        swap_client.initialiseWallet(self.test_coin_from)
        ci = swap_client.ci(self.test_coin_from)
        assert ('490ba1e2c3894d5534c467141ee3cdf77292c362' == ci.getWalletSeedID())
        assert swap_client.checkWalletSeed(self.test_coin_from) is True

    def test_02_part_coin(self):
        logging.info('---------- Test PART to {}'.format(self.test_coin_from.name))
        if not self.test_atomic:
            logging.warning('Skipping test')
            return
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, self.test_coin_from, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[1], bid_id, sent=True)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_03_coin_part(self):
        logging.info('---------- Test {} to PART'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        offer_id = swap_clients[1].postOffer(self.test_coin_from, Coins.PART, 10 * COIN, 9.0 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[1], bid_id)
        swap_clients[1].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[0], bid_id, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_04_coin_btc(self):
        logging.info('---------- Test {} to BTC'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=60)

        js_0bid = read_json_api(1800, 'bids/{}'.format(bid_id.hex()))

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)

        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_05_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info('---------- Test refund, {} to BTC'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 10)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[1].abandonBid(bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.BID_ABANDONED, sent=True, wait_for=60)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

    def test_06_self_bid(self):
        logging.info('---------- Test same client, BTC to {}'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 10 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid_tx_state(test_delay_event, swap_clients[0], bid_id, TxStates.TX_REDEEMED, TxStates.TX_REDEEMED, wait_for=60)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=60)

        js_0 = read_json_api(1800)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_0['num_recv_bids'] == js_0_before['num_recv_bids'] + 1 and js_0['num_sent_bids'] == js_0_before['num_sent_bids'] + 1)

    def test_07_error(self):
        logging.info('---------- Test error, BTC to {}, set fee above bid value'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 0.001 * COIN, 1.0 * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate'] = 10.0
        swap_clients[0].getChainClientSettings(Coins.FIRO)['override_feerate'] = 10.0
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=60)

    def test_08_wallet(self):
        logging.info('---------- Test {} wallet'.format(self.test_coin_from.name))

        logging.info('Test withdrawal')
        addr = self.callnoderpc('getnewaddress', ['Withdrawal test', ])
        wallets = read_json_api(TEST_HTTP_PORT + 0, 'wallets')
        assert (float(wallets[self.test_coin_from.name]['balance']) > 100)

        post_json = {
            'value': 100,
            'address': addr,
            'subfee': False,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, 'wallets/{}/withdraw'.format(self.test_coin_from.name.lower()), post_json)
        assert (len(json_rv['txid']) == 64)

        logging.info('Test createutxo')
        post_json = {
            'value': 10,
        }
        json_rv = read_json_api(TEST_HTTP_PORT + 0, 'wallets/{}/createutxo'.format(self.test_coin_from.name.lower()), post_json)
        assert (len(json_rv['txid']) == 64)

    def test_101_full_swap(self):
        logging.info('---------- Test {} to XMR'.format(self.test_coin_from.name))
        if not self.test_xmr:
            logging.warning('Skipping test')
            return
        swap_clients = self.swap_clients

        js_0 = read_json_api(1800, 'wallets')
        node0_from_before = self.getBalance(js_0)

        js_1 = read_json_api(1801, 'wallets')
        node1_from_before = self.getBalance(js_1)

        js_0_xmr = read_json_api(1800, 'wallets/xmr')
        js_1_xmr = read_json_api(1801, 'wallets/xmr')

        amt_swap = make_int(random.uniform(0.1, 2.0), scale=8, r=1)
        rate_swap = make_int(random.uniform(0.2, 20.0), scale=12, r=1)
        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.XMR, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[0].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True)

        amount_from = float(format_amount(amt_swap, 8))
        js_1 = read_json_api(1801, 'wallets')
        node1_from_after = self.getBalance(js_1)
        assert (node1_from_after > node1_from_before + (amount_from - 0.05))

        js_0 = read_json_api(1800, 'wallets')
        node0_from_after = self.getBalance(js_0)
        # TODO: Discard block rewards
        # assert (node0_from_after < node0_from_before - amount_from)

        js_0_xmr_after = read_json_api(1800, 'wallets/xmr')
        js_1_xmr_after = read_json_api(1801, 'wallets/xmr')

        scale_from = 8
        amount_to = int((amt_swap * rate_swap) // (10 ** scale_from))
        amount_to_float = float(format_amount(amount_to, 12))
        node1_xmr_after = float(js_1_xmr_after['unconfirmed']) + float(js_1_xmr_after['balance'])
        node1_xmr_before = float(js_1_xmr['unconfirmed']) + float(js_1_xmr['balance'])
        assert (node1_xmr_after > node1_xmr_before + (amount_to_float - 0.02))


if __name__ == '__main__':
    unittest.main()
