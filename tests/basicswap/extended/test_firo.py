#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022-2023 tecnovert
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
    DebugTypes,
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
    wait_for_balance,
    wait_for_unspent,
    wait_for_in_progress,
    wait_for_bid_tx_state,
)
from basicswap.interface.contrib.firo_test_framework.mininode import (
    FromHex,
    CTransaction,
    set_regtest,
)
from bin.basicswap_run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from tests.basicswap.test_xmr import BaseTest, test_delay_event, callnoderpc

logger = logging.getLogger()

FIRO_BINDIR = os.path.expanduser(os.getenv('FIRO_BINDIR', os.path.join(cfg.DEFAULT_TEST_BINDIR, 'firo')))
FIROD = os.getenv('FIROD', 'firod' + cfg.bin_suffix)
FIRO_CLI = os.getenv('FIRO_CLI', 'firo-cli' + cfg.bin_suffix)
FIRO_TX = os.getenv('FIRO_TX', 'firo-tx' + cfg.bin_suffix)

FIRO_BASE_PORT = 34832
FIRO_BASE_RPC_PORT = 35832
FIRO_BASE_ZMQ_PORT = 36832


def firoCli(cmd, node_id=0):
    return callrpc_cli(FIRO_BINDIR, os.path.join(cfg.TEST_DATADIRS, 'firo_' + str(node_id)), 'regtest', cmd, FIRO_CLI)


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

        '''
        # qa/rpc-tests/segwit.py
        fp.write('prematurewitness=1\n')
        fp.write('walletprematurewitness=1\n')
        fp.write('blockversion=4\n')
        fp.write('promiscuousmempoolflags=517\n')
        '''

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

    # Particl node mnemonics are test_xmr.py, node 2 is set randomly
    firo_seeds = [
        'd90b7ed1be614e1c172653aee1f3b6230f43b7fa99cf07fa984a17966ad81de7',
        '6c81d6d74ba33a0db9e41518c2b6789fbe938e98018a4597dac661cfc5f2dfc1',
        'c5de2be44834e7e47ad7dc8e35c6b77c79f17c6bb40d5509a00fc3dff384a865',
    ]

    @classmethod
    def prepareExtraDataDir(cls, i):
        extra_opts = []
        if not cls.restore_instance:
            seed_hex = cls.firo_seeds[i]
            extra_opts.append(f'-hdseed={seed_hex}')
            data_dir = prepareDataDir(cfg.TEST_DATADIRS, i, 'firo.conf', 'firo_', base_p2p_port=FIRO_BASE_PORT, base_rpc_port=FIRO_BASE_RPC_PORT)
            if os.path.exists(os.path.join(FIRO_BINDIR, 'firo-wallet')):
                callrpc_cli(FIRO_BINDIR, data_dir, 'regtest', '-wallet=wallet.dat create', 'firo-wallet')

        cls.firo_daemons.append(startDaemon(os.path.join(cfg.TEST_DATADIRS, 'firo_' + str(i)), FIRO_BINDIR, FIROD, opts=extra_opts))
        logging.info('Started %s %d', FIROD, cls.firo_daemons[-1].pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=FIRO_BASE_RPC_PORT))

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.FIRO, cls.firo_daemons[i].pid)

    @classmethod
    def prepareExtraCoins(cls):

        # Raise MTP_SWITCH_TIME and PP_SWITCH_TIME in mininode.py
        set_regtest()

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
            chain_height = callnoderpc(0, 'getblockcount', base_rpc_port=FIRO_BASE_RPC_PORT)
            num_blocks = 1352 - chain_height  # Activate CTLV (bip65)
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
            'bindir': FIRO_BINDIR,
            'use_csv': False,
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

    def mineBlock(self, num_blocks: int = 1):
        self.callnoderpc('generatetoaddress', [num_blocks, self.firo_addr])

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
        decoded_tx.rehash()
        txid_with_scriptsig = decoded_tx.hash

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

    def test_008_gettxout(self):
        logging.info('---------- Test {} gettxout'.format(self.test_coin_from.name))

        swap_client = self.swap_clients[0]

        addr_plain = self.callnoderpc('getnewaddress', ['gettxout test',])

        addr_plain1 = self.callnoderpc('getnewaddress', ['gettxout test 1',])
        addr_witness = self.callnoderpc('addwitnessaddress', [addr_plain1,])

        txid = self.callnoderpc('sendtoaddress', [addr_witness, 1.0])
        assert len(txid) == 64

        self.callnoderpc('generatetoaddress', [1, self.firo_addr])

        unspents = self.callnoderpc('listunspent')

        for u in unspents:
            if u['spendable'] is not True:
                continue
            if u['address'] == addr_witness:
                print(u)

        unspents = self.callnoderpc('listunspent', [0, 999999999, [addr_witness,]])
        assert (len(unspents) == 1)

        utxo = unspents[0]
        txout = self.callnoderpc('gettxout', [utxo['txid'], utxo['vout']])
        assert (addr_witness in txout['scriptPubKey']['addresses'])
        # Spend
        addr_plain2 = self.callnoderpc('getnewaddress', ['gettxout test 2',])
        addr_witness2 = self.callnoderpc('addwitnessaddress', [addr_plain2,])
        tx_funded = self.callnoderpc('createrawtransaction', [[{'txid': utxo['txid'], 'vout': utxo['vout']}], {addr_witness2: 0.99}])
        tx_signed = self.callnoderpc('signrawtransaction', [tx_funded,])['hex']
        self.callnoderpc('sendrawtransaction', [tx_signed,])

        # utxo should be unavailable when spent in the mempool
        txout = self.callnoderpc('gettxout', [utxo['txid'], utxo['vout']])
        assert (txout is None)

        self.callnoderpc('generatetoaddress', [1, self.firo_addr])

        ci = swap_client.ci(Coins.FIRO)
        require_amount: int = ci.make_int(1)
        funds_proof = ci.getProofOfFunds(require_amount, 'test'.encode('utf-8'))

        amount_proved = ci.verifyProofOfFunds(funds_proof[0], funds_proof[1], funds_proof[2], 'test'.encode('utf-8'))
        assert (amount_proved >= require_amount)

    def test_02_part_coin(self):
        logging.info('---------- Test PART to {}'.format(self.test_coin_from.name))
        if not self.test_atomic:
            logging.warning('Skipping test')
            return
        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(Coins.PART, self.test_coin_from, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST, TxLockTypes.ABS_LOCK_TIME)

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

        offer_id = swap_clients[1].postOffer(self.test_coin_from, Coins.PART, 10 * COIN, 9.0 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST, TxLockTypes.ABS_LOCK_TIME)

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

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST, TxLockTypes.ABS_LOCK_TIME)

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
                                             TxLockTypes.ABS_LOCK_BLOCKS, 10)

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

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 10 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST, TxLockTypes.ABS_LOCK_TIME)

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

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 0.001 * COIN, 1.0 * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST, TxLockTypes.ABS_LOCK_TIME)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        try:
            swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate'] = 10.0
            swap_clients[0].getChainClientSettings(Coins.FIRO)['override_feerate'] = 10.0
            wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=60)
            swap_clients[0].abandonBid(bid_id)
        finally:
            del swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate']
            del swap_clients[0].getChainClientSettings(Coins.FIRO)['override_feerate']

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

    def ensure_balance(self, coin_type, node_id, amount):
        tla = coin_type.name
        js_w = read_json_api(1800 + node_id, 'wallets')
        if float(js_w[tla]['balance']) < amount:
            post_json = {
                'value': amount,
                'address': js_w[tla]['deposit_address'],
                'subfee': False,
            }
            json_rv = read_json_api(1800, 'wallets/{}/withdraw'.format(tla.lower()), post_json)
            assert (len(json_rv['txid']) == 64)
            wait_for_balance(test_delay_event, 'http://127.0.0.1:{}/json/wallets/{}'.format(1800 + node_id, tla.lower()), 'balance', amount)

    def test_10_prefunded_itx(self):
        logging.info('---------- Test prefunded itx offer')

        swap_clients = self.swap_clients
        coin_from = Coins.FIRO
        coin_to = Coins.BTC
        swap_type = SwapTypes.SELLER_FIRST
        ci_from = swap_clients[2].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)
        tla_from = coin_from.name

        # Prepare balance
        self.ensure_balance(coin_from, 2, 10.0)
        self.ensure_balance(coin_to, 1, 100.0)

        js_w2 = read_json_api(1802, 'wallets')
        post_json = {
            'value': 10.0,
            'address': read_json_api(1802, 'wallets/{}/nextdepositaddr'.format(tla_from.lower())),
            'subfee': True,
        }
        json_rv = read_json_api(1802, 'wallets/{}/withdraw'.format(tla_from.lower()), post_json)
        wait_for_balance(test_delay_event, 'http://127.0.0.1:1802/json/wallets/{}'.format(tla_from.lower()), 'balance', 9.0)
        assert (len(json_rv['txid']) == 64)

        # Create prefunded ITX
        pi = swap_clients[2].pi(SwapTypes.XMR_SWAP)
        js_w2 = read_json_api(1802, 'wallets')
        swap_value = 10.0
        if float(js_w2[tla_from]['balance']) < swap_value:
            swap_value = js_w2[tla_from]['balance']
        swap_value = ci_from.make_int(swap_value)
        assert (swap_value > ci_from.make_int(9))

        itx = pi.getFundedInitiateTxTemplate(ci_from, swap_value, True)
        itx_decoded = ci_from.describeTx(itx.hex())
        n = pi.findMockVout(ci_from, itx_decoded)
        value_after_subfee = ci_from.make_int(itx_decoded['vout'][n]['value'])
        assert (value_after_subfee < swap_value)
        swap_value = value_after_subfee
        wait_for_unspent(test_delay_event, ci_from, swap_value)

        extra_options = {'prefunded_itx': itx}
        rate_swap = ci_to.make_int(random.uniform(0.2, 10.0), r=1)
        offer_id = swap_clients[2].postOffer(coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type, TxLockTypes.ABS_LOCK_TIME, extra_options=extra_options)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.BID_RECEIVED)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

        # Verify expected inputs were used
        bid, offer = swap_clients[2].getBidAndOffer(bid_id)
        assert (bid.initiate_tx)
        wtx = ci_from.rpc_callback('gettransaction', [bid.initiate_tx.txid.hex(),])
        itx_after = ci_from.describeTx(wtx['hex'])
        assert (len(itx_after['vin']) == len(itx_decoded['vin']))
        for i, txin in enumerate(itx_decoded['vin']):
            assert (txin['txid'] == itx_after['vin'][i]['txid'])
            assert (txin['vout'] == itx_after['vin'][i]['vout'])

    def test_11_xmrswap_to(self):
        logging.info('---------- Test xmr swap protocol to')

        swap_clients = self.swap_clients
        coin_from = Coins.BTC
        coin_to = Coins.FIRO
        swap_type = SwapTypes.XMR_SWAP
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

    def test_12_xmrswap_to_recover_b_lock_tx(self):
        coin_from = Coins.BTC
        coin_to = Coins.FIRO
        logging.info('---------- Test {} to {} follower recovers coin b lock tx'.format(coin_from.name, coin_to.name))

        swap_clients = self.swap_clients
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=32)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=180)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True)

    def test_13_adsswap_reverse(self):
        logging.info('---------- Test ads swap protocol reverse')

        swap_clients = self.swap_clients
        coin_from = Coins.FIRO
        coin_to = Coins.BTC
        swap_type = SwapTypes.XMR_SWAP
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        swap_value = ci_from.make_int(random.uniform(0.2, 20.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=120)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=120)

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
