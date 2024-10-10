#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
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
from basicswap.util.address import (
    decodeWif,
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
    waitForRPC,
)
from basicswap.interface.contrib.nav_test_framework.mininode import (
    ToHex,
    FromHex,
    CTxIn,
    COutPoint,
    CTransaction,
    CTxInWitness,
)
from basicswap.interface.contrib.nav_test_framework.script import (
    CScript,
    OP_EQUAL,
    OP_CHECKSEQUENCEVERIFY
)

from basicswap.bin.run import startDaemon
from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from tests.basicswap.test_xmr import test_delay_event, callnoderpc
from basicswap.contrib.mnemonic import Mnemonic

from tests.basicswap.test_btc_xmr import TestFunctions

logger = logging.getLogger()

NAV_BINDIR = os.path.expanduser(os.getenv('NAV_BINDIR', os.path.join(cfg.DEFAULT_TEST_BINDIR, 'navcoin')))
NAVD = os.getenv('NAVD', 'navcoind' + cfg.bin_suffix)
NAV_CLI = os.getenv('NAV_CLI', 'navcoin-cli' + cfg.bin_suffix)
NAV_TX = os.getenv('NAV_TX', 'navcoin-tx' + cfg.bin_suffix)

NAV_BASE_PORT = 44832
NAV_BASE_RPC_PORT = 45832
NAV_BASE_ZMQ_PORT = 46832


def prepareDataDir(datadir, node_id, conf_file, dir_prefix, base_p2p_port, base_rpc_port, num_nodes=3):
    node_dir = os.path.join(datadir, dir_prefix + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    with open(cfg_file_path, 'w+') as fp:
        fp.write('devnet=1\n')  # regtest=1 ?
        fp.write('port=' + str(base_p2p_port + node_id) + '\n')
        fp.write('rpcport=' + str(base_rpc_port + node_id) + '\n')

        salt = generate_salt(16)
        fp.write('rpcauth={}:{}${}\n'.format('test' + str(node_id), salt, password_to_hmac(salt, 'test_pass' + str(node_id))))

        fp.write('daemon=0\n')
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

        # test/rpc-tests/segwit.py
        fp.write('prematurewitness=1\n')
        fp.write('walletprematurewitness=1\n')
        fp.write('blockversion=4\n')
        fp.write('promiscuousmempoolflags=517\n')

        fp.write('listenonion=0\n')
        fp.write('dandelion=0\n')
        fp.write('ntpminmeasures=-1\n')
        fp.write('torserver=0\n')
        fp.write('suppressblsctwarning=1\n')

        for i in range(0, num_nodes):
            if node_id == i:
                continue
            fp.write('addnode=127.0.0.1:{}\n'.format(base_p2p_port + i))

    return node_dir


class Test(TestFunctions):
    __test__ = True
    test_coin_from = Coins.NAV
    nav_daemons = []
    nav_addr = None
    start_ltc_nodes = False
    start_xmr_nodes = True

    test_atomic = True
    test_xmr = True

    extra_wait_time = 100

    # Particl node mnemonics are test_xmr.py, node 2 is set randomly
    # Get the expected seeds from BasicSwap::initialiseWallet
    nav_seeds = [
        '516b471da2a67bcfd42a1da7f7ae8f9a1b02c34f6a2d6a943ceec5dca68e7fa1',
        'a8c0911fba070d5cc2784703afeb0f7c3b9b524b8a53466c04e01933d9fede78',
        '7b3b533ac3a27114ae17c8cca0d2cd9f736e7519ae52b8ec8f1f452e8223d082',
    ]

    @classmethod
    def prepareExtraDataDir(cls, i):
        extra_opts = []
        if not cls.restore_instance:
            seed_hex = cls.nav_seeds[i]
            mnemonic = Mnemonic('english').to_mnemonic(bytes.fromhex(seed_hex))
            extra_opts.append(f'-importmnemonic={mnemonic}')
            data_dir = prepareDataDir(cfg.TEST_DATADIRS, i, 'navcoin.conf', 'nav_', base_p2p_port=NAV_BASE_PORT, base_rpc_port=NAV_BASE_RPC_PORT)

        cls.nav_daemons.append(startDaemon(os.path.join(cfg.TEST_DATADIRS, 'nav_' + str(i)), NAV_BINDIR, NAVD, opts=extra_opts))
        logging.info('Started %s %d', NAVD, cls.nav_daemons[-1].handle.pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=NAV_BASE_RPC_PORT), test_delay_event, max_tries=12)

    @classmethod
    def addPIDInfo(cls, sc, i):
        sc.setDaemonPID(Coins.NAV, cls.nav_daemons[i].handle.pid)

    @classmethod
    def sync_blocks(cls, wait_for: int = 20, num_nodes: int = 3) -> None:
        logging.info('Syncing blocks')
        for i in range(wait_for):
            if test_delay_event.is_set():
                raise ValueError('Test stopped.')
            block_hash0 = callnoderpc(0, 'getbestblockhash', base_rpc_port=NAV_BASE_RPC_PORT)
            matches: int = 0
            for i in range(1, num_nodes):
                block_hash = callnoderpc(i, 'getbestblockhash', base_rpc_port=NAV_BASE_RPC_PORT)
                if block_hash == block_hash0:
                    matches += 1
            if matches == num_nodes - 1:
                return
            test_delay_event.wait(1)
        raise ValueError('sync_blocks timed out.')

    @classmethod
    def prepareExtraCoins(cls):
        if cls.restore_instance:
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.nav_addr = cls.swap_clients[0].ci(Coins.NAV).pubkey_to_address(void_block_rewards_pubkey)
        else:
            num_blocks = 400
            cls.nav_addr = callnoderpc(0, 'getnewaddress', ['mining_addr'], base_rpc_port=NAV_BASE_RPC_PORT)
            # cls.nav_addr = addwitnessaddress doesn't work with generatetoaddress

            logging.info('Mining %d NAV blocks to %s', num_blocks, cls.nav_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.nav_addr], base_rpc_port=NAV_BASE_RPC_PORT)

            nav_addr1 = callnoderpc(1, 'getnewaddress', ['initial addr'], base_rpc_port=NAV_BASE_RPC_PORT)
            nav_addr1 = callnoderpc(1, 'addwitnessaddress', [nav_addr1], base_rpc_port=NAV_BASE_RPC_PORT)
            for i in range(5):
                callnoderpc(0, 'sendtoaddress', [nav_addr1, 1000], base_rpc_port=NAV_BASE_RPC_PORT)

            # Set future block rewards to nowhere (a random address), so wallet amounts stay constant
            void_block_rewards_pubkey = cls.getRandomPubkey()
            cls.nav_addr = cls.swap_clients[0].ci(Coins.NAV).pubkey_to_address(void_block_rewards_pubkey)
            num_blocks = 100
            logging.info('Mining %d NAV blocks to %s', num_blocks, cls.nav_addr)
            callnoderpc(0, 'generatetoaddress', [num_blocks, cls.nav_addr], base_rpc_port=NAV_BASE_RPC_PORT)

        cls.sync_blocks()

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising NAV Test')
        super(Test, cls).tearDownClass()

        stopDaemons(cls.nav_daemons)
        cls.nav_daemons.clear()

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings['chainclients']['navcoin'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': NAV_BASE_RPC_PORT + node_id,
            'rpcuser': 'test' + str(node_id),
            'rpcpassword': 'test_pass' + str(node_id),
            'datadir': os.path.join(datadir, 'nav_' + str(node_id)),
            'bindir': NAV_BINDIR,
            'use_csv': True,
            'use_segwit': True,
            'blocks_confirmed': 1,
        }

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()
        chain_height: int = callnoderpc(0, 'getblockcount', [], base_rpc_port=NAV_BASE_RPC_PORT)
        staking_info = callnoderpc(0, 'getstakinginfo', [], base_rpc_port=NAV_BASE_RPC_PORT)
        print('Staking loop: NAV node 0 chain_height {}, staking {}, currentblocktx {}'.format(chain_height, staking_info['staking'], staking_info['currentblocktx']))

    def getXmrBalance(self, js_wallets):
        return float(js_wallets[Coins.XMR.name]['unconfirmed']) + float(js_wallets[Coins.XMR.name]['balance'])

    def callnoderpc(self, method, params=[], wallet=None, node_id=0):
        return callnoderpc(node_id, method, params, wallet, base_rpc_port=NAV_BASE_RPC_PORT)

    def mineBlock(self, num_blocks: int = 1):
        self.callnoderpc('generatetoaddress', [num_blocks, self.nav_addr])

    def stake_block(self, num_blocks: int = 1, node_id: int = 0, wait_for: int = 360):
        print(f'Trying to stake {num_blocks} blocks')
        blockcount = self.callnoderpc('getblockcount', node_id=node_id)

        try:
            # Turn staking on
            self.callnoderpc('staking', [True,], node_id=node_id)

            # Wait for a new block to be mined
            for i in range(wait_for):
                if test_delay_event.is_set():
                    raise ValueError('Test stopped.')
                if self.callnoderpc('getblockcount', node_id=node_id) >= blockcount + num_blocks:
                    return
                test_delay_event.wait(1)
            raise ValueError('stake_block timed out.')
        finally:
            # Turn staking off
            self.callnoderpc('staking', [False,], node_id=node_id)

    def test_001_segwit(self):
        logging.info('---------- Test {} segwit'.format(self.test_coin_from.name))

        swap_clients = self.swap_clients

        ci = swap_clients[0].ci(self.test_coin_from)
        assert (ci.using_segwit() is True)

        addr_plain = self.callnoderpc('getnewaddress', ['segwit test', ])
        addr_witness = self.callnoderpc('addwitnessaddress', [addr_plain, ])
        addr_witness_info = self.callnoderpc('validateaddress', [addr_witness, ])
        txid = self.callnoderpc('sendtoaddress', [addr_witness, 1.0])
        assert len(txid) == 64
        self.mineBlock()

        tx_wallet = self.callnoderpc('gettransaction', [txid, ])
        tx_hex = tx_wallet['hex']
        tx = self.callnoderpc('decoderawtransaction', [tx_hex, ])

        prevout_n = -1
        for txo in tx['vout']:
            if addr_witness in txo['scriptPubKey']['addresses']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        inputs = [{'txid': txid, 'vout': prevout_n}, ]
        outputs = {addr_plain: 0.99}
        tx_funded = self.callnoderpc('createrawtransaction', [inputs, outputs])
        tx_signed = self.callnoderpc('signrawtransaction', [tx_funded, ])['hex']

        # Add scriptsig for txids to match
        decoded_tx = CTransaction()
        decoded_tx = FromHex(decoded_tx, tx_funded)

        tx_funded_with_scriptsig = ToHex(decoded_tx)
        decoded_tx.vin[0].scriptSig = bytes.fromhex('16' + addr_witness_info['hex'])
        decoded_tx.rehash()
        txid_with_scriptsig = decoded_tx.hash

        tx_funded_decoded = self.callnoderpc('decoderawtransaction', [tx_funded, ])
        tx_signed_decoded = self.callnoderpc('decoderawtransaction', [tx_signed, ])
        assert tx_funded_decoded['txid'] != tx_signed_decoded['txid']
        assert txid_with_scriptsig == tx_signed_decoded['txid']
        ci = swap_clients[0].ci(self.test_coin_from)
        assert tx_signed_decoded['version'] == ci.txVersion()

        # Ensure txn can get into the chain
        txid = self.callnoderpc('sendrawtransaction', [tx_signed, ])
        # Block must be staked, witness merkle root mismatch if mined
        self.stake_block(1)

        tx_wallet = self.callnoderpc('gettransaction', [txid, ])
        assert (len(tx_wallet['blockhash']) == 64)

    def test_002_scantxoutset(self):
        logging.info('---------- Test {} scantxoutset'.format(self.test_coin_from.name))
        logging.warning('Skipping test')
        return  # TODO
        addr_plain = self.callnoderpc('getnewaddress', ['scantxoutset test', ])
        addr_witness = self.callnoderpc('addwitnessaddress', [addr_plain, ])
        addr_witness_info = self.callnoderpc('validateaddress', [addr_witness, ])
        txid = self.callnoderpc('sendtoaddress', [addr_witness, 1.0])
        assert len(txid) == 64

        self.mineBlock()

        ro = self.callnoderpc('scantxoutset', ['start', ['addr({})'.format(addr_witness)]])
        assert (len(ro['unspents']) == 1)
        assert (ro['unspents'][0]['txid'] == txid)

    def test_003_signature_hash(self):
        logging.info('---------- Test {} signature_hash'.format(self.test_coin_from.name))
        # Test that signing a transaction manually produces the same result when signed with the wallet

        swap_clients = self.swap_clients

        addr_plain = self.callnoderpc('getnewaddress', ['address test',])
        addr_witness = self.callnoderpc('addwitnessaddress', [addr_plain,])
        validate_plain = self.callnoderpc('validateaddress', [addr_plain])
        validate_witness = self.callnoderpc('validateaddress', [addr_witness])
        assert (validate_plain['ismine'] is True)
        assert (validate_witness['script'] == 'witness_v0_keyhash')
        assert (validate_witness['ismine'] is True)

        ci = swap_clients[0].ci(self.test_coin_from)
        pkh = ci.decodeAddress(addr_plain)
        script_out = ci.getScriptForPubkeyHash(pkh)

        addr_out = ci.encodeSegwitAddressScript(script_out)
        assert (addr_out == addr_witness)

        # Test address from pkh
        test_addr = ci.encodeSegwitAddress(pkh)
        assert (addr_out == test_addr)

        txid = self.callnoderpc('sendtoaddress', [addr_out, 1.0])
        assert len(txid) == 64

        self.mineBlock()

        tx_wallet = self.callnoderpc('gettransaction', [txid, ])
        tx_hex = tx_wallet['hex']
        tx = self.callnoderpc('decoderawtransaction', [tx_hex, ])

        prevout_n = -1
        for txo in tx['vout']:
            if addr_witness in txo['scriptPubKey']['addresses']:
                prevout_n = txo['n']
                break
        assert prevout_n > -1

        inputs = [{'txid': txid, 'vout': prevout_n}, ]
        outputs = {addr_witness: 0.99}
        tx_wallet_funded = self.callnoderpc('createrawtransaction', [inputs, outputs])
        tx_wallet_signed = self.callnoderpc('signrawtransaction', [tx_wallet_funded, ])['hex']
        tx_wallet_decoded = self.callnoderpc('decoderawtransaction', [tx_wallet_signed, ])
        script_in = ci.getInputScriptForPubkeyHash(pkh)

        # TODO: Are there more restrictions on tx.nTime?
        #  - tx.nTime can't be greater than the blocktime
        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()
        tx_spend.nTime = tx_wallet_decoded['time']
        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), prevout_n),
                            scriptSig=script_in,
                            nSequence=tx_wallet_decoded['vin'][0]['sequence']))
        tx_spend.vout.append(ci.txoType()(ci.make_int(0.99), script_out))
        tx_spend_bytes = tx_spend.serialize_with_witness()
        tx_spend_hex = tx_spend_bytes.hex()

        script = ci.getScriptForP2PKH(pkh)
        key_wif = self.callnoderpc('dumpprivkey', [addr_plain, ])
        key = decodeWif(key_wif)

        sig = ci.signTx(key, tx_spend_bytes, 0, script, ci.make_int(1.0))

        stack = [
            sig,
            ci.getPubkey(key),
        ]
        tx_spend_signed = ci.setTxSignature(tx_spend_bytes, stack)
        assert (tx_spend_signed.hex() == tx_wallet_signed)

    def test_004_csv(self):
        logging.info('---------- Test {} csv'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients
        ci = swap_clients[0].ci(self.test_coin_from)

        script = CScript([3, OP_CHECKSEQUENCEVERIFY, ])
        script_dest = ci.getScriptDest(script)

        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = self.callnoderpc('fundrawtransaction', [tx_hex])
        utxo_pos: int = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = self.callnoderpc('signrawtransaction', [tx_funded['hex'], ])['hex']
        self.sync_blocks()
        txid = self.callnoderpc('sendrawtransaction', [tx_signed, ])

        self.callnoderpc('getnewaddress', ['used?',])  # First generated address has a positive balance
        addr_out = self.callnoderpc('getnewaddress', ['csv test',])
        addr_witness = self.callnoderpc('addwitnessaddress', [addr_out,])

        # Test switching address from p2pkh to p2sh-p2wsh
        pkh = ci.decodeAddress(addr_out)
        script_out = ci.getScriptForPubkeyHash(pkh)
        # Convert to p2sh-p2wsh
        addr_out = ci.encodeSegwitAddressScript(script_out)
        assert (addr_out == addr_witness)

        p2wsh = ci.getP2SHP2WSHDest(script)
        assert (p2wsh == script_dest)
        addr_out_test = ci.encodeScriptDest(p2wsh)

        tx_decoded = self.callnoderpc('decoderawtransaction', [tx_signed, ])
        assert (addr_out_test in tx_decoded['vout'][utxo_pos]['scriptPubKey']['addresses'])

        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()

        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), utxo_pos),
                            nSequence=3,
                            scriptSig=ci.getScriptScriptSig(script)))
        tx_spend.vout.append(ci.txoType()(ci.make_int(1.0999), script_out))
        tx_spend.wit.vtxinwit.append(CTxInWitness())
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [script, ]

        tx_spend_hex = tx_spend.serialize_with_witness().hex()

        txid_spent = txid
        try:
            txid = self.callnoderpc('sendrawtransaction', [tx_spend_hex, ])
        except Exception as e:
            assert ('non-BIP68-final' in str(e))
        else:
            assert False, 'Should fail'

        self.stake_block(3)

        tx_spend_decoded = self.callnoderpc('decoderawtransaction', [tx_spend_hex, ])
        txid = self.callnoderpc('sendrawtransaction', [tx_spend_hex, ])
        self.stake_block(1)

        ro = self.callnoderpc('listtransactions')
        sum_addr = 0
        for entry in ro:
            if 'address' in entry and entry['address'] == addr_out:
                if 'category' in entry and entry['category'] == 'receive':
                    sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

        # listreceivedbyaddress doesn't seem to find witness utxos
        '''
        ro = self.callnoderpc('listreceivedbyaddress', [0, ])
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr_out:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0999)
        '''

    def test_005_watchonly(self):
        logging.info('---------- Test {} watchonly'.format(self.test_coin_from.name))

        addr = self.callnoderpc('getnewaddress', ['watchonly test'])
        ro = self.callnoderpc('importaddress', [addr, '', False], node_id=1)

        ro = self.callnoderpc('validateaddress', [addr,], node_id=1)
        assert (ro['iswatchonly'] is True)

        txid = self.callnoderpc('sendtoaddress', [addr, 1.0])
        tx_hex = self.callnoderpc('getrawtransaction', [txid, ])

        self.sync_blocks()

        try:
            self.callnoderpc('sendrawtransaction', [tx_hex, ], node_id=1)
        except Exception as e:
            if 'transaction already in block chain' not in str(e):
                raise (e)
        ro = self.callnoderpc('gettransaction', [txid, True], node_id=1)
        assert (ro['txid'] == txid)
        assert (ro['details'][0]['involvesWatchonly'] is True)
        assert (ro['details'][0]['amount'] == 1.0)

        # No watchonly balance in getwalletinfo
        ro = self.callnoderpc('listreceivedbyaddress', [0, False, True], node_id=1)
        sum_addr = 0
        for entry in ro:
            if entry['address'] == addr:
                sum_addr += entry['amount']
        assert (sum_addr == 1.0)

    def test_007_hdwallet(self):
        logging.info('---------- Test {} hdwallet'.format(self.test_coin_from.name))

        # Run initialiseWallet to set 'main_wallet_seedid_'
        for i, sc in enumerate(self.swap_clients):
            if i > 1:
                # node 2 is set from a random seed
                continue
            sc.initialiseWallet(self.test_coin_from)
            ci = sc.ci(self.test_coin_from)
            if i == 0:
                assert ('19ac5fdb423421b7f9a33cf319715742be5f4caa' == ci.getWalletSeedID())
            assert sc.checkWalletSeed(self.test_coin_from) is True

    def test_012_p2sh_p2wsh(self):
        logging.info('---------- Test {} p2sh-p2wsh'.format(self.test_coin_from.name))

        swap_clients = self.swap_clients
        ci = self.swap_clients[0].ci(self.test_coin_from)

        script = CScript([2, 2, OP_EQUAL, ])

        script_dest = ci.getP2SHP2WSHDest(script)
        tx = CTransaction()
        tx.nVersion = ci.txVersion()
        tx.vout.append(ci.txoType()(ci.make_int(1.1), script_dest))
        tx_hex = ToHex(tx)
        tx_funded = self.callnoderpc('fundrawtransaction', [tx_hex])
        utxo_pos = 0 if tx_funded['changepos'] == 1 else 1
        tx_signed = self.callnoderpc('signrawtransaction', [tx_funded['hex'], ])['hex']
        txid = self.callnoderpc('sendrawtransaction', [tx_signed, ])

        self.stake_block(1)

        addr_out = self.callnoderpc('getnewaddress', ['used?',])
        addr_out = self.callnoderpc('getnewaddress', ['csv test'])
        addr_witness = self.callnoderpc('addwitnessaddress', [addr_out,])
        pkh = ci.decodeAddress(addr_out)
        script_out = ci.getScriptForPubkeyHash(pkh)
        addr_out = ci.encodeSegwitAddressScript(script_out)

        # Double check output type
        prev_tx = self.callnoderpc('decoderawtransaction', [tx_signed, ])
        assert (prev_tx['vout'][utxo_pos]['scriptPubKey']['type'] == 'scripthash')

        tx_spend = CTransaction()
        tx_spend.nVersion = ci.txVersion()
        tx_spend.vin.append(CTxIn(COutPoint(int(txid, 16), utxo_pos),
                            scriptSig=ci.getP2SHP2WSHScriptSig(script)))
        tx_spend.vout.append(ci.txoType()(ci.make_int(1.0999), script_out))
        tx_spend.wit.vtxinwit.append(CTxInWitness())
        tx_spend.wit.vtxinwit[0].scriptWitness.stack = [script, ]
        tx_spend_hex = tx_spend.serialize_with_witness().hex()

        txid = self.callnoderpc('sendrawtransaction', [tx_spend_hex, ])
        self.stake_block(1)
        ro = self.callnoderpc('listtransactions')
        sum_addr = 0
        for entry in ro:
            if 'address' in entry and entry['address'] == addr_out:
                if 'category' in entry and entry['category'] == 'receive':
                    sum_addr += entry['amount']
        assert (sum_addr == 1.0999)

        # Ensure tx was mined
        tx_wallet = self.callnoderpc('gettransaction', [txid, ])
        assert (len(tx_wallet['blockhash']) == 64)

    def test_02_part_coin(self):
        logging.info('---------- Test PART to {}'.format(self.test_coin_from.name))
        if not self.test_atomic:
            logging.warning('Skipping test')
            return
        swap_clients = self.swap_clients

        self.callnoderpc('staking', [True,])

        offer_id = swap_clients[0].postOffer(Coins.PART, self.test_coin_from, 100 * COIN, 0.1 * COIN, 100 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[1], bid_id, sent=True)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=260)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=260)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        self.callnoderpc('staking', [False,])

    def test_03_coin_part(self):
        logging.info('---------- Test {} to PART'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        self.callnoderpc('staking', [True,])

        offer_id = swap_clients[1].postOffer(self.test_coin_from, Coins.PART, 10 * COIN, 9.0 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[1], bid_id)
        swap_clients[1].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[0], bid_id, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=260)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, wait_for=260)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        self.callnoderpc('staking', [False,])

    def test_04_coin_btc(self):
        logging.info('---------- Test {} to BTC'.format(self.test_coin_from.name))

        self.callnoderpc('staking', [True,])

        swap_clients = self.swap_clients

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_in_progress(test_delay_event, swap_clients[1], bid_id, sent=True)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=260)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=260)

        js_0bid = read_json_api(1800, 'bids/{}'.format(bid_id.hex()))

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)

        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        self.callnoderpc('staking', [False,])

    def test_05_refund(self):
        # Seller submits initiate txn, buyer doesn't respond
        logging.info('---------- Test refund, {} to BTC'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients

        self.callnoderpc('staking', [True,])

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 0.1 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 5)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[1].abandonBid(bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=260)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.BID_ABANDONED, sent=True, wait_for=260)

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        self.callnoderpc('staking', [False,])

    def test_05_bad_ptx(self):
        # Invalid PTX sent, swap should stall and ITx and PTx should be reclaimed by senders
        logging.info('---------- Test bad PTx, BTC to {}'.format(self.test_coin_from.name))

        self.callnoderpc('staking', [True,])

        swap_clients = self.swap_clients

        swap_value = make_int(random.uniform(0.001, 10.0), scale=8, r=1)
        logging.info('swap_value {}'.format(format_amount(swap_value, 8)))
        offer_id = swap_clients[0].postOffer(Coins.BTC, self.test_coin_from, swap_value, 0.1 * COIN, swap_value, SwapTypes.SELLER_FIRST,
                                             TxLockTypes.SEQUENCE_LOCK_BLOCKS, 5)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.MAKE_INVALID_PTX)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=320)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=320)

        js_0_bid = read_json_api(1800, 'bids/{}'.format(bid_id.hex()))
        js_1_bid = read_json_api(1801, 'bids/{}'.format(bid_id.hex()))
        assert (js_0_bid['itx_state'] == 'Refunded')
        assert (js_1_bid['ptx_state'] == 'Refunded')

        js_0 = read_json_api(1800)
        js_1 = read_json_api(1801)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_1['num_swapping'] == 0 and js_1['num_watched_outputs'] == 0)

        self.callnoderpc('staking', [False,])

    def test_06_self_bid(self):
        logging.info('---------- Test same client, BTC to {}'.format(self.test_coin_from.name))

        self.callnoderpc('staking', [True,])

        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 10 * COIN, 10 * COIN, 10 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)

        wait_for_bid_tx_state(test_delay_event, swap_clients[0], bid_id, TxStates.TX_REDEEMED, TxStates.TX_REDEEMED, wait_for=260)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=260)

        js_0 = read_json_api(1800)
        assert (js_0['num_swapping'] == 0 and js_0['num_watched_outputs'] == 0)
        assert (js_0['num_recv_bids'] == js_0_before['num_recv_bids'] + 1 and js_0['num_sent_bids'] == js_0_before['num_sent_bids'] + 1)
        self.callnoderpc('staking', [False,])

    def test_07_error(self):
        logging.info('---------- Test error, BTC to {}, set fee above bid value'.format(self.test_coin_from.name))

        self.callnoderpc('staking', [True,])

        swap_clients = self.swap_clients

        js_0_before = read_json_api(1800)

        offer_id = swap_clients[0].postOffer(self.test_coin_from, Coins.BTC, 0.001 * COIN, 1.0 * COIN, 0.001 * COIN, SwapTypes.SELLER_FIRST)

        wait_for_offer(test_delay_event, swap_clients[0], offer_id)
        offer = swap_clients[0].getOffer(offer_id)
        bid_id = swap_clients[0].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id)
        swap_clients[0].acceptBid(bid_id)
        try:
            swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate'] = 10.0
            swap_clients[0].getChainClientSettings(Coins.NAV)['override_feerate'] = 10.0
            wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_ERROR, wait_for=260)
            swap_clients[0].abandonBid(bid_id)
        finally:
            del swap_clients[0].getChainClientSettings(Coins.BTC)['override_feerate']
            del swap_clients[0].getChainClientSettings(Coins.NAV)['override_feerate']
        self.callnoderpc('staking', [False,])

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
            wait_for_balance(test_delay_event, 'http://127.0.0.1:{}/json/wallets/{}'.format(1800 + node_id, tla.lower()), 'balance', amount, iterations=120, delay_time=5)

    def test_10_prefunded_itx(self):
        logging.info('---------- Test prefunded itx offer')

        self.callnoderpc('staking', [True,])

        swap_clients = self.swap_clients
        coin_from = Coins.NAV
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
        swap_value = 9.5
        if float(js_w2[tla_from]['balance']) < swap_value:
            swap_value = js_w2[tla_from]['balance']
        swap_value = ci_from.make_int(swap_value)
        assert (swap_value > ci_from.make_int(9))

        # Missing fundrawtransaction subtractFeeFromOutputs parameter
        try:
            itx = pi.getFundedInitiateTxTemplate(ci_from, swap_value, True)
        except Exception as e:
            assert ('subtractFeeFromOutputs' in str(e))
        else:
            assert False, 'Should fail'
        itx = pi.getFundedInitiateTxTemplate(ci_from, swap_value, False)

        itx_decoded = ci_from.describeTx(itx.hex())
        n = pi.findMockVout(ci_from, itx_decoded)
        value_after = ci_from.make_int(itx_decoded['vout'][n]['value'])
        assert (value_after == swap_value)
        swap_value = value_after
        wait_for_unspent(test_delay_event, ci_from, swap_value)

        extra_options = {'prefunded_itx': itx}
        rate_swap = ci_to.make_int(random.uniform(0.2, 10.0), r=1)
        offer_id = swap_clients[2].postOffer(coin_from, coin_to, swap_value, rate_swap, swap_value, swap_type, extra_options=extra_options)

        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)
        bid_id = swap_clients[1].postBid(offer_id, offer.amount_from)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.BID_RECEIVED)
        swap_clients[2].acceptBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[2], bid_id, BidStates.SWAP_COMPLETED, wait_for=320)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=320)

        # Verify expected inputs were used
        bid, offer = swap_clients[2].getBidAndOffer(bid_id)
        assert (bid.initiate_tx)
        wtx = ci_from.rpc('gettransaction', [bid.initiate_tx.txid.hex(),])
        itx_after = ci_from.describeTx(wtx['hex'])
        assert (len(itx_after['vin']) == len(itx_decoded['vin']))
        for i, txin in enumerate(itx_decoded['vin']):
            assert (txin['txid'] == itx_after['vin'][i]['txid'])
            assert (txin['vout'] == itx_after['vin'][i]['vout'])
        self.callnoderpc('staking', [False,])

    def test_11_xmrswap_to(self):
        logging.info('---------- Test xmr swap protocol to')

        self.callnoderpc('staking', [True,])

        swap_clients = self.swap_clients
        coin_from = Coins.BTC
        coin_to = Coins.NAV
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

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.SWAP_COMPLETED, wait_for=320)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.SWAP_COMPLETED, sent=True, wait_for=320)

        self.callnoderpc('staking', [False,])

    def test_12_xmrswap_to_recover_b_lock_tx(self):
        coin_from = Coins.BTC
        coin_to = Coins.NAV
        logging.info('---------- Test {} to {} follower recovers coin b lock tx'.format(coin_from.name, coin_to.name))

        self.callnoderpc('staking', [True,])

        swap_clients = self.swap_clients
        ci_from = swap_clients[0].ci(coin_from)
        ci_to = swap_clients[1].ci(coin_to)

        amt_swap = ci_from.make_int(random.uniform(0.1, 2.0), r=1)
        rate_swap = ci_to.make_int(random.uniform(0.2, 20.0), r=1)
        offer_id = swap_clients[0].postOffer(
            coin_from, coin_to, amt_swap, rate_swap, amt_swap, SwapTypes.XMR_SWAP,
            lock_type=TxLockTypes.SEQUENCE_LOCK_BLOCKS, lock_value=12)
        wait_for_offer(test_delay_event, swap_clients[1], offer_id)
        offer = swap_clients[1].getOffer(offer_id)

        bid_id = swap_clients[1].postXmrBid(offer_id, offer.amount_from)
        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.BID_RECEIVED)

        bid, xmr_swap = swap_clients[0].getXmrBid(bid_id)
        swap_clients[1].setBidDebugInd(bid_id, DebugTypes.CREATE_INVALID_COIN_B_LOCK)
        swap_clients[0].acceptXmrBid(bid_id)

        wait_for_bid(test_delay_event, swap_clients[0], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, wait_for=380)
        wait_for_bid(test_delay_event, swap_clients[1], bid_id, BidStates.XMR_SWAP_FAILED_REFUNDED, sent=True, wait_for=180)

        self.callnoderpc('staking', [False,])

    # Adaptor sig swap tests
    def test_01_a_full_swap(self):
        self.node_a_id = 2
        self.sync_blocks()
        self.callnoderpc('staking', [True,])
        self.do_test_01_full_swap(self.test_coin_from, Coins.XMR)

        self.callnoderpc('staking', [False,])

    def test_01_b_full_swap_reverse(self):
        self.node_a_id = 0
        self.sync_blocks()
        self.callnoderpc('staking', [True,])

        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_01_full_swap(Coins.XMR, self.test_coin_from)

        self.callnoderpc('staking', [False,])

    def test_02_a_leader_recover_a_lock_tx(self):
        self.node_a_id = 2
        self.sync_blocks()
        self.prepare_balance(Coins.NAV, 1000.0, 1802, 1800)
        self.do_test_02_leader_recover_a_lock_tx(self.test_coin_from, Coins.XMR, lock_value=5)

    def test_02_b_leader_recover_a_lock_tx_reverse(self):
        self.sync_blocks()
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_02_leader_recover_a_lock_tx(Coins.XMR, self.test_coin_from, lock_value=5)

    def test_03_a_follower_recover_a_lock_tx(self):
        self.node_a_id = 2
        self.sync_blocks()
        self.prepare_balance(Coins.NAV, 1000.0, 1802, 1800)
        self.do_test_03_follower_recover_a_lock_tx(self.test_coin_from, Coins.XMR, lock_value=5)

    def test_03_b_follower_recover_a_lock_tx_reverse(self):
        self.sync_blocks()
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_03_follower_recover_a_lock_tx(Coins.XMR, self.test_coin_from, lock_value=5)

    def test_04_a_follower_recover_b_lock_tx(self):
        self.node_a_id = 2
        self.sync_blocks()
        self.prepare_balance(Coins.NAV, 1000.0, 1802, 1800)
        self.do_test_04_follower_recover_b_lock_tx(self.test_coin_from, Coins.XMR, lock_value=5)

    def test_04_b_follower_recover_b_lock_tx_reverse(self):
        self.sync_blocks()
        self.prepare_balance(Coins.XMR, 100.0, 1800, 1801)
        self.do_test_04_follower_recover_b_lock_tx(Coins.XMR, self.test_coin_from, lock_value=5)

    def test_05_self_bid(self):
        self.sync_blocks()
        self.do_test_05_self_bid(self.test_coin_from, Coins.XMR)


if __name__ == '__main__':
    unittest.main()
