#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import os
import subprocess
import select
import unittest

import basicswap.config as cfg

from basicswap.basicswap import (
    Coins,
)
from basicswap.util.crypto import (
    hash160
)
from basicswap.interface.dcr.rpc import (
    callrpc,
)
from basicswap.interface.dcr.messages import (
    SigHashType,
    TxSerializeType,
)
from tests.basicswap.common import (
    stopDaemons,
    waitForRPC,
)
from tests.basicswap.util import (
    REQUIRED_SETTINGS,
)

from tests.basicswap.test_xmr import BaseTest, test_delay_event
from basicswap.interface.dcr import DCRInterface
from basicswap.interface.dcr.messages import CTransaction, CTxIn, COutPoint
from basicswap.interface.dcr.script import OP_CHECKSEQUENCEVERIFY, push_script_data
from bin.basicswap_run import startDaemon

logger = logging.getLogger()

DCR_BINDIR = os.path.expanduser(os.getenv('DCR_BINDIR', os.path.join(cfg.DEFAULT_TEST_BINDIR, 'decred')))
DCRD = os.getenv('DCRD', 'dcrd' + cfg.bin_suffix)
DCR_WALLET = os.getenv('DCR_WALLET', 'dcrwallet' + cfg.bin_suffix)
DCR_CLI = os.getenv('DCR_CLI', 'dcrctl' + cfg.bin_suffix)

DCR_BASE_PORT = 44932
DCR_BASE_RPC_PORT = 45932
DCR_BASE_WALLET_RPC_PORT = 45952


def make_rpc_func(node_id, base_rpc_port):
    node_id = node_id
    auth = 'test{0}:test_pass{0}'.format(node_id)

    def rpc_func(method, params=None):
        nonlocal node_id, auth
        return callrpc(base_rpc_port + node_id, auth, method, params)
    return rpc_func


def prepareDCDDataDir(datadir, node_id, conf_file, dir_prefix, num_nodes=3):
    node_dir = os.path.join(datadir, dir_prefix + str(node_id))
    if not os.path.exists(node_dir):
        os.makedirs(node_dir)
    cfg_file_path = os.path.join(node_dir, conf_file)
    if os.path.exists(cfg_file_path):
        return
    config = [
        'simnet=1\n',
        'debuglevel=debug\n',
        f'listen=127.0.0.1:{DCR_BASE_PORT + node_id}\n',
        f'rpclisten=127.0.0.1:{DCR_BASE_RPC_PORT + node_id}\n',
        f'rpcuser=test{node_id}\n',
        f'rpcpass=test_pass{node_id}\n',
        'notls=1\n',
        'miningaddr=SsYbXyjkKAEXXcGdFgr4u4bo4L8RkCxwQpH\n',]

    for i in range(0, num_nodes):
        if node_id == i:
            continue
        config.append('addpeer=127.0.0.1:{}\n'.format(DCR_BASE_PORT + i))

    with open(cfg_file_path, 'w+') as fp:
        for line in config:
            fp.write(line)

    config = [
        'simnet=1\n',
        'debuglevel=debug\n',
        f'rpclisten=127.0.0.1:{DCR_BASE_WALLET_RPC_PORT + node_id}\n',
        f'rpcconnect=127.0.0.1:{DCR_BASE_RPC_PORT + node_id}\n',
        f'username=test{node_id}\n',
        f'password=test_pass{node_id}\n',
        'noservertls=1\n',
        'noclienttls=1\n',
        'enablevoting=1\n',]

    wallet_cfg_file_path = os.path.join(node_dir, 'dcrwallet.conf')
    with open(wallet_cfg_file_path, 'w+') as fp:
        for line in config:
            fp.write(line)


class Test(BaseTest):
    __test__ = True
    test_coin_from = Coins.DCR
    dcr_daemons = []
    start_ltc_nodes = False
    start_xmr_nodes = False
    dcr_mining_addr = 'SsYbXyjkKAEXXcGdFgr4u4bo4L8RkCxwQpH'

    hex_seeds = [
        'e8574b2a94404ee62d8acc0258cab4c0defcfab8a5dfc2f4954c1f9d7e09d72a',
        '10689fc6378e5f318b663560012673441dcdd8d796134e6021a4248cc6342cc6',
        'efc96ffe4fee469407826841d9700ef0a0735b0aa5ec5e7a4aa9bc1afd9a9a30',  # Won't match main seed, as it's set randomly
    ]

    @classmethod
    def prepareExtraCoins(cls):
        if not cls.restore_instance:
            ci0 = cls.swap_clients[0].ci(cls.test_coin_from)
            assert (ci0.rpc_wallet('getnewaddress') == cls.dcr_mining_addr)
            cls.dcr_ticket_account = ci0.rpc_wallet('getaccount', [cls.dcr_mining_addr, ])
            ci0.rpc('generate', [110,])
        else:
            cls.dcr_ticket_account = ci0.rpc_wallet('getaccount', [cls.dcr_mining_addr, ])

    @classmethod
    def tearDownClass(cls):
        logging.info('Finalising Decred Test')
        super(Test, cls).tearDownClass()

        stopDaemons(cls.dcr_daemons)
        cls.dcr_daemons.clear()

    @classmethod
    def coins_loop(cls):
        super(Test, cls).coins_loop()
        ci0 = cls.swap_clients[0].ci(cls.test_coin_from)

        num_passed: int = 0
        for i in range(5):
            try:
                ci0.rpc_wallet('purchaseticket', [cls.dcr_ticket_account, 0.1, 0])
                num_passed += 1
            except Exception as e:
                logging.warning('coins_loop purchaseticket {}'.format(e))

        try:
            if num_passed >= 5:
                ci0.rpc('generate', [1,])
        except Exception as e:
            logging.warning('coins_loop generate {}'.format(e))

    @classmethod
    def prepareExtraDataDir(cls, i):
        extra_opts = []
        if not cls.restore_instance:
            data_dir = prepareDCDDataDir(cfg.TEST_DATADIRS, i, 'dcrd.conf', 'dcr_')

        appdata = os.path.join(cfg.TEST_DATADIRS, 'dcr_' + str(i))
        datadir = os.path.join(appdata, 'data')
        extra_opts.append(f'--appdata="{appdata}"')
        cls.dcr_daemons.append(startDaemon(appdata, DCR_BINDIR, DCRD, opts=extra_opts, extra_config={'add_datadir': False, 'stdout_to_file': True, 'stdout_filename': 'dcrd_stdout.log'}))
        logging.info('Started %s %d', DCRD, cls.dcr_daemons[-1].handle.pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=DCR_BASE_RPC_PORT), test_delay_event, rpc_command='getnetworkinfo', max_tries=12)

        logging.info('Creating wallet')
        extra_opts.append('--pass=test_pass')
        args = [os.path.join(DCR_BINDIR, DCR_WALLET), '--create'] + extra_opts
        (pipe_r, pipe_w) = os.pipe()  # subprocess.PIPE is buffered, blocks when read
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=pipe_w, stderr=pipe_w)

        try:
            while p.poll() is None:
                while len(select.select([pipe_r], [], [], 0)[0]) == 1:
                    buf = os.read(pipe_r, 1024).decode('utf-8')
                    logging.debug(f'dcrwallet {buf}')
                    response = None
                    if 'Use the existing configured private passphrase' in buf:
                        response = b'y\n'
                    elif 'Do you want to add an additional layer of encryption' in buf:
                        response = b'n\n'
                    elif 'Do you have an existing wallet seed' in buf:
                        response = b'y\n'
                    elif 'Enter existing wallet seed' in buf:
                        response = (cls.hex_seeds[i] + '\n').encode('utf-8')
                    elif 'Seed input successful' in buf:
                        pass
                    else:
                        raise ValueError(f'Unexpected output: {buf}')
                    if response is not None:
                        p.stdin.write(response)
                        p.stdin.flush()
                test_delay_event.wait(0.1)
        except Exception as e:
            logging.error(f'{DCR_WALLET} --create failed: {e}')
        finally:
            if p.poll() is None:
                p.terminate()
            os.close(pipe_r)
            os.close(pipe_w)
            p.stdin.close()

        test_delay_event.wait(1.0)

        cls.dcr_daemons.append(startDaemon(appdata, DCR_BINDIR, DCR_WALLET, opts=extra_opts, extra_config={'add_datadir': False, 'stdout_to_file': True, 'stdout_filename': 'dcrwallet_stdout.log'}))
        logging.info('Started %s %d', DCR_WALLET, cls.dcr_daemons[-1].handle.pid)

        waitForRPC(make_rpc_func(i, base_rpc_port=DCR_BASE_WALLET_RPC_PORT), test_delay_event, rpc_command='getinfo', max_tries=12)

    @classmethod
    def addCoinSettings(cls, settings, datadir, node_id):
        settings['chainclients']['decred'] = {
            'connection_type': 'rpc',
            'manage_daemon': False,
            'rpcport': DCR_BASE_RPC_PORT + node_id,
            'walletrpcport': DCR_BASE_WALLET_RPC_PORT + node_id,
            'rpcuser': 'test' + str(node_id),
            'rpcpassword': 'test_pass' + str(node_id),
            'datadir': os.path.join(datadir, 'dcr_' + str(node_id)),
            'bindir': DCR_BINDIR,
            'use_csv': True,
            'use_segwit': True,
            'blocks_confirmed': 1,
        }

    def test_0001_decred_address(self):
        logging.info('---------- Test {}'.format(self.test_coin_from.name))

        coin_settings = {'rpcport': 0, 'rpcauth': 'none'}
        coin_settings.update(REQUIRED_SETTINGS)

        ci = DCRInterface(coin_settings, 'mainnet')

        k = ci.getNewSecretKey()
        K = ci.getPubkey(k)

        pkh = ci.pkh(K)
        address = ci.pkh_to_address(pkh)
        assert (address.startswith('Ds'))

        data = ci.decode_address(address)
        assert (data[2:] == pkh)

        for i, sc in enumerate(self.swap_clients):
            loop_ci = sc.ci(self.test_coin_from)
            root_key = sc.getWalletKey(Coins.DCR, 1)
            masterpubkey = loop_ci.rpc_wallet('getmasterpubkey')
            masterpubkey_data = loop_ci.decode_address(masterpubkey)[4:]

            seed_hash = loop_ci.getSeedHash(root_key)
            if i == 0:
                assert (masterpubkey == 'spubVV1z2AFYjVZvzM45FSaWMPRqyUoUwyW78wfANdjdNG6JGCXrr8AbRvUgYb3Lm1iun9CgHew1KswdePryNLKEnBSQ82AjNpYdQgzXPUme9c6')
            if i < 2:
                assert (seed_hash == hash160(masterpubkey_data))

    def test_001_segwit(self):
        logging.info('---------- Test {} segwit'.format(self.test_coin_from.name))

        swap_clients = self.swap_clients
        ci0 = swap_clients[0].ci(self.test_coin_from)
        assert (ci0.using_segwit() is True)

        addr_out = ci0.rpc_wallet('getnewaddress')
        addr_info = ci0.rpc_wallet('validateaddress', [addr_out,])
        assert (addr_info['isvalid'] is True)
        assert (addr_info['ismine'] is True)

        rtx = ci0.rpc_wallet('createrawtransaction', [[], {addr_out: 2.0}])

        account_from = ci0.rpc_wallet('getaccount', [self.dcr_mining_addr, ])
        frtx = ci0.rpc_wallet('fundrawtransaction', [rtx, account_from])

        f_decoded = ci0.rpc_wallet('decoderawtransaction', [frtx['hex'], ])
        assert (f_decoded['version'] == 1)

        sfrtx = ci0.rpc_wallet('signrawtransaction', [frtx['hex']])
        s_decoded = ci0.rpc_wallet('decoderawtransaction', [sfrtx['hex'], ])
        sent_txid = ci0.rpc_wallet('sendrawtransaction', [sfrtx['hex'], ])

        assert (f_decoded['txid'] == sent_txid)
        assert (f_decoded['txid'] == s_decoded['txid'])
        assert (f_decoded['txid'] == s_decoded['txid'])

        ctx = ci0.loadTx(bytes.fromhex(sfrtx['hex']))
        ser_out = ctx.serialize()
        assert (ser_out.hex() == sfrtx['hex'])
        assert (f_decoded['txid'] == ctx.TxHash().hex())

    def test_003_signature_hash(self):
        logging.info('---------- Test {} signature_hash'.format(self.test_coin_from.name))
        # Test that signing a transaction manually produces the same result when signed with the wallet

        swap_clients = self.swap_clients
        ci0 = swap_clients[0].ci(self.test_coin_from)

        utxos = ci0.rpc_wallet('listunspent')
        addr_out = ci0.rpc_wallet('getnewaddress')
        rtx = ci0.rpc_wallet('createrawtransaction', [[], {addr_out: 2.0}])

        account_from = ci0.rpc_wallet('getaccount', [self.dcr_mining_addr, ])
        frtx = ci0.rpc_wallet('fundrawtransaction', [rtx, account_from])
        sfrtx = ci0.rpc_wallet('signrawtransaction', [frtx['hex']])

        ctx = ci0.loadTx(bytes.fromhex(frtx['hex']))

        prevout = None
        prevout_txid = ctx.vin[0].prevout.get_hash().hex()
        prevout_n = ctx.vin[0].prevout.n
        for utxo in utxos:
            if prevout_txid == utxo['txid'] and prevout_n == utxo['vout']:
                prevout = utxo
                break
        assert (prevout is not None)

        tx_bytes_no_witness: bytes = ctx.serialize(TxSerializeType.NoWitness)
        sig0 = ci0.rpc_wallet('createsignature', [prevout['address'], 0, SigHashType.SigHashAll, prevout['scriptPubKey'], tx_bytes_no_witness.hex()])

        priv_key_wif = ci0.rpc_wallet('dumpprivkey', [prevout['address'], ])
        sig_type, key_bytes = ci0.decodeKey(priv_key_wif)

        addr_info = ci0.rpc_wallet('validateaddress', [prevout['address'],])
        pk_hex: str = addr_info['pubkey']

        sig0_py = ci0.signTx(key_bytes, tx_bytes_no_witness, 0, bytes.fromhex(prevout['scriptPubKey']), ci0.make_int(prevout['amount']))
        tx_bytes_signed = ci0.setTxSignature(tx_bytes_no_witness, [sig0_py, bytes.fromhex(pk_hex)])

        # Set prevout value
        ctx = ci0.loadTx(tx_bytes_signed)
        assert (ctx.vout[0].version == 0)
        ctx.vin[0].value_in = ci0.make_int(prevout['amount'])
        tx_bytes_signed = ctx.serialize()
        assert (tx_bytes_signed.hex() == sfrtx['hex'])

        sent_txid = ci0.rpc_wallet('sendrawtransaction', [tx_bytes_signed.hex(), ])
        assert (len(sent_txid) == 64)

    def test_004_csv(self):
        logging.info('---------- Test {} csv'.format(self.test_coin_from.name))
        swap_clients = self.swap_clients
        ci0 = swap_clients[0].ci(self.test_coin_from)

        script = bytearray()
        push_script_data(script, bytes((3,)))
        script += OP_CHECKSEQUENCEVERIFY.to_bytes(1)

        script_dest = ci0.getScriptDest(script)

        prevout_amount: int = ci0.make_int(1.1)
        tx = CTransaction()
        tx.version = ci0.txVersion()
        tx.vout.append(ci0.txoType()(prevout_amount, script_dest))
        tx_hex = tx.serialize().hex()
        tx_decoded = ci0.rpc_wallet('decoderawtransaction', [tx_hex, ])

        utxo_pos = None
        script_address = None
        for i, txo in enumerate(tx_decoded['vout']):
            script_address = tx_decoded['vout'][0]['scriptPubKey']['addresses'][0]
            addr_info = ci0.rpc_wallet('validateaddress', [script_address,])
            if addr_info['isscript'] is True:
                utxo_pos = i
                break
        assert (utxo_pos is not None)

        accounts = ci0.rpc_wallet('listaccounts')
        for account_from in accounts:
            try:
                frtx = ci0.rpc_wallet('fundrawtransaction', [tx_hex, account_from])
                break
            except Exception as e:
                logging.warning('fundrawtransaction failed {}'.format(e))
        sfrtx = ci0.rpc_wallet('signrawtransaction', [frtx['hex']])
        sent_txid = ci0.rpc_wallet('sendrawtransaction', [sfrtx['hex'], ])

        tx_spend = CTransaction()
        tx_spend.version = ci0.txVersion()

        tx_spend.vin.append(CTxIn(COutPoint(int(sent_txid, 16), utxo_pos), sequence=3))
        tx_spend.vin[0].value_in = prevout_amount
        signature_script = bytearray()
        push_script_data(signature_script, script)
        tx_spend.vin[0].signature_script = signature_script

        addr_out = ci0.rpc_wallet('getnewaddress')
        pkh = ci0.decode_address(addr_out)[2:]

        tx_spend.vout.append(ci0.txoType()())
        tx_spend.vout[0].value = ci0.make_int(1.09)
        tx_spend.vout[0].script_pubkey = ci0.getPubkeyHashDest(pkh)

        tx_spend_hex = tx_spend.serialize().hex()

        try:
            sent_spend_txid = ci0.rpc_wallet('sendrawtransaction', [tx_spend_hex, ])
        except Exception as e:
            assert ('transaction sequence locks on inputs not met' in str(e))
        else:
            assert False, 'Should fail'

        sent_spend_txid = None
        for i in range(20):
            try:
                sent_spend_txid = ci0.rpc_wallet('sendrawtransaction', [tx_spend_hex, ])
                break
            except Exception as e:
                logging.info('sendrawtransaction failed {}, height {}'.format(e, ci0.getChainHeight()))
            test_delay_event.wait(1)

        assert (sent_spend_txid is not None)


if __name__ == '__main__':
    unittest.main()
