#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time
import logging

import basicswap.contrib.ed25519_fast as edf
import basicswap.ed25519_fast_util as edu
import basicswap.util_xmr as xmr_util
from coincurve.ed25519 import (
    ed25519_get_pubkey,
    ed25519_scalar_add,
    ed25519_add)
from coincurve.keys import PrivateKey
from coincurve.dleag import (
    verify_ed25519_point,
    dleag_proof_len,
    dleag_verify,
    dleag_prove)

from .util import (
    dumpj,
    make_int,
    format_amount)
from .rpc_xmr import (
    make_xmr_rpc_func,
    make_xmr_rpc2_func,
    make_xmr_wallet_rpc_func)
from .ecc_util import (
    b2i, b2h)
from .chainparams import CoinInterface, Coins

XMR_COIN = 10 ** 12


class XMRInterface(CoinInterface):
    @staticmethod
    def coin_type():
        return Coins.XMR

    @staticmethod
    def COIN():
        return XMR_COIN

    @staticmethod
    def exp():
        return 12

    @staticmethod
    def nbk():
        return 32

    @staticmethod
    def nbK():  # No. of bytes requires to encode a public key
        return 32

    def __init__(self, coin_settings, network, swap_client=None):
        super().__init__()
        self.rpc_cb = make_xmr_rpc_func(coin_settings['rpcport'], host=coin_settings.get('rpchost', '127.0.0.1'))
        self.rpc_cb2 = make_xmr_rpc2_func(coin_settings['rpcport'], host=coin_settings.get('rpchost', '127.0.0.1'))  # non-json endpoint
        self.rpc_wallet_cb = make_xmr_wallet_rpc_func(coin_settings['walletrpcport'], coin_settings['walletrpcauth'])

        self._network = network
        self.blocks_confirmed = coin_settings['blocks_confirmed']
        self._restore_height = coin_settings.get('restore_height', 0)
        self.setFeePriority(coin_settings.get('fee_priority', 0))
        self._sc = swap_client
        self._log = self._sc.log if self._sc and self._sc.log else logging

    def setFeePriority(self, new_priority):
        assert(new_priority >= 0 and new_priority < 4), 'Invalid fee_priority value'
        self._fee_priority = new_priority

    def setWalletFilename(self, wallet_filename):
        self._wallet_filename = wallet_filename

    def initialiseWallet(self, key_view, key_spend, restore_height=None):
        try:
            self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})
            # TODO: Check address
            return  # Wallet exists
        except Exception as e:
            pass

        Kbv = self.getPubkey(key_view)
        Kbs = self.getPubkey(key_spend)
        address_b58 = xmr_util.encode_address(Kbv, Kbs)

        params = {
            'filename': self._wallet_filename,
            'address': address_b58,
            'viewkey': b2h(key_view[::-1]),
            'spendkey': b2h(key_spend[::-1]),
            'restore_height': self._restore_height,
        }
        rv = self.rpc_wallet_cb('generate_from_keys', params)
        self._log.info('generate_from_keys %s', dumpj(rv))
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})

    def ensureWalletExists(self):
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})

    def testDaemonRPC(self):
        self.rpc_wallet_cb('get_languages')

    def getDaemonVersion(self):
        return self.rpc_wallet_cb('get_version')['version']

    def getBlockchainInfo(self):
        rv = {}

        # get_block_count returns "Internal error" if bootstrap-daemon is active
        # rv['blocks'] = self.rpc_cb('get_block_count')['count']
        rv['blocks'] = self.rpc_cb2('get_height')['height']
        rv['verificationprogress'] = 0  # TODO
        return rv

    def getChainHeight(self):
        # get_block_count returns "Internal error" if bootstrap-daemon is active
        # return self.rpc_cb('get_info')['height']
        # return self.rpc_cb('get_block_count')['count']
        return self.rpc_cb2('get_height')['height']

    def getWalletInfo(self):
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})
        rv = {}
        self.rpc_wallet_cb('refresh')
        balance_info = self.rpc_wallet_cb('get_balance')
        rv['balance'] = format_amount(balance_info['unlocked_balance'], XMRInterface.exp())
        rv['unconfirmed_balance'] = format_amount(balance_info['balance'] - balance_info['unlocked_balance'], XMRInterface.exp())
        return rv

    def getMainWalletAddress(self):
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})
        return self.rpc_wallet_cb('get_address')['address']

    def getNewAddress(self, placeholder):
        self._log.warning('TODO - subaddress?')
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})
        return self.rpc_wallet_cb('get_address')['address']

    def get_fee_rate(self, conf_target=2):
        self._log.warning('TODO - estimate fee rate?')
        return 0.0, 'unused'

    def isValidKey(self, key_bytes):
        ki = b2i(key_bytes)
        return ki < edf.l and ki > 8

    def getNewSecretKey(self):
        return edu.get_secret()

    def pubkey(self, key):
        return edf.scalarmult_B(key)

    def encodePubkey(self, pk):
        return edu.encodepoint(pk)

    def decodePubkey(self, pke):
        return edf.decodepoint(pke)

    def getPubkey(self, privkey):
        return ed25519_get_pubkey(privkey)

    def getAddressFromKeys(self, key_view, key_spend):
        pk_view = self.getPubkey(key_view)
        pk_spend = self.getPubkey(key_spend)
        return xmr_util.encode_address(pk_view, pk_spend)

    def verifyKey(self, k):
        i = b2i(k)
        return(i < edf.l and i > 8)

    def verifyPubkey(self, pubkey_bytes):
        # Calls ed25519_decode_check_point() in secp256k1
        # Checks for small order
        return verify_ed25519_point(pubkey_bytes)

    def proveDLEAG(self, key):
        privkey = PrivateKey(key)
        return dleag_prove(privkey)

    def verifyDLEAG(self, dleag_bytes):
        return dleag_verify(dleag_bytes)

    def lengthDLEAG(self):
        return dleag_proof_len()

    def decodeKey(self, k):
        i = b2i(k)
        assert(i < edf.l and i > 8)
        return i

    def sumKeys(self, ka, kb):
        return ed25519_scalar_add(ka, kb)

    def sumPubkeys(self, Ka, Kb):
        return ed25519_add(Ka, Kb)

    def publishBLockTx(self, Kbv, Kbs, output_amount, feerate):
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})

        shared_addr = xmr_util.encode_address(Kbv, Kbs)

        params = {'destinations': [{'amount': output_amount, 'address': shared_addr}]}
        if self._fee_priority > 0:
            params['priority'] = self._fee_priority
        rv = self.rpc_wallet_cb('transfer', params)
        self._log.info('publishBLockTx %s to address_b58 %s', rv['tx_hash'], shared_addr)
        tx_hash = bytes.fromhex(rv['tx_hash'])

        # Debug
        for i in range(10):
            params = {'out': True, 'pending': True, 'failed': True, 'pool': True, }
            rv = self.rpc_wallet_cb('get_transfers', params)
            self._log.info('[rm] get_transfers {}'.format(dumpj(rv)))
            if 'pending' not in rv:
                break
            time.sleep(1)

        return tx_hash

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):
        Kbv = self.getPubkey(kbv)
        address_b58 = xmr_util.encode_address(Kbv, Kbs)

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            self._log.warning('close_wallet failed %s', str(e))

        kbv_le = kbv[::-1]
        params = {
            'restore_height': restore_height,
            'filename': address_b58,
            'address': address_b58,
            'viewkey': b2h(kbv_le),
        }

        try:
            rv = self.rpc_wallet_cb('open_wallet', {'filename': address_b58})
        except Exception as e:
            rv = self.rpc_wallet_cb('generate_from_keys', params)
            self._log.info('generate_from_keys %s', dumpj(rv))
            rv = self.rpc_wallet_cb('open_wallet', {'filename': address_b58})

        rv = self.rpc_wallet_cb('refresh', timeout=600)

        '''
        # Debug
        try:
            current_height = self.rpc_wallet_cb('get_height')['height']
            self._log.info('findTxB XMR current_height %d\nAddress: %s', current_height, address_b58)
        except Exception as e:
            self._log.info('rpc_cb failed %s', str(e))
            current_height = None  # If the transfer is available it will be deep enough
            #   and (current_height is None or current_height - transfer['block_height'] > cb_block_confirmed):
        '''
        params = {'transfer_type': 'available'}
        rv = self.rpc_wallet_cb('incoming_transfers', params)
        if 'transfers' in rv:
            for transfer in rv['transfers']:
                if transfer['amount'] == cb_swap_value:
                    return {'txid': transfer['tx_hash'], 'amount': transfer['amount'], 'height': 0 if 'block_height' not in transfer else transfer['block_height']}
                else:
                    self._log.warning('Incorrect amount detected for coin b lock txn: {}'.format(transfer['tx_hash']))
                    return -1
        return None

    def waitForLockTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):

        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        address_b58 = xmr_util.encode_address(Kbv_enc, self.encodePubkey(Kbs))

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            self._log.warning('close_wallet failed %s', str(e))

        params = {
            'filename': address_b58,
            'address': address_b58,
            'viewkey': b2h(kbv[::-1]),
            'restore_height': restore_height,
        }
        self.rpc_wallet_cb('generate_from_keys', params)

        self.rpc_wallet_cb('open_wallet', {'filename': address_b58})
        # For a while after opening the wallet rpc cmds return empty data

        num_tries = 40
        for i in range(num_tries + 1):
            try:
                current_height = self.rpc_cb2('get_height')['height']
                print('current_height', current_height)
            except Exception as e:
                self._log.warning('rpc_cb failed %s', str(e))
                current_height = None  # If the transfer is available it will be deep enough

            # TODO: Make accepting current_height == None a user selectable option
            #       Or look for all transfers and check height

            params = {'transfer_type': 'available'}
            rv = self.rpc_wallet_cb('incoming_transfers', params)
            print('rv', rv)

            if 'transfers' in rv:
                for transfer in rv['transfers']:
                    if transfer['amount'] == cb_swap_value \
                       and (current_height is None or current_height - transfer['block_height'] > cb_block_confirmed):
                        return True

            # TODO: Is it necessary to check the address?

            '''
            rv = self.rpc_wallet_cb('get_balance')
            print('get_balance', rv)

            if 'per_subaddress' in rv:
                for sub_addr in rv['per_subaddress']:
                    if sub_addr['address'] == address_b58:

            '''

            if i >= num_tries:
                raise ValueError('Balance not confirming on node')
            time.sleep(1)

        return False

    def findTxnByHash(self, txid):
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})
        self.rpc_wallet_cb('refresh')

        try:
            current_height = self.rpc_cb2('get_height')['height']
            self._log.info('findTxnByHash XMR current_height %d\nhash: %s', current_height, txid)
        except Exception as e:
            self._log.info('rpc_cb failed %s', str(e))
            current_height = None  # If the transfer is available it will be deep enough

        params = {'transfer_type': 'available'}
        rv = self.rpc_wallet_cb('incoming_transfers', params)
        if 'transfers' in rv:
            for transfer in rv['transfers']:
                print('[rm] transfer', transfer)
                if transfer['tx_hash'] == txid \
                   and (current_height is None or current_height - transfer['block_height'] > self.blocks_confirmed):
                    return {'txid': transfer['tx_hash'], 'amount': transfer['amount'], 'height': transfer['block_height']}

        return None

    def spendBLockTx(self, address_to, kbv, kbs, cb_swap_value, b_fee_rate, restore_height):

        Kbv = self.getPubkey(kbv)
        Kbs = self.getPubkey(kbs)
        address_b58 = xmr_util.encode_address(Kbv, Kbs)

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            self._log.warning('close_wallet failed %s', str(e))

        wallet_filename = address_b58 + '_spend'

        params = {
            'filename': wallet_filename,
            'address': address_b58,
            'viewkey': b2h(kbv[::-1]),
            'spendkey': b2h(kbs[::-1]),
            'restore_height': restore_height,
        }

        try:
            self.rpc_wallet_cb('open_wallet', {'filename': wallet_filename})
        except Exception as e:
            rv = self.rpc_wallet_cb('generate_from_keys', params)
            self._log.info('generate_from_keys %s', dumpj(rv))
            self.rpc_wallet_cb('open_wallet', {'filename': wallet_filename})

        # For a while after opening the wallet rpc cmds return empty data
        for i in range(10):
            rv = self.rpc_wallet_cb('get_balance')
            print('get_balance', rv)
            if rv['balance'] >= cb_swap_value:
                break

            time.sleep(1 + i)
        if rv['balance'] < cb_swap_value:
            self._log.error('wallet {} balance {}, expected {}'.format(wallet_filename, rv['balance'], cb_swap_value))
            raise ValueError('Invalid balance')
        if rv['unlocked_balance'] < cb_swap_value:
            self._log.error('wallet {} balance {}, expected {}, blocks_to_unlock {}'.format(wallet_filename, rv['unlocked_balance'], cb_swap_value, rv['blocks_to_unlock']))
            raise ValueError('Invalid unlocked_balance')

        params = {'address': address_to}
        if self._fee_priority > 0:
            params['priority'] = self._fee_priority
        rv = self.rpc_wallet_cb('sweep_all', params)
        print('sweep_all', rv)

        return bytes.fromhex(rv['tx_hash_list'][0])

    def withdrawCoin(self, value, addr_to, subfee):
        self.rpc_wallet_cb('open_wallet', {'filename': self._wallet_filename})

        value_sats = make_int(value, self.exp())
        params = {'destinations': [{'amount': value_sats, 'address': addr_to}]}
        if self._fee_priority > 0:
            params['priority'] = self._fee_priority
        rv = self.rpc_wallet_cb('transfer', params)
        return rv['tx_hash']
