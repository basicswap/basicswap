#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import time
import logging

import basicswap.contrib.ed25519_fast as edf
import basicswap.ed25519_fast_util as edu
from coincurve.ed25519 import ed25519_get_pubkey
from coincurve.keys import PrivateKey
from coincurve.dleag import (
    verify_ed25519_point,
    dleag_proof_len,
    dleag_verify,
    dleag_prove)

from .util import (
    format_amount)
from .rpc_xmr import (
    make_xmr_rpc_func,
    make_xmr_wallet_rpc_func)
from .ecc_util import (
    b2i)
from .chainparams import CoinInterface, Coins

XMR_COIN = 10 ** 12


class XMRInterface(CoinInterface):
    @staticmethod
    def coin_type():
        return Coins.XMR

    @staticmethod
    def exp():
        return 12

    @staticmethod
    def nbk():
        return 32

    @staticmethod
    def nbK():  # No. of bytes requires to encode a public key
        return 32

    def __init__(self, coin_settings, network):
        rpc_cb = make_xmr_rpc_func(coin_settings['rpcport'])
        rpc_wallet_cb = make_xmr_wallet_rpc_func(coin_settings['walletrpcport'], coin_settings['walletrpcauth'])

        self.rpc_cb = rpc_cb
        self.rpc_wallet_cb = rpc_wallet_cb
        self._network = network

    def testDaemonRPC(self):
        self.rpc_wallet_cb('get_languages')

    def getDaemonVersion(self):
        return self.rpc_cb('get_version')['version']

    def getBlockchainInfo(self):
        rv = {}
        rv['blocks'] = self.rpc_cb('get_block_count')['count']
        rv['verificationprogress'] = 0  # TODO
        return rv

    def getChainHeight(self):
        return self.rpc_cb('get_block_count')['count']

    def getWalletInfo(self):
        rv = {}
        balance_info = self.rpc_wallet_cb('get_balance')
        rv['balance'] = format_amount(balance_info['unlocked_balance'], XMRInterface.exp())
        rv['unconfirmed_balance'] = format_amount(balance_info['balance'] - balance_info['unlocked_balance'], XMRInterface.exp())
        return rv

    def getNewAddress(self, placeholder):
        logging.debug('TODO - subaddress?')
        return self.rpc_wallet_cb('get_address')['address']

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

    def verifyKey(self, k):
        i = b2i(k)
        return(i < edf.l and i > 8)

    def verifyPubkey(self, pubkey_bytes):
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
        return (ka + kb) % edf.l

    def sumPubkeys(self, Ka, Kb):
        return edf.edwards_add(Ka, Kb)

    def publishBLockTx(self, Kbv, Kbs, output_amount, feerate):

        shared_addr = xmr_util.encode_address(self.encodePubkey(Kbv), self.encodePubkey(Kbs))

        # TODO: How to set feerate?
        params = {'destinations': [{'amount': output_amount, 'address': shared_addr}]}
        rv = self.rpc_wallet_cb('transfer', params)
        logging.info('publishBLockTx %s to address_b58 %s', rv['tx_hash'], shared_addr)

        return rv['tx_hash']

    def findTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):
        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        address_b58 = xmr_util.encode_address(Kbv_enc, self.encodePubkey(Kbs))

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            logging.warning('close_wallet failed %s', str(e))

        params = {
            'restore_height': restore_height,
            'filename': address_b58,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
        }

        try:
            rv = self.rpc_wallet_cb('open_wallet', {'filename': address_b58})
        except Exception as e:
            rv = self.rpc_wallet_cb('generate_from_keys', params)
            logging.info('generate_from_keys %s', dumpj(rv))
            rv = self.rpc_wallet_cb('open_wallet', {'filename': address_b58})

        # Debug
        try:
            current_height = self.rpc_cb('get_block_count')['count']
            logging.info('findTxB XMR current_height %d\nAddress: %s', current_height, address_b58)
        except Exception as e:
            logging.info('rpc_cb failed %s', str(e))
            current_height = None  # If the transfer is available it will be deep enough

        # For a while after opening the wallet rpc cmds return empty data
        for i in range(5):
            params = {'transfer_type': 'available'}
            rv = self.rpc_wallet_cb('incoming_transfers', params)
            if 'transfers' in rv:
                for transfer in rv['transfers']:
                    if transfer['amount'] == cb_swap_value \
                       and (current_height is None or current_height - transfer['block_height'] > cb_block_confirmed):
                        return True
            time.sleep(1 + i)

        return False

    def waitForLockTxB(self, kbv, Kbs, cb_swap_value, cb_block_confirmed, restore_height):

        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        address_b58 = xmr_util.encode_address(Kbv_enc, self.encodePubkey(Kbs))

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            logging.warning('close_wallet failed %s', str(e))

        params = {
            'filename': address_b58,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
            'restore_height': restore_height,
        }
        self.rpc_wallet_cb('generate_from_keys', params)

        self.rpc_wallet_cb('open_wallet', {'filename': address_b58})
        # For a while after opening the wallet rpc cmds return empty data

        num_tries = 40
        for i in range(num_tries + 1):
            try:
                current_height = self.rpc_cb('get_block_count')['count']
                print('current_height', current_height)
            except Exception as e:
                logging.warning('rpc_cb failed %s', str(e))
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

    def spendBLockTx(self, address_to, kbv, kbs, cb_swap_value, b_fee_rate, restore_height):

        Kbv_enc = self.encodePubkey(self.pubkey(kbv))
        Kbs_enc = self.encodePubkey(self.pubkey(kbs))
        address_b58 = xmr_util.encode_address(Kbv_enc, Kbs_enc)

        try:
            self.rpc_wallet_cb('close_wallet')
        except Exception as e:
            logging.warning('close_wallet failed %s', str(e))

        wallet_filename = address_b58 + '_spend'

        params = {
            'filename': wallet_filename,
            'address': address_b58,
            'viewkey': b2h(intToBytes32_le(kbv)),
            'spendkey': b2h(intToBytes32_le(kbs)),
            'restore_height': restore_height,
        }

        try:
            self.rpc_wallet_cb('open_wallet', {'filename': wallet_filename})
        except Exception as e:
            rv = self.rpc_wallet_cb('generate_from_keys', params)
            logging.info('generate_from_keys %s', dumpj(rv))
            self.rpc_wallet_cb('open_wallet', {'filename': wallet_filename})

        # For a while after opening the wallet rpc cmds return empty data
        for i in range(10):
            rv = self.rpc_wallet_cb('get_balance')
            print('get_balance', rv)
            if rv['balance'] >= cb_swap_value:
                break

            time.sleep(1 + i)

        # TODO: need a subfee from output option
        b_fee = b_fee_rate * 10  # Guess

        num_tries = 20
        for i in range(1 + num_tries):
            try:
                params = {'destinations': [{'amount': cb_swap_value - b_fee, 'address': address_to}]}
                rv = self.rpc_wallet_cb('transfer', params)
                print('transfer', rv)
                break
            except Exception as e:
                print('str(e)', str(e))
            if i >= num_tries:
                raise ValueError('transfer failed.')
            b_fee += b_fee_rate
            logging.info('Raising fee to %d', b_fee)

        return rv['tx_hash']
