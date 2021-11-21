# -*- coding: utf-8 -*-

# Copyright (c) 2019-2021 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import urllib.request


class Explorer():
    def __init__(self, swapclient, coin_type, base_url):
        self.swapclient = swapclient
        self.coin_type = coin_type
        self.base_url = base_url
        self.log = self.swapclient.log

    def readURL(self, url):
        self.log.debug('Explorer url: {}'.format(url))
        headers = {'User-Agent': 'Mozilla/5.0'}
        req = urllib.request.Request(url, headers=headers)
        return urllib.request.urlopen(req).read()


class ExplorerInsight(Explorer):
    def getChainHeight(self):
        return json.loads(self.readURL(self.base_url + '/sync'))['blockChainHeight']

    def getBlock(self, block_hash):
        data = json.loads(self.readURL(self.base_url + '/block/{}'.format(block_hash)))
        return data

    def getTransaction(self, txid):
        data = json.loads(self.readURL(self.base_url + '/tx/{}'.format(txid)))
        return data

    def getBalance(self, address):
        data = json.loads(self.readURL(self.base_url + '/addr/{}/balance'.format(address)))
        return data

    def lookupUnspentByAddress(self, address):
        data = json.loads(self.readURL(self.base_url + '/addr/{}/utxo'.format(address)))
        rv = []
        for utxo in data:
            rv.append({
                'txid': utxo['txid'],
                'index': utxo['vout'],
                'height': utxo['height'],
                'n_conf': utxo['confirmations'],
                'value': utxo['satoshis'],
            })
        return rv


class ExplorerBitAps(Explorer):
    def getChainHeight(self):
        return json.loads(self.readURL(self.base_url + '/block/last'))['data']['block']['height']

    def getBlock(self, block_hash):
        data = json.loads(self.readURL(self.base_url + '/block/{}'.format(block_hash)))
        return data

    def getTransaction(self, txid):
        data = json.loads(self.readURL(self.base_url + '/transaction/{}'.format(txid)))
        return data

    def getBalance(self, address):
        data = json.loads(self.readURL(self.base_url + '/address/state/' + address))
        return data['data']['balance']

    def lookupUnspentByAddress(self, address):
        # Can't get unspents return only if exactly one transaction exists
        data = json.loads(self.readURL(self.base_url + '/address/transactions/' + address))
        try:
            assert(data['data']['list'] == 1)
        except Exception as ex:
            self.log.debug('Explorer error: {}'.format(str(ex)))
            return None
        tx = data['data']['list'][0]
        tx_data = json.loads(self.readURL(self.base_url + '/transaction/{}'.format(tx['txId'])))['data']

        for i, vout in tx_data['vOut'].items():
            if vout['address'] == address:
                return [{
                    'txid': tx_data['txId'],
                    'index': int(i),
                    'height': tx_data['blockHeight'],
                    'n_conf': tx_data['confirmations'],
                    'value': vout['value'],
                }]


class ExplorerChainz(Explorer):
    def getChainHeight(self):
        return int(self.readURL(self.base_url + '?q=getblockcount'))

    def lookupUnspentByAddress(self, address):
        chain_height = self.getChainHeight()
        self.log.debug('[rm] chain_height %d', chain_height)
