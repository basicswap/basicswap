# -*- coding: utf-8 -*-

# Copyright (c) 2019 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

import urllib.request
import json


class Explorer():
    def __init__(self, swapclient, base_url):
        self.swapclient = swapclient
        self.base_url = base_url
        self.log = self.swapclient.log


class ExplorerInsight(Explorer):
    def getChainHeight(self):
        return json.loads(urllib.request.urlopen(self.base_url + '/sync').read())['blockChainHeight']

    def lookupUnspentByAddress(self, address):
        chain_height = self.getChainHeight()
        self.log.debug('[rm] chain_height %d', chain_height)


class ExplorerBitAps(Explorer):
    def getChainHeight(self):
        return json.loads(urllib.request.urlopen(self.base_url + '/block/last').read())['data']['block']['height']

    def lookupUnspentByAddress(self, address):
        chain_height = self.getChainHeight()
        self.log.debug('[rm] chain_height %d', chain_height)


class ExplorerChainz(Explorer):
    def getChainHeight(self):
        return int(urllib.request.urlopen(self.base_url + '?q=getblockcount').read())

    def lookupUnspentByAddress(self, address):
        chain_height = self.getChainHeight()
        self.log.debug('[rm] chain_height %d', chain_height)
