#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2020-2022 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .interface_btc import BTCInterface
from .chainparams import Coins
from .util import (
    make_int,
)


class NMCInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.NMC

    def getLockTxHeight(self, txid, dest_address, bid_amount, rescan_from, find_index=False):
        self._log.debug('[rm] scantxoutset start')  # scantxoutset is slow
        ro = self.rpc_callback('scantxoutset', ['start', ['addr({})'.format(dest_address)]])  # TODO: Use combo(address) where possible
        self._log.debug('[rm] scantxoutset end')
        return_txid = True if txid is None else False
        for o in ro['unspents']:
            if txid and o['txid'] != txid.hex():
                continue
            # Verify amount
            if make_int(o['amount']) != int(bid_amount):
                self._log.warning('Found output to lock tx address of incorrect value: %s, %s', str(o['amount']), o['txid'])
                continue

            rv = {
                'depth': 0,
                'height': o['height']}
            if o['height'] > 0:
                rv['depth'] = ro['height'] - o['height']
            if find_index:
                rv['index'] = o['vout']
            if return_txid:
                rv['txid'] = o['txid']
            return rv
