#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

def checkForks(ro):
    if 'bip9_softforks' in ro:
        assert(ro['bip9_softforks']['csv']['status'] == 'active')
        assert(ro['bip9_softforks']['segwit']['status'] == 'active')
    else:
        assert(ro['softforks']['csv']['active'])
        assert(ro['softforks']['segwit']['active'])
