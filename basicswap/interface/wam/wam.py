# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.interface.btc.btc import BTCInterface
from basicswap.chainparams import Coins


class WAMInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.WAM


# Nothing else is overridden, and that is the whole point. WAM is a Bitcoin
# Core v28.1 fork: the RPC surface, the transaction format, the script language,
# SegWit and PSBT are Bitcoin's, so every method BTCInterface implements is
# already correct here.
#
# LTCInterface is larger only because Litecoin has MimbleWimble, and
# DASHInterface only because Dash has its own address handling. WAM has neither
# and adding overrides that repeat the parent would be code to maintain for no
# behaviour.
#
# RandomX changes how a header is proved, not how it is parsed or spent, and no
# part of an atomic swap looks at proof of work.
