# -*- coding: utf-8 -*-

# Copyright (c) 2023 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from basicswap.chainparams import Coins
from basicswap.basicswap_util import SwapTypes
from basicswap.util import TemporaryError
import basicswap.protocols.atomic_swap_1 as atomic_swap_1


class NavSwapInterface(atomic_swap_1.AtomicSwapInterface):
    swap_type = SwapTypes.SECRET_HASH_BLSCT


def redeemITx(self, bid_id: bytes, cursor):
    _, offer = self.getBidAndOffer(bid_id, cursor, with_txns=False)
    if Coins.NAV not in (Coins(offer.coin_from), Coins(offer.coin_to)):
        # Non-NAV: unchanged upstream behaviour.
        return atomic_swap_1.redeemITx(self, bid_id, cursor)

    # NAV: the ITX redeem is preimage-message-driven and time-critical (must land
    # before the ITX timelock). checkQueuedActions only retries TemporaryError,
    # so wrap transient build/publish failures instead of letting a generic
    # Exception drop the action and strand the swap until manually re-queued.
    try:
        return atomic_swap_1.redeemITx(self, bid_id, cursor)
    except TemporaryError:
        raise
    except Exception as ex:
        raise TemporaryError(f"NAV redeemITx failed, will retry: {ex}")
