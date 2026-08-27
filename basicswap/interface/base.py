# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Copyright (c) 2025-2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import socks
import threading

from enum import IntEnum
from typing import List, Optional

from basicswap.basicswap_util import (
    TxLockTypes,
)
from basicswap.chainparams import (
    chainparams,
)
from basicswap.config import DEFAULT_ALTRUISTIC
from basicswap.util import (
    ensure,
    i2b,
    b2i,
    make_int,
    format_amount,
    TemporaryError,
)
from basicswap.util.crypto import (
    hash160,
)
from basicswap.util.ecc import (
    ep,
    getSecretInt,
)
from coincurve.dleag import verify_secp256k1_point
from coincurve.keys import (
    PrivateKey,
    PublicKey,
)


class Curves(IntEnum):
    secp256k1 = 1
    ed25519 = 2


class CoinInterface:
    _max_mtp_cache_entries: int = 1000

    @staticmethod
    def watch_blocks_for_scripts() -> bool:
        return False

    @staticmethod
    def getVoutValue(vout) -> int:
        return vout.nValue

    @staticmethod
    def setVoutValue(vout, value) -> None:
        vout.nValue = value

    @staticmethod
    def getVoutScriptPubKey(vout) -> bytes:
        return vout.scriptPubKey

    @staticmethod
    def setVoutScriptPubKey(vout, script: bytes) -> None:
        vout.scriptPubKey = script

    @staticmethod
    def setTxLockTime(tx, locktime: int) -> None:
        tx.nLockTime = locktime

    def __init__(self, network, **kwargs):
        self.setDefaults()
        self._network = network
        # Keyed by height, the median time past of a block only changes in a reorg
        self._mtp_at_height_cache = {}
        self._mx_wallet = threading.Lock()
        coin_settings = kwargs.get("coin_settings", {})
        swap_client = kwargs.get("swap_client")
        base_altruistic = (
            swap_client.getBaseAltruistic() if swap_client else DEFAULT_ALTRUISTIC
        )
        self._altruistic = coin_settings.get("altruistic", base_altruistic)
        self._core_version = None  # Set in getDaemonVersion()

    def interface_type(self) -> int:
        # coin_type() returns the base coin type, interface_type() returns the coin+balance type.
        return self.coin_type()

    def setDefaults(self):
        self._unknown_wallet_seed = True
        self._restore_height = None

    def make_int(self, amount_in: int, r: int = 0) -> int:
        return make_int(amount_in, self.exp(), r=r)

    def format_amount(self, amount_in, conv_int=False, r=0):
        amount_int = make_int(amount_in, self.exp(), r=r) if conv_int else amount_in
        return format_amount(amount_int, self.exp())

    def max_money(self) -> int:
        return 21000000 * self.COIN()

    def money_range(self, sats: int) -> bool:
        return sats >= 0 and sats <= self.max_money()

    def coin_name(self) -> str:
        coin_chainparams = chainparams[self.coin_type()]
        if "display_name" in coin_chainparams:
            return coin_chainparams["display_name"]
        return coin_chainparams["name"].capitalize()

    def ticker(self) -> str:
        ticker = chainparams[self.coin_type()]["ticker"]
        if self._network == "testnet":
            ticker = "t" + ticker
        elif self._network == "regtest":
            ticker = "rt" + ticker
        return ticker

    def getExchangeTicker(self, exchange_name: str) -> str:
        return chainparams[self.coin_type()]["ticker"]

    def getExchangeName(self, exchange_name: str) -> str:
        return chainparams[self.coin_type()]["name"]

    def ticker_mainnet(self) -> str:
        ticker = chainparams[self.coin_type()]["ticker"]
        return ticker

    def min_amount(self) -> int:
        return chainparams[self.coin_type()][self._network]["min_amount"]

    def max_amount(self) -> int:
        return chainparams[self.coin_type()][self._network]["max_amount"]

    def setWalletSeedWarning(self, value: bool) -> None:
        self._unknown_wallet_seed = value

    def setWalletRestoreHeight(self, value: int) -> None:
        self._restore_height = value

    def knownWalletSeed(self) -> bool:
        return not self._unknown_wallet_seed

    def chainparams(self):
        return chainparams[self.coin_type()]

    def chainparams_network(self):
        return chainparams[self.coin_type()][self._network]

    def has_segwit(self) -> bool:
        return chainparams[self.coin_type()].get("has_segwit", True)

    def use_p2shp2wsh(self) -> bool:
        # p2sh-p2wsh
        return False

    def is_transient_error(self, ex) -> bool:
        if isinstance(ex, TemporaryError):
            return True
        if isinstance(ex, socks.ProxyError):
            return True
        str_error: str = str(ex).lower()
        if "not enough unlocked money" in str_error:
            return True
        if "no unlocked balance" in str_error:
            return True
        if "transaction was rejected by daemon" in str_error:
            return True
        if "invalid unlocked_balance" in str_error:
            return True
        if "daemon is busy" in str_error:
            return True
        if "timed out" in str_error:
            return True
        if "request-sent" in str_error:
            return True
        return False

    def setConfTarget(self, new_conf_target: int) -> None:
        ensure(
            new_conf_target >= 1 and new_conf_target < 33, "Invalid conf_target value"
        )
        self._conf_target = new_conf_target

    def getConfTarget(self) -> int:
        return self._conf_target

    def walletRestoreHeight(self) -> int:
        return self._restore_height

    def get_connection_type(self):
        return self._connection_type

    def using_segwit(self) -> bool:
        # Using btc native segwit
        return self._use_segwit

    def use_tx_vsize(self) -> bool:
        return self._use_segwit

    def getLockTxSwapOutputValue(self, bid, xmr_swap) -> int:
        return bid.amount

    def getLockRefundTxSwapOutputValue(self, bid, xmr_swap) -> int:
        return xmr_swap.a_swap_refund_value

    def getLockRefundTxSwapOutput(self, xmr_swap) -> int:
        # Only one prevout exists
        return 0

    def checkWallets(self) -> int:
        return 1

    def altruistic(self) -> bool:
        return self._altruistic

    def canSendMercyTx(self) -> bool:
        # Whether a standalone mercy tx spending the swipe's payout can be built.
        # A coin that can't must not fall back to putting the keyshare on the
        # swipe, that publishes it while the swipe can still be replaced.
        return False

    def getMercyWatchVouts(self, swipe_txid_hex: str, swipe_tx=None) -> List[int]:
        # Which outputs of the swipe a mercy tx could spend.  The leader has to
        # watch each one, it can't tell which the swiper will use.
        return [0]

    def getMercyPrevout(self, swipe_txid_hex: str, swipe_tx=None) -> int:
        # The swiper's side of getMercyWatchVouts: the one output the mercy tx
        # spends, and which must stay locked until it is sent.
        return 0

    def lockOutput(self, txid_hex: str, vout: int, bid_id=None, cursor=None) -> None:
        # Keep an output out of coin selection.  Locks are not durable, callers
        # must re-assert them for as long as the output must stay unspent.
        self._log.debug(f"lockOutput not implemented for {self.coin_name()}")

    def unlockOutput(self, txid_hex: str, vout: int, cursor=None) -> None:
        pass


class AdaptorSigInterface:
    def getP2WPKHDummyWitness(self, verifying: bool = True) -> List[bytes]:
        # 72 bytes overestimates by 1. Core uses 71-byte low-R signatures
        return [bytes(71 if verifying else 72), bytes(33)]

    def getScriptLockTxDummyWitness(self, script: bytes) -> List[bytes]:
        return [b"", bytes(72), bytes(72), bytes(len(script))]

    def getScriptLockRefundSpendTxDummyWitness(self, script: bytes) -> List[bytes]:
        return [b"", bytes(72), bytes(72), bytes((1,)), bytes(len(script))]

    def getScriptLockRefundSwipeTxDummyWitness(self, script: bytes) -> List[bytes]:
        return [bytes(72), b"", bytes(len(script))]

    def getLockRefundTxFee(self, locked_coin: int, tx_lock_refund_bytes: bytes) -> int:
        # The lock refund tx spends the lock tx output to its own single output
        tx_lock_refund = self.loadTx(tx_lock_refund_bytes)
        ensure(len(tx_lock_refund.vout) == 1, "Lock refund tx doesn't have one output")
        fee_paid: int = locked_coin - self.getVoutValue(tx_lock_refund.vout[0])
        ensure(fee_paid > 0, "Zero or negative lock refund tx fee")
        return fee_paid

    def getLockRefundVout(self, lock_refund_tx_data: bytes, vbkv: bytes) -> int:
        return 0

    def haveSignedLockRefundTx(self, xmr_swap) -> bool:
        if xmr_swap.a_lock_refund_tx is None:
            return False
        if (
            xmr_swap.al_lock_refund_tx_sig is None
            or xmr_swap.af_lock_refund_tx_sig is None
        ):
            return False

        return (
            len(xmr_swap.al_lock_refund_tx_sig) > 0
            and len(xmr_swap.af_lock_refund_tx_sig) > 0
        )


class Secp256k1Interface(CoinInterface, AdaptorSigInterface):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @staticmethod
    def curve_type():
        return Curves.secp256k1

    def getNewRandomKey(self) -> bytes:
        return i2b(getSecretInt())

    def getPubkey(self, privkey: bytes) -> bytes:
        return PublicKey.from_secret(privkey).format()

    def pkh(self, pubkey: bytes) -> bytes:
        return hash160(pubkey)

    def verifyKey(self, k: bytes) -> bool:
        i = b2i(k)
        return i < ep.o and i > 0

    def verifyPubkey(self, pubkey_bytes: bytes) -> bool:
        return verify_secp256k1_point(pubkey_bytes)

    def isValidAddressHash(self, address_hash: bytes) -> bool:
        if len(address_hash) == 20:
            return True

    def getMedianTimePastAtHeight(self, height: int) -> Optional[int]:
        # BIP68 measures time based relative locks from the median time past of the
        # block before the one containing the output being spent, not its header time
        if height < 0:
            return None
        cached = self._mtp_at_height_cache.get(height, None)
        if cached is not None:
            return cached
        mtp = self._getMedianTimePastAtHeight(height)
        if mtp is not None:
            if len(self._mtp_at_height_cache) >= self._max_mtp_cache_entries:
                self._mtp_at_height_cache.pop(next(iter(self._mtp_at_height_cache)))
            self._mtp_at_height_cache[height] = mtp
        return mtp

    def _getMedianTimePastAtHeight(self, height: int) -> Optional[int]:
        try:
            return self.getBlockHeaderFromHeight(height)["mediantime"]
        except Exception as e:
            self._log.warning(f"getMedianTimePastAtHeight failed: {e}")
            return None

    def csvLockRemaining(
        self,
        lock_type: int,
        encoded_sequence: int,
        parent_block_height: Optional[int],
        parent_block_time: Optional[int],
        chain_height: Optional[int] = None,
        chain_mtp: Optional[int] = None,
        coin_mtp: Optional[int] = None,
    ) -> Optional[int]:
        # Blocks or seconds until the lock matures, None if it can't be determined
        if parent_block_height is None or parent_block_height < 1:
            return None
        lock_value: int = self.decodeSequence(encoded_sequence)
        if lock_type == TxLockTypes.SEQUENCE_LOCK_BLOCKS:
            if chain_height is None:
                chain_height = self.getChainHeight()
            if chain_height is None:
                return None
            return (parent_block_height + lock_value) - (chain_height + 1)
        if lock_type == TxLockTypes.SEQUENCE_LOCK_TIME:
            if parent_block_time is None or parent_block_time < 1:
                return None
            if coin_mtp is None:
                coin_mtp = self.getMedianTimePastAtHeight(
                    max(parent_block_height - 1, 0)
                )
            if coin_mtp is None:
                return None
            if chain_mtp is None:
                chain_mtp = self.getChainMedianTime()
            if chain_mtp is None:
                return None
            return (coin_mtp + lock_value) - chain_mtp
        raise ValueError(f"Unknown lock type {lock_type}")

    def verifySig(self, pubkey: bytes, signed_hash: bytes, sig: bytes) -> bool:
        pubkey = PublicKey(pubkey)
        return pubkey.verify(sig, signed_hash, hasher=None)

    def sumKeys(self, ka: bytes, kb: bytes) -> bytes:
        return PrivateKey(ka).add(kb).secret

    def sumPubkeys(self, Ka: bytes, Kb: bytes) -> bytes:
        return PublicKey.combine_keys([PublicKey(Ka), PublicKey(Kb)]).format()
