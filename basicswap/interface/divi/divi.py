# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""Divi (DIVI) interface.

Divi is a PIVX fork, so this follows interface/pivx/pivx.py closely.  The
differences from PIVX, all verified against divid v3.0.0:

  * Transactions are plain legacy Bitcoin
    (int32 nVersion, vin, vout, uint32 nLockTime) -- no nType, no Sapling.
    So the base CTransaction works and no contrib/messages.py is needed,
    as with Dash.
  * CURRENT_VERSION is 1 and createrawtransaction emits version 1.
  * There is no shielded pool, so none of PIVX's params-download handling
    applies.
  * The wallet exposes dumphdinfo (as Dash does) but has no sethdseed and no
    upgradetohd, so the HD seed can only be set at wallet-creation time via
    the mnemonic= / hdseed= config options.  See initialiseWallet below.
"""

from io import BytesIO

from basicswap.chainparams import Coins
from basicswap.contrib.mnemonic import Mnemonic
from basicswap.contrib.test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
)
from basicswap.contrib.test_framework.script import (
    CScript,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
)
from basicswap.util import b2i, ensure
from basicswap.util.crypto import hash160
from basicswap.interface.btc.btc import BTCInterface, findOutput
from basicswap.rpc import make_rpc_func
from basicswap.util.address import decodeAddress


class DIVIInterface(BTCInterface):
    @staticmethod
    def coin_type():
        return Coins.DIVI

    @staticmethod
    def txVersion() -> int:
        # Divi's CTransaction::CURRENT_VERSION is 1 and it has no BIP68, so
        # version 2 would carry no meaning.
        return 1

    def __init__(self, coin_settings, network, swap_client=None, **kwargs):
        super().__init__(
            coin_settings=coin_settings,
            network=network,
            swap_client=swap_client,
            **kwargs,
        )
        # No multiwallet support
        self.rpc_wallet = make_rpc_func(
            self._rpcport, self._rpcauth, host=self._rpc_host
        )
        self.rpc_wallet_watch = self.rpc_wallet

    # -- wallet ------------------------------------------------------------

    def checkWallets(self) -> int:
        # No multiwallet support: divid has no listwallets, and the single
        # wallet is always loaded.  Same as Firo and Navcoin.
        return 1

    # -- wallet seed -------------------------------------------------------

    def getWalletSeedID(self) -> str:
        # Matches Dash: derive the id from the BIP39 entropy where the wallet
        # reports a mnemonic, so it lines up with what prepare.py set.
        try:
            rv = self.rpc_wallet("dumphdinfo")
        except Exception as e:  # noqa: F841
            self._log.debug(f"{self.ticker()} dumphdinfo failed: {e}.")
            return "Not found"
        mnemonic: str = rv.get("mnemonic", "")
        if mnemonic != "":
            entropy = Mnemonic("english").to_entropy(mnemonic.split(" "))
            return self.getAddressHashFromKey(entropy)[::-1].hex()
        hdseed: str = rv.get("hdseed", "")
        if hdseed == "":
            return "Not found"
        return self.getSeedHash(bytes.fromhex(hdseed)).hex()

    def checkExpectedSeed(self, expect_seedid: str) -> bool:
        self._expect_seedid_hex = expect_seedid
        have_expected_seed: bool = expect_seedid == self.getWalletSeedID()
        self._have_checked_seed = True
        return have_expected_seed

    def entropyToMnemonic(self, key: bytes) -> str:
        return Mnemonic("english").to_mnemonic(key)

    def initialiseWallet(self, key_bytes: bytes, restore_time: int = -1) -> None:
        """Divi cannot be re-seeded over RPC.

        divid only honours mnemonic= / hdseed= while creating a new wallet, and
        exposes no sethdseed or upgradetohd RPC.  bin/prepare.py passes the
        derived mnemonic to the daemon's first start through a piped conf
        (DIVIPrepare.getWalletInitDaemonArgs), so by the time this is reached
        the wallet already holds the right seed.  If
        it does not, the wallet file has to be removed and the daemon
        restarted -- there is no in-place fix.
        """
        self._have_checked_seed = False
        expect_seedid: str = self.getAddressHashFromKey(key_bytes)[::-1].hex()
        if self.getWalletSeedID() == expect_seedid:
            return
        raise ValueError(
            f"{self.coin_name()} cannot set the wallet seed over RPC. "
            "Start the daemon once with -mnemonic from a conf and a fresh "
            "wallet.dat."
        )

    # -- transactions ------------------------------------------------------

    def loadTx(self, tx_bytes: bytes, allow_witness: bool = True) -> CTransaction:
        # Divi has no witness serialisation, always decode as legacy.
        tx = CTransaction()
        tx.deserialize(BytesIO(tx_bytes), False)
        return tx

    def signTxWithWallet(self, tx):
        rv = self.rpc("signrawtransaction", [tx.hex()])
        return bytes.fromhex(rv["hex"])

    def signTxWithKey(self, tx: bytes, key: bytes, prev_amount=None) -> bytes:
        key_wif = self.encodeKey(key)
        rv = self.rpc(
            "signrawtransaction",
            [
                tx.hex(),
                [],
                [
                    key_wif,
                ],
            ],
        )
        return bytes.fromhex(rv["hex"])

    @staticmethod
    def _amountToReal(value) -> float:
        """Divi's JSON-RPC rejects amounts passed as strings.

        PIVX and Bitcoin both accept "1.00000000"; divid answers
        'value is type str, expected real' for createrawtransaction,
        fundrawtransaction and sendtoaddress alike, so every amount has to be
        a JSON number.
        """
        return float(value)

    # Legacy P2PKH size estimates, used for fee calculation since divid cannot
    # size a transaction for us.
    TX_OVERHEAD_BYTES = 10  # version + in/out counts + locktime
    TX_P2PKH_INPUT_BYTES = 148  # outpoint + sequence + scriptSig with sig/pubkey
    TX_OUTPUT_BYTES = 34  # value + P2PKH scriptPubKey

    def _estimateTxFee(self, num_inputs: int, num_outputs: int, fee_rate: int) -> int:
        size: int = (
            self.TX_OVERHEAD_BYTES
            + self.TX_P2PKH_INPUT_BYTES * num_inputs
            + self.TX_OUTPUT_BYTES * num_outputs
        )
        return (fee_rate * size + 999) // 1000  # fee_rate is per kB, round up

    def createRawFundedTransaction(
        self,
        addr_to: str,
        amount: int,
        sub_fee: bool = False,
        lock_unspents: bool = True,
        feerate: int = None,
    ) -> str:
        """Select coins by hand.

        divid has no fundrawtransaction (nor estimatefee / estimatesmartfee /
        settxfee), so everything fundrawtransaction would normally do has to
        happen here: pick inputs, size the transaction, take the fee and add a
        change output.
        """
        if feerate:
            fee_rate = self.format_amount(feerate)
            fee_src = "specified"
        else:
            fee_rate, fee_src = self.get_fee_rate(self._conf_target)
        fee_rate_sats: int = self.make_int(fee_rate)
        self._log.debug(
            f"Fee rate: {fee_rate}, source: {fee_src}, block target: {self._conf_target}"
        )

        # The wallet stakes with the same outputs listunspent reports: divid's
        # staking thread, and setgenerate on regtest once proof of stake starts
        # at block 200, each spend a wallet output as the coinstake input.  An
        # output picked here can be gone by the time the transaction is sent
        # ("Unknown inputs being spent").  Coinstake honours lockunspent, so
        # lock the selection and then confirm every input is still unspent;
        # anything lost in the window between listunspent and the lock is
        # dropped and the selection redone.
        spent_outpoints: set = set()
        for attempt in range(5):
            unspents = [
                u
                for u in self.rpc_wallet("listunspent")
                if u.get("spendable", True)
                and (u["txid"], u["vout"]) not in spent_outpoints
            ]
            # Largest first keeps the input count, and so the fee, down.
            unspents.sort(key=lambda u: self.make_int(u["amount"]), reverse=True)

            selected: list = []
            total_in: int = 0
            fee: int = 0
            have_enough: bool = False
            for u in unspents:
                selected.append(u)
                total_in += self.make_int(u["amount"])
                # Assume a change output; dropped below if it would be dust.
                fee = self._estimateTxFee(len(selected), 2, fee_rate_sats)
                needed: int = amount if sub_fee else amount + fee
                if total_in >= needed:
                    have_enough = True
                    break

            if not have_enough:
                raise ValueError(
                    f"Insufficient {self.ticker()} funds: have "
                    f"{self.format_amount(total_in)}, need "
                    f"{self.format_amount(amount if sub_fee else amount + fee)}."
                )

            inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in selected]
            if lock_unspents:
                self.rpc_wallet("lockunspent", [False, inputs])

            lost = [
                i
                for i in inputs
                if self.rpc("gettxout", [i["txid"], i["vout"]]) is None
            ]
            if not lost:
                break
            if lock_unspents:
                self.rpc_wallet("lockunspent", [True, lost])
            for i in lost:
                spent_outpoints.add((i["txid"], i["vout"]))
            self._log.debug(
                f"{len(lost)} selected input(s) spent by coinstake, reselecting "
                f"(attempt {attempt + 1})."
            )
        else:
            raise ValueError(
                f"{self.ticker()} coin selection keeps losing inputs to coinstake."
            )

        amount_out: int = amount - fee if sub_fee else amount
        if amount_out <= 0:
            raise ValueError("Amount out <= 0 after subtracting fee")

        change: int = total_in - amount_out - fee
        outputs: dict = {addr_to: self._amountToReal(self.format_amount(amount_out))}

        # Below the dust threshold a change output costs more than it returns,
        # so give it to the miners instead.
        dust_threshold: int = self._estimateTxFee(1, 1, fee_rate_sats)
        if change > dust_threshold:
            change_addr: str = self.rpc_wallet("getrawchangeaddress")
            outputs[change_addr] = self._amountToReal(self.format_amount(change))
        else:
            fee += change
            change = 0

        txn = self.rpc("createrawtransaction", [inputs, outputs])

        self._log.debug(
            f"createRawFundedTransaction: {len(inputs)} input(s), "
            f"fee {self.format_amount(fee)}, change {self.format_amount(change)}."
        )
        return txn

    def fundTx(
        self,
        tx: bytes,
        feerate: int,
        lock_unspents: bool = True,
        subfee: bool = False,
        bid_id: bytes = None,
        cursor=None,
        prevouts=None,
    ) -> bytes:
        """fundrawtransaction for a wallet that has none.

        Keeps the outputs of ``tx``, adds inputs from the wallet (after any
        ``prevouts``) and a change output, and returns the unsigned result.
        The fee is taken from the change, or evenly from the existing outputs
        with ``subfee``.
        """
        tx_obj = self.loadTx(tx)
        ensure(len(tx_obj.vout) > 0, "Missing tx outputs")
        fee_rate_sats: int = int(feerate)
        total_out: int = sum(o.nValue for o in tx_obj.vout)

        fixed_in: int = 0
        fixed_outpoints: set = set()
        for prevout in prevouts or []:
            txout = self.rpc("gettxout", [prevout["txid"], prevout["vout"]])
            ensure(txout is not None, "Prevout is spent or unknown")
            fixed_in += self.make_int(txout["value"])
            fixed_outpoints.add((prevout["txid"], prevout["vout"]))
            tx_obj.vin.append(
                CTxIn(COutPoint(b2i(bytes.fromhex(prevout["txid"])), prevout["vout"]))
            )
        num_fixed: int = len(fixed_outpoints)

        # See createRawFundedTransaction for why the selection is locked and
        # then re-checked against the UTXO set.
        spent_outpoints: set = set(fixed_outpoints)
        for attempt in range(5):
            unspents = [
                u
                for u in self.rpc_wallet("listunspent")
                if u.get("spendable", True)
                and (u["txid"], u["vout"]) not in spent_outpoints
            ]
            unspents.sort(key=lambda u: self.make_int(u["amount"]), reverse=True)

            selected: list = []
            total_in: int = fixed_in
            fee: int = 0
            have_enough: bool = False
            while True:
                fee = self._estimateTxFee(
                    num_fixed + len(selected), len(tx_obj.vout) + 1, fee_rate_sats
                )
                if total_in >= (total_out if subfee else total_out + fee):
                    have_enough = True
                    break
                if not unspents:
                    break
                u = unspents.pop(0)
                selected.append(u)
                total_in += self.make_int(u["amount"])
            ensure(
                have_enough,
                f"Insufficient {self.ticker()} funds: have "
                f"{self.format_amount(total_in)}, need "
                f"{self.format_amount(total_out if subfee else total_out + fee)}.",
            )

            inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in selected]
            if lock_unspents and inputs:
                self.rpc_wallet("lockunspent", [False, inputs])
            lost = [
                i
                for i in inputs
                if self.rpc("gettxout", [i["txid"], i["vout"]]) is None
            ]
            if not lost:
                break
            if lock_unspents:
                self.rpc_wallet("lockunspent", [True, lost])
            for i in lost:
                spent_outpoints.add((i["txid"], i["vout"]))
        else:
            raise ValueError(
                f"{self.ticker()} coin selection keeps losing inputs to coinstake."
            )

        for u in selected:
            tx_obj.vin.append(
                CTxIn(COutPoint(b2i(bytes.fromhex(u["txid"])), u["vout"]))
            )

        if subfee:
            share, rem = divmod(fee, len(tx_obj.vout))
            for i, txo in enumerate(tx_obj.vout):
                txo.nValue -= share + (rem if i == 0 else 0)
                ensure(txo.nValue > 0, "Amount out <= 0 after subtracting fee")
            total_out -= fee

        change: int = total_in - total_out - fee
        dust_threshold: int = self._estimateTxFee(1, 1, fee_rate_sats)
        if change > dust_threshold:
            change_addr: str = self.rpc_wallet("getrawchangeaddress")
            pkh: bytes = self.decodeAddress(change_addr)
            tx_obj.vout.append(CTxOut(change, self.getScriptForPubkeyHash(pkh)))
        return tx_obj.serialize()

    def createRawSignedTransaction(self, addr_to, amount) -> str:
        txn_funded = self.createRawFundedTransaction(addr_to, amount)
        return self.rpc("signrawtransaction", [txn_funded])["hex"]

    # -- addresses and scripts --------------------------------------------

    def decodeAddress(self, address: str) -> bytes:
        return decodeAddress(address)[1:]

    def getScriptForPubkeyHash(self, pkh: bytes) -> bytearray:
        # Return P2PKH, Divi has no segwit.
        return CScript([OP_DUP, OP_HASH160, pkh, OP_EQUALVERIFY, OP_CHECKSIG])

    # BTCInterface's getScriptDest/encodeScriptDest are unconditionally P2WSH,
    # which cannot work on a chain without segwit -- encodeScriptDest raises
    # KeyError('hrp') because no bech32 prefix is defined.  Use bare P2SH, the
    # same way the Firo interface does.

    def getScriptDest(self, script: bytearray) -> bytearray:
        # P2SH
        script_hash = hash160(script)
        ensure(len(script_hash) == 20, "Invalid script hash length")
        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def encodeScriptDest(self, script_dest: bytes) -> str:
        # Strip OP_HASH160 / push byte and the trailing OP_EQUAL.
        script_hash = script_dest[2:-1]
        return self.sh_to_address(script_hash)

    def getDestForScriptHash(self, script_hash: bytes) -> bytearray:
        ensure(len(script_hash) == 20, "Invalid script hash length")
        return CScript([OP_HASH160, script_hash, OP_EQUAL])

    def encodeSharedAddress(self, Kbv: bytes, Kbs: bytes) -> str:
        # The chain B lock pays getPkDest(Kbs), which is P2PKH here, so show
        # that address rather than BTCInterface's bech32 one (KeyError('hrp')).
        return self.pubkey_to_address(Kbs)

    def getScriptScriptSig(self, script: bytes) -> bytes:
        # With no witness to carry it, the redeem script goes in the scriptSig.
        return CScript([script])

    # -- chain queries -----------------------------------------------------

    def getTransaction(self, txid_hex: str, verbose: bool = True):
        # divid's getrawtransaction takes an int for verbose and rejects a
        # JSON bool with 'value is type bool, expected int'.  getblock, oddly,
        # does accept a bool.
        return self.rpc("getrawtransaction", [txid_hex, 1 if verbose else 0])

    def getLockTxHeight(
        self,
        txid: bytes,
        dest_address: str,
        bid_amount: int,
        rescan_from: int,
        find_index: bool = False,
        vout: int = -1,
        return_invalid_txids: bool = False,
    ):
        """Find a swap output using Divi's address index.

        The base implementation imports a watch-only address and then calls
        listunspent filtered to it.  That cannot work here: divid's
        listunspent omits watch-only outputs entirely (pre-0.13 behaviour),
        so a confirmed output at a watch-only address comes back as an empty
        list even though validateaddress reports iswatchonly true.

        Divi does ship the address index from the PIVX/Dash lineage, so
        getaddressutxos answers the same question without involving the
        wallet at all.  It needs addressindex=1 in divi.conf, which
        prepare.py writes.

        IronDivi answers the same call by scanning the UTXO set, which takes
        about 7 s on mainnet, so the default 10 s RPC timeout is too tight.
        """
        try:
            utxos = self.rpc(
                "getaddressutxos", [{"addresses": [dest_address]}], timeout=60
            )
        except Exception as e:
            self._log.error(
                f"{self.ticker()} getaddressutxos failed for "
                f"{self._log.addr(dest_address)}: {e}. "
                "Is addressindex=1 set in divi.conf?"
            )
            return None

        invalid_txids: list = []
        found = None
        for utxo in utxos:
            if txid is not None and utxo["txid"] != txid.hex():
                continue
            if isinstance(vout, int) and vout >= 0 and utxo["outputIndex"] != vout:
                continue
            if int(utxo["satoshis"]) == bid_amount:
                found = utxo
                break
            invalid_txids.append(utxo["txid"])

        if found is None:
            if return_invalid_txids and len(invalid_txids):
                return {"invalid": invalid_txids}
            return None

        chain_height: int = self.getChainHeight()
        utxo_height: int = int(found["height"])
        # height 0 means it is still in the mempool
        depth: int = 0 if utxo_height <= 0 else (chain_height - utxo_height) + 1

        rv: dict = {"depth": max(0, depth), "height": max(0, utxo_height)}
        if find_index:
            rv["index"] = found["outputIndex"]
            rv["value"] = int(found["satoshis"])
        if txid is None:
            rv["txid"] = found["txid"]
        return rv

    def getUTXOBalance(self, address: str) -> int:
        # verifyProofOfFunds uses scantxoutset, which divid does not have.
        # The address index holds the same confirmed outputs.  IronDivi scans
        # the UTXO set for it, so allow the same 60 s as getLockTxHeight.
        utxos = self.rpc("getaddressutxos", [{"addresses": [address]}], timeout=60)
        return sum(int(utxo["satoshis"]) for utxo in utxos)

    def isAddressMine(self, address: str, or_watch_only: bool = False) -> bool:
        # divid has no getaddressinfo; validateaddress carries ismine and
        # iswatchonly instead.
        addr_info = self.rpc_wallet("validateaddress", [address])
        if addr_info.get("ismine", False):
            return True
        if or_watch_only is False:
            return False
        return addr_info.get("iswatchonly", False)

    def getBlockHeaderFromHeight(self, height: int) -> dict:
        # getblockheader omits hash and height; getblock carries both.
        block_hash: str = self.rpc("getblockhash", [height])
        return self.rpc("getblock", [block_hash, True])

    def getBlockHeaderAt(self, time_target: int, block_after: bool = False) -> dict:
        """Walk back to the block spanning time_target.

        Same shape as the base implementation, but reading through getblock,
        since callers want ["hash"] and ["height"] and divid's getblockheader
        reports neither.
        """
        blockchaininfo = self.rpc("getblockchaininfo")
        last_block_header = self.rpc(
            "getblock", [blockchaininfo["bestblockhash"], True]
        )

        max_tries: int = 5000
        for _ in range(max_tries):
            prev_block_header = self.rpc(
                "getblock", [last_block_header["previousblockhash"], True]
            )
            if prev_block_header["time"] <= time_target:
                return last_block_header if block_after else prev_block_header
            last_block_header = prev_block_header
        raise ValueError(f"{self.ticker()} getBlockHeaderAt depth exceeded")

    def getBlockchainInfo(self):
        """Add verificationprogress, which divid does not report.

        Divi's getblockchaininfo returns only chain, blocks, headers,
        bestblockhash, difficulty and chainwork.  BasicSwap.getBlockchainInfo
        reads ["verificationprogress"] unconditionally, so without this the
        whole call raises KeyError, getWalletInfo is logged as failed, and the
        coin never gets a balance in the wallets API.
        """
        rv = self.rpc("getblockchaininfo")
        if "verificationprogress" not in rv:
            blocks: int = rv.get("blocks", 0)
            headers: int = rv.get("headers", 0)
            if headers > 0:
                rv["verificationprogress"] = min(1.0, blocks / headers)
            else:
                rv["verificationprogress"] = 0.0
        return rv

    def getWalletRestoreHeight(self) -> int:
        # BTCInterface derives this from getwalletinfo()["keypoololdest"] and
        # getblockheader()["height"]; divid reports neither.  Without a wallet
        # creation time the only safe restore point is the genesis block.
        return 0

    def getBlockWithTxns(self, block_hash: str):
        # Divi's getblock only returns txids.
        block = self.rpc("getblock", [block_hash, True])
        tx_rv = []
        for txid_str in block["tx"]:
            tx_dec = self.getTransaction(txid_str)
            tx_rv.append(tx_dec)
        block["tx"] = tx_rv
        return block

    def getBlockHeader(self, block_hash: str) -> dict:
        # Divi's getblockheader returns only version, previousblockhash,
        # merkleroot, time, bits and nonce -- no height, confirmations or
        # mediantime.  getblock carries all three, so use it instead.
        return self.rpc("getblock", [block_hash, True])

    def getChainMedianTime(self) -> int:
        """BIP113 median-time-past, computed here.

        Neither getblockchaininfo nor getblockheader reports mediantime on
        Divi, so walk back over the last MEDIAN_TIME_SPAN headers and take the
        median of their timestamps, which is what core does internally.
        """
        median_time_span: int = 11
        block_hash: str = self.rpc("getbestblockhash")
        times: list = []
        for _ in range(median_time_span):
            header = self.rpc("getblockheader", [block_hash])
            times.append(header["time"])
            block_hash = header.get("previousblockhash")
            if not block_hash:
                break  # reached the genesis block
        times.sort()
        return times[len(times) // 2]

    def findConfirmedTxnByHash(self, txid_hex: str):
        # Only works for wallet txns
        try:
            rv = self.rpc("gettransaction", [txid_hex])
        except Exception as e:  # noqa: F841
            self._log.debug(
                "findConfirmedTxnByHash gettransaction failed: {}".format(txid_hex)
            )
            return None
        if "confirmations" in rv and rv["confirmations"] >= self.blocks_confirmed:
            block_height = self.getBlockHeader(rv["blockhash"])["height"]
            return {"txid": txid_hex, "amount": 0, "height": block_height}
        return None

    # -- balances and fees -------------------------------------------------

    def getSpendableBalance(self) -> int:
        # getwalletinfo.balance already excludes masternode collateral and
        # locked (staking) outputs, which listunspent would report.
        return self.make_int(self.rpc("getwalletinfo")["balance"])

    def withdrawCoin(self, value, addr_to, subfee):
        # value arrives as a string from the UI; divid needs a JSON number.
        if not subfee:
            return self.rpc("sendtoaddress", [addr_to, self._amountToReal(value)])

        # divid's sendtoaddress has no subtract-fee option (its third argument
        # is a fee mode, not a flag), so spending a whole balance fails with
        # "Insufficient funds".  Build, sign and send the transaction by hand.
        txn = self.createRawFundedTransaction(addr_to, self.make_int(value), True)
        try:
            signed = self.rpc("signrawtransaction", [txn])
            if not signed.get("complete", False):
                raise ValueError("signrawtransaction did not complete")
            return self.rpc("sendrawtransaction", [signed["hex"]])
        except Exception:
            inputs = [
                {"txid": i["txid"], "vout": i["vout"]}
                for i in self.rpc("decoderawtransaction", [txn])["vin"]
            ]
            self.rpc_wallet("lockunspent", [True, inputs])
            raise

    def getBLockTxo(
        self,
        chain_b_lock_txid: bytes,
        lock_tx_vout: int,
        script_pk: bytes,
    ) -> (int, int):
        # BTCInterface reads the lock tx with the watch-only wallet's
        # gettransaction.  Divi has no watch-only wallet and the lock output
        # pays a swap key the wallet does not hold, so read it from the chain.
        tx_hex = self.rpc("getrawtransaction", [chain_b_lock_txid.hex()])
        lock_tx = self.loadTx(bytes.fromhex(tx_hex))
        locked_n = findOutput(lock_tx, script_pk)
        actual_value = None
        if locked_n is not None:
            actual_value = lock_tx.vout[locked_n].nValue
        return locked_n, actual_value

    def getBLockSpendTxFee(self, tx, fee_rate: int) -> int:
        add_bytes = 107
        size = len(tx.serialize_without_witness()) + add_bytes
        pay_fee = round(fee_rate * size / 1000)
        self._log.info(
            f"BLockSpendTx fee_rate, size, fee: {fee_rate}, {size}, {pay_fee}."
        )
        return pay_fee

    # -- wallet encryption -------------------------------------------------

    def encryptWallet(self, password: str, check_seed: bool = True):
        # Watchonly wallets are not encrypted
        seed_id_before: str = self.getWalletSeedID()

        self.rpc_wallet("encryptwallet", [password], timeout=120)

        if check_seed is False or seed_id_before == "Not found":
            return
        seed_id_after: str = self.getWalletSeedID()

        if seed_id_before == seed_id_after:
            return
        self._log.warning(f"{self.ticker()} wallet seed changed after encryption.")
        self._log.debug(
            f"seed_id_before: {seed_id_before} seed_id_after: {seed_id_after}."
        )
        self.setWalletSeedWarning(True)
