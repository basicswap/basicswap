# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.bch.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    ensurePubkey,
    isValidSignature,
)

BITCOINCASH_VERSION = os.getenv("BITCOINCASH_VERSION", "29.0.0")
BITCOINCASH_VERSION_TAG = os.getenv("BITCOINCASH_VERSION_TAG", "")
bitcoincash_signers = {"Calin_Culianu": ("D465135F97D0047E18E99DC321810A542031C02C",)}


BCH_RPC_HOST = os.getenv("BCH_RPC_HOST", "127.0.0.1")
BCH_RPC_PORT = int(os.getenv("BCH_RPC_PORT", 19997))
BCH_PORT = int(os.getenv("BCH_PORT", 19798))
BCH_ONION_PORT = int(os.getenv("BCH_ONION_PORT", 8335))
BCH_RPC_USER = os.getenv("BCH_RPC_USER", "")
BCH_RPC_PWD = os.getenv("BCH_RPC_PWD", "")


class BCHPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": BCH_RPC_HOST,
            "rpcport": BCH_RPC_PORT + ctx.port_offset,
            "onionport": BCH_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("BCH_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "port": BCH_PORT + ctx.port_offset,
            "config_filename": "bitcoin.conf",
            "use_segwit": False,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 22,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        return f"bitcoin-cash-node-{self.version}-{ctx.bin_arch}.{ctx.file_ext}"

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/bitcoin-cash-node/bitcoin-cash-node/releases/download/v{self.version}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        return f"https://gitlab.com/bitcoin-cash-node/announcements/-/raw/master/release-sigs/{self.version}/SHA256SUMS.{self.version}.asc.{signing_key_name}"

    def hasDetachedSig(self) -> bool:
        return False

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return [
            "https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/raw/master/contrib/gitian-signing/pubkeys.txt"
        ]

    def verifyCoreSignature(
        self,
        ctx: PrepareContext,
        gpg,
        release_path: str,
        assert_path: str,
        assert_sig_path: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> None:
        # The hashes file is itself an inline-signed document, verify it directly.
        pubkey_filename = self.getPubkeyFilename(signing_key_name)
        pubkeyurls = self.getAllPubkeyUrls(ctx)

        ensurePubkey(gpg, ctx, signing_key_name, self.signers, pubkey_filename, pubkeyurls)

        with open(assert_path, "rb") as fp:
            verified = gpg.verify_file(fp)

        self.ensureValidSignatureBy(ctx, verified, signing_key_name)

    def getExtractBins(self) -> list:
        bins = ["bitcoind", "bitcoin-cli", "bitcoin-tx"]
        versions = self.version.split(".")
        if int(versions[0]) >= 22 or int(versions[1]) >= 19:
            bins.append("bitcoin-wallet")
        return bins

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        return f"bitcoin-cash-node-{self.version}{self.version_tag}/bin/{bin_name}"

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:
        fp.write("prune=4000\n")
        fp.write("pid=bitcoincashd.pid\n")
        self.writeRpcAuth(fp, salt)


prepare_module = BCHPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=BITCOINCASH_VERSION,
    version_tag=BITCOINCASH_VERSION_TAG,
    signers=bitcoincash_signers,
    rpc_user=BCH_RPC_USER,
    rpc_password=BCH_RPC_PWD,
    onion_port=BCH_ONION_PORT,
    reseed_note=True,
)
