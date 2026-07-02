# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.nmc.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
)

NMC_VERSION = os.getenv("NMC_VERSION", "28.0")
NMC_VERSION_TAG = os.getenv("NMC_VERSION_TAG", "")
nmc_signers = {"RoseTuring": ("FD8366A807A99FA27FD9CCEA9FE3BFDDA6C53495",)}

NMC_RPC_HOST = os.getenv("NMC_RPC_HOST", "127.0.0.1")
NMC_RPC_PORT = int(os.getenv("NMC_RPC_PORT", 19698))
NMC_PORT = int(os.getenv("NMC_PORT", 8134))
NMC_ONION_PORT = int(os.getenv("NMC_ONION_PORT", 9698))
NMC_RPC_USER = os.getenv("NMC_RPC_USER", "")
NMC_RPC_PWD = os.getenv("NMC_RPC_PWD", "")


class NMCPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": NMC_RPC_HOST,
            "rpcport": NMC_RPC_PORT + ctx.port_offset,
            "onionport": NMC_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("NMC_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "port": NMC_PORT + ctx.port_offset,
            "use_segwit": True,
            "use_csv": True,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 28,
            "chain_lookups": "local",
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://www.namecoin.org/files/namecoin-core/namecoin-core-{self.version}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        return f"https://raw.githubusercontent.com/namecoin/guix.sigs/main/{self.version}/Rose%20Turing/noncodesigned.SHA256SUMS"

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:
        fp.write("prune=2000\n")
        fp.write("deprecatedrpc=create_bdb\n")
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")
        fp.write("fallbackfee=0.001\n")  # minrelaytxfee


prepare_module = NMCPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=NMC_VERSION,
    version_tag=NMC_VERSION_TAG,
    signers=nmc_signers,
    rpc_user=NMC_RPC_USER,
    rpc_password=NMC_RPC_PWD,
    onion_port=NMC_ONION_PORT,
    creates_wallet=True,
)
