# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.doge.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    getOSDirNames,
)

DOGECOIN_VERSION = os.getenv("DOGECOIN_VERSION", "23.2.1")
DOGECOIN_VERSION_TAG = os.getenv("DOGECOIN_VERSION_TAG", "")
doge_signers = {"tecnovert": ("8E517DC12EC1CC37F6423A8A13F13651C9CF0D6B",)}

DOGE_RPC_HOST = os.getenv("DOGE_RPC_HOST", "127.0.0.1")
DOGE_RPC_PORT = int(os.getenv("DOGE_RPC_PORT", 42069))
DOGE_ONION_PORT = int(os.getenv("DOGE_ONION_PORT", 6969))
DOGE_RPC_USER = os.getenv("DOGE_RPC_USER", "")
DOGE_RPC_PWD = os.getenv("DOGE_RPC_PWD", "")


class DOGEPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": DOGE_RPC_HOST,
            "rpcport": DOGE_RPC_PORT + ctx.port_offset,
            "onionport": DOGE_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "DOGE_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": False,
            "use_csv": False,
            "blocks_confirmed": 2,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 23,
            "min_relay_fee": 0.01,  # RECOMMENDED_MIN_TX_FEE
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getArchName(self, ctx: PrepareContext, os_name: str, use_guix: bool) -> str:
        if os_name == "osx" and use_guix:
            return "x86_64-apple-darwin18"
        return ctx.bin_arch

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/tecnovert/dogecoin/releases/download/v{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        return f"https://raw.githubusercontent.com/tecnovert/guix.sigs/dogecoin/{self.version}/{signing_key_name}/noncodesigned.SHA256SUMS"

    def getPubkeyFilename(self, signing_key_name: str) -> str:
        return f"particl_{signing_key_name}.pgp"

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
        self.writeRpcAuth(fp, salt)


prepare_module = DOGEPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=DOGECOIN_VERSION,
    version_tag=DOGECOIN_VERSION_TAG,
    signers=doge_signers,
    rpc_user=DOGE_RPC_USER,
    rpc_password=DOGE_RPC_PWD,
    onion_port=DOGE_ONION_PORT,
    creates_wallet=True,
)
