# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.chainparams import Coins
from basicswap.interface.ltc.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    getOSDirNames,
)

LITECOIN_VERSION = os.getenv("LITECOIN_VERSION", "0.21.5.5")
LITECOIN_VERSION_TAG = os.getenv("LITECOIN_VERSION_TAG", "")
litecoin_signers = {"davidburkett38": ("D35621D53A1CC6A3456758D03620E9D387E55666",)}


LTC_RPC_HOST = os.getenv("LTC_RPC_HOST", "127.0.0.1")
LTC_RPC_PORT = int(os.getenv("LTC_RPC_PORT", 19895))
LTC_ONION_PORT = int(os.getenv("LTC_ONION_PORT", 9333))
LTC_RPC_USER = os.getenv("LTC_RPC_USER", "")
LTC_RPC_PWD = os.getenv("LTC_RPC_PWD", "")


class LTCPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": LTC_RPC_HOST,
            "rpcport": LTC_RPC_PORT + ctx.port_offset,
            "onionport": LTC_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("LTC_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": True,
            "blocks_confirmed": 2,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 20,
            "min_relay_fee": 0.00001,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> list:
        os_name, _ = getOSDirNames(ctx.bin_arch)
        return [
            f"https://github.com/litecoin-project/litecoin/releases/download/v{self.version}{self.version_tag}/{release_filename}",
            f"https://download.litecoin.org/litecoin-{self.version}{self.version_tag}/{os_name}/{release_filename}",
        ]

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        major_minor_version: str = ".".join(self.version.split(".")[:2])
        assert_filename: str = (
            f"{self.name}-core-{os_name}-{major_minor_version}-build.assert"
        )
        return f"https://raw.githubusercontent.com/litecoin-project/gitian.sigs.ltc/master/{self.version}-{os_dir_name}/{signing_key_name}/{assert_filename}"

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
        fp.write("changetype=bech32\n")
        self.writeRpcAuth(fp, salt)

    def createWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        super().createWallet(ctx, swap_client, coin_id, core_settings)

        password = (
            ctx.wallet_encryption_pwd if ctx.wallet_encryption_pwd != "" else None
        )
        swap_client.ci(Coins.LTC_MWEB).init_wallet(password)


prepare_module = LTCPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=LITECOIN_VERSION,
    version_tag=LITECOIN_VERSION_TAG,
    signers=litecoin_signers,
    rpc_user=LTC_RPC_USER,
    rpc_password=LTC_RPC_PWD,
    onion_port=LTC_ONION_PORT,
    creates_wallet=True,
)
