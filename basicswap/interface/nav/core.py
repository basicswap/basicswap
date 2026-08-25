# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.nav.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
)

NAVIO_VERSION = os.getenv("NAVIO_VERSION", "0.1.5")
NAVIO_VERSION_TAG = os.getenv("NAVIO_VERSION_TAG", "")
navio_signers = {"navio_builder": ("5E542D3BDB5F4305762330B37A17AA0838680153",)}

NAV_RPC_HOST = os.getenv("NAV_RPC_HOST", "127.0.0.1")
NAV_RPC_PORT = int(os.getenv("NAV_RPC_PORT", 19798))
NAV_ONION_PORT = int(os.getenv("NAV_ONION_PORT", 8336))
NAV_RPC_USER = os.getenv("NAV_RPC_USER", "")
NAV_RPC_PWD = os.getenv("NAV_RPC_PWD", "")


class NAVPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": NAV_RPC_HOST,
            "rpcport": NAV_RPC_PORT + ctx.port_offset,
            "onionport": NAV_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("NAV_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": False,
            "use_csv": False,
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

    def useGuix(self) -> bool:
        return True

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        release_tag: str = f"v{self.version}{self.version_tag}"
        return f"https://github.com/nav-io/navio-core/releases/download/{release_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        release_tag: str = f"v{self.version}{self.version_tag}"
        return f"https://github.com/nav-io/navio-core/releases/download/{release_tag}/SHA256SUMS"

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return ["https://nav.io/releases.asc"]

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
        fp.write("fallbackfee=0.0002\n")
        self.writeRpcAuth(fp, salt)

    def createWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        wallet_name = core_settings.get("wallet_name", "wallet.dat")
        ctx.logger.info(
            f'Creating wallet "{wallet_name}" for {self.name.capitalize()}.'
        )
        use_descriptors = core_settings.get("use_descriptors", False)
        # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse,
        # descriptors, load_on_startup, external_signer, blsct, storage_output
        swap_client.callcoinrpc(
            coin_id,
            "createwallet",
            [
                wallet_name,
                False,
                True,
                ctx.wallet_encryption_pwd,
                False,
                use_descriptors,
                True,
                False,
                True,
                False,
            ],
        )
        swap_client.ci(coin_id).unlockWallet(
            ctx.wallet_encryption_pwd, check_seed=False
        )


prepare_module = NAVPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=NAVIO_VERSION,
    version_tag=NAVIO_VERSION_TAG,
    signers=navio_signers,
    rpc_user=NAV_RPC_USER,
    rpc_password=NAV_RPC_PWD,
    onion_port=NAV_ONION_PORT,
    creates_wallet=True,
)
