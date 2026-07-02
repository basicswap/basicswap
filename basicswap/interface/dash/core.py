# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.dash.chainparams import params
from basicswap.interface.prepare_util import CoinPrepareModule, PrepareContext

DASH_VERSION = os.getenv("DASH_VERSION", "23.1.4")
DASH_VERSION_TAG = os.getenv("DASH_VERSION_TAG", "")
dash_signers = {
    "pasta": (
        "29590362EC878A81FD3C202B52527BEDABE87984",
        "02B8E7D002167C8B451AF05FE2F3D7916E722D38",
    ),
    "UdjinM6": ("3F5D48C9F00293CD365A3A9883592BD1400D58D9",),
}


DASH_RPC_HOST = os.getenv("DASH_RPC_HOST", "127.0.0.1")
DASH_RPC_PORT = int(os.getenv("DASH_RPC_PORT", 9998))
DASH_ONION_PORT = int(os.getenv("DASH_ONION_PORT", 9999))  # nDefaultPort
DASH_RPC_USER = os.getenv("DASH_RPC_USER", "")
DASH_RPC_PWD = os.getenv("DASH_RPC_PWD", "")


class DASHPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": DASH_RPC_HOST,
            "rpcport": DASH_RPC_PORT + ctx.port_offset,
            "onionport": DASH_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "DASH_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": False,
            "use_csv": True,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 18,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def useGuix(self) -> bool:
        return True

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        return f"dashcore-{self.version}{self.version_tag}-{arch_name}.{ctx.file_ext}"

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/dashpay/dash/releases/download/v{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        major_version = int(self.version.split(".")[0])
        sums_name = "all" if major_version >= 21 else "codesigned"
        return f"https://raw.githubusercontent.com/dashpay/guix.sigs/master/{self.version}/{signing_key_name}/{sums_name}.SHA256SUMS"

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return [
            "https://raw.githubusercontent.com/dashpay/dash/master/contrib/gitian-keys/pasta.pgp"
        ]

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        return f"dashcore-{self.version}{self.version_tag}/bin/{bin_name}"

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

    def needsPostInitPasswordChange(self) -> bool:
        # TODO: Remove workaround for Dash sethdseed error when wallet is encrypted
        return True

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
        # TODO: Remove when fixed
        if ctx.wallet_encryption_pwd != "":
            ctx.logger.warning(
                "Workaround for Dash sethdseed error if wallet is encrypted."
            )  # Errors with "AddHDChainSingle failed"
        assert use_descriptors is False
        # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
        swap_client.callcoinrpc(
            coin_id,
            "createwallet",
            [
                wallet_name,
                False,
                True,
                "",
                False,
                use_descriptors,
            ],
        )


prepare_module = DASHPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=DASH_VERSION,
    version_tag=DASH_VERSION_TAG,
    signers=dash_signers,
    rpc_user=DASH_RPC_USER,
    rpc_password=DASH_RPC_PWD,
    onion_port=DASH_ONION_PORT,
    creates_wallet=True,
)
