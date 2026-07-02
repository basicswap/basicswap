# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import platform

from basicswap.interface.wow.chainparams import params
from basicswap.interface.xmr.core import XMRPrepare
from basicswap.interface.prepare_util import PrepareContext

WOWNERO_VERSION = os.getenv("WOWNERO_VERSION", "0.11.3.0")
WOWNERO_VERSION_TAG = os.getenv("WOWNERO_VERSION_TAG", "")
WOW_SITE_COMMIT = (
    "5400b3fa3e76eab2788d8e93edbb70846a62e57a"  # Lock hashes.txt to wownero version
)
wownero_signers = {"wowario": ("AB3A2F725818FCFF2794841C793504B449C69220",)}

USE_PLATFORM = os.getenv("USE_PLATFORM", platform.system())

WOW_RPC_HOST = os.getenv("WOW_RPC_HOST", "127.0.0.1")
WOW_RPC_PORT = int(os.getenv("WOW_RPC_PORT", 34598))
WOW_ZMQ_PORT = int(os.getenv("WOW_ZMQ_PORT", 34698))
WOW_WALLET_RPC_PORT = int(os.getenv("WOW_WALLET_RPC_PORT", 34798))
WOW_WALLET_RPC_HOST = os.getenv("WOW_WALLET_RPC_HOST", "127.0.0.1")
WOW_WALLET_RPC_USER = os.getenv("WOW_WALLET_RPC_USER", "wow_wallet_user")
WOW_WALLET_RPC_PWD = os.getenv("WOW_WALLET_RPC_PWD", "wow_wallet_pwd")
WOW_RPC_USER = os.getenv("WOW_RPC_USER", "")
WOW_RPC_PWD = os.getenv("WOW_RPC_PWD", "")
DEFAULT_WOW_RESTORE_HEIGHT = int(os.getenv("DEFAULT_WOW_RESTORE_HEIGHT", 450000))


class WOWPrepare(XMRPrepare):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        datadir = os.getenv("WOW_DATA_DIR", os.path.join(ctx.data_dir, self.name))
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon("WOW"),
            "manage_wallet_daemon": ctx.should_manage_daemon("WOW_WALLET"),
            "rpcport": WOW_RPC_PORT + ctx.port_offset,
            "zmqport": WOW_ZMQ_PORT + ctx.port_offset,
            "walletrpcport": WOW_WALLET_RPC_PORT + ctx.port_offset,
            "rpchost": WOW_RPC_HOST,
            "walletrpchost": WOW_WALLET_RPC_HOST,
            "walletrpcuser": WOW_WALLET_RPC_USER,
            "walletrpcpassword": WOW_WALLET_RPC_PWD,
            "walletsdir": os.getenv("WOW_WALLETS_DIR", datadir),
            "datadir": datadir,
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "blocks_confirmed": 2,
            "rpctimeout": 60,
            "walletrpctimeout": 120,
            "walletrpctimeoutlong": 300,
            "core_version_no": self.version + self.version_tag,
            "core_type_group": "xmr",
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        use_file_ext = "tar.bz2" if ctx.file_ext == "tar.gz" else ctx.file_ext
        release_filename = f"{self.name}-{self.version}-{ctx.bin_arch}.{use_file_ext}"

        architecture = ctx.bin_arch
        machine: str = platform.machine()
        if USE_PLATFORM == "Darwin":
            if "arm64" in machine:
                architecture = "aarch64-apple-darwin11"
            else:
                architecture = "x86_64-apple-darwin11"
        elif USE_PLATFORM == "Windows":
            if machine == "AMD64":
                machine = "x86_64"
            architecture = machine + "-w64-mingw32"

        release_url = f"https://codeberg.org/wownero/wownero/releases/download/v{self.version}/wownero-{architecture}-v{self.version}.{use_file_ext}"
        release_path = os.path.join(bin_dir, release_filename)
        ctx.download_release(release_url, release_path, extra_opts)

        assert_filename = f"wownero-{self.version}-hashes.txt"
        # Get the hashes file as of WOW_SITE_COMMIT
        assert_url = f"https://codeberg.org/wownero/wownero.org-website/raw/commit/{WOW_SITE_COMMIT}/hashes.txt"
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        return release_path, assert_path, None

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return [
            "https://codeberg.org/wownero/wownero/raw/branch/master/utils/gpg_keys/wowario.asc"
        ]

    def getWalletConfFilename(self) -> str:
        return self.name + "-wallet-rpc.conf"

    def getSharedRingDbOpt(self) -> str:
        return "wow-shared-ringdb-dir"


prepare_module = WOWPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=WOWNERO_VERSION,
    version_tag=WOWNERO_VERSION_TAG,
    signers=wownero_signers,
    rpc_user=WOW_RPC_USER,
    rpc_password=WOW_RPC_PWD,
)
