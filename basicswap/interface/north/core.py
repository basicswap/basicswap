# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import platform

from basicswap.interface.north.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
)

NORTH_VERSION = os.getenv("NORTH_VERSION", "30.5.5")
# SHA256SUMS is signed by a subkey, gpg reports the subkey's fingerprint
north_signers = {
    "septentrion-dev": (
        "3F0BAE0458615427B8CA935E3E242DF5E4478AE5",  # Primary key
        "895B7591E9701E99D87D58A9B932A2FBD92C626D",  # Signing subkey
    ),
}

NORTH_RPC_HOST = os.getenv("NORTH_RPC_HOST", "127.0.0.1")
NORTH_RPC_PORT = int(os.getenv("NORTH_RPC_PORT", 19954))
NORTH_PORT = int(os.getenv("NORTH_PORT", 9555))
NORTH_ONION_PORT = int(os.getenv("NORTH_ONION_PORT", 9556))
NORTH_RPC_USER = os.getenv("NORTH_RPC_USER", "")
NORTH_RPC_PWD = os.getenv("NORTH_RPC_PWD", "")

RELEASES_URL = "https://github.com/truenorth-project/truenorth/releases/download"


class NORTHPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": NORTH_RPC_HOST,
            "rpcport": NORTH_RPC_PORT + ctx.port_offset,
            "onionport": NORTH_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "NORTH_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "port": NORTH_PORT + ctx.port_offset,
            "use_segwit": True,
            "use_csv": True,
            # Consensus refuses reorgs deeper than 72 blocks, TrueNorth's
            # exchange guidance is to wait for more than 72 confirmations, 100.
            "blocks_confirmed": 100,
            "conf_target": 2,
            # Swap txns are presigned at the estimated fee rate, keep a floor
            # under estimates from a quiet mempool
            "min_relay_fee": 0.00001,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 30,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getArchName(self, ctx: PrepareContext, os_name: str, use_guix: bool) -> str:
        # Releases are published for these three platforms only
        if os_name == "osx" and platform.machine() == "arm64":
            return "macos-arm64"
        if os_name == "win" and "win64" in ctx.bin_arch:
            return "windows-x86_64"
        if os_name == "linux" and ctx.bin_arch == "x86_64-linux-gnu":
            return "linux-x86_64"
        raise ValueError(
            f"No TrueNorth Core release for {ctx.bin_arch} ({platform.machine()}), build it from source and set the bindir."
        )

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        return f"truenorth-v{self.version}{self.version_tag}-{arch_name}.{ctx.file_ext}"

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"{RELEASES_URL}/v{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        # The detached signature is SHA256SUMS.asc
        return f"{RELEASES_URL}/v{self.version}{self.version_tag}/SHA256SUMS"

    def verifyCoreHash(
        self, ctx: PrepareContext, release_path: str, assert_path: str
    ) -> str:
        release_hash: str = super().verifyCoreHash(ctx, release_path, assert_path)
        # One key signs every release, so a signed SHA256SUMS of an older
        # release is also valid.  Require the line naming this archive.
        release_filename: str = os.path.basename(release_path)
        with open(assert_path) as fp:
            for line in fp:
                parts = line.split()
                if parts == [release_hash, release_filename]:
                    return release_hash
        raise ValueError(f"{release_filename} {release_hash} is not in SHA256SUMS.")

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return [
            "https://keys.openpgp.org/vks/v1/by-fingerprint/3F0BAE0458615427B8CA935E3E242DF5E4478AE5",
        ]

    def getExtractBins(self) -> list:
        # The release archives hold truenorthd, truenorth-cli and truenorth-miner
        return [self.name + "d", self.name + "-cli"]

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        archive_dir: str = os.path.basename(release_path).removesuffix(
            "." + ctx.file_ext
        )
        return f"{archive_dir}/bin/{bin_name}"

    def writeChainSelection(self, ctx: PrepareContext, fp, chain: str) -> None:
        if chain == "testnet":
            fp.write("testnet4=1\n")
            fp.write("[testnet4]\n\n")
            return
        super().writeChainSelection(ctx, fp, chain)

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
        # The wallet default is P2QRH, swaps use P2WPKH
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")
        fp.write("fallbackfee=0.00002\n")  # 2 mie/vB, as in TrueNorth's doc/testnet.md
        self.writeRpcAuth(fp, salt)


prepare_module = NORTHPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=NORTH_VERSION,
    # Release candidates are published unsigned, prepare installs releases only
    version_tag="",
    signers=north_signers,
    rpc_user=NORTH_RPC_USER,
    rpc_password=NORTH_RPC_PWD,
    onion_port=NORTH_ONION_PORT,
    creates_wallet=True,
)
