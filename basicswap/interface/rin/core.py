# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.rin.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    getOSDirNames,
)

RINCOIN_VERSION = os.getenv("RINCOIN_VERSION", "1.1.0")
RINCOIN_VERSION_TAG = os.getenv("RINCOIN_VERSION_TAG", "")
# SHA256SUMS.asc is made with the signing subkey 0ED99C46...; the primary key
# is listed as well so an imported key is found by its primary fingerprint.
rincoin_signers = {
    "aevust": (
        "0ED99C46B2192E375381EF4AC5BEF8A9FA06C16F",
        "ED20B6354EE4526D01F83B538B6E3BF45C714ECA",
    ),
}

RIN_RPC_HOST = os.getenv("RIN_RPC_HOST", "127.0.0.1")
RIN_RPC_PORT = int(os.getenv("RIN_RPC_PORT", 19956))
RIN_PORT = int(os.getenv("RIN_PORT", 19955))
RIN_ONION_PORT = int(os.getenv("RIN_ONION_PORT", 19957))
RIN_RPC_USER = os.getenv("RIN_RPC_USER", "")
RIN_RPC_PWD = os.getenv("RIN_RPC_PWD", "")

RIN_RELEASE_URL = "https://github.com/Rin-coin/rincoin/releases/download"
RIN_RELEASE_ARCHS = ("x86_64-linux-gnu", "aarch64-linux-gnu", "win64")


class RINPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": RIN_RPC_HOST,
            "rpcport": RIN_RPC_PORT + ctx.port_offset,
            "onionport": RIN_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("RIN_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "port": RIN_PORT + ctx.port_offset,
            "use_segwit": True,
            "use_csv": True,
            "blocks_confirmed": 12,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 20,
            "min_relay_fee": 0.00001,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseTag(self) -> str:
        # A candidate has files named 1.1.0rc3 and the tag v1.1.0-rc3.
        if self.version_tag != "":
            return f"v{self.version}-{self.version_tag}"
        return f"v{self.version}"

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        if arch_name not in RIN_RELEASE_ARCHS:
            raise ValueError(
                f"No Rincoin Core release for {arch_name}, "
                f"available: {', '.join(RIN_RELEASE_ARCHS)}"
            )
        return super().getReleaseFilename(ctx, arch_name)

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"{RIN_RELEASE_URL}/{self.getReleaseTag()}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        return f"{RIN_RELEASE_URL}/{self.getReleaseTag()}/SHA256SUMS"

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        os_name, os_dir_name = getOSDirNames(ctx.bin_arch)
        arch_name = self.getArchName(ctx, os_name, False)

        release_filename = self.getReleaseFilename(ctx, arch_name)
        release_path = os.path.join(bin_dir, release_filename)
        release_url = self.getReleaseUrl(ctx, release_filename)
        ctx.download_release(release_url, release_path, extra_opts)

        # The manifest has the same name, SHA256SUMS, in each release that has
        # one.  Keep the version in the local name, so that a cached manifest
        # is never reused for another release.
        assert_url = self.getAssertUrl(
            ctx, os_name, os_dir_name, signing_key_name, False
        )
        assert_path = os.path.join(
            bin_dir, f"{self.name}-{self.version}{self.version_tag}-SHA256SUMS"
        )
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        assert_sig_path = assert_path + ".asc"
        if not os.path.exists(assert_sig_path):
            ctx.download_file(assert_url + ".asc", assert_sig_path)

        return release_path, assert_path, assert_sig_path

    def verifyCoreHash(
        self, ctx: PrepareContext, release_path: str, assert_path: str
    ) -> str:
        release_hash: str = super().verifyCoreHash(ctx, release_path, assert_path)
        # The key signs more than one release and the archives share one
        # layout.  Require the line of this file, so that the SHA256SUMS of
        # another release is refused.
        release_filename: str = os.path.basename(release_path)
        with open(assert_path, "rb") as fp:
            for line in fp:
                fields = line.decode("utf-8", "replace").split()
                if (
                    len(fields) == 2
                    and fields[0] == release_hash
                    and fields[1].lstrip("*") == release_filename
                ):
                    return release_hash
        raise ValueError(
            f"Error: {release_filename} with hash {release_hash} not found in assert file."
        )

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return [
            "https://keys.openpgp.org/vks/v1/by-fingerprint/ED20B6354EE4526D01F83B538B6E3BF45C714ECA"
        ]

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        # The release archives hold the binaries under bin/, with no top
        # level directory.
        return f"bin/{bin_name}"

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
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")
        self.writeRpcAuth(fp, salt)


prepare_module = RINPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=RINCOIN_VERSION,
    version_tag=RINCOIN_VERSION_TAG,
    signers=rincoin_signers,
    rpc_user=RIN_RPC_USER,
    rpc_password=RIN_RPC_PWD,
    onion_port=RIN_ONION_PORT,
    creates_wallet=True,
)
