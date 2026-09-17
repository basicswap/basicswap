# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
)
from basicswap.interface.shc.chainparams import params

SHARECOIN_VERSION = os.getenv("SHARECOIN_VERSION", "1.0.0")
SHARECOIN_VERSION_TAG = os.getenv("SHARECOIN_VERSION_TAG", "")

# Single-signer release key, not a full gitian/guix multi-builder quorum -
# Sharecoin is a small project and this is a first step, not a claim of
# parity with e.g. Bitcoin Core's reproducible-build process. The key signs
# a SHA256SUMS file (clearsigned, not detached - see hasDetachedSig below)
# covering the release asset already published at v1.0.0 and already
# confirmed byte-identical (sha256) to the sharecoind/sharecoin-cli
# binaries actually running on two of the project's four live mainnet
# nodes (Oracle secondary, GCP) at the time this key was made.
sharecoin_signers = {"releases": ("86B410C06A18A1647557BB2B23AEF4BF0FB8E55E",)}

SHC_RPC_HOST = os.getenv("SHC_RPC_HOST", "127.0.0.1")
SHC_RPC_PORT = int(os.getenv("SHC_RPC_PORT", 8332))
SHC_ONION_PORT = int(os.getenv("SHC_ONION_PORT", 8443))
SHC_RPC_USER = os.getenv("SHC_RPC_USER", "")
SHC_RPC_PWD = os.getenv("SHC_RPC_PWD", "")


class SHCPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": SHC_RPC_HOST,
            "rpcport": SHC_RPC_PORT + ctx.port_offset,
            "onionport": SHC_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("SHC_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            # Real, confirmed against SHC's own chainparams.cpp (see
            # chainparams.py's header comment) - Segwit/CSV/CLTV are all
            # active from genesis on mainnet, unlike DOGE (use_segwit:
            # False in that coin's own core.py).
            "use_segwit": True,
            "use_csv": True,
            "blocks_confirmed": 2,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 29,  # SHC's bitcoin-source is a current (v29-class) Bitcoin Core fork, not an old-lineage codebase like most other integrated coins
            "min_relay_fee": 0.00001,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def hasDetachedSig(self) -> bool:
        # SHA256SUMS is itself clearsigned (gpg --clearsign), not
        # accompanied by a separate .asc/.sig file.
        return False

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        # Only linux-x64 has a verified, signed release asset so far - see
        # the sharecoin_signers comment above. Other platforms aren't
        # covered yet; fail clearly rather than guess a filename that
        # doesn't exist.
        os_name = ctx.bin_arch
        if "linux" not in os_name and "x86_64" not in os_name:
            raise NotImplementedError(
                "Only linux-x64 has a signed Sharecoin release asset so far."
            )
        return "sharecoin-linux-x64.tar.gz"

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/Share-coin/Sharecoin/releases/download/v{self.version}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        return f"https://github.com/Share-coin/Sharecoin/releases/download/v{self.version}/SHA256SUMS.asc"

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


prepare_module = SHCPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=SHARECOIN_VERSION,
    version_tag=SHARECOIN_VERSION_TAG,
    signers=sharecoin_signers,
    rpc_user=SHC_RPC_USER,
    rpc_password=SHC_RPC_PWD,
    onion_port=SHC_ONION_PORT,
    creates_wallet=True,
)
