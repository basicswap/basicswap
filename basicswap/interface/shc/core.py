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

# NOTE, real open item: Sharecoin's tagged GitHub releases
# (github.com/Share-coin/Sharecoin/releases) currently ship a bundled
# portable wallet+miner package (sharecoin-portable-win64.zip), not a bare
# daemon/CLI binary in the gitian/guix-style naming BasicSwap's automatic
# prepare/download system expects (see getReleaseUrl/getAssertUrl below -
# both are best-effort guesses at a URL PATTERN, not confirmed to actually
# resolve to a real matching asset yet). Until a proper daemon-only release
# exists, run BasicSwap against an already-installed/already-running
# sharecoind instead: set manage_daemon=False (or leave SHC out of
# should_manage_daemon's managed list) and point SHC_RPC_HOST/PORT/USER/PWD
# at a real node - this project already runs 4 real synced mainnet nodes,
# so this isn't a hypothetical fallback, it's the realistic near-term path.
SHARECOIN_VERSION = os.getenv("SHARECOIN_VERSION", "1.0.0")
SHARECOIN_VERSION_TAG = os.getenv("SHARECOIN_VERSION_TAG", "")
# TODO real open item: BasicSwap release-signature verification expects a
# signer key fingerprint here (see e.g. doge_signers/litecoin_signers in
# the sibling core.py files) - Sharecoin doesn't currently gitian/guix-sign
# releases at all, so there's no real fingerprint to put here yet. Left
# empty rather than fabricated; this needs a real decision (start signing
# releases, or ask BasicSwap maintainers how unsigned-release coins are
# handled elsewhere in the project) before this is submission-ready.
sharecoin_signers = {}

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

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        # Best-effort URL pattern, NOT confirmed to resolve - see the
        # module-level note above. Sharecoin's actual v1.0.0 release asset
        # is a differently-named bundled package, not `release_filename`
        # in BasicSwap's expected per-platform daemon-binary form.
        return f"https://github.com/Share-coin/Sharecoin/releases/download/v{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        # No real gitian/guix attestation file exists yet - see the
        # sharecoin_signers note above. Placeholder pattern only.
        return f"https://raw.githubusercontent.com/Share-coin/guix.sigs/sharecoin/{self.version}/{signing_key_name}/noncodesigned.SHA256SUMS"

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
