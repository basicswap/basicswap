# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.capstash.chainparams import params
from basicswap.interface.prepare_util import CoinPrepareModule, PrepareContext


CAPS_VERSION = os.getenv("CAPS_VERSION", "27.1.0")
CAPS_RPC_HOST = os.getenv("CAPS_RPC_HOST", "127.0.0.1")
CAPS_RPC_PORT = int(os.getenv("CAPS_RPC_PORT", 19443))
CAPS_PORT = int(os.getenv("CAPS_PORT", 19444))
CAPS_ONION_PORT = int(os.getenv("CAPS_ONION_PORT", 19445))
CAPS_RPC_USER = os.getenv("CAPS_RPC_USER", "")
CAPS_RPC_PWD = os.getenv("CAPS_RPC_PWD", "")


class CapStashPrepare(CoinPrepareModule):
    _DOWNLOAD_DISABLED = (
        "Automatic CapStash binary download is disabled: upstream does not "
        "publish a maintainer-signed checksum chain. Build CapStash Core "
        "locally, set CAPS_BINDIR to the directory containing CapStashd and "
        "CapStash-cli, and prepare with --nocores."
    )

    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        return {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": CAPS_RPC_HOST,
            "rpcport": CAPS_RPC_PORT + ctx.port_offset,
            "onionport": CAPS_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "CAPS_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.expanduser(
                os.getenv("CAPS_BINDIR", os.path.join(ctx.bin_dir, self.name))
            ),
            "port": CAPS_PORT + ctx.port_offset,
            "config_filename": "CapStash.conf",
            "use_segwit": True,
            "use_csv": True,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version,
            "core_version_group": 27,
            "chain_lookups": "local",
        }

    def downloadCore(self, ctx, bin_dir, signing_key_name, extra_opts):
        raise RuntimeError(self._DOWNLOAD_DISABLED)

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        raise RuntimeError(self._DOWNLOAD_DISABLED)

    def getAssertUrl(self, *args, **kwargs) -> str:
        raise RuntimeError(self._DOWNLOAD_DISABLED)

    def getExtractBins(self) -> list:
        return ["CapStashd", "CapStash-cli"]

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:
        self.writeRpcAuth(fp, salt)
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")
        fp.write("fallbackfee=0.0002\n")


prepare_module = CapStashPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=CAPS_VERSION,
    version_tag="",
    signers={"local-only": ()},
    rpc_user=CAPS_RPC_USER,
    rpc_password=CAPS_RPC_PWD,
    onion_port=CAPS_ONION_PORT,
    creates_wallet=True,
)
