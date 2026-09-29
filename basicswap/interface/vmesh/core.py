# -*- coding: utf-8 -*-

# Copyright (c) 2026 The BasicSwap developers
# VargaMesh integration
# Distributed under the MIT software license.

import os

from basicswap.interface.vmesh.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
)


VMESH_VERSION = os.getenv("VMESH_VERSION", "0.2.0")
VMESH_VERSION_TAG = os.getenv("VMESH_VERSION_TAG", "")

# Intentionally empty for now.
# Automatic VMESH Core downloads remain disabled until
# reproducible release hashes / signatures are integrated.
vmesh_signers = {}

VMESH_RPC_HOST = os.getenv("VMESH_RPC_HOST", "127.0.0.1")
VMESH_RPC_PORT = int(os.getenv("VMESH_RPC_PORT", 29667))

VMESH_PORT = int(os.getenv("VMESH_PORT", 29666))
VMESH_ONION_PORT = int(os.getenv("VMESH_ONION_PORT", 29668))

VMESH_RPC_USER = os.getenv("VMESH_RPC_USER", "")
VMESH_RPC_PWD = os.getenv("VMESH_RPC_PWD", "")


class VMESHPrepare(CoinPrepareModule):

    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",

            # Setting VMESH_RPC_HOST / VMESH_RPC_PORT automatically
            # makes BasicSwap treat this as an externally managed node.
            "manage_daemon": ctx.should_manage_daemon(self.ticker),

            "rpchost": VMESH_RPC_HOST,
            "rpcport": VMESH_RPC_PORT + ctx.port_offset,

            "onionport": VMESH_ONION_PORT + ctx.port_offset,

            "datadir": os.getenv(
                "VMESH_DATA_DIR",
                os.path.join(ctx.data_dir, self.name),
            ),

            "bindir": os.getenv(
                "VMESH_BINDIR",
                os.path.join(ctx.bin_dir, self.name),
            ),

            "port": VMESH_PORT + ctx.port_offset,

            "use_segwit": True,
            "use_csv": True,

            "blocks_confirmed": 1,
            "conf_target": 2,

            "core_version_no": self.version + self.version_tag,

            # VargaMesh v0.2.0 is based on modern Bitcoin Core RPC /
            # descriptor-wallet behaviour.
            "core_version_group": 28,

            "chain_lookups": "local",
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseUrl(
        self,
        ctx: PrepareContext,
        release_filename: str,
    ) -> str:
        raise RuntimeError(
            "Automatic VargaMesh Core download is not enabled yet. "
            "Use --nocores and a verified local VargaMesh Core binary."
        )

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        raise RuntimeError(
            "Automatic VargaMesh Core signature retrieval is not enabled yet."
        )

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:

        # Native SegWit for all BasicSwap-generated addresses.
        fp.write("addresstype=bech32\n")
        fp.write("changetype=bech32\n")

        # VMESH mainnet currently advertises minrelaytxfee 0.00000100.
        fp.write("fallbackfee=0.00000100\n")


prepare_module = VMESHPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=VMESH_VERSION,
    version_tag=VMESH_VERSION_TAG,
    signers=vmesh_signers,
    rpc_user=VMESH_RPC_USER,
    rpc_password=VMESH_RPC_PWD,
    onion_port=VMESH_ONION_PORT,
    creates_wallet=True,
)
