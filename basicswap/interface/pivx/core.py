# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import logging
import os
import urllib.parse

from basicswap.interface.pivx.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    getFileHash,
)

PIVX_VERSION = os.getenv("PIVX_VERSION", "5.6.1")
PIVX_VERSION_TAG = os.getenv("PIVX_VERSION_TAG", "")
pivx_signers = {"Fuzzbawls": ("0CFBDA9F60D661BA31EB5D50C1ABA64407731FD9",)}


PIVX_RPC_HOST = os.getenv("PIVX_RPC_HOST", "127.0.0.1")
PIVX_RPC_PORT = int(os.getenv("PIVX_RPC_PORT", 51473))
PIVX_ONION_PORT = int(os.getenv("PIVX_ONION_PORT", 51472))  # nDefaultPort
PIVX_RPC_USER = os.getenv("PIVX_RPC_USER", "")
PIVX_RPC_PWD = os.getenv("PIVX_RPC_PWD", "")


def downloadPIVXParams(output_dir, logger=None):
    # util/fetch-params.sh
    if logger is None:
        logger = logging.getLogger("prepare")

    if os.path.exists(output_dir):
        logger.info(f"Skipping PIVX params download, path exists: {output_dir}")
        return
    os.makedirs(output_dir)

    # Deferred import, would be circular at module load.
    from basicswap.bin.prepare import (
        downloadFile,
        popConnectionParameters,
        setConnectionParameters,
    )

    source_url = "https://download.z.cash/downloads/"
    files = {
        "sapling-spend.params": "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13",
        "sapling-output.params": "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4",
    }

    try:
        setConnectionParameters()
        for k, v in files.items():
            url = urllib.parse.urljoin(source_url, k)
            path = os.path.join(output_dir, k)
            downloadFile(url, path)

            file_hash = getFileHash(path)
            logger.info(f"{k} hash: {file_hash}")
            assert file_hash == v
    finally:
        popConnectionParameters()


class PIVXPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": PIVX_RPC_HOST,
            "rpcport": PIVX_RPC_PORT + ctx.port_offset,
            "onionport": PIVX_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "PIVX_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": False,
            "use_csv": False,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 17,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        # No version tag in the release filename
        return f"{self.name}-{self.version}-{ctx.bin_arch}.{ctx.file_ext}"

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/PIVX-Project/PIVX/releases/download/v{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        assert_filename: str = (
            f"{self.name}-{os_name}-{self.version.rsplit('.', 1)[0]}-build.assert"
        )
        return f"https://raw.githubusercontent.com/PIVX-Project/gitian.sigs/master/{self.version}{self.version_tag}-{os_dir_name}/{signing_key_name}/{assert_filename}"

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        # No version tag in the archive directory
        return f"{self.name}-{self.version}/bin/{bin_name}"

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:
        data_dir = settings["chainclients"][self.name]["datadir"]
        params_dir = os.path.join(data_dir, "pivx-params")
        downloadPIVXParams(params_dir, ctx.logger)
        PIVX_PARAMSDIR = os.getenv(
            "PIVX_PARAMSDIR",
            (
                "/data/pivx-params"
                if extra_opts.get("use_containers", False)
                else params_dir
            ),
        )
        fp.write(f"paramsdir={PIVX_PARAMSDIR}\n")
        self.writeRpcAuth(fp, salt)


prepare_module = PIVXPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=PIVX_VERSION,
    version_tag=PIVX_VERSION_TAG,
    signers=pivx_signers,
    rpc_user=PIVX_RPC_USER,
    rpc_password=PIVX_RPC_PWD,
    onion_port=PIVX_ONION_PORT,
    reseed_note=True,
)
