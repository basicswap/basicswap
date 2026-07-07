# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import platform
import random
import threading

from basicswap.interface.dcr.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    exitWithError,
)

DCR_VERSION = os.getenv("DCR_VERSION", "2.1.5")
DCR_VERSION_TAG = os.getenv("DCR_VERSION_TAG", "")
decred_signers = {"decred_release": ("F516ADB7A069852C7C28A02D6D897EDF518A031D",)}

USE_PLATFORM = os.getenv("USE_PLATFORM", platform.system())

DCR_RPC_HOST = os.getenv("DCR_RPC_HOST", "127.0.0.1")
DCR_RPC_PORT = int(os.getenv("DCR_RPC_PORT", 9109))
DCR_WALLET_RPC_HOST = os.getenv("DCR_WALLET_RPC_HOST", "127.0.0.1")
DCR_WALLET_RPC_PORT = int(os.getenv("DCR_WALLET_RPC_PORT", 9209))
DCR_WALLET_PWD = os.getenv(
    "DCR_WALLET_PWD", random.randbytes(random.randint(14, 18)).hex()
)
DCR_RPC_USER = os.getenv("DCR_RPC_USER", "user")
DCR_RPC_PWD = os.getenv("DCR_RPC_PWD", random.randbytes(random.randint(14, 18)).hex())


class DCRPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        return {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon("DCR"),
            "manage_wallet_daemon": ctx.should_manage_daemon("DCR_WALLET"),
            "wallet_pwd": (DCR_WALLET_PWD if ctx.wallet_encryption_pwd == "" else ""),
            "rpchost": DCR_RPC_HOST,
            "rpcport": DCR_RPC_PORT + ctx.port_offset,
            "walletrpchost": DCR_WALLET_RPC_HOST,
            "walletrpcport": DCR_WALLET_RPC_PORT + ctx.port_offset,
            "rpcuser": DCR_RPC_USER,
            "rpcpassword": DCR_RPC_PWD,
            "datadir": os.getenv("DCR_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_csv": True,
            "use_segwit": True,
            "blocks_confirmed": 2,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_type_group": "dcr",
            "config_filename": "dcrd.conf",
            "min_relay_fee": 0.00001,
        }

    def getArchName(self, ctx: PrepareContext, os_name: str, use_guix: bool) -> str:
        if USE_PLATFORM == "Darwin":
            return "darwin-amd64"
        elif USE_PLATFORM == "Windows":
            return "windows-amd64"
        machine: str = platform.machine()
        if "arm" in machine:
            return "linux-arm"
        return "linux-amd64"

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        arch_name = self.getArchName(ctx, "", False)
        extra_opts["arch_name"] = arch_name

        release_filename = f"decred-{self.version}-{arch_name}.{ctx.file_ext}"
        release_path = os.path.join(bin_dir, release_filename)
        release_page_url = f"https://github.com/decred/decred-binaries/releases/download/v{self.version}"
        release_url = (
            release_page_url
            + "/"
            + f"decred-{arch_name}-v{self.version}.{ctx.file_ext}"
        )
        ctx.download_release(release_url, release_path, extra_opts)

        assert_filename = f"decred-v{self.version}-manifest.txt"
        assert_url = release_page_url + "/" + assert_filename
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        assert_sig_path = assert_path + ".asc"
        assert_sig_url = assert_url + ".asc"
        if not os.path.exists(assert_sig_path):
            ctx.download_file(assert_sig_url, assert_sig_path)

        return release_path, assert_path, assert_sig_path

    def getPubkeyFilename(self, signing_key_name: str) -> str:
        return f"{self.name}_release.pgp"

    def getExtractBins(self) -> list:
        return ["dcrd", "dcrwallet"]

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        return f"decred-{extra_opts['arch_name']}-v{self.version}/{bin_name}"

    def prepareDataDir(
        self,
        ctx: PrepareContext,
        settings: dict,
        chain: str,
        extra_opts: dict,
    ) -> None:
        core_settings = settings["chainclients"][self.name]
        data_dir = core_settings["datadir"]
        tor_control_password = extra_opts.get("tor_control_password", None)

        if not os.path.exists(data_dir):
            os.makedirs(data_dir)

        chainname = "simnet" if chain == "regtest" else chain

        conf_filename: str = core_settings.get("config_filename", "dcrd.conf")
        core_conf_path = os.path.join(data_dir, conf_filename)
        if os.path.exists(core_conf_path):
            exitWithError("{} exists".format(core_conf_path))
        with open(core_conf_path, "w") as fp:
            if chain != "mainnet":
                fp.write(chainname + "=1\n")
            fp.write("debuglevel=info\n")
            fp.write("notls=1\n")

            fp.write(
                "rpclisten={}:{}\n".format(
                    core_settings["rpchost"], core_settings["rpcport"]
                )
            )

            fp.write("rpcuser={}\n".format(core_settings["rpcuser"]))
            fp.write("rpcpass={}\n".format(core_settings["rpcpassword"]))

            if tor_control_password is not None:
                ctx.write_tor_settings(
                    fp, self.name, core_settings, tor_control_password
                )

        wallet_conf_filename: str = core_settings.get(
            "wallet_config_filename", "dcrwallet.conf"
        )
        wallet_conf_path = os.path.join(data_dir, wallet_conf_filename)
        if os.path.exists(wallet_conf_path):
            exitWithError(f"{wallet_conf_path} exists")
        with open(wallet_conf_path, "w") as fp:
            if chain != "mainnet":
                fp.write(chainname + "=1\n")
            fp.write("debuglevel=info\n")
            fp.write("noservertls=1\n")
            fp.write("noclienttls=1\n")

            fp.write(
                "rpcconnect={}:{}\n".format(
                    core_settings["rpchost"], core_settings["rpcport"]
                )
            )
            fp.write(
                "rpclisten={}:{}\n".format(
                    core_settings["walletrpchost"], core_settings["walletrpcport"]
                )
            )

            fp.write("username={}\n".format(core_settings["rpcuser"]))
            fp.write("password={}\n".format(core_settings["rpcpassword"]))

    def startsInitDaemon(self) -> bool:
        return False

    def getPostInitWarning(self, ctx: PrepareContext):
        if ctx.wallet_encryption_pwd != "":
            return "WARNING - dcrwallet requires the password to be entered at the first startup when encrypted.\nPlease use basicswap-run with --startonlycoin=decred and the WALLET_ENCRYPTION_PWD environment var set for the initial sync."
        return None

    def ensureWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        if core_settings["manage_wallet_daemon"] is False:
            return
        self.createWallet(ctx, swap_client, coin_id, core_settings)

    def createWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        from basicswap.interface.dcr.util import createDCRWallet
        from basicswap.bin.run import getWalletBinName

        dcr_password = (
            core_settings["wallet_pwd"]
            if ctx.wallet_encryption_pwd == ""
            else ctx.wallet_encryption_pwd
        )
        extra_args = [
            '--appdata="{}"'.format(core_settings["datadir"]),
            "--pass={}".format(dcr_password),
        ]

        filename: str = getWalletBinName(coin_id, core_settings, "dcrwallet")
        args = [
            os.path.join(core_settings["bindir"], filename),
            "--create",
        ] + extra_args
        hex_seed = swap_client.getWalletKey(coin_id, 1).hex()
        createDCRWallet(args, hex_seed, ctx.logger, threading.Event())


prepare_module = DCRPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=DCR_VERSION,
    version_tag=DCR_VERSION_TAG,
    signers=decred_signers,
    rpc_user=DCR_RPC_USER,
    rpc_password=DCR_RPC_PWD,
    creates_wallet=True,
)
