# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.xmr.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    ensurePubkey,
    exitWithError,
    getOSDirNames,
    isValidSignature,
)

MONERO_VERSION = os.getenv("MONERO_VERSION", "0.18.5.0")
MONERO_VERSION_TAG = os.getenv("MONERO_VERSION_TAG", "")
XMR_SITE_COMMIT = (
    "5e8d74229b742b54173010e3a676215b6f2fd1d7"  # Lock hashes.txt to monero version
)
monero_signers = {"binaryfate": ("81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92",)}


XMR_RPC_HOST = os.getenv("XMR_RPC_HOST", "127.0.0.1")
XMR_RPC_PORT = int(os.getenv("XMR_RPC_PORT", 29798))
XMR_ZMQ_PORT = int(os.getenv("XMR_ZMQ_PORT", 30898))
XMR_WALLET_RPC_PORT = int(os.getenv("XMR_WALLET_RPC_PORT", 29998))
XMR_WALLET_RPC_HOST = os.getenv("XMR_WALLET_RPC_HOST", "127.0.0.1")
XMR_WALLET_RPC_USER = os.getenv("XMR_WALLET_RPC_USER", "xmr_wallet_user")
XMR_WALLET_RPC_PWD = os.getenv("XMR_WALLET_RPC_PWD", "xmr_wallet_pwd")
XMR_RPC_USER = os.getenv("XMR_RPC_USER", "")
XMR_RPC_PWD = os.getenv("XMR_RPC_PWD", "")
DEFAULT_XMR_RESTORE_HEIGHT = int(os.getenv("DEFAULT_XMR_RESTORE_HEIGHT", 2245107))


class XMRPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        datadir = os.getenv("XMR_DATA_DIR", os.path.join(ctx.data_dir, self.name))
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon("XMR"),
            "manage_wallet_daemon": ctx.should_manage_daemon("XMR_WALLET"),
            "rpcport": XMR_RPC_PORT + ctx.port_offset,
            "zmqport": XMR_ZMQ_PORT + ctx.port_offset,
            "walletrpcport": XMR_WALLET_RPC_PORT + ctx.port_offset,
            "rpchost": XMR_RPC_HOST,
            "walletrpchost": XMR_WALLET_RPC_HOST,
            "walletrpcuser": XMR_WALLET_RPC_USER,
            "walletrpcpassword": XMR_WALLET_RPC_PWD,
            "walletsdir": os.getenv("XMR_WALLETS_DIR", datadir),
            "datadir": datadir,
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "blocks_confirmed": 3,
            "rpctimeout": 60,
            "walletrpctimeout": 120,
            "walletrpctimeoutlong": 600,
            "wallet_config_filename": "monero_wallet.conf",
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

        os_name, _ = getOSDirNames(ctx.bin_arch)
        if os_name == "osx":
            os_name = "mac"

        architecture = "x64"
        if "aarch64" in ctx.bin_arch:
            architecture = "armv8"
        elif "arm" in ctx.bin_arch:
            architecture = "armv7"

        release_url = f"https://downloads.getmonero.org/cli/monero-{os_name}-{architecture}-v{self.version}.{use_file_ext}"
        release_path = os.path.join(bin_dir, release_filename)
        ctx.download_release(release_url, release_path, extra_opts)

        assert_filename = f"monero-{self.version}-hashes.txt"
        # Get the hashes file as of XMR_SITE_COMMIT
        assert_url = f"https://raw.githubusercontent.com/monero-project/monero-site/{XMR_SITE_COMMIT}/downloads/hashes.txt"
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        return release_path, assert_path, None

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return [
            "https://raw.githubusercontent.com/monero-project/monero/master/utils/gpg_keys/binaryfate.asc"
        ]

    def verifyCoreSignature(
        self,
        ctx: PrepareContext,
        gpg,
        release_path: str,
        assert_path: str,
        assert_sig_path: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> None:
        # The hashes file is itself an inline-signed document, verify it directly.
        pubkey_filename = self.getPubkeyFilename(signing_key_name)
        pubkeyurls = self.getAllPubkeyUrls(ctx)

        ensurePubkey(gpg, ctx, signing_key_name, self.signers, pubkey_filename, pubkeyurls)

        with open(assert_path, "rb") as fp:
            verified = gpg.verify_file(fp)

        self.ensureValidSignatureBy(ctx, verified, signing_key_name)

    def usesWalletRpcDaemonForInit(self) -> bool:
        return True

    def getExtractBins(self) -> list:
        return [self.name + "d", self.name + "-wallet-rpc"]

    def getWalletConfFilename(self) -> str:
        return "monero_wallet.conf"

    def getSharedRingDbOpt(self) -> str:
        return "shared-ringdb-dir"

    def extractCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        release_path: str,
        extra_opts: dict,
    ) -> None:
        self.extractCoreByBasename(ctx, bin_dir, release_path, extra_opts)

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

        conf_filename: str = core_settings.get("config_filename", self.name + "d.conf")
        core_conf_path = os.path.join(data_dir, conf_filename)
        if os.path.exists(core_conf_path):
            exitWithError("{} exists".format(core_conf_path))
        with open(core_conf_path, "w") as fp:
            if chain == "regtest":
                fp.write("regtest=1\n")
                fp.write("keep-fakechain=1\n")
                fp.write("fixed-difficulty=1\n")
            else:
                fp.write("bootstrap-daemon-address=auto\n")
                fp.write("restricted-rpc=1\n")
            if chain == "testnet":
                fp.write("testnet=1\n")
            config_datadir = data_dir
            if extra_opts.get("use_containers", False) is True:
                config_datadir = "/data"
            fp.write(f"data-dir={config_datadir}\n")
            fp.write("rpc-bind-port={}\n".format(core_settings["rpcport"]))
            fp.write("rpc-bind-ip={}\n".format(ctx.rpcbind_ip))
            fp.write("zmq-rpc-bind-port={}\n".format(core_settings["zmqport"]))
            fp.write("zmq-rpc-bind-ip={}\n".format(ctx.rpcbind_ip))
            fp.write("prune-blockchain=1\n")

            if self.rpc_user != "":
                fp.write(f"rpc-login={self.rpc_user}:{self.rpc_password}\n")
            if tor_control_password is not None:
                for opt_line in ctx.monerod_proxy_config:
                    fp.write(opt_line + "\n")

        wallets_dir = core_settings.get("walletsdir", data_dir)
        if not os.path.exists(wallets_dir):
            os.makedirs(wallets_dir)

        wallet_conf_filename: str = core_settings.get(
            "wallet_config_filename", self.getWalletConfFilename()
        )
        wallet_conf_path = os.path.join(wallets_dir, wallet_conf_filename)
        if os.path.exists(wallet_conf_path):
            exitWithError("{} exists".format(wallet_conf_path))
        with open(wallet_conf_path, "w") as fp:
            config_datadir = os.path.join(data_dir, "wallets")
            if extra_opts.get("use_containers", False) is True:
                fp.write(
                    "daemon-address={}:{}\n".format(
                        core_settings["rpchost"], core_settings["rpcport"]
                    )
                )
                config_datadir = "/data"

            fp.write("no-dns=1\n")
            fp.write("rpc-bind-port={}\n".format(core_settings["walletrpcport"]))
            fp.write("rpc-bind-ip={}\n".format(ctx.rpcbind_ip))
            fp.write(f"wallet-dir={config_datadir}\n")
            fp.write("log-file={}\n".format(os.path.join(config_datadir, "wallet.log")))
            fp.write("max-log-files=5\n")
            fp.write(
                "rpc-login={}:{}\n".format(
                    core_settings["walletrpcuser"], core_settings["walletrpcpassword"]
                )
            )
            fp.write(
                "{}={}\n".format(
                    self.getSharedRingDbOpt(),
                    os.path.join(config_datadir, "shared-ringdb"),
                )
            )
            if chain == "regtest":
                fp.write("allow-mismatched-daemon-version=1\n")

            if tor_control_password is not None:
                if not core_settings["manage_daemon"]:
                    for opt_line in ctx.monero_wallet_rpc_proxy_config:
                        fp.write(opt_line + "\n")


prepare_module = XMRPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=MONERO_VERSION,
    version_tag=MONERO_VERSION_TAG,
    signers=monero_signers,
    rpc_user=XMR_RPC_USER,
    rpc_password=XMR_RPC_PWD,
)
