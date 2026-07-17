# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.firo.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    ensurePubkey,
    exitWithError,
    generate_salt,
)

FIRO_VERSION = os.getenv("FIRO_VERSION", "0.14.16.1")
FIRO_VERSION_TAG = os.getenv("FIRO_VERSION_TAG", "")
firo_signers = {"reuben": ("0186454D63E83D85EF91DE4E1290A1D0FA7EE109",)}


FIRO_RPC_HOST = os.getenv("FIRO_RPC_HOST", "127.0.0.1")
FIRO_RPC_PORT = int(os.getenv("FIRO_RPC_PORT", 8888))
FIRO_ONION_PORT = int(os.getenv("FIRO_ONION_PORT", 8168))  # nDefaultPort
FIRO_RPC_USER = os.getenv("FIRO_RPC_USER", "")
FIRO_RPC_PWD = os.getenv("FIRO_RPC_PWD", "")


class FIROPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": FIRO_RPC_HOST,
            "rpcport": FIRO_RPC_PORT + ctx.port_offset,
            "onionport": FIRO_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "FIRO_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": False,
            "use_csv": False,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 14,
            "min_relay_fee": 0.00001,
            # Firo core pays the conf fallbackfee (0.0002) when estimatefee
            # has no data, above the default max of relayfee * multiplier (4.0).
            "high_estimated_feerate_multiplier": 25.0,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        arch_name = ctx.bin_arch
        if ctx.bin_arch == "x86_64-linux-gnu":
            arch_name = "linux64"
        elif ctx.bin_arch == "osx64":
            arch_name = "macos"
        return (
            f"{self.name}-{self.version}{self.version_tag}-{arch_name}.{ctx.file_ext}"
        )

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/firoorg/firo/releases/download/v{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        return f"https://github.com/firoorg/firo/releases/download/v{self.version}{self.version_tag}/SHA256SUMS"

    def hasDetachedSig(self) -> bool:
        return False

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return ["https://firo.org/reuben.asc"]

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

        ensurePubkey(
            gpg, ctx, signing_key_name, self.signers, pubkey_filename, pubkeyurls
        )

        with open(assert_path, "rb") as fp:
            verified = gpg.verify_file(fp)

        self.ensureValidSignatureBy(
            ctx, verified, signing_key_name, filepath=assert_path
        )

    def extractCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        release_path: str,
        extra_opts: dict,
    ) -> None:
        self.extractCoreByBasename(ctx, bin_dir, release_path, extra_opts)

    def getWalletInitDaemonArgs(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> list:
        return ["-hdseed={}".format(swap_client.getWalletKey(coin_id, 1).hex())]

    def prepareDataDir(
        self,
        ctx: PrepareContext,
        settings: dict,
        chain: str,
        extra_opts: dict,
    ) -> None:
        # As the base but without the [test]/[regtest] config section headers.
        core_settings = settings["chainclients"][self.name]
        wallet_name = core_settings.get("wallet_name", "wallet.dat")
        assert len(wallet_name) > 0
        data_dir = core_settings["datadir"]
        tor_control_password = extra_opts.get("tor_control_password", None)

        if not os.path.exists(data_dir):
            os.makedirs(data_dir)

        core_conf_name: str = core_settings.get("config_filename", self.name + ".conf")
        core_conf_path = os.path.join(data_dir, core_conf_name)
        if os.path.exists(core_conf_path):
            exitWithError(f"{core_conf_path} exists")
        with open(core_conf_path, "w") as fp:
            if chain != "mainnet":
                fp.write(chain + "=1\n")

            if ctx.rpcbind_ip != "127.0.0.1":
                fp.write("rpcallowip=127.0.0.1\n")
                if ctx.docker_mode:
                    fp.write("rpcallowip=172.0.0.0/8\n")
                fp.write(f"rpcbind={ctx.rpcbind_ip}\n")

            fp.write("rpcport={}\n".format(core_settings["rpcport"]))
            fp.write("printtoconsole=0\n")
            fp.write("daemon=0\n")
            fp.write(f"wallet={wallet_name}\n")
            if "watch_wallet_name" in core_settings:
                fp.write("wallet={}\n".format(core_settings["watch_wallet_name"]))

            if tor_control_password is not None:
                ctx.write_tor_settings(
                    fp, self.name, core_settings, tor_control_password
                )

            salt = generate_salt(16)
            self.writeCoinConfig(ctx, fp, chain, salt, settings, extra_opts)

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
        fp.write("fallbackfee=0.0002\n")
        fp.write("txindex=0\n")
        fp.write("usehd=1\n")
        self.writeRpcAuth(fp, salt)


prepare_module = FIROPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=FIRO_VERSION,
    version_tag=FIRO_VERSION_TAG,
    signers=firo_signers,
    rpc_user=FIRO_RPC_USER,
    rpc_password=FIRO_RPC_PWD,
    onion_port=FIRO_ONION_PORT,
)
