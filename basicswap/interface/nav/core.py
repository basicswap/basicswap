# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os

from basicswap.interface.nav.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    ensurePubkey,
    exitWithError,
    getFileHash,
    getOSDirNames,
    isValidSignature,
)
from basicswap.contrib.rpcauth import generate_salt

NAV_VERSION = os.getenv("NAV_VERSION", "7.0.3")
NAV_VERSION_TAG = os.getenv("NAV_VERSION_TAG", "")
nav_signers = {"nav_builder": ("1BF9B51BAED51BA0B3A174EE2782262BF6E7FADB",)}

NAV_RPC_HOST = os.getenv("NAV_RPC_HOST", "127.0.0.1")
NAV_RPC_PORT = int(os.getenv("NAV_RPC_PORT", 44444))
NAV_ONION_PORT = int(os.getenv("NAV_ONION_PORT", 8334))  # TODO?
NAV_RPC_USER = os.getenv("NAV_RPC_USER", "")
NAV_RPC_PWD = os.getenv("NAV_RPC_PWD", "")


class NAVPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": NAV_RPC_HOST,
            "rpcport": NAV_RPC_PORT + ctx.port_offset,
            "onionport": NAV_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("NAV_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": True,
            "use_csv": True,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 18,
            "chain_lookups": "local",
            "startup_tries": 40,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/navcoin/navcoin-core/releases/download/{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        return f"https://github.com/navcoin/navcoin-core/releases/download/{self.version}{self.version_tag}/SHA256SUM_{self.version}.asc"

    def getPubkeyFilename(self, signing_key_name: str) -> str:
        return "navcoin_builder.pgp"

    def hasDetachedSig(self) -> bool:
        return False

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        use_guix: bool = self.useGuix()
        os_name, os_dir_name = getOSDirNames(ctx.bin_arch)
        arch_name = self.getArchName(ctx, os_name, use_guix)

        release_filename = self.getReleaseFilename(ctx, arch_name)
        release_path = os.path.join(bin_dir, release_filename)
        release_url = self.getReleaseUrl(ctx, release_filename)
        ctx.download_release(release_url, release_path, extra_opts)

        assert_url = self.getAssertUrl(
            ctx, os_name, os_dir_name, signing_key_name, use_guix
        )
        assert_filename = (
            f"{self.name}-{os_name}-{self.version}-build-{signing_key_name}.assert"
        )
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        assert_sig_filename = (
            f"{self.name}-{os_name}-{self.version}-build-{signing_key_name}.assert.sig"
        )
        assert_sig_path = os.path.join(bin_dir, assert_sig_filename)
        if not os.path.exists(assert_sig_path):
            assert_sig_url = assert_url + ".sig"
            ctx.download_file(assert_sig_url, assert_sig_path)

        return release_path, assert_path, assert_sig_path

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
        pubkey_filename = self.getPubkeyFilename(signing_key_name)
        pubkeyurls = self.getAllPubkeyUrls(ctx)

        ensurePubkey(gpg, ctx, signing_key_name, self.signers, pubkey_filename, pubkeyurls)

        with open(assert_sig_path, "rb") as fp:
            verified = gpg.verify_file(fp)

        self.ensureValidSignatureBy(ctx, verified, signing_key_name)

        # .sig file is not a detached signature, recheck release hash in decrypted data
        release_hash = getFileHash(release_path)
        ctx.logger.warning("Double checking Navcoin release hash.")
        with open(assert_sig_path, "rb") as fp:
            decrypted = gpg.decrypt_file(fp)
            assert release_hash in str(decrypted)

    def prepareDataDir(
        self,
        ctx: PrepareContext,
        settings: dict,
        chain: str,
        extra_opts: dict,
    ) -> None:
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
                chainname = "devnet" if chain == "regtest" else chain
                fp.write(chainname + "=1\n")

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
        self.writeRpcAuth(fp, salt)


prepare_module = NAVPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=NAV_VERSION,
    version_tag=NAV_VERSION_TAG,
    signers=nav_signers,
    rpc_user=NAV_RPC_USER,
    rpc_password=NAV_RPC_PWD,
    onion_port=NAV_ONION_PORT,
)
