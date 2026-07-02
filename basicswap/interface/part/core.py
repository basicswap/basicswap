# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import os

from basicswap.interface.part.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    getOSDirNames,
)

PARTICL_REPO = os.getenv("PARTICL_REPO", "tecnovert")
PARTICL_VERSION = os.getenv("PARTICL_VERSION", "27.2.4.0")
PARTICL_VERSION_TAG = os.getenv("PARTICL_VERSION_TAG", "")
PARTICL_LINUX_EXTRA = os.getenv("PARTICL_LINUX_EXTRA", "nousb")
particl_signers = {"tecnovert": ("8E517DC12EC1CC37F6423A8A13F13651C9CF0D6B",)}


PART_ZMQ_PORT = int(os.getenv("PART_ZMQ_PORT", 20792))
PART_RPC_HOST = os.getenv("PART_RPC_HOST", "127.0.0.1")
PART_RPC_PORT = int(os.getenv("PART_RPC_PORT", 19792))
PART_ONION_PORT = int(os.getenv("PART_ONION_PORT", 51734))
PART_RPC_USER = os.getenv("PART_RPC_USER", "")
PART_RPC_PWD = os.getenv("PART_RPC_PWD", "")


class PARTPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": PART_RPC_HOST,
            "rpcport": PART_RPC_PORT + ctx.port_offset,
            "onionport": PART_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "PART_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "blocks_confirmed": 2,
            "override_feerate": 0.002,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 23,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getArchName(self, ctx: PrepareContext, os_name: str, use_guix: bool) -> str:
        if os_name == "osx" and use_guix:
            return "x86_64-apple-darwin18"
        return ctx.bin_arch

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        os_name, _ = getOSDirNames(ctx.bin_arch)
        filename_extra = PARTICL_LINUX_EXTRA if os_name == "linux" else ""
        if filename_extra == "":
            return super().getReleaseFilename(ctx, arch_name)
        if self.useGuix():
            return f"{self.name}-{self.version}{self.version_tag}_{filename_extra}-{arch_name}.{ctx.file_ext}"
        return f"{self.name}-{self.version}{self.version_tag}-{arch_name}_{filename_extra}.{ctx.file_ext}"

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://github.com/{PARTICL_REPO}/particl-core/releases/download/v{self.version}{self.version_tag}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        if use_guix:
            return f"https://raw.githubusercontent.com/{PARTICL_REPO}/guix.sigs/master/{self.version}/{signing_key_name}/all.SHA256SUMS"

        assert_filename: str = f"{self.name}-{os_name}-{self.version}-build.assert"
        return f"https://raw.githubusercontent.com/{PARTICL_REPO}/gitian.sigs/master/{self.version}{self.version_tag}-{os_dir_name}/{signing_key_name}/{assert_filename}"

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        if "_nousb-" in release_path:
            return f"{self.name}-{self.version}{self.version_tag}_nousb/bin/{bin_name}"
        return super().getExtractPath(ctx, bin_name, release_path, extra_opts)

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:
        fp.write("deprecatedrpc=create_bdb\n")
        fp.write("debugexclude=libevent\n")
        if chain == "mainnet":
            fp.write("rpcdoccheck=0\n")
        fp.write("zmqpubsmsg=tcp://{}:{}\n".format(ctx.rpcbind_ip, settings["zmqport"]))
        fp.write(
            "zmqpubhashwtx=tcp://{}:{}\n".format(ctx.rpcbind_ip, settings["zmqport"])
        )
        zmqsecret = extra_opts.get("zmqsecret", None)
        if zmqsecret:
            try:
                _ = base64.b64decode(zmqsecret)
            except Exception as e:  # noqa: F841
                raise ValueError("zmqsecret must be base64 encoded")
            fp.write(f"serverkeyzmq={zmqsecret}\n")
        fp.write("spentindex=1\n")
        fp.write("txindex=1\n")
        fp.write("staking=0\n")
        self.writeRpcAuth(fp, salt)

    def getWalletInitDaemonArgs(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> list:
        return ["-nofindpeers", "-nostaking"]

    def loadMasterMnemonic(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        mnemonic_in,
    ) -> tuple:
        ctx.logger.info("Loading Particl mnemonic")
        generated: bool = False
        if mnemonic_in is None:
            mnemonic_in = swap_client.callcoinrpc(coin_id, "mnemonic", ["new"])[
                "mnemonic"
            ]
            generated = True
        swap_client.callcoinrpc(coin_id, "extkeyimportmaster", [mnemonic_in])
        return mnemonic_in, generated

    def createWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        wallet_name = core_settings.get("wallet_name", "wallet.dat")
        ctx.logger.info(
            f'Creating wallet "{wallet_name}" for {self.name.capitalize()}.'
        )
        swap_client.callcoinrpc(
            coin_id,
            "createwallet",
            [
                wallet_name,
            ],
        )
        if ctx.wallet_encryption_pwd != "":
            ci = swap_client.ci(coin_id)
            ci.changeWalletPassword(
                "", ctx.wallet_encryption_pwd, check_seed_if_encrypt=False
            )
            ci.unlockWallet(ctx.wallet_encryption_pwd)


prepare_module = PARTPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=PARTICL_VERSION,
    version_tag=PARTICL_VERSION_TAG,
    signers=particl_signers,
    rpc_user=PART_RPC_USER,
    rpc_password=PART_RPC_PWD,
    onion_port=PART_ONION_PORT,
    creates_wallet=True,
    provides_master_key=True,
)
