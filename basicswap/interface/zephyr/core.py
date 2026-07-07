# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import zipfile

from basicswap.interface.zephyr.chainparams import params
from basicswap.interface.xmr.core import XMRPrepare
from basicswap.interface.prepare_util import PrepareContext, setBinExecPermissions

ZEPHYR_VERSION = os.getenv("ZEPHYR_VERSION", "2.3.0")
ZEPHYR_VERSION_TAG = os.getenv("ZEPHYR_VERSION_TAG", "")
# Zephyr publishes neither a hashes file nor a signature, so there is no signer to pin.
# The download is verified hash-only (verifyCoreHash) against a self-hosted SHA256SUMS, the
# same maintainer-hosted-hash model BasicSwap already uses for DOGE. If Zephyr starts signing
# releases (ZephyrProtocol/zephyr#68) this becomes a real signer entry and the no-op
# verifyCoreSignature below can be dropped.
zephyr_signers = {"": ("",)}

ZEPH_RPC_HOST = os.getenv("ZEPH_RPC_HOST", "127.0.0.1")
ZEPH_RPC_PORT = int(os.getenv("ZEPH_RPC_PORT", 17767))
ZEPH_ZMQ_PORT = int(os.getenv("ZEPH_ZMQ_PORT", 17769))
ZEPH_WALLET_RPC_PORT = int(os.getenv("ZEPH_WALLET_RPC_PORT", 17768))
ZEPH_WALLET_RPC_HOST = os.getenv("ZEPH_WALLET_RPC_HOST", "127.0.0.1")
ZEPH_WALLET_RPC_USER = os.getenv("ZEPH_WALLET_RPC_USER", "zeph_wallet_user")
ZEPH_WALLET_RPC_PWD = os.getenv("ZEPH_WALLET_RPC_PWD", "zeph_wallet_pwd")
ZEPH_RPC_USER = os.getenv("ZEPH_RPC_USER", "")
ZEPH_RPC_PWD = os.getenv("ZEPH_RPC_PWD", "")


class ZEPHPrepare(XMRPrepare):
    # Zephyr is a direct Monero fork and did NOT rebrand the wallet CLI options, so it inherits
    # XMRPrepare's monero_wallet.conf / shared-ringdb-dir / prepareDataDir / getExtractBins
    # (["zephyrd", "zephyr-wallet-rpc"]) unchanged. Only the config ports, the release download
    # (a self-hosted-hash-verified official .zip), the hash-only path, and the zip extraction differ.

    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        datadir = os.getenv("ZEPH_DATA_DIR", os.path.join(ctx.data_dir, self.name))
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon("ZEPH"),
            "manage_wallet_daemon": ctx.should_manage_daemon("ZEPH_WALLET"),
            "rpcport": ZEPH_RPC_PORT + ctx.port_offset,
            "zmqport": ZEPH_ZMQ_PORT + ctx.port_offset,
            "walletrpcport": ZEPH_WALLET_RPC_PORT + ctx.port_offset,
            "rpchost": ZEPH_RPC_HOST,
            "walletrpchost": ZEPH_WALLET_RPC_HOST,
            "walletrpcuser": ZEPH_WALLET_RPC_USER,
            "walletrpcpassword": ZEPH_WALLET_RPC_PWD,
            "walletsdir": os.getenv("ZEPH_WALLETS_DIR", datadir),
            "datadir": datadir,
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "blocks_confirmed": 3,
            "rpctimeout": 60,
            "walletrpctimeout": 120,
            "walletrpctimeoutlong": 300,
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
        # Zephyr ships one official prebuilt CLI zip per release (all platforms) and no hashes
        # file, so download the zip plus our self-hosted SHA256SUMS and return no signature path.
        version = self.version
        release_filename = f"zephyr-cli-linux-v{version}.zip"
        release_url = (
            "https://github.com/ZephyrProtocol/zephyr/releases/download/"
            f"v{version}/zephyr-cli-linux-v{version}.zip"
        )
        release_path = os.path.join(bin_dir, release_filename)
        ctx.download_release(release_url, release_path, extra_opts)

        assert_filename = f"zephyr-{version}-SHA256SUMS"
        assert_url = (
            "https://raw.githubusercontent.com/Notsosmartt-cmd/zephyr-basicswap/"
            f"main/{version}/SHA256SUMS"
        )
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        return release_path, assert_path, None

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
        # No-op: Zephyr publishes no signature. Integrity is already enforced by the
        # verifyCoreHash step the caller runs before this, against our self-hosted SHA256SUMS
        # (the DOGE-style hosted-hash model). Signature verification is the pending upgrade
        # tracked in ZephyrProtocol/zephyr#68.
        ctx.logger.warning(
            "Zephyr publishes no release signature; verified by hash only "
            "(signing requested upstream, ZephyrProtocol/zephyr#68)."
        )
        return

    def extractCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        release_path: str,
        extra_opts: dict,
    ) -> None:
        # The official archive is a .zip on every platform (unlike monero/wownero, which are
        # tar.bz2 on linux), so extract from the zip regardless of host OS. Match by basename
        # because the binaries sit under a zephyr-cli-linux-v{V}/ subdir inside the zip.
        ctx.logger.info(
            f"Extracting core {self.name} v{self.version}{self.version_tag}"
        )
        extract_core_overwrite = extra_opts.get("extract_core_overwrite", True)
        bins = self.getExtractBins()

        num_exist = 0
        for b in bins:
            if os.path.exists(os.path.join(bin_dir, b)):
                num_exist += 1
        if not extract_core_overwrite and num_exist == len(bins):
            ctx.logger.info("Skipping extract, files exist.")
            return

        with zipfile.ZipFile(release_path) as fz:
            namelist = fz.namelist()
            for b in bins:
                out_path = os.path.join(bin_dir, b)
                if (not os.path.exists(out_path)) or extract_core_overwrite:
                    for entry in namelist:
                        if entry == b or entry.endswith("/" + b):
                            with open(out_path, "wb") as fout:
                                fout.write(fz.read(entry))
                            setBinExecPermissions(ctx, out_path)
                            break


prepare_module = ZEPHPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=ZEPHYR_VERSION,
    version_tag=ZEPHYR_VERSION_TAG,
    signers=zephyr_signers,
    rpc_user=ZEPH_RPC_USER,
    rpc_password=ZEPH_RPC_PWD,
)
