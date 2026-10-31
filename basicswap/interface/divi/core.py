# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import platform
import secrets

from basicswap.contrib.mnemonic import Mnemonic
from basicswap.interface.divi.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    getOSDirNames,
)

DIVI_VERSION = os.getenv("DIVI_VERSION", "0.2.7")
DIVI_VERSION_TAG = os.getenv("DIVI_VERSION_TAG", "")

DIVI_RPC_HOST = os.getenv("DIVI_RPC_HOST", "127.0.0.1")
# Not divid's own defaults (51473/51475): Divi forked PIVX without changing
# them, so those are already taken by the PIVX entry.
DIVI_RPC_PORT = int(os.getenv("DIVI_RPC_PORT", 51873))
DIVI_ONION_PORT = int(os.getenv("DIVI_ONION_PORT", 51872))
DIVI_RPC_USER = os.getenv("DIVI_RPC_USER", "")
DIVI_RPC_PWD = os.getenv("DIVI_RPC_PWD", "")

# The node is IronDivi (https://github.com/DiviDomains/IronDivi), a maintained
# implementation of the Divi protocol; Divi Core itself has had no release
# since v3.0.0 (2023).  Each IronDivi release carries a SHA256SUMS file and a
# detached signature over it, SHA256SUMS.asc, checked against the key below.
divi_signers = {"irondivi_builder": ("15F858B57C68A858DD2D131D9A25155BFBB01184",)}

# IronDivi archives are named for the Rust target they were built for.
IRONDIVI_LINUX_ARCHS = {
    "x86_64-linux-gnu": "x86_64-linux-gnu",
    "aarch64-linux-gnu": "aarch64-linux-gnu",
    "arm-linux-gnueabihf": "armv7-linux-gnueabihf",
    "i686-linux-gnu": "i686-linux-gnu",
    "ppc64le-linux-gnu": "powerpc64le-linux-gnu",
    "riscv64-linux-gnu": "riscv64-linux-gnu",
    "s390x-linux-gnu": "s390x-linux-gnu",
}

# IronDivi ships irondivid and irondivi-cli; they are installed under the
# names basicswap starts the Divi node by.  There is no divi-tx.
IRONDIVI_BINS = {"divid": "irondivid", "divi-cli": "irondivi-cli"}


class DIVIPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": DIVI_RPC_HOST,
            "rpcport": DIVI_RPC_PORT + ctx.port_offset,
            "onionport": DIVI_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv(
                "DIVI_DATA_DIR", os.path.join(ctx.data_dir, self.name)
            ),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "use_segwit": False,
            "use_csv": False,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 17,
        }

        # Divi Core has no cookie auth and no -rpcauth option, so credentials
        # are set in both divi.conf and the json settings, for any Divi node;
        # generate them when none are given.
        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password
        else:
            config["rpcuser"] = "basicswap_" + secrets.token_hex(4)
            config["rpcpassword"] = secrets.token_urlsafe(24)

        return config

    def getArchName(self, ctx: PrepareContext, os_name: str, use_guix: bool) -> str:
        if os_name == "osx":
            # prepare.py reports every Mac as osx64.
            if platform.machine() == "arm64":
                return "aarch64-macos"
            return "x86_64-macos"
        if os_name == "win":
            raise ValueError("IronDivi publishes no Windows release.")
        arch_name = IRONDIVI_LINUX_ARCHS.get(ctx.bin_arch)
        if arch_name is None:
            raise ValueError(f"IronDivi publishes no release for {ctx.bin_arch}.")
        return arch_name

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        return f"irondivi-{arch_name}.tar.gz"

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return (
            "https://github.com/DiviDomains/IronDivi/releases/download/"
            f"v{self.version}{self.version_tag}/{release_filename}"
        )

    def getPubkeyFilename(self, signing_key_name: str) -> str:
        return "irondivi_builder.pgp"

    def getExtractBins(self) -> list:
        return list(IRONDIVI_BINS)

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        archive_dir = os.path.basename(release_path)[: -len(".tar.gz")]
        return f"{archive_dir}/{IRONDIVI_BINS[bin_name]}"

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        os_name, _ = getOSDirNames(ctx.bin_arch)
        arch_name = self.getArchName(ctx, os_name, False)

        release_filename = self.getReleaseFilename(ctx, arch_name)
        release_path = os.path.join(bin_dir, release_filename)
        release_url = self.getReleaseUrl(ctx, release_filename)
        ctx.download_release(release_url, release_path, extra_opts)

        # One SHA256SUMS covers every archive of a release; keep it per
        # version so an upgrade does not check against the old list.
        assert_url = self.getReleaseUrl(ctx, "SHA256SUMS")
        assert_path = os.path.join(
            bin_dir, f"irondivi-{self.version}{self.version_tag}-SHA256SUMS"
        )
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        assert_sig_path = assert_path + ".asc"
        if not os.path.exists(assert_sig_path):
            ctx.download_file(assert_url + ".asc", assert_sig_path)

        return release_path, assert_path, assert_sig_path

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:
        # Basicswap finds swap outputs by watching an address it holds no key
        # for, but divid's listunspent omits watch-only outputs, so the
        # address index is the only way to see them.  See
        # DIVIInterface.getLockTxHeight.  txindex lets getrawtransaction read
        # transactions that are not in the wallet.
        fp.write("addressindex=1\n")
        fp.write("txindex=1\n")
        core_settings = settings["chainclients"][self.name]
        fp.write("rpcuser={}\n".format(core_settings["rpcuser"]))
        fp.write("rpcpassword={}\n".format(core_settings["rpcpassword"]))

    def _confPath(self, core_settings: dict) -> str:
        return os.path.join(
            core_settings["datadir"],
            core_settings.get("config_filename", self.name + ".conf"),
        )

    def getWalletInitDaemonArgs(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> list:
        # divid only takes a seed when it creates its wallet, on first start,
        # from -mnemonic, and only from its command line or its conf file.
        # The command line shows in the process list, so the phrase goes in
        # a conf: the whole of divi.conf plus the mnemonic line, written into
        # a pipe and passed as -conf=/dev/fd/N.  divid reads its conf once,
        # at startup, so the phrase is never written to disk.
        # The mnemonic encodes the same key initialiseWallet checks the seed
        # id against (DIVIInterface.entropyToMnemonic).
        if "config_filename" in core_settings:
            # getCoreBinArgs adds --conf after these args, and the last one
            # given wins, so the seed would never be read.
            raise ValueError("Divi wallet init does not support config_filename.")
        if os.name != "posix":
            # Without /dev/fd the only other way in is divi.conf itself, which
            # would put the seed on disk.
            raise ValueError(
                "Divi wallet init needs /dev/fd to pass the seed to divid; "
                "this platform is not supported."
            )
        key = swap_client.getWalletKey(coin_id, 1)
        conf_path = self._confPath(core_settings)
        with open(conf_path) as fp:
            conf_text = fp.read()
        if not conf_text.endswith("\n"):
            conf_text += "\n"
        conf_text += "mnemonic={}\n".format(Mnemonic("english").to_mnemonic(key))

        fd_r, fd_w = os.pipe()
        # A conf is a few hundred bytes, well under the pipe buffer, so this
        # write cannot block before divid starts reading.
        os.write(fd_w, conf_text.encode())
        os.close(fd_w)
        self._seed_fd = fd_r
        return [f"-conf=/dev/fd/{fd_r}"]

    def getWalletInitDaemonPassFds(self) -> tuple:
        fd = getattr(self, "_seed_fd", None)
        return () if fd is None else (fd,)

    def _dropSeed(self) -> None:
        fd = getattr(self, "_seed_fd", None)
        if fd is not None:
            os.close(fd)
            self._seed_fd = None

    def ensureWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        # divid creates its single wallet itself at first start (no
        # multiwallet, no createwallet).  Once RPC answers, the daemon has
        # read its conf and built the wallet, so the seed can go.
        swap_client.waitForDaemonRPC(coin_id, with_wallet=False)
        self._dropSeed()

    def needsPostInitPasswordChange(self) -> bool:
        # creates_wallet is set only to reach ensureWallet; the wallet is
        # still created unencrypted and must be encrypted afterwards.
        return True

    def getPostInitWarning(self, ctx: PrepareContext) -> str | None:
        # Called after the init daemons are stopped; a backstop in case
        # ensureWallet did not run.
        self._dropSeed()
        return None


prepare_module = DIVIPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=DIVI_VERSION,
    version_tag=DIVI_VERSION_TAG,
    signers=divi_signers,
    rpc_user=DIVI_RPC_USER,
    rpc_password=DIVI_RPC_PWD,
    onion_port=DIVI_ONION_PORT,
    reseed_note=True,
    creates_wallet=True,
)
