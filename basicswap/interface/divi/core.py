# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import secrets

from basicswap.contrib.mnemonic import Mnemonic
from basicswap.interface.divi.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    getFileHash,
)

DIVI_VERSION = os.getenv("DIVI_VERSION", "3.0.0")
DIVI_VERSION_TAG = os.getenv("DIVI_VERSION_TAG", "")

# Divi release archives carry the short commit of the build in the filename,
# but the directory inside the archive does not.
DIVI_VERSION_COMMIT = os.getenv("DIVI_VERSION_COMMIT", "9e2f76c")

DIVI_RPC_HOST = os.getenv("DIVI_RPC_HOST", "127.0.0.1")
# Not divid's own defaults (51473/51475): Divi forked PIVX without changing
# them, so those are already taken by the PIVX entry.
DIVI_RPC_PORT = int(os.getenv("DIVI_RPC_PORT", 51873))
DIVI_ONION_PORT = int(os.getenv("DIVI_ONION_PORT", 51872))
DIVI_RPC_USER = os.getenv("DIVI_RPC_USER", "")
DIVI_RPC_PWD = os.getenv("DIVI_RPC_PWD", "")

# Divi publishes no detached signature and no hashes file for its releases --
# the GitHub release is four bare archives.  Every other coin here is verified
# against a signed hash document; for Divi that is not possible, so the
# release hashes are pinned below instead and checked in verifyCoreHash.
#
# This is a weaker guarantee: the binary is trusted because its hash is in
# reviewed source, not because a named maintainer signed it.  Update this
# table deliberately, never automatically, and re-derive the values from the
# published release rather than from a local build.
#
# Computed from the v3.0.0 GitHub release assets, 2026-10-13.
DIVI_RELEASE_HASHES = {
    "divi-3.0.0-osx64-9e2f76c.tar.gz": "0f5e93f1550e116d5becf7818a08f62e0500bbd3be4ea05ec9d49f183f52b32b",
    "divi-3.0.0-RPi2-9e2f76c.tar.gz": "e584348f20d8dbb4942ec13e98769ce6d97511060584686322a3d6af4865156f",
    "divi-3.0.0-win64-9e2f76c.zip": "77feefbdc14a9321fb19e47c057bfe2e634809704cbc270b302a0d9c8463d386",
    "divi-3.0.0-x86_64-linux-gnu-9e2f76c.tar.gz": "d09933ab413335b7472b29c4c255d7affea73630b73a0d5c52aec40a63fbd276",
}


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

        # divid 3.0.0 writes no .cookie file and has no -rpcauth option, so
        # basicswap cannot fall back to cookie auth as it does for other
        # cores.  Credentials must be set in both divi.conf and the json
        # settings; generate them when none are given.
        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password
        else:
            config["rpcuser"] = "basicswap_" + secrets.token_hex(4)
            config["rpcpassword"] = secrets.token_urlsafe(24)

        return config

    def getArchName(self, ctx: PrepareContext, os_name: str, use_guix: bool) -> str:
        # Divi predates guix builds; the macOS archive is osx64, not
        # x86_64-apple-darwin.
        if os_name == "osx":
            return "osx64"
        return ctx.bin_arch

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        # Divi puts the build's short commit in the release filename.
        return (
            f"{self.name}-{self.version}-{arch_name}-"
            f"{DIVI_VERSION_COMMIT}.{ctx.file_ext}"
        )

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return (
            "https://github.com/DiviProject/Divi/releases/download/"
            f"v{self.version}{self.version_tag}/{release_filename}"
        )

    def getExtractBins(self) -> list:
        # No divi-wallet binary is shipped.
        return [self.name + "d", self.name + "-cli", self.name + "-tx"]

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        # The directory inside the archive has no commit suffix.
        return f"{self.name}-{self.version}/bin/{bin_name}"

    def hasDetachedSig(self) -> bool:
        return False

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        """Download the release only.

        There is no assert file and no signature to fetch, so both are None
        and verifyCoreHash falls back to the pinned table.
        """
        os_name, _ = self.getOSDirNamesFor(ctx)
        arch_name = self.getArchName(ctx, os_name, False)

        release_filename = self.getReleaseFilename(ctx, arch_name)
        release_path = os.path.join(bin_dir, release_filename)
        release_url = self.getReleaseUrl(ctx, release_filename)
        ctx.download_release(release_url, release_path, extra_opts)

        return release_path, None, None

    def getOSDirNamesFor(self, ctx: PrepareContext) -> tuple:
        from basicswap.interface.prepare_util import getOSDirNames

        return getOSDirNames(ctx.bin_arch)

    def verifyCoreHash(
        self, ctx: PrepareContext, release_path: str, assert_path: str
    ) -> str:
        release_filename = os.path.basename(release_path)
        expect_hash = DIVI_RELEASE_HASHES.get(release_filename)
        if expect_hash is None:
            raise ValueError(
                f"No pinned hash for {release_filename}. Divi publishes no signed "
                "hashes file, so an unlisted release cannot be verified. Add the "
                "hash to DIVI_RELEASE_HASHES in interface/divi/core.py after "
                "checking it by hand."
            )

        release_hash: str = getFileHash(release_path)
        ctx.logger.info(f"{release_filename} hash: {release_hash}")
        if release_hash != expect_hash:
            raise ValueError(
                f"Hash mismatch for {release_filename}: got {release_hash}, "
                f"expected {expect_hash}."
            )
        ctx.logger.info("Release hash matches the pinned value.")
        return release_hash

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
        ctx.logger.warning(
            "Divi publishes no signed release hashes. This binary was verified "
            "against a hash pinned in interface/divi/core.py, which is a weaker "
            "guarantee than the signature check used for every other coin."
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


# Divi has no release signers.  prepareRelease() in bin/prepare.py iterates
# over signers and fails if the loop body never runs, so one sentinel entry is
# needed; it is named so the reason shows up plainly in the prepare log:
#   "Prepare core: divi v3.0.0 - Signer: unsigned-release-pinned-hash"
# It is never used as a key name -- verifyCoreSignature is a no-op.
DIVI_NO_SIGNER = "unsigned-release-pinned-hash"


prepare_module = DIVIPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=DIVI_VERSION,
    version_tag=DIVI_VERSION_TAG,
    signers={DIVI_NO_SIGNER: ()},
    rpc_user=DIVI_RPC_USER,
    rpc_password=DIVI_RPC_PWD,
    onion_port=DIVI_ONION_PORT,
    reseed_note=True,
    creates_wallet=True,
)
