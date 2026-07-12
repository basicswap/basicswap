# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import hashlib
import mmap
import os
import stat
import sys
import tarfile
import zipfile

from dataclasses import dataclass
from typing import Callable, Optional

from basicswap.contrib.rpcauth import generate_salt, password_to_hmac
from basicswap.util.network import make_reporthook


@dataclass
class PrepareContext:
    """Context passed from bin/prepare.py into per-coin functions in interface/*/core.py."""

    data_dir: str
    bin_dir: str
    port_offset: int
    should_manage_daemon: Callable[[str], bool]
    bin_arch: str = ""
    file_ext: str = ""
    download_release: Optional[Callable] = None
    download_file: Optional[Callable] = None
    import_pubkey: Optional[Callable] = None
    logger: Optional[object] = None  # logging.Logger
    rpcbind_ip: str = "127.0.0.1"
    docker_mode: bool = False
    write_tor_settings: Optional[Callable] = None
    gnupg: Optional[Callable] = None
    gpg_homedir: str = ""
    wallet_encryption_pwd: str = ""
    monerod_proxy_config: Optional[list] = None
    monero_wallet_rpc_proxy_config: Optional[list] = None


def createGPG(gnupg_module, homedir):
    return gnupg_module.GPG(gnupghome=homedir)


def exitWithError(error_msg: str):
    sys.stderr.write(f"Error: {error_msg}, exiting.\n")
    sys.exit(1)


def getOSDirNames(bin_arch: str) -> tuple:
    # Returns (os_name, os_dir_name)
    if "osx" in bin_arch:
        return "osx", "osx-unsigned"
    if "win32" in bin_arch or "win64" in bin_arch:
        return "win", "win-unsigned"
    return "linux", "linux"


def setBinExecPermissions(ctx: PrepareContext, out_path: str) -> None:
    try:
        os.chmod(out_path, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)
    except Exception as e:
        ctx.logger.warning(f"Unable to set file permissions: {e}, for {out_path}")


def isValidSignature(result) -> bool:
    if result.valid is False and (
        result.status == "signature valid"
        and result.key_status == "signing key has expired"
    ):
        return True
    return result.valid


def havePubkey(gpg, key_id: str) -> bool:
    for key in gpg.list_keys():
        if key["fingerprint"] == key_id:
            return True
    return False


def ensureFileHashInFile(release_hash: str, assert_path: str, logger=None) -> None:
    with (
        open(assert_path, "rb", 0) as fp,
        mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as s,
    ):
        if s.find(bytes(release_hash, "utf-8")) == -1:
            raise ValueError(
                f"Error: Release hash {release_hash} not found in assert file."
            )
        if logger is not None:
            logger.info("Found release hash in assert file.")


def getFileHash(file_path: str, print_progress: bool = False, logger=None) -> str:
    h = hashlib.sha256()
    if print_progress:
        reporthook = make_reporthook(0, logger)
        total_size: int = os.stat(file_path).st_size

    block_num: int = 0
    block_size: int = 1024 * 1024
    with open(file_path, "rb") as fp:
        while data_chunk := fp.read(block_size):
            h.update(data_chunk)
            block_num += 1
            if print_progress:
                reporthook(block_num, block_size, total_size)
    return h.hexdigest()


@dataclass
class CoinPrepareModule:
    """Base class for the per-coin provisioning interface exported by interface/*/core.py.

    Each coin subclasses this, overrides the methods and exports an instance
    named prepare_module for bin/prepare.py.
    """

    name: str
    version: str
    version_tag: str
    signers: dict  # signer name -> expected key fingerprints
    ticker: str = ""
    rpc_user: str = ""
    rpc_password: str = ""
    onion_port: int = 0
    creates_wallet: bool = False  # Create the initial wallet through the core daemon
    provides_master_key: bool = False  # Other coin wallets are seeded from this coin
    reseed_note: bool = False  # Wallet can be initialised later from the ui

    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        raise NotImplementedError()

    def useGuix(self) -> bool:
        major_version = int(self.version.split(".")[0])
        return major_version >= 22

    def getArchName(self, ctx: PrepareContext, os_name: str, use_guix: bool) -> str:
        if os_name == "osx" and use_guix:
            return "x86_64-apple-darwin"
        return ctx.bin_arch

    def getReleaseFilename(self, ctx: PrepareContext, arch_name: str) -> str:
        return (
            f"{self.name}-{self.version}{self.version_tag}-{arch_name}.{ctx.file_ext}"
        )

    def hasDetachedSig(self) -> bool:
        # False for coins whose hashes file is itself the signed document.
        return True

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str):
        # Return one url string or a list of fallback urls
        raise NotImplementedError()

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        raise NotImplementedError()

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        """Download the core release and hash assert files into bin_dir.

        Default implementation covers gitian/guix style releases: a release
        archive plus a hashes file with a detached signature.  Coins with a
        different release layout override this method.
        Returns (release_path, assert_path, assert_sig_path).
        """
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

        # Name assert files with the full version and signer
        assert_filename = (
            f"{self.name}-{os_name}-{self.version}-build-{signing_key_name}.assert"
        )
        assert_path = os.path.join(bin_dir, assert_filename)
        if not os.path.exists(assert_path):
            ctx.download_file(assert_url, assert_path)

        if not self.hasDetachedSig():
            return release_path, assert_path, None

        assert_sig_url = assert_url + (".asc" if use_guix else ".sig")
        assert_sig_path = assert_path + ".sig"
        if not os.path.exists(assert_sig_path):
            ctx.download_file(assert_sig_url, assert_sig_path)

        return release_path, assert_path, assert_sig_path

    def getPubkeyFilename(self, signing_key_name: str) -> str:
        return f"{self.name}_{signing_key_name}.pgp"

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return []

    def getAllPubkeyUrls(self, ctx: PrepareContext) -> list:
        pubkeyurls = self.getPubkeyUrls(ctx)
        if self.ticker != "":
            extra_pubkey_url: str = os.getenv(f"{self.ticker}_ADD_PUBKEY_URL", "")
            if extra_pubkey_url != "":
                pubkeyurls.append(extra_pubkey_url)
        return pubkeyurls

    def ensureValidSignatureBy(
        self, ctx: PrepareContext, result, signing_key_name: str, signers=None
    ) -> None:
        if signers is None:
            signers = self.signers
        if not isValidSignature(result):
            raise ValueError("Signature verification failed.")

        if result.fingerprint not in signers[signing_key_name]:
            raise ValueError(
                "Signature made by unexpected key fingerprint: " + result.fingerprint
            )

        ctx.logger.debug(
            f"Found valid signature by {signing_key_name} ({result.key_id})."
        )

    def verifyCoreHash(
        self, ctx: PrepareContext, release_path: str, assert_path: str
    ) -> str:
        release_hash: str = getFileHash(release_path)
        ctx.logger.info(f"{os.path.basename(release_path)} hash: {release_hash}")
        ensureFileHashInFile(release_hash, assert_path, ctx.logger)
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
        """Verify the downloaded release, raises on failure.

        Default implementation covers a detached signature over the assert
        file.  Coins with inline-signed hash files override this method,
        ending with an ensureValidSignatureBy call.
        """
        pubkey_filename = self.getPubkeyFilename(signing_key_name)
        pubkeyurls = self.getAllPubkeyUrls(ctx)

        with open(assert_sig_path, "rb") as fp:
            verified = gpg.verify_file(fp, assert_path)
        if not isValidSignature(verified) and verified.username is None:
            ctx.logger.warning("Signature made by unknown key.")
            ctx.import_pubkey(gpg, pubkey_filename, pubkeyurls)
            with open(assert_sig_path, "rb") as fp:
                verified = gpg.verify_file(fp, assert_path)

        self.ensureValidSignatureBy(ctx, verified, signing_key_name)

    def getExtractBins(self) -> list:
        bins = [self.name + "d", self.name + "-cli", self.name + "-tx"]
        versions = self.version.split(".")
        if int(versions[0]) >= 22 or int(versions[1]) >= 19:
            bins.append(self.name + "-wallet")
        return bins

    def getExtractPath(
        self,
        ctx: PrepareContext,
        bin_name: str,
        release_path: str,
        extra_opts: dict,
    ) -> str:
        return f"{self.name}-{self.version}{self.version_tag}/bin/{bin_name}"

    def extractCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        release_path: str,
        extra_opts: dict,
    ) -> None:
        """Extract the core binaries from the release archive into bin_dir.

        Default implementation covers archives laid out as
        name-version/bin/binaries.  Coins with a different archive layout
        override this method.
        """
        ctx.logger.info(
            f"Extracting core {self.name} v{self.version}{self.version_tag}"
        )
        extract_core_overwrite = extra_opts.get("extract_core_overwrite", True)
        bins = self.getExtractBins()

        if "win32" in ctx.bin_arch or "win64" in ctx.bin_arch:
            with zipfile.ZipFile(release_path) as fz:
                for b in bins:
                    b += ".exe"
                    out_path = os.path.join(bin_dir, b)
                    if (not os.path.exists(out_path)) or extract_core_overwrite:
                        with open(out_path, "wb") as fout:
                            fout.write(
                                fz.read(
                                    self.getExtractPath(
                                        ctx, b, release_path, extra_opts
                                    )
                                )
                            )
                        setBinExecPermissions(ctx, out_path)
            return
        with tarfile.open(release_path) as ft:
            for b in bins:
                out_path = os.path.join(bin_dir, b)
                if not os.path.exists(out_path) or extract_core_overwrite:
                    with (
                        open(out_path, "wb") as fout,
                        ft.extractfile(
                            self.getExtractPath(ctx, b, release_path, extra_opts)
                        ) as fi,
                    ):
                        fout.write(fi.read())
                    setBinExecPermissions(ctx, out_path)

    def extractCoreByBasename(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        release_path: str,
        extra_opts: dict,
    ) -> None:
        # Archive member paths vary, extract by matching basenames.
        ctx.logger.info(
            f"Extracting core {self.name} v{self.version}{self.version_tag}"
        )
        extract_core_overwrite = extra_opts.get("extract_core_overwrite", True)
        bins = self.getExtractBins()

        if "win32" in ctx.bin_arch or "win64" in ctx.bin_arch:
            with zipfile.ZipFile(release_path) as fz:
                namelist = fz.namelist()
                for b in bins:
                    b += ".exe"
                    out_path = os.path.join(bin_dir, b)
                    if (not os.path.exists(out_path)) or extract_core_overwrite:
                        for entry in namelist:
                            if entry.endswith(b):
                                with open(out_path, "wb") as fout:
                                    fout.write(fz.read(entry))
                                setBinExecPermissions(ctx, out_path)
                                break
            return

        num_exist = 0
        for b in bins:
            out_path = os.path.join(bin_dir, b)
            if os.path.exists(out_path):
                num_exist += 1
        if not extract_core_overwrite and num_exist == len(bins):
            ctx.logger.info("Skipping extract, files exist.")
            return

        with tarfile.open(release_path) as ft:
            for member in ft.getmembers():
                if member.isdir():
                    continue
                bin_name = os.path.basename(member.name)
                if bin_name not in bins:
                    continue
                out_path = os.path.join(bin_dir, bin_name)
                if (not os.path.exists(out_path)) or extract_core_overwrite:
                    with open(out_path, "wb") as fout, ft.extractfile(member) as fi:
                        fout.write(fi.read())
                    setBinExecPermissions(ctx, out_path)

    def writeRpcAuth(self, fp, salt: str) -> None:
        if self.rpc_user != "":
            fp.write(
                "rpcauth={}:{}${}\n".format(
                    self.rpc_user, salt, password_to_hmac(salt, self.rpc_password)
                )
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
        # Coin specific config lines, override per coin
        self.writeRpcAuth(fp, salt)

    def prepareDataDir(
        self,
        ctx: PrepareContext,
        settings: dict,
        chain: str,
        extra_opts: dict,
    ) -> None:
        """Create the coin data dir and write the core config file.

        Default implementation covers bitcoin style config files.  Coins
        with a different config layout override this method.
        """
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
                if chain == "testnet":
                    fp.write("[test]\n\n")
                elif chain == "regtest":
                    fp.write("[regtest]\n\n")
                else:
                    ctx.logger.warning(f"Unknown chain {chain}")

            if ctx.rpcbind_ip != "127.0.0.1":
                fp.write("rpcallowip=127.0.0.1\n")
                if ctx.docker_mode:
                    fp.write(
                        "rpcallowip=172.0.0.0/8\n"
                    )  # Allow 172.x.x.x, range used by docker
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

    def startsInitDaemon(self) -> bool:
        # False for coins whose daemon is not started during wallet initialisation
        return True

    def usesWalletRpcDaemonForInit(self) -> bool:
        # True for coins initialised through a separate wallet rpc daemon
        return False

    def getWalletInitDaemonArgs(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> list:
        # Extra daemon arguments for the wallet initialisation run
        return []

    def needsPostInitPasswordChange(self) -> bool:
        # True where the wallet must be encrypted after initialiseWallet
        return not self.creates_wallet

    def getPostInitWarning(self, ctx: PrepareContext) -> Optional[str]:
        return None

    def ensureWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        """Create the initial wallet if it does not exist yet."""
        if core_settings.get("connection_type") == "electrum":
            ctx.logger.info(
                f"Skipping RPC wallet creation for {self.name.capitalize()} (electrum mode)."
            )
            return
        swap_client.waitForDaemonRPC(coin_id, with_wallet=False)
        wallet_name = core_settings.get("wallet_name", "wallet.dat")
        wallets = swap_client.callcoinrpc(coin_id, "listwallets")
        if wallet_name not in wallets:
            self.createWallet(ctx, swap_client, coin_id, core_settings)

    def createWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
    ) -> None:
        """Create the initial wallet through the running core daemon.

        Default implementation covers bitcoin style createwallet.  Coins
        without the descriptor/passphrase arguments override this method.
        """
        wallet_name = core_settings.get("wallet_name", "wallet.dat")
        ctx.logger.info(
            f'Creating wallet "{wallet_name}" for {self.name.capitalize()}.'
        )
        use_descriptors = core_settings.get("use_descriptors", False)
        # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors
        swap_client.callcoinrpc(
            coin_id,
            "createwallet",
            [
                wallet_name,
                False,
                True,
                ctx.wallet_encryption_pwd,
                False,
                use_descriptors,
            ],
        )
        if use_descriptors:
            watch_wallet_name = core_settings["watch_wallet_name"]
            ctx.logger.info(
                f'Creating wallet "{watch_wallet_name}" for {self.name.capitalize()}.'
            )
            swap_client.callcoinrpc(
                coin_id,
                "createwallet",
                [
                    watch_wallet_name,
                    True,
                    True,
                    "",
                    False,
                    use_descriptors,
                ],
            )
        swap_client.ci(coin_id).unlockWallet(
            ctx.wallet_encryption_pwd, check_seed=False
        )
