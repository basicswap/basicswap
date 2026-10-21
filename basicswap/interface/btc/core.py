# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import mmap
import os
import shutil
import tarfile

from basicswap.interface.btc.chainparams import params
from basicswap.interface.prepare_util import (
    CoinPrepareModule,
    PrepareContext,
    createGPG,
    isValidSignature,
    havePubkey,
    getFileHash,
)

BITCOIN_VERSION = os.getenv("BITCOIN_VERSION", "31.1")
BITCOIN_VERSION_TAG = os.getenv("BITCOIN_VERSION_TAG", "")
BITCOIN_LEGACY_VERSION = os.getenv("BITCOIN_LEGACY_VERSION", "29.4")
bitcoin_signers = {
    "laanwj": ("9DEAE0DC7063249FB05474681E4AED62986CD25D",),
    "hebasto": ("D1DBF2C4B96F2DEBF4C16654410108112E7EA81F",),
}

# Fastsync UTXO snapshot hash files are signed by these keys
fastsync_signers = {
    "tecnovert": ("8E517DC12EC1CC37F6423A8A13F13651C9CF0D6B",),
    "nicolasdorier": (
        "AB4CFA9895ACA0DBE27F6B346618763EF09186FE",
        "015B4C837B245509E4AC8995223FDA69DEBEA82D",
        "7121BDE3555D9BE06BDDC68162FE85647DEDDA2E",
    ),
}

BITCOIN_FASTSYNC_URL = os.getenv(
    "BITCOIN_FASTSYNC_URL",
    "https://snapshots.btcpay.tech/",
)
BITCOIN_FASTSYNC_FILE = os.getenv(
    "BITCOIN_FASTSYNC_FILE", "utxo-snapshot-bitcoin-mainnet-867690.tar"
)
BITCOIN_FASTSYNC_SIG_URL = os.getenv(
    "BITCOIN_FASTSYNC_SIG_URL",
    None,
)


BTC_RPC_HOST = os.getenv("BTC_RPC_HOST", "127.0.0.1")
BTC_RPC_PORT = int(os.getenv("BTC_RPC_PORT", 19996))
BTC_PORT = int(os.getenv("BTC_PORT", 8333))
BTC_ONION_PORT = int(os.getenv("BTC_ONION_PORT", 8334))
BTC_RPC_USER = os.getenv("BTC_RPC_USER", "")
BTC_RPC_PWD = os.getenv("BTC_RPC_PWD", "")


def getBasePath():
    base_path = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    if os.path.exists(os.path.join(base_path, "basicswap", "pgp")):
        base_path = os.path.join(base_path, "basicswap")
    return base_path


class BTCPrepare(CoinPrepareModule):
    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        config = {
            "connection_type": "rpc",
            "manage_daemon": ctx.should_manage_daemon(self.ticker),
            "rpchost": BTC_RPC_HOST,
            "rpcport": BTC_RPC_PORT + ctx.port_offset,
            "onionport": BTC_ONION_PORT + ctx.port_offset,
            "datadir": os.getenv("BTC_DATA_DIR", os.path.join(ctx.data_dir, self.name)),
            "bindir": os.path.join(ctx.bin_dir, self.name),
            "port": BTC_PORT + ctx.port_offset,
            "use_segwit": True,
            "blocks_confirmed": 1,
            "conf_target": 2,
            "core_version_no": self.version + self.version_tag,
            "core_version_group": 28,
        }

        if self.rpc_user != "":
            config["rpcuser"] = self.rpc_user
            config["rpcpassword"] = self.rpc_password

        return config

    def getReleaseUrl(self, ctx: PrepareContext, release_filename: str) -> str:
        return f"https://bitcoincore.org/bin/bitcoin-core-{self.version}/{release_filename}"

    def getAssertUrl(
        self,
        ctx: PrepareContext,
        os_name: str,
        os_dir_name: str,
        signing_key_name: str,
        use_guix: bool,
    ) -> str:
        if use_guix:
            return f"https://raw.githubusercontent.com/bitcoin-core/guix.sigs/main/{self.version}/{signing_key_name}/all.SHA256SUMS"

        major_minor_version: str = ".".join(self.version.split(".")[:2])
        assert_filename: str = (
            f"{self.name}-core-{os_name}-{major_minor_version}-build.assert"
        )
        return f"https://raw.githubusercontent.com/bitcoin-core/gitian.sigs/master/{self.version}-{os_dir_name}/{signing_key_name}/{assert_filename}"

    def writeCoinConfig(
        self,
        ctx: PrepareContext,
        fp,
        chain: str,
        salt: str,
        settings: dict,
        extra_opts: dict,
    ) -> None:
        if not settings["chainclients"][self.name].get("use_descriptors", False):
            fp.write("deprecatedrpc=create_bdb\n")
        fp.write("prune=2000\n")
        fp.write("changetype=bech32\n")
        fp.write("fallbackfee=0.0002\n")
        self.writeRpcAuth(fp, salt)

    def hasLegacyWallet(self, core_settings: dict) -> bool:
        if core_settings.get("connection_type") == "electrum":
            return False
        return not core_settings.get("use_descriptors", False)

    def needsWalletMigration(self, core_settings: dict, from_version: str) -> bool:
        if not self.hasLegacyWallet(core_settings):
            return False
        from_major: str = from_version.split(".")[0]
        if from_major.isdigit() and int(from_major) >= 30:
            return False
        return int(self.version.split(".")[0]) >= 30

    def setUpgradeVersion(self, core_settings: dict, use_latest: bool) -> None:
        if use_latest or not self.needsWalletMigration(
            core_settings, core_settings.get("core_version_no", "")
        ):
            return
        self.version = BITCOIN_LEGACY_VERSION
        self.version_tag = ""

    def getVersionNote(self) -> str:
        return f" ({BITCOIN_LEGACY_VERSION} for --upgradecores of a pre-30 install without -uselatest={self.name})"

    def checkWalletBeforeMigration(
        self, ctx: PrepareContext, swap_client, coin_id, core_settings: dict
    ) -> None:
        ci = swap_client.ci(coin_id)
        wallet_name: str = core_settings.get("wallet_name", "wallet.dat")
        if wallet_name not in ci.rpc("listwallets"):
            ci.rpc("loadwallet", [wallet_name])
        wallet_seed_id: str = ci.getWalletSeedID()
        root_seed_id: str = ci.getSeedHash(swap_client.getWalletKey(coin_id, 1)).hex()
        if wallet_seed_id != root_seed_id:
            raise ValueError(
                f"{self.name.capitalize()} wallet seed id {wallet_seed_id} is not derived from the Particl wallet's default account ({root_seed_id}). Rerun with --noseedcheck to migrate it as it is."
            )

    def migrateWallet(
        self,
        ctx: PrepareContext,
        swap_client,
        coin_id,
        core_settings: dict,
        watch_wallet_name: str,
    ) -> None:
        wallet_name: str = core_settings.get("wallet_name", "wallet.dat")
        ctx.logger.info(
            f'Migrating {self.name.capitalize()} wallet "{wallet_name}" to descriptors.'
        )
        params = [wallet_name]
        if ctx.wallet_encryption_pwd != "":
            params.append(ctx.wallet_encryption_pwd)
        rv = swap_client.ci(coin_id).rpc("migratewallet", params, timeout=3600)

        backup_path: str = rv["backup_path"]
        ctx.logger.info(f"Legacy wallet backup: {backup_path}")
        if core_settings.get("manage_daemon", False) and not os.path.isfile(
            backup_path
        ):
            ctx.logger.error(f"Legacy wallet backup not found: {backup_path}")

        if "watchonly_name" in rv:
            watch_wallet_name = rv["watchonly_name"]
        else:
            ctx.logger.info(
                f'Creating wallet "{watch_wallet_name}" for {self.name.capitalize()}.'
            )
            # wallet_name, disable_private_keys, blank, passphrase, avoid_reuse, descriptors, load_on_startup
            swap_client.callcoinrpc(
                coin_id,
                "createwallet",
                [watch_wallet_name, True, True, "", False, True, True],
            )

        core_settings["use_descriptors"] = True
        core_settings["watch_wallet_name"] = watch_wallet_name
        core_settings.pop("use_legacy_key_paths", None)
        coin_client = swap_client.coin_clients[coin_id]
        coin_client["use_descriptors"] = True
        coin_client["watch_wallet_name"] = watch_wallet_name
        coin_client.pop("use_legacy_key_paths", None)
        swap_client.createCoinInterface(coin_id)

        swap_client.storeSeedIDForCoin(swap_client.getWalletKey(coin_id, 1), coin_id)
        if not swap_client.checkWalletSeed(coin_id):
            ctx.logger.error(
                f"{self.name.capitalize()} wallet seed check failed after migration."
            )

    def prepareDataDir(
        self,
        ctx: PrepareContext,
        settings: dict,
        chain: str,
        extra_opts: dict,
    ) -> None:
        super().prepareDataDir(ctx, settings, chain, extra_opts)

        if extra_opts.get("use_btc_fastsync", False) is True:
            ctx.logger.info(
                f"Initialising BTC chain with fastsync {BITCOIN_FASTSYNC_FILE}"
            )
            base_dir = extra_opts["data_dir"]
            data_dir = settings["chainclients"][self.name]["datadir"]

            for dirname in ("blocks", "chainstate"):
                if os.path.exists(os.path.join(data_dir, dirname)):
                    raise ValueError(
                        f"{dirname} directory already exists, not overwriting."
                    )

            sync_file_path = os.path.join(base_dir, BITCOIN_FASTSYNC_FILE)
            if not os.path.exists(sync_file_path):
                raise ValueError(f"BTC fastsync file not found: {sync_file_path}")

            # Double check
            if extra_opts.get("check_btc_fastsync", True):
                self.checkFastsyncData(ctx, BITCOIN_FASTSYNC_FILE)

            with tarfile.open(sync_file_path) as ft:
                if hasattr(tarfile, "data_filter"):
                    ft.extractall(path=data_dir, filter="data")
                else:
                    # TODO: Remove when minimum python version is >= 3.12
                    ft.extractall(path=data_dir)

    def checkFastsyncData(self, ctx: PrepareContext, sync_filename: str):
        ctx.logger.info(f"Validating signature for: {sync_filename}")

        asc_filename = "utxo-snapshot-bitcoin-mainnet-hashes.asc"
        asc_file_path = os.path.join(ctx.data_dir, asc_filename)
        sync_file_path = os.path.join(ctx.data_dir, sync_filename)

        if BITCOIN_FASTSYNC_SIG_URL:
            try:
                ctx.download_file(BITCOIN_FASTSYNC_SIG_URL, asc_file_path)
            except Exception as e:
                ctx.logger.warning(f"Download failed: {e}")
        elif not os.path.exists(asc_file_path):
            base_path = getBasePath()
            local_path = os.path.join(base_path, "pgp", "sigs", asc_filename)
            if os.path.exists(local_path):
                shutil.copyfile(local_path, asc_file_path)
        if not os.path.exists(asc_file_path):
            raise ValueError("Unable to find snapshot assert file.")

        ctx.logger.info(f"Hashing {sync_filename}:")
        utxo_snapshot_hash = getFileHash(
            sync_file_path, print_progress=True, logger=ctx.logger
        )
        ctx.logger.info(f"{sync_filename} hash: {utxo_snapshot_hash}")
        with (
            open(asc_file_path, "rb", 0) as fp,
            mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ) as s,
        ):
            if s.find(bytes(utxo_snapshot_hash, "utf-8")) == -1:
                raise ValueError(
                    f"Error: Snapshot hash {utxo_snapshot_hash} not found in assert file."
                )
            ctx.logger.info("Found snapshot hash in assert file.")

        pubkey_filename = "{}_{}.pgp".format("particl", "tecnovert")
        pubkeyurls = []

        gpg = createGPG(ctx.gnupg, ctx.gpg_homedir)
        if not havePubkey(gpg, fastsync_signers["tecnovert"][0]):
            ctx.import_pubkey(gpg, pubkey_filename, pubkeyurls)
        with open(asc_file_path, "rb") as fp:
            verified = gpg.verify_file(fp)
        if (
            isValidSignature(verified)
            and verified.fingerprint in fastsync_signers["tecnovert"]
        ):
            self.ensureValidSignatureBy(
                ctx, verified, "tecnovert", fastsync_signers, filepath=asc_file_path
            )
        else:
            pubkey_filename = "nicolasdorier.asc"
            if not havePubkey(gpg, fastsync_signers["nicolasdorier"][0]):
                ctx.import_pubkey(gpg, pubkey_filename, pubkeyurls)
            with open(asc_file_path, "rb") as fp:
                verified = gpg.verify_file(fp)
            self.ensureValidSignatureBy(
                ctx, verified, "nicolasdorier", fastsync_signers, filepath=asc_file_path
            )

    def prepareFastsync(self, ctx: PrepareContext, extra_opts):
        from basicswap.bin.prepare import (
            getRemoteFileLength,
        )  # TODO: move to prepare_util

        ctx.logger.info(f"Preparing BTC Fastsync file {BITCOIN_FASTSYNC_FILE}")
        sync_file_path = os.path.join(ctx.data_dir, BITCOIN_FASTSYNC_FILE)
        sync_file_url = os.path.join(BITCOIN_FASTSYNC_URL, BITCOIN_FASTSYNC_FILE)
        check_btc_fastsync = extra_opts.get("check_btc_fastsync", True)
        check_sig = False
        try:
            if not os.path.exists(sync_file_path):
                ctx.download_file(sync_file_url, sync_file_path, timeout=50)
                check_sig = check_btc_fastsync
            elif check_btc_fastsync:
                file_size = os.stat(sync_file_path).st_size
                remote_file_length, can_resume = getRemoteFileLength(sync_file_url)
                if file_size < remote_file_length:
                    ctx.logger.warning(
                        f"{BITCOIN_FASTSYNC_FILE} is an unexpected size, {file_size} < {remote_file_length}"
                    )
                    if not can_resume:
                        ctx.logger.warning(
                            f"{BITCOIN_FASTSYNC_URL} can not be resumed, restarting download."
                        )
                        file_size = 0
                    ctx.download_file(
                        sync_file_url, sync_file_path, timeout=50, resume_from=file_size
                    )
                    check_sig = True
            if check_sig:
                self.checkFastsyncData(ctx, BITCOIN_FASTSYNC_FILE)
        except Exception as e:
            raise ValueError(
                f"Error downloading fastsync, url: {sync_file_url}, error: {e}"
            )


prepare_module = BTCPrepare(
    name=params["name"],
    ticker=params["ticker"],
    version=BITCOIN_VERSION,
    version_tag=BITCOIN_VERSION_TAG,
    signers=bitcoin_signers,
    rpc_user=BTC_RPC_USER,
    rpc_password=BTC_RPC_PWD,
    onion_port=BTC_ONION_PORT,
    creates_wallet=True,
)
