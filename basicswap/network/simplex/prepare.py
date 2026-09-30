# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import platform
import shutil

from basicswap.interface.prepare_util import (
    PrepareContext,
    ReleasePrepareModule,
    getOSDirNames,
    setBinExecPermissions,
)

SIMPLEX_CHAT_VERSION = os.getenv("SIMPLEX_CHAT_VERSION", "7.0.0")
SIMPLEX_WS_PORT = int(os.getenv("SIMPLEX_WS_PORT", 5225))
SIMPLEX_SERVER_ADDRESS = os.getenv(
    "SIMPLEX_SERVER_ADDRESS",
    "smp://u2dS9sG8nMNURyZwqASV4yROM28Er0luVTx5X1CsMrU=@smp4.simplex.im",
)
# Official BasicSwap group, override to join a private network
SIMPLEX_GROUP_LINK = os.getenv(
    "SIMPLEX_GROUP_LINK",
    "https://smp4.simplex.im/g#6wTyP9neyb9ki_J8ntUqjL3q7CWWqPk3Z-o5bpuvfXg",
)

CLIENT_FILENAME = "simplex-chat"
simplex_signers = {"build": ("BBDF7BDAD1548B16836AF5B9D53BDFD153C366BA",)}


class SimplexPrepare(ReleasePrepareModule):
    def getBinDir(self, ctx: PrepareContext) -> str:
        return os.path.join(ctx.bin_dir, self.name)

    def getConfigSegment(self, ctx: PrepareContext) -> dict:
        if not SIMPLEX_GROUP_LINK:
            raise ValueError("SIMPLEX_GROUP_LINK must not be empty.")
        return {
            "type": "simplex",
            "server_address": SIMPLEX_SERVER_ADDRESS,
            "client_path": os.path.join(self.getBinDir(ctx), CLIENT_FILENAME),
            "ws_port": SIMPLEX_WS_PORT,
            "group_link": SIMPLEX_GROUP_LINK,
            "enabled": True,
        }

    def getReleaseFilename(self, ctx: PrepareContext) -> str:
        os_name, _ = getOSDirNames(ctx.bin_arch)
        machine = platform.machine()
        if os_name == "osx":
            if machine == "arm64":
                return "simplex-chat-macos-aarch64"
            return "simplex-chat-macos-x86-64"
        if os_name == "win":
            return "simplex-chat-windows-x86-64"
        arch = "aarch64" if ("arm" in machine or "aarch64" in machine) else "x86_64"
        # Built against the oldest glibc, runs on newer distributions too
        return f"simplex-chat-ubuntu-22_04-{arch}"

    def downloadCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        signing_key_name: str,
        extra_opts: dict,
    ) -> tuple:
        release_dir = os.path.join(bin_dir, self.version)
        if not os.path.exists(release_dir):
            os.makedirs(release_dir)
        base_url = f"https://github.com/simplex-chat/simplex-chat/releases/download/v{self.version}/"

        release_filename = self.getReleaseFilename(ctx)
        release_path = os.path.join(release_dir, release_filename)
        ctx.download_release(base_url + release_filename, release_path, extra_opts)

        assert_path = os.path.join(release_dir, "_sha256sums")
        if not os.path.exists(assert_path):
            ctx.download_file(base_url + "_sha256sums", assert_path)

        assert_sig_path = assert_path + ".asc"
        if not os.path.exists(assert_sig_path):
            ctx.download_file(base_url + "_sha256sums.asc", assert_sig_path)

        return release_path, assert_path, assert_sig_path

    def getPubkeyUrls(self, ctx: PrepareContext) -> list:
        return [
            "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xBBDF7BDAD1548B16836AF5B9D53BDFD153C366BA",
            "https://keys.openpgp.org/vks/v1/by-fingerprint/BBDF7BDAD1548B16836AF5B9D53BDFD153C366BA",
        ]

    def extractCore(
        self,
        ctx: PrepareContext,
        bin_dir: str,
        release_path: str,
        extra_opts: dict,
    ) -> None:
        out_path = os.path.join(bin_dir, CLIENT_FILENAME)
        if not os.path.exists(out_path) or extra_opts.get(
            "extract_core_overwrite", True
        ):
            shutil.copyfile(release_path, out_path)
            setBinExecPermissions(ctx, out_path)


prepare_module = SimplexPrepare(
    name="simplex",
    version=SIMPLEX_CHAT_VERSION,
    version_tag="",
    signers=simplex_signers,
)
