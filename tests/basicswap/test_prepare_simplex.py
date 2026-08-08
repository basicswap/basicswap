#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Tests for simplex-chat binary verification in prepare and at startup.

export PYTHONPATH=$(pwd)
pytest -v tests/basicswap/test_prepare_simplex.py
"""

import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import basicswap.bin.prepare as prepare
from basicswap.bin.run import checkSimplexClientBinary

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


TEST_VERSION = prepare.SIMPLEX_CHAT_VERSION
GOOD_BINARY = b"good simplex binary contents"
BAD_BINARY = b"tampered binary contents"


def sha256hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def writeSumsFile(release_dir: str, hashes) -> str:
    os.makedirs(release_dir, exist_ok=True)
    sums_path = os.path.join(release_dir, "_sha256sums")
    with open(sums_path, "w") as fp:
        for file_hash, filename in hashes:
            fp.write(f"{file_hash}  {filename}\n")
    return sums_path


class TestSimplexVerify(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="bsx_simplex_verify_")
        self.bin_dir = os.path.join(self.test_dir, "bin")
        self.simplex_dir = os.path.join(self.bin_dir, "simplex")
        self.release_dir = os.path.join(self.simplex_dir, TEST_VERSION)
        self.client_path = os.path.join(self.simplex_dir, "simplex-chat")
        self.release_file = prepare.getSimplexClientReleaseFilename()
        os.makedirs(self.release_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def writeClient(self, contents: bytes) -> None:
        with open(self.client_path, "wb") as fp:
            fp.write(contents)
        os.chmod(self.client_path, 0o755)

    def fakeDownloadRelease(self, url, path, extra_opts):
        self.download_calls.append(url)
        with open(path, "wb") as fp:
            fp.write(GOOD_BINARY)

    def preparePatched(self):
        self.download_calls = []
        with (
            mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True),
            mock.patch.object(prepare, "downloadRelease", self.fakeDownloadRelease),
        ):
            return prepare.prepareSimplexClient(self.bin_dir, extra_opts={})

    def test_verify_release_hash_ok(self):
        writeSumsFile(
            self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)]
        )
        self.writeClient(GOOD_BINARY)
        with mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True):
            release_hash = prepare.verifySimplexRelease(
                self.client_path, self.release_dir, extra_opts={}
            )
        assert release_hash == sha256hex(GOOD_BINARY)

    def test_verify_release_hash_mismatch(self):
        writeSumsFile(
            self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)]
        )
        self.writeClient(BAD_BINARY)
        with mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True):
            with self.assertRaises(ValueError):
                prepare.verifySimplexRelease(
                    self.client_path, self.release_dir, extra_opts={}
                )

    def test_fresh_download(self):
        writeSumsFile(
            self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)]
        )
        client_path = self.preparePatched()

        assert client_path == self.client_path
        assert len(self.download_calls) == 1
        with open(client_path, "rb") as fp:
            assert fp.read() == GOOD_BINARY
        assert os.access(client_path, os.X_OK)

        with open(os.path.join(self.simplex_dir, ".verified")) as fp:
            metadata = json.load(fp)
        assert metadata["version"] == TEST_VERSION
        assert metadata["sha256"] == sha256hex(GOOD_BINARY)

    def test_existing_binary_verified(self):
        writeSumsFile(
            self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)]
        )
        self.writeClient(GOOD_BINARY)
        client_path = self.preparePatched()

        # Verified in place, no download
        assert client_path == self.client_path
        assert len(self.download_calls) == 0
        assert os.path.isfile(os.path.join(self.simplex_dir, ".verified"))

    def test_existing_binary_mismatch_redownloads(self):
        writeSumsFile(
            self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)]
        )
        self.writeClient(BAD_BINARY)
        client_path = self.preparePatched()

        assert len(self.download_calls) == 1
        with open(client_path, "rb") as fp:
            assert fp.read() == GOOD_BINARY

    def test_skip_verify(self):
        # No sums file at all: verification would fail if attempted
        self.writeClient(BAD_BINARY)
        self.download_calls = []
        with (
            mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True),
            mock.patch.object(prepare, "SIMPLEX_SKIP_VERIFY", True),
            mock.patch.object(prepare, "downloadRelease", self.fakeDownloadRelease),
        ):
            client_path = prepare.prepareSimplexClient(self.bin_dir, extra_opts={})

        assert len(self.download_calls) == 0
        with open(client_path, "rb") as fp:
            assert fp.read() == BAD_BINARY
        assert not os.path.isfile(os.path.join(self.simplex_dir, ".verified"))

    def test_force_download(self):
        writeSumsFile(
            self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)]
        )
        self.writeClient(GOOD_BINARY)
        self.download_calls = []
        with (
            mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True),
            mock.patch.object(prepare, "SIMPLEX_FORCE_DOWNLOAD", True),
            mock.patch.object(prepare, "downloadRelease", self.fakeDownloadRelease),
        ):
            prepare.prepareSimplexClient(self.bin_dir, extra_opts={})

        assert len(self.download_calls) == 1

    def test_gpg_invalid_signature_rejected(self):
        if shutil.which("gpg") is None:
            raise unittest.SkipTest("gpg binary not found")
        writeSumsFile(
            self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)]
        )
        # Garbage detached signature must be rejected
        with open(os.path.join(self.release_dir, "_sha256sums.asc"), "wb") as fp:
            fp.write(b"not a signature")
        self.writeClient(GOOD_BINARY)

        gpg_homedir = os.path.join(self.test_dir, "gnupg")
        os.makedirs(gpg_homedir, mode=0o700)
        prepare_ctx = mock.Mock()
        prepare_ctx.gpg_homedir = gpg_homedir
        extra_opts = {"prepare_ctx": prepare_ctx}

        with mock.patch.object(prepare, "SKIP_GPG_VALIDATION", False):
            with mock.patch.object(prepare, "ensureSimplexPubkeys", lambda gpg: None):
                with self.assertRaises(ValueError):
                    prepare.verifySimplexRelease(
                        self.client_path, self.release_dir, extra_opts
                    )

    def test_linux_release_filename_v7(self):
        with mock.patch.object(prepare, "USE_PLATFORM", "Linux"):
            with mock.patch.object(prepare.platform, "machine", return_value="x86_64"):
                assert (
                    prepare.getSimplexClientReleaseFilename("7.0.0")
                    == "simplex-chat-ubuntu-24_04-x86_64"
                )

    def test_linux_release_filename_v6(self):
        with mock.patch.object(prepare, "USE_PLATFORM", "Linux"):
            with mock.patch.object(prepare.platform, "machine", return_value="x86_64"):
                assert (
                    prepare.getSimplexClientReleaseFilename("6.3.5")
                    == "simplex-chat-ubuntu-24_04-x86-64"
                )


class TestStartupCheck(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="bsx_simplex_startup_")
        self.client_path = os.path.join(self.test_dir, "simplex-chat")
        self.metadata_path = os.path.join(self.test_dir, ".verified")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def writeClient(self, contents: bytes) -> None:
        with open(self.client_path, "wb") as fp:
            fp.write(contents)
        os.chmod(self.client_path, 0o755)

    def writeMetadata(self, sha256: str, version: str = TEST_VERSION) -> None:
        with open(self.metadata_path, "w") as fp:
            json.dump({"version": version, "sha256": sha256, "verified_at": 0}, fp)

    def test_missing_binary(self):
        network = {}
        assert checkSimplexClientBinary(self.client_path, network, logger) is False
        assert network["verify_status"] == "missing"

    def test_not_executable(self):
        with open(self.client_path, "wb") as fp:
            fp.write(GOOD_BINARY)
        os.chmod(self.client_path, 0o644)
        network = {}
        assert checkSimplexClientBinary(self.client_path, network, logger) is False
        assert network["verify_status"] == "missing"

    def test_no_metadata_allowed_with_warning(self):
        self.writeClient(GOOD_BINARY)
        network = {}
        assert checkSimplexClientBinary(self.client_path, network, logger) is True
        assert network["verify_status"] == "unverified"

    def test_hash_match(self):
        self.writeClient(GOOD_BINARY)
        self.writeMetadata(sha256hex(GOOD_BINARY))
        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(self.client_path, network, logger) is True
        assert network["verify_status"] == "ok"

    def test_hash_mismatch(self):
        self.writeClient(BAD_BINARY)
        self.writeMetadata(sha256hex(GOOD_BINARY))
        network = {}
        assert checkSimplexClientBinary(self.client_path, network, logger) is False
        assert network["verify_status"] == "hash_mismatch"

    def test_version_mismatch_warns_but_starts(self):
        self.writeClient(GOOD_BINARY)
        self.writeMetadata(sha256hex(GOOD_BINARY), version="0.0.1")
        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(self.client_path, network, logger) is True
        assert network["verify_status"] == "ok"


if __name__ == "__main__":
    unittest.main()
