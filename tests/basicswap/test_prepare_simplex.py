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
from basicswap.network.simplex import (
    createSimplexConnectInvitation,
    ensureSimplexGroup,
    formatSimplexChatError,
    getJoinedSimplexLink,
    getNewSimplexLink,
)
from basicswap.util import TemporaryError

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


class TestSimplexLinkParsing(unittest.TestCase):
    # Response shapes from simplex-chat v7.0.0.11
    def test_connect_invitation(self):
        response = {
            "corrId": "1",
            "resp": {
                "type": "invitation",
                "connLinkInvitation": {
                    "connFullLink": "simplex:/invitation#/?v=2-7&smp=test",
                    "connShortLink": "https://smp5.simplex.im/i#test",
                },
                "connection": {"pccConnId": 1},
            },
        }
        self.assertEqual(
            getJoinedSimplexLink(response), "simplex:/invitation#/?v=2-7&smp=test"
        )

    def test_connect_contact(self):
        response = {
            "corrId": "1",
            "resp": {
                "type": "userContactLinkCreated",
                "connLinkContact": {
                    "connFullLink": "simplex:/contact#/?v=2-7&smp=test",
                    "connShortLink": "https://smp5.simplex.im/c#test",
                },
            },
        }
        self.assertEqual(
            getJoinedSimplexLink(response), "simplex:/contact#/?v=2-7&smp=test"
        )

    def test_connect_error(self):
        response = {
            "corrId": "1",
            "resp": {
                "type": "chatCmdError",
                "chatError": {
                    "type": "error",
                    "errorType": {
                        "type": "agentError",
                        "message": "SMP server unreachable",
                    },
                },
            },
        }
        with self.assertRaises(TemporaryError) as cm:
            getJoinedSimplexLink(response)
        self.assertIn("SMP server unreachable", str(cm.exception))

    def test_new_link(self):
        response = {
            "corrId": "1",
            "resp": {
                "type": "userContactLinkCreated",
                "connLinkContact": {
                    "connFullLink": "simplex:/contact#/?v=2-7&smp=test",
                    "connShortLink": "https://smp5.simplex.im/c#test",
                },
            },
        }
        self.assertEqual(
            getNewSimplexLink(response), "simplex:/contact#/?v=2-7&smp=test"
        )

    def test_new_group_link_v7(self):
        # simplex-chat v7 nests the link of "/create link #group" under groupLink
        response = {
            "corrId": "8",
            "resp": {
                "type": "groupLinkCreated",
                "groupInfo": {"groupId": 1, "localDisplayName": "bsx"},
                "groupLink": {
                    "userContactLinkId": 1,
                    "connLinkContact": {
                        "connFullLink": "simplex:/contact#/?v=2-7&smp=group",
                        "connShortLink": "https://127.0.0.1/g#test",
                    },
                    "shortLinkDataSet": True,
                    "shortLinkLargeDataSet": True,
                    "acceptMemberRole": "member",
                },
            },
        }
        self.assertEqual(
            getNewSimplexLink(response), "simplex:/contact#/?v=2-7&smp=group"
        )

    def test_new_link_errors(self):
        error_response = {
            "corrId": "1",
            "resp": {
                "type": "chatCmdError",
                "chatError": {
                    "type": "error",
                    "errorType": {"type": "userContactLinkExists"},
                },
            },
        }
        with self.assertRaises(TemporaryError) as cm:
            getNewSimplexLink(error_response)
        self.assertIn("userContactLinkExists", str(cm.exception))

        unexpected = {"corrId": "1", "resp": {"type": "somethingElse"}}
        with self.assertRaises(ValueError) as cm:
            getNewSimplexLink(unexpected)
        self.assertIn("somethingElse", str(cm.exception))

    def test_format_chat_error(self):
        chat_error = {
            "type": "error",
            "errorType": {"type": "commandError", "message": "invalid request"},
        }
        self.assertEqual(formatSimplexChatError(chat_error), "invalid request")

    def test_format_agent_broker_error(self):
        chat_error = {
            "type": "errorAgent",
            "agentError": {
                "type": "BROKER",
                "brokerAddress": "smp://test@smp5.simplex.im,test.onion",
                "brokerErr": {
                    "type": "NETWORK",
                    "networkError": {
                        "type": "connectError",
                        "connectError": "Connection refused",
                    },
                },
            },
        }
        self.assertEqual(formatSimplexChatError(chat_error), "Connection refused")

    def test_connect_retries_on_transient_error(self):
        class FakeWs:
            def __init__(self):
                self.calls = 0

            def send_command(self, cmd):
                self.calls += 1
                return self.calls

            def wait_for_command_response(self, cmd_id):
                if cmd_id == 1:
                    return {
                        "corrId": "1",
                        "resp": {
                            "type": "chatCmdError",
                            "chatError": {
                                "type": "error",
                                "errorType": {"message": "SMP server unreachable"},
                            },
                        },
                    }
                return {
                    "corrId": "2",
                    "resp": {
                        "type": "invitation",
                        "connLinkInvitation": {
                            "connFullLink": "simplex:/invitation#/?v=2-7&smp=test",
                        },
                        "connection": {"pccConnId": 2},
                    },
                }

        class FakeDelay:
            def wait(self, _seconds):
                pass

        ws = FakeWs()
        conn_link, pcc_conn_id = createSimplexConnectInvitation(
            ws, FakeDelay(), num_tries=3
        )
        self.assertEqual(conn_link, "simplex:/invitation#/?v=2-7&smp=test")
        self.assertEqual(pcc_conn_id, 2)
        self.assertEqual(ws.calls, 2)


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
            mock.patch.object(prepare, "smokeTestSimplexClient", lambda path: None),
        ):
            return prepare.prepareSimplexClient(self.bin_dir, extra_opts={})

    def test_verify_release_hash_ok(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
        self.writeClient(GOOD_BINARY)
        with mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True):
            release_hash, verification = prepare.verifySimplexRelease(
                self.client_path, self.release_dir, extra_opts={}
            )
        assert release_hash == sha256hex(GOOD_BINARY)
        assert verification == "signed"

    def test_verify_release_hash_mismatch(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
        self.writeClient(BAD_BINARY)
        with mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True):
            with self.assertRaises(ValueError):
                prepare.verifySimplexRelease(
                    self.client_path, self.release_dir, extra_opts={}
                )

    def test_listed_file_mismatch_does_not_fall_back(self):
        # A file present in the signed manifest must match it, the release
        # notes are never consulted for it.
        writeSumsFile(
            self.release_dir,
            [(sha256hex(GOOD_BINARY), TEST_VERSION + "/" + self.release_file)],
        )
        with mock.patch.object(
            prepare, "fetchSimplexReleaseBodyHash", return_value=sha256hex(BAD_BINARY)
        ) as mock_fetch:
            with self.assertRaises(ValueError):
                prepare.ensureSimplexReleaseHash(
                    sha256hex(BAD_BINARY),
                    self.release_file,
                    os.path.join(self.release_dir, "_sha256sums"),
                )
        mock_fetch.assert_not_called()

    def writeUnlistedSums(self) -> str:
        writeSumsFile(
            self.release_dir,
            [(sha256hex(BAD_BINARY), TEST_VERSION + "/simplex-chat-other-build")],
        )
        return os.path.join(self.release_dir, "_sha256sums")

    def test_unlisted_file_uses_pinned_hash(self):
        sums_path = self.writeUnlistedSums()
        pinned = {TEST_VERSION: {self.release_file: sha256hex(GOOD_BINARY)}}
        with (
            mock.patch.object(prepare, "SIMPLEX_PINNED_HASHES", pinned),
            mock.patch.object(prepare, "SIMPLEX_ALLOW_UNSIGNED_HASH", True),
            mock.patch.object(
                prepare,
                "fetchSimplexReleaseBodyHash",
                return_value=sha256hex(BAD_BINARY),
            ) as mock_fetch,
        ):
            assert (
                prepare.ensureSimplexReleaseHash(
                    sha256hex(GOOD_BINARY), self.release_file, sums_path
                )
                == "pinned"
            )
            with self.assertRaises(ValueError):
                prepare.ensureSimplexReleaseHash(
                    sha256hex(BAD_BINARY), self.release_file, sums_path
                )
        mock_fetch.assert_not_called()

    def test_current_release_pins_unsigned_builds(self):
        pinned = prepare.SIMPLEX_PINNED_HASHES[prepare.SIMPLEX_CHAT_VERSION]
        for platform_name, machine in (
            ("Darwin", "arm64"),
            ("Darwin", "x86_64"),
            ("Windows", "AMD64"),
        ):
            with (
                mock.patch.object(prepare, "USE_PLATFORM", platform_name),
                mock.patch.object(prepare.platform, "machine", return_value=machine),
            ):
                release_file = prepare.getSimplexClientReleaseFilename()
            assert release_file in pinned, release_file
            assert len(pinned[release_file]) == 64
        for os_release in (
            {"ID": "ubuntu", "VERSION_ID": "24.04"},
            {"ID": "ubuntu", "VERSION_ID": "22.04"},
        ):
            release_file = self.linuxFilename(os_release, machine="aarch64")
            assert release_file in pinned, release_file

    def test_unlisted_unpinned_file_rejected_by_default(self):
        sums_path = self.writeUnlistedSums()
        with (
            mock.patch.object(prepare, "SIMPLEX_PINNED_HASHES", {}),
            mock.patch.object(prepare, "SIMPLEX_ALLOW_UNSIGNED_HASH", False),
            mock.patch.object(
                prepare,
                "fetchSimplexReleaseBodyHash",
                return_value=sha256hex(GOOD_BINARY),
            ) as mock_fetch,
        ):
            with self.assertRaises(ValueError) as cm:
                prepare.ensureSimplexReleaseHash(
                    sha256hex(GOOD_BINARY), self.release_file, sums_path
                )
        assert "SIMPLEX_ALLOW_UNSIGNED_HASH" in str(cm.exception)
        mock_fetch.assert_not_called()

    def test_unlisted_file_release_notes_opt_in(self):
        sums_path = self.writeUnlistedSums()
        for platform_name in ("Linux", "Darwin", "Windows"):
            with (
                mock.patch.object(prepare, "USE_PLATFORM", platform_name),
                mock.patch.object(prepare, "SIMPLEX_PINNED_HASHES", {}),
                mock.patch.object(prepare, "SIMPLEX_ALLOW_UNSIGNED_HASH", True),
                mock.patch.object(
                    prepare,
                    "fetchSimplexReleaseBodyHash",
                    return_value=sha256hex(GOOD_BINARY),
                ) as mock_fetch,
            ):
                assert (
                    prepare.ensureSimplexReleaseHash(
                        sha256hex(GOOD_BINARY), self.release_file, sums_path
                    )
                    == "release_notes"
                )
                mock_fetch.assert_called_once_with(self.release_file)

                with self.assertRaises(ValueError):
                    prepare.ensureSimplexReleaseHash(
                        sha256hex(BAD_BINARY), self.release_file, sums_path
                    )

        with (
            mock.patch.object(prepare, "SIMPLEX_PINNED_HASHES", {}),
            mock.patch.object(prepare, "SIMPLEX_ALLOW_UNSIGNED_HASH", True),
            mock.patch.object(
                prepare, "fetchSimplexReleaseBodyHash", return_value=None
            ),
        ):
            with self.assertRaises(ValueError):
                prepare.ensureSimplexReleaseHash(
                    sha256hex(GOOD_BINARY), self.release_file, sums_path
                )

    def test_release_notes_download_recorded_as_unverified(self):
        self.writeUnlistedSums()
        with (
            mock.patch.object(prepare, "SIMPLEX_PINNED_HASHES", {}),
            mock.patch.object(prepare, "SIMPLEX_ALLOW_UNSIGNED_HASH", True),
            mock.patch.object(
                prepare,
                "fetchSimplexReleaseBodyHash",
                return_value=sha256hex(GOOD_BINARY),
            ),
        ):
            client_path = self.preparePatched()

        with open(os.path.join(self.simplex_dir, ".verified")) as fp:
            metadata = json.load(fp)
        assert metadata["verification"] == "release_notes"

        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(client_path, network, logger) is True
        assert network["verify_status"] == "unverified"

    def test_release_body_hash_parsing(self):
        body = (
            "Release notes\n"
            "SHA2-256(simplex-chat-ubuntu-24_04-aarch64)= 70a4396990 53c1d9\n"
            "SHA2-256(simplex-chat-macos-aarch64)= b2837b8d1e\n"
        )
        fake_json = json.dumps({"body": body}).encode("utf-8")
        with mock.patch.object(prepare, "downloadBytes", return_value=fake_json):
            assert (
                prepare.fetchSimplexReleaseBodyHash("simplex-chat-macos-aarch64")
                == "b2837b8d1e"
            )
            # Trailing text after the hash is ignored
            assert (
                prepare.fetchSimplexReleaseBodyHash("simplex-chat-ubuntu-24_04-aarch64")
                == "70a4396990"
            )
            assert prepare.fetchSimplexReleaseBodyHash("simplex-chat-nope") is None
        with mock.patch.object(
            prepare, "downloadBytes", side_effect=OSError("offline")
        ):
            assert (
                prepare.fetchSimplexReleaseBodyHash("simplex-chat-macos-aarch64")
                is None
            )

    def test_fresh_download(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
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
        assert metadata["verification"] == "signed"

    def test_existing_binary_verified(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
        self.writeClient(GOOD_BINARY)
        client_path = self.preparePatched()

        # Verified in place, no download
        assert client_path == self.client_path
        assert len(self.download_calls) == 0
        assert os.path.isfile(os.path.join(self.simplex_dir, ".verified"))

    def test_existing_binary_mismatch_redownloads(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
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

    def test_skip_verify_clears_stale_metadata(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
        self.preparePatched()
        metadata_path = os.path.join(self.simplex_dir, ".verified")
        assert os.path.isfile(metadata_path)

        self.writeClient(BAD_BINARY)
        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(self.client_path, network, logger) is False
        assert network["verify_status"] == "hash_mismatch"

        self.download_calls = []
        with (
            mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True),
            mock.patch.object(prepare, "SIMPLEX_SKIP_VERIFY", True),
            mock.patch.object(prepare, "downloadRelease", self.fakeDownloadRelease),
        ):
            client_path = prepare.prepareSimplexClient(self.bin_dir, extra_opts={})

        assert len(self.download_calls) == 0
        assert not os.path.isfile(metadata_path)
        with open(client_path, "rb") as fp:
            assert fp.read() == BAD_BINARY

        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(client_path, network, logger) is True
        assert network["verify_status"] == "unverified"

    def test_force_download(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
        self.writeClient(GOOD_BINARY)
        self.download_calls = []
        with (
            mock.patch.object(prepare, "SKIP_GPG_VALIDATION", True),
            mock.patch.object(prepare, "SIMPLEX_FORCE_DOWNLOAD", True),
            mock.patch.object(prepare, "downloadRelease", self.fakeDownloadRelease),
            mock.patch.object(prepare, "smokeTestSimplexClient", lambda path: None),
        ):
            prepare.prepareSimplexClient(self.bin_dir, extra_opts={})

        assert len(self.download_calls) == 1

    def test_version_floor(self):
        with mock.patch.object(prepare, "SIMPLEX_CHAT_VERSION", "6.3.5"):
            with self.assertRaises(ValueError) as cm:
                prepare.prepareSimplexClient(self.bin_dir, extra_opts={})
        assert "minimum supported" in str(cm.exception)

    def test_gpg_invalid_signature_rejected(self):
        if shutil.which("gpg") is None:
            raise unittest.SkipTest("gpg binary not found")
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
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

    def linuxFilename(self, os_release: dict, machine: str = "x86_64") -> str:
        with (
            mock.patch.object(prepare, "USE_PLATFORM", "Linux"),
            mock.patch.object(prepare.platform, "machine", return_value=machine),
            mock.patch.object(prepare, "readOsRelease", lambda: os_release),
        ):
            return prepare.getSimplexClientReleaseFilename()

    def test_linux_ubuntu_24_04(self):
        assert (
            self.linuxFilename({"ID": "ubuntu", "VERSION_ID": "24.04"})
            == "simplex-chat-ubuntu-24_04-x86_64"
        )

    def test_linux_ubuntu_22_04(self):
        assert (
            self.linuxFilename({"ID": "ubuntu", "VERSION_ID": "22.04"})
            == "simplex-chat-ubuntu-22_04-x86_64"
        )

    def test_linux_ubuntu_aarch64(self):
        assert (
            self.linuxFilename({"ID": "ubuntu", "VERSION_ID": "24.04"}, "aarch64")
            == "simplex-chat-ubuntu-24_04-aarch64"
        )

    def test_linux_debian_family_warns_and_proceeds(self):
        assert (
            self.linuxFilename({"ID": "linuxmint", "ID_LIKE": "ubuntu debian"})
            == "simplex-chat-ubuntu-24_04-x86_64"
        )

    def test_linux_unsupported_distro_fails(self):
        with self.assertRaises(ValueError) as cm:
            self.linuxFilename({"ID": "arch"})
        assert "SIMPLEX_ALLOW_UNSUPPORTED_DISTRO" in str(cm.exception)

    def test_linux_unsupported_distro_override(self):
        with mock.patch.object(prepare, "SIMPLEX_ALLOW_UNSUPPORTED_DISTRO", True):
            assert (
                self.linuxFilename({"ID": "arch"}) == "simplex-chat-ubuntu-24_04-x86_64"
            )


class TestSmokeTest(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="bsx_simplex_smoke_")
        self.client_path = os.path.join(self.test_dir, "simplex-chat")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def writeScript(self, body: str) -> None:
        with open(self.client_path, "w") as fp:
            fp.write("#!/bin/sh\n" + body)
        os.chmod(self.client_path, 0o755)

    def test_working_binary_passes(self):
        self.writeScript('echo "SimpleX Chat v7.0.1"\nexit 0\n')
        prepare.smokeTestSimplexClient(self.client_path)

    def test_failing_binary_raises(self):
        self.writeScript('echo "error while loading shared libraries" >&2\nexit 127\n')
        with self.assertRaises(ValueError) as cm:
            prepare.smokeTestSimplexClient(self.client_path)
        assert "exit code 127" in str(cm.exception)

    def test_non_executable_file_raises(self):
        with open(self.client_path, "wb") as fp:
            fp.write(b"not a binary")
        os.chmod(self.client_path, 0o755)
        with self.assertRaises(ValueError):
            prepare.smokeTestSimplexClient(self.client_path)


GROUP_LINK_A = "https://smp4.simplex.im/g#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
GROUP_LINK_B = "https://smp4.simplex.im/g#BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"


def groupInfo(name: str, role: str = "member") -> dict:
    return {
        "groupId": 1,
        "localDisplayName": name,
        "groupProfile": {"displayName": name},
        "membership": {"memberRole": role},
    }


class FakeGroupWs:
    def __init__(self, groups):
        self.groups = list(groups)
        self.commands = []
        self.queue = []
        self.next_id = 1

    def send_command(self, cmd_str: str) -> int:
        cmd_id = self.next_id
        self.next_id += 1
        self.commands.append(cmd_str)
        if cmd_str == "/groups":
            resp = {"type": "groupsList", "groups": list(self.groups)}
        elif cmd_str.startswith("/c "):
            resp = {
                "type": "sentInvitation",
                "connection": {"pccConnId": 7, "groupLinkId": "gl"},
            }
        elif cmd_str.startswith("/leave #"):
            resp = {"type": "leftMemberUser", "groupInfo": {}}
        elif cmd_str.startswith("/delete #"):
            name = cmd_str.split("#", 1)[1]
            self.groups = [g for g in self.groups if g["localDisplayName"] != name]
            resp = {"type": "groupDeletedUser", "groupInfo": {}}
        else:
            raise AssertionError(f"Unexpected command {cmd_str}")
        self.queue.append(json.dumps({"corrId": str(cmd_id), "resp": {"Right": resp}}))
        return cmd_id

    def cmd_queue_get(self):
        return self.queue.pop(0) if self.queue else None


class FakeApp:
    def __init__(self, network_config):
        self.log = logger
        self.delay_event = mock.Mock()
        self.settings = {"networks": [network_config]}
        self.saved = 0

    def _save_settings(self):
        self.saved += 1


class TestSimplexGroup(unittest.TestCase):
    def test_fresh_client_joins_and_records_link(self):
        network = {"type": "simplex", "group_link": GROUP_LINK_A}
        app = FakeApp(network)
        ws = FakeGroupWs([])
        ensureSimplexGroup(app, ws, network)
        assert ws.commands == ["/groups", "/c " + GROUP_LINK_A]
        assert network["joined_group_link"] == GROUP_LINK_A
        assert app.saved == 1

    def test_joined_group_unchanged_link_no_commands(self):
        network = {
            "type": "simplex",
            "group_link": GROUP_LINK_A,
            "joined_group_link": GROUP_LINK_A,
        }
        app = FakeApp(network)
        ws = FakeGroupWs([groupInfo("bsx")])
        ensureSimplexGroup(app, ws, network)
        assert ws.commands == ["/groups"]
        assert app.saved == 0

    def test_existing_install_records_current_link(self):
        network = {"type": "simplex", "group_link": GROUP_LINK_A}
        app = FakeApp(network)
        ws = FakeGroupWs([groupInfo("bsx")])
        ensureSimplexGroup(app, ws, network)
        assert ws.commands == ["/groups"]
        assert network["joined_group_link"] == GROUP_LINK_A
        assert app.saved == 1

    def test_replacement_link_switches_group(self):
        network = {
            "type": "simplex",
            "group_link": GROUP_LINK_B,
            "joined_group_link": GROUP_LINK_A,
        }
        app = FakeApp(network)
        ws = FakeGroupWs([groupInfo("bsx")])
        ensureSimplexGroup(app, ws, network)
        assert ws.commands == [
            "/groups",
            "/leave #bsx",
            "/delete #bsx",
            "/c " + GROUP_LINK_B,
        ]
        assert ws.groups == []
        assert network["joined_group_link"] == GROUP_LINK_B
        assert app.saved == 1

        ws = FakeGroupWs([groupInfo("bsx")])
        ensureSimplexGroup(app, ws, network)
        assert ws.commands == ["/groups"]
        assert app.saved == 1

    def test_owned_group_is_not_replaced(self):
        network = {
            "type": "simplex",
            "group_link": GROUP_LINK_B,
            "joined_group_link": GROUP_LINK_A,
        }
        app = FakeApp(network)
        ws = FakeGroupWs([groupInfo("bsx", role="owner")])
        with self.assertRaises(ValueError) as cm:
            ensureSimplexGroup(app, ws, network)
        assert "owns" in str(cm.exception)
        assert ws.commands == ["/groups"]
        assert network["joined_group_link"] == GROUP_LINK_A
        assert app.saved == 0

    def test_failed_delete_aborts_switch(self):
        network = {
            "type": "simplex",
            "group_link": GROUP_LINK_B,
            "joined_group_link": GROUP_LINK_A,
        }
        app = FakeApp(network)
        ws = FakeGroupWs([groupInfo("bsx")])
        orig_send = ws.send_command

        def failing_send(cmd_str):
            if cmd_str.startswith("/delete #"):
                cmd_id = ws.next_id
                ws.next_id += 1
                ws.commands.append(cmd_str)
                resp = {"type": "chatCmdError", "chatError": {"type": "error"}}
                ws.queue.append(
                    json.dumps({"corrId": str(cmd_id), "resp": {"Right": resp}})
                )
                return cmd_id
            return orig_send(cmd_str)

        ws.send_command = failing_send
        with self.assertRaises(ValueError):
            ensureSimplexGroup(app, ws, network)
        assert not any(c.startswith("/c ") for c in ws.commands)
        assert network["joined_group_link"] == GROUP_LINK_A
        assert app.saved == 0


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

    def writeMetadata(
        self, sha256: str, version: str = TEST_VERSION, verification="signed"
    ) -> None:
        metadata = {"version": version, "sha256": sha256, "verified_at": 0}
        if verification is not None:
            metadata["verification"] = verification
        with open(self.metadata_path, "w") as fp:
            json.dump(metadata, fp)

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
        assert network["verification"] == "signed"

    def test_pinned_hash_is_ok(self):
        self.writeClient(GOOD_BINARY)
        self.writeMetadata(sha256hex(GOOD_BINARY), verification="pinned")
        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(self.client_path, network, logger) is True
        assert network["verify_status"] == "ok"
        assert network["verification"] == "pinned"

    def test_release_notes_hash_is_unverified(self):
        self.writeClient(GOOD_BINARY)
        self.writeMetadata(sha256hex(GOOD_BINARY), verification="release_notes")
        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(self.client_path, network, logger) is True
        assert network["verify_status"] == "unverified"
        assert network["verification"] == "release_notes"

    def test_metadata_without_method_is_unverified(self):
        self.writeClient(GOOD_BINARY)
        self.writeMetadata(sha256hex(GOOD_BINARY), verification=None)
        network = {"client_version": TEST_VERSION}
        assert checkSimplexClientBinary(self.client_path, network, logger) is True
        assert network["verify_status"] == "unverified"

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

    def test_unsupported_configured_version_refused(self):
        self.writeClient(GOOD_BINARY)
        self.writeMetadata(sha256hex(GOOD_BINARY), version="6.3.5")
        network = {"client_version": "6.3.5"}
        assert checkSimplexClientBinary(self.client_path, network, logger) is False
        assert network["verify_status"] == "unsupported_version"


if __name__ == "__main__":
    unittest.main()
