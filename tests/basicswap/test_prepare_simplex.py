#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

"""
Tests for the SimpleX network: prepare, link parsing, group and send handling.

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
import threading
import unittest
import websocket
from unittest import mock

import basicswap.bin.prepare as prepare
import basicswap.network.simplex.prepare as simplex_prepare_mod
from basicswap.interface.prepare_util import PrepareContext
from basicswap.network.simplex.simplex import (
    WebSocketThread,
    createSimplexConnectInvitation,
    ensureSimplexGroup,
    formatSimplexChatError,
    getJoinedSimplexLink,
    getNewSimplexLink,
    submitSimplexMsg,
    waitForResponse,
)
from basicswap.util import TemporaryError

logger = logging.getLogger()
logger.level = logging.DEBUG
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler(sys.stdout))


simplex_prepare = simplex_prepare_mod.prepare_module
TEST_VERSION = simplex_prepare.version
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


class TestSimplexPrepare(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="bsx_simplex_prepare_")
        self.ctx = PrepareContext(
            data_dir=self.test_dir,
            bin_dir=os.path.join(self.test_dir, "bin"),
            port_offset=0,
            should_manage_daemon=lambda name: True,
            bin_arch="x86_64-linux-gnu",
            download_release=self.fakeDownloadRelease,
            download_file=self.fakeDownloadFile,
            import_pubkey=lambda gpg, filename, urls: None,
            logger=logger,
            gpg_homedir=os.path.join(self.test_dir, "gnupg"),
        )
        os.makedirs(self.ctx.gpg_homedir, mode=0o700)
        self.extra_opts = {"prepare_ctx": self.ctx}
        self.simplex_dir = simplex_prepare.getBinDir(self.ctx)
        self.release_dir = os.path.join(self.simplex_dir, TEST_VERSION)
        self.client_path = os.path.join(self.simplex_dir, "simplex-chat")
        self.download_calls = []
        self.release_file = simplex_prepare.getReleaseFilename(self.ctx)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def fakeDownloadRelease(self, url, path, extra_opts):
        self.download_calls.append(url)
        with open(path, "wb") as fp:
            fp.write(GOOD_BINARY)

    def fakeDownloadFile(self, url, path):
        assert url.endswith("/_sha256sums.asc"), url
        with open(path, "wb") as fp:
            fp.write(b"not a signature")

    def runPrepare(self, skip_gpg: bool = True):
        with mock.patch.object(prepare, "SKIP_GPG_VALIDATION", skip_gpg):
            prepare.prepareRelease(simplex_prepare, self.simplex_dir, self.extra_opts)

    def test_fresh_download(self):
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
        self.runPrepare()

        assert self.download_calls == [
            f"https://github.com/simplex-chat/simplex-chat/releases/download/v{TEST_VERSION}/{self.release_file}"
        ]
        with open(self.client_path, "rb") as fp:
            assert fp.read() == GOOD_BINARY
        assert os.access(self.client_path, os.X_OK)

    def test_hash_mismatch_rejected(self):
        writeSumsFile(self.release_dir, [(sha256hex(BAD_BINARY), self.release_file)])
        with self.assertRaises(ValueError):
            self.runPrepare()
        assert not os.path.exists(self.client_path)

    def test_invalid_signature_rejected(self):
        if shutil.which("gpg") is None:
            raise unittest.SkipTest("gpg binary not found")
        writeSumsFile(self.release_dir, [(sha256hex(GOOD_BINARY), self.release_file)])
        with self.assertRaises(ValueError):
            self.runPrepare(skip_gpg=False)
        assert not os.path.exists(self.client_path)

    def test_bundled_signing_key(self):
        key_path = os.path.join(
            prepare.getBasePath(),
            "pgp",
            "keys",
            simplex_prepare.getPubkeyFilename("build"),
        )
        assert os.path.isfile(key_path)

    def test_config_segment(self):
        config = simplex_prepare.getConfigSegment(self.ctx)
        assert config["type"] == "simplex"
        assert config["client_path"] == self.client_path

    def test_release_filename(self):
        for bin_arch, machine, expect in (
            ("x86_64-linux-gnu", "x86_64", "simplex-chat-ubuntu-22_04-x86_64"),
            ("aarch64-linux-gnu", "aarch64", "simplex-chat-ubuntu-22_04-aarch64"),
            ("osx64", "arm64", "simplex-chat-macos-aarch64"),
            ("osx64", "x86_64", "simplex-chat-macos-x86-64"),
            ("win64", "AMD64", "simplex-chat-windows-x86-64"),
        ):
            self.ctx.bin_arch = bin_arch
            with mock.patch.object(
                simplex_prepare_mod.platform, "machine", return_value=machine
            ):
                assert simplex_prepare.getReleaseFilename(self.ctx) == expect


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


class FakeSendWs:
    def __init__(
        self,
        connected: bool = True,
        send_error=None,
        resp_type="newChatItems",
        reply: bool = True,
        after_send=None,
    ):
        self.connected = connected
        self.connection_id = 1
        self.send_error = send_error
        self.resp_type = resp_type
        self.reply = reply
        self.after_send = after_send
        self.commands = []
        self.queue = []

    def send_command(self, cmd_str: str) -> int:
        if self.send_error is not None:
            raise self.send_error
        self.commands.append(cmd_str)
        if self.reply:
            self.queue.append(
                json.dumps({"corrId": "1", "resp": {"Right": {"type": self.resp_type}}})
            )
        if self.after_send is not None:
            self.after_send(self)
        return 1

    def cmd_queue_get(self):
        return self.queue.pop(0) if self.queue else None


class TestSimplexSend(unittest.TestCase):
    def setUp(self):
        self.app = FakeApp({"type": "simplex"})
        self.app.delay_event = threading.Event()
        self.app.num_direct_simplex_messages_sent = 0
        self.app.num_group_simplex_messages_sent = 0

    def test_send_counts(self):
        ws = FakeSendWs()
        submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")
        submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg", to_user_name="bob")
        assert ws.commands[0].startswith("#bsx ")
        assert ws.commands[1].startswith("@bob ")
        assert self.app.num_group_simplex_messages_sent == 1
        assert self.app.num_direct_simplex_messages_sent == 1

    def test_not_connected_is_temporary(self):
        ws = FakeSendWs(connected=False)
        with self.assertRaises(TemporaryError):
            submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")
        assert ws.commands == []

    def test_socket_closed_is_temporary(self):
        ws = FakeSendWs(send_error=websocket.WebSocketConnectionClosedException())
        with self.assertRaises(TemporaryError):
            submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")

    def test_rejected_send_is_permanent(self):
        ws = FakeSendWs(resp_type="chatCmdError")
        with self.assertRaises(ValueError) as cm:
            submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")
        assert not isinstance(cm.exception, TemporaryError)

    def test_disconnect_while_waiting_is_temporary(self):
        def drop(ws):
            ws.connected = False

        ws = FakeSendWs(reply=False, after_send=drop)
        with self.assertRaises(TemporaryError) as cm:
            submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")
        assert "connection lost" in str(cm.exception)
        assert len(ws.commands) == 1

    def test_reconnect_while_waiting_is_temporary(self):
        # The client reconnected before replying, the reply will never arrive.
        def reconnect(ws):
            ws.connection_id += 1

        ws = FakeSendWs(reply=False, after_send=reconnect)
        with self.assertRaises(TemporaryError):
            submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")
        assert self.app.num_group_simplex_messages_sent == 0

    def test_missing_reply_is_temporary(self):
        self.app.delay_event = mock.Mock()
        ws = FakeSendWs(reply=False)
        with self.assertRaises(TemporaryError) as cm:
            submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")
        assert "missing" in str(cm.exception)
        assert self.app.delay_event.wait.call_count == 200

    def test_stale_reply_ignored(self):
        # A reply for another command must not be taken for this one
        def stale(ws):
            ws.queue.append(
                json.dumps({"corrId": "0", "resp": {"Right": {"type": "chatCmdError"}}})
            )
            ws.queue.append(
                json.dumps({"corrId": "1", "resp": {"Right": {"type": "newChatItems"}}})
            )

        ws = FakeSendWs(reply=False, after_send=stale)
        submitSimplexMsg(self.app, {"ws_thread": ws}, b"msg")
        assert self.app.num_group_simplex_messages_sent == 1

    def test_send_command_not_connected(self):
        ws = WebSocketThread("ws://127.0.0.1:1", logger=logger)
        with self.assertRaises(TemporaryError):
            ws.send_command("/groups")
        assert ws.corrId == 0

    def test_plain_wait_times_out_with_value_error(self):
        delay_event = mock.Mock()
        ws = FakeSendWs(reply=False)
        with self.assertRaises(ValueError) as cm:
            waitForResponse(ws, 1, delay_event)
        assert not isinstance(cm.exception, TemporaryError)


class TestAddNetwork(unittest.TestCase):
    def newSettings(self, group_link: str) -> dict:
        return {
            "type": "simplex",
            "server_address": "smp://server",
            "client_path": "/bin/simplex-chat",
            "ws_port": 5225,
            "group_link": group_link,
            "enabled": True,
        }

    def test_fresh_install_appends(self):
        networks = [{"type": "smsg", "enabled": True}]
        prepare.addNetworkConfig(networks, self.newSettings(GROUP_LINK_A))
        assert networks[0] == {"type": "smsg", "enabled": True}
        assert networks[1] == self.newSettings(GROUP_LINK_A)
        assert "joined_group_link" not in networks[1]

    def test_readd_smsg_keeps_bridged(self):
        networks = [
            {"type": "smsg", "enabled": False, "bridged": [{"type": "simplex"}]},
            self.newSettings(GROUP_LINK_A),
        ]
        prepare.addNetworkConfig(networks, {"type": "smsg", "enabled": True})
        assert networks[0] == {
            "type": "smsg",
            "enabled": True,
            "bridged": [{"type": "simplex"}],
        }
        assert networks[1] == self.newSettings(GROUP_LINK_A)

    def test_replacement_link_keeps_joined_marker(self):
        networks = [
            {"type": "smsg", "enabled": False},
            {
                "type": "simplex",
                "server_address": "smp://old",
                "client_path": "/bin/old/simplex-chat",
                "ws_port": 5225,
                "group_link": GROUP_LINK_A,
                "joined_group_link": GROUP_LINK_A,
                "bridged": ["smsg"],
                "enabled": True,
            },
        ]
        prepare.addNetworkConfig(networks, self.newSettings(GROUP_LINK_B))
        assert len(networks) == 2
        simplex = networks[1]
        assert simplex["group_link"] == GROUP_LINK_B
        assert simplex["joined_group_link"] == GROUP_LINK_A
        assert simplex["server_address"] == "smp://server"
        assert simplex["client_path"] == "/bin/simplex-chat"
        assert simplex["bridged"] == ["smsg"]
        assert simplex["enabled"] is True

        # Startup with the existing client database performs the switch and
        # only then records the new link.
        app = FakeApp(simplex)
        ws = FakeGroupWs([groupInfo("bsx")])
        ensureSimplexGroup(app, ws, simplex)
        assert ws.commands == [
            "/groups",
            "/leave #bsx",
            "/delete #bsx",
            "/c " + GROUP_LINK_B,
        ]
        assert simplex["joined_group_link"] == GROUP_LINK_B
        assert app.saved == 1

    def test_legacy_install_without_marker(self):
        networks = [
            {
                "type": "simplex",
                "group_link": GROUP_LINK_A,
                "enabled": True,
            }
        ]
        prepare.addNetworkConfig(networks, self.newSettings(GROUP_LINK_A))
        simplex = networks[0]
        assert "joined_group_link" not in simplex

        app = FakeApp(simplex)
        ws = FakeGroupWs([groupInfo("bsx")])
        ensureSimplexGroup(app, ws, simplex)
        assert ws.commands == ["/groups"]
        assert simplex["joined_group_link"] == GROUP_LINK_A


if __name__ == "__main__":
    unittest.main()
