# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from basicswap.http_server import (
    HttpHandler,
    LOGIN_LOCKOUT_MAX_SECONDS,
    _login_failures,
    login_attempt_delay,
    login_attempt_failed,
    login_attempt_succeeded,
)
from basicswap.util.rfc2440 import rfc2440_hash_password

PASSWORD = "correct-password"


class LoginAttemptTrackingTest(unittest.TestCase):
    def setUp(self):
        _login_failures.clear()

    def test_unknown_client_no_delay(self):
        self.assertEqual(login_attempt_delay("1.2.3.4", time.time()), 0.0)

    def test_free_attempts_no_delay(self):
        now = time.time()
        login_attempt_failed("1.2.3.4", now)
        login_attempt_failed("1.2.3.4", now)
        self.assertEqual(login_attempt_delay("1.2.3.4", now), 0.0)

    def test_backoff_grows_and_caps(self):
        now = time.time()
        for _ in range(3):
            login_attempt_failed("1.2.3.4", now)
        self.assertAlmostEqual(login_attempt_delay("1.2.3.4", now), 2.0)
        login_attempt_failed("1.2.3.4", now)
        self.assertAlmostEqual(login_attempt_delay("1.2.3.4", now), 4.0)
        for _ in range(20):
            login_attempt_failed("1.2.3.4", now)
        self.assertAlmostEqual(
            login_attempt_delay("1.2.3.4", now), LOGIN_LOCKOUT_MAX_SECONDS
        )

    def test_delay_expires(self):
        now = time.time()
        for _ in range(3):
            login_attempt_failed("1.2.3.4", now)
        self.assertEqual(login_attempt_delay("1.2.3.4", now + 3.0), 0.0)

    def test_success_clears_failures(self):
        now = time.time()
        for _ in range(5):
            login_attempt_failed("1.2.3.4", now)
        login_attempt_succeeded("1.2.3.4")
        self.assertEqual(login_attempt_delay("1.2.3.4", now), 0.0)

    def test_clients_tracked_separately(self):
        now = time.time()
        for _ in range(5):
            login_attempt_failed("1.2.3.4", now)
        self.assertEqual(login_attempt_delay("5.6.7.8", now), 0.0)


def make_handler(password):
    handler = HttpHandler.__new__(HttpHandler)
    handler.headers = {"Content-Type": "application/json"}
    handler.client_address = ("1.2.3.4", 12345)
    handler.server = SimpleNamespace(
        swap_client=SimpleNamespace(
            settings={"client_auth_hash": rfc2440_hash_password(PASSWORD)},
            log=MagicMock(),
            ws_server=None,
            debug=False,
        ),
        host_name="127.0.0.1",
    )
    handler.statuses = []
    handler.putHeaders = lambda status, ctype, extra_headers=None: (
        handler.statuses.append(status)
    )
    handler._create_session = lambda: ("sid", ("Set-Cookie", "session=sid"))
    handler._clear_session_cookie = lambda: ("Set-Cookie", "session=")
    post_string = json.dumps({"password": password}).encode("utf-8")
    return handler, post_string


class PageLoginRateLimitTest(unittest.TestCase):
    def setUp(self):
        _login_failures.clear()

    def test_lockout_after_repeated_failures(self):
        for i in range(3):
            handler, post = make_handler("wrong-password")
            rv = handler.page_login([], post)
            self.assertEqual(handler.statuses, [401], f"attempt {i}")
            self.assertIn(b"Invalid password", rv)

        handler, post = make_handler("wrong-password")
        rv = handler.page_login([], post)
        self.assertEqual(handler.statuses, [429])
        self.assertIn(b"Too many failed attempts", rv)

    def test_correct_password_blocked_during_lockout(self):
        now = time.time()
        for _ in range(4):
            login_attempt_failed("1.2.3.4", now)
        handler, post = make_handler(PASSWORD)
        rv = handler.page_login([], post)
        self.assertEqual(handler.statuses, [429])
        self.assertIn(b"Too many failed attempts", rv)

    def test_correct_password_after_lockout_expires(self):
        now = time.time()
        for _ in range(3):
            login_attempt_failed("1.2.3.4", now - 60.0)
        handler, post = make_handler(PASSWORD)
        rv = handler.page_login([], post)
        self.assertEqual(handler.statuses, [200])
        self.assertTrue(json.loads(rv)["success"])
        self.assertEqual(login_attempt_delay("1.2.3.4", time.time()), 0.0)


if __name__ == "__main__":
    unittest.main()
