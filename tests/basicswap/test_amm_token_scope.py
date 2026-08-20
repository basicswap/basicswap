# -*- coding: utf-8 -*-

# Copyright (c) 2026 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import base64
import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from basicswap.http_server import HttpHandler, amm_endpoint_allowed
from basicswap.util.rfc2440 import rfc2440_hash_password

AMM_TOKEN = "test-amm-token"
OPERATOR_PWD = "operator-password"


def split_path(path):
    return path.split("?")[0].split("/")


class AmmEndpointAllowedTest(unittest.TestCase):
    def test_allowed_endpoints(self):
        for path in (
            "/json/offers",
            "/json/offers/new",
            "/json/sentoffers",
            "/json/sentoffers/abcd",
            "/json/revokeoffer/abcd",
            "/json/bids",
            "/json/bids/new",
            "/json/bids/abcd",
            "/json/sentbids",
            "/json/identities/someaddr",
            "/json/rates",
            "/json/offerfeeestimate",
            "/json/validateamount",
            "/json/coins",
            "/json/wallets",
            "/json/wallets/btc",
        ):
            self.assertTrue(amm_endpoint_allowed(split_path(path)), path)

    def test_denied_endpoints(self):
        for path in (
            "/",
            "/offers",
            "/shutdown",
            "/json",
            "/json/",
            "/json/wallets/btc/withdraw",
            "/json/wallets/btc/reseed",
            "/json/wallets/btc/createutxo",
            "/json/smsgaddresses",
            "/json/unlock",
            "/json/lock",
            "/json/generatenotification",
            "/json/automationstrategies",
        ):
            self.assertFalse(amm_endpoint_allowed(split_path(path)), path)


def make_handler(path, password, command="GET"):
    handler = HttpHandler.__new__(HttpHandler)
    handler.path = path
    handler.command = command
    creds = base64.b64encode(f"amm:{password}".encode()).decode()
    handler.headers = {
        "Authorization": f"Basic {creds}",
        "Sec-Fetch-Dest": "empty",
    }
    handler.server = SimpleNamespace(
        swap_client=SimpleNamespace(
            _amm_api_token=AMM_TOKEN,
            settings={"client_auth_hash": rfc2440_hash_password(OPERATOR_PWD)},
            log=MagicMock(),
        ),
        allow_cors=False,
    )
    handler.wfile = MagicMock()
    handler.statuses = []
    handler.putHeaders = lambda status, ctype, extra_headers=None: (
        handler.statuses.append(status)
    )
    handler.is_allowed_host = lambda: True
    handler.is_same_origin_request = lambda: True
    return handler


class AmmTokenScopeTest(unittest.TestCase):
    def test_token_rejected_on_wallet_withdraw(self):
        handler = make_handler("/json/wallets/btc/withdraw", AMM_TOKEN, "POST")
        rv = handler.handle_http(200, handler.path)
        self.assertEqual(handler.statuses, [403])
        self.assertIn(b"not authorized", rv)

    def test_token_rejected_on_ui_page(self):
        handler = make_handler("/settings", AMM_TOKEN)
        rv = handler.handle_http(200, handler.path)
        self.assertEqual(handler.statuses, [403])
        self.assertIn(b"not authorized", rv)

    def test_token_rejected_on_unlock(self):
        handler = make_handler("/json/unlock", AMM_TOKEN)
        rv = handler.handle_http(200, handler.path)
        self.assertEqual(handler.statuses, [403])
        self.assertIn(b"not authorized", rv)

    def test_operator_password_not_scope_restricted(self):
        handler = make_handler("/json/unlock", OPERATOR_PWD)
        rv = handler.handle_http(200, handler.path)
        self.assertEqual(handler.statuses, [405])
        self.assertEqual(json.loads(rv), {"error": "POST required"})

    def test_wrong_password_rejected(self):
        handler = make_handler("/json/offers", "wrong-password")
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        rv = handler.handle_http(200, handler.path)
        self.assertEqual(rv, b"")
        handler.send_response.assert_called_once_with(401)


if __name__ == "__main__":
    unittest.main()
