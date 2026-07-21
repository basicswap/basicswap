# -*- coding: utf-8 -*-

# Copyright (c) 2019-2024 tecnovert
# Copyright (c) 2024-2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import gzip
import hmac
import json
import shlex
import hashlib
import secrets
import traceback
import threading
import http.client
import base64

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from jinja2 import Environment, PackageLoader, select_autoescape
from socket import error as SocketError
from urllib import parse
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, parsedate_to_datetime
from http.cookies import SimpleCookie

from . import __version__, GUI_VERSION, AMM_VERSION
from . import config as cfg
from .util import (
    BalanceError,
    LockedCoinError,
    dumpj,
    format_timestamp,
    toBool,
)
from .chainparams import (
    Coins,
    chainparams,
)
from .basicswap_util import (
    strTxState,
    strBidState,
)
from .util.rfc2440 import verify_rfc2440_password
from .util.network import allowed_entry_hostname, is_origin_allowed

from .js_server import (
    js_error,
    js_url_to_function,
)
from .ui.util import (
    getCoinName,
    get_data_entry,
    get_data_entry_or,
    listAvailableCoins,
)
from .ui.page_automation import (
    page_automation_strategies,
    page_automation_strategy,
    page_automation_strategy_new,
)

from .ui.page_amm import (
    page_amm,
    amm_status_api,
    amm_autostart_api,
    amm_debug_api,
    amm_config_api,
    amm_state_api,
)
from .ui.page_bids import page_bids, page_bid
from .ui.page_offers import page_offers, page_offer, page_newoffer
from .ui.page_tor import page_tor, get_tor_established_state
from .ui.page_wallet import page_wallets, page_wallet
from .ui.page_settings import page_settings
from .ui.page_encryption import page_changepassword, page_unlock, page_lock
from .ui.page_identity import page_identity
from .ui.page_smsgaddresses import page_smsgaddresses
from .ui.page_debug import page_debug

SESSION_COOKIE_NAME = "basicswap_session_id"
LOGIN_NEXT_COOKIE_NAME = "basicswap_login_next"
SESSION_DURATION_MINUTES = 60

env = Environment(
    loader=PackageLoader("basicswap", "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)
env.filters["formatts"] = format_timestamp


def extractDomain(url):
    return url.split("://", 1)[1].split("/", 1)[0]


def listAvailableExplorers(swap_client):
    explorers = []
    for c in Coins:
        if c not in chainparams:
            continue
        for i, e in enumerate(swap_client.coin_clients[c]["explorers"]):
            explorers.append(
                (
                    "{}_{}".format(int(c), i),
                    getCoinName(c) + " - " + extractDomain(e.base_url),
                )
            )
    return explorers


def listExplorerActions(swap_client):
    actions = [
        ("height", "Chain Height"),
        ("block", "Get Block"),
        ("tx", "Get Transaction"),
        ("balance", "Address Balance"),
        ("unspent", "List Unspent"),
    ]
    return actions


def parse_cmd(cmd: str, type_map: str):
    params = shlex.split(cmd)
    if len(params) < 1:
        return "", []
    method = params[0]
    typed_params = []
    params = params[1:]

    for i, param in enumerate(params):
        if i >= len(type_map):
            type_ind = "s"
        else:
            type_ind = type_map[i]
        if type_ind == "i":
            typed_params.append(int(param))
        elif type_ind == "f":
            typed_params.append(float(param))
        elif type_ind == "b":
            typed_params.append(toBool(param))
        elif type_ind == "j":
            typed_params.append(json.loads(param))
        else:
            typed_params.append(param)

    return method, typed_params


# GET is allowed only for these read /json routes. Every other route — including
# any new or unknown endpoint — requires POST (fail closed), so a state-changing
# endpoint can't be reached cross-origin via a GET (<img>/<script>/prefetch)
# just because someone forgot to list it. Add new READ routes here; new
# state-changing routes need no change (they are POST-only by default).
JSON_GET_ALLOWED = frozenset(
    {
        "coins",
        "walletbalances",
        "wallets",
        "wallettransactions",
        "offers",
        "sentoffers",
        "bids",
        "sentbids",
        "network",
        "smsgaddresses",
        "rate",
        "rates",
        "rateslist",
        "offerfeeestimate",
        "checkupdates",
        "updatestatus",
        "notifications",
        "identities",
        "automationstrategies",
        "validateamount",
        "help",
        "readurl",
        "active",
        "coinprices",
        "coinvolume",
        "coinhistory",
        "messageroutes",
        "modeswitchinfo",
    }
)
# Read sub-commands of /wallets/<coin>/<cmd>; every other wallet sub-command
# mutates and requires POST.
JSON_WALLET_GET_CMDS = frozenset({"listaddresses", "mwebbalance"})


def json_requires_post(url_split) -> bool:
    route = url_split[2] if len(url_split) > 2 else ""
    if route == "":
        return False  # /json index — read
    if route not in JSON_GET_ALLOWED:
        return True
    if (
        route == "wallets"
        and len(url_split) > 4
        and url_split[4] not in JSON_WALLET_GET_CMDS
    ):
        return True
    if route == "offers" and len(url_split) > 3 and url_split[3] == "new":
        return True
    return False


class HttpHandler(BaseHTTPRequestHandler):
    def _get_session_cookie(self):
        if "Cookie" in self.headers:
            cookie = SimpleCookie(self.headers["Cookie"])
            if SESSION_COOKIE_NAME in cookie:
                return cookie[SESSION_COOKIE_NAME].value
        return None

    def _session_timeout_minutes(self):
        return self.server.swap_client.settings.get(
            "session_timeout_minutes", SESSION_DURATION_MINUTES
        )

    def _safe_next_path(self, value):
        # Only allow same-site absolute paths as a redirect target (open-redirect guard).
        if not value or not value.startswith("/") or value.startswith("//"):
            return None
        if "\\" in value or "://" in value or "\n" in value or "\r" in value:
            return None
        return value

    def _set_session_cookie(self, session_id):
        cookie = SimpleCookie()
        cookie[SESSION_COOKIE_NAME] = session_id
        cookie[SESSION_COOKIE_NAME]["path"] = "/"
        cookie[SESSION_COOKIE_NAME]["httponly"] = True
        cookie[SESSION_COOKIE_NAME]["samesite"] = "Lax"
        # "Secure" tells the browser to send this cookie back only over HTTPS, so
        # the session id can't leak over plain HTTP. Set when the request
        # actually arrived over TLS (a reverse proxy signals this with
        # X-Forwarded-Proto: https) or when the operator forces it via the
        # secure_cookies setting.
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "").lower()
        if forwarded_proto == "https" or self.server.swap_client.settings.get(
            "secure_cookies", cfg.DEFAULT_SECURE_COOKIES
        ):
            cookie[SESSION_COOKIE_NAME]["secure"] = True
        expires = datetime.now(timezone.utc) + timedelta(
            minutes=SESSION_DURATION_MINUTES
        )
        cookie[SESSION_COOKIE_NAME]["expires"] = expires.strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        return ("Set-Cookie", cookie.output(header="").strip())

    def _clear_session_cookie(self):
        cookie = SimpleCookie()
        cookie[SESSION_COOKIE_NAME] = ""
        cookie[SESSION_COOKIE_NAME]["path"] = "/"
        cookie[SESSION_COOKIE_NAME]["httponly"] = True
        cookie[SESSION_COOKIE_NAME]["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
        return ("Set-Cookie", cookie.output(header="").strip())

    def _set_login_next_cookie(self, next_path):
        cookie = SimpleCookie()
        cookie[LOGIN_NEXT_COOKIE_NAME] = parse.quote(next_path, safe="")
        cookie[LOGIN_NEXT_COOKIE_NAME]["path"] = "/"
        cookie[LOGIN_NEXT_COOKIE_NAME]["samesite"] = "Lax"
        forwarded_proto = self.headers.get("X-Forwarded-Proto", "").lower()
        if forwarded_proto == "https" or self.server.swap_client.settings.get(
            "secure_cookies", cfg.DEFAULT_SECURE_COOKIES
        ):
            cookie[LOGIN_NEXT_COOKIE_NAME]["secure"] = True
        return ("Set-Cookie", cookie.output(header="").strip())

    def _get_login_next_cookie(self):
        if "Cookie" in self.headers:
            cookie = SimpleCookie(self.headers["Cookie"])
            if LOGIN_NEXT_COOKIE_NAME in cookie:
                return parse.unquote(cookie[LOGIN_NEXT_COOKIE_NAME].value)
        return None

    def _clear_login_next_cookie(self):
        cookie = SimpleCookie()
        cookie[LOGIN_NEXT_COOKIE_NAME] = ""
        cookie[LOGIN_NEXT_COOKIE_NAME]["path"] = "/"
        cookie[LOGIN_NEXT_COOKIE_NAME]["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
        return ("Set-Cookie", cookie.output(header="").strip())

    def is_authenticated(self):
        swap_client = self.server.swap_client
        client_auth_hash = swap_client.settings.get("client_auth_hash")

        if not client_auth_hash:
            return True

        session_id = self._get_session_cookie()
        if not session_id:
            return False

        with self.server.session_lock:
            session_data = self.server.active_sessions.get(session_id)
            if session_data and session_data["expires"] > datetime.now(timezone.utc):
                session_data["expires"] = datetime.now(timezone.utc) + timedelta(
                    minutes=SESSION_DURATION_MINUTES
                )
                return True

            if session_id in self.server.active_sessions:
                del self.server.active_sessions[session_id]
        return False

    def is_same_origin_request(self) -> bool:
        # CSRF defence, verify-when-present: a browser always sends Origin on a
        # cross-origin POST, so a header-less client (tests/curl/API scripts) is
        # not a browser CSRF and is allowed. When present, the full Origin/Referer
        # (scheme + host + port) is validated against the allowed origins via the
        # shared is_origin_allowed (also used by the WebSocket handshake). "*" is
        # a Host-check opt-out only; the origin check is always enforced.
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True
        return is_origin_allowed(
            origin,
            getattr(self.server, "host_name", None),
            getattr(self.server, "port_no", None),
            self.server.swap_client.settings.get("allowed_hosts", []),
        )

    def _get_allowed_hosts(self) -> set:
        # The fixed set of hostnames this server is legitimately served under.
        allowed = {"localhost", "127.0.0.1", "::1"}
        host_name = getattr(self.server, "host_name", "") or ""
        # Never add 0.0.0.0/::/empty — a bind-all address is not a hostname a
        # browser sends, and http://0.0.0.0 can reach loopback in some browsers
        # (0.0.0.0-day).
        if host_name and host_name not in ("0.0.0.0", "::"):
            allowed.add(host_name.lower())
        for h in self.server.swap_client.settings.get("allowed_hosts", []) or []:
            if h == "*":
                continue
            hostname = allowed_entry_hostname(h)
            if hostname:
                allowed.add(hostname)
        return allowed

    def _host_check_disabled(self) -> bool:
        # "*" in allowed_hosts opts out of the Host check (Django ALLOWED_HOSTS
        # convention). This re-opens DNS-rebinding exposure, so it only takes
        # effect when client_auth_hash is set (authentication becomes the
        # fallback defence) or the unsafe_allow_any_host_without_auth override
        # is enabled; otherwise the Host check stays enforced. Startup also
        # refuses "*" without client_auth_hash or the override.
        settings = self.server.swap_client.settings
        if "*" not in (settings.get("allowed_hosts", []) or []):
            return False
        if settings.get("unsafe_allow_any_host_without_auth"):
            return True
        return bool(settings.get("client_auth_hash"))

    def is_allowed_host(self) -> bool:
        if self._host_check_disabled():
            return True
        host = self.headers.get("Host")
        if not host:
            return False  # fail closed; HTTP/1.1 requires Host, browsers always send it
        hostname = parse.urlsplit("//" + host).hostname
        if not hostname:
            return False
        return hostname.lower() in self._get_allowed_hosts()

    def log_error(self, format, *args):
        super().log_message(format, *args)

    def log_message(self, format, *args):
        # TODO: Add debug flag to re-enable.
        pass

    def checkForm(self, post_string, name, messages):
        if post_string == "":
            return None
        form_data = parse.parse_qs(post_string)
        try:
            form_id = form_data[b"formid"][0].decode("utf-8")
        except (KeyError, IndexError):
            messages.append("Missing form token.")
            return None
        # Real CSRF check: the form must carry the server-issued token. Replaces
        # the former per-form-name double-submit latch, which was not a security
        # control (any fresh value passed).
        if not hmac.compare_digest(form_id, self.server.session_tokens.get("csrf", "")):
            messages.append("Invalid form token.")
            return None
        return form_data

    def render_template(
        self,
        template,
        args_dict,
        status_code=200,
        version=__version__,
        extra_headers=None,
    ) -> bytes:
        swap_client = self.server.swap_client
        if swap_client.ws_server:
            args_dict["ws_port"] = swap_client.ws_server.client_port
        if swap_client.debug:
            args_dict["debug_mode"] = True
        if swap_client.debug_ui:
            args_dict["debug_ui_mode"] = True

        is_authenticated = self.is_authenticated() or not swap_client.settings.get(
            "client_auth_hash"
        )

        if is_authenticated:
            if swap_client.use_tor_proxy:
                args_dict["use_tor_proxy"] = True
                try:
                    tor_state = get_tor_established_state(swap_client)
                    args_dict["tor_established"] = True if tor_state == "1" else False
                except Exception:
                    args_dict["tor_established"] = False

            from .ui.page_amm import get_amm_status, get_amm_active_count

            try:
                args_dict["current_status"] = get_amm_status()
                args_dict["amm_active_count"] = get_amm_active_count(swap_client)
            except Exception:
                args_dict["current_status"] = "stopped"
                args_dict["amm_active_count"] = 0

            if swap_client._show_notifications:
                args_dict["notifications"] = swap_client.getNotifications()
        else:
            args_dict["current_status"] = "unknown"
            args_dict["amm_active_count"] = 0

        if "messages" in args_dict:
            messages_with_ids = []
            with self.server.msg_id_lock:
                for msg in args_dict["messages"]:
                    messages_with_ids.append((self.server.msg_id_counter, msg))
                    self.server.msg_id_counter += 1
            args_dict["messages"] = messages_with_ids
        if "err_messages" in args_dict:
            err_messages_with_ids = []
            with self.server.msg_id_lock:
                for msg in args_dict["err_messages"]:
                    err_messages_with_ids.append((self.server.msg_id_counter, msg))
                    self.server.msg_id_counter += 1
            args_dict["err_messages"] = err_messages_with_ids

        if self.path:
            parsed = parse.urlparse(self.path)
            url_split = parsed.path.split("/")
            if len(url_split) > 1 and url_split[1]:
                args_dict["current_page"] = url_split[1]
            else:
                args_dict["current_page"] = "index"
        else:
            args_dict["current_page"] = "index"

        shutdown_token = os.urandom(8).hex()
        with self.server.session_lock:
            self.server.session_tokens["shutdown"] = shutdown_token
        args_dict["shutdown_token"] = shutdown_token

        if is_authenticated:
            try:
                encrypted, locked = swap_client.getLockedState()
                args_dict["encrypted"] = encrypted
                args_dict["locked"] = locked
            except Exception as e:
                args_dict["encrypted"] = False
                args_dict["locked"] = False
                if swap_client.debug:
                    swap_client.log.warning(f"Could not get wallet locked state: {e}")
        else:
            args_dict["encrypted"] = args_dict.get("encrypted", False)
            args_dict["locked"] = args_dict.get("locked", False)

        with self.server.msg_id_lock:
            if self.server.msg_id_counter >= 0x7FFFFFFF:
                self.server.msg_id_counter = 0

        args_dict["version"] = version
        args_dict["gui_version"] = GUI_VERSION
        args_dict["amm_version"] = AMM_VERSION
        args_dict["update_available"] = getattr(swap_client, "_update_available", False)
        args_dict["latest_version"] = getattr(swap_client, "_latest_version", None)

        try:
            static_dir = os.path.join(os.path.dirname(__file__), "static")
            mtimes = []
            for rel in (
                os.path.join("css", "style.css"),
                os.path.join("js", "pages", "offer-new-page.js"),
            ):
                mtimes.append(int(os.path.getmtime(os.path.join(static_dir, rel))))
            args_dict["static_v"] = "{}-{}".format(version, max(mtimes))
        except Exception:
            args_dict["static_v"] = version

        self.putHeaders(status_code, "text/html", extra_headers=extra_headers)
        return bytes(
            template.render(
                title=self.server.title,
                h2=self.server.title,
                form_id=self.server.session_tokens["csrf"],
                **args_dict,
            ),
            "UTF-8",
        )

    def render_simple_template(self, template, args_dict):
        self.putHeaders(200, "text/html")
        return bytes(
            template.render(
                title=self.server.title,
                **args_dict,
            ),
            "UTF-8",
        )

    def page_info(self, info_str, post_string=None, extra_headers=None):
        template = env.get_template("info.html")
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()
        return self.render_template(
            template,
            {
                "title_str": "BasicSwap Info",
                "message_str": info_str,
                "summary": summary,
            },
            extra_headers=extra_headers,
        )

    def page_error(self, error_str, post_string=None):
        template = env.get_template("error.html")
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()
        return self.render_template(
            template,
            {
                "title_str": "BasicSwap Error",
                "message_str": error_str,
                "summary": summary,
            },
        )

    def page_login(self, url_split, post_string):
        swap_client = self.server.swap_client
        template = env.get_template("login.html")
        err_messages = []
        extra_headers = []
        is_json_request = "application/json" in self.headers.get("Content-Type", "")
        security_warning = None
        if self.server.host_name not in ("127.0.0.1", "localhost"):
            security_warning = "WARNING: Server is accessible on the network. Sending password over plain HTTP is insecure. Use HTTPS (e.g., via reverse proxy) for non-local access."
            if not is_json_request:
                err_messages.append(security_warning)

        if post_string:
            password = None
            if is_json_request:
                try:
                    json_data = json.loads(post_string.decode("utf-8"))
                    password = json_data.get("password")
                except Exception as e:
                    swap_client.log.error(f"Error parsing JSON login data: {e}")
            else:
                try:
                    form_data = parse.parse_qs(post_string.decode("utf-8"))
                    password = form_data.get("password", [None])[0]
                except Exception as e:
                    swap_client.log.error(f"Error parsing form login data: {e}")

            client_auth_hash = swap_client.settings.get("client_auth_hash")

            if (
                client_auth_hash
                and password is not None
                and verify_rfc2440_password(client_auth_hash, password)
            ):
                session_id = secrets.token_urlsafe(32)
                expires = datetime.now(timezone.utc) + timedelta(
                    minutes=SESSION_DURATION_MINUTES
                )
                with self.server.session_lock:
                    self.server.active_sessions[session_id] = {"expires": expires}
                cookie_header = self._set_session_cookie(session_id)

                if is_json_request:
                    response_data = {"success": True, "session_id": session_id}
                    if security_warning:
                        response_data["warning"] = security_warning
                    self.putHeaders(
                        200, "application/json", extra_headers=[cookie_header]
                    )
                    return json.dumps(response_data).encode("utf-8")
                else:
                    self.send_response(302)
                    self.send_header(
                        "Location",
                        self._safe_next_path(self._get_login_next_cookie())
                        or "/offers",
                    )
                    self.send_header(cookie_header[0], cookie_header[1])
                    clear_next = self._clear_login_next_cookie()
                    self.send_header(clear_next[0], clear_next[1])
                    self.end_headers()
                    return b""
            else:
                if is_json_request:
                    self.putHeaders(401, "application/json")
                    return json.dumps({"error": "Invalid password"}).encode("utf-8")
                else:
                    err_messages.append("Invalid password.")
                    clear_cookie_header = self._clear_session_cookie()
                    extra_headers.append(clear_cookie_header)

        if (
            not is_json_request
            and swap_client.settings.get("client_auth_hash")
            and self.is_authenticated()
        ):
            self.send_response(302)
            self.send_header(
                "Location",
                self._safe_next_path(self._get_login_next_cookie()) or "/offers",
            )
            clear_next = self._clear_login_next_cookie()
            self.send_header(clear_next[0], clear_next[1])
            self.end_headers()
            return b""

        return self.render_template(
            template,
            {
                "title_str": "Login",
                "messages": [],
                "err_messages": err_messages,
                "summary": {},
                "encrypted": False,
                "locked": False,
            },
            status_code=401 if post_string and not is_json_request else 200,
            extra_headers=extra_headers,
        )

    def page_shutdown_ping(self, url_split, post_string):
        if not self.server.stop_event.is_set():
            raise ValueError("Unexpected shutdown ping.")
        self.putHeaders(401, "application/json")
        return json.dumps({"ack": True}).encode("utf-8")

    def page_explorers(self, url_split, post_string):
        swap_client = self.server.swap_client
        swap_client.checkSystemStatus()
        summary = swap_client.getSummary()

        result = None
        explorer = -1
        action = -1
        messages = []
        err_messages = []
        form_data = self.checkForm(post_string, "explorers", err_messages)
        if form_data:

            explorer = get_data_entry(form_data, "explorer")
            action = get_data_entry(form_data, "action")
            args = get_data_entry_or(form_data, "args", "")

            try:
                c, e = explorer.split("_")
                exp = swap_client.coin_clients[Coins(int(c))]["explorers"][int(e)]
                if action == "height":
                    result = str(exp.getChainHeight())
                elif action == "block":
                    result = dumpj(exp.getBlock(args))
                elif action == "tx":
                    result = dumpj(exp.getTransaction(args))
                elif action == "balance":
                    result = dumpj(exp.getBalance(args))
                elif action == "unspent":
                    result = dumpj(exp.lookupUnspentByAddress(args))
                else:
                    result = "Unknown action"
            except Exception as ex:
                result = str(ex)

        template = env.get_template("explorers.html")
        return self.render_template(
            template,
            {
                "messages": messages,
                "err_messages": err_messages,
                "explorers": listAvailableExplorers(swap_client),
                "explorer": explorer,
                "actions": listExplorerActions(swap_client),
                "action": action,
                "result": result,
                "summary": summary,
            },
        )

    def page_rpc(self, url_split, post_string):
        swap_client = self.server.swap_client
        swap_client.checkSystemStatus()
        summary = swap_client.getSummary()

        result = None
        cmd = ""
        coin_type_selected = -1
        coin_type = -1
        call_type = "cli"
        type_map = ""
        messages = []
        err_messages = []
        form_data = self.checkForm(post_string, "rpc", err_messages)
        if form_data:
            try:
                call_type = get_data_entry_or(form_data, "call_type", "cli")
                type_map = get_data_entry_or(form_data, "type_map", "")
                try:
                    coin_type_selected = get_data_entry(form_data, "coin_type")
                    coin_type_split = coin_type_selected.split(",")
                    coin_type = Coins(int(coin_type_split[0]))
                    coin_variant = int(coin_type_split[1])
                except Exception:
                    raise ValueError("Unknown Coin Type")

                if coin_type in (Coins.DCR,):
                    call_type = "http"

                try:
                    cmd = get_data_entry(form_data, "cmd")
                except Exception:
                    raise ValueError("Invalid command")
                if coin_type in swap_client.xmr_based_coins:
                    ci = swap_client.ci(coin_type)
                    arr = cmd.split(None, 1)
                    method = arr[0]
                    params = json.loads(arr[1]) if len(arr) > 1 else []
                    if coin_variant == 2:
                        rv = ci.rpc_wallet(method, params)
                    elif coin_variant == 0:
                        rv = ci.rpc(method, params)
                    elif coin_variant == 1:
                        if params == []:
                            params = None
                        rv = ci.rpc2(method, params)
                    else:
                        raise ValueError("Unknown RPC variant")
                    result = json.dumps(rv, indent=4)
                else:
                    if call_type == "http":
                        ci = swap_client.ci(coin_type)
                        method, params = parse_cmd(cmd, type_map)
                        if coin_variant == 1:
                            rv = ci.rpc_wallet(method, params)
                        elif coin_variant == 2:
                            rv = ci.rpc_wallet_mweb(method, params)
                        else:
                            if coin_type in (Coins.DCR,):
                                rv = ci.rpc(method, params)
                            else:
                                rv = ci.rpc_wallet(method, params)
                        if not isinstance(rv, str):
                            rv = json.dumps(rv, indent=4)
                        result = cmd + "\n" + rv
                    else:
                        result = cmd + "\n" + swap_client.callcoincli(coin_type, cmd)
            except Exception as ex:
                result = cmd + "\n" + str(ex)
                if self.server.swap_client.debug is True:
                    self.server.swap_client.log.error(traceback.format_exc())

        template = env.get_template("rpc.html")

        coin_available = listAvailableCoins(swap_client, with_variants=False)
        with_xmr: bool = any(c[0] == Coins.XMR for c in coin_available)
        with_wow: bool = any(c[0] == Coins.WOW for c in coin_available)
        coins = [
            (str(c[0]) + ",0", c[1])
            for c in coin_available
            if c[0] not in swap_client.xmr_based_coins
        ]

        if any(c[0] == Coins.DCR for c in coin_available):
            coins.append((str(int(Coins.DCR)) + ",1", "Decred Wallet"))
        if any(c[0] == Coins.LTC for c in coin_available):
            coins.append((str(int(Coins.LTC)) + ",2", "Litecoin MWEB Wallet"))
        if with_xmr:
            coins.append((str(int(Coins.XMR)) + ",0", "Monero"))
            coins.append((str(int(Coins.XMR)) + ",1", "Monero JSON"))
            coins.append((str(int(Coins.XMR)) + ",2", "Monero Wallet"))
        if with_wow:
            coins.append((str(int(Coins.WOW)) + ",0", "Wownero"))
            coins.append((str(int(Coins.WOW)) + ",1", "Wownero JSON"))
            coins.append((str(int(Coins.WOW)) + ",2", "Wownero Wallet"))

        return self.render_template(
            template,
            {
                "messages": messages,
                "err_messages": err_messages,
                "coins": coins,
                "coin_type": coin_type_selected,
                "call_type": call_type,
                "result": result,
                "summary": summary,
            },
        )

    def page_active(self, url_split, post_string):
        swap_client = self.server.swap_client
        swap_client.checkSystemStatus()
        active_swaps = swap_client.listSwapsInProgress()
        summary = swap_client.getSummary()

        template = env.get_template("active.html")
        return self.render_template(
            template,
            {
                "active_swaps": [
                    (
                        s[0].hex(),
                        s[1],
                        strBidState(s[2]),
                        strTxState(s[3]),
                        strTxState(s[4]),
                    )
                    for s in active_swaps
                ],
                "summary": summary,
            },
        )

    def page_watched(self, url_split, post_string):
        swap_client = self.server.swap_client
        swap_client.checkSystemStatus()
        watched_outputs, last_scanned = swap_client.listWatchedOutputs()
        summary = swap_client.getSummary()

        template = env.get_template("watched.html")
        return self.render_template(
            template,
            {
                "refresh": 30,
                "last_scanned": [(getCoinName(ls[0]), ls[1]) for ls in last_scanned],
                "watched_outputs": [
                    (wo[1].hex(), getCoinName(wo[0]), wo[2], wo[3], int(wo[4]))
                    for wo in watched_outputs
                ],
                "summary": summary,
            },
        )

    def page_shutdown(self, url_split, post_string):
        swap_client = self.server.swap_client
        extra_headers = []

        token = url_split[2] if len(url_split) > 2 else ""
        with self.server.session_lock:
            expect_token = self.server.session_tokens.get("shutdown", "")
        if not expect_token or not hmac.compare_digest(token, expect_token):
            return self.page_info("Unexpected token, still running.")

        session_id = self._get_session_cookie()
        with self.server.session_lock:
            if session_id and session_id in self.server.active_sessions:
                del self.server.active_sessions[session_id]
        clear_cookie_header = self._clear_session_cookie()
        extra_headers.append(clear_cookie_header)

        try:
            from basicswap.ui.page_amm import stop_amm_process, get_amm_status

            amm_status = get_amm_status()
            if amm_status == "running":
                swap_client.log.info("Web shutdown stopping AMM process...")
                success, msg = stop_amm_process(swap_client)
                if success:
                    swap_client.log.info(f"AMM web shutdown: {msg}")
                else:
                    swap_client.log.warning(f"AMM web shutdown warning: {msg}")
        except Exception as e:
            swap_client.log.error(f"Error stopping AMM in web shutdown: {e}")

        swap_client.stopRunning()

        return self.page_info("Shutting down", extra_headers=extra_headers)

    def page_donation(self, url_split, post_string):
        swap_client = self.server.swap_client
        swap_client.checkSystemStatus()
        summary = swap_client.getSummary()

        template = env.get_template("donation.html")
        return self.render_template(
            template,
            {
                "summary": summary,
            },
        )

    def page_index(self, url_split):
        swap_client = self.server.swap_client
        swap_client.checkSystemStatus()
        self.send_response(302)
        self.send_header("Location", "/offers")
        self.end_headers()
        return b""

    def page_404(self, url_split):
        swap_client = self.server.swap_client
        summary = swap_client.getSummary()
        template = env.get_template("404.html")
        return self.render_template(
            template,
            {
                "summary": summary,
            },
        )

    def putHeaders(self, status_code, content_type, extra_headers=None):
        self.send_response(status_code)
        if self.server.allow_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", content_type)
        if extra_headers:
            for header_tuple in extra_headers:
                self.send_header(header_tuple[0], header_tuple[1])
        self.end_headers()

    def handle_http(self, status_code, path, post_string="", is_json=False):
        swap_client = self.server.swap_client
        parsed = parse.urlparse(self.path)
        url_split = parsed.path.split("/")
        page = url_split[1] if len(url_split) > 1 else ""

        if not self.is_allowed_host():
            if page == "json":
                self.putHeaders(403, "application/json")
                return json.dumps({"error": "Host not allowed"}).encode("utf-8")
            self.putHeaders(403, "text/html")
            return b"Host not allowed"

        exempt_pages = ["login", "static", "error", "info"]
        auth_header = self.headers.get("Authorization")
        basic_auth_ok = False

        if auth_header and auth_header.startswith("Basic "):
            try:
                encoded_creds = auth_header.split(" ", 1)[1]
                decoded_creds = base64.b64decode(encoded_creds).decode("utf-8")
                _, password = decoded_creds.split(":", 1)

                client_auth_hash = swap_client.settings.get("client_auth_hash")
                if client_auth_hash and verify_rfc2440_password(
                    client_auth_hash, password
                ):
                    basic_auth_ok = True
                else:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="Basicswap"')
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(
                        json.dumps({"error": "Invalid Basic Auth credentials"}).encode(
                            "utf-8"
                        )
                    )
                    return b""
            except Exception as e:
                swap_client.log.error(f"Error processing Basic Auth header: {e}")
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Basicswap"')
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"error": "Malformed Basic Auth header"}).encode("utf-8")
                )
                return b""

        if not basic_auth_ok and page not in exempt_pages:
            if not self.is_authenticated():
                if page == "json":
                    self.putHeaders(401, "application/json")
                    self.wfile.write(
                        json.dumps({"error": "Unauthorized"}).encode("utf-8")
                    )
                    return b""
                else:
                    self.send_response(302)
                    self.send_header("Location", "/login")
                    if (
                        self.command == "GET"
                        and self.headers.get("Sec-Fetch-Dest", "document") == "document"
                        and parsed.path not in ("", "/", "/login")
                    ):
                        next_target = parsed.path
                        if parsed.query:
                            next_target += "?" + parsed.query
                        next_cookie = self._set_login_next_cookie(next_target)
                        self.send_header(next_cookie[0], next_cookie[1])
                clear_cookie_header = self._clear_session_cookie()
                self.send_header(clear_cookie_header[0], clear_cookie_header[1])
                self.end_headers()
                return b""

        # CSRF: block cross-origin state-changing requests. Only POST is checked
        # (GET writes are already rejected by the method split); reads are left
        # untouched so a cross-site link to a page still works.
        if self.command == "POST" and not self.is_same_origin_request():
            if page == "json":
                self.putHeaders(403, "application/json")
                return json.dumps({"error": "Cross-origin request blocked"}).encode(
                    "utf-8"
                )
            self.putHeaders(403, "text/html")
            return b"Cross-origin request blocked"

        get_string = parsed.query

        if page == "json":
            if self.command != "POST" and json_requires_post(url_split):
                self.putHeaders(405, "application/json")
                return json.dumps({"error": "POST required"}).encode("utf-8")
            try:
                self.putHeaders(status_code, "application/json")
                func = js_url_to_function(url_split)
                return func(self, url_split, post_string, is_json)
            except Exception as ex:
                if isinstance(ex, LockedCoinError):
                    clean_msg = f"Wallet locked: {getCoinName(ex.coinid)} wallet must be unlocked"
                    swap_client.log.warning(clean_msg)
                    return js_error(self, clean_msg)
                elif isinstance(ex, BalanceError):
                    # Suppress traceback
                    method: str = url_split[2] if len(url_split) > 2 else "unknown"
                    swap_client.log.error(f"js method: {method} failed - {ex}")
                elif swap_client.debug is True:
                    swap_client.log.error(traceback.format_exc())
                return js_error(self, str(ex))

        if page == "static":
            try:
                static_path = os.path.join(os.path.dirname(__file__), "static")
                mime_type = ""
                filepath = ""
                if len(url_split) > 3 and url_split[2] == "sequence_diagrams":
                    filepath = os.path.join(
                        static_path, "sequence_diagrams", url_split[3]
                    )
                    mime_type = "image/svg+xml"
                elif len(url_split) > 3 and url_split[2] == "images":
                    filename = os.path.join(*url_split[3:])
                    filepath = os.path.join(static_path, "images", filename)
                    _, extension = os.path.splitext(filename)
                    mime_type = {
                        ".svg": "image/svg+xml",
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".gif": "image/gif",
                        ".ico": "image/x-icon",
                    }.get(extension, "")
                elif len(url_split) > 3 and url_split[2] == "css":
                    filename = os.path.join(*url_split[3:])
                    filepath = os.path.join(static_path, "css", filename)
                    mime_type = "text/css; charset=utf-8"
                elif len(url_split) > 3 and url_split[2] == "js":
                    filename = os.path.join(*url_split[3:])
                    filepath = os.path.join(static_path, "js", filename)
                    mime_type = "application/javascript"
                else:
                    return self.page_404(url_split)

                if mime_type == "" or not filepath:
                    raise ValueError("Unknown file type or path")

                # Prevent path traversal. Require the resolved file to stay within static_path
                static_real = os.path.realpath(static_path)
                try:
                    within_static = (
                        os.path.commonpath((os.path.realpath(filepath), static_real))
                        == static_real
                    )
                except ValueError:
                    within_static = False
                if not within_static:
                    return self.page_404(url_split)

                file_stat = os.stat(filepath)
                mtime = file_stat.st_mtime
                file_size = file_stat.st_size

                etag_hash = hashlib.md5(f"{file_size}-{mtime}".encode()).hexdigest()
                etag = f'"{etag_hash}"'
                last_modified = formatdate(mtime, usegmt=True)

                if_none_match = self.headers.get("If-None-Match")
                if if_none_match:
                    if if_none_match.strip() == "*" or etag in [
                        t.strip() for t in if_none_match.split(",")
                    ]:
                        self.send_response(304)
                        self.send_header("ETag", etag)
                        self.send_header("Cache-Control", "public")
                        self.end_headers()
                        return b""

                if_modified_since = self.headers.get("If-Modified-Since")
                if if_modified_since and not if_none_match:
                    try:
                        ims_time = parsedate_to_datetime(if_modified_since)
                        file_time = datetime.fromtimestamp(int(mtime), tz=timezone.utc)
                        if file_time <= ims_time:
                            self.send_response(304)
                            self.send_header("Last-Modified", last_modified)
                            self.send_header("Cache-Control", "public")
                            self.end_headers()
                            return b""
                    except (TypeError, ValueError):
                        pass

                is_lib = len(url_split) > 4 and url_split[3] == "libs"
                if is_lib:
                    cache_control = "public, max-age=31536000, immutable"
                elif url_split[2] in ("css", "js"):
                    cache_control = "public, max-age=3600, must-revalidate"
                elif url_split[2] in ("images", "sequence_diagrams"):
                    cache_control = "public, max-age=86400"
                else:
                    cache_control = "public, max-age=3600"

                with open(filepath, "rb") as fp:
                    content = fp.read()

                extra_headers = [
                    ("Cache-Control", cache_control),
                    ("Last-Modified", last_modified),
                    ("ETag", etag),
                ]

                is_compressible = mime_type in (
                    "text/css; charset=utf-8",
                    "application/javascript",
                    "image/svg+xml",
                )
                accept_encoding = self.headers.get("Accept-Encoding", "")
                if is_compressible and "gzip" in accept_encoding:
                    content = gzip.compress(content)
                    extra_headers.append(("Content-Encoding", "gzip"))
                    extra_headers.append(("Vary", "Accept-Encoding"))

                extra_headers.append(("Content-Length", str(len(content))))
                self.putHeaders(status_code, mime_type, extra_headers=extra_headers)
                return content

            except FileNotFoundError:
                return self.page_404(url_split)
            except Exception as ex:
                if swap_client.debug is True:
                    swap_client.log.error(traceback.format_exc())
                return self.page_error(str(ex))

        try:
            if len(url_split) > 1:
                page = url_split[1]

                if page == "login":
                    return self.page_login(url_split, post_string)
                if page == "shutdown_ping":
                    return self.page_shutdown_ping(url_split, post_string)
                if page == "active":
                    return self.page_active(url_split, post_string)
                if page == "wallets":
                    return page_wallets(self, url_split, post_string)
                if page == "wallet":
                    return page_wallet(self, url_split, post_string)
                if page == "settings":
                    return page_settings(self, url_split, post_string)
                if page == "error":
                    return self.page_error(url_split, post_string)
                if page == "info":
                    return self.page_info(url_split, post_string)
                if page == "rpc":
                    return self.page_rpc(url_split, post_string)
                if page == "debug":
                    return page_debug(self, url_split, post_string)
                if page == "explorers":
                    return self.page_explorers(url_split, post_string)
                if page == "offer":
                    return page_offer(self, url_split, post_string)
                if page == "offers":
                    return page_offers(self, url_split, post_string)
                if page == "newoffer":
                    return page_newoffer(self, url_split, post_string, get_string)
                if page == "sentoffers":
                    return page_offers(self, url_split, post_string, sent=True)
                if page == "bid":
                    return page_bid(self, url_split, post_string)
                if page == "bids":
                    return page_bids(self, url_split, post_string)
                if page == "availablebids":
                    return page_bids(self, url_split, post_string, available=True)
                if page == "watched":
                    return self.page_watched(url_split, post_string)
                if page == "donation":
                    return self.page_donation(url_split, post_string)
                if page == "smsgaddresses":
                    return page_smsgaddresses(self, url_split, post_string)
                if page == "identity":
                    return page_identity(self, url_split, post_string)
                if page == "tor":
                    return page_tor(self, url_split, post_string)
                if page == "automation":
                    return page_automation_strategies(self, url_split, post_string)
                if page == "automationstrategy":
                    return page_automation_strategy(self, url_split, post_string)
                if page == "newautomationstrategy":
                    return page_automation_strategy_new(self, url_split, post_string)
                if page == "amm":
                    amm_action = url_split[2] if len(url_split) > 2 else ""
                    if (
                        amm_action in ("autostart", "config", "debug")
                        and self.command != "POST"
                    ):
                        self.putHeaders(405, "application/json")
                        return json.dumps({"error": "POST required"}).encode("utf-8")
                    if len(url_split) > 2 and url_split[2] == "status":
                        query_params = {}
                        if parsed.query:
                            query_params = {
                                k: v[0] for k, v in parse.parse_qs(parsed.query).items()
                            }
                        status_data = amm_status_api(
                            swap_client, self.path, query_params
                        )
                        self.putHeaders(200, "application/json")
                        return json.dumps(status_data).encode("utf-8")
                    elif len(url_split) > 2 and url_split[2] == "autostart":
                        query_params = {}
                        if parsed.query:
                            query_params = {
                                k: v[0] for k, v in parse.parse_qs(parsed.query).items()
                            }
                        autostart_data = amm_autostart_api(
                            swap_client, post_string, query_params
                        )
                        self.putHeaders(200, "application/json")
                        return json.dumps(autostart_data).encode("utf-8")
                    elif len(url_split) > 2 and url_split[2] == "debug":
                        query_params = {}
                        if parsed.query:
                            query_params = {
                                k: v[0] for k, v in parse.parse_qs(parsed.query).items()
                            }
                        debug_data = amm_debug_api(
                            swap_client, post_string, query_params
                        )
                        self.putHeaders(200, "application/json")
                        return json.dumps(debug_data).encode("utf-8")
                    elif len(url_split) > 2 and url_split[2] == "config":
                        query_params = {}
                        if parsed.query:
                            query_params = {
                                k: v[0] for k, v in parse.parse_qs(parsed.query).items()
                            }
                        config_result = amm_config_api(
                            swap_client, post_string, query_params
                        )
                        self.putHeaders(200, "application/json")
                        return json.dumps(config_result).encode("utf-8")
                    elif len(url_split) > 2 and url_split[2] == "state":
                        query_params = {}
                        if parsed.query:
                            query_params = {
                                k: v[0] for k, v in parse.parse_qs(parsed.query).items()
                            }
                        state_result = amm_state_api(
                            swap_client, post_string, query_params
                        )
                        self.putHeaders(200, "application/json")
                        return json.dumps(state_result).encode("utf-8")
                    return page_amm(self, url_split, post_string)
                if page == "shutdown":
                    return self.page_shutdown(url_split, post_string)
                if page == "changepassword":
                    return page_changepassword(self, url_split, post_string)
                if page == "unlock":
                    return page_unlock(self, url_split, post_string)
                if page == "lock":
                    return page_lock(self, url_split, post_string)
                if page != "":
                    return self.page_404(url_split)
            return self.page_index(url_split)
        except LockedCoinError:
            return page_unlock(self, url_split, post_string)
        except Exception as ex:
            if swap_client.debug is True:
                swap_client.log.error(traceback.format_exc())
            return self.page_error(str(ex))

    def do_GET(self):
        try:
            response = self.handle_http(200, self.path)
            try:
                self.wfile.write(response)
            except SocketError as e:
                self.server.swap_client.log.debug(f"do_GET SocketError {e}")
        finally:
            pass

    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            post_string = self.rfile.read(content_length)

            is_json = True if "json" in self.headers.get("Content-Type", "") else False
            response = self.handle_http(200, self.path, post_string, is_json)
            try:
                self.wfile.write(response)
            except SocketError as e:
                self.server.swap_client.log.debug(f"do_POST SocketError {e}")
        finally:
            pass

    def do_HEAD(self):
        self.putHeaders(200, "text/html")

    def do_OPTIONS(self):
        self.send_response(200, "ok")
        if self.server.allow_cors:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()


class HttpThread(threading.Thread, ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host_name, port_no, allow_cors, swap_client):
        threading.Thread.__init__(self)

        self.stop_event = threading.Event()
        self.host_name = host_name
        self.port_no = port_no
        self.allow_cors = allow_cors
        self.swap_client = swap_client
        self.title = "BasicSwap - " + __version__
        self.session_tokens = dict()
        self.session_tokens["csrf"] = secrets.token_urlsafe(32)
        self.active_sessions = {}
        self.env = env
        self.msg_id_counter = 0

        self.session_lock = threading.Lock()
        self.msg_id_lock = threading.Lock()

        self.timeout = 60
        ThreadingHTTPServer.__init__(self, (self.host_name, self.port_no), HttpHandler)

        if swap_client.debug:
            swap_client.log.info("HTTP server initialized with threading support")

    def stop(self):
        self.stop_event.set()

        try:
            conn = http.client.HTTPConnection(self.host_name, self.port_no, timeout=0.5)
            conn.request("GET", "/shutdown_ping")
            conn.close()
        except Exception:
            pass

    def serve_forever(self):
        self.timeout = 1
        while not self.stop_event.is_set():
            self.handle_request()
        self.socket.close()
        self.swap_client.log.info("HTTP server stopped.")

    def run(self):
        self.serve_forever()
