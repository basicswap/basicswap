# -*- coding: utf-8 -*-

# Copyright (c) 2020 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import os
import time
import json
import urllib
import logging
import traceback
import subprocess
from xmlrpc.client import (
    Transport,
    Fault,
)
from .util import jsonDecimal


def waitForRPC(rpc_func, wallet=None, max_tries=7):
    for i in range(max_tries + 1):
        try:
            rpc_func('getwalletinfo')
            return
        except Exception as ex:
            if i < max_tries:
                logging.warning('Can\'t connect to RPC: %s. Retrying in %d second/s.', str(ex), (i + 1))
                time.sleep(i + 1)
    raise ValueError('waitForRPC failed')


class Jsonrpc():
    # __getattr__ complicates extending ServerProxy
    def __init__(self, uri, transport=None, encoding=None, verbose=False,
                 allow_none=False, use_datetime=False, use_builtin_types=False,
                 *, context=None):
        # establish a "logical" server connection

        # get the url
        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme not in ("http", "https"):
            raise OSError("unsupported XML-RPC protocol")
        self.__host = parsed.netloc
        self.__handler = parsed.path
        if not self.__handler:
            self.__handler = "/RPC2"

        if transport is None:
            handler = Transport
            extra_kwargs = {}
            transport = handler(use_datetime=use_datetime,
                                use_builtin_types=use_builtin_types,
                                **extra_kwargs)
        self.__transport = transport

        self.__encoding = encoding or 'utf-8'
        self.__verbose = verbose
        self.__allow_none = allow_none

    def close(self):
        if self.__transport is not None:
            self.__transport.close()

    def json_request(self, method, params):
        try:
            connection = self.__transport.make_connection(self.__host)
            headers = self.__transport._extra_headers[:]

            request_body = {
                'method': method,
                'params': params,
                'id': 2
            }

            connection.putrequest("POST", self.__handler)
            headers.append(("Content-Type", "application/json"))
            headers.append(("User-Agent", 'jsonrpc'))
            self.__transport.send_headers(connection, headers)
            self.__transport.send_content(connection, json.dumps(request_body, default=jsonDecimal).encode('utf-8'))

            resp = connection.getresponse()
            return resp.read()

        except Fault:
            raise
        except Exception:
            # All unexpected errors leave connection in
            # a strange state, so we clear it.
            self.__transport.close()
            raise


def callrpc(rpc_port, auth, method, params=[], wallet=None):
    try:
        url = 'http://%s@127.0.0.1:%d/' % (auth, rpc_port)
        if wallet is not None:
            url += 'wallet/' + urllib.parse.quote(wallet)
        x = Jsonrpc(url)

        v = x.json_request(method, params)
        x.close()
        r = json.loads(v.decode('utf-8'))
    except Exception as ex:
        traceback.print_exc()
        raise ValueError('RPC Server Error')

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_cli(bindir, datadir, chain, cmd, cli_bin='particl-cli'):
    cli_bin = os.path.join(bindir, cli_bin)

    args = cli_bin + ('' if chain == 'mainnet' else (' -' + chain)) + ' -datadir=' + datadir + ' ' + cmd
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    out = p.communicate()

    if len(out[1]) > 0:
        raise ValueError('RPC error ' + str(out[1]))

    r = out[0].decode('utf-8').strip()
    try:
        r = json.loads(r)
    except Exception:
        pass
    return r


def make_rpc_func(port, auth, wallet=None):
    port = port
    auth = auth
    wallet = wallet

    def rpc_func(method, params=None, wallet_override=None):
        nonlocal port, auth, wallet
        return callrpc(port, auth, method, params, wallet if wallet_override is None else wallet_override)
    return rpc_func
