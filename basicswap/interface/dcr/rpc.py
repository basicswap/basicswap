# -*- coding: utf-8 -*-

# Copyright (c) 2024 tecnovert
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

import json
import traceback
from basicswap.rpc import Jsonrpc


def callrpc(rpc_port, auth, method, params=[], host='127.0.0.1'):
    try:
        url = 'http://{}@{}:{}/'.format(auth, host, rpc_port)
        x = Jsonrpc(url)
        x.__handler = None
        v = x.json_request(method, params)
        x.close()
        r = json.loads(v.decode('utf-8'))
    except Exception as ex:
        traceback.print_exc()
        raise ValueError('RPC server error ' + str(ex) + ', method: ' + method)

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def openrpc(rpc_port, auth, host='127.0.0.1'):
    try:
        url = 'http://{}@{}:{}/'.format(auth, host, rpc_port)
        return Jsonrpc(url)
    except Exception as ex:
        traceback.print_exc()
        raise ValueError('RPC error ' + str(ex))


def make_rpc_func(port, auth, host='127.0.0.1'):
    port = port
    auth = auth
    host = host

    def rpc_func(method, params=None):
        nonlocal port, auth, host
        return callrpc(port, auth, method, params, host)
    return rpc_func
