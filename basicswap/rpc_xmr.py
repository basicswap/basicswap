# -*- coding: utf-8 -*-

import json
import requests


def callrpc_xmr(rpc_port, auth, method, params=[], path='json_rpc'):
    # auth is a tuple: (username, password)
    try:
        url = 'http://127.0.0.1:{}/{}'.format(rpc_port, path)
        request_body = {
            'method': method,
            'params': params,
            'id': 2,
            'jsonrpc': '2.0'
        }
        headers = {
            'content-type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(request_body), auth=requests.auth.HTTPDigestAuth(auth[0], auth[1]), headers=headers)
        r = json.loads(p.text)
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_xmr_na(rpc_port, method, params=[], path='json_rpc'):
    try:
        url = 'http://127.0.0.1:{}/{}'.format(rpc_port, path)
        request_body = {
            'method': method,
            'params': params,
            'id': 2,
            'jsonrpc': '2.0'
        }
        headers = {
            'content-type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(request_body), headers=headers)
        r = json.loads(p.text)
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_xmr2(rpc_port, method, params=[]):
    try:
        url = 'http://127.0.0.1:{}/{}'.format(rpc_port, method)
        headers = {
            'content-type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(params), headers=headers)
        r = json.loads(p.text)
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    return r


def make_xmr_rpc_func(port):
    port = port

    def rpc_func(method, params=None, wallet=None):
        nonlocal port
        return callrpc_xmr_na(port, method, params)
    return rpc_func


def make_xmr_wallet_rpc_func(port, auth):
    port = port
    auth = auth

    def rpc_func(method, params=None, wallet=None):
        nonlocal port, auth
        return callrpc_xmr(port, auth, method, params)
    return rpc_func
