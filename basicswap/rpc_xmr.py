# -*- coding: utf-8 -*-

import json
import requests


def callrpc_xmr(rpc_port, auth, method, params=[], rpc_host='127.0.0.1', path='json_rpc', timeout=120):
    # auth is a tuple: (username, password)
    try:
        url = 'http://{}:{}/{}'.format(rpc_host, rpc_port, path)
        request_body = {
            'method': method,
            'params': params,
            'id': 2,
            'jsonrpc': '2.0'
        }
        headers = {
            'Content-Type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(request_body), auth=requests.auth.HTTPDigestAuth(auth[0], auth[1]), headers=headers, timeout=timeout)
        r = json.loads(p.text)
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_xmr_na(rpc_port, method, params=[], rpc_host='127.0.0.1', path='json_rpc', timeout=120):
    try:
        url = 'http://{}:{}/{}'.format(rpc_host, rpc_port, path)
        request_body = {
            'method': method,
            'params': params,
            'id': 2,
            'jsonrpc': '2.0'
        }
        headers = {
            'Content-Type': 'application/json'
        }
        p = requests.post(url, data=json.dumps(request_body), headers=headers, timeout=timeout)
        r = json.loads(p.text)
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_xmr2(rpc_port, method, params=None, rpc_host='127.0.0.1', timeout=120):
    try:
        url = 'http://{}:{}/{}'.format(rpc_host, rpc_port, method)
        headers = {
            'Content-Type': 'application/json'
        }
        if params is None:
            p = requests.post(url, headers=headers, timeout=timeout)
        else:
            p = requests.post(url, data=json.dumps(params), headers=headers, timeout=timeout)
        r = json.loads(p.text)
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    return r


def make_xmr_rpc_func(port, host='127.0.0.1'):
    port = port
    host = host

    def rpc_func(method, params=None, wallet=None, timeout=120):
        nonlocal port
        nonlocal host
        return callrpc_xmr_na(port, method, params, rpc_host=host, timeout=timeout)
    return rpc_func


def make_xmr_rpc2_func(port, host='127.0.0.1'):
    port = port
    host = host

    def rpc_func(method, params=None, wallet=None, timeout=120):
        nonlocal port
        nonlocal host
        return callrpc_xmr2(port, method, params, rpc_host=host, timeout=timeout)
    return rpc_func


def make_xmr_wallet_rpc_func(port, auth, host='127.0.0.1'):
    port = port
    auth = auth
    host = host

    def rpc_func(method, params=None, wallet=None, timeout=120):
        nonlocal port, auth, host
        return callrpc_xmr(port, auth, method, params, rpc_host=host, timeout=timeout)
    return rpc_func
