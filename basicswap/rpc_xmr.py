# -*- coding: utf-8 -*-

import os
import json
import socks
import time
import urllib
import hashlib
from xmlrpc.client import (
    Fault,
    Transport,
    SafeTransport,
)
from sockshandler import SocksiPyConnection
from .util import jsonDecimal


class SocksTransport(Transport):

    def set_proxy(self, proxy_host, proxy_port):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

        self.proxy_type = socks.PROXY_TYPE_SOCKS5
        self.proxy_rdns = True
        self.proxy_username = None
        self.proxy_password = None

    def make_connection(self, host):
        # return an existing connection if possible.  This allows
        # HTTP/1.1 keep-alive.
        if self._connection and host == self._connection[0]:
            return self._connection[1]
        # create a HTTP connection object from a host descriptor
        chost, self._extra_headers, x509 = self.get_host_info(host)
        self._connection = host, SocksiPyConnection(self.proxy_type, self.proxy_host, self.proxy_port, self.proxy_rdns, self.proxy_username, self.proxy_password, chost)
        return self._connection[1]


class JsonrpcDigest():
    # __getattr__ complicates extending ServerProxy
    def __init__(self, uri, transport=None, encoding=None, verbose=False,
                 allow_none=False, use_datetime=False, use_builtin_types=False,
                 *, context=None):

        parsed = urllib.parse.urlparse(uri)
        if parsed.scheme not in ('http', 'https'):
            raise OSError('unsupported XML-RPC protocol')
        self.__host = parsed.netloc
        self.__handler = parsed.path

        if transport is None:
            handler = SafeTransport if parsed.scheme == 'https' else Transport
            extra_kwargs = {}
            transport = handler(use_datetime=use_datetime,
                                use_builtin_types=use_builtin_types,
                                **extra_kwargs)
        self.__transport = transport

        self.__encoding = encoding or 'utf-8'
        self.__verbose = verbose
        self.__allow_none = allow_none

        self.__request_id = 0

    def close(self):
        if self.__transport is not None:
            self.__transport.close()

    def request_id(self):
        return self.__request_id

    def post_request(self, method, params, timeout=None):
        try:
            connection = self.__transport.make_connection(self.__host)
            if timeout:
                connection.timeout = timeout
            headers = self.__transport._extra_headers[:]

            connection.putrequest('POST', self.__handler)
            headers.append(('Content-Type', 'application/json'))
            headers.append(('User-Agent', 'jsonrpc'))
            self.__transport.send_headers(connection, headers)
            self.__transport.send_content(connection, '' if params is None else json.dumps(params, default=jsonDecimal).encode('utf-8'))
            self.__request_id += 1

            resp = connection.getresponse()
            return resp.read()

        except Fault:
            raise
        except Exception:
            self.__transport.close()
            raise

    def json_request(self, request_body, username='', password='', timeout=None):
        try:
            connection = self.__transport.make_connection(self.__host)
            if timeout:
                connection.timeout = timeout

            headers = self.__transport._extra_headers[:]

            connection.putrequest('POST', self.__handler)
            headers.append(('Content-Type', 'application/json'))
            headers.append(('Connection', 'keep-alive'))
            self.__transport.send_headers(connection, headers)
            self.__transport.send_content(connection, json.dumps(request_body, default=jsonDecimal).encode('utf-8') if request_body else '')
            resp = connection.getresponse()

            if resp.status == 401:
                resp_headers = resp.getheaders()
                v = resp.read()

                algorithm = ''
                realm = ''
                nonce = ''
                for h in resp_headers:
                    if h[0] != 'WWW-authenticate':
                        continue
                    fields = h[1].split(',')
                    for f in fields:
                        key, value = f.split('=', 1)
                        if key == 'algorithm' and value != 'MD5':
                            break
                        if key == 'realm':
                            realm = value.strip('"')
                        if key == 'nonce':
                            nonce = value.strip('"')
                    if realm != '' and nonce != '':
                        break

                if realm == '' or nonce == '':
                    raise ValueError('Authenticate header not found.')

                path = self.__handler
                HA1 = hashlib.md5(f'{username}:{realm}:{password}'.encode('utf-8')).hexdigest()

                http_method = 'POST'
                HA2 = hashlib.md5(f'{http_method}:{path}'.encode('utf-8')).hexdigest()

                ncvalue = '{:08x}'.format(1)
                s = ncvalue.encode('utf-8')
                s += nonce.encode('utf-8')
                s += time.ctime().encode('utf-8')
                s += os.urandom(8)
                cnonce = (hashlib.sha1(s).hexdigest()[:16])

                # MD5-SESS
                HA1 = hashlib.md5(f'{HA1}:{nonce}:{cnonce}'.encode('utf-8')).hexdigest()

                respdig = hashlib.md5(f'{HA1}:{nonce}:{ncvalue}:{cnonce}:auth:{HA2}'.encode('utf-8')).hexdigest()

                header_value = f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{path}", response="{respdig}", algorithm="MD5-sess", qop="auth", nc={ncvalue}, cnonce="{cnonce}"'
                headers = self.__transport._extra_headers[:]
                headers.append(('Authorization', header_value))

                connection.putrequest('POST', self.__handler)
                headers.append(('Content-Type', 'application/json'))
                headers.append(('Connection', 'keep-alive'))
                self.__transport.send_headers(connection, headers)
                self.__transport.send_content(connection, json.dumps(request_body, default=jsonDecimal).encode('utf-8') if request_body else '')
                resp = connection.getresponse()

            self.__request_id += 1
            return resp.read()

        except Fault:
            raise
        except Exception:
            self.__transport.close()
            raise


def callrpc_xmr(rpc_port, method, params=[], rpc_host='127.0.0.1', path='json_rpc', auth=None, timeout=120, transport=None):
    # auth is a tuple: (username, password)
    try:
        if rpc_host.count('://') > 0:
            url = '{}:{}/{}'.format(rpc_host, rpc_port, path)
        else:
            url = 'http://{}:{}/{}'.format(rpc_host, rpc_port, path)

        x = JsonrpcDigest(url, transport=transport)
        request_body = {
            'method': method,
            'params': params,
            'jsonrpc': '2.0',
            'id': x.request_id()
        }
        if auth:
            v = x.json_request(request_body, username=auth[0], password=auth[1], timeout=timeout)
        else:
            v = x.json_request(request_body, timeout=timeout)
        x.close()
        r = json.loads(v.decode('utf-8'))
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    if 'error' in r and r['error'] is not None:
        raise ValueError('RPC error ' + str(r['error']))

    return r['result']


def callrpc_xmr2(rpc_port: int, method: str, params=None, auth=None, rpc_host='127.0.0.1', timeout=120, transport=None):
    try:
        if rpc_host.count('://') > 0:
            url = '{}:{}/{}'.format(rpc_host, rpc_port, method)
        else:
            url = 'http://{}:{}/{}'.format(rpc_host, rpc_port, method)

        x = JsonrpcDigest(url, transport=transport)
        if auth:
            v = x.json_request(params, username=auth[0], password=auth[1], timeout=timeout)
        else:
            v = x.json_request(params, timeout=timeout)
        x.close()
        r = json.loads(v.decode('utf-8'))
    except Exception as ex:
        raise ValueError('RPC Server Error: {}'.format(str(ex)))

    return r


def make_xmr_rpc2_func(port, auth, host='127.0.0.1', proxy_host=None, proxy_port=None):
    port = port
    auth = auth
    host = host
    transport = None

    if proxy_host:
        transport = SocksTransport()
        transport.set_proxy(proxy_host, proxy_port)

    def rpc_func(method, params=None, wallet=None, timeout=120):
        nonlocal port, auth, host, transport
        return callrpc_xmr2(port, method, params, auth=auth, rpc_host=host, timeout=timeout, transport=transport)
    return rpc_func


def make_xmr_rpc_func(port, auth, host='127.0.0.1', proxy_host=None, proxy_port=None):
    port = port
    auth = auth
    host = host
    transport = None

    if proxy_host:
        transport = SocksTransport()
        transport.set_proxy(proxy_host, proxy_port)

    def rpc_func(method, params=None, wallet=None, timeout=120):
        nonlocal port, auth, host, transport
        return callrpc_xmr(port, method, params, rpc_host=host, auth=auth, timeout=timeout, transport=transport)
    return rpc_func
