import functools
import json
import os
import socket
import ssl
import unittest

import requests

import spoof
import utils


class BaseMixin(unittest.TestCase):
    @staticmethod
    def unlink(*args):
        for path in args:
            os.unlink(path)


class TestRequest(BaseMixin):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key = spoof.SSLContext.createSelfSignedCert()
        sslContext = spoof.SSLContext.fromCertChain(cls.cert, cls.key)
        cls.httpd = spoof.HTTPServer(sslContext=sslContext)
        cls.httpd6 = spoof.HTTPServer6('::1', sslContext=sslContext)
        cls.httpd.start()
        cls.httpd6.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.stop()
        cls.httpd6.stop()
        cls.httpd = None
        cls.httpd6 = None
        cls.unlink(cls.cert, cls.key)

    def setUp(self):
        self.response = [240, [('X-Server', 'IPv4')], 'This is IPv4']
        self.response6 = [260, [('X-Server', 'IPv6')], 'This is IPv6']
        self.httpd.queueResponse(self.response)
        self.session = requests.Session()
        self.session.verify = self.cert
        self.httpd6.queueResponse(self.response6)
        self.path = '/v4'
        self.path6 = '/v6'
        self.result = self.session.get(self.httpd.url + self.path)
        self.result6 = self.session.get(self.httpd6.url + self.path6)
        self.data = {'this': 'that'}
        self.queryString = 'this=that'

    def tearDown(self):
        self.httpd.reset()
        self.httpd6.reset()
        self.httpd.debug = False
        self.httpd6.debug = False

    def test_spoof_sends_response_status(self):
        self.assertEqual(self.response[0], self.result.status_code)

    def test_spoof_sends_response6_status(self):
        self.assertEqual(self.response6[0], self.result6.status_code)

    def test_spoof_sends_response_content(self):
        self.assertEqual(self.response[2], self.result.text)

    def test_spoof_sends_response6_content(self):
        self.assertEqual(self.response6[2], self.result6.text)

    def test_spoof_sends_response_header(self):
        expected = self.response[1][0][1]
        result = self.result.headers[self.response[1][0][0]]
        self.assertEqual(expected, result)

    def test_spoof_sends_response6_header(self):
        expected = self.response6[1][0][1]
        result = self.result6.headers[self.response6[1][0][0]]
        self.assertEqual(expected, result)

    def test_spoof_returns_request_path(self):
        self.assertEqual(self.path, self.httpd.requests[-1].path)

    def test_spoof_returns_request6_path(self):
        self.assertEqual(self.path6, self.httpd6.requests[-1].path)

    def test_spoof_returns_request_content(self):
        expected = json.loads(json.dumps(self.data))
        self.session.post(self.httpd.url + self.path, json=expected)
        result = json.loads(self.httpd.requests[-1].content.decode('utf-8'))
        self.assertEqual(expected, result)

    def test_spoof_returns_request_contentType(self):
        contentType = 'application/json'
        self.session.post(self.httpd.url + self.path, json=self.data)
        self.assertEqual(contentType, self.httpd.requests[-1].contentType)

    def test_spoof_returns_request_contentLength(self):
        contentLength = len(json.dumps(self.data))
        self.session.post(self.httpd.url + self.path, json=self.data)
        self.assertEqual(contentLength, self.httpd.requests[-1].contentLength)

    def test_spoof_returns_request_queryString(self):
        url = '{0}{1}?{2}'.format(self.httpd.url, self.path, self.queryString)
        self.session.get(url)
        self.assertEqual(self.queryString, self.httpd.requests[-1].queryString)

    def test_spoof_returns_debug_bool(self):
        self.assertIsInstance(self.httpd.debug, bool)

    def test_spoof_sets_debug_attribute(self):
        debug = self.httpd.debug
        self.httpd.debug = not debug
        self.assertNotEqual(self.httpd.debug, debug)

    def test_spoof_returns_maxRequestLength(self):
        self.assertIsInstance(self.httpd.maxRequestLength, int)

    def test_spoof_sets_maxRequestLength(self):
        maxRequestLength = self.httpd.maxRequestLength + 6
        self.httpd.maxRequestLength = maxRequestLength
        self.assertEqual(self.httpd.maxRequestLength, maxRequestLength)

    def test_spoof_returns_defaultResponse(self):
        self.httpd.reset()
        defaultResponse = [200, [], 'OK']
        self.httpd.defaultResponse = defaultResponse
        request = self.session.get(self.httpd.url + '/default')
        self.assertEqual(request.status_code, defaultResponse[0])

    def test_spoof_returns_errorResponse(self):
        self.httpd.reset()
        errorResponse = self.httpd.handlerClass.errorResponse
        request = self.session.get(self.httpd.url + '/error')
        self.assertEqual(request.status_code, errorResponse[0])

    def test_spoof_selfSigned_raises_exception_on_connect(self):
        sslContext = spoof.SSLContext.selfSigned()
        httpd = spoof.HTTPServer(sslContext=sslContext)
        with self.assertRaises(requests.ConnectionError):
            self.session.get(httpd.url + '/random')


class TestProxy(BaseMixin):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key = spoof.SSLContext.createSelfSignedCert(
            commonName='*.com'
        )

    @classmethod
    def tearDownClass(cls):
        cls.unlink(cls.cert, cls.key)

    def setUp(self):
        self.httpd = spoof.HTTPServer()
        self.httpd.start()
        self.session = requests.Session()

    def tearDown(self):
        self.httpd.stop()
        self.httpd = None
        self.session = None

    def test_spoof_connect_https_proxy(self):
        expected = upstream_content = b'windage-gelding-spume'
        upstream_url = 'https://google.com/'
        sslContext = spoof.SSLContext.fromCertChain(self.cert, self.key)
        self.httpd.upstream = spoof.HTTPUpstreamServer(sslContext=sslContext)
        self.httpd.upstream.defaultResponse = [200, [], upstream_content]
        self.httpd.defaultResponse = [200, [('X-Fake-Proxy', 'True')], '']
        self.httpd.upstream.start()
        self.session.verify = self.cert
        proxies = {'https': self.httpd.url}
        result = self.session.get(upstream_url, proxies=proxies).content
        self.httpd.upstream.stop()
        self.assertEqual(expected, result)

    def test_spoof_http_proxy_content(self):
        expected = upstream_content = b'aimless-scanty-thyself'
        upstream_url = 'http://google.com/'
        self.httpd.defaultResponse = [200, [], upstream_content]
        proxies = {'http': self.httpd.url}
        result = self.session.get(upstream_url, proxies=proxies).content
        self.assertEqual(expected, result)

    def test_spoof_http_proxy_path(self):
        upstream_content = b'stimuli-liberia-parable'
        expected = upstream_url = 'http://armour-lipstick-booze.com/'
        self.httpd.defaultResponse = [200, [], upstream_content]
        proxies = {'http': self.httpd.url}
        self.session.get(upstream_url, proxies=proxies).content
        result = self.httpd.requests[-1].path
        self.assertEqual(expected, result)

    @unittest.skipUnless(hasattr(ssl, 'MemoryBIO'), 'requires ssl.MemoryBIO')
    def test_spoof_https_site_through_https_proxy(self):
        # This is a proof-of-concept for proxying HTTPS requests through an
        # HTTPS server. Typically, HTTPS requests are proxied via CONNECT verb
        # on a plain-text HTTP server. This means proxy credentials are sent
        # in the clear, as well as the intended destination. Proxying via HTTPS
        # allows these to be nominally protected. At this time, no major
        # HTTP libraries support proxying HTTPS requests through HTTPS servers,
        # so the actual request portion of the test quite crude, reading and
        # writing directly to sockets. The use of the `ssl.SSLContext.wrap_bio`
        # method allows arbitrary SSL I/O, provided data is written to and read
        # out of BIO instances. This is required as it's not possible to for an
        # `ssl.SSLContext` socket to wrap another `ssl.SSLContext` socket.
        expected = upstream_content = b'octet-comeback-squirmy'
        chunk_size = 4096
        httpd = spoof.HTTPServer(
            sslContext=spoof.SSLContext.fromCertChain(self.cert, self.key)
        )
        httpd.defaultResponse = [200, [], '']
        httpd.start()
        httpd.upstream = spoof.HTTPUpstreamServer(
            sslContext=spoof.SSLContext.fromCertChain(self.cert, self.key)
        )
        httpd.upstream.defaultResponse = [200, [], upstream_content]
        httpd.upstream.start()
        client = ssl.create_default_context(cafile=self.cert).wrap_socket(
            socket.create_connection(httpd.serverAddress),
            server_hostname=httpd.address
        )
        client.sendall(b'CONNECT google.com HTTP/1.0\r\n\r\n')
        client.recv(chunk_size)  # response headers
        tunnel_in = ssl.MemoryBIO()
        tunnel_out = ssl.MemoryBIO()
        tunnel = ssl.create_default_context(cafile=self.cert).wrap_bio(
            tunnel_in, tunnel_out, server_hostname='google.com'
        )
        tunnel_cmd = functools.partial(
            utils.ssl_io_loop, client, tunnel_in, tunnel_out
        )
        tunnel_cmd(tunnel.do_handshake)
        tunnel_cmd(tunnel.write, b'GET / HTTP/1.0\r\n\r\n')
        tunnel_cmd(tunnel.read, chunk_size)  # response headers
        result = tunnel_cmd(tunnel.read, chunk_size)
        client.close()
        httpd.upstream.stop()
        httpd.stop()
        self.assertEqual(expected, result)


if __name__ == '__main__':
    unittest.main()
