import json
import os
import unittest

import requests

import spoof


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
    def test_spoof_https_proxy(self):
        cert, key = spoof.SSLContext.createSelfSignedCert(commonName='*.com')
        expected = upstream_content = b'windage-gelding-spume'
        upstream_url = 'https://google.com/'
        self.addCleanup(self.unlink, cert, key)
        sslContext = spoof.SSLContext.fromCertChain(cert, key)
        httpd = spoof.HTTPServer()
        httpd.upstream = spoof.HTTPUpstreamServer(sslContext=sslContext)
        httpd.upstream.defaultResponse = [200, [], upstream_content]
        httpd.defaultResponse = [200, [('X-Fake-Proxy', 'True')], '']
        httpd.upstream.start()
        httpd.start()
        session = requests.Session()
        session.verify = cert
        proxies = {'https': httpd.url}
        result = session.get(upstream_url, proxies=proxies).content
        httpd.upstream.stop()
        httpd.stop()
        self.assertEqual(expected, result)


if __name__ == '__main__':
    unittest.main()
