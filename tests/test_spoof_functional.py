import itertools
import json
import os
import random
import socket
import ssl
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
        cls.selfSigned = spoof.SelfSignedSSLContext()
        cls.sslContext = cls.selfSigned.sslContext
        cls.httpd = spoof.HTTPServer(sslContext=cls.sslContext).start()
        cls.httpd6 = spoof.HTTPServer6(sslContext=cls.sslContext).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.stop()
        cls.httpd6.stop()
        cls.httpd = None
        cls.httpd6 = None
        cls.selfSigned.cleanup()

    def setUp(self):
        self.response = [240, [("X-Server", "IPv4")], "This is IPv4"]
        self.response6 = [260, [("X-Server", "IPv6")], "This is IPv6"]
        self.httpd.queueResponse(*[self.response])
        self.session = requests.Session()
        self.session.verify = self.selfSigned.certFile
        self.httpd6.queueResponse(self.response6)
        self.path = "/v4"
        self.path6 = "/v6"
        self.result = self.session.get(self.httpd.url + self.path)
        self.result6 = self.session.get(self.httpd6.url + self.path6)
        self.data = {"this": "that"}
        self.queryString = "this=that"

    def tearDown(self):
        self.httpd.reset()
        self.httpd.debug = False
        self.httpd.maxRequestLength = spoof.MEGABYTE
        self.httpd6.reset()
        self.httpd6.debug = False
        self.httpd6.maxRequestLength = spoof.MEGABYTE

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
        result = self.httpd.requests[-1].json()
        self.assertEqual(expected, result)

    def test_spoof_returns_request_contentEncoding(self):
        expected = contentEncoding = "soffit-snell-swore"
        headers = {"Content-Encoding": contentEncoding}
        self.session.post(self.httpd.url + self.path, json=self.data, headers=headers)
        result = self.httpd.requests[-1].contentEncoding
        self.assertEqual(expected, result)

    def test_spoof_returns_request_contentType(self):
        contentType = "application/json"
        self.session.post(self.httpd.url + self.path, json=self.data)
        self.assertEqual(contentType, self.httpd.requests[-1].contentType)

    def test_spoof_returns_request_contentLength(self):
        contentLength = len(json.dumps(self.data))
        self.session.post(self.httpd.url + self.path, json=self.data)
        self.assertEqual(contentLength, self.httpd.requests[-1].contentLength)

    def test_spoof_encodes_and_sets_correct_content_length_for_utf8_text(self):
        expected = "This is Spoof 👻👋"
        self.httpd.queueResponse([200, [], expected])
        result = self.session.get(self.httpd.url).content.decode()
        self.assertEqual(expected, result)

    def test_spoof_returns_request_queryString(self):
        url = "{0}{1}?{2}".format(self.httpd.url, self.path, self.queryString)
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
        defaultResponse = [200, [], "OK"]
        self.httpd.defaultResponse = defaultResponse
        request = self.session.get(self.httpd.url + "/default")
        self.assertEqual(request.status_code, defaultResponse[0])

    def test_spoof_returns_errorResponse(self):
        errorResponse = self.httpd.handlerClass.errorResponse
        request = self.session.get(self.httpd.url + "/error")
        self.assertEqual(request.status_code, errorResponse[0])

    def test_spoof_selfSigned_raises_exception_on_connect(self):
        # this kind of ssl http server setup has no way to access the underlying
        # certificate and key files. the intent is to provide a real ssl context
        # that is untrusted and kicked back as invalid, potentially to test out
        # implementations that trust ssl connections that should not be trusted.
        with spoof.HTTPServer(sslContext=spoof.SSLContext.selfSigned()) as httpd:
            with self.assertRaises(requests.exceptions.SSLError):
                self.session.get(httpd.url)

    def test_spoof_allows_callable_defaultResponse(self):
        status_code = random.randint(205, 299)

        def callback(this):
            return [status_code, [], this.path]

        self.httpd.defaultResponse = callback
        request = self.session.get(self.httpd.url + "/infight-canaille-scorch")
        self.assertEqual(request.status_code, status_code)
        self.assertEqual(request.content.decode(), "/infight-canaille-scorch")

    def test_spoof_allows_callable_queued_response(self):
        status_code = random.randint(205, 299)

        def callback(this):
            return [status_code, [], this.path]

        self.httpd.queueResponse(callback)
        request = self.session.get(self.httpd.url + "/plasma-nausea-shifty")
        self.assertEqual(request.status_code, status_code)
        self.assertEqual(request.content.decode(), "/plasma-nausea-shifty")

    def test_spoof_unquotes_path_and_leaves_uri_quoted(self):
        unquoted_str = "/spoof 👻👋"
        quoted_str = "/spoof%20%F0%9F%91%BB%F0%9F%91%8B"
        self.session.get(self.httpd.url + quoted_str)
        request = self.httpd.requests[-1]
        self.assertEqual(request.path, unquoted_str)
        self.assertEqual(request.uri, quoted_str)

    def test_spoof_sends_no_content_length_header(self):
        self.httpd.defaultResponse = [200, [], None]
        response = self.session.get(self.httpd.url)
        self.assertIsNone(response.headers.get("Content-Length"))

    def test_maxRequestLength_is_honored(self):
        self.httpd.maxRequestLength = 1
        response = self.session.post(self.httpd.url, data=b"OK")
        expected = spoof.HTTP_REQUEST_ENTITY_TOO_LARGE
        result = response.status_code
        self.assertEqual(expected, result)

    def test_queue_single_response(self):
        expected = "One fish"
        self.httpd.responses.append([200, [], expected])
        response = self.session.get(self.httpd.url)
        result = response.text
        self.assertEqual(expected, result)

    def test_queueing_multiple_responses(self):
        expected = ["One fish", "Two fish", "Red fish", "Blue fish"]
        self.httpd.responses.extend([[200, [], text] for text in expected])
        results = [self.session.get(self.httpd.url).text for _ in expected]
        self.assertEqual(expected, results)

    def test_queue_callback(self):
        expected_path = "/correct/horse/battery/staple"
        self.httpd.responses.append(lambda request: [200, [], request.path])
        response = self.session.get(self.httpd.url + expected_path)
        self.assertEqual(expected_path, response.text)
        self.assertEqual(expected_path, self.httpd.requests[-1].path)

    def test_large_batch_queued_responses(self):
        batchSize = 1_000
        responses = [
            [200, [("Content-Type", "application/json")], f'{{"seq": {seq}}}']
            for seq in range(batchSize)
        ]
        with spoof.HTTPServer() as httpd:
            httpd.responses.extend(responses)
            for seq in range(batchSize):
                self.assertEqual({"seq": seq}, requests.get(httpd.url).json())
            self.assertEqual(batchSize, len(httpd.requests))

    def test_large_batch_generated_responses(self):
        def responseGenerator():
            for seq in itertools.count():
                yield [200, [("Content-Type", "application/json")], json.dumps({"seq": seq})]

        with spoof.HTTPServer() as httpd:
            batchSize = 1_000
            response = responseGenerator()
            httpd.defaultResponse = lambda request: next(response)
            for seq in range(batchSize):
                self.assertEqual({"seq": seq}, self.session.get(httpd.url).json())
            self.assertEqual(batchSize, len(httpd.requests))

    def test_attrs_return_None_if_server_is_unbound(self):
        httpd = spoof.HTTPServer()
        self.assertIsNone(httpd.server)
        self.assertIsNone(httpd.address)
        self.assertIsNone(httpd.port)
        self.assertIsNone(httpd.url)

    def test_changing_sslContext_and_restarting(self):
        expected = "set-sslcontext-live"
        httpd = spoof.HTTPServer(sslContext=spoof.SSLContext.selfSigned()).start()
        httpd.defaultResponse = [200, [], expected]
        with self.assertRaises(requests.exceptions.SSLError):
            requests.get(httpd.url)

        httpd.sslContext = self.selfSigned.sslContext
        httpd.restart()
        result = requests.get(httpd.url, verify=self.selfSigned.certFile).text
        self.assertTrue(httpd.url.startswith("https"))
        self.assertEqual(expected, result)

    def test_changing_serverAddress_and_restarting(self):
        httpd = spoof.HTTPServer(host="127.0.0.1").start()
        httpd.defaultResponse = lambda request: [200, [], request.serverName]

        httpd.serverAddress = ("::1", 0)
        httpd.restart()
        self.assertEqual(requests.get(httpd.url).text, "::1")
        self.assertEqual(httpd.server.socket.family, socket.AF_INET6)

        httpd.serverAddress = ("127.0.0.1", 0)
        httpd.restart()
        self.assertEqual(requests.get(httpd.url).text, "127.0.0.1")
        self.assertEqual(httpd.server.socket.family, socket.AF_INET)

    def test_restart_returns_spoof_instance(self):
        expected = httpd = spoof.HTTPServer()
        result = httpd.restart()
        self.assertEqual(expected, result)

    def test_start_returns_spoof_instance(self):
        expected = httpd = spoof.HTTPServer()
        result = httpd.start()
        self.assertEqual(expected, result)

    def test_spoof_alias_minimal_example(self):
        expected = response = "spoof-alias-minimal-example"
        with spoof.http(ssl=True) as http:
            http.defaultResponse = [200, [], response]
            result = requests.get(http.url, verify=http.ssl.certFile).text
            self.assertEqual(expected, result)

    def test_spoof_alias_with_ssl_instance(self):
        expected = response = "spoof-alias-ssl-instance"
        with spoof.http(ssl=spoof.ssl()) as http:
            http.defaultResponse = [200, [], response]
            result = requests.get(http.url, verify=http.ssl.certFile).text
            self.assertEqual(expected, result)

    def test_spoof_alias_with_ssl_value_error(self):
        with self.assertRaises(ValueError):
            with spoof.http(ssl="True"):
                pass

    def test_spoof_http6_alias(self):
        http = spoof.http6().start()
        http.defaultResponse = [200, [], "spoof-http6-alias"]
        self.assertEqual(requests.get(http.url).text, "spoof-http6-alias")
        self.assertEqual(http.server.socket.family, socket.AF_INET6)


class TestProxy(BaseMixin):
    @classmethod
    def setUpClass(cls):
        cls.cert, cls.key = spoof.SSLContext.createSelfSignedCert(commonName="google.com")

    @classmethod
    def tearDownClass(cls):
        cls.unlink(cls.cert, cls.key)

    def setUp(self):
        self.httpd = spoof.HTTPServer().start()
        self.session = requests.Session()
        self.session.verify = self.cert
        self.sslContext = spoof.SSLContext.fromCertChain(self.cert, self.key)

    def tearDown(self):
        self.httpd.stop()
        self.httpd = None
        self.session = None

    def test_spoof_connect_https_proxy(self):
        expected = upstream_content = b"windage-gelding-spume"
        upstream_url = "https://google.com/"
        self.httpd.upstream = spoof.HTTPServer(sslContext=self.sslContext)
        self.httpd.upstream.defaultResponse = [200, [], upstream_content]
        self.httpd.defaultResponse = [200, [], None]
        self.httpd.upstream.start()
        proxies = {"https": self.httpd.url}
        result = self.session.get(upstream_url, proxies=proxies).content
        self.httpd.upstream.stop()
        self.assertEqual(expected, result)

    def test_spoof_http_proxy_content(self):
        expected = upstream_content = b"aimless-scanty-thyself"
        upstream_url = "http://google.com/"
        self.httpd.defaultResponse = [200, [], upstream_content]
        proxies = {"http": self.httpd.url}
        result = self.session.get(upstream_url, proxies=proxies).content
        self.assertEqual(expected, result)

    def test_spoof_http_proxy_path(self):
        upstream_content = b"stimuli-liberia-parable"
        expected = upstream_url = "http://armour-lipstick-booze.com/"
        self.httpd.defaultResponse = [200, [], upstream_content]
        proxies = {"http": self.httpd.url}
        self.session.get(upstream_url, proxies=proxies).content
        result = self.httpd.requests[-1].path
        self.assertEqual(expected, result)

    def test_spoof_https_site_through_https_proxy(self):
        expected = upstream_content = b"octet-comeback-squirmy"
        httpd = spoof.HTTPServer(sslContext=self.sslContext).start()
        httpd.defaultResponse = [200, [], None]
        httpd.upstream = spoof.HTTPServer(sslContext=self.sslContext).start()
        httpd.upstream.defaultResponse = [200, [], upstream_content]

        # https proxies for https supported in requests v2.25.0 / urllib3 v1.26
        result = self.session.get(httpd.upstream.url, proxies={"https": httpd.url}).content
        self.assertTrue(httpd.upstream.url.startswith("https"))
        self.assertTrue(httpd.url.startswith("https"))
        self.assertEqual(expected, result)

    def test_spoof_simple_proxy_mode(self):
        with spoof.HTTPServer(sslContext=self.sslContext, proxy=True) as proxy:
            proxy.upstream.responses.append([200, [], "simple-spoof-proxy-setup"])
            result = self.session.get("https://google.com", proxies={"https": proxy.url}).text
        self.assertEqual(result, "simple-spoof-proxy-setup")


class TestSelfSignedSSLContext(BaseMixin):
    def test_context_manager_returns_ssl_context(self):
        with spoof.SelfSignedSSLContext() as selfSigned:
            self.assertIsInstance(selfSigned.sslContext, ssl.SSLContext)
            self.assertTrue(os.path.exists(selfSigned.keyFile))
            self.assertTrue(os.path.exists(selfSigned.certFile))
        self.assertFalse(os.path.exists(selfSigned.keyFile))
        self.assertFalse(os.path.exists(selfSigned.certFile))


if __name__ == "__main__":
    unittest.main()
