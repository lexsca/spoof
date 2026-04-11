from collections import namedtuple
from io import BytesIO
import random
import unittest

import mock

import spoof


class TestHTTPRequestHandler(unittest.TestCase):
    def setUp(self):
        def fakeInit(request):
            rawRequest = (
                "POST /test HTTP/1.0\r\n"
                "Host: localhost\r\n"
                "Content-Length: 17\r\n"
                "Content-Type: application/json\r\n"
                "\r\n"
                '{"success": true}'
            )
            genServer = namedtuple("HTTPServer", "serverName server_port upstream")
            request.wfile = BytesIO()
            request.rfile = BytesIO(rawRequest.encode(spoof.RESPONSE_ENCODING))
            request.server = genServer("localhost", 8080, True)
            request.client_address = ("127.0.0.1", 8888)
            request.raw_requestline = request.rfile.readline(65537)
            request.parse_request()
            request.request = None

        mock.patch.object(spoof.HTTPRequestHandler, "__init__", fakeInit).start()
        self.handler = spoof.HTTPRequestHandler()

    def tearDown(self):
        self.rfile = None
        self.wfile = None
        self.handler = None
        mock.patch.stopall()

    def test_Handler_sendResponse_handles_empty_response(self):
        status = spoof.HTTP_REQUEST_ENTITY_TOO_LARGE
        self.handler.sendResponse([status, [], ""])
        rawResponse = self.handler.wfile.getvalue()
        response = rawResponse.decode(spoof.RESPONSE_ENCODING)
        formattedStatus = " {0} ".format(status)
        self.assertIn(formattedStatus, response)

    def test_Handler_raises_AttributeError_for_unknown_attributes(self):
        with self.assertRaises(AttributeError):
            self.handler.attributeThatDoesNotExist

    @mock.patch.object(spoof.BaseHTTPServer.BaseHTTPRequestHandler, "log_message")
    def test_Handler_log_message_called_with_debug_true(self, mockLog):
        message = "random test message"
        self.handler.debug = True
        self.handler.log_message(message)
        mockLog.assert_called_once_with(message)

    @mock.patch.object(spoof.BaseHTTPServer.BaseHTTPRequestHandler, "log_message")
    def test_Handler_log_message_not_called_with_debug_false(self, mockLog):
        message = "random test message"
        self.handler.debug = False
        self.handler.log_message(message)
        self.assertFalse(mockLog.called)


class TestHTTPServer(unittest.TestCase):
    def setUp(self):
        self.httpd = spoof.HTTPServer()

    def tearDown(self):
        self.httpd = None
        mock.patch.stopall()

    def test_Server_raises_RuntimeError_if_already_running(self):
        with self.assertRaises(RuntimeError):
            self.httpd.start()
            self.httpd.start()

    def test_Server_context_manager_returns_HTTPServer_instance(self):
        with spoof.HTTPServer() as httpd:
            self.assertIsInstance(httpd, spoof.HTTPServer)

    def test_Server_server_not_None_inside_context_manager(self):
        with spoof.HTTPServer() as httpd:
            self.assertIsNotNone(httpd.server)

    def test_Server_server_is_None_outside_context_manager(self):
        with spoof.HTTPServer() as httpd:
            pass
        self.assertIsNone(httpd.server)

    def test_Server_defaultResponse_returns_None(self):
        result = self.httpd.defaultResponse
        self.assertIsNone(result)

    def test_Server_set_timeout(self):
        expected = random.randint(1, 300)
        self.httpd.timeout = expected
        result = self.httpd.timeout
        self.assertEqual(expected, result)

    def test_Server_get_timeout_gets_server_instance(self):
        randTimeout = random.randint(1, 300)
        with spoof.HTTPServer() as httpd:
            httpd.timeout = randTimeout
            expected = httpd.server.timeout
            result = httpd.timeout
            self.assertEqual(expected, result)

    def test_Server_set_timeout_sets_server_instance(self):
        expected = random.randint(1, 300)
        with spoof.HTTPServer() as httpd:
            httpd.timeout = expected
            result = httpd.server.timeout
            self.assertEqual(expected, result)


class TestSSLContext(unittest.TestCase):
    @mock.patch.object(spoof.subprocess, "check_call")
    def test_createSelfSignedCert_raises_CalledProcessError(self, mockCall):
        errorArgs = [1, "/some/test/command", "You broke it!"]
        mockCall.side_effect = spoof.subprocess.CalledProcessError(*errorArgs)
        with self.assertRaises(spoof.subprocess.CalledProcessError):
            spoof.SSLContext.createSelfSignedCert()


if __name__ == "__main__":
    unittest.main()
