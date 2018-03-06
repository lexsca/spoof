from collections import namedtuple
from io import BytesIO
import random
import unittest

import mock

import spoof


class TestHTTPRequestHandler(unittest.TestCase):
    def setUp(self):
        def fakeInit(request):
            rawRequest = ('POST /test HTTP/1.0\r\n'
                          'Host: localhost\r\n'
                          'Content-Length: 17\r\n'
                          'Content-Type: application/json\r\n'
                          '\r\n'
                          '{"success": true}')
            genServer = namedtuple(
                'HTTPServer', 'serverName server_port upstream'
            )
            request.wfile = BytesIO()
            request.rfile = BytesIO(rawRequest.encode(spoof.RESPONSE_ENCODING))
            request.server = genServer('localhost', 8080, True)
            request.client_address = ('127.0.0.1', 8888)
            request.raw_requestline = request.rfile.readline(65537)
            request.parse_request()
            request.request = None
        mock.patch.object(
            spoof.HTTPRequestHandler, '__init__', fakeInit
        ).start()
        self.handler = spoof.HTTPRequestHandler()
        self.mockRequestQueue = mock.patch.object(
            spoof.HTTPRequestHandler, 'requestReportQueue',
            spec=spoof.Queue.Queue
        ).start()
        self.mockResponseQueue = mock.patch.object(
            spoof.HTTPRequestHandler, 'responseContentQueue',
            spec=spoof.Queue.Queue
        ).start()

    def tearDown(self):
        self.rfile = None
        self.wfile = None
        self.handler = None
        mock.patch.stopall()

    def test_Handler_reportRequestEnv_catches_Queue_Full(self):
        self.mockRequestQueue.put_nowait.side_effect = spoof.Queue.Full('test')
        self.handler.reportRequestEnv()
        self.assertTrue(self.mockRequestQueue.put_nowait.called)

    def test_Handler_reportRequestEnv_does_not_catch_AssertionError(self):
        error = AssertionError
        with self.assertRaises(error):
            self.mockRequestQueue.put_nowait.side_effect = error('raised')
            self.handler.reportRequestEnv()

    @mock.patch.object(spoof, 'unquote')
    def test_Handler_reportRequestEnv_handler_calls_unquote(self, mockUnquote):
        calls = [mock.call.unquote(self.handler.path)]
        self.handler.reportRequestEnv()
        mockUnquote.assert_has_calls(calls)

    def test_Handler_sendResponse_catches_TypeError(self):
        response = [spoof.HTTP_SERVICE_UNAVAILABLE, [], 'You broke it!']

        def fakeWrite(chunk):
            try:
                chunk = chunk.decode(spoof.RESPONSE_ENCODING)
            except (TypeError, AttributeError):
                pass
            if not fakeWrite.exceptionRaised and response[2] in chunk:
                fakeWrite.exceptionRaised = True
                raise TypeError('raised')
            return mock.DEFAULT
        fakeWrite.exceptionRaised = False
        mockWfile = mock.MagicMock(spec=BytesIO)
        mockWfile.write.side_effect = fakeWrite
        self.handler.wfile = mockWfile
        self.handler.sendResponse(response)
        self.assertTrue(fakeWrite.exceptionRaised)

    def test_Handler_sendResponse_handles_empty_response(self):
        status = spoof.HTTP_REQUEST_ENTITY_TOO_LARGE
        self.handler.sendResponse([status, [], ''])
        rawResponse = self.handler.wfile.getvalue()
        response = rawResponse.decode(spoof.RESPONSE_ENCODING)
        formattedStatus = ' {0} '.format(status)
        self.assertIn(formattedStatus, response)

    @mock.patch.object(spoof.HTTPRequestHandler, 'sendResponse')
    def test_Handler_handleRequest_honors_maxRequestLength(self, mockSend):
        self.mockResponseQueue.get_nowait.return_value = [200, [], 'OK']
        self.handler.maxRequestLength = 1
        self.handler.handleRequest()
        expected = spoof.HTTP_REQUEST_ENTITY_TOO_LARGE
        result = mockSend.call_args[0][0][0]
        self.assertEqual(expected, result)

    def test_Handler_raises_AttributeError_for_unknown_attributes(self):
        with self.assertRaises(AttributeError):
            self.handler.attributeThatDoesNotExist

    @mock.patch.object(spoof.BaseHTTPServer.BaseHTTPRequestHandler,
                       'handle_one_request')
    def test_Handler_handle_one_reequest_catches_UNKNOWN_CA_SSLError(self,
                                                                     mockOne):
        mockOne.side_effect = spoof.ssl.SSLError('TLSV1_ALERT_UNKNOWN_CA')
        self.handler.handle_one_request()
        self.assertTrue(mockOne.called)

    @mock.patch.object(spoof.BaseHTTPServer.BaseHTTPRequestHandler,
                       'handle_one_request')
    def test_Handler_handle_one_reequest_doesnt_catch_OTHER_SSLError(self,
                                                                     mockOne):
        mockOne.side_effect = spoof.ssl.SSLError('TLSV1_ALERT_OTHER_CA')
        with self.assertRaises(spoof.ssl.SSLError):
            self.handler.handle_one_request()

    @mock.patch.object(spoof.BaseHTTPServer.BaseHTTPRequestHandler,
                       'log_message')
    def test_Handler_log_message_called_with_debug_true(self, mockLog):
        message = 'random test message'
        self.handler.debug = True
        self.handler.log_message(message)
        mockLog.assert_called_once_with(message)

    @mock.patch.object(spoof.BaseHTTPServer.BaseHTTPRequestHandler,
                       'log_message')
    def test_Handler_log_message_not_called_with_debug_false(self, mockLog):
        message = 'random test message'
        self.handler.debug = False
        self.handler.log_message(message)
        self.assertFalse(mockLog.called)

    @mock.patch.object(spoof.HTTPRequestHandler, 'handleRequest')
    def test_Handler_raises_exception_on_CONNECT_with_content(self, mock_req):
        mock_req.return_value = (None, (200, (), 'Not empty string'))
        with self.assertRaises(RuntimeError):
            self.handler.do_CONNECT()


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

    def test_Server_raises_RuntimeError_if_already_stopped(self):
        with self.assertRaises(RuntimeError):
            self.httpd.stop()

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

    def test_Server_defaultResponse_can_be_set(self):
        expected = [200, [], 'OK']
        self.httpd.defaultResponse = expected
        result = self.httpd.defaultResponse
        self.assertEqual(expected, result)

    def test_Server_get_timeout(self):
        expected = self.httpd.serverClass.timeout
        result = self.httpd.timeout
        self.assertEqual(expected, result)

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

    def test_Server_get_upstream(self):
        expected = None
        result = self.httpd.upstream
        self.assertEqual(expected, result)

    def test_Server_set_upstream(self):
        expected = True
        self.httpd.upstream = expected
        result = self.httpd.upstream
        self.assertEqual(expected, result)

    def test_Server_get_upstream_gets_server_instance(self):
        randupstream = True
        with spoof.HTTPServer() as httpd:
            httpd.upstream = randupstream
            expected = httpd.server.upstream
            result = httpd.upstream
            self.assertEqual(expected, result)

    def test_Server_set_upstream_sets_server_instance(self):
        expected = True
        with spoof.HTTPServer() as httpd:
            httpd.upstream = expected
            result = httpd.server.upstream
            self.assertEqual(expected, result)


class TestUpstreamServer(unittest.TestCase):
    def setUp(self):
        self.httpd = spoof.HTTPUpstreamServer()

    def tearDown(self):
        self.httpd = None

    def test_Upstream_raises_RuntimeError_if_already_running(self):
        with self.assertRaises(RuntimeError):
            self.httpd.start()
            self.httpd.start()

    def test_Upstream_raises_RuntimeError_if_already_stopped(self):
        with self.assertRaises(RuntimeError):
            self.httpd.stop()


class TestSSLContext(unittest.TestCase):
    @mock.patch.object(spoof.subprocess, 'check_call')
    def test_createSelfSignedCert_raises_CalledProcessError(self, mockCall):
        errorArgs = [1, '/some/test/command', 'You broke it!']
        mockCall.side_effect = spoof.subprocess.CalledProcessError(*errorArgs)
        with self.assertRaises(spoof.subprocess.CalledProcessError):
            spoof.SSLContext.createSelfSignedCert()


if __name__ == '__main__':
    unittest.main()
