"""On-demand HTTP server for use in test environments where it's not
practical to mock underlying calls or it's necessary to have an actual
HTTP server listening on a socket (e.g. testing IPv6 connectivity).
"""

try:
    import BaseHTTPServer
except ImportError:
    # class renamed in python 3
    import http.server as BaseHTTPServer
import collections
import os
try:
    import Queue
except ImportError:
    # class renamed in python 3
    import queue as Queue
import re
import select
import socket
import ssl
import subprocess
import tempfile
import threading
try:
    from urllib import unquote
except ImportError:
    # method moved in python 3
    from urllib.parse import unquote

HTTP_OK = 200
HTTP_BAD_GATEWAY = 502
HTTP_SERVICE_UNAVAILABLE = 503
HTTP_REQUEST_ENTITY_TOO_LARGE = 413
RESPONSE_ENCODING = 'utf-8'
URI_QUERY_SEPARATOR = '?'
MEGABYTE = 2 ** 20


class HTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler, object):
    """Provides HTTP handler for use with `BaseHTTPServer.HTTPServer`
    compatible class server. Because the class is passed directly
    instead of an instance of the class, the `*Queue` class attributes
    must be set before passing to the HTTP server.
    """
    responseContentQueue = None
    requestReportQueue = None
    defaultResponse = None
    errorResponse = [HTTP_SERVICE_UNAVAILABLE, [],
                     'No responses queued and no default response set\n\n']
    maxRequestLength = 1 * MEGABYTE
    debug = False

    def reportRequestEnv(self):
        """Returns namedtuple containing request report. It's a report
        because when it's available to the user, an HTTP response has
        already been sent.
        """
        env = {'method': self.command,
               'uri': self.path,
               'protocol': self.request_version,
               'serverName': self.server.serverName,
               'serverPort': int(self.server.server_port),
               'headers': self.headers,
               'path': None,
               'queryString': None,
               'content': None,
               'contentType': self.headers.get('content-type', None),
               'contentLength': int(self.headers.get('content-length', 0))}
        if (env['contentLength'] > 0 and
                env['contentLength'] <= self.maxRequestLength):
            env['content'] = self.rfile.read(env['contentLength'])
        if URI_QUERY_SEPARATOR in env['uri']:
            sep = URI_QUERY_SEPARATOR
            path, _, env['queryString'] = env['uri'].partition(sep)
        else:
            path = self.path
        env['path'] = unquote(path)
        genRequest = collections.namedtuple('SpoofRequestEnv', env.keys())
        requestEnv = genRequest(**env)
        try:
            self.requestReportQueue.put_nowait(requestEnv)
        except Queue.Full:
            pass
        return requestEnv

    def nextResponse(self):
        """Returns next HTTP response to send."""
        try:
            response = self.responseContentQueue.get_nowait()
        except Queue.Empty:
            if self.defaultResponse is not None:
                response = self.defaultResponse
            else:
                response = self.errorResponse
        return response

    def sendResponse(self, response):
        """Sends response to HTTP client."""
        self.send_response(response[0])
        responseLength = len(response[2])
        for header in response[1]:
            self.send_header(*header)
        if responseLength:
            self.send_header('Content-Length', responseLength)
            self.end_headers()
            try:
                self.wfile.write(response[2])
            except TypeError:
                # encode string if content is not bytes
                self.wfile.write(response[2].encode(RESPONSE_ENCODING))
        else:
            self.end_headers()

    def getResponse(self, request):
        """Get response for this request."""
        response = self.nextResponse()
        if request.contentLength > self.maxRequestLength:
            response = [
                HTTP_REQUEST_ENTITY_TOO_LARGE, [],
                'Content-Length > {0}\n\n'.format(self.maxRequestLength)
            ]
        return response

    def handleRequest(self):
        """Sends spoofed HTTP response and reports request environment."""
        request = self.reportRequestEnv()
        response = self.getResponse(request)
        self.sendResponse(response)
        return request, response

    def __getattr__(self, name):
        """Catches `do_COMMAND` method calls from the base class."""
        if not re.match('^do_[A-Z]+$', name):
            error = "'{0}' object has no attribute '{1}'"
            message = error.format(type(self), name)
            raise AttributeError(message)
        return self.handleRequest

    def do_CONNECT(self):
        """Handle CONNECT request, sending it upstream if successful."""
        request, response = self.handleRequest()
        if response[0] == HTTP_OK and self.server.upstream is not None:
            if response[2]:
                message = 'CONNECT requests cannot have response content'
                raise RuntimeError(message)
            self.server.upstream.handleRequest(self.request, request)

    def handle_one_request(self, *args, **kwargs):
        """Overrides base class to squelch TLSV1_ALERT_UNKNOWN_CA exception
        stemming from the use of self-signed certificates.  The error will
        be logged if self.debug is `True`.
        """
        try:
            super(HTTPRequestHandler, self).handle_one_request(*args, **kwargs)
        except ssl.SSLError as error:
            if 'TLSV1_ALERT_UNKNOWN_CA' in str(error):
                self.log_error('SSL negotiation failed: %r', error)
            else:
                raise

    def log_message(self, *args, **kwargs):
        """Overrides base class to squelch logging unless
        self.debug is true.
        """
        if self.debug:
            super(HTTPRequestHandler, self).log_message(*args, **kwargs)


class HTTPServer(object):
    """Provides a single-threaded HTTP testing server.

    Class attributes:
    :serverClass: `BaseHTTPServer.HTTPServer` compatible class
    :handlerClass: `BaseHTTPServer.BaseHTTPRequestHandler` compatible class
    :addressFamily: integer representing network protocol (see `socket`)
    """
    serverClass = BaseHTTPServer.HTTPServer
    handlerClass = HTTPRequestHandler
    addressFamily = socket.AF_INET

    def __init__(self, host='localhost', port=0, timeout=5, sslContext=None):
        """
        :host: IP/IPv6 address string or FQDN string
        :port: TCP port integer (0 selects an unused port)
        :timeout: integer timeout in seconds to wait for server operations
        :sslContext: `ssl.SSLContext` compatible instance
        """
        self._requests = []
        self._sslContext = sslContext
        self.handlerClass = self.configureHandlerClass(self.handlerClass)
        if ':' in str(host):
            self.serverClass = HTTPServer6.configureServerClass(host)
        else:
            self.serverClass = self.configureServerClass(host)
        self.serverClass.timeout = timeout
        self.serverClass.sslContext = sslContext
        self.serverAddress = (host, port)
        self.server = None
        self.thread = None
        self._upstream = None

    @property
    def address(self):
        """Returns server IP/IPv6 address."""
        return self.serverAddress[0]

    @property
    def port(self):
        """Returns server TCP port."""
        return self.serverAddress[1]

    @property
    def url(self):
        """Returns URL string to connect to this server instance."""
        protocol = 'http' if self.sslContext is None else 'https'
        address = ('[{0}]'.format(self.address) if ':' in self.address
                   else self.address)
        return '{0}://{1}:{2}'.format(protocol, address, self.port)

    @property
    def sslContext(self):
        """Returns `ssl.SSLContext` instance."""
        return self._sslContext

    @property
    def timeout(self):
        """Returns HTTP server timeout."""
        timeout = self.serverClass.timeout
        if self.server is not None:
            timeout = self.server.timeout
        return timeout

    @timeout.setter
    def timeout(self, value):
        """Sets HTTP server timeout."""
        self.serverClass.timeout = value
        if self.server is not None:
            self.server.timeout = value

    @property
    def upstream(self):
        """Returns upstream HTTP server, or `None` if not set."""
        upstream = self._upstream
        if self.server is not None and self.server.upstream is not None:
            upstream = self.server.upstream
        return upstream

    @upstream.setter
    def upstream(self, value):
        """Sets upstream HTTP server."""
        self._upstream = value
        if self.server is not None:
            self.server.upstream = value

    @classmethod
    def configureServerClass(cls, host):
        """Reloads and configures server class. This is necessary, because of
        the use of class attributes.  If more than one address family is used
        concurrently (e.g. IPv4 _and_ IPv6), one will overwrite the other, as
        the default behavior is for a class to be loaded once and only once,
        including attributes. Using `type()` effectively creates a new class
        with _discrete_ attributes. This is a class method, because it is
        called outside of the scope of an initialized class instance.

        :host: hostname string of server
        """
        sourceClass = cls.serverClass
        serverClass = type(
            sourceClass.__name__, (sourceClass, object), dict()
        )
        serverClass.address_family = cls.addressFamily
        serverClass.serverName = host
        return serverClass

    def configureHandlerClass(self, sourceClass):
        """Reloads and configures handler class. This is necessary because of
        the use of class attributes, which are necessary because the handler
        class is instantiated anew to handle each request by `BaseServer`.
        To keep the handler class unique to each `Spoof` instance, `type()` is
        used to effectively create a discrete handler class and attributes.
        """
        handlerClass = type(
            sourceClass.__name__, (sourceClass, object), dict()
        )
        self.responseContentQueue = Queue.Queue()
        self.requestReportQueue = Queue.Queue()
        handlerClass.responseContentQueue = self.responseContentQueue
        handlerClass.requestReportQueue = self.requestReportQueue
        return handlerClass

    def start(self):
        """Starts HTTP server thread."""
        if self.server is not None:
            message = 'server at {0} already started'.format(self.url)
            raise RuntimeError(message)
        else:
            self.server = self.serverClass(self.serverAddress,
                                           self.handlerClass)
            self.serverAddress = self.server.server_address
            self.server.upstream = self._upstream
        if self.server.sslContext is not None:
            self.server.socket = self.server.sslContext.wrap_socket(
                self.server.socket, server_side=True
            )
        name = getattr(type(self), '__name__')
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       name=name)
        self.thread.start()

    def stop(self):
        """Stops HTTP server and closes socket."""
        if self.server is None:
            message = 'server at {0} already stopped'.format(self.url)
            raise RuntimeError(message)
        self.server.shutdown()
        self.server.server_close()
        if self.thread is not None:
            self.thread.join()
            self.thread = None
        self.server = None

    def __enter__(self):
        """Starts HTTP server and returns `Spoof` instance when invoked as a
        context manager (with/as)."""
        self.start()
        return self

    def __exit__(self, exceptionType, exceptionValue, traceback):
        """Destroys HTTP server instance when context manager block finishes.
        If context block ends normally, all arguments will be `None`.
        """
        self.stop()

    def __del__(self):
        """Closes HTTP server socket when instance goes out of scope."""
        if getattr(self, 'server', None) is not None:
            self.stop()

    @property
    def debug(self):
        """Returns request handler debug flag."""
        return self.handlerClass.debug

    @debug.setter
    def debug(self, value):
        """Sets request handler debug flag."""
        self.handlerClass.debug = value

    def reset(self):
        """Reset request and response attributes."""
        queues = ['requestReportQueue', 'responseContentQueue']
        for queue in [getattr(self, name) for name in queues]:
            try:
                while True:
                    queue.get_nowait()
            except Queue.Empty:
                pass
        del self._requests[:]
        self.defaultResponse = None

    @property
    def requests(self):
        """Returns list of namedtuple request report instances.
        They're called reports, because they're no longer actionable.
        The HTTP server sends responses unconditionally and reports
        the request after the fact.

        `HTTPRequestHandler.reportRequestEnv` namedtuple attributes:
        :method:        Request method (e.g. GET, POST, HEAD)
        :uri:           Raw URI path and query string, if present
        :protocol:      Protocol version client used to send request
                        (e.g. HTTP/1.0)
        :serverName:    Hostname of server
        :serverPort:    TCP/IP port of server
        :headers:       `mimetools.Message` instance with all request
                        headers; to get specific header use:
                        `headers.get(headerName, defaultValue)`
        :path:          Decoded URI path, without query string
        :queryString:   Anything in URI after URI_QUERY_SEPARATOR,
                        `None` if missing
        :content:       string containing request content if present,
                        `None` if missing
        :contentType:   Content-Type header value if present,
                        `None` if missing
        :contentLength: Content-Length header integer value, 0 if missing
        """
        try:
            while True:
                requestReport = self.requestReportQueue.get_nowait()
                self._requests.append(requestReport)
        except Queue.Empty:
            pass
        return self._requests

    @property
    def maxRequestLength(self):
        """Returns maximum request content length."""
        return self.handlerClass.maxRequestLength

    @maxRequestLength.setter
    def maxRequestLength(self, value):
        """Sets maximum request content length."""
        self.handlerClass.maxRequestLength = int(value)

    @property
    def defaultResponse(self):
        """Returns default response used by the request handler class."""
        return self.handlerClass.defaultResponse

    @defaultResponse.setter
    def defaultResponse(self, response):
        """Sets the default response used by the request handler class to
        respond to requests when no responses are queued. If the default
        response is not set, and no responses are queued, errorResponse
        is sent.  Response format:

        [httpStatus, [(headerName1, value1), (headerName2, value2)], content]

        Example:

        [200, [('Content-Type', 'application/json')], '{"success": true }']
        """
        self.handlerClass.defaultResponse = response

    def queueResponse(self, response):
        """Queues response to be returned once by HTTP server. If no
        esponses are queued, the handler class defaultResponse will be sent.
        If defaultResponse is not set, and no responses are queued,
        errorResponse is sent.

        See `defaultResponse` for response format.
        """
        self.responseContentQueue.put_nowait(response)


class HTTPServer6(HTTPServer):
    """Provides a single-threaded, IPv6-only HTTP server."""

    addressFamily = socket.AF_INET6


class HTTPUpstreamServer(HTTPServer):
    """Handle upstream requests from `HTTPRequestHandler`, which will
    directly invoke the `handleRequest` method to proxy the request.
    """
    def __init__(self, *args, **kwargs):
        """Override base class method to set proxy attributes."""
        super(HTTPUpstreamServer, self).__init__(*args, **kwargs)
        self.proxyThreads = []
        self.selectTimeout = 0.1
        self.recvSize = 4096

    def stop(self, *args, **kwargs):
        """Override base class method to stop proxy threads."""
        for proxy in self.proxyThreads:
            proxy.run.clear()
            proxy.thread.join()
        self.proxyThreads = []
        super(HTTPUpstreamServer, self).stop(*args, **kwargs)

    def proxyRequest(self, client, server, run):
        """This method expects to be run in a thread. It takes a client
        socket and proxies the request to the server socket.

        :client:  downstream `socket.socket` instance
        :server:  upstream `socket.socket` instance
        :run:     `threading.Event` instance control the proxy loop
        """
        select_args = ([client, server], [], [], self.selectTimeout)
        writer = {client: server, server: client}
        while run.is_set():
            read, _, _ = select.select(*select_args)
            for sock in read:
                chunk = sock.recv(self.recvSize)
                if not chunk:
                    run.clear()
                    break
                writer[sock].sendall(chunk)
        for sock in select_args[0]:
            sock.shutdown(socket.SHUT_WR)
            sock.close()

    def handleRequest(self, client, request):
        """Handle upstream request. Starts thread with connection to
        upstream server and proxies request.

        :client:  downstream `socket.socket` instance
        :request: `HTTPRequestHandler.reportRequestEnv` instance
        """
        server = socket.create_connection(self.serverAddress, self.timeout)
        run = threading.Event()
        run.set()
        name = getattr(type(self), '__name__')
        thread = threading.Thread(target=self.proxyRequest, name=name,
                                  args=(client, server, run))
        self.proxyThreads.append(
            collections.namedtuple('Request', 'thread run')(thread, run)
        )
        thread.start()
        thread.join()


class SSLContext(object):
    """Provides methods to create SSL context for use with `HTTPServer`."""

    @staticmethod
    def fromCertChain(certFile, keyFile=None):
        """Returns SSL context from provided certificate chain.

        :certFile: path to X509 certificate
        :keyFile:  path to certificate signing key
                   (may be included in certFile)
        """
        context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certFile, keyFile)
        return context

    @classmethod
    def selfSigned(cls, *args, **kwargs):
        """Returns SSL context via self-signed certificate chain."""
        certFile, keyFile = cls.createSelfSignedCert(*args, **kwargs)
        context = cls.fromCertChain(certFile, keyFile)
        os.unlink(certFile)
        os.unlink(keyFile)
        return context

    @classmethod
    def createSelfSignedCert(cls, commonName='localhost', bits=2048, days=365,
                             openssl='openssl', subjectAltNames=None):
        """Creates and returns file paths to self-signed certificate and key
        via OpenSSL command line tool.

        :commonName: string of hostname for X509 certificate
        :bits: RSA key length in bits
        :days: length in days certificate is valid
        :openssl: name/path string of openssl command
        """
        devNull = open(os.devnull, 'w')
        key = tempfile.mkstemp()
        cert = tempfile.mkstemp()
        config = cls.createOpenSSLConfig(
            commonName=commonName,
            subjectAltNames=subjectAltNames
        )
        call = [openssl, 'req', '-nodes', '-x509', '-config', config,
                '-newkey', 'rsa:' + str(bits), '-keyout', key[1],
                '-out', cert[1], '-days', str(days), '-extensions', 'req_ext']
        for fileDesc in key[0], cert[0]:
            os.close(fileDesc)
        try:
            subprocess.check_call(call, stdout=devNull, stderr=devNull)
        except subprocess.CalledProcessError:
            os.unlink(cert[1])
            os.unlink(key[1])
            raise
        finally:
            devNull.close()
            os.unlink(config)
        return cert[1], key[1]

    @staticmethod
    def createOpenSSLConfig(**kwargs):
        """Creates and returns file path to OpenSSL configuration
        suitable for generating a self signed certificate with
        Subject Alternative Name (SAN) fields. Note that SAN entries
        must have the proper prefix, with 'DNS' for fully qualified
        domain names, and 'IP' for IP addresses. Example:

        DNS.1 = host.example.com
        IP.1 = 192.168.1.100

        The DNS.0 entry is given as the commonNmae in accordance with
        RFC 2818, so any DNS subjectAltNames entries must start with 1.

        Python 2.7: The `requests` library does not appear to honor
        SAN antries of the IP type, but accepts a DNS entry instead.
        Python 3.x is just the opposite, so if interoperability is
        required, each IP address must have an IP and a DNS SAN entry.
        """
        fileDesc, filePath = tempfile.mkstemp()
        template = [
            '[ req ]',
            'prompt = no',
            'default_md = sha256',
            'req_extensions = req_ext',
            'distinguished_name = dn',
            '[ dn ]',
            'O = Test Authority',
            'OU = Test Certificate',
            'CN = {commonName}',
            '[ req_ext ]',
            'subjectAltName = @alt_names',
            '[ alt_names ]',
            'DNS.0 = {commonName}'
        ]
        subjectAltNames = kwargs.get('subjectAltNames')
        if subjectAltNames is None:
            for idx, addr in enumerate(('::1', '127.0.0.1'), start=1):
                template.append('IP.{0} = {1}'.format(idx, addr))
                template.append('DNS.{0} = {1}'.format(idx, addr))
        config = '\n'.join(template).format(**kwargs).encode()
        os.write(fileDesc, config)
        os.close(fileDesc)
        return filePath
