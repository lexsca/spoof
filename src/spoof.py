import collections
import functools
import http.server as BaseHTTPServer
import json
import os
import re
import select
import socket
import ssl
import subprocess
import tempfile
import threading
import urllib.parse

HTTP_OK = 200
HTTP_BAD_GATEWAY = 502
HTTP_SERVICE_UNAVAILABLE = 503
HTTP_REQUEST_ENTITY_TOO_LARGE = 413
RESPONSE_ENCODING = "utf-8"
URI_QUERY_SEPARATOR = "?"
MEGABYTE = 2**20


class HTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """Provides HTTP handler for use with ``http.server`` compatible class
    server. Because the class is passed directly instead of an instance of
    the class, the `*Queue` class attributes must be set before passing to
    the HTTP server.
    """

    debug = False
    defaultResponse = None
    errorResponse = [
        HTTP_SERVICE_UNAVAILABLE,
        [],
        "The .responses queue is empty and .defaultResponse is None\n\n",
    ]
    maxRequestLength = 1 * MEGABYTE
    proxyRequestGen = collections.namedtuple("SpoofProxyRequest", "thread run")
    requestEnvGen = collections.namedtuple(
        "SpoofRequestEnv",
        "content contentEncoding contentLength contentType headers json"
        " method path protocol queryString serverName serverPort uri",
    )
    requestReportQueue = None
    responseContentQueue = None

    def reportRequestEnv(self):
        """Returns namedtuple containing request report."""
        env = {
            "content": None,
            "contentEncoding": self.headers.get("content-encoding", None),
            "contentLength": int(self.headers.get("content-length", 0)),
            "contentType": self.headers.get("content-type", None),
            "headers": self.headers,
            "method": self.command,
            "path": None,
            "protocol": self.request_version,
            "queryString": None,
            "serverName": self.server.serverName,
            "serverPort": int(self.server.server_port),
            "uri": self.path,
        }
        if env["contentLength"] > 0 and env["contentLength"] <= self.maxRequestLength:
            env["content"] = self.rfile.read(env["contentLength"])
        if URI_QUERY_SEPARATOR in env["uri"]:
            sep = URI_QUERY_SEPARATOR
            path, _, env["queryString"] = env["uri"].partition(sep)
        else:
            path = self.path
        env["path"] = urllib.parse.unquote(path)
        env["json"] = functools.partial(json.loads, env["content"])
        requestEnv = self.requestEnvGen(**env)
        self.requestReportQueue.append(requestEnv)
        return requestEnv

    def nextResponse(self):
        """Returns next HTTP response to send."""
        try:
            response = self.responseContentQueue.popleft()
        except IndexError:
            if self.defaultResponse is not None:
                response = self.defaultResponse
            else:
                response = self.errorResponse
        return response

    def encodeResponseContent(self, content):
        if content and isinstance(content, str):
            content = content.encode(RESPONSE_ENCODING)

        return content

    def sendResponse(self, response):
        """Sends response to HTTP client."""
        statusCode, headers, rawContent = response
        content = self.encodeResponseContent(rawContent)

        self.send_response(statusCode)

        if content is not None:
            self.send_header("Content-Length", len(content))
        for header in headers:
            self.send_header(*header)
        self.end_headers()

        if content:
            self.wfile.write(content)

    def getResponse(self, request):
        """Get response for this request."""
        response = self.nextResponse()
        if request.contentLength > self.maxRequestLength:
            response = [
                HTTP_REQUEST_ENTITY_TOO_LARGE,
                [],
                "Content-Length > {0}\n\n".format(self.maxRequestLength),
            ]
        return response(request) if callable(response) else response

    def handleRequest(self):
        """Sends spoofed HTTP response and reports request environment."""
        request = self.reportRequestEnv()
        response = self.getResponse(request)
        self.sendResponse(response)
        return request, response

    def __getattr__(self, name):
        """Catches `do_COMMAND` method calls from the base class."""
        if not re.match("^do_[A-Z]+$", name):
            error = "'{0}' object has no attribute '{1}'"
            message = error.format(type(self), name)
            raise AttributeError(message)
        return self.handleRequest

    def do_CONNECT(self):
        """Handle CONNECT request, sending it upstream if successful."""
        _, response = self.handleRequest()
        if response[0] == HTTP_OK and self.server.upstream is not None:
            self.proxyRequest()

    def proxyRequest(self):
        """Simulate request proxying via threaded bi-directional socket copy
        to upstream ``spoof.HTTPServer`` instance with a ``threading.Event``
        to synchronize I/O exceptions.
        """
        run = threading.Event()
        thread = threading.Thread(target=self._proxyRequest, name="proxyRequest", args=(run,))
        self.server.upstream.proxyThreads.append(self.proxyRequestGen(thread, run))
        run.set()
        thread.start()
        thread.join()

    def _proxyRequest(self, run):
        downstream = self.request
        upstream = socket.create_connection(
            (self.server.upstream.address, self.server.upstream.port), self.server.upstream.timeout
        )
        writer = {downstream: upstream, upstream: downstream}

        while run.is_set():
            ready_to_recv, _, _ = select.select(
                [downstream, upstream], [], [], self.server.upstream.selectTimeout
            )
            for sock in ready_to_recv:
                chunk = sock.recv(self.server.upstream.recvSize)
                if not chunk:
                    run.clear()
                    break
                writer[sock].sendall(chunk)
        for sock in downstream, upstream:
            sock.shutdown(socket.SHUT_WR)
            sock.close()

    def log_message(self, *args, **kwargs):
        """Overrides base class to squelch request logging unless self.debug is true."""

        if self.debug:
            super(HTTPRequestHandler, self).log_message(*args, **kwargs)


class HTTPServer:
    """Provides a single-threaded HTTP testing server.

    Class attributes:
    :serverClass: `BaseHTTPServer.HTTPServer` compatible class
    :handlerClass: `BaseHTTPServer.BaseHTTPRequestHandler` compatible class
    :addressFamily: integer representing network protocol (see `socket`)
    """

    serverClass = BaseHTTPServer.HTTPServer
    handlerClass = HTTPRequestHandler
    addressFamily = socket.AF_INET

    def __init__(self, host="localhost", port=0, timeout=5, sslContext=None, proxy=False):
        """
        :host:       IP/IPv6 address string or FQDN string
        :port:       TCP port integer (0 selects an unused port)
        :timeout:    integer timeout in seconds to wait for server operations
        :sslContext: `ssl.SSLContext` compatible instance
        :proxy:      Configure and manage ``.upstream`` instance?
        """
        self._requests = collections.deque()
        self._responses = collections.deque()
        self._serverAddress = None
        self._upstream = None
        self.handlerClass = self.configureHandlerClass()
        self.proxyMode = proxy
        self.proxyThreads = []
        self.recvSize = 4096
        self.selectTimeout = 0.1
        self.server = None
        self.serverAddress = (host, port)
        self.sslContext = sslContext
        self.thread = None
        self.timeout = timeout

        if self.proxyMode:
            self.setupDefaultUpstream()

    @property
    def serverAddress(self):
        """Returns address to bind for HTTP server."""
        return self._serverAddress

    @serverAddress.setter
    def serverAddress(self, address):
        """Sets address to bind for HTTP server and setup server classes."""
        self._serverAddress = address
        self.serverClass = self.configureServerClass(address[0])

    @property
    def address(self):
        """Returns bound server IP/IPv6 address or ``None`` if unbound."""
        return None if self.server is None else self.server.server_address[0]

    @property
    def port(self):
        """Returns bound server TCP port or ``None`` if unbound."""
        return None if self.server is None else self.server.server_address[1]

    @property
    def url(self):
        """Returns URL string for server instance or ``None`` if unbound."""
        url = None
        if self.server is not None:
            protocol = "http" if self.sslContext is None else "https"
            address = "[{0}]".format(self.address) if ":" in self.address else self.address
            url = "{0}://{1}:{2}".format(protocol, address, self.port)
        return url

    @property
    def timeout(self):
        """Returns HTTP server timeout."""
        timeout = self._timeout
        if self.server is not None:
            timeout = self.server.timeout
        return timeout

    @timeout.setter
    def timeout(self, value):
        """Sets HTTP server timeout."""
        self._timeout = value
        if self.server is not None:
            self.server.timeout = value

    @property
    def upstream(self):
        """Returns upstream HTTP server, or `None` if not set."""
        upstream = self._upstream
        if self.server is not None and getattr(self.server, "upstream", None) is not None:
            upstream = self.server.upstream
        return upstream

    @upstream.setter
    def upstream(self, value):
        """Sets upstream HTTP server."""
        self._upstream = value
        if self.server is not None:
            self.server.upstream = value

    def configureServerClass(self, host):
        """Reloads and configures server class. This is necessary because of
        the use of class attributes.  If more than one address family is used
        concurrently (e.g. IPv4 _and_ IPv6), one will overwrite the other, as
        the default behavior is for a class to be loaded once and only once,
        including attributes. Using `type()` effectively creates a new class
        with _discrete_ attributes.
        """
        sourceClass = type(self).serverClass
        serverClass = type(sourceClass.__name__, (sourceClass, object), dict())
        serverClass.address_family = socket.AF_INET6 if host.count(":") > 1 else self.addressFamily
        serverClass.serverName = host
        return serverClass

    def configureHandlerClass(self):
        """Reloads and configures handler class. This is necessary because of
        the use of class attributes, which are necessary because the handler
        class is instantiated anew to handle each request by `BaseServer`.
        To keep the handler class unique to each `Spoof` instance, `type()` is
        used to effectively create a discrete handler class and attributes.
        """
        sourceClass = type(self).handlerClass
        handlerClass = type(sourceClass.__name__, (sourceClass, object), dict())
        handlerClass.responseContentQueue = self._responses
        handlerClass.requestReportQueue = self._requests
        return handlerClass

    def setupDefaultUpstream(self):
        """Configures ready-to-use default upstream HTTP server."""
        self.upstream = type(self)(
            host="localhost", port=0, sslContext=self.sslContext, proxy=False
        )
        # RFC 7231, Section 4.3.6, "A server MUST NOT send any Transfer-Encoding or
        # Content-Length header fields in a 2xx (Successful) response to CONNECT."
        self.defaultResponse = [200, [], None]

    def restart(self):
        """Stops and starts HTTP server."""
        self.stop()
        self.start()

    def start(self):
        """Starts HTTP server thread(s)."""
        if self.server is not None:
            message = "server at {0} already started".format(self.url)
            raise RuntimeError(message)
        if self.proxyMode:
            self.upstream.start()

        self.server = self.serverClass(self.serverAddress, self.handlerClass)
        self.server.timeout = self._timeout
        self.server.upstream = self._upstream
        if self.sslContext is not None:
            self.server.socket = self.sslContext.wrap_socket(self.server.socket, server_side=True)

        name = getattr(type(self), "__name__")
        self.thread = threading.Thread(target=self.server.serve_forever, name=name)
        self.thread.start()
        return self

    def stop(self):
        """Stops HTTP server thread(s) and closes socket(s)."""
        if self.proxyMode:
            self.upstream.stop()

        for proxy in self.proxyThreads:
            proxy.run.clear()
            proxy.thread.join()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join()

        self.proxyThreads = []
        self.server = None
        self.thread = None

    def __enter__(self):
        """Starts and returns HTTP server instance when invoked as a context manager (with/as)."""
        return self.start()

    def __exit__(self, exceptionType, exceptionValue, traceback):
        """Stops HTTP server instance when context manager block exits."""
        self.stop()

    def __del__(self):
        """Stops HTTP server when instance goes out of scope."""
        if getattr(self, "server", None) is not None:
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
        self._requests.clear()
        self._responses.clear()
        self.defaultResponse = None

    @property
    def requests(self):
        """Returns ``deque`` of namedtuple instances with the
        following properties:

        :content:         string containing request content if present,
                          `None` if missing
        :contentEncoding: Content-Encoding header value if present,
                          `None` if missing
        :contentLength:   Content-Length header integer value, 0 if missing
        :contentType:     Content-Type header value if present,
                          `None` if missing
        :headers:         `mimetools.Message` instance with all request
                          headers; to get specific header use:
                          `headers.get(headerName, defaultValue)`
        :json():          Convenience to call json.loads on content
        :method:          Request method (e.g. GET, POST, HEAD)
        :path:            Decoded URI path, without query string
        :protocol:        Protocol version client used to send request
                           (e.g. HTTP/1.0)
        :queryString:     Anything in URI after URI_QUERY_SEPARATOR,
                          `None` if missing
        :serverName:      Hostname of server
        :serverPort:      TCP/IP port of server
        :uri:             Raw URI path and query string, if present
        """
        return self._requests

    @property
    def responses(self):
        """Returns ``deque`` of responses to send. If no responses are queued,
        then ``self.defaultResponse`` is sent. If no default response is set,
        then ``self.errorResponse`` is sent. Format for responses:

        [httpStatus, [(headerName1, value1), (headerName2, value2)], content]

        Example adding one response and multiple responses:

        self.responses.append([200, [("Content-Type", "text/plain)], "OK"])
        self.responses.extend([
            [200, [("Content-Type", "text/plain)], "One"],
            [200, [("Content-Type", "text/plain)], "Two"],
        ])
        """
        return self._responses

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
        is sent. Format for response:

        [httpStatus, [(headerName1, value1), (headerName2, value2)], content]

        Example:

        [200, [('Content-Type', 'application/json')], '{"success": true }']

        Alternatively, a callable object may used as a response. It should
        accept a request instance as its only argument and it should return
        the response format noted above.  See `requests` for details on the
        request instance.
        """
        response = staticmethod(response) if callable(response) else response
        self.handlerClass.defaultResponse = response

    def queueResponse(self, *responses):
        """Queues one or more response to be returned by HTTP server.

        NOTE: This method is deprecated. Please use ``responses`` instead.
        """
        self._responses.extend(responses)


class HTTPServer6(HTTPServer):
    """Provides a single-threaded, IPv6-only HTTP server."""

    addressFamily = socket.AF_INET6


class SSLContext:
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
    def createSelfSignedCert(
        cls,
        commonName="localhost",
        bits=2048,
        days=365,
        openssl="openssl",
        subjectAltNames=None,
        keyAlgorithm=None,
    ):
        """Creates and returns file paths to self-signed certificate and key
        via OpenSSL command line tool.

        :commonName:   string of hostname for X509 certificate
        :bits:         RSA public key length in bits
        :days:         length in days certificate is valid
        :openssl:      name/path string of openssl command
        :keyAlgorithm: key algorithm to use (e.g. mldsa65); ignores ``bits`` arg
        """
        if keyAlgorithm is None:
            keyAlgorithm = "rsa:" + str(bits)
        devNull = open(os.devnull, "w")
        key = tempfile.mkstemp()
        cert = tempfile.mkstemp()
        config = cls.createOpenSSLConfig(commonName=commonName, subjectAltNames=subjectAltNames)
        call = [
            openssl,
            "req",
            "-nodes",
            "-x509",
            "-config",
            config,
            "-newkey",
            keyAlgorithm,
            "-keyout",
            key[1],
            "-out",
            cert[1],
            "-days",
            str(days),
            "-extensions",
            "req_ext",
        ]
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
        """
        fileDesc, filePath = tempfile.mkstemp()
        template = [
            "[ req ]",
            "prompt = no",
            "default_md = sha256",
            "req_extensions = req_ext",
            "distinguished_name = dn",
            "[ dn ]",
            "O = Test Authority",
            "OU = Test Certificate",
            "CN = {commonName}",
            "[ req_ext ]",
            "subjectAltName = @alt_names",
            "[ alt_names ]",
            "DNS.0 = {commonName}",
        ]
        subjectAltNames = kwargs.get("subjectAltNames")
        if subjectAltNames is None:
            for idx, addr in enumerate(("::1", "127.0.0.1"), start=1):
                template.append("IP.{0} = {1}".format(idx, addr))
                template.append("DNS.{0} = {1}".format(idx, addr))
        config = "\n".join(template).format(**kwargs).encode()
        os.write(fileDesc, config)
        os.close(fileDesc)
        return filePath


class SelfSignedSSLContext(SSLContext):
    """Provides context manager for creating self-signed certificate
    SSL context. Uses same arguments as `SSLContext.createSelfSignedCert`.
    """

    def __init__(self, *args, **kwargs):
        certFile, keyFile = self.createSelfSignedCert(*args, **kwargs)
        self.sslContext = self.fromCertChain(certFile, keyFile)
        self.keyFile = keyFile
        self.certFile = certFile

    def cleanup(self):
        """Remove temporary key and certificate files."""
        attrs = ["keyFile", "certFile"]
        for path in [getattr(self, attr, None) for attr in attrs]:
            if path:
                os.unlink(path)

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.cleanup()
