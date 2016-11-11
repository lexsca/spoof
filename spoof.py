''' On-demand HTTP server for use in test environments where it's not
practical to mock underlying calls or it's necessary to have an actual
HTTP server listening on a socket (e.g. testing IPv6 connectivity).
Multiple HTTP servers can be run concurrently, and by default the port
number is the next available unused port.  Example unittest usage:

import unittest
import spoof
import thing

class TestThing(unittest.TestCase):
  httpd = None
  httpd6 = None

  @classmethod
  def setUpClass(cls):
    # X509 certificates can be expensive to generate, so it should be done
    # infrequently.  Also, creating a new HTTP server instance with a new
    # port number for each and every test can starve a system of available
    # TCP/IP ports.  Because of this, creating an `HTTPServer` instance
    # should also be done infrequently, unless the port number is static.
    sslContext = spoof.SSLContext.selfSigned()
    cls.httpd = spoof.HTTPServer(sslContext=sslContext)
    cls.httpd.start()
    # IPv6-only, if needed; `HTTPServer` also accepts IPv6 addresses
    cls.httpd6 = spoof.HTTPServer6(sslContext=sslContext)
    cls.httpd6.start()

  @classmethod
  def tearDownClass(cls):
    cls.httpd.stop()
    cls.httpd6.stop()
    cls.httpd = None
    cls.httpd6 = None

  def setUp(self):
    # Calling `reset()` suffices to sanitize the HTTP server environment.
    self.httpd.reset()
    self.httpd.debug = False
    self.thing = thing.Thing(self.httpd.address, self.httpd.port)
    # or
    self.altThing = thing.AltThing(self.httpd.url)

  def tearDown(self):
    self.thing = None
    self.altThing = None

  def test_thingUsingSpoof(self):
    response1 = [200, [('Content-Type', 'application/json')], '{"id": 1111}']
    response2 = [200, [('Content-Type', 'application/json')], '{"id": 2222}']
    self.httpd.queueResponse(response1)
    self.httpd.queueResponse(response2)
    # HTTP debug logging, if needed
    self.httpd.debug = True
    self.thing.requiringTwoJSONresponses()
    lastRequest = self.httpd.requests[-1]
    expectedContent = '{"action": "rename", "old": 1111, "new": 2222}'
    self.assertEquals(expectedContent, lastRequest.content)
'''

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

HTTP_SERVICE_UNAVAILABLE = 503
HTTP_REQUEST_ENTITY_TOO_LARGE = 413
RESPONSE_ENCODING = 'utf-8'
URI_QUERY_SEPARATOR = '?'
MEGABYTE = 2 ** 20

class HTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler, object):
  ''' Provides HTTP handler for use with `BaseHTTPServer.HTTPServer`
  compatible class server. Because the class is passed directly instead
  of an instance of the class, the `*Queue` class attributes must be set
  before passing to the HTTP server.
  '''
  responseContentQueue = None
  requestReportQueue = None
  defaultResponse = None
  errorResponse = [HTTP_SERVICE_UNAVAILABLE, [],
                   'No responses queued and no default response set\n\n']
  maxRequestLength = 1 * MEGABYTE
  debug = False

  def reportRequestEnv(self):
    ''' Returns namedtuple containing request report. It's a report because
    when it's available to the user, an HTTP response has already been sent.
    '''
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
      path, _, env['queryString'] = env['uri'].partition(URI_QUERY_SEPARATOR)
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
    ''' Returns next HTTP response to send. '''
    try:
      response = self.responseContentQueue.get_nowait()
    except Queue.Empty:
      response = (self.defaultResponse if self.defaultResponse is not None
                  else self.errorResponse)
    return response

  def sendResponse(self, response):
    ''' Sends response to HTTP client. '''
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

  def handleRequest(self):
    ''' Sends spoofed HTTP response and reports request environment. '''
    request = self.reportRequestEnv()
    response = self.nextResponse()
    if request.contentLength > self.maxRequestLength:
      response = [HTTP_REQUEST_ENTITY_TOO_LARGE, [],
                  'Content-Length > {0}\n\n'.format(self.maxRequestLength)]
    self.sendResponse(response)

  def __getattr__(self, name):
    ''' Catches `do_COMMAND` method calls from the base class. '''
    if not re.match('^do_[A-Z]+$', name):
      message = "'{0}' object has no attribute '{1}'".format(type(self), name)
      raise AttributeError(message)
    return self.handleRequest

  def handle_one_request(self, *args, **kwargs):
    ''' Overrides base class to squelch TLSV1_ALERT_UNKNOWN_CA exception
    stemming from the use of self-signed certificates.  The error will
    be logged if self.debug is `True`.
    '''
    try:
      super(HTTPRequestHandler, self).handle_one_request(*args, **kwargs)
    except ssl.SSLError as error:
      if 'TLSV1_ALERT_UNKNOWN_CA' in str(error):
        self.log_error('SSL negotiation failed: %r', error)
      else:
        raise

  def log_message(self, *args, **kwargs):
    ''' Overrides base class to squelch logging unless self.debug is true. '''
    if self.debug:
      super(HTTPRequestHandler, self).log_message(*args, **kwargs)



class HTTPServer(object):
  ''' Provides a single-threaded HTTP testing server.

  Class attributes:
  :serverClass: `BaseHTTPServer.HTTPServer` compatible class
  :handlerClass: `BaseHTTPServer.BaseHTTPRequestHandler` compatible class
  :addressFamily: integer representing network protocol (see `socket`)
  '''
  serverClass = BaseHTTPServer.HTTPServer
  handlerClass = HTTPRequestHandler
  addressFamily = socket.AF_INET

  def __init__(self, host='localhost', port=0, timeout=5, sslContext=None):
    '''
    :host: IP/IPv6 address string or FQDN string
    :port: TCP port integer (0 selects an unused port)
    :timeout: integer timeout in seconds to wait for server operations
    :sslContext: `ssl.SSLContext` compatible instance
    '''
    self._requests = []
    self.timeout = timeout
    self.sslContext = sslContext
    self.handlerClass = self.configureHandlerClass(self.handlerClass)
    self.serverClass = (self.configureServerClass(host) if ':' not in str(host)
                        else HTTPServer6.configureServerClass(host))
    server = self.serverClass((host, port), self.handlerClass)
    self.serverAddress = server.server_address
    server.server_close()
    self.server = None
    self.thread = None

  @property
  def address(self):
    ''' Returns server IP/IPv6 address. '''
    return self.serverAddress[0]

  @property
  def port(self):
    ''' Returns server TCP port. '''
    return self.serverAddress[1]

  @property
  def url(self):
    ''' Returns URL string to connect to this server instance. '''
    protocol = 'http' if self.sslContext is None else 'https'
    address = ('[{0}]'.format(self.address) if ':' in self.address
               else self.address)
    return '{0}://{1}:{2}'.format(protocol, address, self.port)

  @classmethod
  def configureServerClass(cls, host):
    ''' Reloads and configures server class. This is necessary, because of
    the use of class attributes.  If more than one address family is used
    concurrently (e.g. IPv4 _and_ IPv6), one will overwrite the other, as
    the default behavior is for a class to be loaded once and only once,
    including attributes. Using `type()` effectively creates a new class
    with _discrete_ attributes. This is a class method, because it is
    called outside of the scope of an initialized class instance.

    :host: hostname string of server
    '''
    sourceClass = cls.serverClass
    serverClass = type(sourceClass.__name__, (sourceClass, object), dict())
    serverClass.address_family = cls.addressFamily
    serverClass.serverName = host
    return serverClass

  def configureHandlerClass(self, sourceClass):
    ''' Reloads and configures handler class. This is necessary because of
    the use of class attributes, which are necessary because the handler
    class is instantiated anew to handle each request by `BaseServer`.
    To keep the handler class unique to each `Spoof` instance, `type()` is
    used to effectively create a discrete handler class and attributes.
    '''
    handlerClass = type(sourceClass.__name__, (sourceClass, object), dict())
    self.responseContentQueue = Queue.Queue()
    self.requestReportQueue = Queue.Queue()
    handlerClass.responseContentQueue = self.responseContentQueue
    handlerClass.requestReportQueue = self.requestReportQueue
    return handlerClass

  def start(self):
    ''' Starts HTTP server thread. '''
    if self.server is not None:
      message = 'server at {0} already started'.format(self.url)
      raise RuntimeError(message)
    else:
      self.server = self.serverClass(self.serverAddress, self.handlerClass)
      self.server.timeout = self.timeout
    if self.sslContext is not None:
      self.server.socket = self.sslContext.wrap_socket(self.server.socket,
                                                       server_side=True)
    self.thread = threading.Thread(target=self.server.serve_forever)
    self.thread.start()

  def stop(self):
    ''' Stops HTTP server and closes socket. '''
    if self.server is None:
      message = 'server at {0} already stopped'.format(self.url)
      raise RuntimeError(message)
    self.server.shutdown()
    self.server.server_close()
    self.thread.join()
    self.server = None

  def __enter__(self):
    ''' Starts HTTP server and returns `Spoof` instance when invoked as a
    context manager (with/as). '''
    self.start()
    return self

  def __exit__(self, exceptionType, exceptionValue, traceback):
    ''' Destroys HTTP server instance when context manager block finishes.
    If context block ends normally, all arguments will be `None`.
    '''
    self.stop()

  def __del__(self):
    ''' Closes HTTP server socket when instance goes out of scope. '''
    if getattr(self, 'server', None) is not None:
      self.stop()

  @property
  def debug(self):
    ''' Returns request handler debug flag. '''
    return self.handlerClass.debug

  @debug.setter
  def debug(self, value):
    ''' Sets request handler debug flag. '''
    self.handlerClass.debug = value

  def reset(self):
    ''' Reset request and response attributes. '''
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
    ''' Returns list of namedtuple request report instances. They're called
    reports, because they're no longer actionable.  The HTTP server sends
    responses unconditionally and reports the request after the fact.

    Namedtuple attributes (from `HTTPRequestHandler.reportRequestEnv`):
    :method: Request method (e.g. GET, POST, HEAD)
    :uri: Raw URI path and query string, if present
    :protocol: Protocol version client used to send request (e.g. HTTP/1.0)
    :serverName: Hostname of server
    :serverPort: TCP/IP port of server
    :headers: `mimetools.Message` instance with all request headers; use
      headers.get(headerName, defaultValue) to get specific header
    :path: Decoded URI path, without query string
    :queryString: Anything in URI after URI_QUERY_SEPARATOR, `None` if missing
    :content: string containing request content if present, `None` if missing
    :contentType: Content-Type header value if present, `None` if missing
    :contentLength: Content-Length header integer value, 0 if missing
    '''
    try:
      while True:
        requestReport = self.requestReportQueue.get_nowait()
        self._requests.append(requestReport)
    except Queue.Empty:
      pass
    return self._requests

  @property
  def maxRequestLength(self):
    ''' Returns maximum request content length. '''
    return self.handlerClass.maxRequestLength

  @maxRequestLength.setter
  def maxRequestLength(self, value):
    ''' Sets maximum request content length. '''
    self.handlerClass.maxRequestLength = int(value)

  @property
  def defaultResponse(self):
    ''' Returns default response used by the request handler class. '''
    return self.handlerClass.defaultResponse

  @defaultResponse.setter
  def defaultResponse(self, response):
    ''' Sets the default response used by the request handler class to
    respond to requests when no responses are queued.  If the default
    response is not set, and no responses are queued, errorResponse is
    sent.  Response format:

    [httpStatus, [(headerName1, value1), (headerName2, value2)], content]

    Example:

    [200, [('Content-Type', 'application/json')], '{"success": true }']
    '''
    self.handlerClass.defaultResponse = response

  def queueResponse(self, response):
    ''' Queues response to be returned once by HTTP server. Multiple
    responses may be queued.  If no responses are queued, the handler
    class defaultResponse will be sent.  If defaultResponse is not set,
    and no responses are queued, errorResponse is sent.

    See `defaultResponse` for response format.
    '''
    self.responseContentQueue.put_nowait(response)



class HTTPServer6(HTTPServer):
  ''' Provides a single-threaded, IPv6-only HTTP server. '''

  addressFamily = socket.AF_INET6



class SSLContext(object):
  ''' Provides methods to create SSL context for use with `HTTPServer`. '''

  @staticmethod
  def fromCertChain(certFile, keyFile=None):
    ''' Returns SSL context from provided certificate chain.

    :certFile: path to X509 certificate
    :keyFile: path to certificate signing key (may be included in certFile)
    '''
    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certFile, keyFile)
    return context

  @classmethod
  def selfSigned(cls, *args, **kwargs):
    ''' Returns SSL context via self-signed certificate chain. '''
    certFile, keyFile = cls.createSelfSignedCert(*args, **kwargs)
    context = cls.fromCertChain(certFile, keyFile)
    os.unlink(certFile)
    os.unlink(keyFile)
    return context

  @staticmethod
  def createSelfSignedCert(commonName='localhost', bits=2048, days=365,
                           openssl='openssl'):
    ''' Creates and returns file paths to self-signed certificate and key
    via OpenSSL command line tool.

    :commonName: string of hostname for X509 certificate
    :bits: RSA key length in bits
    :days: length in days certificate is valid
    :openssl: name/path string of openssl command
    '''
    devNull = open(os.devnull, 'w')
    key = tempfile.mkstemp()
    cert = tempfile.mkstemp()
    call = [openssl, 'req', '-nodes', '-x509', '-newkey', 'rsa:' + str(bits),
            '-keyout', key[1], '-out', cert[1], '-days', str(days), '-subj',
            '/O=TestServer/CN=' + commonName]
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
    return cert[1], key[1]
