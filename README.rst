########
Spoof 👻
########
.. image:: https://github.com/lexsca/spoof/actions/workflows/checks.yml/badge.svg
    :target: https://github.com/lexsca/spoof/actions/workflows/checks.yml
.. image:: https://img.shields.io/pypi/v/spoof.svg
    :target: https://pypi.org/project/spoof/
.. image:: https://img.shields.io/pypi/pyversions/spoof.svg
    :target: https://pypi.org/project/spoof/
.. image:: https://img.shields.io/github/license/lexsca/spoof.svg
    :target: https://github.com/lexsca/spoof/blob/master/LICENSE
.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black

|

**Spoof** is a simple HTTP server for test environments.

.. code-block:: python

   >>> import requests
   ... import spoof
   ...
   ... with spoof.HTTPServer() as httpd:
   ...     httpd.queueResponse([200, [], "This is Spoof 👻👋"])
   ...     requests.get(httpd.url).text
   ...     httpd.requests
   ...
   'This is Spoof 👻👋'
   [SpoofRequestEnv(method='GET', uri='/', protocol='HTTP/1.1', serverName='localhost', serverPort=62775, headers=<http.client.HTTPMessage object at 0x10d8a8f50>, path='/', queryString=None, content=None, contentType=None, contentEncoding=None, contentLength=0)]

Test interface for HTTP
=======================
Spoof lets you easily create HTTP servers listening on real network
sockets. Designed for test environments, what responses to return can be
configured while an HTTP server is running, and requests can be inspected
live or after a response is sent.

Unlike a traditional HTTP server, where specific methods and paths are
configured in advance, Spoof accepts and captures *all* requests, sending
whatever responses are queued, or a default response if the queue is empty.

Why would I want this?
======================
Spoof is all about enabling test-driven development (and refactoring) of
HTTP client code. Have you ever felt icky patching a client library to
write tests? Ever been burned by this? Ever wanted to refactor a client
library, but had no way to prove functionality apart from doing live
integration testing? If you answered yes to any of the above, Spoof is
for you.

Compatibility
=============
Spoof is tested on Python 3.10 to 3.14, leverages the ``http.server`` module
included in the standard library, and has no external dependencies. It may
work on older versions of Python, but this is not supported.

Multiple Spoof HTTP servers can be run concurrently, and by default, the port
number is the next available unused port.  With OpenSSL installed, Spoof can
also provide an SSL/TLS HTTP server.  IPv6 is fully supported.

Spoof HTTP servers run in a single background thread, so request and response
order should be predictable. Tests should be able to use the same fixtures,
in the same order, and get the same results.

``SpoofRequestEnv`` instances
=============================
Spoof captures each request as a ``namedtuple`` with the following properties:

+-------------------------+----------------------------------------------+
| Property                | Description                                  |
+=========================+==============================================+
| content                 | ``bytes`` object of request content          |
+-------------------------+----------------------------------------------+
| contentEncoding         | Value of Content-Encoding header, if present |
+-------------------------+----------------------------------------------+
| contentLength           | Value of Content-Length header, if present   |
+-------------------------+----------------------------------------------+
| contentType             | Value of Content-Type header, if present     |
+-------------------------+----------------------------------------------+
| headers                 | ``http.client.HTTPMessage`` object of headers|
+-------------------------+----------------------------------------------+
| method                  | Request method (e.g. GET, POST, HEAD)        |
+-------------------------+----------------------------------------------+
| path                    | Decoded URI path, without query string       |
+-------------------------+----------------------------------------------+
| protocol                | Protocol version (e.g. HTTP/1.0)             |
+-------------------------+----------------------------------------------+
| queryString             | Anything in URI after ``?``                  |
+-------------------------+----------------------------------------------+
| serverName              | Host name of HTTP server                     |
+-------------------------+----------------------------------------------+
| serverPort              | Port number of HTTP server                   |
+-------------------------+----------------------------------------------+
| uri                     | Raw URI path and query string, if present    |
+-------------------------+----------------------------------------------+

Queued responses
================
Queue multiple responses, verify content, and request paths:

.. code-block:: python

   import requests
   import spoof

   with spoof.HTTPServer() as httpd:
       responses = [
           [200, [("Content-Type", "application/json")], '{"id": 1111}'],
           [200, [("Content-Type", "application/json")], '{"id": 2222}'],
       ]
       httpd.queueResponse(*responses)
       httpd.defaultResponse = [404, [], "Not found"]

       assert requests.get(httpd.url + "/path").json() == {"id": 1111}
       assert requests.get(httpd.url + "/alt/path").json() == {"id": 2222}
       assert requests.get(httpd.url + "/oops").status_code == 404
       assert [r.path for r in httpd.requests] == ["/path", "/alt/path", "/oops"]

Callback response
=================
Set a callback as the default response (callbacks can also be queued):

.. code-block:: python

   import requests
   import spoof

   with spoof.HTTPServer() as httpd:
       httpd.defaultResponse = lambda request: [200, [], request.path]

       assert requests.get(httpd.url + "/alt").content == b"/alt"

SSL/TLS Mode
============
Test queued response with a self-signed SSL/TLS certificate:

.. code-block:: python

   import requests
   import spoof

   with spoof.SelfSignedSSLContext() as selfSigned:
       with spoof.HTTPServer(sslContext=selfSigned.sslContext) as httpd:
           httpd.queueResponse([200, [], "No self-signed cert warning!"])
           response = requests.get(httpd.url + "/path",
                                   verify=selfSigned.certFile)

           assert httpd.requests[-1].method == "GET"
           assert httpd.requests[-1].path == "/path"
           assert response.content == b"No self-signed cert warning!"

Proxy Mode
==========
Spoof also supports proxying HTTP requests by setting the ``upstream`` attribute
to another Spoof instance:

.. code-block:: python

   import requests
   import spoof

   with spoof.SelfSignedSSLContext(commonName="example.spoof") as ssl:
       with spoof.HTTPServer(sslContext=ssl.sslContext) as proxy:
           with spoof.HTTPServer(sslContext=ssl.sslContext) as upstream:
               proxy.upstream = upstream
               proxy.defaultResponse = [200, [("X-Spoof-Proxy", "True")], ""]
               upstream.defaultResponse = [200, [], "I'm here!"]
               response = requests.get(
                   "https://example.spoof/ayt",
                   proxies={"https": proxy.url},
                   verify=ssl.certFile
               )
               assert proxy.requests[0].method == "CONNECT"
               assert proxy.requests[0].path == "example.spoof:443"
               assert upstream.requests[0].method == "GET"
               assert upstream.requests[0].path == "/ayt"
               assert response.content == b"I'm here!"

Using IPv6
==========
Setting the ``host`` attribute to an IPv6 address will work as expected. There
is also an IPv6-only ``spoof.HTTPServer6`` class that can be used if needed.

.. code-block:: python

   >>> import requests
   ... import spoof
   ...
   ... with spoof.HTTPServer(host="::1") as httpd:
   ...     httpd.queueResponse([200, [], "This is Spoof on IPv6 👀"])
   ...     requests.get(httpd.url).text
   ...     httpd.url
   ...
   'This is Spoof on IPv6 👀'
   'http://[::1]:51324'

