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
   ...     httpd.responses.append([200, [], "This is Spoof 👻👋"])
   ...     requests.get(httpd.url).text
   ...
   'This is Spoof 👻👋'

A test interface for HTTP
=========================
Spoof lets you easily create HTTP servers listening on real network
sockets. Designed for test environments, what responses to return can be
configured while an HTTP server is running. Requests can be inspected
live or after a response is sent.

Unlike a conventional HTTP server, where specific methods and paths are
configured in advance, Spoof accepts and records *all* requests, sending
whatever responses are queued, or a default response if the queue is empty.

Why would I want this?
======================
Spoof is all about enabling test-driven development (and refactoring) of
HTTP client code. Have you ever felt icky patching a client library to
write tests? Ever been burned by this? Ever wanted to refactor a client
library, but had no way to check correctness apart from doing live
integration testing? Ever wanted mock for HTTP? If you answered yes to
any of the above, Spoof might be for you.

Installation and Compatibility
==============================

Spoof is available on PyPI:

.. code-block:: console

   $ python -m pip install spoof

Spoof is tested on Python 3.10 to 3.14, leverages the ``http.server`` module
included in the Python standard library, and has no external dependencies.
It may work on older versions of Python, but this is not supported.

Multiple Spoof HTTP servers can be run concurrently, and by default, the port
number is the next available unused port. With OpenSSL installed, Spoof can
also provide an SSL/TLS HTTP server. HTTP proxying and IPv6 are also supported.

Response syntax
===============

Spoof expects responses to have the following syntax:

.. code-block:: python

   [httpStatus, [(headerName1, value1), (headerName2, value2)], content]

   # no content (Content-Length header is *not* sent if content is None)
   [200, [], None]

   # utf-8 content
   [200, [], "This is Spoof 👻👋"]

   # bytes content
   [200, [("Content-Type", "application/json")], b'{"success": true }']

   # responses can also be a callback
   def callback(request):
       return [200, [], request.path]

Response precedence
===================

Spoof determines what response to send to incoming requests based on
the following precedence, highest to lowest:

#. Oldest response queued in ``.responses`` using first-in, first-out (FIFO) order
#. Response stored in ``.defaultResponse`` if no responses are queued
#. Response stored in ``.errorResponse`` if ``.defaultResponse`` is ``None``

By default, Spoof will respond with an **HTTP 503 Service Unavailable** error,
because newly created Spoof instances have no responses queued and no default
response set. This requires non-error HTTP responses to be explicitly specified.

Response queue
==============

Spoof will always try to send a response from ``.responses`` first, before falling
back to ``.defaultResponse`` if the queue is empty. Backed by a
`deque <https://docs.python.org/3/library/collections.html#collections.deque>`__
instance, the ``.responses`` queue supports adding items via ``.responses.append()``
and ``.responses.extend()``, similar to a regular list.

Spoof HTTP servers run in a single background thread, so response order should
be predictably serial. Tests using Spoof should be able to use the same fixtures,
in the same order, and get the same results. Example queueing multiple responses,
verifying content, and request paths:

.. code-block:: python

   import requests
   import spoof

   with spoof.HTTPServer() as httpd:
       httpd.responses.extend([
           [200, [("Content-Type", "application/json")], b'{"id": 1111}'],
           [200, [("Content-Type", "application/json")], b'{"id": 2222}'],
       ])
       httpd.defaultResponse = [404, [], "Not found"]

       assert requests.get(httpd.url + "/path").json() == {"id": 1111}
       assert requests.get(httpd.url + "/alt/path").json() == {"id": 2222}
       assert requests.get(httpd.url + "/oops").status_code == 404
       assert [r.path for r in httpd.requests] == ["/path", "/alt/path", "/oops"]

Response default
================

Spoof will always try to send a response from ``.responses`` first, before falling
back to ``.defaultResponse`` if the queue is empty. Here's an example of setting a
callback as a default response:

.. code-block:: python

   import requests
   import spoof

   with spoof.HTTPServer() as httpd:
       httpd.defaultResponse = lambda request: [200, [], request.path]

       assert requests.get(httpd.url + "/alt").text == "/alt"

Request history
===============

Spoof records each request and appends it to the ``.requests`` property,
which is backed by a
`deque <https://docs.python.org/3/library/collections.html#collections.deque>`__
instance, the same as the ``.responses`` property. Think of it like a pre-parsed access log. Example
using request history:

.. code-block:: python

   >>> import requests
   ... import spoof
   ...
   ... with spoof.HTTPServer() as httpd:
   ...     httpd.defaultResponse = [200, [], None]
   ...
   ...     [requests.get(httpd.url + path) for path in ["/a", "/b", "/c"]]
   ...     [f"{r.method} {r.path} {r.protocol}" for r in httpd.requests]
   ...
   [<Response [200]>, <Response [200]>, <Response [200]>]
   ['GET /a HTTP/1.1', 'GET /b HTTP/1.1', 'GET /c HTTP/1.1']

Request properties
==================

``SpoofRequestEnv`` instances have the following properties:

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
| json()                  | Convenience to call ``json.loads`` on content|
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

SSL/TLS Mode
============
Test queued response with a self-signed SSL/TLS certificate:

.. code-block:: python

   import requests
   import spoof

   with spoof.SelfSignedSSLContext() as selfSigned:
       with spoof.HTTPServer(sslContext=selfSigned.sslContext) as httpd:
           httpd.responses.append([200, [], "No self-signed cert warning!"])

           response = requests.get(httpd.url, verify=selfSigned.certFile)
           assert response.text == "No self-signed cert warning!"

If setting the ``verify`` option in ``requests`` isn't workable, the
``REQUESTS_CA_BUNDLE`` or ``CURL_CA_BUNDLE`` environment variables can be
set to the path of the self-signed certificate to silence SSL/TLS errors:

.. code-block:: python

   import os
   import requests
   import spoof

   with spoof.SelfSignedSSLContext() as selfSigned:
       with spoof.HTTPServer(sslContext=selfSigned.sslContext) as httpd:
           httpd.responses.append([200, [], "No self-signed cert warning!"])

           os.environ["REQUESTS_CA_BUNDLE"] = selfSigned.certFile
           response = requests.get(httpd.url)
           assert response.text == "No self-signed cert warning!"

If OpenSSL 3.5.0 or later is installed, Post-Quantum Cryptography (PQC)
key algorithms can be used:

.. code-block:: python

   import requests
   import spoof

   with spoof.SelfSignedSSLContext(keyAlgorithm="mldsa65") as selfSigned:
       with spoof.HTTPServer(sslContext=selfSigned.sslContext) as httpd:
           httpd.responses.append([200, [], "TLS with PQC Key Algorithm"])

           response = requests.get(httpd.url, verify=selfSigned.certFile)
           assert response.text == "TLS with PQC Key Algorithm"

Proxy Mode
==========
Spoof supports proxying by port-forwarding ``CONNECT`` requests to a
separate upstream Spoof instance when the ``proxy=True`` argument is
given. Unlike a real proxy server, Spoof won't try to connect to
external services. Example usage:

.. code-block:: python

   import requests
   import spoof

   with spoof.SelfSignedSSLContext(commonName="example.spoof") as selfSigned:
       with spoof.HTTPServer(sslContext=selfSigned.sslContext, proxy=True) as proxy:
           proxy.upstream.defaultResponse = [200, [], "I'm here!"]

           response = requests.get(
               "https://example.spoof/ayt",
               proxies={"https": proxy.url},
               verify=selfSigned.certFile
           )
           assert proxy.requests[0].method == "CONNECT"
           assert proxy.requests[0].path == "example.spoof:443"
           assert proxy.upstream.requests[0].method == "GET"
           assert proxy.upstream.requests[0].path == "/ayt"
           assert response.text == "I'm here!"

If setting the ``proxies`` option in ``requests`` isn't workable, the
``https_proxy`` environment variable can be set to the URL of the proxy:

.. code-block:: python

   import os
   import requests
   import spoof

   with spoof.SelfSignedSSLContext(commonName="example.spoof") as selfSigned:
       with spoof.HTTPServer(sslContext=selfSigned.sslContext, proxy=True) as proxy:
           proxy.upstream.defaultResponse = [200, [], "I'm here!"]

           os.environ["https_proxy"] = proxy.url
           os.environ["REQUESTS_CA_BUNDLE"] = selfSigned.certFile

           response = requests.get("https://example.spoof/ayt")
           assert proxy.requests[0].method == "CONNECT"
           assert proxy.requests[0].path == "example.spoof:443"
           assert proxy.upstream.requests[0].method == "GET"
           assert proxy.upstream.requests[0].path == "/ayt"
           assert response.text == "I'm here!"

IPv6 Mode
=========
Setting the ``host`` attribute to an IPv6 address will work as expected. There
is also an IPv6-only ``spoof.HTTPServer6`` class that can be used if needed to
only listen on IPv6 sockets.

.. code-block:: python

   >>> import requests
   ... import spoof
   ...
   ... with spoof.HTTPServer(host="::1") as httpd:
   ...     httpd.responses.append([200, [], "This is Spoof on IPv6 👀"])
   ...     requests.get(httpd.url).text
   ...     httpd.url
   ...
   'This is Spoof on IPv6 👀'
   'http://[::1]:51324'

.. code-block:: python

   >>> import requests
   ... import spoof
   ...
   ... with spoof.HTTPServer6(host="localhost") as httpd:
   ...     httpd.responses.append([200, [], "This is also Spoof on IPv6 👀"])
   ...     requests.get(httpd.url).text
   ...     httpd.url
   ...
   'This is also Spoof on IPv6 👀'
   'http://[::1]:54296'

Debug mode
==========
Setting a callback with a ``breakpoint()`` can allow for live HTTP request
debugging, including setting custom responses and inspecting requests. Note
that callbacks can also be queued.

.. code-block:: python

   >>> import requests
   ... import spoof
   ...
   ... def debugCallback(request):
   ...     response = [200, [], ""]
   ...     breakpoint()
   ...     return response
   ...
   ... with spoof.HTTPServer() as httpd:
   ...     httpd.defaultResponse = debugCallback
   ...     requests.get(httpd.url).text
   ...
   > <python-input-0>(6)debugCallback()
   (Pdb) request
   SpoofRequestEnv(content=None, contentEncoding=None, contentLength=0, contentType=None, headers=<http.client.HTTPMessage object at 0x10e16bd90>, method='GET', path='/', protocol='HTTP/1.1', queryString=None, serverName='localhost', serverPort=51612, uri='/')
   (Pdb) response[2] = "content set from pdb"
   (Pdb) c
   'content set from pdb'

