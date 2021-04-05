#####
Spoof
#####


.. image:: https://github.com/lexsca/spoof/actions/workflows/checks.yml/badge.svg
    :target: https://github.com/lexsca/spoof/actions/workflows/checks.yml

.. image:: https://img.shields.io/pypi/v/spoof.svg
    :target: https://pypi.org/project/spoof/

.. image:: https://img.shields.io/pypi/wheel/spoof.svg
    :target: https://pypi.org/project/spoof/

.. image:: https://img.shields.io/pypi/pyversions/spoof.svg
    :target: https://pypi.org/project/spoof/

.. image:: https://img.shields.io/github/license/lexsca/spoof.svg
    :target: https://github.com/lexsca/spoof/blob/master/LICENSE

.. image:: https://codecov.io/gh/lexsca/spoof/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/lexsca/spoof

Spoof is an HTTP server written in Python for use in test environments where
mocking underlying calls isn't an option, or where it's desirable to have an
actual HTTP server listening on a socket. Hello, functional tests!

Unlike a typical HTTP server, where specific method and path combinations are
configured in advance, Spoof accepts *all* requests and sends either a queued
response, a default response if the queue is empty, or an error response if no
default response is configured. Requests can be inspected after a response is sent.

Compatibility
=============

Spoof runs on Python 2.7, 3.4 to 3.8, and has no external dependencies.

Multiple Spoof HTTP servers can be run concurrently, and by default, the port
number is the next available unused port.  With OpenSSL installed, Spoof can
also provide an SSL/TLS HTTP server.  IPv6 is fully supported.

Quickstart
==========

Queue multiple responses, verify content, and request paths:

.. code-block:: python

   import requests
   import spoof

   with spoof.HTTPServer() as httpd:
       responses = [
           [200, [('Content-Type', 'application/json')], '{"id": 1111}'],
           [200, [('Content-Type', 'application/json')], '{"id": 2222}'],
       ]
       httpd.queueResponse(*responses)
       httpd.defaultResponse = [404, [], 'Not found']

       assert requests.get(httpd.url + '/path').json() == {'id': 1111}
       assert requests.get(httpd.url + '/alt/path').json() == {'id': 2222}
       assert requests.get(httpd.url + '/oops').status_code == 404
       assert [r.path for r in httpd.requests] == ['/path', '/alt/path', '/oops']

Set a callback as the default response:

.. code-block:: python

   import requests
   import spoof

   with spoof.HTTPServer() as httpd:
       httpd.defaultResponse = lambda request: [200, [], request.path]

       assert requests.get(httpd.url + '/alt').content == b'/alt'

Test queued response with SSL:

.. code-block:: python

   import requests
   import spoof

   with spoof.SelfSignedSSLContext() as selfSigned:
       with spoof.HTTPServer(sslContext=selfSigned.sslContext) as httpd:
           httpd.queueResponse([200, [], 'No self-signed cert warning!'])
           response = requests.get(httpd.url + '/path',
                                   verify=selfSigned.certFile)

           assert httpd.requests[-1].method == 'GET'
           assert httpd.requests[-1].path == '/path'
           assert response.content == b'No self-signed cert warning!'


SSL Warnings
============

Some libraries like
`Requests <http://docs.python-requests.org/en/master/>`__ will complain
loudly or refuse to connect to HTTP servers with a self-signed SSL
certificate. The preferred way to handle this is to use the `verify`
property in `requests.Session` to trust the certificate:

.. code:: python

    import requests
    import spoof

    cert, key = spoof.SSLContext.createSelfSignedCert()
    sslContext = spoof.SSLContext.fromCertChain(cert, key)
    httpd = spoof.HTTPServer(sslContext=sslContext)
    httpd.queueResponse([200, [], 'OK'])
    httpd.start()

    # trust self-signed certificate
    session = requests.Session()
    session.verify = cert

    response = session.get(httpd.url + '/uri/path')
    print(response.status_code, response.content)
    httpd.stop()

If verifying the certificate is not an option, another way to work around
this is to monkeypatch the requests library in the testing code. For example:

.. code:: python

    import requests

    certVerify = requests.adapters.HTTPAdapter.cert_verify
    def certNoVerify(self, conn, url, verify, cert):
        return certVerify(self, conn, url, False, cert)
    requests.adapters.HTTPAdapter.cert_verify = certNoVerify
    requests.packages.urllib3.disable_warnings()

Another common case is libraries that leverage ``ssl`` directly. One way
to work around this is to globally set the default context to
unverified. For example:

.. code:: python

    import ssl

    try:
        createUnverifiedHttpsContext = ssl._create_unverified_context
    except AttributeError:
        # ignore if ssl context not verified by default
        pass
    else:
        ssl._create_default_https_context = createUnverifiedHttpsContext


