Spoof
=====

On-demand HTTP server for use in test environments where mocking underlying calls isn't an option or where it's necessary to have an actual HTTP server listening on a socket (e.g. testing IPv6 connectivity).  Multiple HTTP servers can be run concurrently, and by default the port number is the next available unused port.

Compatibility
~~~~~~~~~~~~~

Spoof was tested with the following versions of Python (2.6.x and 3.3.x omitted due to SSL compatibility issues):

-  2.7.13
-  3.4.6
-  3.5.3
-  3.6.1

Installation
~~~~~~~~~~~~

Install from source:

::

  python setup.py install

Install from PyPI:

::

  pip install spoof

Example usage
-------------

.. code:: python

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
      self.assertEqual(expectedContent, lastRequest.content)

Squelching SSL warnings
-----------------------

Some libraries like
`Requests <http://docs.python-requests.org/en/master/>`__ will complain
loudly or refuse to connect to HTTP servers with a self-signed SSL
certificate. One way to work around this is to monkeypatch the requests
library in the testing code. For example:

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

