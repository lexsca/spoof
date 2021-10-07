1.5.2 (2021-10-07)
==================

- Add Python 3.10 to supported list and CI checks
- Use setuptools_scm for release versioning

1.5.1 (2021-04-10)
==================

- Blackify source
- Use GitHub Actions now for publishing releases and performing checks
- Update supported Python versions to: 2.7, 3.5, 3.6, 3.7, 3.8, 3.9
- Update README

1.5.0 (2018-12-10)
==================

- Add `spoof.SelfSignedSSLContext` convenience class
- Update README
- Update docstrings
- Update tests

1.4.0 (2018-11-18)
==================

- Allow queueing multiple responses at once
- Update README
- Update docstrings
- Update tests

1.3.0 (2018-11-16)
==================

- Update Python versions to test via pyenv and tox: 3.7.1, 3.6.7, 3.5.4, 3.4.7, 2.7.15
- Add `contentEncoding` convenience property to request object
- Queued responses and `defaultResponse` can now be callbacks!
- Update tests

1.2.0 (2018-03-05)
==================

- Refactor `spoof.HTTPUpstreamServer` to be a proper server, instead of
  simply wrapping the socket in the request handler.
- Add support for proxying HTTPS requests through an HTTPS server via
  CONNECT method.
- Add supporting tests

1.1.1 (2018-02-28)
==================

- Deconstruct `spoof.HTTPUpstreamServer.handleRequest` to allow more control
- Add `spoof.HTTPUpstreamServer` to handle proxy requests via CONNECT method
- Add `spoof.HTTPRequestHandler.do_CONNECT` to handle proxy requests
- Add `spoof.SSLContext.createOpenSSLConfig` to create self-signed
  certificates with subjectAlternativeName entries, so they can be trusted
  by `requests`, including IP addresses
- Add tests for new functionality
- Remove test code that disables SSL warnings!
- Change from nose to pytest for running tests
- Reformat code to pass Flake8
- Add `.python-version` pyenv file for testing convenience
- Re-run tests on latest versions of Python

1.0.5 (2018-02-19)
==================

- First public stable release
- Multiple Python version testing via `tox`
