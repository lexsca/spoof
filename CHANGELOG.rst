
1.1.0 (2018-02-XX)
==================

- Add `spoof.SSLContext.createOpenSSLConfig` to create self-signed
  certificates with subjectAlternativeName entries, so they can be trusted
  by `requests`, including IP addresses
- Remove test code that disables SSL warnings
- Reformat code to pass Flake8
- Add `.python-version` pyenv file for testing convenience
- Re-run tests on latest versions of Python


1.0.5 (2018-02-19)
==================

- First public stable release
- Multiple Python version testing via `tox`
