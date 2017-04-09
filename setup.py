from setuptools import setup
import os
import sys
import unittest

def discoverTests():
  filePatterns = ['*_unit_tests.py', '*_functional_tests.py']
  setupFile = sys.modules['__main__'].__file__
  setupDir = os.path.abspath(os.path.dirname(setupFile))
  testsDir = os.path.join(setupDir, 'tests')
  testSuite = unittest.TestSuite(tests=())
  for pattern in filePatterns:
    tests = unittest.defaultTestLoader.discover(testsDir, pattern)
    testSuite.addTests(tests)
  return testSuite

setup(
  name='spoof',
  version='1.0.3',
  description='HTTP server for testing environments',
  author='Lex Scarisbrick',
  author_email='lex@scarisbrick.org',
  url='https://github.com/lexsca/spoof.git',
  py_modules=['spoof'],
  tests_require=['mock', 'requests'],
  test_suite='__main__.discoverTests',
)
