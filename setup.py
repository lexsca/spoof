from setuptools import setup

setup(
  name='spoof',
  version='1.5.0',
  description='HTTP server for testing environments',
  long_description=open('README.rst').read(),
  author='Lex Scarisbrick',
  author_email='lex@scarisbrick.org',
  license='MIT',
  classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 2',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
    'Topic :: Internet :: Proxy Servers ',
    'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
    'Topic :: Software Development :: Libraries :: Python Modules',
    'Topic :: Software Development :: Quality Assurance',
    'Topic :: Software Development :: Testing',
    'Topic :: Software Development :: Testing :: Traffic Generation'
  ],
  url='https://github.com/lexsca/spoof.git',
  package_dir={'': 'src'},
  py_modules=['spoof'],
  setup_requires=['pytest-runner', 'sphinx', 'sphinx-readable-theme'],
  tests_require=['pytest', 'pytest-cov', 'pytest-flake8', 'mock', 'requests'],
)
