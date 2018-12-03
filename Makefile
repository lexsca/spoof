.PHONY: build docs clean publish test

build:
	python setup.py sdist bdist_wheel

clean:
	rm -fr src/spoof.egg-info dist build .eggs .tox .pytest_cache \
		coverage.xml .coverage
	find . -type d -name __pycache__ -exec /bin/rm -fr {} +
	find . -depth -type f -name '*.pyc' -exec /bin/rm -fr {} +

docs:
	$(MAKE) -C src/docs html
	tar cf - -C src/docs/_build/html . | tar xf - -C docs

publish:
	tox -e cov
	twine upload dist/*

test:
	tox
