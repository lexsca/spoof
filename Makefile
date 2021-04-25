.PHONY: build cleandocs clean docs publish test

build:
	python setup.py sdist bdist_wheel

cleandocs:
	rm -fr src/docs/_build docs/.??* docs/*

clean: cleandocs
	rm -fr src/spoof.egg-info dist build .eggs .tox .pytest_cache \
		coverage.xml .coverage
	find . -type d -name __pycache__ -exec /bin/rm -fr {} +
	find . -depth -type f -name '*.pyc' -exec /bin/rm -fr {} +

docs: cleandocs
	$(MAKE) -C src/docs html
	tar cf - -C src/docs/_build/html . | tar xf - -C docs

publish:
	twine upload dist/*

test:
	tox
