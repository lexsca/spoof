.PHONY: all build clean dev-setup test

all: clean dev-setup test build

build:
	python -m build --wheel --sdist --outdir dist
	twine check --strict dist/*
	unzip -t dist/*.whl
	tar tvfz dist/*.tar.gz

clean:
	rm -fr dist build .pytest_cache .coverage */*.egg-info
	find . -type d -name __pycache__ -exec /bin/rm -fr {} +

dev-setup:
	pip install --upgrade --requirement requirements-dev.txt

test:
	black .
	flake8
	PYTHONPATH=src pytest --cov=spoof --cov-report=term-missing tests
