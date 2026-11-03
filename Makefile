.PHONY: test compile check build install clean

test:
	python3 -m unittest discover -v

compile:
	python3 -m compileall -q vpskitlib tests

check:
	./scripts/check-secrets.sh
	bash -n install.sh
	bash -n scripts/check-secrets.sh
	bash -n vpskitlib/remote_scripts/firewall-guard.sh

build:
	python3 -m build

install:
	python3 -m pip install --user .

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
