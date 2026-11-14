.PHONY: build check test lab-up lab-check lab-smoke fixtures

PYTHON ?= python3

build:
	$(PYTHON) scripts/build.py

check:
	$(PYTHON) scripts/build.py
	$(PYTHON) -m compileall -q apps services infrastructure scripts tests
	$(PYTHON) -m py_compile fixtures/generate.py fixtures/phase-1/generate.py
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) -m scripts.check_repository

test:
	$(PYTHON) -m unittest discover -s tests -v

lab-up:
	$(PYTHON) -m scripts.labctl up

lab-check:
	$(PYTHON) -m scripts.labctl check

lab-smoke:
	$(PYTHON) -m scripts.labctl smoke

fixtures:
	$(PYTHON) fixtures/generate.py
	$(PYTHON) fixtures/phase-1/generate.py
