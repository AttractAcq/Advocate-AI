.PHONY: build check test security-config-scan lab-up lab-check lab-diagnose lab-smoke fixtures recovery-rehearsal

PYTHON ?= .venv/bin/python

build:
	$(PYTHON) scripts/build.py

check:
	$(PYTHON) scripts/build.py
	$(PYTHON) -m compileall -q apps services infrastructure scripts tests
	$(PYTHON) -m py_compile fixtures/generate.py fixtures/phase-1/generate.py
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) -m scripts.check_repository
	$(PYTHON) -m scripts.security_config_scan

test:
	$(PYTHON) -m unittest discover -s tests -v

security-config-scan:
	$(PYTHON) -m scripts.security_config_scan

lab-up:
	$(PYTHON) -m scripts.labctl up

lab-check:
	$(PYTHON) -m scripts.labctl check

lab-diagnose:
	$(PYTHON) -m scripts.diagnose --lab

lab-smoke:
	$(PYTHON) -m scripts.labctl smoke

fixtures:
	$(PYTHON) fixtures/generate.py
	$(PYTHON) fixtures/phase-1/generate.py

recovery-rehearsal: fixtures
	$(PYTHON) -m scripts.phase5_recovery_rehearsal
