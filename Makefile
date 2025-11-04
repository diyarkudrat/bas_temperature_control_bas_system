NOX ?= nox
COVERAGE_CMD ?= ./System/bin/python3 -m coverage

.PHONY: test-api-unit test-auth-unit test-logging-unit coverage-baseline

test-api-unit:
	$(NOX) -s tests_unit_api

test-auth-unit:
	$(NOX) -s tests_unit_auth

test-logging-unit:
	$(NOX) -s tests_unit_logging

coverage-baseline:
	COVERAGE_CMD="$(COVERAGE_CMD)" ./scripts/coverage_baseline.sh --suite all

