# Test Commands Cheat Sheet

## Table of Contents

- [Basics](#basics)
- [Markers](#markers)
- [Contract Validation (Optional)](#contract-validation-optional)
- [Coverage](#coverage)
- [Useful Tips](#useful-tips)

## Basics

```bash
# Activate the project virtual environment (once per shell)
python3 -m venv .venv  # skip if already created
source .venv/bin/activate

# Run the full unit suite with fast failure feedback
python -m pytest tests/unit -v --maxfail=1

# Run a specific file or individual test
python -m pytest tests/unit/auth/test_services.py -v
python -m pytest tests/unit/auth/test_services.py::TestAuthServices::test_login_success -v

# Use NOX sessions (mirrors CI isolation)
nox -s tests_unit_api
nox -s tests_unit_auth
nox -s tests_unit_logging
```

## Markers

```bash
# Domain and type filtering
python -m pytest tests -m unit -v
python -m pytest tests -m auth -v
python -m pytest tests -m "auth and unit" -v
```

## Contract Validation (Optional)

```bash
# Enable runtime checks and generate report
python -m pytest tests --contract-validation -v
python -m pytest tests --contract-report -v

# Skip validation for perf-critical tests
python -m pytest tests -m "not no_contract_validation" -v
```

## Coverage
Test coverage measures how much of your code runs during tests. Higher coverage helps reveal untested paths, reduce regressions, and build confidence when refactoring. Aim for meaningful coverage of critical paths rather than 100% everywhere.

```bash
# Default component coverage (mirrors pytest.ini + `.coveragerc`)
python -m pytest tests -v --cov --cov-report=term-missing --cov-config=coverage/.coveragerc

# Component-specific focus runs
python -m pytest tests/unit/api --cov --cov-config=coverage/.coveragerc -m "api or http" -v
python -m pytest tests/unit/auth --cov --cov-config=coverage/.coveragerc -m auth -v
python -m pytest tests/unit/logging --cov --cov-config=coverage/.coveragerc -m logging -v

# Run the roadmap-themed baseline (HTML + JSON outputs)
scripts/coverage_baseline.sh --suite all

# Make/Nox wrappers (Phase R2 orchestration)
make test-api-unit          # delegates to nox -s tests_unit_api
make test-auth-unit         # delegates to nox -s tests_unit_auth
make test-logging-unit      # delegates to nox -s tests_unit_logging

# CI-equivalent run (enforces fail-under)
COVERAGE_FAIL_UNDER=90 nox -s "tests(unit_api)"
COVERAGE_FAIL_UNDER=90 nox -s "tests(unit_auth)"
COVERAGE_FAIL_UNDER=90 nox -s "tests(unit_logging)"

# Update coverage exceptions register after a local run
python scripts/coverage/update_exceptions.py \
  --suite api \
  --coverage-json coverage/json/api.json \
  --owner "Your Name" --mitigation "Increase tests" --dry-run

# Compare against the committed baseline before pushing
python scripts/coverage/regression_guard.py \
  --current coverage/json/api.json \
  --previous coverage/baselines/api.json

# Re-enable legacy plugins (contract validation) when required
BAS_DISABLE_PLUGINS=0 BAS_ENABLE_CONTRACT_FIXTURES=1 make test-api-unit

# Open HTML report (macOS)
open coverage/html/index.html
```

Each `scripts/coverage_baseline.sh` run executes the suite three times with
`architecture`, `reliability`, and `security` contexts and writes combined
artifacts to `coverage/html/`, `coverage/json/`, and `coverage/xml/`. Compare the
JSON outputs with the committed baselines before pushing, and record any carved-out
modules in `tests/docs/test_framework_upgrades/coverage_exceptions.md`.

### Quick bash examples

```bash
# Fast signal on logging library only
python -m pytest tests/unit/logging --cov --maxfail=1 -q

# Run with branch coverage for a single file
python -m pytest tests/unit/auth/test_services.py \
  --cov --cov-branch --cov-config=coverage/.coveragerc -v

# CI-friendly XML only (for pipelines/tools)
python -m pytest tests -q \
  --cov --cov-config=coverage/.coveragerc --cov-report=xml

# Generate the weekly coverage digest locally
python scripts/coverage/generate_digest.py coverage/json/api.json \
  coverage/json/auth.json coverage/json/logging.json --output docs/metrics/coverage-weekly.md
```

## Useful Tips

```bash
# Filter by substring
python -m pytest -k "auth and login" -v

# Stop on first failure
python -m pytest -x -v

# Show print/log output
python -m pytest -s -vv
```


