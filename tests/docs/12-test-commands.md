# Test Commands Cheat Sheet

## Table of Contents

- [Basics](#basics)
- [Markers](#markers)
- [Contract Validation (Optional)](#contract-validation-optional)
- [Coverage](#coverage)
- [Useful Tips](#useful-tips)

## Basics

```bash
# Activate server venv once per shell
cd server && source venv/bin/activate && cd ..

# Run full unit suite (verbose)
python3 -m pytest tests/unit -v

# Run a specific file or test
python3 -m pytest tests/unit/auth/test_services.py -v
python3 -m pytest tests/unit/auth/test_services.py::TestAuthServices::test_login_success -v
```

## Markers

```bash
# Domain and type filtering
python3 -m pytest tests -m unit -v
python3 -m pytest tests -m auth -v
python3 -m pytest tests -m "auth and unit" -v
```

## Contract Validation (Optional)

```bash
# Enable runtime checks and generate report
python3 -m pytest tests --contract-validation -v
python3 -m pytest tests --contract-report -v

# Skip validation for perf-critical tests
python3 -m pytest tests -m "not no_contract_validation" -v
```

## Coverage
Test coverage measures how much of your code runs during tests. Higher coverage helps reveal untested paths, reduce regressions, and build confidence when refactoring. Aim for meaningful coverage of critical paths rather than 100% everywhere.

```bash
# Default component coverage (mirrors pytest.ini + `.coveragerc`)
python3 -m pytest tests -v --cov --cov-report=term-missing --cov-config=.coveragerc

# Component-specific focus runs
python3 -m pytest tests/unit/api --cov --cov-config=.coveragerc -m "api or http" -v
python3 -m pytest tests/unit/auth --cov --cov-config=.coveragerc -m auth -v
python3 -m pytest tests/unit/logging --cov --cov-config=.coveragerc -m logging -v

# Run the roadmap-themed baseline (HTML + JSON outputs)
scripts/coverage_baseline.sh --suite all

# Make/Nox wrappers (Phase R2 orchestration)
make test-api-unit          # delegates to nox -s tests_unit_api
make test-auth-unit         # delegates to nox -s tests_unit_auth
make test-logging-unit      # delegates to nox -s tests_unit_logging

# CI-equivalent run (enforces fail-under)
COVERAGE_FAIL_UNDER=90 nox -s "tests(unit_api)"

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

### Quick bash examples

```bash
# Fast signal on logging library only
python3 -m pytest tests/unit/logging --cov --maxfail=1 -q

# Run with branch coverage for a single file
python3 -m pytest tests/unit/auth/test_services.py \
  --cov --cov-branch --cov-config=.coveragerc -v

# CI-friendly XML only (for pipelines/tools)
python3 -m pytest tests -q \
  --cov --cov-config=.coveragerc --cov-report=xml

# (Planned) nox session once added to repo
# nox -s tests(unit_api)

# Generate the weekly coverage digest locally
python scripts/coverage/generate_digest.py coverage/json/api.json \
  coverage/json/auth.json coverage/json/logging.json --output docs/metrics/coverage-weekly.md
```

## Useful Tips

```bash
# Filter by substring
python3 -m pytest -k "auth and login" -v

# Stop on first failure
python3 -m pytest -x -v

# Show print/log output
python3 -m pytest -s -vv
```


