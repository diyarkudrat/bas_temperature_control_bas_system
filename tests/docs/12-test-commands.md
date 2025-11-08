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
test -d .venv || python3 -m venv .venv
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
Test coverage measures how much of your code runs during tests. Higher coverage helps reveal untested paths, reduce regressions, and build confidence when refactoring. Aim for meaningful coverage of critical paths—our immediate goal is ≥90% line coverage across `apps/api`, `apps/auth_service`, `adapters`, and `app_platform`.

```bash
# Baseline coverage run (logs to terminal + HTML if requested)
python -m pytest tests -v --cov --cov-report=term-missing --cov-config=coverage/.coveragerc

# Component-specific focus runs (API/Auth/Adapters/Platform)
python -m pytest tests/unit/api --cov --cov-config=coverage/.coveragerc -m "api or http" -v
python -m pytest tests/unit/auth --cov --cov-config=coverage/.coveragerc -m auth -v
python -m pytest tests/unit/adapters --cov --cov-config=coverage/.coveragerc -m adapters -v
python -m pytest tests/unit/platform --cov --cov-config=coverage/.coveragerc -m platform -v

# Optional HTML report for portfolio snapshots
python -m pytest tests --cov --cov-config=coverage/.coveragerc --cov-report=html

# Re-enable contract plugins when validating interfaces
BAS_DISABLE_PLUGINS=0 BAS_ENABLE_CONTRACT_FIXTURES=1 python -m pytest tests/unit/api -m contract -v

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
# Fast signal on adapters only
python -m pytest tests/unit/adapters --cov --maxfail=1 -q

# Run with branch coverage for a single file
python -m pytest tests/unit/auth/test_services.py \
  --cov --cov-branch --cov-config=coverage/.coveragerc -v

# CI-friendly XML only (for pipelines/tools)
python -m pytest tests -q \
  --cov --cov-config=coverage/.coveragerc --cov-report=xml

# Record a manual note for the coverage log
echo \"$(date '+%Y-%m-%d') | api 91.2 | auth 92.0 | adapters 90.5 | platform 90.1 | notes\" >> docs/metrics/coverage-notes.md
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


