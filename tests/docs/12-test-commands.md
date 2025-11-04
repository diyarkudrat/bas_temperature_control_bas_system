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
# Default component coverage (mirrors pytest.ini)
python3 -m pytest tests -v \
  --cov=apps/api \
  --cov=apps/auth_service \
  --cov=logging_lib \
  --cov-report=term-missing \
  --cov-config=coverage/.coveragerc

# Component-specific focus runs
python3 -m pytest tests/unit/api --cov=apps/api --cov-config=coverage/.coveragerc -v
python3 -m pytest tests/unit/auth --cov=apps/auth_service --cov-config=coverage/.coveragerc -v
python3 -m pytest tests/unit/logging --cov=logging_lib --cov-config=coverage/.coveragerc -v

# Generate XML/HTML artifacts
python3 -m pytest tests -v \
  --cov=apps/api --cov=apps/auth_service --cov=logging_lib \
  --cov-config=coverage/.coveragerc \
  --cov-report=term-missing --cov-report=xml --cov-report=html

# Open HTML report (macOS)
open htmlcov/index.html
```

### Quick bash examples

```bash
# Fast signal on logging library only
python3 -m pytest tests/unit/logging --cov=logging_lib --maxfail=1 -q

# Run with branch coverage for a single file
python3 -m pytest tests/unit/auth/test_services.py \
  --cov=apps/auth_service --cov-branch --cov-config=coverage/.coveragerc -v

# CI-friendly XML only (for pipelines/tools)
python3 -m pytest tests -q \
  --cov=apps/api --cov=apps/auth_service --cov=logging_lib \
  --cov-config=coverage/.coveragerc --cov-report=xml

# (Planned) nox session once added to repo
# nox -s tests(unit_api)
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


