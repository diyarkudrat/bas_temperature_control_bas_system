# Running Unit Tests & Coverage (Local)

## Purpose

How to run unit tests locally and measure coverage. CI integration is deferred; this focuses on developer workflows.

## Run Unit Tests

```bash
# Activate server venv once per shell
cd server && source venv/bin/activate && cd ..

# Run full unit suite (verbose)
python3 -m pytest tests/unit -v

# Run a specific test file or test
python3 -m pytest tests/unit/auth/test_services.py -v
python3 -m pytest tests/unit/auth/test_services.py::TestAuthServices::test_login_success -v

# Use markers
python3 -m pytest tests -m unit -v
python3 -m pytest tests -m "auth and unit" -v
```

## Run With Contract Validation (Optional)

```bash
python3 -m pytest tests --contract-validation -v
python3 -m pytest tests --contract-report -v
```

## Coverage

```bash
# Generate terminal summary + XML (coverage.xml) and HTML (htmlcov/)
python3 -m pytest tests \
  --cov=server \
  --cov=src \
  --cov-report=term-missing \
  --cov-report=xml \
  --cov-report=html \
  -v

# Open HTML report
open htmlcov/index.html  # macOS
```

## Tips

- Keep venv active to avoid re-activating for each run
- Narrow scope (file/test/marker) to iterate faster
- Use `-k <expr>` to filter by substring

## Future Enhancements

- GitHub Actions workflow for unit + coverage
- Publish coverage artifact and badge
- Enforce thresholds in CI

