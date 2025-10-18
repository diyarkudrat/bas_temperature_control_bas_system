# Running & CI

## Purpose

Explain how to run tests locally and how contract validation integrates into CI. This ensures consistent quality gates across developer machines and the pipeline.

## Benefits

- Consistent execution (venv activated)
- Early detection of contract and business-rule violations
- Reproducible CI behavior locally

## Local Workflow

```bash
# Activate server venv, then run all tests
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ -v

# Focus a domain
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/unit/auth/ -v

# With contract validation
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ --contract-validation -v

# Contract report
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ --contract-report -v
```

## Selecting Tests with Markers

```bash
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ -m contract -v
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ -m "auth and unit" -v
```

## CI Integration

- CI runs the same flows with contract validation enabled
- Thresholds and behavior configured via `pytest.ini`
- Contract violations fail builds, preventing regressions


