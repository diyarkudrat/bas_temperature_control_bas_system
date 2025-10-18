# Overview

## Goals

- Reliability-first tests that catch regressions early
- Clear organization mirroring application domains (auth, firestore, services)
- Contract-based validation of behaviors and data models
- Centralized business rules to keep behaviors consistent and avoid duplication

## Components

- Configuration: `pytest.ini` defines test markers (labels like `auth`, `contract`) and default options (verbosity, thresholds)
- Global setup: `tests/conftest.py` for paths, fixtures, and hooks
- Fixtures: `tests/fixtures/` shared builders and resources
- Utilities: `tests/utils/` assertions, business rules
- Plugins: `tests/plugins/` runtime helpers and validators
- Contracts: `tests/contracts/` protocols, validators, optimized mocks

## Quick Start

```bash
# Activate server venv, then run full suite
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ -v

# Focus a domain
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/unit/auth/ -v

# Enable contract validation globally
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ --contract-validation -v

# Generate contract compliance report
cd server && source venv/bin/activate && cd .. && python3 -m pytest tests/ --contract-report -v
```