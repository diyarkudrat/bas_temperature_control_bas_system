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
# 1. Bootstrap the local environment (once per shell)
python3 -m venv .venv
source .venv/bin/activate
pip install -r apps/api/requirements.txt

# 2. Run the full unit suite with quick feedback
python -m pytest tests/unit -v --maxfail=1

# 3. Focus on a domain (e.g., auth)
python -m pytest tests/unit/auth -v

# 4. Enable contract validation or reporting when needed
python -m pytest tests --contract-validation -v
python -m pytest tests --contract-report -v

# 5. Use NOX sessions (mirrors CI orchestration)
nox -s tests_unit_api
nox -s tests_unit_auth
nox -s tests_unit_logging

# 6. Generate the roadmap-themed coverage baseline
scripts/coverage_baseline.sh --suite all
```

## Documentation Map

- **Testing Framework (02):** architecture, execution modes, and orchestration.
- **Fixtures & Utilities (03–10):** reusable building blocks and patterns.
- **Component Playbooks:** integrated into the framework guide for API, logging,
  and health/observability coverage.
- **Governance & Metrics:** coverage exceptions, baseline workflow, and roadmap
  alignment captured alongside the framework narrative.