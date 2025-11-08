# Overview

## Goals

- Reliability-first tests that catch regressions early
- Consistent ≥90% line coverage across `apps/api`, `apps/auth_service`, `adapters`, and `app_platform` using contract- and mock-driven suites
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
# 1. Activate the project virtual environment (once per shell)
test -d .venv || python3 -m venv .venv
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

## Current Focus

- Phase 0: simplify tooling with a scoped `.coveragerc`, trimmed `pytest.ini`, and fast `pytest --cov` baseline runs.
- Capture coverage percentages and runtime notes in `docs/metrics/coverage-notes.md` after each local run.
- Draft the fixture split outline emphasizing stateless factories and deterministic fakes for API, auth, adapters, and platform layers.
- Keep workflow lightweight; defer GitHub Actions guardrails and dashboards until coverage milestones are consistently met.

## Documentation Map

- **Testing Framework (02):** architecture, execution modes, and orchestration.
- **Fixtures & Utilities (03–10):** reusable building blocks and patterns.
- **Component Playbooks:** integrated into the framework guide for API, logging,
  and health/observability coverage.
- **Governance & Metrics:** coverage exceptions, baseline workflow, and roadmap
  alignment captured alongside the framework narrative.