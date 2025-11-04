# Phase 1 Patch Plan — Framework Foundations

## Overview
Phase 1 implements the “Framework Foundations” objectives from `api-auth-logging-coverage-plan.md`. The goal is to split heavyweight fixtures, introduce modular helpers, and lay down the coverage governance scaffolding while keeping the suite stable. This document details the patches required, ownership notes, and validation steps.

Key outcomes:
- Extract unit-friendly `conftest` structure with per-layer fixtures (unit, API, auth, logging).
- Add reusable helpers (`flask_client_factory`, `env`, `logging`, `healthcheck`).
- Clean `pytest.ini`, add `.coveragerc`, and seed the coverage exception register.
- Produce docs/knowledge-share artifacts demonstrating leadership and onboarding support.

## High-Level Patch Sequence
1. `pytest.ini` cleanup and `.coveragerc` introduction.
2. Modular fixture extraction and new helper utilities.
3. Coverage exception register and governance docs.
4. Test command updates and developer-facing documentation.
5. Metrics baseline script or instructions.
6. Knowledge-share note template/log entry.

Each patch should build incrementally, keeping unit tests runnable after each stage.

## Detailed Patch Steps

### Patch 1 — `pytest.ini` Simplification & Coverage Config
- **Files:** `pytest.ini`, new `coverage/.coveragerc` (or root `.coveragerc`).
- **Changes:**
  - Remove duplicate `addopts` blocks; consolidate under a single section.
  - Update `--cov` targets to `apps/api`, `apps/auth_service`, `logging_lib`.
  - Reference the new coverage config file.
- **Additions:** `.coveragerc` with `[run] source`, `[report] omit` entries, contexts (api/auth/logging), `branch = True` if desired.
- **Validation:** run `pytest --help` to confirm opts, run `pytest -m unit --maxfail=1` to ensure config loads.

### Patch 2 — Fixture Split (Root + Unit-Level)
- **Files:** `tests/conftest.py`, new `tests/unit/conftest.py`.
- **Changes:**
  - Keep global plugin registration and shared fixtures in root `conftest`.
  - Move unit-specific utilities (e.g., `temp_db_file`, `mock_request`) into `tests/unit/conftest.py`.
  - Ensure imports remain valid; adjust to avoid circular dependencies.
- **Validation:** run `pytest tests/unit --maxfail=1` to ensure discovery and fixtures work.
- **Notes:** Document fixture responsibilities in comments and upcoming docs.

### Patch 3 — API Service Fixture Module
- **Files:** new `tests/unit/api/conftest.py`, potential updates to existing API tests.
- **Changes:**
  - Add Flask app factory fixture building `apps.api.main` via a helper.
  - Provide mocks for rate limiter, tenant middleware, auth provider.
  - Update API unit tests to use fixtures instead of inline monkeypatching.
- **Validation:** run `pytest tests/unit/api --maxfail=1`.

### Patch 4 — Auth Service Fixture Module
- **Files:** new `tests/unit/auth_service/conftest.py` or `tests/unit/auth/conftest.py` (rename for clarity).
- **Changes:**
  - Fixture for `create_app` factory with stubbed config path.
  - Helpers to mock JWT key loading, replay cache, service clients.
- **Validation:** run `pytest tests/unit/auth --maxfail=1`.

### Patch 5 — Logging Fixture Module
- **Files:** new `tests/unit/logging/conftest.py`.
- **Changes:**
  - Fixture resetting metrics, providing in-memory sinks, synchronous dispatcher harness.
- **Validation:** run `pytest tests/unit/logging --maxfail=1`.

### Patch 6 — Helper Utilities Package
- **Files:** new under `tests/utils/`:
  - `flask_client_factory.py`
  - `env.py`
  - `logging.py`
  - `healthcheck.py`
- **Changes:** implement context managers, factory functions, synchronous dispatcher helpers.
- **Validation:** add unit tests for utilities under `tests/unit/utils/` (if needed) and ensure existing tests adopt helpers incrementally.

### Patch 7 — Coverage Exception Register & Governance Docs
- **Files:** new `tests/docs/test_framework_upgrades/coverage_exceptions.md` (table format), update plan doc references.
- **Changes:** define template columns (module, rationale, owner, review date, remediation plan).
- **Validation:** simple markdown consistency check; link from plan.

### Patch 8 — Documentation & Command Updates
- **Files:** `tests/docs/12-test-commands.md`, new/updated `tests/docs/test_framework_upgrades/guide.md` or similar.
- **Changes:** document new commands (`nox`, `make`), fixture usage guidelines, stateless expectations.
- **Validation:** lint docs (optional) and ensure links resolve.

### Patch 9 — Metrics Baseline Script/Instructions
- **Files:** new script (e.g., `scripts/test_metrics_baseline.sh`) or doc section.
- **Changes:** instructions for capturing baseline coverage/runtime/flaky counts; may include `pytest --cov-report=xml` + parsing.
- **Validation:** run script manually; attach outputs to portfolio packet.

### Patch 10 — Knowledge-Share Notes Template
- **Files:** new `tests/docs/test_framework_upgrades/phase1-knowledge-share.md` (optional) or section in existing guide.
- **Changes:** outline agenda, key takeaways, owner actions.
- **Validation:** ensure referenced in plan/resume sound bites.

## Risk Mitigation & Rollback
- Work in small patches; after each patch, run targeted test subset.
- If fixture split causes import errors, revert to previous conftest structure and re-introduce gradually.
- For coverage config changes, keep previous version available for quick rollback.

## Validation Checklist
- [ ] `pytest tests/unit --maxfail=1` passes after fixture split.
- [ ] `pytest tests/unit/api --maxfail=1` passes with new fixtures.
- [ ] `pytest tests/unit/auth --maxfail=1` passes.
- [ ] `pytest tests/unit/logging --maxfail=1` passes.
- [ ] `pytest --cov=apps/api --cov=apps/auth_service --cov=logging_lib` runs with new config.
- [ ] Coverage exception register contains at least initial entries (even if “None yet”).
- [ ] Docs updated; links validated.
- [ ] Metrics baseline recorded and stored.

## Portfolio Notes
- Capture before/after screenshots of coverage reports.
- Log mentoring/code-review summaries linked to fixture refactor commits.
- Prepare short demo showing faster `pytest` startup post fixture split.
- Update resume sound bites with quantifiable improvements once data available.


