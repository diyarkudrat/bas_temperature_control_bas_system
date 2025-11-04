# ADR 2025-11 — CI Runner Strategy for Coverage-Oriented Test Suites

## Status
Proposed — effective once Phase R2 orchestration is merged.

## Context
Phase R2 of the test framework upgrade requires deterministic coverage execution for
API, Auth, and Logging components. We need to anchor the CI environment so coverage
contexts, artifact handling, and caching behave identically to local `nox` runs.

## Decision
- **Owner:** Diyar Kudrat (Platform & Test Framework lead).
- **Runner:** GitHub Actions `ubuntu-24.04` hosted runners provide parity with internal
  staging and include Python 3.11 toolchains.
- **Python version:** Pin to CPython 3.11.x (matching `PYTHON_VERSIONS` in `noxfile.py`).
- **Virtualenv management:** Use `nox` to create per-session environments; no global venvs.
- **Dependency cache:** Leverage `actions/cache` scoped by `poetry.lock`/`requirements.txt`
  plus Nox session name to limit drift while preserving install speed.
- **Coverage artifacts:** Upload `coverage/html/` and `coverage/*.json` as build
  artifacts; retain for 14 days to support roadmap auditing and portfolio evidence.
- **Concurrency:** Run component suites in parallel matrix jobs (`tests_unit_api`,
  `tests_unit_auth`, `tests_unit_logging`) to keep end-to-end time < 10 minutes.

## Consequences
- Local `nox` commands mirror CI, reducing “it works on my machine” variance.
- Coverage outputs become standardized JSON/HTML assets across all phases.
- Artifact retention enables downstream dashboards and hiring portfolio snapshots.
- Requires periodic cache key maintenance when dependency manifests change.

## Follow-Up
- Create GitHub Actions workflow updates in Phase R5 to wire matrix + caching.
- Document cache key strategy in `tests/docs/test_framework_upgrades/orchestration.md`.
- Revisit runner choice quarterly or upon infrastructure migration.


