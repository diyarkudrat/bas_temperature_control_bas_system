# Coverage Snapshot — Phase 0 Kickoff

## Context
- Goal: reach ≥90% line coverage across `apps/api`, `apps/auth_service`, `adapters`, and `app_platform` using contract- and mock-based tests.
- Status: Phase 0 in progress; tooling simplified, documentation refreshed, and tracking scaffolding in place.

## Baseline Actions
- Updated `tests/docs/01-overview.md` with the simplified goals and virtual environment reminder.
- Streamlined test commands (`tests/docs/12-test-commands.md`) for `pytest --cov` runs.
- Authored fixture split outline and phase tracking notes to guide upcoming coverage pushes.
- Created `docs/metrics/coverage-notes.md` to log coverage percentages and runtime after each run.

## Metrics (to be populated)
- Date of baseline run:
- Coverage: API %, Auth %, Adapters %, Platform %
- Pytest runtime:
- Notes: Initial attempt failed because Google Cloud Firestore/Protobuf wheels bundled in the repo do not yet support Python 3.14 (`TypeError: Metaclasses with custom tp_new`). Need workaround (skip suites or pin CPython 3.11) before capturing coverage.

## Narrative Highlights
- Re-centered the framework around lightweight pytest runs so coverage work stays fast for solo iterations.
- Documented immediate next steps and deferred automation items to demonstrate intentional trade-offs.

## Next Update
- Populate baseline metrics after the first `pytest --cov` run.
- Capture key learnings and adjustments before moving into Phase 1 (API coverage push).

